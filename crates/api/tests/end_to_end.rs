//! The API between a real relay and a stand-in readsb: a receiver feeds the relay
//! (`tally_relay::serve`) directly, the relay reports it on its stats listener
//! (`tally_relay::stats`), a stand-in readsb answers its own API queries, and the API serves all
//! three endpoints from them over loopback HTTP, with CORS, caching and the rate limit on each.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{RawQuery, State};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS,
    ACCESS_CONTROL_REQUEST_METHOD, CACHE_CONTROL, ORIGIN,
};
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tally_api::Settings;
use tally_api_types::{
    Aircraft, AircraftResponse, MlatCheck, Network, Position, PositionSource, Station,
};
use tally_merge::Merge;
use tally_mlat_solver::sim::{self, Scenario, Simulation};
use tally_relay::hub::Hub;
use tally_relay::mlat_host::{HostedMlat, MlatHost, MlatReport, SETTLE_MS};
use tally_relay::stations::StationReport;
use tally_wire::batch::ReceiverInfoContent;
use tally_wire::noise;
use tally_wire::{
    Batch, BatchContent, Clock, Identity, Location, Observation, ReceiverInfo, Record, Region,
    RelayAddress, Role,
};
use tokio::net::{TcpListener, TcpStream};

type Result<T = ()> = std::result::Result<T, String>;

const WAIT: Duration = Duration::from_secs(20);
const SITE: &str = "https://tally.flightlines.ai";

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// What the stand-in readsb answers every query with, and the queries it was asked.
const READSB: &str = r#"{
    "now": 1791220000.25,
    "resultCount": 2,
    "ptime": 0.1,
    "aircraft": [
        {"hex": "a1b2c3", "flight": "UAL123  ", "alt_baro": 35000, "gs": 451.5, "track": 271.0,
         "baro_rate": 64, "lat": 37.5, "lon": -122.25, "seen": 0.5},
        {"hex": "abcdef", "alt_baro": "ground", "lat": 37.62, "lon": -122.38, "seen": 2}
    ]
}"#;

type Asked = Arc<Mutex<Vec<String>>>;

async fn readsb(State(asked): State<Asked>, RawQuery(query): RawQuery) -> &'static str {
    if let Ok(mut asked) = asked.lock() {
        asked.push(query.unwrap_or_default());
    }
    READSB
}

async fn start_readsb() -> Result<(String, Asked)> {
    let asked: Asked = Arc::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    let app = axum::Router::new()
        .fallback(readsb)
        .with_state(Arc::clone(&asked));
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok((format!("http://{address}"), asked))
}

/// A real relay with its stats listener: the relay's address and key, and the stats URL.
async fn start_relay() -> Result<(std::net::SocketAddr, tally_wire::PublicKey, String)> {
    let identity = Identity::generate().map_err(text)?;
    let key = identity.public();
    let hub = Arc::new(Hub::new(8));
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    let stats = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let stats_address = stats.local_addr().map_err(text)?;
    tokio::spawn(tally_relay::stats::serve(stats, Arc::clone(&hub)));
    tokio::spawn(tally_relay::serve(listener, vec![identity], hub));
    Ok((address, key, format!("http://{stats_address}")))
}

fn location() -> Location {
    Location {
        lat_e7: 374_100_000,
        lon_e7: -1_221_000_000,
        alt_m: 10,
        precision_m: 0,
    }
}

fn batch(receiver: &Identity, sequence: u64) -> Result<Batch> {
    let observations = (0..3u8)
        .map(|n| Observation {
            format: b'2',
            timestamp: sequence * 1_000 + u64::from(n),
            signal: 90,
            data: vec![0x5d, 0xab, 0xcd, n, sequence as u8, 0, 0],
        })
        .collect();
    Batch::sign(
        receiver,
        &BatchContent {
            boot_id: 7,
            sequence,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations,
        },
    )
    .map_err(text)
}

/// A receiver feeding the relay directly: its description, then batches 0, 1, 2 and 4 (3 never
/// arrives). The connection stays open for the rest of the test.
async fn feed(relay: std::net::SocketAddr, relay_key: &tally_wire::PublicKey) -> Result<Identity> {
    let receiver = Identity::generate().map_err(text)?;
    let stream = TcpStream::connect(relay).await.map_err(text)?;
    let mut session = noise::connect(stream, &receiver, relay_key, Role::Feeder)
        .await
        .map_err(text)?;
    let info = ReceiverInfo::sign(
        &receiver,
        &ReceiverInfoContent {
            issued_ms: 1,
            location: Some(location()),
            clock: Clock::Dump1090,
            software: "tally-feed test".to_owned(),
            relays: Vec::new(),
        },
    )
    .map_err(text)?;
    let mut records = vec![Record::ReceiverInfo(info)];
    for sequence in [0, 1, 2, 4] {
        records.push(Record::Batch(batch(&receiver, sequence)?));
    }
    session.writer.send(&records).await.map_err(text)?;
    tokio::spawn(async move {
        let _session = session;
        std::future::pending::<()>().await;
    });
    Ok(receiver)
}

async fn start_api(settings: Settings) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    tokio::spawn(tally_api::serve(listener, settings));
    Ok(format!("http://{address}"))
}

/// `GET url` from the public site's origin: status, headers and body.
async fn get(url: &str) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let request = Request::get(url)
        .header(ORIGIN, SITE)
        .body(Empty::new())
        .map_err(text)?;
    send(url, request).await
}

/// The preflight a browser sends before a `GET` that carries `traceparent` and `accept`, as the
/// Flightlines client core's fetch port sends every read.
async fn preflight(url: &str) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri(url)
        .header(ORIGIN, SITE)
        .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(ACCESS_CONTROL_REQUEST_HEADERS, "accept,traceparent")
        .body(Empty::new())
        .map_err(text)?;
    send(url, request).await
}

async fn send(url: &str, request: Request<Empty<Bytes>>) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let response = tokio::time::timeout(WAIT, client.request(request))
        .await
        .map_err(|_| format!("{url}: no answer"))?
        .map_err(text)?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(text)?
        .to_bytes();
    Ok((status, headers, body))
}

fn json<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T> {
    serde_json::from_slice(body).map_err(|error| format!("{error}: {body:?}"))
}

fn header<'a>(headers: &'a HeaderMap, name: &hyper::header::HeaderName) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

/// Asks `url` until it answers 200 with a body `done` accepts.
async fn until<T: serde::de::DeserializeOwned>(
    url: &str,
    done: impl Fn(&T) -> bool,
) -> Result<(HeaderMap, T)> {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Ok((StatusCode::OK, headers, body)) = get(url).await
                && let Ok(value) = json::<T>(&body)
                && done(&value)
            {
                return (headers, value);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| format!("{url} never answered as expected"))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_api_serves_aircraft_the_network_and_a_station_from_readsb_and_a_real_relay() -> Result
{
    let (readsb_url, asked) = start_readsb().await?;
    let (relay, relay_key, stats_url) = start_relay().await?;
    let receiver = feed(relay, &relay_key).await?;
    let key = receiver.public();

    // The relay's own report: one direct session, four batches, the one gap.
    let (_, report) = until::<StationReport>(
        &format!("{stats_url}/stations/{}", key.to_base64url()),
        |report| report.batches == 4,
    )
    .await?;
    assert_eq!(
        (
            report.key.as_str(),
            report.sessions,
            report.connected,
            report.gaps,
            report.observations
        ),
        (key.to_base64().as_str(), 1, true, 1, 12)
    );

    let mut settings = Settings::new(stats_url, readsb_url);
    settings.refresh = Duration::from_millis(100);
    let api = start_api(settings).await?;

    // A station, by its key in the URL's form.
    let (headers, station) = until::<Station>(
        &format!("{api}/v1/stations/{}", key.to_base64url()),
        |station| station.batches == 4,
    )
    .await?;
    assert_eq!(
        (
            station.key.as_str(),
            station.online,
            station.gaps,
            station.software.as_deref()
        ),
        (key.to_base64().as_str(), true, 1, Some("tally-feed test"))
    );
    assert_eq!(
        station.location,
        Some(Position {
            lat: 37.41,
            lon: -122.1
        })
    );
    assert!(station.first_seen_at_ms <= station.last_seen_at_ms);
    assert!(station.last_seen_at_ms <= station.now_ms);
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    assert_eq!(header(&headers, &CACHE_CONTROL), "public, max-age=15");

    // A key the relay does not know, and a path that is not a key.
    let stranger = Identity::generate().map_err(text)?.public();
    let (status, headers, _) =
        get(&format!("{api}/v1/stations/{}", stranger.to_base64url())).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    let (status, _, _) = get(&format!("{api}/v1/stations/not-a-key")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The network: the one receiver, and readsb's count.
    let (headers, network) = until::<Network>(&format!("{api}/v1/network"), |network| {
        network.receivers_total == 1
    })
    .await?;
    assert_eq!(
        (
            network.receivers_online,
            network.receivers_total,
            network.aircraft
        ),
        (1, 1, 2)
    );
    assert!(network.messages_per_sec >= 0.0);
    assert_eq!(header(&headers, &CACHE_CONTROL), "public, max-age=15");

    // Aircraft in a viewport, asked of readsb in its own order.
    let (status, headers, body) = get(&format!(
        "{api}/v1/aircraft?west=-123&south=37&east=-121&north=38"
    ))
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, &CACHE_CONTROL), "public, max-age=2");
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    let answer: AircraftResponse = json(&body)?;
    let expected = vec![
        Aircraft {
            hex: "a1b2c3".to_owned(),
            flight: Some("UAL123".to_owned()),
            lat: 37.5,
            lon: -122.25,
            alt_baro_ft: Some(35_000),
            gs_kt: Some(451.5),
            track_deg: Some(271.0),
            baro_rate_fpm: Some(64),
            on_ground: false,
            last_heard_at_ms: 1_791_220_000_250 - 500,
            position_source: PositionSource::Adsb,
            mlat: None,
        },
        Aircraft {
            hex: "abcdef".to_owned(),
            flight: None,
            lat: 37.62,
            lon: -122.38,
            alt_baro_ft: None,
            gs_kt: None,
            track_deg: None,
            baro_rate_fpm: None,
            on_ground: true,
            last_heard_at_ms: 1_791_220_000_250 - 2_000,
            position_source: PositionSource::Adsb,
            mlat: None,
        },
    ];
    assert_eq!(answer.now_ms, 1_791_220_000_250);
    assert_eq!(answer.aircraft, expected);
    let queries = asked.lock().map_err(text)?.clone();
    assert!(
        queries.contains(&"box=37,38,-123,-121&filter_with_pos".to_owned()),
        "{queries:?}"
    );
    assert!(queries.contains(&"all_with_pos".to_owned()), "{queries:?}");

    // Across the antimeridian: two readsb boxes, each aircraft listed once.
    let (status, _, body) = get(&format!(
        "{api}/v1/aircraft?west=170&south=-20&east=-170&north=-10"
    ))
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json::<AircraftResponse>(&body)?.aircraft, expected);
    let queries = asked.lock().map_err(text)?.clone();
    for part in [
        "box=-20,-10,170,180&filter_with_pos",
        "box=-20,-10,-180,-170&filter_with_pos",
    ] {
        assert!(queries.contains(&part.to_owned()), "{queries:?}");
    }

    // The precise feed with no precise product held: unavailable, never an empty sky, and not
    // cached.
    let (status, headers, body) = get(&format!(
        "{api}/v1/aircraft?west=-123&south=37&east=-121&north=38&feed=precise"
    ))
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header(&headers, &CACHE_CONTROL), "no-store");
    assert_eq!(
        json::<serde_json::Value>(&body)?,
        serde_json::json!({ "error": "precise_unavailable" })
    );

    // Too large a viewport, and one not given.
    for query in ["west=-130&south=0&east=-60&north=10", "west=-123&south=37"] {
        let (status, headers, _) = get(&format!("{api}/v1/aircraft?{query}")).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_beyond_its_burst_is_refused_and_the_refusal_is_not_cached() -> Result {
    let (readsb_url, _) = start_readsb().await?;
    let mut settings = Settings::new("http://127.0.0.1:9", readsb_url);
    // A rate so slow no token comes back during the test.
    settings.rate = 0.001;
    settings.burst = 3.0;
    let api = start_api(settings).await?;
    let url = format!("{api}/v1/aircraft?west=-123&south=37&east=-121&north=38");
    for _ in 0..3 {
        assert_eq!(get(&url).await?.0, StatusCode::OK);
    }
    let (status, headers, _) = get(&url).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header(&headers, &CACHE_CONTROL), "no-store");
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_preflight_allows_what_the_client_core_sends_and_costs_no_token() -> Result {
    let (readsb_url, _) = start_readsb().await?;
    let mut settings = Settings::new("http://127.0.0.1:9", readsb_url);
    // One token, and none comes back during the test.
    settings.rate = 0.001;
    settings.burst = 1.0;
    let api = start_api(settings).await?;
    let url = format!("{api}/v1/aircraft?west=-123&south=37&east=-121&north=38");
    for path in [
        url.as_str(),
        &format!("{api}/v1/network"),
        &format!("{api}/v1/stations/k"),
    ] {
        let (status, headers, body) = preflight(path).await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{path}");
        assert!(body.is_empty());
        assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
        assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_METHODS), "GET");
        let allowed: Vec<&str> = header(&headers, &ACCESS_CONTROL_ALLOW_HEADERS)
            .split(',')
            .map(str::trim)
            .collect();
        assert!(allowed.contains(&"traceparent"), "{allowed:?}");
        assert!(allowed.contains(&"accept"), "{allowed:?}");
        assert_eq!(header(&headers, &ACCESS_CONTROL_MAX_AGE), "86400");
    }
    // The preflights spent nothing: the one token is still there for the read itself, and the
    // refusal after it is readable, `Retry-After` included.
    let (status, headers, _) = get(&url).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, &ACCESS_CONTROL_EXPOSE_HEADERS),
        "retry-after"
    );
    let (status, headers, _) = get(&url).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        header(&headers, &ACCESS_CONTROL_EXPOSE_HEADERS),
        "retry-after"
    );
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    Ok(())
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// How long before now the scenario starts: its window bins are past by the relays' clock once it
/// is the wall clock again (a 30 s scenario, a window after it and its settling).
const SCENARIO_AGO_MS: u64 = 150_000;
/// What the relays' ingest clock is held at while the scenario is fed: before its first bin, so
/// every batch is stamped before the step that takes its bin (RFC-0181: raw is late by its stamp,
/// never by when a step ran), and few enough steps before now that the first step is soon.
const HELD_AGO_MS: u64 = 180_000;

/// A scenario that began `SCENARIO_AGO_MS` ago, so every window bin of it is past by the time the
/// relays' clock is released.
fn minutes_ago(scenario: Scenario) -> Scenario {
    let start_ms = wall_ms() - SCENARIO_AGO_MS;
    Scenario {
        midnight_unix_ms: start_ms - start_ms % 86_400_000,
        start_tod_s: (start_ms % 86_400_000) as f64 / 1000.0,
        ..scenario
    }
}

/// A relay's hosted MLAT (`tally_relay::mlat_host`, RFC-0174 §2.1: the relay and its MLAT are
/// one program) pinned to the simulator's areas, whose steps wait until it has taken `batches`
/// batches, and which then releases its relay's clock (`released`): the scenario is past, so every
/// window is due the moment the engine looks, and a step on the clock would solve whatever raw a
/// slow machine had delivered by then.
struct Held {
    host: HostedMlat,
    areas: tally_wire::Regions,
    batches: u64,
    released: Arc<AtomicBool>,
}

impl MlatHost for Held {
    fn set_areas(&self, _: tally_wire::Regions, descriptions: Vec<ReceiverInfo>) {
        self.host.set_areas(self.areas.clone(), descriptions);
    }

    fn offer_description(&self, info: &tally_wire::ReceiverInfo) {
        self.host.offer_description(info);
    }

    fn offer_batch(&self, batch: &std::sync::Arc<tally_wire::Decoded>, now_ms: u64) {
        self.host.offer_batch(batch, now_ms);
    }

    fn sealed_bins(&self) -> Option<tally_mlat_solver::held::SealedBins> {
        self.host.sealed_bins()
    }

    fn take_published(&self, now_ms: u64) -> Vec<Record> {
        if self.host.ingested() >= self.batches {
            self.released.store(true, Ordering::SeqCst);
            self.host.take_published(now_ms)
        } else {
            Vec::new()
        }
    }

    fn cores(&self) -> u16 {
        self.host.cores()
    }

    fn report(&self) -> MlatReport {
        self.host.report()
    }
}

/// The areas within about 150 km of the simulator's centre.
fn areas() -> Result<Vec<Region>> {
    let (lat, lon) = sim::CENTRE;
    let mut areas = Vec::new();
    for north in -2..=2 {
        for east in -2..=2 {
            let location = Location {
                lat_e7: ((lat + f64::from(north) * 0.6) * 1e7) as i32,
                lon_e7: ((lon + f64::from(east) * 1.0) * 1e7) as i32,
                alt_m: 0,
                precision_m: 0,
            };
            let area = Region::containing(&location, tally_wire::rendezvous::AREA_RESOLUTION)
                .map_err(text)?;
            if !areas.contains(&area) {
                areas.push(area);
            }
        }
    }
    Ok(areas)
}

/// A relay hosting MLAT for the simulator's areas, its first step once it holds `batches`
/// batches: its address as a client names it, and its hub.
async fn mlat_relay(batches: u64) -> Result<(RelayAddress, Arc<Hub>)> {
    let identity = Identity::generate().map_err(text)?;
    let key = identity.public();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    // Every feeder here comes from loopback: more than one host's share of connections.
    // Its ingest clock is held before the scenario until every batch is in (`Held`).
    let released = Arc::new(AtomicBool::new(false));
    let held_ms = wall_ms() - HELD_AGO_MS;
    let clock: tally_relay::ingest::Clock = Arc::new({
        let released = Arc::clone(&released);
        move || {
            if released.load(Ordering::SeqCst) {
                wall_ms()
            } else {
                held_ms
            }
        }
    });
    let hub = Arc::new(Hub::clocked(8, clock).max_connections_per_address(64));
    let areas = tally_wire::Regions::new(areas()?);
    let host = HostedMlat::new(
        identity.clone(),
        1,
        tally_mlat::engine::Settings {
            regions: tally_wire::Regions::default(),
            settle_ms: SETTLE_MS,
            threads: 4,
            capacity: tally_mlat::engine::Capacity::default(),
        },
    )?;
    host.set_areas(areas.clone(), Vec::new());
    hub.network().host_mlat(Arc::new(Held {
        host,
        areas,
        batches,
        released,
    }));
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    Ok((
        RelayAddress {
            key,
            address: address.to_string(),
        },
        hub,
    ))
}

/// Waits until `hub` has `links` more links in its fan-out than `before`: from then on everything
/// published reaches them. An event, not a sleep: a slow machine only waits longer.
async fn listening(hub: &Hub, before: usize, links: usize) -> Result {
    tokio::time::timeout(Duration::from_secs(60), async {
        while hub.listening() < before + links {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "{} of {links} links joined the fan-out",
            hub.listening().saturating_sub(before)
        )
    })
}

/// The simulated receivers `receivers`, publishing to `relay` as feeders.
async fn feed_simulation(
    simulation: &Simulation,
    relay: &RelayAddress,
    receivers: std::ops::Range<usize>,
) -> Result {
    let feeds = simulation.feeds().map_err(text)?;
    for feed in &feeds[receivers] {
        {
            let stream = TcpStream::connect(&relay.address).await.map_err(text)?;
            let mut session = noise::connect(stream, &feed.identity, &relay.key, Role::Feeder)
                .await
                .map_err(text)?;
            let mut records = vec![Record::ReceiverInfo(feed.info.clone())];
            records.extend(feed.batches.iter().cloned().map(Record::Batch));
            tokio::spawn(async move {
                for record in records {
                    if session.writer.send(&[record]).await.is_err() {
                        return;
                    }
                }
                std::future::pending::<()>().await;
                drop(session);
            });
        }
    }
    Ok(())
}

/// THE POINT: two relays each solve MLAT from the raw of the receivers that feed it (seven of
/// ten each, overlapping), signed by the relay's own key; the API, subscribed to both, serves one
/// merged MLAT position per aircraft readsb holds no position for, the same one a client merging
/// every record both relays carried holds, aircraft both relays solved included.
#[tokio::test(flavor = "multi_thread")]
async fn the_api_serves_one_merged_mlat_position_per_aircraft_from_two_relays() -> Result {
    let simulation = sim::run(&minutes_ago(Scenario {
        duration_s: 30.0,
        modes_aircraft: 16,
        ..Scenario::new(31)
    }));
    let feeds = simulation.feeds().map_err(text)?;
    let batches = |receivers: std::ops::Range<usize>| -> u64 {
        feeds[receivers]
            .iter()
            .map(|feed| feed.batches.len() as u64)
            .sum()
    };
    let ((west, west_hub), (east, east_hub)) = (
        mlat_relay(batches(0..7)).await?,
        mlat_relay(batches(3..10)).await?,
    );
    let before = (west_hub.listening(), east_hub.listening());
    let (readsb_url, _) = start_readsb().await?;
    let (_, _, stats_url) = start_relay().await?;
    let mut settings = Settings::new(stats_url, readsb_url);
    settings.mlat.relays = vec![west.clone(), east.clone()];
    // The scenario ran minutes ago.
    settings.mlat.max_age = Duration::from_secs(3 * 86_400);
    let api = start_api(settings).await?;
    // A client of its own on both relays: every record the API could have read.
    let (inbound, mut records) = tokio::sync::mpsc::channel(65_536);
    for relay in [&west, &east] {
        tokio::spawn(tally_merge::link::subscribe(
            relay.clone(),
            Identity::generate().map_err(text)?,
            tally_merge::link::streams(false),
            inbound.clone(),
        ));
    }
    // The API's link and the client's are in each relay's fan-out before any receiver
    // publishes, so nothing published is missed.
    listening(&west_hub, before.0, 2).await?;
    listening(&east_hub, before.1, 2).await?;
    feed_simulation(&simulation, &west, 0..7).await?;
    feed_simulation(&simulation, &east, 3..10).await?;

    let mut merge = Merge::new(tally_merge::Settings::new(false));
    let last: Arc<Mutex<String>> = Arc::default();
    let url = format!("{api}/v1/aircraft?west=0&south=49&east=10&north=55");
    let outcome = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            while let Ok(record) = records.try_recv() {
                merge.ingest(&record, 0).map_err(text)?;
            }
            let expected: Vec<(String, f64, f64, Option<i32>)> = tally_api::mlat::served(&merge)
                .into_iter()
                .map(|one| (one.hex(), one.lat, one.lon, one.altitude_ft))
                .collect();
            let contested = merge.tracks().iter().any(|track| {
                track
                    .latest()
                    .is_some_and(|latest| !latest.alternatives().is_empty())
            });
            if let Ok((StatusCode::OK, _, body)) = get(&url).await
                && let Ok(answer) = json::<AircraftResponse>(&body)
            {
                let served: Vec<&Aircraft> = answer
                    .aircraft
                    .iter()
                    .filter(|one| one.position_source == PositionSource::Mlat)
                    .collect();
                let mut got: Vec<(String, f64, f64, Option<i32>)> = served
                    .iter()
                    .map(|one| (one.hex.clone(), one.lat, one.lon, one.alt_baro_ft))
                    .collect();
                got.sort_by(|a, b| a.0.cmp(&b.0));
                if let Ok(mut last) = last.lock() {
                    *last = format!("contested {contested}; expected {expected:?}; served {got:?}");
                }
                // JSON carries a degree to its seven decimal places, read back to within a
                // rounding.
                let same = got.len() == expected.len()
                    && got.iter().zip(&expected).all(|(a, b)| {
                        a.0 == b.0
                            && (a.1 - b.1).abs() < 1e-9
                            && (a.2 - b.2).abs() < 1e-9
                            && a.3 == b.3
                    });
                if contested && expected.len() >= 5 && same {
                    return Ok::<_, String>(served.into_iter().cloned().collect::<Vec<_>>());
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "the API never served the merged positions: {}",
            last.lock().map(|last| last.clone()).unwrap_or_default()
        )
    })??;
    // One position per aircraft, each saying what it is and how it was checked.
    let mut hexes: Vec<&str> = outcome.iter().map(|one| one.hex.as_str()).collect();
    hexes.dedup();
    assert_eq!(hexes.len(), outcome.len());
    for one in &outcome {
        let mlat = one.mlat.ok_or("an MLAT position without its uncertainty")?;
        assert!(mlat.horizontal_sigma_m > 0.0 && mlat.horizontal_sigma_m < 5_000.0);
        assert_eq!(mlat.check, MlatCheck::Signature);
    }
    Ok(())
}
