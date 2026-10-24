//! The API between a real relay and a stand-in readsb: a receiver feeds the relay
//! (`tally_relay::serve`) directly, the relay reports it on its stats listener
//! (`tally_relay::stats`), a stand-in readsb answers its own API queries, and the API serves all
//! three endpoints from them over loopback HTTP, with CORS, caching and the rate limit on each, and
//! pushes a viewport's aircraft as a stream; it answers a client its own stations, the ADS-B
//! Exchange-compatible `/v2` from readsb, and routes from a standing-data directory.
#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{RawQuery, State};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS,
    ACCESS_CONTROL_REQUEST_METHOD, CACHE_CONTROL, CONTENT_TYPE, ORIGIN, RETRY_AFTER,
};
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tally_api::Settings;
use tally_api_types::{
    Aircraft, AircraftResponse, AircraftUpdate, Feed, FeederStats, MeResponse, MlatCheck, Network,
    PositionSource, SourceCounts, Station, fixtures,
};
use tally_merge::Merge;
use tally_mlat::intake::SiteRecord;
use tally_mlat_solver::sim::{self, Scenario, Simulation};
use tally_relay::hub::Hub;
use tally_relay::mlat_host::stepping::{self, Hosting};
use tally_relay::mlat_host::{HostedMlat, MlatHost, MlatReport, SETTLE_MS, WindowClock};
use tally_relay::stations::StationReport;
use tally_wire::batch::PublicInfoContent;
use tally_wire::noise;
use tally_wire::{
    Batch, BatchContent, Clock, Identity, Location, Observation, ReceiverInfo, ReceiverSite,
    ReceiverSiteContent, Record, Region, RelayAddress, Role,
};
use tokio::net::{TcpListener, TcpStream};

type Result<T = ()> = std::result::Result<T, String>;

/// The same key again, from its file form, for a test that hands a key over and still signs or
/// dials as it: `Identity` is not `Clone`.
fn twin(identity: &Identity) -> Result<Identity> {
    Identity::from_base64(&identity.to_base64()).map_err(|error| error.to_string())
}

/// How long a test waits for the event it asserts before calling it a hang: a guard on a server
/// that never gets there, never a verdict on how fast the machine running the test is.
const WAIT: Duration = Duration::from_secs(120);
/// The site whose pages read the API, as this test configures it (`--allow-origin`): the API
/// allows no origin of its own accord.
const SITE: &str = "https://site.example";

/// The API's settings over `relay_stats` and `readsb`, the test's site allowed, on the host's
/// clocks with their bound stated (no test host runs ClockBound).
fn settings(relay_stats: impl Into<String>, readsb: impl Into<String>) -> Settings {
    let mut settings = Settings::new(relay_stats, readsb);
    settings.allow_origins = vec![SITE.to_owned()];
    settings.clock = tally_api::mlat::Clock::host_stated();
    settings
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// What the stand-in readsb answers every query with, and the queries it was asked: a1b2c3's last
/// message is newer than its position.
const READSB: &str = r#"{
    "now": 1791220000.25,
    "resultCount": 2,
    "ptime": 0.1,
    "aircraft": [
        {"hex": "a1b2c3", "type": "adsb_icao", "flight": "UAL123  ", "alt_baro": 35000,
         "gs": 451.5, "track": 271.0, "baro_rate": 64, "lat": 37.5, "lon": -122.25,
         "seen": 0.5, "seen_pos": 1.0},
        {"hex": "abcdef", "type": "adsr_icao", "alt_baro": "ground", "lat": 37.62, "lon": -122.38,
         "seen": 2}
    ]
}"#;

/// readsb a second on: a1b2c3 has a new position, and abcdef is no longer heard.
const READSB_LATER: &str = r#"{
    "now": 1791220001.25,
    "aircraft": [
        {"hex": "a1b2c3", "type": "adsb_icao", "flight": "UAL123  ", "alt_baro": 35000,
         "gs": 451.5, "track": 271.0, "baro_rate": 64, "lat": 37.51, "lon": -122.25,
         "seen": 0.1, "seen_pos": 0.2}
    ]
}"#;

/// readsb another second on: a1b2c3 was heard (a velocity message), its position not.
const READSB_HEARD: &str = r#"{
    "now": 1791220002.25,
    "aircraft": [
        {"hex": "a1b2c3", "type": "adsb_icao", "flight": "UAL123  ", "alt_baro": 35000,
         "gs": 451.5, "track": 271.0, "baro_rate": 64, "lat": 37.51, "lon": -122.25,
         "seen": 0.1, "seen_pos": 1.2}
    ]
}"#;

/// What the stand-in readsb answers a query in ADS-B Exchange's v2 form (`&jv2`): readsb's own v2
/// shape, which `/v2` serves as it is.
const READSB_V2: &str = r#"{"ac":[{"hex":"a1b2c3","type":"adsb_icao","flight":"UAL123  ","r":"N12345","t":"B738","alt_baro":35000,"gs":451.5,"track":271.0,"squawk":"1200","lat":37.5,"lon":-122.25,"nic":8,"rc":186,"seen_pos":1.0,"messages":4521,"seen":0.5,"rssi":-20.1,"r_dst":12.3,"r_dir":45.6,"mlat":[],"tisb":[]}],"msg":"No error","now":1791220000250,"total":1,"ctime":1791220000250,"ptime":0}"#;

type Asked = Arc<Mutex<Vec<String>>>;
/// What the stand-in readsb answers, which a test may change.
type Answer = Arc<Mutex<&'static str>>;

async fn readsb(
    State((asked, answer)): State<(Asked, Answer)>,
    RawQuery(query): RawQuery,
) -> &'static str {
    let query = query.unwrap_or_default();
    let v2 = query.ends_with("&jv2");
    if let Ok(mut asked) = asked.lock() {
        asked.push(query);
    }
    if v2 {
        return READSB_V2;
    }
    answer.lock().map_or(READSB, |answer| *answer)
}

async fn start_readsb() -> Result<(String, Asked)> {
    let (url, asked, _) = start_readsb_answering().await?;
    Ok((url, asked))
}

/// A stand-in readsb answering `READSB` until the test changes its answer.
async fn start_readsb_answering() -> Result<(String, Asked, Answer)> {
    let asked: Asked = Arc::default();
    let answer: Answer = Arc::new(Mutex::new(READSB));
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    let app = axum::Router::new()
        .fallback(readsb)
        .with_state((Arc::clone(&asked), Arc::clone(&answer)));
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok((format!("http://{address}"), asked, answer))
}

/// A real relay with its stats listener, on `clock` (its ingest clock, `Hub::clocked`): the relay's
/// address and key, and the stats URL. It signs its feeder figures every 200 ms by that clock, so a
/// test that moves the clock past the hour it fed reads that hour's figures without waiting it out.
async fn start_relay(
    clock: &Arc<stepping::Clock>,
) -> Result<(std::net::SocketAddr, tally_wire::PublicKey, String)> {
    let identity = Identity::generate().map_err(text)?;
    let key = identity.public();
    let hub = Arc::new(
        Hub::clocked(8, clock.clock(), tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
            .figures_every(200),
    );
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

fn batch(receiver: &Identity, sequence: u64, wall_ms: u64) -> Result<Batch> {
    let observations = (0..3u8)
        .map(|n| Observation {
            format: b'2',
            timestamp: sequence * 1_000 + u64::from(n),
            signal: 90,
            data: vec![0x5d, 0xab, 0xcd, n, sequence as u8, 0, 0],
        })
        .collect();
    anchored_batch(
        receiver,
        &BatchContent {
            boot_id: 7,
            sequence,
            counter_epoch: 0,
            wall_ms,
            dropped: 0,
            previous: [0; 32],
            observations,
        },
    )
    .map_err(text)
}

/// A receiver feeding the relay directly, as a version 3 feeder does: its public description (its
/// public cell, no site) and its site (relay-only), then batches 0, 1, 2 and 4 (3 never arrives),
/// each at `wall_ms` by its clock. The connection stays open for the rest of the test.
async fn feed(
    relay: std::net::SocketAddr,
    relay_key: &tally_wire::PublicKey,
    wall_ms: u64,
) -> Result<Identity> {
    let receiver = Identity::generate().map_err(text)?;
    let stream = TcpStream::connect(relay).await.map_err(text)?;
    let mut session = noise::connect(stream, &receiver, relay_key, Role::Feeder)
        .await
        .map_err(text)?;
    let info = ReceiverInfo::sign_public(
        &receiver,
        &PublicInfoContent {
            issued_ms: 1,
            cell: Some(Region::public_cell(&location()).map_err(text)?),
            clock: Clock::Dump1090,
            software: "tally-feed test".to_owned(),
            relays: Vec::new(),
        },
    )
    .map_err(text)?;
    let site = ReceiverSite::sign(
        &receiver,
        &ReceiverSiteContent {
            issued_ms: 1,
            location: location(),
            clock: Clock::Dump1090,
        },
    )
    .map_err(text)?;
    let mut records = vec![Record::ReceiverInfo(info), Record::ReceiverSite(site)];
    for sequence in [0, 1, 2, 4] {
        records.push(Record::Batch(batch(&receiver, sequence, wall_ms)?));
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
    let identity = Identity::generate().map_err(text)?;
    tokio::spawn(tally_api::serve(listener, settings, identity));
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

/// `GET url` from the public site's origin, as a proxy names the client `client` (`TEST_CLIENT`).
async fn get_as(url: &str, client: &str) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let request = Request::get(url)
        .header(ORIGIN, SITE)
        .header(TEST_CLIENT, client)
        .body(Empty::new())
        .map_err(text)?;
    send(url, request).await
}

/// The header the test's proxy names a client by (`--client-ip-header`).
const TEST_CLIENT: &str = "x-test-client";

/// The preflight a browser sends before a `GET` that carries `traceparent` and `accept`, as a
/// browser client sends every read.
async fn preflight(url: &str) -> Result<(StatusCode, HeaderMap, Bytes)> {
    preflight_for(url, "GET", "accept,traceparent").await
}

/// The preflight a browser sends before `method` with `headers`.
async fn preflight_for(
    url: &str,
    method: &str,
    headers: &str,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri(url)
        .header(ORIGIN, SITE)
        .header(ACCESS_CONTROL_REQUEST_METHOD, method)
        .header(ACCESS_CONTROL_REQUEST_HEADERS, headers)
        .body(Empty::new())
        .map_err(text)?;
    send(url, request).await
}

/// `POST url` with a JSON `body` from the public site's origin, as tar1090 posts its routeset.
async fn post(url: &str, body: &str) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let request = Request::post(url)
        .header(ORIGIN, SITE)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_owned())))
        .map_err(text)?;
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
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

/// The aircraft the stand-in readsb's first answer is, as the API serves them.
fn expected() -> Vec<Aircraft> {
    vec![
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
            position_at_ms: 1_791_220_000_250 - 1_000,
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
            position_at_ms: 1_791_220_000_250 - 2_000,
            position_source: PositionSource::Adsr,
            mlat: None,
        },
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn the_api_serves_aircraft_the_network_and_a_station_from_readsb_and_a_real_relay() -> Result
{
    let (readsb_url, asked) = start_readsb().await?;
    // The relay's clock stands an hour back while it is fed, and is moved to the wall clock once
    // the station is read: the hour it was fed in has passed, so its figures are published.
    let clock = stepping::Clock::at(wall_ms() - tally_wire::FIGURES_BUCKET_MS);
    let (relay, relay_key, stats_url) = start_relay(&clock).await?;
    let receiver = feed(relay, &relay_key, clock.now()).await?;
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

    let mut settings = settings(stats_url, readsb_url);
    settings.refresh = Duration::from_millis(100);
    settings.client_ip_header = Some(hyper::header::HeaderName::from_static(TEST_CLIENT));
    // The API reads the relay as any client does: its feeder figures among what it reads.
    settings.mlat.relays = vec![RelayAddress {
        key: relay_key,
        address: relay.to_string(),
    }];
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
    // Served at a pin inside its public cell, never the place itself: the relay told the API
    // the cell and nothing finer.
    let pin = station.location.ok_or("no pin")?;
    assert!(pin.lat != 37.41 && pin.lon != -122.1, "{pin:?}");
    let pinned = Region::public_cell(&Location {
        lat_e7: (pin.lat * 1e7).round() as i32,
        lon_e7: (pin.lon * 1e7).round() as i32,
        alt_m: 0,
        precision_m: 0,
    })
    .map_err(text)?;
    assert_eq!(pinned, Region::public_cell(&location()).map_err(text)?);
    // The relay's report, which the API reads, names the cell, never a coordinate.
    let report_json = serde_json::to_string(&report).map_err(text)?;
    assert!(!report_json.contains("37.41") && !report_json.contains("122.1,"));

    assert_eq!(station.state, tally_api_types::StationState::Feeding);
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

    // The asker's own stations (matched per host in `snapshot`'s tests): this receiver fed the
    // relay from loopback, which is no feeder's host, so no asker is answered it, not even one
    // the proxy names as loopback. Behind a proxy, a request whose header is missing or does not
    // parse has no address of its own and is answered none, never the proxy's. Never cached: the
    // answer is the asker's.
    for (asker, named) in [
        (None, "no header"),
        (Some("not-an-address"), "a header that does not parse"),
        (Some("198.51.100.9"), "a stranger"),
        (Some("127.0.0.1"), "loopback"),
    ] {
        let url = format!("{api}/v1/me");
        let (status, headers, body) = match asker {
            Some(asker) => get_as(&url, asker).await?,
            None => get(&url).await?,
        };
        assert_eq!(status, StatusCode::OK, "{named}");
        assert!(json::<MeResponse>(&body)?.stations.is_empty(), "{named}");
        assert_eq!(header(&headers, &CACHE_CONTROL), "no-store", "{named}");
        assert_eq!(
            header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN),
            SITE,
            "{named}"
        );
    }

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
    assert_eq!(
        network.aircraft_by_source,
        SourceCounts {
            adsb: 1,
            adsr: 1,
            ..SourceCounts::default()
        }
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
    let expected = expected();
    assert_eq!(answer.now_ms, 1_791_220_000_250);
    assert!(answer.sent_at_ms > 0);
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

    // Its figures, last (the station is not online once the clock moves past its batches): as the
    // relay computed and signed them once the hour it was fed in passed, and the API read them on
    // its client link: the four batches' twelve receptions, in the area of its public cell.
    clock.set(wall_ms());
    let (_, figures) = until::<FeederStats>(
        &format!("{api}/v1/stations/{}/stats", key.to_base64url()),
        |figures| figures.messages == 12,
    )
    .await?;
    let area =
        tally_wire::rendezvous::area_of_public(Region::public_cell(&location()).map_err(text)?)
            .map(|area| format!("{:x}", area.as_u64()));
    assert_eq!(figures.area, area);
    assert!(!figures.standing && figures.ranks.is_none());
    let figures_json = serde_json::to_string(&figures).map_err(text)?;
    assert!(!figures_json.contains("37.41") && !figures_json.contains("-122.1,"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_beyond_its_burst_is_refused_and_the_refusal_is_not_cached() -> Result {
    let (readsb_url, _) = start_readsb().await?;
    let mut settings = settings("http://127.0.0.1:9", readsb_url);
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
    let mut settings = settings("http://127.0.0.1:9", readsb_url);
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
        assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_METHODS), "GET, POST");
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

/// `/v2`: each path one query of readsb in v2 form, as adsb.lol asks it, answered as readsb
/// writes it less what places its receiver, cached as an aircraft answer is; a malformed value refused before readsb is asked.
#[tokio::test(flavor = "multi_thread")]
async fn v2_asks_readsb_as_adsb_lol_does_and_serves_its_answer() -> Result {
    let (readsb_url, asked) = start_readsb().await?;
    let api = start_api(settings("http://127.0.0.1:9", readsb_url)).await?;
    // Served as readsb wrote it, less what it says of its receiver (distance, direction, signal).
    let mut readsb_v2: serde_json::Value = serde_json::from_str(READSB_V2).map_err(text)?;
    let aircraft = readsb_v2["ac"][0]
        .as_object_mut()
        .ok_or("readsb's answer has no aircraft")?;
    for field in tally_api::v2::RECEIVER_FIELDS {
        assert!(aircraft.remove(field).is_some(), "{field}");
    }
    for (path, query) in [
        ("hex/A1B2C3", "find_hex=a1b2c3&jv2"),
        ("icao/a1b2c3,c0ffee", "find_hex=a1b2c3,c0ffee&jv2"),
        ("callsign/UAL123", "find_callsign=UAL123&jv2"),
        ("registration/N12345", "find_reg=N12345&jv2"),
        ("reg/G-KELS", "find_reg=G-KELS&jv2"),
        ("type/B738", "find_type=B738&jv2"),
        ("squawk/1200", "all&filter_squawk=1200&jv2"),
        ("sqk/7700", "all&filter_squawk=7700&jv2"),
        ("mil", "all&filter_mil&jv2"),
        ("ladd", "all&filter_ladd&jv2"),
        ("pia", "all&filter_pia&jv2"),
        ("point/37.5/-122.25/25", "circle=37.5,-122.25,25&jv2"),
        (
            "lat/37.5/lon/-122.25/dist/250",
            "circle=37.5,-122.25,250&jv2",
        ),
        ("closest/37.5/-122.25/10", "closest=37.5,-122.25,10&jv2"),
    ] {
        let (status, headers, body) = get(&format!("{api}/v2/{path}")).await?;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(json::<serde_json::Value>(&body)?, readsb_v2, "{path}");
        assert_eq!(header(&headers, &CONTENT_TYPE), "application/json");
        assert_eq!(header(&headers, &CACHE_CONTROL), "public, max-age=2");
        assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
        // The refresh reads readsb beside it: the v2 query asked last is this path's.
        let queries = asked.lock().map_err(text)?.clone();
        let last = queries.iter().rev().find(|asked| asked.ends_with("&jv2"));
        assert_eq!(last.map(String::as_str), Some(query), "{path}");
    }
    let v2_asked = |asked: &Asked| -> Result<usize> {
        Ok(asked
            .lock()
            .map_err(text)?
            .iter()
            .filter(|query| query.ends_with("&jv2"))
            .count())
    };
    let before = v2_asked(&asked)?;
    for path in [
        "hex/a1b2c",
        "hex/a1b2c3;all",
        "callsign/UAL%20123",
        "squawk/7800",
        "point/91/0/10",
        "point/37.5/-122.25/251",
        "closest/37.5/-200/10",
        "lat/37.5/lon/-122.25/dist/-1",
    ] {
        let (status, headers, _) = get(&format!("{api}/v2/{path}")).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    }
    assert_eq!(v2_asked(&asked)?, before);
    Ok(())
}

/// Routes: none without `--routes`, saying why; with it, tar1090's routeset and the one-callsign
/// route answered from the directory's standing data, a preflight allowing the post, and a post
/// never cached.
#[tokio::test(flavor = "multi_thread")]
async fn routes_are_answered_from_standing_data_as_tar1090_asks() -> Result {
    let (readsb_url, _) = start_readsb().await?;
    let api = start_api(settings("http://127.0.0.1:9", readsb_url.clone())).await?;
    let (status, _, body) =
        post(&format!("{api}/api/0/routeset"), fixtures::ROUTESET_REQUEST).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        String::from_utf8_lossy(&body).contains("--routes"),
        "{body:?}"
    );

    let dir = std::env::temp_dir().join(format!(
        "tally-api-routes-{}-{}",
        std::process::id(),
        wall_ms()
    ));
    for (path, rows) in [
        (
            "routes/schema-01/B/BAW-all.csv",
            "\u{feff}Callsign,Code,Number,AirlineCode,AirportCodes\nBAW1,BAW,1,BAW,EGLL-KJFK\n",
        ),
        (
            "airports/schema-01/E/EG.csv",
            "Code,Name,ICAO,IATA,Location,CountryISO2,Latitude,Longitude,AltitudeFeet\n\
             EGLL,London Heathrow Airport,EGLL,LHR,London,GB,51.4706,-0.461941,83\n",
        ),
        (
            "airports/schema-01/K/KJ.csv",
            "Code,Name,ICAO,IATA,Location,CountryISO2,Latitude,Longitude,AltitudeFeet\n\
             KJFK,John F Kennedy International Airport,KJFK,JFK,New York,US,40.639801,-73.7789,13\n",
        ),
    ] {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().ok_or("no parent")?).map_err(text)?;
        std::fs::write(file, rows).map_err(text)?;
    }
    let mut routed = settings("http://127.0.0.1:9", readsb_url);
    routed.routes = Some(dir.clone());
    let api = start_api(routed).await?;
    let url = format!("{api}/api/0/routeset");
    let (status, headers, body) = tokio::time::timeout(WAIT, async {
        loop {
            match post(&url, fixtures::ROUTESET_REQUEST).await {
                Ok((StatusCode::SERVICE_UNAVAILABLE, ..)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                answered => return answered,
            }
        }
    })
    .await
    .map_err(|_| "the routes were never read".to_owned())??;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        json::<serde_json::Value>(&body)?,
        serde_json::from_str::<serde_json::Value>(fixtures::ROUTESET).map_err(text)?
    );
    assert_eq!(header(&headers, &CACHE_CONTROL), "no-store");
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);

    let (status, headers, _) = preflight_for(&url, "POST", "content-type").await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_METHODS), "GET, POST");
    assert!(header(&headers, &ACCESS_CONTROL_ALLOW_HEADERS).contains("content-type"));

    for refused in ["{\"planes\":[]}", "not json", "{}"] {
        assert_eq!(
            post(&url, refused).await?.0,
            StatusCode::BAD_REQUEST,
            "{refused}"
        );
    }
    let many = format!(
        "{{\"planes\":[{}]}}",
        vec![r#"{"callsign":"BAW1","lat":51.6,"lng":-1.0}"#; 101].join(",")
    );
    assert_eq!(post(&url, &many).await?.0, StatusCode::BAD_REQUEST);
    // A callsign longer than eight characters, and a body past 16 KiB, are refused unread.
    let long = r#"{"planes":[{"callsign":"ABCDEFGHI","lat":51.6,"lng":-1.0}]}"#;
    assert_eq!(post(&url, long).await?.0, StatusCode::BAD_REQUEST);
    let huge = format!(
        "{{\"planes\":[{{\"callsign\":\"BAW1\",\"lat\":51.6,\"lng\":-1.0,\"pad\":\"{}\"}}]}}",
        "x".repeat(16 * 1024)
    );
    assert_eq!(post(&url, &huge).await?.0, StatusCode::PAYLOAD_TOO_LARGE);

    // One callsign, over Sydney: the route is London to New York, so not where it would be.
    let (status, headers, body) = get(&format!("{api}/api/0/route/BAW1/-33.9/151.2")).await?;
    assert_eq!(status, StatusCode::OK);
    let route: tally_api_types::Route = json(&body)?;
    assert_eq!(
        (route.airport_codes_iata.as_str(), route.plausible),
        ("LHR-JFK", Some(false))
    );
    assert_eq!(header(&headers, &CACHE_CONTROL), "public, max-age=15");
    let (status, _, _) = get(&format!("{api}/api/0/route/BAW1/north/151.2")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = get(&format!("{api}/api/0/route/ABCDEFGHI/-33.9/151.2")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    std::fs::remove_dir_all(&dir).map_err(text)
}

/// An open stream: its body, read a block (an event or a comment) at a time.
struct Events {
    body: hyper::body::Incoming,
    buffer: String,
}

impl Events {
    /// The next block, without the blank line that ends it.
    async fn block(&mut self) -> Result<String> {
        loop {
            if let Some(end) = self.buffer.find("\n\n") {
                let block = self.buffer[..end].to_owned();
                self.buffer.drain(..end + 2);
                return Ok(block);
            }
            let frame = tokio::time::timeout(WAIT, self.body.frame())
                .await
                .map_err(|_| "the stream sent nothing".to_owned())?
                .ok_or("the stream ended")?
                .map_err(text)?;
            if let Ok(data) = frame.into_data() {
                self.buffer.push_str(&String::from_utf8_lossy(&data));
            }
        }
    }

    /// The next `aircraft` event, past any comment.
    async fn update(&mut self) -> Result<AircraftUpdate> {
        loop {
            let block = self.block().await?;
            if block.starts_with(':') {
                continue;
            }
            let data = block
                .strip_prefix("event: aircraft\ndata: ")
                .ok_or_else(|| format!("not an aircraft event: {block:?}"))?;
            return serde_json::from_str(data).map_err(|error| format!("{error}: {data}"));
        }
    }
}

/// Opens a stream from the public site's origin: its status and headers once they come, and its
/// body to read.
async fn stream(url: &str) -> Result<(StatusCode, HeaderMap, Events)> {
    let request = Request::get(url)
        .header(ORIGIN, SITE)
        .body(Empty::<Bytes>::new())
        .map_err(text)?;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let response = tokio::time::timeout(WAIT, client.request(request))
        .await
        .map_err(|_| format!("{url}: no answer"))?
        .map_err(text)?;
    let (parts, body) = response.into_parts();
    Ok((
        parts.status,
        parts.headers,
        Events {
            body,
            buffer: String::new(),
        },
    ))
}

/// THE STREAM (RFC-0184): every aircraft in the viewport first, then only what changed and what
/// left, a comment while nothing changes (a message that moved no position is no change), and at
/// most four streams open from one address.
#[tokio::test(flavor = "multi_thread")]
async fn a_stream_pushes_every_aircraft_then_what_changed_and_holds_an_address_to_four() -> Result {
    let (readsb_url, asked, answer) = start_readsb_answering().await?;
    let mut settings = settings("http://127.0.0.1:9", readsb_url);
    settings.stream_heartbeat = Duration::from_millis(300);
    let api = start_api(settings).await?;
    let url = format!("{api}/v1/aircraft/stream?west=-123&south=37&east=-121&north=38");

    // Refused as `/v1/aircraft` refuses, and never cached.
    for (query, refused) in [
        (
            "west=-130&south=0&east=-60&north=10",
            StatusCode::BAD_REQUEST,
        ),
        (
            "west=-123&south=37&east=-121&north=38&feed=precise",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let (status, headers, _) = get(&format!("{api}/v1/aircraft/stream?{query}")).await?;
        assert_eq!(status, refused, "{query}");
        assert_eq!(header(&headers, &CACHE_CONTROL), "no-store");
        assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    }

    let (status, headers, mut events) = stream(&url).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, &CONTENT_TYPE), "text/event-stream");
    assert_eq!(header(&headers, &CACHE_CONTROL), "no-store");
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    let first = events.update().await?;
    assert_eq!(
        (first.full, first.feed, first.now_ms, first.gone.len()),
        (true, Feed::Live, 1_791_220_000_250, 0)
    );
    assert_eq!(first.aircraft, expected());
    assert!(first.sent_at_ms > 0);
    // One read of every aircraft readsb positions, not a box per stream.
    let queries = asked.lock().map_err(text)?.clone();
    assert!(queries.contains(&"all_with_pos".to_owned()), "{queries:?}");
    assert!(
        !queries.iter().any(|query| query.starts_with("box=")),
        "{queries:?}"
    );

    // Nothing changes: a comment keeps the stream open.
    assert!(events.block().await?.starts_with(':'));

    // a1b2c3 moves and abcdef goes silent: only those.
    *answer.lock().map_err(text)? = READSB_LATER;
    let update = events.update().await?;
    let moved = Aircraft {
        lat: 37.51,
        last_heard_at_ms: 1_791_220_001_150,
        position_at_ms: 1_791_220_001_050,
        ..expected()[0].clone()
    };
    assert_eq!(
        (update.full, update.now_ms, update.aircraft, update.gone),
        (
            false,
            1_791_220_001_250,
            vec![moved],
            vec!["abcdef".to_owned()]
        )
    );

    // A velocity message alone: heard later, the position where it was, nothing to send.
    *answer.lock().map_err(text)? = READSB_HEARD;
    for _ in 0..3 {
        let block = events.block().await?;
        assert!(block.starts_with(':'), "{block:?}");
    }

    // Three more from the same address are open; a fifth is refused, and not cached.
    let mut open = Vec::new();
    for _ in 0..3 {
        let (status, _, events) = stream(&url).await?;
        assert_eq!(status, StatusCode::OK);
        open.push(events);
    }
    let (status, headers, _) = get(&url).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header(&headers, &CACHE_CONTROL), "no-store");
    assert_eq!(header(&headers, &ACCESS_CONTROL_ALLOW_ORIGIN), SITE);
    assert!(!header(&headers, &RETRY_AFTER).is_empty());

    // One closed gives its place back, once the API notices (its next write fails).
    drop(events);
    tokio::time::timeout(WAIT, async {
        loop {
            if let Ok((StatusCode::OK, _, events)) = stream(&url).await {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "a closed stream never gave its place back".to_owned())?;
    drop(open);
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "a test's stand-in feeder signs by its own host clock"
)]
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// How long before now the scenario starts: its window bins are past by the time the relays'
/// clock, walking it from its start (`stepping`), reaches the wall clock (a 30 s scenario, a window
/// after it and its settling).
const SCENARIO_AGO_MS: u64 = 150_000;

/// A scenario that began `SCENARIO_AGO_MS` ago, so every window bin of it is past by the time the
/// relays' clock reaches the wall clock.
fn minutes_ago(scenario: Scenario) -> Scenario {
    let start_ms = wall_ms() - SCENARIO_AGO_MS;
    Scenario {
        midnight_unix_ms: start_ms - start_ms % 86_400_000,
        start_tod_s: (start_ms % 86_400_000) as f64 / 1000.0,
        ..scenario
    }
}

/// A relay's hosted MLAT (`tally_relay::mlat_host`, RFC-0174 §2.1: the relay and its MLAT are
/// one program) pinned to the simulator's areas. Its relay's clock walks the scenario a step at a
/// time (`tally_relay::mlat_host::stepping`), each step once the engine has been offered every
/// batch fed by then and has stepped to it and published: raw is late by its stamp, never by when
/// a step ran (RFC-0181), so no step solves whatever raw a slow machine had delivered by then.
struct Held {
    host: HostedMlat,
    areas: tally_wire::Regions,
}

impl Hosting for Held {
    fn host(&self) -> &HostedMlat {
        &self.host
    }
}

impl MlatHost for Held {
    fn set_areas(&self, _: tally_wire::Regions, descriptions: Vec<SiteRecord>) {
        self.host.set_areas(self.areas.clone(), descriptions);
    }

    fn offer_description(&self, info: &SiteRecord, stamp_ms: u64) {
        self.host.offer_description(info, stamp_ms);
    }

    fn offer_batch(&self, batch: &std::sync::Arc<tally_wire::Decoded>, now_ms: u64) {
        self.host.offer_batch(batch, now_ms);
    }

    fn sealed_bins(&self) -> Option<tally_mlat_solver::held::SealedBins> {
        self.host.sealed_bins()
    }

    fn take_published(&self, watermark: tally_relay::products::Watermark) -> Vec<Record> {
        self.host.take_published(watermark)
    }

    fn cores(&self) -> u16 {
        self.host.cores()
    }

    fn report(&self) -> MlatReport {
        self.host.report()
    }

    fn take_own_models(&self) -> Vec<tally_relay::mlat_host::OwnModel> {
        self.host.take_own_models()
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

/// A relay hosting MLAT for the simulator's areas, on `clock`: its address as a client names it,
/// its hub and its hosted MLAT.
#[allow(
    clippy::disallowed_methods,
    reason = "the hosted MLAT's signer, on a clock that always judges"
)]
async fn mlat_relay(clock: &Arc<stepping::Clock>) -> Result<(RelayAddress, Arc<Hub>, Arc<Held>)> {
    let identity = Identity::generate().map_err(text)?;
    let key = identity.public();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    // Every feeder here comes from loopback: more than one host's share of connections.
    let hub = Arc::new(
        Hub::clocked(8, clock.clock(), tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
            .max_connections_per_address(64)
            // Its raw planned, as `tally-relay` plans a relay hosting MLAT.
            .memory(tally_relay::hub::DEFAULT_MEMORY, true),
    );
    let areas = tally_wire::Regions::new(areas()?);
    let host = HostedMlat::new(
        tally_wire::Signer::new(twin(&identity)?, std::sync::Arc::new(|| true)),
        1,
        tally_mlat::engine::Settings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, SETTLE_MS>(),
            threads: 4,
            capacity: tally_mlat::engine::Capacity::default(),
        },
        // Its clock walks no faster than it keeps up (`stepping`): it is never overloaded.
        WindowClock::KEEPING_UP,
    )?;
    host.set_areas(areas.clone(), Vec::new());
    let held = Arc::new(Held { host, areas });
    hub.host_mlat(Arc::clone(&held) as Arc<dyn MlatHost>)?;
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
        held,
    ))
}

/// Waits until `hub` has `links` more links in its fan-out than `before`: from then on everything
/// published reaches them. An event, not a sleep: a slow machine only waits longer.
async fn listening(hub: &Hub, before: usize, links: usize) -> Result {
    tokio::time::timeout(WAIT, async {
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

/// The simulated receivers `receivers`, publishing to `relay` as feeders: each its description at
/// once, then each batch once `clock` reaches its wall clock. The wall clocks of the batches fed.
async fn feed_simulation(
    simulation: &Simulation,
    relay: &RelayAddress,
    receivers: std::ops::Range<usize>,
    clock: &Arc<stepping::Clock>,
) -> Result<Vec<u64>> {
    let feeds = simulation.feeds().map_err(text)?;
    let mut walls = Vec::new();
    for feed in &feeds[receivers] {
        let stream = TcpStream::connect(&relay.address).await.map_err(text)?;
        let mut session = noise::connect(stream, &feed.identity, &relay.key, Role::Feeder)
            .await
            .map_err(text)?;
        let description = Record::ReceiverInfo(feed.info.clone());
        let site = Record::ReceiverSite(feed.site.clone());
        let mut batches = Vec::new();
        for batch in &feed.batches {
            let wall = batch.content().map_err(text)?.wall_ms;
            walls.push(wall);
            batches.push((wall, Record::Batch(batch.clone())));
        }
        let clock = Arc::clone(clock);
        tokio::spawn(async move {
            if session.writer.send(&[description, site]).await.is_err() {
                return;
            }
            for (wall, record) in batches {
                clock.reached(wall).await;
                if session.writer.send(&[record]).await.is_err() {
                    return;
                }
            }
            std::future::pending::<()>().await;
            drop(session);
        });
    }
    Ok(walls)
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
    // Both relays' clock, walking the scenario from the step its first batch is in.
    let first = simulation
        .receptions
        .iter()
        .map(|reception| reception.wall_ms)
        .min()
        .ok_or("a scenario heard nothing")?;
    let clock = stepping::Clock::at(
        first / tally_relay::mlat_host::STEP_MS * tally_relay::mlat_host::STEP_MS,
    );
    let ((west, west_hub, west_mlat), (east, east_hub, east_mlat)) =
        (mlat_relay(&clock).await?, mlat_relay(&clock).await?);
    let before = (west_hub.listening(), east_hub.listening());
    let (readsb_url, _) = start_readsb().await?;
    let (_, _, stats_url) = start_relay(&stepping::Clock::wall()).await?;
    let mut settings = settings(stats_url, readsb_url);
    settings.mlat.relays = vec![west.clone(), east.clone()];
    // The scenario ran minutes ago.
    settings.mlat.max_age = Duration::from_secs(3 * 86_400);
    let api = start_api(settings).await?;
    // A client of its own on both relays: every record the API could have read.
    let (inbound, mut records) = tokio::sync::mpsc::channel(65_536);
    for relay in [&west, &east] {
        tokio::spawn(tally_merge::link::subscribe(
            relay.clone(),
            tally_wire::NoiseKey::of(Identity::generate().map_err(text)?),
            tally_merge::link::streams(),
            inbound.clone(),
        ));
    }
    // The API's link and the client's are in each relay's fan-out before any receiver
    // publishes, so nothing published is missed.
    listening(&west_hub, before.0, 2).await?;
    listening(&east_hub, before.1, 2).await?;
    let west_walls = feed_simulation(&simulation, &west, 0..7, &clock).await?;
    let east_walls = feed_simulation(&simulation, &east, 3..10, &clock).await?;
    let stepper = stepping::step(
        Arc::clone(&clock),
        vec![
            (west_mlat as Arc<dyn Hosting>, west_walls),
            (east_mlat as Arc<dyn Hosting>, east_walls),
        ],
        WAIT,
    );

    let mut merge = Merge::new(tally_merge::Settings::default());
    // One reading for every record: this merge never waits out a provisional's deadline.
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's merge, read at one scripted instant"
    )]
    let at = tally_wire::clocks::recorded::mono(0);
    let last: Arc<Mutex<String>> = Arc::default();
    let url = format!("{api}/v1/aircraft?west=0&south=49&east=10&north=55");
    // The scenario at the wall clock's pace at most, and a hang guard beyond: the clock walks no
    // faster than the relays keep up, so a loaded machine takes longer, and only a clock that
    // stands still (the stepper's `WAIT`) or an API that never serves is a failure.
    let outcome = tokio::time::timeout(Duration::from_secs(180) + WAIT, async {
        loop {
            while let Ok(record) = records.try_recv() {
                merge.ingest(&record, at).map_err(text)?;
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
    .await;
    // The clock's own error first, when it stood still: the deadline only follows from it.
    if outcome.is_err() && stepper.is_finished() {
        stepper.await.map_err(text)??;
    } else {
        stepper.abort();
    }
    let outcome = outcome.map_err(|_| {
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

/// `content` signed by `identity` as a feeder of this build signs it (RFC-0171 §3.6): anchored by
/// the relay its session is to as that relay's clock read its signed time, here the simulation's
/// anchoring relay (`tally_mlat_solver::sim::anchoring_relay`), which every relay these tests
/// start accepts.
fn anchored_batch(
    identity: &Identity,
    content: &BatchContent,
) -> std::result::Result<Batch, tally_wire::WireError> {
    anchored_batch_with(identity, content, tally_wire::Codec::Plain)
}

/// As `anchored_batch`, its receptions written by `codec`.
fn anchored_batch_with(
    identity: &Identity,
    content: &BatchContent,
    codec: tally_wire::Codec,
) -> std::result::Result<Batch, tally_wire::WireError> {
    let anchor =
        tally_wire::Anchor::sign(&tally_mlat_solver::sim::anchoring_relay(), content.wall_ms);
    Batch::sign_anchored(identity, content, codec, &[anchor])
}
