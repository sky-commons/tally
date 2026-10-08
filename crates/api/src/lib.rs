//! The Tally API (RFC-0173 §2.5): public, read-only JSON beside a relay. Aircraft come from a
//! readsb the operator runs on the relay's BEAST output (readsb is the decoder, RFC-0119 §3.3);
//! station and network figures come from the relay's own station reports (`--stats-listen`).
//! Nothing here decodes a frame or decides anything about an aircraft. The JSON it serves is
//! `tally_api_types`, the one declaration every client reads too.
//!
//! - `GET /v1/aircraft?west=&south=&east=&north=`: aircraft in a viewport of at most 60 degrees
//!   each way (`area`), from readsb's `?box=` query, per request, and the merged MLAT position of
//!   every aircraft in it readsb holds no position for (`mlat`), each saying which it is.
//! - `GET /v1/network`: receivers online and known, their messages a second, and aircraft held.
//! - `GET /v1/stations/{key}`: one receiver, the key as base64url without padding.
//! - `GET /v1/stations/{key}/stats`: what one feeder gave the network over the last day (`feeders`),
//!   computed by this API as a client from public signed records, never by a relay.
//! - `GET /v1/leaderboards` and `GET /v1/leaderboards/{area}`: the areas whose feeders are ranked,
//!   and one area's two leaderboards (by unique coverage and by MLAT help; only feeders with
//!   standing).
//!
//! Every response carries CORS for the configured origins and a `Cache-Control` for the edge.
//! Each client is held to a token bucket (`limit`), requests in flight and connections are
//! capped, and every request, header read and upstream read has a deadline.

pub mod area;
pub mod config;
pub mod feeders;
pub mod limit;
pub mod mlat;
pub mod readsb;
pub mod routes;
pub mod snapshot;
pub mod upstream;

#[cfg(test)]
mod fixtures_test;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::http::HeaderName;
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use tally_relay::stations::StationsReport;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt;

use crate::limit::Limiter;
use crate::snapshot::{Snapshot, Stations};
use crate::upstream::Upstream;

/// Requests handled at once, by default; beyond it a request is answered 503 at once.
pub const DEFAULT_MAX_REQUESTS: usize = 256;
/// Connections held at once, by default; beyond it a new one is closed unanswered.
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;
/// The longest a client may take to send a request's headers.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest a connection is kept, however busy: then it is closed between requests, so no
/// client holds a place forever.
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(120);
/// How long a connection being closed is given to finish the request it is on.
const CLOSING_GRACE: Duration = Duration::from_secs(10);

/// Everything an operator tells the API (`config`).
#[derive(Clone, Debug)]
pub struct Settings {
    /// The relay's stats listener, such as `http://127.0.0.1:10901`.
    pub relay_stats: String,
    /// readsb's API port, such as `http://127.0.0.1:30152`.
    pub readsb: String,
    /// The origins CORS allows, the first answered when a request names none of them. None by
    /// default: a page on another site may read the API only where its operator allows that site.
    pub allow_origins: Vec<String>,
    /// A header a fronting proxy sets to the client's address (such as `CF-Connecting-IP`), read
    /// instead of the connection's peer. Only set it when every request comes through that proxy.
    pub client_ip_header: Option<HeaderName>,
    pub rate: f64,
    pub burst: f64,
    pub max_requests: usize,
    pub max_connections: usize,
    /// How often the relay's stations and readsb's count are read.
    pub refresh: Duration,
    /// Where MLAT positions come from.
    pub mlat: mlat::Settings,
}

impl Settings {
    pub fn new(relay_stats: impl Into<String>, readsb: impl Into<String>) -> Self {
        Self {
            relay_stats: relay_stats.into(),
            readsb: readsb.into(),
            allow_origins: Vec::new(),
            client_ip_header: None,
            rate: limit::DEFAULT_RATE,
            burst: limit::DEFAULT_BURST,
            max_requests: DEFAULT_MAX_REQUESTS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            refresh: snapshot::DEFAULT_REFRESH,
            mlat: mlat::Settings::default(),
        }
    }
}

/// What every request shares.
pub struct App {
    pub settings: Settings,
    pub upstream: Upstream,
    pub limiter: Limiter,
    pub requests: Arc<Semaphore>,
    pub snapshot: Snapshot,
    pub mlat: Arc<mlat::Positions>,
    /// What the feeder figures are computed from, fed by the MLAT subscription's records.
    pub feeders: Arc<Mutex<feeders::Ledger>>,
    /// The receivers with standing, as the merge's ledger says (`mlat::with_standing`).
    pub standing: Arc<RwLock<Arc<BTreeSet<tally_wire::PublicKey>>>>,
}

impl App {
    pub fn new(settings: Settings) -> Self {
        Self {
            upstream: Upstream::new(),
            limiter: Limiter::new(settings.rate, settings.burst),
            requests: Arc::new(Semaphore::new(settings.max_requests)),
            snapshot: Snapshot::default(),
            mlat: Arc::default(),
            feeders: Arc::default(),
            standing: Arc::default(),
            settings,
        }
    }

    /// Reads the relay's stations and readsb's count every `refresh`, for as long as the API runs.
    pub async fn refresh(self: Arc<Self>) {
        let mut tick = tokio::time::interval(self.settings.refresh);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let stations_url = format!(
            "{}/stations",
            self.settings.relay_stats.trim_end_matches('/')
        );
        let all_url = readsb::all_query(&self.settings.readsb);
        loop {
            tick.tick().await;
            let (stations, aircraft) = tokio::join!(
                self.upstream.get(&stations_url),
                self.upstream.get(&all_url)
            );
            match stations.and_then(|body| {
                serde_json::from_slice::<StationsReport>(&body)
                    .map_err(|error| format!("{stations_url}: {error}"))
            }) {
                Ok(report) => {
                    // Rates are taken against the last report read, stale or not.
                    let previous = self.snapshot.last_stations();
                    let stations = Stations::from_report(report, previous.as_deref());
                    self.snapshot.set_stations(stations, Instant::now());
                }
                Err(error) => eprintln!("tally-api: {error}"),
            }
            if !self.settings.mlat.relays.is_empty() {
                self.compute_board();
            }
            match aircraft.and_then(|body| readsb::parse(&body)) {
                Ok(answer) => self.snapshot.set_aircraft(
                    u32::try_from(answer.count()).unwrap_or(u32::MAX),
                    Instant::now(),
                ),
                Err(error) => eprintln!("tally-api: {error}"),
            }
        }
    }
}

impl App {
    /// Computes the feeder figures and leaderboards now, over where the relay's stations say each
    /// receiver is (from its own signed description) and the merge's standing.
    pub fn compute_board(&self) {
        let locations: Vec<(tally_wire::PublicKey, feeders::LatLon)> = self
            .snapshot
            .stations(Instant::now())
            .map(|stations| {
                stations
                    .by_key
                    .iter()
                    .filter_map(|(key, report)| {
                        let at = report.location?;
                        Some((
                            *key,
                            feeders::LatLon {
                                lat: at.lat,
                                lon: at.lon,
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let standing = self
            .standing
            .read()
            .map(|held| Arc::clone(&held))
            .unwrap_or_default();
        let Ok(mut ledger) = self.feeders.lock() else {
            return;
        };
        if !locations.is_empty() {
            ledger.locate(locations);
        }
        let board = ledger.board(routes::wall_ms(), |key| standing.contains(key));
        drop(ledger);
        self.snapshot.set_board(board, Instant::now());
    }
}

/// Serves the API on `listener`, and keeps its snapshot fresh, for as long as it runs.
pub async fn serve(listener: TcpListener, settings: Settings) -> ! {
    let app = Arc::new(App::new(settings));
    tokio::spawn(Arc::clone(&app).refresh());
    if let Err(error) = mlat::start(
        &app.settings.mlat,
        Arc::clone(&app.mlat),
        Arc::clone(&app.feeders),
        Arc::clone(&app.standing),
    ) {
        eprintln!("tally-api: mlat: {error}");
    }
    let connections = Arc::new(Semaphore::new(app.settings.max_connections));
    let router = routes::router(Arc::clone(&app));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("tally-api: accept: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(place) = Arc::clone(&connections).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let router = router.clone();
        tokio::spawn(async move {
            let _place = place;
            let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
                request.extensions_mut().insert(routes::Peer(peer));
                router.clone().oneshot(request)
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service);
            tokio::pin!(connection);
            tokio::select! {
                _ = connection.as_mut() => {}
                () = tokio::time::sleep(CONNECTION_LIFETIME) => {
                    connection.as_mut().graceful_shutdown();
                    let _ = tokio::time::timeout(CLOSING_GRACE, connection).await;
                }
            }
        });
    }
}
