//! The relay's station reports over HTTP (`--stats-listen`): read-only JSON, unauthenticated, for
//! a process on the same host such as `tally-api`. It binds loopback only: the relay refuses any
//! other address (`config::parse_loopback`), and `serve` refuses a listener bound anywhere
//! else, so no other host reads it. What it serves is a client's (RFC-0171 §3.5): a receiver's
//! public cell, never its site (`stations::StationReport::cell`).
//!
//! - `GET /stations`: every station held (`StationsReport`).
//! - `GET /stations/{key}`: one (`StationReport`), the key as base64url without padding; 400 when
//!   it is not a key, 404 when the relay holds nothing for it. Each names the address its connected
//!   session came from, which is why this listener is loopback's alone: `tally-api` answers a
//!   client only the stations of its own address (its `GET /v1/me`).
//! - `GET /egress`: the upload cap and what it carries (`egress::EgressReport`): the cap and the
//!   most it lets out in a month, billed and loopback bytes sent, the headroom left, each priority
//!   class's rate, demand, waiting sends and queued bytes and peers shed, and feeders turned away.
//! - `GET /mlat`: what the hosted MLAT has done and let go (`mlat_host::MlatReport`): batches
//!   taken, offers refused for a full queue, signed records overflowed, every other drop by why,
//!   and its step reports; 404 when the relay hosts no MLAT.
//! - `GET /memory`: the memory budget, every store's gauge and the decoded batches alive
//!   (`hub::MemoryReport`), and the feeders' batches dropped past their receiver's wanted
//!   receptions a second (`over_reception_ceiling`), and what the relay's standing holds and has
//!   taken in (`standing`, `standing::StandingReport`).
//! - `GET /products`: what the regional and world products have done and let go
//!   (`products::ProductsReport`), every drop by why.
//!
//! - `GET /listeners`: every port the relay listens on (`listeners::ListenerReport`): its
//!   connections open now, those accepted and refused, and its accepts that failed, skipped and
//!   in runs, and whether one is under way.
//!
//! What it writes is counted like every other socket's, and its connections like every other
//! listener's (`listeners::Acceptor`): at most [`MAX_CONNECTIONS`] at once, each closed once it
//! has moved nothing for [`IDLE`].

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tally_wire::PublicKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::egress::Socket;
use crate::hub::Hub;
use crate::listeners::{Acceptor, Idle, Starved};

/// The most stats connections open at once; one past it is closed as it is accepted. Its readers
/// are a process or two on the same host, each asking a request at a time.
pub const MAX_CONNECTIONS: usize = 16;

/// How long a stats connection may move nothing either way before it is closed.
pub const IDLE: Duration = Duration::from_secs(60);

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/stations", get(stations))
        .route("/stations/{key}", get(station))
        .route("/egress", get(egress))
        .route("/mlat", get(mlat))
        .route("/products", get(products))
        .route("/memory", get(memory))
        .route("/listeners", get(listeners))
        .with_state(hub)
}

/// Serves `router` on `listener` for as long as the relay runs. A listener not bound to a loopback
/// address is refused before anything is served; otherwise it returns only when its listener has
/// starved (`listeners::Starved`), which ends the relay.
pub async fn serve(listener: TcpListener, hub: Arc<Hub>) -> std::io::Result<Infallible> {
    crate::sockets::loopback_only(&listener, "--stats-listen")?;
    let acceptor = Acceptor::new(
        listener,
        hub.listeners().gauge("stats"),
        Arc::clone(hub.egress()),
        crate::sockets::Role::Feeder,
    )
    .capped(MAX_CONNECTIONS);
    let (starving, starved) = oneshot::channel();
    let listener = Http {
        acceptor,
        starving: Some(starving),
    };
    tokio::select! {
        served = axum::serve(listener, router(hub)) => Err(match served {
            Ok(()) => std::io::Error::other("stats: stopped serving"),
            Err(error) => std::io::Error::other(format!("stats: {error}")),
        }),
        Ok(starved) = starved => Err(std::io::Error::other(starved.to_string())),
    }
}

/// The stats' listener as axum takes one: each connection an [`Acceptor`]'s, held to [`IDLE`].
/// A starved listener is handed to `serve` (`starving`), which ends with it.
struct Http {
    acceptor: Acceptor<TcpListener>,
    starving: Option<oneshot::Sender<Starved>>,
}

impl axum::serve::Listener for Http {
    type Io = Idle<Socket<TcpStream>>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.acceptor.next().await {
            Ok((socket, peer)) => (Idle::new(socket, IDLE), peer),
            Err(starved) => {
                if let Some(starving) = self.starving.take() {
                    let _ = starving.send(starved);
                }
                std::future::pending().await
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.acceptor.local_addr()
    }
}

/// `GET /listeners`: every listener's connections and accepts (`listeners::Listeners`).
async fn listeners(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(hub.listeners().report()).into_response()
}

async fn egress(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(hub.egress().report()).into_response()
}

async fn mlat(State(hub): State<Arc<Hub>>) -> Response {
    match hub.network().mlat() {
        Some(mlat) => {
            let mut report = mlat.report();
            (report.cuts_sent, report.cuts_received, report.cuts_refused) = hub.network().cuts();
            axum::Json(report).into_response()
        }
        None => (StatusCode::NOT_FOUND, "this relay hosts no MLAT").into_response(),
    }
}

async fn products(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(hub.network().products.report()).into_response()
}

/// The budget and every store's gauge, with what the stores that count their own bytes hold
/// (the batch byte store, the delivery tags) and the decoded batches alive in all.
/// `GET /memory`: the memory report, and beside it the feeders' batches dropped for taking their
/// receiver past its wanted receptions a second (`Hub::over_reception_ceiling`), and what standing
/// holds and has taken in (`Standing::report`).
#[derive(serde::Serialize)]
struct Memory {
    #[serde(flatten)]
    report: crate::hub::MemoryReport,
    over_reception_ceiling: crate::hub::OverCeiling,
    standing: crate::standing::StandingReport,
}

async fn memory(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(Memory {
        report: hub.memory_report(),
        over_reception_ceiling: hub.over_reception_ceiling(),
        standing: hub.network().standing.report(),
    })
    .into_response()
}

async fn stations(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(hub.stations()).into_response()
}

async fn station(State(hub): State<Arc<Hub>>, Path(key): Path<String>) -> Response {
    let Ok(key) = PublicKey::from_base64url(&key) else {
        return (StatusCode::BAD_REQUEST, "not a key").into_response();
    };
    match hub.station(&key) {
        Some(report) => axum::Json(report).into_response(),
        None => (StatusCode::NOT_FOUND, "no such station").into_response(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use crate::stations::{StationReport, StationsReport};
    use tally_wire::batch::ReceiverInfoContent;
    use tally_wire::{Batch, BatchContent, Clock, Identity, Location, Observation, ReceiverInfo};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// `GET path` over a fresh connection: the status code and the body.
    async fn get(address: std::net::SocketAddr, path: &str) -> Result<(u16, String), String> {
        let mut stream = TcpStream::connect(address).await.map_err(text)?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: stats\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.map_err(text)?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await.map_err(text)?;
        let (head, body) = response.split_once("\r\n\r\n").ok_or("no body")?;
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or("no status")?;
        Ok((status, body.to_owned()))
    }

    fn batch(receiver: &Identity, sequence: u64) -> Result<Batch, String> {
        crate::anchors::anchored(
            receiver,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms: crate::clock::RelayClock::system().judged().ms(),
                dropped: 0,
                previous: [0; 32],
                observations: vec![Observation {
                    format: b'2',
                    timestamp: sequence,
                    signal: 1,
                    data: vec![0x5d, 1, 2, 3, 4, 5, sequence as u8],
                }],
            },
        )
        .map_err(text)
    }

    #[tokio::test]
    async fn the_stations_are_served_as_json_with_what_their_descriptions_declare()
    -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
        let receiver = Identity::generate().map_err(text)?;
        let key = receiver.public();
        let location = Location {
            lat_e7: 515_000_000,
            lon_e7: -1_000_000,
            alt_m: 30,
            precision_m: 100,
        };
        let info = ReceiverInfo::sign(
            &receiver,
            &ReceiverInfoContent {
                issued_ms: 5,
                location: Some(location),
                clock: Clock::Dump1090,
                software: "tally-feed 0.1.0".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(text)?;
        hub.publish_info(9, info, key, 5, Some(location), false);
        hub.opened(&key, 9, None);
        for sequence in [0, 1, 3] {
            hub.publish_batch(9, batch(&receiver, sequence)?, key);
        }
        hub.fed_by(
            &key,
            9,
            Some(std::net::Ipv4Addr::new(198, 51, 100, 4).into()),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        tokio::spawn(serve(listener, Arc::clone(&hub)));

        let (status, body) = get(address, "/stations").await?;
        assert_eq!(status, 200, "{body}");
        let all: StationsReport = serde_json::from_str(&body).map_err(text)?;
        assert_eq!(all.stations.len(), 1);

        let (status, body) = get(address, &format!("/stations/{}", key.to_base64url())).await?;
        assert_eq!(status, 200, "{body}");
        let one: StationReport = serde_json::from_str(&body).map_err(text)?;
        assert_eq!(one.key, all.stations[0].key);
        assert_eq!(
            (
                one.key,
                one.online,
                one.connected,
                one.sessions,
                one.batches,
                one.gaps,
                one.observations
            ),
            (key.to_base64(), true, true, 1, 3, 1, 3)
        );
        // Its public cell, and nothing of its site: no coordinate, no altitude, in any form.
        assert_eq!(
            one.cell,
            Some(crate::stations::cell_name(
                tally_wire::Region::public_cell(&location).map_err(text)?
            ))
        );
        for canary in ["51.5", "515000000", "-0.1", "-1000000"] {
            assert!(!body.contains(canary), "{canary} in {body}");
        }
        assert!(!body.contains("alt"), "{body}");
        assert_eq!(one.software.as_deref(), Some("tally-feed 0.1.0"));
        assert_eq!(one.address.as_deref(), Some("198.51.100.4"));

        // The feeder leaves: still known, no longer connected.
        hub.left(&key, 9);
        let (_, body) = get(address, &format!("/stations/{}", key.to_base64url())).await?;
        let one: StationReport = serde_json::from_str(&body).map_err(text)?;
        assert!(!one.connected);

        let stranger = Identity::generate().map_err(text)?.public();
        let (status, _) = get(address, &format!("/stations/{}", stranger.to_base64url())).await?;
        assert_eq!(status, 404);

        // A feeder connected whose decoder sends nothing: listed and served as connected with
        // nothing forwarded, and placed nowhere though its description declares a place.
        let silent = Identity::generate().map_err(text)?;
        let quiet = silent.public();
        let described = ReceiverInfo::sign(
            &silent,
            &ReceiverInfoContent {
                issued_ms: 5,
                location: Some(location),
                clock: Clock::Dump1090,
                software: "tally-feed 0.3.0".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(text)?;
        hub.publish_info(10, described, quiet, 5, Some(location), false);
        hub.opened(&quiet, 10, None);
        let (status, body) = get(address, &format!("/stations/{}", quiet.to_base64url())).await?;
        assert_eq!(status, 200, "{body}");
        let one: StationReport = serde_json::from_str(&body).map_err(text)?;
        assert_eq!(
            (one.online, one.connected, one.batches, one.cell),
            (false, true, 0, None)
        );
        assert!(one.connected_since_ms.is_some());
        let (_, body) = get(address, "/stations").await?;
        let all: StationsReport = serde_json::from_str(&body).map_err(text)?;
        assert_eq!(all.stations.len(), 2);
        assert!(
            all.stations
                .iter()
                .all(|station| station.key != quiet.to_base64() || station.cell.is_none())
        );
        hub.left(&quiet, 10);
        let (status, _) = get(address, &format!("/stations/{}", quiet.to_base64url())).await?;
        assert_eq!(status, 404);
        let (status, _) = get(address, "/stations/not-a-key").await?;
        assert_eq!(status, 400);
        Ok(())
    }

    /// The stats endpoint refuses a listener bound anywhere but loopback: its reports are served to
    /// no other host.
    #[tokio::test]
    async fn a_listener_off_loopback_is_refused() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
        let listener = TcpListener::bind("0.0.0.0:0").await.map_err(text)?;
        let refused = serve(listener, hub).await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::InvalidInput),
            "{refused:?}"
        );
        Ok(())
    }

    /// The products' and the hosted MLAT's counters are served, every drop by why; a relay that
    /// hosts no MLAT says so.
    #[tokio::test]
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's signer, on a clock that always judges"
    )]
    async fn the_products_and_mlat_counters_are_served() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        tokio::spawn(serve(listener, Arc::clone(&hub)));
        let (status, body) = get(address, "/products").await?;
        assert_eq!(status, 200, "{body}");
        let products: crate::products::ProductsReport =
            serde_json::from_str(&body).map_err(text)?;
        assert_eq!(products, crate::products::ProductsReport::default());
        let (status, _) = get(address, "/mlat").await?;
        assert_eq!(status, 404);

        let hosted = Arc::new(crate::mlat_host::HostedMlat::new(
            tally_wire::Signer::new(Identity::from_seed([3; 32]), std::sync::Arc::new(|| true)),
            1,
            tally_mlat::engine::Settings {
                regions: tally_wire::Regions::default(),
                settle: crate::mlat_host::SETTLE,
                threads: 1,
                capacity: tally_mlat::engine::Capacity::default(),
            },
            crate::mlat_host::WindowClock::KEEPING_UP,
        )?);
        let hub = Arc::new(
            Hub::new(8, crate::sharing::Deadlines::RELAY).memory(crate::hub::DEFAULT_MEMORY, true),
        );
        hub.host_mlat(hosted)?;
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        tokio::spawn(serve(listener, Arc::clone(&hub)));
        let (status, body) = get(address, "/mlat").await?;
        assert_eq!(status, 200, "{body}");
        let report: crate::mlat_host::MlatReport = serde_json::from_str(&body).map_err(text)?;
        // Nothing has happened, but the seats the host was planned (its capacity's receivers, here
        // the default) are served: no cut is in force, so the cap is the limit.
        assert_eq!(report.seat_cap, report.seat_limit, "{body}");
        assert_eq!(
            report,
            crate::mlat_host::MlatReport {
                seat_cap: report.seat_limit,
                seat_limit: report.seat_limit,
                // How many MLAT runners met the lowest priority follows the nice the test runs
                // at (`mlat_host`'s own tests hold it), not the report's serving.
                priority_unset: report.priority_unset,
                ..crate::mlat_host::MlatReport::default()
            }
        );
        for counter in [
            "refused",
            "overflowed",
            "replayed",
            "orphans_dropped",
            "steps_discarded",
        ] {
            assert!(body.contains(counter), "{counter} not served: {body}");
        }
        // `/memory` serves standing beside what it served before (an addition: no field renamed).
        let (status, body) = get(address, "/memory").await?;
        assert_eq!(status, 200, "{body}");
        let memory: serde_json::Value = serde_json::from_str(&body).map_err(text)?;
        assert!(memory.get("over_reception_ceiling").is_some(), "{body}");
        assert!(memory.get("budget").is_some(), "{body}");
        assert_eq!(
            memory.get("standing"),
            Some(&serde_json::to_value(hub.network().standing.report()).map_err(text)?),
            "{body}"
        );
        Ok(())
    }
}
