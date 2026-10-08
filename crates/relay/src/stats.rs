//! The relay's station reports over HTTP (`--stats-listen`): read-only JSON, unauthenticated, for
//! a process on the same host such as `tally-api`. Bind it to loopback.
//!
//! - `GET /stations`: every station held (`StationsReport`).
//! - `GET /stations/{key}`: one (`StationReport`), the key as base64url without padding; 400 when
//!   it is not a key, 404 when the relay holds nothing for it.
//! - `GET /egress`: the upload cap and what it carries (`egress::EgressReport`): the cap and the
//!   most it lets out in a month, billed and loopback bytes sent, the headroom left, each priority
//!   class's rate, demand, waiting sends and queued bytes and peers shed, and feeders turned away.
//! - `GET /mlat`: what the hosted MLAT has done and let go (`mlat_host::MlatReport`): batches
//!   taken, offers refused for a full queue, signed records overflowed, every other drop by why,
//!   and its step reports; 404 when the relay hosts no MLAT.
//! - `GET /products`: what the regional and world products have done and let go
//!   (`products::ProductsReport`), every drop by why.
//!
//! What it writes is counted like every other socket's (`egress::Listener`).

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tally_wire::PublicKey;
use tokio::net::TcpListener;

use crate::hub::Hub;

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/stations", get(stations))
        .route("/stations/{key}", get(station))
        .route("/egress", get(egress))
        .route("/mlat", get(mlat))
        .route("/products", get(products))
        .route("/memory", get(memory))
        .with_state(hub)
}

/// Serves `router` on `listener` for as long as the relay runs.
pub async fn serve(listener: TcpListener, hub: Arc<Hub>) -> std::io::Result<()> {
    let listener = crate::egress::Listener::new(listener, Arc::clone(hub.egress()));
    axum::serve(listener, router(hub)).await
}

async fn egress(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(hub.egress().report()).into_response()
}

async fn mlat(State(hub): State<Arc<Hub>>) -> Response {
    match hub.network().mlat() {
        Some(mlat) => axum::Json(mlat.report()).into_response(),
        None => (StatusCode::NOT_FOUND, "this relay hosts no MLAT").into_response(),
    }
}

async fn products(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(hub.network().products.report()).into_response()
}

/// The budget and every store's gauge, with what the stores that count their own bytes hold
/// (the batch byte store, the delivery tags) and the decoded batches alive in all.
async fn memory(State(hub): State<Arc<Hub>>) -> Response {
    axum::Json(hub.memory_report()).into_response()
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
        Batch::sign(
            receiver,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms: 0,
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
        let hub = Arc::new(Hub::new(8));
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
        for sequence in [0, 1, 3] {
            hub.publish_batch(9, batch(&receiver, sequence)?, key);
        }
        hub.fed_by(&key, 9);

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
        assert_eq!(one.location, Some(location.into()));
        assert_eq!(one.software.as_deref(), Some("tally-feed 0.1.0"));

        // The feeder leaves: still known, no longer connected.
        hub.left(&key, 9);
        let (_, body) = get(address, &format!("/stations/{}", key.to_base64url())).await?;
        let one: StationReport = serde_json::from_str(&body).map_err(text)?;
        assert!(!one.connected);

        let stranger = Identity::generate().map_err(text)?.public();
        let (status, _) = get(address, &format!("/stations/{}", stranger.to_base64url())).await?;
        assert_eq!(status, 404);
        let (status, _) = get(address, "/stations/not-a-key").await?;
        assert_eq!(status, 400);
        Ok(())
    }

    /// The products' and the hosted MLAT's counters are served, every drop by why; a relay that
    /// hosts no MLAT says so.
    #[tokio::test]
    async fn the_products_and_mlat_counters_are_served() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8));
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
            Identity::from_seed([3; 32]),
            1,
            tally_mlat::engine::Settings {
                regions: Vec::new(),
                settle_ms: crate::mlat_host::SETTLE_MS,
                threads: 1,
                capacity: tally_mlat::engine::Capacity::default(),
            },
        )?);
        let hub = Arc::new(Hub::new(8));
        hub.network().host_mlat(hosted);
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        tokio::spawn(serve(listener, Arc::clone(&hub)));
        let (status, body) = get(address, "/mlat").await?;
        assert_eq!(status, 200, "{body}");
        let report: crate::mlat_host::MlatReport = serde_json::from_str(&body).map_err(text)?;
        assert_eq!(report, crate::mlat_host::MlatReport::default());
        for counter in [
            "refused",
            "overflowed",
            "replayed",
            "orphans_dropped",
            "steps_discarded",
        ] {
            assert!(body.contains(counter), "{counter} not served: {body}");
        }
        Ok(())
    }
}
