//! A Tally relay (RFC-0171 §3.6, RFC-0174): accepts feeders, clients and other relays on one
//! port, checks every signature, forwards each batch and each relay's positions once, signs its
//! own deduplicated stream, and serves plain BEAST on loopback for a local decoder. There is no
//! separate MLAT engine: the relay runs MLAT itself (`mlat_host`, one program, RFC-0174 §2.1).
//! Its RFC-0174 duties (`network`) take areas and share them in striped groups, answer probes and
//! delivery checks, hold the provider directory, run MLAT for the areas it is chosen for, gate
//! clients by credit, and build the regional and world products: the world product decodes
//! aircraft positions from the receptions it gathers, so a relay that builds it reads aircraft as
//! well as frames.

pub mod admission;
pub mod bounded;
pub mod budget;
pub mod ceiling;
pub mod config;
pub mod credit;
pub mod deduplicated;
pub mod delivery;
pub mod directory;
pub mod egress;
pub mod exchange;
pub mod fanout;
pub mod hub;
pub mod ingest;
pub mod link;
pub mod mlat_host;
pub mod network;
pub mod parts;
pub mod peers;
pub mod products;
pub mod seal;
pub mod selection;
pub mod sharing;
pub mod standing;
pub mod stations;
pub mod stats;
pub mod subscription;

use std::sync::Arc;
use std::time::Duration;

use tally_wire::Identity;
use tokio::net::TcpListener;

use crate::hub::Hub;

/// Makes every panic, on any thread of the process (a stage's, a connection's task, the hosted
/// engine's, a pool worker's), end it once it is reported, before anything unwinds: a part that
/// stopped would hold its epochs open, its charges taken and its locks poisoned while the rest ran
/// on as if it were whole, and nothing else would say so. The process's supervisor restarts it (the
/// unit's `Restart=always`, the pod's restart policy). The relay's program sets it first thing
/// (`main`), so every build of the binary (Cargo's, Bazel's) has it and no runtime that catches a
/// task's panic (as tokio does) can keep the relay running without the part that panicked; it is
/// the one mechanism (tests/panic.rs holds it to that). The library sets no hook of its own: its
/// only other users are tests, where a panic is a test's failure to report, not a process to end.
pub fn abort_on_any_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        eprintln!(
            "tally-relay: a thread panicked; ending the relay rather than running without it"
        );
        std::process::abort();
    }));
}

/// Accepts connections on `listener` up to the hub's connection caps, the relay's and each source
/// address's (beyond either, a connection is closed before its handshake), each counted and capped
/// from its first byte (`egress::Socket`); and signs its own records (its products, the
/// deduplicated stream among them, and its network records) with the newest key (`identities[0]`),
/// for as long as the relay runs. The relay's cap counts only the connections that hold no place
/// of their role's own (`hub::Connection::general`): a connection gives its place up once it is a
/// feeder, a subscriber or a member, each bounded by its own cap and told when that is full, so a
/// relay full of feeders still answers a member's handshake (`link::inbound`).
pub async fn serve(listener: TcpListener, identities: Vec<Identity>, hub: Arc<Hub>) -> ! {
    if let Some(newest) = identities.first() {
        hub.network().adopt_identity(newest.clone());
    }
    tokio::spawn(network::run(Arc::clone(&hub)));
    let identities = Arc::new(identities);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(connection) = hub.connection(peer.ip()) else {
                    drop(stream);
                    continue;
                };
                let stream = hub.egress().socket(stream, Some(peer.ip()));
                let identities = Arc::clone(&identities);
                let hub = Arc::clone(&hub);
                tokio::spawn(async move {
                    if let Err(error) = link::inbound(stream, &identities, hub, connection).await {
                        eprintln!("tally-relay: {peer}: {error}");
                    }
                });
            }
            Err(error) => {
                eprintln!("tally-relay: accept: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
