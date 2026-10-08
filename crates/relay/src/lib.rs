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

/// Accepts connections on `listener` up to the hub's connection caps, the relay's and each source
/// address's (beyond either, a connection is closed before its handshake), each counted and capped
/// from its first byte (`egress::Socket`); and signs the deduplicated stream with the newest key
/// (`identities[0]`), for as long as the relay runs.
pub async fn serve(listener: TcpListener, identities: Vec<Identity>, hub: Arc<Hub>) -> ! {
    if let Some(newest) = identities.first() {
        tokio::spawn(deduplicated::run(Arc::clone(&hub), newest.clone()));
        hub.network().adopt_identity(newest.clone());
    }
    tokio::spawn(network::run(Arc::clone(&hub)));
    let identities = Arc::new(identities);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(slot) = hub.connection(peer.ip()) else {
                    drop(stream);
                    continue;
                };
                let stream = hub.egress().socket(stream, Some(peer.ip()));
                let identities = Arc::clone(&identities);
                let hub = Arc::clone(&hub);
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(error) = link::inbound(stream, &identities, hub).await {
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
