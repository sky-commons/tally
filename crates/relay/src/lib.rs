//! A Tally relay (RFC-0171 §3.6): accepts feeders, subscribers, MLAT engines and other relays on
//! one port, checks every signature, forwards each batch and each engine's positions once, signs
//! its own deduplicated stream, and serves plain BEAST on loopback for a local decoder. It decides
//! nothing about aircraft: it reads frames only to compare their bytes.

pub mod bounded;
pub mod ceiling;
pub mod config;
pub mod deduplicated;
pub mod hub;
pub mod link;
pub mod subscription;

use std::sync::Arc;
use std::time::Duration;

use tally_wire::Identity;
use tokio::net::TcpListener;

use crate::hub::Hub;

/// Accepts connections on `listener` up to the hub's connection caps, the relay's and each source
/// address's (beyond either, a connection is closed before its handshake), and signs the deduplicated stream with the newest key
/// (`identities[0]`), for as long as the relay runs.
pub async fn serve(listener: TcpListener, identities: Vec<Identity>, hub: Arc<Hub>) -> ! {
    if let Some(newest) = identities.first() {
        tokio::spawn(deduplicated::run(Arc::clone(&hub), newest.clone()));
    }
    let identities = Arc::new(identities);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(slot) = hub.connection(peer.ip()) else {
                    drop(stream);
                    continue;
                };
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
