//! A Tally relay (RFC-0166 §3.6): accepts feeders, subscribers and other relays on one port,
//! checks every batch's signature, forwards each batch once, and serves plain BEAST on loopback
//! for a local decoder. It decodes no frame and decides nothing about aircraft.

pub mod config;
pub mod hub;
pub mod link;

use std::sync::Arc;
use std::time::Duration;

use tally_wire::Identity;
use tokio::net::TcpListener;

use crate::hub::Hub;

/// Accepts connections on `listener` for as long as the relay runs.
pub async fn serve(listener: TcpListener, identities: Vec<Identity>, hub: Arc<Hub>) -> ! {
    let identities = Arc::new(identities);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let identities = Arc::clone(&identities);
                let hub = Arc::clone(&hub);
                tokio::spawn(async move {
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
