//! `tally-relay`: the relay's command line (RFC-0166 §3.6).

use std::sync::Arc;

use tally_relay::config::Config;
use tally_relay::hub::Hub;
use tally_relay::link;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("tally-relay: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let Some(config) = Config::from_args(std::env::args().skip(1))? else {
        return Ok(());
    };
    let identities = config.identities()?;
    let hub = Arc::new(
        Hub::new(config.max_subscribers)
            .advertising(config.hints())
            .accepting_relays(config.accept_relays.iter().copied())
            .max_connections(config.max_connections)
            .max_connections_per_address(config.max_connections_per_address)
            .max_dedup_bytes(config.max_dedup_bytes)
            .max_feeder_bytes_per_sec(config.max_feeder_bytes_per_sec),
    );
    eprintln!(
        "tally-relay: key {} listening on {}",
        identities[0].public(),
        config.listen
    );
    if let Some(address) = &config.beast_out {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("beast-out {address}: {error}"))?;
        tokio::spawn(link::serve_beast(listener, Arc::clone(&hub)));
    }
    for upstream in &config.upstreams {
        tokio::spawn(link::upstream(
            upstream.clone(),
            identities[0].clone(),
            Arc::clone(&hub),
        ));
    }
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|error| format!("listen {}: {error}", config.listen))?;
    tally_relay::serve(listener, identities, hub).await
}
