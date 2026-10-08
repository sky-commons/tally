//! `tally-api`: the Tally API's command line (RFC-0173 §2.5).

use tally_api::config::Config;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("tally-api: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let Some(config) = Config::from_args(std::env::args().skip(1))? else {
        return Ok(());
    };
    let mut settings = config.settings;
    // Who this client is to the relays it reads, and the relay that vouches for it.
    settings.mlat.key_file = config.key_file;
    settings.mlat.linked = config.linked_relay;
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|error| format!("listen {}: {error}", config.listen))?;
    eprintln!("tally-api: listening on {}", config.listen);
    tally_api::serve(listener, settings).await
}
