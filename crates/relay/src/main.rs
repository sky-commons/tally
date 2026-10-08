//! `tally-relay`: the relay's command line (RFC-0171 §3.6).

use std::sync::Arc;

use tally_relay::config::Config;
use tally_relay::egress;
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
    eprintln!(
        "tally-relay: upload capped at {}/s to billed peers, at most {} in 31 days",
        egress::decimal(config.max_upload.rate()),
        egress::decimal(config.max_upload.most_a_month())
    );
    let hosts_mlat = config.relay_duties && config.mlat_threads > 0;
    let hub = Arc::new(
        Hub::new(config.max_subscribers)
            .advertising(config.hints())
            .accepting_relays(config.accept_relays.iter().copied())
            .vouching_for(config.clients.iter().copied())
            .max_connections(config.max_connections)
            .max_connections_per_address(config.max_connections_per_address)
            .max_feeder_bytes_per_sec(config.max_feeder_bytes_per_sec)
            .max_member_bytes_per_sec(config.max_member_bytes_per_sec)
            .max_upload(config.max_upload)
            .memory(config.memory, hosts_mlat)
            // A stage short of a thread would close no epoch: the relay fails to start instead.
            .staged(config.threads)?,
    );
    // A relay whose memory admits no feeder would refuse every Hello: it refuses to start instead.
    hub.budget().check()?;
    eprintln!(
        "tally-relay: {} of memory admits {} feeders ({} each); {} ingest and {} message threads",
        egress::decimal(config.memory as u64),
        hub.budget().ceiling(),
        egress::decimal(hub.budget().per_feeder().total() as u64),
        config.threads.ingest,
        config.threads.message,
    );
    eprintln!(
        "tally-relay: key {} listening on {}",
        identities[0].public(),
        config.listen
    );
    // RFC-0174's duties, configured once here.
    let network = hub.network();
    network.selection.set_taken(config.areas.clone());
    network.products.set_taken(config.areas.clone());
    network.products.set_world(config.world);
    network.products.set_world_precise(config.world_precise);
    network
        .admission
        .configure(config.network, config.relay_duties);
    network.credit.set_upload_cap(config.max_upload.rate());
    if let Some(host) =
        tally_relay::mlat_host::host_for(&config, identities[0].clone(), boot_id()?, hub.budget())?
    {
        eprintln!(
            "tally-relay: hosting MLAT on {} threads for the areas it is chosen to solve",
            config.mlat_threads
        );
        network.host_mlat(Arc::new(host));
    }
    if let Some(address) = &config.beast_out {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("beast-out {address}: {error}"))?;
        tokio::spawn(link::serve_beast(listener, Arc::clone(&hub)));
    }
    if let Some(address) = &config.stats_listen {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("stats-listen {address}: {error}"))?;
        let hub = Arc::clone(&hub);
        tokio::spawn(async move {
            if let Err(error) = tally_relay::stats::serve(listener, hub).await {
                eprintln!("tally-relay: stats: {error}");
            }
        });
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

/// A random boot id for the hosted MLAT's records, so relays tell this process's from the last.
fn boot_id() -> Result<u64, String> {
    let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
    let bytes = identity.public();
    let mut id = [0; 8];
    id.copy_from_slice(&bytes.as_bytes()[..8]);
    Ok(u64::from_be_bytes(id))
}
