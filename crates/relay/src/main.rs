//! `tally-relay`: the relay's command line (RFC-0171 §3.6).

use std::io::Write as _;
use std::sync::Arc;

use tally_relay::config::{Command, Config};
use tally_relay::egress;
use tally_relay::hub::Hub;
use tally_relay::link;
use tally_wire::Identity;
use tokio::net::TcpListener;

fn main() {
    // What the allocator keeps is bounded (`budget::bound_the_allocator`), before any thread runs.
    tally_relay::budget::bound_the_allocator();
    // Every panic ends the relay (`tally_relay::abort_on_any_panic`), set before any thread runs.
    tally_relay::abort_on_any_panic();
    serve_main();
}

#[tokio::main]
async fn serve_main() {
    if let Err(error) = run().await {
        eprintln!("tally-relay: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    match Command::from_args(std::env::args().skip(1))? {
        Command::Done => Ok(()),
        Command::Check(config) => check(&config),
        Command::Run(config) => serve(config).await,
    }
}

/// `tally-relay check`: everything a start does before it reads its keys and opens its sockets,
/// each refusal included (`prepare`), then the plan on stdout, one `name value` a line: the
/// memory's, the cores' and the stages' threads. Every part of what the relay holds before any
/// feeder is printed from the plan's own list (`Plan::before_feeders_parts`), with their sum,
/// `before-feeders`: a part the plan gains is a line printed, and `planned` is `before-feeders`
/// and the feeders' shares.
/// The keys are an operator's secrets, not its configuration: a throwaway key stands in for them.
fn check(config: &Config) -> Result<(), String> {
    let identity = Identity::generate().map_err(|error| error.to_string())?;
    let (hub, _) = prepare(config, &identity)?;
    let budget = hub.budget();
    let threads = budget.threads();
    let plan = budget.plan();
    let mut lines: Vec<(&str, usize)> = vec![("memory", budget.memory())];
    lines.extend(plan.before_feeders_parts());
    lines.extend([
        ("before-feeders", plan.before_feeders()),
        ("connections", plan.connections),
        ("per-feeder", budget.per_feeder().total()),
        ("feeders", budget.ceiling()),
        ("memory-feeders", budget.memory_feeders()),
        ("cores", config.cores),
        ("core-feeders", plan.core_feeders().unwrap_or(usize::MAX)),
        (
            "feeder-records",
            usize::try_from(plan.feeder_records_per_sec).unwrap_or(usize::MAX),
        ),
        ("general-sessions", plan.sessions.general),
        ("subscriber-sessions", plan.sessions.subscribers),
        (
            "session-records-per-minute",
            usize::try_from(plan.sessions.records_per_minute()).unwrap_or(usize::MAX),
        ),
        ("ingest-threads", threads.ingest),
        ("message-threads", threads.message),
        ("seal-threads", threads.seal),
        ("mlat-threads", budget.mlat_threads()),
        ("members", budget.members()),
        ("per-member", plan.per_member()),
        ("member-feeders", budget.member_feeders()),
        ("member-rate-pool", plan.member_rate_pool()),
        ("planned", budget.planned()),
        (
            "headroom",
            tally_relay::budget::headroom_for(budget.memory()),
        ),
        ("limit", config.memory_limit),
    ]);
    let plan: String = lines
        .iter()
        .map(|(name, value)| format!("{name} {value}\n"))
        .collect();
    let mut stdout = std::io::stdout();
    stdout
        .write_all(plan.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("stdout: {error}"))?;
    // The hub's stages and the hosted engine hold threads a return would wait on.
    std::process::exit(0)
}

/// The relay as its configuration builds it, before any socket: its hub, staged, with its budget
/// checked and its RFC-0174 duties configured, and whether it hosts MLAT. Every refusal a start
/// makes after reading its arguments (but for reading its keys and binding its sockets) is made
/// here, so `check` refuses exactly what a start refuses.
fn prepare(config: &Config, identity: &Identity) -> Result<(Arc<Hub>, bool), String> {
    let hosts_mlat = config.relay_duties && config.mlat;
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
            // Its areas, which the member sessions are planned from (`budget::members_for`).
            .taking(config.areas.clone())
            // Its cores, which bound the feeders it admits (`cores::feeders_carried`).
            .cores(config.cores)
            // Each stage on the threads the load it admits needs (`cores::threads_for`), and
            // MLAT's steps on what the cores leave them (`cores::mlat_threads_for`). A stage
            // short of a thread would close no epoch: the relay fails to start instead.
            .staged_as_planned()?,
    );
    // A relay whose memory cannot hold its members' pool and a feeder beside it would refuse every
    // Hello, or its members: it refuses to start instead.
    hub.budget().check()?;
    // RFC-0174's duties, configured once here.
    let network = hub.network();
    network.products.set_world(config.world);
    network.products.set_world_precise(config.world_precise);
    network
        .admission
        .configure(config.network, config.relay_duties);
    network.credit.set_upload_cap(config.max_upload.rate());
    let hosted =
        match tally_relay::mlat_host::host_for(config, identity.clone(), boot_id()?, hub.budget())?
        {
            Some(host) => {
                network.host_mlat(Arc::new(host));
                true
            }
            None => false,
        };
    Ok((hub, hosted))
}

async fn serve(config: Config) -> Result<(), String> {
    let identities = config.identities()?;
    eprintln!(
        "tally-relay: upload capped at {}/s to billed peers, at most {} in 31 days",
        egress::decimal(config.max_upload.rate()),
        egress::decimal(config.max_upload.most_a_month())
    );
    let (hub, hosted) = prepare(&config, &identities[0])?;
    let budget = hub.budget();
    let threads = budget.threads();
    eprintln!(
        "tally-relay: admits {} feeders: {} of memory holds {} ({} each) beside {} member \
         sessions ({} each, and {} for their shared rate), and its {} cores carry {}; {} ingest, \
         {} message and {} seal threads for them",
        budget.ceiling(),
        egress::decimal(config.memory as u64),
        budget.memory_feeders(),
        egress::decimal(budget.per_feeder().total() as u64),
        budget.members(),
        egress::decimal(budget.plan().per_member() as u64),
        egress::decimal(budget.plan().member_rate_pool() as u64),
        config.cores,
        budget.plan().core_feeders().unwrap_or(usize::MAX),
        threads.ingest,
        threads.message,
        threads.seal,
    );
    eprintln!(
        "tally-relay: key {} listening on {}",
        identities[0].public(),
        config.listen
    );
    if hosted {
        eprintln!(
            "tally-relay: hosting MLAT on {} threads for the areas it is chosen to solve, below \
             the stages' priority",
            budget.mlat_threads()
        );
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
    let identity = Identity::generate().map_err(|error| error.to_string())?;
    let bytes = identity.public();
    let mut id = [0; 8];
    id.copy_from_slice(&bytes.as_bytes()[..8]);
    Ok(u64::from_be_bytes(id))
}
