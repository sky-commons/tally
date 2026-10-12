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
/// each refusal included (`prepare`), then the plan on stdout, one `name value` a line (RFC-0181
/// §9, "Admission"): the memory's, the cores' and the stages' threads. In order: what the relay
/// holds before any feeder (every part from the plan's own list, `Plan::before_feeders_parts`, with
/// their sum `before-feeders`); the floor a connection reserves and the connection limit with what
/// bound it; `R_max` (receptions and its bytes a second, `ingest::rate_cost`, and the records)
/// with what bound it and the feeders it carries at the planned mean and at the ceiling a source is held to; every
/// rate-driven store's limit as its window (bytes held per reception a second) times
/// `R_max` and the members' rate; the MLAT seats and what bound them; the handshakes allowed at
/// once; and the totals against the memory the relay runs in with the allocator's share:
/// `planned` is `before-feeders`, the floors, the windows and the seats.
/// The keys are an operator's secrets, not its configuration: a throwaway key stands in for them.
fn check(config: &Config) -> Result<(), String> {
    let identity = Identity::generate().map_err(|error| error.to_string())?;
    let (hub, _) = prepare(config, &identity)?;
    let budget = hub.budget();
    let threads = budget.threads();
    let plan = budget.plan();
    let admission = budget.admission();
    let number = |value: usize| value.to_string();
    let wide = |value: u64| value.to_string();
    let optional =
        |value: Option<u64>| value.map_or("unbounded".to_owned(), |value| value.to_string());
    let mut lines: Vec<(String, String)> = vec![("memory".into(), number(budget.memory()))];
    for (name, bytes) in plan.before_feeders_parts() {
        lines.push((name.into(), number(bytes)));
    }
    let member_rate =
        plan.member_feeders as u64 * tally_relay::budget::PLANNED_RECEPTIONS_PER_SEC as u64;
    let mut fixed: Vec<(&str, String)> = vec![
        ("before-feeders", number(plan.before_feeders())),
        ("connections", number(plan.connections)),
        ("floor", number(admission.floor)),
        (
            "per-connection",
            number(admission.floor + plan.per_rate.total()),
        ),
        ("per-seat", number(plan.per_seat.total())),
        (
            "mlat-share-percent",
            number(if plan.holds_raw {
                tally_relay::cores::MLAT_SHARE_PERCENT
            } else {
                0
            }),
        ),
        ("connection-limit", number(admission.connections)),
        (
            "connections-by-memory",
            number(admission.connections_by_memory),
        ),
        (
            "connections-by-cores",
            optional(admission.connections_by_cores.map(|value| value as u64)),
        ),
        (
            "connection-limit-bound",
            admission.connections_bound.name().into(),
        ),
        ("max-receptions-per-sec", wide(admission.rate)),
        ("max-bytes-per-sec", wide(admission.bytes_per_sec())),
        ("max-records-per-sec", wide(admission.records_per_sec())),
        ("rate-by-memory", wide(admission.rate_by_memory)),
        ("rate-by-cores", optional(admission.rate_by_cores)),
        ("rate-bound", admission.rate_bound.name().into()),
        ("members-receptions-per-sec", wide(member_rate)),
        ("feeders-at-mean", wide(admission.feeders_at_mean())),
        ("feeders-at-ceiling", wide(admission.feeders_at_ceiling())),
    ];
    let mut gauges: Vec<(String, String)> = Vec::new();
    for store in tally_relay::budget::Store::ALL {
        let name = store.name();
        gauges.push((format!("limit-{name}"), number(budget.store_bytes(store))));
        if store.driver() == tally_relay::budget::Driver::Rate {
            gauges.push((
                format!("window-{name}"),
                number(
                    plan.per_rate
                        .of(store)
                        .div_ceil(tally_relay::budget::PLANNED_RECEPTIONS_PER_SEC),
                ),
            ));
        }
    }
    let tail: Vec<(&str, String)> = vec![
        ("mlat-seats", number(admission.seats)),
        ("mlat-seats-by-memory", number(admission.seats_by_memory)),
        (
            "mlat-seats-by-cores",
            wide(if plan.holds_raw {
                admission
                    .seats_by_cores
                    .map_or(u64::MAX, |value| value as u64)
            } else {
                0
            }),
        ),
        ("mlat-seats-bound", admission.seats_bound.name().into()),
        ("cores", number(config.cores)),
        ("feeder-records", wide(plan.feeder_records_per_sec)),
        ("general-sessions", number(plan.sessions.general)),
        ("subscriber-sessions", number(plan.sessions.subscribers)),
        (
            "session-records-per-minute",
            wide(plan.sessions.records_per_minute()),
        ),
        ("ingest-threads", number(threads.ingest)),
        ("message-threads", number(threads.message)),
        ("seal-threads", number(threads.seal)),
        ("mlat-threads", number(budget.mlat_threads())),
        (
            "handshakes-in-flight",
            number(tally_relay::cores::handshakes_in_flight(config.cores)),
        ),
        (
            "handshakes-per-sec",
            wide(tally_relay::cores::handshake_pace_of(
                tally_relay::cores::handshakes_in_flight(config.cores),
            )),
        ),
        ("members", number(budget.members())),
        ("member-feeders", number(budget.member_feeders())),
        ("member-rate-pool", number(plan.member_rate_pool())),
        ("planned", number(budget.planned())),
        (
            "allocator",
            number(
                tally_relay::budget::headroom_for(budget.memory())
                    - tally_relay::budget::HEADROOM_BYTES,
            ),
        ),
        (
            "headroom",
            number(tally_relay::budget::headroom_for(budget.memory())),
        ),
        ("limit", number(config.memory_limit)),
    ];
    lines.extend(
        fixed
            .drain(..)
            .map(|(name, value)| (name.to_owned(), value)),
    );
    lines.extend(gauges);
    lines.extend(
        tail.into_iter()
            .map(|(name, value)| (name.to_owned(), value)),
    );
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
            // Its cores, which bound the connections, the rate and the MLAT seats it admits
            // (`budget::Plan::admit`).
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
    // What the arenas keep free below their tops is returned on a thread of its own, off every
    // stage (`budget::spawn_allocator_trimmer`).
    tally_relay::budget::spawn_allocator_trimmer(tally_relay::budget::TRIM_PERIOD)
        .map_err(|error| format!("the allocator's trimmer: {error}"))?;
    let budget = hub.budget();
    let threads = budget.threads();
    let admission = budget.admission();
    eprintln!(
        "tally-relay: admits {} connections ({} of memory holds {}, its {} cores carry {}; {} \
         each), a rate of {} receptions a second ({} feeders at the planned mean) and {} MLAT \
         seats, beside {} member sessions ({} for their shared rate); {} ingest, {} message and {} \
         seal threads",
        admission.connections,
        egress::decimal(config.memory as u64),
        admission.connections_by_memory,
        config.cores,
        admission
            .connections_by_cores
            .map_or("any".to_owned(), |cores| cores.to_string()),
        egress::decimal(admission.floor as u64),
        admission.rate,
        admission.feeders_at_mean(),
        admission.seats,
        budget.members(),
        egress::decimal(budget.plan().member_rate_pool() as u64),
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
