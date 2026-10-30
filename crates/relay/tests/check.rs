//! `tally-relay check` (RFC-0181 §9, RFC-0180 §3): a configuration is checked by the relay itself,
//! along the path a start takes, so an operator's own check of its deploy asks the relay rather
//! than copying its rules. Run here against the built binary with this file's own arguments, and
//! against what Tally itself publishes: the packaged unit (`tally/packaging/systemd`), with no
//! operator arguments and with an area taken, holds a relay that starts and admits its feeders and
//! every member session its areas bring.
//!
//! The binary and the unit are named by the build (`TALLY_RELAY_BIN`, `TALLY_RELAY_UNIT`, runfiles
//! paths); `cargo test` finds the same two itself.

use std::path::PathBuf;
use std::process::Command;

type Result<T = ()> = std::result::Result<T, String>;

fn binary() -> Result<PathBuf> {
    std::env::var_os("TALLY_RELAY_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_tally-relay").map(PathBuf::from))
        .ok_or_else(|| "TALLY_RELAY_BIN names the relay (set by the build)".to_owned())
}

fn packaged_unit() -> PathBuf {
    std::env::var_os("TALLY_RELAY_UNIT").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packaging/systemd/tally-relay.service")
        },
        PathBuf::from,
    )
}

/// What `check` said: its exit, its stdout's plan (`name value` a line) and its stderr.
struct Checked {
    /// The arguments it was checked with.
    args: Vec<String>,
    accepted: bool,
    plan: Vec<(String, String)>,
    refusal: String,
}

impl Checked {
    /// A line as the text it printed (a figure, or a word: what bound it, `unbounded`).
    fn text(&self, name: &str) -> Result<&str> {
        self.plan
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| format!("the plan has no {name}: {:?}", self.plan))
    }

    fn get(&self, name: &str) -> Result<usize> {
        self.text(name)?
            .parse()
            .map_err(|_| format!("{name} is not a number: {:?}", self.plan))
    }

    /// A figure the cores may leave unbounded (`unbounded`: no cores planned), as a number.
    fn bounded(&self, name: &str) -> Result<Option<usize>> {
        match self.text(name)? {
            "unbounded" => Ok(None),
            text => text
                .parse()
                .map(Some)
                .map_err(|_| format!("{name} is not a number: {:?}", self.plan)),
        }
    }
}

/// The flags without which `check` plans for the host the test runs on, not the deploy it is
/// asked about: a build worker of four cores refused for its cores what the test expected refused
/// for its memory. Every check here names both.
const STATED: [&str; 2] = ["--memory-limit", "--cores"];

fn check(args: &[&str]) -> Result<Checked> {
    if let Some(missing) = STATED.iter().find(|flag| !args.contains(flag)) {
        return Err(format!(
            "{args:?} names no {missing}: the plan would be the build worker's, not the deploy's"
        ));
    }
    let binary = binary()?;
    let output = Command::new(&binary)
        .arg("check")
        .args(args)
        .output()
        .map_err(|error| format!("{}: {error}", binary.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let plan = stdout
        .lines()
        .map(|line| {
            let (name, value) = line
                .split_once(' ')
                .ok_or_else(|| format!("{line}: expected `name value`"))?;
            Ok((name.to_owned(), value.to_owned()))
        })
        .collect::<Result<Vec<(String, String)>>>()?;
    Ok(Checked {
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        accepted: output.status.success(),
        plan,
        refusal: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// The load the plan admits (`cores::Load`): `R_max`, its connections, its seats, the feeders its
/// members' rate is worth, and its other sessions, each at its role's pace.
fn load(checked: &Checked) -> Result<tally_relay::cores::Load> {
    let sessions = tally_relay::cores::Sessions {
        general: checked.get("general-sessions")?,
        subscribers: checked.get("subscriber-sessions")?,
    };
    assert_eq!(
        checked.get("session-records-per-minute")? as u64,
        sessions.records_per_minute(),
        "{:?}",
        checked.plan
    );
    Ok(tally_relay::cores::Load {
        receptions_per_sec: checked.get("max-receptions-per-sec")? as u64,
        connections: checked.get("connection-limit")?,
        seats: checked.get("mlat-seats")?,
        member_feeders: checked.get("member-feeders")?,
        sessions,
    })
}

/// The plan holds together (RFC-0181 §9, "Admission"): the budget is the memory, what it holds
/// before any feeder taken first (every part the plan lists, each printed), the floors of the
/// connections admitted, the windows of `R_max` and the members' rate in every rate-driven store,
/// and the seats, all of it inside the memory, and the budget keeps the declared headroom (the
/// allocator's share and the fixed one) below the memory the relay runs in. The connection limit
/// is the fewer of what the memory and the cores carry, `R_max` the lesser of the two, each with
/// what bound it, and every stage runs on a thread at least.
fn assert_plan_holds(checked: &Checked) -> Result {
    let plan = &checked.plan;
    let (memory, base, floor, connections, members, pool, planned) = (
        checked.get("memory")?,
        checked.get("base")?,
        checked.get("floor")?,
        checked.get("connection-limit")?,
        checked.get("members")?,
        checked.get("member-pool")?,
        checked.get("planned")?,
    );
    let (headroom, allocator, limit) = (
        checked.get("headroom")?,
        checked.get("allocator")?,
        checked.get("limit")?,
    );
    let (member_feeders, rate_pool, links) = (
        checked.get("member-feeders")?,
        checked.get("member-rate-pool")?,
        checked.get("member-links")?,
    );
    assert_eq!(
        links,
        members * tally_relay::peers::WAITING_PER_LINK_BYTES,
        "{plan:?}"
    );
    assert!(
        connections > 0,
        "a plan admitting no connection was accepted"
    );
    assert_eq!(
        members == 0,
        member_feeders == 0 && rate_pool == 0,
        "{plan:?}"
    );
    let (sockets, non_feeder, buffers) = (
        checked.get("connection-sockets")?,
        checked.get("connections")?,
        checked.get("connection-buffers")?,
    );
    // Every connection but a feeder's has its kernel socket buffers planned, at least a feeder's.
    assert!(
        sockets >= non_feeder * tally_relay::sockets::FEEDER_KERNEL_BYTES,
        "{plan:?}"
    );
    assert!(
        non_feeder > 0 && buffers % non_feeder == 0 && buffers / non_feeder > 0,
        "{plan:?}"
    );
    // And its pace state, at what a connection's pace state allocates at most.
    assert_eq!(
        checked.get("connection-paces")?,
        non_feeder * tally_relay::ingest::PACE_BYTES_PER_CONNECTION,
        "{plan:?}"
    );
    // Its open files: every connection planned and every feeder admitted, the stats' and what
    // the process holds beside them (`Hub::descriptors`).
    assert_eq!(
        checked.get("descriptors")?,
        non_feeder
            + connections
            + tally_relay::stats::MAX_CONNECTIONS
            + tally_relay::listeners::OTHER_DESCRIPTORS,
        "{plan:?}"
    );
    // A member session holds nothing of its own beside the members' rate: its records wait in the
    // one ingest pool.
    assert_eq!(pool, rate_pool);
    // What it holds before any feeder is every part the plan lists, each printed. The parts are
    // the plan's own list (`before_feeders_parts`), never one written here, so a part the plan
    // gains cannot be left out of the sum.
    let before = checked.get("before-feeders")?;
    let mut parts = 0;
    for (name, _) in tally_relay::budget::Plan::planned(false).before_feeders_parts() {
        parts += checked.get(name)?;
    }
    assert_eq!(before, parts, "{plan:?}");
    assert!(
        before >= base + buffers + sockets + pool + links,
        "{plan:?}"
    );
    // The connection limit: the fewer of the memory's and the cores'.
    let by_memory = checked.get("connections-by-memory")?;
    let by_cores = checked.bounded("connections-by-cores")?;
    assert_eq!(
        connections,
        by_memory.min(by_cores.unwrap_or(usize::MAX)),
        "{plan:?}"
    );
    let bound = checked.text("connection-limit-bound")?;
    assert_eq!(
        bound,
        if by_cores.is_some_and(|cores| cores < by_memory) {
            "cores"
        } else {
            "memory"
        },
        "{plan:?}"
    );
    // R_max: the lesser of what the memory and the cores carry, at least the connections' mean
    // (connections are admitted at the planned mean), and the bytes and records it admits.
    let rate = checked.get("max-receptions-per-sec")?;
    let rate_memory = checked.get("rate-by-memory")?;
    let rate_cores = checked.bounded("rate-by-cores")?;
    assert_eq!(
        rate,
        rate_memory.min(rate_cores.unwrap_or(usize::MAX)),
        "{plan:?}"
    );
    assert!(
        rate >= connections * tally_relay::budget::PLANNED_RECEPTIONS_PER_SEC,
        "{plan:?}"
    );
    // R_max's bytes are charged bytes (`ingest::charge_of`), the unit the stores are planned in.
    assert_eq!(
        checked.get("max-bytes-per-sec")?,
        rate * tally_relay::budget::PLANNED_CHARGED_BYTES_PER_SEC
            / tally_relay::budget::PLANNED_RECEPTIONS_PER_SEC,
        "{plan:?}"
    );
    assert_eq!(
        checked.get("feeders-at-mean")?,
        rate / tally_relay::budget::PLANNED_RECEPTIONS_PER_SEC,
        "{plan:?}"
    );
    assert!(
        checked.get("feeders-at-ceiling")? <= checked.get("feeders-at-mean")?,
        "{plan:?}"
    );
    assert!(
        ["memory", "cores"].contains(&checked.text("rate-bound")?),
        "{plan:?}"
    );
    // Every rate-driven store's limit is its window (bytes held per reception a second) times
    // R_max, and the members' window times the members' rate; the connections' stores are their
    // floors'.
    let members_rate = checked.get("members-receptions-per-sec")?;
    let served = rate + members_rate;
    let mut gauges = 0;
    for store in tally_relay::budget::Store::ALL {
        let limit = checked.get(&format!("limit-{}", store.name()))?;
        gauges += limit;
        if store.driver() == tally_relay::budget::Driver::Rate {
            let window = checked.get(&format!("window-{}", store.name()))?;
            let members_window = checked.get(&format!("members-window-{}", store.name()))?;
            // The fingerprints' tables' fixed part, what waits for the sealer whatever it holds,
            // the tables' of what was taken, the fan-out's queues, the sharing outbox's slots and
            // the receivers' tables' fixed parts are held before any feeder, beside the rate's.
            let limit = match store {
                tally_relay::budget::Store::Dedup => limit - checked.get("dedup-tables")?,
                tally_relay::budget::Store::Epochs => limit - checked.get("epochs-fixed")?,
                tally_relay::budget::Store::FeederStrikes => {
                    limit - checked.get("feeder-strike-tables")?
                }
                tally_relay::budget::Store::PeerStrikes => {
                    limit - checked.get("peer-strike-tables")?
                }
                tally_relay::budget::Store::OwnStrikes => {
                    limit - checked.get("own-strike-tables")?
                }
                tally_relay::budget::Store::Fanout => limit - checked.get("fanout-queues")?,
                tally_relay::budget::Store::Batches => limit - checked.get("sharing-outbox")?,
                // The tables of one entry per receiver: what they hold whatever the rate.
                tally_relay::budget::Store::Credit => limit - checked.get("credit-tables")?,
                tally_relay::budget::Store::Stations => limit - checked.get("station-tables")?,
                tally_relay::budget::Store::Descriptions => {
                    limit - checked.get("description-tables")?
                }
                tally_relay::budget::Store::Located => limit - checked.get("located-tables")?,
                // The inboxes' spare, whatever they hold.
                tally_relay::budget::Store::Inbox => limit - checked.get("inbox-spare")?,
                tally_relay::budget::Store::Consistency => {
                    limit - checked.get("consistency-tables")?
                }
                _ => limit,
            };
            let expected = window * rate + members_window * members_rate;
            assert!(
                limit <= expected && limit + served >= expected,
                "{store:?}: {limit} is not {window} x {rate} and {members_window} x \
                 {members_rate}: {plan:?}"
            );
        }
    }
    assert!(
        gauges <= memory - base,
        "the gauges pass the memory: {plan:?}"
    );
    assert!(planned <= memory, "{plan:?}");
    assert!(planned >= before + floor * connections, "{plan:?}");
    // MLAT's seats: none where it is not hosted, else what the connections leave of the memory and
    // the cores (planned after them), no more than the connections, and a seat at least.
    let hosted = checked.text("mlat-seats-bound")? != "not-hosted";
    assert_eq!(checked.get("mlat-seats")? > 0, hosted, "{plan:?}");
    assert!(checked.get("mlat-seats")? <= connections, "{plan:?}");
    // The tables that grow with what the relay is sent are each held before any feeder: the
    // products' remembered tables always, standing's where MLAT is hosted (among MLAT's tables),
    // the world's fixes only where they are gathered (`--world`).
    assert!(checked.get("remembered-tables")? > 0, "{plan:?}");
    assert_eq!(checked.get("mlat-tables")? > 0, hosted, "{plan:?}");
    assert!(checked.get("consistency-tables")? > 0, "{plan:?}");
    assert_eq!(
        checked.get("world-fixes")? > 0,
        checked.args.iter().any(|arg| arg.starts_with("--world")),
        "{plan:?}"
    );
    // The handshakes allowed at once are a core's worth of them.
    assert!(
        checked.get("handshakes-in-flight")? >= checked.get("cores")?,
        "{plan:?}"
    );
    assert!(checked.get("handshakes-per-sec")? > 0, "{plan:?}");
    for stage in ["ingest-threads", "message-threads", "seal-threads"] {
        assert!(checked.get(stage)? >= 1, "{stage}: {plan:?}");
    }
    // The headroom is the fixed part and the allocator's share of what the budget plans.
    assert!(
        allocator > 0 && headroom == allocator + tally_relay::budget::HEADROOM_BYTES,
        "{plan:?}"
    );
    assert!(memory + headroom <= limit, "{plan:?}");
    Ok(())
}

#[test]
fn a_configuration_the_relay_takes_is_accepted_with_its_plan() -> Result {
    // A key file that does not exist: check reads no key, which is an operator's secret.
    // Its memory the least round figure that holds what it plans before any feeder (its members'
    // rate's models over their hold among it, `models::BYTES_PER_MEMBER_SEAT`) and a
    // connection with its seat.
    let checked = check(&[
        "--memory-limit",
        "1536M",
        "--cores",
        "2",
        "--key",
        "/nonexistent/relay.key",
        "--max-upload",
        "6Mbit/s",
        "--memory",
        "1152M",
        "--max-connections",
        "32",
        "--max-member-bytes-per-sec",
        "131072",
        "--area",
        "8001fffffffffff",
    ])?;
    assert!(checked.accepted, "{}", checked.refusal);
    assert_eq!(checked.get("memory")?, 1152 << 20);
    // It hosts MLAT by default, on the threads its cores' plan gives it.
    assert!(checked.get("mlat-threads")? >= 1, "{:?}", checked.plan);
    assert_eq!(checked.get("limit")?, 1536 << 20);
    // A base cell's groups reach every relay offering it or a cell under it, far more than 32:
    // the member sessions planned are the cap's worth.
    assert_eq!(checked.get("members")?, 32);
    // Every connection but a feeder's has its buffers planned, each role by its own cap: the 32
    // under --max-connections, the member sessions and the subscribers (64 by default).
    let members = checked.get("members")?;
    assert_eq!(checked.get("connections")?, 32 + members + 64);
    // The members' rate is the feeders it is worth, once: 128 KiB/s is 16 feeders at 8 KiB/s, each
    // a feeder's cost but for the connection's own buffers and sockets, which each session takes
    // from the connections' room.
    let (rate_pool, each) = (
        checked.get("member-rate-pool")?,
        checked.get("per-connection")? + checked.get("per-seat")?,
    );
    assert_eq!(checked.get("member-feeders")?, 16);
    assert!(
        rate_pool % 16 == 0 && rate_pool < 16 * each,
        "{:?}",
        checked.plan
    );
    assert_plan_holds(&checked)?;
    // Without --memory the budget is the memory the relay runs in less its headroom, as a start
    // finds its cgroup's.
    let whole = check(&[
        "--memory-limit",
        "3G",
        "--cores",
        "2",
        "--key",
        "k",
        "--max-upload",
        "0Mbit/s",
        "--max-member-bytes-per-sec",
        "1048576",
    ])?;
    assert!(whole.accepted, "{}", whole.refusal);
    // (to the byte the allocator's share rounds to: `budget::budget_within`)
    let kept = whole.get("memory")? + whole.get("headroom")?;
    assert!(kept <= 3 << 30 && kept + 2 >= 3 << 30, "{:?}", whole.plan);
    // No area taken: no group shared, no member session planned.
    assert_eq!(whole.get("members")?, 0);
    assert_plan_holds(&whole)
}

/// The stages' threads follow the load the relay admits, never the host's cores alone, and its
/// cores bound what it admits (`tally_relay::cores`): the configuration measured on 2026-10-09
/// (`TEN_CORES`: 10 cores, memory for 5,000 feeders and more) runs more than one ingest worker
/// and the one message thread its rate needs (one table a thread carries 20 M receptions a second,
/// `cores::MESSAGE_RECEPTIONS_PER_THREAD`), the same memory on one core admits what one core
/// carries, and a relay of many cores and little memory runs the threads its few feeders need.
#[test]
fn the_stages_follow_the_load_admitted_and_the_cores_bound_it() -> Result {
    let on = |cores: &'static str, memory: &'static str| -> Result<Checked> {
        let mut args = ten_cores(cores, memory);
        args.push("--no-mlat");
        let checked = check(&args)?;
        assert!(checked.accepted, "{}", checked.refusal);
        assert_plan_holds(&checked)?;
        assert_eq!(checked.get("cores")?, cores.parse::<usize>().unwrap_or(0));
        assert_eq!(checked.get("mlat-threads")?, 0, "{:?}", checked.plan);
        Ok(checked)
    };
    let expected = |checked: &Checked| -> Result<tally_relay::ingest::Threads> {
        Ok(tally_relay::cores::threads_for(
            load(checked)?,
            false,
            Some(checked.get("cores")?),
        ))
    };
    let threads = |checked: &Checked| -> Result<tally_relay::ingest::Threads> {
        Ok(tally_relay::ingest::Threads {
            ingest: checked.get("ingest-threads")?,
            message: checked.get("message-threads")?,
            seal: checked.get("seal-threads")?,
        })
    };
    let measured = on("10", "24G")?;
    assert!(
        measured.get("connection-limit")? >= 5_000,
        "{:?}",
        measured.plan
    );
    assert_eq!(threads(&measured)?, expected(&measured)?);
    assert!(
        threads(&measured)?.ingest >= 2 && threads(&measured)?.message >= 1,
        "{:?}",
        threads(&measured)?
    );
    // One core: the cores bound the connections and the rate, below what the memory holds.
    let one = on("1", "24G")?;
    assert!(
        one.bounded("connections-by-cores")? == Some(one.get("connection-limit")?)
            && one.get("connection-limit")? < one.get("connections-by-memory")?
            && one.text("connection-limit-bound")? == "cores"
            && one.text("rate-bound")? == "cores"
            && one.get("max-receptions-per-sec")? < one.get("rate-by-memory")?,
        "{:?}",
        one.plan
    );
    assert_eq!(threads(&one)?, expected(&one)?);
    // Many cores and little memory: the memory bounds it, and the threads follow its rate.
    // 12G: since the ingest was planned at what the measured mix costs (2026-10-26), ten cores
    // carry about what 16G holds, so 16G no longer made a relay of few feeders.
    let small = on("32", "12G")?;
    assert!(
        small.get("connection-limit")? == small.get("connections-by-memory")?
            && Some(small.get("connection-limit")?) < small.bounded("connections-by-cores")?
            && small.text("connection-limit-bound")? == "memory"
            && small.text("rate-bound")? == "memory",
        "{:?}",
        small.plan
    );
    assert_eq!(threads(&small)?, expected(&small)?);
    assert!(
        threads(&small)?.ingest < threads(&measured)?.ingest
            && threads(&small)?.message <= threads(&measured)?.message,
        "{:?} {:?}",
        threads(&small)?,
        threads(&measured)?
    );
    Ok(())
}

/// A relay hosting MLAT plans its steps in the same cores (RFC-0181 §10, "The cores"): the stages
/// keep the threads their load needs, MLAT is given the cores they leave, and the feeders admitted
/// are no more than the cores carry with both, so the same cores admit fewer than without MLAT.
/// On `TEN_CORES`: 10 cores, two areas.
#[test]
fn hosted_mlat_takes_the_cores_the_stages_leave_and_bounds_admission() -> Result {
    let on = |mlat: bool| -> Result<Checked> {
        let mut args = TEN_CORES.to_vec();
        if !mlat {
            args.push("--no-mlat");
        }
        let checked = check(&args)?;
        assert!(checked.accepted, "{}", checked.refusal);
        assert_plan_holds(&checked)?;
        Ok(checked)
    };
    let (hosting, without) = (on(true)?, on(false)?);
    let load = load(&hosting)?;
    // Hosting, the connections are fewer than without MLAT (MLAT's share of the memory and the
    // cores is kept for its seats), and the seats are a pool of their own: planned from what the
    // connections leave, never more than they are.
    assert!(hosting.get("connection-limit")? < without.get("connection-limit")?);
    assert!(hosting.get("max-receptions-per-sec")? < without.get("max-receptions-per-sec")?);
    assert_eq!(without.get("mlat-seats")?, 0);
    assert!(hosting.get("mlat-seats")? <= hosting.get("connection-limit")?);
    assert_eq!(
        hosting.get("mlat-seats")?,
        hosting
            .get("mlat-seats-by-memory")?
            .min(
                hosting
                    .bounded("mlat-seats-by-cores")?
                    .unwrap_or(usize::MAX)
            )
            .min(hosting.get("connection-limit")?)
    );
    // MLAT takes what the stages leave; the stages' threads are their own plan's.
    assert_eq!(
        hosting.get("mlat-threads")?,
        tally_relay::cores::mlat_threads_for(load, true, Some(10))
    );
    let stages = tally_relay::cores::threads_for(load, true, Some(10));
    assert_eq!(hosting.get("ingest-threads")?, stages.ingest);
    assert_eq!(hosting.get("message-threads")?, stages.message);
    assert_eq!(hosting.get("seal-threads")?, stages.seal);
    assert!(hosting.get("mlat-threads")? > 1, "{:?}", hosting.plan);
    assert_eq!(without.get("mlat-threads")?, 0);
    Ok(())
}

#[test]
fn a_configuration_a_start_refuses_is_refused_and_says_why() -> Result {
    let refused = |args: &[&str], why: &str| -> Result {
        let checked = check(args)?;
        assert!(!checked.accepted, "{args:?} was accepted");
        assert!(checked.plan.is_empty(), "{args:?} printed a plan");
        assert!(
            checked.refusal.contains(why),
            "{args:?}: {}",
            checked.refusal
        );
        Ok(())
    };
    // A budget that admits no feeder (refused once the hub is built, as a start refuses it), on
    // cores that would carry many.
    refused(
        &[
            "--memory-limit",
            "1G",
            "--cores",
            "16",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--memory",
            "100M",
        ],
        "admit no feeder",
    )?;
    // Memory that holds feeders but not the members' pool beside one: the 64 member sessions an
    // area brings under a cap of 64 connections, sharing 16 MiB/s (2,048 feeders' worth), on cores
    // that carry them and many feeders beside (their solving among them: sixteen did before it
    // was measured in seconds' steps, `cores::MLAT_SOLVE_NANOS_PER_KEPT`).
    refused(
        &[
            "--memory-limit",
            "4G",
            "--cores",
            "64",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--max-connections",
            "64",
            "--max-member-bytes-per-sec",
            "16777216",
            "--area",
            "8001fffffffffff",
        ],
        "admit no feeder beside 64 member sessions",
    )?;
    // Cores that carry no feeder beside the members' shared rate: 128 MiB/s is 16,384 feeders'
    // worth, more than one core carries.
    refused(
        &[
            "--memory-limit",
            "64G",
            "--cores",
            "1",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--max-member-bytes-per-sec",
            "134217728",
            "--area",
            "8001fffffffffff",
        ],
        "1 cores carry no feeder beside the 15977 feeders",
    )?;
    // The stages' threads are the plan's: no operator picks them.
    for flag in ["--ingest-threads", "--message-threads"] {
        refused(
            &[
                "--memory-limit",
                "2G",
                "--cores",
                "2",
                "--key",
                "k",
                "--max-upload",
                "6Mbit/s",
                flag,
                "2",
            ],
            &format!("unknown argument {flag}"),
        )?;
    }
    refused(
        &[
            "--memory-limit",
            "2G",
            "--cores",
            "0",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
        ],
        "--cores needs a number of cores, at least 1",
    )?;
    // The member sessions follow the areas: no operator picks them.
    refused(
        &[
            "--memory-limit",
            "2G",
            "--cores",
            "2",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--max-members",
            "1",
        ],
        "unknown argument --max-members",
    )?;
    // More memory than the relay will run in, or all of it: the kernel would throttle or kill it
    // before its budget turned a feeder away, so the headroom is kept whatever --memory says.
    for memory in ["576M", "512M"] {
        refused(
            &[
                "--memory-limit",
                "512M",
                "--cores",
                "2",
                "--key",
                "k",
                "--max-upload",
                "6Mbit/s",
                "--memory",
                memory,
            ],
            &format!(
                "is above the {} bytes this relay may plan",
                tally_relay::budget::budget_within(512 << 20)
            ),
        )?;
    }
    // The world product over a part of the world.
    refused(
        &[
            "--memory-limit",
            "2G",
            "--cores",
            "2",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--world",
            "--area",
            "8001fffffffffff",
        ],
        "do not cover the globe",
    )?;
    // A flag the relay does not take, and the cap it requires.
    refused(
        &[
            "--memory-limit",
            "2G",
            "--cores",
            "2",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--egress-budget",
            "1TB",
        ],
        "unknown argument --egress-budget",
    )?;
    refused(
        &["--memory-limit", "2G", "--cores", "2", "--key", "k"],
        "--max-upload is required",
    )?;
    refused(
        &["--cores", "2", "--memory-limit", "lots"],
        "--memory-limit lots: expected bytes",
    )
}

/// A unit's `[Service]` settings, continuation lines joined, comments dropped.
fn unit_settings(text: &str) -> Vec<(String, String)> {
    let mut joined = Vec::new();
    let mut line = String::new();
    for raw in text.lines() {
        let raw = raw.trim();
        if line.is_empty() && (raw.starts_with('#') || raw.starts_with(';')) {
            continue;
        }
        match raw.strip_suffix('\\') {
            Some(head) => {
                line.push_str(head);
                line.push(' ');
            }
            None => {
                line.push_str(raw);
                joined.push(std::mem::take(&mut line));
            }
        }
    }
    joined
        .into_iter()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// What a unit gives the relay, as systemd gives it: the arguments `ExecStart` passes (each
/// `${NAME}` its `Environment=` default, an operator's `$NAME` list empty), and the memory it runs
/// in: the lesser of `MemoryHigh=` and `MemoryMax=` (each the last setting winning), its cgroup's
/// `memory.high` and `memory.max`, in bytes; and the cores its `CPUQuota=` gives it, rounded down
/// and at least one as the relay counts them, or none (the host's).
fn read_unit(text: &str) -> Result<(Vec<String>, usize, Option<usize>)> {
    let settings = unit_settings(text);
    let environment: Vec<(String, String)> = settings
        .iter()
        .filter(|(key, _)| key == "Environment")
        .filter_map(|(_, value)| {
            let (name, value) = value.split_once('=')?;
            Some((name.to_owned(), value.to_owned()))
        })
        .collect();
    let exec = settings
        .iter()
        .find(|(key, _)| key == "ExecStart")
        .map(|(_, value)| value.clone())
        .ok_or("no ExecStart")?;
    let mut args = Vec::new();
    for word in exec.split_whitespace().skip(1) {
        if let Some(name) = word
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
        {
            let value = environment
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
                .ok_or_else(|| format!("${{{name}}} has no default"))?;
            args.push(value);
        } else if !word.starts_with('$') {
            args.push(word.to_owned());
        }
    }
    let last = |name: &str| -> Result<Option<usize>> {
        settings
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| unit_size(value).ok_or_else(|| format!("{name}={value}: not a size")))
            .transpose()
    };
    let limit = match (last("MemoryHigh")?, last("MemoryMax")?) {
        (Some(high), Some(max)) => high.min(max),
        (None, Some(max)) => max,
        (_, None) => return Err("no MemoryMax: the relay would take the whole host".to_owned()),
    };
    let cores = settings
        .iter()
        .rev()
        .find(|(key, _)| key == "CPUQuota")
        .filter(|(_, value)| !value.is_empty())
        .map(|(_, value)| {
            value
                .strip_suffix('%')
                .and_then(|percent| percent.parse::<usize>().ok())
                .map(|percent| (percent / 100).max(1))
                .ok_or_else(|| format!("CPUQuota={value}: not a quota"))
        })
        .transpose()?;
    Ok((args, limit, cores))
}

/// A systemd size: a number with K, M, G or T, base 1024 (systemd.resource-control(5)).
fn unit_size(text: &str) -> Option<usize> {
    let (number, shift) = match text.chars().last()? {
        'K' => (&text[..text.len() - 1], 10),
        'M' => (&text[..text.len() - 1], 20),
        'G' => (&text[..text.len() - 1], 30),
        'T' => (&text[..text.len() - 1], 40),
        _ => (text, 0),
    };
    number.parse::<usize>().ok()?.checked_mul(1 << shift)
}

#[test]
fn a_unit_is_read_as_systemd_reads_it() -> Result {
    let unit = "\
[Service]
# a comment
Environment=RATE=2Mbit/s
ExecStart=/usr/local/bin/tally-relay \\
    --key /k --max-upload ${RATE} $ARGS
MemoryMax=3G
MemoryMax=4G
";
    let (args, limit, cores) = read_unit(unit)?;
    assert_eq!(
        args,
        ["--key", "/k", "--max-upload", "2Mbit/s"].map(str::to_owned)
    );
    assert_eq!((limit, cores), (4 << 30, None));
    // The throttle is a limit too: the lesser is the memory the relay runs in.
    let (_, high, _) = read_unit(&format!("{unit}MemoryHigh=3G\n"))?;
    assert_eq!(high, 3 << 30);
    // A quota is the cores the relay counts: rounded down, at least one.
    assert_eq!(read_unit(&format!("{unit}CPUQuota=250%\n"))?.2, Some(2));
    assert_eq!(read_unit(&format!("{unit}CPUQuota=50%\n"))?.2, Some(1));
    Ok(())
}

/// The packaged unit reads the judging clock's bound as ClockBound publishes it: ordered after
/// `clockbound.service` and never pulling it in (a host without it runs a relay that judges
/// nothing), and letting its client read VMClock (`tally_wire::clock_bound::unit_faults`); it
/// filters every call that would set the clock (`ProtectClock=yes`), since nothing in the relay
/// reads `adjtimex` any more; and a call it refuses fails with EPERM rather than SIGSYS.
#[test]
fn the_packaged_unit_reads_clockbound_and_cannot_set_the_clock() -> Result {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let faults = tally_wire::clock_bound::unit_faults(&text);
    assert!(faults.is_empty(), "{}: {faults:?}", path.display());
    let last = |name: &str| {
        unit_settings(&text)
            .into_iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    assert_eq!(
        last("ProtectClock").as_deref(),
        Some("yes"),
        "{}",
        path.display()
    );
    assert_eq!(
        last("SystemCallErrorNumber").as_deref(),
        Some("EPERM"),
        "{}",
        path.display()
    );
    Ok(())
}

#[test]
fn the_packaged_unit_starts_a_relay_that_admits_feeders() -> Result {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let (args, limit, cores) =
        read_unit(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    // The packaged unit sets no quota: it runs on whatever host an operator has, so it must start
    // and admit feeders on the least any host gives it, one core. A quota, if it states one, is
    // the cores it runs on.
    let (limit, cores) = (limit.to_string(), cores.unwrap_or(1).to_string());
    let mut line = vec!["--memory-limit", limit.as_str(), "--cores", cores.as_str()];
    line.extend(args.iter().map(String::as_str));
    // The open files it gives the relay: what every connection its caps admit needs, or the
    // relay refuses to start (`listeners::raise_open_files`).
    let open_files = unit_settings(&text)
        .into_iter()
        .rev()
        .find(|(key, _)| key == "LimitNOFILE")
        .ok_or_else(|| format!("{}: no LimitNOFILE", path.display()))?
        .1;
    let open_files: usize = open_files
        .parse()
        .map_err(|_| format!("LimitNOFILE={open_files}: not a number"))?;
    // As packaged, and with a base cell taken (an operator's `--area` in its arguments) and a
    // local decoder's beast-out beside it: every member session that area brings fits beside the
    // feeders, and every connection has a descriptor.
    let taking = ["--area", "8001fffffffffff"];
    let decoding = [
        "--area",
        "8001fffffffffff",
        "--beast-out",
        "127.0.0.1:30105",
    ];
    for extra in [&[][..], &taking[..], &decoding[..]] {
        let mut line = line.clone();
        line.extend(extra);
        let area = extra.contains(&"--area").then_some("8001fffffffffff");
        let checked = check(&line)?;
        assert!(checked.accepted, "{}: {}", path.display(), checked.refusal);
        assert_plan_holds(&checked)?;
        assert_eq!(checked.get("members")? > 0, area.is_some());
        // Beast-out's clients are planned as subscribers, where it is served (8 by default).
        assert_eq!(
            checked.get("subscriber-sessions")?,
            if extra.contains(&"--beast-out") {
                64 + 8
            } else {
                64
            },
            "{:?}",
            checked.plan
        );
        let needed = checked.get("descriptors")?;
        assert!(
            needed <= open_files,
            "{}: LimitNOFILE={open_files} is below the {needed} open files its caps need",
            path.display()
        );
        println!(
            "{}{}: a limit of {limit}, a budget admitting {} feeders beside {} member sessions, \
             {needed} open files",
            path.display(),
            area.map(|area| format!(" taking {area}"))
                .unwrap_or_default(),
            checked.get("connection-limit")?,
            checked.get("members")?
        );
    }
    Ok(())
}

/// The lines of `check`'s plan RFC-0181 ("Sizing", "What the cores carry") quotes, and the
/// configuration it quotes them for: ten cores, the two areas the harness's clusters are, memory to
/// spare (so the cores bound it), with hosted MLAT and without.
const CORE_LINES: [&str; 20] = [
    "cores",
    "connection-limit",
    "connections-by-cores",
    "connection-limit-bound",
    "max-receptions-per-sec",
    "rate-by-cores",
    "rate-bound",
    "mlat-seats",
    "mlat-seats-bound",
    "feeder-records",
    "general-sessions",
    "subscriber-sessions",
    "session-records-per-minute",
    "member-feeders",
    "ingest-threads",
    "message-threads",
    "seal-threads",
    "mlat-threads",
    "handshakes-in-flight",
    "handshakes-per-sec",
];

/// Ten cores, 24 GB and the harness's two areas, the configuration the 2026-10-09 runs had, with
/// the connection cap at 2,048. What it measures is how a relay plans ten cores: the stages'
/// threads, what MLAT is given of what they leave, and the connections both admit
/// (`tests/cores-10.txt`). It is no seat floor: a seat's kept raw is planned over
/// `tally_wire::budget::FIX_ARRIVED` and its seats are what its memory leaves. The floor is the
/// world relay's (`tests/world-relay.txt`). A relay taking a base cell plans a
/// member session for every connection the cap allows, and each holds its kernel socket buffers,
/// a link dialled to it and an engine's place (`budget::Plan::connection_sockets`), and every
/// connection under the cap may listen to the fan-out: at 5,024 they took some 10 GB before any
/// feeder and the memory, not the cores, bound what it admits.
const TEN_CORES: [&str; 18] = [
    "--memory-limit",
    "32G",
    "--cores",
    "10",
    "--key",
    "k",
    "--max-upload",
    "10Gbit/s",
    "--memory",
    "24G",
    "--max-connections",
    "2048",
    "--max-connections-per-address",
    "2048",
    "--area",
    "801ffffffffffff",
    "--area",
    "8027fffffffffff",
];

/// `TEN_CORES` on `cores` and `memory` instead.
fn ten_cores(cores: &'static str, memory: &'static str) -> Vec<&'static str> {
    let mut args = TEN_CORES.to_vec();
    for (flag, value) in [("--cores", cores), ("--memory", memory)] {
        if let Some(at) = args.iter().position(|arg| *arg == flag) {
            args[at + 1] = value;
        }
    }
    args
}

/// RFC-0181's figures for what ten cores carry are this test's printed output,
/// held equal to `tests/cores-10.txt`, never prose: the plan the relay prints for that
/// configuration, hosting MLAT and not. A change to the cores' plan (a figure measured again, a
/// cost planned that was not) fails here until the file is regenerated from what this test prints,
/// and the RFC quotes the file. Before, the RFC's prose said ten cores admitted 4,129 hosting MLAT
/// while the relay planned 3,917, its figures from before a record's cost was planned.
#[test]
fn the_cores_figures_the_rfc_quotes_are_the_relays_own() -> Result {
    let mut printed = String::new();
    for (name, mlat) in [("hosting MLAT", true), ("without MLAT (--no-mlat)", false)] {
        let mut args = TEN_CORES.to_vec();
        if !mlat {
            args.push("--no-mlat");
        }
        let checked = check(&args)?;
        assert!(checked.accepted, "{}", checked.refusal);
        printed.push_str(&format!(
            "# tally-relay check {}, {name}\n",
            TEN_CORES.join(" ")
        ));
        for line in CORE_LINES {
            printed.push_str(&format!("{line} {}\n", checked.text(line)?));
        }
    }
    print!("{printed}");
    let held = include_str!("cores-10.txt");
    assert!(
        held == printed,
        "tally/crates/relay/tests/cores-10.txt is not what the relay plans: write this test's \
         output there (`bazel test //crates/relay:check --test_output=all`) and quote it in \
         RFC-0181, \"What the cores carry\":\n{printed}"
    );
    Ok(())
}

/// The world's relay (RFC-0181 §9, "Admission"): 16 cores in a 32 GB container, no MLAT (it does
/// not fit one box beside the world's feeders), the public relay's caps. The plan it prints is
/// held whole in `tests/world-relay.txt`, never prose, so what quotes it (RFC-0181's table, the
/// seats RFC-0171 and `tally_wire::budget` weigh the hosted MLAT's settling against) reads what the
/// relay says: its connection limit and `R_max` with what bound each, the feeders carried at the
/// planned mean and at the ceiling a source is held to, every gauge's limit, the handshakes
/// allowed at once and the totals against the memory with the allocator's share. And the same
/// relay hosting MLAT, whose seats are its own pool and whose connections are fewer. A change to
/// the plan fails here until the file is written again from what this test prints. Its floors,
/// asserted here: more than 15,000 connections without MLAT, and 2,000 seats hosting it.
#[test]
fn the_world_relay_prints_what_it_admits() -> Result {
    let printed = std::cell::RefCell::new(String::new());
    let world = |mlat: bool| -> Result<Checked> {
        let mut args = vec![
            "--memory-limit",
            "32G",
            "--cores",
            "16",
            "--key",
            "k",
            "--max-upload",
            "10Gbit/s",
            "--max-connections",
            "1024",
            "--max-connections-per-address",
            "1024",
            "--area",
            "801ffffffffffff",
        ];
        if !mlat {
            args.push("--no-mlat");
        }
        let checked = check(&args)?;
        assert!(checked.accepted, "{}", checked.refusal);
        assert_plan_holds(&checked)?;
        let mut printed = printed.borrow_mut();
        printed.push_str(&format!(
            "# tally-relay check {}{}\n",
            args.join(" "),
            if mlat { "" } else { " (without MLAT)" }
        ));
        for (name, value) in &checked.plan {
            printed.push_str(&format!("{name} {value}\n"));
        }
        Ok(checked)
    };
    let (hosting, without) = (world(true)?, world(false)?);
    let printed = printed.into_inner();
    print!("{printed}");
    assert!(
        include_str!("world-relay.txt") == printed,
        "tally/crates/relay/tests/world-relay.txt is not what the relay plans: write this test's \
         output there (`bazel test //crates/relay:check --test_output=all`) and quote it in \
         RFC-0181, \"What it admits\":\n{printed}"
    );
    // The relay's whole plan: the connections, the rate and what bound each.
    assert!(
        without.get("connection-limit")? > 15_000,
        "{:?}",
        without.plan
    );
    assert_eq!(without.get("mlat-seats")?, 0);
    // The world relay hosting MLAT seats 2,000 receivers at least (RFC-0181's floor).
    assert!(
        hosting.get("mlat-seats")? >= 2_000,
        "{} seats",
        hosting.get("mlat-seats")?
    );
    assert!(hosting.get("connection-limit")? < without.get("connection-limit")?);
    Ok(())
}

/// `tally-relay check` with a state directory runs beside the live relay that holds it: the test
/// holds the directory as a relay does (`durable::StateDir::open`, its lock), and a check naming it
/// is accepted, makes no key there and leaves the lock with its holder. Before, a check opened the
/// directory as a start does: it took the lock (refused here) and wrote the key.
#[test]
fn a_check_beside_the_live_relay_takes_no_lock_and_writes_no_key() -> Result {
    let base = std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = base.join(format!("check-state-{}", std::process::id()));
    let fresh = path.join("fresh");
    let _ = std::fs::remove_dir_all(&path);
    let live = tally_relay::durable::StateDir::open(&path).map_err(|error| error.to_string())?;
    let key = std::fs::read(path.join("strike.key")).map_err(|error| error.to_string())?;
    let path_text = path.display().to_string();
    let fresh_text = fresh.display().to_string();
    for dir in [path_text.as_str(), fresh_text.as_str()] {
        let checked = check(&[
            "--memory-limit",
            "4G",
            "--cores",
            "2",
            "--key",
            "k",
            "--max-upload",
            "10Mbit/s",
            "--state-dir",
            dir,
        ])?;
        assert!(checked.accepted, "{dir}: {}", checked.refusal);
    }
    assert_eq!(
        std::fs::read(path.join("strike.key")).map_err(|error| error.to_string())?,
        key
    );
    assert!(!fresh.join("strike.key").exists());
    assert!(!fresh.join("lock").exists());
    drop(live);
    let _ = std::fs::remove_dir_all(&path);
    Ok(())
}
