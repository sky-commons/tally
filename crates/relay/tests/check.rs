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
    accepted: bool,
    plan: Vec<(String, usize)>,
    refusal: String,
}

impl Checked {
    fn get(&self, name: &str) -> Result<usize> {
        self.plan
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| *value)
            .ok_or_else(|| format!("the plan has no {name}: {:?}", self.plan))
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
            let value = value.parse().map_err(|_| format!("{line}: not a number"))?;
            Ok((name.to_owned(), value))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Checked {
        accepted: output.status.success(),
        plan,
        refusal: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// The plan holds together: the budget is the memory, what it holds before any feeder taken first
/// (every part the plan lists: its base, the oversize room, its connections' buffers, its members'
/// pool: their shared rate's worth, planned once, and each member session's allowance, what waits
/// for its link to each member, a link's share each, and the rest), one feeder fits, each
/// admitted feeder's share fits in what is left, and the budget keeps the declared headroom below
/// the memory the relay runs in. A relay holding member sessions plans their rate; one holding
/// none (it takes no area) plans nothing for them. It admits the fewer of the feeders its memory
/// holds and those its cores carry, and runs every stage on a thread at least.
/// The load the plan admits (`cores::Load`): its feeders, each held to the records it prints, and
/// the feeders its members' rate is worth, and its other sessions, each at its role's pace.
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
        feeders: checked.get("feeders")?,
        member_feeders: checked.get("member-feeders")?,
        feeder_records_per_sec: checked.get("feeder-records")? as u64,
        sessions,
    })
}

fn assert_plan_holds(checked: &Checked) -> Result {
    let (memory, base, each, feeders, members, per_member, pool, planned, headroom, limit) = (
        checked.get("memory")?,
        checked.get("base")?,
        checked.get("per-feeder")?,
        checked.get("feeders")?,
        checked.get("members")?,
        checked.get("per-member")?,
        checked.get("member-pool")?,
        checked.get("planned")?,
        checked.get("headroom")?,
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
        "{:?}",
        checked.plan
    );
    assert!(feeders > 0, "a plan admitting no feeder was accepted");
    assert!(per_member > 0, "{:?}", checked.plan);
    assert_eq!(
        members == 0,
        member_feeders == 0 && rate_pool == 0,
        "{:?}",
        checked.plan
    );
    let (oversize, connections, buffers) = (
        checked.get("oversize")?,
        checked.get("connections")?,
        checked.get("connection-buffers")?,
    );
    assert!(oversize > 0, "{:?}", checked.plan);
    assert!(
        connections > 0 && buffers % connections == 0 && buffers / connections > 0,
        "{:?}",
        checked.plan
    );
    assert_eq!(pool, rate_pool + per_member * members);
    // What it holds before any feeder is every part the plan lists, each printed, and the plan is
    // that and the feeders' shares. The parts are the plan's own list (`before_feeders_parts`),
    // never one written here, so a part the plan gains cannot be left out of the sum.
    let before = checked.get("before-feeders")?;
    let mut parts = 0;
    for (name, _) in tally_relay::budget::Plan::planned(false).before_feeders_parts() {
        parts += checked.get(name)?;
    }
    assert_eq!(before, parts, "{:?}", checked.plan);
    assert!(
        before >= base + oversize + buffers + pool + links,
        "{:?}",
        checked.plan
    );
    assert_eq!(planned, before + each * feeders, "{:?}", checked.plan);
    let (memory_feeders, core_feeders) =
        (checked.get("memory-feeders")?, checked.get("core-feeders")?);
    assert_eq!(
        feeders,
        memory_feeders.min(core_feeders),
        "{:?}",
        checked.plan
    );
    assert!(planned <= memory, "{:?}", checked.plan);
    // Bound by its memory, it plans all of it but less than a feeder.
    assert!(
        feeders < memory_feeders || memory - planned < each,
        "{:?}",
        checked.plan
    );
    for stage in ["ingest-threads", "message-threads", "seal-threads"] {
        assert!(checked.get(stage)? >= 1, "{stage}: {:?}", checked.plan);
    }
    assert!(headroom > 0, "{:?}", checked.plan);
    assert!(memory + headroom <= limit, "{:?}", checked.plan);
    Ok(())
}

#[test]
fn a_configuration_the_relay_takes_is_accepted_with_its_plan() -> Result {
    // A key file that does not exist: check reads no key, which is an operator's secret.
    let checked = check(&[
        "--memory-limit",
        "800M",
        "--cores",
        "2",
        "--key",
        "/nonexistent/relay.key",
        "--max-upload",
        "6Mbit/s",
        "--memory",
        "560M",
        "--max-connections",
        "32",
        "--max-member-bytes-per-sec",
        "131072",
        "--area",
        "8001fffffffffff",
    ])?;
    assert!(checked.accepted, "{}", checked.refusal);
    assert_eq!(checked.get("memory")?, 560 << 20);
    // It hosts MLAT by default, on the threads its cores' plan gives it.
    assert!(checked.get("mlat-threads")? >= 1, "{:?}", checked.plan);
    assert_eq!(checked.get("limit")?, 800 << 20);
    // A base cell's groups reach every relay offering it or a cell under it, far more than 32:
    // the member sessions planned are the cap's worth.
    assert_eq!(checked.get("members")?, 32);
    // Every connection but a feeder's has its buffers planned, each role by its own cap: the 32
    // under --max-connections, the member sessions and the subscribers (64 by default).
    let members = checked.get("members")?;
    assert_eq!(checked.get("connections")?, 32 + members + 64);
    // The members' rate is the feeders it is worth, once: 128 KiB/s is 16 feeders at 8 KiB/s, each
    // a feeder's cost but for the connection buffers and the allowance each session takes itself.
    let (rate_pool, each) = (checked.get("member-rate-pool")?, checked.get("per-feeder")?);
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
        "2G",
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
    assert!(kept <= 2 << 30 && kept + 2 >= 2 << 30, "{:?}", whole.plan);
    // No area taken: no group shared, no member session planned.
    assert_eq!(whole.get("members")?, 0);
    assert_plan_holds(&whole)
}

/// The stages' threads follow the load the relay admits, never the host's cores alone, and its
/// cores bound what it admits (`tally_relay::cores`): the configuration measured on 2026-10-09
/// (10 cores, memory for 5,000 feeders and more) runs more than one message thread, the same
/// memory on one core admits what one core carries, and a relay of many cores and little memory
/// runs the threads its few feeders need.
#[test]
fn the_stages_follow_the_load_admitted_and_the_cores_bound_it() -> Result {
    let on = |cores: &str, memory: &str| -> Result<Checked> {
        let checked = check(&[
            "--memory-limit",
            "32G",
            "--cores",
            cores,
            "--key",
            "k",
            "--max-upload",
            "10Gbit/s",
            "--no-mlat",
            "--memory",
            memory,
            "--max-connections",
            "11024",
            "--max-connections-per-address",
            "11024",
            "--area",
            "801ffffffffffff",
            "--area",
            "8027fffffffffff",
        ])?;
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
    assert!(measured.get("feeders")? >= 5_000, "{:?}", measured.plan);
    assert_eq!(threads(&measured)?, expected(&measured)?);
    assert!(
        threads(&measured)?.message >= 2,
        "{:?}",
        threads(&measured)?
    );
    // One core: the cores bound it, below what the memory holds.
    let one = on("1", "24G")?;
    assert!(
        one.get("feeders")? == one.get("core-feeders")?
            && one.get("feeders")? < one.get("memory-feeders")?,
        "{:?}",
        one.plan
    );
    assert_eq!(threads(&one)?, expected(&one)?);
    // Many cores and little memory: the memory bounds it, and the threads follow its feeders.
    let small = on("32", "16G")?;
    assert!(
        small.get("feeders")? == small.get("memory-feeders")?
            && small.get("feeders")? < small.get("core-feeders")?,
        "{:?}",
        small.plan
    );
    assert_eq!(threads(&small)?, expected(&small)?);
    assert!(threads(&small)?.message < threads(&measured)?.message);
    Ok(())
}

/// A relay hosting MLAT plans its steps in the same cores (RFC-0181 §10, "The cores"): the stages
/// keep the threads their load needs, MLAT is given the cores they leave, and the feeders admitted
/// are no more than the cores carry with both, so the same cores admit fewer than without MLAT.
/// The configuration the 2026-10-09 MLAT runs measured: 10 cores, two areas, memory to spare.
#[test]
fn hosted_mlat_takes_the_cores_the_stages_leave_and_bounds_admission() -> Result {
    let on = |mlat: bool| -> Result<Checked> {
        let mut args = vec![
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
            "5024",
            "--max-connections-per-address",
            "5024",
            "--area",
            "801ffffffffffff",
            "--area",
            "8027fffffffffff",
        ];
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
    // The cores bound it, below what its memory holds, and below what they carry without MLAT.
    assert_eq!(hosting.get("feeders")?, hosting.get("core-feeders")?);
    assert!(hosting.get("feeders")? < hosting.get("memory-feeders")?);
    assert!(hosting.get("core-feeders")? < without.get("core-feeders")?);
    assert_eq!(
        hosting.get("core-feeders")?,
        tally_relay::cores::feeders_carried(10, true, load)
    );
    // The 2,000 feeders measured hosting MLAT fit.
    assert!(hosting.get("feeders")? >= 2_000, "{:?}", hosting.plan);
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
    // that carry them and many feeders beside.
    refused(
        &[
            "--memory-limit",
            "4G",
            "--cores",
            "16",
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
        "1 cores carry no feeder beside the 16384 feeders",
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
    // As packaged, and with a base cell taken (an operator's `--area` in its arguments): every
    // member session that area brings fits beside the feeders.
    for area in [None, Some("8001fffffffffff")] {
        let mut line = line.clone();
        line.extend(area.iter().flat_map(|area| ["--area", area]));
        let checked = check(&line)?;
        assert!(checked.accepted, "{}: {}", path.display(), checked.refusal);
        assert_plan_holds(&checked)?;
        assert_eq!(checked.get("members")? > 0, area.is_some());
        println!(
            "{}{}: a limit of {limit}, a budget admitting {} feeders beside {} member sessions",
            path.display(),
            area.map(|area| format!(" taking {area}"))
                .unwrap_or_default(),
            checked.get("feeders")?,
            checked.get("members")?
        );
    }
    Ok(())
}

/// The lines of `check`'s plan RFC-0181 ("Sizing", "What the cores carry") quotes, and the
/// configuration it quotes them for: ten cores, the two areas the harness's clusters are, memory to
/// spare (so the cores bound it), with hosted MLAT and without.
const CORE_LINES: [&str; 11] = [
    "cores",
    "core-feeders",
    "feeder-records",
    "general-sessions",
    "subscriber-sessions",
    "session-records-per-minute",
    "member-feeders",
    "ingest-threads",
    "message-threads",
    "seal-threads",
    "mlat-threads",
];

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
    "5024",
    "--max-connections-per-address",
    "5024",
    "--area",
    "801ffffffffffff",
    "--area",
    "8027fffffffffff",
];

/// N15 of sweep 5: RFC-0181's figures for what ten cores carry are this test's printed output,
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
            printed.push_str(&format!("{line} {}\n", checked.get(line)?));
        }
    }
    print!("{printed}");
    let held = include_str!("cores-10.txt");
    assert!(
        held == printed,
        "tally/crates/relay/tests/cores-10.txt is not what the relay plans: write this test's \
         output there (`bazel test //tally/crates/relay:check --test_output=all`) and quote it in \
         RFC-0181, \"What the cores carry\":\n{printed}"
    );
    Ok(())
}
