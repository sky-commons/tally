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

fn check(args: &[&str]) -> Result<Checked> {
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
/// (its base, the oversize room, its connections' buffers, its members' pool: their shared rate's
/// worth, planned once, and each member session's allowance, and what waits for its link to each
/// member, a link's share each), one feeder fits, each
/// admitted feeder's share fits in what is left, and the budget keeps the declared headroom below
/// the memory the relay runs in. A relay holding member sessions plans their rate; one holding
/// none (it takes no area) plans nothing for them.
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
    assert_eq!(
        planned,
        base + oversize + buffers + pool + links + each * feeders
    );
    assert!(
        planned <= memory && memory - planned < each,
        "{:?}",
        checked.plan
    );
    assert!(headroom > 0, "{:?}", checked.plan);
    assert!(memory + headroom <= limit, "{:?}", checked.plan);
    Ok(())
}

#[test]
fn a_configuration_the_relay_takes_is_accepted_with_its_plan() -> Result {
    // A key file that does not exist: check reads no key, which is an operator's secret.
    let checked = check(&[
        "--memory-limit",
        "640M",
        "--key",
        "/nonexistent/relay.key",
        "--max-upload",
        "6Mbit/s",
        "--mlat-threads",
        "1",
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
    assert_eq!(checked.get("limit")?, 640 << 20);
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
        "--key",
        "k",
        "--max-upload",
        "0Mbit/s",
        "--max-member-bytes-per-sec",
        "1048576",
    ])?;
    assert!(whole.accepted, "{}", whole.refusal);
    assert_eq!(whole.get("memory")?, (2 << 30) - whole.get("headroom")?);
    // No area taken: no group shared, no member session planned.
    assert_eq!(whole.get("members")?, 0);
    assert_plan_holds(&whole)
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
    // A budget that admits no feeder (refused once the hub is built, as a start refuses it).
    refused(
        &[
            "--memory-limit",
            "1G",
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
    // area brings under a cap of 64 connections, sharing 16 MiB/s (2,048 feeders' worth).
    refused(
        &[
            "--memory-limit",
            "4G",
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
    // The member sessions follow the areas: no operator picks them.
    refused(
        &[
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
                "--key",
                "k",
                "--max-upload",
                "6Mbit/s",
                "--memory",
                memory,
            ],
            "is above the 469762048 bytes this relay may plan",
        )?;
    }
    // The world product over a part of the world.
    refused(
        &[
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
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--egress-budget",
            "1TB",
        ],
        "unknown argument --egress-budget",
    )?;
    refused(&["--key", "k"], "--max-upload is required")?;
    refused(
        &["--memory-limit", "lots"],
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
/// `memory.high` and `memory.max`, in bytes.
fn read_unit(text: &str) -> Result<(Vec<String>, usize)> {
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
    Ok((args, limit))
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
    let (args, limit) = read_unit(unit)?;
    assert_eq!(
        args,
        ["--key", "/k", "--max-upload", "2Mbit/s"].map(str::to_owned)
    );
    assert_eq!(limit, 4 << 30);
    // The throttle is a limit too: the lesser is the memory the relay runs in.
    let (_, high) = read_unit(&format!("{unit}MemoryHigh=3G\n"))?;
    assert_eq!(high, 3 << 30);
    Ok(())
}

#[test]
fn the_packaged_unit_starts_a_relay_that_admits_feeders() -> Result {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let (args, limit) = read_unit(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let limit = limit.to_string();
    let mut line = vec!["--memory-limit", limit.as_str()];
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
