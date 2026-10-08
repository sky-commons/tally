//! `tally-relay check` (RFC-0181 §9, RFC-0180 §3): a configuration is checked by the relay itself,
//! along the path a start takes, so an operator's own check of its deploy asks the relay rather
//! than copying its rules. Run here against the built binary with this file's own arguments, and
//! against what Tally itself publishes: the packaged unit (`tally/packaging/systemd`), with no
//! operator arguments, holds a relay that starts and admits feeders.
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

/// The plan holds together: the budget is the memory, its base taken first, and each admitted
/// feeder's share fits in what is left.
fn assert_plan_holds(checked: &Checked) -> Result {
    let (memory, base, each, feeders, planned, limit) = (
        checked.get("memory")?,
        checked.get("base")?,
        checked.get("per-feeder")?,
        checked.get("feeders")?,
        checked.get("planned")?,
        checked.get("limit")?,
    );
    assert!(feeders > 0, "a plan admitting no feeder was accepted");
    assert_eq!(planned, base + each * feeders);
    assert!(
        planned <= memory && memory - planned < each,
        "{:?}",
        checked.plan
    );
    assert!(memory <= limit, "{:?}", checked.plan);
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
        "576M",
        "--area",
        "8001fffffffffff",
    ])?;
    assert!(checked.accepted, "{}", checked.refusal);
    assert_eq!(checked.get("memory")?, 576 << 20);
    assert_eq!(checked.get("limit")?, 640 << 20);
    assert_plan_holds(&checked)?;
    // Without --memory the relay's memory is the limit it runs in, as a start finds its cgroup's.
    let whole = check(&[
        "--memory-limit",
        "2G",
        "--key",
        "k",
        "--max-upload",
        "0Mbit/s",
    ])?;
    assert!(whole.accepted, "{}", whole.refusal);
    assert_eq!(whole.get("memory")?, 2 << 30);
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
    // More memory than the relay will run in: the kernel would kill it first.
    refused(
        &[
            "--memory-limit",
            "512M",
            "--key",
            "k",
            "--max-upload",
            "6Mbit/s",
            "--memory",
            "576M",
        ],
        "is above the 536870912 bytes this relay runs in",
    )?;
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
/// `${NAME}` its `Environment=` default, an operator's `$NAME` list empty), and the memory limit
/// (`MemoryMax=`, the last setting winning), which is the relay's cgroup's.
fn read_unit(text: &str) -> Result<(Vec<String>, String)> {
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
    let limit = settings
        .iter()
        .rev()
        .find(|(key, _)| key == "MemoryMax")
        .map(|(_, value)| value.clone())
        .ok_or("no MemoryMax")?;
    Ok((args, limit))
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
    assert_eq!(limit, "4G");
    Ok(())
}

#[test]
fn the_packaged_unit_starts_a_relay_that_admits_feeders() -> Result {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let (args, limit) = read_unit(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut line = vec!["--memory-limit", limit.as_str()];
    line.extend(args.iter().map(String::as_str));
    let checked = check(&line)?;
    assert!(checked.accepted, "{}: {}", path.display(), checked.refusal);
    assert_plan_holds(&checked)?;
    println!(
        "{}: a limit of {limit}, a budget admitting {} feeders",
        path.display(),
        checked.get("feeders")?
    );
    Ok(())
}
