//! Every deployed relay's configuration admits feeders (RFC-0177 §9). A relay's memory is its
//! `--memory`, or else its cgroup's limit (a systemd unit's `MemoryMax=`, a Kubernetes container's
//! `limits.memory`); the budget takes `budget::BASE_BYTES` of it first, and a relay whose budget
//! holds no feeder refuses to start (`Budget::check`). Each deployed configuration is read here as
//! the relay reads it: its arguments through the relay's own parser (`config::Config`), its memory
//! as the relay would find it, and its budget built as `main` builds it. A unit given too little
//! memory is a red test here, not a relay that turns every feeder away in production.
//!
//! The files are named by the build (`TALLY_RELAY_DEPLOYED`, their runfiles paths); `cargo test`
//! reads the same files from the repository.

use tally_relay::budget::{Budget, PerFeeder};
use tally_relay::config::{Config, parse_bytes};

type Result<T = ()> = std::result::Result<T, String>;

/// The deployed configurations: the production host's unit and the packaged unit.
fn deployed() -> Vec<std::path::PathBuf> {
    match std::env::var("TALLY_RELAY_DEPLOYED") {
        Ok(paths) => paths
            .split_whitespace()
            .map(std::path::PathBuf::from)
            .collect(),
        Err(_) => {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
            vec![
                root.join("infra/prod-host/tally/units/tally-relay.service"),
                root.join("tally/packaging/systemd/tally-relay.service"),
            ]
        }
    }
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

/// systemd's sizes: a number with K, M, G or T, base 1024.
fn unit_bytes(text: &str) -> Result<usize> {
    parse_bytes(text)
}

/// What a deployed unit gives the relay: its arguments as `ExecStart` passes them (each
/// `${NAME}` its `Environment=` default, and an operator's `$NAME` list empty), and its memory.
struct Deployed {
    args: Vec<String>,
    memory_max: Option<usize>,
}

fn read_unit(text: &str) -> Result<Deployed> {
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
        } else if word.starts_with('$') {
            // The operator's own arguments, from their environment file: none by default.
        } else {
            args.push(word.to_owned());
        }
    }
    // The last setting wins, as systemd reads it.
    let memory_max = settings
        .iter()
        .rev()
        .find(|(key, _)| key == "MemoryMax")
        .map(|(_, value)| unit_bytes(value))
        .transpose()?;
    Ok(Deployed { args, memory_max })
}

#[test]
fn every_deployed_relay_admits_feeders() -> Result {
    let files = deployed();
    assert!(!files.is_empty(), "no deployed configuration named");
    for file in files {
        let name = file.display().to_string();
        let text = std::fs::read_to_string(&file).map_err(|error| format!("{name}: {error}"))?;
        let deployed = read_unit(&text).map_err(|error| format!("{name}: {error}"))?;
        let config = Config::from_args(deployed.args.iter().cloned())
            .map_err(|error| format!("{name}: {error}"))?
            .ok_or_else(|| format!("{name}: the arguments run no relay"))?;
        // `--memory` if given, else the cgroup's limit, as `budget::memory_available` finds it.
        let memory = if deployed.args.iter().any(|arg| arg == "--memory") {
            config.memory
        } else {
            deployed
                .memory_max
                .ok_or_else(|| format!("{name}: neither --memory nor MemoryMax"))?
        };
        let hosts_mlat = config.relay_duties && config.mlat_threads > 0;
        let budget = Budget::of_memory(memory, PerFeeder::planned(hosts_mlat));
        budget.check().map_err(|error| format!("{name}: {error}"))?;
        println!("{name}: {memory} bytes admit {} feeders", budget.ceiling());
    }
    Ok(())
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
";
    let deployed = read_unit(unit)?;
    assert_eq!(
        deployed.args,
        ["--key", "/k", "--max-upload", "2Mbit/s"].map(str::to_owned)
    );
    assert_eq!(deployed.memory_max, Some(3 << 30));
    // A budget of 1 GiB holds no feeder: what the production unit had.
    let budget = Budget::of_memory(1 << 30, PerFeeder::planned(true));
    assert!(budget.check().is_err());
    Ok(())
}
