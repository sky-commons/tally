//! Every deployed relay's configuration admits feeders (RFC-0178 §9). A relay's memory is its
//! `--memory`, or else its cgroup's limit (a systemd unit's `MemoryMax=`, a Kubernetes container's
//! `limits.memory`); the budget takes the relay's base (`budget::Plan::base`) of it first, and a
//! relay whose budget holds no feeder refuses to start (`Budget::check`). Each deployed configuration is read here as
//! the relay reads it: its arguments through the relay's own parser (`config::Config`), its memory
//! as the relay would find it, and its budget built as `main` builds it. A deployment given too
//! little memory, or an argument the relay no longer takes, is a red test here, not a relay that
//! turns every feeder away (or never starts) in production.
//!
//! Two kinds of deployment run a relay: a systemd unit (`.service`) and a Kubernetes manifest
//! (`.yaml` with a `Deployment`, its container named `relay`). A manifest's `$(NAME)` arguments
//! are its container's environment, read from the ConfigMaps named among the files (a `.yaml`
//! whose kind is `ConfigMap`), as the kubelet fills them in.
//!
//! The files are named by the build (`TALLY_RELAY_DEPLOYED`, their runfiles paths); `cargo test`
//! reads the same files from the repository.

use tally_relay::budget::{Budget, Plan};
use tally_relay::config::{Config, parse_bytes};

type Result<T = ()> = std::result::Result<T, String>;

/// The deployed configurations, and the ConfigMaps their manifests read: the production host's
/// unit, the packaged unit, and the public relay's manifest with its keys.
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
                root.join("infra/kubernetes/tally/relay.yaml"),
                root.join("infra/kubernetes/tally/public-keys.yaml"),
            ]
        }
    }
}

/// What a deployment gives the relay: its arguments as they reach it, and its memory limit.
struct Deployed {
    args: Vec<String>,
    limit: Option<usize>,
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
    let limit = settings
        .iter()
        .rev()
        .find(|(key, _)| key == "MemoryMax")
        .map(|(_, value)| unit_bytes(value))
        .transpose()?;
    Ok(Deployed { args, limit })
}

/// A line's indentation, in spaces.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Whether a line carries nothing a reader takes: blank, or a whole-line comment.
fn is_blank(line: &str) -> bool {
    let line = line.trim();
    line.is_empty() || line.starts_with('#')
}

/// The lines of the YAML block a line opens: those after it indented deeper than `depth`, up to the
/// first line that is not (comments and blank lines inside it kept).
fn block<'a>(lines: &[&'a str], from: usize, depth: usize) -> Vec<&'a str> {
    let rest = lines.get(from + 1..).unwrap_or_default();
    let end = rest
        .iter()
        .position(|line| !line.trim().is_empty() && indent(line) <= depth)
        .unwrap_or(rest.len());
    rest[..end].to_vec()
}

/// A YAML scalar as written in a flow collection or after a key: quotes taken off (`''` in a
/// single-quoted one is a quote).
fn scalar(text: &str) -> Result<String> {
    let text = text.trim();
    if let Some(inner) = text
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        return Ok(inner.replace("''", "'"));
    }
    if let Some(inner) = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        if inner.contains('\\') {
            return Err(format!("{text}: an escape this reader does not read"));
        }
        return Ok(inner.to_owned());
    }
    if text.contains(['#', '\'', '"', '{', '}', '[', ']']) {
        return Err(format!("{text}: not a plain scalar"));
    }
    Ok(text.to_owned())
}

/// The items of a flow collection's text (`[a, 'b', c]` or `{ k: v, ... }` without its brackets),
/// split at the commas outside quotes and nested brackets.
fn flow_items(inner: &str) -> Result<Vec<String>> {
    let mut items = Vec::new();
    let mut item = String::new();
    let mut quote = None;
    let mut depth = 0usize;
    for c in inner.chars() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '[' | '{') => depth += 1,
            (None, ']' | '}') => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("{inner}: unbalanced"))?;
            }
            (None, ',') if depth == 0 => {
                items.push(std::mem::take(&mut item));
                continue;
            }
            (None, '#') => return Err(format!("{inner}: a comment inside a flow collection")),
            _ => {}
        }
        item.push(c);
    }
    if quote.is_some() || depth != 0 {
        return Err(format!("{inner}: unbalanced"));
    }
    items.push(item);
    Ok(items
        .into_iter()
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect())
}

/// The text between a flow collection's brackets, which may run over lines (whole-line comments
/// between them dropped).
fn flow(first: &str, more: &[&str], open: char, close: char) -> Result<String> {
    let mut text = String::new();
    for line in std::iter::once(first).chain(more.iter().copied()) {
        if is_blank(line) {
            continue;
        }
        text.push_str(line.trim());
        text.push(' ');
        if text.trim_end().ends_with(close) {
            let text = text.trim();
            return text
                .strip_prefix(open)
                .and_then(|rest| rest.strip_suffix(close))
                .map(str::to_owned)
                .ok_or_else(|| format!("{text}: expected {open} .. {close}"));
        }
    }
    Err(format!("{first}: no closing {close}"))
}

/// A flow map's `key: value` pairs, values as written (a nested map stays its text).
fn flow_map(inner: &str) -> Result<Vec<(String, String)>> {
    flow_items(inner)?
        .into_iter()
        .map(|item| {
            let (key, value) = item
                .split_once(':')
                .ok_or_else(|| format!("{item}: expected key: value"))?;
            Ok((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// A Kubernetes quantity in bytes: a number with Ki, Mi, Gi or Ti (base 1024) or k, M, G or T
/// (base 1000), or none.
fn quantity_bytes(text: &str) -> Result<usize> {
    const UNITS: [(&str, usize); 8] = [
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1 << 40),
        ("k", 1_000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
    ];
    let (number, scale) = UNITS
        .iter()
        .find_map(|(suffix, scale)| Some((text.strip_suffix(suffix)?, *scale)))
        .unwrap_or((text, 1));
    number
        .parse::<usize>()
        .ok()
        .and_then(|number| number.checked_mul(scale))
        .ok_or_else(|| format!("{text}: not a quantity of bytes"))
}

/// The ConfigMaps a file declares: (map, key, value) for each of its `data` entries.
fn read_config_map(text: &str) -> Result<Vec<(String, String, String)>> {
    let lines: Vec<&str> = text.lines().collect();
    let at = |key: &str| {
        lines
            .iter()
            .position(|line| indent(line) == 0 && line.trim_end() == key)
            .ok_or_else(|| format!("no {key}"))
    };
    let name = block(&lines, at("metadata:")?, 0)
        .iter()
        .find_map(|line| line.trim().strip_prefix("name:").map(scalar))
        .ok_or("a ConfigMap without a name")??;
    block(&lines, at("data:")?, 0)
        .iter()
        .filter(|line| !is_blank(line))
        .map(|line| {
            let (key, value) = line
                .trim()
                .split_once(':')
                .ok_or_else(|| format!("{line}: expected key: value"))?;
            Ok((name.clone(), key.trim().to_owned(), scalar(value)?))
        })
        .collect()
}

/// What a Kubernetes manifest gives its container named `relay`: its arguments, each `$(NAME)` its
/// environment's value (a literal, or a ConfigMap's key from `maps`), and its memory limit.
fn read_manifest(text: &str, maps: &[(String, String, String)]) -> Result<Deployed> {
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.trim() == "- name: relay")
        .ok_or("no container named relay")?;
    let container = block(&lines, at, indent(lines[at]));
    let key = |name: &str| {
        container
            .iter()
            .position(|line| line.trim_start().starts_with(name))
            .ok_or_else(|| format!("the relay container has no {name}"))
    };
    // The environment: each `- name:` entry's `value` or `valueFrom.configMapKeyRef`.
    let env_at = key("env:")?;
    let env_lines = block(&container, env_at, indent(container[env_at]));
    let mut environment = Vec::new();
    let mut name = None;
    for line in env_lines.iter().filter(|line| !is_blank(line)) {
        let line = line.trim();
        if let Some(entry) = line.strip_prefix("- name:") {
            name = Some(scalar(entry)?);
        } else if let Some(value) = line.strip_prefix("value:") {
            let name = name.take().ok_or_else(|| format!("{line}: no name"))?;
            environment.push((name, scalar(value)?));
        } else if let Some(source) = line.strip_prefix("valueFrom:") {
            let name = name.take().ok_or_else(|| format!("{line}: no name"))?;
            let outer = flow_map(flow(source.trim(), &[], '{', '}')?.as_str())?;
            let reference = outer
                .iter()
                .find(|(key, _)| key == "configMapKeyRef")
                .ok_or_else(|| format!("{line}: only configMapKeyRef is read"))?;
            let reference = flow_map(&flow(&reference.1, &[], '{', '}')?)?;
            let field = |wanted: &str| {
                reference
                    .iter()
                    .find(|(key, _)| key == wanted)
                    .map(|(_, value)| scalar(value))
                    .ok_or_else(|| format!("{line}: no {wanted}"))?
            };
            let (map, entry) = (field("name")?, field("key")?);
            let value = maps
                .iter()
                .find(|(named, key, _)| *named == map && *key == entry)
                .map(|(.., value)| value.clone())
                .ok_or_else(|| format!("ConfigMap {map} has no key {entry} among the files"))?;
            environment.push((name, value));
        }
    }
    // The arguments: one flow sequence, each `$(NAME)` filled in as the kubelet does.
    let args_at = key("args:")?;
    let first = container[args_at]
        .trim_start()
        .strip_prefix("args:")
        .unwrap_or_default();
    let more = block(&container, args_at, indent(container[args_at]));
    // The sequence opens after `args:` on its line, or on the first line below it.
    let (first, rest) = if first.trim().is_empty() {
        let mut below = more.iter().copied().filter(|line| !is_blank(line));
        let opening = below.next().ok_or("args: empty")?;
        (opening, below.collect::<Vec<_>>())
    } else {
        (first, more)
    };
    let args = flow_items(&flow(first, &rest, '[', ']')?)?
        .iter()
        .map(|item| {
            let mut arg = scalar(item)?;
            while let Some(start) = arg.find("$(") {
                let end = arg[start..]
                    .find(')')
                    .map(|end| start + end)
                    .ok_or_else(|| format!("{arg}: unclosed $("))?;
                let name = &arg[start + 2..end];
                let value = environment
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone())
                    .ok_or_else(|| format!("$({name}) is not in the relay's environment"))?;
                arg.replace_range(start..=end, &value);
            }
            Ok(arg)
        })
        .collect::<Result<Vec<_>>>()?;
    // The memory limit, the container's cgroup limit.
    let limits = container
        .iter()
        .find_map(|line| line.trim().strip_prefix("limits:"))
        .ok_or("the relay container has no limits")?;
    let limit = flow_map(&flow(limits.trim(), &[], '{', '}')?)?
        .into_iter()
        .find(|(key, _)| key == "memory")
        .map(|(_, value)| quantity_bytes(&scalar(&value)?))
        .transpose()?;
    Ok(Deployed { args, limit })
}

/// The relay's budget as `main` builds it from what a deployment gives it: `--memory` if given
/// (never above the deployment's limit, or the kernel kills the relay before its budget refuses
/// anyone), else the limit, as `budget::memory_available` finds it.
fn budget_of(deployed: &Deployed) -> Result<Budget> {
    let config =
        Config::from_args(deployed.args.iter().cloned())?.ok_or("the arguments run no relay")?;
    let memory = if deployed.args.iter().any(|arg| arg == "--memory") {
        if let Some(limit) = deployed.limit
            && config.memory > limit
        {
            return Err(format!(
                "--memory {} is above the memory limit {limit}",
                config.memory
            ));
        }
        config.memory
    } else {
        deployed
            .limit
            .ok_or("neither --memory nor a memory limit")?
    };
    let hosts_mlat = config.relay_duties && config.mlat_threads > 0;
    let budget = Budget::of_memory(memory, Plan::planned(hosts_mlat));
    budget.check()?;
    Ok(budget)
}

/// Whether a manifest's kind is `kind`.
fn is_kind(text: &str, kind: &str) -> bool {
    text.lines()
        .any(|line| line.trim_end() == format!("kind: {kind}"))
}

#[test]
fn every_deployed_relay_admits_feeders() -> Result {
    let files = deployed();
    let texts = files
        .iter()
        .map(|file| {
            std::fs::read_to_string(file)
                .map(|text| (file.display().to_string(), text))
                .map_err(|error| format!("{}: {error}", file.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut maps = Vec::new();
    for (name, text) in &texts {
        if name.ends_with(".yaml") && is_kind(text, "ConfigMap") {
            maps.extend(read_config_map(text).map_err(|error| format!("{name}: {error}"))?);
        }
    }
    let mut relays = 0;
    for (name, text) in &texts {
        let deployed = if name.ends_with(".service") {
            read_unit(text)
        } else if name.ends_with(".yaml") && is_kind(text, "Deployment") {
            read_manifest(text, &maps)
        } else if name.ends_with(".yaml") && is_kind(text, "ConfigMap") {
            continue;
        } else {
            Err("neither a unit, a Deployment nor a ConfigMap".to_owned())
        }
        .map_err(|error| format!("{name}: {error}"))?;
        let budget = budget_of(&deployed).map_err(|error| format!("{name}: {error}"))?;
        println!(
            "{name}: a limit of {:?} bytes, a budget admitting {} feeders",
            deployed.limit,
            budget.ceiling()
        );
        relays += 1;
    }
    assert!(
        relays >= 3,
        "{relays} deployed relays read; the build names three"
    );
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
    assert_eq!(deployed.limit, Some(3 << 30));
    // Memory that is the relay's base and no more holds no feeder, and is refused.
    let budget = Budget::of_memory(Plan::planned(true).base, Plan::planned(true));
    assert!(budget.check().is_err());
    Ok(())
}

#[test]
fn a_manifest_is_read_as_the_kubelet_fills_it_in() -> Result {
    let keys = "\
apiVersion: v1
kind: ConfigMap
metadata:
  name: keys
data:
  relay: 'JHSEe+sJIFnbegZAoEvGzLcBKS1UYzgPBU7jpIuUJ8o='
";
    let manifest = "\
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: relay
          # prettier-ignore
          args:
            [
              --key, /k,
              # a comment between items
              --max-upload, 6Mbit/s,
              --advertise, 'relay.example:10900=$(KEY)',
              --memory, 448M,
            ]
          env:
            - name: KEY
              valueFrom: { configMapKeyRef: { name: keys, key: relay } }
            - name: OTHER
              value: '1'
          resources:
            requests: { cpu: 500m, memory: 384Mi }
            limits: { cpu: 1500m, memory: 512Mi, ephemeral-storage: 64Mi }
        - name: other
          args: [--not-the-relay]
          resources:
            limits: { memory: 1Gi }
";
    let maps = read_config_map(keys)?;
    assert_eq!(maps.len(), 1);
    let deployed = read_manifest(manifest, &maps)?;
    assert_eq!(
        deployed.args,
        [
            "--key",
            "/k",
            "--max-upload",
            "6Mbit/s",
            "--advertise",
            "relay.example:10900=JHSEe+sJIFnbegZAoEvGzLcBKS1UYzgPBU7jpIuUJ8o=",
            "--memory",
            "448M",
        ]
        .map(str::to_owned)
    );
    assert_eq!(deployed.limit, Some(512 << 20));
    assert_eq!(quantity_bytes("1222680Ki")?, 1_222_680 << 10);
    assert_eq!(quantity_bytes("2G")?, 2_000_000_000);
    assert!(quantity_bytes("640m").is_err());
    // A key the ConfigMaps do not hold is an error, never an argument left unfilled.
    assert!(read_manifest(manifest, &[]).is_err());
    // --memory above the limit is refused: the kernel would kill the relay first.
    let over = Deployed {
        args: deployed.args.clone(),
        limit: Some(400 << 20),
    };
    assert!(budget_of(&over).is_err_and(|error| error.contains("above the memory limit")));
    Ok(())
}
