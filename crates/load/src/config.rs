//! The harness's command line.

use std::ops::Range;
use std::path::PathBuf;
use std::time::Duration;

use tally_wire::{RelayAddress, Streams};

use crate::traffic::Spec;

pub const USAGE: &str = "\
usage: tally-load [options]

Runs N simulated receivers, each the real feeder (tally_feed::start: probing, choosing, signed
chained batches over Noise), fed by the MLAT simulator's receivers and aircraft, against one relay,
and one subscriber that measures what the relay delivers. Prints a summary table.

The relay, one of:
  --relay-bin PATH       spawn this tally-relay here (default: $TALLY_RELAY, which `bazel run`
                         sets to the relay built beside this binary)
  --relay HOST:PORT=KEY  an existing relay; repeatable with the same KEY at more addresses (the
                         feeders are spread over them: each address is its own set of source
                         ports, see below)
  --relay-pid PID        the existing relay's pid on this host, to read its CPU and memory
  --relay-stats ADDR     the existing relay's --stats-listen, to read feeders admitted and refused

For a spawned relay:
  --relay-listen ADDR    where it listens (default 127.0.0.1:0, a free port)
  --max-upload RATE      its --max-upload (default 10Gbit/s)
  --relay-arg ARG        one more argument to it, after the harness's own (so it overrides them);
                         repeatable. The harness passes --max-connections and
                         --max-connections-per-address of twice the feeders plus 1024 (a feeder
                         holds a session and, while it probes, a probe) and --no-mlat
  --relay-mlat           let it host MLAT (no --no-mlat): it plans MLAT's memory and cores
                         beside the stages, so it admits fewer feeders

The load:
  --feeders N            simulated receivers in the whole run, across every shard (default 20000)
  --shard I/N            run only the I-th of N equal slices of them (default 0/1), so the
                         feeders can be split over processes and hosts: every shard simulates the
                         same world from the same seed and runs its own receivers
  --no-feeders           run no feeders (a subscriber-only process)
  --no-subscriber        run no subscriber (a feeders-only shard)
  --receptions-per-sec R each receiver's mean receptions a second (default 600: box-01's measured
                         7.9 KB/s upload, RFC-0171 §5, at the 13.7 bytes a reception a signed
                         DEFLATE batch measured here costs)
  --aircraft A           aircraft in each of the two clusters, a third Mode S-only (default 9000:
                         the clusters are RFC-0174's world benchmark, 20,000 receivers as Europe's
                         and the US's are, but its 4,500 aircraft a cluster give a receiver at most
                         about 320 receptions a second, since a simulated aircraft sends about
                         3.4 messages a second; 9,000 reach 600)
  --period SECS          seconds of simulated traffic, played forward then backward in a loop,
                         so no aircraft and no receiver's clock jumps at a loop's end (default 5)
  --seed S               the simulation's seed (default 0: the world benchmark's clusters)
  --ceiling BYTES        each feeder's --ceiling (default 64000, the feeder's own default)
  --ramp SECS            start the feeders evenly over this long (default 60)
  --warmup SECS          wait this long after the ramp before measuring (default 30)
  --duration SECS        measure for this long (default 60)
  --streams LIST         what the subscriber asks for, of raw, dedup and provisional, comma
                         separated (default raw,dedup). provisional measures how long a
                         provisional MLAT position takes from its transmission to the subscriber
                         (the relay must host MLAT: RFC-0174 §2.4's fast MLAT, which must reach
                         the live world before its second is sealed, 4 s after it ends)
  --no-verify            the subscriber does not check signatures
  --decode-threads N     threads the subscriber decodes batches on (default 4)
  --simulate-only        simulate the traffic, print what it came to, and exit
  --state-dir DIR        where the feeders' state and the spawned relay's key and log go
                         (default $TMPDIR/tally-load-PID)

Limits of the host, checked at start:
  every feeder holds a socket and, while probing, another: `ulimit -n` must be at least twice the
  shard's feeders plus 1024, and the spawned relay inherits it. One source address reaches one
  relay address over at most the ephemeral port range (`net.ipv4.ip_local_port_range`, 28,232 ports
  by default): widen it to 1024 65535, or give the relay more addresses (--relay at
  127.0.0.2..127.0.0.N with --relay-listen 0.0.0.0:PORT, or more shards on more hosts).
";

/// The relay under load.
#[derive(Clone, Debug)]
pub enum Relay {
    /// A relay the harness starts on this host.
    Spawn {
        bin: PathBuf,
        listen: String,
        max_upload: String,
        args: Vec<String>,
        /// Whether it hosts MLAT (`--relay-mlat`): else it is started `--no-mlat`.
        mlat: bool,
    },
    /// A relay already running, at one or more addresses under one key.
    Existing {
        addresses: Vec<RelayAddress>,
        pid: Option<u32>,
        stats: Option<String>,
    },
}

/// One slice of the feeders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shard {
    pub index: usize,
    pub count: usize,
}

impl Shard {
    /// The feeders (by index in the whole run) this shard runs: a contiguous slice, the remainder
    /// spread one each over the first shards.
    pub fn range(self, feeders: usize) -> Range<usize> {
        let count = self.count.max(1);
        let base = feeders / count;
        let extra = feeders % count;
        let start = self.index * base + self.index.min(extra);
        let len = base + usize::from(self.index < extra);
        start..start + len
    }

    fn parse(text: &str) -> Result<Self, String> {
        let (index, count) = text
            .split_once('/')
            .ok_or_else(|| format!("--shard {text}: expected I/N"))?;
        let index: usize = number("--shard", index)?;
        let count: usize = number("--shard", count)?;
        if count == 0 || index >= count {
            return Err(format!("--shard {text}: I must be below N"));
        }
        Ok(Self { index, count })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub relay: Relay,
    pub spec: Spec,
    pub shard: Shard,
    pub run_feeders: bool,
    pub subscriber: bool,
    pub ceiling: u32,
    pub ramp: Duration,
    pub warmup: Duration,
    pub duration: Duration,
    pub streams: Streams,
    pub verify: bool,
    pub decode_threads: usize,
    pub state_dir: PathBuf,
    pub simulate_only: bool,
}

/// `None` when the command was fully handled (usage).
pub fn parse(args: impl Iterator<Item = String>) -> Result<Option<Config>, String> {
    let mut spec = Spec {
        feeders: 20_000,
        receptions_per_sec: 600.0,
        aircraft: 9_000,
        period_s: 5,
        seed: 0,
    };
    let mut relay_bin = std::env::var_os("TALLY_RELAY").map(PathBuf::from);
    let mut listen = "127.0.0.1:0".to_owned();
    let mut max_upload = "10Gbit/s".to_owned();
    let mut relay_args = Vec::new();
    let mut relay_mlat = false;
    let mut addresses: Vec<RelayAddress> = Vec::new();
    let mut pid = None;
    let mut stats = None;
    let mut config = Config {
        relay: Relay::Existing {
            addresses: Vec::new(),
            pid: None,
            stats: None,
        },
        spec: spec.clone(),
        shard: Shard { index: 0, count: 1 },
        run_feeders: true,
        subscriber: true,
        ceiling: 64_000,
        ramp: Duration::from_secs(60),
        warmup: Duration::from_secs(30),
        duration: Duration::from_secs(60),
        streams: Streams(Streams::RAW.0 | Streams::DEDUPLICATED.0),
        verify: true,
        decode_threads: 4,
        state_dir: std::env::temp_dir().join(format!("tally-load-{}", std::process::id())),
        simulate_only: false,
    };
    let mut args = args.peekable();
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--relay-bin" => relay_bin = Some(PathBuf::from(value()?)),
            "--relay" => addresses.push(tally_feed::config::parse_relay(&value()?)?),
            "--relay-pid" => pid = Some(number(&flag, &value()?)?),
            "--relay-stats" => stats = Some(value()?),
            "--relay-listen" => listen = value()?,
            "--max-upload" => max_upload = value()?,
            "--relay-arg" => relay_args.push(value()?),
            "--relay-mlat" => relay_mlat = true,
            "--feeders" => spec.feeders = number(&flag, &value()?)?,
            "--shard" => config.shard = Shard::parse(&value()?)?,
            "--no-feeders" => config.run_feeders = false,
            "--no-subscriber" => config.subscriber = false,
            "--receptions-per-sec" => spec.receptions_per_sec = number(&flag, &value()?)?,
            "--aircraft" => spec.aircraft = number(&flag, &value()?)?,
            "--period" => spec.period_s = number(&flag, &value()?)?,
            "--seed" => spec.seed = number(&flag, &value()?)?,
            "--ceiling" => config.ceiling = number(&flag, &value()?)?,
            "--ramp" => config.ramp = seconds(&flag, &value()?)?,
            "--warmup" => config.warmup = seconds(&flag, &value()?)?,
            "--duration" => config.duration = seconds(&flag, &value()?)?,
            "--streams" => config.streams = streams(&value()?)?,
            "--no-verify" => config.verify = false,
            "--decode-threads" => config.decode_threads = number(&flag, &value()?)?,
            "--state-dir" => config.state_dir = PathBuf::from(value()?),
            "--simulate-only" => config.simulate_only = true,
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    if spec.period_s < 3 {
        // The relay forgets a message's bytes after two seconds (its deduplication window), so
        // a loop shorter than three would replay messages it still remembers.
        return Err("--period must be at least 3 seconds".to_owned());
    }
    if spec.receptions_per_sec.is_nan() || spec.receptions_per_sec <= 0.0 {
        return Err("--receptions-per-sec must be above 0".to_owned());
    }
    if let Some(first) = addresses.first()
        && addresses.iter().any(|each| each.key != first.key)
    {
        return Err("every --relay must name the same relay (one KEY)".to_owned());
    }
    config.spec = spec;
    config.relay = match (addresses.is_empty(), relay_bin) {
        (false, _) => Relay::Existing {
            addresses,
            pid,
            stats,
        },
        (true, Some(bin)) => Relay::Spawn {
            bin,
            listen,
            max_upload,
            args: relay_args,
            mlat: relay_mlat,
        },
        (true, None) => {
            return Err(format!(
                "no relay: name --relay-bin (or set TALLY_RELAY) or --relay\n\n{USAGE}"
            ));
        }
    };
    Ok(Some(config))
}

fn streams(text: &str) -> Result<Streams, String> {
    let mut bits = 0;
    for part in text.split(',') {
        bits |= match part {
            "raw" => Streams::RAW.0,
            "dedup" => Streams::DEDUPLICATED.0,
            "provisional" => Streams::PROVISIONAL.0,
            other => {
                return Err(format!(
                    "--streams: unknown stream {other} (raw, dedup, provisional)"
                ));
            }
        };
    }
    Ok(Streams(bits))
}

fn seconds(flag: &str, text: &str) -> Result<Duration, String> {
    let seconds: f64 = number(flag, text)?;
    Duration::try_from_secs_f64(seconds).map_err(|_| format!("{flag}: {text} is not a duration"))
}

fn number<T: std::str::FromStr>(flag: &str, text: &str) -> Result<T, String> {
    text.parse()
        .map_err(|_| format!("{flag}: {text} is not a number"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shards_cover_every_feeder_once_in_order() {
        for feeders in [0, 1, 7, 20_000, 20_003] {
            for count in [1, 2, 3, 7] {
                let mut next = 0;
                for index in 0..count {
                    let range = Shard { index, count }.range(feeders);
                    assert_eq!(range.start, next);
                    assert!(range.len() <= feeders / count + 1);
                    next = range.end;
                }
                assert_eq!(next, feeders);
            }
        }
    }

    #[test]
    fn a_relay_named_twice_must_be_one_relay() {
        let key = |seed| tally_wire::Identity::from_seed([seed; 32]).public();
        let first = format!("127.0.0.1:1={}", key(1));
        let second = format!("127.0.0.2:1={}", key(2));
        let first = first.as_str();
        let second = second.as_str();
        let args = ["--relay", first, "--relay", second].map(str::to_owned);
        assert!(parse(args.into_iter()).is_err());
        let args = ["--relay", first, "--relay", first, "--shard", "1/2"].map(str::to_owned);
        let config = parse(args.into_iter()).ok().flatten();
        assert!(matches!(
            config.as_ref().map(|config| &config.relay),
            Some(Relay::Existing { addresses, .. }) if addresses.len() == 2
        ));
        assert_eq!(
            config.map(|config| config.shard),
            Some(Shard { index: 1, count: 2 })
        );
    }
}
