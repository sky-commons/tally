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
                         --max-connections-per-address of the feeders and a fifth more, plus 1024
                         (a feeder holds a session and, while it probes, a probe; the relay plans
                         a connection's buffers for every connection the cap allows) and --no-mlat
  --relay-mlat           let it host MLAT (no --no-mlat): it plans MLAT's memory and cores
                         beside the stages, so it admits fewer feeders
  --relay-fit            give it --memory exactly what --feeders need (`tally-relay check`'s
                         before-feeders and per-connection (and per-seat, hosting MLAT)), as a deploy sized for them is: the run
                         then fails if the relay's peak resident memory passed that budget and
                         the headroom the relay keeps below the memory it runs in

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
  --seed S               the simulation's seed (default 0: the world benchmark's clusters)
  --client-sample N      the client decodes one raw batch in N (default 1, all): the rest are
                         counted from their own receptions count and followed by sequence, so
                         receptions, bytes and losses stay whole, while the latency, the
                         coverage line and the feeders' drops are of the sample. Decoding every
                         batch of 12 M receptions a second takes about 3 cores
  --deflate-level N      the DEFLATE level the feeders compress their batches at, 1 to 9, or 0 for
                         the wire's own, 6 (default 2: within 2% of the size, a quarter of the
                         time, which is what lets one box's cores carry 20,000 feeders)
  --replay K             make traffic for N/K receivers and have K feeders play each (the first
                         with the receiver's identity, the rest with identities of their own that
                         hear what it hears): for runs of more feeders than the simulation (one
                         thread a cluster) can make real-time traffic for, at the cost of every
                         message being heard by K times as many feeders as it would be (default 1)
  --feeder-networks M    where the feeders connect from, which the relay groups them by (their
                         /16): many (each from its own address across 127.0.0.0/8, in 256 groups,
                         so the relay sees honest feeders), one (all from one address, one group:
                         the Sybil case), auto (many if every relay is on loopback; the default)
  --ceiling BYTES        each feeder's --ceiling (default 64000, the feeder's own default)
  --ramp SECS            start the feeders evenly over this long (default 60)
  --warmup SECS          wait this long after the ramp before measuring (default 30)
  --duration SECS        measure for this long (default 60)
  --streams LIST         what the subscriber asks for, of raw, dedup and provisional, comma
                         separated (default raw,dedup). provisional measures how long a
                         provisional MLAT position takes from its transmission to the subscriber
                         (the relay must host MLAT: RFC-0174 §2.4's fast MLAT, which must reach
                         the live world before its second is sealed, 32.5 s after it ends)
  --no-verify            the subscriber does not check signatures
  --decode-threads N     threads the subscriber decodes batches on (default 4)
  --simulate-only        simulate the run's first seconds, print what they came to, and exit
  --state-dir DIR        where the feeders' state and the spawned relay's key and log go
                         (default $TMPDIR/tally-load-PID)

The whole run (ramp, warm-up and measured window) is simulated forward in time as it is played, on
a thread for each cluster, a few seconds ahead of the feeders: every aircraft flies on and every
receiver's clock runs on for the whole run, and nothing is heard twice that a real sky would not
repeat. A feeder that finds its next second not yet simulated waits, counted (the summary's
simulation line).

Limits of the host, checked at start:
  every feeder holds a socket and, while probing, another: `ulimit -n` must be at least twice the
  shard's feeders plus 1024, and the spawned relay inherits it. One source address reaches one
  relay address over at most the ephemeral port range (`net.ipv4.ip_local_port_range`, 28,232 ports
  by default): widen it to 1024 65535, or give the relay more addresses (--relay at
  127.0.0.2..127.0.0.N with --relay-listen 0.0.0.0:PORT, or more shards on more hosts).
";

/// The DEFLATE level the simulated feeders compress at: compressing a batch is half of what a
/// harness spends, and level 2 makes batches within 2% of the wire's level 6 in a quarter of the
/// time (860 receptions: 13.6 against 13.4 bytes a reception).
const DEFAULT_DEFLATE_LEVEL: u8 = 2;

/// Seconds simulated past the measured window's end.
const RUN_SPARE: Duration = Duration::from_secs(30);

/// The relay under load.
#[derive(Clone, Debug)]
pub enum Relay {
    /// A relay the harness starts on this host.
    Spawn(Spawn),
    /// A relay already running, at one or more addresses under one key.
    Existing {
        addresses: Vec<RelayAddress>,
        pid: Option<u32>,
        stats: Option<String>,
    },
}

/// A relay the harness starts: its binary and how it is started.
#[derive(Clone, Debug)]
pub struct Spawn {
    pub bin: PathBuf,
    pub listen: String,
    pub max_upload: String,
    pub args: Vec<String>,
    /// Whether it hosts MLAT (`--relay-mlat`): else it is started `--no-mlat`.
    pub mlat: bool,
    /// Whether its `--memory` is exactly what the feeders need (`--relay-fit`).
    pub fit: bool,
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

/// Where the simulated feeders connect from, which is what a relay groups them by (their network
/// group, the /16 of an IPv4 address): it shares its ingest rate between groups, so feeders in one
/// group are one share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Networks {
    /// `Many` where every relay is on loopback, else `One`.
    Auto,
    /// Each feeder connects from an address of its own across 127.0.0.0/8 (Linux routes all of it
    /// to loopback), spread over its 256 /16 groups, so a run measures honest feeders, each in
    /// a network of its own kind.
    Many,
    /// Every feeder connects from the system's address: one group, as a Sybil does.
    One,
}

impl Networks {
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "auto" => Ok(Self::Auto),
            "many" => Ok(Self::Many),
            "one" => Ok(Self::One),
            other => Err(format!(
                "--feeder-networks: {other} is not auto, many or one"
            )),
        }
    }

    /// The address feeder number `index` of the run connects from, when it is given one. 256
    /// groups (127.G.0.0/16, G from the index) hold the feeders in turn, each feeder its own host
    /// in its group.
    pub fn source_address(self, index: usize, loopback: bool) -> Option<std::net::IpAddr> {
        let many = match self {
            Self::Many => true,
            Self::One => false,
            Self::Auto => loopback,
        };
        many.then(|| {
            let group = (index % 256) as u8;
            let host = (index / 256 + 1) as u16;
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                127,
                group,
                (host >> 8) as u8,
                (host & 0xff) as u8,
            ))
        })
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
    pub networks: Networks,
    /// Feeders playing each simulated receiver (`--replay`).
    pub replay: usize,
    /// The DEFLATE level the feeders compress their batches at (`--deflate-level`); `None` is the
    /// wire's own.
    pub deflate_level: Option<u8>,
    /// The client decodes one raw batch in this many (`--client-sample`).
    pub client_sample: u32,
}

/// `None` when the command was fully handled (usage).
pub fn parse(args: impl Iterator<Item = String>) -> Result<Option<Config>, String> {
    let mut spec = Spec {
        feeders: 20_000,
        receptions_per_sec: 600.0,
        aircraft: 9_000,
        seconds: 0,
        seed: 0,
    };
    let mut relay_bin = std::env::var_os("TALLY_RELAY").map(PathBuf::from);
    let mut listen = "127.0.0.1:0".to_owned();
    let mut max_upload = "10Gbit/s".to_owned();
    let mut relay_args = Vec::new();
    let mut relay_mlat = false;
    let mut relay_fit = false;
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
        networks: Networks::Auto,
        replay: 1,
        deflate_level: Some(DEFAULT_DEFLATE_LEVEL),
        client_sample: 1,
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
            "--relay-fit" => relay_fit = true,
            "--feeders" => spec.feeders = number(&flag, &value()?)?,
            "--shard" => config.shard = Shard::parse(&value()?)?,
            "--no-feeders" => config.run_feeders = false,
            "--no-subscriber" => config.subscriber = false,
            "--receptions-per-sec" => spec.receptions_per_sec = number(&flag, &value()?)?,
            "--aircraft" => spec.aircraft = number(&flag, &value()?)?,
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
            "--client-sample" => config.client_sample = number::<u32>(&flag, &value()?)?.max(1),
            "--deflate-level" => {
                let level: u8 = number(&flag, &value()?)?;
                if level > 9 {
                    return Err("--deflate-level: 0 to 9".to_owned());
                }
                config.deflate_level = (level != 0).then_some(level);
            }
            "--replay" => config.replay = number::<usize>(&flag, &value()?)?.max(1),
            "--feeder-networks" => config.networks = Networks::parse(&value()?)?,
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    if spec.receptions_per_sec.is_nan() || spec.receptions_per_sec <= 0.0 {
        return Err("--receptions-per-sec must be above 0".to_owned());
    }
    if let Some(first) = addresses.first()
        && addresses.iter().any(|each| each.key != first.key)
    {
        return Err("every --relay must name the same relay (one KEY)".to_owned());
    }
    // The run simulated whole, and some to spare for the feeders' last second and the summary.
    let run = config.ramp + config.warmup + config.duration + RUN_SPARE;
    spec.seconds = u32::try_from(run.as_secs().saturating_add(1)).unwrap_or(u32::MAX);
    // The simulation makes traffic for the receivers each feeder plays (`--replay`).
    spec.feeders = spec.feeders.div_ceil(config.replay);
    config.spec = spec;
    config.relay = match (addresses.is_empty(), relay_bin) {
        (false, _) => Relay::Existing {
            addresses,
            pid,
            stats,
        },
        (true, Some(bin)) => Relay::Spawn(Spawn {
            bin,
            listen,
            max_upload,
            args: relay_args,
            mlat: relay_mlat,
            fit: relay_fit,
        }),
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
    fn the_help_states_the_live_worlds_settle_the_relay_uses() {
        let ms = tally_relay::products::WORLD_SETTLE_MS;
        let stated = match ms % 1_000 {
            0 => format!("{} s", ms / 1_000),
            part => format!(
                "{}.{} s",
                ms / 1_000,
                format!("{part:03}").trim_end_matches('0')
            ),
        };
        assert!(
            USAGE.contains(&format!(
                "before its second is sealed, {stated} after it ends"
            )),
            "the help does not say {stated}"
        );
    }

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
