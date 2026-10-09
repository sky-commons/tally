//! A load harness for one Tally relay (RFC-0171 §3.6, RFC-0174): many simulated receivers, each
//! the real feeder (`tally_feed::start`) publishing what the MLAT simulator says it hears, and one
//! subscriber measuring what the relay delivers, with the relay's CPU and memory read from `/proc`.
//! The feeders split over processes and hosts by shard (`config::Shard`): every shard simulates the
//! same world and runs its own slice of it.

pub mod config;
pub mod feeders;
pub mod histogram;
pub mod relay;
pub mod subscriber;
pub mod traffic;

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tally_wire::RelayAddress;

use crate::config::{Config, Relay};
use crate::relay::{Admission, Sample};
use crate::subscriber::{Client, Snapshot};
use crate::traffic::Traffic;

/// How often a progress line is printed.
const PROGRESS_EVERY: Duration = Duration::from_secs(10);

/// Checks the host can hold the sockets asked of it: the open file limit, and the source ports one
/// address has towards one relay address. Fails on the first, warns on the second.
fn check_host(
    config: &Config,
    local: usize,
    addresses: usize,
    spawning: bool,
) -> Result<(), String> {
    let soft = relay::raise_open_files()?;
    let mut needed = if config.run_feeders { 2 * local } else { 0 } + 1024;
    if spawning {
        needed = needed.max(2 * config.spec.feeders + 1024);
    }
    if soft < needed as u64 {
        return Err(format!(
            "the open file limit is {soft} (raised to the hard limit) and this run needs \
             {needed}: each feeder holds a socket, and another while it probes, and a spawned \
             relay holds one per feeder. Raise the hard limit (`ulimit -Hn {}` as root, or \
             `nofile` in /etc/security/limits.conf)",
            needed.next_power_of_two()
        ));
    }
    let range =
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap_or_default();
    let mut bounds = range
        .split_whitespace()
        .filter_map(|value| value.parse::<usize>().ok());
    if let (Some(low), Some(high)) = (bounds.next(), bounds.next()) {
        let ports = high.saturating_sub(low) + 1;
        let per_address = local.div_ceil(addresses.max(1));
        // A session each, and a probe each while the ramp has them probing at once.
        if config.run_feeders && per_address + per_address / 4 > ports {
            eprintln!(
                "tally-load: warning: {per_address} feeders reach each relay address from one \
                 source address, over {ports} ephemeral ports ({low}-{high}); widen them \
                 (`sudo sysctl -w net.ipv4.ip_local_port_range=\"1024 65535\"`), give the relay \
                 more addresses (--relay 127.0.0.2:PORT=KEY ...), or split over hosts (--shard)"
            );
        }
    }
    Ok(())
}

/// What one sample of the run saw.
struct Moment {
    sample: Option<Sample>,
    own: Option<Sample>,
    client: Snapshot,
    admission: Option<Admission>,
    offered: u64,
}

struct Watch {
    pid: Option<u32>,
    stats: Option<String>,
    client: Arc<Client>,
    counts: Arc<feeders::Counts>,
    ticks: f64,
}

impl Watch {
    fn moment(&self) -> Moment {
        Moment {
            sample: self.pid.and_then(|pid| Sample::read(Some(pid)).ok()),
            own: Sample::read(None).ok(),
            client: self.client.counts.snapshot(),
            admission: self
                .stats
                .as_deref()
                .and_then(|stats| relay::admission(stats).ok()),
            offered: self.counts.offered.load(Ordering::Relaxed),
        }
    }
}

/// Runs the harness as configured and returns its summary table.
pub async fn run(config: Config) -> Result<String, String> {
    let range = config.shard.range(config.spec.feeders);
    let local = if config.run_feeders { range.len() } else { 0 };
    let (addresses, pid, stats, mut spawned) = match &config.relay {
        Relay::Existing {
            addresses,
            pid,
            stats,
        } => (addresses.clone(), *pid, stats.clone(), None),
        Relay::Spawn { .. } => (Vec::new(), None, None, None),
    };
    if !config.simulate_only {
        check_host(
            &config,
            local,
            addresses.len().max(1),
            matches!(config.relay, Relay::Spawn { .. }),
        )?;
    }
    let started = Instant::now();
    let traffic = if config.run_feeders {
        let local_range = range.clone();
        eprintln!(
            "tally-load: simulating {} receivers ({} here), {} aircraft a cluster, {} s looped",
            config.spec.feeders,
            local_range.len(),
            config.spec.aircraft,
            config.spec.period_s
        );
        let spec = config.spec.clone();
        let built = tokio::task::spawn_blocking(move || Traffic::build(&spec, local_range))
            .await
            .map_err(|error| error.to_string())??;
        let calibration = built.calibration;
        eprintln!(
            "tally-load: simulated in {:.1} s: {:.0} receptions a second a receiver ({:.0} in \
             reach, kept at {:.3}), {:.0} distinct transmissions a second, each heard by {:.1} \
             receivers, {:.0} distinct messages a second by their bytes, about {:.0} a second for \
             the deduplicated stream; {} receptions held",
            started.elapsed().as_secs_f64(),
            calibration.per_sec,
            calibration.in_reach_per_sec,
            calibration.probability,
            calibration.messages_per_sec,
            calibration.receivers_per_message,
            calibration.contents_per_sec,
            calibration.deduplicated_per_sec,
            built.held()
        );
        if config.simulate_only {
            let own = Sample::read(None)?;
            return Ok(format!(
                "tally-load: simulated only; this process holds {} MiB",
                own.rss_kib / 1024
            ));
        }
        Some(Arc::new(built))
    } else {
        None
    };
    let (addresses, pid, stats) = match &config.relay {
        Relay::Spawn {
            bin,
            listen,
            max_upload,
            args,
            mlat,
        } => {
            let relay = relay::spawn(
                bin,
                listen,
                max_upload,
                *mlat,
                args,
                config.spec.feeders,
                &config.state_dir,
            )?;
            eprintln!(
                "tally-load: relay pid {} at {}={} (log {}); other shards join with --relay {}={}",
                relay.pid(),
                relay.address.address,
                relay.address.key,
                relay.log.display(),
                relay.address.address,
                relay.address.key,
            );
            let found = (
                vec![relay.address.clone()],
                Some(relay.pid()),
                Some(relay.stats.clone()),
            );
            spawned = Some(relay);
            found
        }
        Relay::Existing { .. } => (addresses, pid, stats),
    };
    let client = Arc::new(Client::default());
    if config.subscriber {
        tokio::spawn(subscriber::run(
            addresses[0].clone(),
            config.streams,
            config.verify,
            config.decode_threads,
            Arc::clone(&client),
        ));
    }
    let counts = Arc::new(feeders::Counts::default());
    if let Some(traffic) = &traffic {
        feeders::spawn(
            Arc::clone(traffic),
            &addresses,
            config.ceiling,
            config.ramp,
            &config.state_dir,
            Arc::clone(&counts),
            tokio::time::Instant::now(),
        );
    }
    let watch = Watch {
        pid,
        stats,
        client: Arc::clone(&client),
        counts: Arc::clone(&counts),
        ticks: relay::ticks_a_second(),
    };
    let begin = Instant::now();
    let measure_from = config.ramp + config.warmup;
    let measure_to = measure_from + config.duration;
    let mut last = watch.moment();
    let mut window: Option<(Moment, Instant)> = None;
    let mut relay_peak_cores: f64 = 0.0;
    loop {
        let elapsed = begin.elapsed();
        let next = if window.is_none() {
            measure_from.min(elapsed + PROGRESS_EVERY)
        } else {
            measure_to.min(elapsed + PROGRESS_EVERY)
        };
        tokio::time::sleep(next.saturating_sub(elapsed)).await;
        if let Some(relay) = spawned.as_mut()
            && let Some(status) = relay.exited()
        {
            return Err(format!(
                "the relay exited ({status}); see {}",
                relay.log.display()
            ));
        }
        let now = watch.moment();
        let cores = match (&now.sample, &last.sample) {
            (Some(now), Some(before)) => Some(now.cores_since(before, watch.ticks)),
            _ => None,
        };
        if window.is_some()
            && let Some(cores) = cores
        {
            relay_peak_cores = relay_peak_cores.max(cores);
        }
        eprintln!(
            "{}",
            progress(&watch, &last, &now, cores, begin.elapsed(), &counts)
        );
        let elapsed = begin.elapsed();
        if window.is_none() && elapsed >= measure_from {
            client.reset_window();
            window = Some((watch.moment(), Instant::now()));
        }
        last = now;
        if elapsed >= measure_to {
            break;
        }
    }
    let end = watch.moment();
    let Some((start, at)) = window else {
        return Err("no window was measured".to_owned());
    };
    let seconds = at.elapsed().as_secs_f64();
    let table = summary(&Summary {
        config: &config,
        local,
        addresses: &addresses,
        traffic: traffic.as_deref(),
        client: &client,
        counts: &counts,
        start: &start,
        end: &end,
        seconds,
        ticks: watch.ticks,
        relay_peak_cores,
    });
    let _ = std::fs::remove_dir_all(config.state_dir.join("feeders"));
    drop(spawned);
    Ok(table)
}

fn progress(
    watch: &Watch,
    before: &Moment,
    now: &Moment,
    cores: Option<f64>,
    elapsed: Duration,
    counts: &feeders::Counts,
) -> String {
    let seconds = now
        .own
        .zip(before.own)
        .map_or(1.0, |(now, before)| {
            now.at.duration_since(before.at).as_secs_f64()
        })
        .max(1e-3);
    let delta = now.client - before.client;
    let mut line = format!(
        "tally-load: {:>4.0} s: feeders started {}",
        elapsed.as_secs_f64(),
        counts.started.load(Ordering::Relaxed)
    );
    if let Some(admission) = now.admission {
        let _ = write!(
            line,
            ", relay holds {} (refused {})",
            admission.feeders, admission.refused
        );
    }
    let _ = write!(
        line,
        "; offered {:.0}/s",
        now.offered.saturating_sub(before.offered) as f64 / seconds
    );
    if watch.client.connected.load(Ordering::Relaxed) || delta.raw_batches > 0 {
        let _ = write!(
            line,
            "; client {:.0} batches/s {:.0} receptions/s",
            delta.raw_batches as f64 / seconds,
            delta.raw_receptions as f64 / seconds
        );
    }
    if let (Some(cores), Some(sample)) = (cores, now.sample) {
        let _ = write!(
            line,
            "; relay {:.2} cores {} MiB, {} fds",
            cores,
            sample.rss_kib / 1024,
            sample.fds
        );
    }
    line
}

struct Summary<'a> {
    config: &'a Config,
    local: usize,
    addresses: &'a [RelayAddress],
    traffic: Option<&'a Traffic>,
    client: &'a Client,
    counts: &'a feeders::Counts,
    start: &'a Moment,
    end: &'a Moment,
    seconds: f64,
    ticks: f64,
    relay_peak_cores: f64,
}

fn summary(summary: &Summary) -> String {
    let Summary {
        config,
        local,
        addresses,
        traffic,
        client,
        counts,
        start,
        end,
        seconds,
        ticks,
        relay_peak_cores,
    } = summary;
    let seconds = seconds.max(1e-3);
    let rate = |count: u64| count as f64 / seconds;
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut row = |name: &str, value: String| rows.push((name.to_owned(), value));
    row(
        "relay",
        addresses
            .iter()
            .map(|each| each.address.clone())
            .collect::<Vec<_>>()
            .join(", "),
    );
    row(
        "feeders",
        format!(
            "{} in the run, {} here (shard {}/{}), {} started, {} failed to start",
            config.spec.feeders,
            local,
            config.shard.index,
            config.shard.count,
            counts.started.load(Ordering::Relaxed),
            counts.failed.load(Ordering::Relaxed)
        ),
    );
    if let Some(traffic) = traffic {
        let calibration = traffic.calibration;
        row(
            "simulated traffic",
            format!(
                "{:.0} receptions/s a receiver; {:.0} distinct transmissions/s, each heard by \
                 {:.1}; {:.0} distinct messages/s by their bytes",
                calibration.per_sec,
                calibration.messages_per_sec,
                calibration.receivers_per_message,
                calibration.contents_per_sec
            ),
        );
        row(
            "offered to the feeders",
            format!(
                "{:.0} receptions/s",
                rate(end.offered.saturating_sub(start.offered))
            ),
        );
    }
    if let Some(admission) = end.admission {
        row(
            "relay: feeders",
            format!(
                "{} held at the end, {} turned away (no feeder slot) since it started",
                admission.feeders, admission.refused
            ),
        );
        let before = start.admission.unwrap_or_default();
        row(
            "relay: sent",
            format!(
                "{:.1} MB/s billed, {:.1} MB/s loopback (uncapped)",
                rate(admission.billed_bytes.saturating_sub(before.billed_bytes)) / 1e6,
                rate(
                    admission
                        .loopback_bytes
                        .saturating_sub(before.loopback_bytes)
                ) / 1e6
            ),
        );
    }
    if let (Some(now), Some(before)) = (end.sample, start.sample) {
        row(
            "relay: CPU",
            format!(
                "{:.2} cores mean, {:.2} peak over a progress interval",
                now.cores_since(&before, *ticks),
                relay_peak_cores
            ),
        );
        row(
            "relay: memory",
            format!(
                "{} MiB resident at the end, {} MiB peak; {} threads, {} fds",
                now.rss_kib / 1024,
                now.peak_rss_kib / 1024,
                now.threads,
                now.fds
            ),
        );
    }
    if config.subscriber {
        let delta = end.client - start.client;
        let publishing = client
            .receivers
            .lock()
            .map_or(0, |receivers| receivers.len());
        row(
            "client: raw",
            format!(
                "{:.0} batches/s, {:.0} receptions/s, {:.2} MB/s, from {} receivers",
                rate(delta.raw_batches),
                rate(delta.raw_receptions),
                rate(delta.raw_bytes) / 1e6,
                publishing
            ),
        );
        row(
            "feeder upload",
            format!(
                "{:.0} B/s each (signed batches, before Noise framing)",
                rate(delta.raw_bytes) / (publishing.max(1)) as f64
            ),
        );
        let expected = traffic.map_or(String::new(), |traffic| {
            format!(
                " (expected about {:.0}/s: the simulation's distinct messages, by the relay's \
                 rule; where its stamps fall moves it)",
                traffic.calibration.deduplicated_per_sec
            )
        });
        row(
            "client: deduplicated",
            format!(
                "{:.1} batches/s, {:.0} receptions/s{expected}, {:.2} MB/s",
                rate(delta.dedup_batches),
                rate(delta.dedup_receptions),
                rate(delta.dedup_bytes) / 1e6
            ),
        );
        if config.streams.0 & tally_wire::Streams::RAW.0 != 0
            && config.streams.0 & tally_wire::Streams::DEDUPLICATED.0 != 0
        {
            let (heard, missing) = client.heard.coverage();
            row(
                "client: dedup coverage",
                format!(
                    "{missing} of the {heard} distinct messages read raw this window never in the \
                     deduplicated stream (0 when the relay loses none)"
                ),
            );
        }
        // A batch's time is when it was made: a feeder's seal for raw, and for the deduplicated
        // stream the end of the epoch the relay signed it for (`tally_relay::deduplicated`).
        // A provisional solution's time is its transmission's.
        for (name, histogram, since, what) in [
            ("latency: raw", &client.raw_latency, "sealed", "batches"),
            (
                "latency: deduplicated",
                &client.dedup_latency,
                "epoch end",
                "batches",
            ),
            (
                "latency: provisional",
                &client.provisional_latency,
                "transmitted",
                "solutions",
            ),
        ] {
            let histogram = histogram
                .lock()
                .map(|each| each.clone())
                .unwrap_or_default();
            let at = |quantile| {
                histogram
                    .quantile(quantile)
                    .map_or("-".to_owned(), |ms| ms.to_string())
            };
            row(
                name,
                format!(
                    "p50 {} ms, p90 {} ms, p99 {} ms, p99.9 {} ms, max {} ms ({since} to read, {} {what})",
                    at(0.5),
                    at(0.9),
                    at(0.99),
                    at(0.999),
                    histogram.max(),
                    histogram.total()
                ),
            );
        }
        if config.streams.0 & tally_wire::Streams::PROVISIONAL.0 != 0 {
            // RFC-0174 §2.4: a provisional position must reach the live world before its second
            // is sealed, `WORLD_SETTLE_MS` after the second ends.
            let settle = tally_relay::products::WORLD_SETTLE_MS;
            let histogram = client
                .provisional_latency
                .lock()
                .map(|each| each.clone())
                .unwrap_or_default();
            row(
                "client: provisional",
                format!(
                    "{} of the {} solutions read more than {settle} ms after their transmission \
                     (too late for the live world wherever its second ended first)",
                    histogram.over(settle),
                    histogram.total()
                ),
            );
        }
        row(
            "client: losses",
            format!(
                "{} batches missing from receivers' sequences, {} repeated or late, {} \
                 receptions the feeders dropped",
                delta.gaps, delta.repeats, delta.feeder_dropped
            ),
        );
        let endings = client
            .endings
            .lock()
            .map(|endings| {
                endings
                    .iter()
                    .map(|(why, count)| format!("{count}x {why}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        row(
            "client: sessions",
            format!(
                "{} sessions, {} ended this window{}",
                end.client.sessions,
                delta.disconnects,
                if endings.is_empty() {
                    String::new()
                } else {
                    format!(" (all run: {endings})")
                }
            ),
        );
        row(
            "client: own limits",
            format!(
                "{} batches skipped (its decoders behind), {} bad signatures, {} undecodable",
                delta.skipped, delta.bad_signatures, delta.undecodable
            ),
        );
    }
    if let (Some(now), Some(before)) = (end.own, start.own) {
        row(
            "harness",
            format!(
                "{:.2} cores, {} MiB resident",
                now.cores_since(&before, *ticks),
                now.rss_kib / 1024
            ),
        );
    }
    let width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let mut out = format!("\ntally-load: measured {seconds:.0} s\n");
    for (name, value) in rows {
        let _ = writeln!(out, "  {name:<width$}  {value}");
    }
    out
}
