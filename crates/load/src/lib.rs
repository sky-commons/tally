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
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tally_wire::RelayAddress;

use crate::config::{Config, Relay};
use crate::relay::{Admission, Sample};
use crate::subscriber::{Client, Snapshot};
use crate::traffic::Traffic;

/// How much nicer than the instruments the feeders run (`lower_priority`).
const FEEDERS_NICE: libc::c_int = 5;

/// Lowers the calling thread's priority below the harness's other threads: the simulation that
/// makes the sky, the client that reads the relay and its decoders are the instruments, and when
/// thousands of feeders ask for more cores than there are, the instruments must still get theirs
/// (a client that cannot keep up is dropped by the relay as too slow, a simulation that falls
/// behind starves the feeders it feeds), while a feeder that waits only delays its own batch.
/// Run on each of the feeders' runtime threads as it starts. Failing, it leaves the thread as it is.
pub fn lower_priority() {
    // SAFETY: `gettid` and `setpriority` take and touch no memory of ours.
    unsafe {
        let _ = libc::setpriority(
            libc::PRIO_PROCESS,
            libc::gettid() as libc::id_t,
            FEEDERS_NICE,
        );
    }
}

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
        needed = needed.max(2 * config.spec.feeders * config.replay + 1024);
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

/// What the simulation made, a line of the summary.
fn made_line(made: &traffic::Made, feeders: usize) -> String {
    format!(
        "{:.0} receptions/s a receiver; {:.0} distinct transmissions/s, each heard by {:.1}; {:.0} \
         distinct messages/s by their bytes",
        made.per_sec(made.receptions) / feeders.max(1) as f64,
        made.per_sec(made.transmissions),
        made.receptions as f64 / made.transmissions.max(1) as f64,
        made.per_sec(made.contents)
    )
}

/// What one sample of the run saw.
struct Moment {
    sample: Option<Sample>,
    own: Option<Sample>,
    client: Snapshot,
    admission: Option<Admission>,
    /// The hosted MLAT's clock fits, where the relay hosts it (`relay::fits`).
    fits: Option<relay::Fits>,
    /// What the relay's base and stores are charged (`relay::charged`).
    charged: Option<relay::Charged>,
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
            fits: self
                .stats
                .as_deref()
                .and_then(|stats| relay::fits(stats).ok()),
            charged: self
                .stats
                .as_deref()
                .and_then(|stats| relay::charged(stats).ok()),
            offered: self.counts.offered.load(Ordering::Relaxed),
        }
    }
}

/// Runs the harness as configured and returns its summary table.
pub async fn run(config: Config) -> Result<String, String> {
    let range = config.shard.range(config.spec.feeders);
    let local = if config.run_feeders {
        range.len() * config.replay
    } else {
        0
    };
    let (addresses, pid, stats, mut spawned) = match &config.relay {
        Relay::Existing {
            addresses,
            pid,
            stats,
        } => (addresses.clone(), *pid, stats.clone(), None),
        Relay::Spawn(_) => (Vec::new(), None, None, None),
    };
    if !config.simulate_only {
        check_host(
            &config,
            local,
            addresses.len().max(1),
            matches!(config.relay, Relay::Spawn(_)),
        )?;
    }
    let started = Instant::now();
    let traffic = if config.run_feeders {
        let local_range = range.clone();
        eprintln!(
            "tally-load: simulating {} receivers ({} here), {} aircraft a cluster, {} s forward \
             in time as the run plays",
            config.spec.feeders,
            local_range.len(),
            config.spec.aircraft,
            config.spec.seconds
        );
        let spec = config.spec.clone();
        let subscriber = config.subscriber || config.simulate_only;
        // On a thread of its own, not the runtime's blocking pool: the simulation's threads
        // inherit this one's priority, and the runtime's are the feeders' (`lower_priority`).
        let (made, built) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("tally-load-build".to_owned())
            .spawn(move || {
                // Only the process with the subscriber counts what the whole run hears (its
                // expectations); a feeders-only shard makes its own receivers' share.
                let _ = made.send(Traffic::build_for(
                    &spec,
                    local_range,
                    traffic::Pace::Run,
                    subscriber,
                ));
            })
            .map_err(|error| error.to_string())?;
        let built = built.await.map_err(|error| error.to_string())??;
        let calibration = built.calibration;
        eprintln!(
            "tally-load: measured in {:.1} s: a receiver hears {:.0} receptions a second in \
             reach, kept at {:.3}",
            started.elapsed().as_secs_f64(),
            calibration.in_reach_per_sec,
            calibration.probability,
        );
        if config.simulate_only {
            // The run's first seconds, as they are made.
            built.begin(Instant::now());
            let seconds = 5;
            built.wait_for(seconds - 1);
            let made = built.made(0..seconds);
            let own = Sample::read(None)?;
            return Ok(format!(
                "tally-load: simulated only; over the first {seconds} s {}; this process holds {} \
                 MiB",
                made_line(&made, config.spec.feeders),
                own.rss_kib / 1024
            ));
        }
        Some(Arc::new(built))
    } else {
        None
    };
    let (addresses, pid, stats) = match &config.relay {
        Relay::Spawn(how) => {
            let relay = relay::spawn(how, config.spec.feeders * config.replay, &config.state_dir)?;
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
        subscriber::start(
            addresses[0].clone(),
            config.streams,
            config.verify,
            config.decode_threads,
            config.client_sample,
            Arc::clone(&client),
        );
    }
    let counts = Arc::new(feeders::Counts::default());
    if let Some(traffic) = &traffic {
        feeders::spawn(
            feeders::Run {
                traffic: Arc::clone(traffic),
                relays: addresses.clone(),
                ceiling: config.ceiling,
                ramp: config.ramp,
                state_dir: config.state_dir.clone(),
                networks: config.networks,
                replay: config.replay,
                seed: config.spec.seed,
                deflate: config.deflate_level,
            },
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
    // The most its base and stores were charged so far, and the most the relay was resident beyond
    // that and the headroom for it at any sample (F3 of sweep 6): (beyond, resident, peak charged).
    let mut peak_charged = 0u64;
    let mut beyond: Option<(i64, u64, u64)> = None;
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
        if let (Some(sample), Some(charged)) = (&now.sample, now.charged) {
            peak_charged = peak_charged.max(charged.total());
            let rss = sample.rss_kib * 1024;
            let over = rss as i64 - relay::resident_allowed(peak_charged) as i64;
            if beyond.is_none_or(|(most, _, _)| over > most) {
                beyond = Some((over, rss, peak_charged));
            }
        }
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
    // A relay named by its pid that cannot be read at the end is gone: no summary of it is one.
    if let (Some(pid), None) = (watch.pid, &end.sample) {
        return Err(format!(
            "the relay (pid {pid}) could not be read at the end: it has gone"
        ));
    }
    let window_start = at.duration_since(begin);
    // The run's clock is the feeders' (`feeders::spawn`), started just before `begin`.
    let run_second = |since_begin: Duration| since_begin.as_secs();
    let seconds = at.elapsed().as_secs_f64();
    let fit = match (&end.sample, watch.stats.as_deref()) {
        (Some(sample), Some(stats)) => Some(relay::Fit {
            peak_bytes: sample.peak_rss_kib * 1024,
            budget_bytes: relay::budget(stats)?,
            headroom_bytes: tally_relay::budget::headroom_for(
                usize::try_from(relay::budget(stats)?).unwrap_or(usize::MAX),
            ) as u64,
        }),
        _ => None,
    };
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
        measured: run_second(window_start)..run_second(begin.elapsed()),
        ticks: watch.ticks,
        relay_peak_cores,
        fit,
        beyond,
    });
    let _ = std::fs::remove_dir_all(config.state_dir.join("feeders"));
    drop(spawned);
    // F3 of sweep 6: the relay's peak resident memory is held to its budget and the headroom it
    // keeps below the memory it runs in, whatever the allocator keeps; past them a relay sized
    // for its load is throttled or killed.
    if let Some((over, _, _)) = beyond
        && over > 0
    {
        return Err(format!(
            "{table}\nthe relay was resident {} MiB beyond the most its base and stores were \
             charged and the headroom for them (`budget::headroom_for`)",
            over >> 20
        ));
    }
    match fit {
        Some(fit) if !fit.within() => Err(format!(
            "{table}\nthe relay's peak resident memory, {} MiB, passed its budget ({} MiB) and \
             headroom ({} MiB) by {} MiB",
            fit.peak_bytes >> 20,
            fit.budget_bytes >> 20,
            fit.headroom_bytes >> 20,
            (fit.peak_bytes - fit.budget_bytes - fit.headroom_bytes) >> 20
        )),
        _ => Ok(table),
    }
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
        "; offered {:.0}/s ({} waits for the simulation)",
        now.offered.saturating_sub(before.offered) as f64 / seconds,
        counts.behind.load(Ordering::Relaxed)
    );
    if watch.client.connected.load(Ordering::Relaxed) || delta.raw_batches > 0 {
        let _ = write!(
            line,
            "; client {:.0} batches/s {:.0} receptions/s, raw at most {} ms",
            delta.raw_batches as f64 / seconds,
            delta.raw_receptions as f64 / seconds,
            watch.client.raw_max_since_ms.swap(0, Ordering::Relaxed)
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
    /// The run's seconds measured, for what the simulation made over them.
    measured: Range<u64>,
    ticks: f64,
    relay_peak_cores: f64,
    /// The relay's peak resident memory beside its budget and headroom, where it can be read.
    fit: Option<relay::Fit>,
    beyond: Option<(i64, u64, u64)>,
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
        measured,
        ticks,
        relay_peak_cores,
        fit,
        beyond,
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
        row(
            "simulated traffic",
            made_line(&traffic.made(measured.clone()), config.spec.feeders),
        );
        row(
            "offered to the feeders",
            format!(
                "{:.0} receptions/s",
                rate(end.offered.saturating_sub(start.offered))
            ),
        );
        row(
            "simulation",
            format!(
                "{} times a feeder waited for its second to be simulated (0 when the simulation \
                 keeps ahead of the run)",
                counts.behind.load(Ordering::Relaxed)
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
    if let (Some(now), Some(before)) = (&end.fits, &start.fits)
        && now.steps > 0
    {
        // `fits` counts every fit tried, the failed among them (`relay::Fits::failed_since`).
        row(
            "relay: MLAT clock fits",
            format!(
                "{} tried, {} fitted, {} failed this window ({}), {} clocks dropped as cut off, \
                 over {} window steps; the last failure: {}",
                now.fits.saturating_sub(before.fits),
                now.fitted_since(before),
                now.unfitted.saturating_sub(before.unfitted),
                now.failed_since(before)
                    .map_or("none tried".to_owned(), |share| format!(
                        "{:.1}% failed",
                        share * 100.0
                    )),
                now.disconnected.saturating_sub(before.disconnected),
                now.steps.saturating_sub(before.steps),
                now.reason.as_deref().unwrap_or("none")
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
    if let Some((over, rss, peak)) = beyond {
        row(
            "relay: beyond its plan",
            format!(
                "at its worst sample {} MiB resident, its base and stores charged at most {} MiB \
                 so far, which with their headroom allow {} MiB: {}",
                rss >> 20,
                peak >> 20,
                relay::resident_allowed(*peak) >> 20,
                if *over <= 0 { "within" } else { "OVER" }
            ),
        );
    }
    if let Some(fit) = fit {
        row(
            "relay: peak vs budget",
            format!(
                "{} MiB peak resident, budget {} MiB, {} MiB past it of the {} MiB headroom: {}",
                fit.peak_bytes >> 20,
                fit.budget_bytes >> 20,
                fit.over_budget() >> 20,
                fit.headroom_bytes >> 20,
                if fit.within() { "within" } else { "OVER" }
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
            let made = traffic.made(measured.clone());
            format!(
                " (expected about {:.0}/s: the simulation's distinct messages, by the relay's \
                 rule; where its stamps fall moves it)",
                made.per_sec(made.deduplicated)
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
        // A provisional solution's time is its transmission's, and its latency is split at the
        // stamp of the relay's step that solved it (`subscriber::Client::provisional`): what the
        // relay's lateness budget does not see (the feeder's batching, ingest, the watermark),
        // then what it does.
        for (name, stream, histogram, span, what) in [
            (
                "latency: raw",
                tally_wire::Streams::RAW,
                &client.raw_latency,
                "sealed to read",
                "batches",
            ),
            (
                "latency: deduplicated",
                tally_wire::Streams::DEDUPLICATED,
                &client.dedup_latency,
                "epoch end to read",
                "batches",
            ),
            (
                "latency: provisional",
                tally_wire::Streams::PROVISIONAL,
                &client.provisional_latency,
                "transmitted to read",
                "solutions",
            ),
            (
                "  to its step's stamp",
                tally_wire::Streams::PROVISIONAL,
                &client.provisional_to_stamp,
                "transmitted to the stamp of the relay's step that solved it",
                "solutions",
            ),
            (
                "  from its step's stamp",
                tally_wire::Streams::PROVISIONAL,
                &client.provisional_from_stamp,
                "that stamp to read",
                "solutions",
            ),
        ] {
            // A stream not asked for has no latency, not an empty one: a row of "0 solutions"
            // read as a relay that published none.
            if config.streams.0 & stream.0 == 0 {
                row(name, "not asked for (--streams)".to_owned());
                continue;
            }
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
                    "p50 {} ms, p90 {} ms, p99 {} ms, p99.9 {} ms, max {} ms ({span}, {} {what})",
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
            let delta = end.client - start.client;
            row(
                "client: provisional",
                format!(
                    "{} of the {} solutions read more than {settle} ms after their transmission \
                     (too late for the live world wherever its second ended first); {} dated \
                     after their step's stamp (a free-running gauge dates a transmission by the \
                     seal of the batch that anchored its model, up to a second late)",
                    histogram.over(settle),
                    histogram.total(),
                    delta.provisional_after_stamp
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
