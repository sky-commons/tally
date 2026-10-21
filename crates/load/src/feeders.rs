//! The simulated feeders: each one is `tally_feed::start`, the feeder itself (its relay directory,
//! probes, choice of relays, Noise sessions, rate limits, signed chained batches sealed every
//! second), with the simulator in place of readsb. They share one runtime, so thousands run in one
//! process; they start evenly over the ramp.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tally_feed::config::{Config, Key};
use tally_wire::RelayAddress;

use crate::traffic::Traffic;

/// A decoder hands its receptions over as they come; this many times a second here.
const SLICES_A_SECOND: u64 = 10;

/// What the feeders did, counted as they run.
#[derive(Default)]
pub struct Counts {
    /// Feeders started.
    pub started: AtomicUsize,
    /// Feeders that could not start (their error is printed).
    pub failed: AtomicUsize,
    /// Receptions handed to the feeders' batchers.
    pub offered: AtomicU64,
    /// Times a feeder found the second it was to hear not yet simulated, and waited: zero when the
    /// simulation keeps ahead of the run.
    pub behind: AtomicU64,
}

/// What the feeders play and where they connect from (`spawn`).
pub struct Run {
    pub traffic: Arc<Traffic>,
    pub relays: Vec<RelayAddress>,
    pub ceiling: u32,
    pub ramp: Duration,
    pub state_dir: std::path::PathBuf,
    pub networks: crate::config::Networks,
    /// Feeders playing each simulated receiver (`--replay`).
    pub replay: usize,
    /// The simulation's seed, from which the identities of the replaying feeders are made.
    pub seed: u64,
    /// The DEFLATE level the feeders compress at (`None`: the wire's own).
    pub deflate: Option<u8>,
}

/// Starts this shard's feeders, the `i`-th of them after `ramp * i / n`, each publishing to one of
/// `relays` (by its index in the run, so every address takes its share). Every feeder plays the
/// simulation on one clock, from `start`: second `n` of the run is heard by every receiver in it
/// during the same second, as one transmission is heard by every receiver in reach at once, and the
/// simulation makes the run's seconds a few ahead of that clock. A feeder that starts later joins
/// the second being heard.
pub fn spawn(run: Run, counts: Arc<Counts>, start: tokio::time::Instant) {
    let Run {
        traffic,
        relays,
        ceiling,
        ramp,
        state_dir,
        networks,
        replay,
        seed,
        deflate,
    } = run;
    let relays = relays.as_slice();
    let state_dir = state_dir.as_path();
    let local = (traffic.receivers.len().max(1) * replay.max(1)) as u32;
    // The wall clock of `start`, which a GNSS-disciplined receiver's counter reads (`frames`).
    let start_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
        .saturating_sub(start.elapsed().as_millis() as u64);
    // The simulation runs a few seconds ahead of this clock (`Traffic::begin`).
    traffic.begin(start.into_std());
    // A feeder on a relay at a loopback address connects from one of its own (`Networks`).
    let loopback = relays.iter().all(|relay| {
        relay.address.rsplit_once(':').is_some_and(|(host, _)| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    });
    // Each simulated receiver is played by `replay` feeders (`--replay`): the first with its own
    // identity, the others with identities of their own that hear what it hears, so a run of more
    // feeders than the simulation can make traffic for in real time still has each feeder send
    // signed, chained batches of its own.
    let each: Vec<(usize, usize)> = (0..replay.max(1))
        .flat_map(|round| (0..traffic.receivers.len()).map(move |at| (round, at)))
        .collect();
    for (round, at) in each {
        let receiver = &traffic.receivers[at];
        let index = round * traffic.receivers.len() + at;
        let relay = relays[index % relays.len()].clone();
        let config = Config {
            // Never read: the identity is handed over (`tally_feed::start`).
            key: Key::File(state_dir.join("unused")),
            source: String::new(),
            uat: None,
            acars: Vec::new(),
            acars_ceiling: tally_feed::source::DEFAULT_ACARS_CEILING,
            relays: vec![relay],
            seeds: Vec::new(),
            state_dir: state_dir.join("feeders").join(index.to_string()),
            location: Some(receiver.location),
            clock: receiver.clock,
            ceiling,
            source_address: networks.source_address(index, loopback),
            deflate_level: deflate,
        };
        let identity = if round == 0 {
            receiver.identity.clone()
        } else {
            tally_mlat_solver::sim::receiver_identity(
                seed.wrapping_add((round as u64).wrapping_mul(1_000_003)),
                receiver.index,
            )
        };
        let traffic = Arc::clone(&traffic);
        let counts = Arc::clone(&counts);
        let wait = ramp.mul_f64(f64::from(at as u32) / f64::from(local));
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            let (inputs, batching) = match tally_feed::start(identity, &config) {
                Ok(started) => started,
                Err(error) => {
                    eprintln!(
                        "tally-load: feeder {}: {error}",
                        traffic.receivers[at].index
                    );
                    counts.failed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            tokio::spawn(batching);
            counts.started.fetch_add(1, Ordering::Relaxed);
            let mut slices = tokio::time::interval(Duration::from_millis(1000 / SLICES_A_SECOND));
            slices.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut second = u64::MAX;
            let mut frames = Vec::new();
            let mut handed = 0;
            loop {
                slices.tick().await;
                let elapsed = start.elapsed();
                let now = elapsed.as_secs();
                if now != second {
                    // What was left of the last second goes with it; a receiver never holds one back.
                    inputs.offer_frames(frames[handed..].to_vec());
                    counts
                        .offered
                        .fetch_add(frames.len() as u64, Ordering::Relaxed);
                    frames.clear();
                    handed = 0;
                    if !traffic.frames(at, now, start_unix_ms, &mut frames) {
                        // Not yet simulated: tried again at the next slice.
                        counts.behind.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    second = now;
                }
                // The share of this second's receptions due by now.
                let tenth = u64::from(elapsed.subsec_millis()) * SLICES_A_SECOND / 1000 + 1;
                let due = (frames.len() as u64 * tenth / SLICES_A_SECOND) as usize;
                inputs.offer_frames(frames[handed..due.max(handed)].to_vec());
                handed = due.max(handed);
            }
        });
    }
}
