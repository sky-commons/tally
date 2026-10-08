//! The simulated feeders: each one is `tally_feed::start`, the feeder itself (its relay directory,
//! probes, choice of relays, Noise sessions, rate limits, signed chained batches sealed every
//! second), with the simulator in place of readsb. They share one runtime, so thousands run in one
//! process; they start evenly over the ramp.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tally_feed::config::Config;
use tally_feed::source::Input;
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
}

/// Starts this shard's feeders, the `i`-th of them after `ramp * i / n`, each publishing to one of
/// `relays` (by its index in the run, so every address takes its share). Every feeder plays the
/// simulation on one clock, from `start`: second `n` of the run is heard by every receiver in it
/// during the same second, as one transmission is heard by every receiver in reach at once. A
/// feeder that starts later joins the second being heard.
pub fn spawn(
    traffic: Arc<Traffic>,
    relays: &[RelayAddress],
    ceiling: u32,
    ramp: Duration,
    state_dir: &Path,
    counts: Arc<Counts>,
    start: tokio::time::Instant,
) {
    let local = traffic.receivers.len().max(1) as u32;
    for (at, receiver) in traffic.receivers.iter().enumerate() {
        let relay = relays[receiver.index % relays.len()].clone();
        let config = Config {
            // Never read: the identity is handed over (`tally_feed::start`).
            key_file: state_dir.join("unused"),
            source: String::new(),
            uat: None,
            relays: vec![relay],
            seeds: Vec::new(),
            state_dir: state_dir.join("feeders").join(receiver.index.to_string()),
            location: Some(receiver.location),
            clock: receiver.clock,
            ceiling,
        };
        let identity = receiver.identity.clone();
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
                    for frame in &frames[handed..] {
                        inputs.offer(Input::Frame(*frame));
                    }
                    counts
                        .offered
                        .fetch_add(frames.len() as u64, Ordering::Relaxed);
                    frames.clear();
                    traffic.frames(at, now, &mut frames);
                    second = now;
                    handed = 0;
                }
                // The share of this second's receptions due by now.
                let tenth = u64::from(elapsed.subsec_millis()) * SLICES_A_SECOND / 1000 + 1;
                let due = (frames.len() as u64 * tenth / SLICES_A_SECOND) as usize;
                for frame in &frames[handed..due.max(handed)] {
                    inputs.offer(Input::Frame(*frame));
                }
                handed = due.max(handed);
            }
        });
    }
}
