//! What the simulated receivers hear: the MLAT simulator's receivers and aircraft (`sim`), laid
//! out as RFC-0174's world benchmark lays them (two clusters, as Europe's and the US's receivers
//! are), so one transmission is heard by every receiver in reach, as real traffic is.
//!
//! The whole run is simulated forward in time, once, as it is played: each cluster's sky is made in
//! the order its transmissions are sent (`sim::run_into_in_time_order`) on a thread of its own, a
//! few seconds ahead of the feeders (`AHEAD_S`), and a second is handed to them once the
//! simulation has passed it ([`Traffic::frames`]). So every aircraft flies on and every receiver's
//! clock runs on at its own rate for the whole run, as real ones do, and no reception is ever heard
//! twice: what the simulator repeats is what a real aircraft repeats (an all-call reply's bytes,
//! an unchanged altitude), never a whole sky.
//!
//! Before, a few seconds were simulated once and replayed in a loop, forward then backward, each
//! receiver's counter moved on by the clock error the loops would have carried. A reply heard `u`
//! into the period was heard again, byte for byte, at `2P - u`; feeders seal at their own phases of
//! the second, so near a bin's edge a forward and a backward copy of one message fell in one MLAT
//! bin, receptions 2.9 s apart as one event, and a clock fit that took the event failed (sweep 6,
//! F8 and F9). Before that, each loop replayed the period forward with every counter moved on by
//! the period exactly, so every aircraft and every free-running clock jumped at each boundary.
//!
//! The rate is set, not assumed: a first pass measures what each receiver would hear if it heard
//! every transmission in reach, and the run keeps each reception with the probability that gives
//! the rate asked for (`Spec::receptions_per_sec`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash as _, Hasher as _};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tally_mlat_solver::sim::{self, Scenario};
use tally_wire::{Clock, Frame, FrameKind, Identity, Location};

/// What to simulate.
#[derive(Clone, Debug)]
pub struct Spec {
    /// Receivers in the whole run, across every shard.
    pub feeders: usize,
    /// Each receiver's mean receptions a second.
    pub receptions_per_sec: f64,
    /// Aircraft in each cluster.
    pub aircraft: usize,
    /// Seconds of the run simulated: the ramp, the warm-up and the measured window, and some to
    /// spare (`config::parse`).
    pub seconds: u32,
    pub seed: u64,
}

/// RFC-0174's world benchmark (`world_scale_one_node` in tally-mlat-solver): receivers spread over
/// Europe and over the US, half the run in each, with their own aircraft.
const CLUSTERS: [((f64, f64), f64); 2] =
    [((50.0, 10.0), 1_500_000.0), ((39.0, -95.0), 2_000_000.0)];

/// The benchmark's one GNSS-disciplined receiver in fifty.
const GPS_EVERY: usize = 50;

/// The scenario's seconds before the run's second 0: aircraft begin within their first second or
/// two, so the scenario's second 0 is thin and the run plays from its second 1.
const SKIPPED_S: u64 = 1;

/// Seconds the simulation runs ahead of the run's clock, at most: what it holds beyond the second
/// being played, so a simulation thread that a busy host holds back for a few seconds still has
/// the next seconds ready. A second is handed out once the simulation has passed it by `SETTLED_S`.
const AHEAD_S: u64 = 8;

/// Seconds past a second the simulation must reach before that second is whole: a transmission is
/// heard up to a couple of milliseconds after it is sent, so its receptions can fall in the next
/// second while the simulation has moved on by one transmission.
const SETTLED_S: u64 = 2;

/// Seconds a played second is kept after the run's clock passes it, for a feeder that starts or
/// wakes late within the next.
const KEPT_S: u64 = 2;

/// One reception, as small as it can be held: the receiver's counter and the message's index in its
/// second's messages.
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Heard {
    stamp: u64,
    message: u32,
}

/// One simulated receiver: its identity, where it is and its clock.
pub struct Receiver {
    /// Its index in the whole run.
    pub index: usize,
    pub identity: Identity,
    pub location: Location,
    pub clock: Clock,
    /// Its cluster, and its place among this shard's receivers in that cluster.
    cluster: usize,
    slot: usize,
}

/// How the rate was met, for the run's whole population (every shard's receivers).
#[derive(Clone, Copy, Debug)]
pub struct Calibration {
    /// Receptions a second a receiver would make hearing everything in reach.
    pub in_reach_per_sec: f64,
    /// The share of those kept.
    pub probability: f64,
}

/// What the simulation made over some of the run's seconds, for its whole population.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Made {
    /// Seconds counted.
    pub seconds: u64,
    /// Receptions, by every receiver of the run.
    pub receptions: u64,
    /// Distinct transmissions heard, by anyone.
    pub transmissions: u64,
    /// Distinct messages (by their bytes: a reply an aircraft repeats unchanged is one message)
    /// heard, each second's counted in it.
    pub contents: u64,
    /// What the relay's deduplicated stream carries when it loses nothing ([`Dedup`]).
    pub deduplicated: u64,
}

impl Made {
    fn add(&mut self, other: &Self) {
        self.receptions += other.receptions;
        self.transmissions += other.transmissions;
        self.contents += other.contents;
        self.deduplicated += other.deduplicated;
    }

    /// A count a second.
    pub fn per_sec(&self, count: u64) -> f64 {
        count as f64 / self.seconds.max(1) as f64
    }
}

/// The receptions a second the relay's deduplicated stream keeps, each second's distinct messages
/// (by their bytes): the relay's rule (`tally_relay::exchange::MessageShard`), by the second. A
/// message kept in a second is remembered for that second and the `DEDUP_GENERATIONS - 1` after it,
/// so one heard every second is kept once every `DEDUP_GENERATIONS` seconds.
///
/// It is the count with each second's receptions stamped in one of the relay's seconds. The relay
/// stamps by arrival: a feeder holds a reception up to a second before its batch is sealed and its
/// second does not begin with the relay's, so one second's receptions are stamped across two or
/// three of the relay's. The stream then carries somewhat more or fewer than this; what it lost is
/// the coverage line (`subscriber::Heard`), never this rate.
#[derive(Default)]
struct Dedup {
    /// What each of the last `DEDUP_GENERATIONS - 1` seconds kept, oldest first.
    kept_before: VecDeque<HashSet<u64>>,
}

impl Dedup {
    /// The messages of the next second (by their bytes' hash) the stream keeps.
    fn keep(&mut self, second: &HashSet<u64>) -> u64 {
        const { assert!(tally_relay::seal::EPOCH_MS == 1_000) };
        let remembered = tally_relay::exchange::DEDUP_GENERATIONS - 1;
        let kept: HashSet<u64> = second
            .iter()
            .filter(|message| {
                !self
                    .kept_before
                    .iter()
                    .any(|before| before.contains(message))
            })
            .copied()
            .collect();
        let count = kept.len() as u64;
        self.kept_before.push_back(kept);
        while self.kept_before.len() > remembered {
            self.kept_before.pop_front();
        }
        count
    }
}

/// One second of one cluster: what this shard's receivers in it heard, and the messages.
#[derive(Default)]
struct Second {
    /// By the receiver's slot in its cluster; each in the order its decoder hands them over.
    heard: Vec<Vec<Heard>>,
    messages: Vec<Vec<u8>>,
}

/// A second being made, until the simulation has passed it.
struct Making {
    second: Second,
    /// The last transmission noted, and its index in `second.messages`.
    last: Option<(usize, u32)>,
    /// What everyone heard, by the bytes' hash.
    contents: HashSet<u64>,
    made: Made,
}

impl Making {
    fn new(slots: usize) -> Self {
        Self {
            second: Second {
                heard: (0..slots).map(|_| Vec::new()).collect(),
                messages: Vec::new(),
            },
            last: None,
            contents: HashSet::new(),
            made: Made::default(),
        }
    }
}

/// What one cluster's simulation has handed over.
#[derive(Default)]
struct Handed {
    /// Whole seconds, by the run's second.
    seconds: std::collections::BTreeMap<u64, Arc<Second>>,
    /// The first second not yet whole; `u64::MAX` once the simulation has ended.
    whole_to: u64,
    /// What it made, by the run's second.
    made: Vec<Made>,
}

/// The state the simulations and the feeders share.
struct Shared {
    clusters: [Mutex<Handed>; 2],
    /// Signalled whenever a cluster hands a second over, or the run's clock starts.
    handed: Condvar,
    /// The lock `handed` waits on.
    waiting: Mutex<()>,
    /// When the run's second 0 began, once it has; the simulation runs ahead of it.
    start: OnceLock<Instant>,
    /// Whether the simulation runs ahead of the run's clock by `AHEAD_S` at most (else as fast as
    /// it can).
    paced: bool,
    /// Set when the traffic is dropped: the simulations stop keeping what they make.
    stopped: AtomicBool,
}

impl Shared {
    /// Blocks a simulation about to make `second` until the run's clock is near enough to it.
    fn wait_to_make(&self, second: u64) {
        if !self.paced {
            return;
        }
        loop {
            if self.stopped.load(Ordering::Relaxed) {
                return;
            }
            let playing = self
                .start
                .get()
                .map_or(0, |start| start.elapsed().as_secs());
            if second < playing + AHEAD_S + SETTLED_S {
                return;
            }
            let Ok(guard) = self.waiting.lock() else {
                return;
            };
            let _ = self.handed.wait_timeout(guard, Duration::from_millis(100));
        }
    }

    /// The second the run's clock is in, if it has started.
    fn playing(&self) -> Option<u64> {
        self.start.get().map(|start| start.elapsed().as_secs())
    }
}

pub struct Traffic {
    pub receivers: Vec<Receiver>,
    shared: Arc<Shared>,
    /// The Unix time a GNSS-disciplined receiver's counter reads at the run's second 0, in the
    /// scenario: what `frames` moves those counters from, so they read the run's own UTC time of
    /// day.
    gps_first_unix_ms: u64,
    pub calibration: Calibration,
}

impl Drop for Traffic {
    fn drop(&mut self) {
        self.shared.stopped.store(true, Ordering::Relaxed);
        self.shared.handed.notify_all();
    }
}

/// How fast the simulation runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pace {
    /// Up to `AHEAD_S` ahead of the run's clock ([`Traffic::begin`]), holding only that.
    Run,
    /// As fast as it can, holding every second: for a test over a few seconds.
    Free,
}

/// The cluster and the index within it of each receiver of the run, and each cluster's size.
fn layout(feeders: usize) -> [usize; 2] {
    [feeders.div_ceil(2), feeders / 2]
}

fn scenario(spec: &Spec, cluster: usize, receivers: usize, duration_s: f64, p: f64) -> Scenario {
    let ((lat, lon), spread_m) = CLUSTERS[cluster];
    let adsb = spec.aircraft * 2 / 3;
    Scenario {
        duration_s,
        receivers,
        adsb_aircraft: adsb,
        modes_aircraft: spec.aircraft - adsb,
        centre: (lat, lon),
        spread_m,
        reception_probability: p,
        named: false,
        gps: (0..receivers).step_by(GPS_EVERY).collect(),
        // Seed 0 is the benchmark's: clusters 901 and 902.
        ..Scenario::new(901 + spec.seed * 2 + cluster as u64)
    }
}

/// The second of the scenario a reception's batch is sealed for: `Scenario::wall_ms` seals at the
/// end of each second, so second 0 is sealed at 1000 ms.
fn second_of(scenario: &Scenario, wall_ms: u64) -> u64 {
    let start = scenario.midnight_unix_ms + (scenario.start_tod_s * 1000.0) as u64;
    (wall_ms.saturating_sub(start) / 1000).saturating_sub(1)
}

fn content_hash(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

impl Traffic {
    /// Measures the rate, then starts simulating the run's whole population, keeping what the
    /// receivers in `local` hear.
    pub fn build(spec: &Spec, local: Range<usize>, pace: Pace) -> Result<Self, String> {
        let sizes = layout(spec.feeders);
        let total: usize = sizes.iter().sum();
        if total == 0 {
            return Err("no feeders".to_owned());
        }
        if sizes[0] >= usize::from(u16::MAX) - 1 {
            return Err(format!(
                "at most {} feeders: the simulator names a cluster's receivers by u16",
                2 * (usize::from(u16::MAX) - 2)
            ));
        }
        // Pass one: everything in reach, over second 1 (aircraft begin within their first
        // second or two, so second 0 is thin).
        let mut in_reach = 0u64;
        for (cluster, &receivers) in sizes.iter().enumerate() {
            if receivers == 0 {
                continue;
            }
            let scenario = scenario(spec, cluster, receivers, 2.0, 1.0);
            sim::run_into(&scenario, &mut |reception, _| {
                in_reach += u64::from(second_of(&scenario, reception.wall_ms) == 1);
            });
        }
        let in_reach_per_sec = in_reach as f64 / total as f64;
        if in_reach_per_sec <= 0.0 {
            return Err("the simulation heard nothing: too few aircraft or receivers".to_owned());
        }
        let probability = (spec.receptions_per_sec / in_reach_per_sec).min(1.0);
        if probability >= 1.0 {
            eprintln!(
                "tally-load: a receiver hears at most {in_reach_per_sec:.0} receptions a second \
                 with {} aircraft a cluster; raise --aircraft for {}",
                spec.aircraft, spec.receptions_per_sec
            );
        }
        let shared = Arc::new(Shared {
            clusters: [Mutex::default(), Mutex::default()],
            handed: Condvar::new(),
            waiting: Mutex::new(()),
            start: OnceLock::new(),
            paced: pace == Pace::Run,
            stopped: AtomicBool::new(false),
        });
        let duration_s = (u64::from(spec.seconds) + SKIPPED_S + SETTLED_S) as f64;
        let mut receivers: Vec<Receiver> = Vec::with_capacity(local.len());
        let mut first = 0usize;
        for (cluster, &size) in sizes.iter().enumerate() {
            let cluster_range = first..first + size;
            first += size;
            let mine = local.start.max(cluster_range.start)..local.end.min(cluster_range.end);
            if size == 0 {
                if let Ok(mut made) = shared.clusters[cluster].lock() {
                    made.whole_to = u64::MAX;
                }
                continue;
            }
            let scenario = scenario(spec, cluster, size, duration_s, probability);
            // The receivers alone (no aircraft): the sites, clocks and identities the simulation
            // gives them, which no aircraft's draws change.
            let sites = sim::run(&Scenario {
                adsb_aircraft: 0,
                modes_aircraft: 0,
                duration_s: 1.0,
                ..scenario.clone()
            });
            let mut by: HashMap<tally_wire::PublicKey, usize> = HashMap::new();
            for index in mine.clone() {
                let within = index - cluster_range.start;
                let simulated = &sites.receivers[within];
                by.insert(simulated.key, index - mine.start);
                receivers.push(Receiver {
                    index,
                    identity: sim::receiver_identity(scenario.seed, within),
                    location: simulated.site.location,
                    clock: simulated.site.clock,
                    cluster,
                    slot: index - mine.start,
                });
            }
            let shared = Arc::clone(&shared);
            let slots = mine.len();
            std::thread::Builder::new()
                .name(format!("tally-load-sim-{cluster}"))
                .spawn(move || simulate(&scenario, cluster, slots, &by, &shared))
                .map_err(|error| error.to_string())?;
        }
        let first = Scenario::new(0);
        let traffic = Self {
            receivers,
            shared,
            gps_first_unix_ms: first.midnight_unix_ms
                + (first.start_tod_s * 1000.0) as u64
                + SKIPPED_S * 1000,
            calibration: Calibration {
                in_reach_per_sec,
                probability,
            },
        };
        // The run starts with the simulation ahead of it: its first seconds made (each cluster
        // lays out its whole sky before its first reception), so no feeder waits for them.
        if pace == Pace::Run {
            traffic.wait_for(AHEAD_S - 1);
        }
        Ok(traffic)
    }

    /// Starts the run's clock at `start`: second `n` of the run is heard during the `n`-th second
    /// after it, and the simulation runs up to `AHEAD_S` ahead of it.
    pub fn begin(&self, start: Instant) {
        let _ = self.shared.start.set(start);
        self.shared.handed.notify_all();
    }

    /// The receptions `receiver` (by its place in `receivers`) makes in second `second` of the
    /// run, as its decoder would hand them over, into `into`; false (and nothing) when the
    /// simulation has not yet passed that second. A GNSS-disciplined receiver's counter is the UTC
    /// time of day, so it is moved to the run's own: second `second` of a run whose second 0 began
    /// at `start_unix_ms` reads that wall clock, as a real Radarcape's does, never the scenario's
    /// (else every model whose gauge is one dates its solutions hours from the wall clock of the
    /// batches that carried them). A second the run's clock has left long behind is gone: true,
    /// and nothing.
    pub fn frames(
        &self,
        receiver: usize,
        second: u64,
        start_unix_ms: u64,
        into: &mut Vec<Frame>,
    ) -> bool {
        let Some(receiver) = self.receivers.get(receiver) else {
            return true;
        };
        let part = {
            let Ok(made) = self.shared.clusters[receiver.cluster].lock() else {
                return true;
            };
            if second >= made.whole_to {
                return false;
            }
            match made.seconds.get(&second) {
                Some(part) => Arc::clone(part),
                None => return true,
            }
        };
        let gps = receiver.clock == Clock::RadarcapeGps;
        let Some(heard) = part.heard.get(receiver.slot) else {
            return true;
        };
        for each in heard {
            let Some(data) = part.messages.get(each.message as usize) else {
                continue;
            };
            let kind = if data.len() == FrameKind::ModeSLong.message_len() {
                FrameKind::ModeSLong
            } else {
                FrameKind::ModeSShort
            };
            let mut stamp = each.stamp;
            if gps {
                stamp = shift_time_of_day(stamp, start_unix_ms, self.gps_first_unix_ms);
            }
            if let Ok(frame) = Frame::new(kind, stamp, 128, data) {
                into.push(frame);
            }
        }
        true
    }

    /// Blocks until the simulation has passed `second` (or ended), for a test.
    pub fn wait_for(&self, second: u64) {
        for cluster in &self.shared.clusters {
            loop {
                let whole = match cluster.lock() {
                    Ok(made) => made.whole_to > second,
                    Err(_) => true,
                };
                if whole || self.shared.stopped.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(guard) = self.shared.waiting.lock() else {
                    return;
                };
                let _ = self
                    .shared
                    .handed
                    .wait_timeout(guard, Duration::from_millis(50));
            }
        }
    }

    /// What the simulation made over the run's seconds `seconds`, as far as it has made them.
    pub fn made(&self, seconds: Range<u64>) -> Made {
        let mut sum = Made::default();
        let mut made_to = 0u64;
        for cluster in &self.shared.clusters {
            let Ok(made) = cluster.lock() else {
                continue;
            };
            made_to = made_to.max(made.made.len() as u64);
            let from = usize::try_from(seconds.start).unwrap_or(usize::MAX);
            let to = usize::try_from(seconds.end).unwrap_or(usize::MAX);
            for each in made.made.get(from..to.min(made.made.len())).unwrap_or(&[]) {
                sum.add(each);
            }
        }
        sum.seconds = seconds.end.min(made_to).saturating_sub(seconds.start);
        sum
    }

    /// The first second of the run the simulation has not yet passed, of the cluster furthest
    /// behind: how far ahead of the run's clock it is.
    pub fn whole_to(&self) -> u64 {
        self.shared
            .clusters
            .iter()
            .filter_map(|cluster| cluster.lock().ok().map(|made| made.whole_to))
            .min()
            .unwrap_or(0)
    }
}

/// Runs one cluster's scenario forward in time, handing each second to the feeders once it has
/// passed it: the body of that cluster's simulation thread.
fn simulate(
    scenario: &Scenario,
    cluster: usize,
    slots: usize,
    by: &HashMap<tally_wire::PublicKey, usize>,
    shared: &Shared,
) {
    // Seconds being made, from `base`.
    let mut making: VecDeque<Making> = VecDeque::new();
    let mut base = 0u64;
    let mut dedup = Dedup::default();
    let hand = |making: &mut VecDeque<Making>, base: &mut u64, dedup: &mut Dedup, upto: u64| {
        while *base < upto {
            // A second nobody heard anything in is handed over empty.
            let mut done = making.pop_front().unwrap_or_else(|| Making::new(slots));
            done.made.contents = done.contents.len() as u64;
            done.made.deduplicated = dedup.keep(&done.contents);
            if let Ok(mut made) = shared.clusters[cluster].lock() {
                made.seconds.insert(*base, Arc::new(done.second));
                made.made.push(done.made);
                made.whole_to = *base + 1;
                if shared.paced {
                    let keep_from = shared.playing().unwrap_or(0).saturating_sub(KEPT_S);
                    made.seconds = made.seconds.split_off(&keep_from);
                }
            }
            *base += 1;
            shared.handed.notify_all();
        }
    };
    sim::run_into_in_time_order(scenario, &mut |reception, source| {
        if shared.stopped.load(Ordering::Relaxed) {
            return;
        }
        let Some(second) = second_of(scenario, reception.wall_ms).checked_sub(SKIPPED_S) else {
            return;
        };
        if second < base {
            // Past a second already handed over (by more than `SETTLED_S`): never, since a
            // reception is heard milliseconds after its transmission; dropped rather than late.
            return;
        }
        if second > base + SETTLED_S {
            hand(&mut making, &mut base, &mut dedup, second - SETTLED_S);
            shared.wait_to_make(second);
        }
        while making.len() as u64 <= second - base {
            making.push_back(Making::new(slots));
        }
        let Some(now) = making.get_mut((second - base) as usize) else {
            return;
        };
        now.made.receptions += 1;
        let message = match now.last {
            Some((last, at)) if last == source => at,
            _ => {
                now.made.transmissions += 1;
                now.contents
                    .insert(content_hash(&reception.observation.data));
                let at = now.second.messages.len() as u32;
                now.second.messages.push(reception.observation.data.clone());
                now.last = Some((source, at));
                at
            }
        };
        if let Some(&slot) = by.get(&reception.receiver)
            && let Some(heard) = now.second.heard.get_mut(slot)
        {
            heard.push(Heard {
                stamp: reception.observation.timestamp,
                message,
            });
        }
    });
    let end = base + making.len() as u64;
    hand(&mut making, &mut base, &mut dedup, end);
    if let Ok(mut made) = shared.clusters[cluster].lock() {
        made.whole_to = u64::MAX;
    }
    shared.handed.notify_all();
}

/// Nanoseconds in a UTC day.
const DAY_NANOS: i128 = 86_400 * 1_000_000_000;

/// A Radarcape GPS counter (seconds of the UTC day above 30 bits of nanoseconds) that read
/// `from_unix_ms` moved to read `to_unix_ms` instead, around the day.
pub fn shift_time_of_day(stamp: u64, to_unix_ms: u64, from_unix_ms: u64) -> u64 {
    let nanos = i128::from(stamp >> 30) * 1_000_000_000 + i128::from(stamp & ((1 << 30) - 1));
    let shift = (i128::from(to_unix_ms) - i128::from(from_unix_ms)) * 1_000_000;
    let moved = (nanos + shift).rem_euclid(DAY_NANOS);
    let (seconds, nanos) = (moved / 1_000_000_000, moved % 1_000_000_000);
    ((seconds as u64) << 30) | nanos as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(feeders: usize, receptions_per_sec: f64, seconds: u32) -> Spec {
        Spec {
            feeders,
            receptions_per_sec,
            aircraft: 300,
            seconds,
            seed: 0,
        }
    }

    /// Every frame `receiver` hears over the run's first `seconds`, each with its second.
    fn heard(traffic: &Traffic, receiver: usize, seconds: u64, start_ms: u64) -> Vec<(u64, Frame)> {
        let mut all = Vec::new();
        for second in 0..seconds {
            traffic.wait_for(second);
            let mut frames = Vec::new();
            assert!(traffic.frames(receiver, second, start_ms, &mut frames));
            all.extend(frames.into_iter().map(|frame| (second, frame)));
        }
        all
    }

    /// An airborne position (DF17, type code 11): unique bytes, its CPR and its noise.
    fn position(data: &[u8]) -> bool {
        data.len() == 14 && data[0] >> 3 == 17 && data[4] >> 3 == 11
    }

    /// F8 and F9 of sweep 6: over the whole run, no receiver hears an airborne position twice (its
    /// bytes carry the aircraft's noisy CPR, so a real one is never repeated), and a
    /// free-running receiver's counter less a GNSS receiver's, for each position both heard, lies on
    /// one line (its clock's rate) to within its jitter. Before, the period played backward made
    /// every position heard again at `2P - u`, so a receiver heard each one twice, and the clock fits
    /// MLAT ran over those copies failed.
    #[test]
    fn the_run_is_simulated_forward_and_nothing_is_heard_twice() -> Result<(), String> {
        let spec = small(120, 200.0, 16);
        let traffic = Traffic::build(&spec, 0..120, Pace::Free)?;
        let start_ms = 36_000_000;
        let seconds = u64::from(spec.seconds);
        let gps = traffic
            .receivers
            .iter()
            .position(|each| each.clock == Clock::RadarcapeGps)
            .ok_or("no GNSS receiver simulated")?;
        let reference: HashMap<Vec<u8>, f64> = heard(&traffic, gps, seconds, start_ms)
            .into_iter()
            .filter(|(_, frame)| position(frame.message()))
            .map(|(_, frame)| {
                let stamp = frame.timestamp();
                let read = (stamp >> 30) as f64 + (stamp & ((1 << 30) - 1)) as f64 * 1e-9;
                (frame.message().to_vec(), read)
            })
            .collect();
        let mut positions = 0usize;
        let mut lined = 0usize;
        for receiver in 0..traffic.receivers.len() {
            let all = heard(&traffic, receiver, seconds, start_ms);
            let mut seen: HashSet<&[u8]> = HashSet::new();
            for (second, frame) in &all {
                if position(frame.message()) {
                    assert!(
                        seen.insert(frame.message()),
                        "receiver {receiver} heard one position twice (second {second})"
                    );
                    positions += 1;
                }
            }
            if traffic.receivers[receiver].clock == Clock::RadarcapeGps {
                continue;
            }
            // Its counter against the GNSS receiver's time for each position both heard.
            let pairs: Vec<(f64, f64)> = all
                .iter()
                .filter_map(|(_, frame)| {
                    let true_s = *reference.get(frame.message())?;
                    Some((true_s, frame.timestamp() as f64 / 12e6 - true_s))
                })
                .collect();
            if pairs.len() < 40 {
                continue;
            }
            let n = pairs.len() as f64;
            let (mx, my) = pairs
                .iter()
                .fold((0.0, 0.0), |(x, y), (a, b)| (x + a / n, y + b / n));
            let (sxy, sxx) = pairs.iter().fold((0.0, 0.0), |(xy, xx), (a, b)| {
                (xy + (a - mx) * (b - my), xx + (a - mx) * (a - mx))
            });
            let slope = sxy / sxx;
            // The two paths differ by at most the clusters' spread over light (some 7 ms), and
            // change smoothly; a replayed sky or a counter put back jumps by seconds.
            let worst = pairs
                .iter()
                .map(|(a, b)| (b - my - slope * (a - mx)).abs())
                .fold(0.0, f64::max);
            assert!(
                worst < 0.01,
                "receiver {receiver}: {:.1} ms off its clock's line over {} shared positions",
                worst * 1e3,
                pairs.len()
            );
            lined += 1;
        }
        assert!(positions > 1_000, "{positions}");
        assert!(
            lined >= 5,
            "only {lined} receivers shared enough with the GNSS one"
        );
        Ok(())
    }

    #[test]
    fn a_gps_counter_reads_the_runs_time_of_day() {
        // 12:00:00.5 in the scenario, played in a run whose second 0 began at 06:54:57.25 UTC
        // the scenario day's next day: it reads 06:54:57.75.
        let day_ms = 86_400_000u64;
        let scenario_ms = 20 * day_ms + 43_200_000;
        let stamp = (43_200 << 30) | 500_000_000;
        let run_ms = 21 * day_ms + 24_897_250;
        assert_eq!(
            shift_time_of_day(stamp, run_ms, scenario_ms),
            (24_897 << 30) | 750_000_000
        );
        // Earlier in the day than the scenario's: around midnight, never negative.
        let stamp = (10 << 30) | 1;
        assert_eq!(
            shift_time_of_day(stamp, scenario_ms - 20_000, scenario_ms),
            ((86_390) << 30) | 1
        );
    }

    #[test]
    fn played_frames_of_a_gps_receiver_read_the_wall_clock() -> Result<(), String> {
        let spec = small(120, 20.0, 8);
        let traffic = Traffic::build(&spec, 0..120, Pace::Free)?;
        let gps = traffic
            .receivers
            .iter()
            .position(|each| each.clock == Clock::RadarcapeGps)
            .ok_or("no GNSS receiver simulated")?;
        let start_ms = 1_791_528_897_000u64;
        for second in [0u64, 4, 7] {
            traffic.wait_for(second);
            let mut frames = Vec::new();
            assert!(traffic.frames(gps, second, start_ms, &mut frames));
            assert!(!frames.is_empty());
            let second_of_day = (start_ms / 1000 + second) % 86_400;
            for frame in &frames {
                let read = frame.timestamp() >> 30;
                // Within the second it is played in, give or take the simulated clock's error.
                assert!(
                    read == second_of_day || read + 1 == second_of_day || read == second_of_day + 1,
                    "second {second}: read {read}, wall {second_of_day}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn the_rate_asked_for_is_the_rate_simulated_and_shards_see_one_world() -> Result<(), String> {
        let spec = small(400, 20.0, 6);
        let whole = Traffic::build(&spec, 0..400, Pace::Free)?;
        assert_eq!(whole.receivers.len(), 400);
        whole.wait_for(u64::from(spec.seconds));
        let made = whole.made(0..u64::from(spec.seconds));
        let per_sec = made.per_sec(made.receptions) / 400.0;
        assert!((per_sec - 20.0).abs() < 5.0, "{made:?}");
        assert!(made.receptions > made.transmissions, "{made:?}");
        assert!(made.deduplicated <= made.contents, "{made:?}");
        // A shard holds exactly the whole run's receivers in its slice, hearing the same.
        let shard = Traffic::build(&spec, 185..215, Pace::Free)?;
        assert_eq!(shard.receivers.len(), 30);
        for second in [1u64, 4] {
            shard.wait_for(second);
            for (mine, theirs) in shard.receivers.iter().zip(&whole.receivers[185..215]) {
                assert_eq!(mine.index, theirs.index);
                assert_eq!(mine.identity.public(), theirs.identity.public());
                let (mut a, mut b) = (Vec::new(), Vec::new());
                assert!(shard.frames(mine.index - 185, second, 0, &mut a));
                assert!(whole.frames(theirs.index, second, 0, &mut b));
                assert_eq!(a, b);
            }
        }
        Ok(())
    }

    /// Paced, the simulation holds a few seconds ahead of the run's clock and no more: it has not
    /// made the run's tenth second while the clock is in its first.
    #[test]
    fn paced_the_simulation_runs_a_few_seconds_ahead() -> Result<(), String> {
        let spec = small(60, 20.0, 30);
        let traffic = Traffic::build(&spec, 0..60, Pace::Run)?;
        traffic.begin(Instant::now());
        traffic.wait_for(AHEAD_S - 1);
        std::thread::sleep(Duration::from_millis(300));
        let ahead = traffic.whole_to();
        assert!(ahead >= AHEAD_S - 1, "{ahead}");
        assert!(ahead <= AHEAD_S + SETTLED_S + 2, "{ahead}");
        let mut frames = Vec::new();
        assert!(!traffic.frames(0, ahead + 3, 0, &mut frames));
        assert!(frames.is_empty());
        Ok(())
    }

    /// The deduplicated stream's rule: a message heard every second is kept once every
    /// `DEDUP_GENERATIONS` seconds.
    #[test]
    fn the_dedup_rule_keeps_a_repeated_message_once_a_window() {
        let mut dedup = Dedup::default();
        let every: HashSet<u64> = [7].into_iter().collect();
        let kept: u64 = (0..30).map(|_| dedup.keep(&every)).sum();
        assert_eq!(kept, 30 / tally_relay::exchange::DEDUP_GENERATIONS as u64);
    }
}
