//! What the simulated receivers hear: the MLAT simulator's receivers and aircraft (`sim`), laid
//! out as RFC-0174's world benchmark lays them (two clusters, as Europe's and the US's receivers
//! are), so one transmission is heard by every receiver in reach, as real traffic is. A few seconds
//! are simulated once and replayed in a loop, each loop's counters moved on by the loop's length.
//!
//! The rate is set, not assumed: a first pass measures what each receiver would hear if it heard
//! every transmission in reach, and the second keeps each reception with the probability that
//! gives the rate asked for (`Spec::receptions_per_sec`).

use std::ops::Range;

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
    /// Seconds simulated, replayed in a loop.
    pub period_s: u32,
    pub seed: u64,
}

/// RFC-0174's world benchmark (`world_scale_one_node` in tally-mlat-solver): receivers spread over
/// Europe and over the US, half the run in each, with their own aircraft.
const CLUSTERS: [((f64, f64), f64); 2] =
    [((50.0, 10.0), 1_500_000.0), ((39.0, -95.0), 2_000_000.0)];

/// The benchmark's one GNSS-disciplined receiver in fifty.
const GPS_EVERY: usize = 50;

/// What a receiver's 48-bit counter wraps at (BEAST's timestamp).
const COUNTER_MASK: u64 = (1 << 48) - 1;

/// A 12 MHz counter's ticks a second.
const TICKS_A_SECOND: u64 = 12_000_000;

/// Bits of a stored reception's key that hold the message's index; the rest hold its second.
const MESSAGE_BITS: u32 = 27;

/// One reception, as small as it can be held: the receiver's counter, and the message's index in
/// `Traffic::messages` under the second of the period it was heard in (top bits).
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Heard {
    stamp: u64,
    key: u32,
}

/// One simulated receiver: its identity, where it is, its clock, and what it hears each second.
pub struct Receiver {
    /// Its index in the whole run.
    pub index: usize,
    pub identity: Identity,
    pub location: Location,
    pub clock: Clock,
    heard: Vec<Heard>,
    /// Where each second's receptions begin in `heard`; one more than the period, for the end.
    seconds: Vec<u32>,
}

/// How the rate was met, for the run's whole population (every shard's receivers).
#[derive(Clone, Copy, Debug)]
pub struct Calibration {
    /// Receptions a second a receiver would make hearing everything in reach.
    pub in_reach_per_sec: f64,
    /// The share of those kept.
    pub probability: f64,
    /// Receptions a second a receiver makes, as simulated.
    pub per_sec: f64,
    /// Distinct transmissions heard a second, by anyone: the deduplicated stream's messages.
    pub messages_per_sec: f64,
    /// Receivers that heard each of them, on average.
    pub receivers_per_message: f64,
}

pub struct Traffic {
    pub receivers: Vec<Receiver>,
    messages: Vec<Vec<u8>>,
    period_s: u32,
    pub calibration: Calibration,
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

impl Traffic {
    /// Simulates the run's whole population and keeps what the receivers in `local` hear.
    pub fn build(spec: &Spec, local: Range<usize>) -> Result<Self, String> {
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
        // Pass two: the period, one second either side, each reception kept with `probability`.
        let period = u64::from(spec.period_s);
        let mut receivers: Vec<Receiver> = Vec::with_capacity(local.len());
        let mut messages: Vec<Vec<u8>> = Vec::new();
        let (mut kept, mut distinct) = (0u64, 0u64);
        let mut first = 0usize;
        for (cluster, &size) in sizes.iter().enumerate() {
            let cluster_range = first..first + size;
            first += size;
            if size == 0 {
                continue;
            }
            let scenario = scenario(spec, cluster, size, (period + 2) as f64, probability);
            let mine = local.start.max(cluster_range.start)..local.end.min(cluster_range.end);
            let offset = messages.len();
            let mut heard: Vec<Vec<Heard>> = (0..mine.len()).map(|_| Vec::new()).collect();
            let by: std::collections::HashMap<tally_wire::PublicKey, usize> = mine
                .clone()
                .map(|index| {
                    let key =
                        sim::receiver_identity(scenario.seed, index - cluster_range.start).public();
                    (key, index - mine.start)
                })
                .collect();
            let mut used: Vec<bool> = Vec::new();
            let mut overflow = false;
            let simulation = sim::run_into(&scenario, &mut |reception, source| {
                let second = second_of(&scenario, reception.wall_ms);
                if second == 0 || second > period {
                    return;
                }
                kept += 1;
                if used.len() <= source {
                    used.resize(source + 1, false);
                }
                if !used[source] {
                    used[source] = true;
                    distinct += 1;
                }
                let Some(&at) = by.get(&reception.receiver) else {
                    return;
                };
                let message = offset + source;
                if message >= 1 << MESSAGE_BITS {
                    overflow = true;
                    return;
                }
                let key = ((second - 1) as u32) << MESSAGE_BITS | message as u32;
                heard[at].push(Heard {
                    stamp: reception.observation.timestamp,
                    key,
                });
            });
            if overflow {
                return Err("too many transmissions to index: lower --aircraft or --period".into());
            }
            messages.extend(simulation.transmissions.into_iter().map(|each| each.data));
            for (at, mut list) in heard.into_iter().enumerate() {
                let index = mine.start + at;
                let within = index - cluster_range.start;
                let site = simulation.receivers[within].site;
                list.sort_unstable_by_key(|each| ({ each.key } >> MESSAGE_BITS, { each.stamp }));
                let mut seconds = Vec::with_capacity(spec.period_s as usize + 1);
                let mut at_second = 0;
                for second in 0..=spec.period_s {
                    while at_second < list.len()
                        && ({ list[at_second].key } >> MESSAGE_BITS) < second
                    {
                        at_second += 1;
                    }
                    seconds.push(at_second as u32);
                }
                list.shrink_to_fit();
                receivers.push(Receiver {
                    index,
                    identity: sim::receiver_identity(scenario.seed, within),
                    location: site.location,
                    clock: site.clock,
                    heard: list,
                    seconds,
                });
            }
        }
        let seconds = (total as u64 * period) as f64;
        Ok(Self {
            receivers,
            messages,
            period_s: spec.period_s,
            calibration: Calibration {
                in_reach_per_sec,
                probability,
                per_sec: kept as f64 / seconds,
                messages_per_sec: distinct as f64 / period as f64,
                receivers_per_message: kept as f64 / distinct.max(1) as f64,
            },
        })
    }

    /// The receptions `receiver` (by its place in `receivers`) makes in second `second` of the
    /// run, as its decoder would hand them over, the counters moved on by the loops before it.
    pub fn frames(&self, receiver: usize, second: u64, into: &mut Vec<Frame>) {
        let Some(receiver) = self.receivers.get(receiver) else {
            return;
        };
        let period = u64::from(self.period_s);
        let within = (second % period) as usize;
        let moved = second - second % period;
        let (Some(&begin), Some(&end)) = (
            receiver.seconds.get(within),
            receiver.seconds.get(within + 1),
        ) else {
            return;
        };
        let gps = receiver.clock == Clock::RadarcapeGps;
        for heard in &receiver.heard[begin as usize..end as usize] {
            let message = ({ heard.key } & ((1 << MESSAGE_BITS) - 1)) as usize;
            let Some(data) = self.messages.get(message) else {
                continue;
            };
            let kind = if data.len() == FrameKind::ModeSLong.message_len() {
                FrameKind::ModeSLong
            } else {
                FrameKind::ModeSShort
            };
            if let Ok(frame) = Frame::new(kind, advance(heard.stamp, moved, gps), 128, data) {
                into.push(frame);
            }
        }
    }

    /// Receptions held for this shard's receivers.
    pub fn held(&self) -> usize {
        self.receivers.iter().map(|each| each.heard.len()).sum()
    }
}

/// A receiver's counter `seconds` later: a 12 MHz counter by that many ticks, a Radarcape's GPS
/// counter (seconds of the UTC day above 30 bits of nanoseconds) by that many seconds of the day.
pub fn advance(stamp: u64, seconds: u64, gps: bool) -> u64 {
    if gps {
        let nanos = stamp & ((1 << 30) - 1);
        let tod = ((stamp >> 30) + seconds) % 86_400;
        (tod << 30) | nanos
    } else {
        stamp.wrapping_add(seconds.wrapping_mul(TICKS_A_SECOND)) & COUNTER_MASK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_move_on_by_the_loop() {
        assert_eq!(advance(100, 5, false), 100 + 5 * TICKS_A_SECOND);
        assert_eq!(advance(COUNTER_MASK, 1, false), TICKS_A_SECOND - 1);
        let stamp = (86_399 << 30) | 7;
        assert_eq!(advance(stamp, 2, true), (1 << 30) | 7);
    }

    #[test]
    fn the_rate_asked_for_is_the_rate_simulated_and_shards_see_one_world() -> Result<(), String> {
        let spec = Spec {
            feeders: 400,
            receptions_per_sec: 20.0,
            aircraft: 300,
            period_s: 3,
            seed: 0,
        };
        let whole = Traffic::build(&spec, 0..400)?;
        let calibration = whole.calibration;
        assert!((calibration.per_sec - 20.0).abs() < 5.0, "{calibration:?}");
        assert!(calibration.receivers_per_message > 1.0, "{calibration:?}");
        assert_eq!(whole.receivers.len(), 400);
        // A shard holds exactly the whole run's receivers in its slice, hearing the same.
        let shard = Traffic::build(&spec, 185..215)?;
        assert_eq!(shard.receivers.len(), 30);
        for (mine, theirs) in shard.receivers.iter().zip(&whole.receivers[185..215]) {
            assert_eq!(mine.index, theirs.index);
            assert_eq!(mine.identity.public(), theirs.identity.public());
            let (mut a, mut b) = (Vec::new(), Vec::new());
            shard.frames(mine.index - 185, 4, &mut a);
            whole.frames(theirs.index, 4, &mut b);
            assert_eq!(a, b);
        }
        // Each second is heard once a loop, counters later by the loop.
        let (mut first, mut again) = (Vec::new(), Vec::new());
        whole.frames(0, 1, &mut first);
        whole.frames(0, 4, &mut again);
        assert_eq!(first.len(), again.len());
        assert!(!first.is_empty());
        Ok(())
    }
}
