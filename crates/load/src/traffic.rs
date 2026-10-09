//! What the simulated receivers hear: the MLAT simulator's receivers and aircraft (`sim`), laid
//! out as RFC-0174's world benchmark lays them (two clusters, as Europe's and the US's receivers
//! are), so one transmission is heard by every receiver in reach, as real traffic is. A few seconds
//! are simulated once and replayed in a loop, forward then backward ([`Traffic::frames`]), so
//! nothing a receiver hears jumps at a loop's boundary: an aircraft flies the period and back
//! (where it is is continuous, its heading turns round), and each receiver's clock runs on through
//! every loop at its own rate, the simulated clock's error continued, never put back. Before, each
//! loop replayed the period forward with every counter moved on by the loop's length exactly, so at
//! each boundary every aircraft jumped back to where it began and every free-running clock (its
//! rate some 30 ppm off) jumped by its rate's error over the period (about 150 us at 5 s): a 60 s
//! clock fit saw a dozen jumps and failed, and positions decoded across the boundary were wrong.
//!
//! The rate is set, not assumed: a first pass measures what each receiver would hear if it heard
//! every transmission in reach, and the second keeps each reception with the probability that
//! gives the rate asked for (`Spec::receptions_per_sec`).

use std::ops::Range;

use tally_mlat_solver::linalg::{self, Vec3};
use tally_mlat_solver::sim::{self, ClockTruth, Scenario};
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

/// The simulation's first played second (`second_of`'s second 1: aircraft begin within their
/// first second or two, so second 0 is thin), in its own time: where the period begins.
const PLAYED_FROM_S: f64 = 1.0;

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
    /// Where it is, for the time each transmission takes to reach it.
    ecef: Vec3,
    /// How its clock truly behaves over the simulated period, which the loops continue
    /// ([`Traffic::moved`]).
    truth: ClockTruth,
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
    /// Distinct transmissions heard a second, by anyone.
    pub messages_per_sec: f64,
    /// Receivers that heard each of them, on average.
    pub receivers_per_message: f64,
    /// Distinct messages (by their bytes: a reply an aircraft repeats unchanged is one message)
    /// heard a second, by anyone.
    pub contents_per_sec: f64,
    /// What the relay's deduplicated stream carries a second when it loses nothing
    /// ([`expected_deduplicated`]): the receptions its rule keeps from this traffic, each second's
    /// stamped in one of the relay's seconds.
    pub deduplicated_per_sec: f64,
}

/// The receptions a second the relay's deduplicated stream keeps from `heard`, each second's
/// distinct messages (by their bytes), the run's loop of them repeating for ever: the relay's rule
/// (`tally_relay::exchange::MessageShard`), by the second. A message kept in a second is remembered
/// for that second and the `DEDUP_GENERATIONS - 1` after it, so one heard every second is kept once
/// every `DEDUP_GENERATIONS` seconds, and one heard once a loop, once a loop.
///
/// It is the count with each second's receptions stamped in one of the relay's seconds. The relay
/// stamps by arrival: a feeder holds a reception up to a second before its batch is sealed and its
/// second does not begin with the relay's, so one second's receptions are stamped across two or
/// three of the relay's, and which copy of a message falls in which window moves with them. The
/// stream then carries somewhat more or fewer than this; what it lost is the coverage line
/// (`subscriber::Heard`), never this rate.
pub fn expected_deduplicated(heard: &[std::collections::HashSet<u32>]) -> f64 {
    const { assert!(tally_relay::seal::EPOCH_MS == 1_000) };
    let remembered = tally_relay::exchange::DEDUP_GENERATIONS - 1;
    if heard.is_empty() {
        return 0.0;
    }
    // What each of the last `remembered` seconds kept, oldest first.
    let mut kept_before: std::collections::VecDeque<std::collections::HashSet<u32>> =
        std::collections::VecDeque::new();
    let mut last_loop = 0usize;
    // The first loop starts from nothing; by the third, every second's keep is the loop's own.
    for round in 0..3 {
        last_loop = 0;
        for second in heard {
            let kept: std::collections::HashSet<u32> = second
                .iter()
                .filter(|message| !kept_before.iter().any(|before| before.contains(message)))
                .copied()
                .collect();
            if round == 2 {
                last_loop += kept.len();
            }
            kept_before.push_back(kept);
            if kept_before.len() > remembered {
                kept_before.pop_front();
            }
        }
    }
    last_loop as f64 / heard.len() as f64
}

pub struct Traffic {
    pub receivers: Vec<Receiver>,
    messages: Vec<Vec<u8>>,
    /// When and where each message (by its index in `messages`) was sent, in the simulation's
    /// time: what playing it backward needs ([`Traffic::moved`]).
    sent: Vec<(f64, Vec3)>,
    period_s: u32,
    /// The Unix time a GNSS-disciplined receiver's counter reads in the first second the
    /// simulation plays (`second_of`'s second 1, its scenario's first second after the thin one):
    /// what `frames` moves those counters from, so they read the run's own UTC time of day.
    gps_first_unix_ms: u64,
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
        let mut sent: Vec<(f64, Vec3)> = Vec::new();
        let (mut kept, mut distinct) = (0u64, 0u64);
        let mut first = 0usize;
        // The messages (by index) anyone heard, each second of the period.
        let mut seconds_heard: Vec<Vec<u32>> = vec![Vec::new(); period as usize];
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
            let mut by_second: Vec<Vec<u32>> = vec![Vec::new(); period as usize];
            // Per transmission, the second it was last noted in, plus one.
            let mut noted: Vec<u32> = Vec::new();
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
                if noted.len() <= source {
                    noted.resize(source + 1, 0);
                }
                if noted[source] != second as u32
                    && let Ok(message) = u32::try_from(offset + source)
                {
                    noted[source] = second as u32;
                    by_second[(second - 1) as usize].push(message);
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
            sent.extend(
                simulation
                    .transmissions
                    .iter()
                    .map(|each| (each.time, each.ecef)),
            );
            messages.extend(simulation.transmissions.into_iter().map(|each| each.data));
            for (second, heard) in by_second.into_iter().enumerate() {
                seconds_heard[second].extend(heard);
            }
            for (at, mut list) in heard.into_iter().enumerate() {
                let index = mine.start + at;
                let within = index - cluster_range.start;
                let simulated = &simulation.receivers[within];
                let site = simulated.site;
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
                    ecef: simulated.ecef,
                    truth: simulated.truth.clone(),
                    heard: list,
                    seconds,
                });
            }
        }
        let seconds = (total as u64 * period) as f64;
        // Each message by its bytes: two transmissions of the same bytes are one message to a
        // deduplication.
        let mut content: std::collections::HashMap<&[u8], u32> = std::collections::HashMap::new();
        let mut content_of = Vec::with_capacity(messages.len());
        for data in &messages {
            let next = content.len() as u32;
            content_of.push(*content.entry(data.as_slice()).or_insert(next));
        }
        let heard_contents: Vec<std::collections::HashSet<u32>> = seconds_heard
            .iter()
            .map(|heard| heard.iter().map(|&m| content_of[m as usize]).collect())
            .collect();
        let contents_per_sec = heard_contents
            .iter()
            .map(std::collections::HashSet::len)
            .sum::<usize>() as f64
            / period.max(1) as f64;
        // The loop is the period forward then backward ([`Traffic::frames`]).
        let played: Vec<std::collections::HashSet<u32>> = heard_contents
            .iter()
            .chain(heard_contents.iter().rev())
            .cloned()
            .collect();
        let deduplicated_per_sec = expected_deduplicated(&played);
        let first = Scenario::new(0);
        Ok(Self {
            receivers,
            messages,
            sent,
            period_s: spec.period_s,
            gps_first_unix_ms: first.midnight_unix_ms + (first.start_tod_s * 1000.0) as u64 + 1000,
            calibration: Calibration {
                in_reach_per_sec,
                probability,
                per_sec: kept as f64 / seconds,
                messages_per_sec: distinct as f64 / period as f64,
                receivers_per_message: kept as f64 / distinct.max(1) as f64,
                contents_per_sec,
                deduplicated_per_sec,
            },
        })
    }

    /// The receptions `receiver` (by its place in `receivers`) makes in second `second` of the
    /// run, as its decoder would hand them over. The simulated period is played forward in even
    /// loops and backward in odd ones, so every aircraft flies on from where the last loop left it
    /// (turning round at each boundary), and each counter reads its clock carried on through the
    /// loops before it ([`Traffic::moved`]), never put back. A GNSS-disciplined receiver's counter
    /// is the UTC time of day, so it is moved to the run's own: second `second` of a run whose
    /// second 0 began at `start_unix_ms` reads that wall clock, as a real Radarcape's does, never
    /// the scenario's (else every model whose gauge is one dates its solutions hours from the wall
    /// clock of the batches that carried them).
    pub fn frames(&self, receiver: usize, second: u64, start_unix_ms: u64, into: &mut Vec<Frame>) {
        let Some(receiver) = self.receivers.get(receiver) else {
            return;
        };
        let period = u64::from(self.period_s);
        let lap = second / period;
        let backward = lap % 2 == 1;
        let within = second % period;
        // Backward, second `within` of the loop is the period's second `period - 1 - within`,
        // its receptions in the reverse order.
        let played = if backward {
            period - 1 - within
        } else {
            within
        } as usize;
        let (Some(&begin), Some(&end)) = (
            receiver.seconds.get(played),
            receiver.seconds.get(played + 1),
        ) else {
            return;
        };
        let gps = receiver.clock == Clock::RadarcapeGps;
        let heard = &receiver.heard[begin as usize..end as usize];
        let mut play = |heard: &Heard| {
            let message = ({ heard.key } & ((1 << MESSAGE_BITS) - 1)) as usize;
            let Some(data) = self.messages.get(message) else {
                return;
            };
            let kind = if data.len() == FrameKind::ModeSLong.message_len() {
                FrameKind::ModeSLong
            } else {
                FrameKind::ModeSShort
            };
            let mut stamp = advance(heard.stamp, self.moved(receiver, lap, message), gps);
            if gps {
                stamp = shift_time_of_day(stamp, start_unix_ms, self.gps_first_unix_ms);
            }
            if let Ok(frame) = Frame::new(kind, stamp, 128, data) {
                into.push(frame);
            }
        };
        if backward {
            heard.iter().rev().for_each(&mut play);
        } else {
            heard.iter().for_each(&mut play);
        }
    }

    /// Seconds `receiver`'s counter is moved on from what it read hearing `message` in the
    /// simulation, played in loop `lap` (from 0). The period is the simulation's seconds `T0`
    /// (1, its first whole second) to `T1` (`T0` and the period); its clock read `t + e(t)` at true
    /// time `t`, `e` its error (`ClockTruth::error`), and over the period gained `d = e(T1) - e(T0)`.
    ///
    /// Played in loop `k`, a reception is heard at the run's time `T0 + kP + u`, `u` its time into
    /// the loop, and its clock is to read that time plus an error carried on from the loops
    /// before: `k d` and the period's own error forward (`e(T0 + u)`), or backward its mirror
    /// (`e(T0) + e(T1) - e(T1 - u)`), which keeps the clock's rate where the period reversed would
    /// run it back. Both meet the next loop where the last left off, so the clock never jumps.
    /// Forward, `u` is the reception's own time into the period, so it moves `k (P + d)`. Backward,
    /// the message sent at `t` is sent at `T0 + T1 - t` instead and heard the same time after it.
    fn moved(&self, receiver: &Receiver, lap: u64, message: usize) -> f64 {
        let period = f64::from(self.period_s);
        let (t0, t1) = (PLAYED_FROM_S, PLAYED_FROM_S + period);
        let error = |t: f64| receiver.truth.error(t);
        let lap_f = lap as f64;
        let gained = error(t1) - error(t0);
        if lap.is_multiple_of(2) {
            return lap_f * (period + gained);
        }
        let Some(&(sent, from)) = self.sent.get(message) else {
            return lap_f * (period + gained);
        };
        let flight = linalg::norm(linalg::sub(from, receiver.ecef)) / tally_mlat_solver::geo::C;
        let heard = sent + flight;
        let into = t1 - sent + flight;
        let reads =
            t0 + lap_f * period + into + lap_f * gained + error(t0) + error(t1) - error(t1 - into);
        reads - (heard + error(heard))
    }

    /// Receptions held for this shard's receivers.
    pub fn held(&self) -> usize {
        self.receivers.iter().map(|each| each.heard.len()).sum()
    }
}

/// A receiver's counter `seconds` later: a 12 MHz counter by that many ticks, a Radarcape's GPS
/// counter (seconds of the UTC day above 30 bits of nanoseconds) by that many seconds of the day.
pub fn advance(stamp: u64, seconds: f64, gps: bool) -> u64 {
    if gps {
        let nanos = i128::from(stamp >> 30) * 1_000_000_000 + i128::from(stamp & ((1 << 30) - 1));
        let moved = (nanos + (seconds * 1e9).round() as i128).rem_euclid(DAY_NANOS);
        (((moved / 1_000_000_000) as u64) << 30) | (moved % 1_000_000_000) as u64
    } else {
        let ticks = (seconds * TICKS_A_SECOND as f64).round() as i128;
        (i128::from(stamp) + ticks).rem_euclid(i128::from(COUNTER_MASK) + 1) as u64
    }
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

    #[test]
    fn counters_move_on_by_the_loop() {
        assert_eq!(advance(100, 5.0, false), 100 + 5 * TICKS_A_SECOND);
        assert_eq!(advance(COUNTER_MASK, 1.0, false), TICKS_A_SECOND - 1);
        assert_eq!(
            advance(TICKS_A_SECOND, -1.5, false),
            COUNTER_MASK + 1 - TICKS_A_SECOND / 2
        );
        let stamp = (86_399 << 30) | 7;
        assert_eq!(advance(stamp, 2.0, true), (1 << 30) | 7);
        assert_eq!(advance(7, -0.000_000_007, true), 0);
    }

    /// H-a: across loops, a free-running clock runs on at its own rate and an aircraft flies on
    /// from where it was, so what a free-running receiver and a GNSS one both hear of one
    /// transmission differs by the free-running clock's error and the two paths' difference, both
    /// smooth through every loop's boundary. Before, each loop moved every counter on by the
    /// period exactly and put every aircraft back where it began: the free-running clock jumped by
    /// its rate's error over the period (and the paths by the aircraft's jump) at each boundary.
    #[test]
    fn clocks_and_aircraft_run_on_through_every_loop() -> Result<(), String> {
        let spec = Spec {
            feeders: 120,
            receptions_per_sec: 60.0,
            aircraft: 300,
            period_s: 3,
            seed: 0,
        };
        let traffic = Traffic::build(&spec, 0..120)?;
        let period = f64::from(spec.period_s);
        let at = |receiver: &Receiver| receiver.location;
        let gps = traffic
            .receivers
            .iter()
            .position(|each| each.clock == Clock::RadarcapeGps)
            .ok_or("no GNSS receiver simulated")?;
        // Free-running receivers near it whose clocks are well off (above 10 ppm), so a jump of
        // their error over the period would be 30 us or more.
        let near = |receiver: &Receiver| {
            let (a, b) = (at(receiver), at(&traffic.receivers[gps]));
            (i64::from(a.lat_e7) - i64::from(b.lat_e7)).abs()
                + (i64::from(a.lon_e7) - i64::from(b.lon_e7)).abs()
        };
        let mut free: Vec<usize> = (0..traffic.receivers.len())
            .filter(|&index| {
                let receiver = &traffic.receivers[index];
                let gained = receiver.truth.error(PLAYED_FROM_S + period)
                    - receiver.truth.error(PLAYED_FROM_S);
                receiver.clock != Clock::RadarcapeGps && gained.abs() > 10e-6 * period
            })
            .collect();
        free.sort_by_key(|&index| near(&traffic.receivers[index]));
        // An airborne position (DF17, type code 11): unique bytes, its CPR and its noise.
        let position = |data: &[u8]| data.len() == 14 && data[0] >> 3 == 17 && data[4] >> 3 == 11;
        // Each message by its bytes, and how long it took to reach a receiver.
        let index: std::collections::HashMap<&[u8], usize> = traffic
            .messages
            .iter()
            .enumerate()
            .map(|(at, data)| (data.as_slice(), at))
            .collect();
        let flight = |receiver: &Receiver, message: usize| {
            let (_, from) = traffic.sent[message];
            linalg::norm(linalg::sub(from, receiver.ecef)) / tally_mlat_solver::geo::C
        };
        // Ten hours into a day: no GNSS reading wraps at midnight.
        let start_ms = 36_000_000;
        let mut checked = 0;
        for &receiver in free.iter().take(5) {
            // What both heard of each position message, over four loops: the GNSS receiver's reading (the true time, give or take 20 ns) and the
            // difference of the two readings.
            let mut pairs: Vec<(f64, f64)> = Vec::new();
            for second in 0..4 * u64::from(spec.period_s) {
                let (mut theirs, mut ours) = (Vec::new(), Vec::new());
                traffic.frames(gps, second, start_ms, &mut theirs);
                traffic.frames(receiver, second, start_ms, &mut ours);
                for frame in &ours {
                    if !position(frame.message()) {
                        continue;
                    }
                    let same: Vec<&Frame> = theirs
                        .iter()
                        .filter(|each| each.message() == frame.message())
                        .collect();
                    let ([reference], Some(&message)) =
                        (same.as_slice(), index.get(frame.message()))
                    else {
                        continue;
                    };
                    let true_s = (reference.timestamp() >> 30) as f64
                        + (reference.timestamp() & ((1 << 30) - 1)) as f64 * 1e-9;
                    let read_s = frame.timestamp() as f64 / TICKS_A_SECOND as f64;
                    let paths = flight(&traffic.receivers[receiver], message)
                        - flight(&traffic.receivers[gps], message);
                    pairs.push((true_s, read_s - true_s - paths));
                }
            }
            if pairs.len() < 40 {
                continue;
            }
            // Fitted by a line (a clock's rate), what is left is jitter and the paths' slow
            // change: a jump at any boundary leaves its half on either side.
            let n = pairs.len() as f64;
            let (mx, my) = pairs
                .iter()
                .fold((0.0, 0.0), |(x, y), (a, b)| (x + a / n, y + b / n));
            let (sxy, sxx) = pairs.iter().fold((0.0, 0.0), |(xy, xx), (a, b)| {
                (xy + (a - mx) * (b - my), xx + (a - mx) * (a - mx))
            });
            let slope = sxy / sxx;
            let worst = pairs
                .iter()
                .map(|(a, b)| (b - my - slope * (a - mx)).abs())
                .fold(0.0, f64::max);
            assert!(
                worst < 4e-6,
                "receiver {receiver}: {:.1} us off its clock's line over {} shared messages",
                worst * 1e6,
                pairs.len()
            );
            checked += 1;
        }
        assert!(
            checked >= 2,
            "only {checked} receivers shared enough with the GNSS one"
        );
        // Each aircraft the GNSS receiver hears flies on: between two of its messages, read by
        // that receiver's true time, it moved no further than an airliner can (250 m/s and the
        // simulator's 30 m of reported noise). Before, it was back where it began each loop.
        let mut tracks: std::collections::HashMap<[u8; 3], Vec<(f64, usize)>> =
            std::collections::HashMap::new();
        for second in 0..4 * u64::from(spec.period_s) {
            let mut theirs = Vec::new();
            traffic.frames(gps, second, start_ms, &mut theirs);
            for frame in &theirs {
                let data = frame.message();
                if let (true, Some(&message)) = (position(data), index.get(data)) {
                    let read = (frame.timestamp() >> 30) as f64
                        + (frame.timestamp() & ((1 << 30) - 1)) as f64 * 1e-9;
                    let address = [data[1], data[2], data[3]];
                    tracks.entry(address).or_default().push((read, message));
                }
            }
        }
        let mut steps = 0;
        for track in tracks.values_mut() {
            track.sort_by(|a, b| a.0.total_cmp(&b.0));
            for pair in track.windows(2) {
                let ((t0, a), (t1, b)) = (pair[0], pair[1]);
                let moved = linalg::norm(linalg::sub(traffic.sent[b].1, traffic.sent[a].1));
                assert!(
                    moved <= 250.0 * (t1 - t0) + 30.0,
                    "an aircraft moved {moved:.0} m in {:.2} s",
                    t1 - t0
                );
                steps += 1;
            }
        }
        assert!(steps > 100, "{steps}");
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
        let spec = Spec {
            feeders: 120,
            receptions_per_sec: 20.0,
            aircraft: 300,
            period_s: 3,
            seed: 0,
        };
        let traffic = Traffic::build(&spec, 0..120)?;
        let gps = traffic
            .receivers
            .iter()
            .position(|each| each.clock == Clock::RadarcapeGps)
            .ok_or("no GNSS receiver simulated")?;
        let start_ms = 1_791_528_897_000u64;
        for second in [0u64, 4, 7] {
            let mut frames = Vec::new();
            traffic.frames(gps, second, start_ms, &mut frames);
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
            shard.frames(mine.index - 185, 4, 0, &mut a);
            whole.frames(theirs.index, 4, 0, &mut b);
            assert_eq!(a, b);
        }
        // Each second is heard once a loop, counters later by the loop.
        let (mut first, mut again) = (Vec::new(), Vec::new());
        whole.frames(0, 1, 0, &mut first);
        whole.frames(0, 4, 0, &mut again);
        assert_eq!(first.len(), again.len());
        assert!(!first.is_empty());
        Ok(())
    }
}
