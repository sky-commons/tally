//! Rate shedding at ingest (RFC-0181 §10, "Admission", decided 2026-10-09): the one place the
//! relay refuses a feeder's batch for its rate, before the batch is signed, shared or sent
//! anywhere. Past it a batch is the relay's to keep, to the last, and nothing after it refuses a
//! member's batch for want of room (the stores' limits are planned from the rate admitted here,
//! `budget`), so two relays holding one area never disagree about which batches were dropped for
//! load: each drops its own feeders' before sharing them, and what is shared is kept.
//!
//! The rule is a relay-wide token bucket on `R_max` (receptions and bytes a second) beside each
//! receiver's own pace (`ingest::ReceptionCeilings`), judged by the batch's own stamp, never a
//! clock. While the relay carries what it is sized for nothing is cut. Over demand, each
//! source's allowance is its max-min fair share:
//!
//! > `min(source ceiling, R_max x weight / active weight)`, and more where a source wants less
//!
//! A source is a [`Unit`]: a receiver this relay corroborated first-hand (it has earned credit,
//! `credit::Credit::corroborated_receiver`), or else its network group, so a hundred keys behind
//! one address block hold one share, not a hundred. Every unit weighs one.
//!
//! The division is the water-filling one: a source wanting less than the level keeps all it
//! wants, and the rest share what those leave, none past the source ceiling; the level is found
//! again every quarter of [`ACTIVE_MS`] from each unit's attempted rate (`State::levelled`). A
//! source wanting no more than the level is admitted whenever the bucket holds its batch. A
//! source wanting more is kept to the level by what it has been admitted over the last
//! [`WINDOW_MS`] of stamps, and, while the bucket runs short, held back by a mark of the bucket's
//! fill that rises with how many levels it wants (`1 - level / wanted`, times [`RESERVE`]), so the
//! source furthest over is cut first, and of equal overage the one with the higher key-hash rank.
//! What a source wants is what it attempted, admitted or cut, so a cut source does not become a
//! guest again by being cut. Every cut is counted per source and reason ([`Cause`]) and reported
//! on `/memory`.
//!
//! Closed-loop admission (by observed load) is not used: a Sybil connects quiet and then sends at
//! pace. The allowance depends on the declared rate and the weights alone.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tally_wire::PublicKey;

use crate::ingest::Group;

/// A rate in receptions and bytes a second: `R_max`, or a source's ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Rates {
    pub receptions_per_s: u64,
    pub bytes_per_s: u64,
}

impl Rates {
    /// No limit.
    pub const UNBOUNDED: Self = Self {
        receptions_per_s: u64::MAX,
        bytes_per_s: u64::MAX,
    };

    fn dims(self) -> [f64; DIMS] {
        [self.receptions_per_s as f64, self.bytes_per_s as f64]
    }
}

/// What one batch costs the rate: the receptions it states and its bytes on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    pub receptions: u64,
    pub bytes: u64,
}

impl Cost {
    fn dims(self) -> [f64; DIMS] {
        [self.receptions as f64, self.bytes as f64]
    }
}

const DIMS: usize = 2;

/// Whose share a batch is charged to: a receiver this relay corroborated, which earned its own
/// share, or every other receiver by its network group (`None`: an address with none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unit {
    Corroborated(PublicKey),
    Group(Option<Group>),
}

impl Unit {
    /// The unit as a name for `/memory`.
    pub fn label(self) -> String {
        match self {
            Self::Corroborated(key) => format!("key:{key}"),
            Self::Group(Some(Group::V4(prefix))) => {
                format!("v4:{}.{}.0.0/16", prefix >> 8, prefix & 0xff)
            }
            Self::Group(Some(Group::V6(prefix))) => {
                format!("v6:{:x}:{:x}::/32", prefix >> 16, prefix & 0xffff)
            }
            Self::Group(None) => "no-address".to_owned(),
        }
    }

    /// A rank in [0, 1) from the unit alone (FNV-1a over its bytes, nothing random): the same on
    /// every run and every relay. Of equal overage, the higher rank is cut first.
    fn rank(self) -> f64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0100_0000_01b3);
            }
        };
        match self {
            Self::Corroborated(key) => {
                feed(&[0]);
                feed(key.as_bytes());
            }
            Self::Group(Some(group)) => {
                feed(&[1]);
                feed(&group.as_u64().to_be_bytes());
            }
            Self::Group(None) => feed(&[2]),
        }
        (hash >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Why a batch was cut at ingest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// Past its receiver's own pace (`ingest::ReceptionCeilings`).
    ReceiverCeiling,
    /// Its source was over its fair share and the bucket's surplus was below the mark its overage
    /// sets.
    OverShare,
    /// Its source was within its share and the bucket held less than the batch costs: the relay
    /// is past `R_max` even for the sources it guarantees, which the reserve exists to prevent.
    RelayRate,
}

const CAUSES: usize = 3;

impl Cause {
    const fn index(self) -> usize {
        match self {
            Self::ReceiverCeiling => 0,
            Self::OverShare => 1,
            Self::RelayRate => 2,
        }
    }
}

/// The span of stamps a source's rate is measured over (an exponential window, so a source's past
/// fades, never a cliff).
pub const WINDOW_MS: u64 = 2_000;
/// How long a unit may send nothing and still be counted in the active weight.
pub const ACTIVE_MS: u64 = 2_000;
/// The seconds of `R_max` the bucket holds: a second of arrivals bunched on the way.
pub const BURST_SECS: f64 = 1.0;
/// The part of the bucket only sources within their share may spend: the guarantee. A source over
/// its share is cut once the bucket is below this, whatever its overage.
pub const RESERVE: f64 = 0.1;
/// Units whose usage is tracked, at most. A unit past it is judged as one over its share.
pub const UNITS_TRACKED: usize = 1 << 17;
/// Sources whose cuts are counted, at most; past it the least cut are forgotten (their totals stay
/// in the reason counts).
pub const SOURCES_COUNTED: usize = 4_096;
/// Sources a report names, the most cut first.
pub const SOURCES_REPORTED: usize = 16;

struct Bucket {
    tokens: f64,
    burst: f64,
    rate_per_ms: f64,
}

struct Use {
    /// Decayed sums of what the unit attempted and of what was admitted, per dimension, as of
    /// `at_ms`.
    attempted: [f64; DIMS],
    admitted: [f64; DIMS],
    at_ms: u64,
}

struct State {
    rate: Rates,
    ceiling: Rates,
    buckets: [Bucket; DIMS],
    at_ms: u64,
    units: HashMap<Unit, Use>,
    scanned_ms: u64,
    /// The water level: the rate a second each source may be admitted at, per dimension, as the
    /// last scan found it (`State::levelled`).
    level: [f64; DIMS],
    counted: HashMap<Unit, [u64; CAUSES]>,
}

/// The relay-wide rate, shared by every ingest worker.
pub struct Shedder {
    state: Mutex<State>,
    bounded: bool,
    /// Batches and receptions cut, by reason, exact whatever the per-source map forgot.
    batches: [AtomicU64; CAUSES],
    receptions: [AtomicU64; CAUSES],
}

/// What was cut, for `/memory`.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShedReport {
    /// `R_max`, or `None` where the relay sheds nothing for its rate.
    pub rate: Option<Rates>,
    pub ceiling: Option<Rates>,
    pub active_sources: usize,
    pub receiver_ceiling: Cuts,
    pub over_share: Cuts,
    pub relay_rate: Cuts,
    /// The sources cut most, with their cuts by reason.
    pub sources: Vec<SourceCuts>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Cuts {
    pub batches: u64,
    pub receptions: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SourceCuts {
    pub source: String,
    pub receiver_ceiling: u64,
    pub over_share: u64,
    pub relay_rate: u64,
}

impl Default for Shedder {
    fn default() -> Self {
        Self::unbounded()
    }
}

impl Shedder {
    /// A relay that sheds nothing for its rate (a test's hub, before it is planned).
    pub fn unbounded() -> Self {
        Self::bounded_by(Rates::UNBOUNDED, Rates::UNBOUNDED)
    }

    /// `rate` is `R_max`; `ceiling` is the most one source's share may be (the pace ceiling).
    pub fn new(rate: Rates, ceiling: Rates) -> Self {
        Self::bounded_by(rate, ceiling)
    }

    fn bounded_by(rate: Rates, ceiling: Rates) -> Self {
        let bounded = rate != Rates::UNBOUNDED;
        let burst_floor = [
            ceiling.receptions_per_s.min(1 << 40) as f64,
            ceiling.bytes_per_s.min(1 << 40) as f64,
        ];
        let rates = rate.dims();
        let bucket = |dim: usize| {
            let burst = (rates[dim] * BURST_SECS).max(burst_floor[dim]).max(1.0);
            Bucket {
                tokens: burst,
                burst,
                rate_per_ms: rates[dim] / 1_000.0,
            }
        };
        Self {
            state: Mutex::new(State {
                rate,
                ceiling,
                buckets: [bucket(0), bucket(1)],
                at_ms: 0,
                units: HashMap::new(),
                scanned_ms: 0,
                level: rate.dims().map(|r| r.min(1e15)),
                counted: HashMap::new(),
            }),
            bounded,
            batches: Default::default(),
            receptions: Default::default(),
        }
    }

    /// Whether the relay sheds for its rate at all.
    pub fn is_bounded(&self) -> bool {
        self.bounded
    }

    /// `R_max`, when bounded.
    pub fn rate(&self) -> Option<Rates> {
        self.bounded.then(|| self.lock().rate)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `unit`'s batch costing `cost`, stamped `stamp_ms`, is admitted. A cut is counted
    /// (per source and reason) before this returns it. Takes the bucket's tokens when admitted.
    pub fn judge(&self, unit: Unit, cost: Cost, stamp_ms: u64) -> Result<(), Cause> {
        if !self.bounded {
            return Ok(());
        }
        let mut state = self.lock();
        let verdict = state.judge(unit, cost, stamp_ms);
        if let Err(cause) = verdict {
            state.count(unit, cause);
            drop(state);
            self.add(cause, cost);
        }
        verdict
    }

    /// A cut made elsewhere at ingest (the receiver's own pace), counted with the rest. The batch
    /// was judged first (`judge` took its tokens), so a cut for the receiver's own pace gives them
    /// back: the relay's rate is for what it keeps, not for a receiver past its own pace.
    pub fn cut(&self, unit: Unit, cause: Cause, cost: Cost) {
        if self.bounded {
            let mut state = self.lock();
            if cause == Cause::ReceiverCeiling {
                for (bucket, cost) in state.buckets.iter_mut().zip(cost.dims()) {
                    bucket.tokens = (bucket.tokens + cost).min(bucket.burst);
                }
            }
            state.count(unit, cause);
        } else {
            self.lock().count(unit, cause);
        }
        self.add(cause, cost);
    }

    fn add(&self, cause: Cause, cost: Cost) {
        self.batches[cause.index()].fetch_add(1, Ordering::Relaxed);
        self.receptions[cause.index()].fetch_add(cost.receptions, Ordering::Relaxed);
    }

    /// Batches cut for `cause` so far.
    pub fn cut_batches(&self, cause: Cause) -> u64 {
        self.batches[cause.index()].load(Ordering::Relaxed)
    }

    pub fn report(&self) -> ShedReport {
        let cuts = |cause: Cause| Cuts {
            batches: self.batches[cause.index()].load(Ordering::Relaxed),
            receptions: self.receptions[cause.index()].load(Ordering::Relaxed),
        };
        let state = self.lock();
        let mut sources: Vec<(u64, SourceCuts)> = state
            .counted
            .iter()
            .map(|(unit, counts)| {
                (
                    counts.iter().sum::<u64>(),
                    SourceCuts {
                        source: unit.label(),
                        receiver_ceiling: counts[Cause::ReceiverCeiling.index()],
                        over_share: counts[Cause::OverShare.index()],
                        relay_rate: counts[Cause::RelayRate.index()],
                    },
                )
            })
            .collect();
        sources.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.source.cmp(&b.1.source)));
        ShedReport {
            rate: self.bounded.then_some(state.rate),
            ceiling: self.bounded.then_some(state.ceiling),
            active_sources: state.units.len(),
            receiver_ceiling: cuts(Cause::ReceiverCeiling),
            over_share: cuts(Cause::OverShare),
            relay_rate: cuts(Cause::RelayRate),
            sources: sources
                .into_iter()
                .take(SOURCES_REPORTED)
                .map(|(_, source)| source)
                .collect(),
        }
    }
}

impl State {
    /// The rate each source may be admitted at, per dimension: the water level of a max-min
    /// fair division of `R_max`, where a source that wants less than the level keeps all it wants
    /// and the rest share what those leave, none past the source ceiling. A relay under its rate
    /// has no level below the ceiling. Weights are one each (a unit is one share, `Unit`).
    fn levelled(&mut self, now: u64) {
        let rate = self.rate.dims();
        let ceiling = self.ceiling.dims();
        for dim in 0..DIMS {
            let mut wants: Vec<f64> = self
                .units
                .values()
                .map(|used| Self::faded(used, now, false)[dim].min(ceiling[dim]))
                .collect();
            wants.sort_unstable_by(f64::total_cmp);
            let mut left = rate[dim];
            let mut count = wants.len() as f64;
            let mut level = ceiling[dim];
            for want in wants {
                if want * count <= left {
                    left -= want;
                    count -= 1.0;
                } else {
                    level = (left / count).min(ceiling[dim]);
                    break;
                }
            }
            self.level[dim] = level.max(1.0);
        }
    }

    /// A unit's attempted (or admitted) rate a second, faded to `now`.
    fn faded(used: &Use, now: u64, admitted: bool) -> [f64; DIMS] {
        let fade = (-(now.saturating_sub(used.at_ms) as f64) / WINDOW_MS as f64).exp();
        let sums = if admitted {
            used.admitted
        } else {
            used.attempted
        };
        sums.map(|sum| sum * fade / (WINDOW_MS as f64 / 1_000.0))
    }

    fn judge(&mut self, unit: Unit, cost: Cost, stamp_ms: u64) -> Result<(), Cause> {
        // Time only goes forward: a stamp behind the newest read adds nothing to the bucket.
        let now = stamp_ms.max(self.at_ms);
        let elapsed = now - self.at_ms;
        self.at_ms = now;
        for bucket in &mut self.buckets {
            bucket.tokens = (bucket.tokens + elapsed as f64 * bucket.rate_per_ms).min(bucket.burst);
        }
        if now >= self.scanned_ms + ACTIVE_MS / 4 {
            self.units
                .retain(|_, used| now.saturating_sub(used.at_ms) <= ACTIVE_MS);
            self.levelled(now);
            self.scanned_ms = now;
        }
        let attempted = cost.dims();
        let tracked = self.units.contains_key(&unit) || self.units.len() < UNITS_TRACKED;
        // What it attempted and was admitted before this batch.
        let prior = tracked.then(|| {
            let used = self.units.entry(unit).or_insert(Use {
                attempted: [0.0; DIMS],
                admitted: [0.0; DIMS],
                at_ms: now,
            });
            let before = (Self::faded(used, now, false), Self::faded(used, now, true));
            let fade = (-(now.saturating_sub(used.at_ms) as f64) / WINDOW_MS as f64).exp();
            for (sum, cost) in used.attempted.iter_mut().zip(attempted) {
                *sum = sum.mul_add(fade, cost);
            }
            for sum in &mut used.admitted {
                *sum *= fade;
            }
            used.at_ms = now;
            before
        });
        let times = |rates: [f64; DIMS]| {
            (0..DIMS)
                .map(|dim| rates[dim] / self.level[dim])
                .fold(0.0, f64::max)
        };
        // How many levels it wants, and how many it has been admitted: an untracked unit is
        // judged as one far over.
        let (wants, has) = prior.map_or((2.0, 2.0), |(wants, has)| (times(wants), times(has)));
        let fits = (0..DIMS).all(|dim| self.buckets[dim].tokens >= attempted[dim]);
        let verdict = if wants <= 1.0 {
            fits.then_some(()).ok_or(Cause::RelayRate)
        } else {
            // Over the level: kept to it by what it has been admitted, and, while the bucket is
            // short, held back by a mark that rises with how far over it wants, a hair more for
            // a higher key-hash rank: the furthest over goes first.
            let ranked = wants * (1.0 + unit.rank() * 1e-6);
            let mark = RESERVE * (1.0 - 1.0 / ranked);
            let surplus = (0..DIMS).all(|dim| {
                let bucket = &self.buckets[dim];
                (bucket.tokens - attempted[dim]) / bucket.burst >= mark
            });
            (has <= 1.0 && fits && surplus)
                .then_some(())
                .ok_or(Cause::OverShare)
        };
        if verdict.is_ok() {
            for (bucket, cost) in self.buckets.iter_mut().zip(attempted) {
                bucket.tokens -= cost;
            }
            if let Some(used) = self.units.get_mut(&unit) {
                for (sum, cost) in used.admitted.iter_mut().zip(attempted) {
                    *sum += cost;
                }
            }
        }
        verdict
    }

    fn count(&mut self, unit: Unit, cause: Cause) {
        self.counted.entry(unit).or_default()[cause.index()] += 1;
        if self.counted.len() > SOURCES_COUNTED {
            let mut totals: Vec<u64> = self
                .counted
                .values()
                .map(|counts| counts.iter().sum())
                .collect();
            totals.sort_unstable();
            let keep_from = totals[totals.len() / 4];
            self.counted
                .retain(|_, counts| counts.iter().sum::<u64>() > keep_from);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(n: u16) -> Unit {
        Unit::Group(Some(Group::V4(n)))
    }

    const RATE: Rates = Rates {
        receptions_per_s: 10_000,
        bytes_per_s: 10_000_000,
    };
    const CEILING: Rates = Rates {
        receptions_per_s: 3_000,
        bytes_per_s: 3_000_000,
    };

    fn cost(receptions: u64) -> Cost {
        Cost {
            receptions,
            bytes: receptions * 20,
        }
    }

    /// `seconds` of stamps. Each batch is one source's tenth of a second of its rate (receptions a
    /// second), and the sources' batches are spread over each tenth the way real feeders' are,
    /// never bunched at one stamp. Returns the receptions admitted, by source.
    fn run(shedder: &Shedder, sources: &[(Unit, u64)], seconds: u64) -> HashMap<Unit, u64> {
        let mut admitted: HashMap<Unit, u64> = HashMap::new();
        for tick in 0..seconds * 10 {
            for (index, (unit, per_s)) in sources.iter().enumerate() {
                let stamp = tick * 100 + index as u64 * 100 / sources.len() as u64;
                let receptions = per_s / 10;
                if shedder.judge(*unit, cost(receptions), stamp).is_ok() {
                    *admitted.entry(*unit).or_default() += receptions;
                }
            }
        }
        admitted
    }

    fn got(admitted: &HashMap<Unit, u64>, unit: Unit) -> u64 {
        admitted.get(&unit).copied().unwrap_or(0)
    }

    #[test]
    fn nothing_is_cut_below_the_rate() {
        let shedder = Shedder::new(RATE, CEILING);
        let sources: Vec<_> = (0..10).map(|n| (group(n), 600)).collect();
        let admitted = run(&shedder, &sources, 20);
        for (unit, _) in &sources {
            assert_eq!(got(&admitted, *unit), 600 * 20, "{unit:?}");
        }
        let report = shedder.report();
        assert_eq!(report.over_share.batches + report.relay_rate.batches, 0);
    }

    #[test]
    fn honest_sources_keep_their_share_past_the_rate_and_flooders_are_held_to_the_rest() {
        let shedder = Shedder::new(RATE, CEILING);
        // 10 honest at 600 (6,000), 4 hostile at the ceiling (12,000): 18,000 against 10,000.
        let mut sources: Vec<_> = (0..10).map(|n| (group(n), 600)).collect();
        sources.extend((100..104).map(|n| (group(n), 3_000)));
        let seconds = 40;
        let admitted = run(&shedder, &sources, seconds);
        for (unit, per_s) in sources.iter().take(10) {
            let kept = got(&admitted, *unit);
            assert!(
                kept >= per_s * (seconds - 1),
                "honest {unit:?} kept {kept} of {}",
                per_s * seconds
            );
        }
        let total: u64 = admitted.values().sum();
        assert!(
            total <= RATE.receptions_per_s * (seconds + 1),
            "R_max holds: {total}"
        );
        // And the hostile share what the honest leave, none starved, none past it.
        for (unit, _) in sources.iter().skip(10) {
            let kept = got(&admitted, *unit);
            assert!(kept > 0, "{unit:?} is held to a share, not starved");
            assert!(
                kept <= 1_500 * seconds,
                "{unit:?} kept {kept}, past the 1,000 a second left"
            );
        }
        let report = shedder.report();
        assert!(report.over_share.batches > 0);
        assert_eq!(
            report
                .sources
                .iter()
                .filter(|cut| (0..10).any(|n| cut.source == format!("v4:0.{n}.0.0/16")))
                .count(),
            0,
            "no honest source was cut: {:?}",
            report.sources
        );
    }

    #[test]
    fn a_sybil_set_behind_one_group_holds_one_share_not_one_per_key() {
        let seconds = 30;
        let honest: Vec<_> = (0..10).map(|n| (group(n), 900)).collect();
        // Behind one group: 200 keys, each at 900, are one unit, one share.
        let shedder = Shedder::new(RATE, CEILING);
        let mut sources = honest.clone();
        let sybil = group(500);
        let mut admitted: HashMap<Unit, u64> = HashMap::new();
        for tick in 0..seconds * 10 {
            for (index, (unit, per_s)) in sources.iter().enumerate() {
                let receptions = per_s / 10;
                if shedder
                    .judge(*unit, cost(receptions), tick * 100 + index as u64)
                    .is_ok()
                {
                    *admitted.entry(*unit).or_default() += receptions;
                }
            }
            for key in 0..200u64 {
                if shedder
                    .judge(sybil, cost(90), tick * 100 + 20 + key / 4)
                    .is_ok()
                {
                    *admitted.entry(sybil).or_default() += 90;
                }
            }
        }
        for (unit, per_s) in &honest {
            assert!(
                got(&admitted, *unit) >= per_s * (seconds - 1),
                "{unit:?} kept {} of {}",
                got(&admitted, *unit),
                per_s * seconds
            );
        }
        // One share is what the honest leave (1,000 a second), never 200 keys' worth.
        assert!(
            got(&admitted, sybil) <= 1_500 * seconds,
            "{}",
            got(&admitted, sybil)
        );
        // Where each of the 200 keys is its own unit (no group to fold them into), they take the
        // honest sources' room: the fold is what holds them.
        let shedder = Shedder::new(RATE, CEILING);
        sources.extend((0..200u16).map(|n| (group(1_000 + n), 900)));
        let drowned = run(&shedder, &sources, seconds);
        let honest_kept: u64 = honest.iter().map(|(unit, _)| got(&drowned, *unit)).sum();
        assert!(
            honest_kept < honest.iter().map(|(_, per_s)| per_s * seconds).sum::<u64>() / 2,
            "200 shares drown ten: {honest_kept}"
        );
    }

    #[test]
    fn the_source_furthest_over_is_cut_most_and_rank_breaks_ties_the_same_everywhere() {
        // 7,500 wanted against 6,000: the level settles at 1,950, so only the two heaviest are cut.
        let rate = Rates {
            receptions_per_s: 6_000,
            bytes_per_s: 6_000_000,
        };
        let shedder = Shedder::new(rate, CEILING);
        let sources = [
            (group(1), 3_000),
            (group(2), 2_400),
            (group(3), 1_500),
            (group(4), 600),
        ];
        run(&shedder, &sources, 30);
        let report = shedder.report();
        let cuts = |name: &str| {
            report
                .sources
                .iter()
                .find(|cut| cut.source == name)
                .map_or(0, |cut| cut.over_share + cut.relay_rate)
        };
        assert!(cuts("v4:0.1.0.0/16") > cuts("v4:0.2.0.0/16"));
        assert!(cuts("v4:0.2.0.0/16") > 0);
        assert_eq!(
            cuts("v4:0.3.0.0/16"),
            0,
            "a source within its share is never cut"
        );
        assert_eq!(cuts("v4:0.4.0.0/16"), 0);
        let (a, b) = (group(7), group(8));
        assert_ne!(a.rank(), b.rank());
        assert_eq!(a.rank(), group(7).rank());
        assert!((0.0..1.0).contains(&a.rank()));
    }

    #[test]
    fn every_cut_is_counted_by_source_and_reason() {
        let shedder = Shedder::new(RATE, CEILING);
        let sources: Vec<_> = (1..=4).map(|n| (group(n), 3_000)).collect();
        let admitted = run(&shedder, &sources, 20);
        let report = shedder.report();
        let offered: u64 = 4 * 3_000 * 20;
        let cut = report.over_share.receptions + report.relay_rate.receptions;
        assert_eq!(cut + admitted.values().sum::<u64>(), offered);
        let by_source: u64 = report
            .sources
            .iter()
            .map(|s| s.over_share + s.relay_rate)
            .sum();
        assert_eq!(
            by_source,
            report.over_share.batches + report.relay_rate.batches
        );
        shedder.cut(group(9), Cause::ReceiverCeiling, cost(5));
        let after = shedder.report();
        assert_eq!(
            after.receiver_ceiling,
            Cuts {
                batches: 1,
                receptions: 5
            }
        );
        assert!(
            after
                .sources
                .iter()
                .any(|s| s.source == "v4:0.9.0.0/16" && s.receiver_ceiling == 1)
        );
    }

    #[test]
    fn unbounded_sheds_nothing_and_tracks_nothing() {
        let shedder = Shedder::unbounded();
        for n in 0..1000 {
            assert!(shedder.judge(group(n), cost(1 << 30), 0).is_ok());
        }
        assert_eq!(shedder.report().active_sources, 0);
    }

    #[test]
    fn a_stamp_behind_the_newest_adds_no_tokens() {
        let shedder = Shedder::new(RATE, CEILING);
        let mut admitted = 0;
        for n in 0..40u64 {
            if shedder
                .judge(group((n % 4) as u16), cost(3_000), 10_000 - n % 5)
                .is_ok()
            {
                admitted += 1;
            }
        }
        // A full bucket of 10,000 and no refill: three batches of 3,000 at most.
        assert!(admitted <= 3, "{admitted}");
    }
}
