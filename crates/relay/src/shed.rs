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
//! > `R_max x weight / active weight`, and more where a source wants less
//!
//! A source is a [`Unit`]: a receiver this relay corroborated first-hand (it has earned credit,
//! `credit::Credit::corroborated_receiver`), or else its network group, so a hundred keys behind
//! one address block hold one share, not a hundred. Every unit weighs one: corroboration is a
//! yes or a no (`credit::Credit::corroborated_receiver`; the relay holds no finer measure of
//! a receiver's credit), and a corroborated receiver is a proven separate receiver, worth as much
//! as a group is. A weight greater than one would hand a key more than the groups of honest
//! feeders it competes with. The units tracked are held in a store of their own
//! (`budget::Store::Shed`); past its room every further unit shares [`Unit::Overflow`].
//!
//! The division is the water-filling one: a source wanting less than the level keeps all it
//! wants, and the rest share what those leave; with demand within `R_max` there is no level at
//! all, so a group of any size is cut for nothing. The level is found
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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tally_wire::PublicKey;

use crate::budget::{Charge, Gauge};
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
    /// Every unit past the room the shed store holds for tracking them, together: one share
    /// between them, so a flood of new groups or keys neither grows the table nor takes a share
    /// each, and a newcomer is never judged as one far over.
    Overflow,
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
            Self::Overflow => "overflow".to_owned(),
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
            Self::Overflow => feed(&[3]),
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
/// How often the water level is found again, in stamps: a quarter of the window's two seconds.
pub const ACTIVE_MS: u64 = 2_000;
/// How long a unit that sends nothing stays tracked: until its rate has faded to a few percent of
/// the window. A unit that sends one batch every few seconds keeps its history across them, so it
/// is never judged as a newcomer each time.
pub const RETAIN_MS: u64 = 4 * WINDOW_MS;
/// The seconds of `R_max` the bucket holds: a second of arrivals bunched on the way.
pub const BURST_SECS: f64 = 1.0;
/// The part of the bucket only sources within their share may spend: the guarantee. A source over
/// its share is cut once the bucket is below this, whatever its overage.
pub const RESERVE: f64 = 0.1;
/// Units whose usage is tracked, at most, where no store limits them. Past it (or past the room
/// the store holds) every further unit shares [`Unit::Overflow`], one share between them.
pub const UNITS_TRACKED: usize = 1 << 17;
/// Bytes of the shed store one tracked unit holds: its key in the table, its two decayed sums and
/// the table's room to grow.
pub const BYTES_PER_UNIT: usize = 256;
/// The units one connection can bring into the table: its network group's and, once this relay
/// has corroborated it, its own, and the room for one of another's while that is not yet let go.
pub const UNITS_PER_CONNECTION: usize = 2;
/// Sources whose cuts are counted, at most; past it the least cut are forgotten (their totals stay
/// in the reason counts).
pub const SOURCES_COUNTED: usize = 4_096;
/// Sources a report names, the most cut first.
pub const SOURCES_REPORTED: usize = 16;
/// Tables the tracked units are split into: the water level is found a table at a time, a few
/// tables with each batch judged, so no judgement ever walks them all.
const TABLES: usize = 64;
/// Tables one judgement scans while a level is being found.
pub const TABLES_PER_JUDGEMENT: usize = 2;
/// Buckets of the histogram a level is found from: this many to an octave of rate, from one a
/// second.
const BUCKETS_PER_OCTAVE: usize = 16;
const OCTAVES: usize = 48;
const BUCKETS: usize = BUCKETS_PER_OCTAVE * OCTAVES;

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
    /// Nothing of it has been judged yet.
    fresh: bool,
    /// The room this entry holds in the shed store, let go with it.
    _room: Charge,
}

/// The token buckets, which every judgement takes from in the order stamps come.
struct Flow {
    rate: Rates,
    ceiling: Rates,
    buckets: [Bucket; DIMS],
    at_ms: u64,
}

/// A histogram of units by the rate they want, from which the water level is found without
/// sorting them.
struct Wants {
    counts: Vec<u32>,
    sums: Vec<f64>,
}

impl Wants {
    fn new() -> Self {
        Self {
            counts: vec![0; BUCKETS],
            sums: vec![0.0; BUCKETS],
        }
    }

    fn clear(&mut self) {
        self.counts.fill(0);
        self.sums.fill(0.0);
    }

    fn add(&mut self, want: f64) {
        let bucket = if want <= 1.0 {
            0
        } else {
            ((want.log2() * BUCKETS_PER_OCTAVE as f64) as usize).min(BUCKETS - 1)
        };
        self.counts[bucket] += 1;
        self.sums[bucket] += want;
    }

    /// The water level of a max-min fair division of `rate` among the units counted: the rate a
    /// unit wanting more is kept to, the rest of them keeping all they want. Infinite where
    /// demand is within `rate` (no unit is held to a share however many there are).
    fn level(&self, rate: f64) -> f64 {
        let mut left = rate;
        let mut remaining = self
            .counts
            .iter()
            .map(|count| f64::from(*count))
            .sum::<f64>();
        for (count, sum) in self.counts.iter().zip(&self.sums) {
            if *count == 0 {
                continue;
            }
            let count = f64::from(*count);
            if sum / count * remaining <= left {
                left -= sum;
                remaining -= count;
            } else {
                return left / remaining;
            }
        }
        f64::INFINITY
    }
}

/// The scan that finds the water level again, a few tables at a time.
struct Scan {
    /// Tables still to visit in this scan; none between scans.
    remaining: usize,
    next: usize,
    /// The stamp this scan reads rates at, and the stamp the last one began.
    at_ms: u64,
    began_ms: u64,
    wants: [Wants; DIMS],
}

/// The relay-wide rate, shared by every ingest worker.
pub struct Shedder {
    flow: Mutex<Flow>,
    bounded: bool,
    /// Units tracked, by table (a hash of the unit picks its table).
    tables: Vec<Mutex<HashMap<Unit, Use>>>,
    tracked: AtomicUsize,
    /// What a tracked unit holds ([`BYTES_PER_UNIT`]) is charged here when there is a store.
    room: Option<Arc<Gauge>>,
    scan: Mutex<Scan>,
    /// Tables the scans have visited, all told.
    visits: AtomicU64,
    /// The water level (an `f64`'s bits) per dimension, as the last scan found it.
    level: [AtomicU64; DIMS],
    counted: Mutex<HashMap<Unit, [u64; CAUSES]>>,
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

fn table_of(unit: Unit) -> usize {
    // The rank is a hash of the unit alone, spread over [0, 1).
    ((unit.rank() * TABLES as f64) as usize).min(TABLES - 1)
}

impl Shedder {
    /// A relay that sheds nothing for its rate (a test's hub, before it is planned).
    pub fn unbounded() -> Self {
        Self::bounded_by(Rates::UNBOUNDED, Rates::UNBOUNDED)
    }

    /// `rate` is `R_max`; `ceiling` is the per-receiver pace told to feeders, reported only: it is no cap on a group.
    pub fn new(rate: Rates, ceiling: Rates) -> Self {
        Self::bounded_by(rate, ceiling)
    }

    /// The units tracked are held in `room` (the shed store, [`BYTES_PER_UNIT`] each): a unit the
    /// store has no room for shares [`Unit::Overflow`] with every other.
    #[must_use]
    pub fn within(mut self, room: Arc<Gauge>) -> Self {
        self.room = Some(room);
        self
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
        let level = |dim: usize| AtomicU64::new(rates[dim].min(1e15).to_bits());
        Self {
            flow: Mutex::new(Flow {
                rate,
                ceiling,
                buckets: [bucket(0), bucket(1)],
                at_ms: 0,
            }),
            bounded,
            tables: (0..if bounded { TABLES } else { 0 })
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            tracked: AtomicUsize::new(0),
            room: None,
            scan: Mutex::new(Scan {
                remaining: 0,
                next: 0,
                at_ms: 0,
                began_ms: 0,
                wants: [Wants::new(), Wants::new()],
            }),
            visits: AtomicU64::new(0),
            level: [level(0), level(1)],
            counted: Mutex::new(HashMap::new()),
            batches: Default::default(),
            receptions: Default::default(),
        }
    }

    /// Tables of tracked units the water level's scans have visited, all told: a judgement visits
    /// at most [`TABLES_PER_JUDGEMENT`] of them.
    pub fn visited(&self) -> u64 {
        self.visits.load(Ordering::Relaxed)
    }

    /// Whether the relay sheds for its rate at all.
    pub fn is_bounded(&self) -> bool {
        self.bounded
    }

    /// `R_max`, when bounded.
    pub fn rate(&self) -> Option<Rates> {
        self.bounded.then(|| self.flow().rate)
    }

    fn flow(&self) -> std::sync::MutexGuard<'_, Flow> {
        self.flow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn level(&self, dim: usize) -> f64 {
        f64::from_bits(self.level[dim].load(Ordering::Relaxed))
    }

    /// Whether `unit`'s batch costing `cost`, stamped `stamp_ms`, is admitted. A cut is counted
    /// (per source and reason) before this returns it. Takes the bucket's tokens when admitted.
    /// The unit is judged on what it has attempted and been admitted including this batch, so a
    /// unit's first batch, or its only one in a long while, is judged as the rate it would make.
    pub fn judge(&self, unit: Unit, cost: Cost, stamp_ms: u64) -> Result<(), Cause> {
        if !self.bounded {
            return Ok(());
        }
        let (verdict, now) = {
            let mut flow = self.flow();
            let now = stamp_ms.max(flow.at_ms);
            (self.judged(&mut flow, unit, cost, now), now)
        };
        if let Err(cause) = verdict {
            self.count(unit, cause);
            self.add(cause, cost);
        }
        self.scanned(now);
        verdict
    }

    /// The table `unit` is tracked in, or the overflow's: a unit already tracked keeps its entry,
    /// one not yet tracked is given an entry while the store has room for it.
    fn entry<'a>(
        &'a self,
        unit: Unit,
        now: u64,
    ) -> (Unit, std::sync::MutexGuard<'a, HashMap<Unit, Use>>) {
        let lock = |unit: Unit| {
            self.tables[table_of(unit)]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let mut table = lock(unit);
        if table.contains_key(&unit) || unit == Unit::Overflow {
            return (unit, table);
        }
        let room = match &self.room {
            Some(gauge) => gauge.try_charge(BYTES_PER_UNIT),
            None => (self.tracked.load(Ordering::Relaxed) < UNITS_TRACKED).then(Charge::none),
        };
        if let Some(room) = room {
            self.tracked.fetch_add(1, Ordering::Relaxed);
            table.insert(unit, Use::new(now, room));
            return (unit, table);
        }
        drop(table);
        let mut table = lock(Unit::Overflow);
        table
            .entry(Unit::Overflow)
            .or_insert_with(|| Use::new(now, Charge::none()));
        (Unit::Overflow, table)
    }

    fn judged(&self, flow: &mut Flow, unit: Unit, cost: Cost, now: u64) -> Result<(), Cause> {
        // Time only goes forward: a stamp behind the newest read adds nothing to the bucket.
        let elapsed = now - flow.at_ms;
        flow.at_ms = now;
        for bucket in &mut flow.buckets {
            bucket.tokens = (bucket.tokens + elapsed as f64 * bucket.rate_per_ms).min(bucket.burst);
        }
        let attempted = cost.dims();
        let (resolved, mut table) = self.entry(unit, now);
        let fresh = table.get(&resolved).is_some_and(|used| used.fresh);
        let Some(used) = table.get_mut(&resolved) else {
            return Err(Cause::OverShare);
        };
        used.fresh = false;
        // What it has attempted and been admitted, this batch included: a unit new to the table,
        // or idle for a whole window, is judged on its batch as the rate it makes alone, never as
        // nothing. One with a history counts half of it (the sums are read just after an arrival,
        // when they stand at their highest: half a batch is what reads a steady rate unbiased).
        let weight = if fresh || now.saturating_sub(used.at_ms) >= WINDOW_MS {
            1.0
        } else {
            0.5
        };
        used.fade_to(now);
        for (sum, cost) in used.attempted.iter_mut().zip(attempted) {
            *sum += cost;
        }
        let window_s = WINDOW_MS as f64 / 1_000.0;
        let times = |sums: [f64; DIMS], extra: [f64; DIMS]| {
            (0..DIMS)
                .map(|dim| (sums[dim] + extra[dim]) / window_s / self.level(dim))
                .fold(0.0, f64::max)
        };
        let wants = times(used.attempted, attempted.map(|cost| (weight - 1.0) * cost));
        let has = times(used.admitted, attempted.map(|cost| weight * cost));
        let fits = (0..DIMS).all(|dim| flow.buckets[dim].tokens >= attempted[dim]);
        let verdict = if wants <= 1.0 {
            fits.then_some(()).ok_or(Cause::RelayRate)
        } else {
            // Over the level: kept to it by what it has been admitted, and, while the bucket is
            // short, held back by a mark that rises with how far over it wants, a hair more for
            // a higher key-hash rank: the furthest over goes first.
            let ranked = wants * (1.0 + resolved.rank() * 1e-6);
            let mark = RESERVE * (1.0 - 1.0 / ranked);
            let surplus = (0..DIMS).all(|dim| {
                let bucket = &flow.buckets[dim];
                (bucket.tokens - attempted[dim]) / bucket.burst >= mark
            });
            (has <= 1.0 && fits && surplus)
                .then_some(())
                .ok_or(Cause::OverShare)
        };
        if verdict.is_ok() {
            for (bucket, cost) in flow.buckets.iter_mut().zip(attempted) {
                bucket.tokens -= cost;
            }
            for (sum, cost) in used.admitted.iter_mut().zip(attempted) {
                *sum += cost;
            }
        }
        verdict
    }

    /// A cut made elsewhere at ingest (the receiver's own pace), counted with the rest. The batch
    /// was judged first (`judge` took its tokens and its unit's use), so a cut for the receiver's
    /// own pace gives all of it back: the relay's rate and a share are for what the relay keeps,
    /// not for a receiver past its own pace.
    pub fn cut(&self, unit: Unit, cause: Cause, cost: Cost) {
        if self.bounded && cause == Cause::ReceiverCeiling {
            let mut flow = self.flow();
            for (bucket, cost) in flow.buckets.iter_mut().zip(cost.dims()) {
                bucket.tokens = (bucket.tokens + cost).min(bucket.burst);
            }
            let (resolved, mut table) = self.entry(unit, flow.at_ms);
            if let Some(used) = table.get_mut(&resolved) {
                for (sum, cost) in used.attempted.iter_mut().zip(cost.dims()) {
                    *sum = (*sum - cost).max(0.0);
                }
                for (sum, cost) in used.admitted.iter_mut().zip(cost.dims()) {
                    *sum = (*sum - cost).max(0.0);
                }
            }
        }
        self.count(unit, cause);
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

    /// Finds the water level again every [`ACTIVE_MS`] / 4 of stamps, a few tables with each
    /// judgement: the cost of a scan is spread over the batches that follow it, never paid by one.
    /// Skipped where another worker is scanning.
    fn scanned(&self, now: u64) {
        let Ok(mut scan) = self.scan.try_lock() else {
            return;
        };
        if scan.remaining == 0 {
            if now < scan.began_ms + ACTIVE_MS / 4 {
                return;
            }
            scan.remaining = TABLES;
            scan.next = 0;
            scan.at_ms = now;
            scan.began_ms = now;
            for wants in &mut scan.wants {
                wants.clear();
            }
        }
        for _ in 0..TABLES_PER_JUDGEMENT.min(scan.remaining) {
            let at_ms = scan.at_ms;
            let index = scan.next;
            let mut table = self.tables[index]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = table.len();
            table.retain(|unit, used| {
                *unit == Unit::Overflow || at_ms.saturating_sub(used.at_ms) <= RETAIN_MS
            });
            self.tracked
                .fetch_sub(before - table.len(), Ordering::Relaxed);
            for used in table.values() {
                let wants = used.rates(at_ms);
                for (dim, want) in wants.into_iter().enumerate() {
                    scan.wants[dim].add(want);
                }
            }
            drop(table);
            scan.next += 1;
            scan.remaining -= 1;
            self.visits.fetch_add(1, Ordering::Relaxed);
        }
        if scan.remaining == 0 {
            let rate = self.flow().rate.dims();
            for ((wants, rate), stored) in scan.wants.iter().zip(rate).zip(&self.level) {
                stored.store(wants.level(rate).max(1.0).to_bits(), Ordering::Relaxed);
            }
        }
    }

    fn count(&self, unit: Unit, cause: Cause) {
        let mut counted = self
            .counted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        counted.entry(unit).or_default()[cause.index()] += 1;
        if counted.len() > SOURCES_COUNTED {
            let mut totals: Vec<u64> = counted.values().map(|counts| counts.iter().sum()).collect();
            totals.sort_unstable();
            let keep_from = totals[totals.len() / 4];
            counted.retain(|_, counts| counts.iter().sum::<u64>() > keep_from);
        }
    }

    pub fn report(&self) -> ShedReport {
        let cuts = |cause: Cause| Cuts {
            batches: self.batches[cause.index()].load(Ordering::Relaxed),
            receptions: self.receptions[cause.index()].load(Ordering::Relaxed),
        };
        let mut sources: Vec<(u64, SourceCuts)> = self
            .counted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let flow = self.flow();
        ShedReport {
            rate: self.bounded.then_some(flow.rate),
            ceiling: self.bounded.then_some(flow.ceiling),
            active_sources: self.tracked.load(Ordering::Relaxed),
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

impl Use {
    fn new(at_ms: u64, room: Charge) -> Self {
        Self {
            attempted: [0.0; DIMS],
            admitted: [0.0; DIMS],
            at_ms,
            fresh: true,
            _room: room,
        }
    }

    /// The sums faded from when they were last read to `now`.
    fn fade_to(&mut self, now: u64) {
        let fade = (-(now.saturating_sub(self.at_ms) as f64) / WINDOW_MS as f64).exp();
        for sum in self.attempted.iter_mut().chain(&mut self.admitted) {
            *sum *= fade;
        }
        self.at_ms = self.at_ms.max(now);
    }

    /// What the unit attempts a second, faded to `now`.
    fn rates(&self, now: u64) -> [f64; DIMS] {
        let fade = (-(now.saturating_sub(self.at_ms) as f64) / WINDOW_MS as f64).exp();
        self.attempted
            .map(|sum| sum * fade / (WINDOW_MS as f64 / 1_000.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Store;

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

    /// Many keys behind one group, as one unit, in tenths of a second.
    fn run_group(shedder: &Shedder, unit: Unit, keys: u64, per_key: u64, seconds: u64) -> u64 {
        let mut admitted = 0;
        for tick in 0..seconds * 10 {
            for key in 0..keys {
                let stamp = tick * 100 + key * 100 / keys;
                if shedder.judge(unit, cost(per_key / 10), stamp).is_ok() {
                    admitted += per_key / 10;
                }
            }
        }
        admitted
    }

    #[test]
    fn nothing_is_cut_while_demand_is_within_the_rate_whatever_the_group_layout() {
        // One group of 100 keys at 90 a second each: 9,000 a second against 10,000, three times
        // the source ceiling, all in one /16.
        let shedder = Shedder::new(RATE, CEILING);
        assert_eq!(
            run_group(&shedder, group(1), 100, 90, 20),
            9_000 * 20,
            "a lone group within R_max is cut for nothing"
        );
        let report = shedder.report();
        assert_eq!(report.over_share.batches + report.relay_rate.batches, 0);
        // Two groups, one of them far past the ceiling, together within the rate.
        let shedder = Shedder::new(RATE, CEILING);
        let sources = [(group(1), 6_000), (group(2), 3_900)];
        let admitted = run(&shedder, &sources, 20);
        assert_eq!(got(&admitted, group(1)), 6_000 * 20);
        assert_eq!(got(&admitted, group(2)), 3_900 * 20);
    }

    #[test]
    fn past_the_rate_honest_groups_keep_their_share_and_a_sybil_group_holds_one() {
        let seconds = 30;
        let shedder = Shedder::new(RATE, CEILING);
        // Four honest groups at 1,500 (6,000) and one Sybil group of 200 keys at 450 each
        // (90,000): the Sybil holds the 4,000 the honest leave, as one share.
        let sybil = group(500);
        let mut honest = 0;
        let mut hostile = 0;
        for tick in 0..seconds * 10 {
            for n in 0..4u16 {
                let stamp = tick * 100 + u64::from(n) * 25;
                if shedder.judge(group(n), cost(150), stamp).is_ok() {
                    honest += 150;
                }
            }
            for key in 0..200u64 {
                if shedder
                    .judge(sybil, cost(45), tick * 100 + 10 + key / 4)
                    .is_ok()
                {
                    hostile += 45;
                }
            }
        }
        assert!(honest >= 4 * 1_500 * (seconds - 1), "honest kept {honest}");
        assert!(
            hostile <= 4_500 * seconds,
            "the Sybil set holds one share: {hostile}"
        );
        assert!(hostile > 0);
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

    /// Batches in the order of their stamps, as `(stamp, unit, receptions)`.
    fn replay(shedder: &Shedder, mut events: Vec<(u64, Unit, u64)>) -> Vec<(u64, Unit, u64, bool)> {
        events.sort_by_key(|(stamp, ..)| *stamp);
        events
            .into_iter()
            .map(|(stamp, unit, receptions)| {
                let kept = shedder.judge(unit, cost(receptions), stamp).is_ok();
                (stamp, unit, receptions, kept)
            })
            .collect()
    }

    fn kept_after(
        replayed: &[(u64, Unit, u64, bool)],
        from_ms: u64,
        wanted: impl Fn(Unit) -> bool,
    ) -> (u64, u64) {
        let (mut offered, mut kept) = (0, 0);
        for (stamp, unit, receptions, was_kept) in replayed {
            if *stamp >= from_ms && wanted(*unit) {
                offered += receptions;
                if *was_kept {
                    kept += receptions;
                }
            }
        }
        (offered, kept)
    }

    /// A unit's first batch is judged as the rate it makes, not as nothing: twenty groups
    /// that each send one large batch every 2.1 seconds (so each is a newcomer to a table that
    /// forgets the idle after two seconds, and its usage before the batch is always zero) do not
    /// drain the bucket and cut the honest groups that are within their share.
    #[test]
    fn newcomers_sending_one_large_batch_each_cannot_drain_the_bucket() {
        let shedder = Shedder::new(RATE, CEILING);
        let mut events = Vec::new();
        for tick in 0..300u64 {
            for n in 0..5u16 {
                events.push((tick * 100 + u64::from(n), group(n), 30));
            }
        }
        for n in 0..20u64 {
            for round in 0..14u64 {
                events.push((n * 100 + round * 2_100, group(1_000 + n as u16), 3_000));
            }
        }
        let replayed = replay(&shedder, events);
        let honest = |unit: Unit| (0..5).any(|n| unit == group(n));
        let (offered, kept) = kept_after(&replayed, 8_000, honest);
        assert!(
            kept * 100 >= offered * 99,
            "honest groups within their share kept {kept} of {offered}"
        );
        let (offered, kept) = kept_after(&replayed, 8_000, |unit| !honest(unit));
        assert!(
            kept * 10 <= offered,
            "the swarm of newcomers kept {kept} of {offered}"
        );
    }

    /// A batch cut for its receiver's own pace gives back its group's use as well as the
    /// bucket's tokens: a hostile key behind a group that floods past its own pace (every batch
    /// judged, then cut) does not make the group look over its share and cut the honest key
    /// beside it.
    #[test]
    fn a_batch_cut_for_its_receivers_pace_leaves_its_group_no_poorer() {
        let shedder = Shedder::new(RATE, CEILING);
        let mixed = group(50);
        let mut honest = (0, 0);
        for tick in 0..300u64 {
            let stamp = tick * 100;
            for n in 0..4u16 {
                // Four groups at 2,000 a second: 8,000 of the 10,000.
                let _ = shedder.judge(group(n), cost(200), stamp + u64::from(n));
            }
            if shedder.judge(mixed, cost(50), stamp + 10).is_ok() {
                honest.1 += 50;
            }
            honest.0 += 50;
            // The hostile key's batch, 5,000 a second beyond its pace: judged, then cut.
            let flood = cost(500);
            if shedder.judge(mixed, flood, stamp + 11).is_ok() {
                shedder.cut(mixed, Cause::ReceiverCeiling, flood);
            }
        }
        assert!(
            honest.1 * 100 >= honest.0 * 99,
            "the honest key in a flooded group kept {} of {}",
            honest.1,
            honest.0
        );
    }

    /// Five thousand honest groups beside a few hostile ones, past `R_max`: every honest group
    /// keeps its batches and the hostile hold what the honest leave, at a scale of thousands of
    /// sources rather than tens.
    #[test]
    fn at_thousands_of_sources_the_honest_keep_their_share_and_the_hostile_the_rest() {
        let rate = Rates {
            receptions_per_s: 1_000_000,
            bytes_per_s: 1_000_000_000,
        };
        let shedder = Shedder::new(rate, CEILING);
        let mut events = Vec::new();
        for tick in 0..100u64 {
            for n in 0..5_000u64 {
                events.push((tick * 100 + n % 100, group(n as u16), 10));
            }
            for n in 0..50u64 {
                events.push((tick * 100 + n, group(10_000 + n as u16), 3_000));
            }
        }
        let replayed = replay(&shedder, events);
        let honest = |unit: Unit| matches!(unit, Unit::Group(Some(Group::V4(n))) if n < 5_000);
        let (offered, kept) = kept_after(&replayed, 3_000, honest);
        assert!(
            kept * 100 >= offered * 99,
            "5,000 honest groups kept {kept} of {offered}"
        );
        let (offered, kept) = kept_after(&replayed, 3_000, |unit| !honest(unit));
        // What the honest leave of 1,000,000 a second (500,000), over 7 seconds, with the bucket.
        assert!(
            kept <= 7 * 500_000 + 2 * 500_000 && kept > 0,
            "the hostile kept {kept} of {offered}"
        );
    }

    /// Every feeder seals on the same second (an epoch closes): all of them send their batch at
    /// one stamp, each second. The bucket's second of burst carries it while demand is within
    /// `R_max`, and nothing is cut; past `R_max` the total admitted is still at most the rate and
    /// the burst, and every cut is counted.
    #[test]
    fn all_feeders_bursting_at_an_epoch_close_are_carried_within_the_rate() {
        let rate = Rates {
            receptions_per_s: 132_000,
            bytes_per_s: 1_000_000_000,
        };
        let shedder = Shedder::new(rate, CEILING);
        let events: Vec<_> = (0..20u64)
            .flat_map(|second| (0..200u16).map(move |n| (second * 1_000, group(n), 600)))
            .collect();
        let replayed = replay(&shedder, events);
        assert!(
            replayed.iter().all(|(.., kept)| *kept),
            "demand within R_max is carried whatever the batches' alignment"
        );
        let shedder = Shedder::new(rate, CEILING);
        let events: Vec<_> = (0..20u64)
            .flat_map(|second| (0..400u16).map(move |n| (second * 1_000, group(n), 600)))
            .collect();
        let replayed = replay(&shedder, events);
        let total: u64 = replayed
            .iter()
            .filter(|(.., kept)| *kept)
            .map(|(_, _, receptions, _)| receptions)
            .sum();
        assert!(total <= 21 * 132_000, "R_max and one burst: {total}");
        let report = shedder.report();
        let cut = report.over_share.receptions + report.relay_rate.receptions;
        assert_eq!(cut + total, 20 * 400 * 600, "every cut is counted");
    }

    /// A receiver this relay corroborated has a share of its own: past `R_max` it keeps what it
    /// wants while a flooded group is held to one share, the receiver's own group not charged for
    /// it.
    #[test]
    fn a_corroborated_unit_keeps_its_share_past_the_rate() {
        let key = tally_wire::Identity::from_seed([3; 32]).public();
        let proven = Unit::Corroborated(key);
        let shedder = Shedder::new(RATE, CEILING);
        let mut events = Vec::new();
        for tick in 0..300u64 {
            events.push((tick * 100, proven, 200));
            // The flooded network, which the proven receiver is in: 20,000 a second.
            for n in 0..20u64 {
                events.push((tick * 100 + 1 + n, group(7), 100));
            }
            for n in 0..4u16 {
                events.push((tick * 100 + 30 + u64::from(n), group(n), 150));
            }
        }
        let replayed = replay(&shedder, events);
        let (offered, kept) = kept_after(&replayed, 5_000, |unit| unit == proven);
        assert_eq!(kept, offered, "the corroborated receiver kept all it sent");
        let (offered, kept) = kept_after(&replayed, 5_000, |unit| unit == group(7));
        assert!(
            kept * 2 < offered,
            "the flooded group was cut: {kept} of {offered}"
        );
    }

    /// The units tracked are a store's, and bounded by it: past the room it holds, every further
    /// unit is judged together as one (never first to be cut, never a table that grows), and a
    /// unit idle past its retention gives its room back.
    #[test]
    fn tracked_units_are_a_stores_and_the_rest_share_one_overflow_unit() {
        let room = Gauge::new(Store::Shed, BYTES_PER_UNIT * 100);
        let shedder = Shedder::new(RATE, CEILING).within(Arc::clone(&room));
        for n in 0..1_000u64 {
            let _ = shedder.judge(group(n as u16), cost(10), n);
        }
        assert!(room.held() <= BYTES_PER_UNIT * 100, "{}", room.held());
        assert_eq!(shedder.report().active_sources, 100);
        // A newcomer past the room is judged with the others past it, as a unit within its share.
        let unit = group(60_000);
        assert!(shedder.judge(unit, cost(10), 1_001).is_ok());
        // Left idle, they all go, and the room is whole again.
        for tick in 0..200u64 {
            let _ = shedder.judge(group(0), cost(1), 20_000 + tick * 100);
        }
        assert!(room.held() <= BYTES_PER_UNIT * 2, "{}", room.held());
        assert!(shedder.report().active_sources <= 2);
    }

    /// The water level is found a few tables at a time with the batches judged, never all at once
    /// by one: a judgement visits at most `TABLES_PER_JUDGEMENT` of the units' tables, with a
    /// hundred thousand units tracked, and the level still comes round.
    #[test]
    fn no_judgement_walks_all_the_tracked_units() {
        let rate = Rates {
            receptions_per_s: 1_000_000,
            bytes_per_s: 1_000_000_000,
        };
        let shedder = Shedder::new(rate, CEILING);
        for n in 0..100_000u64 {
            let _ = shedder.judge(group((n % 60_000) as u16), cost(1), n % 400);
        }
        let mut most = 0;
        let mut rounds = 0;
        for call in 0..2_000u64 {
            let before = shedder.visited();
            let _ = shedder.judge(group(1), cost(1), 5_000 + call * 10);
            most = most.max(shedder.visited() - before);
            rounds = shedder.visited() / TABLES as u64;
        }
        assert!(
            most <= TABLES_PER_JUDGEMENT as u64,
            "{most} tables in one judgement"
        );
        assert!(rounds >= 2, "the level was found again, {rounds} times");
    }
}
