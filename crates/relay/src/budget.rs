//! Capacity is admission, never a silent drop inside a store (RFC-0181 §9). Every store and
//! every queue that holds something per feeder ([`Store`]) states what one feeder costs it
//! ([`PerFeeder::planned`]); a feeder's bytes in every store are reserved together when it is
//! admitted ([`Budget::reserve`]), beside the upload cap's headroom check (RFC-0171, `admission`),
//! and released when it leaves ([`Reservation`] dropped). A sharing member reserves the feeders its
//! ingest ceiling is worth ([`Budget::reserve_feeders`]), so data from peers is admitted the same
//! way. The feeder ceiling is what the relay's memory (`--memory`, by default what the relay's
//! cgroup or the host allows, [`memory_available`]) holds of that sum, after its own base ([`Plan::base`]: [`BASE_BYTES`], and
//! [`MLAT_BASE_BYTES`] more when it hosts MLAT); a
//! Hello beyond it is refused ("no spare slot"), and a relay whose memory admits no feeder at all
//! refuses to start ([`Budget::check`]). The MLAT engine's receiver limit comes from the same
//! ceiling.
//!
//! The reservation is a plan; each store's [`Gauge`] is what holds the plan. Every store and queue
//! that holds bytes beyond one batch at a time charges its gauge ([`Gauge::try_charge`],
//! [`Gauge::charge`]) for what it holds and is released when it lets go ([`Charge`] dropped). A
//! gauge's limit is that store's share at the ceiling (`per feeder x ceiling`), so the stores
//! together never hold more than the relay's memory, whatever arrives and however slow a stage is.
//! A charge is taken before the bytes are held, never after: there is no way to charge a gauge
//! past its limit, so a store whose stage falls behind cannot grow past its share by holding what
//! it already took. What a full gauge does is the store's policy (RFC-0181 §10): raw pushes back (a
//! connection's batch waits for room, its socket unread), derived products refuse whole (an epoch,
//! counted), the fan-out lets its laggard go, and hosted MLAT sheds whole steps it is behind on
//! (`mlat_host`). The gauges are served on `--stats-listen` (`GET /memory`).
//!
//! The per-feeder costs are planning figures at the rate the RFC sizes a feeder to
//! ([`PLANNED_RECEPTIONS_PER_SEC`], [`PLANNED_BYTES_PER_SEC`]) times each store's own window,
//! named where the store defines it, so a store that changes its window changes its reservation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::sync::Notify;

/// The stores that hold bytes per feeder: every store and queue of the relay whose size grows
/// with what feeders send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Store {
    /// The one batch byte store, over the sharing repair horizon.
    Batches,
    /// MLAT's sealed raw (`Held`'s sealed bins), shared by the engine and standing.
    Held,
    /// MLAT's open raw: the bins not yet sealed, in the raw shards and on their way to sealing,
    /// over a bin, its settling and the steps MLAT may fall behind (`mlat_host::STEPS_BEHIND`).
    Open,
    /// What batches told hosted MLAT's provisional solving and its step has not yet weighed: the
    /// decoded batches the notes keep alive, and the notes (`mlat_host::NOTES_PER_RECEIVER_STEP`),
    /// over the step intervals MLAT may fall behind; and the batches of receivers not yet described.
    Notes,
    /// The hosted engine's own tables that grow with its receivers: the receptions waiting for
    /// provisional solving (`tally_mlat::engine::Capacity::waiting`) and a window step's working
    /// set while it runs (`mlat_host::SOLVE_BYTES_PER_RECEIVER`).
    Engine,
    /// The message exchange's generations of fingerprints (`exchange::DEDUP_GENERATIONS`).
    Dedup,
    /// Subscriber queues' share of one feeder's inbound.
    Fanout,
    /// Delivery tags over the audit window.
    Delivery,
    /// Connection buffers.
    Buffers,
    /// Batches read off connections and waiting for, or in, the ingest stage (`ingest::CREDIT`).
    Ingest,
    /// Decoded batches between ingest and the sealer: each epoch open in the message exchange,
    /// closing, and waiting at the sealer (`seal::EPOCHS_HELD`).
    Epochs,
    /// What the sealer has signed and the hub has not yet taken (the deduplicated stream's
    /// batches and the products), and the peers' records waiting for the sealer.
    Products,
}

impl Store {
    pub const ALL: [Self; 12] = [
        Self::Batches,
        Self::Held,
        Self::Open,
        Self::Notes,
        Self::Engine,
        Self::Dedup,
        Self::Fanout,
        Self::Delivery,
        Self::Buffers,
        Self::Ingest,
        Self::Epochs,
        Self::Products,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// What one feeder costs each store, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerFeeder {
    pub batches: usize,
    pub held: usize,
    pub open: usize,
    pub notes: usize,
    pub engine: usize,
    pub dedup: usize,
    pub fanout: usize,
    pub delivery: usize,
    pub buffers: usize,
    pub ingest: usize,
    pub epochs: usize,
    pub products: usize,
}

impl PerFeeder {
    pub fn of(&self, store: Store) -> usize {
        match store {
            Store::Batches => self.batches,
            Store::Held => self.held,
            Store::Open => self.open,
            Store::Notes => self.notes,
            Store::Engine => self.engine,
            Store::Dedup => self.dedup,
            Store::Fanout => self.fanout,
            Store::Delivery => self.delivery,
            Store::Buffers => self.buffers,
            Store::Ingest => self.ingest,
            Store::Epochs => self.epochs,
            Store::Products => self.products,
        }
    }

    /// Every store's cost together: what admitting one feeder reserves.
    pub fn total(&self) -> usize {
        Store::ALL
            .iter()
            .fold(0usize, |sum, store| sum.saturating_add(self.of(*store)))
    }

    /// What one feeder at the planned rate costs each store over that store's window. `holds_raw`:
    /// whether this relay holds MLAT raw (`Held`, `Open`) at all, which it does only when it hosts
    /// MLAT.
    pub fn planned(holds_raw: bool) -> Self {
        let receptions = PLANNED_RECEPTIONS_PER_SEC;
        let bytes = PLANNED_BYTES_PER_SEC;
        // One second of one feeder's batches as the stages hold them: signed, inflated once, each
        // reception referenced (`tally_wire::Decoded::footprint`).
        let decoded = bytes + receptions * DECODED_BYTES_PER_RECEPTION;
        Self {
            // The one batch byte store, over the sharing repair horizon.
            batches: bytes * crate::sharing::member::HORIZON_SECONDS as usize,
            // MLAT's sealed raw (`Held`): the sealed bins a holder keeps, at the rates measured
            // (`held::Rates::MEASURED`).
            held: if holds_raw {
                tally_mlat_solver::held::Rates::MEASURED
                    .cost(crate::mlat_host::SETTLE_MS)
                    .sealed
            } else {
                0
            },
            // MLAT's open raw (`Open`): a receiver's bins open over a bin, the engine's settling
            // and the steps it may fall behind before the oldest is shed
            // (`mlat_host::OPEN_MS`), at its ceiling.
            open: if holds_raw {
                tally_mlat_solver::held::Rates::MEASURED
                    .cost(crate::mlat_host::OPEN_MS)
                    .open
            } else {
                0
            },
            // Provisional solving's notes, where MLAT is hosted: a batch told is held (its decode
            // kept alive, and its notes) until the step after its stamp's interval weighs it, and
            // the steps MLAT may fall behind wait with theirs, so `mlat_host::INTERVALS_HELD` step
            // intervals of decoded batches, and the notes a step admits a seat
            // (`mlat_host::NOTES_PER_RECEIVER_STEP`) for each.
            notes: if holds_raw {
                let step = crate::mlat_host::STEP_MS as usize;
                crate::mlat_host::INTERVALS_HELD
                    * (decoded * step / 1_000
                        + crate::mlat_host::NOTES_PER_RECEIVER_STEP
                            * std::mem::size_of::<tally_mlat::provisional::Note>())
            } else {
                0
            },
            // The engine's own tables (`Engine`): the receptions a seat may have waiting for
            // provisional solving, and its share of a window step's working set.
            engine: if holds_raw {
                tally_mlat::engine::WAITING_PER_RECEIVER * tally_mlat::provisional::WAITING_BYTES
                    + crate::mlat_host::SOLVE_BYTES_PER_RECEIVER
            } else {
                0
            },
            // `exchange::DEDUP_GENERATIONS` generations of fingerprints, one epoch each, the
            // deduplication's window (`exchange::DEDUP_WINDOW_MS`), as if no reception were a copy
            // of another's, with the tables' room to grow.
            dedup: receptions
                * crate::exchange::DEDUP_SLOTS_PER_RECEPTION
                * crate::exchange::DEDUP_ENTRY_BYTES
                * crate::seal::EPOCH_MS as usize
                / 1_000,
            // A subscriber's queue holds `BEHIND_MS` of inbound: the batches, and while they wait
            // their one decode.
            fanout: decoded * crate::fanout::BEHIND_MS as usize / 1_000,
            // A delivery tag per batch over the audit window (`delivery`).
            delivery: crate::delivery::PER_FEEDER_BYTES,
            // A connection's Noise buffers come from one pool and an idle connection holds none
            // (`noise`): what the pool keeps idle is the process's (`BASE_BYTES`), not a feeder's.
            buffers: 0,
            // A connection's credit of batches read and not yet decoded (`ingest::CREDIT`), at a
            // second's batches each.
            ingest: crate::ingest::CREDIT * bytes,
            // The decoded batches of the epochs between ingest and the sealer.
            epochs: decoded * crate::seal::EPOCHS_HELD as usize * crate::seal::EPOCH_MS as usize
                / 1_000,
            // What the sealer signed of those epochs and the hub has not taken: every reception
            // twice as a signed record's observation, in the deduplicated stream and in its area's
            // regional batch, as if none were a copy (`products::OUTBOX_EPOCHS`).
            products: receptions * PRODUCT_BYTES_PER_RECEPTION * crate::products::OUTBOX_EPOCHS,
        }
    }
}

/// The rate the RFC sizes one feeder to: about 600 receptions and 8 KB of signed batches a second
/// (RFC-0181, "Requirement").
pub const PLANNED_RECEPTIONS_PER_SEC: usize = 600;
pub const PLANNED_BYTES_PER_SEC: usize = 8 * 1024;
/// One reception in a decoded batch: its reference, and its encoded observation in the inflated
/// bytes (the fixed part and a 14-byte Mode S message).
const DECODED_BYTES_PER_RECEPTION: usize =
    std::mem::size_of::<tally_wire::ObsRef>() + tally_wire::decoded::OBSERVATION_FIXED + 14;
/// One reception as the products hold it before the hub takes them: its encoded observation (the
/// fixed part and a 14-byte Mode S message) in two signed records, the deduplicated stream's batch
/// and its area's regional batch. Both are signed from the epoch's batches, so neither holds an
/// owned copy (`deduplicated::Stream::sign`, `tally_wire::RegionalBatch::sign_draft`).
const PRODUCT_BYTES_PER_RECEPTION: usize = 2 * (tally_wire::decoded::OBSERVATION_FIXED + 14);
/// What the relay holds whatever its feeders: descriptions, stream tables, the runtime and the one
/// batch each ingest worker is decoding (256 MiB), and the connection buffers the Noise pool keeps
/// idle (`noise::POOL_IDLE` messages). Measured (RFC-0181, "Sizing", 2026-10-07): resident memory
/// grew 247 KiB a feeder from 1,000 to 5,000 feeders and about 100 KiB from 5,000 to 20,000, so the
/// cost of a feeder falls as feeders are added and the 1k/5k line taken back to no feeders (260 MiB)
/// is an upper bound on the base. A feeder's reservation (`PerFeeder::planned`) is several times
/// that measured growth, so this base is safe at any load.
pub const BASE_BYTES: usize =
    (256 << 20) + tally_wire::noise::POOL_IDLE * tally_wire::noise::MAX_MESSAGE;
/// What hosting MLAT adds to the relay's own base, whatever its feeders: the engine's thread, its
/// pool and its empty tables (its raw is `Held`'s and `Open`'s, its notes `Notes`', its waiting
/// receptions and working set `Engine`'s, per feeder), and the signed records not yet taken
/// (`mlat_host::PUBLISHED_BYTES`). Measured (RFC-0181, "Sizing", 2026-10-08): a relay hosting MLAT
/// on two areas, before any feeder, was 19.8 MiB resident where the same relay without it was
/// 17.3 MiB. 2.5 MiB measured, held at 4 MiB, and the records' bound beside it.
pub const MLAT_BASE_BYTES: usize = (4 << 20) + crate::mlat_host::PUBLISHED_BYTES;

/// What a relay plans to hold: its own base, and each feeder's cost in every store. Both follow
/// one switch, whether the relay hosts MLAT, so the base and the reservation cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub base: usize,
    pub per_feeder: PerFeeder,
}

impl Plan {
    /// The plan of a relay that hosts MLAT (`hosts_mlat`) or does not.
    pub fn planned(hosts_mlat: bool) -> Self {
        Self {
            base: BASE_BYTES + if hosts_mlat { MLAT_BASE_BYTES } else { 0 },
            per_feeder: PerFeeder::planned(hosts_mlat),
        }
    }
}

/// The bytes this relay may use, unless told (`--memory`): its cgroup's limit when it has one,
/// else the host's memory.
pub fn memory_available() -> usize {
    cgroup_limit()
        .or_else(host_memory)
        .unwrap_or(BASE_BYTES * 4)
}

/// cgroup v2's `memory.max` for this process, when it is a number.
fn cgroup_limit() -> Option<usize> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim();
    let max = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.max")).ok()?;
    max.trim().parse().ok()
}

/// `MemTotal` of `/proc/meminfo`.
fn host_memory() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib: usize = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

/// One store's bytes held now, against its limit (its share of the budget at the ceiling).
#[derive(Debug)]
pub struct Gauge {
    store: Store,
    limit: AtomicUsize,
    held: AtomicUsize,
    peak: AtomicUsize,
    /// Charges refused for room (`try_charge`), and charges that waited for it (`charge`).
    refused: AtomicU64,
    waited: AtomicU64,
    /// Charges waiting for room now: a release wakes them only when there are any.
    waiting: AtomicUsize,
    released: Notify,
}

impl Gauge {
    pub fn new(store: Store, limit: usize) -> Arc<Self> {
        Arc::new(Self {
            store,
            limit: AtomicUsize::new(limit),
            held: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            refused: AtomicU64::new(0),
            waited: AtomicU64::new(0),
            waiting: AtomicUsize::new(0),
            released: Notify::new(),
        })
    }

    /// A gauge of no store, never full: for a part built without a budget (a test's).
    pub fn unlimited(store: Store) -> Arc<Self> {
        Self::new(store, usize::MAX)
    }

    pub fn store(&self) -> Store {
        self.store
    }

    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Release);
        self.released.notify_waiters();
    }

    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn waited(&self) -> u64 {
        self.waited.load(Ordering::Relaxed)
    }

    /// Takes `bytes` if they fit under the limit. A charge larger than the whole limit is taken
    /// only while nothing else is held, so one oversized item is never refused forever.
    fn take(self: &Arc<Self>, bytes: usize) -> Option<Charge> {
        let limit = self.limit();
        let taken = self
            .held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                let after = held.checked_add(bytes)?;
                (after <= limit || held == 0).then_some(after)
            })
            .ok()?;
        self.peak.fetch_max(taken + bytes, Ordering::Relaxed);
        Some(Charge {
            gauge: Some(Arc::clone(self)),
            bytes,
        })
    }

    /// A charge of nothing yet on this gauge, to grow (`Charge::try_grow`).
    pub fn empty(self: &Arc<Self>) -> Charge {
        Charge {
            gauge: Some(Arc::clone(self)),
            bytes: 0,
        }
    }

    /// Whether `bytes` more would fit now.
    pub fn fits(&self, bytes: usize) -> bool {
        self.held().saturating_add(bytes) <= self.limit()
    }

    /// `bytes` charged now, or `None` (counted) when the store is full: for a store that refuses
    /// whole.
    pub fn try_charge(self: &Arc<Self>, bytes: usize) -> Option<Charge> {
        let charge = self.take(bytes);
        if charge.is_none() {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        charge
    }

    /// `bytes` charged, waiting for room while the store is full: for a store that pushes back.
    pub async fn charge(self: &Arc<Self>, bytes: usize) -> Charge {
        if let Some(charge) = self.take(bytes) {
            return charge;
        }
        self.waited.fetch_add(1, Ordering::Relaxed);
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let _waiting = Waiting(&self.waiting);
        loop {
            let released = self.released.notified();
            if let Some(charge) = self.take(bytes) {
                return charge;
            }
            released.await;
        }
    }

    fn release(&self, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::SeqCst);
        // A waiter counts itself before it looks for room (all sequentially consistent), so a
        // release its look missed sees it waiting.
        if self.waiting.load(Ordering::SeqCst) > 0 {
            self.released.notify_waiters();
        }
    }

    pub fn report(&self) -> GaugeReport {
        GaugeReport {
            store: self.store,
            held: self.held(),
            limit: self.limit(),
            peak: self.peak(),
            refused: self.refused(),
            waited: self.waited(),
        }
    }
}

/// A charge waiting for room, counted while it waits (however its wait ends).
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Bytes a store holds for one thing, released when it is dropped.
#[derive(Debug, Default)]
pub struct Charge {
    gauge: Option<Arc<Gauge>>,
    bytes: usize,
}

impl Charge {
    /// Nothing charged.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// `bytes` more on the same gauge, if they fit (a charge of nothing never grows): false,
    /// counted, when the store is full.
    pub fn try_grow(&mut self, bytes: usize) -> bool {
        let Some(gauge) = &self.gauge else {
            return bytes == 0;
        };
        match gauge.try_charge(bytes) {
            Some(mut more) => {
                more.gauge = None;
                self.bytes += more.bytes;
                true
            }
            None => false,
        }
    }

    /// `bytes` of this charge (all of it, if it holds less) moved into a charge of their own on the
    /// same gauge, nothing taken or released: what a store hands on with the thing it holds (open
    /// raw handed to its seal).
    pub fn split(&mut self, bytes: usize) -> Charge {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        Charge {
            gauge: self.gauge.clone(),
            bytes,
        }
    }

    /// Releases all but `bytes` of this charge.
    pub fn shrink_to(&mut self, bytes: usize) {
        if let Some(gauge) = &self.gauge
            && bytes < self.bytes
        {
            gauge.release(self.bytes - bytes);
            self.bytes = bytes;
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        if let Some(gauge) = self.gauge.take() {
            gauge.release(self.bytes);
        }
    }
}

/// One store as served on `GET /memory`.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct GaugeReport {
    pub store: Store,
    pub held: usize,
    pub limit: usize,
    pub peak: usize,
    pub refused: u64,
    pub waited: u64,
}

/// The relay's memory for feeders, how much of it admitted feeders hold, and each store's gauge.
#[derive(Debug)]
pub struct Budget {
    memory: usize,
    /// What the relay holds whatever its feeders (`Plan::base`).
    base: usize,
    total: usize,
    per_feeder: PerFeeder,
    reserved: Arc<AtomicUsize>,
    gauges: Arc<[Arc<Gauge>]>,
}

impl Budget {
    /// The budget of a relay that may use `memory` bytes: what is left after its base.
    pub fn of_memory(memory: usize, plan: Plan) -> Self {
        let mut budget = Self::new(memory.saturating_sub(plan.base), plan.per_feeder);
        budget.memory = memory;
        budget.base = plan.base;
        budget
    }

    /// A budget of `total` bytes for feeders, above a base of `BASE_BYTES`.
    pub fn new(total: usize, per_feeder: PerFeeder) -> Self {
        let gauges: Arc<[Arc<Gauge>]> = Store::ALL
            .iter()
            .map(|store| Gauge::new(*store, 0))
            .collect();
        let budget = Self {
            memory: total.saturating_add(BASE_BYTES),
            base: BASE_BYTES,
            total,
            per_feeder,
            reserved: Arc::new(AtomicUsize::new(0)),
            gauges,
        };
        budget.limit_gauges();
        budget
    }

    /// The same gauges (whoever holds one keeps it), resized for `memory` bytes: what a relay is
    /// told after its parts were built.
    pub fn resize(&mut self, memory: usize, plan: Plan) {
        self.memory = memory;
        self.base = plan.base;
        self.total = memory.saturating_sub(plan.base);
        self.per_feeder = plan.per_feeder;
        self.limit_gauges();
    }

    fn limit_gauges(&self) {
        for store in Store::ALL {
            self.gauges[store.index()].set_limit(self.store_bytes(store));
        }
    }

    /// Whether the budget admits a feeder at all: a relay that would refuse every Hello refuses to
    /// start instead, saying what it was given and what it needs.
    pub fn check(&self) -> Result<(), String> {
        if self.ceiling() > 0 {
            return Ok(());
        }
        Err(format!(
            "{} bytes of memory admit no feeder: the relay needs {} bytes for itself and {} \
             for each feeder; give it more (--memory, or the unit's MemoryMax)",
            self.memory,
            self.base,
            self.per_feeder.total()
        ))
    }

    /// The least memory that admits `feeders`.
    pub fn memory_for(feeders: usize, plan: Plan) -> usize {
        plan.base
            .saturating_add(plan.per_feeder.total().saturating_mul(feeders))
    }

    /// The most feeders the budget admits: the feeder ceiling.
    pub fn ceiling(&self) -> usize {
        self.total
            .checked_div(self.per_feeder.total())
            .unwrap_or(usize::MAX)
    }

    /// Reserves one feeder's bytes in every store, or `None` when they do not fit (the Hello is
    /// refused).
    pub fn reserve(&self) -> Option<Reservation> {
        self.reserve_feeders(1)
    }

    /// Reserves `feeders` feeders' bytes in every store at once: what a sharing member, which
    /// forwards many receivers' records up to its own ceiling, reserves for as long as it is
    /// linked (`feeders_for_rate`). `None` when they do not fit.
    pub fn reserve_feeders(&self, feeders: usize) -> Option<Reservation> {
        let needed = self.per_feeder.total().saturating_mul(feeders);
        self.reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                reserved
                    .checked_add(needed)
                    .filter(|after| *after <= self.total)
            })
            .ok()?;
        Some(Reservation {
            bytes: needed,
            reserved: Arc::clone(&self.reserved),
        })
    }

    /// The feeders a connection allowed `bytes_per_sec` is worth: its ceiling over a planned
    /// feeder's rate, rounded up.
    pub fn feeders_for_rate(bytes_per_sec: u64) -> usize {
        usize::try_from(bytes_per_sec)
            .unwrap_or(usize::MAX)
            .div_ceil(PLANNED_BYTES_PER_SEC)
            .max(1)
    }

    pub fn reserved(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }

    pub fn per_feeder(&self) -> PerFeeder {
        self.per_feeder
    }

    pub fn memory(&self) -> usize {
        self.memory
    }

    /// What the relay holds whatever its feeders.
    pub fn base(&self) -> usize {
        self.base
    }

    /// What the relay plans to hold at its ceiling: its base and every admitted feeder's share
    /// (`memory`, less what no whole feeder fits in).
    pub fn planned(&self) -> usize {
        self.base
            .saturating_add(self.per_feeder.total().saturating_mul(self.ceiling()))
    }

    /// What every admitted feeder together may hold in `store`, at the ceiling.
    pub fn store_bytes(&self, store: Store) -> usize {
        self.per_feeder.of(store).saturating_mul(self.ceiling())
    }

    /// The gauge of `store`: the same one for the budget's life, whatever it is resized to.
    pub fn gauge(&self, store: Store) -> Arc<Gauge> {
        Arc::clone(&self.gauges[store.index()])
    }

    pub fn report(&self) -> MemoryReport {
        MemoryReport {
            memory: self.memory,
            base: self.base,
            per_feeder: self.per_feeder.total(),
            ceiling: self.ceiling(),
            reserved: self.reserved(),
            stores: self.gauges.iter().map(|gauge| gauge.report()).collect(),
        }
    }
}

/// The budget as served on `GET /memory`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MemoryReport {
    pub memory: usize,
    pub base: usize,
    pub per_feeder: usize,
    pub ceiling: usize,
    pub reserved: usize,
    pub stores: Vec<GaugeReport>,
}

/// Admitted bytes, released when dropped.
#[derive(Debug)]
pub struct Reservation {
    bytes: usize,
    reserved: Arc<AtomicUsize>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.reserved.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_feeder_is_admitted_only_with_room_in_every_store_and_leaving_frees_it() {
        let per_feeder = PerFeeder {
            batches: 10,
            held: 20,
            ..PerFeeder::default()
        };
        let budget = Budget::new(65, per_feeder);
        assert_eq!(budget.ceiling(), 2);
        let first = budget.reserve();
        let second = budget.reserve();
        assert!(first.is_some() && second.is_some());
        assert!(budget.reserve().is_none());
        drop(first);
        assert_eq!(budget.reserved(), 30);
        assert!(budget.reserve().is_some());
    }

    #[test]
    fn the_planned_feeder_reserves_every_store_and_raw_only_where_held() {
        let without = PerFeeder::planned(false);
        let with = PerFeeder::planned(true);
        for store in [Store::Held, Store::Open, Store::Notes, Store::Engine] {
            assert_eq!(without.of(store), 0, "{store:?}");
            assert!(with.of(store) > 0, "{store:?}");
        }
        for store in Store::ALL {
            if !matches!(
                store,
                Store::Held | Store::Open | Store::Notes | Store::Engine | Store::Buffers
            ) {
                assert!(without.of(store) > 0, "{store:?}");
            }
        }
        // A relay of 64 GiB holds thousands of planned feeders, never none.
        let budget = Budget::of_memory(64 << 30, Plan::planned(true));
        assert!(budget.ceiling() > 1_000);
        assert!(budget.check().is_ok());
        assert!(memory_available() > 0);
    }

    #[test]
    fn a_relay_whose_memory_admits_no_feeder_will_not_start() {
        for hosts_mlat in [false, true] {
            let plan = Plan::planned(hosts_mlat);
            let none = Budget::of_memory(plan.base + plan.per_feeder.total() - 1, plan);
            assert_eq!(none.ceiling(), 0);
            assert!(none.check().is_err());
            let one = Budget::of_memory(Budget::memory_for(1, plan), plan);
            assert_eq!(one.ceiling(), 1);
            assert!(one.check().is_ok());
        }
        // Hosting MLAT adds its own base, beside each feeder's raw and notes.
        assert_eq!(
            Plan::planned(true).base,
            Plan::planned(false).base + MLAT_BASE_BYTES
        );
    }

    #[test]
    fn a_member_reserves_the_feeders_its_ceiling_is_worth() {
        let per_feeder = PerFeeder {
            batches: 10,
            ..PerFeeder::default()
        };
        let budget = Budget::new(100, per_feeder);
        assert_eq!(
            Budget::feeders_for_rate(3 * PLANNED_BYTES_PER_SEC as u64 + 1),
            4
        );
        let member = budget.reserve_feeders(4);
        assert!(member.is_some());
        assert_eq!(budget.reserved(), 40);
        assert!(budget.reserve_feeders(7).is_none());
        drop(member);
        assert_eq!(budget.reserved(), 0);
    }

    /// Every store's gauge is its share of the budget at the ceiling, and resizing the budget
    /// resizes the gauges whoever holds them; together they never pass the feeders' memory.
    #[test]
    fn the_gauges_are_each_stores_share_and_follow_a_resize() {
        let plan = Plan::planned(false);
        let per_feeder = plan.per_feeder;
        let mut budget = Budget::of_memory(Budget::memory_for(10, plan), plan);
        let epochs = budget.gauge(Store::Epochs);
        assert_eq!(epochs.limit(), per_feeder.epochs * 10);
        let all: usize = Store::ALL
            .iter()
            .map(|store| budget.gauge(*store).limit())
            .sum();
        assert!(all <= budget.memory() - budget.base());
        budget.resize(Budget::memory_for(20, plan), plan);
        assert_eq!(epochs.limit(), per_feeder.epochs * 20);
    }

    #[test]
    fn a_gauge_refuses_past_its_limit_counted_and_frees_what_is_let_go() {
        let gauge = Gauge::new(Store::Products, 100);
        let first = gauge.try_charge(60);
        assert!(first.is_some());
        assert!(gauge.try_charge(50).is_none());
        assert_eq!(gauge.refused(), 1);
        let mut grown = gauge.empty();
        assert!(grown.try_grow(40));
        assert!(!grown.try_grow(1));
        assert_eq!(gauge.held(), 100);
        drop(first);
        grown.shrink_to(10);
        assert_eq!(gauge.held(), 10);
        assert_eq!(gauge.peak(), 100);
        // One item larger than the whole limit is taken only when nothing else is held.
        assert!(gauge.try_charge(500).is_none());
        drop(grown);
        assert!(gauge.try_charge(500).is_some());
        assert_eq!(gauge.held(), 0);
    }

    /// A charge handed on with what it holds moves its bytes, taking and releasing nothing, and
    /// no charge ever takes a gauge past its limit.
    #[test]
    fn a_charge_split_moves_its_bytes_and_none_passes_the_limit() {
        let gauge = Gauge::new(Store::Open, 100);
        let mut held = gauge.empty();
        assert!(held.try_grow(70));
        let handed = held.split(30);
        assert_eq!((held.bytes(), handed.bytes(), gauge.held()), (40, 30, 70));
        // More than it holds moves all of it.
        let mut rest = held.split(1_000);
        assert_eq!((held.bytes(), rest.bytes(), gauge.held()), (0, 40, 70));
        drop(handed);
        assert_eq!(gauge.held(), 40);
        assert!(!rest.try_grow(61));
        assert!(rest.try_grow(60));
        assert!(gauge.try_charge(1).is_none());
        assert_eq!(gauge.peak(), 100);
        drop(rest);
        assert_eq!(gauge.held(), 0);
    }

    #[tokio::test]
    async fn a_gauge_that_pushes_back_waits_for_room() {
        let gauge = Gauge::new(Store::Ingest, 100);
        let held = gauge.charge(80).await;
        let waiting = tokio::spawn({
            let gauge = Arc::clone(&gauge);
            async move { gauge.charge(50).await.bytes() }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(held);
        assert_eq!(waiting.await.ok(), Some(50));
        assert_eq!(gauge.waited(), 1);
        assert_eq!(gauge.held(), 0);
    }
}
