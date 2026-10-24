//! The ingest stage (RFC-0181 §2): where a batch becomes one immutable [`Decoded`], once, before
//! any other stage reads it. A connection task does I/O only and holds at most its [`Allowance`]
//! of records in flight, a count ([`CREDIT`]), each charged in bytes ([`charge_of`]: its signed
//! bytes, what it inflates to and its receptions' references, from the batch alone before it is
//! decoded) to the relay's one ingest pool (`Store::Ingest`), which every connection waits for in
//! turn by source (`budget::Gauge::charge_for`); out of credit or of room it stops reading its
//! socket, so TCP pushes back on the feeder (whose signed `dropped` records its own loss), no
//! source can take another's turn, and nothing queues unbounded. A batch's charge ([`InFlight`])
//! is let go once it is decoded: from then its decode and its signed bytes are each charged once,
//! for their life, inside their own allocations (`Store::Decoded`, [`Stages::decode_owned`]),
//! whichever stages hold them. The work
//! (verify, hash, admit, inflate, decode, route) runs on a [`Pool`] of dedicated OS threads sized
//! from the load the relay is planned to admit ([`Threads`], `cores::threads_for`), never on the
//! async runtime's workers, so a burst of verification never stalls a heartbeat or an egress
//! write.
//!
//! A batch runs on the worker that owns its receiver's raw shard (`exchange::raw_shard`, fixed
//! logical shards mapped onto the workers), so one receiver's batches are admitted, and reach every
//! subscriber, in the order its connection read them, and its admission state (what its shard took
//! in, `strikes`) and station counters are touched by that worker alone.
//!
//! Every batch is stamped here ([`Stamp`]): the ingest clock's reading and the batch's place in the
//! ingest order, never going back on one worker. Every later decision (which epoch a reception is
//! in, when a shard may seal, which copy of a message is kept) reads the stamp's time and the batch
//! itself (`seal::canonical`), never a clock of its own and never the ingest order the workers
//! raced to, so the same stamped batches give the same output on any number of threads and whatever
//! a stage's delays (RFC-0181, invariants 1 and 2). A stage is held up only by a test's [`Pause`],
//! at the points [`Stage`] names. Each worker
//! ticks the message exchange (`exchange::Envelope::Tick`) as its stamps advance and when idle, so
//! epochs close whether or not batches flow.
//!
//! A worker or message thread that panics ends the relay (`crate::abort_on_any_panic`, which the
//! program sets for every thread): a stage that stopped would hold every epoch open for ever, and a
//! lock it left poisoned would refuse every batch of its shard, both silently.
//!
//! Ed25519 batch verification is not used: it accepts some signatures strict verification refuses
//! (a torsion component in `R` passes a batch equation one time in eight), and every reader of a
//! relay's stream verifies strictly, so a relay that batched could be made to forward what its
//! readers reject. Each batch's key is decompressed once instead (`Batch` keeps it).

use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tally_wire::{Batch, Decoded, ObsRef, Undecodable};
use tokio::sync::Notify;

use crate::budget::{Charge, Gauge, PLANNED_BYTES_PER_SEC, PLANNED_RECEPTIONS_PER_SEC, Store};
use crate::clock::RelayClock;
use crate::exchange::{Gauges, MessageExchange, Sink};
use crate::footprint::{self, Table};
use tally_wire::clocks::{Judged, Moment, Mono, Raw, recorded};
use tally_wire::decoded::NotDecoded;

/// Records one feeder's connection may have in the ingest stage at once. Two: one being worked on,
/// one read and waiting, so a connection's socket is read while its previous batch is decoded. A
/// count, never bytes: what each holds is charged to the one ingest pool, which every connection
/// waits for in turn by source, so a peer sending large batches waits for its bytes as one sending
/// small ones does, and no connection holds room it does not use.
pub const CREDIT: usize = 2;

/// What a batch costs from the moment it is read, from what the batch states: the decode's struct
/// in its `Arc`, its signed bytes (`wire`) in the allocation that carries their charge
/// (`Batch::owned_by`) with its kept key (`batch::KEPT_BYTES`), its observations inflated (`inflated`) with the header `Bytes` adds, and a
/// reference for each reception it can hold (`receptions`). At least `Decoded::footprint` of its
/// decode and `Batch::footprint` of its bytes together, so what is charged at ingest bounds what
/// the decode and the bytes are charged for their life.
pub const fn charge_for(wire: usize, inflated: usize, receptions: usize) -> usize {
    tally_wire::decoded::ARC_HEADER
        + std::mem::size_of::<Decoded>()
        + wire
        + tally_wire::batch::OWNED_HEADER
        + tally_wire::batch::KEPT_BYTES
        + inflated
        + tally_wire::decoded::BYTES_HEADER
        + receptions * std::mem::size_of::<ObsRef>()
}

/// What `batch` is charged before it is decoded: as [`charge_for`], its inflated length and the
/// most receptions it can hold read from its stated length (`Batch::inflated_len`, held to the
/// wire's inflation rule; `Batch::receptions_at_most`), never its wire bytes alone, and never less
/// than [`CHARGE_FLOOR`]. A batch of a format this build cannot read is never inflated or decoded,
/// and costs its signed bytes.
pub fn charge_of(batch: &Batch) -> usize {
    let wire = batch.as_bytes().len();
    floored(match (batch.inflated_len(), batch.receptions_at_most()) {
        (Ok(inflated), Ok(receptions)) => charge_for(wire, inflated, receptions),
        _ => charge_for(wire, 0, 0),
    })
}

/// How many charged bytes a planned batch costs for each of its signed bytes, rounded down: a
/// planned second of a feeder's batches, as charged ([`PLANNED_BATCH_CHARGE`]), over its signed
/// bytes (`budget::PLANNED_BYTES_PER_SEC`).
pub const CHARGED_PER_SIGNED: usize = PLANNED_BATCH_CHARGE / PLANNED_BYTES_PER_SEC;
const _: () = assert!(CHARGED_PER_SIGNED >= 1);

/// What `batch` costs of the relay-wide rate (`R_max`'s bytes) and of a member's pace: its charge
/// ([`charge_of`]), or [`CHARGED_PER_SIGNED`] times its signed bytes if that is more. The stores
/// that hold a decode are planned in charged bytes, which the charge bounds; the sharing groups
/// hold the signed bytes past the decode, over the repair horizon, which the charge alone does not
/// bound: a batch of a format this build cannot read, or one padded with empty DEFLATE blocks, is
/// nearly all signed bytes for what it is charged. Weighed this way, a second of admitted batches
/// carries at most `R_max`'s bytes over [`CHARGED_PER_SIGNED`] of signed bytes, what the groups
/// are planned for (`budget::PerFeeder::planned_for`), and a batch at the planned mix costs its
/// charge, as before.
pub fn rate_cost(batch: &Batch) -> usize {
    charge_of(batch).max(batch.as_bytes().len().saturating_mul(CHARGED_PER_SIGNED))
}

/// The least a record handed to the ingest workers is charged (a batch's [`charge_of`], a
/// description's bytes): its bytes, or [`CHARGE_FLOOR`] if more.
pub const fn floored(bytes: usize) -> usize {
    if bytes < CHARGE_FLOOR {
        CHARGE_FLOOR
    } else {
        bytes
    }
}

/// A batch at the planned rate (RFC-0181, "Requirement": a second of a feeder's batches, its
/// receptions each a 14-byte Mode S message), as [`charge_of`] charges it: what `R_max`'s bytes
/// are counted in a planned feeder's worth of (`budget::PLANNED_CHARGED_BYTES_PER_SEC`).
pub const PLANNED_BATCH_CHARGE: usize = {
    let inflated = 4 + PLANNED_RECEPTIONS_PER_SEC * (tally_wire::decoded::OBSERVATION_FIXED + 14);
    charge_for(
        PLANNED_BYTES_PER_SEC,
        inflated,
        (inflated - 4) / tally_wire::decoded::OBSERVATION_FIXED,
    )
};

/// The most records one member session holds in the ingest stage at once, however small they are
/// (a feeder's connection holds [`CREDIT`]). Each costs an ingest worker a strict Ed25519
/// verification whatever its bytes, so the count bounds the verifications one session has waiting
/// ahead of every honest batch behind them. Eight, four times a feeder's, so a member session
/// forwarding many feeders' small batches still has room while each is verified.
pub const RECORDS_IN_FLIGHT: usize = 8;

/// The least one record is charged in the ingest pool until it is decoded ([`floored`]): a
/// planned batch's charge, [`CREDIT`] of them, over [`RECORDS_IN_FLIGHT`], so the pool's room
/// bounds the records waiting for the workers ([`Room::records`]) however small they are.
pub const CHARGE_FLOOR: usize = CREDIT * PLANNED_BATCH_CHARGE / RECORDS_IN_FLIGHT;
// A batch at the planned rate is charged its bytes, never the floor.
const _: () = assert!(PLANNED_BATCH_CHARGE >= CHARGE_FLOOR);

/// How long a record read may wait for an ingest worker, as the ingest pool is planned
/// (`Store::Ingest`: what the workers take a second times this, Little's law). The workers are
/// planned at `cores::BUSY_PERCENT`, so a record's wait is its share of a busy moment: the ones
/// measured are the hundred milliseconds or so around an epoch's close, when the message threads
/// stop taking slices and the workers routing to them wait (RFC-0181, "BUSY_PERCENT stays 50").
/// A quarter of a second holds that with room; past it the pool is full and the connections wait
/// for it in turn, their sockets unread.
pub const INGEST_WAIT_MS: u64 = 250;

/// The bytes of its byte ceiling each record a connection sends is paced as, at least
/// ([`records_per_sec`]): whatever its bytes, a record costs the relay a fixed amount (a signature
/// verified on an ingest worker, or one checked or signed for an answer on the async runtime, and
/// its decode), so a connection's records a second are held to its byte ceiling over this. A feeder
/// seals a batch once a second and early only at 48 KiB (`tally_feed`), so one keeping to its
/// ceiling sends fewer: at the default 256 KiB/s, eight a second, where it sends five at most.
pub const RECORD_BYTES: u64 = 32 << 10;

/// The records a second a connection held to `bytes_per_sec` may send, at least one: its
/// ceiling over [`RECORD_BYTES`]. The ingest cores plan each feeder's worth of these
/// ([`INGEST_NANOS_PER_RECORD`] each, `cores`). Before, a feeder sending tiny batches within its
/// 256 KiB/s was some 870 signature checks a second, and a few dozen such feeders took every
/// ingest worker: [`CHARGE_FLOOR`] bounded how many it had waiting at once, never how many a
/// second.
pub const fn records_per_sec(bytes_per_sec: u64) -> u64 {
    let records = bytes_per_sec.div_ceil(RECORD_BYTES);
    if records == 0 { 1 } else { records }
}

/// The records a second the members' shared rate may bring, all member sessions together, for
/// `member_feeders` planned feeders' worth (`budget::Plan::member_feeders`): [`MEMBER_RECORDS_PER_FEEDER`]
/// each. What a member forwards is feeders' batches at the planned rate (one a second each) and
/// their descriptions.
pub const fn member_records_per_sec(member_feeders: usize) -> u64 {
    let feeders = member_feeders as u64;
    let records = feeders.saturating_mul(MEMBER_RECORDS_PER_FEEDER);
    if records == 0 { 1 } else { records }
}

/// The members' shared rate, in bytes and in receptions a second, fair between member sessions
/// (RFC-0181 §9). Both are the one rate `--max-member-bytes-per-sec` is worth, planned once as the
/// feeders it is worth (`budget::feeders_for_rate`): a member's batch is a feeder's another relay
/// kept, so what it brings in is bounded by its receptions as well as its bytes, or batches of many
/// small receptions would bring in more than the plan holds. Its bytes are charged bytes
/// ([`charge_of`]), the unit the stores are planned in, those feeders' worth of them: a member
/// forwarding inflated batches brings in no more than the plan holds either. A session waits first for its own
/// share of each (the rate over the sessions waiting now, [`FairPace`]) and then for the shared
/// total, so one member sending large batches cannot take the rate from the rest, and the members
/// together never pass it.
///
/// Their MLAT records (positions of either form, clock models and their parts, client clock
/// models) spend the same bytes, their signed bytes each (`Admitted::in_flight`), so what the
/// stores that hold them (the checks' twins, the ingest pool) are planned from, the members'
/// rate, bounds what they are sent (`budget::Plan::member_paced_bytes_per_sec`).
pub struct MemberPace {
    bytes: Arc<FairPace>,
    receptions: Arc<FairPace>,
}

impl MemberPace {
    /// The pace for `bytes_per_sec` of signed batches all together: the charged bytes and the
    /// receptions of the feeders it is worth.
    pub fn new(bytes_per_sec: u64) -> Self {
        let feeders = crate::budget::feeders_for_rate(bytes_per_sec) as u64;
        Self {
            bytes: Arc::new(FairPace::new(
                feeders.saturating_mul(PLANNED_BATCH_CHARGE as u64),
            )),
            receptions: Arc::new(FairPace::new(
                feeders.saturating_mul(PLANNED_RECEPTIONS_PER_SEC as u64),
            )),
        }
    }

    /// A member session's place in it.
    pub fn session(&self) -> MemberSession {
        MemberSession {
            bytes: FairSession::new(&self.bytes),
            receptions: FairSession::new(&self.receptions),
        }
    }

    /// Bytes a second, and receptions a second, all member sessions together.
    pub fn rates(&self) -> (u64, u64) {
        (self.bytes.total.rate(), self.receptions.total.rate())
    }
}

/// One member session's place in the [`MemberPace`].
pub struct MemberSession {
    bytes: FairSession,
    receptions: FairSession,
}

impl MemberSession {
    /// Spends `bytes` and `receptions` of the session's share and the members' total, waiting
    /// while it owes more than has refilled.
    pub async fn take(&self, bytes: u64, receptions: u64) {
        tokio::join!(self.bytes.take(bytes), self.receptions.take(receptions));
    }
}

/// One rate several sessions share, divided evenly between those using it (max-min: a session
/// using little leaves the rest to the others), under a total all of them share
/// (`ceiling::Pace`). A session is using it if it took anything in the last second or the one
/// before.
struct FairPace {
    total: crate::ceiling::Pace,
    began: tokio::time::Instant,
    /// The second counted now, and the sessions that took in it and in the second before.
    using: Mutex<Using>,
}

#[derive(Default)]
struct Using {
    second: u64,
    now: usize,
    before: usize,
}

impl FairPace {
    fn new(rate: u64) -> Self {
        Self {
            total: crate::ceiling::Pace::new(rate),
            began: tokio::time::Instant::now(),
            using: Mutex::new(Using::default()),
        }
    }

    /// The sessions using the rate, `session` among them (it took in `second` or not yet).
    fn sharing(&self, last: &mut Option<u64>) -> usize {
        let second = self.began.elapsed().as_secs();
        let Ok(mut using) = self.using.lock() else {
            return 1;
        };
        if second > using.second {
            using.before = if second == using.second + 1 {
                using.now
            } else {
                0
            };
            using.now = 0;
            using.second = second;
        }
        if *last != Some(second) {
            *last = Some(second);
            using.now += 1;
        }
        using.now.max(using.before).max(1)
    }
}

struct FairSession {
    pace: Arc<FairPace>,
    /// Units still allowed (negative: owed), as of when, and the second it last counted itself
    /// among the sessions using the rate.
    state: Mutex<(f64, tokio::time::Instant, Option<u64>)>,
}

impl FairSession {
    fn new(pace: &Arc<FairPace>) -> Self {
        Self {
            pace: Arc::clone(pace),
            state: Mutex::new((
                crate::ceiling::burst(pace.total.rate()) as f64,
                tokio::time::Instant::now(),
                None,
            )),
        }
    }

    async fn take(&self, units: u64) {
        let rate = self.pace.total.rate();
        let wait = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            let now = tokio::time::Instant::now();
            let elapsed = now.saturating_duration_since(state.1).as_secs_f64();
            // This session and every other one using the rate: its share is an even part.
            let sharing = self.pace.sharing(&mut state.2);
            let share = (rate as f64 / sharing as f64).max(1.0);
            let burst = crate::ceiling::burst(rate) as f64 / sharing as f64;
            let allowed = (state.0 + elapsed * share).min(burst) - units as f64;
            state.0 = allowed;
            state.1 = now;
            (allowed < 0.0 && rate > 0).then(|| Duration::from_secs_f64(-allowed / share))
        };
        if let Some(wait) = wait {
            tokio::time::sleep(wait).await;
        }
        self.pace.total.take(units).await;
    }
}

/// The records a second one planned feeder's worth of the members' rate may bring: four times the
/// planned batch a second, the headroom the notes plan for feeders above their rate
/// (`mlat_host::NOTES_HEADROOM`).
pub const MEMBER_RECORDS_PER_FEEDER: u64 = 4;

/// Nanoseconds of an ingest worker one record costs whatever its receptions: its strict Ed25519
/// verification, its hash, admission and decode. Measured (2026-10-09, `-c opt`-equivalent release
/// build, one core of the 32-core build host): an empty batch and a batch of one reception, read as
/// the connection task reads them (the key decompressed there), cost 24.3 to 25.1 us each to verify,
/// hash and decode, the verification nearly all of it; admission, routing and the fan-out's offer
/// add a few more, so 30 us is planned. A planned batch costs some 151 us
/// (`cores::INGEST_RECEPTIONS_PER_THREAD`), so a feeder at [`records_per_sec`] of the default
/// ceiling (eight tiny records a second, 240 us) costs the workers some 1.8 times a planned one.
pub const INGEST_NANOS_PER_RECORD: usize = 30_000;

/// The wanted receptions a second (`tally_wire::modes::wanted_reception`) one receiver's feeder may
/// send, at most (RFC-0181 §10, "The cores", decided 2026-10-09): the one ceiling a receiver is
/// held to, the same constant MLAT's raw holder sizes a receiver's open bins by
/// (`tally_mlat_solver::held::Rates::MEASURED`, `ceiling_per_s`, which counts wanted receptions
/// too), five times the 360 wanted a planned feeder sends of its 600 (`budget::PLANNED_RECEPTIONS_PER_SEC`).
/// A feeder is told it with its `RateLimit` (`wanted_per_sec`) and sheds what is past it before it
/// signs (`tally_feed::source::Batcher`), counted in its batches' `dropped`. The relay holds each
/// receiver to it by its batches' stamps ([`ReceptionCeilings`]) and drops a batch that would take
/// the receiver past it, counted (`Hub::over_reception_ceiling`), never slowing the read loop: a
/// feeder's socket is read at the pace of its records and bytes alone, so a real-time feeder is
/// never seconds behind. Before, the read loop waited for every reception, wanted
/// or not, against a ceiling stated in wanted ones (1,800 wanted is some 3,000 in all), and the
/// feeder, told nothing, fell behind by seconds while its batches went stale for MLAT.
pub const FEEDER_RECEPTIONS_PER_SEC: u64 =
    tally_mlat_solver::held::Rates::MEASURED.ceiling_per_s as u64;

/// The seconds of [`FEEDER_RECEPTIONS_PER_SEC`] a receiver may send at once, by its batches'
/// stamps: the second a feeder keeping to its ceiling may seal in one batch (its own bucket holds
/// a second, `tally_feed::source`), and a second for the batches' arrival to bunch on the way (a
/// batch delayed, then the next on its heels), so a feeder that sheds to its ceiling is never
/// dropped here.
pub const FEEDER_RECEPTIONS_BURST_SECS: u64 = 2;

/// Each receiver's wanted receptions against [`FEEDER_RECEPTIONS_PER_SEC`], by its batches' stamps
/// (never a clock: the same stamped batches are kept or dropped alike on any number of threads,
/// RFC-0181 invariant 1). A token bucket per receiver, kept in its raw shard and touched by the
/// ingest worker that owns the shard alone, so a receiver's batches meet it in the order they were
/// stamped. A receiver whose bucket has refilled holds nothing a fresh one would not, so it is
/// forgotten once the map has grown past twice what it held after its last pruning: what is held
/// is the receivers that sent within the last [`FEEDER_RECEPTIONS_BURST_SECS`]. Its table is
/// charged what it allocates to the paces' entries ([`PaceRoom`]), growth before it grows; a
/// receiver the room has no place for, once the refilled are forgotten, shares one bucket with
/// every other such receiver, so a flood of keys neither grows the table past its room nor gets a
/// bucket each.
pub struct ReceptionCeilings {
    /// Tokens held (wanted receptions), as of a stamp.
    held: std::collections::HashMap<tally_wire::PublicKey, Bucket>,
    pruned_to: usize,
    room: PaceRoom,
    /// The bucket every receiver past the room shares.
    overflow: Bucket,
}

/// Tokens held, as of a stamp.
type Bucket = (f64, u64);

impl Default for ReceptionCeilings {
    fn default() -> Self {
        Self::within(PaceRoom::unlimited())
    }
}

impl ReceptionCeilings {
    const RATE_PER_MS: f64 = FEEDER_RECEPTIONS_PER_SEC as f64 / 1_000.0;
    const BURST: f64 = (FEEDER_RECEPTIONS_PER_SEC * FEEDER_RECEPTIONS_BURST_SECS) as f64;

    /// Held in `room`.
    pub fn within(room: PaceRoom) -> Self {
        Self {
            held: std::collections::HashMap::new(),
            pruned_to: 0,
            room,
            overflow: (Self::BURST, 0),
        }
    }

    /// The receivers whose buckets have refilled forgotten, and the table kept to what is left.
    fn prune(&mut self, stamp_ms: u64) {
        self.held
            .retain(|_, held| Self::refilled(*held, stamp_ms) < Self::BURST);
        self.pruned_to = self.held.len();
        self.room.settle(&mut self.held, 0);
    }

    /// `receiver`'s bucket: its own, made full if it has none and the room holds one more (the
    /// refilled forgotten first if it does not), else the one every receiver past the room shares.
    fn bucket(&mut self, receiver: tally_wire::PublicKey, stamp_ms: u64) -> &mut Bucket {
        if !self.held.contains_key(&receiver) {
            if !self.room.room_for(&self.held, 0) {
                self.prune(stamp_ms);
                if !self.room.room_for(&self.held, 0) {
                    return &mut self.overflow;
                }
            }
            self.held.insert(receiver, (Self::BURST, stamp_ms));
            self.room.inserted(&mut self.held, 0);
        }
        match self.held.get_mut(&receiver) {
            Some(held) => held,
            None => &mut self.overflow,
        }
    }

    fn refilled((tokens, at_ms): (f64, u64), stamp_ms: u64) -> f64 {
        (tokens + stamp_ms.saturating_sub(at_ms) as f64 * Self::RATE_PER_MS).min(Self::BURST)
    }

    /// Whether `receiver`'s batch of `wanted` wanted receptions, stamped `stamp_ms`, is within its
    /// ceiling: taken if it is, and if not, nothing is taken (the batch is dropped whole, so what
    /// it would have spent stays for the next).
    pub fn take(&mut self, receiver: tally_wire::PublicKey, wanted: usize, stamp_ms: u64) -> bool {
        if self.held.len() > 2 * self.pruned_to.max(64) {
            self.prune(stamp_ms);
        }
        let held = self.bucket(receiver, stamp_ms);
        let tokens = Self::refilled(*held, stamp_ms);
        let within = wanted as f64 <= tokens;
        *held = (
            if within {
                tokens - wanted as f64
            } else {
                tokens
            },
            stamp_ms.max(held.1),
        );
        within
    }

    /// The receivers held now.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// What its table is charged now.
    pub fn charged(&self) -> usize {
        self.room.charged()
    }
}

/// What one pace map is charged ([`footprint::Table`], the store's `Store::Paces`): its table and
/// what each entry owns beside its slot, charged to the entries' share of the paces' store
/// (`Budget::pace_entries`) and to the store itself alike, so the maps together never take the
/// room planned for what the connections hold of their own ([`OWN_BYTES_PER_CONNECTION`], charged
/// to the store alone).
/// Growth is charged before a map grows (`room_for`), and the charge is brought down to what the
/// map allocates once it has (`inserted`, `settle`).
pub struct PaceRoom {
    table: Table,
    share: Charge,
    store: Charge,
}

impl PaceRoom {
    /// Charged to `store` and to `share`, its entries' share (`Budget::pace_entries`).
    pub fn within(store: &Arc<Gauge>, share: &Arc<Gauge>) -> Self {
        Self {
            table: Table::default(),
            share: share.empty(),
            store: store.empty(),
        }
    }

    /// Charged to no budget: a part built without one (a test's).
    pub fn unlimited() -> Self {
        Self::within(
            &Gauge::unlimited(Store::Paces),
            &Gauge::unlimited(Store::Paces),
        )
    }

    /// What it is charged now.
    pub fn charged(&self) -> usize {
        self.store.bytes()
    }

    /// `bytes` more on both, or on neither.
    fn try_grow(&mut self, bytes: usize) -> bool {
        if !self.share.try_grow(bytes) {
            return false;
        }
        if self.store.try_grow(bytes) {
            return true;
        }
        let back = self.share.bytes() - bytes;
        self.share.shrink_to(back);
        false
    }

    /// Whether one more entry of `map`, owning `owned` bytes beside its slot, has room: what the
    /// map grows by and what the entry owns, charged now if it has.
    fn room_for<K, V>(&mut self, map: &std::collections::HashMap<K, V>, owned: usize) -> bool {
        let growth = self.table.growth::<K, V>(map.len(), map.capacity());
        self.try_grow(growth + owned)
    }

    /// An entry went into `map`, each owning `owned`: its table followed, and the charge settled.
    fn inserted<K, V>(&mut self, map: &mut std::collections::HashMap<K, V>, owned: usize)
    where
        K: Eq + std::hash::Hash,
    {
        self.table.inserted(map.capacity());
        self.settle(map, owned);
    }

    /// `map`, each entry owning `owned`, kept within [`PACES_KEPT_WITHIN`] times what it holds, and
    /// charged what it allocates.
    fn settle<K, V>(&mut self, map: &mut std::collections::HashMap<K, V>, owned: usize)
    where
        K: Eq + std::hash::Hash,
    {
        self.table.kept(map, PACES_KEPT_WITHIN);
        let bytes = self.table.bytes::<K, V>() + map.len() * owned;
        self.share.shrink_to(bytes);
        self.store.shrink_to(bytes);
    }
}

/// A pace map's table is kept within this many times what it holds (`footprint::Table::kept`).
const PACES_KEPT_WITHIN: usize = 4;
/// The entries one connection can bring into each pace map it touches: its own (its receiver's
/// bucket, its group's grant, its group's directory share), and the room for one of another's
/// while that is not yet forgotten.
pub const PACE_ENTRIES_PER_CONNECTION: usize = 2;
/// A connection's own record pace (`link`'s `Paces`), one allocation for its session, charged to
/// the paces' store.
pub const OWN_PACE_BYTES: usize = footprint::arc::<RecordPace>();
/// One receiver's entry in its shard's reception ceilings, at the most an entry of a table kept
/// within [`PACES_KEPT_WITHIN`] allocates ([`footprint::table_per_entry`]).
pub const CEILING_ENTRY_BYTES: usize =
    footprint::table_per_entry::<tally_wire::PublicKey, Bucket>(PACES_KEPT_WITHIN);
/// One network group's entry in the burst grants ([`BurstGrants`]): its pace, in its slot.
pub const GRANT_ENTRY_BYTES: usize =
    footprint::table_per_entry::<Option<Group>, RecordPace>(PACES_KEPT_WITHIN);
/// What one directory group's entry owns beside its slot: its place and its pace.
const DIRECTORY_OWNED_BYTES: usize =
    footprint::arc::<DirectoryGroup>() + footprint::arc::<RecordPace>();
/// One network group's entry in the directory's shares ([`DirectoryPaces`]).
pub const DIRECTORY_ENTRY_BYTES: usize =
    footprint::table_per_entry::<Option<Group>, Arc<DirectoryGroup>>(PACES_KEPT_WITHIN)
        + DIRECTORY_OWNED_BYTES;
/// The entries one connection holds in the pace maps at most: a feeder's receiver's bucket and its
/// group's grant, or a relay's group's directory share (a relay has no own pace, so no grant), each
/// [`PACE_ENTRIES_PER_CONNECTION`] times.
pub const PACE_ENTRIES_BYTES: usize = {
    let feeder = PACE_ENTRIES_PER_CONNECTION * (CEILING_ENTRY_BYTES + GRANT_ENTRY_BYTES);
    let relay = PACE_ENTRIES_PER_CONNECTION * DIRECTORY_ENTRY_BYTES;
    if feeder > relay { feeder } else { relay }
};
/// What one connection holds of its own for its session at most, whatever its role, charged to
/// the paces' store alone: its own record pace ([`OWN_PACE_BYTES`]), and a feeder's entry in its
/// receiver's station connections (`stations::CONNECTION_BYTES`).
pub const OWN_BYTES_PER_CONNECTION: usize = OWN_PACE_BYTES + crate::stations::CONNECTION_BYTES;
/// What one connection's pace state allocates at most, whatever its role: what it holds of its
/// own and its entries in the pace maps. Every connection is planned at it (`budget::Store::Paces`).
pub const PACE_BYTES_PER_CONNECTION: usize = OWN_BYTES_PER_CONNECTION + PACE_ENTRIES_BYTES;

/// The entries' share of the paces' store of `limit` bytes (`Budget::pace_entries`): all but the
/// own paces of the connections it is planned for.
pub fn pace_entries_part(limit: usize) -> usize {
    limit - limit / PACE_BYTES_PER_CONNECTION * OWN_BYTES_PER_CONNECTION
}

/// The receptions a second (all of them, wanted or not) one source's share of the relay's rate is
/// at most (`shed`): its wanted ceiling ([`FEEDER_RECEPTIONS_PER_SEC`]) over the wanted share of
/// what a planned feeder hears (360 of its 600, `budget::PLANNED_RECEPTIONS_PER_SEC`).
pub const SOURCE_RECEPTIONS_PER_SEC: u64 = FEEDER_RECEPTIONS_PER_SEC
    * PLANNED_RECEPTIONS_PER_SEC as u64
    / PLANNED_WANTED_RECEPTIONS_PER_SEC;
/// The wanted receptions a second of a planned feeder's 600 (`tally_wire::modes::wanted_reception`).
pub const PLANNED_WANTED_RECEPTIONS_PER_SEC: u64 = 360;

/// The cores this host gives the process (`std::thread::available_parallelism`), at least one.
pub fn host_cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// How fast, and how far ahead, one session of a role may send records: `per_minute` a minute,
/// and `burst` at once from rest. What the cores plan for a session is its `per_minute`
/// (`cores::Sessions`); its `burst` is what its role legitimately sends at once (with its Hello,
/// or a credential and its evidence), refilled at `per_minute`. A new session starts with
/// [`SESSION_BURST`] of it and the rest only as it is granted ([`BurstGrants`]): so a peer that
/// reconnects does not refill a burst outside the plan each time it dials. By the minute, since
/// what most roles need is a heartbeat every 30 s and a few records when something changes, far
/// under one a second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RolePace {
    pub per_minute: u64,
    pub burst: u64,
}

impl RolePace {
    /// A pace of this role's, full from rest.
    pub fn pace(self) -> RecordPace {
        RecordPace::per_minute(self.per_minute, self.burst)
    }

    /// A new session's pace of this role's: [`SESSION_BURST`] of its burst, and as much of the
    /// rest as `grants` give a session from `group` now (`BurstGrants::grant`).
    pub fn session(self, grants: &BurstGrants, group: Option<Group>) -> RecordPace {
        let base = self.burst.min(SESSION_BURST);
        let granted = grants.grant(group, self.burst - base);
        RecordPace::starting(self.per_minute, self.burst, base + granted)
    }
}

/// The network group (`directory::Group`) a session's address is in, or `None` for one with no
/// address (an in-process stream): the unit a pace that outlives sessions is kept by, since a key
/// is free and an address in another network is not.
pub type Group = crate::directory::Group;

/// The group of `address`.
pub fn group_of(address: Option<std::net::IpAddr>) -> Option<Group> {
    address.map(Group::of)
}

/// What every new session starts with of its role's burst, whoever it is: what any role sends with
/// its Hello but a credential's evidence (a probe's round, an engine's `Subscribe`, a feeder's
/// second of records). The rest of a burst ([`SUBSCRIBER_RECORDS`]'s evidence) is granted
/// ([`BurstGrants`]).
pub const SESSION_BURST: u64 = 8;

/// The burst tokens a minute, and at once, new sessions are granted past [`SESSION_BURST`], all
/// groups together: what the cores plan for bursts (`cores::Sessions`), whatever the connections
/// come and go. Sixteen evidence bundles' worth a minute, and the default subscriber cap's
/// (`--max-subscribers`, 64) at once, so a relay's subscribers reconnecting together after it
/// restarts each bring their credential's evidence at once.
pub const BURST_GRANTS: RolePace = RolePace {
    per_minute: 16 * EVIDENCE_SIGNATURES,
    burst: 64 * EVIDENCE_SIGNATURES,
};

/// The burst tokens a minute, and at once, one network group's new sessions are granted: two
/// evidence bundles' worth a minute and eight at once, so one network reconnecting as fast as it
/// can takes an eighth of [`BURST_GRANTS`] at most and every other network's sessions still get
/// theirs. Kept by group across its sessions, so a reconnect finds the grant its last one took.
pub const GROUP_BURST_GRANTS: RolePace = RolePace {
    per_minute: 2 * EVIDENCE_SIGNATURES,
    burst: 8 * EVIDENCE_SIGNATURES,
};

/// What new sessions are granted of their roles' bursts past [`SESSION_BURST`]:
/// a token bucket per network group ([`GROUP_BURST_GRANTS`]), kept across its sessions, under one
/// the relay's groups share ([`BURST_GRANTS`]). A grant is taken from both, as much as both hold,
/// never waited for: a session granted less starts with less and earns the rest at its role's
/// pace. Before, every connection started with its role's whole burst, so a subscriber that
/// reconnected as fast as it could had some 136 signatures verified a connection, against the
/// twelve records a minute the cores planned for it.
pub struct BurstGrants {
    shared: RecordPace,
    groups: Mutex<ByGroup>,
}

impl Default for BurstGrants {
    fn default() -> Self {
        Self::new(BURST_GRANTS, GROUP_BURST_GRANTS)
    }
}

impl BurstGrants {
    pub fn new(shared: RolePace, group: RolePace) -> Self {
        Self {
            shared: shared.pace(),
            groups: Mutex::new(ByGroup::new(group, PaceRoom::unlimited())),
        }
    }

    /// Its groups held in `room`.
    pub fn within(self, room: PaceRoom) -> Self {
        let pace = self
            .groups
            .into_inner()
            .map_or(GROUP_BURST_GRANTS, |groups| groups.pace);
        Self {
            shared: self.shared,
            groups: Mutex::new(ByGroup::new(pace, room)),
        }
    }

    /// What its groups' table is charged now.
    pub fn charged(&self) -> usize {
        self.groups.lock().map_or(0, |groups| groups.room.charged())
    }

    /// The groups held now.
    pub fn groups_held(&self) -> usize {
        self.groups.lock().map_or(0, |groups| groups.held.len())
    }

    /// Up to `wanted` tokens for a new session from `group`, taken now: what both its group and
    /// the shared grants hold, at most.
    pub fn grant(&self, group: Option<Group>, wanted: u64) -> u64 {
        if wanted == 0 {
            return 0;
        }
        let Ok(mut groups) = self.groups.lock() else {
            return 0;
        };
        let own = groups.get(group);
        let granted = wanted.min(own.available()).min(self.shared.available());
        own.take_now(granted);
        self.shared.take_now(granted);
        granted
    }
}

/// Paces kept by network group, across that group's sessions: each made at `pace` the first time
/// its group is seen, full. One whose bucket has refilled holds nothing a new one would not, so
/// once the map has grown past twice what it held after its last pruning, those are forgotten:
/// what is held is the groups that spent within one refill. Its table is charged what it
/// allocates ([`PaceRoom`]); a group the room has no place for, once the refilled are forgotten,
/// shares one pace with every other such group.
struct ByGroup {
    pace: RolePace,
    held: std::collections::HashMap<Option<Group>, RecordPace>,
    pruned_to: usize,
    room: PaceRoom,
    /// The pace every group past the room shares.
    overflow: RecordPace,
}

impl ByGroup {
    fn new(pace: RolePace, room: PaceRoom) -> Self {
        Self {
            pace,
            held: std::collections::HashMap::new(),
            pruned_to: 0,
            room,
            overflow: pace.pace(),
        }
    }

    fn prune(&mut self) {
        self.held.retain(|_, pace| !pace.is_full());
        self.pruned_to = self.held.len();
        self.room.settle(&mut self.held, 0);
    }

    fn get(&mut self, group: Option<Group>) -> &RecordPace {
        if self.held.len() > 2 * self.pruned_to.max(64) {
            self.prune();
        }
        if !self.held.contains_key(&group) {
            if !self.room.room_for(&self.held, 0) {
                self.prune();
                if !self.room.room_for(&self.held, 0) {
                    return &self.overflow;
                }
            }
            self.held.insert(group, self.pace.pace());
            self.room.inserted(&mut self.held, 0);
        }
        self.held.get(&group).unwrap_or(&self.overflow)
    }
}

/// Every directory link's pace: one per network group, kept across that group's
/// links (so what a link owes, its evidence's signatures, `credit::check`, is its group's and
/// outlives its session), each at an equal share of [`DIRECTORY_RECORDS`] among the groups with
/// a link now. The shares together are the one rate the cores plan for the directory, however
/// many links; a group that sends as fast as it may, or owes for every bundle it sends, waits on
/// its own share alone, and every other group's links keep theirs. Before, every link shared one
/// pace: a link's evidence owed up to 128 tokens to it a bundle, so one hostile link held every
/// other link's gossip back, and kept doing so after it hung up.
///
/// Its table and each group's place and pace are charged what they allocate ([`PaceRoom`]); a
/// group the room has no place for, once the groups that owe nothing and have no link are
/// forgotten, shares one place with every other such group (one share of the rate between them).
pub struct DirectoryPaces {
    pace: RolePace,
    /// The groups with a link now: the share's divisor.
    live: Arc<std::sync::atomic::AtomicUsize>,
    groups: Mutex<DirectoryGroups>,
    pruned_to: std::sync::atomic::AtomicUsize,
    /// The place every group past the room shares: the struct's own, made with it.
    overflow: Arc<DirectoryGroup>,
}

struct DirectoryGroups {
    held: std::collections::HashMap<Option<Group>, Arc<DirectoryGroup>>,
    room: PaceRoom,
}

impl DirectoryGroups {
    /// The groups that owe nothing and have no link forgotten, and the table kept to the rest.
    fn prune(&mut self) {
        self.held
            .retain(|_, held| held.links.load(Ordering::SeqCst) > 0 || !held.pace.is_full());
        self.room.settle(&mut self.held, DIRECTORY_OWNED_BYTES);
    }
}

struct DirectoryGroup {
    pace: Arc<RecordPace>,
    links: std::sync::atomic::AtomicUsize,
}

/// One directory link's place in its group's share, for as long as the link holds it.
pub struct DirectoryLink {
    paces: Arc<DirectoryPaces>,
    group: Option<Group>,
    held: Arc<DirectoryGroup>,
    /// Whether its place is its group's own, not the one the groups past the room share.
    own: bool,
}

impl DirectoryLink {
    /// Its group's pace, which its records wait for and its work beyond them is owed to.
    pub fn pace(&self) -> Arc<RecordPace> {
        Arc::clone(&self.held.pace)
    }
}

impl Drop for DirectoryLink {
    fn drop(&mut self) {
        let Ok(mut groups) = self.paces.groups.lock() else {
            return;
        };
        if self.held.links.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.paces.live.fetch_sub(1, Ordering::SeqCst);
            // A group that owes nothing and has refilled is forgotten with its last link; one in
            // debt is kept, so its debt is paid by its next link and no other group's.
            if self.own && self.held.pace.is_full() {
                let groups = &mut *groups;
                groups.held.remove(&self.group);
                groups.room.settle(&mut groups.held, DIRECTORY_OWNED_BYTES);
            }
        }
    }
}

impl DirectoryPaces {
    pub fn new(pace: RolePace) -> Arc<Self> {
        Self::within(pace, PaceRoom::unlimited())
    }

    /// Its groups held in `room`.
    pub fn within(pace: RolePace, room: PaceRoom) -> Arc<Self> {
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Arc::new(Self {
            pace,
            overflow: Self::group(pace, &live),
            live,
            groups: Mutex::new(DirectoryGroups {
                held: std::collections::HashMap::new(),
                room,
            }),
            pruned_to: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn group(pace: RolePace, live: &Arc<std::sync::atomic::AtomicUsize>) -> Arc<DirectoryGroup> {
        Arc::new(DirectoryGroup {
            pace: Arc::new(RecordPace::shared_by(pace, Arc::clone(live))),
            links: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// A link from `group` takes its place in its group's share: its group's own, made if it has
    /// none and the room holds one more, else the one the groups past the room share.
    pub fn join(self: &Arc<Self>, group: Option<Group>) -> Option<DirectoryLink> {
        let mut groups = self.groups.lock().ok()?;
        let pruned_to = self.pruned_to.load(Ordering::Relaxed);
        if groups.held.len() > 2 * pruned_to.max(64) {
            groups.prune();
            self.pruned_to.store(groups.held.len(), Ordering::Relaxed);
        }
        let groups = &mut *groups;
        let held = match groups.held.get(&group) {
            Some(held) => Some(Arc::clone(held)),
            None => {
                let room = groups.room.room_for(&groups.held, DIRECTORY_OWNED_BYTES) || {
                    groups.prune();
                    self.pruned_to.store(groups.held.len(), Ordering::Relaxed);
                    groups.room.room_for(&groups.held, DIRECTORY_OWNED_BYTES)
                };
                room.then(|| {
                    let held = Self::group(self.pace, &self.live);
                    groups.held.insert(group, Arc::clone(&held));
                    groups
                        .room
                        .inserted(&mut groups.held, DIRECTORY_OWNED_BYTES);
                    held
                })
            }
        };
        let own = held.is_some();
        let held = held.unwrap_or_else(|| Arc::clone(&self.overflow));
        if held.links.fetch_add(1, Ordering::SeqCst) == 0 {
            self.live.fetch_add(1, Ordering::SeqCst);
        }
        Some(DirectoryLink {
            paces: Arc::clone(self),
            group,
            held,
            own,
        })
    }

    /// The groups with a link now.
    pub fn groups_linked(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// The groups whose pace is held now, linked or still owing.
    pub fn groups_held(&self) -> usize {
        self.groups.lock().map_or(0, |groups| groups.held.len())
    }

    /// What its groups are charged now.
    pub fn charged(&self) -> usize {
        self.groups.lock().map_or(0, |groups| groups.room.charged())
    }

    /// The records a minute every group's share comes to together: the one rate planned.
    pub fn per_minute(&self) -> u64 {
        self.pace.per_minute
    }
}

/// The most signatures one evidence bundle carries inside it: `MAX_EVIDENCE` feeders'
/// descriptions and as many receipts, each a token of its asker's pace (`credit::check`).
pub const EVIDENCE_SIGNATURES: u64 = 2 * tally_wire::credit::MAX_EVIDENCE as u64;

/// A subscriber's session: a heartbeat every 30 s, a `Subscribe` when the regions
/// it reads change, a firehose credential with its relay's evidence when it starts and each time
/// the credential is renewed (at most hourly, `MAX_CREDENTIAL_LIFETIME_MS`), and a provider query
/// or an echo now and then: twelve a minute, one every five seconds, holds them with room. Its
/// burst is what it sends with its Hello at most: the credential, the evidence and every signature
/// inside it ([`EVIDENCE_SIGNATURES`], each a token, `credit::check`), and a few more.
pub const SUBSCRIBER_RECORDS: RolePace = RolePace {
    per_minute: 12,
    burst: EVIDENCE_SIGNATURES + 8,
};

/// Another relay's hosted MLAT taking raw one hop (`Role::Engine`): a heartbeat every 30 s and a
/// `Subscribe` when the band it solves changes; it publishes nothing here. Six a minute, and a
/// burst of a few for what comes with its Hello.
pub const ENGINE_RECORDS: RolePace = RolePace {
    per_minute: 6,
    burst: 8,
};

/// A measurement session (`Role::Probe`): a feeder's round of echoes (five, `tally_feed::probe`,
/// each sent once the one before is answered) and one timed heartbeat asking this relay's clock,
/// or one delivery query, then it hangs up, and the
/// feeder probes again minutes later. Its burst holds a round; past it, one every ten seconds.
pub const PROBE_RECORDS: RolePace = RolePace {
    per_minute: 6,
    burst: 8,
};

/// The most records a minute of every session under the connection cap that is not a directory
/// link (not yet identified, probes, engines): what the cores plan each of them at.
pub const GENERAL_RECORDS_PER_MINUTE: u64 = if PROBE_RECORDS.per_minute > ENGINE_RECORDS.per_minute
{
    PROBE_RECORDS.per_minute
} else {
    ENGINE_RECORDS.per_minute
};

/// Every directory link together (a relay that dialled in and is not a member: offers, queries,
/// evidence, echoes, heartbeats, `subscription::on_directory_link`), one rate planned once, as the
/// members' is: the gossip a relay must take does not grow with the links it comes over (each
/// offer is the same offer on every link), so a relay with many links is planned no more. Shared
/// out equally among the network groups with a link now ([`DirectoryPaces`]), so no group's links
/// take another's share. Twice what the directory holds at its bound (`directory::OFFERS_HELD`),
/// each offer re-signed once a minute (`OWN_RESIGN_EVERY_MS`), some 546 a second: half for the
/// offers, half for the queries, echoes and the evidence and its signatures (each a token,
/// `credit::check`). Gossip past it waits: an offer lives three re-signings and evidence a
/// half-life of 30 minutes, so waiting seconds loses nothing.
pub const DIRECTORY_RECORDS: RolePace = RolePace {
    per_minute: 2 * crate::directory::OFFERS_HELD as u64 * 60_000
        / crate::directory::OWN_RESIGN_EVERY_MS,
    burst: 2 * crate::directory::OFFERS_HELD as u64 * 60_000
        / crate::directory::OWN_RESIGN_EVERY_MS,
};

/// A count a second, waited for: a connection's (or the member sessions', or a directory group's)
/// records a second ([`records_per_sec`], [`RolePace`]). A token bucket of `rate` a second and
/// `burst` at once from rest. Past it the read loop waits before it takes the next record, its
/// socket unread, so TCP holds the sender back as the ingest allowance does. Work a record brings
/// beyond its one token (each signature inside an evidence bundle, `credit::check`) is owed
/// ([`RecordPace::owe`]) and paid before the connection's next record is read. A pace that is one
/// share of a rate (a directory group's, [`DirectoryPaces`]) has its rate and burst divided by the
/// shares held now. Read off tokio's clock, so a test that pauses time paces with it.
pub struct RecordPace {
    /// Tokens a second (the whole rate, for a share).
    rate: f64,
    burst: u64,
    /// The shares the rate and burst are divided among, when it is one.
    shares: Option<Arc<std::sync::atomic::AtomicUsize>>,
    /// Tokens still allowed (negative: owed), as of when.
    state: Mutex<(f64, tokio::time::Instant)>,
}

impl RecordPace {
    /// `rate` a second, a second's worth at once.
    pub fn new(rate: u64) -> Self {
        Self::with_burst(rate, rate)
    }

    /// `rate` a second, `burst` at once.
    pub fn with_burst(rate: u64, burst: u64) -> Self {
        Self::per_minute(rate.saturating_mul(60), burst)
    }

    /// `per_minute` a minute, `burst` at once.
    pub fn per_minute(per_minute: u64, burst: u64) -> Self {
        Self::starting(per_minute, burst, burst)
    }

    /// `per_minute` a minute, `burst` at once, `start` of it held now.
    pub fn starting(per_minute: u64, burst: u64, start: u64) -> Self {
        let burst = burst.max(1);
        Self {
            rate: per_minute.max(1) as f64 / 60.0,
            burst,
            shares: None,
            state: Mutex::new((start.min(burst) as f64, tokio::time::Instant::now())),
        }
    }

    /// One share of `pace` among `shares` (at least one), full from rest.
    fn shared_by(pace: RolePace, shares: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        let mut shared = pace.pace();
        shared.shares = Some(shares);
        let burst = shared.now().1;
        shared.state = Mutex::new((burst, tokio::time::Instant::now()));
        shared
    }

    /// Tokens a second and the burst, now: a share's, of the shares held now.
    fn now(&self) -> (f64, f64) {
        let shares = self
            .shares
            .as_ref()
            .map_or(1, |shares| shares.load(Ordering::SeqCst).max(1)) as f64;
        (self.rate / shares, (self.burst as f64 / shares).max(1.0))
    }

    /// Tokens a minute (a share's, now).
    pub fn per_minute_rate(&self) -> u64 {
        (self.now().0 * 60.0).round() as u64
    }

    /// Refilled to the moment: tokens held, the state's lock held.
    fn refilled(&self) -> Option<(std::sync::MutexGuard<'_, (f64, tokio::time::Instant)>, f64)> {
        let mut state = self.state.lock().ok()?;
        let now = tokio::time::Instant::now();
        let (rate, burst) = self.now();
        let elapsed = now.saturating_duration_since(state.1).as_secs_f64();
        let held = (state.0 + elapsed * rate).min(burst);
        *state = (held, now);
        Some((state, held))
    }

    /// Takes `count` tokens now, refilled to the moment: how long the pace then owes, if it does.
    fn spend(&self, count: u64) -> Option<Duration> {
        let (mut state, held) = self.refilled()?;
        let allowed = held - count as f64;
        state.0 = allowed;
        let rate = self.now().0;
        (allowed < 0.0).then(|| Duration::from_secs_f64(-allowed / rate))
    }

    /// Whole tokens held now (none while it owes).
    pub fn available(&self) -> u64 {
        self.refilled()
            .map_or(0, |(_, held)| if held > 0.0 { held as u64 } else { 0 })
    }

    /// Whether it holds its whole burst: as a fresh pace would, owing nothing.
    pub fn is_full(&self) -> bool {
        self.refilled()
            .is_some_and(|(_, held)| held >= self.now().1)
    }

    /// `count` taken now, whatever it then owes; never waited for.
    fn take_now(&self, count: u64) {
        if count > 0 {
            let _ = self.spend(count);
        }
    }

    /// One record, waiting while the pace owes more than it has refilled.
    pub async fn take(&self) {
        self.take_many(1).await;
    }

    /// `count` at once, waiting until the pace has refilled them.
    pub async fn take_many(&self, count: u64) {
        if let Some(wait) = self.spend(count) {
            tokio::time::sleep(wait).await;
        }
    }

    /// `count` owed without waiting: work done for a record already taken, paid for by the wait
    /// before the next.
    pub fn owe(&self, count: u64) {
        let _ = self.spend(count);
    }
}

/// What a connection holds of Noise buffers at most, both directions together
/// (`tally_wire::noise::READER_BUFFERS`, `tally_wire::noise::WRITER_BUFFERS`, each a whole
/// message): the reader's frame and its plaintext, then the plaintext and the records decoded
/// from it, until every one is handed on; and the writer's plaintext and ciphertext for as long as
/// a send waits on the peer (up to `noise::WRITE_TIMEOUT`). Carved when a connection is admitted
/// and held for the session, so a peer that trickles a message, or reads slowly what it is sent,
/// holds what was planned for it and no more. Before, only the reader's two were carved, while
/// a send held two more for up to 30 s and the reader held a third while it decoded: some 2 GB
/// outside every gauge at 20,000 slow subscribers. With them, the network duties' replies waiting
/// for the write side ([`REPLIES_BYTES`]).
pub const BUFFERS_PER_CONNECTION: usize = (tally_wire::noise::READER_BUFFERS
    + tally_wire::noise::WRITER_BUFFERS)
    * tally_wire::noise::MAX_MESSAGE
    + REPLIES_BYTES;

/// What one connection's replies from the network duties (echo replies, delivery answers, offers
/// for a provider query) hold at most while they wait for its write side, by their encoded bytes:
/// a message's worth, carved with its buffers ([`BUFFERS_PER_CONNECTION`]). A reply past it is
/// dropped (`link::ReplyRoom`): a peer that asks faster than it reads gets fewer answers, never
/// more of the relay's memory. Before, the answers to a whole message were gathered,
/// uncharged, while its records were paced at eight a second, and up to 64 such lists waited for
/// the write side: one 64 KiB message of `ProviderQuery`s, each answered with up to 32 offers,
/// held some 25 MB a connection for minutes.
pub const REPLIES_BYTES: usize = tally_wire::noise::MAX_MESSAGE;

/// How often an idle worker ticks the message exchange, and the least advance of its stamps that
/// makes a busy one tick: a shard's watermark is at most this behind the ingest clock.
pub const TICK_MS: u64 = 10;

/// When a batch, a record or a tick was taken, and its place in the ingest order: the relay's
/// monotonic clock (`mono`, what the epochs, ticks and paces run on), its judging clock read with
/// it as one pair (`judged`, what a signed time is judged by and what is signed for it), the raw
/// clock beside them (`raw`, what this relay's own anchors are aged by), and whether the judging
/// clock judged (`judging`): all read at one instant (`clock::RelayClock::stamp`), so whatever the
/// stamp decides later is decided by what was true as it was taken, never by a clock read then.
/// Ordered by `(mono, ingest_seq)`: a watermark (`exchange::Envelope::Tick`) is a stamp.
///
/// Made only by the relay's clock, or given back by a trace or a test ([`Stamp::recorded`],
/// [`Stamp::at`], which Clippy refuses elsewhere). It has no default: a stamp is a reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stamp {
    moment: Moment,
    ingest_seq: u64,
    raw: Raw,
    judging: bool,
}

impl Ord for Stamp {
    /// By `(mono, ingest_seq)`, then the rest, so it is a total order.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.moment.mono(),
            self.ingest_seq,
            self.moment.judged(),
            self.raw,
            self.judging,
        )
            .cmp(&(
                other.moment.mono(),
                other.ingest_seq,
                other.moment.judged(),
                other.raw,
                other.judging,
            ))
    }
}

impl PartialOrd for Stamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Stamp {
    /// The stamp of one read of the relay's clocks (`clock::RelayClock::stamp`).
    pub(crate) const fn read(moment: Moment, ingest_seq: u64, raw: Raw, judging: bool) -> Self {
        Self {
            moment,
            ingest_seq,
            raw,
            judging,
        }
    }

    /// A stamp a trace or a test recorded: its monotonic reading `mono_ms`, place `ingest_seq`,
    /// judging reading `judged_ms`, raw reading `raw_ms`, and whether its judging clock judged.
    #[allow(
        clippy::disallowed_methods,
        reason = "a recorded stamp is made from recorded readings"
    )]
    pub const fn recorded(
        mono_ms: u64,
        ingest_seq: u64,
        judged_ms: u64,
        raw_ms: u64,
        judging: bool,
    ) -> Self {
        Self {
            moment: recorded::moment(mono_ms, judged_ms),
            ingest_seq,
            raw: recorded::raw(raw_ms),
            judging,
        }
    }

    /// A recorded stamp whose clocks read alike, judging: a trace's or a test's.
    #[allow(clippy::disallowed_methods, reason = "a recorded stamp, made of one")]
    pub const fn at(stamp_ms: u64, ingest_seq: u64) -> Self {
        Self::recorded(stamp_ms, ingest_seq, stamp_ms, stamp_ms, true)
    }

    /// The monotonic reading.
    pub const fn mono(self) -> Mono {
        self.moment.mono()
    }

    /// The monotonic reading's milliseconds: what the epochs, ticks and paces count.
    pub const fn mono_ms(self) -> u64 {
        self.moment.mono().ms()
    }

    /// Its place in the ingest order.
    pub const fn ingest_seq(self) -> u64 {
        self.ingest_seq
    }

    /// The judging reading.
    pub const fn judged(self) -> Judged {
        self.moment.judged()
    }

    /// The raw reading.
    pub const fn raw(self) -> Raw {
        self.raw
    }

    /// Whether the judging clock judged as the stamp was taken: what usability, blame and signing
    /// of what it stamps are decided by, never the clock as it is later read.
    pub const fn judging(self) -> bool {
        self.judging
    }

    /// Both clocks' readings, as one instant.
    pub const fn moment(self) -> Moment {
        self.moment
    }

    /// The stamp carried on to `last`, the producer's newest stamp's monotonic reading, when it
    /// reads before it (a producer's stamps never go back): its judging reading moved with it by
    /// the pair's offset just read (`Moment::at`). Its raw reading is the one taken: the raw clock
    /// is no daemon's, so a span of `M` never moves it.
    #[must_use]
    pub(crate) fn not_before(self, last: Mono) -> Self {
        if self.moment.mono() >= last {
            return self;
        }
        Self {
            moment: self.moment.at(last),
            ..self
        }
    }

    /// The stamp moved to `mono`, a reading of its monotonic clock on that clock's own grid (an
    /// epoch's end, `seal::Epoch::end`): its judging reading moved with it by the pair's offset
    /// (`Moment::at`), its judging bit its own. Its raw reading is the one taken: the raw clock is
    /// no daemon's and runs apart from `M`, so a span of `M` never moves it. What the products
    /// sign an epoch at, by its newest tick.
    #[must_use]
    pub(crate) fn at_mono(self, mono: Mono) -> Self {
        Self {
            moment: self.moment.at(mono),
            ..self
        }
    }

    /// The same readings at place `ingest_seq`.
    #[must_use]
    pub const fn with_seq(self, ingest_seq: u64) -> Self {
        Self { ingest_seq, ..self }
    }
}

/// A stage that a [`Pause`] holds up, at the point where it holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// An ingest worker, after a batch is stamped and before it is admitted and routed.
    Ingest,
    /// A message thread, before each envelope it takes.
    Message,
    /// The sealer, before each command it takes, and its pool, before each job.
    Sealer,
}

/// What holds a stage up, inside it: a test's injected delay or stall (RFC-0181 invariant 2, "no
/// consumer reads a clock": what a stage is given, not when, decides its output). A relay runs with
/// none.
pub type Pause = Arc<dyn Fn(Stage) + Send + Sync>;

/// How many threads each stage runs on. A relay's follow the load it is planned to admit
/// (`Budget::threads`, from `cores::threads_for`); a test names its own, and the output bytes are
/// the same on any of them (RFC-0181, invariant 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threads {
    /// Ingest workers: verify, hash, admit, inflate, decode, route.
    pub ingest: usize,
    /// Message exchange threads: the one deduplication.
    pub message: usize,
    /// Sealer threads: the sealer and its pool's helpers beside it (`products::Products::on_thread`).
    pub seal: usize,
}

/// One connection's allowance in the ingest stage (RFC-0181 §2, §10, "Memory is charged once, for
/// its life"): a count of records it may have read and not yet decoded ([`CREDIT`] for a feeder,
/// [`RECORDS_IN_FLIGHT`] for a member session), each charged its bytes ([`charge_of`]) to the one
/// ingest pool (`Store::Ingest`), waiting for room in turn by source (`Gauge::charge_for`). A
/// connection out of credit or waiting for room stops reading its socket.
///
/// Before, each connection carved two planned batches' bytes (some 137 kB) from `Store::Ingest`
/// when it was admitted and held them for its life, used or not, and a batch larger than all of it
/// took the rest from an oversize room: 2.6 GB of the world relay's plan held for connections that
/// mostly held nothing. What waits for a worker is the rate the workers take over the time a
/// record waits for one (Little's law, [`INGEST_WAIT_MS`]), whatever the connections, so the pool
/// is sized by that; a connection's credit stays a count, which bounds the verifications one
/// connection has waiting.
pub struct Allowance {
    pool: Arc<Gauge>,
    credit: Arc<tokio::sync::Semaphore>,
    /// Whose turn this connection's records wait in when the pool is full
    /// ([`Gauge::charge_for`]): its network group's ([`network_source`]) for a feeder, a member
    /// session's own ([`member_source`]), so connections of one network share one turn.
    source: u64,
}

/// The turn the relay's own batches wait in ([`Gauge::charge_for`]): a test's trace, a replay, a
/// description it hands in.
pub const RELAY_SOURCE: u64 = 0;

/// The turn a feeder connection from `group` waits in for room in a gauge: its network group's,
/// the same unit its share of the ingest rate is (`shed::Unit`), so a hundred connections from one
/// block of addresses are one source in the queue, not a hundred. A connection with no address is
/// a source of its own.
pub fn network_source(group: Option<Group>, connection: u64) -> u64 {
    match group {
        Some(group) => group.as_u64(),
        None => (3 << 32) | (connection & 0xffff_ffff),
    }
}

/// The turn a sharing member's session waits in: its own.
pub fn member_source(connection: u64) -> u64 {
    (4 << 32) | (connection & 0xffff_ffff)
}

impl Allowance {
    /// `records` records at once in the ingest stage, each charged to `pool` (the relay's
    /// `Store::Ingest`), waiting in `source`'s turn.
    pub fn new(pool: &Arc<Gauge>, records: usize, source: u64) -> Self {
        Self {
            pool: Arc::clone(pool),
            credit: Arc::new(tokio::sync::Semaphore::new(records.max(1))),
            source,
        }
    }

    /// One record's charge of `bytes`, waiting while the connection holds all its credit, then for
    /// room in the pool in its source's turn. A record larger than the whole pool waits until the
    /// pool holds nothing else (`Gauge::charge_for`).
    pub async fn acquire(&self, bytes: usize) -> InFlight {
        let credit = Arc::clone(&self.credit).acquire_owned().await.ok();
        let charge = self.pool.charge_for(self.source, bytes).await;
        InFlight {
            charge,
            _credit: credit,
        }
    }

    /// Records it may still have read now.
    pub fn available(&self) -> usize {
        self.credit.available_permits()
    }
}

/// One record's charge in the ingest stage ([`charge_of`]), from its connection's [`Allowance`]
/// or, for a batch the relay itself hands in, from `Store::Ingest` directly
/// ([`InFlight::trusted`]). Every batch handed to the stage carries one (`hub::Inbound`) until it
/// is decoded ([`Stages::decode_owned`]): from then its decode and its signed bytes carry charges
/// of their own for their life, and this one is let go, with the connection's credit.
#[derive(Debug)]
pub struct InFlight {
    charge: Charge,
    _credit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl InFlight {
    /// `bytes` charged to `gauge` (the relay's `Store::Ingest`), the caller waiting for room: for
    /// a batch handed in by the relay itself (a test's trace, a replay), on a thread that may
    /// wait. A charge larger than the whole limit waits until nothing else is held.
    pub fn trusted(gauge: &Arc<Gauge>, bytes: usize) -> Self {
        Self {
            charge: block_on(gauge.charge_for(RELAY_SOURCE, bytes)),
            _credit: None,
        }
    }

    /// `bytes` charged to `gauge` (the relay's `Store::Ingest`) now, or `None` when it has no room:
    /// for a record the relay itself hands in from a thread that must not wait (the timed duties
    /// taking in a record rebuilt from parity, `Hub::take_rebuilt`), which counts the refusal.
    pub fn try_trusted(gauge: &Arc<Gauge>, bytes: usize) -> Option<Self> {
        Some(Self {
            charge: gauge.try_charge(bytes)?,
            _credit: None,
        })
    }

    /// Nothing charged: for a test that hands a stage its parts by hand.
    #[cfg(test)]
    pub fn free() -> Self {
        Self {
            charge: Charge::none(),
            _credit: None,
        }
    }

    pub fn bytes(&self) -> usize {
        self.charge.bytes()
    }
}

/// Runs `future` to its end on the calling thread, parked between polls, outside tokio's
/// cooperative budget (`tokio::task::unconstrained`). The caller may be a thread of a tokio
/// runtime (a test's or a replay's task handing batches in): there each receive of a waiter's
/// grant spends the task's budget, which only a return to the scheduler renews, so past its 128th
/// wait every poll was told to yield and woke itself, and the caller spun forever with its charge
/// granted. Parked here, it never returns to the scheduler, so the budget is not its to keep.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(tokio::task::unconstrained(future));
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::park();
    }
}

/// A connection's verdict from the ingest stage: a batch it sent failed its signature or could
/// not be read, so the connection ends without a word, as it did when the check ran inline. A
/// clock never ends one (RFC-0171 §3.6): short of that, whether its feeder signed a batch by a
/// clock drifting from the relay's (`drifted`), which its link answers by stating the relay's
/// clock again (`RateLimit`'s `clock_ms`) at its next heartbeat, but only to a feeder that signed
/// in step with the clock last stated (`in_step`) since it was stated.
#[derive(Default)]
pub struct Refusal {
    why: Mutex<Option<String>>,
    notify: Notify,
    drifted: std::sync::atomic::AtomicBool,
    in_step: std::sync::atomic::AtomicBool,
}

impl Refusal {
    /// Ends the connection without a word: it broke a rule it cannot have broken by accident.
    pub fn refuse(&self, why: String) {
        if let Ok(mut held) = self.why.lock() {
            held.get_or_insert(why);
        }
        self.notify.notify_one();
    }

    /// Its feeder signed a batch by a clock drifting from the relay's: its link states the
    /// relay's clock again.
    pub fn drifted(&self) {
        self.drifted
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Its feeder signed a batch in step with the relay's clock (within half the tolerance): its
    /// clock is good now, so any drift noted before it is forgotten. A reconnect's backlog (batches
    /// that waited, too old, then the ones signed now, in step) is a wait and no drift, and alone
    /// never has the clock stated again: to a feeder that predates `clock_ms` a `RateLimit` starts
    /// its pace again.
    pub fn in_step(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.drifted.store(false, Relaxed);
        self.in_step.store(true, Relaxed);
    }

    /// Whether its link states the relay's clock again: its feeder's clock drifted since this was
    /// last asked and since it last signed in step, and it had signed in step since the clock was
    /// last stated, so it reads what it is told (or kept good time of its own until now). A
    /// `RateLimit` is a feeder's pace, and one that predates `clock_ms` (0.5.2, 0.6.x) starts its
    /// pace again on each, so a feeder whose clock is off from the start, or stays off after it
    /// was told, is not told again: its batches are judged by the window alone, and the ones too
    /// old to use are counted against its receiver (`stations::StationReport`'s `late_batches`).
    pub fn take_drift(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        self.drifted.swap(false, Relaxed) && self.in_step.swap(false, Relaxed)
    }

    /// Why, if a batch was refused.
    pub fn now(&self) -> Option<String> {
        self.why.lock().ok().and_then(|held| held.clone())
    }

    /// Resolves with why, once a batch was refused.
    pub async fn refused(&self) -> String {
        loop {
            if let Some(why) = self.now() {
                return why;
            }
            self.notify.notified().await;
        }
    }
}

/// Work for one worker, given its producer number. The relay hands a worker a record only with its
/// charge ([`Stages::run_charged`], [`Stages::run_stamped`]), each at least [`CHARGE_FLOOR`] of
/// `Store::Ingest`, so the records the charges admit are at most its bytes over [`CHARGE_FLOOR`]
/// ([`Room::records`]), however many connections came and went; and the
/// workers' queues take no more than that, whatever the charges say ([`lanes::Lanes`]). Anything else a
/// worker is given is a trace's or a test's (`advance`, `flush`), at most [`CONTROL_QUEUED`] at
/// once, its sender waiting for room; a worker ticks itself.
type Work = Box<dyn FnOnce(usize) + Send>;

/// The room a record handed to the ingest workers is charged to: `Store::Ingest`, the one pool.
/// What bounds the workers' queues ([`Room::records`]).
#[derive(Clone)]
pub struct Room {
    pub ingest: Arc<Gauge>,
}

impl Room {
    /// The room of a relay's budget.
    pub fn of(budget: &crate::budget::Budget) -> Self {
        Self {
            ingest: budget.gauge(Store::Ingest),
        }
    }

    /// The most records the pool admits at once, each charged at least [`CHARGE_FLOOR`] (and one,
    /// however large, while nothing else is held): read from its limit now, so a budget resized is
    /// followed.
    pub fn records(&self) -> usize {
        self.ingest
            .limit()
            .checked_div(CHARGE_FLOOR)
            .unwrap_or(usize::MAX)
            .max(1)
    }
}

/// The most control work (`Stages::advance`, `Stages::flush`: a trace's and a test's) waiting for
/// the workers at once; a sender past it waits for room.
pub const CONTROL_QUEUED: usize = 64;

/// The workers' queues: one a worker, each pushed only through [`lanes::Lanes`], whose
/// two ways in count what they push. A charged record is counted against [`Room::records`], every
/// worker together, and one past it is refused and counted, never queued; control work waits while
/// [`CONTROL_QUEUED`] wait. A queue is a `VecDeque` behind its lane's lock with no way to push but
/// those two, so no path can hand a worker anything uncounted.
///
/// Before, each queue was an `mpsc::channel`, unbounded, with the count kept beside it: bounded
/// only while every path that sent on it counted first, and the refusals it counted were read by
/// no report (`Hub::memory_report` serves them now, `ingest_refused`).
mod lanes {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use super::{CONTROL_QUEUED, Room, Work};

    enum Item {
        Record(Work),
        Control(Work),
    }

    #[derive(Default)]
    struct State {
        items: VecDeque<Item>,
        closed: bool,
    }

    #[derive(Default)]
    struct Lane {
        state: Mutex<State>,
        ready: Condvar,
    }

    impl Lane {
        fn lock(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    /// What a worker is given next.
    pub(super) enum Next {
        Work(Work),
        /// Nothing came within the wait: the worker ticks.
        Idle,
        /// Its stages are dropped and its queue is empty: the worker ends.
        Closed,
    }

    pub(super) struct Lanes {
        lanes: Box<[Lane]>,
        room: Room,
        records: AtomicUsize,
        refused: AtomicU64,
        control: Mutex<usize>,
        control_taken: Condvar,
    }

    impl Lanes {
        pub(super) fn new(workers: usize, room: Room) -> Self {
            Self {
                lanes: (0..workers.max(1)).map(|_| Lane::default()).collect(),
                room,
                records: AtomicUsize::new(0),
                refused: AtomicU64::new(0),
                control: Mutex::new(0),
                control_taken: Condvar::new(),
            }
        }

        pub(super) fn width(&self) -> usize {
            self.lanes.len()
        }

        fn lane(&self, worker: usize) -> &Lane {
            &self.lanes[worker % self.lanes.len()]
        }

        /// A charged record onto worker `worker`'s queue, counted: false, counted refused, when
        /// the queues hold all the records the rooms admit ([`Room::records`]). One handed to a
        /// worker that is gone (the stages being dropped) is dropped unrun.
        pub(super) fn push_record(&self, worker: usize, work: Work) -> bool {
            let bound = self.room.records();
            let admitted = self
                .records
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                    (queued < bound).then_some(queued + 1)
                })
                .is_ok();
            if !admitted {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            if !self.push(worker, Item::Record(work)) {
                self.records.fetch_sub(1, Ordering::AcqRel);
            }
            true
        }

        /// Control work onto worker `worker`'s queue, waiting while [`CONTROL_QUEUED`] wait.
        pub(super) fn push_control(&self, worker: usize, work: Work) {
            {
                let mut waiting = self.control.lock().unwrap_or_else(PoisonError::into_inner);
                while *waiting >= CONTROL_QUEUED {
                    waiting = self
                        .control_taken
                        .wait(waiting)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                *waiting += 1;
            }
            if !self.push(worker, Item::Control(work)) {
                self.control_done();
            }
        }

        fn push(&self, worker: usize, item: Item) -> bool {
            let lane = self.lane(worker);
            let mut state = lane.lock();
            if state.closed {
                return false;
            }
            state.items.push_back(item);
            drop(state);
            lane.ready.notify_one();
            true
        }

        fn control_done(&self) {
            {
                let mut waiting = self.control.lock().unwrap_or_else(PoisonError::into_inner);
                *waiting = waiting.saturating_sub(1);
            }
            self.control_taken.notify_all();
        }

        /// Worker `worker`'s next work, waiting up to `wait` for it; uncounted as it is taken.
        pub(super) fn next(&self, worker: usize, wait: Duration) -> Next {
            let lane = self.lane(worker);
            let mut state = lane.lock();
            loop {
                match state.items.pop_front() {
                    Some(Item::Record(work)) => {
                        self.records.fetch_sub(1, Ordering::AcqRel);
                        return Next::Work(work);
                    }
                    Some(Item::Control(work)) => {
                        drop(state);
                        self.control_done();
                        return Next::Work(work);
                    }
                    None if state.closed => return Next::Closed,
                    None => {
                        let (again, waited) = lane
                            .ready
                            .wait_timeout(state, wait)
                            .unwrap_or_else(PoisonError::into_inner);
                        state = again;
                        if waited.timed_out() && state.items.is_empty() && !state.closed {
                            return Next::Idle;
                        }
                    }
                }
            }
        }

        /// No more work is taken: each worker runs what its queue holds, then ends.
        pub(super) fn close(&self) {
            for lane in &*self.lanes {
                lane.lock().closed = true;
                lane.ready.notify_all();
            }
        }

        /// Records refused because the queues held their bound.
        pub(super) fn refused(&self) -> u64 {
            self.refused.load(Ordering::Relaxed)
        }

        /// Records waiting for the workers now.
        pub(super) fn queued(&self) -> usize {
            self.records.load(Ordering::Acquire)
        }
    }
}

/// A batch's work for one worker: given its producer number and the batch's charge.
pub type ChargedWork = Box<dyn FnOnce(usize, InFlight) + Send>;

/// A record's work for one worker, stamped there (`Stages::run_stamped`): given its stamp and its
/// charge.
pub type StampedWork = Box<dyn FnOnce(Stamp, InFlight) + Send>;

/// The threads the ingest work runs on, each a producer of the message exchange.
enum Pool {
    /// Run by the caller, one at a time: producer 0. For tests, and nothing else.
    Inline(Mutex<()>),
    Threads {
        lanes: Arc<lanes::Lanes>,
        handles: Vec<JoinHandle<()>>,
    },
}

/// The relay's clocks, every worker's stamps, and the message exchange the workers feed.
struct Core {
    clock: RelayClock,
    next: AtomicU64,
    /// Per producer: the newest stamp it took or ticked.
    last: Box<[AtomicU64]>,
    /// Per producer: when it last ticked.
    ticked: Box<[AtomicU64]>,
    message: MessageExchange,
    pause: Option<Pause>,
}

impl Core {
    /// The producer's stamp now (`clock::RelayClock::stamp`), at place `ingest_seq`, carried on
    /// to its last stamp when the monotonic clock reads before it ([`Stamp::not_before`]).
    #[allow(
        clippy::disallowed_methods,
        reason = "the producer's own newest monotonic reading, kept as a number between stamps and given back"
    )]
    fn now(&self, producer: usize, ingest_seq: u64) -> Stamp {
        let last = recorded::mono(self.last[producer].load(Ordering::Relaxed));
        self.clock.stamp(ingest_seq).not_before(last)
    }

    fn stamp(&self, producer: usize) -> Stamp {
        let stamp = self.now(producer, self.next.fetch_add(1, Ordering::Relaxed));
        self.last[producer].store(stamp.mono_ms(), Ordering::Relaxed);
        stamp
    }

    /// A stamp the trace gave: kept, and the producer's stamps go on from it.
    fn stamped(&self, producer: usize, stamp: Stamp) -> Stamp {
        self.last[producer].fetch_max(stamp.mono_ms(), Ordering::Relaxed);
        stamp
    }

    /// Ticks `producer` at its stamps' newest when `TICK_MS` has passed since its last tick, or
    /// always when `force`.
    fn tick(&self, producer: usize, force: bool) {
        let stamp = self.now(producer, 0);
        let now = stamp.mono_ms();
        let ticked = self.ticked[producer].load(Ordering::Relaxed);
        if force || now >= ticked + TICK_MS {
            self.last[producer].store(now, Ordering::Relaxed);
            self.ticked[producer].store(now, Ordering::Relaxed);
            self.message.tick(producer, stamp);
        }
    }

    /// Ticks `producer` at `stamp_ms`, moving its stamps on to it.
    fn tick_at(&self, producer: usize, stamp_ms: u64) {
        self.last[producer].fetch_max(stamp_ms, Ordering::Relaxed);
        self.tick(producer, true);
    }
}

/// The staged relay's ingest side: the workers and the message exchange they feed.
pub struct Stages {
    core: Arc<Core>,
    pool: Pool,
}

impl Stages {
    /// Every stage run by the caller (one producer, one message thread): for tests.
    pub fn inline(clock: RelayClock, sink: Sink, gauges: Gauges) -> Self {
        Self {
            core: Arc::new(Core {
                clock,
                next: AtomicU64::new(0),
                last: vec![AtomicU64::new(0)].into_boxed_slice(),
                ticked: vec![AtomicU64::new(0)].into_boxed_slice(),
                message: MessageExchange::inline(sink, gauges),
                pause: None,
            }),
            pool: Pool::Inline(Mutex::new(())),
        }
    }

    /// The stages on `threads`, closed epochs going to `sink`, each stage held up by `pause` (a
    /// test's; none in a relay), the records waiting for the workers at most what `room` admits
    /// ([`Room::records`]). Every thread is running or the stages are not made: a worker that
    /// cannot be started fails the relay at its start, since every message thread waits for every
    /// worker's tick and one missing would close no epoch ever.
    pub fn threaded(
        clock: RelayClock,
        threads: Threads,
        (sink, gauges, room): (&Sink, &Gauges, Room),
        pause: Option<Pause>,
    ) -> Result<Self, String> {
        let workers = threads.ingest.max(1);
        let core = Arc::new(Core {
            clock,
            next: AtomicU64::new(0),
            last: (0..workers).map(|_| AtomicU64::new(0)).collect(),
            ticked: (0..workers).map(|_| AtomicU64::new(0)).collect(),
            message: MessageExchange::threads(
                threads.message,
                workers,
                sink,
                gauges,
                pause.as_ref(),
            )?,
            pause,
        });
        let lanes = Arc::new(lanes::Lanes::new(workers, room));
        // Dropping `stages` on a failure stops and joins the workers already started.
        let mut stages = Self {
            core: Arc::clone(&core),
            pool: Pool::Threads {
                lanes: Arc::clone(&lanes),
                handles: Vec::with_capacity(workers),
            },
        };
        for producer in 0..workers {
            let core = Arc::clone(&core);
            let lanes = Arc::clone(&lanes);
            let spawned = std::thread::Builder::new()
                .name(format!("tally-ingest-{producer}"))
                .spawn(move || {
                    loop {
                        match lanes.next(producer, Duration::from_millis(TICK_MS)) {
                            lanes::Next::Work(work) => {
                                work(producer);
                                core.tick(producer, false);
                            }
                            lanes::Next::Idle => core.tick(producer, true),
                            lanes::Next::Closed => break,
                        }
                    }
                });
            let handle = spawned
                .map_err(|error| format!("ingest thread {producer} of {workers}: {error}"))?;
            if let Pool::Threads { handles, .. } = &mut stages.pool {
                handles.push(handle);
            }
        }
        Ok(stages)
    }

    /// Holds the calling stage up as the test's [`Pause`] says; nothing in a relay.
    pub fn pause(&self, stage: Stage) {
        if let Some(pause) = &self.core.pause {
            pause(stage);
        }
    }

    /// Whether the work runs on the caller.
    pub fn is_inline(&self) -> bool {
        matches!(self.pool, Pool::Inline(_))
    }

    /// Workers: the producers of the message exchange.
    pub fn width(&self) -> usize {
        match &self.pool {
            Pool::Inline(_) => 1,
            Pool::Threads { lanes, .. } => lanes.width(),
        }
    }

    /// The worker that owns raw shard `shard`.
    pub fn worker_of(&self, shard: crate::exchange::ShardId) -> usize {
        crate::exchange::thread_of(shard, self.width())
    }

    /// Runs a batch's `work` on worker `worker`, with its charge: the one way a batch reaches a
    /// worker, so the batches waiting for the workers are charged. False, counted
    /// ([`Stages::refused`]), when the workers' queues hold all the records the rooms admit
    /// ([`Room::records`]): the record is let go with its charge, never queued past the bound.
    pub fn run_charged(&self, worker: usize, in_flight: InFlight, work: ChargedWork) -> bool {
        self.run_record(worker, Box::new(move |producer| work(producer, in_flight)))
    }

    /// Records refused because the workers' queues held their bound: none while every record is
    /// charged as it should be. Served on `GET /memory` (`hub::MemoryReport::ingest_refused`).
    pub fn refused(&self) -> u64 {
        match &self.pool {
            Pool::Inline(_) => 0,
            Pool::Threads { lanes, .. } => lanes.refused(),
        }
    }

    /// Records waiting for the workers now.
    pub fn queued(&self) -> usize {
        match &self.pool {
            Pool::Inline(_) => 0,
            Pool::Threads { lanes, .. } => lanes.queued(),
        }
    }

    /// Runs `work` on worker `worker` with its charge, stamped there as a batch is: by `given`, a
    /// trace's stamp, else the worker's next stamp by the ingest clock. A record that is not a
    /// batch but must fall among a receiver's batches in the trace's order (its description) goes
    /// this way, on the worker that owns the receiver.
    pub fn run_stamped(
        &self,
        worker: usize,
        in_flight: InFlight,
        given: Option<Stamp>,
        work: StampedWork,
    ) -> bool {
        let core = Arc::clone(&self.core);
        self.run_record(
            worker,
            Box::new(move |producer| {
                let stamp = given.map_or_else(
                    || core.stamp(producer),
                    |stamp| core.stamped(producer, stamp),
                );
                work(stamp, in_flight);
            }),
        )
    }

    /// Runs a charged record's `work` on worker `worker`, counted in the workers' queues until a
    /// worker takes it; false, counted, when they hold their bound.
    fn run_record(&self, worker: usize, work: Work) -> bool {
        match &self.pool {
            Pool::Inline(lock) => {
                self.run_inline(lock, work);
                true
            }
            Pool::Threads { lanes, .. } => lanes.push_record(worker, work),
        }
    }

    /// Runs control work (a trace's or a test's) on worker `worker`, waiting while
    /// [`CONTROL_QUEUED`] wait.
    fn run_control(&self, worker: usize, work: Work) {
        match &self.pool {
            Pool::Inline(lock) => self.run_inline(lock, work),
            Pool::Threads { lanes, .. } => lanes.push_control(worker, work),
        }
    }

    /// Runs `work` now, on the caller, then ticks.
    fn run_inline(&self, lock: &Mutex<()>, work: Work) {
        let _held = lock.lock();
        work(0);
        self.core.tick(0, true);
    }

    /// The next stamp of `producer`: now by the ingest clock, never before its last.
    pub fn stamp(&self, producer: usize) -> Stamp {
        self.core.stamp(producer)
    }

    /// A stamp a trace gave, for `producer`.
    pub fn stamped(&self, producer: usize, stamp: Stamp) -> Stamp {
        self.core.stamped(producer, stamp)
    }

    /// The relay's clocks.
    pub fn clock(&self) -> RelayClock {
        self.core.clock.clone()
    }

    /// The monotonic clock now: the stamp of a record that is not a batch (a description,
    /// positions) for a subscriber queue's age.
    pub fn now_ms(&self) -> u64 {
        self.core.clock.mono().ms()
    }

    /// Decodes `batch`, verified, stamped `stamp`: the one decode every later stage shares. A
    /// batch of a format this build cannot read comes back whole, to be forwarded raw and read by
    /// nothing else.
    pub fn decode(batch: Batch, stamp: Stamp) -> Result<Arc<Decoded>, Box<Undecodable>> {
        Decoded::from_verified_stamped(batch, (stamp.moment(), stamp.judging()), stamp.ingest_seq)
    }

    /// As `decode`, the batch's signed bytes and its decode each charged once, for their life, to
    /// `gauge` (the relay's `Store::Decoded`): the bytes in the allocation every holder of the batch
    /// shares (`Batch::owned_by`), the decode inside its own (`Decoded::from_verified_owned`), and
    /// each let go with its last holder, never before it, whichever stages share them. The decode
    /// is entered in `covered` (the process's, `budget::Covered`) before it is counted alive, so no
    /// decode is ever alive uncharged, even for an instant. A batch the store has no room for comes
    /// back ([`NotDecoded::NoRoom`]), as one of a format this build cannot read does
    /// ([`NotDecoded::Undecodable`], its bytes charged).
    pub fn decode_owned(
        batch: Batch,
        stamp: Stamp,
        gauge: &Arc<Gauge>,
        covered: &'static crate::budget::Covered,
    ) -> Result<Arc<Decoded>, NotDecoded> {
        let batch = batch
            .owned_by(|bytes| {
                gauge
                    .try_charge(bytes)
                    .map(|charge| Box::new(charge) as tally_wire::decoded::Owner)
            })
            .map_err(NotDecoded::NoRoom)?;
        let charged = std::cell::Cell::new(0);
        Decoded::from_verified_owned(
            batch,
            (stamp.moment(), stamp.judging()),
            stamp.ingest_seq,
            |decoded| {
                charged.set(decoded.footprint());
                gauge
                    .try_charge(charged.get())
                    .map(|charge| Box::new(charge) as tally_wire::decoded::Owner)
            },
            |decoded| covered.own(decoded, charged.get()),
        )
    }

    pub fn message(&self) -> &MessageExchange {
        &self.core.message
    }

    /// Every worker ticks at `stamp_ms`: everything before it has been handed in. For a trace's
    /// end, and a test's.
    pub fn advance(&self, stamp_ms: u64) {
        match &self.pool {
            Pool::Inline(lock) => {
                let _held = lock.lock();
                self.core.tick_at(0, stamp_ms);
            }
            Pool::Threads { lanes, .. } => {
                for worker in 0..lanes.width() {
                    let core = Arc::clone(&self.core);
                    self.run_control(
                        worker,
                        Box::new(move |producer| {
                            core.tick_at(producer, stamp_ms);
                        }),
                    );
                }
            }
        }
    }
}

impl Stages {
    /// Waits until every worker has done everything handed to it before this call (each worker
    /// takes its work in order). For a trace's end, and a test's.
    pub fn flush(&self) {
        if let Pool::Threads { lanes, .. } = &self.pool {
            let (done, finished) = std::sync::mpsc::channel::<()>();
            let waiting = lanes.width();
            for worker in 0..waiting {
                let done = done.clone();
                self.run_control(
                    worker,
                    Box::new(move |_| {
                        let _ = done.send(());
                    }),
                );
            }
            drop(done);
            for _ in 0..waiting {
                if finished.recv().is_err() {
                    break;
                }
            }
        }
    }
}

impl Drop for Stages {
    fn drop(&mut self) {
        if let Pool::Threads { lanes, handles } = &mut self.pool {
            lanes.close();
            let here = std::thread::current().id();
            for handle in handles.drain(..) {
                // Dropped by work on one of its own workers: that one ends when its work does.
                if handle.thread().id() != here {
                    let _ = handle.join();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;

    /// The keys and network groups the pace maps' tests fill them with.
    fn pace_keys(count: usize) -> Result<(Vec<tally_wire::PublicKey>, Vec<Option<Group>>), String> {
        let keys = (0..count)
            .map(|_| tally_wire::Identity::generate().map(|identity| identity.public()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let groups = (0..count)
            .map(|n| {
                let n = u8::try_from(n % 200).unwrap_or(0);
                group_of(Some(std::net::IpAddr::from([20 + n, 1, 0, 1])))
            })
            .collect();
        Ok((keys, groups))
    }

    /// Every pace map is charged what its table and its entries allocate, read from the
    /// allocator, as entries come and are forgotten, and never more than its entries planned
    /// (`CEILING_ENTRY_BYTES`, `GRANT_ENTRY_BYTES`, `DIRECTORY_ENTRY_BYTES`). Before, none of them
    /// was charged to any store: a connection's pace state was planned at a kibibyte
    /// (`PACE_STATE_BYTES`) whatever the maps allocated.
    #[test]
    fn the_pace_maps_are_charged_what_they_allocate() -> Result<(), String> {
        use tally_counting::Counting;
        let (keys, groups) = pace_keys(200)?;
        let room = || {
            PaceRoom::within(
                &Gauge::unlimited(Store::Paces),
                &Gauge::unlimited(Store::Paces),
            )
        };

        let mut ceilings = ReceptionCeilings::within(room());
        let base = Counting::live();
        for (n, key) in keys.iter().enumerate() {
            // A millisecond apart: the buckets before refill, and the pruning forgets them.
            assert!(ceilings.take(*key, 1, n as u64));
            assert_eq!(Counting::since(base), ceilings.charged() as isize, "{n}");
            assert!(ceilings.charged() <= ceilings.len() * CEILING_ENTRY_BYTES);
        }
        assert!(ceilings.len() < keys.len(), "nothing was forgotten");
        drop(ceilings);
        // A pruning that keeps only a receiver already held gives the table's room back at once,
        // with no insert after it to do so: one receiver spent, then a hundred and twenty-eight
        // others refilled by the time it sends again.
        let mut ceilings = ReceptionCeilings::within(room());
        let base = Counting::live();
        let burst = ReceptionCeilings::BURST as usize;
        assert!(ceilings.take(keys[0], burst, 0));
        for key in &keys[1..=128] {
            assert!(ceilings.take(*key, 1, 0));
        }
        assert!(!ceilings.take(keys[0], burst, 1_000));
        assert_eq!(ceilings.len(), 1);
        assert_eq!(Counting::since(base), ceilings.charged() as isize);
        assert!(ceilings.charged() <= CEILING_ENTRY_BYTES);
        drop(ceilings);

        let grants = BurstGrants::new(
            RolePace {
                per_minute: 1 << 40,
                burst: 1 << 40,
            },
            GROUP_BURST_GRANTS,
        )
        .within(room());
        let base = Counting::live();
        for (n, group) in groups.iter().enumerate() {
            assert_eq!(grants.grant(*group, 1), 1);
            assert_eq!(Counting::since(base), grants.charged() as isize, "{n}");
            assert!(grants.charged() <= grants.groups_held() * GRANT_ENTRY_BYTES);
        }
        assert_eq!(grants.groups_held(), groups.len());
        drop(grants);

        let directory = DirectoryPaces::within(DIRECTORY_RECORDS, room());
        let mut links = Vec::with_capacity(groups.len());
        let base = Counting::live();
        for (n, group) in groups.iter().enumerate() {
            links.push(directory.join(*group).ok_or("joined")?);
            assert_eq!(Counting::since(base), directory.charged() as isize, "{n}");
            assert!(directory.charged() <= directory.groups_held() * DIRECTORY_ENTRY_BYTES);
        }
        // Each group owes nothing, so it is forgotten with its last link, and its room given back.
        while let Some(link) = links.pop() {
            drop(link);
            assert_eq!(Counting::since(base), directory.charged() as isize);
        }
        assert_eq!((directory.groups_held(), directory.charged()), (0, 0));
        Ok(())
    }

    /// A pace map holds no more than its entries' share of the store: a receiver, or a group, the
    /// room has no place for shares one entry with every other such newcomer, so a flood of keys
    /// or networks neither grows a map past its room nor gets a bucket each.
    #[test]
    fn a_pace_map_past_its_room_shares_one_entry() -> Result<(), String> {
        // Three entries' room, and forty newcomers: a small table's buckets hold more than three
        // (`table_per_entry` is an entry's most), never forty.
        let (keys, groups) = pace_keys(40)?;
        let store = Gauge::unlimited(Store::Paces);

        let share = Gauge::new(Store::Paces, 3 * CEILING_ENTRY_BYTES);
        let mut ceilings = ReceptionCeilings::within(PaceRoom::within(&store, &share));
        for key in &keys {
            assert!(ceilings.take(*key, 1, 0));
        }
        assert!(
            (1..keys.len()).contains(&ceilings.len()),
            "{}",
            ceilings.len()
        );
        assert!(share.held() <= share.limit());
        // The first receiver still has its own bucket; the ones past the room spent theirs together.
        let burst = ReceptionCeilings::BURST as usize;
        assert!(ceilings.take(keys[0], burst - 1, 0));
        assert!(!ceilings.take(keys[39], burst, 0));

        let share = Gauge::new(Store::Paces, 3 * GRANT_ENTRY_BYTES);
        let grants = BurstGrants::new(
            RolePace {
                per_minute: 1 << 40,
                burst: 1 << 40,
            },
            GROUP_BURST_GRANTS,
        )
        .within(PaceRoom::within(&store, &share));
        let whole = GROUP_BURST_GRANTS.burst;
        let granted: Vec<u64> = groups
            .iter()
            .map(|group| grants.grant(*group, whole))
            .collect();
        let held = grants.groups_held();
        assert!((1..groups.len()).contains(&held), "{held}");
        assert!(share.held() <= share.limit());
        // Each group held was granted its whole burst, and the rest one burst between them.
        assert_eq!(granted.iter().sum::<u64>(), (held as u64 + 1) * whole);

        let share = Gauge::new(Store::Paces, 3 * DIRECTORY_ENTRY_BYTES);
        let directory = DirectoryPaces::within(DIRECTORY_RECORDS, PaceRoom::within(&store, &share));
        let links = groups
            .iter()
            .map(|group| directory.join(*group))
            .collect::<Option<Vec<_>>>()
            .ok_or("joined")?;
        let held = directory.groups_held();
        assert!((1..groups.len()).contains(&held), "{held}");
        assert!(share.held() <= share.limit());
        // The groups past the room hold one share of the rate between them.
        assert_eq!(directory.groups_linked(), held + 1);
        drop(links);
        assert_eq!(directory.groups_linked(), 0);
        Ok(())
    }

    #[test]
    fn stamps_read_the_ingest_clock_never_go_back_and_count_up() {
        let sink: Sink = Arc::new(|_| Ok(()));
        let stages = Stages::inline(
            RelayClock::scripted(Arc::new(|| 42)),
            sink,
            Gauges::unlimited(),
        );
        let first = stages.stamp(0);
        let second = stages.stamp(0);
        assert_eq!((first.mono_ms(), first.ingest_seq()), (42, 0));
        assert_eq!((second.mono_ms(), second.ingest_seq()), (42, 1));
        assert!(first < second);
        stages.stamped(0, Stamp::recorded(100, 9, 100, 100, true));
        assert_eq!(stages.stamp(0).mono_ms(), 100);
    }

    /// A batch the relay hands in itself waits for room on its own thread, however many times it
    /// waits, a task of a tokio runtime among them: each wait is outside tokio's cooperative
    /// budget, so the 129th is served as the first was. (Inside the budget, a task that waited
    /// 128 times without returning to the scheduler spun on its granted charge forever.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_trusted_charge_waits_any_number_of_times_on_a_runtime_s_thread() {
        let gauge = Gauge::new(Store::Ingest, 10);
        let mut held = InFlight::trusted(&gauge, 10);
        for _ in 0..300 {
            let release = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_micros(200));
                drop(held);
            });
            held = InFlight::trusted(&gauge, 10);
            assert!(release.join().is_ok());
        }
        assert_eq!(gauge.held(), 10);
        assert!(gauge.waited() > 128, "{}", gauge.waited());
    }

    /// RFC-0181 §2, "Memory is charged once, for its life": a connection's allowance is a count of
    /// records, each charged its bytes to the one pool. A connection out of credit waits whatever
    /// room the pool has, so it never holds more than its records' worth of anyone's room; one
    /// with credit waits for room while the pool is full; and a record larger than the whole pool
    /// waits until the pool holds nothing. A connection that holds nothing holds no room.
    #[tokio::test]
    async fn a_connection_holds_its_credit_and_its_records_bytes_and_no_more() -> Result<(), String>
    {
        let pool = Gauge::new(Store::Ingest, 300);
        let greedy = Allowance::new(&pool, 2, network_source(Some(Group::V4(1)), 1));
        let honest = Allowance::new(&pool, 2, network_source(Some(Group::V4(2)), 2));
        // Admitted, neither holds anything.
        assert_eq!(pool.held(), 0);
        let first = greedy.acquire(100).await;
        let second = greedy.acquire(100).await;
        assert_eq!((greedy.available(), pool.held()), (0, 200));
        // Out of credit, the greedy one waits though the pool has room.
        let third = tokio::time::timeout(Duration::from_millis(20), greedy.acquire(10)).await;
        assert!(third.is_err());
        // The honest one takes the room left, then waits for room as the pool is full.
        let mine = honest.acquire(100).await;
        assert_eq!(pool.held(), 300);
        let waiting = tokio::spawn(async move {
            let more = honest.acquire(50).await;
            (more.bytes(), honest)
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(first);
        let (more, honest) = waiting.await.map_err(|error| error.to_string())?;
        assert_eq!(more, 50);
        drop((second, mine));
        // A record larger than the whole pool waits for it to hold nothing, then takes it.
        let large = tokio::spawn(async move { greedy.acquire(1_000).await.bytes() });
        tokio::task::yield_now().await;
        assert_eq!(large.await.ok(), Some(1_000));
        assert_eq!(pool.held(), 0);
        drop(honest);
        Ok(())
    }

    /// Waiting for the ingest pool is fair between networks, end to end through the connections'
    /// allowances: a network with four connections each waiting on a record, queued first, does
    /// not keep a second network's one waiting behind all four; the second is served after the
    /// first network's first. (Every waiter was one source before, so the queue was first come,
    /// first served.)
    #[tokio::test]
    async fn waiting_for_the_pool_is_fair_between_networks() -> Result<(), String> {
        const RECORD: usize = 200 * 1024;
        let pool = Gauge::new(Store::Ingest, RECORD);
        let allowance = |group: u16, connection: u64| {
            Allowance::new(
                &pool,
                CREDIT,
                network_source(Some(Group::V4(group)), connection),
            )
        };
        let greedy: Vec<_> = (0..4).map(|connection| allowance(1, connection)).collect();
        let honest = allowance(2, 9);
        // The pool is held, so everyone below waits for it.
        let held = pool.try_charge(RECORD).ok_or("the pool is free to take")?;
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for (n, allowance) in greedy.into_iter().enumerate() {
            let order = Arc::clone(&order);
            tasks.push(tokio::spawn(async move {
                let batch = allowance.acquire(RECORD).await;
                order
                    .lock()
                    .map(|mut order| order.push(format!("greedy {n}")))
                    .ok();
                drop(batch);
            }));
            tokio::task::yield_now().await;
        }
        let behind = Arc::clone(&order);
        tasks.push(tokio::spawn(async move {
            let batch = honest.acquire(RECORD).await;
            behind
                .lock()
                .map(|mut order| order.push("honest".to_owned()))
                .ok();
            drop(batch);
        }));
        tokio::task::yield_now().await;
        assert_eq!(pool.waiting(), 5);
        drop(held);
        for task in tasks {
            task.await.map_err(|error| error.to_string())?;
        }
        let order = order.lock().map_err(|error| error.to_string())?.clone();
        let place = order.iter().position(|name| name == "honest");
        assert!(
            place.is_some_and(|place| place <= 1),
            "the second network is served after the first network's first, not last: {order:?}"
        );
        Ok(())
    }

    /// Member sessions share the members' rate evenly between those using it: one that sends
    /// large batches holds no more of it than one that sends small ones. (Behind one shared
    /// pace, each waited for the debt of all, so throughput followed the size of a take: a 64 KiB
    /// batch moved sixty-four times the bytes of a 1 KiB one.)
    #[tokio::test(start_paused = true)]
    async fn member_sessions_share_the_rate_evenly_whatever_their_batch_size() {
        let pace = Arc::new(MemberPace::new(1 << 20));
        let moved = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let started = tokio::time::Instant::now();
        let mut tasks = Vec::new();
        for (index, size) in [64u64 << 10, 1 << 10].into_iter().enumerate() {
            let session = pace.session();
            let moved = Arc::clone(&moved);
            tasks.push(tokio::spawn(async move {
                while started.elapsed() < Duration::from_secs(30) {
                    session.take(size, 0).await;
                    moved[index].fetch_add(size, Ordering::Relaxed);
                }
            }));
        }
        for task in tasks {
            assert!(task.await.is_ok());
        }
        let (large, small) = (
            moved[0].load(Ordering::Relaxed),
            moved[1].load(Ordering::Relaxed),
        );
        assert!(
            small * 10 >= large * 8 && small <= large * 12 / 10,
            "large batches moved {large}, small ones {small}"
        );
        // And together they stayed within the members' rate and its burst, in charged bytes: the
        // feeders 1 MiB/s of signed batches is worth, each a planned batch's charge a second.
        let (rate, _) = pace.rates();
        assert_eq!(
            rate,
            crate::budget::feeders_for_rate(1 << 20) as u64 * PLANNED_BATCH_CHARGE as u64
        );
        assert!(large + small <= 30 * rate + crate::ceiling::burst(rate) + (256 << 10));
    }

    /// A member's batches are held to receptions as well as bytes: many small receptions in few
    /// bytes cannot bring in more than the plan holds for the members' rate.
    #[tokio::test(start_paused = true)]
    async fn a_members_receptions_are_paced_beside_its_bytes() {
        let pace = MemberPace::new(1 << 20);
        let (_, receptions_per_sec) = pace.rates();
        let session = pace.session();
        let started = tokio::time::Instant::now();
        for _ in 0..100 {
            // 1 KiB carrying 10,000 receptions: a hundred of them are a million.
            session.take(1 << 10, 10_000).await;
        }
        let needed = (1_000_000 - crate::ceiling::burst(receptions_per_sec)) as f64
            / receptions_per_sec as f64;
        assert!(
            started.elapsed().as_secs_f64() >= needed * 0.9,
            "{:?} for a million receptions at {receptions_per_sec} a second",
            started.elapsed()
        );
    }

    /// What a batch is charged before it is decoded bounds what its decode and its signed bytes
    /// are charged for their life, plain or inflated: the ingest charge is let go at the decode,
    /// the two charged by themselves from then (`Stages::decode_owned`). Its inflated bytes are
    /// allocated at their stated length, never at a growing buffer's capacity.
    #[test]
    fn a_batch_charge_bounds_its_decode_and_bytes_and_is_let_go_there() -> Result<(), String> {
        let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        for codec in [
            tally_wire::batch::Codec::Plain,
            tally_wire::batch::Codec::Deflate,
        ] {
            let batch = crate::anchors::anchored_with(
                &identity,
                &tally_wire::BatchContent {
                    boot_id: 1,
                    sequence: 0,
                    counter_epoch: 0,
                    wall_ms: 0,
                    dropped: 0,
                    previous: [0; 32],
                    observations: (0..40u8)
                        .map(|n| tally_wire::Observation {
                            format: b'3',
                            timestamp: u64::from(n),
                            signal: 0,
                            data: vec![n; 14],
                        })
                        .collect(),
                },
                codec,
            )
            .map_err(|error| error.to_string())?;
            let charge = charge_of(&batch);
            let at_most = batch
                .receptions_at_most()
                .map_err(|error| error.to_string())?;
            let unfloored = charge_for(
                batch.as_bytes().len(),
                batch.inflated_len().map_err(|error| error.to_string())?,
                at_most,
            );
            let pool = Gauge::new(Store::Ingest, charge);
            let in_flight = InFlight::trusted(&pool, charge);
            let decoded_store = Gauge::unlimited(Store::Decoded);
            let decoded = Stages::decode_owned(
                batch,
                Stamp::at(0, 0),
                &decoded_store,
                crate::budget::Covered::process(),
            )
            .map_err(|error| format!("{error:?}"))?;
            drop(in_flight);
            assert_eq!(pool.held(), 0);
            let both = decoded.footprint() + decoded.batch().footprint();
            assert_eq!(decoded_store.held(), both);
            assert!(charge >= both, "{codec:?}: {charge} charged, {both} held");
            // Charged, before the floor, no more than that and its slack, to the byte: the references for the
            // receptions its length could hold and it does not, and a plain batch's inflated
            // bytes, which are its signed bytes' own (each part of the charge is a part of what the
            // two allocate, the kept key's included, `batch::KEPT_BYTES`).
            let slack = (at_most - decoded.receptions()) * std::mem::size_of::<ObsRef>()
                + match codec {
                    tally_wire::batch::Codec::Plain => {
                        decoded.inflated_len() + tally_wire::decoded::BYTES_HEADER
                    }
                    tally_wire::batch::Codec::Deflate | tally_wire::batch::Codec::DeflateAt(_) => 0,
                };
            assert_eq!(unfloored, both + slack, "{codec:?}");
            assert_eq!(decoded.plain().len(), decoded.inflated_len());
            drop(decoded);
            assert_eq!(decoded_store.held(), 0);
        }
        Ok(())
    }

    /// RFC-0181 §2: a batch a connection read holds the store for its own bytes for as long as
    /// anything holds it, whenever the connection ended. A peer that connects, sends a batch the
    /// workers have not taken, and hangs up, again and again, holds `Store::Ingest` for every batch
    /// it left queued and nothing more: the pool's room is what is queued, whoever connected.
    #[tokio::test]
    async fn a_batch_a_connection_left_holds_the_pool_for_its_own_bytes() -> Result<(), String> {
        let pool = Gauge::new(Store::Ingest, 300);
        let mut queued = Vec::new();
        for connected in 1..=7 {
            let allowance = Allowance::new(&pool, CREDIT, RELAY_SOURCE);
            // A batch handed to the workers, then the connection ends.
            match tokio::time::timeout(Duration::from_millis(20), allowance.acquire(40)).await {
                Ok(in_flight) => queued.push(in_flight),
                Err(_) => break,
            }
            drop(allowance);
            assert_eq!(pool.held(), 40 * connected);
        }
        // Seven batches left behind, each holding its own bytes and no more.
        assert_eq!(queued.len(), 7);
        drop(queued.remove(0));
        assert_eq!(pool.held(), 240);
        drop(queued);
        assert_eq!(pool.held(), 0);
        Ok(())
    }

    /// RFC-0181 §2: however small its records, a connection has at most its credit of them waiting
    /// for, or in, the workers (a member session `RECORDS_IN_FLIGHT`), each charged at least
    /// `CHARGE_FLOOR`, the cost of its verification. By bytes alone a 300-byte batch took some 500
    /// places.
    #[tokio::test]
    async fn a_connection_holds_at_most_its_records_in_flight_however_small() -> Result<(), String>
    {
        let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        let tiny = crate::anchors::anchored(
            &identity,
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        assert!(tiny.as_bytes().len() < 400);
        assert_eq!(charge_of(&tiny), CHARGE_FLOOR);
        let pool = Gauge::unlimited(Store::Ingest);
        let allowance = Allowance::new(&pool, RECORDS_IN_FLIGHT, RELAY_SOURCE);
        let mut held = Vec::new();
        while let Ok(in_flight) =
            tokio::time::timeout(Duration::ZERO, allowance.acquire(charge_of(&tiny))).await
        {
            held.push(in_flight);
            if held.len() > 10 * RECORDS_IN_FLIGHT {
                break;
            }
        }
        assert_eq!(held.len(), RECORDS_IN_FLIGHT);
        Ok(())
    }

    /// A room that bounds nothing: a test's stages.
    fn unlimited_room() -> Room {
        Room {
            ingest: Gauge::unlimited(Store::Ingest),
        }
    }

    /// The workers' queues are bounded by construction, not only by what the charges admit.
    /// The one worker is held at a gate while records are handed in: the queues take as many as
    /// the rooms admit (`Room::records`, here two) and refuse, counted, the next, letting its charge
    /// go at once; the worker let go runs the two it holds. Before, each worker's queue was an
    /// unbounded channel: a record handed in past what the charges allow (a path that charged
    /// short, or not at all) was queued all the same, and the queue grew without limit.
    #[test]
    fn the_workers_queues_hold_no_more_than_the_rooms_admit() -> Result<(), String> {
        let room = Room {
            ingest: Gauge::new(Store::Ingest, 2 * CHARGE_FLOOR),
        };
        assert_eq!(room.records(), 2);
        let sink: Sink = Arc::new(|_| Ok(()));
        let threads = Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        };
        let stages = Stages::threaded(
            crate::clock::RelayClock::scripted(Arc::new(|| 0)),
            threads,
            (&sink, &Gauges::unlimited(), room),
            None,
        )?;
        // The worker takes the first and waits at the gate inside it.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (started, running) = channel::<()>();
        let held = Arc::clone(&gate);
        assert!(stages.run_charged(
            0,
            InFlight::free(),
            Box::new(move |_, _| {
                let _ = started.send(());
                let (open, opened) = &*held;
                if let Ok(mut open) = open.lock() {
                    while !*open {
                        match opened.wait(open) {
                            Ok(again) => open = again,
                            Err(_) => return,
                        }
                    }
                }
            }),
        ));
        running
            .recv_timeout(Duration::from_secs(60))
            .map_err(|_| "the worker never took the first record".to_owned())?;
        // Two wait for it, each charged; the third is refused and its charge let go.
        let charges = Gauge::unlimited(Store::Ingest);
        let (ran, done) = channel::<()>();
        let mut handed = Vec::new();
        for _ in 0..3 {
            let ran = ran.clone();
            handed.push(stages.run_charged(
                0,
                InFlight::trusted(&charges, CHARGE_FLOOR),
                Box::new(move |_, in_flight| {
                    drop(in_flight);
                    let _ = ran.send(());
                }),
            ));
        }
        drop(ran);
        assert_eq!(handed, [true, true, false]);
        assert_eq!((stages.queued(), stages.refused()), (2, 1));
        assert_eq!(charges.held(), 2 * CHARGE_FLOOR);
        // Let go, the worker runs the two it holds, and the queues are empty again.
        let (open, opened) = &*gate;
        if let Ok(mut open) = open.lock() {
            *open = true;
        }
        opened.notify_all();
        for _ in 0..2 {
            done.recv_timeout(Duration::from_secs(60))
                .map_err(|_| "a queued record never ran".to_owned())?;
        }
        stages.flush();
        assert_eq!((stages.queued(), charges.held()), (0, 0));
        Ok(())
    }

    /// A connection's records a second are held to its byte ceiling over `RECORD_BYTES`,
    /// whatever their bytes: at the default feeder ceiling, eight a second after a second's burst,
    /// so tiny batches sent as fast as the socket takes them are some eight signature checks a
    /// second, not the 870 they were. Paused time: each wait is the pace's exactly.
    #[tokio::test(start_paused = true)]
    async fn a_connections_records_a_second_are_held_to_its_ceiling() {
        assert_eq!(records_per_sec(256 * 1024), 8);
        assert_eq!(records_per_sec(0), 1);
        let pace = RecordPace::new(records_per_sec(256 * 1024));
        let start = tokio::time::Instant::now();
        // The burst at once.
        for _ in 0..8 {
            pace.take().await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
        // Then eight a second: forty more take five seconds.
        for _ in 0..40 {
            pace.take().await;
        }
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    /// Opens a stalled stage's gate when dropped, so a test that fails never leaves a thread
    /// waiting at it.
    struct Gate(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Gate {
        fn closed() -> Self {
            Self(Arc::new((Mutex::new(false), std::sync::Condvar::new())))
        }

        /// A pause that holds `stage` until the gate opens.
        fn holding(&self, stage: Stage) -> Pause {
            let gate = Arc::clone(&self.0);
            Arc::new(move |at| {
                if at != stage {
                    return;
                }
                let (open, opened) = &*gate;
                let Ok(mut held) = open.lock() else {
                    return;
                };
                while !*held {
                    match opened.wait(held) {
                        Ok(again) => held = again,
                        Err(_) => return,
                    }
                }
            })
        }

        fn open(&self) {
            let (open, opened) = &*self.0;
            if let Ok(mut held) = open.lock() {
                *held = true;
            }
            opened.notify_all();
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            self.open();
        }
    }

    /// RFC-0181 invariant 9: no lock is held across a seal and nothing on the ingest path waits for
    /// the sealer. The real sealer is stalled outright (held at its first command until the test
    /// lets it go) while twenty epochs of batches are handed in by a scripted ingest clock: every
    /// one is decoded and routed all the same, and once the sealer runs again it catches up to the
    /// last epoch. Decided by what completes while the sealer stands still, never by timing: had
    /// any batch waited on the sealer, its routing could not finish (the deadline below only turns
    /// that hang into a failure).
    #[test]
    fn ingest_never_waits_for_a_stalled_sealer() -> Result<(), String> {
        let gate = Gate::closed();
        let pause = gate.holding(Stage::Sealer);
        let products = Arc::new(crate::products::Products::with_boot(1, 1));
        let threads = Threads {
            ingest: 2,
            message: 2,
            seal: 2,
        };
        products.on_thread(threads, Some(&pause))?;
        let sink = products.sink();
        let clock = Arc::new(AtomicU64::new(0));
        let reading = Arc::clone(&clock);
        let stages = Arc::new(Stages::threaded(
            crate::clock::RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed))),
            threads,
            (&sink, &Gauges::unlimited(), unlimited_room()),
            Some(pause),
        )?);
        drop(sink);
        let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        let (done, finished) = channel::<()>();
        const BATCHES: u64 = 2_000;
        const MS_APART: u64 = 10;
        for sequence in 0..BATCHES {
            let batch = crate::anchors::anchored(
                &identity,
                &tally_wire::BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: 0,
                    dropped: 0,
                    previous: [0; 32],
                    observations: (0..50u32)
                        .map(|n| tally_wire::Observation {
                            format: b'3',
                            timestamp: u64::from(n),
                            signal: 0,
                            data: (n ^ (sequence as u32) << 8).to_be_bytes().repeat(3)[..12]
                                .iter()
                                .chain(&[0, 0])
                                .copied()
                                .collect(),
                        })
                        .collect(),
                },
            )
            .map_err(|error| error.to_string())?;
            // The ingest clock moves on as the batches come: twenty epochs of them.
            clock.store(sequence * MS_APART, Ordering::Relaxed);
            let done = done.clone();
            let working = Arc::clone(&stages);
            stages.run_record(
                sequence as usize,
                Box::new(move |producer| {
                    let stamp = working.stamp(producer);
                    let raw = stamp.raw();
                    if let Ok(decoded) = Stages::decode(batch, stamp) {
                        working.message().route(producer, &decoded, None, raw);
                    }
                    let _ = done.send(());
                }),
            );
        }
        drop(done);
        for routed in 0..BATCHES {
            match finished.recv_timeout(Duration::from_secs(120)) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "{routed} of {BATCHES} routed: ingest waits for the stalled sealer"
                    ));
                }
            }
        }
        // Everything is routed and the sealer has sealed nothing: it still stands at its gate.
        assert_eq!(products.watermark_ms(), 0);
        let end_ms = BATCHES * MS_APART + crate::seal::EPOCH_MS;
        stages.advance(end_ms);
        stages.flush();
        gate.open();
        // Let go, it takes everything the shards closed while it stood: up to the last epoch.
        let due = (end_ms / crate::seal::EPOCH_MS) * crate::seal::EPOCH_MS;
        let mut waited = 0;
        while products.watermark_ms() < due {
            waited += 1;
            if waited > 24_000 {
                return Err(format!(
                    "the sealer reached {} of {due} once let go",
                    products.watermark_ms()
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(stages);
        Ok(())
    }

    /// A stamp moved along the monotonic clock (to an epoch's end, or on to its producer's last
    /// stamp) carries its judging reading by the pair's offset, and keeps the raw reading it took:
    /// the raw clock runs apart from `M` (a daemon slews `M` with `J`, and never the raw clock), so
    /// a span of `M` is no span of it. Before, both moves added the monotonic span to the raw
    /// reading too, and an anchor's age was reckoned on a raw time no clock read.
    #[test]
    fn a_stamp_moved_on_the_monotonic_clock_keeps_its_raw_reading() {
        // `J` an hour ahead of `M`, the raw clock on an origin of its own.
        let stamp = Stamp::recorded(10_000, 7, 3_610_000, 500, true);
        let moved = stamp.at_mono(recorded::mono(12_000));
        assert_eq!(
            (moved.mono_ms(), moved.judged().ms(), moved.raw().ms()),
            (12_000, 3_612_000, 500)
        );
        assert_eq!((moved.ingest_seq(), moved.judging()), (7, true));
        let carried = stamp.not_before(recorded::mono(11_000));
        assert_eq!(
            (carried.mono_ms(), carried.judged().ms(), carried.raw().ms()),
            (11_000, 3_611_000, 500)
        );
        // Never back.
        assert_eq!(stamp.not_before(recorded::mono(9_000)), stamp);
    }
}
