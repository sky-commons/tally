//! The raw a holder has received, as it arrived (RFC-0171 §3.8.1 as amended 2026-10-24, crate
//! docs § Holding raw; RFC-0181 §5): one pool for every receiver the holder takes raw of, held in
//! one-second slices of signed wall clock, with each receiver's contiguous frontier of batches and
//! the transmissions still settling. A model's inputs are what had arrived when it was fitted,
//! cited by each member's frontier ([`Arrived::inputs`]); a transmission is solved from the
//! receptions of it that had arrived `SETTLE_MS` after its first one did (its considered set,
//! [`Arrived::due`]). One implementation for every holder (an engine solving, a relay judging a
//! model or a fix it holds the raw of), so two holders of the same batches hold the same receptions
//! and rebuild the same inputs.
//!
//! - **What is held** is decided by each batch alone (`threshold`): of one receiver's batch, the
//!   sync events and operational status of the reference aircraft, and its replies but those of
//!   an aircraft the batch carries an ADS-B position of (unless it is in the calibration sample),
//!   each thinned by its threshold only when the batch is over its cap. Nothing a later batch,
//!   another receiver or the arrival order says changes what one batch keeps, so a holder of more
//!   batches holds a superset of what a holder of fewer holds.
//! - **Held once a slice**: a reception is 16 bytes in its slice (its message an index into the
//!   slice's messages, each held once with its hash), its batch's receptions one contiguous run
//!   (sync and status first), so a member's sync raw is read without a pass over anyone else's.
//! - **Frontiers** ([`Frontier`]): per receiver, its newest boot's batches taken, as runs with no
//!   gap, in any order they came; the frontier is the last batch of the lowest run. A batch above
//!   a gap is held but cited by no model until the gap fills, or until the batch just above it is
//!   older than anything held ([`HELD_MS`]), when nothing the gap held could be in any window and
//!   it is passed. A copy of a batch already taken adds nothing.
//! - **Bounded, whole** ([`Limits`]): one pool of bytes for every receiver (relay-wide, as the
//!   relay's tables are), and a cap on what one receiver holds in a slice. A batch beyond either
//!   is refused whole and counted ([`Refused`]), never trimmed by rank; it is a gap in its
//!   receiver's frontier like any batch that never came. Every growth is reckoned before it is
//!   allocated, so the pool is never passed.
//! - **Accounted as allocated**: every byte [`Arrived::bytes`] reports is a capacity actually
//!   allocated (vectors by capacity, maps by their tables), so admission is sized on what is
//!   really in memory.
//! - **Due sets** ([`Considered`]): held replies by their message bytes alone. A reply joins the
//!   set of its bytes whose first reception arrived within [`JOIN_MS`] of it, or starts one. A set
//!   may hold several transmissions of the same bytes (Mode S replies repeat byte for byte about
//!   every second); model time is the only thing that tells them apart, so the solver splits a
//!   set by it (`group`), never the pool, and never a signed wall clock (feeders' differ by
//!   seconds). A set is due [`SETTLE_MS`] after its first reception arrived, due again, with every
//!   reception held of it, at each seal after one more joins (a repeat of its bytes is a new
//!   transmission, solved at once), and due once more at the seal that closes it, [`JOIN_MS`]
//!   after its first arrived, if any joined since it was first due. The bound on solving is the
//!   transmission's, after grouping (`tally_mlat`'s engine): solved when first seen, and again
//!   once, if it grew, once its own raw has come ([`Considered::come_ms`]) or as its set closes.
//!   A holder of more batches holds a superset of each set it shares.
//! - **Never ahead, never late**: a batch signed more than [`AHEAD_MS`] past its arrival is
//!   refused; one signed more than [`HELD_MS`] before it is older than every window and refused as
//!   late, which passes it in its frontier (nothing it held could be cited).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use tally_wire::budget::{
    ARRIVED_SLICE, FIT_LAG_MS, FIX_SETTLE, MLAT_AHEAD, MLAT_BATCHING, REFIT_EVERY_MS,
    SIGNED_LAG_MS, TRAILING_WINDOW_MS,
};
use tally_wire::clocks::Judged;
use tally_wire::{PublicKey, Region};

use crate::modes;
use crate::obs::{ByDigest, ModeS, ObservationId, Reception, Site, message_hash};
use crate::pair::PairModel;
use crate::scope::{Citation, Frontier, Inputs, Part, Sites, SyncMessage, SyncReception, Trailing};
use crate::threshold::{
    KEPT_KEEP, REPLIES_PER_BATCH, batch_sync_keep, reference, reply_key, sync_key_of,
};
use crate::verify::PairModelFailure;

/// Whether MLAT ever uses a message (module docs, What is held): the network's one rule, which the
/// feeder sheds by and the relay counts by too.
pub use tally_wire::modes::{LONG, wanted};

/// A slice of signed wall clock, milliseconds: `tally_wire::budget::ARRIVED_SLICE`.
pub const SLICE_MS: u64 = ARRIVED_SLICE.span::<Judged>().ms();
const _: () = assert!(SLICE_MS == 1_000);
/// How long after a transmission's first reception arrives it is due (its considered set closed):
/// `tally_wire::budget::FIX_SETTLE`.
pub const SETTLE_MS: u64 = FIX_SETTLE.span::<Judged>().ms();
/// How long arrived raw is held: the longer of what a fit and what a settlement need. A fit needs a
/// trailing window and what its first blocks read before it (`pair::READ_BACK_MS`), how far its
/// edge trails the clock it ran at (`FIT_LAG_MS`), how late a
/// reception's signed wall clock may be behind its arrival, and one step, so a model is rebuilt
/// from what is held for as long as its fixes may be judged. A settlement (`standing::SETTLE`,
/// `tally_wire::budget::FIX_ARRIVED`) asks for the raw of a transmission that long after it was
/// sent.
pub const HELD_MS: u64 = {
    let fit = TRAILING_WINDOW_MS
        + crate::pair::READ_BACK_MS
        + FIT_LAG_MS
        + SIGNED_LAG_MS
        + REFIT_EVERY_MS;
    let settle = tally_wire::budget::FIX_ARRIVED.span::<Judged>().ms();
    if fit > settle { fit } else { settle }
};
/// How long after a due set's first reception arrives a later reception of the same bytes still
/// joins it: `tally_wire::budget::SIGNED_LAG`, how far behind the judging clock an honest
/// receiver's raw reaches its relay. Every honest reception of a transmission arrives within this
/// of when it was sent, and the first arrived no earlier than that, so every honest reception of
/// the set's first transmission arrives within this of the first. A set that grew since it was
/// first due is due once more at the seal that closes it (`Arrived::seal`): a transmission's
/// complete fix leaves within a step of `JOIN_MS` after its set's first arrival at the latest,
/// which is no later than its transmission plus `SIGNED_LAG`, and within `FIX_SOLVE` after that,
/// inside `FIX_LEAVES`; one whose raw has come sooner ([`Considered::come_ms`]) is solved again
/// then.
pub const JOIN_MS: u64 = SIGNED_LAG_MS;
const _: () = assert!(JOIN_MS + SLICE_MS <= HELD_MS);

/// How far past its arrival a batch may be signed and still be held: the error budget's
/// `tally_wire::budget::MLAT_AHEAD`, as far as an honest feeder's signed time may be ahead of a
/// relay's judging clock.
pub const AHEAD_MS: u64 = MLAT_AHEAD.span::<Judged>().ms();
/// Batches a verifier names as missing for one frontier, at most: enough to say which, never a
/// list as long as a feeder's gap.
pub const MISSING_NAMED: usize = 8;

/// One aircraft heard with ADS-B in this many is solved by MLAT too, chosen by hash, so the
/// published covariance can be measured against the aircraft's own GNSS position.
pub const CALIBRATION_SAMPLE: u32 = 16;
/// What the calibration sample is hashed under.
const SAMPLE_DOMAIN: &[u8] = b"tally calibration sample";
/// The span the calibration sample is drawn afresh in, milliseconds: an aircraft is in it, or not,
/// for five seconds of signed wall clock at a time.
pub const SAMPLE_PERIOD_MS: u64 = 5_000;

/// Whether `address`, heard with ADS-B at `wall_ms`, is in the calibration sample: the first byte
/// of BLAKE2s-256 over `"tally calibration sample" 0x00`, the address and the sample period
/// (`wall_ms / SAMPLE_PERIOD_MS`, as an `i64`), big-endian, below `256 / CALIBRATION_SAMPLE`.
pub fn sampled(address: u32, wall_ms: u64) -> bool {
    use blake2::{Blake2s256, Digest};
    let period = i64::try_from(wall_ms / SAMPLE_PERIOD_MS).unwrap_or(i64::MAX);
    let mut hasher = Blake2s256::new();
    hasher.update(SAMPLE_DOMAIN);
    hasher.update([0]);
    hasher.update(address.to_be_bytes());
    hasher.update(period.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    u32::from(digest[0]) < 256 / CALIBRATION_SAMPLE
}

/// The most replies a second one receiver keeps whole (a feeder seals a batch every second, and a
/// batch over [`REPLIES_PER_BATCH`] is thinned): what a holder keeps of a receiver at the
/// world benchmark's density, where every receiver reaches it (`Rates::MEASURED`).
pub const KEPT_CEILING_PER_S: usize = 300;

/// One signed batch: its receiver, the receiver's boot and the batch's sequence in that boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BatchId {
    pub receiver: PublicKey,
    pub boot_id: u64,
    pub sequence: u64,
}

/// Which due set a considered set is, inside one holder: its message's hash and the slice of
/// arrival clock its first reception arrived in. Stable as more receptions join it (for
/// `JOIN_MS`), and one a message a slice, as the sets of one message are `JOIN_MS` apart. A
/// grouping key, not an identity across holders: a fix's identity is over the receptions it
/// considered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransmissionKey {
    pub message: [u8; 32],
    pub slice: u64,
}

/// Why a batch was not admitted: refused whole, never trimmed by rank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A hard cap of the holder's limits: `count` would pass `cap`.
    OverCap {
        what: &'static str,
        count: usize,
        cap: usize,
    },
    /// Signed more than [`HELD_MS`] before it arrived: older than every window.
    Late { wall_ms: u64 },
    /// Signed more than [`AHEAD_MS`] past its arrival.
    Ahead { wall_ms: u64 },
}

/// What admitting one batch did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    /// Receptions held.
    pub kept: u32,
    /// Receptions a threshold, or the batch's own content (module docs, What is held), dropped.
    pub thinned: u32,
    pub refused: Option<Refused>,
}

/// A transmission due to be solved: the receptions of it that had arrived `SETTLE_MS` after its
/// first did, which is all a solution of it may be judged on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Considered {
    pub key: TransmissionKey,
    pub first_arrival_ms: u64,
    /// Whether this is its set's last due, as it closes (`JOIN_MS` after its first arrival):
    /// what an engine that solves a transmission twice at most solves it again at.
    pub closing: bool,
    /// Sorted by identity.
    pub receptions: Vec<Reception>,
    /// When each of `receptions` arrived, by the arrival clock its batch was admitted at, in its
    /// order: what tells when the raw of one transmission of the set had all come
    /// (`tally_mlat`'s `fix::back_off`).
    pub arrived_ms: Vec<u64>,
}

impl Considered {
    /// When the raw of one transmission of the set, whose receptions are `group`, has all come, by
    /// the arrival clock: [`MLAT_BATCHING`] after the first of `group` arrived (a receiver's raw of
    /// a moment reaches its relay within it, its batch gathered and on its way). A transmission
    /// solved before is solved again once it has (`tally_mlat`'s `fix::again`). A function of the
    /// set alone, the same on every holder it arrived at alike. Every reception of a set is of one
    /// message, so its receptions in their order (`Reception::id`'s) are found by their receiver,
    /// epoch and counter, with no message hashed. Before, each step of the search hashed both
    /// receptions' messages, and that was a third of the host's serial stepping at 2,000 feeders
    /// (2026-10-26).
    pub fn come_ms<R: std::borrow::Borrow<Reception>>(&self, group: &[R]) -> u64 {
        let order = |one: &Reception| (one.receiver, one.epoch, one.timestamp);
        group
            .iter()
            .map(std::borrow::Borrow::borrow)
            .filter_map(|reception| {
                let at = self
                    .receptions
                    .binary_search_by(|held| order(held).cmp(&order(reception)))
                    .ok()?;
                self.arrived_ms.get(at).copied()
            })
            .min()
            .unwrap_or(self.first_arrival_ms)
            .saturating_add(MLAT_BATCHING.span::<Judged>().ms())
    }
}

/// A held reception of a due set: its slice's start, the slice, its batch and its entry.
type HeldReception<'a> = (u64, &'a Slice, &'a SliceBatch, &'a Entry);

/// A held reception's wall clock, as its [`Reception`] would carry it.
fn held_wall((slice_at, _, _, entry): &HeldReception<'_>) -> u64 {
    slice_at * SLICE_MS + u64::from(entry.into_ms)
}

/// A due set as the pool holds it ([`Arrived::due_set`]): its receptions in identity order, each
/// identity once, read where they lie. Judged by its receivers, its size, its earliest wall clock
/// and its message; made into a [`Considered`] only once taken up.
pub struct Due<'a> {
    pub key: TransmissionKey,
    pub first_arrival_ms: u64,
    pub closing: bool,
    held: Vec<HeldReception<'a>>,
}

impl Due<'_> {
    /// Its receptions held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Its one message's bytes (every reception of a set is of one), `None` when it holds none.
    pub fn message(&self) -> Option<&[u8]> {
        self.held
            .first()
            .map(|(_, slice, _, entry)| slice.messages[entry.message as usize].key.bytes())
    }

    /// Keeps only the receptions of receivers `keep` takes.
    pub fn retain_receivers(&mut self, keep: impl Fn(&PublicKey) -> bool) {
        self.held.retain(|(_, _, batch, _)| keep(&batch.receiver));
    }

    /// Its receivers, ascending, each once.
    pub fn receivers(&self) -> impl Iterator<Item = &PublicKey> + '_ {
        let mut last: Option<&PublicKey> = None;
        self.held.iter().filter_map(move |(_, _, batch, _)| {
            let receiver = &batch.receiver;
            (last != Some(receiver)).then(|| {
                last = Some(receiver);
                receiver
            })
        })
    }

    /// Its earliest reception's wall clock.
    pub fn earliest_wall_ms(&self) -> Option<u64> {
        self.held.iter().map(held_wall).min()
    }

    /// Its receptions made, with when each arrived: `None` when it holds none.
    pub fn considered(self) -> Option<Considered> {
        if self.held.is_empty() {
            return None;
        }
        let (receptions, arrived_ms) = self
            .held
            .iter()
            .map(|(slice_at, slice, batch, entry)| {
                (slice.reception(*slice_at, batch, entry), batch.arrived_ms)
            })
            .unzip();
        Some(Considered {
            key: self.key,
            first_arrival_ms: self.first_arrival_ms,
            closing: self.closing,
            receptions,
            arrived_ms,
        })
    }
}

/// What a holder refuses beyond (module docs, Bounded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Bytes held at once, every receiver's together: the pool.
    pub bytes: usize,
    /// Receptions one receiver may hold in one slice.
    pub per_receiver_slice: usize,
    /// How long raw is held: [`HELD_MS`], or longer for a holder fitting over a longer trailing
    /// window than the specification's (the trailing window sweep).
    pub held_ms: u64,
}

impl Limits {
    pub const UNBOUNDED: Self = Self {
        bytes: usize::MAX,
        per_receiver_slice: usize::MAX,
        held_ms: HELD_MS,
    };

    /// Bounded by bytes alone.
    pub fn bytes(bytes: usize) -> Self {
        Self {
            bytes,
            per_receiver_slice: usize::MAX,
            held_ms: HELD_MS,
        }
    }

    /// What a holder of `receivers` receivers at `rates` is bounded by: a pool of every receiver's
    /// share at the mean (`Rates::cost`), and each receiver's own ceiling a slice.
    pub fn for_receivers(receivers: usize, rates: Rates) -> Self {
        Self {
            bytes: receivers.saturating_mul(rates.cost()),
            per_receiver_slice: rates.per_slice_ceiling(),
            held_ms: HELD_MS,
        }
    }
}

/// The rates a receiver's raw is admitted at, which decide what it costs a holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rates {
    /// Wanted receptions a second (what `wanted` keeps), the mean an admitted receiver sends.
    pub wanted_per_s: usize,
    /// Of them, what a holder keeps (module docs, What is held), on average: what the pool is
    /// planned at, since one pool serves every receiver and they are not all at their ceiling at
    /// once.
    pub kept_per_s: usize,
    /// The most wanted receptions a second one receiver may send: beyond a slice's share, its
    /// batch is refused whole. `MEASURED`'s is also the one ceiling a relay paces every feeder's
    /// receptions at, wanted or not (`tally_relay::ingest::FEEDER_RECEPTIONS_PER_SEC`): one
    /// constant, so a feeder the relay lets in at its pace is never refused here for its rate.
    pub ceiling_per_s: usize,
}

const _: () = assert!(Rates::MEASURED.kept_per_s <= KEPT_CEILING_PER_S);
const _: () = assert!(REPLIES_PER_BATCH == KEPT_CEILING_PER_S);

/// Bytes a kept reception costs, at most, its share of its slice's messages and their index, and
/// a reply's place in its transmission for `JOIN_MS`, included: measured over the simulator
/// (`tests::the_pool_is_sized_on_what_a_reception_costs`, about 55), and a reply's tag in its
/// set's tags (`Pending::tags`) beside it at the most a table holds an entry in, just after it
/// doubled: two buckets of the tag and its control byte over seven eighths, 12 bytes. Before the
/// tags, 56; with them and 56, the world relay's load passed its `Arrived` store
/// (`arrived_over`, 2026-10-26).
pub const BYTES_PER_KEPT: usize = 68;
/// Bytes a receiver costs a holder in each slice it sends raw in, beyond its receptions: its
/// batch's place in the slice and in its frontier.
pub const BYTES_PER_RECEIVER_SLICE: usize = size_of::<SliceBatch>() + size_of::<Held>();
/// Bytes a receiver costs a holder beyond its slices: its frontier, and its share of the map.
pub const BYTES_PER_RECEIVER: usize = 2 * (size_of::<Feed>() + size_of::<PublicKey>()) + 64;

impl Rates {
    /// A real receiver (RFC-0181, box-01): about 600 receptions a second, of which about 60%
    /// survive `wanted`, and of those what a holder keeps of each at most, `KEPT_CEILING_PER_S`:
    /// measured by `tally-load` (2,000 feeders sending that mix at the world benchmark's density,
    /// the world relay's 16 cores, 2026-10-26), the pool held 1.34 to 1.40 MB a seat over its
    /// trailing window with nothing refused, about 300 kept a seat a second, every seat at the
    /// ceiling, and a relay's plan cannot know its feeders' density, as its cores' cannot
    /// (`tally_relay::cores`). The wanted ceiling is five times the mean. Before, 150 kept, what a
    /// holder kept in the simulated world benchmark: the pool of the world relay's seats refused
    /// 68% of its batches, and nine in ten of its clock fits failed for want of the raw.
    pub const MEASURED: Self = Self {
        wanted_per_s: 360,
        kept_per_s: KEPT_CEILING_PER_S,
        ceiling_per_s: 1_800,
    };

    /// Receptions a receiver may hold in one slice.
    pub fn per_slice_ceiling(&self) -> usize {
        self.ceiling_per_s.saturating_mul(SLICE_MS as usize) / 1_000
    }

    /// What one receiver at these rates costs a holder's pool: its kept receptions over what is
    /// held ([`HELD_MS`]) at the mean, a batch in every slice of it, and its frontier.
    pub fn cost(&self) -> usize {
        let held_slices = (HELD_MS / SLICE_MS) as usize + 2;
        (self.kept_per_s as u64 * HELD_MS / 1_000) as usize * BYTES_PER_KEPT
            + held_slices * BYTES_PER_RECEIVER_SLICE
            + BYTES_PER_RECEIVER
    }
}

/// What a held message is to MLAT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    /// An airborne position with an altitude of a reference aircraft.
    Sync,
    /// An operational status with a NACp of a reference aircraft.
    Status,
    /// A reply MLAT solves.
    Reply,
}

/// A message, held once a slice.
#[derive(Clone, Copy, Debug)]
struct Message {
    hash: [u8; 32],
    address: u32,
    kind: Kind,
    key: ModeS,
}

/// One held reception: 16 bytes, its receiver and boot its batch's.
#[derive(Clone, Copy, Debug)]
struct Entry {
    message: u32,
    epoch: u32,
    /// The 48-bit counter's low 32 bits.
    counter_low: u32,
    counter_high: u16,
    /// The wall clock's milliseconds into the slice.
    into_ms: u16,
}

impl Entry {
    fn counter(&self) -> u64 {
        (u64::from(self.counter_high) << 32) | u64::from(self.counter_low)
    }
}

/// One batch's receptions in one slice: its entries `first..first + len`, the sync and status ones
/// first (`sync` of them).
#[derive(Clone, Copy, Debug)]
struct SliceBatch {
    receiver: PublicKey,
    first: u32,
    len: u32,
    sync: u32,
    /// Its sync and status entries' digest (`scope::Part::digest`): what a citation cites it by.
    digest: [u8; 32],
    /// The arrival clock it was admitted at.
    arrived_ms: u64,
    /// Its receiver was forgotten: nothing of it is read again.
    forgotten: bool,
}

/// One slice of signed wall clock.
#[derive(Debug, Default)]
struct Slice {
    /// Ascending by `first`.
    batches: Vec<SliceBatch>,
    messages: Vec<Message>,
    index: HashMap<ModeS, u32>,
    entries: Vec<Entry>,
}

impl Slice {
    fn bytes(&self) -> usize {
        vec_bytes::<SliceBatch>(self.batches.capacity())
            + vec_bytes::<Message>(self.messages.capacity())
            + map_bytes(&self.index)
            + vec_bytes::<Entry>(self.entries.capacity())
    }

    /// The batch entry `entry` is of.
    fn batch_of(&self, entry: u32) -> Option<&SliceBatch> {
        let at = self.batches.partition_point(|batch| batch.first <= entry);
        self.batches
            .get(at.checked_sub(1)?)
            .filter(|batch| entry < batch.first + batch.len)
    }

    fn reception(&self, slice: u64, batch: &SliceBatch, entry: &Entry) -> Reception {
        Reception {
            receiver: batch.receiver,
            epoch: entry.epoch,
            timestamp: entry.counter(),
            message: self.messages[entry.message as usize].key,
            wall_ms: slice * SLICE_MS + u64::from(entry.into_ms),
        }
    }

    fn id(&self, batch: &SliceBatch, entry: &Entry) -> ObservationId {
        ObservationId {
            receiver: batch.receiver,
            epoch: entry.epoch,
            timestamp: entry.counter(),
            message: self.messages[entry.message as usize].hash,
        }
    }
}

/// One of a receiver's batches in one slice, as its frontier holds it.
#[derive(Clone, Copy, Debug)]
struct Held {
    slice: u64,
    /// Its place in the slice's batches.
    at: u32,
    sequence: u64,
}

/// A run of a feed's batches with no gap: its first and last sequence, and its first's signed
/// wall clock (what came before it is no later).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Run {
    first: u64,
    last: u64,
    first_wall_ms: u64,
}

/// One receiver's frontier and its batches of its newest boot.
#[derive(Debug)]
struct Feed {
    boot_id: u64,
    /// The newest signed wall clock of any of its batches: which boot is newest.
    newest_wall_ms: u64,
    /// The batches of the boot taken, as runs with no gap, ascending: the first is the frontier's
    /// (module docs, Frontiers). Never empty.
    runs: Vec<Run>,
    /// Its held batches of the boot, ascending by slice.
    batches: VecDeque<Held>,
}

impl Feed {
    fn new(batch: &BatchId, wall_ms: u64) -> Self {
        Self {
            boot_id: batch.boot_id,
            newest_wall_ms: wall_ms,
            runs: vec![Run {
                first: batch.sequence,
                last: batch.sequence,
                first_wall_ms: wall_ms,
            }],
            batches: VecDeque::new(),
        }
    }

    fn bytes(&self) -> usize {
        vec_bytes::<Run>(self.runs.capacity()) + vec_bytes::<Held>(self.batches.capacity())
    }

    /// The last batch of the first run: the frontier.
    fn through(&self) -> u64 {
        self.runs.first().map_or(0, |run| run.last)
    }

    /// Whether `sequence` of the boot was taken already.
    fn holds(&self, sequence: u64) -> bool {
        let at = self.runs.partition_point(|run| run.last < sequence);
        self.runs.get(at).is_some_and(|run| run.first <= sequence)
    }

    /// `sequence`, signed at `wall_ms`, taken (or passed): a run of its own, joined to its
    /// neighbours where they meet.
    fn taken(&mut self, sequence: u64, wall_ms: u64) {
        self.newest_wall_ms = self.newest_wall_ms.max(wall_ms);
        if self.holds(sequence) {
            return;
        }
        let at = self.runs.partition_point(|run| run.last < sequence);
        self.runs.insert(
            at,
            Run {
                first: sequence,
                last: sequence,
                first_wall_ms: wall_ms,
            },
        );
        if self
            .runs
            .get(at + 1)
            .is_some_and(|next| next.first == sequence + 1)
        {
            self.runs[at].last = self.runs[at + 1].last;
            self.runs.remove(at + 1);
        }
        if at > 0 && self.runs[at - 1].last + 1 == sequence {
            self.runs[at - 1].last = self.runs[at].last;
            self.runs.remove(at);
        }
    }

    /// Whether nothing of the boot below the first run can be in `trailing`'s inputs: the run
    /// starts the boot, or its first batch is older than what the inputs read
    /// (`Trailing::read_from_ms`; what came before it is no later). The
    /// one rule both the inputs and their rebuild cite a member by, so a holder whose first batch
    /// arrived inside the window (before the receiver was described, after it was forgotten,
    /// after the holder restarted) never cites what a holder of earlier batches would read more
    /// of.
    fn whole_over(&self, trailing: &Trailing) -> bool {
        self.runs
            .first()
            .is_some_and(|first| first.first == 0 || first.first_wall_ms < trailing.read_from_ms())
    }

    /// Passes every gap above the first run whose batch just above is older than anything held
    /// (module docs, Frontiers): nothing the gap held could be in any window.
    fn pass_gaps(&mut self, now_ms: u64, held_ms: u64) {
        while self.runs.len() >= 2 && self.runs[1].first_wall_ms.saturating_add(held_ms) < now_ms {
            self.runs[0].last = self.runs[1].last;
            self.runs.remove(1);
        }
    }

    /// The batches at or below `through` a holder of this feed lacks, for a model citing `through`
    /// over `trailing` (at most `MISSING_NAMED`): those of the gaps up to it, and the one before
    /// this holder's first when that first is inside the window (what came before it may be too).
    fn missing(&self, receiver: PublicKey, through: u64, trailing: &Trailing) -> Vec<BatchId> {
        let batch = |sequence| BatchId {
            receiver,
            boot_id: self.boot_id,
            sequence,
        };
        let Some(first) = self.runs.first() else {
            return vec![batch(through)];
        };
        if through < first.first {
            return vec![batch(through)];
        }
        let mut missing = Vec::new();
        if !self.whole_over(trailing) {
            missing.push(batch(first.first.saturating_sub(1)));
        }
        for pair in self.runs.windows(2) {
            let mut sequence = pair[0].last + 1;
            while sequence < pair[1].first && sequence <= through && missing.len() < MISSING_NAMED {
                missing.push(batch(sequence));
                sequence += 1;
            }
        }
        let mut sequence = self.runs.last().map_or(through, |run| run.last) + 1;
        while sequence <= through && missing.len() < MISSING_NAMED {
            missing.push(batch(sequence));
            sequence += 1;
        }
        missing
    }
}

/// A due set held while receptions may still join it (`JOIN_MS`): its receptions arrived so far,
/// by their place in their slices.
#[derive(Debug)]
struct Pending {
    key: TransmissionKey,
    first_arrival_ms: u64,
    /// Its receptions when it was last due, and when it was first due; none before it was.
    yielded: usize,
    first_yielded: usize,
    receptions: Vec<Joined>,
    /// The tags of its receptions ([`Joined::tag`]): what a reception joining is looked up in.
    tags: HashSet<u32>,
}

impl Pending {
    fn bytes(&self) -> usize {
        vec_bytes::<Joined>(self.receptions.capacity()) + set_bytes(&self.tags)
    }
}

/// A reception of a due set: its place in its slice, and a tag of its identity
/// ([`identity_tag`]) in what was the place's padding, so a reception joining the set is told
/// from a copy of one it holds by its tag, found in the set's tags (`Pending::tags`), and only a
/// tag held already looks the identity up. Before, every reception joining looked up every one
/// the set held, so a transmission heard by `n` receivers cost `n²` slice lookups, and taking a
/// second's raw passed the second at 400 receivers; and then every reception joining compared
/// every tag the set held, still `n²`: a set is every identical message within `JOIN_MS`, a
/// Mode S reply repeated by the aircraft each second as well as heard by many, about 900
/// receptions as one joined at 2,000 feeders, and that scan was a third of the host's serial
/// taking (2026-10-26).
#[derive(Clone, Copy, Debug)]
struct Joined {
    slice_at: u64,
    entry: u32,
    tag: u32,
}

const _: () = assert!(size_of::<Joined>() == size_of::<(u64, u32)>());

/// A reception's identity in a due set, folded to 32 bits: every reception of a set is of one
/// message, so its receiver, epoch and counter are its identity there. Equal identities have
/// equal tags; equal tags are compared whole.
fn identity_tag(receiver: &PublicKey, epoch: u32, counter: u64) -> u32 {
    let bytes = receiver.as_bytes();
    let key = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    key ^ epoch.rotate_left(16) ^ (counter as u32) ^ ((counter >> 32) as u32)
}

/// The raw a holder has received (module docs).
#[derive(Debug)]
pub struct Arrived {
    limits: Limits,
    slices: BTreeMap<u64, Slice>,
    feeds: HashMap<PublicKey, Feed>,
    /// The transmissions held, in order of first arrival; `first_pending` numbers the front.
    pending: VecDeque<Pending>,
    first_pending: u64,
    /// The newest due set held of each message, by its hash.
    open: HashMap<[u8; 32], u64>,
    /// The transmissions the last seal let go of and found due, by number, ascending.
    closed: Vec<(u64, Pending)>,
    /// What the last seal found due, by number, ascending.
    due: Vec<u64>,
    /// Bytes the slices, feeds and transmissions allocate themselves (beside the maps and lists
    /// holding them).
    held: usize,
    /// Receptions held.
    len: usize,
}

/// One batch's receptions as the pool would hold them ([`classify`]): which are kept, each with
/// its message's hash, and how many were thinned. A function of the receptions alone, never of
/// what a pool holds, so a host classifies a step's batches on many threads and admits them on
/// one ([`Arrived::admit_classified`]) to the same pool, byte for byte, as admitting each in line.
/// It borrows the receptions it classified, so it is admitted with them and no others.
#[derive(Debug)]
pub struct Classified<'a> {
    receptions: &'a [Reception],
    taken: Vec<Taken<'a>>,
    thinned: u32,
}

impl<'a> Classified<'a> {
    /// The receptions classified.
    pub fn receptions(&self) -> &'a [Reception] {
        self.receptions
    }
}

/// One reception of a batch being admitted, classified.
#[derive(Debug)]
struct Taken<'a> {
    reception: &'a Reception,
    key: ModeS,
    hash: [u8; 32],
    address: u32,
    kind: Kind,
}

/// What of `receptions` is held (module docs, What is held), sync and status first, each in
/// the order given; the rest counted as thinned. Every message's hash is made here, on whichever
/// thread classifies, never looked up in a pool.
pub fn classify(receptions: &[Reception]) -> Classified<'_> {
    let adsb: BTreeSet<u32> = receptions
        .iter()
        .filter(|r| modes::airborne_position(&r.message).is_some())
        .filter_map(|r| modes::address(&r.message))
        .collect();
    let mut sync: Vec<Taken<'_>> = Vec::new();
    let mut replies: Vec<Taken<'_>> = Vec::new();
    let mut thinned = 0usize;
    for reception in receptions {
        let data = &reception.message;
        let address = modes::address(data);
        let kind = match (
            tally_wire::modes::wanted_reception(reception.message.format(), data),
            address,
        ) {
            (true, Some(address)) => match modes::downlink_format(data) {
                Some(17 | 18) => {
                    if !reference(address) {
                        None
                    } else if modes::airborne_position(data)
                        .is_some_and(|position| position.altitude.is_some())
                    {
                        Some(Kind::Sync)
                    } else if modes::nacp(data).is_some() {
                        Some(Kind::Status)
                    } else {
                        None
                    }
                }
                _ if adsb.contains(&address) && !sampled(address, reception.wall_ms) => None,
                _ => Some(Kind::Reply),
            },
            _ => None,
        };
        let (Some(kind), Some(address)) = (kind, address) else {
            thinned += 1;
            continue;
        };
        let key = reception.message;
        let one = Taken {
            reception,
            key,
            hash: message_hash(key.bytes()),
            address,
            kind,
        };
        if kind == Kind::Reply {
            replies.push(one);
        } else {
            sync.push(one);
        }
    }
    let events = sync.iter().filter(|one| one.kind == Kind::Sync).count();
    let keep = batch_sync_keep(events);
    let before = sync.len();
    sync.retain(|one| one.kind == Kind::Status || keep.keeps(&sync_key_of(&one.hash)));
    thinned += before - sync.len();
    if replies.len() > REPLIES_PER_BATCH {
        let before = replies.len();
        replies.retain(|one| KEPT_KEEP.keeps(&reply_key(&one.hash)));
        thinned += before - replies.len();
    }
    sync.extend(replies);
    Classified {
        receptions,
        taken: sync,
        thinned: u32::try_from(thinned).unwrap_or(u32::MAX),
    }
}

impl Arrived {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            slices: BTreeMap::new(),
            feeds: HashMap::new(),
            pending: VecDeque::new(),
            first_pending: 0,
            open: HashMap::new(),
            closed: Vec::new(),
            due: Vec::new(),
            held: 0,
            len: 0,
        }
    }

    /// Every reception of `receptions` admitted, unbounded, each receiver's as its batches (one per
    /// signed wall clock, in order, sequences from zero, boot `sim::BOOT_ID`) arriving at their
    /// own signed time: what a test, or a whole simulator's run, holds.
    pub fn holding(receptions: &[Reception]) -> Self {
        let mut batches: BTreeMap<(PublicKey, u64), Vec<Reception>> = BTreeMap::new();
        for reception in receptions {
            batches
                .entry((reception.receiver, reception.wall_ms))
                .or_default()
                .push(reception.clone());
        }
        let mut sequences: BTreeMap<PublicKey, u64> = BTreeMap::new();
        let mut arrivals: Vec<(u64, BatchId, Vec<Reception>)> = batches
            .into_iter()
            .map(|((receiver, wall_ms), receptions)| {
                let sequence = sequences.entry(receiver).or_default();
                let batch = BatchId {
                    receiver,
                    boot_id: crate::sim::BOOT_ID,
                    sequence: *sequence,
                };
                *sequence += 1;
                (wall_ms, batch, receptions)
            })
            .collect();
        arrivals.sort_by_key(|(wall_ms, batch, _)| (*wall_ms, *batch));
        let mut arrived = Self::new(Limits::UNBOUNDED);
        for (wall_ms, batch, receptions) in arrivals {
            arrived.admit(batch, wall_ms, &receptions);
        }
        arrived
    }

    /// What it refuses beyond.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Receptions held.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Admits one batch's receptions, arrived at `now_ms`, by threshold (module docs, What is
    /// held), within the limits, or refuses it whole.
    pub fn admit(&mut self, batch: BatchId, now_ms: u64, receptions: &[Reception]) -> Admitted {
        self.admit_classified(batch, now_ms, &classify(receptions))
    }

    /// Admits one batch's receptions, classified apart ([`classify`]): what [`Arrived::admit`]
    /// does with them.
    pub fn admit_classified(
        &mut self,
        batch: BatchId,
        now_ms: u64,
        classified: &Classified<'_>,
    ) -> Admitted {
        let receptions = classified.receptions;
        let mut admitted = Admitted::default();
        let newest = receptions.iter().map(|r| r.wall_ms).max().unwrap_or(0);
        let oldest = receptions.iter().map(|r| r.wall_ms).min().unwrap_or(0);
        // A batch of an older boot than the receiver's newest is held for the transmissions it
        // joins, but no frontier names it; a newer boot starts the receiver's frontier afresh.
        let current = match self.feeds.get(&batch.receiver) {
            Some(feed) if feed.boot_id == batch.boot_id => {
                if feed.holds(batch.sequence) {
                    // A copy of a batch already taken.
                    return admitted;
                }
                true
            }
            Some(feed) => newest >= feed.newest_wall_ms,
            None => true,
        };
        if newest > now_ms.saturating_add(AHEAD_MS) {
            admitted.refused = Some(Refused::Ahead { wall_ms: newest });
            return admitted;
        }
        if newest.saturating_add(self.limits.held_ms) < now_ms {
            admitted.refused = Some(Refused::Late { wall_ms: newest });
            // Passed in its frontier, unless it is below the frontier's run (it would start a run
            // below every batch held).
            let below = self.feeds.get(&batch.receiver).is_some_and(|feed| {
                feed.boot_id == batch.boot_id
                    && feed
                        .runs
                        .first()
                        .is_some_and(|run| batch.sequence < run.first)
            });
            if current && !below {
                self.take(&batch, newest);
            }
            return admitted;
        }
        let taken = &classified.taken;
        admitted.thinned = classified.thinned;
        // The per-receiver cap a slice, on what this batch adds to each slice it reaches.
        let mut per_slice: BTreeMap<u64, usize> = BTreeMap::new();
        for one in taken {
            *per_slice
                .entry(one.reception.wall_ms / SLICE_MS)
                .or_default() += 1;
        }
        for (slice, adds) in &per_slice {
            let already = self.held_in(&batch, *slice);
            if already + adds > self.limits.per_receiver_slice {
                admitted.kept = 0;
                admitted.refused = Some(Refused::OverCap {
                    what: "receptions one receiver holds in a slice",
                    count: already + adds,
                    cap: self.limits.per_receiver_slice,
                });
                return admitted;
            }
        }
        let growth = self.growth(&batch, now_ms, current, taken, &per_slice);
        let bytes = self.bytes();
        if bytes.saturating_add(growth) > self.limits.bytes {
            admitted.refused = Some(Refused::OverCap {
                what: "bytes held",
                count: bytes.saturating_add(growth),
                cap: self.limits.bytes,
            });
            return admitted;
        }
        if current {
            self.take(&batch, newest.max(oldest));
        }
        self.insert(&batch, now_ms, current, taken, &per_slice);
        admitted.kept = u32::try_from(taken.len()).unwrap_or(u32::MAX);
        admitted
    }

    /// Receptions `batch`'s receiver holds in `slice`, of its boot.
    fn held_in(&self, batch: &BatchId, slice: u64) -> usize {
        let (Some(feed), Some(held)) = (self.feeds.get(&batch.receiver), self.slices.get(&slice))
        else {
            return 0;
        };
        feed.batches
            .iter()
            .filter(|one| one.slice == slice)
            .filter_map(|one| held.batches.get(one.at as usize))
            .map(|one| one.len as usize)
            .sum()
    }

    /// What admitting `taken` would allocate, at most, every list and map as it grows when
    /// `insert` reserves for it.
    fn growth(
        &self,
        batch: &BatchId,
        now_ms: u64,
        current: bool,
        taken: &[Taken<'_>],
        per_slice: &BTreeMap<u64, usize>,
    ) -> usize {
        let mut growth = 0;
        let mut new_slices = 0;
        for (slice, adds) in per_slice {
            let mut fresh: BTreeSet<ModeS> = BTreeSet::new();
            for one in taken
                .iter()
                .filter(|one| one.reception.wall_ms / SLICE_MS == *slice)
            {
                if self
                    .slices
                    .get(slice)
                    .is_none_or(|held| !held.index.contains_key(&one.key))
                {
                    fresh.insert(one.key);
                }
            }
            let (batches, messages, index, entries) = match self.slices.get(slice) {
                Some(held) => (
                    (held.batches.len(), held.batches.capacity()),
                    (held.messages.len(), held.messages.capacity()),
                    (held.index.len(), held.index.capacity()),
                    (held.entries.len(), held.entries.capacity()),
                ),
                None => {
                    new_slices += 1;
                    ((0, 0), (0, 0), (0, 0), (0, 0))
                }
            };
            growth += vec_growth::<SliceBatch>(batches, 1)
                + vec_growth::<Message>(messages, fresh.len())
                + map_growth::<ModeS, u32>(index, fresh.len())
                + vec_growth::<Entry>(entries, *adds);
        }
        growth += tally_wire::footprint::btree::<u64, Slice>(self.slices.len() + new_slices)
            .saturating_sub(tally_wire::footprint::btree::<u64, Slice>(
                self.slices.len(),
            ));
        // The due sets the replies start or join.
        let mut joins: BTreeMap<u64, usize> = BTreeMap::new();
        let mut starts: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for one in taken.iter().filter(|one| one.kind == Kind::Reply) {
            match self.joins(&one.hash, now_ms) {
                Some(number) => *joins.entry(number).or_default() += 1,
                None => *starts.entry(one.hash).or_default() += 1,
            }
        }
        for (number, more) in &joins {
            if let Some(pending) = self.pending_at(*number) {
                growth +=
                    vec_growth::<Joined>(
                        (pending.receptions.len(), pending.receptions.capacity()),
                        *more,
                    ) + map_growth::<u32, ()>((pending.tags.len(), pending.tags.capacity()), *more);
            }
        }
        let new_messages = starts
            .keys()
            .filter(|hash| !self.open.contains_key(*hash))
            .count();
        let started: usize = starts.values().sum();
        let started_tags: usize = starts
            .values()
            .map(|count| table_bytes::<u32, ()>(buckets_for(*count)))
            .sum();
        let starts = starts.len();
        growth += vec_growth::<Pending>((self.pending.len(), self.pending.capacity()), starts)
            + map_growth::<[u8; 32], u64>((self.open.len(), self.open.capacity()), new_messages)
            + vec_bytes::<Joined>(started)
            + started_tags;
        // Its frontier.
        if current {
            match self.feeds.get(&batch.receiver) {
                Some(feed) if feed.boot_id == batch.boot_id => {
                    growth += vec_growth::<Held>(
                        (feed.batches.len(), feed.batches.capacity()),
                        per_slice.len(),
                    ) + vec_growth::<Run>((feed.runs.len(), feed.runs.capacity()), 1);
                }
                Some(_) => {
                    growth += vec_bytes::<Held>(per_slice.len().max(4)) + vec_bytes::<Run>(4);
                }
                None => {
                    growth +=
                        map_growth::<PublicKey, Feed>((self.feeds.len(), self.feeds.capacity()), 1)
                            + vec_bytes::<Held>(per_slice.len().max(4))
                            + vec_bytes::<Run>(4);
                }
            }
        }
        growth
    }

    fn pending_at(&self, number: u64) -> Option<&Pending> {
        self.pending
            .get(usize::try_from(number.checked_sub(self.first_pending)?).ok()?)
    }

    /// The due set a reply of `hash` arriving at `now_ms` joins, by number: the newest of its
    /// bytes, if its first reception arrived within `JOIN_MS`.
    fn joins(&self, hash: &[u8; 32], now_ms: u64) -> Option<u64> {
        let number = *self.open.get(hash)?;
        self.pending_at(number)
            .filter(|pending| pending.first_arrival_ms.saturating_add(JOIN_MS) >= now_ms)
            .map(|_| number)
    }

    /// Holds `taken`, each slice's lists reserved first as `growth` reckons.
    fn insert(
        &mut self,
        batch: &BatchId,
        now_ms: u64,
        current: bool,
        taken: &[Taken<'_>],
        per_slice: &BTreeMap<u64, usize>,
    ) {
        let mut places: Vec<Held> = Vec::with_capacity(per_slice.len());
        let mut replies: Vec<(usize, u64, u32)> = Vec::new();
        for (slice, adds) in per_slice {
            let held = self.slices.entry(*slice).or_default();
            let before = held.bytes();
            let fresh = taken
                .iter()
                .filter(|one| one.reception.wall_ms / SLICE_MS == *slice)
                .filter(|one| !held.index.contains_key(&one.key))
                .map(|one| one.key)
                .collect::<BTreeSet<_>>()
                .len();
            reserve(&mut held.batches, 1);
            reserve(&mut held.messages, fresh);
            reserve_map(&mut held.index, fresh);
            reserve(&mut held.entries, *adds);
            let first = u32::try_from(held.entries.len()).unwrap_or(u32::MAX);
            let mut sync = 0u32;
            for (at, one) in taken.iter().enumerate() {
                if one.reception.wall_ms / SLICE_MS != *slice {
                    continue;
                }
                let message = match held.index.get(&one.key) {
                    Some(message) => *message,
                    None => {
                        let message = u32::try_from(held.messages.len()).unwrap_or(u32::MAX);
                        held.messages.push(Message {
                            hash: one.hash,
                            address: one.address,
                            kind: one.kind,
                            key: one.key,
                        });
                        held.index.insert(one.key, message);
                        message
                    }
                };
                let counter = one.reception.timestamp & 0xffff_ffff_ffff;
                let entry = u32::try_from(held.entries.len()).unwrap_or(u32::MAX);
                held.entries.push(Entry {
                    message,
                    epoch: one.reception.epoch,
                    counter_low: counter as u32,
                    counter_high: (counter >> 32) as u16,
                    into_ms: (one.reception.wall_ms % SLICE_MS) as u16,
                });
                if one.kind == Kind::Reply {
                    replies.push((at, *slice, entry));
                } else {
                    sync += 1;
                }
            }
            let at = u32::try_from(held.batches.len()).unwrap_or(u32::MAX);
            let digest = Part::digest(
                held.entries[first as usize..(first + sync) as usize]
                    .iter()
                    .map(|entry| {
                        (
                            entry.epoch,
                            entry.counter(),
                            held.messages[entry.message as usize].hash,
                            entry.into_ms,
                        )
                    }),
            );
            held.batches.push(SliceBatch {
                receiver: batch.receiver,
                first,
                len: u32::try_from(*adds).unwrap_or(u32::MAX),
                sync,
                digest,
                arrived_ms: now_ms,
                forgotten: false,
            });
            self.held += held.bytes() - before;
            places.push(Held {
                slice: *slice,
                at,
                sequence: batch.sequence,
            });
        }
        self.len += taken.len();
        // The due sets the replies start or join.
        let mut started: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for (at, _, _) in &replies {
            let hash = taken[*at].hash;
            if self.joins(&hash, now_ms).is_none() {
                *started.entry(hash).or_default() += 1;
            }
        }
        reserve_deque(&mut self.pending, started.len());
        let new_messages = started
            .keys()
            .filter(|hash| !self.open.contains_key(*hash))
            .count();
        reserve_map(&mut self.open, new_messages);
        for (at, slice, entry) in replies {
            let hash = taken[at].hash;
            let number = match self.joins(&hash, now_ms) {
                Some(number) => number,
                None => {
                    let number = self.first_pending + self.pending.len() as u64;
                    let pending = Pending {
                        key: TransmissionKey {
                            message: hash,
                            slice: now_ms / SLICE_MS,
                        },
                        first_arrival_ms: now_ms,
                        yielded: 0,
                        first_yielded: 0,
                        receptions: Vec::with_capacity(started.get(&hash).copied().unwrap_or(1)),
                        tags: HashSet::with_capacity(started.get(&hash).copied().unwrap_or(1)),
                    };
                    self.held += pending.bytes();
                    self.pending.push_back(pending);
                    self.open.insert(hash, number);
                    number
                }
            };
            let index = usize::try_from(number - self.first_pending).unwrap_or(usize::MAX);
            // A copy of a reply the set already holds (a batch sent twice) is not a reception
            // more: skipping it keeps `yielded` a count of distinct identities, so a copy never
            // makes a set due again. Only a reception whose tag the set holds is looked up.
            let identity = |slice_at: u64, entry: u32| {
                let held = self.slices.get(&slice_at)?;
                let batch = held.batch_of(entry).filter(|batch| !batch.forgotten)?;
                Some(held.id(batch, held.entries.get(entry as usize)?))
            };
            let reception = taken[at].reception;
            let tag = identity_tag(
                &batch.receiver,
                reception.epoch,
                reception.timestamp & 0xffff_ffff_ffff,
            );
            let copy = self.pending.get(index).is_some_and(|pending| {
                pending.tags.contains(&tag) && {
                    let id = identity(slice, entry);
                    id.is_some()
                        && pending
                            .receptions
                            .iter()
                            .filter(|one| one.tag == tag)
                            .any(|one| identity(one.slice_at, one.entry) == id)
                }
            });
            if copy {
                continue;
            }
            if let Some(pending) = self.pending.get_mut(index) {
                let before = pending.bytes();
                reserve(&mut pending.receptions, 1);
                reserve_set(&mut pending.tags, 1);
                pending.receptions.push(Joined {
                    slice_at: slice,
                    entry,
                    tag,
                });
                pending.tags.insert(tag);
                self.held += pending.bytes() - before;
            }
        }
        if let Some(feed) = self.feeds.get_mut(&batch.receiver).filter(|_| current) {
            let before = feed.bytes();
            reserve_deque(&mut feed.batches, places.len());
            for place in places {
                let at = feed.batches.partition_point(|one| one.slice <= place.slice);
                feed.batches.insert(at, place);
            }
            let after = feed.bytes();
            self.held = self.held + after - before;
        }
    }

    /// `batch`, signed at `wall_ms`, taken into its receiver's frontier (or passed): its feed
    /// started afresh when it is the first of a newer boot.
    fn take(&mut self, batch: &BatchId, wall_ms: u64) {
        let fresh = self
            .feeds
            .get(&batch.receiver)
            .is_none_or(|feed| feed.boot_id != batch.boot_id);
        if fresh {
            reserve_map(&mut self.feeds, 1);
            let feed = Feed::new(batch, wall_ms);
            self.held += feed.bytes();
            if let Some(old) = self.feeds.insert(batch.receiver, feed) {
                self.held -= old.bytes();
            }
            return;
        }
        if let Some(feed) = self.feeds.get_mut(&batch.receiver) {
            let before = feed.bytes();
            reserve(&mut feed.runs, 1);
            feed.taken(batch.sequence, wall_ms);
            self.held = self.held + feed.bytes() - before;
        }
    }

    /// Finds the transmissions due at `now_ms` (what [`Arrived::due`] then yields): those settled
    /// and never due yet, those a reception joined since they last were, and those this seal
    /// closes (past `JOIN_MS`) that a reception joined since they were first due, so a solver
    /// that holds a grown transmission back while its raw is still coming (module docs, Due sets)
    /// solves it once more as its set closes at the latest. Lets go of the transmissions past `JOIN_MS` and of raw older
    /// than `Limits::held_ms`, and passes the gaps nothing held could reach.
    pub fn seal(&mut self, now_ms: u64) {
        for (_, pending) in std::mem::take(&mut self.closed) {
            self.held -= pending.bytes();
        }
        self.due.clear();
        for (at, pending) in self.pending.iter_mut().enumerate() {
            let len = pending.receptions.len();
            let due = if pending.yielded == 0 {
                pending.first_arrival_ms.saturating_add(SETTLE_MS) <= now_ms
            } else if pending.first_arrival_ms.saturating_add(JOIN_MS) < now_ms {
                len > pending.first_yielded
            } else {
                len > pending.yielded
            };
            if due {
                if pending.yielded == 0 {
                    pending.first_yielded = len;
                }
                pending.yielded = len;
                self.due.push(self.first_pending + at as u64);
            }
        }
        // Let go of what no reception may join any more, kept for this seal's due.
        while let Some(front) = self.pending.front() {
            if front.first_arrival_ms.saturating_add(JOIN_MS) >= now_ms {
                break;
            }
            let Some(pending) = self.pending.pop_front() else {
                break;
            };
            if self.open.get(&pending.key.message) == Some(&self.first_pending) {
                self.open.remove(&pending.key.message);
            }
            if self.due.binary_search(&self.first_pending).is_ok() {
                self.closed.push((self.first_pending, pending));
            } else {
                self.held -= pending.bytes();
            }
            self.first_pending += 1;
        }
        self.forget_older(now_ms);
    }

    /// Lets go of raw older than `Limits::held_ms` at `now_ms`, and of the frontiers of receivers
    /// quiet as long, as a seal does, touching no due set: what a host that collapses the steps it
    /// fell behind on does at each step it takes and does not step, so taking several seconds at
    /// once holds no more than stepping each would. Before, a host that collapsed ten steps took
    /// ten seconds of raw past the pool's plan before the one step that let any go, refused the
    /// rest of every receiver's batches, and its areas lost their models for a window
    /// (2026-10-26).
    pub fn forget_older(&mut self, now_ms: u64) {
        let held_ms = self.limits.held_ms;
        let oldest = now_ms.saturating_sub(held_ms) / SLICE_MS;
        let kept = self.slices.split_off(&oldest);
        for (_, slice) in std::mem::replace(&mut self.slices, kept) {
            self.held -= slice.bytes();
            self.len -= slice.entries.len();
        }
        let mut quiet = Vec::new();
        for (key, feed) in &mut self.feeds {
            let before = feed.bytes();
            while feed.batches.front().is_some_and(|held| held.slice < oldest) {
                feed.batches.pop_front();
            }
            feed.pass_gaps(now_ms, held_ms);
            self.held = self.held + feed.bytes() - before;
            if feed.batches.is_empty() && feed.newest_wall_ms.saturating_add(held_ms) < now_ms {
                quiet.push(*key);
            }
        }
        for key in quiet {
            if let Some(feed) = self.feeds.remove(&key) {
                self.held -= feed.bytes();
            }
        }
        // A burst's tables let go once they are four times what they hold.
        if self.open.capacity() > 4 * self.open.len().max(8) {
            self.open.shrink_to(self.open.len() * 2);
        }
        if self.feeds.capacity() > 4 * self.feeds.len().max(8) {
            self.feeds.shrink_to(self.feeds.len() * 2);
        }
    }

    /// Forgets `receiver` (it left, or became unusable): its frontier at once, and its raw is
    /// never read again (let go with its slices).
    pub fn forget(&mut self, receiver: PublicKey) {
        if let Some(feed) = self.feeds.remove(&receiver) {
            self.held -= feed.bytes();
        }
        for slice in self.slices.values_mut() {
            for batch in &mut slice.batches {
                if batch.receiver == receiver {
                    batch.forgotten = true;
                }
            }
        }
    }

    /// Each of `ids`' held receptions (its receiver not forgotten; of copies, the earliest
    /// batch's) with the arrival clock its batch was admitted at, found in the slices a reception
    /// of a transmission at `wall_ms` can be signed in ([`AHEAD_MS`] and a slice either side). An
    /// id not held is left out; the rest keep the order of `ids`.
    pub fn held(&self, ids: &[ObservationId], wall_ms: u64) -> Vec<(Reception, u64)> {
        let reach = AHEAD_MS + SLICE_MS;
        let first = wall_ms.saturating_sub(reach) / SLICE_MS;
        let last = wall_ms.saturating_add(reach) / SLICE_MS;
        let receivers: BTreeSet<PublicKey> = ids.iter().map(|id| id.receiver).collect();
        // Of each id, the slice, batch and entry of its earliest admitted copy.
        let mut found: Vec<Option<(u64, u64, usize, u32)>> = vec![None; ids.len()];
        for (number, slice) in self.slices.range(first..=last) {
            // The ids of each of the slice's messages they name.
            let mut named: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
            for (at, message) in slice.messages.iter().enumerate() {
                for (index, id) in ids.iter().enumerate() {
                    if id.message == message.hash {
                        named
                            .entry(u32::try_from(at).unwrap_or(u32::MAX))
                            .or_default()
                            .push(index);
                    }
                }
            }
            if named.is_empty() {
                continue;
            }
            for (at, batch) in slice.batches.iter().enumerate() {
                if batch.forgotten || !receivers.contains(&batch.receiver) {
                    continue;
                }
                for entry in batch.first..batch.first + batch.len {
                    let one = &slice.entries[entry as usize];
                    let Some(indices) = named.get(&one.message) else {
                        continue;
                    };
                    let id = slice.id(batch, one);
                    for index in indices {
                        if ids[*index] != id {
                            continue;
                        }
                        let earlier = found[*index]
                            .is_none_or(|(_, arrived_ms, _, _)| batch.arrived_ms < arrived_ms);
                        if earlier {
                            found[*index] = Some((*number, batch.arrived_ms, at, entry));
                        }
                    }
                }
            }
        }
        found
            .into_iter()
            .flatten()
            .filter_map(|(number, arrived_ms, at, entry)| {
                let slice = self.slices.get(&number)?;
                let batch = slice.batches.get(at)?;
                let reception = slice.reception(number, batch, slice.entries.get(entry as usize)?);
                Some((reception, arrived_ms))
            })
            .collect()
    }

    /// The receiver's contiguous frontier: its newest boot's batches with no gap below.
    pub fn frontier(&self, receiver: PublicKey) -> Option<Frontier> {
        self.feeds.get(&receiver).map(|feed| Frontier {
            receiver,
            boot_id: feed.boot_id,
            through_sequence: feed.through(),
        })
    }

    /// The area's inputs at the trailing edge `edge_ms`, from what has arrived: its members by
    /// their sites alone (`Sites::members`), each cited through its frontier at the edge
    /// (`Arrived::cited`) when nothing of it below its frontier's run can be in the window
    /// (`Feed::whole_over`, the rule `rebuild` judges by). `None` when it has fewer than two
    /// members.
    pub fn area_inputs(&self, area: Region, sites: &Sites, edge_ms: u64) -> Option<Inputs> {
        self.area_inputs_over(area, sites, Trailing::at(edge_ms))
    }

    /// As `area_inputs`, over `trailing`: a window of another span than the specification's, for
    /// measuring one. Raw is held for `Limits::held_ms`, which a longer window needs to be longer.
    pub fn area_inputs_over(
        &self,
        area: Region,
        sites: &Sites,
        trailing: Trailing,
    ) -> Option<Inputs> {
        let scope: Vec<Site> = sites.members(area).to_vec();
        if scope.len() < 2 {
            return None;
        }
        let frontier: Vec<Frontier> = scope
            .iter()
            .filter_map(|site| {
                let feed = self
                    .feeds
                    .get(&site.receiver)
                    .filter(|feed| feed.whole_over(&trailing))?;
                self.cited(site.receiver, feed, &trailing)
            })
            .collect();
        Some(self.collect(area, trailing, scope, frontier))
    }

    /// The frontier a model at `trailing`'s edge cites of `feed`: the newest batch of its
    /// contiguous run holding a reception signed at or before the edge, so what arrived after
    /// the edge's raw (a later batch) is never cited, and two holders of every batch at or before
    /// the edge cite the same, however much more either holds (crate docs, The trailing window).
    /// `None` when no batch of the run holds one.
    fn cited(&self, receiver: PublicKey, feed: &Feed, trailing: &Trailing) -> Option<Frontier> {
        let through = feed.through();
        let last_slice = trailing.edge_ms / SLICE_MS;
        let reaches = |held: &Held| {
            held.slice < last_slice
                || self
                    .slices
                    .get(&held.slice)
                    .and_then(|slice| {
                        let batch = slice.batches.get(held.at as usize)?;
                        let entries = slice
                            .entries
                            .get(batch.first as usize..(batch.first + batch.len) as usize)?;
                        Some(entries.iter().any(|entry| {
                            held.slice * SLICE_MS + u64::from(entry.into_ms) <= trailing.edge_ms
                        }))
                    })
                    .unwrap_or(false)
        };
        let through_sequence = feed
            .batches
            .iter()
            .filter(|held| held.sequence <= through && held.slice <= last_slice)
            .filter(|held| reaches(held))
            .map(|held| held.sequence)
            .max()?;
        Some(Frontier {
            receiver,
            boot_id: feed.boot_id,
            through_sequence,
        })
    }

    /// The inputs `model` cites, rebuilt from what has arrived: `PairModelFailure::Unjudged` when
    /// a batch at or below a cited frontier has not, `PairModelFailure::Frontier` when its
    /// frontiers are not one a member, in order. Whether the rebuilt inputs are the ones it cites
    /// (their citation) is the model verifier's to judge.
    pub fn rebuild(&self, model: &PairModel) -> Result<Inputs, PairModelFailure> {
        let members: BTreeSet<PublicKey> = model.scope.iter().map(|site| site.receiver).collect();
        let ordered = model
            .frontier
            .windows(2)
            .all(|pair| pair[0].receiver < pair[1].receiver);
        if !ordered
            || model
                .frontier
                .iter()
                .any(|frontier| !members.contains(&frontier.receiver))
        {
            return Err(PairModelFailure::Frontier);
        }
        let mut missing = Vec::new();
        for frontier in &model.frontier {
            let cited = BatchId {
                receiver: frontier.receiver,
                boot_id: frontier.boot_id,
                sequence: frontier.through_sequence,
            };
            match self.feeds.get(&frontier.receiver) {
                Some(feed) if feed.boot_id == frontier.boot_id => missing.extend(feed.missing(
                    frontier.receiver,
                    frontier.through_sequence,
                    &model.trailing,
                )),
                _ => missing.push(cited),
            }
        }
        if !missing.is_empty() {
            return Err(PairModelFailure::Unjudged { missing });
        }
        Ok(self.collect(
            model.area,
            model.trailing,
            model.scope.clone(),
            model.frontier.clone(),
        ))
    }

    /// The inputs of `area` over `trailing` from the batches at or below each of `frontier` (each
    /// of a feed held now, of its boot; ascending by receiver, each once, as both callers' are),
    /// crate docs § Thinning: of the members' sync receptions in the window, deduplicated by
    /// identity, each event two or more members heard (a message one member heard twice too: the
    /// pairs' read leaves that clock out of it, crate docs § Sync events); and every member
    /// reception of a status message of a kept event's aircraft.
    fn collect(
        &self,
        area: Region,
        trailing: Trailing,
        scope: Vec<Site>,
        frontier: Vec<Frontier>,
    ) -> Inputs {
        /// A reception gathered: its counter, signed wall clock, epoch, and message by its place
        /// in `messages`. A third of the identity it is sorted by, the rest found through its
        /// message: before (2026-10-27), each carried its whole identity, receiver and message
        /// hash too, and moving them was a third of a refit's gathering.
        #[derive(Clone, Copy)]
        struct Item {
            timestamp: u64,
            wall_ms: u64,
            epoch: u32,
            message: u32,
        }
        let first_slice = trailing.read_from_ms() / SLICE_MS;
        let last_slice = trailing.edge_ms / SLICE_MS;
        let mut parts: Vec<Part> = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        // Each member's run of `items`: its receiver, and where its run ends.
        let mut runs: Vec<(PublicKey, usize)> = Vec::with_capacity(frontier.len());
        // Each distinct message of the window once, where its slice holds it: found through each
        // slice's own table of its messages, and across slices by hash. Held by reference, so
        // reading one is no lookup of its slice: before (2026-10-27), every reception read its
        // message through the slices' map, two lookups each, a fifth of a refit's gathering.
        let mut messages: Vec<&Message> = Vec::new();
        let mut by_hash: HashMap<[u8; 32], u32, ByDigest> = HashMap::default();
        let mut tables: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
        for cited in &frontier {
            crate::gate::checkpoint();
            let Some(feed) = self
                .feeds
                .get(&cited.receiver)
                .filter(|feed| feed.boot_id == cited.boot_id)
            else {
                continue;
            };
            let (first_part, first_item) = (parts.len(), items.len());
            // Room for every sync reception of its batches in the window's slices at once: grown
            // reception by reception, the list was a tenth of a refit's gathering (2026-10-27).
            items.reserve(
                feed.batches
                    .iter()
                    .filter(|held| (first_slice..=last_slice).contains(&held.slice))
                    .filter_map(|held| self.slices.get(&held.slice)?.batches.get(held.at as usize))
                    .map(|batch| batch.sync as usize)
                    .sum(),
            );
            for held in &feed.batches {
                if held.slice < first_slice
                    || held.slice > last_slice
                    || held.sequence > cited.through_sequence
                {
                    continue;
                }
                let Some(slice) = self.slices.get(&held.slice) else {
                    continue;
                };
                let Some(batch) = slice.batches.get(held.at as usize) else {
                    continue;
                };
                if batch.forgotten || batch.sync == 0 {
                    continue;
                }
                parts.push(Part {
                    receiver: cited.receiver,
                    boot_id: cited.boot_id,
                    sequence: held.sequence,
                    slice: held.slice,
                    digest: batch.digest,
                });
                let table = tables
                    .entry(held.slice)
                    .or_insert_with(|| vec![u32::MAX; slice.messages.len()]);
                let entries = slice
                    .entries
                    .get(batch.first as usize..(batch.first + batch.sync) as usize)
                    .unwrap_or_default();
                for one in entries {
                    let wall_ms = held.slice * SLICE_MS + u64::from(one.into_ms);
                    if !trailing.reads(wall_ms) {
                        continue;
                    }
                    let local = one.message as usize;
                    if table[local] == u32::MAX {
                        let next = u32::try_from(messages.len()).unwrap_or(u32::MAX);
                        let found = *by_hash.entry(slice.messages[local].hash).or_insert(next);
                        if found == next {
                            messages.push(&slice.messages[local]);
                        }
                        table[local] = found;
                    }
                    items.push(Item {
                        timestamp: one.counter(),
                        wall_ms,
                        epoch: one.epoch,
                        message: table[local],
                    });
                }
            }
            // A member's parts by sequence, then slice: the same whatever order they arrived in.
            parts[first_part..].sort_unstable_by_key(|part| (part.sequence, part.slice));
            // Its receptions in identity order (the message compared only when the counter is),
            // of copies the earliest wall clock first, each identity once.
            let run = &mut items[first_item..];
            run.sort_unstable_by(|a, b| {
                (a.epoch, a.timestamp)
                    .cmp(&(b.epoch, b.timestamp))
                    .then_with(|| {
                        messages[a.message as usize]
                            .hash
                            .cmp(&messages[b.message as usize].hash)
                    })
                    .then(a.wall_ms.cmp(&b.wall_ms))
            });
            let mut kept = first_item;
            for at in first_item..items.len() {
                let one = items[at];
                if kept > first_item {
                    let last = items[kept - 1];
                    if (last.epoch, last.timestamp, last.message)
                        == (one.epoch, one.timestamp, one.message)
                    {
                        continue;
                    }
                }
                items[kept] = one;
                kept += 1;
            }
            items.truncate(kept);
            runs.push((cited.receiver, items.len()));
        }
        let message = |at: u32| messages[at as usize];
        let each = || {
            runs.iter()
                .scan(0, |start, (receiver, end)| {
                    let run = &items[*start..*end];
                    *start = *end;
                    Some(run.iter().map(move |item| (*receiver, item)))
                })
                .flatten()
        };
        // Events: each message's sync receptions; one two or more members heard is kept, every
        // hearer of it.
        let mut heard = vec![0u32; messages.len()];
        for (_, item) in each() {
            if message(item.message).kind == Kind::Sync {
                heard[item.message as usize] += 1;
            }
        }
        let event = |at: u32| message(at).kind == Kind::Sync && heard[at as usize] >= 2;
        let mut aircraft: Vec<u32> = (0..messages.len() as u32)
            .filter(|at| event(*at))
            .map(|at| message(at).address)
            .collect();
        aircraft.sort_unstable();
        aircraft.dedup();
        // Status: every member reception of a kept event's aircraft's, so a holder of more raw
        // keeps a superset (one lowest-identity reception a message would change with what
        // arrived). In identity order; its messages numbered as they first come.
        let mut numbered = vec![u32::MAX; messages.len()];
        let mut carried: Vec<SyncMessage> = Vec::new();
        let mut sync: Vec<SyncReception> = Vec::new();
        for (receiver, item) in each() {
            let kept = match message(item.message).kind {
                Kind::Sync => event(item.message),
                Kind::Status => aircraft
                    .binary_search(&message(item.message).address)
                    .is_ok(),
                Kind::Reply => false,
            };
            if !kept {
                continue;
            }
            let number = &mut numbered[item.message as usize];
            if *number == u32::MAX {
                *number = u32::try_from(carried.len()).unwrap_or(u32::MAX);
                let one = message(item.message);
                carried.push(SyncMessage {
                    hash: one.hash,
                    data: one.key.bytes().into(),
                });
            }
            sync.push(SyncReception {
                receiver,
                epoch: item.epoch,
                timestamp: item.timestamp,
                wall_ms: item.wall_ms,
                message: *number,
            });
        }
        let citation = Citation::of_parts(&parts, sync.len());
        Inputs {
            area,
            trailing,
            scope,
            frontier,
            sync,
            messages: carried,
            citation,
        }
    }

    /// The transmissions the last seal found due (settled, grown since they last were, or closed
    /// and grown since they first were) whose
    /// first arrival plus `SETTLE_MS` is at or before
    /// `now_ms`, each with the receptions of it that had arrived (and are still held), sorted by
    /// identity, copies once.
    pub fn due(&self, now_ms: u64) -> impl Iterator<Item = Considered> + '_ {
        self.due
            .iter()
            .filter_map(move |number| self.considered(*number, now_ms))
    }

    /// The due sets the last seal found ([`Arrived::due`]), by number: what
    /// [`Arrived::considered`] builds each of, on any thread, in any order.
    pub fn due_numbers(&self) -> &[u64] {
        &self.due
    }

    /// The due set `number` (one of [`Arrived::due_numbers`]) as [`Arrived::due`] yields it at
    /// `now_ms`: `None` when it is not settled by then or holds no reception any more.
    pub fn considered(&self, number: u64, now_ms: u64) -> Option<Considered> {
        self.due_set(number, now_ms)?.considered()
    }

    /// The due set `number` as it is held, its receptions read where they lie ([`Due`]): what a
    /// set is judged by before any reception of it is made, so a set not taken up costs no copy
    /// of its receptions. `None` when it is not settled by `now_ms`.
    pub fn due_set(&self, number: u64, now_ms: u64) -> Option<Due<'_>> {
        let (pending, closing) = self
            .pending_at(number)
            .map(|pending| (pending, false))
            .or_else(|| {
                self.closed
                    .binary_search_by_key(&number, |(at, _)| *at)
                    .ok()
                    .map(|at| (&self.closed[at].1, true))
            })?;
        if pending.first_arrival_ms.saturating_add(SETTLE_MS) > now_ms {
            return None;
        }
        // Each reception held (its receiver not forgotten) by its slice, batch and entry. A
        // transmission's receptions come mostly from one slice or two: the last one looked up is
        // kept, so each reception is no lookup of the slices' tree (2026-10-27).
        let mut held: Vec<HeldReception<'_>> = Vec::with_capacity(pending.receptions.len());
        let mut last: Option<(u64, &Slice)> = None;
        held.extend(pending.receptions.iter().filter_map(
            |&Joined {
                 slice_at, entry, ..
             }| {
                let slice = match last {
                    Some((at, slice)) if at == slice_at => slice,
                    _ => {
                        let slice = self.slices.get(&slice_at)?;
                        last = Some((slice_at, slice));
                        slice
                    }
                };
                let batch = slice.batch_of(entry).filter(|batch| !batch.forgotten)?;
                Some((slice_at, slice, batch, slice.entries.get(entry as usize)?))
            },
        ));
        // In identity order, of copies the earliest wall clock (then the first joined), each
        // identity once. Every reception of a set is of its one message, so its identity is its
        // receiver, epoch and counter: sorted by those.
        held.sort_by(|a, b| {
            (&a.2.receiver, a.3.epoch, a.3.counter(), held_wall(a)).cmp(&(
                &b.2.receiver,
                b.3.epoch,
                b.3.counter(),
                held_wall(b),
            ))
        });
        held.dedup_by(|later, earlier| {
            (later.2.receiver, later.3.epoch, later.3.counter())
                == (earlier.2.receiver, earlier.3.epoch, earlier.3.counter())
        });
        Some(Due {
            key: pending.key,
            first_arrival_ms: pending.first_arrival_ms,
            closing,
            held,
        })
    }

    /// What the slices, feeds and transmissions allocate, counted afresh: what `held` keeps as
    /// they change, for a test to hold it to.
    #[cfg(test)]
    fn recounted(&self) -> usize {
        self.slices.values().map(Slice::bytes).sum::<usize>()
            + self.feeds.values().map(Feed::bytes).sum::<usize>()
            + self
                .pending
                .iter()
                .chain(self.closed.iter().map(|(_, pending)| pending))
                .map(Pending::bytes)
                .sum::<usize>()
    }

    /// Bytes held, every byte counted as allocated.
    pub fn bytes(&self) -> usize {
        self.held
            + tally_wire::footprint::btree::<u64, Slice>(self.slices.len())
            + map_bytes(&self.feeds)
            + vec_bytes::<Pending>(self.pending.capacity())
            + map_bytes(&self.open)
            + vec_bytes::<(u64, Pending)>(self.closed.capacity())
            + vec_bytes::<u64>(self.due.capacity())
    }
}

/// What a vector or deque of `capacity` allocates.
const fn vec_bytes<T>(capacity: usize) -> usize {
    tally_wire::footprint::vec::<T>(capacity)
}

/// The capacity `reserve` grows a list of `len` and `capacity` to for `more`: as it is when they
/// fit, else twice it, and at least what they need and four.
fn reserved(len: usize, capacity: usize, more: usize) -> usize {
    if len + more <= capacity {
        capacity
    } else {
        (capacity * 2).max(len + more).max(4)
    }
}

/// What `reserve` of `more` allocates more on a list of `(len, capacity)`.
fn vec_growth<T>((len, capacity): (usize, usize), more: usize) -> usize {
    vec_bytes::<T>(reserved(len, capacity, more)) - vec_bytes::<T>(capacity)
}

/// Makes room in `vec` for `more`, exactly as `reserved` reckons.
fn reserve<T>(vec: &mut Vec<T>, more: usize) {
    let to = reserved(vec.len(), vec.capacity(), more);
    if to > vec.capacity() {
        vec.reserve_exact(to - vec.len());
    }
}

/// As `reserve`, a deque.
fn reserve_deque<T>(deque: &mut VecDeque<T>, more: usize) {
    let to = reserved(deque.len(), deque.capacity(), more);
    if to > deque.capacity() {
        deque.reserve_exact(to - deque.len());
    }
}

/// As `reserve`, a map: its table grown once for all `more`.
fn reserve_map<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>, more: usize) {
    if map.len() + more > map.capacity() {
        map.reserve(more);
    }
}

/// As `reserve_map`, a set.
fn reserve_set<K: Eq + std::hash::Hash>(set: &mut HashSet<K>, more: usize) {
    if set.len() + more > set.capacity() {
        set.reserve(more);
    }
}

/// The buckets hashbrown makes a table of to hold `capacity` entries (its `capacity_to_buckets`).
fn buckets_for(capacity: usize) -> usize {
    if capacity == 0 {
        0
    } else if capacity < 4 {
        4
    } else if capacity < 8 {
        8
    } else {
        (capacity * 8 / 7).next_power_of_two()
    }
}

/// The buckets a map of `capacity` has (the table that capacity is of).
fn buckets_of_capacity(capacity: usize) -> usize {
    if capacity == 0 {
        0
    } else if capacity < 8 {
        (capacity + 1).next_power_of_two()
    } else {
        (capacity * 8 / 7).next_power_of_two()
    }
}

/// Bytes a hash table of `buckets` buckets allocates (hashbrown's layout: each bucket an entry and
/// a control byte, and a group of control bytes more).
fn table_bytes<K, V>(buckets: usize) -> usize {
    if buckets == 0 {
        return 0;
    }
    (buckets * size_of::<(K, V)>()).next_multiple_of(16) + buckets + 16
}

/// Bytes a hash map's table allocates.
fn map_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    table_bytes::<K, V>(buckets_of_capacity(map.capacity()))
}

/// Bytes a hash set's table allocates (a map of no values).
fn set_bytes<K>(set: &HashSet<K>) -> usize {
    table_bytes::<K, ()>(buckets_of_capacity(set.capacity()))
}

/// What `reserve_map` of `more` allocates more on a map of `(len, capacity)`: its new table, when
/// it grows (hashbrown's `reserve`: a table for `len + more`, at least one past its capacity).
fn map_growth<K, V>((len, capacity): (usize, usize), more: usize) -> usize {
    if len + more <= capacity {
        return 0;
    }
    let buckets = buckets_for((len + more).max(capacity + 1));
    table_bytes::<K, V>(buckets).saturating_sub(table_bytes::<K, V>(buckets_of_capacity(capacity)))
}

#[cfg(test)]
#[path = "arrived_tests.rs"]
mod tests;
