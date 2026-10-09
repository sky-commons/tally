//! Keyed exchanges between the ingest stage and the shards that own state (RFC-0181 §3). There
//! are [`SHARDS`] logical shards per exchange, mapped onto threads (shard `s` on thread
//! `s % threads`), each owning its state outright, so nothing on the per-reception path takes a
//! lock. A producer (an ingest worker) sends each thread one [`Slice`] per batch, never one message
//! per reception: the batch, shared, and the index ranges of its receptions whose key falls in that
//! thread's shards. Each thread's queue is bounded ([`QUEUE_SLICES`] per producer): a producer
//! that finds it full waits, which holds its connections' allowances (`ingest::Allowance`), which
//! stops their sockets being read. That is the back-pressure raw meets (RFC-0181 §10).
//!
//! Keys are uniform hashes only, never geography, so a dense area cannot make a hot shard; the two
//! a peer chooses (a receiver's key, an aircraft's address) are keyed under this process's secret
//! (`tally_wire::FingerprintKey::process`), so no peer can choose its shard either:
//!
//! - [`Exchange::Message`]: by a reception's fingerprint. The one deduplication
//!   ([`MessageShard`]): the hub's stream and each area's first-heard.
//! - [`Exchange::Raw`]: by receiver, under a key only this process knows ([`raw_shard`]), so no
//!   feeder can choose its shard. Admission, station counters and each receiver's place, owned by
//!   the ingest worker of the receiver's shard (`ingest::Stages`).
//! - [`Exchange::Address`]: by ICAO address, under the same secret ([`address_shard`]). The
//!   hosted MLAT's provisional state is held in these shards (`mlat_host`,
//!   `tally_mlat::provisional::shard_of`); the world candidates arrive per record, not per
//!   reception, and one sealer owns them whole (`products::Sealer`).
//!
//! What a thread holds is charged to the relay's budget (`budget`): each open epoch's decoded
//! batches to [`Store::Epochs`] (a batch's share by the receptions its slice carries), and its
//! [`DEDUP_GENERATIONS`] generations of fingerprints to [`Store::Dedup`]. A slice comes down its
//! queue with its share of the batch's ingest charge (`ingest::InFlight`), let go only once the
//! epoch holds it (or the slice is let go), so the queues are charged in bytes all the way. An
//! epoch that would pass either store on any thread is refused whole: its slices are let go, and
//! the sealer is told it was refused ([`Frozen::refused`]), so it counts it and makes no product of
//! any part of it (RFC-0181 §10). The charge travels with the epoch's batches to the sealer and is
//! released when the sealer is done with them.
//!
//! A batch's slices on other threads keep its decode alive, so a slice let go is not a decode let
//! go: what a slice let go was charged (its share in the epoch, or its ingest charge) is held by
//! its thread ([`Held`]) for as long as anything else holds the decode, and let go once nothing
//! does. Before, a thread that refused an epoch released its slices' shares at once while another
//! thread's slices of the same batches held them until the epoch closed there: hundreds of
//! kilobytes of decoded batches alive, under a flood, that no store was charged.
//!
//! Whether an epoch is admitted is settled once, for every thread, before any commits it
//! ([`Admission`]): each thread decides its part against what it remembers and holds the
//! fingerprints it would add aside (its generation of that epoch), and only when every thread has
//! posted its part, and none refused, are they kept. An epoch refused anywhere is forgotten by
//! every thread, so a message decided in it is still new in the next, never lost to an epoch that
//! was never published. A thread decides the epoch after one it posted only once that one is
//! settled. The settled epoch goes to the sealer as one word, and waits, held and charged, while
//! the sealer's queue is full: once kept, an epoch is never lost on its way.
//!
//! Every producer sends [`Envelope::Tick`] down every queue as its stamps advance; a thread's
//! watermark ([`Watermark`]) is the least of its producers' ticks, and it closes an epoch once its
//! watermark passes it (`seal::Closer`). Nothing is decided on arrival: an epoch's receptions are
//! decided at its close, in the canonical order (`seal::canonical`: the stamp's milliseconds, then
//! the batch's receiver, boot and sequence, then the index), never by which worker or thread took a
//! batch first, so which copy of a message is kept, and in which area, is the same on any number of
//! threads and whatever the stages' delays. A slice whose epoch has already closed (only a trace
//! can stamp one behind its producer's tick) is late: let go and counted ([`Frozen::late`]), never
//! decided in a later epoch and never costing another epoch anything.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tally_wire::{Decoded, ObsRef, PublicKey, Region};

use crate::budget::{Budget, Charge, Gauge, Store};
use crate::ingest::{InFlight, Pause, Stage, Stamp, TICK_MS};
use crate::seal::{Closer, EPOCH_MS, Epoch};

/// Logical shards per exchange: fixed, so a key's shard never depends on how many threads run.
pub const SHARDS: usize = 256;

/// Slices a thread's queue holds per producer before the producer waits: about a second of one
/// feeder's batches per producer at the RFC's rate, bounded whatever the shard's speed.
pub const QUEUE_SLICES: usize = 1_024;

/// One fingerprint remembered, as the table holds it: the key, what was kept of it, and the table's
/// control byte, at the table's most loaded (seven eighths full).
pub const DEDUP_ENTRY_BYTES: usize = (std::mem::size_of::<(u128, Areas)>() + 1) * 8 / 7;

/// How far apart two copies of one message may be stamped and still be one message: the
/// deduplication's window, at least. The relay's deduplication before the stages held two 2 s
/// generations (a copy was caught 2 to 4 s after the first); the epochs made it one 1 s epoch and
/// the one before, so a copy a feeder's network or a relay's queue held back a second or more was
/// kept again (at 20,000 feeders the stream carried 77,000 receptions a second where 42,000 were
/// messages). A copy stamped up to this after the copy kept is never kept again.
pub const DEDUP_WINDOW_MS: u64 = 2_000;

/// Generations of fingerprints a message shard holds, one an epoch: the epoch being decided and
/// enough before it that two stamps `DEDUP_WINDOW_MS` apart (whose epochs are at most
/// `DEDUP_WINDOW_MS / EPOCH_MS` apart) always meet. A message is remembered from the epoch it was
/// kept in to the end of the epoch `DEDUP_GENERATIONS - 1` after, by stamps alone.
pub const DEDUP_GENERATIONS: usize = (DEDUP_WINDOW_MS / EPOCH_MS) as usize + 1;
const _: () = assert!(DEDUP_GENERATIONS >= 2);

/// Table slots one reception may take at the worst, every reception new: the epoch being decided
/// reserves two for each (a table grows by doubling) beside each older generation's one, which a
/// rotation may leave at up to twice its entries.
pub const DEDUP_SLOTS_PER_RECEPTION: usize = 2 * DEDUP_GENERATIONS;

/// The gauges the message exchange charges.
#[derive(Clone, Debug)]
pub struct Gauges {
    pub epochs: Arc<Gauge>,
    pub dedup: Arc<Gauge>,
}

impl Gauges {
    pub fn of(budget: &Budget) -> Self {
        Self {
            epochs: budget.gauge(Store::Epochs),
            dedup: budget.gauge(Store::Dedup),
        }
    }

    /// Never full: for a test's exchange.
    pub fn unlimited() -> Self {
        Self {
            epochs: Gauge::unlimited(Store::Epochs),
            dedup: Gauge::unlimited(Store::Dedup),
        }
    }
}

/// A shard of one exchange, `0..SHARDS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(pub u16);

/// The exchanges, by what their shards are keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exchange {
    Message,
    Raw,
    Address,
}

/// The shard of a reception's fingerprint: its low bits, uniform whatever the messages (the
/// fingerprint is keyed, `tally_wire::decoded`).
pub fn message_shard(fp: u128) -> ShardId {
    ShardId((fp % SHARDS as u128) as u16)
}

/// The shard of a receiver: a keyed hash of its key (SipHash under the process's secret,
/// `tally_wire::FingerprintKey::process`, in its own domain, `tally_wire::decoded::keyed`). A feeder
/// chooses its key, and could grind one whose plain bytes land on any shard it liked; a raw shard
/// holds per-shard tables (sequence windows, hashes, station counters, each receiver's area), each
/// a `SHARDS`th of the relay's, so a few hundred ground keys in one shard would evict the honest
/// receivers there. Under a key it does not know, a feeder's keys land on shards it cannot
/// predict, so filling any shard's tables takes as many keys as filling the relay's. Fixed for the
/// process, so a receiver's shard (its worker, its admission state) never moves while it runs.
pub fn raw_shard(receiver: &PublicKey) -> ShardId {
    let keyed = tally_wire::FingerprintKey::process()
        .fingerprint(tally_wire::decoded::keyed::RAW_SHARD, receiver.as_bytes());
    ShardId((keyed % SHARDS as u128) as u16)
}

/// The shard of an ICAO address: provisional solving's own (`tally_mlat::provisional::shard_of`),
/// one hash for every state kept by aircraft, keyed under the process's secret so a feeder
/// reporting crafted addresses cannot fill one shard.
pub fn address_shard(address: u32) -> ShardId {
    const { assert!(tally_mlat::provisional::SHARDS == SHARDS) };
    ShardId(tally_mlat::provisional::shard_of(address) as u16)
}

/// The thread of `threads` a shard runs on.
pub fn thread_of(shard: ShardId, threads: usize) -> usize {
    usize::from(shard.0) % threads.max(1)
}

/// One batch's receptions for one thread: the batch, shared, the runs of its observation indices
/// whose key falls in the thread's shards, ascending, and the area the batch's receiver is in for
/// this relay's regional product (`products::Products::area_for`), if any.
#[derive(Clone, Debug)]
pub struct Slice {
    pub decoded: Arc<Decoded>,
    pub ranges: Box<[Range<u32>]>,
    pub area: Option<Region>,
}

impl Slice {
    /// The receptions of the slice, with their indices, in the batch's order.
    pub fn observations(&self) -> impl Iterator<Item = (u32, &ObsRef)> + '_ {
        let all = self.decoded.observations();
        self.ranges.iter().flat_map(move |range| {
            range
                .clone()
                .map(move |index| (index, &all[index as usize]))
        })
    }

    fn epoch(&self) -> Epoch {
        crate::seal::epoch_of_ms(self.decoded.stamp_ms())
    }

    fn receptions(&self) -> usize {
        self.ranges.iter().map(|range| range.len()).sum()
    }

    /// This slice's share of its batch's bytes (`Decoded::footprint`), by the receptions it
    /// carries, rounded up: a batch's slices together are charged the batch once, and never a
    /// byte less (N14 of sweep 5: rounded down, a batch cut in `n` slices was charged up to `n - 1`
    /// bytes below what it holds, which a check by the byte sees).
    pub fn share(&self) -> usize {
        let all = self.decoded.observations().len().max(1);
        (self.decoded.footprint() * self.receptions()).div_ceil(all)
    }
}

/// What travels down a thread's queue.
#[derive(Debug)]
pub enum Envelope {
    /// A slice, and its share of its batch's ingest charge: let go once the epoch holds it.
    Slice(Slice, InFlight),
    /// Everything this producer sends from now on is stamped at or after this.
    Tick(Stamp),
}

/// Splits a batch into one slice per thread its receptions' message shards run on, threads
/// ascending, each slice's ranges ascending.
pub fn split(decoded: &Arc<Decoded>, threads: usize, area: Option<Region>) -> Vec<(usize, Slice)> {
    let mut runs: Vec<Vec<Range<u32>>> = vec![Vec::new(); threads.max(1)];
    for (index, obs) in decoded.observations().iter().enumerate() {
        let index = index as u32;
        let ranges = &mut runs[thread_of(message_shard(obs.fp), threads)];
        match ranges.last_mut() {
            Some(range) if range.end == index => range.end += 1,
            _ => ranges.push(index..index + 1),
        }
    }
    runs.into_iter()
        .enumerate()
        .filter(|(_, ranges)| !ranges.is_empty())
        .map(|(thread, ranges)| {
            (
                thread,
                Slice {
                    decoded: Arc::clone(decoded),
                    ranges: ranges.into_boxed_slice(),
                    area,
                },
            )
        })
        .collect()
}

/// A shard's view of its producers' progress: the newest tick from each, and the least of them,
/// before which nothing more will arrive.
#[derive(Clone, Debug)]
pub struct Watermark {
    ticks: Box<[Option<Stamp>]>,
}

impl Watermark {
    pub fn new(producers: usize) -> Self {
        Self {
            ticks: vec![None; producers.max(1)].into_boxed_slice(),
        }
    }

    /// Producer `producer` ticked at `stamp`; the watermark after it. A tick never goes back.
    pub fn tick(&mut self, producer: usize, stamp: Stamp) -> Stamp {
        if let Some(tick) = self.ticks.get_mut(producer) {
            *tick = Some(tick.map_or(stamp, |tick| tick.max(stamp)));
        }
        self.at()
    }

    /// Whether every producer has ticked.
    pub fn complete(&self) -> bool {
        self.ticks.iter().all(Option::is_some)
    }

    /// The least producer tick: every slice stamped before it has arrived. Zero until every
    /// producer has ticked.
    pub fn at(&self) -> Stamp {
        self.ticks
            .iter()
            .map(|tick| tick.unwrap_or_default())
            .min()
            .unwrap_or_default()
    }
}

/// Hashes a fingerprint by its high half: the fingerprint is already a keyed pseudorandom value
/// (`tally_wire::decoded`), and its low bits choose the shard, so hashing it again buys nothing.
#[derive(Clone, Copy, Default)]
pub struct ByFingerprint;

/// The hasher of [`ByFingerprint`].
#[derive(Default)]
pub struct FingerprintHasher(u64);

impl Hasher for FingerprintHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Only `write_u128` is ever called; anything else is folded in, never ignored.
        for byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
        }
    }

    fn write_u128(&mut self, value: u128) {
        self.0 = (value >> 64) as u64;
    }
}

impl BuildHasher for ByFingerprint {
    type Hasher = FingerprintHasher;

    fn build_hasher(&self) -> FingerprintHasher {
        FingerprintHasher::default()
    }
}

/// What one generation recorded of a message: whether it was kept for the hub's stream, and the
/// areas it was kept for, almost always none or one. The two are separate windows: a message kept
/// in an area does not count as kept for the stream, and the other way round, so a message heard in
/// one area after another keeps its place in the stream's window and not the areas'.
#[derive(Clone, Debug, Default)]
struct Areas {
    stream: bool,
    first: Option<Region>,
    more: Vec<Region>,
}

impl Areas {
    fn holds(&self, area: Region) -> bool {
        self.first == Some(area) || self.more.contains(&area)
    }

    fn add(&mut self, area: Region) {
        if self.holds(area) {
            return;
        }
        if self.first.is_none() {
            self.first = Some(area);
        } else {
            self.more.push(area);
        }
    }
}

type Heard = HashMap<u128, Areas, ByFingerprint>;

/// One message shard: the messages kept in the epoch being decided and the
/// `DEDUP_GENERATIONS - 1` before it, one generation an epoch, rotated as the epochs close (so
/// forgetting costs nothing per message). A message is new to the stream when no generation kept it
/// for the stream, and new to an area when none kept it for that area: each is remembered across
/// `DEDUP_GENERATIONS` epochs, apart, so two copies stamped up to `DEDUP_WINDOW_MS` apart are one.
pub struct MessageShard {
    generations: [Heard; DEDUP_GENERATIONS],
    /// The generation of the epoch being decided.
    current: usize,
}

impl Default for MessageShard {
    fn default() -> Self {
        Self {
            generations: std::array::from_fn(|_| Heard::default()),
            current: 0,
        }
    }
}

/// What a message shard decided of one reception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// First heard by the relay this window: in the hub's deduplicated stream.
    pub stream: bool,
    /// First heard in its area this window: in that area's regional product.
    pub regional: bool,
}

impl MessageShard {
    /// Decides one reception of message `fp` by a receiver in `area`, and remembers it.
    pub fn decide(&mut self, fp: u128, area: Option<Region>) -> Decision {
        let mut stream = true;
        let mut regional = area.is_some();
        for heard in self
            .generations
            .iter()
            .filter_map(|generation| generation.get(&fp))
        {
            stream &= !heard.stream;
            regional &= area.is_some_and(|area| !heard.holds(area));
        }
        if stream || regional {
            let heard = self.generations[self.current].entry(fp).or_default();
            heard.stream |= stream;
            if let Some(area) = area.filter(|_| regional) {
                heard.add(area);
            }
        }
        Decision { stream, regional }
    }

    /// `epochs` epochs begin after the one last decided: each takes the oldest generation's table,
    /// cleared (kept, unless it is much larger than what the others hold, so a burst's table does
    /// not outlive it). `DEDUP_GENERATIONS` or more forget everything.
    pub fn rotate(&mut self, epochs: u64) {
        let steps = usize::try_from(epochs)
            .map_or(DEDUP_GENERATIONS, |epochs| epochs.min(DEDUP_GENERATIONS));
        for _ in 0..steps {
            self.current = (self.current + 1) % DEDUP_GENERATIONS;
            self.generations[self.current].clear();
            // What the others hold: an epoch's worth, as this one will again.
            let held = self
                .generations
                .iter()
                .map(HashMap::len)
                .max()
                .unwrap_or(0)
                .max(64);
            let oldest = &mut self.generations[self.current];
            if oldest.capacity() > 2 * held {
                oldest.shrink_to(held);
            }
        }
    }

    /// Forgets what the epoch being decided kept: it was refused (`Admission`), so nothing of it
    /// was published, and every message in it is new again.
    pub fn forget_current(&mut self) {
        self.generations[self.current].clear();
    }

    /// The table slots every generation holds: what they cost (`DEDUP_ENTRY_BYTES` each).
    pub fn capacity(&self) -> usize {
        self.generations.iter().map(HashMap::capacity).sum()
    }

    /// Fingerprints held.
    pub fn len(&self) -> usize {
        self.generations.iter().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What one message thread hands the sealer: an epoch it closed that held receptions (the
/// batches they came from, and which are new to the stream and to an area, each as (batch,
/// observation) indices, in canonical order), an epoch it refused, or only how far it has closed.
/// A thread sends nothing for an epoch it held nothing of, so a watermark that jumps costs nothing;
/// its epoch parts are numbered (`seq`) so the sealer knows when one was lost
/// (`seal::Coordinator`).
#[derive(Debug, Default)]
pub struct Frozen {
    pub thread: usize,
    /// This thread's count of epoch parts (`epoch` is some) sent before this one: a marker carries
    /// the count sent so far. A gap is a part lost, never a marker.
    pub seq: u64,
    /// The epoch closed, when it held receptions.
    pub epoch: Option<Epoch>,
    /// The epoch was refused whole here (its bytes would have passed the budget): it carries
    /// nothing, and the sealer refuses the epoch.
    pub refused: bool,
    /// Every epoch before this is closed on this thread.
    pub closed_before: Epoch,
    /// Receptions that arrived for an epoch this thread had already closed, since its last word:
    /// let go, never decided (`products::ProductsReport::receptions_late`).
    pub late: u64,
    pub batches: Vec<Arc<Decoded>>,
    pub stream: Vec<(u32, u32)>,
    pub regional: Vec<(Region, u32, u32)>,
    /// What its batches are charged (`Store::Epochs`), released when the sealer lets them go.
    /// Declared after `batches`, so a word dropped lets its decodes go before their charge (Rust
    /// drops a struct's fields in order): never a decode alive past what it is charged. Words held
    /// together (one epoch's parts) are let go together, every part's batches first ([`Parts`]).
    pub charge: Charge,
}

/// One epoch's parts held together, gathered across message threads (`Settling`, and the sealer's
/// `seal::Coordinator`): a batch cut into several threads' slices is in several parts, each charged
/// its slices' share, so letting the parts go one by one (each its batches, then its charge) would
/// leave such a decode alive, charged for less than it holds, between the first part's charge and
/// the last part's batches. Let go, every part's batches go before any part's charge. Before, the
/// flood check sampled twice before it called a short decode a holder, to step over that moment.
#[derive(Debug, Default)]
pub struct Parts(Vec<Frozen>);

impl Parts {
    pub fn push(&mut self, part: Frozen) {
        self.0.push(part);
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Frozen> {
        self.0.iter()
    }

    /// The parts, for a holder that takes each one's batches and charge on together (`settle`,
    /// `seal::merge`), and so lets nothing go between them.
    pub fn into_vec(mut self) -> Vec<Frozen> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Parts {
    fn drop(&mut self) {
        for part in &mut self.0 {
            part.batches.clear();
        }
    }
}

/// What one reception may cost an epoch's word beside its batch's decode, at most: its place in
/// the stream's decisions and in its area's (`Frozen::stream`, `Frozen::regional`), charged with
/// the epoch's batches to `Store::Epochs` while the word waits for the sealer.
pub const DECISION_BYTES_PER_RECEPTION: usize =
    std::mem::size_of::<(u32, u32)>() + std::mem::size_of::<(Region, u32, u32)>();

impl Frozen {
    /// What a word holds beside its batches' decodes: itself, and its lists of batches and of
    /// decisions, at `batches`, `stream` and `regional` entries.
    pub const fn bytes_for(batches: usize, stream: usize, regional: usize) -> usize {
        std::mem::size_of::<Self>()
            + batches * std::mem::size_of::<Arc<Decoded>>()
            + stream * std::mem::size_of::<(u32, u32)>()
            + regional * std::mem::size_of::<(Region, u32, u32)>()
    }

    /// What it holds beside its batches' decodes now, by its lists' capacities.
    pub fn own_bytes(&self) -> usize {
        Self::bytes_for(
            self.batches.capacity(),
            self.stream.capacity(),
            self.regional.capacity(),
        )
    }
}

/// Where closed epochs go: the sealer (`seal::Coordinator`). The word back when it could not take
/// it now (its queue is full): the exchange holds it, charged, and offers it again, in order.
pub type Sink = Arc<dyn Fn(Frozen) -> Result<(), Box<Frozen>> + Send + Sync>;

/// How every message thread settles each epoch once ([`Admission`]), and hands the sealer one word
/// for it: the epochs' parts posted, and each thread's progress.
///
/// What waits for the sealer is charged until the sealer takes it (`Store::Epochs`): an epoch's
/// word its batches and its lists of decisions (each thread's part charged them before it decided
/// any, and the word is merged within what they were charged), a refused epoch's word its own
/// bytes. A refused word with no room is not queued: the sealer reads the gap in the words'
/// numbers as an epoch lost on the way, refuses it and counts it (`seal::Coordinator`), as it does
/// a word its queue had no room for. A word that only says how far a thread has closed replaces
/// that thread's last such word when nothing was queued after it, so a stalled sealer is owed at
/// most one of them per thread beside each epoch's. Before, every word waited uncharged, and a
/// sealer behind for an hour was owed some 3,600 epochs' words and a marker per thread for each.
pub struct Admission {
    threads: usize,
    sink: Sink,
    /// What the words waiting for the sealer are charged to (`Store::Epochs`).
    epochs: Arc<Gauge>,
    ledger: Mutex<Ledger>,
    /// Words waiting for the sealer: a flush takes the ledger only when there are any.
    waiting: AtomicUsize,
    /// Held while words are offered, so they reach the sealer in the order they were settled.
    sending: Mutex<()>,
}

#[derive(Default)]
struct Ledger {
    /// Per thread: every epoch before this it has posted (decided, refused, or held nothing of).
    through: Vec<Option<Epoch>>,
    /// Epochs some thread posted a part of, not yet settled.
    pending: BTreeMap<Epoch, Settling>,
    /// Per thread: the epoch it awaits and whether it was admitted, once settled.
    verdicts: Vec<Option<(Epoch, bool)>>,
    /// Every epoch before this is settled and told the sealer.
    frontier: Option<Epoch>,
    outbox: VecDeque<Frozen>,
    /// Epoch words sent the sealer: they go as thread 0's (`Frozen::seq`).
    parts: u64,
    /// Receptions let go late, not yet told.
    late: u64,
}

#[derive(Default)]
struct Settling {
    parts: Parts,
    refused: bool,
    /// The threads that decided a part of it and keep it only if it is admitted.
    awaiting: Vec<usize>,
}

impl Admission {
    /// Settling for `threads` message threads, words for `sink`, those waiting charged to `epochs`.
    pub fn new(threads: usize, sink: Sink, epochs: Arc<Gauge>) -> Arc<Self> {
        let threads = threads.max(1);
        Arc::new(Self {
            threads,
            sink,
            epochs,
            ledger: Mutex::new(Ledger {
                through: vec![None; threads],
                verdicts: vec![None; threads],
                ..Ledger::default()
            }),
            waiting: AtomicUsize::new(0),
            sending: Mutex::new(()),
        })
    }

    /// Thread `thread` decided its part of `epoch` (`part`), or refused it (`None`).
    fn post(&self, thread: usize, epoch: Epoch, part: Option<Frozen>) {
        if let Ok(mut ledger) = self.ledger.lock() {
            let settling = ledger.pending.entry(epoch).or_default();
            match part {
                Some(part) => {
                    settling.parts.push(part);
                    settling.awaiting.push(thread);
                }
                None => settling.refused = true,
            }
        }
    }

    /// Receptions thread `thread` let go, their epoch closed before they came.
    fn late(&self, receptions: u64) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.late += receptions;
        }
    }

    /// Whether `epoch`, which thread `thread` decided a part of, was admitted, once every thread
    /// has posted it; `None` until then.
    fn verdict(&self, thread: usize, epoch: Epoch) -> Option<bool> {
        let mut ledger = self.ledger.lock().ok()?;
        match ledger.verdicts.get(thread).copied().flatten() {
            Some((settled, admitted)) if settled == epoch => {
                ledger.verdicts[thread] = None;
                Some(admitted)
            }
            _ => None,
        }
    }

    /// Thread `thread` has posted every epoch before `through`: every epoch every thread has
    /// posted is settled, in order, and told the sealer.
    fn progress(&self, thread: usize, through: Epoch) {
        if let Ok(mut ledger) = self.ledger.lock() {
            let ledger = &mut *ledger;
            if let Some(held) = ledger.through.get_mut(thread) {
                *held = Some(held.map_or(through, |held| held.max(through)));
            }
            if let Some(frontier) = ledger
                .through
                .iter()
                .copied()
                .collect::<Option<Vec<Epoch>>>()
                .and_then(|through| through.into_iter().min())
                && ledger.frontier.is_none_or(|before| frontier > before)
            {
                while let Some(entry) = ledger.pending.first_entry() {
                    if *entry.key() >= frontier {
                        break;
                    }
                    let (epoch, settling) = entry.remove_entry();
                    let word = settle(epoch, settling, ledger);
                    ledger.push(word, &self.epochs);
                }
                ledger.frontier = Some(frontier);
                for thread in 0..self.threads {
                    let marker = Frozen {
                        thread,
                        seq: if thread == 0 { ledger.parts } else { 0 },
                        closed_before: frontier,
                        ..Frozen::default()
                    };
                    ledger.push(marker, &self.epochs);
                }
            }
            self.waiting.store(ledger.outbox.len(), Ordering::Release);
        }
        self.flush();
    }

    /// Offers the sealer every word waiting, in order, until it takes no more.
    fn flush(&self) {
        if self.waiting.load(Ordering::Acquire) == 0 {
            return;
        }
        let Ok(_sending) = self.sending.lock() else {
            return;
        };
        loop {
            let Some(word) = self
                .ledger
                .lock()
                .ok()
                .and_then(|mut ledger| ledger.outbox.pop_front())
            else {
                break;
            };
            if let Err(word) = (self.sink)(word) {
                if let Ok(mut ledger) = self.ledger.lock() {
                    ledger.outbox.push_front(*word);
                }
                break;
            }
        }
        if let Ok(ledger) = self.ledger.lock() {
            self.waiting.store(ledger.outbox.len(), Ordering::Release);
        }
    }
}

impl Ledger {
    /// Queues `word` for the sealer, with the late receptions not yet told, charged to `epochs`
    /// while it waits. A marker (no epoch) replaces its thread's marker queued after the last
    /// epoch word, if any: the newer says all the older did. A refused epoch's word is charged its
    /// own bytes, and with no room is not queued: the gap in thread 0's numbers it leaves tells the
    /// sealer an epoch was lost, which it refuses and counts. An admitted epoch's word comes
    /// charged (`settle`).
    fn push(&mut self, mut word: Frozen, epochs: &Arc<Gauge>) {
        let late = std::mem::take(&mut self.late);
        if word.epoch.is_none() {
            let since_last_epoch = self
                .outbox
                .iter_mut()
                .rev()
                .take_while(|queued| queued.epoch.is_none());
            for queued in since_last_epoch {
                if queued.thread == word.thread {
                    queued.seq = queued.seq.max(word.seq);
                    queued.closed_before = queued.closed_before.max(word.closed_before);
                    queued.late += late;
                    return;
                }
            }
        } else if word.refused && word.charge.bytes() == 0 {
            match epochs.try_charge(std::mem::size_of::<Frozen>()) {
                Some(charge) => word.charge = charge,
                None => {
                    // Not queued: what it would have said of late receptions waits for the next.
                    self.late += late;
                    return;
                }
            }
        }
        word.late = late;
        self.outbox.push_back(word);
    }
}

/// `epoch` settled: every thread that decided a part of it told whether it was admitted, and its
/// one word for the sealer, every part as one (thread 0's), or its refusal.
fn settle(epoch: Epoch, settling: Settling, ledger: &mut Ledger) -> Frozen {
    let mut word = Frozen {
        thread: 0,
        seq: ledger.parts,
        epoch: Some(epoch),
        closed_before: epoch + 1,
        ..Frozen::default()
    };
    ledger.parts += 1;
    let mut admitted = !settling.refused;
    // A part's charge the word could not take: let go only once every batch is (`Parts`).
    let mut kept_back = Vec::new();
    let parts = settling.parts.into_vec();
    if admitted {
        // Each list exactly as long as its parts' together: within what the parts were charged
        // for theirs, which the word takes on.
        word.batches
            .reserve_exact(parts.iter().map(|part| part.batches.len()).sum());
        word.stream
            .reserve_exact(parts.iter().map(|part| part.stream.len()).sum());
        word.regional
            .reserve_exact(parts.iter().map(|part| part.regional.len()).sum());
        for mut part in parts {
            let at = word.batches.len() as u32;
            word.stream.extend(
                part.stream
                    .iter()
                    .map(|(batch, index)| (batch + at, *index)),
            );
            word.regional.extend(
                part.regional
                    .iter()
                    .map(|(area, batch, index)| (*area, batch + at, *index)),
            );
            word.batches.append(&mut part.batches);
            // Every part is charged to the one `Store::Epochs`: a charge on another could not be
            // handed on with the word, so the epoch is refused rather than held uncharged.
            if let Err(charge) = word.charge.absorb(std::mem::take(&mut part.charge)) {
                kept_back.push(charge);
                admitted = false;
            }
        }
    } else {
        // Refused: every part's batches go before any part's charge (`Parts`).
        drop(Parts(parts));
    }
    if !admitted {
        word = Frozen {
            refused: true,
            ..word
        };
        word.batches = Vec::new();
        word.stream = Vec::new();
        word.regional = Vec::new();
        word.charge = Charge::none();
    }
    // Every batch let go is gone by now: the charges the word could not take go after them.
    drop(kept_back);
    for thread in settling.awaiting {
        if let Some(verdict) = ledger.verdicts.get_mut(thread) {
            *verdict = Some((epoch, admitted));
        }
    }
    word
}

/// The state one message thread owns: its logical shards, its watermark, its open epochs.
pub struct MessageThread {
    thread: usize,
    threads: usize,
    /// Its shards, `thread`, `thread + threads`, ... at `shard / threads`.
    shards: Vec<MessageShard>,
    watermark: Watermark,
    closer: Closer,
    open: BTreeMap<Epoch, Open>,
    gauges: Gauges,
    /// What the generations' tables are charged (`Store::Dedup`).
    dedup: Charge,
    /// The last epoch decided: its shards' generations are its and the ones before.
    decided: Option<Epoch>,
    /// Every epoch before this is closed by the watermark: no slice of it will be taken.
    closed_to: Option<Epoch>,
    /// The epoch it decided a part of and posted, until it is settled: the next is decided only
    /// after, against what that one kept.
    awaiting: Option<Epoch>,
    admission: Arc<Admission>,
    /// What the slices it let go were charged, while their decodes live on elsewhere.
    held: Held,
}

impl MessageThread {
    pub fn new(
        thread: usize,
        threads: usize,
        producers: usize,
        admission: Arc<Admission>,
        gauges: Gauges,
    ) -> Self {
        let owned = (thread..SHARDS).step_by(threads.max(1)).count();
        Self {
            dedup: gauges.dedup.empty(),
            gauges,
            thread,
            threads: threads.max(1),
            shards: (0..owned).map(|_| MessageShard::default()).collect(),
            watermark: Watermark::new(producers),
            closer: Closer::default(),
            open: BTreeMap::new(),
            decided: None,
            closed_to: None,
            awaiting: None,
            admission,
            held: Held::default(),
        }
    }

    pub fn take(&mut self, producer: usize, envelope: Envelope) {
        self.held.sweep();
        match envelope {
            Envelope::Slice(slice, in_flight) => {
                let epoch = slice.epoch();
                if self.closer.closed(epoch) {
                    // Its epoch is decided and gone: late, let go, counted at the next word.
                    self.admission.late(slice.receptions() as u64);
                    return;
                }
                let gauge = &self.gauges.epochs;
                let open = self.open.entry(epoch).or_insert_with(|| Open {
                    slices: Vec::new(),
                    charge: gauge.empty(),
                    refused: false,
                });
                if open.refused {
                    self.held.let_go(slice, in_flight);
                    return;
                }
                if open.charge.try_grow(slice.share()) {
                    open.charge.cover(&slice.decoded);
                    open.slices.push(slice);
                    // The epoch holds its bytes now: the ingest charge is done.
                    drop(in_flight);
                } else {
                    // Past the budget: the whole epoch is refused, never a part of it.
                    open.refuse(&mut self.held);
                    self.held.let_go(slice, in_flight);
                }
            }
            Envelope::Tick(stamp) => {
                let watermark = self.watermark.tick(producer, stamp);
                // Nothing closes until every producer has ticked once: before that the least
                // tick is no watermark.
                if !self.watermark.complete() {
                    return;
                }
                let oldest = self.open.keys().next().copied();
                let closing = self.closer.advance(watermark, oldest);
                self.closed_to = Some(self.closed_to.map_or(closing.end, |to| to.max(closing.end)));
                self.settle();
            }
        }
    }

    /// Takes up what waits on the other threads: an epoch they have settled since, and the words
    /// the sealer could not take before. Called between envelopes, and when none comes.
    pub fn resume(&mut self) {
        self.held.sweep();
        self.settle();
        self.admission.flush();
    }

    /// Decides every closed epoch it holds, oldest first, each only once the one before it is
    /// settled (`Admission`), and tells the others how far it has posted.
    fn settle(&mut self) {
        let Some(closed_to) = self.closed_to else {
            return;
        };
        loop {
            let through = self
                .open
                .keys()
                .next()
                .copied()
                .map_or(closed_to, |first| first.min(closed_to));
            self.admission.progress(self.thread, through);
            if let Some(epoch) = self.awaiting {
                let Some(admitted) = self.admission.verdict(self.thread, epoch) else {
                    return;
                };
                if !admitted {
                    // Refused on some thread: nothing of it is published, so nothing of it is
                    // remembered.
                    self.shards
                        .iter_mut()
                        .for_each(MessageShard::forget_current);
                    self.dedup
                        .shrink_to(self.held_slots().saturating_mul(DEDUP_ENTRY_BYTES));
                }
                self.awaiting = None;
            }
            let Some(epoch) = self.open.keys().next().copied().filter(|e| *e < closed_to) else {
                return;
            };
            if self.close(epoch) {
                self.awaiting = Some(epoch);
            }
        }
    }

    /// Decides epoch `epoch`'s receptions in canonical order and posts them (`Admission`): true
    /// when it decided a part, to keep only if the epoch is admitted; false when it refused it
    /// here. Every epoch open before it was posted and settled before it (`settle` takes them
    /// oldest first, and a slice for an epoch already closed never opens one), so none is ever
    /// decided after a later one.
    fn close(&mut self, epoch: Epoch) -> bool {
        let Some(open) = self.open.remove(&epoch) else {
            return false;
        };
        // The generations follow the epochs by number, not by which held anything: the
        // `DEDUP_GENERATIONS - 1` epochs before this one are remembered, older ones are not.
        if let Some(last) = self.decided {
            let epochs = epoch.saturating_sub(last);
            self.shards
                .iter_mut()
                .for_each(|shard| shard.rotate(epochs));
        }
        self.decided = Some(epoch);
        // Room for every reception of the epoch to be new, before any is decided: an epoch the
        // fingerprints' budget cannot hold is refused whole, never decided in part.
        let receptions: usize = open.slices.iter().map(Slice::receptions).sum();
        // The charge already covers the tables as they stand (set at the last close; a rotation
        // never grows them).
        // A table grows by doubling, so deciding them may at most double what the tables and the
        // new entries take; the charge is cut to what they hold once decided.
        let needed = (self.held_slots() + receptions)
            .saturating_mul(2)
            .saturating_mul(DEDUP_ENTRY_BYTES);
        let more = needed.saturating_sub(self.dedup.bytes());
        let Open {
            mut slices,
            mut charge,
            refused,
        } = open;
        // And room for its word: its lists of batches and of decisions as long as they can be
        // (every reception kept for the stream and for its area), charged with its batches before
        // any is decided, so what waits for the sealer is charged all the way (`Admission`).
        let batches_bytes = charge.bytes();
        let in_areas: usize = slices
            .iter()
            .filter(|slice| slice.area.is_some())
            .map(Slice::receptions)
            .sum();
        let room = !refused
            && self.dedup.try_grow(more)
            && charge.try_grow(Frozen::bytes_for(slices.len(), receptions, in_areas));
        if !room {
            self.dedup
                .shrink_to(self.held_slots().saturating_mul(DEDUP_ENTRY_BYTES));
            Open {
                slices,
                charge,
                refused,
            }
            .refuse(&mut self.held);
            self.admission.post(self.thread, epoch, None);
            return false;
        }
        slices.sort_by(|a, b| {
            crate::seal::canonical(&a.decoded).cmp(&crate::seal::canonical(&b.decoded))
        });
        let mut frozen = Frozen {
            thread: self.thread,
            epoch: Some(epoch),
            closed_before: epoch + 1,
            batches: Vec::with_capacity(slices.len()),
            stream: Vec::with_capacity(receptions),
            regional: Vec::with_capacity(in_areas),
            ..Frozen::default()
        };
        for (at, slice) in slices.iter().enumerate() {
            let at = at as u32;
            for (index, obs) in slice.observations() {
                let shard = usize::from(message_shard(obs.fp).0) / self.threads;
                let decision = self.shards[shard].decide(obs.fp, slice.area);
                if decision.stream {
                    frozen.stream.push((at, index));
                }
                if decision.regional
                    && let Some(area) = slice.area
                {
                    frozen.regional.push((area, at, index));
                }
            }
        }
        frozen.batches = slices.into_iter().map(|slice| slice.decoded).collect();
        // The lists as decided, and their charge cut to them.
        frozen.stream.shrink_to_fit();
        frozen.regional.shrink_to_fit();
        charge.shrink_to(batches_bytes + frozen.own_bytes());
        frozen.charge = charge;
        // What the tables hold now, no more.
        self.dedup
            .shrink_to(self.held_slots().saturating_mul(DEDUP_ENTRY_BYTES));
        self.admission.post(self.thread, epoch, Some(frozen));
        true
    }

    /// Fingerprints held across its shards.
    pub fn held(&self) -> usize {
        self.shards.iter().map(MessageShard::len).sum()
    }

    /// Table slots its shards' generations hold.
    fn held_slots(&self) -> usize {
        self.shards.iter().map(MessageShard::capacity).sum()
    }
}

/// An epoch open on a message thread: its slices so far and what they are charged, or refused.
struct Open {
    slices: Vec<Slice>,
    charge: Charge,
    refused: bool,
}

impl Open {
    /// Refused whole: its slices are let go now, and what each was charged with them, but for a
    /// slice whose decode something else still holds (another thread's slice of its batch): that
    /// share is held while it does (`held`).
    fn refuse(&mut self, held: &mut Held) {
        self.refused = true;
        for slice in std::mem::take(&mut self.slices) {
            // Its share covers its own decode, not every decode the epoch held: one cover a slice,
            // never a copy of the epoch's (N5).
            let share = self.charge.split_covering(slice.share(), &slice.decoded);
            held.keep(slice, Some(share), None);
        }
        self.charge.shrink_to(0);
        // It holds no decode now: a refused epoch stays open, holding nothing, until it closes.
        self.charge.uncover();
    }
}

/// What the slices a thread let go were charged, each kept while anything else still holds its
/// decode (another thread's slice of its batch, another stage) and let go once nothing does
/// (`sweep`, between envelopes), so a decode alive is never charged only part of its footprint.
#[derive(Debug, Default)]
struct Held {
    parts: Vec<HeldPart>,
}

/// A slice's charge kept while anything else holds its decode, by a weak hold: two threads' parts
/// of one decode must not keep each other. A cover whose decode is gone counts for nothing
/// (`budget::Covered::gone`), so what lingers here until the next sweep is never counted.
#[derive(Debug)]
struct HeldPart {
    decoded: std::sync::Weak<Decoded>,
    _share: Option<Charge>,
    _in_flight: Option<InFlight>,
}

impl Held {
    /// `slice` let go, with what it was charged: kept while something else holds its decode,
    /// dropped now otherwise, the slice first: its decode is never alive past its charge, even
    /// for the instant between the two. Taken by value so no caller holds the slice on past it.
    fn keep(&mut self, slice: Slice, share: Option<Charge>, in_flight: Option<InFlight>) {
        if Arc::strong_count(&slice.decoded) > 1 {
            self.parts.push(HeldPart {
                decoded: Arc::downgrade(&slice.decoded),
                _share: share,
                _in_flight: in_flight,
            });
            drop(slice);
        } else {
            drop(slice);
            drop((share, in_flight));
        }
    }

    /// A slice let go (its epoch refused here), with its ingest charge.
    fn let_go(&mut self, slice: Slice, in_flight: InFlight) {
        self.keep(slice, None, Some(in_flight));
    }

    /// Lets go what was kept for a decode nothing holds any more.
    fn sweep(&mut self) {
        if !self.parts.is_empty() {
            self.parts.retain(|part| part.decoded.strong_count() > 0);
        }
    }
}

/// The message exchange: its threads, or for a test one state run by the caller.
pub enum MessageExchange {
    /// Run by whoever sends, under one lock: one producer, every shard.
    Inline(Mutex<MessageThread>),
    Threads {
        senders: Vec<SyncSender<(usize, Envelope)>>,
        handles: Vec<JoinHandle<()>>,
    },
}

impl MessageExchange {
    pub fn inline(sink: Sink, gauges: Gauges) -> Self {
        Self::Inline(Mutex::new(MessageThread::new(
            0,
            1,
            1,
            Admission::new(1, sink, Arc::clone(&gauges.epochs)),
            gauges,
        )))
    }

    /// `threads` threads, fed by `producers` producers, each queue bounded per producer, each
    /// held up by `pause` before every envelope it takes (a test's delay; none in a relay). Every
    /// thread is running or none is: a thread that cannot be started fails the relay at its start
    /// (the others are stopped), since the watermark waits for every thread's word and one missing
    /// would close no epoch ever.
    pub fn threads(
        threads: usize,
        producers: usize,
        sink: &Sink,
        gauges: &Gauges,
        pause: Option<&Pause>,
    ) -> Result<Self, String> {
        let threads = threads.max(1);
        let mut exchange = Self::Threads {
            senders: Vec::with_capacity(threads),
            handles: Vec::with_capacity(threads),
        };
        let admission = Admission::new(threads, Arc::clone(sink), Arc::clone(&gauges.epochs));
        for thread in 0..threads {
            let (sender, receiver) = sync_channel(QUEUE_SLICES * producers.max(1));
            let state = MessageThread::new(
                thread,
                threads,
                producers,
                Arc::clone(&admission),
                gauges.clone(),
            );
            let pause = pause.cloned();
            let handle = std::thread::Builder::new()
                .name(format!("tally-message-{thread}"))
                .spawn(move || run(state, &receiver, pause.as_ref()))
                // Dropping `exchange` stops and joins the threads already started.
                .map_err(|error| format!("message thread {thread} of {threads}: {error}"))?;
            if let Self::Threads { senders, handles } = &mut exchange {
                senders.push(sender);
                handles.push(handle);
            }
        }
        Ok(exchange)
    }

    /// Threads the shards run on.
    pub fn width(&self) -> usize {
        match self {
            Self::Inline(_) => 1,
            Self::Threads { senders, .. } => senders.len().max(1),
        }
    }

    /// Routes a batch's receptions to their shards' threads, waiting while a thread's queue is
    /// full, each slice with its share of the batch's charge (`in_flight`), so the bytes waiting in
    /// the queues are charged until the epochs hold them. What no slice carries is let go here.
    pub fn route(
        &self,
        producer: usize,
        decoded: &Arc<Decoded>,
        area: Option<Region>,
        mut in_flight: InFlight,
    ) {
        let slices = split(decoded, self.width(), area);
        let last = slices.len().saturating_sub(1);
        for (at, (thread, slice)) in slices.into_iter().enumerate() {
            let share = if at == last {
                in_flight.bytes()
            } else {
                slice.share()
            };
            let charge = in_flight.split(share, decoded);
            self.send(producer, thread, Envelope::Slice(slice, charge));
        }
    }

    /// Producer `producer` will send nothing stamped before `stamp`.
    pub fn tick(&self, producer: usize, stamp: Stamp) {
        for thread in 0..self.width() {
            self.send(producer, thread, Envelope::Tick(stamp));
        }
    }

    fn send(&self, producer: usize, thread: usize, envelope: Envelope) {
        match self {
            Self::Inline(state) => {
                if let Ok(mut state) = state.lock() {
                    state.take(0, envelope);
                }
            }
            Self::Threads { senders, .. } => {
                if let Some(sender) = senders.get(thread) {
                    // Blocks while the thread is behind: back-pressure, by design.
                    let _ = sender.send((producer, envelope));
                }
            }
        }
    }
}

impl Drop for MessageExchange {
    fn drop(&mut self) {
        if let Self::Threads { senders, handles } = self {
            senders.clear();
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

fn run(mut state: MessageThread, receiver: &Receiver<(usize, Envelope)>, pause: Option<&Pause>) {
    loop {
        match receiver.recv_timeout(Duration::from_millis(TICK_MS)) {
            Ok((producer, envelope)) => {
                if let Some(pause) = pause {
                    pause(Stage::Message);
                }
                state.take(producer, envelope);
            }
            // Nothing came: what waits on the other threads or the sealer is taken up anyway.
            Err(RecvTimeoutError::Timeout) => state.resume(),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::{Batch, BatchContent, Identity, Observation};

    fn decoded(count: u8, stamp_ms: u64, ingest_seq: u64) -> Result<Arc<Decoded>, String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let content = BatchContent {
            boot_id: 1,
            sequence: 0,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: (0..count)
                .map(|n| Observation {
                    format: b'3',
                    timestamp: u64::from(n),
                    signal: 0,
                    data: vec![n; 14],
                })
                .collect(),
        };
        let batch = Batch::sign(&identity, &content).map_err(|error| error.to_string())?;
        Decoded::from_verified(batch, stamp_ms, ingest_seq)
            .map_err(|undecodable| undecodable.error.to_string())
    }

    #[test]
    fn a_batch_splits_into_each_threads_receptions_once_in_order() -> Result<(), String> {
        let decoded = decoded(200, 0, 0)?;
        let slices = split(&decoded, 7, None);
        let mut seen: Vec<u64> = Vec::new();
        for (thread, slice) in &slices {
            let mut previous = None;
            for (_, obs) in slice.observations() {
                assert_eq!(thread_of(message_shard(obs.fp), 7), *thread);
                assert!(previous.is_none_or(|previous| previous < obs.timestamp));
                previous = Some(obs.timestamp);
                seen.push(obs.timestamp);
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..200).collect::<Vec<u64>>());
        assert!(slices.windows(2).all(|pair| pair[0].0 < pair[1].0));
        Ok(())
    }

    #[test]
    fn the_watermark_is_the_slowest_producers_tick() {
        let at = |stamp_ms| Stamp {
            stamp_ms,
            ingest_seq: 0,
        };
        let mut watermark = Watermark::new(2);
        assert_eq!(watermark.tick(0, at(10)), at(0));
        assert_eq!(watermark.tick(1, at(5)), at(5));
        assert_eq!(watermark.tick(1, at(3)), at(5));
        assert_eq!(watermark.tick(1, at(20)), at(10));
    }

    #[test]
    fn a_message_is_new_once_a_window_and_once_per_area() -> Result<(), String> {
        let area = |lat_e7| {
            Region::containing(
                &tally_wire::Location {
                    lat_e7,
                    lon_e7: -843_880_000,
                    alt_m: 0,
                    precision_m: 0,
                },
                4,
            )
            .map_err(|error| error.to_string())
        };
        let (a, b) = (area(337_490_000)?, area(407_490_000)?);
        let mut shard = MessageShard::default();
        let new = |stream, regional| Decision { stream, regional };
        assert_eq!(shard.decide(7, Some(a)), new(true, true));
        assert_eq!(shard.decide(7, Some(a)), new(false, false));
        assert_eq!(shard.decide(7, Some(b)), new(false, true));
        assert_eq!(shard.decide(7, None), new(false, false));
        // Remembered `DEDUP_GENERATIONS - 1` more epochs, then forgotten.
        for _ in 1..DEDUP_GENERATIONS {
            shard.rotate(1);
            assert_eq!(shard.decide(7, Some(a)), new(false, false));
        }
        shard.rotate(1);
        assert_eq!(shard.decide(7, Some(a)), new(true, true));
        // A gap of the whole window forgets everything at once.
        shard.rotate(DEDUP_GENERATIONS as u64);
        assert!(shard.is_empty());
        Ok(())
    }

    /// The stream's window and the areas' are apart: a message heard in one area after another,
    /// epoch after epoch, is kept for the stream once a window, as one heard in one area is.
    /// Before they were apart, each new area renewed the message in the stream's window too, and a
    /// message heard across areas reached the stream once and never again.
    #[test]
    fn an_area_kept_does_not_renew_the_streams_window() -> Result<(), String> {
        let area = |lat_e7| {
            Region::containing(
                &tally_wire::Location {
                    lat_e7,
                    lon_e7: -843_880_000,
                    alt_m: 0,
                    precision_m: 0,
                },
                4,
            )
            .map_err(|error| error.to_string())
        };
        let areas = [area(337_490_000)?, area(407_490_000)?, area(457_490_000)?];
        let mut shard = MessageShard::default();
        let mut kept = 0;
        for epoch in 0..12usize {
            // Heard every epoch, in an area the last epoch did not hear it in.
            let decision = shard.decide(7, Some(areas[epoch % areas.len()]));
            kept += usize::from(decision.stream);
            shard.rotate(1);
        }
        assert_eq!(kept, 12 / DEDUP_GENERATIONS);
        Ok(())
    }

    /// One batch from a receiver of its own, holding message `n` once.
    fn copy_of(n: u8, stamp_ms: u64) -> Result<Slice, String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let content = BatchContent {
            boot_id: 1,
            sequence: 0,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: vec![Observation {
                format: b'3',
                timestamp: stamp_ms,
                signal: 0,
                data: vec![n; 14],
            }],
        };
        let batch = Batch::sign(&identity, &content).map_err(|error| error.to_string())?;
        let decoded = Decoded::from_verified(batch, stamp_ms, 0)
            .map_err(|undecodable| undecodable.error.to_string())?;
        split(&decoded, 1, None)
            .pop()
            .map(|(_, slice)| slice)
            .ok_or_else(|| "no slice".to_owned())
    }

    /// One message thread whose words are kept, and the words.
    fn thread() -> (MessageThread, Arc<Mutex<Vec<Frozen>>>) {
        let words = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&words);
        let sink: Sink = Arc::new(move |frozen| match kept.lock() {
            Ok(mut kept) => {
                kept.push(frozen);
                Ok(())
            }
            Err(_) => Err(Box::new(frozen)),
        });
        (
            MessageThread::new(
                0,
                1,
                1,
                Admission::new(1, sink, Gauge::unlimited(Store::Epochs)),
                Gauges::unlimited(),
            ),
            words,
        )
    }

    fn tick(stamp_ms: u64) -> Envelope {
        Envelope::Tick(Stamp {
            stamp_ms,
            ingest_seq: 0,
        })
    }

    /// The window is at least `DEDUP_WINDOW_MS`, by stamps: copies of one message stamped up to
    /// two seconds after the copy kept are never kept again, whichever epochs they fall in (at one
    /// epoch and the one before, a copy a second late was kept twice). Past the window it is kept
    /// again.
    #[test]
    fn copies_up_to_two_seconds_apart_are_kept_once() -> Result<(), String> {
        let (mut thread, words) = thread();
        // Message 1 first at 0 ms, again 1.5 s and 2 s later; message 2 at 999 ms and 2,999 ms
        // (two seconds apart, two epochs apart); message 1 once more 3 s after its first copy.
        for (n, stamp_ms) in [
            (1, 0),
            (1, 1_500),
            (2, 999),
            (1, 2_000),
            (2, 2_999),
            (1, 3_000),
        ] {
            thread.take(0, Envelope::Slice(copy_of(n, stamp_ms)?, InFlight::free()));
        }
        thread.take(0, tick(10_000));
        let words = words.lock().map_err(|error| error.to_string())?;
        let mut kept: HashMap<u8, Vec<u64>> = HashMap::new();
        for word in words.iter() {
            for (at, index) in &word.stream {
                let batch = &word.batches[*at as usize];
                let obs = &batch.observations()[*index as usize];
                kept.entry(batch.data(obs)[0])
                    .or_default()
                    .push(batch.stamp_ms());
            }
        }
        assert_eq!(kept.get(&1), Some(&vec![0, 3_000]));
        assert_eq!(kept.get(&2), Some(&vec![999]));
        Ok(())
    }

    /// The word the sealer was told for `epoch`: whether it was refused, and the first byte of
    /// each message it kept for the stream.
    fn word_of(
        words: &Mutex<Vec<Frozen>>,
        epoch: Epoch,
    ) -> Result<Option<(bool, Vec<u8>)>, String> {
        let words = words.lock().map_err(|error| error.to_string())?;
        Ok(words
            .iter()
            .find(|word| word.epoch == Some(epoch))
            .map(|word| {
                let kept = word
                    .stream
                    .iter()
                    .map(|(at, index)| {
                        let batch = &word.batches[*at as usize];
                        batch.data(&batch.observations()[*index as usize])[0]
                    })
                    .collect();
                (word.refused, kept)
            }))
    }

    /// N5: an epoch refused whole hands each slice's share on covering that slice's decode and
    /// no other, and no split along the way copies the epoch's covers: a part split off a charge
    /// covering many decodes covers none of them until it is split with one. Before, every split
    /// cloned every cover of the epoch's charge, a lock a cover, so refusing an epoch of `n`
    /// slices took `n²` of them on the message thread.
    #[test]
    fn a_refused_epochs_shares_each_cover_their_own_decode_and_copy_no_other() -> Result<(), String>
    {
        let covered = crate::budget::Covered::process();
        let decodes = (0..4u64)
            .map(|at| decoded(20, 0, at))
            .collect::<Result<Vec<_>, String>>()?;
        let epochs = Gauge::unlimited(Store::Epochs);
        let mut charge = epochs.empty();
        for decode in &decodes {
            assert!(charge.try_grow(decode.footprint()));
            charge.cover(decode);
        }
        // A plain split moves bytes and copies no cover.
        let part = charge.split(10);
        assert!(decodes.iter().all(|decode| covered.covers_of(decode) == 1));
        // Split with a decode, the part covers that one alone.
        let with_first = charge.split_covering(10, &decodes[0]);
        assert_eq!(covered.covers_of(&decodes[0]), 2);
        assert!(
            decodes[1..]
                .iter()
                .all(|decode| covered.covers_of(decode) == 1)
        );
        drop((part, with_first));
        // Refused whole: each kept share covers its own decode, the epoch's charge none.
        let mut open = Open {
            slices: decodes
                .iter()
                .map(|decode| Slice {
                    decoded: Arc::clone(decode),
                    ranges: std::iter::once(0..20).collect(),
                    area: None,
                })
                .collect(),
            charge,
            refused: false,
        };
        let mut held = Held::default();
        open.refuse(&mut held);
        assert!(open.refused);
        assert_eq!(open.charge.bytes(), 0);
        assert!(decodes.iter().all(|decode| covered.covers_of(decode) == 1));
        assert_eq!(held.parts.len(), decodes.len());
        drop(held);
        assert!(decodes.iter().all(|decode| covered.covers_of(decode) == 0));
        Ok(())
    }

    /// RFC-0181 §10, invariant 7: an epoch refused on one message thread is refused on every
    /// one, and what another thread decided in it is forgotten, never kept: a message decided on
    /// thread 1 in an epoch thread 0 refused is still new in the next epoch, and published there.
    /// Before admission was settled once, thread 1 kept it in the refused epoch and dropped its
    /// copy in the next as a duplicate, so it was in no product at all.
    #[test]
    fn an_epoch_refused_on_one_thread_is_forgotten_on_every_thread() -> Result<(), String> {
        let words = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&words);
        let sink: Sink = Arc::new(move |frozen| match kept.lock() {
            Ok(mut kept) => {
                kept.push(frozen);
                Ok(())
            }
            Err(_) => Err(Box::new(frozen)),
        });
        let admission = Admission::new(2, sink, Gauge::unlimited(Store::Epochs));
        // Thread 0's epochs hold one slice: a second refuses the epoch there.
        let tight = Gauges {
            epochs: Gauge::new(Store::Epochs, 1),
            dedup: Gauge::unlimited(Store::Dedup),
        };
        let mut zero = MessageThread::new(0, 2, 1, Arc::clone(&admission), tight);
        let mut one = MessageThread::new(1, 2, 1, Arc::clone(&admission), Gauges::unlimited());
        one.take(0, Envelope::Slice(copy_of(7, 500)?, InFlight::free()));
        zero.take(0, Envelope::Slice(copy_of(1, 500)?, InFlight::free()));
        zero.take(0, Envelope::Slice(copy_of(2, 600)?, InFlight::free()));
        // Thread 1 closes epoch 0 first, deciding message 7 in it; thread 0 then refuses it.
        one.take(0, tick(1_000));
        one.take(0, Envelope::Slice(copy_of(7, 1_500)?, InFlight::free()));
        zero.take(0, tick(1_000));
        one.take(0, tick(2_000));
        zero.take(0, tick(2_000));
        assert_eq!(word_of(&words, 0)?, Some((true, Vec::new())));
        assert_eq!(word_of(&words, 1)?, Some((false, vec![7])));
        Ok(())
    }

    /// RFC-0181 §9: a batch split across two threads, refused on one, is charged its whole
    /// footprint for as long as the other thread's slice keeps its decode alive, and let go once
    /// nothing does. Before, the refusing thread let its share go at once, and the
    /// decode lived on in the other thread's epoch, charged half, until that epoch closed: the
    /// flood test's hundreds of kilobytes of decoded batches alive that no store was charged.
    #[test]
    fn a_batch_refused_on_one_thread_stays_charged_while_another_holds_it() -> Result<(), String> {
        let sink: Sink = Arc::new(|_| Ok(()));
        let epochs = Gauge::unlimited(Store::Epochs);
        let admission = Admission::new(2, sink, Arc::clone(&epochs));
        let ingest = Gauge::unlimited(Store::Ingest);
        // Thread 0's epochs are full: its slice refuses the epoch there.
        let tight = Gauges {
            epochs: Gauge::new(Store::Epochs, 1),
            dedup: Gauge::unlimited(Store::Dedup),
        };
        let _full = tight.epochs.try_charge(1);
        let mut zero = MessageThread::new(0, 2, 1, Arc::clone(&admission), tight.clone());
        let mut one = MessageThread::new(
            1,
            2,
            1,
            Arc::clone(&admission),
            Gauges {
                epochs: Arc::clone(&epochs),
                dedup: Gauge::unlimited(Store::Dedup),
            },
        );
        // One batch whose receptions fall on both threads.
        let mut slices = Vec::new();
        let mut n = 0u8;
        while slices.len() < 2 {
            n += 1;
            let identity = Identity::generate().map_err(|error| error.to_string())?;
            let content = BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: (0..64u8)
                    .map(|m| Observation {
                        format: b'3',
                        timestamp: 500,
                        signal: 0,
                        data: vec![m.wrapping_add(n); 14],
                    })
                    .collect(),
            };
            let batch = Batch::sign(&identity, &content).map_err(|error| error.to_string())?;
            let decoded = Decoded::from_verified(batch, 500, 0)
                .map_err(|undecodable| undecodable.error.to_string())?;
            slices = split(&decoded, 2, None);
        }
        let footprint = slices[0].1.decoded.footprint();
        let mut parts = slices.into_iter();
        let ((_, first), (_, second)) = parts
            .next()
            .zip(parts.next())
            .ok_or_else(|| "two slices".to_owned())?;
        let (first_share, second_share) = (first.share(), second.share());
        one.take(
            0,
            Envelope::Slice(second, InFlight::trusted(&ingest, second_share)),
        );
        zero.take(
            0,
            Envelope::Slice(first, InFlight::trusted(&ingest, first_share)),
        );
        // Refused on thread 0, alive on thread 1: charged whole between them.
        assert_eq!(tight.epochs.held(), 1);
        assert!(
            epochs.held() + ingest.held() + 2 >= footprint,
            "{} + {} charged for {footprint}",
            epochs.held(),
            ingest.held()
        );
        zero.take(0, tick(1_000));
        assert!(epochs.held() + ingest.held() + 2 >= footprint);
        // Settled once thread 1 closes it too: refused everywhere, its part let go, and with the
        // decode gone, what thread 0 kept for it.
        one.take(0, tick(1_000));
        zero.resume();
        assert_eq!((epochs.held(), ingest.held()), (0, 0));
        Ok(())
    }

    /// RFC-0181 §9: a slice's share of its batch's ingest charge is held down the queue and let
    /// go only once the epoch holds the bytes, or the slice is let go late.
    #[test]
    fn a_slices_ingest_charge_is_held_until_its_epoch_holds_it() -> Result<(), String> {
        let (mut thread, _) = thread();
        let ingest = Gauge::unlimited(Store::Ingest);
        let slice = copy_of(1, 500)?;
        let share = slice.share();
        let envelope = Envelope::Slice(slice, InFlight::trusted(&ingest, share));
        assert_eq!(ingest.held(), share);
        thread.take(0, envelope);
        assert_eq!(ingest.held(), 0);
        thread.take(0, tick(2_000));
        let late = copy_of(2, 600)?;
        thread.take(0, Envelope::Slice(late, InFlight::trusted(&ingest, share)));
        assert_eq!(ingest.held(), 0);
        Ok(())
    }

    /// RFC-0181 §9: an epoch's word is charged its lists of decisions beside its batches, from
    /// before any reception is decided until the sealer lets it go. They were charged nothing:
    /// some 24 bytes a reception beside its decode waited uncounted for the sealer.
    #[test]
    fn an_epochs_word_is_charged_its_decisions_beside_its_batches() -> Result<(), String> {
        let (mut thread, words) = thread();
        for n in 1..=5 {
            thread.take(0, Envelope::Slice(copy_of(n, 500)?, InFlight::free()));
        }
        thread.take(0, tick(2_000));
        let words = words.lock().map_err(|error| error.to_string())?;
        let word = words
            .iter()
            .find(|word| word.epoch == Some(0))
            .ok_or("no word for epoch 0")?;
        assert_eq!(word.stream.len(), 5);
        let batches: usize = word.batches.iter().map(|batch| batch.footprint()).sum();
        assert!(
            word.charge.bytes() >= batches + word.own_bytes(),
            "{} charged for {batches} of batches and {} of its own",
            word.charge.bytes(),
            word.own_bytes()
        );
        Ok(())
    }

    /// RFC-0181 §9: what waits for a stalled sealer is charged and bounded. A thousand epochs
    /// refused while the sealer takes nothing leave as many refused words as the store holds and
    /// one marker a thread; every other epoch is a gap in the words' numbers, which the sealer,
    /// once it takes them, refuses and counts as lost: none goes unaccounted. Before, every word
    /// and two markers an epoch waited, uncharged.
    #[test]
    fn what_waits_for_a_stalled_sealer_is_charged_and_bounded() -> Result<(), String> {
        let taking = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let words = Arc::new(Mutex::new(Vec::new()));
        let sink: Sink = {
            let (taking, words) = (Arc::clone(&taking), Arc::clone(&words));
            Arc::new(move |frozen| {
                if !taking.load(Ordering::Relaxed) {
                    return Err(Box::new(frozen));
                }
                match words.lock() {
                    Ok(mut words) => {
                        words.push(frozen);
                        Ok(())
                    }
                    Err(_) => Err(Box::new(frozen)),
                }
            })
        };
        const ROOM: usize = 10;
        let epochs = Gauge::new(Store::Epochs, ROOM * std::mem::size_of::<Frozen>());
        let admission = Admission::new(2, sink, Arc::clone(&epochs));
        const EPOCHS: u64 = 1_000;
        for epoch in 0..EPOCHS {
            admission.post(0, epoch, None);
            admission.progress(0, epoch + 1);
            admission.progress(1, epoch + 1);
        }
        let waiting = admission
            .ledger
            .lock()
            .map_err(|error| error.to_string())?
            .outbox
            .len();
        assert!(waiting <= ROOM * 3 + 2, "{waiting} words wait");
        assert!(epochs.held() <= epochs.limit());
        // The sealer takes them: every epoch is refused or counted lost, none merged.
        taking.store(true, Ordering::Relaxed);
        admission.flush();
        let mut coordinator = crate::seal::Coordinator::new(2);
        let (mut refused, mut lost) = (0, 0);
        for word in std::mem::take(&mut *words.lock().map_err(|error| error.to_string())?) {
            let ready = coordinator.take(word);
            lost += ready.parts_lost;
            for merged in ready.merged {
                assert!(merged.refused);
                refused += 1;
            }
        }
        assert_eq!(refused, ROOM as u64);
        assert_eq!(refused + lost, EPOCHS);
        // The sealer done with them, their charges are let go.
        assert_eq!(epochs.held(), 0);
        Ok(())
    }

    /// A slice for an epoch its thread has already closed is late: let go and counted, never
    /// decided in a later epoch, and the epochs around it are decided whole.
    #[test]
    fn a_late_slice_is_counted_and_never_decided_or_costs_another_epoch() -> Result<(), String> {
        let (mut thread, words) = thread();
        thread.take(0, Envelope::Slice(copy_of(1, 500)?, InFlight::free()));
        thread.take(0, tick(2_000));
        // Epoch 0 is closed: a slice stamped in it is late. Epoch 2's is not.
        thread.take(0, Envelope::Slice(copy_of(2, 600)?, InFlight::free()));
        thread.take(0, Envelope::Slice(copy_of(3, 2_100)?, InFlight::free()));
        thread.take(0, tick(4_000));
        let words = words.lock().map_err(|error| error.to_string())?;
        assert_eq!(words.iter().map(|word| word.late).sum::<u64>(), 1);
        let decided: Vec<(Epoch, bool, usize)> = words
            .iter()
            .filter_map(|word| word.epoch.map(|e| (e, word.refused, word.stream.len())))
            .collect();
        assert_eq!(decided, vec![(0, false, 1), (2, false, 1)]);
        Ok(())
    }
}
