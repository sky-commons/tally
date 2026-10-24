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
//! What a thread allocates is charged to the relay's budget (`budget`): each open epoch's slices,
//! their runs and the places its receptions take in the epoch's decisions to [`Store::Epochs`]
//! ([`Slice::bytes`]), and its [`DEDUP_GENERATIONS`] generations of fingerprints to
//! [`Store::Dedup`], allocated once at the capacity the plan reserved and held for the thread's
//! life ([`Generation`]). The decodes the slices share are not charged here: each is charged once, for
//! its life, inside itself, by the ingest stage that made it (`budget::Store::Decoded`), however
//! many threads, epochs and other stages hold it, and let go with its last holder. An epoch that
//! would pass the epochs' store, or hold more receptions on a thread than its generation of
//! fingerprints holds, is refused whole: its slices are let go, and the sealer is
//! told it was refused ([`Frozen::refused`]), so it counts it and makes no product of any part of
//! it (RFC-0181 §10). The epochs' room is planned for the receptions `R_max` admits over the epochs
//! held, so it is also what holds the epochs to their window: past it they refuse, and the decodes
//! they would keep alive are let go. The charge travels with the epoch's word to the sealer and is
//! released when the sealer is done with it.
//!
//! Before, each epoch charged its slices' shares of their decodes' footprints, which the fan-out,
//! MLAT's notes and orphans and the ingest allowance charged again, and a slice let go was held,
//! charged, while another thread's slice of its batch kept the decode alive: one decode, charged
//! in up to four stores, and the plan summed their windows.
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
//!
//! The threads together hold a window of epochs open or settling ([`EPOCHS_OPEN`], [`Window`]):
//! every thread asks one table with its first slice of an epoch, so an epoch is taken everywhere
//! or let go everywhere, and what the trees of epochs open and settling allocate is bounded by
//! construction and charged when the exchange is made ([`admission_fixed_bytes`]). A slice is its
//! producer's tick as well, so a batch after an idle gap closes and settles what came before it
//! first; a thread that meets an epoch past the window settles what it can and waits up to
//! [`WINDOW_WAIT_MS`] for the others, and past that lets the slice go, counted apart from the late
//! ([`Frozen::past`], RFC-0181 "Loss only at named places").

use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tally_wire::clocks::{Mono, Raw};
use tally_wire::footprint::{Deque, Tree};
use tally_wire::{Decoded, ObsRef, PublicKey, Region};

use crate::budget::{Budget, Charge, Gauge, Store};
use crate::ingest::{Pause, Stage, Stamp, TICK_MS};
use crate::seal::{Closer, EPOCH_MS, Epoch};

/// Logical shards per exchange: fixed, so a key's shard never depends on how many threads run.
pub const SHARDS: usize = 256;

/// Slices a thread's queue holds per producer before the producer waits: about a second of one
/// feeder's batches per producer at the RFC's rate, bounded whatever the shard's speed.
pub const QUEUE_SLICES: usize = 1_024;

/// What a generation allocates for each entry of its capacity ([`Generation`]): a slot and a half
/// (its table is at most two thirds full, [`DEDUP_SLOTS_PER_ENTRY`]), the entry's place in the list
/// that clears it, and one link of the areas it was kept for. Allocated once, at the thread's
/// start, for the relay's life.
pub const DEDUP_ENTRY_BYTES: usize = DEDUP_SLOT_BYTES * DEDUP_SLOTS_PER_ENTRY.0
    / DEDUP_SLOTS_PER_ENTRY.1
    + std::mem::size_of::<u32>()
    + std::mem::size_of::<Link>();

/// A table slot: the fingerprint and its mark ([`Generation`]), five 32-bit words.
const DEDUP_SLOT_BYTES: usize = SLOT_WORDS * std::mem::size_of::<u32>();

/// Slots a generation's table holds for each entry of its capacity, as a fraction: at most two
/// thirds full, so a probe for a fingerprint not held (most of them: each reception looks in
/// every generation) reads about five slots, two cache lines, before an empty one ends it.
const DEDUP_SLOTS_PER_ENTRY: (usize, usize) = (3, 2);

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

/// Entries of capacity ([`DEDUP_ENTRY_BYTES`] each) the generations hold for each reception an
/// epoch at the planned rate, all generations together: each generation holds a third more than
/// a thread's share of an epoch, every reception new. A thread's share is its shards' (the
/// fingerprint's low byte, uniform under the process's key, which no peer knows), so the
/// receptions it takes in an epoch at the planned rate pass its share by a third only at many
/// standard deviations (one at 150 receptions a share, eleven at 10,000). The tables are allocated
/// at this capacity once and never grow, so no epoch is charged room for a table to double.
pub const DEDUP_SLOTS_PER_RECEPTION: usize =
    DEDUP_GENERATIONS * DEDUP_CAPACITY_MARGIN.0 / DEDUP_CAPACITY_MARGIN.1;
const _: () =
    assert!((DEDUP_GENERATIONS * DEDUP_CAPACITY_MARGIN.0).is_multiple_of(DEDUP_CAPACITY_MARGIN.1));

/// A generation's capacity over its thread's share of an epoch at the planned rate, as a fraction.
const DEDUP_CAPACITY_MARGIN: (usize, usize) = (4, 3);

/// What the generations of fingerprints cost, all generations together, for each reception a
/// second of the planned rate: the plan's dedup line is this times the rate (`budget`).
pub const DEDUP_BYTES_PER_RECEPTION_PER_SEC: usize =
    DEDUP_SLOTS_PER_RECEPTION * DEDUP_ENTRY_BYTES * EPOCH_MS as usize / 1_000;

/// Receptions an epoch an exchange made for a test sizes its generations for (`Gauges::unlimited`).
pub const TEST_DEDUP_RECEPTIONS: usize = 1 << 16;

/// The gauges the message exchange charges, and the receptions an epoch its generations of
/// fingerprints are sized for.
#[derive(Clone, Debug)]
pub struct Gauges {
    pub epochs: Arc<Gauge>,
    pub dedup: Arc<Gauge>,
    /// Receptions an epoch, relay-wide, the generations are allocated for, once: what the plan
    /// reserved for them ([`Gauges::of`]).
    pub dedup_receptions: usize,
}

impl Gauges {
    /// The budget's gauges, and the generations sized to what the plan reserved for them: the
    /// dedup store's limit over what a reception an epoch costs them
    /// ([`DEDUP_SLOTS_PER_RECEPTION`] entries of [`DEDUP_ENTRY_BYTES`]), so what they allocate
    /// is what the plan holds for them. Taken when the exchange is made, so made after the
    /// budget's last resize.
    pub fn of(budget: &Budget) -> Self {
        let dedup = budget.gauge(Store::Dedup);
        Self {
            dedup_receptions: dedup.limit().saturating_sub(DEDUP_FIXED_BYTES)
                / (DEDUP_SLOTS_PER_RECEPTION * DEDUP_ENTRY_BYTES),
            epochs: budget.gauge(Store::Epochs),
            dedup,
        }
    }

    /// Never full: for a test's exchange, its generations sized for [`TEST_DEDUP_RECEPTIONS`].
    pub fn unlimited() -> Self {
        Self {
            epochs: Gauge::unlimited(Store::Epochs),
            dedup: Gauge::unlimited(Store::Dedup),
            dedup_receptions: TEST_DEDUP_RECEPTIONS,
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
/// `tally_wire::FingerprintKey::process`, in its own domain, `tally_wire::decoded::keyed`). A
/// feeder chooses its key, and could grind one whose plain bytes land on any shard it liked; a raw
/// shard holds per-shard tables (what it took in, `strikes`, station counters, each receiver's
/// area), each a `SHARDS`th of the relay's, so a few hundred ground keys in one shard would crowd
/// out the honest receivers there. Under a key it does not know, a feeder's keys land on shards it
/// cannot predict, so filling any shard's tables takes as many keys as filling the relay's. Fixed
/// for the process, so a receiver's shard (its worker, its admission state) never moves while it
/// runs.
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
/// this relay's regional product (`products::Products::area_for`), if any, and the relay's raw
/// clock as the batch was stamped: with the decode's two clocks, its stamp ([`Slice::stamp`]).
#[derive(Clone, Debug)]
pub struct Slice {
    pub decoded: Arc<Decoded>,
    pub ranges: Box<[Range<u32>]>,
    pub area: Option<Region>,
    pub raw: Raw,
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
        Epoch::of(self.decoded.at().mono())
    }

    /// The stamp its batch was taken at (`ingest::Stamp`): the decode's two clocks, its place in
    /// the ingest order and whether it judged, with the raw clock read beside them.
    pub fn stamp(&self) -> Stamp {
        Stamp::read(
            self.decoded.at(),
            self.decoded.ingest_seq(),
            self.raw,
            self.decoded.judging(),
        )
    }

    fn receptions(&self) -> usize {
        self.ranges.iter().map(|range| range.len()).sum()
    }

    /// What its epoch allocates for it while it waits to be sealed beside its place in the
    /// epoch's list (charged as the list grows, `Open`): its runs, its batch's place in the word,
    /// and each of its receptions' places in the epoch's decisions, at the most (every reception
    /// kept for the stream and for its area, [`DECISION_BYTES_PER_RECEPTION`]). Never its decode,
    /// which charges itself.
    pub fn bytes(&self) -> usize {
        std::mem::size_of_val(&*self.ranges)
            + std::mem::size_of::<Arc<Decoded>>()
            + self.receptions() * DECISION_BYTES_PER_RECEPTION
    }
}

/// What the epochs allocate for one reception at most ([`Slice::bytes`]) beside its slice's own
/// ([`EPOCH_BYTES_PER_SLICE`]): a run of its own (a batch whose receptions alternate between
/// threads is cut into a run a reception) and its place in the decisions. What `Store::Epochs`
/// is planned at a reception (`budget::PerFeeder::planned_for`).
pub const EPOCH_BYTES_PER_RECEPTION: usize =
    std::mem::size_of::<Range<u32>>() + DECISION_BYTES_PER_RECEPTION;

/// What the epochs allocate for one slice at most ([`Slice::bytes`]): its place in its epoch's
/// list (a list of `n` slices allocates at most `n` places, a quarter again and one more,
/// `footprint::Deque::capacity_at_most`: the place and a quarter are a slice's, the one more its
/// epoch's, [`EPOCHS_FIXED_BYTES`]) and its batch's place in the word. A batch is cut into one
/// slice for each message thread that holds a reception of it ([`split`]), so slices come at
/// most a batch's rate times the threads ([`slices_per_sec`]), however many receptions they hold.
pub const EPOCH_BYTES_PER_SLICE: usize =
    std::mem::size_of::<Slice>() + Slices::SPARE_PER_ENTRY + std::mem::size_of::<Arc<Decoded>>();

/// The message threads a batch may be cut across on `cores` cores: no more than the cores
/// (`cores::threads_for`) and the shards (a thread past [`SHARDS`] owns none), and the shards
/// where the cores are not known.
pub const fn slicing_threads(cores: Option<usize>) -> usize {
    match cores {
        Some(cores) if cores < SHARDS => {
            if cores == 0 {
                1
            } else {
                cores
            }
        }
        _ => SHARDS,
    }
}

/// The slices a second `batches` batches a second are cut into at most, across `threads` message
/// threads: one a thread for each ([`split`]).
pub const fn slices_per_sec(batches: usize, threads: usize) -> usize {
    batches.saturating_mul(threads)
}

/// What travels down a thread's queue.
#[derive(Debug)]
pub enum Envelope {
    /// A slice: its decode charged by itself, whatever holds it.
    Slice(Slice),
    /// Everything this producer sends from now on is stamped at or after this.
    Tick(Stamp),
}

/// Splits a batch into one slice per thread its receptions' message shards run on, threads
/// ascending, each slice's ranges ascending. A reception that is no product's
/// (`tally_wire::batch::format::in_products`: an ACARS-family message) is in no slice, so neither
/// the deduplicated stream nor the regional product, nor any client form of them, carries one: it
/// leaves the relay by `--acars-out` alone.
pub fn split(
    decoded: &Arc<Decoded>,
    threads: usize,
    area: Option<Region>,
    raw: Raw,
) -> Vec<(usize, Slice)> {
    let mut runs: Vec<Vec<Range<u32>>> = vec![Vec::new(); threads.max(1)];
    for (index, obs) in decoded.observations().iter().enumerate() {
        if !tally_wire::batch::format::in_products(obs.format) {
            continue;
        }
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
                    raw,
                },
            )
        })
        .collect()
}

/// A shard's view of its producers' progress: the newest tick from each on the monotonic clock
/// its stamps and epochs are counted by, and the least of them, before which nothing more will
/// arrive.
#[derive(Clone, Debug)]
pub struct Watermark {
    ticks: Box<[Option<Mono>]>,
}

impl Watermark {
    pub fn new(producers: usize) -> Self {
        Self {
            ticks: vec![None; producers.max(1)].into_boxed_slice(),
        }
    }

    /// Producer `producer` ticked at `at`; the watermark after it, none until every producer has
    /// ticked. A tick never goes back.
    pub fn tick(&mut self, producer: usize, at: Mono) -> Option<Mono> {
        if let Some(tick) = self.ticks.get_mut(producer) {
            *tick = Some(tick.map_or(at, |tick| tick.latest(at)));
        }
        self.at()
    }

    /// The least producer tick: every slice stamped before it has arrived. None until every
    /// producer has ticked: before that the least tick is no watermark.
    pub fn at(&self) -> Option<Mono> {
        self.ticks
            .iter()
            .copied()
            .collect::<Option<Vec<Mono>>>()
            .and_then(|ticks| ticks.into_iter().min())
    }
}

/// A table slot's words: the fingerprint's four and its mark.
const SLOT_WORDS: usize = 5;
/// A mark's bit for a slot that holds a fingerprint; an empty slot's mark is zero.
const OCCUPIED: u32 = 1 << 31;
/// A mark's bit for a message kept for the hub's stream.
const STREAM: u32 = 1 << 30;
/// A mark's low bits: the first link of the areas it was kept for, numbered from one (zero: none).
const HEAD: u32 = STREAM - 1;
/// The most entries one generation holds: its links are numbered in a mark's low bits.
const MAX_ENTRIES: usize = HEAD as usize;

/// One area a message was kept for, and the next (numbered from one; zero ends the list). The
/// area's number in two words, so a link is three words, not padded to four.
#[derive(Clone, Copy, Debug)]
struct Link {
    area: [u32; 2],
    next: u32,
}

impl Link {
    fn area(region: Region) -> [u32; 2] {
        let number = region.as_u64();
        [number as u32, (number >> 32) as u32]
    }
}

/// One generation: the messages one epoch kept, on one thread. A fixed table allocated once at
/// its capacity, never grown and never shrunk: open addressing over `slots` (each a fingerprint
/// and its mark: kept for the stream, and the first of the areas it was kept for), probed from the
/// fingerprint's high half (its low byte chose the shard, so it is the same across a shard), at
/// most two thirds full. The areas a message was kept for (almost always none or one) are a list
/// through `links`, one link a reception at most, so an entry is the fingerprint and an index,
/// never an allocation of its own. Every entry's slot is listed in `filled`, so clearing it costs
/// what it held, not its capacity: the table's untouched pages are never touched.
///
/// It holds at most `capacity` entries and links, and an epoch's receptions on its thread are
/// counted before any is decided ([`MessageThread::close`]): an epoch with more than its
/// generation holds is refused whole, as any epoch past its room is, never decided in part. Each
/// reception adds at most one entry and one link, so the table never fills mid-epoch.
pub struct Generation {
    slots: Box<[u32]>,
    filled: Vec<u32>,
    links: Vec<Link>,
    capacity: usize,
}

impl Generation {
    /// A generation holding up to `capacity` entries, allocated now: the slots zeroed (an empty
    /// table, from the kernel's zero pages where it is mapped apart), the lists reserved.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.min(MAX_ENTRIES);
        // One slot more than the fraction, so a table at capacity always has an empty slot that
        // ends a probe.
        let slots = capacity * DEDUP_SLOTS_PER_ENTRY.0 / DEDUP_SLOTS_PER_ENTRY.1 + 1;
        Self {
            slots: vec![0u32; slots * SLOT_WORDS].into_boxed_slice(),
            filled: Vec::with_capacity(capacity),
            links: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// The bytes it allocated, for its life.
    pub fn bytes(&self) -> usize {
        self.slots.len() * std::mem::size_of::<u32>()
            + self.filled.capacity() * std::mem::size_of::<u32>()
            + self.links.capacity() * std::mem::size_of::<Link>()
    }

    fn key(fp: u128) -> [u32; 4] {
        [
            fp as u32,
            (fp >> 32) as u32,
            (fp >> 64) as u32,
            (fp >> 96) as u32,
        ]
    }

    /// The slot holding `fp`, or the empty one where it would go.
    fn find(&self, fp: u128) -> usize {
        let key = Self::key(fp);
        let count = self.slots.len() / SLOT_WORDS;
        // The high half scaled onto the slots: uniform, with no power of two.
        let mut slot = ((u128::from((fp >> 64) as u64) * count as u128) >> 64) as usize;
        loop {
            let words = &self.slots[slot * SLOT_WORDS..(slot + 1) * SLOT_WORDS];
            if words[4] == 0 || words[..4] == key {
                return slot;
            }
            slot = if slot + 1 == count { 0 } else { slot + 1 };
        }
    }

    /// The mark of `fp`, zero if it holds none.
    fn mark(&self, fp: u128) -> u32 {
        self.slots[self.find(fp) * SLOT_WORDS + 4]
    }

    /// Whether the areas listed from `mark` hold `area`.
    fn holds(&self, mark: u32, area: Region) -> bool {
        let area = Link::area(area);
        let mut next = mark & HEAD;
        while let Some(link) = next
            .checked_sub(1)
            .and_then(|at| self.links.get(at as usize))
        {
            if link.area == area {
                return true;
            }
            next = link.next;
        }
        false
    }

    /// Keeps `fp` for the stream if `stream`, and for `area` if one: the caller has found it kept
    /// for neither here. False, keeping nothing, when it is full (an epoch counted against its
    /// capacity never finds it so).
    fn keep(&mut self, fp: u128, stream: bool, area: Option<Region>) -> bool {
        let slot = self.find(fp);
        let at = slot * SLOT_WORDS;
        let mut mark = self.slots[at + 4];
        if (mark == 0 && self.filled.len() >= self.capacity)
            || (area.is_some() && self.links.len() >= self.capacity)
        {
            return false;
        }
        if mark == 0 {
            self.slots[at..at + 4].copy_from_slice(&Self::key(fp));
            self.filled.push(slot as u32);
            mark = OCCUPIED;
        }
        if stream {
            mark |= STREAM;
        }
        if let Some(area) = area {
            self.links.push(Link {
                area: Link::area(area),
                next: mark & HEAD,
            });
            mark = (mark & !HEAD) | self.links.len() as u32;
        }
        self.slots[at + 4] = mark;
        true
    }

    /// Forgets every entry, touching only the slots they held.
    fn clear(&mut self) {
        for slot in self.filled.drain(..) {
            let at = slot as usize * SLOT_WORDS;
            self.slots[at..at + SLOT_WORDS].fill(0);
        }
        self.links.clear();
    }

    fn len(&self) -> usize {
        self.filled.len()
    }
}

/// The message shards one thread owns, together: the messages kept in the epoch being decided and
/// the `DEDUP_GENERATIONS - 1` before it, one generation an epoch, rotated as the epochs close (so
/// forgetting costs what was kept, never a walk of the table). A message is new to the stream when
/// no generation kept it for the stream, and new to an area when none kept it for that area: each
/// is remembered across `DEDUP_GENERATIONS` epochs, apart, so two copies stamped up to
/// `DEDUP_WINDOW_MS` apart are one. Its shards share its tables: a fingerprint is in one shard,
/// so one table keyed by fingerprint holds them all, and a thread's share of an epoch varies less
/// than a shard's.
pub struct MessageShard {
    /// Boxed, so a thread's state stays small where it is moved.
    generations: Box<[Generation; DEDUP_GENERATIONS]>,
    /// The generation of the epoch being decided.
    current: usize,
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
    /// Generations of `capacity` entries each, allocated now and never again.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            generations: Box::new(std::array::from_fn(|_| Generation::with_capacity(capacity))),
            current: 0,
        }
    }

    /// The entries each generation holds at most: an epoch with more receptions on this thread is
    /// refused before any is decided.
    pub fn capacity(&self) -> usize {
        self.generations[self.current].capacity
    }

    /// Decides one reception of message `fp` by a receiver in `area`, and remembers it. Kept and
    /// not remembered only past the generation's capacity, which an epoch counted against it
    /// never reaches.
    pub fn decide(&mut self, fp: u128, area: Option<Region>) -> Decision {
        let mut stream = true;
        let mut regional = area.is_some();
        for generation in self.generations.iter() {
            let mark = generation.mark(fp);
            if mark == 0 {
                continue;
            }
            stream &= mark & STREAM == 0;
            regional &= area.is_some_and(|area| !generation.holds(mark, area));
        }
        if stream || regional {
            self.generations[self.current].keep(fp, stream, area.filter(|_| regional));
        }
        Decision { stream, regional }
    }

    /// `epochs` epochs begin after the one last decided: each takes the oldest generation, cleared.
    /// `DEDUP_GENERATIONS` or more forget everything.
    pub fn rotate(&mut self, epochs: u64) {
        let steps = usize::try_from(epochs)
            .map_or(DEDUP_GENERATIONS, |epochs| epochs.min(DEDUP_GENERATIONS));
        for _ in 0..steps {
            self.current = (self.current + 1) % DEDUP_GENERATIONS;
            self.generations[self.current].clear();
        }
    }

    /// Forgets what the epoch being decided kept: it was refused (`Admission`), so nothing of it
    /// was published, and every message in it is new again.
    pub fn forget_current(&mut self) {
        self.generations[self.current].clear();
    }

    /// The bytes every generation allocated, for the thread's life.
    pub fn bytes(&self) -> usize {
        self.generations.iter().map(Generation::bytes).sum()
    }

    /// Fingerprints held.
    pub fn len(&self) -> usize {
        self.generations.iter().map(Generation::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The entries each generation of `thread` of `threads` holds for `receptions` an epoch,
/// relay-wide: its shards' share ([`SHARDS`], uniform by fingerprint), a third more
/// ([`DEDUP_SLOTS_PER_RECEPTION`]).
pub fn dedup_capacity(receptions: usize, thread: usize, threads: usize) -> usize {
    let owned = (thread..SHARDS).step_by(threads.max(1)).count();
    let share = (receptions as u128 * owned as u128 / SHARDS as u128) as usize;
    share.saturating_mul(DEDUP_CAPACITY_MARGIN.0) / DEDUP_CAPACITY_MARGIN.1
}

/// What every message thread's generations allocate for `receptions` an epoch on `threads`
/// threads: at most `receptions` times [`DEDUP_SLOTS_PER_RECEPTION`] entries of
/// [`DEDUP_ENTRY_BYTES`], and [`DEDUP_FIXED_BYTES`].
pub fn dedup_bytes(receptions: usize, threads: usize) -> usize {
    (0..threads.max(1))
        .map(|thread| {
            let capacity = dedup_capacity(receptions, thread, threads).min(MAX_ENTRIES);
            DEDUP_GENERATIONS * generation_bytes(capacity)
        })
        .sum()
}

/// What one generation of `capacity` entries allocates (`Generation::with_capacity`).
const fn generation_bytes(capacity: usize) -> usize {
    let slots = capacity * DEDUP_SLOTS_PER_ENTRY.0 / DEDUP_SLOTS_PER_ENTRY.1 + 1;
    slots * DEDUP_SLOT_BYTES + capacity * (std::mem::size_of::<u32>() + std::mem::size_of::<Link>())
}

/// What a thread's generations allocate beyond [`DEDUP_ENTRY_BYTES`] an entry: each table's one
/// slot more than its fraction (`Generation::with_capacity`).
const DEDUP_FIXED_BYTES_PER_THREAD: usize = DEDUP_GENERATIONS * DEDUP_SLOT_BYTES;

/// What the generations allocate beyond [`DEDUP_ENTRY_BYTES`] an entry, relay-wide, on any number
/// of message threads up to [`SHARDS`] (a thread past it owns no shard): the plan's dedup line is
/// this beside the rate's ([`DEDUP_BYTES_PER_RECEPTION_PER_SEC`]).
pub const DEDUP_FIXED_BYTES: usize = SHARDS * DEDUP_FIXED_BYTES_PER_THREAD;

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
    /// Every epoch before this is closed on this thread; none before it closed any.
    pub closed_before: Option<Epoch>,
    /// Receptions that arrived for an epoch this thread had already closed, since its last word:
    /// let go, never decided (`products::ProductsReport::receptions_late`).
    pub late: u64,
    /// Receptions let go because their epoch lay past the window ([`EPOCHS_OPEN`]), since the last
    /// word: their epoch refused whole (`products::ProductsReport::receptions_past_window`).
    pub past: u64,
    pub batches: Vec<Arc<Decoded>>,
    pub stream: Vec<(u32, u32)>,
    pub regional: Vec<(Region, u32, u32)>,
    /// The newest tick its thread was given as it closed the epoch, both clocks read in it: the
    /// epoch is signed by the judging clock at its end by this reading (`Stamp::judging`), so a
    /// step of that clock moves what is signed and nothing else.
    pub judged: Option<Stamp>,
    /// What the word allocates itself (`Store::Epochs`: its lists, [`Frozen::own_bytes`]),
    /// released when the sealer lets it go. Its batches' decodes are charged by themselves.
    pub charge: Charge,
    /// Its place while it waits for the sealer: its share of the outbox's spare room, and for a
    /// refused epoch's word its own bytes ([`Ledger::push`]), charged before its verdict.
    pub place: Charge,
}

/// One epoch's parts held together, gathered across message threads (`Settling`, and the sealer's
/// `seal::Coordinator`). Let go, every part's batches go before any part's charge, as each word's
/// own fields are dropped: what a part's charge holds is its lists, and the decodes its batches
/// share are charged by themselves, so the order costs nothing and no part outlives its charge.
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
/// bytes, and each its share of the outbox's spare room ([`OUTBOX_SHARE_BYTES`]), its place,
/// charged before its verdict exists (`Admission::progress`): an epoch with no room for its place
/// is refused, so a word for an epoch any thread was told was admitted is always queued, and a
/// refused one with no place is not, the gap in the words' numbers telling the sealer an epoch was
/// lost on the way, which it refuses and counts (`seal::Coordinator`), as it does a word its queue
/// had no room for. What a thread has closed to waits once a thread, in a table allocated and charged
/// when the admission is made ([`outbox_fixed_bytes`]): a newer replaces it and goes after every
/// word queued since, so the sealer is never owed more than one a thread, and never waits on one
/// for want of room. Before, every word waited uncharged, a sealer behind for an hour was owed some
/// 3,600 epochs' words and a marker per thread for each, and the outbox's spare room was charged
/// nothing.
pub struct Admission {
    threads: usize,
    sink: Sink,
    /// What the words waiting for the sealer are charged to (`Store::Epochs`).
    epochs: Arc<Gauge>,
    /// What the table of marks and the outbox's fixed spare room are charged
    /// ([`outbox_fixed_bytes`]), for the admission's life; none when the store could not hold
    /// them, an exchange that must not start (`MessageExchange::threads`).
    fixed: Option<Charge>,
    /// The epochs the threads hold, and those let go past them ([`Window`]): every thread's
    /// first slice of an epoch asks it, so an epoch is taken everywhere or let go everywhere.
    window: Mutex<Window>,
    /// Told whenever the epochs settle further, for a thread waiting for the window to move.
    moved: Condvar,
    ledger: Mutex<Ledger>,
    /// Words waiting for the sealer: a flush takes the ledger only when there are any.
    waiting: AtomicUsize,
    /// Held while words are offered, so they reach the sealer in the order they were settled.
    sending: Mutex<()>,
}

#[derive(Default)]
struct Ledger {
    /// The newest stamp a thread has closed by (`Admission::progress`).
    judged: Option<Stamp>,
    /// Per thread: every epoch before this it has posted (decided, refused, or held nothing of).
    through: Vec<Option<Epoch>>,
    /// Epochs some thread posted a part of, not yet settled: inside the window, so at most
    /// [`EPOCHS_OPEN`], their tree and lists allocated within what the admission was charged
    /// ([`admission_fixed_bytes`]).
    pending: Tree<Epoch, Settling>,
    /// Per thread: the epoch it awaits and whether it was admitted, once settled.
    verdicts: Vec<Option<(Epoch, bool)>>,
    /// Every epoch before this is settled and told the sealer.
    frontier: Option<Epoch>,
    /// The epochs' words waiting for the sealer, in order: each charged its own bytes and its
    /// share of the deque's spare room ([`OUTBOX_SHARE_BYTES`]), beside the deque's fixed spare
    /// (`Admission::fixed`), so what it allocates is charged whatever it holds.
    outbox: Outbox,
    /// Per thread, how far it has closed, waiting for the sealer: the oldest not yet told, and
    /// every newer one as one, two a thread at most ([`Marks`]).
    marks: Vec<Marks>,
    /// Epoch words queued since the start, and taken by the sealer.
    queued: u64,
    taken: u64,
    /// Epoch words sent the sealer: they go as thread 0's (`Frozen::seq`).
    parts: u64,
    /// Receptions let go late, not yet told.
    late: u64,
    /// Receptions let go past the window, not yet told.
    past: u64,
}

/// One thread's marks waiting for the sealer: the oldest, told as soon as the words queued before
/// it are, and every newer as one behind it. Before, every newer mark was merged into the one
/// waiting, which took the newest's place in the queue: under a sealer's backlog each advance
/// pushed the mark behind every word queued since, and the sealer's watermark could not pass
/// epochs every thread had closed long before. Now the oldest keeps its place, so the watermark
/// moves on as the backlog drains, a step at a time.
type Marks = [Option<Mark>; 2];

/// The epochs' words waiting for the sealer.
type Outbox = Deque<Frozen, 1>;

/// What each epoch's word waiting for the sealer is charged beside its own bytes: its share of the
/// outbox's spare room (`footprint::Deque::SPARE_PER_ENTRY`). Kept with the word until it is let
/// go, since the sealer's taking it is never charged back.
pub const OUTBOX_SHARE_BYTES: usize = Outbox::SPARE_PER_ENTRY;

/// What an admission of `threads` message threads allocates whatever waits: its table of marks
/// and the outbox's fixed spare room (`footprint::Deque::SPARE_FIXED`).
pub const fn outbox_fixed_bytes(threads: usize) -> usize {
    tally_wire::footprint::vec::<Marks>(threads) + Outbox::SPARE_FIXED
}

/// The epochs every message thread together may hold open or settling at once: the oldest and the
/// newest any thread holds are fewer than this apart ([`Window`]). A slice of an epoch that would
/// widen it past this is let go, counted as past the window
/// (`products::ProductsReport::receptions_past_window`), and its epoch let go on every thread,
/// so the maps of epochs open and settling never hold more, and what they may allocate is charged
/// before any is taken ([`admission_fixed_bytes`]). The relay holds `seal::EPOCHS_HELD` between
/// ingest and the sealer; the rest is for threads and producers a few epochs apart. A thread that
/// meets an epoch past the window first settles what it can and waits for the others to settle,
/// up to [`WINDOW_WAIT_MS`], so a thread that has only not yet read its producers' ticks costs
/// nothing; one stalled longer than that is where this loss is (RFC-0181, "Loss only at named
/// places").
pub const EPOCHS_OPEN: u64 = 8;

/// The longest a message thread waits for the window to move before it lets a slice past it go:
/// a few of an idle producer's ticks (`ingest::TICK_MS`), the time another thread takes to read
/// the tick queued for it.
pub const WINDOW_WAIT_MS: u64 = 4 * TICK_MS;

/// The runs of epochs let go past the window held at once ([`Window`]): a run is a span of epochs
/// let go with none taken between. Past it the two nearest runs are joined, and the epochs between
/// them are let go too, counted as past the window: only a schedule that lets go epochs with
/// taken ones between them, sixteen times over, before any of them settles, meets that.
pub const LET_GO_RUNS: usize = 16;

// Some gap between the runs always lies outside the held span, which meets at most `EPOCHS_OPEN`.
const _: () = assert!(LET_GO_RUNS as u64 > EPOCHS_OPEN);

/// What an admission of `threads` message threads allocates whatever it holds: what waits for the
/// sealer ([`outbox_fixed_bytes`]), the epochs settling at the window's most (their tree, and
/// each one's lists of parts and of threads, made as long as the threads), the runs of epochs
/// let go past the window ([`LET_GO_RUNS`], and one more while two are joined), the ledger's lists
/// a thread long ([`ledger_fixed_bytes`]), and each thread's tree of the epochs it holds open at the
/// window's most. Charged when it is made, so a refusal never needs room it lacks.
pub const fn admission_fixed_bytes(threads: usize) -> usize {
    outbox_fixed_bytes(threads)
        + settling_fixed_bytes(threads)
        + ledger_fixed_bytes(threads)
        + tally_wire::footprint::vec::<Range<Epoch>>(LET_GO_RUNS + 1)
        + threads * Tree::<Epoch, Open>::bytes_at(EPOCHS_OPEN as usize)
}

/// What the ledger's lists a thread long allocate: how far each thread has posted, and the verdict
/// each awaits (`Ledger::through`, `Ledger::verdicts`).
const fn ledger_fixed_bytes(threads: usize) -> usize {
    tally_wire::footprint::vec::<Option<Epoch>>(threads)
        + tally_wire::footprint::vec::<Option<(Epoch, bool)>>(threads)
}

/// What the epochs settling allocate at the window's most ([`EPOCHS_OPEN`]): their tree, and each
/// one's lists of parts and of threads, made as long as the threads (`Settling::of`).
const fn settling_fixed_bytes(threads: usize) -> usize {
    let open = EPOCHS_OPEN as usize;
    Tree::<Epoch, Settling>::bytes_at(open)
        + open
            * (tally_wire::footprint::vec::<Frozen>(threads)
                + tally_wire::footprint::vec::<usize>(threads))
}

/// What the epochs allocate whatever the rate, as planned, for any number of message threads up to
/// [`SHARDS`] (a thread past it owns no shard): what the admission allocates whatever it holds
/// ([`admission_fixed_bytes`]), and the one place more each open epoch's list of slices may keep
/// (`footprint::Deque::SPARE_FIXED`), for the epochs a thread may hold open ([`EPOCHS_OPEN`]).
/// What the plan's epochs store holds before any feeder.
pub const EPOCHS_FIXED_BYTES: usize =
    admission_fixed_bytes(SHARDS) + SHARDS * EPOCHS_OPEN as usize * Slices::SPARE_FIXED;

/// How far one thread has closed, not yet told the sealer: told once the words queued before it
/// (`after`) are.
#[derive(Clone, Copy, Debug)]
struct Mark {
    after: u64,
    seq: u64,
    closed_before: Epoch,
    late: u64,
    past: u64,
    /// The stamp it closed by: the newest any thread had closed by then.
    judged: Option<Stamp>,
}

impl Mark {
    /// `self` and a newer mark of the same thread, as one: the newer's place, the further close,
    /// every late reception told by either.
    fn and(self, newer: Self) -> Self {
        Self {
            after: self.after.max(newer.after),
            seq: self.seq.max(newer.seq),
            closed_before: self.closed_before.max(newer.closed_before),
            late: self.late + newer.late,
            past: self.past + newer.past,
            judged: self.judged.max(newer.judged),
        }
    }
}

#[derive(Default)]
struct Settling {
    parts: Parts,
    refused: bool,
    /// The threads that decided a part of it and keep it only if it is admitted.
    awaiting: Vec<usize>,
}

impl Settling {
    /// Its lists made as long as `threads` parts, once, so they never grow
    /// ([`admission_fixed_bytes`]).
    fn of(threads: usize) -> Self {
        Self {
            parts: Parts(Vec::with_capacity(threads)),
            refused: false,
            awaiting: Vec::with_capacity(threads),
        }
    }
}

/// The epochs the message threads hold open or settling, all of them together, and those let go
/// past them: one table every thread asks the first time it takes a slice of an epoch, so an
/// epoch is either taken by every thread that has a slice of it or let go by every one, and the
/// oldest and newest held are always fewer than [`EPOCHS_OPEN`] apart, whatever the schedule (the
/// threads' trees of epochs open, and the epochs settling, are bounded by construction, not by the
/// schedule a test or a relay happens to run).
///
/// Before, the window was counted from a floor: the first epoch any thread took, then the epochs
/// settled. A thread took an epoch from the floor up to [`EPOCHS_OPEN`] past it, and every epoch
/// one let go was remembered as one range per thread, its first to its last. So the first epoch
/// taken at the start pinned the floor and an older one taken a moment later on another thread was
/// lost; a batch after an idle gap of eight epochs, read before its producer's tick moved the floor,
/// was lost; and an epoch between two let go, taken in full by every thread, was refused.
#[derive(Default)]
struct Window {
    /// The oldest and the newest epoch any thread holds open or settling; none when none is.
    held: Option<(Epoch, Epoch)>,
    /// Every epoch before this is settled: a slice of one is late.
    settled: Option<Epoch>,
    /// The epochs let go past the window that may still come, as runs, ascending and apart.
    let_go: Vec<Range<Epoch>>,
}

/// What a thread may do with the first slice of an epoch it holds nothing of ([`Window::admit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admit {
    /// Taken: it is in the window, now held.
    Open,
    /// Its epoch is settled: late.
    Late,
    /// Its epoch was let go past the window, or is older than the window holds: let go.
    LetGo,
    /// Newer than the window holds: let go unless the window moves first.
    Ahead,
}

impl Window {
    fn admit(&mut self, epoch: Epoch) -> Admit {
        if self.settled.is_some_and(|settled| epoch < settled) {
            return Admit::Late;
        }
        if self.let_go.iter().any(|run| run.contains(&epoch)) {
            return Admit::LetGo;
        }
        let Some((oldest, newest)) = self.held else {
            self.held = Some((epoch, epoch));
            return Admit::Open;
        };
        let (from, to) = (oldest.min(epoch), newest.max(epoch));
        if to.after(from) < EPOCHS_OPEN {
            self.held = Some((from, to));
            Admit::Open
        } else if epoch > newest {
            Admit::Ahead
        } else {
            // Older than the window holds: no thread holds it, and none ever will (the newest held
            // only grows), so it needs no record.
            Admit::LetGo
        }
    }

    /// `epoch`, newer than the window holds, let go: every thread lets go every slice of it.
    fn let_go(&mut self, epoch: Epoch) {
        let at = self.let_go.partition_point(|run| run.end < epoch);
        match self.let_go.get_mut(at) {
            Some(run) if run.contains(&epoch) => return,
            Some(run) if run.end == epoch => run.end = epoch.next(),
            Some(run) if run.start == epoch.next() => run.start = epoch,
            _ => self.let_go.insert(at, epoch..epoch.next()),
        }
        // The run changed at `at` joins a neighbour it now touches, in place, so the runs keep the
        // room reserved for them.
        if at + 1 < self.let_go.len() && self.let_go[at].end >= self.let_go[at + 1].start {
            let next = self.let_go.remove(at + 1);
            self.let_go[at].end = self.let_go[at].end.max(next.end);
        }
        if at > 0 && self.let_go[at - 1].end >= self.let_go[at].start {
            let run = self.let_go.remove(at);
            self.let_go[at - 1].end = self.let_go[at - 1].end.max(run.end);
        }
        if self.let_go.len() > LET_GO_RUNS {
            // The nearest two joined, what lies between let go too, but never across an epoch the
            // window holds: a thread may have taken it, and another would then let it go. The held
            // span is fewer than `EPOCHS_OPEN` epochs, so it meets fewer gaps than there are.
            let held = self.held;
            let nearest = (1..self.let_go.len())
                .filter(|at| {
                    held.is_none_or(|(oldest, newest)| {
                        self.let_go[*at - 1].end > newest || self.let_go[*at].start <= oldest
                    })
                })
                .min_by_key(|at| self.let_go[*at].start.after(self.let_go[*at - 1].end));
            if let Some(nearest) = nearest {
                let run = self.let_go.remove(nearest);
                self.let_go[nearest - 1].end = run.end;
            }
        }
    }

    /// Every epoch before `frontier` is settled.
    fn settle(&mut self, frontier: Epoch) {
        self.settled = Some(
            self.settled
                .map_or(frontier, |settled| settled.max(frontier)),
        );
        self.held = self
            .held
            .filter(|(_, newest)| *newest >= frontier)
            .map(|(oldest, newest)| (oldest.max(frontier), newest));
        self.let_go.retain(|run| run.end > frontier);
    }

    /// Whether `epoch` is let go past the window.
    fn is_let_go(&self, epoch: Epoch) -> bool {
        self.let_go.iter().any(|run| run.contains(&epoch))
    }
}

impl Admission {
    /// Settling for `threads` message threads, words for `sink`, those waiting charged to `epochs`.
    pub fn new(threads: usize, sink: Sink, epochs: Arc<Gauge>) -> Arc<Self> {
        let threads = threads.max(1);
        let marks: Vec<Marks> = vec![[None; 2]; threads];
        debug_assert_eq!(
            tally_wire::footprint::vec::<Marks>(marks.capacity()),
            outbox_fixed_bytes(threads) - Outbox::SPARE_FIXED
        );
        let through: Vec<Option<Epoch>> = vec![None; threads];
        let verdicts: Vec<Option<(Epoch, bool)>> = vec![None; threads];
        debug_assert_eq!(
            tally_wire::footprint::vec::<Option<Epoch>>(through.capacity())
                + tally_wire::footprint::vec::<Option<(Epoch, bool)>>(verdicts.capacity()),
            ledger_fixed_bytes(threads)
        );
        Arc::new(Self {
            threads,
            sink,
            fixed: epochs.try_charge(admission_fixed_bytes(threads)),
            window: Mutex::new(Window {
                let_go: Vec::with_capacity(LET_GO_RUNS + 1),
                ..Window::default()
            }),
            moved: Condvar::new(),
            epochs,
            ledger: Mutex::new(Ledger {
                through,
                verdicts,
                marks,
                ..Ledger::default()
            }),
            waiting: AtomicUsize::new(0),
            sending: Mutex::new(()),
        })
    }

    /// Thread `thread` decided its part of `epoch` (`part`), or refused it (`None`).
    fn post(&self, thread: usize, epoch: Epoch, part: Option<Frozen>) {
        if let Ok(mut ledger) = self.ledger.lock() {
            let threads = self.threads;
            let settling = ledger
                .pending
                .entry(epoch)
                .or_insert_with(|| Settling::of(threads));
            match part {
                Some(part) => {
                    settling.parts.push(part);
                    settling.awaiting.push(thread);
                }
                None => settling.refused = true,
            }
        }
    }

    /// What a thread may do with the first slice it takes of `epoch` ([`Window::admit`]).
    fn admit(&self, epoch: Epoch) -> Admit {
        self.window
            .lock()
            .map_or(Admit::LetGo, |mut window| window.admit(epoch))
    }

    /// Whether `epoch` is let go past the window, for a thread that holds nothing of it.
    fn is_let_go(&self, epoch: Epoch) -> bool {
        self.window
            .lock()
            .is_ok_and(|window| window.is_let_go(epoch))
    }

    /// Waits up to [`WINDOW_WAIT_MS`] for the window to take `epoch`, newer than it holds: taken
    /// if it moves up in time, else let go on every thread.
    fn admit_ahead(&self, epoch: Epoch) -> Admit {
        let deadline = std::time::Instant::now() + Duration::from_millis(WINDOW_WAIT_MS);
        let Ok(mut window) = self.window.lock() else {
            return Admit::LetGo;
        };
        loop {
            match window.admit(epoch) {
                Admit::Ahead => {}
                other => return other,
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                window.let_go(epoch);
                return Admit::LetGo;
            }
            window = match self.moved.wait_timeout(window, deadline - now) {
                Ok((window, _)) => window,
                Err(_) => return Admit::LetGo,
            };
        }
    }

    /// Receptions a thread let go past the window: counted at the next word.
    fn past(&self, receptions: u64) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.past += receptions;
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
    fn progress(&self, thread: usize, through: Epoch, judged: Option<Stamp>) {
        if let Ok(mut ledger) = self.ledger.lock() {
            // The newest stamp any thread closed by: what the sealer's watermark is judged by when
            // no epoch carries one (`Frozen::judged`), so a relay with nothing flowing still
            // seals, and steps its MLAT, by a judging clock.
            ledger.judged = ledger.judged.max(judged);
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
                while ledger
                    .pending
                    .first_key_value()
                    .is_some_and(|(epoch, _)| *epoch < frontier)
                {
                    let Some((epoch, settling)) = ledger.pending.pop_first() else {
                        break;
                    };
                    // Its word's place, and its share of the outbox, charged before any verdict
                    // exists: an epoch with no room for them is refused, so one told it was
                    // admitted is always queued.
                    let place = self
                        .epochs
                        .try_charge(std::mem::size_of::<Frozen>() + OUTBOX_SHARE_BYTES);
                    let let_go = self
                        .window
                        .lock()
                        .is_ok_and(|window| window.is_let_go(epoch));
                    let word = settle(epoch, settling, ledger, place.is_some() && !let_go);
                    ledger.push(word, place);
                }
                ledger.frontier = Some(frontier);
                // Every epoch before it is settled: the window moves up, and what was let go past
                // it before is done.
                if let Ok(mut window) = self.window.lock() {
                    window.settle(frontier);
                }
                self.moved.notify_all();
                for thread in 0..self.threads {
                    let mark = Mark {
                        after: ledger.queued,
                        seq: if thread == 0 { ledger.parts } else { 0 },
                        closed_before: frontier,
                        late: std::mem::take(&mut ledger.late),
                        past: std::mem::take(&mut ledger.past),
                        judged: ledger.judged,
                    };
                    ledger.mark(thread, mark);
                }
            }
            self.waiting.store(ledger.waiting(), Ordering::Release);
        }
        self.flush();
    }

    /// Whether what it allocates whatever waits was charged ([`outbox_fixed_bytes`]).
    pub fn charged(&self) -> bool {
        self.fixed.is_some()
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
            let Some(word) = self.ledger.lock().ok().and_then(|mut ledger| ledger.next()) else {
                break;
            };
            let (epoch, thread) = (word.epoch.is_some(), word.thread);
            match (self.sink)(word) {
                Ok(()) => {
                    if let Ok(mut ledger) = self.ledger.lock() {
                        if epoch {
                            ledger.sent();
                        } else {
                            ledger.mark_sent(thread);
                        }
                    }
                }
                Err(word) => {
                    if epoch && let Ok(mut ledger) = self.ledger.lock() {
                        ledger.unsent(*word);
                    }
                    break;
                }
            }
        }
        if let Ok(ledger) = self.ledger.lock() {
            self.waiting.store(ledger.waiting(), Ordering::Release);
        }
    }
}

impl Ledger {
    /// Queues epoch `word` for the sealer, with the receptions let go not yet told, charged while
    /// it waits: an admitted epoch's word comes charged its own bytes (`settle`) and takes on
    /// `place`, its share of the outbox's spare room ([`OUTBOX_SHARE_BYTES`]) and its own place
    /// (released, the parts having charged it); a refused one's is `place` whole. `place` was
    /// charged before the verdict (`Admission::progress`), and an epoch without it is refused, so
    /// an admitted word is always queued. A refused one with no place is not: the gap in thread
    /// 0's numbers it leaves tells the sealer an epoch was lost, which it refuses and counts, as
    /// it was told.
    fn push(&mut self, mut word: Frozen, place: Option<Charge>) {
        let Some(mut place) = place else {
            debug_assert!(word.refused, "an admitted epoch was settled with no place");
            return;
        };
        if word.charge.bytes() > 0 {
            place.shrink_to(OUTBOX_SHARE_BYTES);
        }
        word.place = place;
        word.late = std::mem::take(&mut self.late);
        word.past = std::mem::take(&mut self.past);
        self.outbox.push_back(word);
        self.queued += 1;
    }

    /// Thread `thread` has closed to `mark`: told once every word queued before it is. Behind the
    /// oldest waiting, as one with every newer.
    fn mark(&mut self, thread: usize, mark: Mark) {
        if let Some([oldest, newer]) = self.marks.get_mut(thread) {
            if oldest.is_none() {
                *oldest = Some(mark);
            } else {
                *newer = Some(newer.map_or(mark, |older| older.and(mark)));
            }
        }
    }

    /// The sealer took thread `thread`'s oldest mark: the newer takes its place.
    fn mark_sent(&mut self, thread: usize) {
        if let Some([oldest, newer]) = self.marks.get_mut(thread) {
            *oldest = newer.take();
        }
    }

    /// What waits for the sealer: the epoch words and the marks.
    fn waiting(&self) -> usize {
        self.outbox.len() + self.marks.iter().flatten().flatten().count()
    }

    /// The next word for the sealer: a thread's oldest mark once every word queued before it was
    /// taken (which stays until it is taken, [`Ledger::mark_sent`]), else the first epoch word,
    /// taken out of its place (which stays until it is taken, [`Ledger::sent`]).
    fn next(&mut self) -> Option<Frozen> {
        let taken = self.taken;
        let due = self
            .marks
            .iter()
            .enumerate()
            .find_map(|(thread, [oldest, _])| {
                oldest
                    .filter(|mark| mark.after <= taken)
                    .map(|mark| (thread, mark))
            });
        if let Some((thread, mark)) = due {
            return Some(Frozen {
                thread,
                seq: mark.seq,
                closed_before: Some(mark.closed_before),
                late: mark.late,
                past: mark.past,
                judged: mark.judged,
                ..Frozen::default()
            });
        }
        self.outbox.front_mut().map(std::mem::take)
    }

    /// The sealer took the first epoch word: its place goes.
    fn sent(&mut self) {
        self.outbox.pop_front();
        self.taken += 1;
    }

    /// The sealer could not take epoch `word`: it goes back where it was. (A mark the sealer
    /// could not take never left its place.)
    fn unsent(&mut self, word: Frozen) {
        if let Some(front) = self.outbox.front_mut() {
            *front = word;
        }
    }
}

/// `epoch` settled: every thread that decided a part of it told whether it was admitted, and its
/// one word for the sealer, every part as one (thread 0's), or its refusal. `may_admit`: whether
/// its word has its place ([`Ledger::push`]) and no thread let a slice of it go past the window.
fn settle(epoch: Epoch, settling: Settling, ledger: &mut Ledger, may_admit: bool) -> Frozen {
    let mut word = Frozen {
        thread: 0,
        seq: ledger.parts,
        epoch: Some(epoch),
        closed_before: Some(epoch.next()),
        ..Frozen::default()
    };
    ledger.parts += 1;
    // Refused on a thread that refused it, or with no place, or let go past the window on one
    // (only where two runs let go were joined, `LET_GO_RUNS`).
    let mut admitted = !settling.refused && may_admit;
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
            word.judged = word.judged.max(part.judged);
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
    /// Its shards, `thread`, `thread + threads`, ..., their generations in one table each.
    messages: MessageShard,
    watermark: Watermark,
    closer: Closer,
    /// The epochs it holds open, at most [`EPOCHS_OPEN`]: their tree is allocated within what the
    /// admission was charged ([`admission_fixed_bytes`]).
    open: Tree<Epoch, Open>,
    gauges: Gauges,
    /// What the generations' tables are charged (`Store::Dedup`): all they allocated, from the
    /// thread's start to its end; none if the store could not hold them.
    dedup: Option<Charge>,
    /// The last epoch decided: its shards' generations are its and the ones before.
    decided: Option<Epoch>,
    /// Every epoch before this is closed by the watermark: no slice of it will be taken.
    closed_to: Option<Epoch>,
    /// The newest tick it was given, both clocks read in it: what an epoch it closes is signed by
    /// (`Frozen::judged`).
    judged: Option<Stamp>,
    /// The epoch it decided a part of and posted, until it is settled: the next is decided only
    /// after, against what that one kept.
    awaiting: Option<Epoch>,
    admission: Arc<Admission>,
}

impl MessageThread {
    pub fn new(
        thread: usize,
        threads: usize,
        producers: usize,
        admission: Arc<Admission>,
        gauges: Gauges,
    ) -> Self {
        // Its generations, allocated once at the capacity the plan reserved and charged for the
        // thread's life; none when the store cannot hold them (`MessageThread::tables_charged`),
        // and then every epoch with a reception is refused here.
        let capacity = dedup_capacity(gauges.dedup_receptions, thread, threads);
        let dedup = gauges
            .dedup
            .try_charge(DEDUP_GENERATIONS * generation_bytes(capacity));
        let capacity = if dedup.is_some() { capacity } else { 0 };
        Self {
            dedup,
            gauges,
            thread,
            messages: MessageShard::with_capacity(capacity),
            watermark: Watermark::new(producers),
            closer: Closer::default(),
            open: Tree::new(),
            decided: None,
            closed_to: None,
            judged: None,
            awaiting: None,
            admission,
        }
    }

    pub fn take(&mut self, producer: usize, envelope: Envelope) {
        match envelope {
            Envelope::Slice(slice) => {
                // A producer's stamps never go back (`ingest::Stamp`): its slice is its tick too,
                // so a batch after an idle gap closes and settles what came before it before it
                // asks the window. Before, a batch read before its producer's tick, eight epochs
                // after the last, met a window that had not moved, and was let go. And it is a
                // tick of both clocks: what it closes is signed by the judging clock its own stamp
                // read, as by a tick's (`Frozen::judged`). Before, only its monotonic reading
                // moved anything, and an epoch it closed was signed by the last tick's judging
                // clock, however long before.
                let stamp = slice.stamp();
                self.judged = self.judged.max(Some(stamp));
                self.tick(producer, stamp.mono());
                let epoch = slice.epoch();
                if self.closer.closed(epoch) {
                    // Its epoch is decided and gone: late, let go, counted at the next word.
                    self.admission.late(slice.receptions() as u64);
                    return;
                }
                if !self.open.contains_key(&epoch) {
                    let admitted = match self.admission.admit(epoch) {
                        Admit::Ahead => {
                            // Settle what it can, then wait for the others to move the window.
                            self.settle();
                            self.admission.admit_ahead(epoch)
                        }
                        other => other,
                    };
                    match admitted {
                        Admit::Open => {}
                        Admit::Late => {
                            self.admission.late(slice.receptions() as u64);
                            return;
                        }
                        Admit::LetGo | Admit::Ahead => {
                            // Past the window: let go, counted, and its epoch let go everywhere.
                            self.admission.past(slice.receptions() as u64);
                            return;
                        }
                    }
                } else if self.admission.is_let_go(epoch) {
                    // Held here, and since let go past the window by a join of runs: refused whole
                    // when it settles, so its slices are let go now.
                    self.admission.past(slice.receptions() as u64);
                    return;
                }
                let gauge = &self.gauges.epochs;
                let open = self.open.entry(epoch).or_insert_with(|| Open {
                    slices: Slices::new(),
                    charge: gauge.empty(),
                    refused: false,
                });
                if open.refused {
                    return;
                }
                // Its runs and decisions, and its place in the list as the list grows to take it.
                if open.charge.try_grow(slice.bytes() + open.slices.growth()) {
                    open.slices.push_back(slice);
                } else {
                    // Past the budget: the whole epoch is refused, never a part of it.
                    open.refuse();
                }
            }
            Envelope::Tick(stamp) => {
                self.judged = self.judged.max(Some(stamp));
                self.tick(producer, stamp.mono());
            }
        }
    }

    /// Producer `producer` will send nothing stamped before `at` on the monotonic clock: the
    /// epochs before every producer's tick close, and are decided and settled.
    fn tick(&mut self, producer: usize, at: Mono) {
        // Nothing closes until every producer has ticked once: before that the least tick is no
        // watermark.
        let Some(watermark) = self.watermark.tick(producer, at) else {
            return;
        };
        let oldest = self.open.keys().next().copied();
        let closing = self.closer.advance(watermark, oldest);
        self.closed_to = Some(self.closed_to.map_or(closing.end, |to| to.max(closing.end)));
        self.settle();
    }

    /// Takes up what waits on the other threads: an epoch they have settled since, and the words
    /// the sealer could not take before. Called between envelopes, and when none comes.
    pub fn resume(&mut self) {
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
            self.admission.progress(self.thread, through, self.judged);
            if let Some(epoch) = self.awaiting {
                let Some(admitted) = self.admission.verdict(self.thread, epoch) else {
                    return;
                };
                if !admitted {
                    // Refused on some thread: nothing of it is published, so nothing of it is
                    // remembered.
                    self.messages.forget_current();
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
            self.messages.rotate(epoch.after(last));
        }
        self.decided = Some(epoch);
        // Room for every reception of the epoch to be new, before any is decided: the generation
        // being decided is empty (rotated, or forgotten when refused) and holds its capacity, so
        // an epoch with more receptions here than that is refused whole, never decided in part.
        // Its tables never grow: what they cost was charged when the thread started.
        let receptions: usize = open.slices.iter().map(Slice::receptions).sum();
        let fits = receptions <= self.messages.capacity();
        let Open {
            mut slices,
            mut charge,
            refused,
        } = open;
        // Its word's lists of batches and of decisions, as long as they can be (every reception
        // kept for the stream and for its area), were charged with its slices
        // (`Slice::bytes`), so what waits for the sealer is charged all the way (`Admission`).
        let in_areas: usize = slices
            .iter()
            .filter(|slice| slice.area.is_some())
            .map(Slice::receptions)
            .sum();
        let room = !refused && fits;
        if !room {
            Open {
                slices,
                charge,
                refused,
            }
            .refuse();
            self.admission.post(self.thread, epoch, None);
            return false;
        }
        let mut slices = Vec::from(slices.take());
        slices.sort_by(|a, b| {
            crate::seal::canonical(&a.decoded).cmp(&crate::seal::canonical(&b.decoded))
        });
        let mut frozen = Frozen {
            thread: self.thread,
            epoch: Some(epoch),
            closed_before: Some(epoch.next()),
            judged: self.judged,
            batches: Vec::with_capacity(slices.len()),
            stream: Vec::with_capacity(receptions),
            regional: Vec::with_capacity(in_areas),
            ..Frozen::default()
        };
        for (at, slice) in slices.iter().enumerate() {
            let at = at as u32;
            for (index, obs) in slice.observations() {
                let decision = self.messages.decide(obs.fp, slice.area);
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
        // The lists as decided, and their charge cut to them: the slices are let go.
        frozen.stream.shrink_to_fit();
        frozen.regional.shrink_to_fit();
        charge.shrink_to(frozen.own_bytes());
        frozen.charge = charge;
        self.admission.post(self.thread, epoch, Some(frozen));
        true
    }

    /// Fingerprints held across its shards.
    pub fn held(&self) -> usize {
        self.messages.len()
    }

    /// Whether its generations were allocated: false only when the dedup store could not hold
    /// what the plan sized them for, a relay that must not start (`MessageExchange::threads`).
    pub fn tables_charged(&self) -> bool {
        self.dedup.is_some()
    }
}

/// An epoch's slices, its place for each charged as it grows (`Open`).
type Slices = Deque<Slice, 1>;

/// An epoch open on a message thread: its slices so far and what they are charged (their list as
/// it allocates, and each one's [`Slice::bytes`]), or refused.
struct Open {
    slices: Slices,
    charge: Charge,
    refused: bool,
}

impl Open {
    /// Refused whole: its slices are let go now, and what they were charged with them. A decode
    /// another thread's slice or another stage still holds stays charged by itself.
    fn refuse(&mut self) {
        self.refused = true;
        self.slices.clear();
        // A refused epoch stays open, holding nothing, until it closes.
        self.charge.shrink_to(0);
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
            if !admission.charged() {
                return Err(format!(
                    "message threads: the epochs store cannot hold what the admission allocates \
                     whatever it holds ({} bytes, the store's limit {}, {} already charged)",
                    admission_fixed_bytes(threads),
                    gauges.epochs.limit(),
                    gauges.epochs.held(),
                ));
            }
            if !state.tables_charged() {
                // Dropping `exchange` stops and joins the threads already started.
                return Err(format!(
                    "message thread {thread} of {threads}: the dedup store cannot hold its \
                     generations of fingerprints ({} receptions an epoch: {} bytes for every \
                     thread, the store's limit {}, {} already charged)",
                    gauges.dedup_receptions,
                    dedup_bytes(gauges.dedup_receptions, threads),
                    gauges.dedup.limit(),
                    gauges.dedup.held(),
                ));
            }
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
    /// full. The decode the slices share is charged by itself while they wait
    /// (`budget::Store::Decoded`), so the queues hold nothing uncharged.
    pub fn route(&self, producer: usize, decoded: &Arc<Decoded>, area: Option<Region>, raw: Raw) {
        for (thread, slice) in split(decoded, self.width(), area, raw) {
            self.send(producer, thread, Envelope::Slice(slice));
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
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use std::collections::HashMap;
    use tally_wire::clocks::recorded::aligned;

    /// Epoch number `number`.
    fn e(number: u64) -> Epoch {
        Epoch::of(tally_wire::clocks::recorded::mono(number * EPOCH_MS))
    }
    use tally_wire::{BatchContent, Identity, Observation};

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
        let batch =
            crate::anchors::anchored(&identity, &content).map_err(|error| error.to_string())?;
        Decoded::from_verified(batch, aligned(stamp_ms), ingest_seq)
            .map_err(|undecodable| undecodable.error.to_string())
    }

    #[test]
    fn a_batch_splits_into_each_threads_receptions_once_in_order() -> Result<(), String> {
        let decoded = decoded(200, 0, 0)?;
        let slices = split(&decoded, 7, None, tally_wire::clocks::recorded::raw(0));
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
        let at = tally_wire::clocks::recorded::mono;
        let mut watermark = Watermark::new(2);
        assert_eq!(watermark.tick(0, at(10)), None);
        assert_eq!(watermark.tick(1, at(5)), Some(at(5)));
        assert_eq!(watermark.tick(1, at(3)), Some(at(5)));
        assert_eq!(watermark.tick(1, at(20)), Some(at(10)));
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
        let mut shard = MessageShard::with_capacity(64);
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
        let mut shard = MessageShard::with_capacity(64);
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

    /// The generations are allocated once, at their capacity, and never grow or shrink: a
    /// generation filled to its capacity (half its messages heard in two areas, half for the
    /// stream alone: every entry and every link it holds), rotated and filled again, allocates
    /// nothing more and holds what it kept. Before, a table doubled as it filled,
    /// mid-epoch, and the plan held room for every table to double.
    #[test]
    fn a_generation_holds_its_capacity_and_never_grows() -> Result<(), String> {
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
        let capacity = 1_000;
        let mut shard = MessageShard::with_capacity(capacity);
        let allocated = shard.bytes();
        assert_eq!(allocated, DEDUP_GENERATIONS * generation_bytes(capacity));
        assert!(allocated <= DEDUP_GENERATIONS * (capacity * DEDUP_ENTRY_BYTES + DEDUP_SLOT_BYTES));
        // Fingerprints spread as the keyed ones are: the low byte any shard, the high half any slot.
        let fp = |n: u64| (u128::from(n.wrapping_mul(0x9e37_79b9_7f4a_7c15)) << 64) | u128::from(n);
        for round in 0..2 * DEDUP_GENERATIONS as u64 {
            for n in 0..capacity as u64 {
                let message = fp(round * capacity as u64 + n);
                if n < capacity as u64 / 2 {
                    assert_eq!(
                        shard.decide(message, Some(a)),
                        Decision {
                            stream: true,
                            regional: true
                        }
                    );
                    assert_eq!(
                        shard.decide(message, Some(b)),
                        Decision {
                            stream: false,
                            regional: true
                        }
                    );
                } else {
                    assert_eq!(
                        shard.decide(message, None),
                        Decision {
                            stream: true,
                            regional: false
                        }
                    );
                }
            }
            // Every one of them remembered, in its areas.
            for n in 0..capacity as u64 {
                let message = fp(round * capacity as u64 + n);
                let area = if n < capacity as u64 / 2 {
                    Some(b)
                } else {
                    None
                };
                assert_eq!(
                    shard.decide(message, area),
                    Decision {
                        stream: false,
                        regional: false
                    }
                );
            }
            assert_eq!(shard.bytes(), allocated);
            shard.rotate(1);
        }
        // Past its links, a generation keeps no more and grows no more.
        let mut full = MessageShard::with_capacity(2);
        for n in 0..4 {
            full.decide(fp(n), Some(a));
        }
        assert_eq!(full.len(), 2);
        assert_eq!(full.bytes(), DEDUP_GENERATIONS * generation_bytes(2));
        Ok(())
    }

    /// An epoch with more receptions on a thread than its generation holds is refused whole,
    /// before any is decided, and forgotten: the next epoch, within it, is decided as if the
    /// refused one never was. Which epoch is refused follows its receptions alone.
    #[test]
    fn an_epoch_past_the_generations_capacity_is_refused_whole() -> Result<(), String> {
        let words = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&words);
        let sink: Sink = Arc::new(move |frozen| match kept.lock() {
            Ok(mut kept) => {
                kept.push(frozen);
                Ok(())
            }
            Err(_) => Err(Box::new(frozen)),
        });
        // Three receptions an epoch planned: a generation of four, on one thread.
        let gauges = Gauges {
            dedup_receptions: 3,
            ..Gauges::unlimited()
        };
        let mut thread = MessageThread::new(
            0,
            1,
            1,
            Admission::new(1, sink, Gauge::unlimited(Store::Epochs)),
            gauges,
        );
        assert!(thread.tables_charged());
        assert_eq!(thread.messages.capacity(), 4);
        for n in 1..=5 {
            thread.take(0, Envelope::Slice(copy_of(n, 100)?));
        }
        thread.take(0, tick(1_000));
        for n in 1..=4 {
            thread.take(0, Envelope::Slice(copy_of(n, 1_100)?));
        }
        thread.take(0, tick(2_000));
        thread.take(0, tick(3_000));
        assert_eq!(word_of(&words, 0)?, Some((true, Vec::new())));
        let (refused, mut kept) = word_of(&words, 1)?.ok_or("no word for epoch 1")?;
        kept.sort_unstable();
        assert!(!refused);
        assert_eq!(kept, vec![1, 2, 3, 4]);
        Ok(())
    }

    /// What the plan holds for the generations ([`DEDUP_BYTES_PER_RECEPTION_PER_SEC`] a reception
    /// a second, and [`DEDUP_FIXED_BYTES`]) is at least what they allocate on any number of
    /// threads, and a store holding exactly that sizes them to fit it ([`Gauges::of`]'s inverse).
    #[test]
    fn the_plan_holds_what_the_generations_allocate() {
        for receptions in [0, 1, 3, 255, 256, 10_000, 1_234_567, 12_470_000] {
            let planned =
                receptions * DEDUP_SLOTS_PER_RECEPTION * DEDUP_ENTRY_BYTES + DEDUP_FIXED_BYTES;
            for threads in [1, 2, 3, 7, 16, 64, 256] {
                assert!(
                    dedup_bytes(receptions, threads) <= planned,
                    "{receptions} on {threads}: {} > {planned}",
                    dedup_bytes(receptions, threads)
                );
            }
            let sized = planned.saturating_sub(DEDUP_FIXED_BYTES)
                / (DEDUP_SLOTS_PER_RECEPTION * DEDUP_ENTRY_BYTES);
            assert_eq!(sized, receptions);
        }
        assert_eq!(
            DEDUP_BYTES_PER_RECEPTION_PER_SEC,
            DEDUP_SLOTS_PER_RECEPTION * DEDUP_ENTRY_BYTES * EPOCH_MS as usize / 1_000
        );
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
        let batch =
            crate::anchors::anchored(&identity, &content).map_err(|error| error.to_string())?;
        let decoded = Decoded::from_verified(batch, aligned(stamp_ms), 0)
            .map_err(|undecodable| undecodable.error.to_string())?;
        split(
            &decoded,
            1,
            None,
            tally_wire::clocks::recorded::raw(stamp_ms),
        )
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
        Envelope::Tick(Stamp::recorded(stamp_ms, 0, stamp_ms, stamp_ms, true))
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
            (2, 999),
            (1, 1_500),
            (1, 2_000),
            (2, 2_999),
            (1, 3_000),
        ] {
            thread.take(0, Envelope::Slice(copy_of(n, stamp_ms)?));
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
    fn word_of(words: &Mutex<Vec<Frozen>>, epoch: u64) -> Result<Option<(bool, Vec<u8>)>, String> {
        let words = words.lock().map_err(|error| error.to_string())?;
        Ok(words
            .iter()
            .find(|word| word.epoch == Some(e(epoch)))
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

    /// With nothing flowing, the words a thread tells the sealer as its ticks close empty epochs
    /// carry the newest tick's judging clock and whether it judged (`Frozen::judged`), so the
    /// sealer's watermark, and the MLAT it steps, go by the judging clock even while no batch
    /// comes: here a minute ahead of the monotonic one, as after the host's clock was stepped.
    /// Before, a word with no epoch could carry no reading, and the watermark fell back on none.
    #[test]
    fn with_nothing_flowing_the_watermark_carries_the_judging_clock() {
        const AHEAD_MS: u64 = 60_000;
        let (mut thread, words) = thread();
        for mono_ms in (500..=10_500).step_by(1_000) {
            thread.take(
                0,
                Envelope::Tick(Stamp::recorded(
                    mono_ms,
                    0,
                    mono_ms + AHEAD_MS,
                    mono_ms,
                    true,
                )),
            );
        }
        thread.resume();
        let words: Vec<(Option<Epoch>, Option<Stamp>)> = words
            .lock()
            .map(|words| words.iter().map(|word| (word.epoch, word.judged)).collect())
            .unwrap_or_default();
        assert!(!words.is_empty(), "no word for the sealer");
        assert!(
            words.iter().all(|(epoch, _)| epoch.is_none()),
            "an epoch with nothing in it"
        );
        let last = words.last().and_then(|(_, judged)| *judged);
        assert_eq!(
            last.map(|judged| (judged.mono_ms(), judged.judged().ms(), judged.judging())),
            Some((10_500, 10_500 + AHEAD_MS, true)),
        );
    }

    /// A slice is a tick of both clocks: the epoch it closes is signed by the judging clock its
    /// own stamp read (`Frozen::judged`), here a minute ahead of the monotonic one, with no tick
    /// between. Before, it moved only the monotonic watermark, and the epoch went to the sealer
    /// with no judging reading at all.
    #[test]
    fn a_slice_closes_its_epochs_by_its_own_judging_clock() -> Result<(), String> {
        const AHEAD_MS: u64 = 60_000;
        let slice = |n: u8, mono_ms: u64| -> Result<Slice, String> {
            let decoded = decoded(1, mono_ms, u64::from(n))?;
            let at = tally_wire::clocks::recorded::moment(mono_ms, mono_ms + AHEAD_MS);
            let decoded = Arc::new(
                Decoded::from_verified(decoded.batch().clone(), at, u64::from(n))
                    .map_err(|undecodable| undecodable.error.to_string())?,
            );
            split(
                &decoded,
                1,
                None,
                tally_wire::clocks::recorded::raw(mono_ms),
            )
            .pop()
            .map(|(_, slice)| slice)
            .ok_or_else(|| "no slice".to_owned())
        };
        let (mut thread, words) = thread();
        thread.take(0, Envelope::Slice(slice(1, 500)?));
        thread.take(0, Envelope::Slice(slice(2, 1_600)?));
        thread.resume();
        let first = words
            .lock()
            .map_err(|error| error.to_string())?
            .iter()
            .find(|word| word.epoch == Some(e(0)))
            .map(|word| word.judged)
            .ok_or("the first epoch was not closed")?;
        assert_eq!(
            first.map(|judged| (judged.mono_ms(), judged.judged().ms(), judged.judging())),
            Some((1_600, 1_600 + AHEAD_MS, true)),
        );
        Ok(())
    }

    /// A batch after an idle gap longer than the window, read before its producer's tick, is kept:
    /// its stamp is its producer's tick, so what came before closes and settles before it asks the
    /// window. Before, the window had not moved, and it was let go.
    #[test]
    fn a_batch_after_an_idle_gap_is_kept() -> Result<(), String> {
        let (mut thread, words) = thread();
        thread.take(0, Envelope::Slice(copy_of(1, 500)?));
        thread.take(0, tick(500));
        // The next batch, 10 s later, routed before its producer ticks (ingest: work, then tick).
        thread.take(0, Envelope::Slice(copy_of(2, 10_500)?));
        thread.take(0, tick(10_500));
        thread.take(0, tick(20_000));
        thread.resume();
        let w = word_of(&words, 10)?;
        assert_eq!(
            w,
            Some((false, vec![2])),
            "the batch after the gap was lost"
        );
        Ok(())
    }

    /// What an admission allocates when it is made is within what it charged beside the trees it
    /// holds later (the epochs settling, and each thread's open). Before, the ledger's lists of how
    /// far each thread posted and the verdict each awaits were allocated uncharged.
    #[test]
    fn an_admission_allocates_within_what_it_charged() {
        use tally_counting::Counting;
        let threads = SHARDS;
        let sink: Sink = Arc::new(|_| Ok(()));
        let epochs = Gauge::unlimited(Store::Epochs);
        let base = Counting::live();
        let admission = Admission::new(threads, sink, epochs);
        let allocated = Counting::since(base) - std::mem::size_of_val(&*admission) as isize;
        let charged = admission_fixed_bytes(threads)
            - settling_fixed_bytes(threads)
            - threads * Tree::<Epoch, Open>::bytes_at(EPOCHS_OPEN as usize);
        assert!(
            allocated <= charged as isize,
            "{allocated} allocated past {charged}"
        );
    }

    /// Past `LET_GO_RUNS` runs the nearest two are joined, but never across an epoch a thread has
    /// taken: one thread holds it open while another, asking later, would be told it was let go.
    /// Before, the nearest gap was joined whatever lay in it. The runs merge in place, keeping the
    /// room reserved for them; before, they were rebuilt into a fresh list that dropped it.
    #[test]
    fn runs_let_go_are_never_joined_across_a_taken_epoch() {
        let mut window = Window {
            let_go: Vec::with_capacity(LET_GO_RUNS + 1),
            ..Window::default()
        };
        let room = window.let_go.capacity();
        // Epoch 101 taken, with a run let go on either side of it, one epoch apart: the nearest gap.
        assert_eq!(window.admit(e(101)), Admit::Open);
        for epoch in [99, 100, 102, 103] {
            window.let_go(e(epoch));
        }
        assert_eq!(window.let_go, vec![e(99)..e(101), e(102)..e(104)]);
        // Fifteen more runs, each two epochs from the last: seventeen in all.
        for run in 0..15 {
            window.let_go(e(106 + 3 * run));
        }
        assert!(window.let_go.len() <= LET_GO_RUNS, "{:?}", window.let_go);
        assert!(
            !window.is_let_go(e(101)),
            "the taken epoch was let go: {:?}",
            window.let_go
        );
        assert_eq!(
            window.admit(e(101)),
            Admit::Open,
            "a later thread is refused it"
        );
        assert_eq!(
            window.let_go.capacity(),
            room,
            "the reserved room was dropped"
        );
    }

    /// An epoch inside the window that no thread let go is kept, though epochs on either side of
    /// it were let go. Before, the epochs let go were one range per thread, first to last, and an
    /// epoch between them taken in full was refused.
    #[test]
    fn an_epoch_between_two_let_go_is_kept() -> Result<(), String> {
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
        // Two producers: one that read epoch 17 early does not move the window, which follows the
        // slower (`Watermark`), so epoch 17 is let go while epoch 8's run is still held.
        let gauges = Gauges::unlimited();
        let mut zero = MessageThread::new(0, 2, 2, Arc::clone(&admission), gauges.clone());
        let mut one = MessageThread::new(1, 2, 2, Arc::clone(&admission), gauges);
        let at = |epoch: u64| epoch * EPOCH_MS + 500;
        zero.take(0, Envelope::Slice(copy_of(1, at(0))?));
        // Epoch 8 is past the window [0, 8): let go.
        zero.take(0, Envelope::Slice(copy_of(2, at(8))?));
        for t in [&mut zero, &mut one] {
            for producer in 0..2 {
                t.take(producer, tick(at(5) - 500));
            }
        }
        zero.resume();
        one.resume();
        // Settled to 5: epoch 9 is taken, and the window is [9, 17).
        zero.take(0, Envelope::Slice(copy_of(3, at(9))?));
        assert!(zero.open.contains_key(&e(9)));
        // Epoch 17 is past it: let go, a second run beside epoch 8's.
        zero.take(1, Envelope::Slice(copy_of(4, at(17))?));
        assert!(!zero.open.contains_key(&e(17)));
        // Epoch 11, inside the window and between the two runs, never let go by anyone.
        one.take(0, Envelope::Slice(copy_of(5, at(11))?));
        zero.take(0, Envelope::Slice(copy_of(6, at(11))?));
        for t in [&mut zero, &mut one] {
            for producer in 0..2 {
                t.take(producer, tick(at(30)));
            }
        }
        zero.resume();
        one.resume();
        zero.resume();
        let words = words.lock().map_err(|e| e.to_string())?;
        assert!(
            words
                .iter()
                .find(|w| w.epoch == Some(e(9)))
                .is_some_and(|w| !w.refused),
            "epoch 9, in the window, refused"
        );
        let kept = |epoch: u64| {
            words
                .iter()
                .any(|w| w.epoch == Some(e(epoch)) && !w.refused)
        };
        assert!(kept(11), "epoch 11, in the window, refused");
        assert!(!kept(8), "epoch 8, let go, was kept");
        Ok(())
    }

    /// An epoch told admitted is always sent: its word's place is charged before its verdict, and
    /// an epoch with no room for it is refused. Before, the verdict was written first, and a word
    /// with no room for its place was dropped while every thread kept its messages.
    #[test]
    fn an_epoch_told_admitted_is_never_lost_on_its_way() -> Result<(), String> {
        let words = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&words);
        let sink: Sink = Arc::new(move |frozen| match kept.lock() {
            Ok(mut kept) => {
                kept.push(frozen);
                Ok(())
            }
            Err(_) => Err(Box::new(frozen)),
        });
        let part_bytes = 4_096;
        let epochs = Gauge::new(Store::Epochs, admission_fixed_bytes(1) + part_bytes);
        let admission = Admission::new(1, sink, Arc::clone(&epochs));
        assert!(admission.charged());
        // The thread's part, charged up to the store's limit (its batches and decisions).
        let charge = epochs
            .try_charge(part_bytes)
            .ok_or("no room for the part")?;
        let part = Frozen {
            thread: 0,
            epoch: Some(e(0)),
            closed_before: Some(e(1)),
            charge,
            ..Frozen::default()
        };
        admission.post(0, e(0), Some(part));
        admission.progress(0, e(1), None);
        let verdict = admission.verdict(0, e(0));
        let words = words.lock().map_err(|e| e.to_string())?;
        assert!(
            verdict == Some(false) || words.iter().any(|w| w.epoch == Some(e(0))),
            "told admitted, never sent"
        );
        Ok(())
    }

    /// At the start, an epoch taken on one thread a moment after a newer one was taken on another
    /// is kept. Before, the first epoch any thread took pinned the window's floor, and the older
    /// one was lost.
    #[test]
    fn an_older_epoch_taken_after_a_newer_at_the_start_is_kept() -> Result<(), String> {
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
        let mut zero = MessageThread::new(0, 2, 2, Arc::clone(&admission), Gauges::unlimited());
        let mut one = MessageThread::new(1, 2, 2, Arc::clone(&admission), Gauges::unlimited());
        // Producer 1 stamped epoch 5 a moment after producer 0 stamped epoch 4, but thread 0
        // took its slice first.
        zero.take(1, Envelope::Slice(copy_of(1, 5_100)?));
        one.take(0, Envelope::Slice(copy_of(2, 4_900)?));
        for t in [&mut zero, &mut one] {
            t.take(0, tick(10_000));
            t.take(1, tick(10_000));
        }
        zero.resume();
        one.resume();
        zero.resume();
        let words = words.lock().map_err(|e| e.to_string())?;
        let late: u64 = words.iter().map(|w| w.late + w.past).sum();
        assert!(
            words.iter().any(|w| w.epoch == Some(e(4))),
            "epoch 4 lost at start"
        );
        assert_eq!(late, 0);
        Ok(())
    }

    /// The epochs open and settling are allocated within what the admission and the epochs' store
    /// were charged, read from an allocator counting this thread's bytes, and the threads settle
    /// no more than the window at once, whatever the schedule: here one thread takes every epoch
    /// while the other keeps up, falls behind for a stretch, takes a slice now and then out of
    /// step, and catches up. The bound is the window's, held by every thread's first slice of an
    /// epoch asking it ([`Window`]), never by the schedule. Before, the epochs settling were held
    /// to the window only by the order the threads happened to post them in.
    #[test]
    fn the_epochs_settling_allocate_within_what_the_admission_was_charged() -> Result<(), String> {
        use tally_counting::Counting;
        let sink: Sink = Arc::new(|_| Ok(()));
        let epochs = Gauge::unlimited(Store::Epochs);
        let gauges = Gauges {
            epochs: Arc::clone(&epochs),
            dedup: Gauge::unlimited(Store::Dedup),
            dedup_receptions: 1 << 10,
        };
        let admission = Admission::new(2, sink, Arc::clone(&epochs));
        let mut zero = MessageThread::new(0, 2, 1, Arc::clone(&admission), gauges.clone());
        let mut one = MessageThread::new(1, 2, 1, Arc::clone(&admission), gauges);
        const ROUNDS: u64 = 120;
        let at = |epoch: u64| epoch * EPOCH_MS + 500;
        let mut slices = (0..ROUNDS)
            .map(|epoch| Ok((copy_of(1, at(epoch))?, copy_of(2, at(epoch))?)))
            .collect::<Result<Vec<_>, String>>()?
            .into_iter();
        let held = epochs.held() as isize;
        let base = Counting::live();
        for epoch in 0..ROUNDS {
            let (first, second) = slices.next().ok_or("a slice")?;
            zero.take(0, Envelope::Slice(first));
            zero.take(0, tick(at(epoch) + 500));
            // Thread 1 keeps up, but for a stretch of twenty epochs it hears nothing, and every
            // seventh epoch it is sent a slice of out of step.
            let behind = (40..60).contains(&epoch);
            if epoch % 7 == 0 {
                one.take(0, Envelope::Slice(second));
            }
            if !behind {
                one.take(0, tick(at(epoch) + 500));
            }
            zero.resume();
            one.resume();
            let pending = admission
                .ledger
                .lock()
                .map_or(0, |ledger| ledger.pending.len());
            assert!(pending <= EPOCHS_OPEN as usize, "{pending} settling");
            assert!(zero.open.len() <= EPOCHS_OPEN as usize);
            assert!(one.open.len() <= EPOCHS_OPEN as usize);
            let allocated = Counting::since(base);
            let charged = epochs.held() as isize - held + admission_fixed_bytes(2) as isize;
            assert!(allocated <= charged, "{allocated} allocated past {charged}");
        }
        Ok(())
    }

    /// The threads hold no more than the window of epochs open or settling: a slice of an epoch
    /// past it is let go, counted as past the window, and its epoch is let go on every thread,
    /// even one that comes to it once the window has moved up to it; an epoch inside the window is
    /// kept.
    #[test]
    fn an_epoch_past_the_window_is_let_go_whole_everywhere() -> Result<(), String> {
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
        let mut zero = MessageThread::new(0, 2, 1, Arc::clone(&admission), Gauges::unlimited());
        let mut one = MessageThread::new(1, 2, 1, Arc::clone(&admission), Gauges::unlimited());
        let at = |epoch: u64| epoch * EPOCH_MS + 500;
        let mut n = 0u8;
        let mut slice = |epoch: u64| {
            n += 1;
            copy_of(n, at(epoch))
        };
        // Thread 0 is sent one slice of every epoch to 20 while thread 1 hears nothing: it decides
        // epoch 0 and waits for it to settle, and holds the rest of the window.
        for epoch in 0..=20 {
            zero.take(0, Envelope::Slice(slice(epoch)?));
            assert!(zero.open.len() < EPOCHS_OPEN as usize);
            assert!(zero.open.bytes() <= Tree::<Epoch, Open>::bytes_at(EPOCHS_OPEN as usize));
        }
        assert_eq!(zero.open.len(), EPOCHS_OPEN as usize - 1);
        // A tree held at the window, on each thread, is within what the admission was charged
        // beside its outbox, its epochs settling and its runs let go.
        let trees = admission_fixed_bytes(2)
            - outbox_fixed_bytes(2)
            - settling_fixed_bytes(2)
            - ledger_fixed_bytes(2)
            - tally_wire::footprint::vec::<Range<Epoch>>(LET_GO_RUNS + 1);
        assert!(
            2 * zero.open.bytes() <= trees,
            "{} past {trees}",
            zero.open.bytes()
        );
        // Thread 1 comes to epoch 9, let go past the window by thread 0: it lets it go too, though
        // the window has moved up to it.
        one.take(0, tick(at(2) - 500));
        zero.resume();
        one.take(0, Envelope::Slice(slice(9)?));
        assert!(!one.open.contains_key(&e(9)));
        for thread in [&mut zero, &mut one] {
            thread.take(0, tick(at(30)));
        }
        zero.resume();
        one.resume();
        zero.resume();
        let words = words.lock().map_err(|error| error.to_string())?;
        let word = |epoch: u64| words.iter().find(|word| word.epoch == Some(e(epoch)));
        assert!(word(9).is_none_or(|word| word.refused), "epoch 9 was kept");
        for epoch in 0..EPOCHS_OPEN {
            assert!(
                word(epoch).is_some_and(|word| !word.refused),
                "epoch {epoch} was not kept"
            );
        }
        // Every slice let go past the window was counted so, and none as late.
        let past: u64 = words.iter().map(|word| word.past).sum();
        let late: u64 = words.iter().map(|word| word.late).sum();
        assert_eq!((past, late), (14, 0));
        Ok(())
    }

    /// An open epoch's list of slices is charged what it allocates as it grows, beside each
    /// slice's runs and decisions. Before, each slice was charged one place in a list that
    /// doubled, so the list kept up to as many places again uncharged.
    #[test]
    fn an_open_epochs_slices_are_charged_what_their_list_allocates() -> Result<(), String> {
        use tally_counting::Counting;
        let (mut thread, _words) = thread();
        let slices = (1..=200u8)
            .map(|n| copy_of(n, 500))
            .collect::<Result<Vec<_>, String>>()?;
        let mut slices = slices.into_iter();
        // The epoch open, so what follows is its list alone.
        let first = slices.next().ok_or("no slice")?;
        let mut runs = first.bytes();
        thread.take(0, Envelope::Slice(first));
        let epochs = Arc::clone(&thread.gauges.epochs);
        let listed =
            |thread: &MessageThread| thread.open.get(&e(0)).map_or(0, |open| open.slices.bytes());
        let (base, at_base) = (Counting::live(), listed(&thread));
        for slice in slices {
            runs += slice.bytes();
            thread.take(0, Envelope::Slice(slice));
            let list = listed(&thread);
            assert_eq!(Counting::since(base), (list - at_base) as isize);
            assert_eq!(epochs.held(), runs + list);
        }
        Ok(())
    }

    /// What waits for a stalled sealer is charged what it allocates as it comes and goes: every
    /// word its own bytes and its share of the outbox's spare room, the outbox's fixed spare and
    /// the marks with the admission. Before, each word was charged one place in a deque that
    /// doubled, so its spare room, up to as many places again, was charged nothing.
    #[test]
    fn what_waits_for_the_sealer_is_charged_what_it_allocates() -> Result<(), String> {
        use tally_counting::Counting;
        let taking = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink: Sink = {
            let taking = Arc::clone(&taking);
            Arc::new(move |frozen| {
                if taking.load(Ordering::Relaxed) {
                    Ok(())
                } else {
                    Err(Box::new(frozen))
                }
            })
        };
        let epochs = Gauge::unlimited(Store::Epochs);
        let admission = Admission::new(2, sink, Arc::clone(&epochs));
        assert_eq!(epochs.held(), admission_fixed_bytes(2));
        // One epoch settled first, so the ledger's tables are as they stay.
        let mut epoch = 0;
        let settle = |admission: &Admission, epoch: &mut u64| {
            admission.post(0, e(*epoch), None);
            admission.progress(0, e(*epoch + 1), None);
            admission.progress(1, e(*epoch + 1), None);
            *epoch += 1;
        };
        settle(&admission, &mut epoch);
        taking.store(true, Ordering::Relaxed);
        admission.flush();
        taking.store(false, Ordering::Relaxed);
        let base = Counting::live();
        let held = epochs.held();
        let mut mix = 7u64;
        for round in 0..60 {
            mix = mix.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            for _ in 0..(mix >> 58) + if round % 13 == 0 { 300 } else { 0 } {
                settle(&admission, &mut epoch);
                let allocated = Counting::since(base);
                assert!(
                    allocated <= (epochs.held() - held) as isize,
                    "{allocated} allocated for {} charged",
                    epochs.held() - held
                );
            }
            taking.store(round % 3 == 0, Ordering::Relaxed);
            admission.flush();
            taking.store(false, Ordering::Relaxed);
            let allocated = Counting::since(base);
            assert!(allocated <= (epochs.held() - held) as isize);
        }
        taking.store(true, Ordering::Relaxed);
        admission.flush();
        assert_eq!(epochs.held(), admission_fixed_bytes(2));
        assert!(Counting::since(base) <= 0);
        Ok(())
    }

    /// An epoch refused whole lets its slices go and releases what it was charged for them, all of
    /// it: what it charged was what it allocated for them, never their decodes, which charge
    /// themselves and go with their last holder.
    #[test]
    fn a_refused_epoch_lets_its_slices_go_and_holds_no_charge() -> Result<(), String> {
        let decodes = (0..4u64)
            .map(|at| decoded(20, 0, at))
            .collect::<Result<Vec<_>, String>>()?;
        let epochs = Gauge::unlimited(Store::Epochs);
        let slices: Vec<Slice> = decodes
            .iter()
            .map(|decode| Slice {
                decoded: Arc::clone(decode),
                ranges: std::iter::once(0..20).collect(),
                area: None,
                raw: tally_wire::clocks::recorded::raw(0),
            })
            .collect();
        let mut charge = epochs.empty();
        for slice in &slices {
            assert!(charge.try_grow(slice.bytes()));
        }
        // What a slice costs its epoch is its runs and its receptions' decisions, never its decode
        // (its place in the list is the list's, charged as it grows).
        assert_eq!(
            slices[0].bytes(),
            std::mem::size_of::<Range<u32>>()
                + std::mem::size_of::<Arc<Decoded>>()
                + 20 * DECISION_BYTES_PER_RECEPTION
        );
        assert!(slices[0].bytes() <= 20 * EPOCH_BYTES_PER_RECEPTION);
        let mut open = Open {
            slices: Deque::of(slices),
            charge,
            refused: false,
        };
        open.refuse();
        assert!(open.refused && open.slices.is_empty());
        assert_eq!((open.charge.bytes(), epochs.held()), (0, 0));
        assert!(decodes.iter().all(|decode| Arc::strong_count(decode) == 1));
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
            dedup_receptions: TEST_DEDUP_RECEPTIONS,
        };
        let mut zero = MessageThread::new(0, 2, 1, Arc::clone(&admission), tight);
        let mut one = MessageThread::new(1, 2, 1, Arc::clone(&admission), Gauges::unlimited());
        one.take(0, Envelope::Slice(copy_of(7, 500)?));
        zero.take(0, Envelope::Slice(copy_of(1, 500)?));
        zero.take(0, Envelope::Slice(copy_of(2, 600)?));
        // Thread 1 closes epoch 0 first, deciding message 7 in it; thread 0 then refuses it.
        one.take(0, tick(1_000));
        one.take(0, Envelope::Slice(copy_of(7, 1_500)?));
        zero.take(0, tick(1_000));
        one.take(0, tick(2_000));
        zero.take(0, tick(2_000));
        assert_eq!(word_of(&words, 0)?, Some((true, Vec::new())));
        assert_eq!(word_of(&words, 1)?, Some((false, vec![7])));
        Ok(())
    }

    /// RFC-0181, "Memory is charged once, for its life": a batch split across two threads is
    /// charged once, by its decode and its signed bytes, whichever threads hold it and whether its
    /// epoch is refused on one of them; each thread's epochs are charged what they allocate for
    /// their slices and no more. Before, each thread charged its slice's share of the decode, a
    /// refused one kept that share while the other's slice held the decode, and the decode was
    /// charged again in every subscriber's queue.
    #[test]
    fn a_batch_split_across_threads_is_charged_once_by_its_decode() -> Result<(), String> {
        let sink: Sink = Arc::new(|_| Ok(()));
        let epochs = Gauge::unlimited(Store::Epochs);
        let admission = Admission::new(2, sink, Arc::clone(&epochs));
        let store = Gauge::unlimited(Store::Decoded);
        // Thread 0's epochs are full: its slice refuses the epoch there.
        let tight = Gauges {
            epochs: Gauge::new(Store::Epochs, 1),
            dedup: Gauge::unlimited(Store::Dedup),
            dedup_receptions: TEST_DEDUP_RECEPTIONS,
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
                dedup_receptions: TEST_DEDUP_RECEPTIONS,
            },
        );
        // One batch whose receptions fall on both threads, decoded as ingest decodes it.
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
            let batch =
                crate::anchors::anchored(&identity, &content).map_err(|error| error.to_string())?;
            let decoded = crate::ingest::Stages::decode_owned(
                batch,
                Stamp::recorded(500, 0, 500, 500, true),
                &store,
                crate::budget::Covered::process(),
            )
            .map_err(|error| format!("{error:?}"))?;
            slices = split(&decoded, 2, None, tally_wire::clocks::recorded::raw(500));
        }
        let decoded = Arc::clone(&slices[0].1.decoded);
        let once = decoded.footprint() + decoded.batch().footprint();
        let mut parts = slices.into_iter();
        let ((_, first), (_, second)) = parts
            .next()
            .zip(parts.next())
            .ok_or_else(|| "two slices".to_owned())?;
        let second_bytes = second.bytes();
        one.take(0, Envelope::Slice(second));
        zero.take(0, Envelope::Slice(first));
        // Refused on thread 0, held on thread 1: the decode charged once, by itself, and thread
        // 1's epoch only what it allocated for its slice: its runs and decisions, and its place in
        // the epoch's list.
        assert_eq!(tight.epochs.held(), 1);
        // Beside what the admission allocates whatever waits for the sealer.
        let fixed = admission_fixed_bytes(2);
        assert_eq!(
            epochs.held(),
            fixed + second_bytes + std::mem::size_of::<Slice>()
        );
        assert_eq!(store.held(), once);
        // Settled once thread 1 closes it too: refused everywhere, its slices let go.
        zero.take(0, tick(1_000));
        one.take(0, tick(1_000));
        zero.resume();
        assert_eq!(epochs.held(), fixed);
        assert_eq!(store.held(), once);
        drop(decoded);
        assert_eq!(store.held(), 0);
        Ok(())
    }

    /// RFC-0181 §9: an epoch's word is charged its lists of decisions, from before any reception
    /// is decided (with its slices, at the most they can be) until the sealer lets it go, and
    /// nothing for its batches, whose decodes charge themselves. The lists were charged nothing
    /// once: some 24 bytes a reception waited uncounted for the sealer.
    #[test]
    fn an_epochs_word_is_charged_its_decisions_beside_its_batches() -> Result<(), String> {
        let (mut thread, words) = thread();
        for n in 1..=5 {
            thread.take(0, Envelope::Slice(copy_of(n, 500)?));
        }
        thread.take(0, tick(2_000));
        let words = words.lock().map_err(|error| error.to_string())?;
        let word = words
            .iter()
            .find(|word| word.epoch == Some(e(0)))
            .ok_or("no word for epoch 0")?;
        assert_eq!(word.stream.len(), 5);
        // Its own bytes (and what the sealer's queue holds for a word), never its decodes'.
        let batches: usize = word.batches.iter().map(|batch| batch.footprint()).sum();
        assert!(
            word.charge.bytes() >= word.own_bytes()
                && word.charge.bytes() < word.own_bytes() + batches,
            "{} charged for {} of its own beside {batches} of decodes",
            word.charge.bytes(),
            word.own_bytes()
        );
        Ok(())
    }

    /// Under a sealer's backlog, a thread's oldest mark is told as soon as the words queued before
    /// it are, and the newer ones after: the sealer's watermark moves on a step at a time as the
    /// backlog drains. Before, every newer mark was merged into the one waiting and took the
    /// newest's place, behind every word queued since.
    #[test]
    fn a_threads_mark_is_told_as_soon_as_the_words_before_it_are() -> Result<(), String> {
        let taking = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let words = Arc::new(Mutex::new(Vec::new()));
        let sink: Sink = {
            let (taking, words) = (Arc::clone(&taking), Arc::clone(&words));
            Arc::new(move |frozen: Frozen| {
                if !taking.load(Ordering::Relaxed) {
                    return Err(Box::new(frozen));
                }
                match words.lock() {
                    Ok(mut words) => {
                        words.push((frozen.thread, frozen.epoch, frozen.closed_before));
                        Ok(())
                    }
                    Err(_) => Err(Box::new(frozen)),
                }
            })
        };
        let admission = Admission::new(2, sink, Gauge::unlimited(Store::Epochs));
        for epoch in 0..3 {
            let part = Frozen {
                epoch: Some(e(epoch)),
                closed_before: Some(e(epoch + 1)),
                ..Frozen::default()
            };
            admission.post(0, e(epoch), Some(part));
            admission.progress(0, e(epoch + 1), None);
            admission.progress(1, e(epoch + 1), None);
        }
        taking.store(true, Ordering::Relaxed);
        admission.flush();
        let words = words.lock().map_err(|error| error.to_string())?;
        let first_mark = words
            .iter()
            .position(|(thread, epoch, _)| *thread == 1 && epoch.is_none())
            .ok_or("no mark of thread 1")?;
        let second_epoch = words
            .iter()
            .position(|(_, epoch, _)| *epoch == Some(e(1)))
            .ok_or("no word for epoch 1")?;
        assert_eq!(words[first_mark].2, Some(e(1)), "{words:?}");
        assert!(first_mark < second_epoch, "{words:?}");
        Ok(())
    }

    /// RFC-0181 §9: what waits for a stalled sealer is charged and bounded. A thousand epochs
    /// refused while the sealer takes nothing leave as many refused words as the store holds and
    /// two markers a thread at most (the oldest, and every newer as one); every other epoch is a gap in the words' numbers, which the sealer,
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
        let epochs = Gauge::new(
            Store::Epochs,
            admission_fixed_bytes(2) + ROOM * (std::mem::size_of::<Frozen>() + OUTBOX_SHARE_BYTES),
        );
        let admission = Admission::new(2, sink, Arc::clone(&epochs));
        const EPOCHS: u64 = 1_000;
        for epoch in 0..EPOCHS {
            admission.post(0, e(epoch), None);
            admission.progress(0, e(epoch + 1), None);
            admission.progress(1, e(epoch + 1), None);
        }
        let waiting = admission
            .ledger
            .lock()
            .map_err(|error| error.to_string())?
            .waiting();
        assert!(waiting <= ROOM + 2 * 2, "{waiting} words wait");
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
        // The sealer done with them, their charges are let go: what is left is what the admission
        // allocates whatever waits.
        assert_eq!(epochs.held(), admission_fixed_bytes(2));
        drop(admission);
        assert_eq!(epochs.held(), 0);
        Ok(())
    }

    /// A slice for an epoch its thread has already closed is late: let go and counted, never
    /// decided in a later epoch, and the epochs around it are decided whole.
    #[test]
    fn a_late_slice_is_counted_and_never_decided_or_costs_another_epoch() -> Result<(), String> {
        let (mut thread, words) = thread();
        thread.take(0, Envelope::Slice(copy_of(1, 500)?));
        thread.take(0, tick(2_000));
        // Epoch 0 is closed: a slice stamped in it is late. Epoch 2's is not.
        thread.take(0, Envelope::Slice(copy_of(2, 600)?));
        thread.take(0, Envelope::Slice(copy_of(3, 2_100)?));
        thread.take(0, tick(4_000));
        let words = words.lock().map_err(|error| error.to_string())?;
        assert_eq!(words.iter().map(|word| word.late).sum::<u64>(), 1);
        let decided: Vec<(u64, bool, usize)> = words
            .iter()
            .filter_map(|word| {
                word.epoch
                    .map(|epoch| (epoch.number(), word.refused, word.stream.len()))
            })
            .collect();
        assert_eq!(decided, vec![(0, false, 1), (2, false, 1)]);
        Ok(())
    }
}
