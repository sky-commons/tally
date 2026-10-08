//! Keyed exchanges between the ingest stage and the shards that own state (RFC-0177 §3). There
//! are [`SHARDS`] logical shards per exchange, mapped onto threads (shard `s` on thread
//! `s % threads`), each owning its state outright, so nothing on the per-reception path takes a
//! lock. A producer (an ingest worker) sends each thread one [`Slice`] per batch, never one message
//! per reception: the batch, shared, and the index ranges of its receptions whose key falls in that
//! thread's shards. Each thread's queue is bounded ([`QUEUE_SLICES`] per producer): a producer
//! that finds it full waits, which holds its connections' credit (`ingest::CREDIT`), which stops
//! their sockets being read. That is the back-pressure raw meets (RFC-0177 §10).
//!
//! Keys are uniform hashes only, never geography, so a dense area cannot make a hot shard:
//!
//! - [`Exchange::Message`]: by a reception's fingerprint. The one deduplication
//!   ([`MessageShard`]): the hub's stream and each area's first-heard.
//! - [`Exchange::Raw`]: by receiver. Admission, station counters and each receiver's place, owned
//!   by the ingest worker of the receiver's shard (`ingest::Stages`).
//! - [`Exchange::Address`]: by ICAO address. The hosted MLAT's provisional state is held in these
//!   shards (`mlat_host`, `tally_mlat::provisional::shard_of`); the world candidates arrive per
//!   record, not per reception, and one sealer owns them whole (`products::Sealer`).
//!
//! Every producer sends [`Envelope::Tick`] down every queue as its stamps advance; a thread's
//! watermark ([`Watermark`]) is the least of its producers' ticks, and it closes an epoch once its
//! watermark passes it (`seal::Closer`). Nothing is decided on arrival: an epoch's receptions are
//! decided at its close, in the canonical order of their stamps (`ingest::Stamp`) and indices, so
//! which copy of a message is kept, and in which area, is the same on any number of threads.

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};
use std::ops::Range;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tally_wire::{Decoded, ObsRef, PublicKey, Region};

use crate::ingest::Stamp;
use crate::seal::{Closer, Epoch, epoch_of};

/// Logical shards per exchange: fixed, so a key's shard never depends on how many threads run.
pub const SHARDS: usize = 256;

/// Slices a thread's queue holds per producer before the producer waits: about a second of one
/// feeder's batches per producer at the RFC's rate, bounded whatever the shard's speed.
pub const QUEUE_SLICES: usize = 1_024;

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

/// The shard of a receiver: its key's low bytes. A public key is uniform; a feeder can choose its
/// key, and choosing one that lands on a busy shard only puts its own batches in that shard's queue.
pub fn raw_shard(receiver: &PublicKey) -> ShardId {
    let bytes = receiver.as_bytes();
    ShardId((u16::from_le_bytes([bytes[0], bytes[1]]) as usize % SHARDS) as u16)
}

/// The shard of an ICAO address: provisional solving's own (`tally_mlat::provisional::shard_of`),
/// one hash for every state kept by aircraft.
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

    fn stamp(&self) -> Stamp {
        Stamp {
            stamp_ms: self.decoded.stamp_ms(),
            ingest_seq: self.decoded.ingest_seq(),
        }
    }
}

/// What travels down a thread's queue.
#[derive(Clone, Debug)]
pub enum Envelope {
    Slice(Slice),
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

/// One message shard: the messages kept in the epoch being closed and the one before it (two
/// generations, swapped per epoch, so forgetting costs nothing per message). A message is new to
/// the stream when neither generation kept it for the stream, and new to an area when neither kept
/// it for that area: each is remembered for one to two epochs, apart.
#[derive(Default)]
pub struct MessageShard {
    previous: Heard,
    current: Heard,
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
        let before = self.previous.get(&fp);
        let now = self.current.get(&fp);
        let stream =
            !before.is_some_and(|heard| heard.stream) && !now.is_some_and(|heard| heard.stream);
        let regional = area.is_some_and(|area| {
            !before.is_some_and(|heard| heard.holds(area))
                && !now.is_some_and(|heard| heard.holds(area))
        });
        if stream || regional {
            let heard = self.current.entry(fp).or_default();
            heard.stream |= stream;
            if let Some(area) = area.filter(|_| regional) {
                heard.add(area);
            }
        }
        Decision { stream, regional }
    }

    /// The next epoch begins: what the last one heard becomes the previous generation.
    pub fn swap(&mut self) {
        self.previous = std::mem::take(&mut self.current);
        self.previous.shrink_to_fit();
    }

    /// An epoch begins two or more after the last: nothing heard is remembered.
    pub fn clear(&mut self) {
        self.previous = Heard::default();
        self.current = Heard::default();
    }

    /// Fingerprints held.
    pub fn len(&self) -> usize {
        self.previous.len() + self.current.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What one message thread hands the sealer: an epoch it closed that held receptions (the
/// batches they came from, and which are new to the stream and to an area, each as (batch,
/// observation) indices, in canonical order), or only how far it has closed. A thread sends nothing
/// for an epoch it held nothing of, so a watermark that jumps costs nothing; its messages are
/// numbered (`seq`) so the sealer knows when one was lost (`seal::Coordinator`).
#[derive(Debug, Default)]
pub struct Frozen {
    pub thread: usize,
    /// This thread's count of messages before this one.
    pub seq: u64,
    /// The epoch closed, when it held receptions.
    pub epoch: Option<Epoch>,
    /// Every epoch before this is closed on this thread.
    pub closed_before: Epoch,
    pub batches: Vec<Arc<Decoded>>,
    pub stream: Vec<(u32, u32)>,
    pub regional: Vec<(Region, u32, u32)>,
}

/// Where closed epochs go: the sealer (`seal::Coordinator`). False when it could not take one,
/// which it then refuses whole.
pub type Sink = Arc<dyn Fn(Frozen) -> bool + Send + Sync>;

/// The state one message thread owns: its logical shards, its watermark, its open epochs.
pub struct MessageThread {
    thread: usize,
    threads: usize,
    /// Its shards, `thread`, `thread + threads`, ... at `shard / threads`.
    shards: Vec<MessageShard>,
    watermark: Watermark,
    closer: Closer,
    open: BTreeMap<Epoch, Vec<Slice>>,
    /// The last epoch decided: its shards' generations are its and the one before.
    decided: Option<Epoch>,
    /// Messages sent the sealer.
    sent: u64,
    /// Every epoch before this is closed.
    closed_before: Option<Epoch>,
    sink: Sink,
}

impl MessageThread {
    pub fn new(thread: usize, threads: usize, producers: usize, sink: Sink) -> Self {
        let owned = (thread..SHARDS).step_by(threads.max(1)).count();
        Self {
            thread,
            threads: threads.max(1),
            shards: (0..owned).map(|_| MessageShard::default()).collect(),
            watermark: Watermark::new(producers),
            closer: Closer::default(),
            open: BTreeMap::new(),
            decided: None,
            sent: 0,
            closed_before: None,
            sink,
        }
    }

    pub fn take(&mut self, producer: usize, envelope: Envelope) {
        match envelope {
            Envelope::Slice(slice) => {
                let epoch = epoch_of(slice.stamp());
                self.open.entry(epoch).or_default().push(slice);
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
                // Only the epochs that held something are decided; the rest close by count.
                let held: Vec<Epoch> = self.open.range(..closing.end).map(|(e, _)| *e).collect();
                for epoch in held {
                    self.close(epoch, closing.end);
                }
                if self.closed_before.is_none_or(|before| closing.end > before) {
                    self.closed_before = Some(closing.end);
                    let marker = Frozen {
                        thread: self.thread,
                        closed_before: closing.end,
                        ..Frozen::default()
                    };
                    self.send(marker);
                }
            }
        }
    }

    /// Decides epoch `epoch`'s receptions in canonical order and hands them to the sealer.
    fn close(&mut self, epoch: Epoch, closed_before: Epoch) {
        let mut slices = self.open.remove(&epoch).unwrap_or_default();
        // Anything older still open came after its epoch closed: impossible while producers keep
        // their ticks, and kept out of any later epoch if it ever happened.
        while let Some(entry) = self.open.first_entry() {
            if *entry.key() > epoch {
                break;
            }
            slices.extend(entry.remove());
        }
        slices.sort_by_key(Slice::stamp);
        // The generations follow the epochs: the one before is remembered, older ones are not.
        match self.decided {
            Some(last) if epoch == last + 1 => self.shards.iter_mut().for_each(MessageShard::swap),
            Some(last) if epoch > last + 1 => self.shards.iter_mut().for_each(MessageShard::clear),
            _ => {}
        }
        self.decided = Some(epoch);
        let mut frozen = Frozen {
            thread: self.thread,
            epoch: Some(epoch),
            closed_before: (epoch + 1).min(closed_before),
            batches: Vec::with_capacity(slices.len()),
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
        self.send(frozen);
    }

    fn send(&mut self, mut frozen: Frozen) {
        frozen.seq = self.sent;
        self.sent += 1;
        (self.sink)(frozen);
    }

    /// Fingerprints held across its shards.
    pub fn held(&self) -> usize {
        self.shards.iter().map(MessageShard::len).sum()
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
    pub fn inline(sink: Sink) -> Self {
        Self::Inline(Mutex::new(MessageThread::new(0, 1, 1, sink)))
    }

    /// `threads` threads, fed by `producers` producers, each queue bounded per producer.
    pub fn threads(threads: usize, producers: usize, sink: &Sink) -> Self {
        let threads = threads.max(1);
        let mut senders = Vec::with_capacity(threads);
        let mut handles = Vec::with_capacity(threads);
        for thread in 0..threads {
            let (sender, receiver) = sync_channel(QUEUE_SLICES * producers.max(1));
            let state = MessageThread::new(thread, threads, producers, Arc::clone(sink));
            let handle = std::thread::Builder::new()
                .name(format!("tally-message-{thread}"))
                .spawn(move || run(state, &receiver));
            match handle {
                Ok(handle) => {
                    senders.push(sender);
                    handles.push(handle);
                }
                Err(error) => {
                    eprintln!("tally-relay: message thread {thread}: {error}");
                    break;
                }
            }
        }
        Self::Threads { senders, handles }
    }

    /// Threads the shards run on.
    pub fn width(&self) -> usize {
        match self {
            Self::Inline(_) => 1,
            Self::Threads { senders, .. } => senders.len().max(1),
        }
    }

    /// Routes a batch's receptions to their shards' threads, waiting while a thread's queue is
    /// full.
    pub fn route(&self, producer: usize, decoded: &Arc<Decoded>, area: Option<Region>) {
        for (thread, slice) in split(decoded, self.width(), area) {
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

fn run(mut state: MessageThread, receiver: &Receiver<(usize, Envelope)>) {
    while let Ok((producer, envelope)) = receiver.recv() {
        state.take(producer, envelope);
    }
}

/// Sends `frozen` to a bounded queue without waiting: a sealer that is behind refuses the epoch
/// whole rather than slow the shards (RFC-0177 §10).
pub fn offer(sender: &SyncSender<Frozen>, frozen: Frozen) -> bool {
    match sender.try_send(frozen) {
        Ok(()) => true,
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
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
        shard.swap();
        // Remembered one more epoch, then forgotten.
        assert_eq!(shard.decide(7, Some(a)), new(false, false));
        shard.swap();
        shard.swap();
        assert_eq!(shard.decide(7, Some(a)), new(true, true));
        Ok(())
    }

    /// The stream's window and the areas' are apart: a message heard in one area after another,
    /// epoch after epoch, is kept for the stream every other epoch, as one heard in one area is.
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
            shard.swap();
        }
        assert_eq!(kept, 6);
        Ok(())
    }
}
