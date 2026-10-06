//! What every connection of a relay shares: the fan-out, the record of batches and positions
//! already forwarded, the deduplicated stream being gathered, each receiver's newest
//! self-description, and the relays this one offers as hints.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tally_wire::batch::Hash;
use tally_wire::{
    Batch, Location, Observation, Positions, PublicKey, ReceiverInfo, Record, Region, RelayAddress,
};
use tokio::sync::broadcast;

use crate::bounded::Bounded;
use crate::subscription::{Described, Subscription};

/// How many records a subscriber may fall behind before it is dropped. readsb's rule: drop the
/// slow consumer, never slow the producers (RFC-0171 §3.6). Sized with the other defaults to the
/// relay unit's memory (see `DEFAULT_MAX_CONNECTIONS`).
pub const FAN_OUT_CAPACITY: usize = 4096;

/// How long a forwarded batch's hash is remembered, by default. Longer than any loop through the
/// relay tree, so a batch arriving again by another path is recognised and forwarded once. It is
/// not what stops a replay: the hash forgets, so a batch replayed after one to two windows passes
/// it, and at a slow enough batch rate (a receiver hearing little seals seldom) any window is
/// shorter than `REORDER_ALLOWANCE` sequences. Each stream's window of sequences already forwarded
/// (`Sequences`) refuses a replay at any rate; the hash covers a stream the relay has forgotten
/// and a stream's other copies arriving inside the window.
const SEEN_WINDOW: Duration = Duration::from_secs(60);

/// The most hashes one generation of `Seen` holds: a generation that fills is retired early, so the
/// hashes are bounded by count (two generations, about 9 MB a table) as well as by time. At the
/// network's planned 20,000 receivers sealing once a second that is still five to ten seconds of
/// batches, longer than a loop through the relay tree takes.
pub const HASHES_REMEMBERED: usize = 100_000;

/// How far behind the newest sequence of its stream a batch or positions may arrive and still be
/// forwarded: a few relays' paths reordering about a minute of one receiver's batches. Anything
/// older is a replay or too late to matter, whether or not its hash is still remembered. One bit
/// each of a `u64` remembers which of these were forwarded, so it is at most 64.
pub const REORDER_ALLOWANCE: u64 = 64;
const _: () = assert!(REORDER_ALLOWANCE <= u64::BITS as u64);

/// How many streams (a receiver's boot, an engine's boot) the relay remembers the newest sequence
/// of, per table. At about 150 bytes each this is some 30 MB, ten times the network's planned
/// 20,000 receivers with room for their reboots. When full, the stream that published least
/// recently is forgotten (`Bounded`: a new stream counts as publishing when it is first seen), so a
/// churn of fresh boots forgets itself oldest first, a stream publishing at least once per table's
/// worth of new streams keeps its place, and a new honest boot is remembered as soon as it starts.
/// A forgotten stream is again bounded only by the hash window.
///
/// Who can make use of a forgotten stream: a feeder may publish only its own batches and an engine
/// only its own positions (`link::Peer`), so a record of *another* author reaches this relay only
/// from a relay the operator accepted (`--accept-relay`) or an upstream it chose to dial. A replay
/// across authors therefore needs a peer the operator trusted; churning its own streams lets a
/// stranger replay nothing but its own records.
pub const STREAMS_REMEMBERED: usize = 200_000;

/// How many receivers' descriptions the relay holds. When full, the one least recently active is
/// forgotten: a receiver is active when it is first described and whenever a batch of it is
/// forwarded, never by a description alone (`Bounded`). So descriptions from throwaway keys forget
/// each other oldest first, a receiver publishing at least once per table's worth of new keys keeps
/// its place, and a new receiver is described from its first description, however full the table
/// of receivers that publish. A forgotten receiver's batches still flow, to whole-world subscribers
/// only, until it describes itself again (a feeder's link does so at its next batch, see `link`;
/// one known only through a relay link, at its feeder's next periodic description).
pub const RECEIVERS_REMEMBERED: usize = 50_000;

/// The most bytes of receiver descriptions held. A description is at most one message, so the count
/// alone would let 50,000 throwaway keys hold 3 GB; this holds an honest description (a few hundred
/// bytes) for every receiver remembered many times over.
pub const DESCRIPTION_BYTES_HELD: usize = 64 * 1024 * 1024;

/// The default ceilings an operator may change (`config`).
///
/// With the other defaults these fit the relay unit's `MemoryMax=4G` (`MemoryHigh=3G`) at their
/// worst, every buffer full, with headroom:
///
/// | what                                                         | worst case |
/// | ------------------------------------------------------------ | ---------- |
/// | 2,048 connections x ~320 KiB (Noise buffers, a decoded read) | 640 MiB    |
/// | kernel socket buffers charged to the unit, ~100 fan-out links x 4 MiB | 400 MiB |
/// | fan-out ring, 4,096 records x one 64 KiB message             | 256 MiB    |
/// | records a link has gathered but not sent, ~100 x 320 KiB     | 32 MiB     |
/// | deduplicated stream (`DEFAULT_MAX_DEDUP_BYTES`)              | 256 MiB    |
/// | descriptions (`DESCRIPTION_BYTES_HELD`) and their index      | 80 MiB     |
/// | streams, two tables x 200,000 x ~150 B                       | 60 MiB     |
/// | hashes, two tables x two generations x 100,000               | 18 MiB     |
/// | total                                                        | ~1.7 GiB   |
///
/// The earlier defaults (4,096 connections, an 8,192-record ring, descriptions bounded only by
/// count) reached past 5 GB.
pub const DEFAULT_MAX_CONNECTIONS: usize = 2048;
/// Per IPv4 address, or per IPv6 /64 (what one host is usually given), so one host cannot take
/// the whole connection cap with handshakes it never finishes.
pub const DEFAULT_MAX_CONNECTIONS_PER_ADDRESS: usize = 16;
pub const DEFAULT_MAX_FEEDER_BYTES_PER_SEC: u64 = 262_144;
/// The most the deduplicated stream holds of messages being compared, by default.
pub const DEFAULT_MAX_DEDUP_BYTES: usize = 256 * 1024 * 1024;

/// What one gathered observation costs the deduplicator beside its bytes: its fields, its vector
/// and its place in arrival order. An estimate, on the high side.
const DEDUP_ENTRY_OVERHEAD: usize = 96;

/// What one message remembered as heard costs the deduplicator: a 128-bit fingerprint and an
/// instant in a hash map, with the map's slack. An estimate, on the high side.
const DEDUP_KEY_COST: usize = 64;

/// How many independently locked parts the deduplicator is split into, by fingerprint, so feeders
/// offering observations at once rarely wait on each other.
const DEDUP_SHARDS: usize = 64;

/// How long a message's bytes are remembered for the deduplicated stream: another receiver's copy
/// of the same transmission arrives well inside it, and a message an aircraft repeats a second or
/// two later is a new transmission.
const DEDUPLICATION_WINDOW: Duration = Duration::from_secs(2);

/// The connection id of records the relay makes itself (its deduplicated stream). Connections
/// are numbered from 1, so nothing is ever held back from a link as its own.
pub const RELAY_ITSELF: u64 = 0;

/// A record on its way out, and the connection it came in on, so it is never sent back there.
#[derive(Clone, Debug)]
pub struct Item {
    pub source: u64,
    pub record: Arc<Record>,
    /// For a receiver's batch or description: the finest cell (`Region::point`) of where that
    /// receiver last declared itself, if it has, computed once when its description was kept.
    /// Regions route by this and by nothing else.
    pub cell: Option<Region>,
}

/// Two generations of hashes: a hash is remembered for one to two windows, or until `most` newer
/// hashes have retired its generation, whichever is sooner. The oldest are forgotten first.
struct Seen {
    window: Duration,
    most: usize,
    current: HashSet<Hash>,
    previous: HashSet<Hash>,
    rotated: Instant,
}

impl Seen {
    fn new(window: Duration, most: usize) -> Self {
        Self {
            window,
            most: most.max(1),
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated: Instant::now(),
        }
    }

    fn rotate(&mut self) {
        if self.rotated.elapsed() >= self.window {
            self.retire();
        }
    }

    fn retire(&mut self) {
        self.previous = std::mem::take(&mut self.current);
        self.rotated = Instant::now();
    }

    fn insert(&mut self, hash: Hash) {
        if self.current.len() >= self.most {
            self.retire();
        }
        self.current.insert(hash);
    }

    fn contains(&self, hash: &Hash) -> bool {
        self.current.contains(hash) || self.previous.contains(hash)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }
}

/// One stream's newest sequence forwarded, and which of the `REORDER_ALLOWANCE` before it were.
#[derive(Clone, Copy)]
struct Sequences {
    newest: u64,
    /// Bit `n` is set when `newest - n` was forwarded.
    forwarded: u64,
}

impl Sequences {
    fn first(sequence: u64) -> Self {
        Self {
            newest: sequence,
            forwarded: 1,
        }
    }

    /// The window with `sequence` forwarded, or `None` when it already was or is too far behind.
    fn admit(self, sequence: u64) -> Option<Self> {
        if sequence > self.newest {
            let ahead = sequence - self.newest;
            let forwarded = if ahead >= u64::from(u64::BITS) {
                0
            } else {
                self.forwarded << ahead
            };
            return Some(Self {
                newest: sequence,
                forwarded: forwarded | 1,
            });
        }
        let behind = self.newest - sequence;
        if behind >= REORDER_ALLOWANCE {
            return None;
        }
        let bit = 1u64 << behind;
        (self.forwarded & bit == 0).then_some(Self {
            newest: self.newest,
            forwarded: self.forwarded | bit,
        })
    }
}

/// What has been forwarded on one kind of signed stream: recent hashes, and each stream's window
/// of sequences. A record is forwarded when it is new by both: an unseen hash, and a sequence no
/// further than `REORDER_ALLOWANCE` behind its stream's newest and not already forwarded. The hash
/// alone forgets after its window, so an old record replayed later would pass it; the sequences do
/// not forget, whatever the stream's rate, until the stream itself is forgotten (see
/// `STREAMS_REMEMBERED` for which goes first, and who could replay into one that was).
///
/// A stream is its author and its boot id, for batches and positions alike, so an author that
/// restarts begins a new stream at sequence 0 instead of being refused as a replay of its last boot.
struct Forwarded<K> {
    seen: Seen,
    newest: Bounded<K, Sequences>,
}

impl<K: std::hash::Hash + Eq + Clone> Forwarded<K> {
    fn new(window: Duration) -> Self {
        Self::bounded(window, STREAMS_REMEMBERED, HASHES_REMEMBERED)
    }

    fn bounded(window: Duration, streams: usize, hashes: usize) -> Self {
        Self {
            seen: Seen::new(window, hashes),
            newest: Bounded::new(streams),
        }
    }

    /// True, and remembered, when the record is new.
    fn admit(&mut self, hash: Hash, stream: K, sequence: u64) -> bool {
        self.seen.rotate();
        if self.seen.contains(&hash) {
            return false;
        }
        let known = self.newest.get(&stream).copied();
        let window = match known {
            Some(window) => window.admit(sequence),
            None => Some(Sequences::first(sequence)),
        };
        let Some(window) = window else {
            return false;
        };
        self.seen.insert(hash);
        // Every record forwarded is the stream publishing, new stream or known.
        self.newest.insert_active(stream, window);
        true
    }
}

/// The deduplicated stream on its way to being signed: first copies of each message, and when
/// each message was first heard, across every receiver. It holds at most `max_bytes` (counted by
/// `cost` and `DEDUP_KEY_COST`, one budget for every shard, an atomic); a new message beyond that
/// is still forwarded raw in its receiver's batch, but is not compared or gathered here until there
/// is room, and is counted in `skipped`.
///
/// A message is remembered by a 128-bit fingerprint of its format and bytes, keyed by this
/// process's random keys, not by a copy of its bytes: two of the standard library's SipHash keys,
/// so nobody outside the process can make two messages share a fingerprint, and the chance that
/// two real messages do is about 2^-128 a pair. The fingerprint also chooses the message's shard.
/// Each shard is locked on its own; bytes are added to and released from `held` only under the
/// shard that holds them, so the count never runs below what the shards hold.
struct Deduplicator {
    shards: Vec<Mutex<Shard>>,
    keys: (RandomState, RandomState),
    /// The order observations are offered in, so what is taken keeps arrival order across shards.
    arrived: AtomicU64,
    held: AtomicUsize,
    max_bytes: usize,
    skipped: AtomicU64,
}

#[derive(Default)]
struct Shard {
    first_heard: HashMap<u128, Instant>,
    gathered: Vec<(u64, Observation)>,
}

/// What holding `data` once as a gathered observation costs the deduplicator.
fn cost(data: &[u8]) -> usize {
    data.len() + DEDUP_ENTRY_OVERHEAD
}

impl Deduplicator {
    fn new(max_bytes: usize) -> Self {
        Self {
            shards: (0..DEDUP_SHARDS).map(|_| Mutex::default()).collect(),
            keys: (RandomState::new(), RandomState::new()),
            arrived: AtomicU64::new(0),
            held: AtomicUsize::new(0),
            max_bytes,
            skipped: AtomicU64::new(0),
        }
    }

    fn fingerprint(&self, format: u8, data: &[u8]) -> u128 {
        let half = |keys: &RandomState| {
            let mut hasher = keys.build_hasher();
            // The format is one byte, always first, so (format, data) reads one way only.
            hasher.write_u8(format);
            hasher.write(data);
            hasher.finish()
        };
        (u128::from(half(&self.keys.0)) << 64) | u128::from(half(&self.keys.1))
    }

    fn offer(&self, observation: Observation, now: Instant) {
        let fingerprint = self.fingerprint(observation.format, &observation.data);
        // The low bits of one half: uniform, whatever the messages.
        let at = usize::try_from(fingerprint % DEDUP_SHARDS as u128).unwrap_or(0);
        let Some(Ok(mut shard)) = self.shards.get(at).map(Mutex::lock) else {
            return;
        };
        let heard = shard.first_heard.get(&fingerprint);
        if heard.is_some_and(|heard| now.duration_since(*heard) < DEDUPLICATION_WINDOW) {
            return;
        }
        // A key already held (heard a window ago, not yet purged) costs nothing more as a key.
        let as_key = if heard.is_some() { 0 } else { DEDUP_KEY_COST };
        let needed = as_key + cost(&observation.data);
        let reserved = self
            .held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(needed)
                    .filter(|after| *after <= self.max_bytes)
            });
        if reserved.is_err() {
            self.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        shard.first_heard.insert(fingerprint, now);
        let order = self.arrived.fetch_add(1, Ordering::Relaxed);
        shard.gathered.push((order, observation));
    }

    /// The observations gathered since the last call, in the order they were offered; forgets the
    /// messages heard a window ago.
    fn take(&self, now: Instant) -> Vec<Observation> {
        let mut gathered = Vec::new();
        for shard in &self.shards {
            let Ok(mut shard) = shard.lock() else {
                continue;
            };
            let before = shard.first_heard.len();
            shard
                .first_heard
                .retain(|_, heard| now.duration_since(*heard) < DEDUPLICATION_WINDOW);
            let mut released = (before - shard.first_heard.len()) * DEDUP_KEY_COST;
            let taken = std::mem::take(&mut shard.gathered);
            released += taken
                .iter()
                .map(|(_, observation)| cost(&observation.data))
                .sum::<usize>();
            // Released under the lock it was added under, so `held` never runs below zero.
            self.held.fetch_sub(released, Ordering::AcqRel);
            gathered.extend(taken);
        }
        gathered.sort_unstable_by_key(|(order, _)| *order);
        gathered
            .into_iter()
            .map(|(_, observation)| observation)
            .collect()
    }

    /// How many new messages were left out since the last call.
    fn take_skipped(&self) -> u64 {
        self.skipped.swap(0, Ordering::Relaxed)
    }

    #[cfg(test)]
    fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
}

/// A receiver's newest description, ready to send, and the finest cell of the location it
/// declared in it.
struct Known {
    issued_ms: u64,
    record: Arc<Record>,
    cell: Option<Region>,
    bytes: usize,
}

impl Known {
    fn item(&self) -> Item {
        Item {
            source: RELAY_ITSELF,
            record: Arc::clone(&self.record),
            cell: self.cell,
        }
    }
}

/// Every description held, for joining subscribers, under a lock the batch path never takes.
/// Which receivers are held, and which is forgotten first, is `Hub::receivers`; this follows it
/// key for key.
struct Directory {
    known: HashMap<PublicKey, Known>,
    /// The located receivers by their finest cell's number, so the receivers inside a region are
    /// one range read (`Region::span`): a subscription's answer costs its matches and a lookup a
    /// region, never a test of every receiver.
    by_point: BTreeMap<u64, Vec<PublicKey>>,
    bytes: usize,
    max_bytes: usize,
}

/// The descriptions a subscription covers, and how many index entries were read to find them.
struct Answer {
    items: Vec<Item>,
    /// Read by the tests, which hold it equal to the matches: the proof that an answer reads only
    /// what it returns.
    #[cfg_attr(not(test), allow(dead_code))]
    visited: usize,
}

impl Directory {
    fn new(max_bytes: usize) -> Self {
        Self {
            known: HashMap::new(),
            by_point: BTreeMap::new(),
            bytes: 0,
            max_bytes,
        }
    }

    fn insert(&mut self, receiver: PublicKey, known: Known) {
        self.bytes += known.bytes;
        if let Some(cell) = known.cell {
            self.by_point
                .entry(cell.as_u64())
                .or_default()
                .push(receiver);
        }
        if let Some(old) = self.known.insert(receiver, known) {
            self.forget(&receiver, &old);
        }
    }

    fn remove(&mut self, receiver: &PublicKey) {
        if let Some(old) = self.known.remove(receiver) {
            self.forget(receiver, &old);
        }
    }

    /// Takes back what `old`, no longer held for `receiver`, added.
    fn forget(&mut self, receiver: &PublicKey, old: &Known) {
        self.bytes -= old.bytes;
        let Some(cell) = old.cell else {
            return;
        };
        if let Some(keys) = self.by_point.get_mut(&cell.as_u64()) {
            // Only the old entry's: a description that kept its cell was indexed again already.
            if let Some(at) = keys.iter().position(|key| key == receiver) {
                keys.swap_remove(at);
            }
            if keys.is_empty() {
                self.by_point.remove(&cell.as_u64());
            }
        }
    }

    fn all(&self) -> Vec<Item> {
        self.known.values().map(Known::item).collect()
    }

    fn answer(&self, subscription: &Subscription) -> Answer {
        match subscription.described() {
            Described::None => Answer {
                items: Vec::new(),
                visited: 0,
            },
            Described::All => {
                let items = self.all();
                let visited = items.len();
                Answer { items, visited }
            }
            Described::Within(spans) => {
                let mut items = Vec::new();
                let mut visited = 0;
                for span in spans {
                    for key in self.by_point.range(span).flat_map(|(_, keys)| keys) {
                        visited += 1;
                        if let Some(known) = self.known.get(key) {
                            items.push(known.item());
                        }
                    }
                }
                Answer { items, visited }
            }
        }
    }
}

pub struct Hub {
    out: broadcast::Sender<Item>,
    batches: Mutex<Forwarded<(PublicKey, u64)>>,
    positions: Mutex<Forwarded<(PublicKey, u64)>>,
    deduplicator: Deduplicator,
    /// The receivers described, each with its cell, in the order they are forgotten: what the
    /// batch path reads (a cell to route by) and marks (the receiver is publishing), O(1) each.
    receivers: Mutex<Bounded<PublicKey, Option<Region>>>,
    /// Their descriptions. Taken by `publish_info` (then `receivers`, in that order) and by a
    /// joining subscriber, never by the batch path, so no scan ever stalls a batch.
    directory: Mutex<Directory>,
    next_connection: AtomicU64,
    subscribers: Arc<AtomicUsize>,
    max_subscribers: usize,
    connections: Arc<AtomicUsize>,
    max_connections: usize,
    /// Connections held per source (`source_of`), each entry removed when its last one ends.
    per_address: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_connections_per_address: usize,
    max_feeder_bytes_per_sec: u64,
    accepted_relays: HashSet<PublicKey>,
    hints: Vec<RelayAddress>,
}

/// Held for as long as a subscriber (or a connection) is served; releases its place when dropped.
pub struct Slot {
    taken: Arc<AtomicUsize>,
}

impl Slot {
    /// A place among `taken`, or `None` (and no place) when `limit` are already taken.
    fn take(taken: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let before = taken.fetch_add(1, Ordering::SeqCst);
        let slot = Self {
            taken: Arc::clone(taken),
        };
        (before < limit).then_some(slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.taken.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Held for as long as one connection is open: its place under the relay's cap and under its
/// source's.
pub struct Connection {
    _relay: Slot,
    _source: SourceSlot,
}

/// One connection's place among its source's.
struct SourceSlot {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    source: IpAddr,
}

impl SourceSlot {
    fn take(
        counts: &Arc<Mutex<HashMap<IpAddr, usize>>>,
        source: IpAddr,
        limit: usize,
    ) -> Option<Self> {
        let mut held = counts.lock().ok()?;
        let count = held.entry(source).or_insert(0);
        if *count >= limit {
            if *count == 0 {
                held.remove(&source);
            }
            return None;
        }
        *count += 1;
        Some(Self {
            counts: Arc::clone(counts),
            source,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        if let Ok(mut held) = self.counts.lock()
            && let Some(count) = held.get_mut(&self.source)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.source);
            }
        }
    }
}

/// Who a connection counts against: its IPv4 address, or its IPv6 /64. An IPv4 address mapped
/// into IPv6 (a dual-stack listener) is its IPv4 address.
pub fn source_of(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
    }
}

impl Hub {
    pub fn new(max_subscribers: usize) -> Self {
        Self::with_capacity(max_subscribers, FAN_OUT_CAPACITY)
    }

    /// `capacity` records of slack before a slow subscriber is dropped.
    pub fn with_capacity(max_subscribers: usize, capacity: usize) -> Self {
        Self {
            out: broadcast::channel(capacity).0,
            batches: Mutex::new(Forwarded::new(SEEN_WINDOW)),
            positions: Mutex::new(Forwarded::new(SEEN_WINDOW)),
            deduplicator: Deduplicator::new(DEFAULT_MAX_DEDUP_BYTES),
            receivers: Mutex::new(Bounded::new(RECEIVERS_REMEMBERED)),
            directory: Mutex::new(Directory::new(DESCRIPTION_BYTES_HELD)),
            next_connection: AtomicU64::new(RELAY_ITSELF + 1),
            subscribers: Arc::new(AtomicUsize::new(0)),
            max_subscribers,
            connections: Arc::new(AtomicUsize::new(0)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            per_address: Arc::new(Mutex::new(HashMap::new())),
            max_connections_per_address: DEFAULT_MAX_CONNECTIONS_PER_ADDRESS,
            max_feeder_bytes_per_sec: DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
            accepted_relays: HashSet::new(),
            hints: Vec::new(),
        }
    }

    /// How long a forwarded hash is remembered (one to two of `window`), instead of a minute.
    pub fn remembering_hashes_for(mut self, window: Duration) -> Self {
        self.batches = Mutex::new(Forwarded::new(window));
        self.positions = Mutex::new(Forwarded::new(window));
        self
    }

    /// The relays this one offers feeders as hints, and names when it turns a subscriber away.
    pub fn advertising(mut self, hints: Vec<RelayAddress>) -> Self {
        self.hints = hints;
        self
    }

    /// The only keys accepted as relays when they dial in. A relay forwards anyone's batches and
    /// is not held to the subscriber cap, so that trust is the operator's to give, key by key.
    pub fn accepting_relays(mut self, keys: impl IntoIterator<Item = PublicKey>) -> Self {
        self.accepted_relays = keys.into_iter().collect();
        self
    }

    /// Connections served at once before a new one is closed unanswered.
    pub fn max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Connections from one source (`source_of`) served at once before a new one from it is
    /// closed unanswered.
    pub fn max_connections_per_address(mut self, max: usize) -> Self {
        self.max_connections_per_address = max;
        self
    }

    /// The most the deduplicated stream holds of messages being compared (see `Deduplicator`).
    pub fn max_dedup_bytes(mut self, max: usize) -> Self {
        self.deduplicator = Deduplicator::new(max);
        self
    }

    /// The most bytes a second one connection may send, beyond its burst.
    pub fn max_feeder_bytes_per_sec(mut self, rate: u64) -> Self {
        self.max_feeder_bytes_per_sec = rate;
        self
    }

    pub fn hints(&self) -> &[RelayAddress] {
        &self.hints
    }

    pub fn accepts_relay(&self, key: &PublicKey) -> bool {
        self.accepted_relays.contains(key)
    }

    pub fn feeder_bytes_per_sec(&self) -> u64 {
        self.max_feeder_bytes_per_sec
    }

    /// A place for one more connection from `address`, or `None` when the relay, or that
    /// address's source, holds as many as it will.
    pub fn connection(&self, address: IpAddr) -> Option<Connection> {
        let source = SourceSlot::take(
            &self.per_address,
            source_of(address),
            self.max_connections_per_address,
        )?;
        let relay = Slot::take(&self.connections, self.max_connections)?;
        Some(Connection {
            _relay: relay,
            _source: source,
        })
    }

    /// Subscribers (and engines) being served now.
    pub fn subscribers(&self) -> usize {
        self.subscribers.load(Ordering::SeqCst)
    }

    pub fn connection_id(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    /// Forwards a verified batch if it is new (see `Forwarded`), and offers its observations to
    /// the deduplicated stream. True when it was new.
    pub fn publish_batch(&self, source: u64, batch: Batch, receiver: PublicKey) -> bool {
        let new = self.batches.lock().is_ok_and(|mut forwarded| {
            forwarded.admit(batch.hash(), (receiver, batch.boot_id()), batch.sequence())
        });
        if !new {
            return false;
        }
        // A format this build cannot read is still forwarded raw; it just adds nothing here.
        if let Ok(content) = batch.content() {
            let now = Instant::now();
            for observation in content.observations {
                self.deduplicator.offer(observation, now);
            }
        }
        // The receiver is publishing, so its description is the last to be forgotten.
        let cell = self.receivers.lock().ok().and_then(|mut receivers| {
            receivers.touch(&receiver);
            receivers.get(&receiver).copied().flatten()
        });
        // An error only means nobody is subscribed right now.
        let _ = self.out.send(Item {
            source,
            record: Arc::new(Record::Batch(batch)),
            cell,
        });
        true
    }

    /// Whether the relay holds a description of `receiver`.
    pub fn describes(&self, receiver: &PublicKey) -> bool {
        self.receivers
            .lock()
            .is_ok_and(|receivers| receivers.get(receiver).is_some())
    }

    /// Keeps a verified receiver description if it is the newest for its key, and forwards it.
    /// `place` is the location it declares, when this build can read it. `publishing` says the
    /// receiver has just had a batch forwarded, so the description is kept as one that is.
    pub fn publish_info(
        &self,
        source: u64,
        info: ReceiverInfo,
        receiver: PublicKey,
        issued_ms: u64,
        place: Option<Location>,
        publishing: bool,
    ) {
        let Ok(mut directory) = self.directory.lock() else {
            return;
        };
        let newer = directory
            .known
            .get(&receiver)
            .is_none_or(|known| issued_ms > known.issued_ms);
        if !newer {
            return;
        }
        let Ok(mut receivers) = self.receivers.lock() else {
            return;
        };
        // Projected once, here; every region test after is integer work.
        let cell = place.and_then(|place| Region::point(&place).ok());
        let bytes = info.as_bytes().len();
        let record = Arc::new(Record::ReceiverInfo(info));
        directory.insert(
            receiver,
            Known {
                issued_ms,
                record: Arc::clone(&record),
                cell,
                bytes,
            },
        );
        let forgotten = if publishing {
            receivers.insert_active(receiver, cell)
        } else {
            receivers.insert(receiver, cell)
        };
        if let Some(forgotten) = forgotten {
            directory.remove(&forgotten);
        }
        // Held to bytes as well as count, forgetting in the same order.
        while directory.bytes > directory.max_bytes {
            let Some(forgotten) = receivers.forget_first() else {
                break;
            };
            directory.remove(&forgotten);
        }
        drop(receivers);
        drop(directory);
        // A link joining reads its descriptions first and takes its place in the fan-out only once
        // it has sent them (see `subscribe`), so one changed in between reaches it at its
        // receiver's next description.
        let _ = self.out.send(Item {
            source,
            record,
            cell,
        });
    }

    /// Forwards verified positions by `engine` if they are new (see `Forwarded`). True when they
    /// were.
    pub fn publish_positions(&self, source: u64, positions: Positions, engine: PublicKey) -> bool {
        let new = self.positions.lock().is_ok_and(|mut forwarded| {
            forwarded.admit(
                positions.hash(),
                (engine, positions.boot_id()),
                positions.sequence(),
            )
        });
        if new {
            let _ = self.out.send(Item {
                source,
                record: Arc::new(Record::Positions(positions)),
                cell: None,
            });
        }
        new
    }

    /// The first copies gathered since the last call, for the relay to sign, and how many new
    /// messages were left out of them for want of room.
    pub fn take_deduplicated(&self) -> (Vec<Observation>, u64) {
        let gathered = self.deduplicator.take(Instant::now());
        (gathered, self.deduplicator.take_skipped())
    }

    /// Broadcasts a batch the relay signed itself.
    pub fn publish_relay_batch(&self, batch: Batch) {
        let _ = self.out.send(Item {
            source: RELAY_ITSELF,
            record: Arc::new(Record::RelayBatch(batch)),
            cell: None,
        });
    }

    /// A place among the subscribers, with the known receiver descriptions `subscription` covers
    /// to send first, or `None` when the relay is serving as many subscribers as it will.
    ///
    /// The link joins the fan-out (`listen`) only once it has sent these, so the ring does not
    /// fill behind a large first send and drop it as fallen behind. A description that changes
    /// between this read and that join is not in either; it reaches the subscriber when its
    /// receiver next describes itself, which a feeder does every ten minutes
    /// (`INFO_EVERY` in `tally_feed`'s relays).
    pub fn subscribe(&self, subscription: &Subscription) -> Option<(Vec<Item>, Slot)> {
        let slot = Slot::take(&self.subscribers, self.max_subscribers)?;
        Some((self.infos_for(subscription), slot))
    }

    /// Every description, for a link to another relay, which does not count against the
    /// subscriber cap (it carries load as well as takes it). It joins the fan-out after sending
    /// them, as a subscriber does (see `subscribe`).
    pub fn peer(&self) -> Vec<Item> {
        self.directory
            .lock()
            .map(|directory| directory.all())
            .unwrap_or_default()
    }

    /// A place in the fan-out from now on, with no descriptions: for the loopback BEAST output, and
    /// for a link once it has sent the descriptions it joined with.
    pub fn listen(&self) -> broadcast::Receiver<Item> {
        self.out.subscribe()
    }

    /// Every known receiver description a subscription covers: what a subscriber is sent when it
    /// changes what it wants, so receivers it newly covers are described before their batches.
    pub fn infos_for(&self, subscription: &Subscription) -> Vec<Item> {
        self.answer(subscription).items
    }

    fn answer(&self, subscription: &Subscription) -> Answer {
        self.directory
            .lock()
            .map(|directory| directory.answer(subscription))
            .unwrap_or(Answer {
                items: Vec::new(),
                visited: 0,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::batch::ReceiverInfoContent;
    use tally_wire::{BatchContent, Clock, Identity};

    #[test]
    fn a_record_is_forwarded_once_and_never_far_behind_its_stream() {
        let mut forwarded = Forwarded::new(Duration::from_secs(60));
        assert!(forwarded.admit([1; 32], "engine", 100));
        // The same hash again, by another path.
        assert!(!forwarded.admit([1; 32], "engine", 100));
        // Reordered a little: still forwarded.
        assert!(forwarded.admit([2; 32], "engine", 100 - REORDER_ALLOWANCE + 1));
        // Older than the allowance, with a hash never seen: a replay, dropped.
        assert!(!forwarded.admit([3; 32], "engine", 100 - REORDER_ALLOWANCE));
        // Another stream has its own sequence.
        assert!(forwarded.admit([3; 32], "other", 0));
    }

    #[test]
    fn a_replay_inside_the_reorder_allowance_is_dropped_after_its_hash_is_forgotten() {
        let mut forwarded = Forwarded::new(Duration::ZERO);
        assert!(forwarded.admit([1; 32], "receiver", 10));
        assert!(forwarded.admit([2; 32], "receiver", 12));
        // Reordered, never forwarded: still taken.
        assert!(forwarded.admit([3; 32], "receiver", 11));
        assert!(forwarded.admit([4; 32], "receiver", 13));
        assert!(!forwarded.seen.contains(&[1; 32]));
        // Its hash forgotten and only three sequences behind, it was still forwarded once.
        assert!(!forwarded.admit([1; 32], "receiver", 10));
        // Far ahead, the window starts again and the newest is taken once.
        assert!(forwarded.admit([5; 32], "receiver", 1_000));
        assert!(!forwarded.admit([6; 32], "receiver", 1_000));
        assert!(forwarded.admit([7; 32], "receiver", 1_000 - REORDER_ALLOWANCE + 1));
    }

    fn signed_info(identity: &Identity) -> Result<ReceiverInfo, String> {
        ReceiverInfo::sign(
            identity,
            &ReceiverInfoContent {
                issued_ms: 1,
                location: None,
                clock: Clock::Dump1090,
                software: "test".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())
    }

    fn signed_batch(
        identity: &Identity,
        sequence: u64,
        observations: Vec<Observation>,
    ) -> Result<Batch, String> {
        Batch::sign(
            identity,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations,
            },
        )
        .map_err(|error| error.to_string())
    }

    fn key() -> Result<(Identity, PublicKey), String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let public = identity.public();
        Ok((identity, public))
    }

    #[test]
    fn a_flood_of_descriptions_never_forgets_a_receiver_that_is_publishing() -> Result<(), String> {
        const CAP: usize = 200;
        let mut hub = Hub::new(8);
        hub.receivers = Mutex::new(Bounded::new(CAP));
        let (honest, honest_key) = key()?;
        hub.publish_info(1, signed_info(&honest)?, honest_key, 1, None, false);
        hub.publish_batch(1, signed_batch(&honest, 0, Vec::new())?, honest_key);
        // Keys that only ever describe themselves, eleven times the map's size, the honest
        // receiver publishing once per half a map's worth of them.
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        for n in 0..11 * CAP {
            let (_, throwaway) = key()?;
            hub.publish_info(2, info.clone(), throwaway, 1, None, false);
            if n % (CAP / 2) == 0 {
                let sequence = u64::try_from(n / (CAP / 2) + 1).map_err(|e| e.to_string())?;
                hub.publish_batch(1, signed_batch(&honest, sequence, Vec::new())?, honest_key);
            }
            assert!(
                hub.describes(&honest_key),
                "forgot the honest receiver at {n}"
            );
        }
        // The directory joining subscribers copy follows the order of forgetting key for key.
        assert_eq!(held(&hub)?, (CAP, CAP));
        Ok(())
    }

    /// How many receivers the batch path knows, and how many descriptions the directory holds.
    fn held(hub: &Hub) -> Result<(usize, usize), String> {
        let receivers = hub.receivers.lock().map_err(|e| e.to_string())?.len();
        let directory = hub.directory.lock().map_err(|e| e.to_string())?.known.len();
        Ok((receivers, directory))
    }

    #[test]
    fn when_full_the_receiver_least_recently_active_is_forgotten() -> Result<(), String> {
        let mut hub = Hub::new(8);
        hub.receivers = Mutex::new(Bounded::new(2));
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        let (_, first) = key()?;
        let (_, second) = key()?;
        let (_, third) = key()?;
        hub.publish_info(2, info.clone(), first, 1, None, false);
        hub.publish_info(2, info.clone(), second, 1, None, false);
        hub.publish_info(2, info, third, 1, None, true);
        assert_eq!(
            (
                hub.describes(&first),
                hub.describes(&second),
                hub.describes(&third)
            ),
            (false, true, true)
        );
        assert_eq!(held(&hub)?, (2, 2));
        Ok(())
    }

    fn observation(n: u8) -> Observation {
        Observation {
            format: b'3',
            timestamp: u64::from(n),
            signal: 0,
            data: vec![n; 14],
        }
    }

    #[test]
    fn a_full_deduplicator_still_forwards_raw_and_counts_what_it_left_out() -> Result<(), String> {
        // Room for two new messages: each costs a key and a gathered copy.
        let one = DEDUP_KEY_COST + cost(&[0; 14]);
        let hub = Hub::new(8).max_dedup_bytes(2 * one + one / 2);
        let mut out = hub.out.subscribe();
        let (receiver, receiver_key) = key()?;
        let batch = signed_batch(&receiver, 0, (0..5).map(observation).collect())?;
        assert!(hub.publish_batch(1, batch.clone(), receiver_key));
        let forwarded = out.try_recv().map_err(|error| error.to_string())?;
        assert_eq!(*forwarded.record, Record::Batch(batch));
        let (gathered, skipped) = hub.take_deduplicated();
        assert_eq!((gathered.len(), skipped), (2, 3));
        // The gathered copies are released when taken; the two keys stay a window.
        let deduplicator = Deduplicator::new(2 * one + one / 2);
        let now = Instant::now();
        for n in 0..5 {
            deduplicator.offer(observation(n), now);
        }
        assert_eq!(deduplicator.take(now).len(), 2);
        deduplicator.offer(observation(5), now);
        deduplicator.offer(observation(6), now);
        assert_eq!(deduplicator.take_skipped(), 4);
        // A window later everything is forgotten and there is room again.
        let later = now + DEDUPLICATION_WINDOW;
        assert_eq!(deduplicator.take(later).len(), 1);
        assert_eq!(deduplicator.held(), 0);
        deduplicator.offer(observation(7), later);
        deduplicator.offer(observation(8), later);
        assert_eq!(deduplicator.take(later).len(), 2);
        Ok(())
    }

    #[test]
    fn a_source_is_an_ipv4_address_or_an_ipv6_64() -> Result<(), String> {
        let parse = |text: &str| text.parse::<IpAddr>().map_err(|error| error.to_string());
        assert_eq!(source_of(parse("192.0.2.7")?), parse("192.0.2.7")?);
        assert_eq!(source_of(parse("::ffff:192.0.2.7")?), parse("192.0.2.7")?);
        assert_eq!(
            source_of(parse("2001:db8:1:2:aaaa:bbbb:cccc:dddd")?),
            parse("2001:db8:1:2::")?
        );
        let hub = Hub::new(8).max_connections_per_address(2);
        let a = parse("2001:db8:1:2::1")?;
        let b = parse("2001:db8:1:2::2")?;
        let held = (hub.connection(a), hub.connection(b));
        assert!(held.0.is_some() && held.1.is_some());
        assert!(hub.connection(a).is_none());
        assert!(hub.connection(parse("2001:db8:1:3::1")?).is_some());
        drop(held);
        assert!(hub.connection(a).is_some());
        assert!(
            hub.per_address
                .lock()
                .map_err(|e| e.to_string())?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn a_replay_is_dropped_after_its_hash_is_forgotten() {
        let mut forwarded = Forwarded::new(Duration::ZERO);
        assert!(forwarded.admit([1; 32], "engine", 0));
        assert!(forwarded.admit([2; 32], "engine", 200));
        assert!(forwarded.admit([4; 32], "engine", 201));
        // Two rotations later the first hash is gone, and only its sequence refuses it.
        assert!(!forwarded.seen.contains(&[1; 32]));
        assert!(!forwarded.admit([1; 32], "engine", 0));
    }

    #[test]
    fn descriptions_are_held_to_bytes_as_well_as_count() -> Result<(), String> {
        let hub = Hub::new(8);
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        let size = info.as_bytes().len();
        hub.directory.lock().map_err(|e| e.to_string())?.max_bytes = 3 * size;
        let keys = (0..5)
            .map(|_| key().map(|(_, public)| public))
            .collect::<Result<Vec<_>, _>>()?;
        for receiver in &keys {
            hub.publish_info(2, info.clone(), *receiver, 1, None, false);
        }
        assert_eq!(held(&hub)?, (3, 3));
        // The oldest were forgotten, from both structures.
        assert_eq!(
            keys.iter()
                .map(|key| hub.describes(key))
                .collect::<Vec<_>>(),
            vec![false, false, true, true, true]
        );
        assert_eq!(
            hub.directory.lock().map_err(|e| e.to_string())?.bytes,
            3 * size
        );
        Ok(())
    }

    #[test]
    fn hashes_are_bounded_by_count_and_the_oldest_go_first() {
        let mut seen = Seen::new(Duration::from_secs(3_600), 4);
        for n in 0..10u8 {
            seen.insert([n; 32]);
            assert!(seen.len() <= 8);
        }
        assert!(!seen.contains(&[0; 32]) && !seen.contains(&[3; 32]));
        assert!(seen.contains(&[8; 32]) && seen.contains(&[9; 32]));
    }

    #[test]
    fn a_new_boot_is_remembered_in_a_table_full_of_streams_that_publish() {
        const STREAMS: usize = 1_000;
        let mut forwarded = Forwarded::bounded(Duration::from_secs(3_600), STREAMS, 1_000_000);
        let mut hashes = 0u32;
        let mut next = || {
            hashes += 1;
            let mut hash = [0; 32];
            hash[..4].copy_from_slice(&hashes.to_be_bytes());
            hash
        };
        // Every stream held has published more than once.
        for stream in 0..STREAMS {
            assert!(forwarded.admit(next(), ("old", stream), 0));
            assert!(forwarded.admit(next(), ("old", stream), 1));
        }
        // A new boot's first batch is remembered, so a replay of it is refused by sequence.
        assert!(forwarded.admit(next(), ("new", 0), 5));
        assert!(forwarded.newest.get(&("new", 0)).is_some());
        assert!(!forwarded.admit(next(), ("new", 0), 5));
        assert!(forwarded.newest.len() <= STREAMS);
    }

    #[test]
    fn a_churn_of_new_streams_never_forgets_one_that_is_publishing() {
        const STREAMS: usize = 16;
        let mut forwarded = Forwarded::bounded(Duration::from_secs(3_600), STREAMS, 1_000_000);
        let mut hashes = 0u32;
        let mut next = || {
            hashes += 1;
            let mut hash = [0; 32];
            hash[..4].copy_from_slice(&hashes.to_be_bytes());
            hash
        };
        // An established stream: it has published twice.
        assert!(forwarded.admit(next(), ("honest", 0), 0));
        assert!(forwarded.admit(next(), ("honest", 0), 1));
        // A stranger churning boots, each its own new stream, many times the table's size; the
        // honest stream publishing only now and then.
        for boot in 0..(20 * STREAMS as u64) {
            assert!(forwarded.admit(next(), ("stranger", boot), 0));
            // Publishing once per half a table's worth of new streams.
            if boot % (STREAMS as u64 / 2) == 0 {
                assert!(forwarded.admit(next(), ("honest", 0), 2 + boot / (STREAMS as u64 / 2)));
            }
        }
        assert!(forwarded.newest.len() <= STREAMS);
        // Still remembered: a replay of an old sequence, under a hash never seen, is refused.
        assert!(!forwarded.admit(next(), ("honest", 0), 1));
    }

    fn signed_positions(
        engine: &Identity,
        boot_id: u64,
        sequence: u64,
    ) -> Result<Positions, String> {
        Positions::sign(
            engine,
            &tally_wire::PositionsContent {
                boot_id,
                sequence,
                issued_ms: 1,
                positions: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())
    }

    #[test]
    fn a_restarted_engine_is_a_new_stream_not_a_replay() -> Result<(), String> {
        let hub = Hub::new(8);
        let (engine, engine_key) = key()?;
        assert!(hub.publish_positions(1, signed_positions(&engine, 1, 1_000)?, engine_key));
        // A new boot at 0 is forwarded; the old boot far behind is still refused.
        assert!(hub.publish_positions(1, signed_positions(&engine, 2, 0)?, engine_key));
        assert!(!hub.publish_positions(1, signed_positions(&engine, 1, 0)?, engine_key));
        assert!(hub.publish_positions(1, signed_positions(&engine, 2, 1)?, engine_key));
        Ok(())
    }

    /// `count` distinct valid keys, cheaply: encodings of small y coordinates, about half of which
    /// are points. Nothing is signed by them.
    fn throwaways(count: usize) -> Vec<PublicKey> {
        (0u64..)
            .filter_map(|y| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&y.to_le_bytes());
                PublicKey::from_bytes(bytes).ok()
            })
            .take(count)
            .collect()
    }

    /// The descriptions `items` holds, by identity (each kept description is its own record).
    fn identities(items: &[Item]) -> Vec<usize> {
        let mut identities: Vec<usize> = items
            .iter()
            .map(|item| Arc::as_ptr(&item.record) as usize)
            .collect();
        identities.sort_unstable();
        identities
    }

    /// What `Subscription::wants` keeps of every description, one test each: the rule the index
    /// must agree with.
    fn brute_force(hub: &Hub, subscription: &Subscription) -> Result<Vec<usize>, String> {
        let directory = hub.directory.lock().map_err(|e| e.to_string())?;
        let all = directory.all();
        Ok(identities(
            &all.into_iter()
                .filter(|item| subscription.wants(item))
                .collect::<Vec<_>>(),
        ))
    }

    #[test]
    fn a_64_region_subscription_over_50000_receivers_reads_only_its_matches_off_the_batch_lock()
    -> Result<(), String> {
        use std::sync::mpsc;
        use tally_wire::Streams;
        const RECEIVERS: usize = RECEIVERS_REMEMBERED;
        let hub = Arc::new(Hub::new(8));
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        // Receivers spread over a few degrees, one in a hundred declaring no location.
        let place = |n: usize| -> Result<Location, String> {
            let n = i32::try_from(n).map_err(|e| e.to_string())?;
            Ok(Location {
                lat_e7: 350_000_000 + (n % 250) * 200_000,
                lon_e7: -1_200_000_000 + (n / 250) * 200_000,
                alt_m: 0,
                precision_m: 0,
            })
        };
        let keys = throwaways(RECEIVERS);
        for (n, receiver) in keys.iter().enumerate() {
            let at = (n % 100 != 0).then(|| place(n)).transpose()?;
            hub.publish_info(2, info.clone(), *receiver, 1, at, false);
        }
        // A thousand move: the index follows a newer description's cell.
        for (n, receiver) in keys.iter().enumerate().take(1_000) {
            hub.publish_info(
                2,
                info.clone(),
                *receiver,
                2,
                Some(place(n + 25_000)?),
                false,
            );
        }
        assert_eq!(held(&hub)?, (RECEIVERS, RECEIVERS));
        {
            let directory = hub.directory.lock().map_err(|e| e.to_string())?;
            let indexed: usize = directory.by_point.values().map(Vec::len).sum();
            let located = directory
                .known
                .values()
                .filter(|known| known.cell.is_some());
            assert_eq!(indexed, located.count());
        }
        // Mostly resolution 5, some coarser, one named twice and one inside another, 64 in all.
        let mut regions = Vec::new();
        for n in 0..60 {
            let resolution = if n % 10 == 0 { 3 } else { 5 };
            regions
                .push(Region::containing(&place(n * 761)?, resolution).map_err(|e| e.to_string())?);
        }
        regions.push(regions[1]);
        regions.push(Region::containing(&place(0)?, 7).map_err(|e| e.to_string())?);
        regions.push(Region::containing(&place(0)?, 4).map_err(|e| e.to_string())?);
        regions.push(Region::containing(&place(49_999)?, 2).map_err(|e| e.to_string())?);
        assert_eq!(regions.len(), tally_wire::record::MAX_REGIONS);
        let subscription = Subscription {
            streams: Streams::RAW,
            regions,
        };
        let expected = brute_force(&hub, &subscription)?;
        assert!(!expected.is_empty() && expected.len() < RECEIVERS);
        // The batch path's lock held throughout: the answer is read without it, or never.
        let batch_lock = hub.receivers.lock().map_err(|e| e.to_string())?;
        let (answered, answer) = mpsc::channel();
        let asking = Arc::clone(&hub);
        let asked = subscription.clone();
        std::thread::spawn(move || {
            let _ = answered.send(asking.answer(&asked));
        });
        let Answer { items, visited } = answer.recv().map_err(|e| e.to_string())?;
        drop(batch_lock);
        // The same receivers as testing every one, each once, and nothing else read to find them.
        assert_eq!(identities(&items), expected);
        assert_eq!(items.len(), expected.len());
        assert_eq!(visited, items.len());
        // The whole world reads everything; no raw stream reads nothing.
        for (streams, regions) in [
            (Streams::RAW, Vec::new()),
            (Streams::POSITIONS, subscription.regions.clone()),
        ] {
            let other = Subscription { streams, regions };
            let Answer { items, visited } = hub.answer(&other);
            assert_eq!(identities(&items), brute_force(&hub, &other)?);
            assert_eq!(visited, items.len());
        }
        Ok(())
    }

    #[test]
    fn a_new_receiver_is_described_in_a_table_full_of_receivers_that_publish() -> Result<(), String>
    {
        let hub = Hub::new(8);
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        // Every receiver held has had batches forwarded.
        // Then more new keys than the table holds, so only its own activity can keep it.
        let full = throwaways(2 * RECEIVERS_REMEMBERED + 1_000);
        let (publishing, churn) = full.split_at(RECEIVERS_REMEMBERED);
        for receiver in publishing {
            hub.publish_info(2, info.clone(), *receiver, 1, None, false);
            hub.receivers
                .lock()
                .map_err(|e| e.to_string())?
                .touch(receiver);
        }
        assert_eq!(held(&hub)?, (RECEIVERS_REMEMBERED, RECEIVERS_REMEMBERED));
        // A new located receiver, known through a relay link: its description, then its batches.
        let (new, new_key) = key()?;
        let place = Location {
            lat_e7: 515_000_000,
            lon_e7: -1_000_000,
            alt_m: 0,
            precision_m: 0,
        };
        let cell = Region::point(&place).map_err(|e| e.to_string())?;
        hub.publish_info(2, signed_info(&new)?, new_key, 1, Some(place), false);
        assert!(hub.describes(&new_key), "dropped on its first description");
        let mut out = hub.out.subscribe();
        // New keys keep arriving; it publishes once per hundred of them, and stays.
        for (n, receiver) in churn.iter().enumerate() {
            if n % 100 == 0 {
                let sequence = u64::try_from(n / 100).map_err(|e| e.to_string())?;
                assert!(hub.publish_batch(2, signed_batch(&new, sequence, Vec::new())?, new_key));
                let routed = out.try_recv().map_err(|e| e.to_string())?;
                assert_eq!(
                    routed.cell,
                    Some(cell),
                    "a batch routed with no cell at {n}"
                );
            }
            hub.publish_info(2, info.clone(), *receiver, 1, None, false);
            let _ = out.try_recv();
            assert!(hub.describes(&new_key), "forgot the new receiver at {n}");
        }
        assert_eq!(held(&hub)?, (RECEIVERS_REMEMBERED, RECEIVERS_REMEMBERED));
        Ok(())
    }

    #[test]
    fn the_deduplicator_keeps_one_copy_of_each_message_across_threads_in_the_order_offered()
    -> Result<(), String> {
        let deduplicator = Arc::new(Deduplicator::new(usize::MAX));
        let messages = |offset: u32| -> Vec<Observation> {
            (0..2_000u32)
                .map(|n| Observation {
                    format: b'3',
                    timestamp: u64::from(offset),
                    signal: 0,
                    data: n.to_be_bytes().repeat(4),
                })
                .collect()
        };
        let now = Instant::now();
        // The same messages heard by eight receivers at once.
        let threads: Vec<_> = (0..8)
            .map(|receiver| {
                let deduplicator = Arc::clone(&deduplicator);
                let heard = messages(receiver);
                std::thread::spawn(move || {
                    for observation in heard {
                        deduplicator.offer(observation, now);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread
                .join()
                .map_err(|_| "a receiver's thread panicked".to_owned())?;
        }
        let gathered = deduplicator.take(now);
        let mut data: Vec<Vec<u8>> = gathered.iter().map(|o| o.data.clone()).collect();
        data.sort_unstable();
        data.dedup();
        assert_eq!((gathered.len(), data.len()), (2_000, 2_000));
        // One thread alone: what is taken is in the order it was offered, across every shard.
        let alone = Deduplicator::new(usize::MAX);
        for observation in messages(0) {
            alone.offer(observation, now);
        }
        assert_eq!(alone.take(now), messages(0));
        // The keys are a window's; then nothing is held.
        deduplicator.take(now + DEDUPLICATION_WINDOW);
        assert_eq!(deduplicator.held(), 0);
        Ok(())
    }
}
