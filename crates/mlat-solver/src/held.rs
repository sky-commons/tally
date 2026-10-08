//! The raw an MLAT participant holds (RFC-0171 §3.8.1, crate docs § Holding raw; RFC-0177 §5): a
//! grow-only set of Mode S receptions keyed by observation identity, the union of everything
//! delivered, kept per 5 s grid bin and indexed once per bin. One implementation for everyone who
//! holds raw (an engine solving, a relay's standing, a consumer verifying and re-solving), so two
//! holders of the same deliveries hold the same bins, and a relay holds it once.
//!
//! - **What is held** is decided by the message alone (`wanted`): the Mode S replies MLAT solves
//!   (DF0, 4, 5, 11, 16, 20, 21 with an address), and of DF17/18 only what syncs clocks (an
//!   airborne position with an altitude) or gives a sync position its prior (an operational
//!   status with a NACp). Everything else ADS-B sends (identification, velocity, surface) is
//!   never used and never held, nor are Mode A/C or UAT.
//! - **An observation is held once**, by identity (receiver, epoch, counter, message hash): of its
//!   copies, the earliest signed batch wall clock, which places it in its bin.
//! - **Two stages.** A bin is open while its raw may still arrive ([`Open`]): per receiver, its
//!   receptions as they came (28 bytes each, the message inline), in chunks that grow without
//!   ever being copied, and nothing shared between receivers, so raw split by receiver (a relay's
//!   raw shards) is held by independent owners. Then it is sealed ([`Bin::seal_from`]): each
//!   receiver's receptions sorted on their own (in parallel), the bin's messages gathered once
//!   and ordered by hash, the receivers merged in key order, and the result deduplicated, thinned
//!   and indexed once. Sealing any split of a bin's raw by receiver gives the same bin, byte for
//!   byte, at any number of threads. A sealed bin is immutable and shared (`Arc`) through
//!   [`SealedBins`], so a window, or a relay's standing, reads it without a copy.
//! - **Bounded, whole** ([`Limits`]): a receiver may hold at most `per_receiver_bin` wanted
//!   receptions in a bin, and beyond them its raw of that bin is refused whole (what it held there
//!   is let go), which depends on that receiver's own raw alone, never on arrival order. Beyond
//!   `bytes` held in all, the same: the receiver's raw of the bin is refused whole. Both counted.
//!   What a holder reserves per receiver to never reach either is [`Rates::cost`].
//! - **Accounted as allocated**: every byte [`Held::bytes`] reports is a capacity actually
//!   allocated (vectors by capacity, maps by their tables), so admission is sized on what is
//!   really in memory.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use tally_wire::batch::{BatchContent, format};
use tally_wire::{Decoded, ObsView, PublicKey};

use crate::modes;
use crate::obs::{ObservationId, Reception, message_hash};
use crate::scope::{AFTER, BEFORE, GRID_MS, STRIDE, bin_of};

/// The longest Mode S message.
const LONG: usize = 14;

/// Whether MLAT ever uses `data` (module docs, What is held).
pub fn wanted(data: &[u8]) -> bool {
    let Some(df) = modes::downlink_format(data) else {
        return false;
    };
    match df {
        0 | 4 | 5 | 11 | 16 | 20 | 21 => modes::address(data).is_some(),
        17 | 18 => {
            modes::airborne_position(data).is_some_and(|position| position.altitude.is_some())
                || modes::nacp(data).is_some()
        }
        _ => false,
    }
}

/// What one batch added.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Added {
    /// Observations taken (an open bin deduplicates when it is sealed, so copies count here).
    pub new: usize,
    /// Observations MLAT never uses, not held.
    pub filtered: usize,
    /// Wanted observations for a bin already sealed: later than its settling, so missing for
    /// every reader of the bins alike.
    pub late: usize,
    /// Wanted observations refused with their receiver's whole raw of the bin (`Limits`): this
    /// batch's, and what the receiver had held in the bin until it was refused.
    pub refused: usize,
}

impl Added {
    /// Observations not held, for any reason but MLAT never using them.
    pub fn dropped(&self) -> usize {
        self.late + self.refused
    }
}

/// One held observation of a sealed bin: 24 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// The 48-bit counter above, the wall clock's milliseconds into the bin below.
    packed: u64,
    pub receiver: u32,
    pub epoch: u32,
    pub message: u32,
}

impl Record {
    pub fn counter(&self) -> u64 {
        self.packed >> 16
    }

    pub fn into_ms(&self) -> u16 {
        (self.packed & 0xffff) as u16
    }
}

/// A message, held once per bin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub hash: [u8; 32],
    len: u8,
    data: [u8; LONG],
    /// The address it names, if any (`modes::address`).
    pub address: Option<u32>,
    /// An airborne position with an altitude and an address: a sync candidate.
    pub sync: bool,
    /// An operational status with a NACp.
    pub status: bool,
}

impl Message {
    fn of(data: &[u8]) -> Self {
        let mut bytes = [0u8; LONG];
        let len = data.len().min(LONG);
        bytes[..len].copy_from_slice(&data[..len]);
        let address = modes::address(data);
        Self {
            hash: message_hash(data),
            len: len as u8,
            data: bytes,
            address,
            sync: address.is_some()
                && modes::airborne_position(data).is_some_and(|p| p.altitude.is_some()),
            status: modes::nacp(data).is_some(),
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }
}

/// Sync candidates a receiver keeps per bin at sealing, the lowest message hashes first (`S`):
/// more than any tile keeps of it there (ten, and one with each of its partners), so the tile
/// rule's choice among them is the choice it would have made among all of them nearly always,
/// and every holder keeps the same ones.
pub const SYNC_PER_RECEIVER: usize = 32;
/// One aircraft heard with ADS-B in this many is solved by MLAT too, chosen by hash, so the
/// published covariance can be measured against the aircraft's own GNSS position.
pub const CALIBRATION_SAMPLE: u32 = 16;
/// What the calibration sample is hashed under.
const SAMPLE_DOMAIN: &[u8] = b"tally calibration sample";

/// Whether `address`, heard with ADS-B in `bin`, is in the calibration sample: the first byte of
/// BLAKE2s-256 over `"tally calibration sample" 0x00`, the address and the bin, big-endian, below
/// `256 / CALIBRATION_SAMPLE`.
pub fn sampled(address: u32, bin: i64) -> bool {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(SAMPLE_DOMAIN);
    hasher.update([0]);
    hasher.update(address.to_be_bytes());
    hasher.update(bin.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    u32::from(digest[0]) < 256 / CALIBRATION_SAMPLE
}

/// Canonical ingest thinning, when a bin is sealed (crate docs, § Holding raw): of the sync
/// candidates (an airborne position with an altitude heard by two or more), each receiver keeps
/// its `SYNC_PER_RECEIVER` lowest-hash ones; replies of an aircraft heard with ADS-B in the bin
/// are dropped (it is no MLAT target) unless it is in the calibration sample, whose receptions are
/// all kept; operational status is kept. Messages nothing keeps are dropped, and the rest
/// renumbered in their order. What it returns is allocated to its size.
fn thin(
    bin: i64,
    messages: Vec<Message>,
    records: Vec<Record>,
    receivers: usize,
    adsb: &BTreeSet<u32>,
) -> (Vec<Message>, Vec<Record>) {
    let by_message = by_message(messages.len(), &records);
    let mut keep = vec![false; records.len()];
    let mut taken = vec![0usize; receivers];
    // Messages ascend by hash: the rank.
    for (message, list) in messages.iter().zip(&by_message) {
        let sample = message.address.is_some_and(|address| sampled(address, bin));
        if message.status || sample {
            for record in list {
                keep[*record as usize] = true;
            }
            continue;
        }
        if message.sync {
            let mut distinct: Vec<u32> = list
                .iter()
                .map(|record| records[*record as usize].receiver)
                .collect();
            distinct.dedup();
            if distinct.len() < 2 {
                continue;
            }
            let kept: Vec<u32> = list
                .iter()
                .copied()
                .filter(|record| {
                    taken[records[*record as usize].receiver as usize] < SYNC_PER_RECEIVER
                })
                .collect();
            let mut by: Vec<u32> = kept
                .iter()
                .map(|record| records[*record as usize].receiver)
                .collect();
            by.dedup();
            if by.len() < 2 {
                continue;
            }
            for receiver in by {
                taken[receiver as usize] += 1;
            }
            for record in kept {
                keep[record as usize] = true;
            }
            continue;
        }
        let target = message
            .address
            .is_some_and(|address| !adsb.contains(&address));
        if target {
            for record in list {
                keep[*record as usize] = true;
            }
        }
    }
    drop(by_message);
    let mut used = vec![false; messages.len()];
    for (record, kept) in records.iter().zip(&keep) {
        if *kept {
            used[record.message as usize] = true;
        }
    }
    let mut renumber = vec![u32::MAX; messages.len()];
    let mut out_messages = Vec::with_capacity(used.iter().filter(|used| **used).count());
    for (index, message) in messages.into_iter().enumerate() {
        if used[index] {
            renumber[index] = out_messages.len() as u32;
            out_messages.push(message);
        }
    }
    let mut out_records = Vec::with_capacity(keep.iter().filter(|kept| **kept).count());
    out_records.extend(records.into_iter().zip(keep).filter(|(_, kept)| *kept).map(
        |(record, _)| Record {
            message: renumber[record.message as usize],
            ..record
        },
    ));
    (out_messages, out_records)
}

/// Per message, its records, ascending.
fn by_message(messages: usize, records: &[Record]) -> Vec<Vec<u32>> {
    let mut counts = vec![0u32; messages];
    for record in records {
        counts[record.message as usize] += 1;
    }
    let mut lists: Vec<Vec<u32>> = counts
        .into_iter()
        .map(|count| Vec::with_capacity(count as usize))
        .collect();
    for (index, record) in records.iter().enumerate() {
        lists[record.message as usize].push(index as u32);
    }
    lists
}

/// One reception while its bin is open: 28 bytes, the message inline, the receiver implied by
/// whose list it is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Raw {
    /// The 48-bit counter's low 32 bits.
    counter_low: u32,
    /// Its high 16 bits above, the wall clock's milliseconds into the bin below.
    high_into: u32,
    epoch: u32,
    len: u8,
    data: [u8; LONG],
}

impl Raw {
    fn new(epoch: u32, counter: u64, into_ms: u16, data: &[u8]) -> Self {
        let counter = counter & 0xffff_ffff_ffff;
        let mut bytes = [0u8; LONG];
        bytes[..data.len()].copy_from_slice(data);
        Self {
            counter_low: counter as u32,
            high_into: (((counter >> 32) as u32) << 16) | u32::from(into_ms),
            epoch,
            len: data.len() as u8,
            data: bytes,
        }
    }

    fn counter(&self) -> u64 {
        (u64::from(self.high_into >> 16) << 32) | u64::from(self.counter_low)
    }

    fn wall_into_bin(&self) -> u16 {
        self.high_into as u16
    }

    fn message(&self) -> MessageKey {
        MessageKey {
            len: self.len,
            data: self.data,
        }
    }
}

/// A message's bytes as a value: what an open bin's messages are gathered by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct MessageKey {
    len: u8,
    data: [u8; LONG],
}

impl MessageKey {
    fn bytes(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }

    /// Which of `parts` it is gathered in at sealing (FNV-1a): any split works, this one spreads.
    fn part(&self, parts: usize) -> usize {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        (hash % parts.max(1) as u64) as usize
    }
}

/// The first chunk a receiver's list of a bin allocates, and the largest: the list grows by
/// doubling chunks up to the largest, and no chunk is ever moved or copied, so growing costs no
/// copy and at most one chunk is part empty.
const FIRST_CHUNK: usize = 32;
const LAST_CHUNK: usize = 256;

/// A list that grows by chunks (`FIRST_CHUNK`, `LAST_CHUNK`).
#[derive(Debug)]
struct Chunks<T> {
    chunks: Vec<Vec<T>>,
    len: usize,
}

impl<T> Default for Chunks<T> {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }
}

impl<T: Copy> Chunks<T> {
    /// Bytes allocated.
    fn bytes(&self) -> usize {
        self.chunks.capacity() * size_of::<Vec<T>>()
            + self
                .chunks
                .iter()
                .map(|chunk| chunk.capacity() * size_of::<T>())
                .sum::<usize>()
    }

    /// The bytes the next `push` allocates, at most.
    fn next_growth(&self) -> usize {
        match self.chunks.last() {
            Some(chunk) if chunk.len() < chunk.capacity() => 0,
            last => {
                let size = last.map_or(FIRST_CHUNK, |chunk| (chunk.capacity() * 2).min(LAST_CHUNK));
                let list = if self.chunks.len() == self.chunks.capacity() {
                    self.chunks.capacity().max(4) * size_of::<Vec<T>>()
                } else {
                    0
                };
                size * size_of::<T>() + list
            }
        }
    }

    /// Adds `item`: the bytes this allocated.
    fn push(&mut self, item: T) -> usize {
        let before = if self.next_growth() == 0 {
            None
        } else {
            Some(self.bytes())
        };
        if before.is_some() {
            let size = self
                .chunks
                .last()
                .map_or(FIRST_CHUNK, |chunk| (chunk.capacity() * 2).min(LAST_CHUNK));
            self.chunks.push(Vec::with_capacity(size));
        }
        if let Some(chunk) = self.chunks.last_mut() {
            chunk.push(item);
        }
        self.len += 1;
        before.map_or(0, |before| self.bytes() - before)
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.chunks.iter().flatten()
    }
}

/// One receiver's raw of an open bin.
#[derive(Debug)]
struct Slot {
    key: PublicKey,
    raws: Chunks<Raw>,
    /// Refused whole (`Limits`): nothing more of it is taken in this bin, and it is absent from
    /// the sealed bin.
    refused: bool,
}

/// Bytes a hash map's table allocates (hashbrown's layout: a power-of-two bucket count at 7/8
/// load, each bucket an entry and a control byte, and a group of control bytes more).
fn map_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    let capacity = map.capacity();
    if capacity == 0 {
        return 0;
    }
    let buckets = if capacity < 8 {
        (capacity + 1).next_power_of_two()
    } else {
        (capacity * 8 / 7).next_power_of_two()
    };
    (buckets * size_of::<(K, V)>()).next_multiple_of(16) + buckets + 16
}

/// The open raw of one bin, of some receivers: what an owner of raw (a whole holder, or one of a
/// relay's raw shards) hands to sealing ([`Bin::seal_from`]).
#[derive(Debug)]
pub struct Fragment {
    bin: i64,
    slots: Vec<Slot>,
    index: HashMap<PublicKey, u32>,
    /// Bytes allocated by the slots' lists.
    raw_bytes: usize,
}

impl Fragment {
    pub fn new(bin: i64) -> Self {
        Self {
            bin,
            slots: Vec::new(),
            index: HashMap::new(),
            raw_bytes: 0,
        }
    }

    pub fn bin(&self) -> i64 {
        self.bin
    }

    /// Bytes allocated.
    pub fn bytes(&self) -> usize {
        self.raw_bytes + self.slots.capacity() * size_of::<Slot>() + map_bytes(&self.index)
    }

    /// Receptions held (copies included).
    pub fn len(&self) -> usize {
        self.slots.iter().map(|slot| slot.raws.len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `receiver`'s slot, made if it has none.
    fn slot(&mut self, receiver: PublicKey) -> usize {
        if let Some(at) = self.index.get(&receiver) {
            return *at as usize;
        }
        let at = self.slots.len();
        self.slots.push(Slot {
            key: receiver,
            raws: Chunks::default(),
            refused: false,
        });
        self.index.insert(receiver, at as u32);
        at
    }

    /// Lets go of everything `slot` held and refuses it: the bytes freed and receptions let go.
    fn refuse(&mut self, slot: usize) -> (usize, usize) {
        let held = std::mem::take(&mut self.slots[slot].raws);
        self.slots[slot].refused = true;
        self.raw_bytes -= held.bytes();
        (held.bytes(), held.len)
    }

    /// Forgets `receiver` entirely: the bytes freed.
    fn forget(&mut self, receiver: &PublicKey) -> usize {
        let Some(at) = self.index.get(receiver).copied() else {
            return 0;
        };
        let before = self.bytes();
        let held = std::mem::take(&mut self.slots[at as usize].raws);
        self.raw_bytes -= held.bytes();
        self.slots.swap_remove(at as usize);
        self.index.remove(receiver);
        if let Some(moved) = self.slots.get(at as usize) {
            self.index.insert(moved.key, at);
        }
        before - self.bytes()
    }
}

/// Bins of raw a holder keeps sealed beyond a canonical window and its stride, for settling
/// standing (the merge rule's: a solution is settled against raw a few bins after its window).
pub const RAW_SPARE_BINS: i64 = 4;
/// Sealed bins a holder keeps at once, at most: a canonical window (`BEFORE + 1 + AFTER`), the
/// stride it is solved after, the spare bins standing settles in, and the bin being sealed.
pub const SEALED_BINS_HELD: i64 = BEFORE + 1 + AFTER + STRIDE + RAW_SPARE_BINS;

/// What a holder of raw refuses beyond (module docs, Bounded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Bytes held at once, open and sealed.
    pub bytes: usize,
    /// Wanted receptions one receiver may hold in one bin.
    pub per_receiver_bin: usize,
}

impl Limits {
    pub const UNBOUNDED: Self = Self {
        bytes: usize::MAX,
        per_receiver_bin: usize::MAX,
    };

    /// Bounded by bytes alone.
    pub fn bytes(bytes: usize) -> Self {
        Self {
            bytes,
            per_receiver_bin: usize::MAX,
        }
    }

    /// What a holder of `receivers` receivers at `rates`, sealing `settle_ms` after a bin ends,
    /// is bounded by: every receiver's reservation (`Rates::cost`), and each receiver's ceiling.
    pub fn for_receivers(receivers: usize, rates: Rates, settle_ms: u64) -> Self {
        Self {
            bytes: receivers.saturating_mul(rates.cost(settle_ms).total()),
            per_receiver_bin: rates.per_bin_ceiling(),
        }
    }
}

/// The rates a receiver's raw is admitted at, which decide what it costs a holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rates {
    /// Wanted receptions a second (what `wanted` keeps), the mean an admitted receiver sends.
    pub wanted_per_s: usize,
    /// Of them, what canonical thinning keeps when a bin is sealed.
    pub kept_per_s: usize,
    /// The most wanted receptions a second one receiver may send: beyond its bin's share, its raw
    /// of the bin is refused whole.
    pub ceiling_per_s: usize,
}

/// Bytes an open reception costs: its record, as allocated.
pub const OPEN_BYTES_PER_RECEPTION: usize = size_of::<Raw>();
/// Bytes a receiver's raw of one open bin costs beyond its receptions, at most: its slot, its
/// entry in the bin's map, its list of chunks, and one chunk part empty.
pub const OPEN_BYTES_PER_RECEIVER_BIN: usize = size_of::<Slot>()
    + 2 * (size_of::<PublicKey>() + size_of::<u32>() + 1)
    + 16 * size_of::<Vec<Raw>>()
    + LAST_CHUNK * size_of::<Raw>();
/// Bytes a kept observation of a sealed bin costs, its share of the bin's messages and index
/// included, at most: measured on the world benchmark (`tests::world_scale_one_node`) at the real
/// reception rate, and held by `tests::a_sealed_bin_costs_what_admission_reserves`.
pub const SEALED_BYTES_PER_RECORD: usize = 40;

impl Rates {
    /// A real receiver (RFC-0177, box-01): about 600 receptions a second, of which about 60%
    /// survive `wanted`, and of those what thinning kept in the world benchmark at that rate. The
    /// ceiling is five times the mean.
    pub const MEASURED: Self = Self {
        wanted_per_s: 360,
        kept_per_s: 150,
        ceiling_per_s: 1_800,
    };

    /// Wanted receptions a receiver may hold in one bin.
    pub fn per_bin_ceiling(&self) -> usize {
        self.ceiling_per_s.saturating_mul(GRID_MS as usize) / 1_000
    }

    /// What one receiver at these rates costs a holder that seals a bin `settle_ms` after it ends:
    /// its open raw over a bin and its settling, and its thinned raw over the bins a holder keeps
    /// sealed (`SEALED_BINS_HELD`).
    pub fn cost(&self, settle_ms: u64) -> Cost {
        let open_ms = GRID_MS + settle_ms;
        let open_bins = open_ms.div_ceil(GRID_MS) as usize + 1;
        let sealed_ms = SEALED_BINS_HELD as u64 * GRID_MS;
        Cost {
            open: (self.wanted_per_s as u64 * open_ms / 1_000) as usize * OPEN_BYTES_PER_RECEPTION
                + open_bins * OPEN_BYTES_PER_RECEIVER_BIN,
            sealed: (self.kept_per_s as u64 * sealed_ms / 1_000) as usize * SEALED_BYTES_PER_RECORD,
        }
    }
}

/// What one receiver costs a holder of raw, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    /// Open bins: wanted rate times a bin and its settling, at 28 bytes a reception.
    pub open: usize,
    /// Sealed bins: kept rate times the bins held, at their measured bytes a record.
    pub sealed: usize,
}

impl Cost {
    pub fn total(&self) -> usize {
        self.open.saturating_add(self.sealed)
    }
}

/// The open bins of a holder of raw (or of one of a relay's raw shards).
#[derive(Debug)]
pub struct Open {
    limits: Limits,
    bins: BTreeMap<i64, Fragment>,
    bytes: usize,
    /// No bin up to this is open any more: raw for it is late.
    through: Option<i64>,
}

impl Open {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            bins: BTreeMap::new(),
            bytes: 0,
            through: None,
        }
    }

    /// Bytes allocated.
    pub fn bytes(&self) -> usize {
        self.bytes + btree_bytes::<i64, Fragment>(self.bins.len())
    }

    /// Receptions held (copies included).
    pub fn len(&self) -> usize {
        self.bins.values().map(Fragment::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The last bin taken for sealing, if any.
    pub fn through(&self) -> Option<i64> {
        self.through
    }

    /// Takes the wanted Mode S receptions of one verified batch of `receiver`.
    pub fn add(&mut self, receiver: PublicKey, content: &BatchContent) -> Added {
        let room = self.limits.bytes;
        self.add_observations(
            receiver,
            content.counter_epoch,
            content.wall_ms,
            content.observations.iter().map(ObsView::from),
            room,
        )
    }

    /// As `add`, a batch decoded once (`tally_wire::Decoded`): the messages are read in place.
    pub fn add_decoded(&mut self, decoded: &Decoded) -> Added {
        let room = self.limits.bytes;
        self.add_decoded_within(decoded, room)
    }

    /// As `add_decoded`, these open bins growing to `room` bytes at most (the holder's limit less
    /// what it holds sealed).
    pub fn add_decoded_within(&mut self, decoded: &Decoded, room: usize) -> Added {
        let room = room.min(self.limits.bytes);
        self.add_observations(
            decoded.receiver(),
            decoded.counter_epoch(),
            decoded.wall_ms(),
            decoded.views(),
            room,
        )
    }

    /// `room`: the bytes these open bins may grow to.
    fn add_observations<'a>(
        &mut self,
        receiver: PublicKey,
        counter_epoch: u32,
        wall_ms: u64,
        observations: impl Iterator<Item = ObsView<'a>>,
        room: usize,
    ) -> Added {
        let mut added = Added::default();
        let bin = bin_of(wall_ms);
        let wanted: Vec<ObsView<'a>> = observations
            .filter(|observation| {
                let keep = matches!(
                    observation.format,
                    format::MODE_S_SHORT | format::MODE_S_LONG
                ) && observation.data.len() <= LONG
                    && wanted(observation.data);
                added.filtered += usize::from(!keep);
                keep
            })
            .collect();
        if self.through.is_some_and(|through| bin <= through) {
            added.late = wanted.len();
            return added;
        }
        let into_ms = (wall_ms % GRID_MS) as u16;
        let fragment = self.bins.entry(bin).or_insert_with(|| Fragment::new(bin));
        if wanted.is_empty() {
            return added;
        }
        let before = fragment.bytes();
        let slot = fragment.slot(receiver);
        self.bytes += fragment.bytes() - before;
        if fragment.slots[slot].refused {
            added.refused = wanted.len();
            return added;
        }
        let over_count =
            fragment.slots[slot].raws.len + wanted.len() > self.limits.per_receiver_bin;
        let mut grown = 0;
        if !over_count {
            for observation in &wanted {
                let raws = &mut fragment.slots[slot].raws;
                if self.bytes + grown + raws.next_growth() > room {
                    break;
                }
                grown += raws.push(Raw::new(
                    counter_epoch,
                    observation.timestamp,
                    into_ms,
                    observation.data,
                ));
                added.new += 1;
            }
        }
        fragment.raw_bytes += grown;
        self.bytes += grown;
        if added.new < wanted.len() {
            // Over its count or over the room: the receiver's raw of the bin is refused whole.
            let (freed, held) = fragment.refuse(slot);
            self.bytes -= freed;
            added.refused = held - added.new + wanted.len();
            added.new = 0;
        }
        added
    }

    /// Takes every open bin up to `bin` for sealing: from here on raw for them is late.
    pub fn take_through(&mut self, bin: i64) -> Vec<Fragment> {
        let later = self.bins.split_off(&(bin.saturating_add(1)));
        let taken: Vec<Fragment> = std::mem::replace(&mut self.bins, later)
            .into_values()
            .collect();
        for fragment in &taken {
            self.bytes -= fragment.bytes();
        }
        self.through = Some(self.through.map_or(bin, |through| through.max(bin)));
        taken
    }

    /// Forgets every open bin before `bin`.
    pub fn forget_before(&mut self, bin: i64) {
        let kept = self.bins.split_off(&bin);
        for old in std::mem::replace(&mut self.bins, kept).into_values() {
            self.bytes -= old.bytes();
        }
    }

    /// Forgets everything of `receiver` in the open bins.
    pub fn forget_receiver(&mut self, receiver: &PublicKey) {
        for fragment in self.bins.values_mut() {
            self.bytes -= fragment.forget(receiver);
        }
    }
}

/// A sync candidate of one bin: a message and the records of it (by distinct receivers, at least
/// two), ascending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub message: u32,
    pub records: Vec<u32>,
}

/// One sealed bin: its records in identity order, and their index.
#[derive(Debug, PartialEq, Eq)]
pub struct Bin {
    pub bin: i64,
    /// Ascending.
    pub receivers: Vec<PublicKey>,
    /// Ascending by hash.
    pub messages: Vec<Message>,
    /// In identity order: (receiver, epoch, counter, message hash).
    pub records: Vec<Record>,
    /// Per address, its records, ascending.
    pub by_address: BTreeMap<u32, Vec<u32>>,
    /// The sync candidates, ascending by message hash.
    pub candidates: Vec<Candidate>,
    /// Per receiver (its index), the candidates it heard, ascending.
    pub heard: Vec<Vec<u32>>,
    /// Per receiver, whether it heard a candidate.
    pub sync_active: Vec<bool>,
    /// Per address, its status messages, each with its records, ascending.
    pub status: BTreeMap<u32, Vec<(u32, Vec<u32>)>>,
    /// The aircraft heard with ADS-B (an airborne position with an altitude) in the bin, before
    /// thinning: no MLAT target, unless in the calibration sample.
    pub adsb: BTreeSet<u32>,
}

/// `items` cut into at most `threads` contiguous runs of about equal `weight`, in order.
fn runs<T>(
    items: &[T],
    threads: usize,
    weight: impl Fn(&T) -> usize,
) -> Vec<std::ops::Range<usize>> {
    let threads = threads.max(1).min(items.len().max(1));
    let total: usize = items.iter().map(&weight).sum::<usize>().max(1);
    let share = total.div_ceil(threads);
    let mut runs = Vec::with_capacity(threads);
    let (mut start, mut load) = (0, 0);
    for (at, item) in items.iter().enumerate() {
        load += weight(item);
        if load >= share && runs.len() + 1 < threads {
            runs.push(start..at + 1);
            start = at + 1;
            load = 0;
        }
    }
    runs.push(start..items.len());
    runs
}

/// Runs `work` on each of `inputs` on a thread of its own (here, when there is one), and returns
/// the results in the inputs' order.
fn on_threads<I: Send, R: Send>(inputs: Vec<I>, work: impl Fn(I) -> R + Sync) -> Vec<R> {
    if inputs.len() <= 1 {
        return inputs.into_iter().map(work).collect();
    }
    let work = &work;
    std::thread::scope(|scope| {
        let handles: Vec<_> = inputs
            .into_iter()
            .map(|input| scope.spawn(move || work(input)))
            .collect();
        handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(result) => result,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    })
}

/// Splits `items` into owned runs at `runs`' boundaries.
fn split_owned<T>(items: Vec<T>, runs: &[std::ops::Range<usize>]) -> Vec<Vec<T>> {
    let mut out = Vec::with_capacity(runs.len());
    let mut rest = items.into_iter();
    for run in runs {
        out.push(rest.by_ref().take(run.len()).collect());
    }
    out
}

/// A heap allocation's own cost beside what it holds (the allocator's header and rounding).
const ALLOCATION: usize = 16;

/// Bytes a vector allocates.
fn vec_bytes<T>(vec: &Vec<T>) -> usize {
    if vec.capacity() == 0 {
        0
    } else {
        vec.capacity() * size_of::<T>() + ALLOCATION
    }
}

/// Bytes a B-tree of `len` entries allocates: at least one leaf of eleven, and per entry its share
/// of a leaf at the two-thirds fill insertion in any order leaves, and of the internal nodes above.
fn btree_bytes<K, V>(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let leaf = 16 + 11 * (size_of::<K>() + size_of::<V>()) + ALLOCATION;
    let internal = leaf + 12 * size_of::<usize>();
    (len * (leaf + internal / 6).div_ceil(7)).max(leaf)
}

impl Bin {
    /// Seals `fragments`, the open raw of `bin` split among owners by receiver (module docs, Two
    /// stages), on up to `threads` threads: the same bin, byte for byte, for any split and any
    /// number of threads. A receiver in more than one fragment is held once, its raw the union.
    pub fn seal_from(bin: i64, fragments: Vec<Fragment>, threads: usize) -> Self {
        let threads = threads.max(1);
        // Every receiver's raw, in key order.
        let mut lists: Vec<(PublicKey, Vec<Chunks<Raw>>)> = Vec::new();
        {
            let mut slots: Vec<Slot> = fragments
                .into_iter()
                .flat_map(|fragment| fragment.slots)
                .filter(|slot| !slot.refused && slot.raws.len > 0)
                .collect();
            slots.sort_by_key(|slot| slot.key);
            for slot in slots {
                match lists.last_mut() {
                    Some((key, raws)) if *key == slot.key => raws.push(slot.raws),
                    _ => lists.push((slot.key, vec![slot.raws])),
                }
            }
        }
        let receivers: Vec<PublicKey> = lists.iter().map(|(key, _)| *key).collect();
        let cut = runs(&lists, threads, |(_, chunks)| {
            chunks.iter().map(|raws| raws.len).sum::<usize>()
        });
        // Each receiver's raw on its own: in (epoch, counter, message bytes) order, of copies the
        // earliest wall clock first, then copies dropped.
        let sorted: Vec<Vec<Vec<Raw>>> = on_threads(split_owned(lists, &cut), |run| {
            run.into_iter()
                .map(|(_, chunks)| {
                    let mut raws: Vec<Raw> =
                        Vec::with_capacity(chunks.iter().map(|raws| raws.len).sum());
                    for list in chunks {
                        raws.extend(list.iter().copied());
                    }
                    raws.sort_unstable_by_key(|raw| {
                        (raw.epoch, raw.counter(), raw.message(), raw.wall_into_bin())
                    });
                    raws.dedup_by_key(|raw| (raw.epoch, raw.counter(), raw.message()));
                    raws
                })
                .collect()
        });
        // The bin's messages, gathered once: each run's distinct ones split into parts by their
        // bytes, each part made (hashed, decoded) on its own, then all ordered by hash.
        let parts = cut.len();
        let gathered: Vec<Vec<Vec<MessageKey>>> = on_threads(sorted.iter().collect(), |run| {
            let mut by_part: Vec<Vec<MessageKey>> = vec![Vec::new(); parts];
            for raws in run {
                for raw in raws {
                    let key = raw.message();
                    by_part[key.part(parts)].push(key);
                }
            }
            for keys in &mut by_part {
                keys.sort_unstable();
                keys.dedup();
            }
            by_part
        });
        let mut by_part: Vec<Vec<Vec<MessageKey>>> = (0..parts).map(|_| Vec::new()).collect();
        for run in gathered {
            for (part, keys) in run.into_iter().enumerate() {
                by_part[part].push(keys);
            }
        }
        let made: Vec<(Vec<MessageKey>, Vec<Message>)> = on_threads(by_part, |lists| {
            let mut keys: Vec<MessageKey> = lists.into_iter().flatten().collect();
            keys.sort_unstable();
            keys.dedup();
            let messages = keys.iter().map(|key| Message::of(key.bytes())).collect();
            (keys, messages)
        });
        let mut order: Vec<([u8; 32], u32, u32)> = made
            .iter()
            .enumerate()
            .flat_map(|(part, (_, list))| {
                list.iter()
                    .enumerate()
                    .map(move |(at, message)| (message.hash, part as u32, at as u32))
            })
            .collect();
        order.sort_unstable();
        let mut global: Vec<Vec<u32>> = made.iter().map(|(keys, _)| vec![0; keys.len()]).collect();
        let mut messages: Vec<Message> = Vec::with_capacity(order.len());
        for (index, (_, part, at)) in order.into_iter().enumerate() {
            global[part as usize][at as usize] = index as u32;
            messages.push(made[part as usize].1[at as usize]);
        }
        let keys: Vec<Vec<MessageKey>> = made.into_iter().map(|(keys, _)| keys).collect();
        // Each receiver's records, its messages by their index, in identity order, written in
        // place into the bin's one vector.
        let total: usize = sorted.iter().flatten().map(Vec::len).sum();
        let mut records = vec![
            Record {
                packed: 0,
                receiver: 0,
                epoch: 0,
                message: 0,
            };
            total
        ];
        {
            let mut slices = Vec::with_capacity(sorted.len());
            let mut rest: &mut [Record] = &mut records;
            let mut first = 0u32;
            for run in sorted {
                let len: usize = run.iter().map(Vec::len).sum();
                let (slice, after) = rest.split_at_mut(len);
                rest = after;
                let receivers = run.len() as u32;
                slices.push((first, run, slice));
                first += receivers;
            }
            let (keys, global) = (&keys, &global);
            on_threads(slices, |(first, run, slice)| {
                let mut at = 0;
                for (offset, raws) in run.into_iter().enumerate() {
                    let out = &mut slice[at..at + raws.len()];
                    for (record, raw) in out.iter_mut().zip(&raws) {
                        let key = raw.message();
                        let part = key.part(parts);
                        let index = keys[part].binary_search(&key).unwrap_or(0);
                        *record = Record {
                            packed: (raw.counter() << 16) | u64::from(raw.wall_into_bin()),
                            receiver: first + offset as u32,
                            epoch: raw.epoch,
                            message: global[part][index],
                        };
                    }
                    out.sort_unstable_by_key(|record| {
                        (record.epoch, record.counter(), record.message)
                    });
                    at += raws.len();
                }
            });
        }
        Self::index(bin, receivers, messages, records)
    }

    /// Thins and indexes a bin's records, deduplicated in identity order.
    fn index(
        bin: i64,
        receivers: Vec<PublicKey>,
        messages: Vec<Message>,
        records: Vec<Record>,
    ) -> Self {
        let adsb: BTreeSet<u32> = messages
            .iter()
            .filter(|message| message.sync)
            .filter_map(|message| message.address)
            .collect();
        let (messages, records) = thin(bin, messages, records, receivers.len(), &adsb);
        // The index, once.
        let by_message = by_message(messages.len(), &records);
        let mut by_address: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut candidates = Vec::new();
        let mut heard: Vec<Vec<u32>> = vec![Vec::new(); receivers.len()];
        let mut sync_active = vec![false; receivers.len()];
        let mut status: BTreeMap<u32, Vec<(u32, Vec<u32>)>> = BTreeMap::new();
        for (message, list) in by_message.into_iter().enumerate() {
            let entry = &messages[message];
            let Some(address) = entry.address else {
                continue;
            };
            by_address.entry(address).or_default().extend(&list);
            if entry.status {
                status
                    .entry(address)
                    .or_default()
                    .push((message as u32, list.clone()));
            }
            if entry.sync {
                let mut distinct: Vec<u32> = list
                    .iter()
                    .map(|record| records[*record as usize].receiver)
                    .collect();
                distinct.dedup();
                if distinct.len() >= 2 {
                    let at = candidates.len() as u32;
                    for receiver in &distinct {
                        heard[*receiver as usize].push(at);
                        sync_active[*receiver as usize] = true;
                    }
                    candidates.push(Candidate {
                        message: message as u32,
                        records: list,
                    });
                }
            }
        }
        for list in by_address.values_mut() {
            list.sort_unstable();
            list.shrink_to_fit();
        }
        for list in &mut heard {
            list.shrink_to_fit();
        }
        candidates.shrink_to_fit();
        Self {
            bin,
            receivers,
            messages,
            records,
            by_address,
            candidates,
            heard,
            sync_active,
            status,
            adsb,
        }
    }

    /// Bytes allocated, index included (module docs, Accounted as allocated).
    pub fn bytes(&self) -> usize {
        vec_bytes(&self.receivers)
            + vec_bytes(&self.messages)
            + vec_bytes(&self.records)
            + vec_bytes(&self.candidates)
            + self
                .candidates
                .iter()
                .map(|candidate| vec_bytes(&candidate.records))
                .sum::<usize>()
            + vec_bytes(&self.heard)
            + self.heard.iter().map(vec_bytes).sum::<usize>()
            + vec_bytes(&self.sync_active)
            + btree_bytes::<u32, Vec<u32>>(self.by_address.len())
            + self.by_address.values().map(vec_bytes).sum::<usize>()
            + btree_bytes::<u32, Vec<(u32, Vec<u32>)>>(self.status.len())
            + self
                .status
                .values()
                .map(|list| {
                    vec_bytes(list)
                        + list
                            .iter()
                            .map(|(_, records)| vec_bytes(records))
                            .sum::<usize>()
                })
                .sum::<usize>()
            + btree_bytes::<u32, ()>(self.adsb.len())
    }

    /// The receiver index of `key`, if it is in this bin.
    pub fn receiver(&self, key: &PublicKey) -> Option<u32> {
        self.receivers.binary_search(key).ok().map(|at| at as u32)
    }

    pub fn wall_ms(&self, record: &Record) -> u64 {
        u64::try_from(self.bin).unwrap_or(0) * GRID_MS + u64::from(record.into_ms())
    }

    /// A record as the mathematics takes it.
    pub fn reception(&self, index: u32) -> Reception {
        let record = &self.records[index as usize];
        let message = &self.messages[record.message as usize];
        Reception {
            receiver: self.receivers[record.receiver as usize],
            epoch: record.epoch,
            observation: tally_wire::Observation {
                format: if message.data().len() == LONG {
                    format::MODE_S_LONG
                } else {
                    format::MODE_S_SHORT
                },
                timestamp: record.counter(),
                signal: 0,
                data: message.data().to_vec(),
            },
            wall_ms: self.wall_ms(record),
        }
    }

    /// A record's identity.
    pub fn id(&self, index: u32) -> ObservationId {
        let record = &self.records[index as usize];
        ObservationId {
            receiver: self.receivers[record.receiver as usize],
            epoch: record.epoch,
            timestamp: record.counter(),
            message: self.messages[record.message as usize].hash,
        }
    }

    /// The record of an identity, if it is held, by binary search in identity order.
    pub fn find(&self, id: &ObservationId) -> Option<u32> {
        let receiver = self.receiver(&id.receiver)?;
        let message = self
            .messages
            .binary_search_by_key(&id.message, |message| message.hash)
            .ok()?;
        let key = (receiver, id.epoch, id.timestamp, message as u32);
        self.records
            .binary_search_by_key(&key, |record| {
                (
                    record.receiver,
                    record.epoch,
                    record.counter(),
                    record.message,
                )
            })
            .ok()
            .map(|at| at as u32)
    }

    /// Whether an identity is held.
    pub fn contains(&self, id: &ObservationId) -> bool {
        self.find(id).is_some()
    }

    /// This bin's raw, open again without `receiver`: what forgetting a receiver reseals.
    fn reopen_without(&self, receiver: &PublicKey) -> Fragment {
        let mut fragment = Fragment::new(self.bin);
        let skip = self.receiver(receiver);
        for record in &self.records {
            if Some(record.receiver) == skip {
                continue;
            }
            let slot = fragment.slot(self.receivers[record.receiver as usize]);
            let grown = fragment.slots[slot].raws.push(Raw::new(
                record.epoch,
                record.counter(),
                record.into_ms(),
                self.messages[record.message as usize].data(),
            ));
            fragment.raw_bytes += grown;
        }
        fragment
    }
}

/// Where sealed bins are read from: a holder, or the shared handle of its sealed bins.
pub trait HoldsBins {
    /// The sealed bins from `first` to `last`, ascending (a bin with no raw is absent).
    fn bins(&self, first: i64, last: i64) -> Vec<Arc<Bin>>;
}

/// The sealed bins of one holder, shared: a cheap handle (`Clone` is an `Arc`) every reader of the
/// holder's raw keeps (a relay's MLAT engine and its standing read the same bins, so raw later than
/// settling is missing for both alike). Only the holder inserts and forgets; reading takes a read
/// lock for as long as it takes to clone the bins' `Arc`s, never across a seal.
#[derive(Clone, Debug, Default)]
pub struct SealedBins {
    shared: Arc<SealedShared>,
}

#[derive(Debug, Default)]
struct SealedShared {
    bins: RwLock<BTreeMap<i64, Arc<Bin>>>,
    bytes: AtomicUsize,
    records: AtomicUsize,
}

impl SealedBins {
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<i64, Arc<Bin>>> {
        self.shared
            .bins
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<i64, Arc<Bin>>> {
        self.shared
            .bins
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The sealed bin numbered `bin`, if any.
    pub fn get(&self, bin: i64) -> Option<Arc<Bin>> {
        self.read().get(&bin).cloned()
    }

    /// The sealed bins' numbers, ascending.
    pub fn numbers(&self) -> Vec<i64> {
        self.read().keys().copied().collect()
    }

    /// Bytes allocated by the sealed bins, and the handle's own.
    pub fn bytes(&self) -> usize {
        self.shared.bytes.load(Ordering::Acquire)
            + size_of::<SealedShared>()
            + 2 * size_of::<usize>()
    }

    /// Observations held in sealed bins.
    pub fn len(&self) -> usize {
        self.shared.records.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether an identity is held in a sealed bin.
    pub fn contains(&self, id: &ObservationId) -> bool {
        self.read().values().any(|bin| bin.contains(id))
    }

    /// Bytes a sealed bin costs here: its own, its shared allocation, and its share of the map.
    fn cost(bin: &Bin) -> usize {
        bin.bytes()
            + size_of::<Bin>()
            + 2 * size_of::<usize>()
            + ALLOCATION
            + btree_bytes::<i64, Arc<Bin>>(7) / 7
    }

    /// Makes `bin` readable, in place of any bin of its number.
    pub fn insert(&self, bin: Bin) {
        let bin = Arc::new(bin);
        let (bytes, records) = (Self::cost(&bin), bin.records.len());
        let old = self.write().insert(bin.bin, bin);
        self.shared.bytes.fetch_add(bytes, Ordering::AcqRel);
        self.shared.records.fetch_add(records, Ordering::AcqRel);
        if let Some(old) = old {
            self.let_go(&old);
        }
    }

    fn let_go(&self, old: &Bin) {
        self.shared
            .bytes
            .fetch_sub(Self::cost(old), Ordering::AcqRel);
        self.shared
            .records
            .fetch_sub(old.records.len(), Ordering::AcqRel);
    }

    /// Forgets every bin before `bin`.
    pub fn forget_before(&self, bin: i64) {
        let old = {
            let mut bins = self.write();
            let kept = bins.split_off(&bin);
            std::mem::replace(&mut *bins, kept)
        };
        for old in old.values() {
            self.let_go(old);
        }
    }

    /// Forgets every bin.
    pub fn clear(&self) {
        self.forget_before(i64::MAX);
        let old = std::mem::take(&mut *self.write());
        for old in old.values() {
            self.let_go(old);
        }
    }

    /// Forgets `receiver` in every sealed bin (it left, or became unusable): the bins that held
    /// it are sealed again without it, on up to `threads` threads, each built before it replaces
    /// the old one, so a reader sees one bin or the other, never none. Rare.
    pub fn forget_receiver(&self, receiver: &PublicKey, threads: usize) {
        let holding: Vec<Arc<Bin>> = self
            .read()
            .values()
            .filter(|bin| bin.receiver(receiver).is_some())
            .cloned()
            .collect();
        for old in holding {
            let fragment = old.reopen_without(receiver);
            self.insert(Bin::seal_from(old.bin, vec![fragment], threads));
        }
    }
}

impl HoldsBins for SealedBins {
    fn bins(&self, first: i64, last: i64) -> Vec<Arc<Bin>> {
        SealedBins::bins(self, first, last)
    }
}

impl SealedBins {
    /// The sealed bins from `first` to `last`, ascending (a bin with no raw is absent).
    pub fn bins(&self, first: i64, last: i64) -> Vec<Arc<Bin>> {
        if first > last {
            return Vec::new();
        }
        self.read()
            .range(first..=last)
            .map(|(_, bin)| Arc::clone(bin))
            .collect()
    }
}

/// Raw, per bin: open while it may still arrive, sealed once it may not.
#[derive(Debug)]
pub struct Held {
    limits: Limits,
    open: Open,
    sealed: SealedBins,
    threads: usize,
}

impl Held {
    /// Holds at most `capacity` bytes, sealing on one thread.
    pub fn new(capacity: usize) -> Self {
        Self::with(Limits::bytes(capacity), 1, SealedBins::new())
    }

    /// Holds within `limits`, sealing on up to `threads` threads into `sealed` (which every reader
    /// of this holder's raw shares).
    pub fn with(limits: Limits, threads: usize, sealed: SealedBins) -> Self {
        Self {
            limits,
            open: Open::new(Limits {
                bytes: usize::MAX,
                ..limits
            }),
            sealed,
            threads: threads.max(1),
        }
    }

    /// The handle of the sealed bins, for a reader to keep.
    pub fn sealed_bins(&self) -> &SealedBins {
        &self.sealed
    }

    /// Bytes allocated, open and sealed.
    pub fn bytes(&self) -> usize {
        self.open.bytes() + self.sealed.bytes()
    }

    /// Bytes allocated by the open bins.
    pub fn open_bytes(&self) -> usize {
        self.open.bytes()
    }

    /// Observations held (an open bin's copies included until it is sealed).
    pub fn len(&self) -> usize {
        self.sealed.len() + self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn room(&self) -> usize {
        self.limits.bytes.saturating_sub(self.sealed.bytes())
    }

    /// Takes the wanted Mode S receptions of one verified batch of `receiver`.
    pub fn add(&mut self, receiver: PublicKey, content: &BatchContent) -> Added {
        let room = self.room();
        self.open.add_observations(
            receiver,
            content.counter_epoch,
            content.wall_ms,
            content.observations.iter().map(ObsView::from),
            room,
        )
    }

    /// As `add`, a batch decoded once (`tally_wire::Decoded`): the messages are read in place.
    pub fn add_decoded(&mut self, decoded: &Decoded) -> Added {
        let room = self.room();
        self.open.add_observations(
            decoded.receiver(),
            decoded.counter_epoch(),
            decoded.wall_ms(),
            decoded.views(),
            room,
        )
    }

    /// Takes one reception, as `add` would within a batch of it: what a simulator at world scale
    /// feeds without building batches.
    pub fn add_one(&mut self, reception: &Reception) -> Added {
        let room = self.room();
        self.open.add_observations(
            reception.receiver,
            reception.epoch,
            reception.wall_ms,
            std::iter::once(ObsView::from(&reception.observation)),
            room,
        )
    }

    /// Seals every open bin up to `bin`: from here on raw for them is late.
    pub fn seal_through(&mut self, bin: i64) {
        for fragment in self.open.take_through(bin) {
            let at = fragment.bin();
            self.sealed
                .insert(Bin::seal_from(at, vec![fragment], self.threads));
        }
    }

    /// Forgets every bin before `bin`.
    pub fn forget_before(&mut self, bin: i64) {
        self.sealed.forget_before(bin);
        self.open.forget_before(bin);
    }

    /// Forgets everything of `receiver` (it left, or became unusable). Rare, so it reseals the
    /// bins that held it.
    pub fn forget_receiver(&mut self, receiver: &PublicKey) {
        self.open.forget_receiver(receiver);
        self.sealed.forget_receiver(receiver, self.threads);
    }

    /// The sealed bins' numbers, ascending.
    pub fn sealed(&self) -> Vec<i64> {
        self.sealed.numbers()
    }

    /// Whether an identity is held in a sealed bin.
    pub fn contains(&self, id: &ObservationId) -> bool {
        self.sealed.contains(id)
    }

    /// The sealed bins from `first` to `last`, ascending (a bin with no raw is absent).
    pub fn bins(&self, first: i64, last: i64) -> Vec<Arc<Bin>> {
        self.sealed.bins(first, last)
    }
}

impl HoldsBins for Held {
    fn bins(&self, first: i64, last: i64) -> Vec<Arc<Bin>> {
        self.sealed.bins(first, last)
    }
}

/// Every reception of `receptions` held and sealed in its bin: what a test or a simulator's whole
/// run needs.
pub fn bins_of(receptions: &[Reception]) -> BTreeMap<i64, Arc<Bin>> {
    let mut held = Held::new(usize::MAX);
    let mut batches: BTreeMap<(PublicKey, u32, u64), Vec<tally_wire::Observation>> =
        BTreeMap::new();
    for reception in receptions {
        batches
            .entry((reception.receiver, reception.epoch, reception.wall_ms))
            .or_default()
            .push(reception.observation.clone());
    }
    for ((receiver, epoch, wall_ms), observations) in batches {
        held.add(
            receiver,
            &BatchContent {
                boot_id: 0,
                sequence: 0,
                counter_epoch: epoch,
                wall_ms,
                dropped: 0,
                previous: [0; 32],
                observations,
            },
        );
    }
    held.seal_through(i64::MAX - 1);
    held.bins(i64::MIN, i64::MAX - 1)
        .into_iter()
        .map(|bin| (bin.bin, bin))
        .collect()
}

#[cfg(test)]
#[path = "held_tests.rs"]
mod tests;
