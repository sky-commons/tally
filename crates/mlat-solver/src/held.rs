//! The raw an MLAT participant holds (RFC-0171 §3.8.1, crate docs § Holding raw): a grow-only set
//! of Mode S receptions keyed by observation identity, the union of everything delivered, kept
//! per 5 s grid bin in a compact form and indexed once per bin. One implementation for everyone
//! who holds raw (an engine solving, a consumer verifying and re-solving), so two holders of the
//! same deliveries hold the same bins.
//!
//! - **What is held** is decided by the message alone (`wanted`): the Mode S replies MLAT solves
//!   (DF0, 4, 5, 11, 16, 20, 21 with an address), and of DF17/18 only what syncs clocks (an
//!   airborne position with an altitude) or gives a sync position its prior (an operational
//!   status with a NACp). Everything else ADS-B sends (identification, velocity, surface) is
//!   never used and never held, nor are Mode A/C or UAT.
//! - **An observation is held once**, by identity (receiver, epoch, counter, message hash): of its
//!   copies, the earliest signed batch wall clock, which places it in its bin.
//! - **Compact**: a held observation is 24 bytes (its counter and wall clock within the bin in one
//!   word, receiver, epoch and message as indices); a message's bytes and hash are held once per
//!   bin however many heard it; a receiver's key once per bin.
//! - **Two stages**: a bin is open while its raw may still arrive, then sealed (`seal_through`),
//!   when its records are sorted into identity order, deduplicated and indexed once; a sealed bin
//!   is immutable and shared (`Arc`), so a window is assembled from its bins without a copy.
//! - **Bounded by bytes**: beyond `capacity` bytes a new observation is refused (and counted)
//!   until a bin is forgotten.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use tally_wire::PublicKey;
use tally_wire::batch::{BatchContent, format};

use crate::modes;
use crate::obs::{ObservationId, Reception, message_hash};
use crate::scope::{GRID_MS, bin_of};

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
    /// Observations refused for room, or for a bin already sealed.
    pub dropped: usize,
}

/// One held observation: 24 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// The 48-bit counter above, the wall clock's milliseconds into the bin below.
    packed: u64,
    pub receiver: u32,
    pub epoch: u32,
    pub message: u32,
}

impl Record {
    fn new(receiver: u32, epoch: u32, counter: u64, into_ms: u16, message: u32) -> Self {
        Self {
            packed: (counter << 16) | u64::from(into_ms),
            receiver,
            epoch,
            message,
        }
    }

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
/// renumbered in their order.
fn thin(
    bin: i64,
    messages: Vec<Message>,
    records: Vec<Record>,
    receivers: usize,
) -> (Vec<Message>, Vec<Record>) {
    let mut by_message: Vec<Vec<u32>> = vec![Vec::new(); messages.len()];
    for (index, record) in records.iter().enumerate() {
        by_message[record.message as usize].push(index as u32);
    }
    let adsb: std::collections::BTreeSet<u32> = messages
        .iter()
        .filter(|message| message.sync)
        .filter_map(|message| message.address)
        .collect();
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
    let mut used = vec![false; messages.len()];
    for (record, kept) in records.iter().zip(&keep) {
        if *kept {
            used[record.message as usize] = true;
        }
    }
    let mut renumber = vec![u32::MAX; messages.len()];
    let mut out_messages = Vec::new();
    for (index, message) in messages.into_iter().enumerate() {
        if used[index] {
            renumber[index] = out_messages.len() as u32;
            out_messages.push(message);
        }
    }
    let out_records = records
        .into_iter()
        .zip(keep)
        .filter(|(_, kept)| *kept)
        .map(|(record, _)| Record {
            message: renumber[record.message as usize],
            ..record
        })
        .collect();
    (out_messages, out_records)
}

/// A bin still taking raw.
#[derive(Default)]
struct Open {
    receivers: HashMap<PublicKey, u32>,
    keys: Vec<PublicKey>,
    messages: HashMap<Vec<u8>, u32>,
    data: Vec<Vec<u8>>,
    records: Vec<Record>,
}

impl Open {
    fn bytes(&self) -> usize {
        self.records.len() * size_of::<Record>()
            + self.data.len() * (size_of::<Message>() + 2 * size_of::<usize>())
            + self.keys.len() * 48
    }
}

/// A sync candidate of one bin: a message and the records of it (by distinct receivers, at least
/// two), ascending.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub message: u32,
    pub records: Vec<u32>,
}

/// One sealed bin: its records in identity order, and their index.
#[derive(Debug)]
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
    pub adsb: std::collections::BTreeSet<u32>,
}

impl Bin {
    fn seal(bin: i64, open: Open) -> Self {
        // Receivers and messages in canonical order, and the records renumbered.
        let mut receiver_order: Vec<u32> = (0..open.keys.len() as u32).collect();
        receiver_order.sort_unstable_by_key(|index| open.keys[*index as usize]);
        let mut receiver_map = vec![0u32; open.keys.len()];
        for (new, old) in receiver_order.iter().enumerate() {
            receiver_map[*old as usize] = new as u32;
        }
        let receivers: Vec<PublicKey> = receiver_order
            .iter()
            .map(|old| open.keys[*old as usize])
            .collect();
        let unsorted: Vec<Message> = open.data.iter().map(|data| Message::of(data)).collect();
        let mut message_order: Vec<u32> = (0..unsorted.len() as u32).collect();
        message_order.sort_unstable_by_key(|index| unsorted[*index as usize].hash);
        let mut message_map = vec![0u32; unsorted.len()];
        for (new, old) in message_order.iter().enumerate() {
            message_map[*old as usize] = new as u32;
        }
        let messages: Vec<Message> = message_order
            .iter()
            .map(|old| unsorted[*old as usize])
            .collect();
        let mut records: Vec<Record> = open
            .records
            .into_iter()
            .map(|record| Record {
                receiver: receiver_map[record.receiver as usize],
                message: message_map[record.message as usize],
                ..record
            })
            .collect();
        // Identity order, of copies the earliest wall clock first; then copies dropped.
        records.sort_unstable_by_key(|record| {
            (
                record.receiver,
                record.epoch,
                record.counter(),
                record.message,
                record.into_ms(),
            )
        });
        records.dedup_by(|later, earlier| {
            (later.receiver, later.epoch, later.counter(), later.message)
                == (
                    earlier.receiver,
                    earlier.epoch,
                    earlier.counter(),
                    earlier.message,
                )
        });
        let adsb: std::collections::BTreeSet<u32> = messages
            .iter()
            .filter(|message| message.sync)
            .filter_map(|message| message.address)
            .collect();
        let (messages, mut records) = thin(bin, messages, records, receivers.len());
        records.shrink_to_fit();
        // The index, once.
        let mut by_message: Vec<Vec<u32>> = vec![Vec::new(); messages.len()];
        for (index, record) in records.iter().enumerate() {
            by_message[record.message as usize].push(index as u32);
        }
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
        }
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

    /// Bytes held, index included.
    pub fn bytes(&self) -> usize {
        let index: usize = self.by_address.values().map(Vec::len).sum::<usize>()
            + self
                .candidates
                .iter()
                .map(|candidate| candidate.records.len() + 2)
                .sum::<usize>()
            + self.heard.iter().map(Vec::len).sum::<usize>()
            + self
                .status
                .values()
                .flatten()
                .map(|(_, records)| records.len() + 1)
                .sum::<usize>();
        self.records.len() * size_of::<Record>()
            + self.messages.len() * size_of::<Message>()
            + self.receivers.len() * (size_of::<PublicKey>() + 2 * size_of::<Vec<u32>>() + 1)
            + index * size_of::<u32>()
            + self.by_address.len() * 48
            + self.status.len() * 48
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

    /// Whether an identity is held, by binary search in identity order.
    pub fn contains(&self, id: &ObservationId) -> bool {
        let Some(receiver) = self.receiver(&id.receiver) else {
            return false;
        };
        let Ok(message) = self
            .messages
            .binary_search_by_key(&id.message, |message| message.hash)
        else {
            return false;
        };
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
            .is_ok()
    }
}

/// Raw, per bin: open while it may still arrive, sealed once it may not.
pub struct Held {
    capacity: usize,
    open: BTreeMap<i64, Open>,
    sealed: BTreeMap<i64, Arc<Bin>>,
    sealed_bytes: usize,
    /// No bin up to this is open any more: raw for it is refused.
    sealed_through: Option<i64>,
}

impl Held {
    /// Holds at most `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            open: BTreeMap::new(),
            sealed: BTreeMap::new(),
            sealed_bytes: 0,
            sealed_through: None,
        }
    }

    /// Bytes held, open bins at their estimate.
    pub fn bytes(&self) -> usize {
        self.sealed_bytes + self.open.values().map(Open::bytes).sum::<usize>()
    }

    /// Observations held (an open bin's copies included until it is sealed).
    pub fn len(&self) -> usize {
        self.sealed
            .values()
            .map(|bin| bin.records.len())
            .sum::<usize>()
            + self
                .open
                .values()
                .map(|open| open.records.len())
                .sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Takes the wanted Mode S receptions of one verified batch of `receiver`.
    pub fn add(&mut self, receiver: PublicKey, content: &BatchContent) -> Added {
        self.add_observations(
            receiver,
            content.counter_epoch,
            content.wall_ms,
            &content.observations,
        )
    }

    /// Takes one reception, as `add` would within a batch of it: what a simulator at world scale
    /// feeds without building batches.
    pub fn add_one(&mut self, reception: &Reception) -> Added {
        self.add_observations(
            reception.receiver,
            reception.epoch,
            reception.wall_ms,
            std::slice::from_ref(&reception.observation),
        )
    }

    fn add_observations(
        &mut self,
        receiver: PublicKey,
        counter_epoch: u32,
        wall_ms: u64,
        observations: &[tally_wire::Observation],
    ) -> Added {
        let mut added = Added::default();
        let bin = bin_of(wall_ms);
        if self.sealed_through.is_some_and(|through| bin <= through) {
            added.dropped = observations.len();
            return added;
        }
        let into_ms = (wall_ms % GRID_MS) as u16;
        let mut bytes = self.bytes();
        let open = self.open.entry(bin).or_default();
        for observation in observations {
            if !matches!(
                observation.format,
                format::MODE_S_SHORT | format::MODE_S_LONG
            ) || observation.data.len() > LONG
                || !wanted(&observation.data)
            {
                added.filtered += 1;
                continue;
            }
            let needed = size_of::<Record>()
                + if open.receivers.contains_key(&receiver) {
                    0
                } else {
                    48
                }
                + if open.messages.contains_key(&observation.data) {
                    0
                } else {
                    size_of::<Message>() + 2 * size_of::<usize>()
                };
            if bytes + needed > self.capacity {
                added.dropped += 1;
                continue;
            }
            let receiver_index = match open.receivers.get(&receiver) {
                Some(index) => *index,
                None => {
                    let index = open.keys.len() as u32;
                    open.keys.push(receiver);
                    open.receivers.insert(receiver, index);
                    bytes += 48;
                    index
                }
            };
            let message = match open.messages.get(&observation.data) {
                Some(index) => *index,
                None => {
                    let index = open.data.len() as u32;
                    open.data.push(observation.data.clone());
                    open.messages.insert(observation.data.clone(), index);
                    bytes += size_of::<Message>() + 2 * size_of::<usize>();
                    index
                }
            };
            open.records.push(Record::new(
                receiver_index,
                counter_epoch,
                observation.timestamp & 0xffff_ffff_ffff,
                into_ms,
                message,
            ));
            bytes += size_of::<Record>();
            added.new += 1;
        }
        added
    }

    /// Seals every open bin up to `bin`: from here on raw for them is refused.
    pub fn seal_through(&mut self, bin: i64) {
        let later = self.open.split_off(&(bin + 1));
        let sealing = std::mem::replace(&mut self.open, later);
        for (at, open) in sealing {
            let sealed = Bin::seal(at, open);
            self.sealed_bytes += sealed.bytes();
            self.sealed.insert(at, Arc::new(sealed));
        }
        self.sealed_through = Some(self.sealed_through.map_or(bin, |through| through.max(bin)));
    }

    /// Forgets every bin before `bin`.
    pub fn forget_before(&mut self, bin: i64) {
        let kept = self.sealed.split_off(&bin);
        for old in std::mem::replace(&mut self.sealed, kept).into_values() {
            self.sealed_bytes -= old.bytes();
        }
        self.open = self.open.split_off(&bin);
    }

    /// Forgets everything of `receiver` (it left, or became unusable). Rare, so it rebuilds the
    /// bins that held it.
    pub fn forget_receiver(&mut self, receiver: &PublicKey) {
        for open in self.open.values_mut() {
            if let Some(index) = open.receivers.get(receiver).copied() {
                open.records.retain(|record| record.receiver != index);
            }
        }
        let affected: Vec<i64> = self
            .sealed
            .iter()
            .filter(|(_, bin)| bin.receiver(receiver).is_some())
            .map(|(at, _)| *at)
            .collect();
        for at in affected {
            let Some(old) = self.sealed.remove(&at) else {
                continue;
            };
            self.sealed_bytes -= old.bytes();
            let mut open = Open::default();
            let skip = old.receiver(receiver);
            for record in &old.records {
                if Some(record.receiver) == skip {
                    continue;
                }
                let key = old.receivers[record.receiver as usize];
                let receiver_index = *open.receivers.entry(key).or_insert_with(|| {
                    open.keys.push(key);
                    open.keys.len() as u32 - 1
                });
                let data = old.messages[record.message as usize].data().to_vec();
                let message = match open.messages.get(&data) {
                    Some(index) => *index,
                    None => {
                        let index = open.data.len() as u32;
                        open.data.push(data.clone());
                        open.messages.insert(data, index);
                        index
                    }
                };
                open.records.push(Record {
                    receiver: receiver_index,
                    message,
                    ..*record
                });
            }
            let sealed = Bin::seal(at, open);
            self.sealed_bytes += sealed.bytes();
            self.sealed.insert(at, Arc::new(sealed));
        }
    }

    /// The sealed bins from `first` to `last`, ascending (a bin with no raw is absent).
    pub fn bins(&self, first: i64, last: i64) -> Vec<Arc<Bin>> {
        self.sealed
            .range(first..=last)
            .map(|(_, bin)| Arc::clone(bin))
            .collect()
    }

    /// The sealed bins' numbers, ascending.
    pub fn sealed(&self) -> Vec<i64> {
        self.sealed.keys().copied().collect()
    }

    /// Whether an identity is held in a sealed bin.
    pub fn contains(&self, id: &ObservationId) -> bool {
        self.sealed.values().any(|bin| bin.contains(id))
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
    held.sealed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::{Identity, Observation};

    /// A DF11 all-call reply of `address`, which MLAT uses.
    fn df11(address: u32) -> Vec<u8> {
        let body = [
            (11 << 3) | 5,
            (address >> 16) as u8,
            (address >> 8) as u8,
            address as u8,
        ];
        modes::with_parity(&body, 0)
    }

    fn content(wall_ms: u64, messages: &[(u8, Vec<u8>, u64)]) -> BatchContent {
        BatchContent {
            boot_id: 1,
            sequence: 0,
            counter_epoch: 3,
            wall_ms,
            dropped: 0,
            previous: [0; 32],
            observations: messages
                .iter()
                .map(|(format, data, timestamp)| Observation {
                    format: *format,
                    timestamp: *timestamp,
                    signal: 0,
                    data: data.clone(),
                })
                .collect(),
        }
    }

    #[test]
    fn what_mlat_uses_is_held_once_in_24_bytes_and_the_rest_is_never_held() {
        assert_eq!(size_of::<Record>(), 24);
        let key = Identity::from_seed([1; 32]).public();
        let mut held = Held::new(usize::MAX);
        let reply = df11(0x40621d);
        let added = held.add(
            key,
            &content(
                9_000,
                &[
                    (format::MODE_S_SHORT, reply.clone(), 10),
                    (format::MODE_S_SHORT, vec![0x5d, 1, 2, 3, 4, 5, 6], 11),
                    (b'1', vec![1, 2], 12),
                ],
            ),
        );
        assert_eq!((added.new, added.filtered), (1, 2));
        // The same reception again, in an earlier batch: held once, with the earlier wall clock.
        held.add(
            key,
            &content(6_000, &[(format::MODE_S_SHORT, reply.clone(), 10)]),
        );
        held.seal_through(1);
        let bins = held.bins(0, 10);
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0].records.len(), 1);
        assert_eq!(bins[0].wall_ms(&bins[0].records[0]), 6_000);
        assert!(held.contains(&bins[0].id(0)));
        // A sealed bin takes nothing more.
        let late = held.add(key, &content(7_000, &[(format::MODE_S_SHORT, reply, 99)]));
        assert_eq!(late.dropped, 1);
        held.forget_before(2);
        assert!(held.is_empty());
    }

    #[test]
    fn beyond_its_bytes_new_raw_is_refused() {
        let key = Identity::from_seed([1; 32]).public();
        let mut held = Held::new(400);
        let added = held.add(
            key,
            &content(
                1,
                &(0..10u64)
                    .map(|n| (format::MODE_S_SHORT, df11(0x400000 + n as u32), n))
                    .collect::<Vec<_>>(),
            ),
        );
        assert!(added.dropped > 0 && added.new > 0);
        assert!(held.bytes() <= 400, "{}", held.bytes());
    }
}
