//! Answering delivery checks (RFC-0174 §2.2, RFC-0177 §7): the relay tags each batch it takes in
//! with the key its feeder gave this relay for it, keeps the 16-byte tag (never the bytes) for
//! `TAG_WINDOW_MS`, and answers a `DeliveryQuery` with a signed `DeliveryAnswer`: per batch asked,
//! its tag, or "not seen", or, for a feeder of an area it does not take, that it does not take it.
//! A query also carries the feeder's grant of keys (`TagKeys`), taken here. Its answers are also
//! evidence for its clients' credit (`credit`).
//!
//! **What it costs.** One tag a feeder a second for the window: `TAG_WINDOW_MS` of 40-byte entries,
//! about 12 KB a feeder ([`PER_FEEDER_BYTES`]), 240 MB at 20,000 feeders, where holding the
//! batches themselves for the same window would be some 8 GB. Bounded in all by [`TAGS_HELD`];
//! past it a batch is refused whole (no tag, and never denied) and counted.
//!
//! **"Not seen" is said only when it is known.** A batch is "not seen" when the relay has been
//! watching for that long and holds no entry for it: an entry is kept for every batch taken in,
//! tagged or not, for the whole window, and a feeder asks only within the window, so a batch that
//! came is still there. Neither proved nor denied (left out of the answer, which a feeder counts
//! as no vote): a batch that came while the relay held no key for its feeder (it has an entry but
//! no tag); one refused past the bound, or let go, below its stream's horizon; and any batch while
//! the relay has not yet been watching for a whole window (it may have restarted). Per stream
//! (receiver and boot) the relay keeps the horizon below which it may have let a batch go. A stream
//! silent for `STREAM_MEMORY_MS` is forgotten; a stream forgotten sooner, to bound memory, makes
//! every unknown stream unanswerable until that time has passed.
//!
//! The state is sharded by receiver, under a process-secret hash, so one lock is never every
//! feeder's.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tally_wire::delivery::{KEY_PERIOD_MS, TAG_WINDOW_MS};
use tally_wire::{
    Batch, DeliveryAnswer, DeliveryAnswerContent, DeliveryQuery, Identity, Possession, PublicKey,
    Region, Tag, TagKey, TagKeysContent, delivery_tag,
};

use crate::selection::Selection;

/// One entry a batch costs while it is held.
pub const TAG_BYTES: usize = std::mem::size_of::<Tagged>();
/// What one feeder costs the store: a batch a second (RFC-0177's feeder) for the window.
pub const PER_FEEDER_BYTES: usize = TAG_BYTES * (TAG_WINDOW_MS / 1000) as usize;
/// The most entries held in all until the relay's budget says otherwise (`Delivery::set_capacity`,
/// its `budget::Store::Delivery` share): 8 Mi, some 28,000 feeders' windows, 320 MiB. Past the
/// capacity a batch is refused whole and counted (`refused`).
pub const TAGS_HELD: usize = 8 << 20;
/// The most feeders whose keys are held.
pub const KEYED_FEEDERS: usize = 100_000;
/// The most streams (receiver and boot) whose horizon is remembered.
pub const STREAMS_REMEMBERED: usize = 100_000;
/// How long a silent stream's horizon is remembered: what "not seen" of an unknown stream means.
pub const STREAM_MEMORY_MS: u64 = 60 * 60 * 1000;
/// Locks the state is split under.
const SHARDS: usize = 64;

type StreamKey = (PublicKey, u64);

/// A batch taken in: its sequence, when, and its tag if the relay held a key for its feeder.
#[derive(Clone, Copy)]
struct Tagged {
    sequence: u64,
    at_ms: u64,
    tag: Option<(u32, Tag)>,
}

pub struct Delivery {
    shards: Box<[Mutex<Shard>]>,
    /// Which shard a receiver is in: secret, so no feeder grinds keys into one.
    placement: RandomState,
    /// When the relay began watching (the first call); `u64::MAX` before.
    started_ms: AtomicU64,
    /// Batches refused whole past `TAGS_HELD`, and grants refused past `KEYED_FEEDERS`.
    refused: AtomicU64,
    refused_keys: AtomicU64,
    /// The most entries held in all (`TAGS_HELD` until set).
    capacity: std::sync::atomic::AtomicUsize,
}

impl Default for Delivery {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct Shard {
    keys: HashMap<PublicKey, Keys>,
    streams: HashMap<StreamKey, Stream>,
    /// Streams holding entries, by their last arrival: the order entries age out in.
    active: BTreeSet<(u64, StreamKey)>,
    /// Streams holding none, by their last arrival: the order they are forgotten in.
    idle: BTreeSet<(u64, StreamKey)>,
    entries: usize,
    /// Until then a stream the relay knows nothing of may be one it forgot early.
    unsure_until_ms: u64,
}

/// A feeder's keys for this relay: `current` until `switch_at_ms`, then `next` for a period.
struct Keys {
    current: TagKey,
    next: TagKey,
    switch_at_ms: u64,
}

impl Keys {
    fn in_force(&self, now_ms: u64) -> Option<&TagKey> {
        if now_ms < self.switch_at_ms {
            Some(&self.current)
        } else if now_ms < self.switch_at_ms.saturating_add(KEY_PERIOD_MS) {
            Some(&self.next)
        } else {
            None
        }
    }
}

struct Stream {
    /// Sequences below this may have been taken in and let go (or refused).
    horizon: u64,
    last_ms: u64,
    /// In arrival order, each kept `TAG_WINDOW_MS`.
    entries: VecDeque<Tagged>,
}

/// What the relay can say of one sequence.
enum Said {
    Proved(u32, Tag),
    NotSeen,
    /// Taken in untagged, let go, refused, or of a time the relay was not watching.
    Unknown,
}

impl Delivery {
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            capacity: std::sync::atomic::AtomicUsize::new(TAGS_HELD),
            placement: RandomState::new(),
            started_ms: AtomicU64::new(u64::MAX),
            refused: AtomicU64::new(0),
            refused_keys: AtomicU64::new(0),
        }
    }

    fn shard(&self, receiver: &PublicKey) -> Option<std::sync::MutexGuard<'_, Shard>> {
        let index = usize::try_from(self.placement.hash_one(receiver.as_bytes()) % SHARDS as u64)
            .unwrap_or(0);
        self.shards.get(index)?.lock().ok()
    }

    /// The first instant the relay was asked or told anything: when it began watching.
    fn started(&self, now_ms: u64) -> u64 {
        let _ =
            self.started_ms
                .compare_exchange(u64::MAX, now_ms, Ordering::AcqRel, Ordering::Acquire);
        self.started_ms.load(Ordering::Acquire)
    }

    /// Whether the relay has watched for a whole window by `now_ms`.
    fn watched(&self, now_ms: u64) -> bool {
        now_ms >= self.started(now_ms).saturating_add(TAG_WINDOW_MS)
    }

    /// A receiver's batch the relay took in (new, verified): tagged under the key its feeder gave
    /// this relay, if one is in force, and held as an entry for the window.
    pub fn hold(&self, batch: &Batch, now_ms: u64) {
        let Ok(receiver) = batch.receiver() else {
            return;
        };
        self.hold_bytes(
            receiver,
            (batch.boot_id(), batch.sequence()),
            batch.as_bytes(),
            now_ms,
        );
    }

    /// `hold` of a batch named by its receiver, (boot, sequence) and signed bytes.
    /// The most bytes of entries held in all: the relay's budget for the store. Past it a batch is
    /// refused whole, counted.
    pub fn set_capacity(&self, bytes: usize) {
        self.capacity
            .store((bytes / TAG_BYTES).max(SHARDS), Ordering::Release);
    }

    fn hold_bytes(&self, receiver: PublicKey, name: (u64, u64), bytes: &[u8], now_ms: u64) {
        let watched = self.watched(now_ms);
        let bound = self.capacity.load(Ordering::Acquire) / SHARDS;
        let Some(mut shard) = self.shard(&receiver) else {
            return;
        };
        if !shard.hold(receiver, name, bytes, (watched, bound), now_ms) {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The signed answer to `query` from a feeder whose signed location falls at `point`: per
    /// sequence asked, its tag, "not seen" for one known never to have come, and nothing for one
    /// the relay cannot speak for; or, outside the areas the relay takes, that it does not take
    /// the area and nothing else. The query's keys, if it carries a grant for this relay signed by
    /// the feeder of an area it takes, are taken first.
    pub fn answer_at(
        &self,
        selection: &Selection,
        identity: Option<&Identity>,
        query: &DeliveryQuery,
        point: Option<Region>,
        now_ms: u64,
    ) -> Option<DeliveryAnswer> {
        let identity = identity?;
        let takes_area = selection.takes_receiver(point);
        let watched = self.watched(now_ms);
        let entries = if takes_area {
            if let Some(keys) = &query.keys
                && keys.verify().is_ok()
                && keys.signer().is_ok_and(|signer| signer == query.receiver)
                && let Ok(content) = keys.content()
                && content.member == identity.public()
            {
                self.take_keys(query.receiver, &content, now_ms);
            }
            let mut shard = self.shard(&query.receiver)?;
            let stream = (query.receiver, query.boot_id);
            query
                .ranges
                .iter()
                .flat_map(|range| range.first..=range.last)
                .filter_map(
                    |sequence| match shard.said(stream, sequence, watched, now_ms) {
                        Said::Proved(key, tag) => Some((sequence, Possession::Proved { key, tag })),
                        Said::NotSeen => Some((sequence, Possession::NotSeen)),
                        Said::Unknown => None,
                    },
                )
                .collect()
        } else {
            Vec::new()
        };
        let content = DeliveryAnswerContent {
            nonce: query.nonce,
            receiver: query.receiver,
            boot_id: query.boot_id,
            issued_ms: now_ms,
            takes_area,
            entries,
        };
        DeliveryAnswer::sign(identity, &content).ok()
    }

    /// A feeder's grant, checked and verified: in force from now. A grant older than the keys
    /// held (a replay) changes nothing.
    fn take_keys(&self, receiver: PublicKey, content: &TagKeysContent, now_ms: u64) {
        self.started(now_ms);
        let Some(mut shard) = self.shard(&receiver) else {
            return;
        };
        if !shard.take_keys(receiver, content, now_ms) {
            self.refused_keys.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Entries held now, and their bytes.
    pub fn tags(&self) -> usize {
        self.each(|shard| shard.entries)
    }

    pub fn held_bytes(&self) -> usize {
        self.tags() * TAG_BYTES
    }

    /// Streams remembered now.
    pub fn streams(&self) -> usize {
        self.each(|shard| shard.streams.len())
    }

    /// Feeders whose keys are held now.
    pub fn keyed(&self) -> usize {
        self.each(|shard| shard.keys.len())
    }

    /// Batches refused whole past `TAGS_HELD`, and grants past `KEYED_FEEDERS`, since start.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn refused_keys(&self) -> u64 {
        self.refused_keys.load(Ordering::Relaxed)
    }

    fn each(&self, count: impl Fn(&Shard) -> usize) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.lock().ok().map(|shard| count(&shard)))
            .sum()
    }
}

impl Shard {
    /// False when the batch was refused past the bound.
    fn hold(
        &mut self,
        receiver: PublicKey,
        (boot_id, sequence): (u64, u64),
        bytes: &[u8],
        (watched, bound): (bool, usize),
        now_ms: u64,
    ) -> bool {
        self.let_go(now_ms);
        let key = (receiver, boot_id);
        let tag = match self.keys.get(&receiver) {
            Some(keys) => match keys.in_force(now_ms) {
                Some(key) => Some((key.id, delivery_tag(&key.key, bytes))),
                None => {
                    self.keys.remove(&receiver);
                    None
                }
            },
            None => None,
        };
        let before = self.streams.get(&key).map(|stream| stream.last_ms);
        let stream = self.streams.entry(key).or_insert(Stream {
            // A stream first seen before the relay has watched a whole window may have sent
            // earlier batches it did not see.
            horizon: if watched { 0 } else { sequence },
            last_ms: now_ms,
            entries: VecDeque::new(),
        });
        // The hub hands each batch once; a copy straight after is all that is checked for (a
        // scan of the stream would make a long one quadratic).
        if stream
            .entries
            .back()
            .is_some_and(|held| held.sequence == sequence)
        {
            return true;
        }
        let was_active = before.is_some() && !stream.entries.is_empty();
        self.entries -= age(stream, now_ms);
        let mut full = self.entries >= bound;
        if full {
            // Room the window would have made in the other streams is made before refusing.
            let freed = age_all(&mut self.streams, &self.active, now_ms);
            self.entries -= freed;
            full = self.entries >= bound;
        }
        let Some(stream) = self.streams.get_mut(&key) else {
            return true;
        };
        if full {
            // Refused whole: it has no entry, so it must never be said "not seen".
            stream.horizon = stream.horizon.max(sequence.saturating_add(1));
        } else {
            stream.entries.push_back(Tagged {
                sequence,
                at_ms: now_ms,
                tag,
            });
            self.entries += 1;
        }
        stream.last_ms = stream.last_ms.max(now_ms);
        let after = stream.last_ms;
        let active = !stream.entries.is_empty();
        if let Some(before) = before {
            if was_active {
                self.active.remove(&(before, key));
            } else {
                self.idle.remove(&(before, key));
            }
        }
        if active {
            self.active.insert((after, key));
        } else {
            self.idle.insert((after, key));
        }
        self.bound_streams();
        !full
    }

    fn take_keys(&mut self, receiver: PublicKey, content: &TagKeysContent, now_ms: u64) -> bool {
        if let Some(held) = self.keys.get(&receiver)
            && held.current.id > content.current.id
        {
            return true;
        }
        if !self.keys.contains_key(&receiver) && self.keys.len() >= KEYED_FEEDERS / SHARDS {
            self.keys.retain(|_, keys| keys.in_force(now_ms).is_some());
            if self.keys.len() >= KEYED_FEEDERS / SHARDS {
                return false;
            }
        }
        self.keys.insert(
            receiver,
            Keys {
                current: content.current,
                next: content.next,
                switch_at_ms: now_ms.saturating_add(content.switch_in_ms),
            },
        );
        true
    }

    /// Lets go entries past the window: the oldest of each stream as it is held again, and every
    /// entry of a stream silent for the window; forgets streams silent past their memory.
    fn let_go(&mut self, now_ms: u64) {
        while let Some((last_ms, key)) = self.active.first().copied() {
            if last_ms.saturating_add(TAG_WINDOW_MS) >= now_ms {
                break;
            }
            self.active.pop_first();
            if let Some(stream) = self.streams.get_mut(&key) {
                self.entries -= stream.entries.len();
                for held in stream.entries.drain(..) {
                    stream.horizon = stream.horizon.max(held.sequence.saturating_add(1));
                }
                stream.entries = VecDeque::new();
            }
            self.idle.insert((last_ms, key));
        }
        while let Some((last_ms, key)) = self.idle.first().copied() {
            if last_ms.saturating_add(STREAM_MEMORY_MS) >= now_ms {
                break;
            }
            self.idle.pop_first();
            self.streams.remove(&key);
        }
        // The oldest entries of a stream still active age out as it is held again or asked of.
    }

    /// Bounds the streams remembered: the longest silent first, idle before active.
    fn bound_streams(&mut self) {
        while self.streams.len() > STREAMS_REMEMBERED / SHARDS {
            let Some((last_ms, key)) = self.idle.pop_first().or_else(|| self.active.pop_first())
            else {
                break;
            };
            // Forgotten early: until its memory would have run out, an unknown stream may be it.
            self.unsure_until_ms = self
                .unsure_until_ms
                .max(last_ms.saturating_add(STREAM_MEMORY_MS));
            if let Some(stream) = self.streams.remove(&key) {
                self.entries -= stream.entries.len();
            }
        }
    }

    fn said(&mut self, key: StreamKey, sequence: u64, watched: bool, now_ms: u64) -> Said {
        if let Some(stream) = self.streams.get_mut(&key) {
            let freed = age(stream, now_ms);
            self.entries -= freed;
        }
        match self.streams.get(&key) {
            Some(stream) => {
                match stream
                    .entries
                    .iter()
                    .rev()
                    .find(|held| held.sequence == sequence)
                {
                    Some(held) => match held.tag {
                        Some((id, tag)) => Said::Proved(id, tag),
                        None => Said::Unknown,
                    },
                    None if sequence >= stream.horizon && watched => Said::NotSeen,
                    None => Said::Unknown,
                }
            }
            None if !watched || now_ms < self.unsure_until_ms => Said::Unknown,
            None => Said::NotSeen,
        }
    }
}

/// Ages every active stream (only at the bound, so a refusal is never for room the window would
/// have made); how many entries it let go.
fn age_all(
    streams: &mut HashMap<StreamKey, Stream>,
    active: &BTreeSet<(u64, StreamKey)>,
    now_ms: u64,
) -> usize {
    active
        .iter()
        .filter_map(|(_, key)| streams.get_mut(key).map(|stream| age(stream, now_ms)))
        .sum()
}

/// Lets go a stream's entries older than the window, raising its horizon past them; how many.
fn age(stream: &mut Stream, now_ms: u64) -> usize {
    let mut freed = 0;
    while let Some(oldest) = stream.entries.front() {
        if oldest.at_ms.saturating_add(TAG_WINDOW_MS) >= now_ms {
            break;
        }
        stream.horizon = stream.horizon.max(oldest.sequence.saturating_add(1));
        stream.entries.pop_front();
        freed += 1;
    }
    freed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::delivery::{TAG_KEY_LEN, key_period, tag_keys_for};
    use tally_wire::rendezvous::area_of;
    use tally_wire::{BatchContent, Location, SequenceRange, TagKeys};

    type Result = std::result::Result<(), String>;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn here() -> Location {
        Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        }
    }

    /// Past a whole window from the relay's first call at `T0`: "not seen" can be said.
    const T0: u64 = 1_000;
    const WATCHED: u64 = T0 + TAG_WINDOW_MS;

    fn batch(feeder: &Identity, boot_id: u64, sequence: u64) -> std::result::Result<Batch, String> {
        Batch::sign(
            feeder,
            &BatchContent {
                boot_id,
                sequence,
                counter_epoch: 0,
                wall_ms: sequence,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(text)
    }

    /// A batch's bytes, unsigned (the hub verifies before it holds; holding reads only the
    /// prefix), `len` long: for floods, which signing would make slow.
    fn unsigned(
        key: &PublicKey,
        boot_id: u64,
        sequence: u64,
        len: usize,
    ) -> std::result::Result<Batch, String> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&boot_id.to_be_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.resize(len.max(bytes.len() + 64), 0);
        Batch::from_bytes(bytes).map_err(text)
    }

    fn query(feeder: &Identity, boot_id: u64, first: u64, last: u64) -> DeliveryQuery {
        DeliveryQuery {
            nonce: [first as u8 ^ 0x5a; 32],
            receiver: feeder.public(),
            boot_id,
            ranges: vec![SequenceRange { first, last }],
            keys: None,
        }
    }

    /// The feeder's keys for `member` in the period of `now_ms`, as its grant then names them.
    fn keys_at(member: &PublicKey, id: u32) -> (TagKey, TagKey) {
        let key = |id: u32| {
            let mut key = [0; TAG_KEY_LEN];
            key[..32].copy_from_slice(member.as_bytes());
            key[..4].copy_from_slice(&id.to_be_bytes());
            TagKey { id, key }
        };
        (key(id), key(id + 1))
    }

    fn grant(
        feeder: &Identity,
        member: &PublicKey,
        now_ms: u64,
    ) -> std::result::Result<TagKeys, String> {
        let (current, next) = keys_at(member, key_period(now_ms));
        TagKeys::sign(
            feeder,
            &TagKeysContent {
                member: *member,
                current,
                next,
                switch_in_ms: KEY_PERIOD_MS - now_ms % KEY_PERIOD_MS,
            },
        )
        .map_err(text)
    }

    /// Gives `relay` the feeder's keys, as a query carrying them does.
    fn keyed(
        delivery: &Delivery,
        selection: &Selection,
        relay: &Identity,
        feeder: &Identity,
        point: Region,
        now_ms: u64,
    ) -> Result {
        let carrying = DeliveryQuery {
            ranges: Vec::new(),
            keys: Some(grant(feeder, &relay.public(), now_ms)?),
            ..query(feeder, 0, 0, 0)
        };
        delivery
            .answer_at(selection, Some(relay), &carrying, Some(point), now_ms)
            .ok_or("no answer")?;
        Ok(())
    }

    fn taking_here() -> std::result::Result<(Selection, Region), String> {
        let selection = Selection::new();
        selection.set_taken(vec![area_of(&here()).map_err(text)?]);
        Ok((selection, Region::point(&here()).map_err(text)?))
    }

    /// What the feeder checks: the tag under one of the keys in force when it sent the batch.
    fn verifies(member: &PublicKey, batch: &Batch, sent_ms: u64, key: u32, tag: &Tag) -> bool {
        tag_keys_for(sent_ms).contains(&key)
            && delivery_tag(&keys_at(member, key).0.key, batch.as_bytes()) == *tag
    }

    #[test]
    fn tags_verify_against_the_batch_and_a_batch_never_taken_is_not_seen() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        keyed(&delivery, &selection, &relay, &feeder, point, T0)?;
        let now = WATCHED + 1_000;
        // Keyed again in the period it sends in: a feeder grants every period.
        keyed(&delivery, &selection, &relay, &feeder, point, now)?;
        let held: Vec<Batch> = (10..13)
            .map(|seq| batch(&feeder, 4, seq))
            .collect::<std::result::Result<_, _>>()?;
        for batch in &held {
            delivery.hold(batch, now);
        }
        let asked = query(&feeder, 4, 9, 14);
        let answer = delivery
            .answer_at(&selection, Some(&relay), &asked, Some(point), now + 1_000)
            .ok_or("no answer")?;
        answer.verify().map_err(text)?;
        assert_eq!(answer.signer().map_err(text)?, relay.public());
        let content = answer.content().map_err(text)?;
        assert!(content.takes_area);
        assert_eq!(content.nonce, asked.nonce);
        let said: Vec<u64> = content
            .entries
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect();
        assert_eq!(said, vec![9, 10, 11, 12, 13, 14]);
        for (sequence, possession) in &content.entries {
            match (
                held.iter().find(|batch| batch.sequence() == *sequence),
                possession,
            ) {
                (Some(batch), Possession::Proved { key, tag }) => {
                    assert!(verifies(&relay.public(), batch, now, *key, tag));
                }
                (None, Possession::NotSeen) => {}
                other => return Err(format!("{sequence}: {other:?}")),
            }
        }
        // Another boot of the same feeder, never taken in: not seen.
        let other_boot = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 5, 10, 10),
                Some(point),
                now,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert_eq!(other_boot.entries, vec![(10, Possession::NotSeen)]);
        Ok(())
    }

    #[test]
    fn nothing_is_denied_before_a_whole_window_was_watched_or_without_a_key() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        // Just started (it may have restarted): nothing it did not see is denied.
        delivery.hold(&batch(&feeder, 1, 5)?, T0);
        let early = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 1, 4, 6),
                Some(point),
                T0 + 1,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        // 5 came with no key: no tag, and not denied. 4 is below where the stream was first
        // seen, 6 is of a time not yet watched whole.
        assert!(early.entries.is_empty(), "{:?}", early.entries);
        // A grant from another key than the feeder's is not taken: still untagged.
        let impostor = Identity::generate().map_err(text)?;
        let forged = DeliveryQuery {
            keys: Some(grant(&impostor, &relay.public(), WATCHED)?),
            ..query(&feeder, 1, 7, 7)
        };
        assert!(forged.keys.is_some());
        let refused = delivery.answer_at(&selection, Some(&relay), &forged, Some(point), WATCHED);
        assert!(refused.is_some());
        assert_eq!(delivery.keyed(), 0);
        // A grant for another member is not taken either.
        let elsewhere = DeliveryQuery {
            keys: Some(grant(&feeder, &impostor.public(), WATCHED)?),
            ..query(&feeder, 1, 7, 7)
        };
        delivery.answer_at(&selection, Some(&relay), &elsewhere, Some(point), WATCHED);
        assert_eq!(delivery.keyed(), 0);
        delivery.hold(&batch(&feeder, 1, 7)?, WATCHED);
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 1, 7, 8),
                Some(point),
                WATCHED,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        // 7 came untagged: no word. 8 never came and the relay has watched a window: not seen.
        assert_eq!(content.entries, vec![(8, Possession::NotSeen)]);
        Ok(())
    }

    #[test]
    fn a_feeder_outside_the_relays_areas_gets_takes_area_false() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, _) = taking_here()?;
        let delivery = Delivery::new();
        delivery.hold(&batch(&feeder, 1, 1)?, T0);
        let london = Region::point(&Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        for point in [Some(london), None] {
            let carrying = DeliveryQuery {
                keys: Some(grant(&feeder, &relay.public(), WATCHED)?),
                ..query(&feeder, 1, 1, 1)
            };
            let content = delivery
                .answer_at(&selection, Some(&relay), &carrying, point, WATCHED)
                .ok_or("no answer")?
                .content()
                .map_err(text)?;
            assert!(!content.takes_area);
            assert!(content.entries.is_empty(), "nothing said of the batches");
        }
        // Outside its areas it holds no feeder's keys.
        assert_eq!(delivery.keyed(), 0);
        // With no key to sign with, nothing is said at all.
        assert!(
            delivery
                .answer_at(&selection, None, &query(&feeder, 1, 1, 1), None, WATCHED)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn a_batch_let_go_is_neither_proved_nor_denied() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        keyed(&delivery, &selection, &relay, &feeder, point, T0)?;
        let start = WATCHED;
        delivery.hold(&batch(&feeder, 1, 1)?, start);
        delivery.hold(&batch(&feeder, 1, 2)?, start + TAG_WINDOW_MS);
        delivery.hold(&batch(&feeder, 1, 3)?, start + TAG_WINDOW_MS + 1_000);
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 1, 0, 4),
                Some(point),
                start + TAG_WINDOW_MS + 2_000,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        let said: Vec<u64> = content
            .entries
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect();
        // 0 and 1 are below the horizon: nothing said. 2 and 3 came untagged (the keys granted at
        // T0 ran out two periods later) or tagged; 4 is not seen.
        assert!(!said.contains(&0) && !said.contains(&1), "{said:?}");
        assert_eq!(content.entries.last(), Some(&(4, Possession::NotSeen)));
        Ok(())
    }

    #[test]
    fn a_replayed_old_tag_fails_after_rotation() -> Result {
        // A member that kept an old key and tags a newer batch under it, or answers with a tag it
        // made long ago, proves nothing: the feeder takes a tag only under a key in force when it
        // sent the batch.
        let relay = Identity::generate().map_err(text)?;
        let feeder = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        let first = 10 * KEY_PERIOD_MS;
        keyed(&delivery, &selection, &relay, &feeder, point, first)?;
        let old = batch(&feeder, 1, 1)?;
        delivery.hold(&old, first + 1);
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 1, 1, 1),
                Some(point),
                first + 2,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        let [(_, Possession::Proved { key, tag })] = content.entries[..] else {
            return Err(format!("{:?}", content.entries));
        };
        assert!(verifies(&relay.public(), &old, first + 1, key, &tag));
        // Three periods on, the old key is no key for a batch sent now.
        let later = first + 3 * KEY_PERIOD_MS;
        let fresh = batch(&feeder, 1, 2)?;
        let replayed = delivery_tag(&keys_at(&relay.public(), key).0.key, fresh.as_bytes());
        assert!(!verifies(&relay.public(), &fresh, later, key, &replayed));
        // And the relay itself has rotated: keyed in the new period, it tags under the new key.
        keyed(&delivery, &selection, &relay, &feeder, point, later)?;
        delivery.hold(&fresh, later + 1);
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 1, 2, 2),
                Some(point),
                later + 2,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        let [(_, Possession::Proved { key: now_key, tag })] = content.entries[..] else {
            return Err(format!("{:?}", content.entries));
        };
        assert_eq!(now_key, key_period(later));
        assert!(verifies(&relay.public(), &fresh, later, now_key, &tag));
        // A replayed grant older than the keys held changes nothing.
        keyed(&delivery, &selection, &relay, &feeder, point, first)?;
        delivery.hold(&batch(&feeder, 1, 3)?, later + 3);
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 1, 3, 3),
                Some(point),
                later + 4,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert!(matches!(
            content.entries[..],
            [(3, Possession::Proved { key, .. })] if key == key_period(later)
        ));
        Ok(())
    }

    #[test]
    fn a_tag_made_four_minutes_ago_proves_delivery_at_twenty_thousand_feeders() -> Result {
        // 20,000 feeders, each a batch a second, for four minutes: the relay's whole arrival rate
        // at RFC-0177's target. The first batch of each is proved at the end, from the tag made
        // when it came; the store holds every entry within its bound, refusing none.
        const FEEDERS: usize = 20_000;
        const SECONDS: u64 = 240;
        let relay = Identity::generate().map_err(text)?;
        let member = relay.public();
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        let feeders: Vec<PublicKey> = (0..FEEDERS)
            .map(|index| {
                let mut seed = [0; 32];
                seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
                Identity::from_seed(seed).public()
            })
            .collect();
        let start = 10 * KEY_PERIOD_MS;
        // Keys as a grant gives them (the signature is checked in its own test; 20,000 of them
        // would only be slow here).
        let (current, next) = keys_at(&member, key_period(start));
        for feeder in &feeders {
            delivery.take_keys(
                *feeder,
                &TagKeysContent {
                    member,
                    current,
                    next,
                    switch_in_ms: KEY_PERIOD_MS,
                },
                start,
            );
        }
        assert_eq!(delivery.keyed(), FEEDERS);
        // A batch's bytes, its sequence and feeder in place (short: what is measured here is the
        // store at the arrival rate, not the hash, which is linear in the bytes).
        let mut bytes = vec![0x5a; 160];
        for second in 0..SECONDS {
            let now = start + second * 1_000;
            bytes[..8].copy_from_slice(&second.to_be_bytes());
            for feeder in &feeders {
                bytes[8..40].copy_from_slice(feeder.as_bytes());
                delivery.hold_bytes(*feeder, (1, second), &bytes, now);
            }
        }
        assert_eq!(delivery.refused(), 0);
        assert_eq!(delivery.tags(), FEEDERS * SECONDS as usize);
        assert!(delivery.held_bytes() <= FEEDERS * PER_FEEDER_BYTES);
        let feeder = feeders[FEEDERS / 2];
        let mut first = vec![0x5a; 160];
        first[..8].copy_from_slice(&0u64.to_be_bytes());
        first[8..40].copy_from_slice(feeder.as_bytes());
        let asked = DeliveryQuery {
            nonce: [7; 32],
            receiver: feeder,
            boot_id: 1,
            ranges: vec![SequenceRange { first: 0, last: 1 }],
            keys: None,
        };
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &asked,
                Some(point),
                start + SECONDS * 1_000,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        let [
            (0, Possession::Proved { key, tag }),
            (1, Possession::Proved { .. }),
        ] = content.entries[..]
        else {
            return Err(format!("{:?}", content.entries));
        };
        assert!(tag_keys_for(start).contains(&key));
        assert_eq!(delivery_tag(&keys_at(&member, key).0.key, &first), tag);
        Ok(())
    }

    #[test]
    fn past_its_bound_a_batch_is_refused_whole_counted_and_never_denied() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        let feeder = Identity::from_seed([4; 32]);
        delivery.started(T0);
        let shard_bound = TAGS_HELD / SHARDS;
        // One stream fills its shard's bound at one instant (age lets nothing go).
        for sequence in 0..shard_bound as u64 + 10 {
            delivery.hold(&unsigned(&feeder.public(), 0, sequence, 0)?, WATCHED);
        }
        assert_eq!(delivery.refused(), 10);
        assert!(delivery.tags() <= shard_bound);
        let last = shard_bound as u64 + 9;
        let content = delivery
            .answer_at(
                &selection,
                Some(&relay),
                &query(&feeder, 0, last, last),
                Some(point),
                WATCHED,
            )
            .ok_or("no answer")?
            .content()
            .map_err(text)?;
        assert!(content.entries.is_empty(), "a refused batch is not denied");
        Ok(())
    }

    #[test]
    fn streams_are_bounded_and_an_early_forgotten_one_is_not_denied() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let (selection, point) = taking_here()?;
        let delivery = Delivery::new();
        delivery.started(T0);
        // One feeder, one stream per boot (all in its shard), more than a shard remembers.
        let feeder = Identity::from_seed([3; 32]);
        let boots = (STREAMS_REMEMBERED / SHARDS) as u64 + 10;
        for boot in 0..boots {
            delivery.hold(&unsigned(&feeder.public(), boot, 0, 0)?, WATCHED + boot);
        }
        assert!(delivery.streams() <= STREAMS_REMEMBERED / SHARDS);
        let asked = |boot: u64, now: u64| -> std::result::Result<Vec<(u64, Possession)>, String> {
            Ok(delivery
                .answer_at(
                    &selection,
                    Some(&relay),
                    &query(&feeder, boot, 1, 1),
                    Some(point),
                    now,
                )
                .ok_or("no answer")?
                .content()
                .map_err(text)?
                .entries)
        };
        // A remembered boot that never sent sequence 1: not seen.
        assert_eq!(
            asked(boots - 1, WATCHED + boots)?,
            vec![(1, Possession::NotSeen)]
        );
        // Boot 0 was forgotten early: it might have sent it, so it is not denied, nor is any
        // stream unknown until that boot's memory would have run out.
        assert!(asked(0, WATCHED + boots)?.is_empty());
        assert!(asked(boots + 5, WATCHED + boots)?.is_empty());
        let later = WATCHED + STREAM_MEMORY_MS + boots;
        assert_eq!(asked(boots + 5, later)?, vec![(1, Possession::NotSeen)]);
        Ok(())
    }
}
