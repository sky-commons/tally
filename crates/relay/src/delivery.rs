//! Answering delivery checks (RFC-0174 §2.2, RFC-0181 §7): the relay tags each batch it takes in
//! from a receiver of its areas with the key its feeder gave this relay for it, keeps the 16-byte
//! tag (never the bytes) for `TAG_WINDOW_MS`, and answers a `DeliveryQuery` with a signed
//! `DeliveryAnswer`: per batch asked, its tag, or "not seen", or, for a feeder of an area it does
//! not take, that it does not take it. A query also carries the feeder's grant of keys
//! (`TagKeys`), taken here. Its answers are also evidence for its clients' credit (`credit`).
//!
//! **Whose batches.** Only a receiver whose signed location is in the relay's areas is watched:
//! whether it is, is the one rule `selection::Taken::takes_receiver` decides from the relay's own
//! regions, alike for a batch held and a query answered. A batch of any other receiver costs the
//! store nothing, and a query about one is answered "I do not take this area".
//!
//! **What it costs.** One tag a feeder a second for the window: `TAG_WINDOW_MS` of 40-byte entries,
//! about 12 KB a feeder ([`PER_FEEDER_BYTES`]), 240 MB at 20,000 feeders, where holding the
//! batches themselves for the same window would be some 8 GB. Bounded per receiver by
//! [`ENTRIES_PER_RECEIVER`] (twice a feeder's rate over the window), so one receiver, however
//! fast it sends, fills only its own share, which is what each feeder's connection is planned at
//! ([`PER_RECEIVER_BYTES`], its floor), and in all by the store's gauge (the budget's
//! `Store::Delivery`, [`Delivery::charge_to`]), which every entry is charged to before it is held
//! and released from as it is let go, and which is the store's only bound in all; past either a
//! batch is refused whole (no tag, and never denied) and counted.
//!
//! **"Not seen" is said only when it is known.** A batch is "not seen" when the relay has watched
//! its receiver for that long and holds no entry for it: an entry is kept for every batch taken in,
//! tagged or not, for the whole window, and a feeder asks only within the window, so a batch that
//! came is still there. Neither proved nor denied (left out of the answer, which a feeder counts
//! as no vote): a batch that came while the relay held no key for its feeder (it has an entry but
//! no tag); one refused past a bound, or let go, below its stream's horizon; any batch of a
//! receiver the relay has not yet watched for a whole window (it may have restarted, or the
//! receiver may only now be in its areas); and anything of a receiver it is not watching at all.
//! Per stream (receiver and boot) the relay keeps the horizon below which it may have let a batch
//! go. A stream silent for `STREAM_MEMORY_MS` is forgotten, and a receiver with no stream left is
//! no longer watched; a stream forgotten sooner, to bound memory, makes every unknown stream of its
//! receiver unanswerable until that time has passed.
//!
//! **Grants only from feeders.** A grant is taken only from a receiver of the relay's areas that
//! fed it a batch within `FED_WITHIN_MS`: the keys live in the receiver's own record, so fresh
//! keys that never fed cost the store nothing, and the keys held are bounded as the receivers are.
//!
//! **Queries are cheap and rationed.** A query names at most `MAX_SEQUENCES` batches, each found
//! by its sequence in a stream kept in sequence order (a binary search, never a scan), and a
//! prober is answered at most `PROBER_QUERIES` queries at once, one more each
//! `PROBER_QUERY_EVERY_MS`: the shard locks ingest holds batches under are never a querier's. The
//! allowance is never a connection's and never a bare key's, since a key is free: it is held in
//! the record of a receiver that fed the relay (a feeder asks as its receiver's key, about its own
//! batches), so it is bounded as the receivers watched are and outlives the prober's reconnects,
//! and a key that never fed the relay shares one allowance with every other such key asking from
//! the same network group (`Strangers`; the group of the address its connection came from, an IPv4
//! /16 or an IPv6 /32, `directory::Group`, the unit every flood is bucketed by). A fresh key per
//! connection therefore starts from what its network's strangers left, never from a full allowance
//! of its own, and takes nothing from any feeder's; and one hostile prober, however many keys it
//! makes, spends only its own network's allowance, never a stranger's elsewhere, however many
//! networks it asks from: past the groups remembered, the one nearest to whole is forgotten for a
//! new one, never a group shared by every network past them. Beside the groups', all strangers
//! together have one relay-wide allowance (`STRANGER_BURST`, `STRANGER_EVERY_MS`), so what strangers
//! can cost the relay is bounded however many networks they ask from.
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

use crate::budget::{Charge, Gauge, Store};
use crate::directory::Group;
use crate::selection::Selection;

/// One entry a batch costs while it is held.
pub const TAG_BYTES: usize = std::mem::size_of::<Tagged>();
/// What one feeder costs the store: a batch a second (RFC-0181's feeder) for the window.
pub const PER_FEEDER_BYTES: usize = TAG_BYTES * (TAG_WINDOW_MS / 1000) as usize;
/// The most entries one receiver holds, over all its streams: twice a feeder's batch a second over
/// the window, room for a burst. Past it that receiver's batch is refused whole and counted; no
/// other receiver's is.
pub const ENTRIES_PER_RECEIVER: usize = 2 * (TAG_WINDOW_MS / 1000) as usize;
/// What one receiver can hold of the store whatever it sends: its entries to the cap
/// ([`ENTRIES_PER_RECEIVER`]). What a feeder's connection reserves (its floor), so a feeder
/// sending past a batch a second fills what was planned for it and no more. Before, a feeder was
/// planned at a batch a second ([`PER_FEEDER_BYTES`]) and the cap was twice it.
pub const PER_RECEIVER_BYTES: usize = TAG_BYTES * ENTRIES_PER_RECEIVER;
/// The most streams (receiver and boot) whose horizon is remembered.
pub const STREAMS_REMEMBERED: usize = 100_000;
/// The most boots of one receiver whose streams are remembered: past it the receiver's stream held
/// longest ago is forgotten, so one feeder churning boot ids forgets only its own streams, never
/// another's (the hub's `BOOTS_PER_AUTHOR`, for the same reason).
pub const BOOTS_PER_RECEIVER: usize = crate::hub::BOOTS_PER_AUTHOR;
/// How long a silent stream's horizon is remembered: what "not seen" of an unknown stream means.
pub const STREAM_MEMORY_MS: u64 = 60 * 60 * 1000;
/// How recently a receiver must have fed the relay a batch for its grant to be taken: a feeder
/// grants every minute, to members its batches reach, so a window is ample.
pub const FED_WITHIN_MS: u64 = TAG_WINDOW_MS;
/// Queries one prober (a receiver that fed the relay, by its key) is answered at once, and how
/// often it may ask one more, over all its sessions: a feeder asks a member once a check, and
/// grants it keys once a minute. Every key that never fed the relay, together, is one prober.
pub const PROBER_QUERIES: u32 = 4;
pub const PROBER_QUERY_EVERY_MS: u64 = 1_000;
/// The network groups whose strangers' allowances are remembered at most. Past the bound the group
/// nearest to having earned its allowance back whole is forgotten to make room for a new one
/// (`Strangers::spend`): a group that earned it back is no different from one never seen, so a
/// new group always has an allowance of its own, and the groups kept are those that spent most,
/// whose debts forgetting would forgive.
pub const STRANGER_GROUPS: usize = 4_096;
/// Queries every stranger, from every network group together, is answered at once, and how often
/// one more: the relay-wide cap that bounds what strangers cost however many network groups they
/// ask from (each group has its own allowance, [`PROBER_QUERIES`], and a botnet holds
/// [`STRANGER_GROUPS`] of them). A query is a signature check and a sealed answer, so this is the
/// most work strangers can make the relay do, a hundred a second, whoever they are; a feeder's
/// own queries are never charged to it.
pub const STRANGER_BURST: u32 = 128;
pub const STRANGER_EVERY_MS: u64 = 10;
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
    /// Batches refused whole past a bound, grants refused from a receiver that has not fed here,
    /// and queries past their prober's allowance.
    refused: AtomicU64,
    refused_keys: AtomicU64,
    unanswered: AtomicU64,
    /// The store's gauge (`budget::Store::Delivery`), which each shard's entries are charged to:
    /// unlimited until the relay charges the store to its budget (`charge_to`).
    gauge: Mutex<std::sync::Arc<Gauge>>,
    /// The allowances of the probers whose keys are no receiver the relay watches (a key that
    /// never fed it, which costs nothing to make), one per network group they ask from.
    strangers: Mutex<Strangers>,
}

/// The strangers' allowances, one per network group (`Delivery::allowed`): a key costs nothing,
/// an address in another network does, so strangers are rationed by where they ask from. A prober
/// with no address (a stream that is no socket) is a group of its own, `None`.
///
/// At most `STRANGER_GROUPS` are remembered, and a new group past them takes the place of the one
/// nearest to whole ([`Allowance::whole_at`], the least spent). Never one allowance every further
/// group shares: then a prober spread over more networks than the bound (a botnet's) spent that
/// one and every honest newcomer was refused. Nor the group that spent most: forgetting it
/// forgives the largest debt, so a botnet cycling its groups would have each one's allowance
/// back whole. Forgetting the least spent forgives the least there is, a newcomer is answered at
/// once, and the groups that spent their allowances stay remembered, refused until they earn
/// queries back.
#[derive(Default)]
struct Strangers {
    groups: HashMap<Option<Group>, Allowance>,
    /// Every group remembered, by when its allowance is whole again: the first is the one
    /// forgotten for a new group.
    by_whole: BTreeSet<(u64, Option<Group>)>,
    /// What every stranger together may ask (`STRANGER_BURST`): spent after the group's own.
    relay: RelayWide,
}

/// The relay-wide allowance of all strangers: a bucket of `STRANGER_BURST` earning one query each
/// `STRANGER_EVERY_MS`.
#[derive(Clone, Copy)]
struct RelayWide {
    left: u32,
    as_of_ms: u64,
}

impl Default for RelayWide {
    fn default() -> Self {
        Self {
            left: STRANGER_BURST,
            as_of_ms: 0,
        }
    }
}

impl RelayWide {
    /// Spends one query at `now_ms` if one is left after what it earned since.
    fn spend(&mut self, now_ms: u64) -> bool {
        let earned = now_ms.saturating_sub(self.as_of_ms) / STRANGER_EVERY_MS;
        if earned > 0 {
            self.as_of_ms = self
                .as_of_ms
                .saturating_add(earned.saturating_mul(STRANGER_EVERY_MS));
            self.left = u32::try_from(u64::from(self.left).saturating_add(earned))
                .unwrap_or(u32::MAX)
                .min(STRANGER_BURST);
        }
        match self.left.checked_sub(1) {
            Some(left) => {
                self.left = left;
                true
            }
            None => false,
        }
    }

    /// Whether a query at `now_ms` would be left, spending nothing.
    fn has_one(&self, now_ms: u64) -> bool {
        let earned = now_ms.saturating_sub(self.as_of_ms) / STRANGER_EVERY_MS;
        self.left > 0 || earned > 0
    }
}

impl Strangers {
    /// Spends one query of `group`'s strangers and one of the relay-wide allowance at `now_ms`, if
    /// both have one left: a refusal by the relay-wide cap spends nothing of the group's.
    fn spend(&mut self, group: Option<Group>, now_ms: u64) -> bool {
        if !self.relay.has_one(now_ms) {
            return false;
        }
        let spent = self.spend_in_group(group, now_ms);
        if spent {
            self.relay.spend(now_ms);
        }
        spent
    }

    /// Spends one query of `group`'s strangers at `now_ms`, if one is left.
    fn spend_in_group(&mut self, group: Option<Group>, now_ms: u64) -> bool {
        let mut allowance = match self.groups.get(&group) {
            Some(allowance) => {
                self.by_whole.remove(&(allowance.whole_at(), group));
                *allowance
            }
            None => {
                if self.groups.len() >= STRANGER_GROUPS
                    && let Some((_, least)) = self.by_whole.pop_first()
                {
                    self.groups.remove(&least);
                }
                Allowance::full(now_ms)
            }
        };
        let spent = allowance.spend(now_ms);
        self.by_whole.insert((allowance.whole_at(), group));
        self.groups.insert(group, allowance);
        spent
    }
}

/// How long an allowance spent to nothing takes to be earned back whole.
#[cfg(test)]
const WHOLE_AFTER_MS: u64 = PROBER_QUERIES as u64 * PROBER_QUERY_EVERY_MS;

impl Default for Delivery {
    fn default() -> Self {
        Self::new()
    }
}

struct Shard {
    /// The receivers watched: those of the relay's areas that fed it, while a stream of theirs is
    /// remembered.
    receivers: HashMap<PublicKey, Receiver>,
    streams: HashMap<StreamKey, Stream>,
    /// Streams holding entries, by their last arrival: the order entries age out in.
    active: BTreeSet<(u64, StreamKey)>,
    /// Streams holding none, by their last arrival: the order they are forgotten in.
    idle: BTreeSet<(u64, StreamKey)>,
    entries: usize,
    /// Its entries' bytes (`TAG_BYTES` each), charged to the store's gauge before an entry is
    /// held and released as one is let go: `entries * TAG_BYTES`, always.
    held: Charge,
}

impl Shard {
    fn new(gauge: &std::sync::Arc<Gauge>) -> Self {
        Self {
            receivers: HashMap::new(),
            streams: HashMap::new(),
            active: BTreeSet::new(),
            idle: BTreeSet::new(),
            entries: 0,
            held: gauge.empty(),
        }
    }
}

/// One receiver watched.
struct Receiver {
    /// Since when it has been watched: "not seen" is said of it only a whole window after.
    since_ms: u64,
    /// When it last fed the relay a batch: a grant is taken only from one that did recently.
    fed_ms: u64,
    /// Its boots whose streams are remembered, the boot held most recently last.
    boots: Vec<u64>,
    /// Until then a boot of it the relay knows nothing of may be one it forgot early.
    unsure_until_ms: u64,
    /// The keys its feeder gave this relay.
    keys: Option<Keys>,
    /// Entries it holds over all its streams (`ENTRIES_PER_RECEIVER`).
    entries: usize,
    /// Its queries' allowance, when it asks as itself (`Delivery::allowed`): held here, so it is
    /// bounded as the receivers are and a reconnect earns it nothing.
    allowance: Allowance,
}

/// A prober's queries: `left` of `PROBER_QUERIES`, one more earned each `PROBER_QUERY_EVERY_MS`
/// after `as_of_ms`.
#[derive(Clone, Copy)]
struct Allowance {
    left: u32,
    as_of_ms: u64,
}

impl Allowance {
    fn full(now_ms: u64) -> Self {
        Self {
            left: PROBER_QUERIES,
            as_of_ms: now_ms,
        }
    }

    /// When it has earned back every query, and is no different from a fresh one: the later, the
    /// more it has spent.
    fn whole_at(&self) -> u64 {
        let owed = u64::from(PROBER_QUERIES.saturating_sub(self.left));
        self.as_of_ms
            .saturating_add(owed.saturating_mul(PROBER_QUERY_EVERY_MS))
    }

    /// Spends one query at `now_ms` if one is left after what it earned since; false if none is.
    fn spend(&mut self, now_ms: u64) -> bool {
        let earned = now_ms.saturating_sub(self.as_of_ms) / PROBER_QUERY_EVERY_MS;
        let left = u64::from(self.left)
            .saturating_add(earned)
            .min(u64::from(PROBER_QUERIES));
        self.as_of_ms = self
            .as_of_ms
            .saturating_add(earned.saturating_mul(PROBER_QUERY_EVERY_MS));
        let Some(left) = left.checked_sub(1) else {
            self.left = 0;
            return false;
        };
        self.left = u32::try_from(left).unwrap_or(0);
        true
    }
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
    /// In sequence order, each kept `TAG_WINDOW_MS` (a batch is found by binary search). Batches
    /// arrive in sequence order but for the odd straggler, so the oldest are at the front.
    entries: VecDeque<Tagged>,
}

impl Stream {
    fn find(&self, sequence: u64) -> Result<usize, usize> {
        self.entries
            .binary_search_by_key(&sequence, |held| held.sequence)
    }
}

/// What the relay can say of one sequence.
enum Said {
    Proved(u32, Tag),
    NotSeen,
    /// Taken in untagged, let go, refused, of a time the relay was not watching its receiver, or
    /// of a receiver it does not watch.
    Unknown,
}

impl Delivery {
    pub fn new() -> Self {
        let gauge = Gauge::unlimited(Store::Delivery);
        Self {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(Shard::new(&gauge)))
                .collect(),
            gauge: Mutex::new(gauge),
            placement: RandomState::new(),
            refused: AtomicU64::new(0),
            refused_keys: AtomicU64::new(0),
            unanswered: AtomicU64::new(0),
            strangers: Mutex::default(),
        }
    }

    fn shard(&self, receiver: &PublicKey) -> Option<std::sync::MutexGuard<'_, Shard>> {
        let index = usize::try_from(self.placement.hash_one(receiver.as_bytes()) % SHARDS as u64)
            .unwrap_or(0);
        self.shards.get(index)?.lock().ok()
    }

    /// A receiver's batch the relay took in (new, verified), its receiver's signed location
    /// falling at `point`: held, as an entry for the window, only for a receiver of the relay's
    /// areas (`selection`), tagged under the key its feeder gave this relay if one is in force.
    pub fn hold(&self, selection: &Selection, batch: &Batch, point: Option<Region>, now_ms: u64) {
        if !selection.takes_receiver(point) {
            return;
        }
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

    /// The store's entries are charged to `gauge` (the budget's `Store::Delivery`) from now on: its
    /// limit, the store's share of the budget, is its only bound in all. Past it a batch is refused
    /// whole, counted. What a shard holds now is moved to it, or let go if it cannot take it.
    pub fn charge_to(&self, gauge: std::sync::Arc<Gauge>) {
        if let Ok(mut held) = self.gauge.lock() {
            if std::sync::Arc::ptr_eq(&held, &gauge) {
                return;
            }
            *held = std::sync::Arc::clone(&gauge);
        }
        for shard in self.shards.iter() {
            if let Ok(mut shard) = shard.lock() {
                shard.charge_to(&gauge);
            }
        }
    }

    /// `hold` of a batch of a receiver of the relay's areas, named by its receiver,
    /// (boot, sequence) and signed bytes.
    fn hold_bytes(&self, receiver: PublicKey, name: (u64, u64), bytes: &[u8], now_ms: u64) {
        let Some(mut shard) = self.shard(&receiver) else {
            return;
        };
        if !shard.hold(receiver, name, bytes, now_ms) {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The signed answer to `query`, asked by `prober` (the key its session's handshake proved,
    /// from the network group `group` of the address its connection came from), about a feeder
    /// whose signed
    /// location falls at `point`: per sequence asked, its tag, "not seen" for one known never to
    /// have come, and nothing for one the relay cannot speak for; or, outside the areas the relay
    /// takes, that it does not take the area and nothing else. The query's keys, if it carries a
    /// grant for this relay signed by a feeder of an area it takes that fed it recently, are taken
    /// first. None past the prober's allowance (`PROBER_QUERIES`), counted.
    pub fn answer_at(
        &self,
        selection: &Selection,
        identity: Option<&Identity>,
        query: &DeliveryQuery,
        (point, prober, group): (Option<Region>, PublicKey, Option<Group>),
        now_ms: u64,
    ) -> Option<DeliveryAnswer> {
        let identity = identity?;
        if !self.allowed(prober, group, now_ms) {
            self.unanswered.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let takes_area = selection.takes_receiver(point);
        let entries = if takes_area {
            let mut shard = self.shard(&query.receiver)?;
            if let Some(keys) = &query.keys
                && keys.verify().is_ok()
                && keys.signer().is_ok_and(|signer| signer == query.receiver)
                && let Ok(content) = keys.content()
                && content.member == identity.public()
                && !shard.take_keys(query.receiver, &content, now_ms)
            {
                self.refused_keys.fetch_add(1, Ordering::Relaxed);
            }
            let stream = (query.receiver, query.boot_id);
            query
                .ranges
                .iter()
                .flat_map(|range| range.first..=range.last)
                .filter_map(|sequence| match shard.said(stream, sequence, now_ms) {
                    Said::Proved(key, tag) => Some((sequence, Possession::Proved { key, tag })),
                    Said::NotSeen => Some((sequence, Possession::NotSeen)),
                    Said::Unknown => None,
                })
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

    /// Whether `prober` may be answered one more query at `now_ms`, and if so spends it: from its
    /// own allowance if it is a receiver the relay watches (one that fed it), else from the one
    /// every other key asking from its network group shares (`Strangers`).
    fn allowed(&self, prober: PublicKey, group: Option<Group>, now_ms: u64) -> bool {
        {
            let Some(mut shard) = self.shard(&prober) else {
                return false;
            };
            if let Some(record) = shard.receivers.get_mut(&prober) {
                return record.allowance.spend(now_ms);
            }
        }
        let Ok(mut strangers) = self.strangers.lock() else {
            return false;
        };
        strangers.spend(group, now_ms)
    }

    /// `receiver`'s grant, its signature already checked: what `answer_at` takes.
    #[cfg(test)]
    fn take_keys(&self, receiver: PublicKey, content: &TagKeysContent, now_ms: u64) -> bool {
        self.shard(&receiver)
            .is_some_and(|mut shard| shard.take_keys(receiver, content, now_ms))
    }

    /// Entries held now, and their bytes.
    pub fn tags(&self) -> usize {
        self.each(|shard| shard.entries)
    }

    pub fn held_bytes(&self) -> usize {
        self.tags() * TAG_BYTES
    }

    /// The bytes of every entry the streams hold, counted afresh: what the gauge must read.
    #[cfg(test)]
    fn counted_bytes(&self) -> usize {
        self.each(|shard| {
            shard
                .streams
                .values()
                .map(|stream| stream.entries.len())
                .sum::<usize>()
        }) * TAG_BYTES
    }

    /// Streams remembered now.
    pub fn streams(&self) -> usize {
        self.each(|shard| shard.streams.len())
    }

    /// Receivers whose keys are held now.
    pub fn keyed(&self) -> usize {
        self.each(|shard| {
            shard
                .receivers
                .values()
                .filter(|receiver| receiver.keys.is_some())
                .count()
        })
    }

    /// Batches refused whole past a bound, grants refused from a receiver that has not fed here
    /// (or not of the relay's areas), and queries past their prober's allowance, since start.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn refused_keys(&self) -> u64 {
        self.refused_keys.load(Ordering::Relaxed)
    }

    pub fn unanswered(&self) -> u64 {
        self.unanswered.load(Ordering::Relaxed)
    }

    fn each(&self, count: impl Fn(&Shard) -> usize) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.lock().ok().map(|shard| count(&shard)))
            .sum()
    }
}

impl Shard {
    /// Its entries charged to `gauge` from now on: moved there, or every stream forgotten early if
    /// the gauge cannot take them.
    fn charge_to(&mut self, gauge: &std::sync::Arc<Gauge>) {
        let mut moved = gauge.empty();
        if !moved.try_grow(self.held.bytes()) {
            let keys: Vec<StreamKey> = self.streams.keys().copied().collect();
            for key in keys {
                self.forget_stream(key, true);
            }
        }
        self.held = moved;
    }

    /// False when the batch was refused past a bound: its receiver's share, or the store's gauge.
    fn hold(
        &mut self,
        receiver: PublicKey,
        (boot_id, sequence): (u64, u64),
        bytes: &[u8],
        now_ms: u64,
    ) -> bool {
        self.let_go(now_ms);
        let key = (receiver, boot_id);
        let before = self.streams.get(&key).map(|stream| stream.last_ms);
        if before.is_none() {
            self.room_for_boot(receiver);
        }
        let record = self.receivers.entry(receiver).or_insert(Receiver {
            since_ms: now_ms,
            fed_ms: now_ms,
            boots: Vec::new(),
            unsure_until_ms: 0,
            keys: None,
            entries: 0,
            allowance: Allowance::full(now_ms),
        });
        record.fed_ms = record.fed_ms.max(now_ms);
        // A receiver first watched now may have sent earlier batches the relay did not see.
        let watched = now_ms >= record.since_ms.saturating_add(TAG_WINDOW_MS);
        let tag = match &record.keys {
            Some(keys) => match keys.in_force(now_ms) {
                Some(key) => Some((key.id, delivery_tag(&key.key, bytes))),
                None => {
                    record.keys = None;
                    None
                }
            },
            None => None,
        };
        let stream = self.streams.entry(key).or_insert(Stream {
            horizon: if watched { 0 } else { sequence },
            last_ms: now_ms,
            entries: VecDeque::new(),
        });
        // The hub hands each batch once; a copy is held once.
        if stream.find(sequence).is_ok() {
            return true;
        }
        let was_active = before.is_some() && !stream.entries.is_empty();
        let freed = age(stream, now_ms);
        self.freed(receiver, freed);
        if !self.held.fits(TAG_BYTES) {
            // Room the window would have made in the other streams is made before refusing.
            for (other, freed) in age_all(&mut self.streams, &self.active, now_ms) {
                self.freed(other, freed);
            }
        }
        let over_quota = self
            .receivers
            .get(&receiver)
            .is_some_and(|record| record.entries >= ENTRIES_PER_RECEIVER);
        // Charged before it is held: past the store's share it is refused whole.
        let refused = over_quota || !self.held.try_grow(TAG_BYTES);
        let Some(stream) = self.streams.get_mut(&key) else {
            if !refused {
                self.held.shrink_to(self.entries * TAG_BYTES);
            }
            return true;
        };
        if refused {
            // Refused whole: it has no entry, so it must never be said "not seen".
            stream.horizon = stream.horizon.max(sequence.saturating_add(1));
        } else {
            // In sequence order: at the back but for a straggler.
            let at = match stream.entries.back() {
                Some(last) if last.sequence > sequence => {
                    stream.find(sequence).unwrap_or_else(|at| at)
                }
                _ => stream.entries.len(),
            };
            stream.entries.insert(
                at,
                Tagged {
                    sequence,
                    at_ms: now_ms,
                    tag,
                },
            );
            self.entries += 1;
            if let Some(record) = self.receivers.get_mut(&receiver) {
                record.entries += 1;
            }
        }
        let Some(stream) = self.streams.get_mut(&key) else {
            return true;
        };
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
        if let Some(record) = self.receivers.get_mut(&receiver) {
            record.boots.retain(|held| *held != boot_id);
            record.boots.push(boot_id);
        }
        self.bound_streams();
        !refused
    }

    /// `freed` of `receiver`'s entries were let go, and their bytes released.
    fn freed(&mut self, receiver: PublicKey, freed: usize) {
        self.entries -= freed;
        self.held.shrink_to(self.entries * TAG_BYTES);
        if let Some(record) = self.receivers.get_mut(&receiver) {
            record.entries = record.entries.saturating_sub(freed);
        }
    }

    /// Before a new stream of `receiver`: when it has `BOOTS_PER_RECEIVER` boots remembered, the
    /// one it held longest ago is forgotten, and until that one's memory would have run out an
    /// unknown boot of this receiver may be it. Its own churn costs only itself.
    fn room_for_boot(&mut self, receiver: PublicKey) {
        loop {
            let oldest = match self.receivers.get_mut(&receiver) {
                Some(record) if record.boots.len() >= BOOTS_PER_RECEIVER => record.boots.remove(0),
                _ => return,
            };
            self.forget_stream((receiver, oldest), true);
        }
    }

    /// Forgets `key`'s stream and its entries; `early` when its memory had not run out, so until
    /// it would have, an unknown boot of its receiver may be it. A receiver with no stream left
    /// is no longer watched.
    fn forget_stream(&mut self, key: StreamKey, early: bool) {
        if let Some(stream) = self.streams.remove(&key) {
            self.active.remove(&(stream.last_ms, key));
            self.idle.remove(&(stream.last_ms, key));
            self.freed(key.0, stream.entries.len());
            if early && let Some(record) = self.receivers.get_mut(&key.0) {
                record.unsure_until_ms = record
                    .unsure_until_ms
                    .max(stream.last_ms.saturating_add(STREAM_MEMORY_MS));
            }
        }
        let gone = match self.receivers.get_mut(&key.0) {
            Some(record) => {
                record.boots.retain(|held| *held != key.1);
                record.boots.is_empty()
            }
            None => false,
        };
        if gone {
            self.receivers.remove(&key.0);
        }
    }

    /// A grant from `receiver`, checked and verified: in force from now, if the receiver fed the
    /// relay within `FED_WITHIN_MS`. False when refused; a grant older than the keys held (a
    /// replay) changes nothing and is not refused.
    fn take_keys(&mut self, receiver: PublicKey, content: &TagKeysContent, now_ms: u64) -> bool {
        let Some(record) = self.receivers.get_mut(&receiver) else {
            return false;
        };
        if now_ms.saturating_sub(record.fed_ms) > FED_WITHIN_MS {
            return false;
        }
        if record
            .keys
            .as_ref()
            .is_some_and(|held| held.current.id > content.current.id)
        {
            return true;
        }
        record.keys = Some(Keys {
            current: content.current,
            next: content.next,
            switch_at_ms: now_ms.saturating_add(content.switch_in_ms),
        });
        true
    }

    /// Lets go entries past the window: every entry of a stream silent for the window; forgets
    /// streams silent past their memory, and receivers with none left.
    fn let_go(&mut self, now_ms: u64) {
        while let Some((last_ms, key)) = self.active.first().copied() {
            if last_ms.saturating_add(TAG_WINDOW_MS) >= now_ms {
                break;
            }
            self.active.pop_first();
            let mut freed = 0;
            if let Some(stream) = self.streams.get_mut(&key) {
                freed = stream.entries.len();
                for held in stream.entries.drain(..) {
                    stream.horizon = stream.horizon.max(held.sequence.saturating_add(1));
                }
                stream.entries = VecDeque::new();
            }
            self.freed(key.0, freed);
            self.idle.insert((last_ms, key));
        }
        while let Some((last_ms, key)) = self.idle.first().copied() {
            if last_ms.saturating_add(STREAM_MEMORY_MS) >= now_ms {
                break;
            }
            self.forget_stream(key, false);
        }
        // The oldest entries of a stream still active age out as it is held again or asked of.
    }

    /// Bounds the streams remembered: the longest silent first, idle before active, each
    /// forgotten early.
    fn bound_streams(&mut self) {
        while self.streams.len() > STREAMS_REMEMBERED / SHARDS {
            let Some((_, key)) = self.idle.first().or_else(|| self.active.first()).copied() else {
                break;
            };
            self.forget_stream(key, true);
        }
    }

    fn said(&mut self, key: StreamKey, sequence: u64, now_ms: u64) -> Said {
        let Some(record) = self.receivers.get(&key.0) else {
            // Not watched: nothing is known of it.
            return Said::Unknown;
        };
        let watched = now_ms >= record.since_ms.saturating_add(TAG_WINDOW_MS);
        let unsure = now_ms < record.unsure_until_ms;
        let freed = self
            .streams
            .get_mut(&key)
            .map_or(0, |stream| age(stream, now_ms));
        self.freed(key.0, freed);
        match self.streams.get(&key) {
            Some(stream) => match stream.find(sequence) {
                Ok(at) => match stream.entries[at].tag {
                    Some((id, tag)) => Said::Proved(id, tag),
                    None => Said::Unknown,
                },
                Err(_) if sequence >= stream.horizon && watched => Said::NotSeen,
                Err(_) => Said::Unknown,
            },
            None if !watched || unsure => Said::Unknown,
            None => Said::NotSeen,
        }
    }
}

/// Ages every active stream (only at the bound, so a refusal is never for room the window would
/// have made); how many entries it let go, by receiver.
fn age_all(
    streams: &mut HashMap<StreamKey, Stream>,
    active: &BTreeSet<(u64, StreamKey)>,
    now_ms: u64,
) -> Vec<(PublicKey, usize)> {
    active
        .iter()
        .filter_map(|(_, key)| {
            streams
                .get_mut(key)
                .map(|stream| (key.0, age(stream, now_ms)))
        })
        .filter(|(_, freed)| *freed > 0)
        .collect()
}

/// Lets go a stream's entries older than the window from its front, raising its horizon past
/// them; how many.
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
    use tally_wire::{BatchContent, Location, Record, SequenceRange, TagKeys};

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

    fn london() -> std::result::Result<Region, String> {
        Region::point(&Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)
    }

    /// When a receiver first fed the relay, and a whole window after: "not seen" can be said of
    /// it from then.
    const T0: u64 = 1_000;
    const WATCHED: u64 = T0 + TAG_WINDOW_MS;
    /// The boot the helpers feed under to make a receiver one that fed the relay.
    const FEEDING_BOOT: u64 = u64::MAX;

    /// A key that never fed the relay, fresh each call.
    fn prober() -> PublicKey {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut seed = [5; 32];
        seed[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        Identity::from_seed(seed).public()
    }

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

    /// The relay taking the area here, and the point of a receiver here.
    struct Relay {
        identity: Identity,
        selection: Selection,
        point: Region,
        delivery: Delivery,
    }

    impl Relay {
        fn new() -> std::result::Result<Self, String> {
            let selection = Selection::new();
            selection.set_taken(vec![area_of(&here()).map_err(text)?]);
            Ok(Self {
                identity: Identity::generate().map_err(text)?,
                selection,
                point: Region::point(&here()).map_err(text)?,
                delivery: Delivery::new(),
            })
        }

        /// Takes in `batch` of a receiver here.
        fn hold(&self, batch: &Batch, now_ms: u64) {
            self.delivery
                .hold(&self.selection, batch, Some(self.point), now_ms);
        }

        /// The answer to `query` from a receiver at `point`, asked as a feeder asks: by the
        /// receiver's own key.
        fn ask_at(
            &self,
            query: &DeliveryQuery,
            point: Option<Region>,
            now_ms: u64,
        ) -> std::result::Result<DeliveryAnswerContent, String> {
            self.delivery
                .answer_at(
                    &self.selection,
                    Some(&self.identity),
                    query,
                    (point, query.receiver, None),
                    now_ms,
                )
                .ok_or("no answer")?
                .content()
                .map_err(text)
        }

        fn ask(
            &self,
            query: &DeliveryQuery,
            now_ms: u64,
        ) -> std::result::Result<DeliveryAnswerContent, String> {
            self.ask_at(query, Some(self.point), now_ms)
        }

        /// Gives the relay the feeder's keys, as a query carrying them does, the feeder having fed
        /// it a batch just before (a grant is taken only from a receiver that did).
        fn keyed(&self, feeder: &Identity, now_ms: u64) -> Result {
            self.hold(
                &unsigned(&feeder.public(), FEEDING_BOOT, now_ms, 0)?,
                now_ms,
            );
            let carrying = DeliveryQuery {
                ranges: Vec::new(),
                keys: Some(grant(feeder, &self.identity.public(), now_ms)?),
                ..query(feeder, 0, 0, 0)
            };
            self.ask(&carrying, now_ms)?;
            Ok(())
        }
    }

    /// What the feeder checks: the tag under one of the keys in force when it sent the batch.
    fn verifies(member: &PublicKey, batch: &Batch, sent_ms: u64, key: u32, tag: &Tag) -> bool {
        tag_keys_for(sent_ms).contains(&key)
            && delivery_tag(&keys_at(member, key).0.key, batch.as_bytes()) == *tag
    }

    #[test]
    fn tags_verify_against_the_batch_and_a_batch_never_taken_is_not_seen() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        relay.keyed(&feeder, T0)?;
        let now = WATCHED + 1_000;
        // Keyed again in the period it sends in: a feeder grants every period.
        relay.keyed(&feeder, now)?;
        let held: Vec<Batch> = (10..13)
            .map(|seq| batch(&feeder, 4, seq))
            .collect::<std::result::Result<_, _>>()?;
        for batch in &held {
            relay.hold(batch, now);
        }
        let asked = query(&feeder, 4, 9, 14);
        let answer = relay
            .delivery
            .answer_at(
                &relay.selection,
                Some(&relay.identity),
                &asked,
                (Some(relay.point), feeder.public(), None),
                now + 1_000,
            )
            .ok_or("no answer")?;
        answer.verify().map_err(text)?;
        assert_eq!(answer.signer().map_err(text)?, relay.identity.public());
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
                    assert!(verifies(&relay.identity.public(), batch, now, *key, tag));
                }
                (None, Possession::NotSeen) => {}
                other => return Err(format!("{sequence}: {other:?}")),
            }
        }
        // Another boot of the same feeder, never taken in: not seen.
        let other_boot = relay.ask(&query(&feeder, 5, 10, 10), now)?;
        assert_eq!(other_boot.entries, vec![(10, Possession::NotSeen)]);
        Ok(())
    }

    #[test]
    fn nothing_is_denied_before_its_receiver_was_watched_a_window_or_without_a_key() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        // Never fed the relay: nothing is known of it, so nothing is denied.
        assert!(
            relay
                .ask(&query(&feeder, 1, 0, 3), WATCHED)?
                .entries
                .is_empty()
        );
        // Just first fed (the relay may have restarted): nothing it did not see is denied.
        relay.hold(&batch(&feeder, 1, 5)?, T0);
        let early = relay.ask(&query(&feeder, 1, 4, 6), T0 + 1)?;
        // 5 came with no key: no tag, and not denied. 4 is below where the stream was first
        // seen, 6 is of a time its receiver was not yet watched whole.
        assert!(early.entries.is_empty(), "{:?}", early.entries);
        // A grant from another key than the feeder's is not taken: still untagged.
        let impostor = Identity::generate().map_err(text)?;
        let forged = DeliveryQuery {
            keys: Some(grant(&impostor, &relay.identity.public(), WATCHED)?),
            ..query(&feeder, 1, 7, 7)
        };
        relay.ask(&forged, WATCHED)?;
        assert_eq!(relay.delivery.keyed(), 0);
        // A grant for another member is not taken either.
        let elsewhere = DeliveryQuery {
            keys: Some(grant(&feeder, &impostor.public(), WATCHED)?),
            ..query(&feeder, 1, 7, 7)
        };
        relay.ask(&elsewhere, WATCHED)?;
        assert_eq!(relay.delivery.keyed(), 0);
        relay.hold(&batch(&feeder, 1, 7)?, WATCHED);
        let content = relay.ask(&query(&feeder, 1, 7, 8), WATCHED)?;
        // 7 came untagged: no word. 8 never came and its receiver was watched a window: not
        // seen.
        assert_eq!(content.entries, vec![(8, Possession::NotSeen)]);
        Ok(())
    }

    /// A receiver outside the relay's areas costs the store nothing, its
    /// grants are not taken, and a query about it is answered "I do not take this area".
    #[test]
    fn a_feeder_outside_the_relays_areas_costs_nothing_and_gets_takes_area_false() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        let london = london()?;
        for point in [Some(london), None] {
            for sequence in 0..1_000 {
                relay.delivery.hold(
                    &relay.selection,
                    &unsigned(&feeder.public(), 1, sequence, 0)?,
                    point,
                    T0,
                );
            }
        }
        assert_eq!(relay.delivery.tags(), 0);
        assert_eq!(relay.delivery.streams(), 0);
        for point in [Some(london), None] {
            let carrying = DeliveryQuery {
                keys: Some(grant(&feeder, &relay.identity.public(), WATCHED)?),
                ..query(&feeder, 1, 1, 1)
            };
            let content = relay.ask_at(&carrying, point, WATCHED)?;
            assert!(!content.takes_area);
            assert!(content.entries.is_empty(), "nothing said of the batches");
        }
        // Outside its areas it holds no feeder's keys.
        assert_eq!(relay.delivery.keyed(), 0);
        // With no key to sign with, nothing is said at all.
        assert!(
            relay
                .delivery
                .answer_at(
                    &relay.selection,
                    None,
                    &query(&feeder, 1, 1, 1),
                    (None, prober(), None),
                    WATCHED
                )
                .is_none()
        );
        Ok(())
    }

    /// A grant is taken only from a receiver of the relay's areas that fed
    /// it a batch within `FED_WITHIN_MS`, so keys that never fed cost the key table nothing.
    #[test]
    fn grants_are_taken_only_from_receivers_that_fed_the_relay() -> Result {
        let relay = Relay::new()?;
        let grant_of =
            |feeder: &Identity, now_ms: u64| -> std::result::Result<DeliveryQuery, String> {
                Ok(DeliveryQuery {
                    ranges: Vec::new(),
                    keys: Some(grant(feeder, &relay.identity.public(), now_ms)?),
                    ..query(feeder, 0, 0, 0)
                })
            };
        // A thousand fresh keys, each granting (at the pace the keys that never fed are answered
        // at, together): none is taken.
        for at in 0..1_000 {
            let fresh = Identity::generate().map_err(text)?;
            let now = T0 + at * PROBER_QUERY_EVERY_MS;
            relay.ask(&grant_of(&fresh, now)?, now)?;
        }
        assert_eq!(relay.delivery.keyed(), 0);
        assert_eq!(relay.delivery.refused_keys(), 1_000);
        // A feeder that fed: taken.
        let start = T0 + 1_000 * PROBER_QUERY_EVERY_MS;
        let feeder = Identity::generate().map_err(text)?;
        relay.hold(&batch(&feeder, 1, 1)?, start);
        relay.ask(&grant_of(&feeder, start + 1)?, start + 1)?;
        assert_eq!(relay.delivery.keyed(), 1);
        // One that fed, but longer ago than `FED_WITHIN_MS`: not taken.
        let quiet = Identity::generate().map_err(text)?;
        relay.hold(&batch(&quiet, 1, 1)?, start);
        let late = start + FED_WITHIN_MS + 1;
        relay.ask(&grant_of(&quiet, late)?, late)?;
        assert_eq!(relay.delivery.keyed(), 1);
        Ok(())
    }

    /// A prober is answered `PROBER_QUERIES` queries at once
    /// and one more each `PROBER_QUERY_EVERY_MS`; past that it is not answered, and counted. The
    /// allowance is in the record of the receiver that fed the relay, so reconnecting (a new
    /// session, the same key) earns it nothing; another feeder has its own.
    #[test]
    fn a_prober_is_answered_at_its_allowance_however_often_it_reconnects() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        let other = Identity::generate().map_err(text)?;
        relay.hold(&unsigned(&feeder.public(), FEEDING_BOOT, 0, 0)?, T0);
        relay.hold(&unsigned(&other.public(), FEEDING_BOOT, 0, 0)?, T0);
        let this = feeder.public();
        let ask = |now_ms: u64| {
            relay.delivery.answer_at(
                &relay.selection,
                Some(&relay.identity),
                &query(&feeder, 1, 0, 63),
                (Some(relay.point), this, None),
                now_ms,
            )
        };
        for _ in 0..PROBER_QUERIES {
            assert!(ask(T0).is_some());
        }
        // A session ends and the prober dials again, many times: still nothing until it earns it.
        for _ in 0..16 {
            assert!(ask(T0).is_none());
        }
        assert!(ask(T0 + PROBER_QUERY_EVERY_MS - 1).is_none());
        assert!(ask(T0 + PROBER_QUERY_EVERY_MS).is_some());
        assert!(ask(T0 + PROBER_QUERY_EVERY_MS).is_none());
        assert_eq!(relay.delivery.unanswered(), 18);
        // Another feeder has its own.
        assert!(relay.ask(&query(&other, 1, 0, 63), T0).is_ok());
        Ok(())
    }

    /// A key is free, so a prober that takes a fresh one for every connection
    /// is answered no more than every key that never fed the relay is together, and takes nothing
    /// from a feeder's own allowance, however many keys it makes.
    #[test]
    fn a_fresh_key_per_connection_earns_no_fresh_allowance() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        relay.hold(&unsigned(&feeder.public(), FEEDING_BOOT, 0, 0)?, T0);
        let asked = |prober: PublicKey, now_ms: u64| {
            relay
                .delivery
                .answer_at(
                    &relay.selection,
                    Some(&relay.identity),
                    &query(&feeder, 1, 0, 63),
                    (Some(relay.point), prober, None),
                    now_ms,
                )
                .is_some()
        };
        let fresh = (0..1_000).filter(|_| asked(prober(), T0)).count();
        assert_eq!(fresh, PROBER_QUERIES as usize);
        // Earned back at the strangers' pace, not per key.
        let later = T0 + PROBER_QUERY_EVERY_MS;
        let fresh = (0..1_000).filter(|_| asked(prober(), later)).count();
        assert_eq!(fresh, 1);
        // The feeder's own allowance is untouched.
        let own = (0..1_000).filter(|_| asked(feeder.public(), later)).count();
        assert_eq!(own, PROBER_QUERIES as usize);
        Ok(())
    }

    /// The strangers' allowance is per network group, so one hostile prober,
    /// however many keys it makes from its network, spends only that network's allowance, and a
    /// stranger asking from another network is answered all the same. Without the groups the
    /// prober's thousand fresh keys spent the one allowance every stranger shared.
    #[test]
    fn a_hostile_prober_spends_only_its_own_networks_allowance() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        relay.hold(&unsigned(&feeder.public(), FEEDING_BOOT, 0, 0)?, T0);
        let asked =
            |prober: PublicKey, address: &str, now_ms: u64| -> std::result::Result<bool, String> {
                let address: std::net::IpAddr = address.parse().map_err(text)?;
                Ok(relay
                    .delivery
                    .answer_at(
                        &relay.selection,
                        Some(&relay.identity),
                        &query(&feeder, 1, 0, 63),
                        (Some(relay.point), prober, Some(Group::of(address))),
                        now_ms,
                    )
                    .is_some())
            };
        // The hostile prober: a fresh key and a fresh address in its /16 each query.
        let mut hostile = 0;
        for n in 0..1_000u32 {
            let address = format!("198.51.{}.{}", (n / 250) % 256, n % 250 + 1);
            hostile += usize::from(asked(prober(), &address, T0)?);
        }
        assert_eq!(hostile, PROBER_QUERIES as usize);
        // A stranger elsewhere has its network's whole allowance; one in the hostile's has none.
        let elsewhere = (0..1_000)
            .filter(|_| asked(prober(), "203.0.113.7", T0).unwrap_or(false))
            .count();
        assert_eq!(elsewhere, PROBER_QUERIES as usize);
        assert!(!asked(prober(), "198.51.200.9", T0)?);
        // An IPv6 prober is grouped by its /32: another /64 of the same /32 is the same network.
        let v6 = (0..8)
            .filter(|n| asked(prober(), &format!("2001:db8:{n}::1"), T0).unwrap_or(false))
            .count();
        assert_eq!(v6, PROBER_QUERIES as usize);
        Ok(())
    }

    /// The strangers' groups remembered are bounded, and a flood of groups past the
    /// bound (a botnet's networks, here twice as many as are remembered, each spending every
    /// query it is given) never refuses a newcomer: each network that asks after it is answered
    /// its own allowance. The flood's groups that spent theirs stay remembered and refused, so
    /// what is forgotten to make room is never the debt of a group that spent it; and once a
    /// group has earned its allowance back it is the first forgotten. When every group past the
    /// bound shared one allowance, the botnet spent it and every newcomer was refused.
    #[test]
    fn a_flood_of_groups_never_refuses_a_newcomer() {
        let mut strangers = Strangers::default();
        let group = |n: usize| Some(Group::V6(u32::try_from(n).unwrap_or(u32::MAX)));
        let queries = PROBER_QUERIES as usize;
        // The botnet floods first, from every one of its networks.
        let botnet = 2 * STRANGER_GROUPS;
        for n in 0..botnet {
            while strangers.spend_in_group(group(n), T0) {}
        }
        assert!(strangers.groups.len() <= STRANGER_GROUPS);
        // Newcomers, each from a network of its own: every one is answered its whole allowance.
        let newcomers = 100;
        let answered = (0..newcomers)
            .map(|n| {
                (0..2 * queries)
                    .filter(|_| strangers.spend_in_group(group(botnet + n), T0 + 1))
                    .count()
            })
            .collect::<Vec<_>>();
        assert_eq!(answered, vec![queries; newcomers]);
        assert!(strangers.groups.len() <= STRANGER_GROUPS);
        // Each newcomer took the place of the network nearest to whole: a hundred of the botnet's,
        // and every one of its networks still remembered is still refused.
        let remembered: Vec<_> = (STRANGER_GROUPS..botnet)
            .filter(|n| strangers.groups.contains_key(&group(*n)))
            .collect();
        assert!(remembered.len() >= STRANGER_GROUPS - newcomers);
        assert!(
            remembered
                .iter()
                .all(|n| !strangers.spend_in_group(group(*n), T0 + 1))
        );
        // Once the remembered groups have earned their queries back, a new group still has an
        // allowance of its own, and so does each of the botnet's.
        let later = T0 + 1 + WHOLE_AFTER_MS;
        let fresh = (0..7)
            .map(|n| {
                (0..queries)
                    .filter(|_| strangers.spend_in_group(group(10 * botnet + n), later))
                    .count()
            })
            .sum::<usize>();
        assert_eq!(fresh, 7 * queries);
        assert!(strangers.spend_in_group(group(botnet - 1), later));
    }

    /// All strangers together are answered at most `STRANGER_BURST` queries at
    /// once and `1000 / STRANGER_EVERY_MS` a second after, however many network groups they ask
    /// from (each group alone is allowed `PROBER_QUERIES`, so a botnet of 4,096 groups had 16,384
    /// at once); a query the relay-wide cap refuses spends nothing of its group's.
    #[test]
    fn strangers_together_are_answered_a_relay_wide_rate() {
        let mut strangers = Strangers::default();
        let group = |n: usize| Some(Group::V6(u32::try_from(n).unwrap_or(u32::MAX)));
        let mut answered = 0;
        for n in 0..STRANGER_GROUPS {
            for _ in 0..PROBER_QUERIES {
                answered += usize::from(strangers.spend(group(n), T0));
            }
        }
        assert_eq!(answered, STRANGER_BURST as usize);
        // A group the cap refused kept its whole allowance: one query's worth of time later it is
        // answered, while the groups that spent theirs are not.
        let refused = STRANGER_GROUPS - 1;
        assert!(!strangers.spend(group(refused), T0));
        let later = T0 + 10 * STRANGER_EVERY_MS;
        let after = (0..PROBER_QUERIES)
            .filter(|_| strangers.spend(group(refused), later))
            .count();
        assert_eq!(after, PROBER_QUERIES as usize);
        // Then the pace: a second of time earns `1000 / STRANGER_EVERY_MS` more, from any groups,
        // beside the 10 earned and 4 spent above.
        let mut paced = 0;
        for n in 0..4 * STRANGER_GROUPS {
            paced += usize::from(strangers.spend(group(n % STRANGER_GROUPS), later + 1_000));
        }
        assert_eq!(paced, 6 + (1_000 / STRANGER_EVERY_MS) as usize);
    }

    #[test]
    fn a_batch_let_go_is_neither_proved_nor_denied() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        relay.keyed(&feeder, T0)?;
        let start = WATCHED;
        relay.hold(&batch(&feeder, 1, 1)?, start);
        relay.hold(&batch(&feeder, 1, 2)?, start + TAG_WINDOW_MS);
        relay.hold(&batch(&feeder, 1, 3)?, start + TAG_WINDOW_MS + 1_000);
        let content = relay.ask(&query(&feeder, 1, 0, 4), start + TAG_WINDOW_MS + 2_000)?;
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
    fn a_straggler_is_found_by_its_sequence() -> Result {
        let relay = Relay::new()?;
        let feeder = Identity::generate().map_err(text)?;
        relay.keyed(&feeder, T0)?;
        for sequence in [1, 2, 4, 5, 3] {
            relay.hold(&batch(&feeder, 1, sequence)?, WATCHED + sequence);
        }
        // A copy changes nothing.
        relay.hold(&batch(&feeder, 1, 3)?, WATCHED + 9);
        assert_eq!(relay.delivery.tags(), 5);
        let content = relay.ask(&query(&feeder, 1, 1, 6), WATCHED + 10)?;
        let proved: Vec<u64> = content
            .entries
            .iter()
            .filter(|(_, said)| matches!(said, Possession::Proved { .. }))
            .map(|(sequence, _)| *sequence)
            .collect();
        assert_eq!(proved, vec![1, 2, 3, 4, 5]);
        assert_eq!(content.entries.last(), Some(&(6, Possession::NotSeen)));
        Ok(())
    }

    #[test]
    fn a_replayed_old_tag_fails_after_rotation() -> Result {
        // A member that kept an old key and tags a newer batch under it, or answers with a tag it
        // made long ago, proves nothing: the feeder takes a tag only under a key in force when it
        // sent the batch.
        let relay = Relay::new()?;
        let member = relay.identity.public();
        let feeder = Identity::generate().map_err(text)?;
        let first = 10 * KEY_PERIOD_MS;
        relay.keyed(&feeder, first)?;
        let old = batch(&feeder, 1, 1)?;
        relay.hold(&old, first + 1);
        let content = relay.ask(&query(&feeder, 1, 1, 1), first + 2)?;
        let [(_, Possession::Proved { key, tag })] = content.entries[..] else {
            return Err(format!("{:?}", content.entries));
        };
        assert!(verifies(&member, &old, first + 1, key, &tag));
        // Three periods on, the old key is no key for a batch sent now.
        let later = first + 3 * KEY_PERIOD_MS;
        let fresh = batch(&feeder, 1, 2)?;
        let replayed = delivery_tag(&keys_at(&member, key).0.key, fresh.as_bytes());
        assert!(!verifies(&member, &fresh, later, key, &replayed));
        // And the relay itself has rotated: keyed in the new period, it tags under the new key.
        relay.keyed(&feeder, later)?;
        relay.hold(&fresh, later + 1);
        let content = relay.ask(&query(&feeder, 1, 2, 2), later + 2)?;
        let [(_, Possession::Proved { key: now_key, tag })] = content.entries[..] else {
            return Err(format!("{:?}", content.entries));
        };
        assert_eq!(now_key, key_period(later));
        assert!(verifies(&member, &fresh, later, now_key, &tag));
        // A replayed grant older than the keys held changes nothing.
        let replay = DeliveryQuery {
            ranges: Vec::new(),
            keys: Some(grant(&feeder, &member, first)?),
            ..query(&feeder, 0, 0, 0)
        };
        relay.ask(&replay, later + 3)?;
        relay.hold(&batch(&feeder, 1, 3)?, later + 3);
        let content = relay.ask(&query(&feeder, 1, 3, 3), later + 4)?;
        assert!(matches!(
            content.entries[..],
            [(3, Possession::Proved { key, .. })] if key == key_period(later)
        ));
        Ok(())
    }

    #[test]
    fn a_tag_made_four_minutes_ago_proves_delivery_at_twenty_thousand_feeders() -> Result {
        // 20,000 feeders, each a batch a second, for four minutes: the relay's whole arrival rate
        // at RFC-0181's target. The first batch of each is proved at the end, from the tag made
        // when it came; the store holds every entry within its bound, refusing none.
        const FEEDERS: usize = 20_000;
        const SECONDS: u64 = 240;
        let relay = Relay::new()?;
        let member = relay.identity.public();
        let feeders: Vec<PublicKey> = (0..FEEDERS)
            .map(|index| {
                let mut seed = [0; 32];
                seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
                Identity::from_seed(seed).public()
            })
            .collect();
        let start = 10 * KEY_PERIOD_MS;
        // Each has fed the relay, and granted keys as a grant gives them (the signature is checked
        // in its own test; 20,000 of them would only be slow here).
        let (current, next) = keys_at(&member, key_period(start));
        for feeder in &feeders {
            relay
                .delivery
                .hold_bytes(*feeder, (0, 0), feeder.as_bytes(), start - 1);
            assert!(relay.delivery.take_keys(
                *feeder,
                &TagKeysContent {
                    member,
                    current,
                    next,
                    switch_in_ms: KEY_PERIOD_MS,
                },
                start,
            ));
        }
        assert_eq!(relay.delivery.keyed(), FEEDERS);
        // A batch's bytes, its sequence and feeder in place (short: what is measured here is the
        // store at the arrival rate, not the hash, which is linear in the bytes).
        let mut bytes = vec![0x5a; 160];
        for second in 0..SECONDS {
            let now = start + second * 1_000;
            bytes[..8].copy_from_slice(&second.to_be_bytes());
            for feeder in &feeders {
                bytes[8..40].copy_from_slice(feeder.as_bytes());
                relay.delivery.hold_bytes(*feeder, (1, second), &bytes, now);
            }
        }
        assert_eq!(relay.delivery.refused(), 0);
        assert_eq!(relay.delivery.tags(), FEEDERS * (SECONDS as usize + 1));
        assert!(relay.delivery.held_bytes() <= FEEDERS * PER_FEEDER_BYTES);
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
        let content = relay.ask(&asked, start + SECONDS * 1_000)?;
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

    /// Many feeders flooding as fast as they can each fill only their own
    /// share (`ENTRIES_PER_RECEIVER`); an honest feeder in whatever shard is never refused and
    /// its audits are answered, and a flooder's batch refused is never denied.
    #[test]
    fn a_flood_from_many_feeders_fills_only_their_own_shares() -> Result {
        const FLOODERS: u64 = 256;
        let relay = Relay::new()?;
        let honest: Vec<Identity> = (0..64_u8)
            .map(|seed| Identity::from_seed([seed; 32]))
            .collect();
        for feeder in &honest {
            relay.keyed(feeder, T0)?;
        }
        // Every flooder at 100 batches a second for ten seconds: past its share.
        let flooders: Vec<PublicKey> = (0..FLOODERS)
            .map(|index| {
                let mut seed = [0xf0; 32];
                seed[..8].copy_from_slice(&index.to_be_bytes());
                Identity::from_seed(seed).public()
            })
            .collect();
        let per = 1_000_u64;
        for sequence in 0..per {
            let now = WATCHED + sequence * 10;
            for flooder in &flooders {
                relay.hold(&unsigned(flooder, 1, sequence, 0)?, now);
            }
        }
        let refused = relay.delivery.refused();
        let over = per - ENTRIES_PER_RECEIVER as u64;
        assert_eq!(refused, FLOODERS * over);
        let flood_end = WATCHED + per * 10;
        // Every honest feeder's batch is held, tagged, and proved.
        for (feeder, sequence) in honest.iter().zip(1_u64..) {
            relay.hold(&batch(feeder, 1, sequence)?, flood_end);
        }
        assert_eq!(relay.delivery.refused(), refused);
        for (feeder, sequence) in honest.iter().zip(1_u64..) {
            let content = relay.ask(&query(feeder, 1, sequence, sequence + 1), flood_end + 1)?;
            assert!(
                matches!(
                    content.entries[..],
                    [(_, Possession::Proved { .. }), (_, Possession::NotSeen)]
                ),
                "{:?}",
                content.entries
            );
        }
        // A flooder's refused batch is never denied, even once its feeder has been watched a
        // whole window.
        let flooder = Identity::from_seed({
            let mut seed = [0xf0; 32];
            seed[..8].copy_from_slice(&0_u64.to_be_bytes());
            seed
        });
        let last = per - 1;
        assert!(
            relay
                .ask(&query(&flooder, 1, last, last), WATCHED + TAG_WINDOW_MS)?
                .entries
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn past_the_relays_bound_a_batch_is_refused_whole_counted_and_never_denied() -> Result {
        let relay = Relay::new()?;
        // Room for a receiver's share in each shard, and no more.
        let limit = SHARDS * ENTRIES_PER_RECEIVER * TAG_BYTES;
        let gauge = Gauge::new(Store::Delivery, limit);
        relay.delivery.charge_to(std::sync::Arc::clone(&gauge));
        let feeders: Vec<Identity> = (0..4 * SHARDS as u64)
            .map(|index| {
                let mut seed = [0x33; 32];
                seed[..8].copy_from_slice(&index.to_be_bytes());
                Identity::from_seed(seed)
            })
            .collect();
        for sequence in 0..ENTRIES_PER_RECEIVER as u64 {
            for feeder in &feeders {
                relay.hold(&unsigned(&feeder.public(), 0, sequence, 0)?, T0);
            }
        }
        // Driven to its limit, the gauge is what the streams hold, entry by entry, and full.
        assert!(relay.delivery.refused() > 0);
        assert!(gauge.refused() > 0);
        assert_eq!(gauge.held(), relay.delivery.counted_bytes());
        assert_eq!(gauge.held(), relay.delivery.held_bytes());
        assert!(gauge.held() <= limit && limit - gauge.held() < TAG_BYTES);
        // Let go past the window, the entries' bytes are released with them.
        relay.hold(
            &unsigned(&feeders[0].public(), 0, ENTRIES_PER_RECEIVER as u64, 0)?,
            T0 + 2 * TAG_WINDOW_MS,
        );
        assert_eq!(gauge.held(), relay.delivery.counted_bytes());
        // A refused batch is not denied, whichever feeder's it was.
        let content = relay.ask(
            &query(&feeders[0], 0, 0, ENTRIES_PER_RECEIVER as u64 - 1),
            WATCHED,
        )?;
        assert!(
            content
                .entries
                .iter()
                .all(|(_, said)| !matches!(said, Possession::NotSeen)),
            "a refused batch is not denied"
        );
        Ok(())
    }

    /// The streams a shard remembers are bounded over many feeders, not one;
    /// the streams forgotten early to make room are never denied, and their receivers' newer
    /// streams, and every stream the shard did keep, still are.
    #[test]
    fn streams_are_bounded_over_many_feeders_and_one_forgotten_early_is_not_denied() {
        let mut shard = Shard::new(&Gauge::unlimited(Store::Delivery));
        let bound = STREAMS_REMEMBERED / SHARDS;
        let feeders: Vec<PublicKey> = (0..2 * bound as u64)
            .map(|index| {
                let mut seed = [0x44; 32];
                seed[..8].copy_from_slice(&index.to_be_bytes());
                Identity::from_seed(seed).public()
            })
            .collect();
        // Each feeder's first batch in the order they came, a moment apart.
        for (feeder, at) in feeders.iter().zip(0_u64..) {
            assert!(shard.hold(*feeder, (1, 1), feeder.as_bytes(), T0 + at));
        }
        assert_eq!(shard.streams.len(), bound);
        assert!(shard.receivers.len() <= bound);
        let now = WATCHED + 2 * bound as u64;
        // The first half went to make room: nothing is said of them.
        for feeder in &feeders[..bound] {
            assert!(matches!(shard.said((*feeder, 1), 2, now), Said::Unknown));
        }
        // The second half are remembered, and their unsent batches not seen.
        for feeder in &feeders[bound..] {
            assert!(matches!(shard.said((*feeder, 1), 2, now), Said::NotSeen));
        }
    }

    /// Audit 2.2's twin here: a feeder churning boot ids forgets only its own streams. Another
    /// feeder's stream (whatever shard either is in) is remembered, so a sequence it never sent
    /// is still said not seen, and the churner's forgotten boots are never denied.
    #[test]
    fn a_churn_of_one_feeders_boots_forgets_only_its_own_streams() -> Result {
        let relay = Relay::new()?;
        let honest = Identity::from_seed([4; 32]);
        let churner = Identity::from_seed([5; 32]);
        relay.hold(&unsigned(&honest.public(), 1, 0, 0)?, T0);
        // Four times what a shard remembers, all the churner's.
        let boots = 4 * (STREAMS_REMEMBERED / SHARDS) as u64;
        for boot in 0..boots {
            relay.hold(&unsigned(&churner.public(), boot, 0, 0)?, T0 + 1);
        }
        assert_eq!(relay.delivery.streams(), 1 + BOOTS_PER_RECEIVER);
        let asked =
            |feeder: &Identity, boot: u64| -> std::result::Result<Vec<(u64, Possession)>, String> {
                Ok(relay.ask(&query(feeder, boot, 1, 1), WATCHED + 2)?.entries)
            };
        assert_eq!(asked(&honest, 1)?, vec![(1, Possession::NotSeen)]);
        assert_eq!(asked(&churner, boots - 1)?, vec![(1, Possession::NotSeen)]);
        assert!(asked(&churner, 0)?.is_empty());
        // An unknown boot of the churner may be one it forgot: not denied either.
        assert!(asked(&churner, boots + 5)?.is_empty());
        Ok(())
    }

    /// Through the relay's own dispatch: a prober that asks
    /// on a new connection each time (a new hub source), with the same key or a fresh one each
    /// time, is answered no more than one allowance.
    #[test]
    fn a_probers_allowance_survives_its_reconnects() -> Result {
        let hub = crate::hub::Hub::new(8);
        hub.network()
            .adopt_identity(Identity::generate().map_err(text)?);
        let feeder = Identity::generate().map_err(text)?;
        let same = prober();
        let answered = (1..=8 * u64::from(PROBER_QUERIES))
            .filter(|source| {
                let key = if source % 2 == 0 { same } else { prober() };
                let asker = crate::network::Asker {
                    role: crate::network::AskerRole::Feeder,
                    key,
                    source: *source,
                    loopback: false,
                    address: Some(std::net::IpAddr::from([192, 0, 2, 1])),
                };
                !hub.network()
                    .handle(
                        &hub,
                        &asker,
                        Record::DeliveryQuery(query(&feeder, 1, 0, 3)),
                        T0,
                        None,
                    )
                    .is_empty()
            })
            .count();
        assert_eq!(answered, PROBER_QUERIES as usize);
        Ok(())
    }
}
