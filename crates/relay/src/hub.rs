//! What every connection of a relay shares: the fan-out, the record of batches and positions
//! already forwarded, the deduplicated stream being gathered, each receiver's newest
//! self-description, and the relays this one offers as hints.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tally_wire::batch::Hash;
use tally_wire::{
    Batch, Location, Observation, Positions, PublicKey, ReceiverInfo, Record, RelayAddress,
};
use tokio::sync::broadcast;

use crate::subscription::Subscription;

/// How many records a subscriber may fall behind before it is dropped. readsb's rule: drop the
/// slow consumer, never slow the producers (RFC-0166 §3.6).
const FAN_OUT_CAPACITY: usize = 8192;

/// How long a forwarded batch's hash is remembered. Longer than any loop through the relay tree,
/// so a batch arriving again by another path is recognised and forwarded once.
const SEEN_WINDOW: Duration = Duration::from_secs(60);

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
    /// For a receiver's batch or description: where that receiver last declared itself, if it
    /// has. Regions route by this and by nothing else.
    pub place: Option<Location>,
}

/// Two generations of hashes: a hash is remembered for one to two windows.
struct Seen {
    current: HashSet<Hash>,
    previous: HashSet<Hash>,
    rotated: Instant,
}

impl Seen {
    fn new() -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated: Instant::now(),
        }
    }

    fn insert(&mut self, hash: Hash) -> bool {
        if self.rotated.elapsed() >= SEEN_WINDOW {
            self.previous = std::mem::take(&mut self.current);
            self.rotated = Instant::now();
        }
        if self.previous.contains(&hash) {
            return false;
        }
        self.current.insert(hash)
    }
}

/// The deduplicated stream on its way to being signed: first copies of each message, and when
/// each message was first heard, across every receiver.
struct Deduplicator {
    first_heard: HashMap<(u8, Vec<u8>), Instant>,
    gathered: Vec<Observation>,
}

impl Deduplicator {
    fn offer(&mut self, observation: Observation, now: Instant) {
        let key = (observation.format, observation.data.clone());
        let fresh = self
            .first_heard
            .get(&key)
            .is_none_or(|heard| now.duration_since(*heard) >= DEDUPLICATION_WINDOW);
        if fresh {
            self.first_heard.insert(key, now);
            self.gathered.push(observation);
        }
    }

    fn take(&mut self, now: Instant) -> Vec<Observation> {
        self.first_heard
            .retain(|_, heard| now.duration_since(*heard) < DEDUPLICATION_WINDOW);
        std::mem::take(&mut self.gathered)
    }
}

/// A receiver's newest description, and the location it declared in it.
struct Known {
    issued_ms: u64,
    info: ReceiverInfo,
    place: Option<Location>,
}

pub struct Hub {
    out: broadcast::Sender<Item>,
    batches: Mutex<Seen>,
    positions: Mutex<Seen>,
    deduplicator: Mutex<Deduplicator>,
    infos: Mutex<HashMap<PublicKey, Known>>,
    next_connection: AtomicU64,
    subscribers: Arc<AtomicUsize>,
    max_subscribers: usize,
    hints: Vec<RelayAddress>,
}

/// Held for as long as a subscriber is served; releases its slot when dropped.
pub struct Slot {
    subscribers: Arc<AtomicUsize>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.subscribers.fetch_sub(1, Ordering::SeqCst);
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
            batches: Mutex::new(Seen::new()),
            positions: Mutex::new(Seen::new()),
            deduplicator: Mutex::new(Deduplicator {
                first_heard: HashMap::new(),
                gathered: Vec::new(),
            }),
            infos: Mutex::new(HashMap::new()),
            next_connection: AtomicU64::new(RELAY_ITSELF + 1),
            subscribers: Arc::new(AtomicUsize::new(0)),
            max_subscribers,
            hints: Vec::new(),
        }
    }

    /// The relays this one offers feeders as hints, and names when it turns a subscriber away.
    pub fn advertising(mut self, hints: Vec<RelayAddress>) -> Self {
        self.hints = hints;
        self
    }

    pub fn hints(&self) -> &[RelayAddress] {
        &self.hints
    }

    pub fn connection_id(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    /// Forwards a verified batch unless it was already forwarded, and offers its observations to
    /// the deduplicated stream. True when it was new.
    pub fn publish_batch(&self, source: u64, batch: Batch, receiver: PublicKey) -> bool {
        let new = self
            .batches
            .lock()
            .is_ok_and(|mut seen| seen.insert(batch.hash()));
        if !new {
            return false;
        }
        // A format this build cannot read is still forwarded raw; it just adds nothing here.
        if let (Ok(content), Ok(mut deduplicator)) = (batch.content(), self.deduplicator.lock()) {
            let now = Instant::now();
            for observation in content.observations {
                deduplicator.offer(observation, now);
            }
        }
        let place = self
            .infos
            .lock()
            .ok()
            .and_then(|infos| infos.get(&receiver).and_then(|known| known.place));
        // An error only means nobody is subscribed right now.
        let _ = self.out.send(Item {
            source,
            record: Arc::new(Record::Batch(batch)),
            place,
        });
        true
    }

    /// Keeps a verified receiver description if it is the newest for its key, and forwards it.
    /// `place` is the location it declares, when this build can read it.
    pub fn publish_info(
        &self,
        source: u64,
        info: ReceiverInfo,
        receiver: PublicKey,
        issued_ms: u64,
        place: Option<Location>,
    ) {
        let Ok(mut infos) = self.infos.lock() else {
            return;
        };
        let newer = infos
            .get(&receiver)
            .is_none_or(|known| issued_ms > known.issued_ms);
        if newer {
            infos.insert(
                receiver,
                Known {
                    issued_ms,
                    info: info.clone(),
                    place,
                },
            );
            // Sent under the lock, so a joining subscriber gets each description either in its
            // first list or from the fan-out, never both and never neither.
            let _ = self.out.send(Item {
                source,
                record: Arc::new(Record::ReceiverInfo(info)),
                place,
            });
        }
    }

    /// Forwards verified positions unless they were already forwarded. True when they were new.
    pub fn publish_positions(&self, source: u64, positions: Positions) -> bool {
        let new = self
            .positions
            .lock()
            .is_ok_and(|mut seen| seen.insert(positions.hash()));
        if new {
            let _ = self.out.send(Item {
                source,
                record: Arc::new(Record::Positions(positions)),
                place: None,
            });
        }
        new
    }

    /// The first copies gathered since the last call, for the relay to sign.
    pub fn take_deduplicated(&self) -> Vec<Observation> {
        self.deduplicator
            .lock()
            .map(|mut deduplicator| deduplicator.take(Instant::now()))
            .unwrap_or_default()
    }

    /// Broadcasts a batch the relay signed itself.
    pub fn publish_relay_batch(&self, batch: Batch) {
        let _ = self.out.send(Item {
            source: RELAY_ITSELF,
            record: Arc::new(Record::RelayBatch(batch)),
            place: None,
        });
    }

    /// A place in the fan-out, with every known receiver description to send first, or `None`
    /// when the relay is serving as many subscribers as it will.
    pub fn subscribe(&self) -> Option<(broadcast::Receiver<Item>, Vec<Item>, Slot)> {
        let taken = self.subscribers.fetch_add(1, Ordering::SeqCst);
        let slot = Slot {
            subscribers: Arc::clone(&self.subscribers),
        };
        if taken >= self.max_subscribers {
            return None;
        }
        let (receiver, infos) = self.peer();
        Some((receiver, infos, slot))
    }

    /// A place in the fan-out that does not count against the subscriber cap: for links to other
    /// relays, which carry load as well as take it.
    pub fn peer(&self) -> (broadcast::Receiver<Item>, Vec<Item>) {
        // Joined under the descriptions' lock (see `publish_info`).
        match self.infos.lock() {
            Ok(infos) => (self.out.subscribe(), described(&infos)),
            Err(_) => (self.out.subscribe(), Vec::new()),
        }
    }

    /// Every known receiver description a subscription covers: what a subscriber is sent when it
    /// changes what it wants, so receivers it newly covers are described before their batches.
    pub fn infos_for(&self, subscription: &Subscription) -> Vec<Item> {
        self.infos
            .lock()
            .map(|infos| described(&infos))
            .unwrap_or_default()
            .into_iter()
            .filter(|item| subscription.wants(item))
            .collect()
    }
}

fn described(infos: &HashMap<PublicKey, Known>) -> Vec<Item> {
    infos
        .values()
        .map(|known| Item {
            source: RELAY_ITSELF,
            record: Arc::new(Record::ReceiverInfo(known.info.clone())),
            place: known.place,
        })
        .collect()
}
