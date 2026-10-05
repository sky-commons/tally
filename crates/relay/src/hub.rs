//! What every connection of a relay shares: the fan-out, the record of batches already forwarded,
//! and each receiver's newest self-description.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tally_wire::batch::Hash;
use tally_wire::{Batch, PublicKey, ReceiverInfo, Record};
use tokio::sync::broadcast;

/// How many records a subscriber may fall behind before it is dropped. readsb's rule: drop the
/// slow consumer, never slow the producers (RFC-0166 §3.6).
const FAN_OUT_CAPACITY: usize = 8192;

/// How long a forwarded batch's hash is remembered. Longer than any loop through the relay tree,
/// so a batch arriving again by another path is recognised and forwarded once.
const SEEN_WINDOW: Duration = Duration::from_secs(60);

/// A record on its way out, and the connection it came in on, so it is never sent back there.
#[derive(Clone, Debug)]
pub struct Item {
    pub source: u64,
    pub record: Arc<Record>,
}

/// Two generations of hashes: a hash is remembered for one to two windows.
struct Seen {
    current: HashSet<Hash>,
    previous: HashSet<Hash>,
    rotated: Instant,
}

impl Seen {
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

pub struct Hub {
    out: broadcast::Sender<Item>,
    seen: Mutex<Seen>,
    infos: Mutex<HashMap<PublicKey, (u64, ReceiverInfo)>>,
    next_connection: AtomicU64,
    subscribers: Arc<AtomicUsize>,
    max_subscribers: usize,
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
            seen: Mutex::new(Seen {
                current: HashSet::new(),
                previous: HashSet::new(),
                rotated: Instant::now(),
            }),
            infos: Mutex::new(HashMap::new()),
            next_connection: AtomicU64::new(1),
            subscribers: Arc::new(AtomicUsize::new(0)),
            max_subscribers,
        }
    }

    pub fn connection_id(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    /// Forwards a verified batch unless it was already forwarded. True when it was new.
    pub fn publish_batch(&self, source: u64, batch: Batch) -> bool {
        let new = self
            .seen
            .lock()
            .is_ok_and(|mut seen| seen.insert(batch.hash()));
        if new {
            // An error only means nobody is subscribed right now.
            let _ = self.out.send(Item {
                source,
                record: Arc::new(Record::Batch(batch)),
            });
        }
        new
    }

    /// Keeps a verified receiver description if it is the newest for its key, and forwards it.
    pub fn publish_info(
        &self,
        source: u64,
        info: ReceiverInfo,
        receiver: PublicKey,
        issued_ms: u64,
    ) {
        let newer = self.infos.lock().is_ok_and(|mut infos| {
            let newer = infos
                .get(&receiver)
                .is_none_or(|(known, _)| issued_ms > *known);
            if newer {
                infos.insert(receiver, (issued_ms, info.clone()));
            }
            newer
        });
        if newer {
            let _ = self.out.send(Item {
                source,
                record: Arc::new(Record::ReceiverInfo(info)),
            });
        }
    }

    /// A place in the fan-out, with every known receiver description to send first, or `None`
    /// when the relay is serving as many subscribers as it will.
    pub fn subscribe(&self) -> Option<(broadcast::Receiver<Item>, Vec<ReceiverInfo>, Slot)> {
        let taken = self.subscribers.fetch_add(1, Ordering::SeqCst);
        let slot = Slot {
            subscribers: Arc::clone(&self.subscribers),
        };
        if taken >= self.max_subscribers {
            return None;
        }
        let receiver = self.out.subscribe();
        let infos = self
            .infos
            .lock()
            .map(|infos| infos.values().map(|(_, info)| info.clone()).collect())
            .unwrap_or_default();
        Some((receiver, infos, slot))
    }

    /// A place in the fan-out that does not count against the subscriber cap: for links to other
    /// relays, which carry load as well as take it.
    pub fn peer(&self) -> (broadcast::Receiver<Item>, Vec<ReceiverInfo>) {
        let receiver = self.out.subscribe();
        let infos = self
            .infos
            .lock()
            .map(|infos| infos.values().map(|(_, info)| info.clone()).collect())
            .unwrap_or_default();
        (receiver, infos)
    }
}
