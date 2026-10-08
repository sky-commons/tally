//! Fan-out to subscribers (RFC-0177 §8). A [`Router`] keyed by subscription cell feeds one queue
//! per subscriber ([`Queue`]), bounded in bytes and in time ([`Bounds`]): a subscriber whose queue
//! would hold more than [`BEHIND_MS`] of inbound, or more bytes than its bound, has fallen behind and
//! is let go with a Goodbye that says so (`Reason::FellBehind`), never cut for a full shared ring,
//! and never slowing the producers. A relay's directory link is the one exception: what it is sent
//! is held whole elsewhere, so it is sent that again ([`Fell::Resync`]) instead.
//!
//! Each receiver's batches are published by the one ingest worker that owns its shard
//! (`ingest`), in the order they were admitted, and its description is published before its first
//! batch, so every subscriber reads each (receiver, boot) in admitted order, described first.
//!
//! Every item queued is charged once to the relay's budget (`budget::Store::Fanout`), however many
//! queues hold it, and released when the last lets it go. When an item would pass the budget, the
//! subscriber holding the most is let go as fallen behind, and the next, until it fits: the queues
//! together never hold more than their share of the relay's memory, and no subscriber ever misses
//! an item without being told.
//!
//! Routing reads a subscription's regions once, when it changes ([`Router::set`]): a record placed
//! at a cell is offered to the whole-world subscribers and to the subscribers of that cell's
//! ancestors at the resolutions anyone subscribed at, a few hash lookups whatever the number of
//! subscribers; every offer is then the subscription's own rule (`Subscription::wants`).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tally_wire::{Record, Region};
use tokio::sync::Notify;

use crate::budget::{Charge, Gauge, Store};

use crate::hub::Item;
use crate::subscription::{Subscription, directory_wants};

/// How far behind its inbound a subscriber may fall before it is let go.
pub const BEHIND_MS: u64 = 2_000;

/// A subscriber queue's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub max_bytes: usize,
    pub max_age_ms: u64,
}

/// Why a subscriber is let go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FellBehind {
    /// It holds more than `max_bytes`.
    Bytes,
    /// Its oldest item is more than `max_age_ms` older than the newest offered.
    Age,
}

/// One subscriber's queue of `T`, each with its size in bytes and its ingest stamp.
#[derive(Debug)]
pub struct Queue<T> {
    bounds: Bounds,
    items: VecDeque<(T, usize, u64)>,
    bytes: usize,
}

impl<T> Queue<T> {
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            items: VecDeque::new(),
            bytes: 0,
        }
    }

    /// Queues `item` of `bytes` stamped `stamp_ms`, or says the subscriber fell behind (the item
    /// is not queued, and the subscriber is to be disconnected).
    pub fn push(&mut self, item: T, bytes: usize, stamp_ms: u64) -> Result<(), FellBehind> {
        if self.bytes + bytes > self.bounds.max_bytes {
            return Err(FellBehind::Bytes);
        }
        if let Some((_, _, oldest)) = self.items.front()
            && stamp_ms.saturating_sub(*oldest) > self.bounds.max_age_ms
        {
            return Err(FellBehind::Age);
        }
        self.bytes += bytes;
        self.items.push_back((item, bytes, stamp_ms));
        Ok(())
    }

    /// The oldest item, to write.
    pub fn pop(&mut self) -> Option<T> {
        let (item, bytes, _) = self.items.pop_front()?;
        self.bytes -= bytes;
        Some(item)
    }

    /// Lets everything queued go.
    pub fn clear(&mut self) {
        self.items.clear();
        self.bytes = 0;
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// What a subscriber is offered.
#[derive(Clone, Debug)]
pub enum Filter {
    /// Another relay: the directory only (`directory_wants`).
    Directory,
    /// A subscriber or engine: its subscription.
    Subscription(Subscription),
    /// The loopback BEAST output: every receiver's batch this build reads.
    Beast,
    /// Every record: what a test of the hub reads.
    #[cfg(test)]
    Everything,
}

impl Filter {
    pub fn wants(&self, item: &Item) -> bool {
        match self {
            Self::Directory => directory_wants(item),
            Self::Subscription(subscription) => subscription.wants(item),
            Self::Beast => item.decoded.is_some(),
            #[cfg(test)]
            Self::Everything => true,
        }
    }

    /// The regions it is keyed by in the router: none for whole-world (and for what is not a
    /// subscription).
    fn regions(&self) -> &[Region] {
        match self {
            Self::Subscription(subscription) => &subscription.regions,
            Self::Directory | Self::Beast => &[],
            #[cfg(test)]
            Self::Everything => &[],
        }
    }
}

/// Why a listener stopped reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fell {
    /// It fell behind: let it go, saying so.
    Behind(FellBehind),
    /// A directory link overflowed: send it the directory held now, whole, and go on.
    Resync,
}

/// What an item costs a queue: a batch's one decode (its signed bytes among it,
/// `Decoded::footprint`), or the record's encoded bytes.
pub fn item_bytes(item: &Item) -> usize {
    match &item.decoded {
        Some(decoded) => decoded.footprint(),
        None => item.record.encoded_len(),
    }
}

/// An item as a queue holds it: with the one charge every queue holding it shares.
type Queued = (Item, Arc<Charge>);

struct Subscriber {
    /// The connection it is, so nothing is sent back down the connection it came in on.
    source: u64,
    queue: Mutex<State>,
    notify: Notify,
    /// A directory link: on overflow, resynchronised, never let go.
    resyncs: bool,
}

struct State {
    queue: Queue<Queued>,
    fell: Option<Fell>,
}

impl Subscriber {
    fn offer(&self, item: &Item, charge: &Arc<Charge>, bytes: usize) {
        let Ok(mut state) = self.queue.lock() else {
            return;
        };
        if matches!(state.fell, Some(Fell::Behind(_))) {
            return;
        }
        if let Err(why) = state
            .queue
            .push((item.clone(), Arc::clone(charge)), bytes, item.stamp_ms)
        {
            // What it holds is no use to it now: let it go at once, not when it is read.
            state.queue.clear();
            state.fell = Some(if self.resyncs {
                Fell::Resync
            } else {
                Fell::Behind(why)
            });
        }
        drop(state);
        self.notify.notify_one();
    }

    /// Bytes it holds now.
    fn bytes(&self) -> usize {
        self.queue.lock().map_or(0, |state| state.queue.bytes())
    }

    /// Let go for the budget: told it fell behind (a directory link is resynchronised), and what
    /// it held let go now.
    fn let_go(&self) {
        if let Ok(mut state) = self.queue.lock() {
            state.queue.clear();
            state.fell = Some(if self.resyncs {
                Fell::Resync
            } else {
                Fell::Behind(FellBehind::Bytes)
            });
        }
        self.notify.notify_one();
    }
}

struct Entry {
    id: u64,
    subscriber: Arc<Subscriber>,
    filter: Filter,
}

/// The subscribers by how they are routed to: whole-world ones, and the rest by their regions'
/// cells.
#[derive(Default)]
struct Index {
    entries: Vec<Entry>,
    /// Entries that take records from anywhere: no regions.
    everywhere: Vec<usize>,
    /// Entries with regions, by each region's cell number.
    by_cell: HashMap<u64, Vec<usize>>,
    /// Entries with regions, all of them: offered what is routed by no place.
    regional: Vec<usize>,
    /// The resolutions any region is at, ascending.
    resolutions: Vec<u8>,
}

impl Index {
    fn build(entries: Vec<Entry>) -> Self {
        let mut index = Self {
            entries,
            ..Self::default()
        };
        for (at, entry) in index.entries.iter().enumerate() {
            let regions = entry.filter.regions();
            if regions.is_empty() {
                index.everywhere.push(at);
                continue;
            }
            index.regional.push(at);
            for region in regions {
                let keyed = index.by_cell.entry(region.as_u64()).or_default();
                if keyed.last() != Some(&at) {
                    keyed.push(at);
                }
                index.resolutions.push(region.resolution());
            }
        }
        index.resolutions.sort_unstable();
        index.resolutions.dedup();
        index
    }

    /// The entries with regions that hold one of `cells`, each once, ascending.
    fn holding(&self, cells: &[Region], into: &mut Vec<usize>) {
        for cell in cells {
            for resolution in &self.resolutions {
                if let Some(ancestor) = cell.ancestor(*resolution)
                    && let Some(keyed) = self.by_cell.get(&ancestor.as_u64())
                {
                    into.extend_from_slice(keyed);
                }
            }
        }
        into.sort_unstable();
        into.dedup();
    }
}

/// Where a record is placed for routing: its receiver's or area's cell, the aircraft it places, or
/// nowhere (offered to every subscriber, each deciding by its streams alone).
enum Place<'a> {
    Cells(&'a [Region]),
    Nowhere,
}

fn place(item: &Item) -> Place<'_> {
    match &*item.record {
        Record::Batch(_)
        | Record::ReceiverInfo(_)
        | Record::RegionalBatch(_)
        | Record::BundleIndex(_) => match &item.cell {
            Some(cell) => Place::Cells(std::slice::from_ref(cell)),
            // Unplaced: whole-world subscribers only (`Subscription::covers`).
            None => Place::Cells(&[]),
        },
        Record::Positions(_) | Record::Provisional(_) | Record::ClockModel(_) => {
            match &item.points {
                Some(points) => Place::Cells(points),
                None => Place::Nowhere,
            }
        }
        _ => Place::Nowhere,
    }
}

/// Every subscriber's queue, and the index records are routed by.
pub struct Router {
    index: RwLock<Index>,
    bounds: Bounds,
    gauge: Arc<Gauge>,
    next: AtomicU64,
}

impl Router {
    /// Queues bounded by `bounds` alone: for a test.
    pub fn new(bounds: Bounds) -> Self {
        Self::charged(bounds, Gauge::unlimited(Store::Fanout))
    }

    /// Queues bounded by `bounds`, and together by `gauge` (the budget's `Store::Fanout`).
    pub fn charged(bounds: Bounds, gauge: Arc<Gauge>) -> Self {
        Self {
            index: RwLock::new(Index::default()),
            bounds,
            gauge,
            next: AtomicU64::new(0),
        }
    }

    pub fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// Offers `item` to every subscriber that takes it. Never waits on a subscriber: one whose
    /// queue is past its bounds is let go.
    pub fn publish(&self, item: Item) {
        let Ok(index) = self.index.read() else {
            return;
        };
        if index.entries.is_empty() {
            return;
        }
        // Who takes it: every whole-world subscriber, and those whose regions hold its place.
        let mut takers = Vec::new();
        let mut take = |at: usize| {
            let entry = &index.entries[at];
            if entry.subscriber.source != item.source && entry.filter.wants(&item) {
                takers.push(at);
            }
        };
        for at in &index.everywhere {
            take(*at);
        }
        match place(&item) {
            Place::Nowhere => {
                for at in &index.regional {
                    take(*at);
                }
            }
            Place::Cells(cells) if !cells.is_empty() && !index.regional.is_empty() => {
                let mut held = Vec::new();
                index.holding(cells, &mut held);
                for at in held {
                    take(at);
                }
            }
            Place::Cells(_) => {}
        }
        if takers.is_empty() {
            return;
        }
        let bytes = item_bytes(&item);
        // Room in the budget, made by letting go whoever holds most, as many as it takes.
        for _ in 0..index.entries.len() {
            if self.gauge.fits(bytes) {
                break;
            }
            let Some((_, laggard)) = index
                .entries
                .iter()
                .map(|entry| (entry.subscriber.bytes(), &entry.subscriber))
                .filter(|(held, _)| *held > 0)
                .max_by_key(|(held, _)| *held)
            else {
                break;
            };
            laggard.let_go();
        }
        // Charged once whatever holds it; released when the last queue lets it go.
        let charge = Arc::new(self.gauge.force(bytes));
        for at in takers {
            index.entries[at].subscriber.offer(&item, &charge, bytes);
        }
    }

    /// A new subscriber on connection `source`, offered what `filter` takes from now on.
    pub fn listen(self: &Arc<Self>, source: u64, filter: Filter) -> Listener {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let subscriber = Arc::new(Subscriber {
            source,
            queue: Mutex::new(State {
                queue: Queue::new(self.bounds),
                fell: None,
            }),
            notify: Notify::new(),
            resyncs: matches!(filter, Filter::Directory),
        });
        self.edit(|entries| {
            entries.push(Entry {
                id,
                subscriber: Arc::clone(&subscriber),
                filter,
            });
        });
        Listener {
            id,
            subscriber,
            router: Arc::clone(self),
        }
    }

    /// How many listen now.
    pub fn listening(&self) -> usize {
        self.index.read().map_or(0, |index| index.entries.len())
    }

    fn edit(&self, change: impl FnOnce(&mut Vec<Entry>)) {
        let Ok(mut index) = self.index.write() else {
            return;
        };
        let mut entries = std::mem::take(&mut index.entries);
        change(&mut entries);
        *index = Index::build(entries);
    }
}

/// One subscriber's end of the fan-out: removed from the router when dropped.
pub struct Listener {
    id: u64,
    subscriber: Arc<Subscriber>,
    router: Arc<Router>,
}

impl Listener {
    /// From now on it is offered what `filter` takes.
    pub fn set(&self, filter: Filter) {
        let id = self.id;
        self.router.edit(|entries| {
            if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
                entry.filter = filter;
            }
        });
    }

    /// Waits for at least one item, then moves up to `most` into `out`; or says it fell.
    pub async fn recv_many(&self, out: &mut Vec<Item>, most: usize) -> Result<(), Fell> {
        loop {
            if self.try_recv_many(out, most)? > 0 {
                return Ok(());
            }
            // `notify_one` keeps a permit when nobody waits, so an offer between the check and
            // here is not missed.
            self.subscriber.notify.notified().await;
        }
    }

    /// Moves up to `most` items into `out` without waiting: how many.
    pub fn try_recv_many(&self, out: &mut Vec<Item>, most: usize) -> Result<usize, Fell> {
        let Ok(mut state) = self.subscriber.queue.lock() else {
            return Err(Fell::Behind(FellBehind::Bytes));
        };
        match state.fell {
            Some(Fell::Behind(why)) => return Err(Fell::Behind(why)),
            Some(Fell::Resync) => {
                state.fell = None;
                return Err(Fell::Resync);
            }
            None => {}
        }
        let mut moved = 0;
        while moved < most {
            let Some((item, _charge)) = state.queue.pop() else {
                break;
            };
            out.push(item);
            moved += 1;
        }
        Ok(moved)
    }

    /// The next item, if one waits: for tests.
    #[cfg(test)]
    pub fn try_recv(&self) -> Option<Item> {
        let mut one = Vec::with_capacity(1);
        self.try_recv_many(&mut one, 1).ok()?;
        one.pop()
    }

    /// Bytes waiting.
    pub fn queued_bytes(&self) -> usize {
        self.subscriber
            .queue
            .lock()
            .map_or(0, |state| state.queue.bytes())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let id = self.id;
        self.router
            .edit(|entries| entries.retain(|entry| entry.id != id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::{Location, Streams};

    #[test]
    fn a_queue_is_bounded_in_bytes_and_in_time() {
        let mut queue = Queue::new(Bounds {
            max_bytes: 100,
            max_age_ms: BEHIND_MS,
        });
        assert_eq!(queue.push(1, 60, 0), Ok(()));
        assert_eq!(queue.push(2, 60, 10), Err(FellBehind::Bytes));
        assert_eq!(queue.push(3, 10, BEHIND_MS + 1), Err(FellBehind::Age));
        assert_eq!(queue.push(4, 10, BEHIND_MS), Ok(()));
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.bytes(), 10);
        assert_eq!(queue.pop(), Some(4));
        assert!(queue.is_empty());
    }

    fn item(source: u64, cell: Option<Region>, stamp_ms: u64) -> Item {
        Item {
            source,
            record: Arc::new(Record::Heartbeat),
            cell,
            points: None,
            decoded: None,
            stamp_ms,
        }
    }

    fn info_item(cell: Option<Region>, stamp_ms: u64) -> Result<Item, String> {
        let identity = tally_wire::Identity::from_seed([5; 32]);
        let info = tally_wire::ReceiverInfo::sign(
            &identity,
            &tally_wire::batch::ReceiverInfoContent {
                issued_ms: 1,
                location: None,
                clock: tally_wire::Clock::Dump1090,
                software: "test".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        Ok(Item {
            record: Arc::new(Record::ReceiverInfo(info)),
            ..item(1, cell, stamp_ms)
        })
    }

    fn cell(lat: f64, lon: f64, resolution: u8) -> Result<Region, String> {
        Region::containing(
            &Location {
                lat_e7: (lat * 1e7) as i32,
                lon_e7: (lon * 1e7) as i32,
                alt_m: 0,
                precision_m: 0,
            },
            resolution,
        )
        .map_err(|error| error.to_string())
    }

    #[tokio::test]
    async fn a_record_reaches_the_subscribers_of_its_cell_and_the_whole_world_only()
    -> Result<(), String> {
        let router = Arc::new(Router::new(Bounds {
            max_bytes: 1 << 20,
            max_age_ms: BEHIND_MS,
        }));
        let atlanta = cell(33.749, -84.388, 15)?;
        let paris = cell(48.857, 2.352, 15)?;
        let raw = |regions| {
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions,
            })
        };
        let world = router.listen(10, raw(Vec::new()));
        let south = router.listen(11, raw(vec![atlanta.ancestor(3).ok_or("no ancestor")?]));
        let france = router.listen(12, raw(vec![paris.ancestor(5).ok_or("no ancestor")?]));
        router.publish(info_item(Some(atlanta), 0)?);
        router.publish(info_item(None, 0)?);
        let mut out = Vec::new();
        assert_eq!(world.try_recv_many(&mut out, 10), Ok(2));
        out.clear();
        assert_eq!(south.try_recv_many(&mut out, 10), Ok(1));
        assert_eq!(out[0].cell, Some(atlanta));
        assert_eq!(france.try_recv_many(&mut out, 10), Ok(0));
        // Never back down the connection it came in on.
        let own = router.listen(1, raw(Vec::new()));
        router.publish(info_item(Some(atlanta), 0)?);
        assert_eq!(own.try_recv_many(&mut out, 10), Ok(0));
        assert_eq!(router.listening(), 4);
        drop(own);
        assert_eq!(router.listening(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn a_subscriber_past_its_bounds_is_let_go_and_a_directory_link_resynchronised()
    -> Result<(), String> {
        let router = Arc::new(Router::new(Bounds {
            max_bytes: 1 << 20,
            max_age_ms: BEHIND_MS,
        }));
        let slow = router.listen(
            10,
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: Vec::new(),
            }),
        );
        let directory = router.listen(11, Filter::Directory);
        router.publish(info_item(None, 0)?);
        router.publish(info_item(None, BEHIND_MS + 1)?);
        let mut out = Vec::new();
        assert_eq!(
            slow.try_recv_many(&mut out, 10),
            Err(Fell::Behind(FellBehind::Age))
        );
        // Once let go it stays let go, and nothing more is queued for it.
        router.publish(info_item(None, BEHIND_MS + 2)?);
        assert_eq!(slow.queued_bytes(), 0);
        assert_eq!(directory.try_recv_many(&mut out, 10), Ok(0));
        Ok(())
    }
}
