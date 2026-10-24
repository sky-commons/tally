//! Fan-out to subscribers (RFC-0181 §8). A [`Router`] keyed by subscription cell feeds one queue
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
//! queues hold it, for what the fan-out allocates itself (the item and a slot in each queue that
//! takes it, [`item_charge`]; a batch's decode and signed bytes are charged once, for their life,
//! by their own allocations, `budget::Store::Decoded`, and no queue charges them again), and
//! released when the last lets it go: a link takes it with its charge
//! ([`Taken`]) and holds both while it gathers and sends it, so what waits for a slow socket is
//! charged until the send returns. What a subscriber holds is what its queue holds and what its
//! link took and has not yet sent (its items in hand, [`Hold`]), both: its bounds count both, and
//! when an item would pass the budget, the subscriber holding the most of both is let go as fallen
//! behind, and the next, until it fits. Letting a subscriber go lets go of its charges at once,
//! those its link holds in hand among them ([`Hold`] is only a claim on a charge the subscriber
//! keeps; an item still held whole keeps a claim of its own until it is dropped, [`Taken`]), so
//! the room the budget counted on is free before the next is ranked: before, only its
//! queue was cleared and its link let go of what it held in hand when it next woke, so a stalled
//! socket holding its items in hand with an empty queue freed nothing, and an honest subscriber
//! was let go in its place. A link let go stops its send at once ([`Listener::fallen`]), and no
//! subscriber's send of taken items outlives [`BEHIND_MS`] (`link`). The queues together never hold more than their
//! share of the relay's memory, and no subscriber ever misses an item without being told. Before,
//! the subscribers were ranked by their queues alone: a socket that stalled with items taken held
//! their charges for up to `noise::WRITE_TIMEOUT` (30 s) with an empty queue, never ranked, and
//! honest subscribers were let go in its place.
//!
//! Routing reads a subscription's regions once, when it changes ([`Router::set`]): a record placed
//! at a cell is offered to the whole-world subscribers and to the subscribers of that cell's
//! ancestors at the resolutions anyone subscribed at, a few hash lookups whatever the number of
//! subscribers; every offer is then the subscription's own rule (`Subscription::wants`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tally_wire::{Record, Region};
use tokio::sync::Notify;

use crate::budget::{Charge, Gauge, Store};
use crate::footprint::Deque;

use crate::hub::Item;
use crate::subscription::{ClientPlace, ClientSubscription, Subscription, directory_wants};

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

/// One subscriber's queue of `T`, each with its size in bytes and its ingest stamp: a [`Deque`],
/// so what it allocates is bounded by what it holds ([`Queue::allocated`]) and given back as it
/// empties.
#[derive(Debug)]
pub struct Queue<T> {
    bounds: Bounds,
    items: Deque<(T, usize, u64)>,
    bytes: usize,
}

impl<T> Queue<T> {
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            items: Deque::new(),
            bytes: 0,
        }
    }

    /// Queues `item` of `bytes` stamped `stamp_ms`, or says the subscriber fell behind (the item
    /// is not queued, and the subscriber is to be disconnected).
    pub fn push(&mut self, item: T, bytes: usize, stamp_ms: u64) -> Result<(), FellBehind> {
        self.push_beside(item, bytes, stamp_ms, 0)
    }

    /// As `push`, its subscriber holding `beside` bytes besides the queue (taken, not yet sent):
    /// the byte bound is on both.
    pub fn push_beside(
        &mut self,
        item: T,
        bytes: usize,
        stamp_ms: u64,
        beside: usize,
    ) -> Result<(), FellBehind> {
        if self.bytes.saturating_add(beside).saturating_add(bytes) > self.bounds.max_bytes {
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
        self.pop_sized().map(|(item, _)| item)
    }

    /// The oldest item, and what it was counted.
    fn pop_sized(&mut self) -> Option<(T, usize)> {
        let (item, bytes, _) = self.items.pop_front()?;
        self.bytes -= bytes;
        Some((item, bytes))
    }

    /// Lets everything queued go.
    pub fn clear(&mut self) {
        self.items.clear();
        self.bytes = 0;
    }

    /// What its slots allocate now (not what the items keep alive, [`Queue::bytes`]).
    pub fn allocated(&self) -> usize {
        self.items.bytes()
    }

    /// What one more item's slot allocates more ([`Deque::growth`]).
    pub fn growth(&self) -> usize {
        self.items.growth()
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
    /// An engine: its subscription, by its receivers' sites (`Subscription::wants`).
    Subscription(Subscription),
    /// A client: its subscription, routing an item's client form by its client place and nothing
    /// else (`ClientSubscription::serves`, `Item::client`).
    Client(ClientSubscription),
    /// A loopback output (`--beast-out`, `--acars-out`, `link::LocalOutput`): every receiver's
    /// batch this build reads.
    Local,
    /// Every record: what a test of the hub reads.
    #[cfg(test)]
    Everything,
}

impl Filter {
    pub fn wants(&self, item: &Item) -> bool {
        match self {
            Self::Directory => directory_wants(item),
            Self::Subscription(subscription) => subscription.wants(item),
            Self::Client(subscription) => item
                .client
                .as_ref()
                .is_some_and(|client| subscription.serves(client)),
            Self::Local => item.decoded.is_some(),
            #[cfg(test)]
            Self::Everything => true,
        }
    }

    /// The regions it is keyed by in the router: none for whole-world (and for what is not a
    /// subscription).
    fn regions(&self) -> &[Region] {
        match self {
            Self::Subscription(subscription) => &subscription.regions,
            Self::Client(subscription) => subscription.regions(),
            Self::Directory | Self::Local => &[],
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

/// What an item keeps alive while a queue holds it, by which a subscriber is bounded and ranked
/// ([`Bounds::max_bytes`], the laggard let go first): a batch's decode and its signed bytes
/// (`Decoded::footprint`, `Batch::footprint`), or the record's encoded bytes. Not what the queue is
/// charged: those are charged once, by their own allocations (`budget::Store::Decoded`), for as
/// long as anything holds them ([`item_charge`]).
pub fn item_bytes(item: &Item) -> usize {
    match (&item.decoded, &*item.record) {
        (Some(decoded), Record::Batch(batch)) => decoded.footprint() + batch.footprint(),
        (Some(decoded), _) => decoded.footprint(),
        (None, record) => record.encoded_len(),
    }
}

/// What one item allocates once, whatever takes it: itself in the one `Arc` every queue holding it
/// shares, its record's `Arc`, and the `Arc` of the one charge they share.
pub const ITEM_BYTES: usize = crate::footprint::arc::<Item>()
    + crate::footprint::arc::<Record>()
    + crate::footprint::arc::<Charge>();

/// One queue's slot for an item: its claim on the item and on the charge, its bytes and its stamp.
type Slot = (Queued, usize, u64);

/// The charges a link holds in hand, by its hold, in the order it took them ([`InHand`]).
type Held = Deque<(u64, Arc<Charge>, usize)>;

/// What a subscriber's queue and its link's hand allocate for each item they hold, at most, as
/// planned: its slot in a queue, or its place among the charges in hand, each in a deque that
/// keeps a quarter again what it holds ([`Deque`]), whichever is more, since an item is in one or
/// the other and the two are held to one bound together (`Bounds`).
pub const SLOT_BYTES: usize = max(
    crate::footprint::vec::<Slot>(1) * 5 / 4,
    crate::footprint::vec::<(u64, Arc<Charge>, usize)>(1) * 5 / 4,
);

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// What a subscriber's queue and its link's hand allocate at most whatever they hold, as planned:
/// the slots a queue and its hand may each keep beyond a quarter again what they hold
/// (`Deque::LEAST`).
pub const LISTENER_BYTES: usize = Deque::<Slot>::bytes_at_most(0) + Held::bytes_at_most(0);

/// What the fan-out charges for an item, once, however many queues take it
/// (`budget::Store::Fanout`): what it allocates itself ([`ITEM_BYTES`]), and a record's bytes where
/// no allocation of their own carries their charge (any record but a batch kept at ingest, whose
/// signed bytes and decode are charged once for their life, whoever holds them,
/// `budget::Store::Decoded`). Each queue's slots are charged by the queue, as they are allocated
/// ([`Queue::allocated`], `State::settle`). Before, every item was charged its decode's footprint
/// here as well as in the epochs, the notes and the orphans; then a slot of an assumed size in each
/// queue, which a queue's spare capacity passed and never gave back.
pub fn item_charge(item: &Item) -> usize {
    // What the record allocates of its own (`Record::allocated`: nothing for a batch kept at
    // ingest), the aircraft's cells it is routed by, and a client form: its own record and item,
    // each in an `Arc` (its place's cells are the item's, shared).
    let record = item.record.allocated();
    let points = item.points.as_ref().map_or(0, |points| {
        tally_wire::decoded::ARC_HEADER + std::mem::size_of_val(&**points)
    });
    let client = item.client.as_ref().map_or(0, |client| {
        client.record.allocated()
            + crate::footprint::arc::<tally_wire::ClientRecord>()
            + crate::footprint::arc::<crate::subscription::ClientItem>()
    });
    ITEM_BYTES
        .saturating_add(record)
        .saturating_add(points)
        .saturating_add(client)
}

/// An item as a queue holds it: with the one charge every queue holding it shares.
/// A queue's claim on an item, shared by every queue that holds it, and on its charge.
type Queued = (Arc<Item>, Arc<Charge>);

/// An item a link took from its queue, with the charge every holder of it shares and its place
/// among what its subscriber holds in hand: held for as long as the link holds the item
/// (gathering it, sending it), released with the last holder.
///
/// It holds a claim of its own on the charge beside its subscriber's (`charge`), declared after
/// the item, so the item's own allocation goes before that claim (Rust drops a struct's fields in
/// order): a subscriber let go releases what it holds in hand at once ([`Hold`]), but the charge of
/// an item a link still holds in a `Taken` stays until the `Taken` is dropped. A link that keeps an
/// item past taking it keeps only its [`Hold`] (`Taken::hold`). The decode the item keeps alive is
/// charged by itself, whoever holds it.
#[derive(Debug)]
pub struct Taken {
    item: Arc<Item>,
    charge: Arc<Charge>,
    hold: Hold,
}

/// What a link keeps of an item it took while it sends it: its claim on the item's charge (shared
/// by every holder), which its subscriber keeps among what it holds in hand ([`InHand`]) and which
/// ranks and bounds the subscriber as its queue's bytes do. Let go once the item is sent, or by
/// the subscriber at once when it is let go.
#[derive(Debug)]
pub struct Hold {
    subscriber: Arc<Subscriber>,
    id: u64,
}

impl Drop for Hold {
    fn drop(&mut self) {
        // Taken out under the lock, dropped after it: a charge released wakes its gauge's waiters.
        let released = self.subscriber.queue.lock().ok().and_then(|mut state| {
            let released = state.in_hand.release(self.id);
            state.settle();
            released
        });
        drop(released);
    }
}

/// What one subscriber's link holds in hand: each item's charge it took, by its hold, and their
/// bytes together.
#[derive(Debug, Default)]
struct InHand {
    next: u64,
    held: Held,
    bytes: usize,
}

impl InHand {
    /// What it allocates now.
    fn allocated(&self) -> usize {
        self.held.bytes()
    }

    fn take(&mut self, charge: Arc<Charge>, bytes: usize) -> u64 {
        let id = self.next;
        self.next += 1;
        // Taken in order, so the hand is ordered by hold.
        self.held.push_back((id, charge, bytes));
        self.bytes += bytes;
        id
    }

    fn release(&mut self, id: u64) -> Option<Arc<Charge>> {
        let at = self
            .held
            .binary_search_by_key(&id, |(held, _, _)| *held)
            .ok()?;
        let (_, charge, bytes) = self.held.remove(at)?;
        self.bytes -= bytes;
        Some(charge)
    }

    /// Every charge held, taken out to be let go.
    fn release_all(&mut self) -> Held {
        self.bytes = 0;
        std::mem::take(&mut self.held)
    }
}

impl Taken {
    pub fn item(&self) -> &Item {
        &self.item
    }

    /// What to hold beside what the link keeps of the item (its record, never its decode), until
    /// it is sent: the item and this claim on its charge go now, the item first.
    pub fn hold(self) -> Hold {
        let Self { item, charge, hold } = self;
        drop(item);
        drop(charge);
        hold
    }

    /// The item, its charge let go: for a test that reads what it was sent.
    pub fn into_item(self) -> Item {
        Arc::unwrap_or_clone(self.item)
    }
}

impl std::ops::Deref for Taken {
    type Target = Item;

    fn deref(&self) -> &Item {
        &self.item
    }
}

#[derive(Debug)]
struct Subscriber {
    /// The connection it is, so nothing is sent back down the connection it came in on.
    source: u64,
    queue: Mutex<State>,
    notify: Notify,
    /// A directory link: on overflow, resynchronised, never let go.
    resyncs: bool,
}

#[derive(Debug)]
struct State {
    queue: Queue<Queued>,
    fell: Option<Fell>,
    /// What its link took and has not yet sent ([`Hold`]).
    in_hand: InHand,
    /// What its queue's slots and its hand allocate, charged to the fan-out's store
    /// (`budget::Store::Fanout`) before they grow, and brought down to it as they shrink.
    slots: Charge,
}

impl State {
    /// What its queue's slots and its hand allocate now.
    fn allocated(&self) -> usize {
        self.queue.allocated() + self.in_hand.allocated()
    }

    /// Its charge brought down to what it allocates now.
    fn settle(&mut self) {
        let allocated = self.allocated();
        self.slots.shrink_to(allocated);
        debug_assert_eq!(self.slots.bytes(), allocated);
    }

    /// Fallen (behind, or to be resynchronised): what it holds, queued and in hand, is no use to
    /// it now, and is let go at once, returned to be dropped outside the lock.
    fn fall(&mut self, fell: Fell) -> (Queue<Queued>, Held) {
        self.fell = Some(fell);
        let bounds = self.queue.bounds;
        let fallen = (
            std::mem::replace(&mut self.queue, Queue::new(bounds)),
            self.in_hand.release_all(),
        );
        self.settle();
        fallen
    }
}

impl Subscriber {
    /// How it falls for `why`: a directory link is resynchronised, never let go; any other is
    /// let go. The one place that says so, so no path lets a directory link go.
    fn fell(&self, why: FellBehind) -> Fell {
        if self.resyncs {
            Fell::Resync
        } else {
            Fell::Behind(why)
        }
    }

    /// Offers `item`, its slot's growth paid from `reserved` (what `Router::publish` charged for
    /// it with the item, so no publisher meanwhile takes the room it found), any shortfall
    /// charged now and any surplus given back; the store full, it falls behind. A test's: the
    /// publisher offers through `try_offer`, which hands a shortfall back (`Router::deliver`).
    #[cfg(test)]
    fn offer(&self, item: &Arc<Item>, charge: &Arc<Charge>, bytes: usize, reserved: Charge) {
        let _ = self.try_offer(item, charge, bytes, reserved, true);
    }

    /// As `offer`, but when the store has no room for what its slot must grow by (the queue's
    /// growth read here, under its lock, where no other publisher can move it) and `fall` is
    /// false: nothing is queued, and the shortfall is handed back with `reserved`, for the
    /// publisher to make room for and offer again (`Router::publish`). Before, the growth was
    /// read outside the lock, and a publisher between that read and the push left an honest
    /// taker short of its slot, let go while the laggard kept what it held.
    fn try_offer(
        &self,
        item: &Arc<Item>,
        charge: &Arc<Charge>,
        bytes: usize,
        mut reserved: Charge,
        fall: bool,
    ) -> Option<(usize, Charge)> {
        let Ok(mut state) = self.queue.lock() else {
            return None;
        };
        if matches!(state.fell, Some(Fell::Behind(_))) {
            return None;
        }
        let in_hand = state.in_hand.bytes;
        let mut fallen = None;
        // Its slot is charged before the queue grows for it: the store full, it falls behind as
        // a queue past its bounds does.
        let growth = state.queue.growth();
        let short = growth.saturating_sub(reserved.bytes());
        if short > 0 && !fall && !reserved.try_grow(short) {
            return Some((short, reserved));
        }
        let paid = if reserved.bytes() == 0 {
            state.slots.try_grow(growth)
        } else {
            (short == 0 || reserved.bytes() >= growth || reserved.try_grow(short))
                && state.slots.absorb(reserved).is_ok()
        };
        let pushed = if paid {
            state.queue.push_beside(
                (Arc::clone(item), Arc::clone(charge)),
                bytes,
                item.stamp.ms(),
                in_hand,
            )
        } else {
            Err(FellBehind::Bytes)
        };
        state.settle();
        if let Err(why) = pushed {
            // What it holds is no use to it now: let it go at once, not when it is read.
            fallen = Some(state.fall(self.fell(why)));
        }
        drop(state);
        drop(fallen);
        self.notify.notify_one();
        None
    }

    /// What its queue's slots and its hand allocate now, and what they are charged: for a test.
    #[cfg(test)]
    fn charged(&self) -> (usize, usize) {
        self.queue
            .lock()
            .map_or((0, 0), |state| (state.allocated(), state.slots.bytes()))
    }

    /// What its queue's slots must grow by to take one more item, while it still takes them:
    /// `None` once it fell behind.
    fn growth(&self) -> Option<usize> {
        let state = self.queue.lock().ok()?;
        (!matches!(state.fell, Some(Fell::Behind(_)))).then(|| state.queue.growth())
    }

    /// Bytes it holds now, queued and in hand, while it may still be let go: `None` once it was
    /// (it held nothing from then), so it is never let go twice.
    fn holding(&self) -> Option<usize> {
        let state = self.queue.lock().ok()?;
        state
            .fell
            .is_none()
            .then(|| state.queue.bytes() + state.in_hand.bytes)
    }

    /// Let go for the budget: told it fell behind (a directory link is resynchronised), and what
    /// it held, queued and in its link's hand, let go now, so the room is free before this
    /// returns.
    fn let_go(&self) {
        let fallen = self
            .queue
            .lock()
            .ok()
            .map(|mut state| state.fall(self.fell(FellBehind::Bytes)));
        drop(fallen);
        self.notify.notify_one();
    }
}

struct Entry {
    id: u64,
    subscriber: Arc<Subscriber>,
    filter: Filter,
}

/// One set of subscribers by how they are routed to: whole-world ones, and the rest by their
/// regions' cells.
#[derive(Default)]
struct Routes {
    /// Entries that take records from anywhere: no regions.
    everywhere: Vec<usize>,
    /// Entries with regions, by each region's cell number.
    by_cell: HashMap<u64, Vec<usize>>,
    /// Entries with regions, by each of their regions' ancestors' cell numbers: what a coarser
    /// cell overlaps (a client of a public cell is offered its area's records).
    by_ancestor: HashMap<u64, Vec<usize>>,
    /// Entries with regions, all of them: offered what is routed by no place.
    regional: Vec<usize>,
    /// The resolutions any region is at, ascending.
    resolutions: Vec<u8>,
}

impl Routes {
    fn add(&mut self, at: usize, regions: &[Region]) {
        if regions.is_empty() {
            self.everywhere.push(at);
            return;
        }
        self.regional.push(at);
        for region in regions {
            let keyed = self.by_cell.entry(region.as_u64()).or_default();
            if keyed.last() != Some(&at) {
                keyed.push(at);
            }
            for resolution in 0..region.resolution() {
                if let Some(ancestor) = region.ancestor(resolution) {
                    let keyed = self.by_ancestor.entry(ancestor.as_u64()).or_default();
                    if keyed.last() != Some(&at) {
                        keyed.push(at);
                    }
                }
            }
            self.resolutions.push(region.resolution());
        }
    }

    fn sort(&mut self) {
        self.resolutions.sort_unstable();
        self.resolutions.dedup();
    }

    /// The entries with regions that hold one of `cells` or lie inside one, each once, ascending.
    fn holding(&self, cells: &[Region], into: &mut Vec<usize>) {
        for cell in cells {
            for resolution in &self.resolutions {
                if let Some(ancestor) = cell.ancestor(*resolution)
                    && let Some(keyed) = self.by_cell.get(&ancestor.as_u64())
                {
                    into.extend_from_slice(keyed);
                }
            }
            if let Some(keyed) = self.by_ancestor.get(&cell.as_u64()) {
                into.extend_from_slice(keyed);
            }
        }
        into.sort_unstable();
        into.dedup();
    }

    /// The entries offered a record placed at `place`: every whole-world one, and those with
    /// regions by the place.
    fn offered(&self, place: Place<'_>, into: &mut Vec<usize>) {
        into.extend_from_slice(&self.everywhere);
        if self.regional.is_empty() {
            return;
        }
        match place {
            Place::Nowhere => into.extend_from_slice(&self.regional),
            Place::Cells(cells) if !cells.is_empty() => {
                let mut held = Vec::new();
                self.holding(cells, &mut held);
                into.extend(held);
            }
            Place::Cells(_) => {}
        }
    }
}

/// The subscribers, routed apart: relay-role ones (engines, directory links, the BEAST output) by
/// what the relay holds of an item (`place`), and clients by its client place alone
/// (`ClientItem`), so no client is ever offered a record by a receiver's site.
#[derive(Default)]
struct Index {
    entries: Vec<Entry>,
    relays: Routes,
    clients: Routes,
}

impl Index {
    fn build(entries: Vec<Entry>) -> Self {
        let mut index = Self {
            entries,
            ..Self::default()
        };
        for (at, entry) in index.entries.iter().enumerate() {
            let regions = entry.filter.regions();
            if matches!(entry.filter, Filter::Client(_)) {
                index.clients.add(at, regions);
            } else {
                index.relays.add(at, regions);
            }
        }
        index.relays.sort();
        index.clients.sort();
        index
    }

    /// Whether any entry is a client's (`Filter::Client`): an item is given its client form only
    /// then.
    fn has_clients(&self) -> bool {
        !self.clients.everywhere.is_empty() || !self.clients.regional.is_empty()
    }
}

/// Where a record is placed for routing: the cells it is placed at, or nowhere (offered to every
/// subscriber, each deciding by its streams alone).
#[derive(Clone, Copy)]
enum Place<'a> {
    Cells(&'a [Region]),
    Nowhere,
}

/// Where a relay-role subscriber is offered `item`: its receiver's site's finest cell or its
/// area's cell (`Item::cell`), the aircraft it places (`Item::points`), or nowhere.
fn place(item: &Item) -> Place<'_> {
    match &*item.record {
        Record::Batch(_)
        | Record::ReceiverInfo(_)
        | Record::ReceiverSite(_)
        | Record::RegionalBatch(_)
        | Record::ClientRegionalBatch(_)
        | Record::FeederFigures(_)
        | Record::BundleIndex(_) => match &item.cell {
            Some(cell) => Place::Cells(std::slice::from_ref(cell)),
            // Unplaced: whole-world subscribers only (`Subscription::covers`).
            None => Place::Cells(&[]),
        },
        Record::Positions(_)
        | Record::Provisional(_)
        | Record::ClockModel(_)
        | Record::ClientClockModel(_) => match &item.points {
            Some(points) => Place::Cells(points),
            None => Place::Nowhere,
        },
        _ => Place::Nowhere,
    }
}

/// Where a client is offered an item: by its client place, and nothing else.
fn client_place(place: &ClientPlace) -> Place<'_> {
    match place {
        ClientPlace::World => Place::Nowhere,
        ClientPlace::Unplaced => Place::Cells(&[]),
        ClientPlace::Cell(cell) => Place::Cells(std::slice::from_ref(cell.as_region())),
        ClientPlace::Aircraft(points) => Place::Cells(points),
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

    /// Lets go the subscriber that keeps the most alive (its queue and what its link holds in
    /// hand, by [`item_bytes`]), as fallen behind: what a store holding decodes does when it has
    /// no room for the next (`hub`, `budget::Store::Decoded`), as the fan-out's own gauge does for
    /// an item. A subscriber is the one holder of a decode that may let it go without loss to
    /// anyone else, and it is told. False when no subscriber holds anything.
    pub fn let_go_largest(&self) -> bool {
        let Ok(index) = self.index.read() else {
            return false;
        };
        let largest = index
            .entries
            .iter()
            .filter_map(|entry| Some((entry.subscriber.holding()?, &entry.subscriber)))
            .filter(|(held, _)| *held > 0)
            .max_by_key(|(held, _)| *held);
        match largest {
            Some((_, laggard)) => {
                laggard.let_go();
                true
            }
            None => false,
        }
    }

    /// Offers `item` to every subscriber that takes it. Never waits on a subscriber: one whose
    /// queue is past its bounds is let go.
    pub fn publish(&self, mut item: Item) {
        let Ok(index) = self.index.read() else {
            return;
        };
        if index.entries.is_empty() {
            return;
        }
        // Its client item, made once for every client that may take it: what a client link
        // sends, and all it can, with where it is routed (`outbound`, `ClientItem`).
        if index.has_clients() && item.client.is_none() {
            item.client = crate::outbound::client_item(&item);
        }
        // Who takes it: relay-role subscribers by its place, clients by its client place.
        let mut offered = Vec::new();
        index.relays.offered(place(&item), &mut offered);
        if let Some(client) = &item.client {
            index
                .clients
                .offered(client_place(client.place()), &mut offered);
        }
        let takers: Vec<usize> = offered
            .into_iter()
            .filter(|at| {
                let entry = &index.entries[*at];
                entry.subscriber.source != item.source && entry.filter.wants(&item)
            })
            .collect();
        if takers.is_empty() {
            return;
        }
        let bytes = item_bytes(&item);
        let charged = item_charge(&item);
        // Room in the budget, made by letting go whoever holds most, as many as it takes. Charged
        // once whatever holds it, before any queue holds it; released when the last queue lets it
        // go.
        // The room is the item's charge and every taker's slot for it together: a queue whose
        // slots must grow to hold it charges that growth when it is offered (`Subscriber::offer`),
        // and room made for the item alone left an honest taker to fall behind on its slot while
        // the laggard kept what it held.
        // Both are charged here together, the slots' growth handed to each taker with the item,
        // so the room found is the room used: before, only the item was charged, and a publisher
        // meanwhile took the slots' room, so an honest taker fell behind on its slot.
        let growths: Vec<usize> = takers
            .iter()
            .map(|at| index.entries[*at].subscriber.growth().unwrap_or(0))
            .collect();
        let need = charged.saturating_add(growths.iter().sum());
        let mut charge = None;
        for _ in 0..=index.entries.len() {
            if self.gauge.fits(need) {
                charge = self.gauge.try_charge(need);
            } else if self.gauge.held() == 0 {
                // An item whose takers' slots do not fit an empty store: the item alone, each
                // slot charged as it is offered (and its taker let go if it does not fit).
                charge = self.gauge.try_charge(charged);
            }
            if charge.is_some() {
                break;
            }
            let Some((_, laggard)) = index
                .entries
                .iter()
                .filter_map(|entry| Some((entry.subscriber.holding()?, &entry.subscriber)))
                .filter(|(held, _)| *held > 0)
                .max_by_key(|(held, _)| *held)
            else {
                break;
            };
            laggard.let_go();
        }
        // No room even with every queue let go (another publisher took it meanwhile): the item is
        // held by none, and those it was for fall behind, as a full queue does.
        let Some(mut reserved) = charge else {
            for at in takers {
                index.entries[at].subscriber.let_go();
            }
            return;
        };
        let charge = reserved.split(charged);
        let (item, charge) = (Arc::new(item), Arc::new(charge));
        let offering: Vec<(usize, Charge)> = takers
            .into_iter()
            .zip(growths)
            .map(|(at, growth)| (at, reserved.split(growth)))
            .collect();
        Self::deliver(&index, &item, &charge, bytes, offering);
    }

    /// Queues `item` to each taker (`offering`: its index, and the charge read for its slot).
    fn deliver(
        index: &Index,
        item: &Arc<Item>,
        charge: &Arc<Charge>,
        bytes: usize,
        mut offering: Vec<(usize, Charge)>,
    ) {
        // A taker whose slot must grow by more than was read for it (another publisher pushed
        // meanwhile) is handed back its shortfall: room is made for it as for the item, by letting
        // go whoever holds most, and it is offered again. The last round falls behind as a full
        // store does.
        for round in 0..=index.entries.len() {
            let fall = round == index.entries.len();
            let mut short = Vec::new();
            for (at, slot) in offering {
                if let Some((missing, slot)) = index.entries[at]
                    .subscriber
                    .try_offer(item, charge, bytes, slot, fall)
                {
                    short.push((at, missing, slot));
                }
            }
            if short.is_empty() {
                break;
            }
            offering = Vec::with_capacity(short.len());
            for (at, missing, mut slot) in short {
                while !slot.try_grow(missing) {
                    let Some((_, laggard)) = index
                        .entries
                        .iter()
                        .filter_map(|entry| Some((entry.subscriber.holding()?, &entry.subscriber)))
                        .filter(|(held, _)| *held > 0)
                        .max_by_key(|(held, _)| *held)
                    else {
                        break;
                    };
                    laggard.let_go();
                }
                offering.push((at, slot));
            }
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
                in_hand: InHand::default(),
                slots: self.gauge.empty(),
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

    /// Whether some client's subscription covers one of `cells` (a subscription of no regions
    /// covers every cell): what a client may be sent of a record placed there. What the positions
    /// checks hold a raw solution for (`Hub::hold_twins`).
    pub fn clients_at(&self, cells: &[Region]) -> bool {
        let Ok(index) = self.index.read() else {
            return true;
        };
        if !index.clients.everywhere.is_empty() {
            return true;
        }
        let mut holding = Vec::new();
        index.clients.holding(cells, &mut holding);
        !holding.is_empty()
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

    /// Waits for at least one item, then moves up to `most` into `out`, each with its charge; or
    /// says it fell.
    pub async fn recv_many(&self, out: &mut Vec<Taken>, most: usize) -> Result<(), Fell> {
        loop {
            if self.try_recv_many(out, most)? > 0 {
                return Ok(());
            }
            // `notify_one` keeps a permit when nobody waits, so an offer between the check and
            // here is not missed.
            self.subscriber.notify.notified().await;
        }
    }

    /// Moves up to `most` items into `out`, each with its charge, without waiting: how many.
    pub fn try_recv_many(&self, out: &mut Vec<Taken>, most: usize) -> Result<usize, Fell> {
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
        while moved < most && !state.queue.is_empty() {
            // Its place in hand is charged before it is taken: the store full, what was taken goes
            // out, and a link that can take nothing falls behind.
            let growth = state.in_hand.held.growth();
            if !state.slots.try_grow(growth) {
                // No room for its place in hand: room is made as it is for an item, by letting go
                // whoever holds most (another subscriber, or this one if it holds most), outside
                // this lock, since letting go reads every subscriber's. Then it tries once more.
                drop(state);
                self.router.let_go_largest();
                state = match self.subscriber.queue.lock() {
                    Ok(state) => state,
                    Err(_) => return Err(Fell::Behind(FellBehind::Bytes)),
                };
                match state.fell {
                    Some(Fell::Behind(why)) => return Err(Fell::Behind(why)),
                    // Let go to make the room itself, a directory link: what it held is gone, so
                    // it is told to resynchronise now, as it would be on its next take.
                    Some(Fell::Resync) => {
                        state.fell = None;
                        return Err(Fell::Resync);
                    }
                    None => {}
                }
                let growth = state.in_hand.held.growth();
                if state.slots.try_grow(growth) {
                    // Charged now: taken below.
                } else if moved == 0 {
                    // No room for even one: it falls as a full store makes it fall, a directory
                    // link resynchronised, never let go.
                    let fell = self.subscriber.fell(FellBehind::Bytes);
                    let fallen = state.fall(fell);
                    if fell == Fell::Resync {
                        state.fell = None;
                    }
                    drop(state);
                    drop(fallen);
                    return Err(fell);
                } else {
                    break;
                }
            }
            let Some(((item, charge), bytes)) = state.queue.pop_sized() else {
                break;
            };
            // In hand from here until the link lets it go (or the subscriber is let go), counted
            // before it leaves the queue's lock, so the subscriber's bytes are never seen short.
            let id = state.in_hand.take(Arc::clone(&charge), bytes);
            out.push(Taken {
                item,
                charge,
                hold: Hold {
                    subscriber: Arc::clone(&self.subscriber),
                    id,
                },
            });
            moved += 1;
        }
        state.settle();
        Ok(moved)
    }

    /// Resolves once this subscriber is let go as fallen behind (never for a directory link's
    /// resync): what a link sending items it took waits on beside the send, so it stops at once
    /// and what it holds in hand goes with it.
    pub async fn fallen(&self) {
        loop {
            let notified = self.subscriber.notify.notified();
            let fell = self
                .subscriber
                .queue
                .lock()
                .map_or(true, |state| matches!(state.fell, Some(Fell::Behind(_))));
            if fell {
                return;
            }
            notified.await;
        }
    }

    /// Whether the fan-out resynchronises this listener rather than letting it go (a directory
    /// link, [`Fell::Resync`]): such a link is never let go as fallen behind, so its sends are held
    /// to no in-hand deadline (`link`).
    pub fn resyncs(&self) -> bool {
        self.subscriber.resyncs
    }

    /// Bytes its link holds in hand: taken, not yet let go.
    pub fn in_hand(&self) -> usize {
        self.subscriber
            .queue
            .lock()
            .map_or(0, |state| state.in_hand.bytes)
    }

    /// The next item, if one waits: for tests.
    #[cfg(test)]
    pub fn try_recv(&self) -> Option<Item> {
        let mut one = Vec::with_capacity(1);
        self.try_recv_many(&mut one, 1).ok()?;
        one.pop().map(Taken::into_item)
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
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
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
            stamp: tally_wire::clocks::recorded::mono(stamp_ms),
            client: None,
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

    /// A client is routed by its client place alone, never by what the relay holds of a record:
    /// a receiver whose site's cell (`Item::cell`) lies in one area and whose public cell lies in
    /// another reaches the clients of its public cell's area and none of its site's, while an
    /// engine is routed by its site. A client clock model is routed by its area, so a client of a
    /// public cell inside that area is sent it and one of the next area is not.
    #[test]
    fn a_client_is_routed_by_its_client_place_and_never_by_a_site() -> Result<(), String> {
        use crate::subscription::{ClientItem, ClientPlace, Coarse};
        let text = |error: tally_wire::WireError| error.to_string();
        let router = Arc::new(Router::new(Bounds {
            max_bytes: 1 << 20,
            max_age_ms: BEHIND_MS,
        }));
        let atlanta = cell(33.749, -84.388, 6)?;
        let paris_site = cell(48.857, 2.352, 15)?;
        let atlanta_area = atlanta.ancestor(3).ok_or("no ancestor")?;
        let paris_area = paris_site.ancestor(3).ok_or("no ancestor")?;
        let client =
            |streams, regions| Filter::Client(Subscription { streams, regions }.for_client());
        let near = router.listen(10, client(Streams::RAW, vec![atlanta_area]));
        let at_site = router.listen(11, client(Streams::RAW, vec![paris_area]));
        let engine = router.listen(
            12,
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: vec![paris_area],
            }),
        );
        let info = tally_wire::ReceiverInfo::sign_public(
            &tally_wire::Identity::from_seed([6; 32]),
            &tally_wire::batch::PublicInfoContent {
                issued_ms: 1,
                cell: Some(atlanta),
                clock: tally_wire::Clock::Dump1090,
                software: String::new(),
                relays: Vec::new(),
            },
        )
        .map_err(text)?;
        router.publish(Item {
            record: Arc::new(Record::ReceiverInfo(info)),
            ..item(1, Some(paris_site), 0)
        });
        let mut out = Vec::new();
        assert_eq!(near.try_recv_many(&mut out, 10), Ok(1));
        assert_eq!(
            out[0].client.as_deref().map(ClientItem::place),
            Some(&ClientPlace::Cell(Coarse::of(atlanta)))
        );
        out.clear();
        assert_eq!(at_site.try_recv_many(&mut out, 10), Ok(0));
        assert_eq!(engine.try_recv_many(&mut out, 10), Ok(1));
        out.clear();
        // A client clock model: placed by its area, however fine the point it was published at.
        let model = tally_wire::ClientClockModel::sign(
            &tally_wire::Identity::from_seed([7; 32]),
            &tally_wire::ClientClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1,
                spec_version: 6,
                model: [1; 32],
                inputs: [2; 32],
                window_first: 0,
                window_last: 0,
            },
        )
        .map_err(text)?;
        let models = |regions| client(Streams::CLOCK_MODELS, regions);
        let inside = router.listen(20, models(vec![atlanta]));
        let next = router.listen(21, models(vec![paris_area]));
        let fine = cell(33.749, -84.388, 15)?;
        router.publish(Item {
            record: Arc::new(Record::ClientClockModel(model)),
            points: Some(Arc::from([fine].as_slice())),
            ..item(1, None, 0)
        });
        assert_eq!(inside.try_recv_many(&mut out, 10), Ok(1));
        assert_eq!(
            out[0].client.as_deref().map(ClientItem::place),
            Some(&ClientPlace::Cell(Coarse::of(atlanta_area)))
        );
        assert_eq!(next.try_recv_many(&mut out, 10), Ok(0));
        Ok(())
    }

    /// RFC-0181, "Memory is charged once, for its life": the fan-out is charged what it allocates
    /// for an item, the item once and a slot in each queue that takes it, and a record's bytes
    /// only where no allocation of their own carries their charge: a batch kept at ingest, whose
    /// signed bytes are owned and charged for their life, costs its queues their slots and no
    /// more, however large it is.
    #[test]
    fn an_item_is_charged_once_and_never_an_owned_batchs_bytes() -> Result<(), String> {
        let identity = tally_wire::Identity::from_seed([3; 32]);
        let batch = crate::anchors::anchored(
            &identity,
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence: 1,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: vec![tally_wire::Observation {
                    format: b'U',
                    timestamp: 1,
                    signal: 0,
                    data: vec![7; 432],
                }],
            },
        )
        .map_err(|error| error.to_string())?;
        let item = |batch: tally_wire::Batch| Item {
            source: 1,
            record: Arc::new(Record::Batch(batch)),
            cell: None,
            points: None,
            decoded: None,
            stamp: tally_wire::clocks::recorded::mono(0),
            client: None,
        };
        let plain = item(batch.clone());
        assert_eq!(item_charge(&plain), ITEM_BYTES + plain.record.allocated());
        let owned = batch
            .owned_by(|_| Some(Box::new(()) as tally_wire::decoded::Owner))
            .map_err(|_| "owned".to_owned())?;
        let owned = item(owned);
        assert_eq!(item_charge(&owned), ITEM_BYTES);
        // What it keeps alive, by which its subscriber is bounded, is still its bytes.
        assert_eq!(item_bytes(&owned), owned.record.encoded_len());
        Ok(())
    }

    /// An item published to many queues is allocated once, shared by every queue that takes it,
    /// and charged what it allocates: itself, its charge and each queue's slot. Before, each queue
    /// held a clone of the item, its fields copied into every slot.
    #[test]
    fn an_item_is_allocated_once_however_many_queues_take_it() -> Result<(), String> {
        use tally_counting::Counting;
        let gauge = Gauge::new(Store::Fanout, 1 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 1 << 20,
                max_age_ms: BEHIND_MS,
            },
            Arc::clone(&gauge),
        ));
        let listeners: Vec<Listener> = (10..14)
            .map(|source| {
                router.listen(
                    source,
                    Filter::Subscription(Subscription {
                        streams: Streams::RAW,
                        regions: Vec::new(),
                    }),
                )
            })
            .collect();
        let item = info_item(None, 0)?;
        // Made before what is counted: its record's `Arc` and what the record allocates.
        let made = crate::footprint::arc::<Record>() + item.record.allocated();
        let charged = item_charge(&item);
        let held = gauge.held();
        let base = Counting::live();
        router.publish(item);
        let allocated = Counting::since(base);
        assert_eq!(allocated + made as isize, (gauge.held() - held) as isize);
        // Each queue holds a slot of its own beside the one item.
        let slots: usize = listeners
            .iter()
            .map(|listener| listener.subscriber.charged().1)
            .sum();
        assert_eq!(gauge.held() - held - slots, charged);
        Ok(())
    }

    /// An item's cells it is routed by are charged what their `Arc` allocates, its counts with
    /// them. Before, only the cells were, and the counts went uncharged on every item.
    #[test]
    fn an_items_cells_are_charged_what_they_allocate() -> Result<(), String> {
        use tally_counting::Counting;
        let cells = (0..5)
            .map(|at| cell(33.0 + f64::from(at), -84.0, 15))
            .collect::<Result<Vec<_>, String>>()?;
        let plain = item(1, None, 0);
        let base = Counting::live();
        let points: Arc<[Region]> = Arc::from(cells.as_slice());
        let allocated = Counting::since(base);
        let routed = Item {
            points: Some(points),
            ..item(1, None, 0)
        };
        assert_eq!(
            (item_charge(&routed) - item_charge(&plain)) as isize,
            allocated
        );
        Ok(())
    }

    /// RFC-0181 §8: an item's charge is let go when the last holder lets it go, the link that
    /// took it among them, never when it leaves the queue.
    #[test]
    fn an_items_charge_is_held_until_its_link_lets_it_go() -> Result<(), String> {
        let gauge = Gauge::new(Store::Fanout, 1 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 1 << 20,
                max_age_ms: BEHIND_MS,
            },
            Arc::clone(&gauge),
        ));
        let world = router.listen(
            10,
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: Vec::new(),
            }),
        );
        let item = info_item(None, 0)?;
        let kept = item_bytes(&item);
        // The items' charges: the store less what the queue's slots and the hand are charged.
        let items = || gauge.held() - world.subscriber.charged().1;
        router.publish(item);
        let held = items();
        assert!(held > 0);
        let mut out = Vec::new();
        assert_eq!(world.try_recv_many(&mut out, 10), Ok(1));
        assert_eq!((world.queued_bytes(), items()), (0, held));
        // What a link keeps of it while it sends keeps its charge, and counts in its hand.
        let sending = out.pop().map(Taken::hold).ok_or("nothing taken")?;
        assert_eq!((items(), world.in_hand()), (held, kept));
        drop(sending);
        assert_eq!((items(), world.in_hand()), (0, 0));
        Ok(())
    }

    /// RFC-0181 §8: what a subscriber's link took and has not sent counts as what it holds, both
    /// for the budget's choice of whom to let go and for its own bound. A stalled link holding
    /// most of the store in hand, its queue nearly empty, is let go before an honest subscriber
    /// with a few items queued; ranked by queues alone, the honest one was let go and the stalled
    /// one kept its charges for the 30 s its send could wait.
    #[tokio::test]
    async fn a_link_holding_items_in_hand_is_let_go_before_an_honest_queue() -> Result<(), String> {
        // What a subscriber holds, and what the fan-out is charged for an item one queue takes.
        let unit = item_bytes(&info_item(None, 0)?);
        let charged = item_charge(&info_item(None, 0)?);
        let gauge = Gauge::new(Store::Fanout, 1 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 1 << 20,
                max_age_ms: BEHIND_MS,
            },
            Arc::clone(&gauge),
        ));
        let atlanta = cell(33.749, -84.388, 15)?;
        let paris = cell(48.857, 2.352, 15)?;
        let raw = |region: Region| {
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: vec![region],
            })
        };
        let stalled = router.listen(10, raw(atlanta));
        let honest = router.listen(11, raw(paris));
        for _ in 0..6 {
            router.publish(info_item(Some(atlanta), 0)?);
        }
        // The stalled link took all six and sends none of them: its queue is empty, everything it
        // holds is in its hand. It keeps five as a link keeps what it gathers, their claims alone
        // (`Taken::hold`, as `link`'s `Pending` does), and one still whole, item and all.
        let mut taken = Vec::new();
        assert_eq!(stalled.try_recv_many(&mut taken, 10), Ok(6));
        assert_eq!((stalled.in_hand(), stalled.queued_bytes()), (6 * unit, 0));
        let whole = taken.pop().ok_or("took none")?;
        let in_hand: Vec<Hold> = taken.into_iter().map(Taken::hold).collect();
        for _ in 0..2 {
            router.publish(info_item(Some(paris), 0)?);
        }
        // The items' charges: the store less what the queues' slots and the hands are charged,
        // and less what fills it.
        let slots = || stalled.subscriber.charged().1 + honest.subscriber.charged().1;
        assert_eq!(gauge.held() - slots(), 8 * charged);
        // The store filled to one item short of room for the next, with the honest queue's slot
        // for it already allocated.
        assert_eq!(
            honest
                .subscriber
                .queue
                .lock()
                .map_err(|_| "poisoned")?
                .queue
                .growth(),
            0
        );
        let fill = gauge.limit() - gauge.held() - (charged - 1);
        let filled = gauge.try_charge(fill).ok_or("no room to fill")?;
        let items = || gauge.held() - fill - slots();
        // One more for the honest subscriber does not fit: the stalled one holds the most, and
        // letting it go frees what it holds in hand at once, while its link still has the claims:
        // the honest one keeps all three. Before, only the stalled one's (empty) queue was
        // cleared, the store stayed full, and the honest one was let go next. The item its link
        // still holds whole stays charged until it is dropped, never a moment past it: its
        // `Taken` holds a claim of its own.
        router.publish(info_item(Some(paris), 0)?);
        assert_eq!((items(), stalled.in_hand()), (4 * charged, 0));
        drop(whole);
        assert_eq!(items(), 3 * charged);
        let mut out = Vec::new();
        assert_eq!(honest.try_recv_many(&mut out, 10), Ok(3));
        assert_eq!(
            stalled.try_recv_many(&mut out, 10),
            Err(Fell::Behind(FellBehind::Bytes))
        );
        // Its link is told at once, to stop the send it is stuck in; the honest one's is not.
        let told = |listener: &Listener| {
            let fallen = std::pin::pin!(listener.fallen());
            let waker = std::task::Waker::noop();
            fallen
                .poll(&mut std::task::Context::from_waker(waker))
                .is_ready()
        };
        assert!(told(&stalled));
        assert!(!told(&honest));
        // Its link letting go of the items later releases nothing twice.
        drop(in_hand);
        assert_eq!((stalled.in_hand(), items()), (0, 3 * charged));
        drop(filled);
        Ok(())
    }

    /// RFC-0181 §8: the room publishing makes for an item is the item's charge and its takers'
    /// slots together. An honest subscriber whose queue must grow its slots for the item, the
    /// store holding room for the item's charge alone, keeps the item and the laggard is let go.
    /// Before, room was made for the charge only, the honest queue's slot growth was refused, and
    /// the honest subscriber fell behind while the laggard kept everything it held.
    #[tokio::test]
    async fn an_honest_queue_whose_slots_must_grow_is_kept_before_a_laggard() -> Result<(), String>
    {
        let charged = item_charge(&info_item(None, 0)?);
        let gauge = Gauge::new(Store::Fanout, 1 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 1 << 20,
                max_age_ms: BEHIND_MS,
            },
            Arc::clone(&gauge),
        ));
        let atlanta = cell(33.749, -84.388, 15)?;
        let paris = cell(48.857, 2.352, 15)?;
        let raw = |region: Region| {
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: vec![region],
            })
        };
        let stalled = router.listen(10, raw(atlanta));
        let honest = router.listen(11, raw(paris));
        for _ in 0..6 {
            router.publish(info_item(Some(atlanta), 0)?);
        }
        // The honest queue is empty, so its slots must grow for the next item.
        assert!(honest.subscriber.growth().ok_or("fell")? > 0);
        // Room for exactly one item's charge, and none for its slot.
        let fill = gauge.limit() - gauge.held() - charged;
        let filled = gauge.try_charge(fill).ok_or("no room to fill")?;
        router.publish(info_item(Some(paris), 0)?);
        let mut out = Vec::new();
        assert_eq!(honest.try_recv_many(&mut out, 10), Ok(1));
        assert_eq!(
            stalled.try_recv_many(&mut out, 10),
            Err(Fell::Behind(FellBehind::Bytes))
        );
        drop((out, filled));
        Ok(())
    }

    /// The room `publish` finds for an item and its takers' slots is charged then, together, and
    /// each slot's share handed to its taker with the item: two publishers at once, the store
    /// holding a laggard's items and room for both items but one slot, each finds room, and the
    /// second to charge lets the laggard go, so neither honest taker falls. Before, only the item
    /// was charged, both found room, and the second honest taker fell behind on its slot while the
    /// laggard kept what it held. Two threads released together, many times, so the interleaving
    /// that loses comes.
    #[test]
    fn two_publishers_at_once_never_lose_an_honest_taker_to_the_others_slot() -> Result<(), String>
    {
        let charged = item_charge(&info_item(None, 0)?);
        let atlanta = cell(33.749, -84.388, 15)?;
        let paris = cell(48.857, 2.352, 15)?;
        let tokyo = cell(35.676, 139.650, 15)?;
        let raw = |region: Region| {
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: vec![region],
            })
        };
        for _ in 0..2_000 {
            let gauge = Gauge::new(Store::Fanout, 1 << 20);
            let router = Arc::new(Router::charged(
                Bounds {
                    max_bytes: 1 << 20,
                    max_age_ms: BEHIND_MS,
                },
                Arc::clone(&gauge),
            ));
            let stalled = router.listen(10, raw(atlanta));
            let first = router.listen(11, raw(paris));
            let second = router.listen(12, raw(tokyo));
            for _ in 0..8 {
                router.publish(info_item(Some(atlanta), 0)?);
            }
            let slot = first.subscriber.growth().ok_or("fell")?;
            assert_eq!(second.subscriber.growth(), Some(slot));
            // Room for both items and one slot: each publisher alone finds room.
            let fill = gauge.limit() - gauge.held() - (2 * charged + slot);
            let filled = gauge.try_charge(fill).ok_or("no room to fill")?;
            let start = std::sync::Barrier::new(2);
            let items = (info_item(Some(paris), 0)?, info_item(Some(tokyo), 0)?);
            std::thread::scope(|scope| {
                for item in [items.0, items.1] {
                    let (router, start) = (&router, &start);
                    scope.spawn(move || {
                        start.wait();
                        router.publish(item);
                    });
                }
            });
            let mut out = Vec::new();
            assert_eq!(first.try_recv_many(&mut out, 10), Ok(1));
            assert_eq!(second.try_recv_many(&mut out, 10), Ok(1));
            assert_eq!(
                stalled.try_recv_many(&mut out, 10),
                Err(Fell::Behind(FellBehind::Bytes))
            );
            drop((out, filled));
        }
        Ok(())
    }

    /// A directory link is resynchronised, never let go: also when the store has no room for its
    /// place in hand as it takes (`Listener::try_recv_many`), where it is let go to make the room
    /// and no other holds any. It is told to resynchronise, and takes what comes after. Before,
    /// it fell behind there and its link was dropped.
    #[tokio::test]
    async fn a_directory_link_with_no_room_to_take_is_resynchronised_never_let_go()
    -> Result<(), String> {
        let gauge = Gauge::new(Store::Fanout, 1 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 1 << 20,
                max_age_ms: BEHIND_MS,
            },
            Arc::clone(&gauge),
        ));
        let directory = router.listen(11, Filter::Directory);
        let relay = tally_wire::Identity::from_seed([9; 32]);
        let offer = |issued_ms: u64| -> Result<Item, String> {
            let offer = tally_wire::ProviderOffer::sign(
                &relay,
                &tally_wire::ProviderOfferContent {
                    address: "relay.example:10900".to_owned(),
                    cell: cell(48.857, 2.352, 4)?,
                    products: Streams::RAW,
                    stripes_of: 1,
                    stripes: 1,
                    mlat_cores: 1,
                    feeder_slots: 10,
                    network: 64_512,
                    issued_ms,
                    expires_ms: issued_ms + 600_000,
                },
            )
            .map_err(|error| error.to_string())?;
            Ok(Item {
                record: Arc::new(Record::ProviderOffer(offer)),
                ..item(1, None, 0)
            })
        };
        router.publish(offer(1)?);
        assert!(directory.queued_bytes() > 0);
        // The store full to the byte: its hand's first slot does not fit.
        let fill = gauge.limit() - gauge.held();
        let filled = gauge.try_charge(fill).ok_or("no room to fill")?;
        let mut out = Vec::new();
        assert_eq!(directory.try_recv_many(&mut out, 10), Err(Fell::Resync));
        drop(filled);
        router.publish(offer(2)?);
        assert_eq!(directory.try_recv_many(&mut out, 10), Ok(1));
        Ok(())
    }

    /// RFC-0181 §8: a subscriber's place in hand is charged before it takes an item, and when the
    /// store has no room for it, room is made as it is for an item, by letting go whoever holds
    /// most. An honest subscriber taking its queue, the store full of a laggard's items, takes
    /// them and the laggard is let go; before, the honest one fell behind.
    #[tokio::test]
    async fn an_honest_take_whose_hand_must_grow_is_kept_before_a_laggard() -> Result<(), String> {
        let gauge = Gauge::new(Store::Fanout, 1 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 1 << 20,
                max_age_ms: BEHIND_MS,
            },
            Arc::clone(&gauge),
        ));
        let atlanta = cell(33.749, -84.388, 15)?;
        let paris = cell(48.857, 2.352, 15)?;
        let raw = |region: Region| {
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: vec![region],
            })
        };
        let stalled = router.listen(10, raw(atlanta));
        let honest = router.listen(11, raw(paris));
        for _ in 0..6 {
            router.publish(info_item(Some(atlanta), 0)?);
        }
        router.publish(info_item(Some(paris), 0)?);
        // The store full to the byte: the honest hand's first slot does not fit.
        let fill = gauge.limit() - gauge.held();
        let filled = gauge.try_charge(fill).ok_or("no room to fill")?;
        let mut out = Vec::new();
        assert_eq!(honest.try_recv_many(&mut out, 10), Ok(1));
        assert_eq!(
            stalled.try_recv_many(&mut out, 10),
            Err(Fell::Behind(FellBehind::Bytes))
        );
        drop((out, filled));
        Ok(())
    }

    /// A subscriber's byte bound is on what it holds queued and in hand together: a link that
    /// takes items and does not send them fills its bound as its queue would.
    #[test]
    fn a_subscribers_bound_counts_what_its_link_holds_in_hand() -> Result<(), String> {
        let unit = item_bytes(&info_item(None, 0)?);
        let router = Arc::new(Router::new(Bounds {
            max_bytes: 3 * unit,
            max_age_ms: BEHIND_MS,
        }));
        let world = router.listen(
            10,
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: Vec::new(),
            }),
        );
        router.publish(info_item(None, 0)?);
        router.publish(info_item(None, 0)?);
        let mut in_hand = Vec::new();
        assert_eq!(world.try_recv_many(&mut in_hand, 10), Ok(2));
        router.publish(info_item(None, 0)?);
        router.publish(info_item(None, 0)?);
        let mut out = Vec::new();
        assert_eq!(
            world.try_recv_many(&mut out, 10),
            Err(Fell::Behind(FellBehind::Bytes))
        );
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

    /// A subscriber's queue and its link's hand are charged what they allocate, read from an
    /// allocator that counts this thread's every byte, as items come, are taken in bursts and are
    /// let go out of order; the queue gives its spare slots back as it empties, so a subscriber
    /// that once held many holds little once caught up; and at a store too small for the slots, it
    /// falls behind rather than holding slots uncharged. Before, each item was charged a slot of an
    /// assumed size in every queue, and a queue kept the capacity of its longest backlog, uncharged,
    /// for the rest of its session.
    #[test]
    fn a_subscribers_slots_are_charged_what_they_allocate_as_items_churn() -> Result<(), String> {
        use tally_counting::Counting;
        let gauge = Gauge::new(Store::Fanout, 64 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 64 << 20,
                max_age_ms: u64::MAX,
            },
            Arc::clone(&gauge),
        ));
        let world = router.listen(
            10,
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: Vec::new(),
            }),
        );
        // Made before anything is measured: what they allocate is theirs, not the queue's.
        let items: Vec<Arc<Item>> = (0..64).map(|at| Arc::new(item(1, None, at))).collect();
        let none = Arc::new(Charge::none());
        let mut out = Vec::with_capacity(64);
        let mut sending: Vec<Hold> = Vec::with_capacity(1 << 16);
        let mut mix = 0x5eed_u64;
        let mut roll = |n: u64| {
            mix = mix
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (mix >> 33) % n
        };
        let base = Counting::live();
        let charged_base = world.subscriber.charged().1;
        let mut most = 0;
        for step in 0..4_000_u64 {
            for _ in 0..roll(if step % 500 < 50 { 40 } else { 4 }) {
                world
                    .subscriber
                    .offer(&items[roll(64) as usize], &none, 1, Charge::none());
            }
            if roll(3) == 0 {
                world
                    .try_recv_many(&mut out, roll(64) as usize)
                    .map_err(|fell| format!("{fell:?}"))?;
                sending.extend(out.drain(..).map(Taken::hold));
            }
            while !sending.is_empty() && roll(2) == 0 {
                let at = roll(sending.len() as u64) as usize;
                drop(sending.swap_remove(at));
            }
            let (allocated, charged) = world.subscriber.charged();
            assert_eq!(charged, allocated, "step {step}");
            let live = Counting::since(base);
            // The queue's slots and the hand's, exactly.
            assert_eq!(
                live,
                (charged - charged_base) as isize,
                "step {step}: {live} allocated, {charged} charged"
            );
            let queued = world
                .subscriber
                .queue
                .lock()
                .map_err(|_| "poisoned")?
                .queue
                .len();
            most = most.max(queued);
            assert!(
                charged
                    <= Deque::<Slot>::bytes_at_most(queued) + Held::bytes_at_most(sending.len()),
                "step {step}: {charged} for {queued} queued and {} in hand",
                sending.len()
            );
        }
        // Caught up: what it once held is given back.
        sending.clear();
        while world
            .try_recv_many(&mut out, 64)
            .map_err(|fell| format!("{fell:?}"))?
            > 0
        {
            out.clear();
        }
        assert!(most > 100, "the queue never grew: {most}");
        let kept = Deque::<Slot>::bytes_at_most(0) + Held::bytes_at_most(0);
        assert!(world.subscriber.charged().1 <= kept);
        assert!(Counting::since(base) as usize <= kept);
        drop(world);
        assert_eq!(gauge.held(), 0);

        // A store with room for a few slots only: past them the subscriber falls behind, and
        // nothing it allocates is uncharged.
        let small = Gauge::new(Store::Fanout, crate::footprint::vec::<Slot>(8));
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 64 << 20,
                max_age_ms: u64::MAX,
            },
            Arc::clone(&small),
        ));
        let tight = router.listen(
            10,
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: Vec::new(),
            }),
        );
        for one in &items[..32] {
            tight.subscriber.offer(one, &none, 1, Charge::none());
            let (allocated, charged) = tight.subscriber.charged();
            assert_eq!(charged, allocated);
            assert!(small.held() <= small.limit());
        }
        assert_eq!(
            tight.try_recv_many(&mut out, 1),
            Err(Fell::Behind(FellBehind::Bytes))
        );
        Ok(())
    }

    /// Two publishers read one subscriber's slot growth as nothing while its queue is one slot
    /// from full: the first fills it, and the second's slot must grow by more than it reserved,
    /// the store full but for what a laggard holds. The honest subscriber is made room for (the
    /// laggard let go) and takes the item; before, the growth was read outside its lock and it
    /// fell behind on the slot while the laggard kept what it held.
    #[test]
    fn a_slot_a_publisher_meanwhile_outgrew_is_made_room_for_not_fallen_behind()
    -> Result<(), String> {
        let gauge = Gauge::new(Store::Fanout, 1 << 20);
        let router = Arc::new(Router::charged(
            Bounds {
                max_bytes: 64 << 20,
                max_age_ms: u64::MAX,
            },
            Arc::clone(&gauge),
        ));
        let wants = || {
            Filter::Subscription(Subscription {
                streams: Streams::RAW,
                regions: Vec::new(),
            })
        };
        let honest = router.listen(10, wants());
        let laggard = router.listen(11, wants());
        let none = Arc::new(Charge::none());
        let one = Arc::new(info_item(None, 0)?);
        // One slot from full: the next push fills the queue, the one after grows it.
        honest.subscriber.offer(&one, &none, 1, gauge.empty());
        while honest.subscriber.growth() != Some(0) {
            honest.subscriber.offer(&one, &none, 1, gauge.empty());
        }
        loop {
            honest.subscriber.offer(&one, &none, 1, gauge.empty());
            if honest.subscriber.growth().is_some_and(|growth| growth > 0) {
                break;
            }
        }
        // The laggard holds room; the rest of the store is taken.
        for _ in 0..64 {
            laggard.subscriber.offer(&one, &none, 1, gauge.empty());
        }
        let _rest = gauge
            .try_charge(gauge.limit() - gauge.held())
            .ok_or("no room to take")?;
        let queued = honest.queued_bytes();
        let index = router.index.read().map_err(|_| "poisoned")?;
        let at = index
            .entries
            .iter()
            .position(|entry| Arc::ptr_eq(&entry.subscriber, &honest.subscriber))
            .ok_or("not listed")?;
        // The second publisher's slot, read as nothing.
        Router::deliver(&index, &one, &none, 1, vec![(at, gauge.empty())]);
        drop(index);
        assert!(
            honest.subscriber.growth().is_some(),
            "the honest subscriber fell behind"
        );
        assert_eq!(honest.queued_bytes(), queued + 1, "the item was not queued");
        assert!(
            laggard.subscriber.growth().is_none(),
            "the laggard was kept"
        );
        let (allocated, charged) = honest.subscriber.charged();
        assert_eq!(allocated, charged);
        Ok(())
    }
}
