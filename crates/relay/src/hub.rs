//! What every connection of a relay shares: the fan-out (`fanout::Router`), the staged ingest of
//! receivers' batches (`ingest::Stages`, RFC-0181), the record of positions, clock models and fault
//! proofs already forwarded, each receiver's newest self-description, the admission budget
//! (`budget`), and the relays this one offers as hints.
//!
//! A receiver's batch is admitted on the ingest worker that owns its raw shard ([`RawShard`]: its
//! sequence windows, hashes and station counters, touched by that worker alone), decoded once,
//! routed to the message exchange (the one deduplication, `exchange`) and offered to the fan-out
//! from there, so its subscribers read it in admitted order.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tally_wire::batch::Hash;
use tally_wire::{
    Batch, ClockModel, ClockModelPart, Decoded, FaultProof, Location, Positions, PublicKey,
    ReceiverInfo, Record, Region, RelayAddress,
};

use crate::bounded::Bounded;
use crate::budget::{Budget, Plan, Store};
use crate::egress::{Cap, Egress};
use crate::exchange::{Gauges, SHARDS, Sink, raw_shard};
use crate::fanout::{BEHIND_MS, Bounds, Filter, Listener, Router};
use crate::ingest::{Clock, InFlight, Pause, Refusal, Stage, Stages, Stamp, Threads};
use crate::network::{Asker, Network};
use crate::parts::Parts;
use crate::stations::{STATIONS_REMEMBERED, StationReport, Stations, StationsReport};
use crate::subscription::{Described, Subscription};

/// The memory a hub is budgeted until it is told its own (`Hub::memory`, which a relay always
/// does from `--memory`): a fixed figure, never the host's, so a hub a test builds behaves the
/// same on any machine.
pub const DEFAULT_MEMORY: usize = 16 << 30;

/// The least a subscriber's queue may hold, whatever the budget: a few seconds of one busy
/// feeder, so a relay sized for few feeders still serves a subscriber a burst.
pub const MIN_QUEUE_BYTES: usize = 64 * 1024 * 1024;

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

/// How many authors (a receiver, an engine) the relay remembers the streams of, per table, each
/// with up to `BOOTS_PER_AUTHOR` boots' newest sequences. At about 250 bytes each this is some
/// 25 MB, five times the network's planned 20,000 receivers. When full, the author that published
/// least recently is forgotten (`Bounded`: a new author counts as publishing when it is first
/// seen), so a churn of fresh keys forgets itself oldest first, an author publishing at least once
/// per table's worth of new keys keeps its place, and a new honest author is remembered as soon as
/// it starts. A forgotten stream is again bounded only by the hash window. The batches' table is
/// split across the raw shards (`exchange::raw_shard`), whose key no feeder knows, so filling any
/// shard's part takes as many keys as filling the whole.
///
/// Who can make use of a forgotten stream: a feeder may publish only its own batches and an engine
/// only its own positions (`link::Peer`), so a record of *another* author reaches this relay only
/// from a member (`Hub::relay_trust`: a relay whose offer this one verified at its address) or a
/// member link this relay dialled. A replay across authors therefore needs a relay that answers
/// at an address of its own; churning its own boots lets a stranger forget nothing but its own
/// older boots (`BOOTS_PER_AUTHOR`).
pub const AUTHORS_REMEMBERED: usize = 100_000;

/// The boots of one author whose windows are remembered: the one it publishes under and the last
/// few before it. An author churning boot ids forgets only its own oldest boots, never another
/// author's window, so it cannot reopen anyone else's stream to a replay. A boot older than these
/// is again bounded only by the hash window, and only the author (or a member relaying it) can
/// send its records.
pub const BOOTS_PER_AUTHOR: usize = 4;

/// What a relay's session is trusted with (`Hub::relay_trust`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayTrust {
    /// A relay whose offer this relay verified: a sharing member.
    Member,
    /// A relay the operator accepted and whose offer is not verified: the directory only.
    Directory,
}

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
/// What the relay holds is not sized here: the admission budget (`budget`) is, from the memory the
/// relay is given (`--memory`, by default the memory it runs in less `budget::HEADROOM_BYTES`). Every store that
/// grows with what feeders send (subscriber queues, deduplication, the epochs between ingest and
/// the sealer, the products, MLAT's raw, the batch store) is charged to its gauge and held to its
/// share at the feeder ceiling, and a Hello past the ceiling is refused; a relay whose memory
/// admits no feeder refuses to start. What every relay holds whatever its feeders (`BASE_BYTES`)
/// covers the tables below, which are bounded by count and so need no feeder's reservation:
///
/// | what                                                         | at most    |
/// | ------------------------------------------------------------ | ---------- |
/// | descriptions (`DESCRIPTION_BYTES_HELD`) and their index      | 80 MiB     |
/// | streams, three tables x 100,000 authors x ~250 B             | 75 MiB     |
/// | hashes, four tables x two generations x 100,000              | 36 MiB     |
/// | clock model parts awaiting manifests, and manifests' lists    | 96 MiB     |
///
/// A connection's Noise buffers come from one pool (`tally_wire::noise`), and each connection
/// carves what it may hold of them, reading and writing (`ingest::BUFFERS_PER_CONNECTION`), for
/// its whole session: a feeder from what it reserved (`Store::Buffers`), every other connection
/// from room the plan sizes to every connection but a feeder's the caps allow (this cap, the
/// member sessions and the subscribers, `Hub::plan`, `budget::Plan::connection_buffers`), so a
/// peer trickling a message, or reading slowly, holds what was planned for it. The kernel's
/// socket buffers for the fan-out's links are charged to the relay's cgroup beside it.
///
/// The members (the sessions over which other relays' data comes in) share one rate
/// (`DEFAULT_MAX_MEMBER_BYTES_PER_SEC`), planned once as the feeders it is worth, and each member
/// session carves its ingest allowance from the members' own pool, sized at start for every member
/// session the areas taken bring, at most this cap (`budget::members_for`,
/// `budget::Budget::reserve_member`), so what they send is admitted the same way as a feeder's and
/// never competes with feeders for room; past them a member is turned away as full
/// (`Reason::Full`) and routed around (RFC-0174 §2.5). This cap holds the sessions that have no
/// place of their role's own: a connection not yet identified, a probe, an engine, a directory
/// link, a dial that only sends (`Hub::connection`, `Hub::dialled`); a feeder, a subscriber and a
/// member give their place under it up for their own (`hub::Connection::general`), so no role
/// takes another's. What members cost beyond that is bandwidth
/// in, up to their shared rate; an operator sizes `--max-member-bytes-per-sec` to the host's link.
pub const DEFAULT_MAX_CONNECTIONS: usize = 2048;
/// Per IPv4 address, or per IPv6 /64 (what one host is usually given), so one host cannot take
/// the whole connection cap with handshakes it never finishes.
pub const DEFAULT_MAX_CONNECTIONS_PER_ADDRESS: usize = 16;
pub const DEFAULT_MAX_FEEDER_BYTES_PER_SEC: u64 = 262_144;
/// What the sharing members may send a second, all of them together, by default: 1 MiB, planned
/// once as the 128 feeders it is worth (`budget::Plan::with_members`) and held by one pace they
/// share (`ceiling::Pace`). Any one member may carry all of it (a relay may be another's parent in
/// every stripe of every area it takes), so it is also each member's own ceiling. A whole-world
/// MLAT relay sharing its products (clock models, final and provisional positions, about 4.2 MB/s
/// together, RFC-0171 §3.8.1) raises it, with the memory to match. A member's place is known from
/// its handshake (`Hub::relay_trust`), so it is held to this, and every other connection that
/// dialled in to the feeders' ceiling, whatever the key. An engine publishes nothing (an MLAT relay
/// shares its positions through its groups), so it is held to the feeders' ceiling like any
/// connection that only asks.
pub const DEFAULT_MAX_MEMBER_BYTES_PER_SEC: u64 = 1 << 20;
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
    /// For positions and clock models: the finest cells of the aircraft they place (a clock
    /// model's, its tile's centre), computed once when published, so a client's regions route
    /// them as they route raw. `None` is unrouted: whole-world.
    pub points: Option<Arc<[Region]>>,
    /// For a receiver's batch of a format this build reads: its one decode (`ingest`), so no
    /// reader of the fan-out (the BEAST output) inflates or parses it again.
    pub decoded: Option<Arc<Decoded>>,
    /// The ingest clock when it was taken: a subscriber queue's age is read from this
    /// (`fanout::BEHIND_MS`).
    pub stamp_ms: u64,
}

/// Two generations of hashes: a hash is remembered for one to two windows, or until `most` newer
/// hashes have retired its generation, whichever is sooner. The oldest are forgotten first. The
/// windows are read from the stamps of what it is shown (the ingest clock's, `ingest::Stamp`),
/// never from a clock of its own (RFC-0181 invariant 2): the same stamped batches are new or not
/// the same way however late a stage takes them.
struct Seen {
    window_ms: u64,
    most: usize,
    current: HashSet<Hash>,
    previous: HashSet<Hash>,
    /// The stamp its current generation began at, once it has been shown one.
    rotated_ms: Option<u64>,
}

impl Seen {
    fn new(window: Duration, most: usize) -> Self {
        Self {
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            most: most.max(1),
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated_ms: None,
        }
    }

    /// Retires the current generation once `stamp_ms` is a window past its start.
    fn rotate(&mut self, stamp_ms: u64) {
        match self.rotated_ms {
            None => self.rotated_ms = Some(stamp_ms),
            Some(rotated) if stamp_ms.saturating_sub(rotated) >= self.window_ms => {
                self.retire(stamp_ms);
            }
            Some(_) => {}
        }
    }

    fn retire(&mut self, stamp_ms: u64) {
        self.previous = std::mem::take(&mut self.current);
        self.rotated_ms = Some(self.rotated_ms.map_or(stamp_ms, |at| at.max(stamp_ms)));
    }

    fn insert(&mut self, hash: Hash) {
        if self.current.len() >= self.most {
            let at = self.rotated_ms.unwrap_or(0);
            self.retire(at);
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
#[derive(Clone, Copy, Debug)]
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
/// The streams are held by author, each author's boots bounded apart (`BOOTS_PER_AUTHOR`), so one
/// author's churn of boots never forgets another author's window.
/// Positions held until the models they cite have gone out, at most, and for at most how long.
const AWAITING_MAX: usize = 4_096;
const AWAITING_MS: Duration = Duration::from_secs(10);

/// Positions held for their models (`Hub::forward_positions`).
struct Awaiting {
    source: u64,
    record: Record,
    cited: Vec<Hash>,
    since: Instant,
}

/// The clock models a positions record cites, each once.
fn cited_models(record: &Record) -> Vec<Hash> {
    let (Record::Positions(positions) | Record::Provisional(positions)) = record else {
        return Vec::new();
    };
    let mut cited: Vec<Hash> = positions
        .solutions()
        .map(|content| {
            content
                .solutions
                .iter()
                .map(|solution| solution.clock_model)
                .collect()
        })
        .unwrap_or_default();
    cited.sort_unstable();
    cited.dedup();
    cited
}

/// One author's boots and each one's window, the boot forwarded most recently last.
#[derive(Clone, Debug, Default)]
struct Boots(Vec<(u64, Sequences)>);

impl Boots {
    fn window(&self, boot: u64) -> Option<Sequences> {
        self.0
            .iter()
            .find(|(held, _)| *held == boot)
            .map(|(_, window)| *window)
    }

    /// `boot`'s window is now `window`, and it is the boot forwarded most recently; the author's
    /// oldest boot is forgotten if that is one too many.
    fn set(&mut self, boot: u64, window: Sequences) {
        self.0.retain(|(held, _)| *held != boot);
        if self.0.len() >= BOOTS_PER_AUTHOR {
            self.0.remove(0);
        }
        self.0.push((boot, window));
    }
}

struct Forwarded<A> {
    seen: Seen,
    newest: Bounded<A, Boots>,
}

impl<A: std::hash::Hash + Eq + Clone> Forwarded<A> {
    fn new(window: Duration) -> Self {
        Self::bounded(window, AUTHORS_REMEMBERED, HASHES_REMEMBERED)
    }

    fn bounded(window: Duration, authors: usize, hashes: usize) -> Self {
        Self {
            seen: Seen::new(window, hashes),
            newest: Bounded::new(authors),
        }
    }

    /// True, and remembered, when the record (`author`'s, under `boot`, stamped `stamp_ms`) is
    /// new.
    fn admit(&mut self, hash: Hash, author: A, boot: u64, sequence: u64, stamp_ms: u64) -> bool {
        self.seen.rotate(stamp_ms);
        if self.seen.contains(&hash) {
            return false;
        }
        let known = self
            .newest
            .get(&author)
            .and_then(|boots| boots.window(boot));
        let window = match known {
            Some(window) => window.admit(sequence),
            None => Some(Sequences::first(sequence)),
        };
        let Some(window) = window else {
            return false;
        };
        self.seen.insert(hash);
        // Every record forwarded is its author publishing, new author or known.
        match self.newest.get_mut(&author) {
            Some(boots) => {
                boots.set(boot, window);
                self.newest.touch(&author);
            }
            None => {
                self.newest
                    .insert_active(author, Boots(vec![(boot, window)]));
            }
        }
        true
    }

    /// The streams (author and boot) remembered.
    #[cfg(test)]
    fn streams(&self) -> usize {
        self.newest.values().map(|boots| boots.0.len()).sum()
    }
}

/// A receiver's newest description, ready to send, and the finest cell of the location it
/// declared in it.
struct Known {
    issued_ms: u64,
    record: Arc<Record>,
    cell: Option<Region>,
    bytes: usize,
    /// What it declares, read once when kept, for the station reports.
    place: Option<Location>,
    software: Option<String>,
}

impl Known {
    fn item(&self) -> Item {
        Item {
            source: RELAY_ITSELF,
            record: Arc::clone(&self.record),
            cell: self.cell,
            points: None,
            decoded: None,
            stamp_ms: 0,
        }
    }
}

/// One raw shard's state (`exchange::raw_shard`): its receivers' batch streams and their station
/// counters. Owned by the ingest worker of the shard, which alone takes it on the batch path; the
/// lock is for the reports and a feeder's arrival and departure.
struct RawShard {
    batches: Forwarded<PublicKey>,
    stations: Stations,
}

impl RawShard {
    fn new(window: Duration) -> Self {
        Self {
            batches: Forwarded::bounded(
                window,
                AUTHORS_REMEMBERED.div_ceil(SHARDS),
                HASHES_REMEMBERED.div_ceil(SHARDS),
            ),
            stations: Stations::new(STATIONS_REMEMBERED.div_ceil(SHARDS)),
        }
    }
}

/// A feeder's own description, as its link last took it: given to the hub again when the hub has
/// forgotten it and the feeder is publishing (see `RECEIVERS_REMEMBERED`).
#[derive(Clone, Debug)]
pub struct OwnDescription {
    pub info: ReceiverInfo,
    pub issued_ms: u64,
    pub place: Option<Location>,
}

/// Where a batch came from, for what follows its admission.
#[derive(Clone, Debug)]
pub enum Origin {
    /// The receiver's own feeder, with its description as its link holds it: seeded into the
    /// receiver's sharing group by this relay, its origin.
    Feeder(Option<Arc<OwnDescription>>),
    /// A sharing member or a relay link: a piece of a group.
    Peer(Asker),
    /// Anywhere else (a subscriber, a test): forwarded, nothing more.
    Elsewhere,
}

/// What the relay's memory holds (`Hub::memory_report`, `GET /memory`): the budget and its gauges,
/// the one batch byte store's and the delivery tags' own counts of what they hold (kept apart from
/// their charges, so each is read beside its gauge, `Store::Batches` and `Store::Delivery`, which
/// hold them). Every decoded batch alive, whichever stores share it, is the budget's
/// (`budget::MemoryReport::decoded`), read beside what those stores are charged.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MemoryReport {
    pub budget: crate::budget::MemoryReport,
    pub batches_held: usize,
    pub delivery_held: usize,
    /// Sharing members turned away for want of room in the members' pool.
    pub members_refused: u64,
}

/// A batch a link took in, on its way to the ingest stage.
pub struct Inbound {
    pub source: u64,
    pub batch: Batch,
    pub origin: Origin,
    /// Check the receiver's signature first (every batch a link takes; a test's may be trusted).
    pub verify: bool,
    /// Its stamp, when a trace gives one; else the ingest clock's when it is worked on.
    pub stamp: Option<Stamp>,
    /// Its charge in the ingest stage (`ingest::charge_of`), from its connection's allowance or,
    /// handed in by the relay itself, from `Store::Ingest` (`Hub::in_flight_for`): no batch reaches
    /// the stage uncharged. Shrunk to its decode, carried with its slices to the message exchange,
    /// released when the epochs hold it or it is let go.
    pub in_flight: InFlight,
    /// Where a refused signature ends the connection.
    pub refusal: Option<Arc<Refusal>>,
}

impl Inbound {
    /// A batch with nothing to follow it: forwarded, from `source`, charged `in_flight`.
    pub fn trusted(source: u64, batch: Batch, in_flight: InFlight) -> Self {
        Self {
            source,
            batch,
            origin: Origin::Elsewhere,
            verify: false,
            stamp: None,
            in_flight,
            refusal: None,
        }
    }
}

/// A receiver's description a link took in (or a trace hands in), on its way to the hub: kept if
/// it is the newest for its key, and then handed to the hosted MLAT through the ingest stage, on the
/// worker that owns its receiver's raw shard and stamped there as that receiver's batches are
/// (`Hub::describe`), so where it falls among them is the trace's, never the threads'.
pub struct Description {
    pub source: u64,
    pub info: ReceiverInfo,
    pub receiver: PublicKey,
    pub issued_ms: u64,
    /// The location it declares, when this build can read it.
    pub place: Option<Location>,
    /// The receiver has just had a batch forwarded, so it is kept as one that publishes.
    pub publishing: bool,
    /// Its stamp, when a trace gives one; else the ingest clock's when it is worked on.
    pub stamp: Option<Stamp>,
    /// Its charge in the ingest stage, as a batch's: from its connection's allowance, or handed in
    /// by the relay itself, from `Store::Ingest` (`Hub::in_flight_of`). Released once the hosted
    /// MLAT holds it.
    pub in_flight: InFlight,
}

/// One raw shard's receivers described (`exchange::raw_shard`), each with its cell, in the order
/// they are forgotten, and the bytes of their descriptions: held to a count and to bytes, each a
/// `SHARDS`th of the relay's. The batch path takes only its receiver's shard, so no lock is shared
/// by every batch; and the shard's key is one no feeder knows, so filling a shard takes as many
/// keys as filling the relay.
struct ReceiverShard {
    held: Bounded<PublicKey, Option<Region>>,
    bytes: usize,
    max_bytes: usize,
}

/// The receivers described, sharded by receiver: what the batch path reads (a cell to route by)
/// and marks (the receiver is publishing), O(1) each under one shard's lock.
struct Receivers {
    shards: Box<[Mutex<ReceiverShard>]>,
}

impl Receivers {
    /// `shards` shards (`SHARDS` in a relay; a test may hold one), each of `count` receivers and
    /// `bytes` of descriptions at most.
    fn new(shards: usize, count: usize, bytes: usize) -> Self {
        Self {
            shards: (0..shards.max(1))
                .map(|_| {
                    Mutex::new(ReceiverShard {
                        held: Bounded::new(count),
                        bytes: 0,
                        max_bytes: bytes,
                    })
                })
                .collect(),
        }
    }

    fn shard(&self, receiver: &PublicKey) -> &Mutex<ReceiverShard> {
        &self.shards[usize::from(raw_shard(receiver).0) % self.shards.len()]
    }

    /// Receivers held.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.lock().ok().map(|shard| shard.held.len()))
            .sum()
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
    fn new() -> Self {
        Self {
            known: HashMap::new(),
            by_point: BTreeMap::new(),
            bytes: 0,
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
    fanout: Arc<Router>,
    /// The ingest workers and the message exchange (`ingest`, `exchange`).
    stages: Stages,
    /// Each raw shard's streams and stations, `SHARDS` of them.
    raw: Box<[Mutex<RawShard>]>,
    /// How long a forwarded batch's hash is remembered.
    window: Duration,
    budget: Budget,
    positions: Mutex<Forwarded<PublicKey>>,
    /// An engine's provisional positions: a stream per engine boot, sequenced apart from its
    /// final positions.
    provisional: Mutex<Forwarded<PublicKey>>,
    /// An engine's clock models: a stream per engine boot, sequenced apart from its positions.
    clock_models: Mutex<Forwarded<PublicKey>>,
    /// Clock model parts held for their manifests, and forwarded manifests' lists (`parts`).
    parts: Mutex<Parts>,
    /// Positions held until the clock models they cite have gone out (`awaiting`).
    awaiting: Mutex<VecDeque<Awaiting>>,
    /// Fault proofs, by hash only: a proof is anyone's and unsigned, so it has no stream to
    /// window. One replayed after its hash is forgotten is forwarded again, which costs the
    /// replayer its own ingest ceiling and tells a consumer nothing it did not already act on.
    fault_proofs: Mutex<Seen>,
    /// The products a peer's record is passed on as (bundle indexes, regional batches), by hash:
    /// each into the fan-out once. Without it a record that comes back round a loop of relays (an
    /// index read on a one-hop raw link, passed on, read back) went round for ever, thousands a
    /// second, and every link behind the fan-out fell behind it.
    passed_on: Mutex<Seen>,
    /// The receivers described, each with its cell, in the order they are forgotten, sharded by
    /// receiver: what the batch path reads (a cell to route by) and marks (the receiver is
    /// publishing), under its receiver's shard's lock alone.
    receivers: Receivers,
    /// Their descriptions. Taken by `publish_info` (then a receiver's shard, in that order) and by
    /// a joining subscriber, never by the batch path, so no scan ever stalls a batch.
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
    max_member_bytes_per_sec: u64,
    /// The pace every member session shares (`ceiling::Pace`), at `max_member_bytes_per_sec`.
    member_pace: Arc<crate::ceiling::Pace>,
    /// The areas taken (RFC-0174 §2.1): what the member sessions are planned from
    /// (`budget::members_for`).
    areas: Vec<Region>,
    /// Whether the relay holds MLAT raw: its plan's base and each feeder's cost (`Hub::memory`).
    holds_raw: bool,
    /// The time the ingest ceilings read.
    ceiling_clock: crate::ceiling::Clock,
    accepted_relays: HashSet<PublicKey>,
    hints: Vec<RelayAddress>,
    /// What the relay may send a second, and every byte it has sent (`egress`).
    egress: Arc<Egress>,
    /// RFC-0174's duties (`network`): the one place they meet the hub.
    network: Network,
    /// Sharing members turned away because the members' pool was full (`Budget::reserve_member`).
    members_refused: AtomicU64,
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

/// Held for as long as one connection is open: its place under its source's cap, and, until it
/// is given up for a place of the connection's own role (`Connection::general`), under the
/// relay's.
pub struct Connection {
    general: Option<Slot>,
    _source: SourceSlot,
}

impl Connection {
    /// Its place under the relay's connection cap, to hold while the connection has no place of
    /// its own and to let go when it takes one: a feeder once it holds its reservation, a
    /// subscriber its place among the subscribers, a relay its member's place. Each role is
    /// bounded by its own cap, never by another's (`Hub::plan`).
    pub fn general(&mut self) -> Option<Slot> {
        self.general.take()
    }
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
    /// A hub whose stages run on the caller (`ingest::Stages::inline`), by the system clock, its
    /// budget `DEFAULT_MEMORY`: what a test builds. A relay is then `staged` onto its threads.
    pub fn new(max_subscribers: usize) -> Self {
        Self::clocked(max_subscribers, crate::ingest::anchored_wall_clock())
    }

    /// As `new`, its ingest clock `clock`. Its budget is sized from its own plan (`Hub::plan`),
    /// as every change to its caps resizes it.
    pub fn clocked(max_subscribers: usize, clock: Clock) -> Self {
        let network = Network::new();
        let budget = Budget::of_memory(
            DEFAULT_MEMORY,
            Plan::planned(false)
                .with_members(0, DEFAULT_MAX_MEMBER_BYTES_PER_SEC)
                .with_connections(DEFAULT_MAX_CONNECTIONS),
        );
        network.charge_to(&budget);
        let stages = Stages::inline(
            Arc::clone(&clock),
            network.products.sink(),
            Gauges::of(&budget),
        );
        Self {
            fanout: Arc::new(router(&budget)),
            stages,
            raw: (0..SHARDS)
                .map(|_| Mutex::new(RawShard::new(SEEN_WINDOW)))
                .collect(),
            window: SEEN_WINDOW,
            budget,
            positions: Mutex::new(Forwarded::new(SEEN_WINDOW)),
            provisional: Mutex::new(Forwarded::new(SEEN_WINDOW)),
            clock_models: Mutex::new(Forwarded::new(SEEN_WINDOW)),
            parts: Mutex::new(Parts::default()),
            awaiting: Mutex::new(VecDeque::new()),
            fault_proofs: Mutex::new(Seen::new(SEEN_WINDOW, HASHES_REMEMBERED)),
            passed_on: Mutex::new(Seen::new(SEEN_WINDOW, HASHES_REMEMBERED)),
            receivers: Receivers::new(
                SHARDS,
                RECEIVERS_REMEMBERED.div_ceil(SHARDS),
                DESCRIPTION_BYTES_HELD.div_ceil(SHARDS),
            ),
            directory: Mutex::new(Directory::new()),
            next_connection: AtomicU64::new(RELAY_ITSELF + 1),
            subscribers: Arc::new(AtomicUsize::new(0)),
            max_subscribers,
            connections: Arc::new(AtomicUsize::new(0)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            per_address: Arc::new(Mutex::new(HashMap::new())),
            max_connections_per_address: DEFAULT_MAX_CONNECTIONS_PER_ADDRESS,
            max_feeder_bytes_per_sec: DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
            max_member_bytes_per_sec: DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
            member_pace: Arc::new(crate::ceiling::Pace::new(DEFAULT_MAX_MEMBER_BYTES_PER_SEC)),
            areas: Vec::new(),
            holds_raw: false,
            ceiling_clock: crate::ceiling::system_clock(),
            accepted_relays: HashSet::new(),
            hints: Vec::new(),
            // Until the operator names a cap, nothing billed leaves the host (loopback peers are
            // still served): a hub can never send without one.
            egress: Arc::new(Egress::new(Cap::NONE)),
            network,
            members_refused: AtomicU64::new(0),
        }
        .replanned()
    }

    /// The stages on threads of their own (`threads`), the sealer on its own: what a relay runs.
    /// Built before the hub is shared, so nothing has been ingested yet. Every thread starts or
    /// this fails, and the relay with it: a stage short of a thread would close no epoch ever, or
    /// refuse every one.
    pub fn staged(self, threads: Threads) -> Result<Self, String> {
        self.staged_pausing(threads, None)
    }

    /// As `staged`, each stage held up inside by `pause` (`ingest::Stage`): a test's delays, to
    /// show that they change nothing a relay makes.
    pub fn staged_pausing(
        mut self,
        threads: Threads,
        pause: Option<Pause>,
    ) -> Result<Self, String> {
        let clock = self.stages.clock();
        let gauges = Gauges::of(&self.budget);
        // The sealer moves onto its thread wherever it is held: no exclusive hold is needed, so
        // it can never be left inline behind threaded stages.
        self.network
            .products
            .on_thread(threads.message.max(1), pause.as_ref())?;
        self.stages = Stages::threaded(
            clock,
            threads,
            &self.network.products.sink(),
            &gauges,
            pause,
        )?;
        Ok(self)
    }

    /// The relay's own streams under fixed boot ids instead of random ones (the regional product
    /// under `boot_id`, the deduplicated stream under the next): what two runs of one trace
    /// compare byte for byte by. Built before the hub is shared or staged.
    pub fn product_boots(mut self, boot_id: u64) -> Self {
        let clock = self.stages.clock();
        let unused: Sink = Arc::new(|_| Ok(()));
        let gauges = Gauges::of(&self.budget);
        self.stages = Stages::inline(Arc::clone(&clock), unused, gauges.clone());
        self.network.products = Arc::new(crate::products::Products::with_boots(
            boot_id,
            boot_id.wrapping_add(1),
            1,
        ));
        self.network.charge_to(&self.budget);
        self.stages = Stages::inline(clock, self.network.products.sink(), gauges);
        self
    }

    /// The relay may use `memory` bytes, and holds MLAT raw (`holds_raw`: it hosts MLAT) or not:
    /// the admission budget (`budget`), sized from this hub's plan (`Hub::plan`), and every
    /// store's and queue's share of it (each store's gauge, resized in place). Whatever order the
    /// hub's caps are set in, the budget follows the last of them.
    pub fn memory(mut self, memory: usize, holds_raw: bool) -> Self {
        self.holds_raw = holds_raw;
        self.budget.resize(memory, self.plan());
        self.fanout = Arc::new(router(&self.budget));
        self.network.charge_to(&self.budget);
        self
    }

    /// The least memory that admits `feeders` beside everything this hub plans before any
    /// (`budget::Plan::before_feeders`), holding MLAT raw or not: a test's exact budget.
    pub fn memory_for_feeders(self, feeders: usize, holds_raw: bool) -> Self {
        let plan = Self { holds_raw, ..self };
        let memory = Budget::memory_for(feeders, plan.plan());
        plan.memory(memory, holds_raw)
    }

    /// What this hub plans to hold (`budget::Plan`): whether it holds MLAT raw, its members'
    /// pool (the member sessions its areas bring, `budget::members_for`, sharing
    /// `max_member_bytes_per_sec`) and its connections' buffers (`max_connections`), from its own
    /// settings, so the budget and the caps it enforces cannot disagree.
    pub fn plan(&self) -> Plan {
        let members = crate::budget::members_for(&self.areas, self.holds_raw, self.max_connections);
        Plan::planned(self.holds_raw)
            .with_members(members, self.max_member_bytes_per_sec)
            .with_connections(self.non_feeder_connections(members))
    }

    /// Every connection but a feeder's the relay holds at once, each by its own role's cap: those
    /// under the connection cap (not yet identified, probes, engines, directory links, the dials
    /// that hold no member's place), the member sessions (`members`), and the subscribers. A
    /// feeder's are its reservation's. Before, the three shared the one cap, so the plan counted
    /// some 128 members, 25 feeders and 64 subscribers in 128 connections, and a member past the
    /// connections the others held was closed on before its handshake, with no word to route
    /// around it by.
    fn non_feeder_connections(&self, members: usize) -> usize {
        self.max_connections
            .saturating_add(members)
            .saturating_add(self.max_subscribers)
    }

    /// Takes `areas` (RFC-0174 §2.1): the areas its sharing and MLAT choose from
    /// (`Selection::set_taken`) and its regional product gathers (`Products::set_taken`), and the
    /// areas its member sessions are planned from, so the three cannot disagree.
    pub fn taking(mut self, areas: Vec<Region>) -> Self {
        self.network.selection.set_taken(areas.clone());
        self.network.products.set_taken(areas.clone());
        self.areas = areas;
        self.replanned()
    }

    /// The budget resized for this hub's plan as it now stands, at the same memory.
    fn replanned(self) -> Self {
        let (memory, holds_raw) = (self.budget.memory(), self.holds_raw);
        self.memory(memory, holds_raw)
    }

    /// Each subscriber's queue holds at most `bytes` (and `fanout::BEHIND_MS` of inbound), instead
    /// of the budget's share: a test's small queue, or an operator's.
    pub fn queue_bytes(mut self, bytes: usize) -> Self {
        self.fanout = Arc::new(Router::charged(
            Bounds {
                max_bytes: bytes,
                max_age_ms: BEHIND_MS,
            },
            self.budget.gauge(Store::Fanout),
        ));
        self
    }

    /// What the relay's memory holds, store by store (`GET /memory`).
    pub fn memory_report(&self) -> MemoryReport {
        let (sharing, _) = self.network.sharing.held();
        MemoryReport {
            budget: self.budget.report(),
            batches_held: sharing,
            delivery_held: self.network.delivery.held_bytes(),
            members_refused: self.members_refused.load(Ordering::Relaxed),
        }
    }

    /// The admission budget: a feeder is admitted only with its bytes reserved in every store.
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// A sharing member was turned away: the members' pool was full. Counted on `GET /memory`.
    pub fn member_refused(&self) {
        self.members_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// A connection's ingest allowance of `bytes` (`ingest::Allowance`), carved from
    /// `Store::Ingest`: a feeder's (`ingest::FEEDER_ALLOWANCE`) or a member's, each within what it
    /// reserved. `None` when the store has no room for it.
    pub fn allowance(&self, bytes: usize) -> Option<crate::ingest::Allowance> {
        crate::ingest::Allowance::carve(
            &self.budget.gauge(Store::Ingest),
            &self.budget.oversize(),
            bytes,
        )
    }

    /// A batch the relay itself hands in (a test's trace, a replay): charged to `Store::Ingest`
    /// as a link's is (`ingest::charge_of`), the caller's thread waiting for room.
    pub fn in_flight_for(&self, batch: &Batch) -> InFlight {
        self.in_flight_of(crate::ingest::charge_of(batch))
    }

    /// `bytes` the relay itself hands the ingest stage (a batch's, a description's), charged to
    /// `Store::Ingest`, the caller's thread waiting for room.
    pub fn in_flight_of(&self, bytes: usize) -> InFlight {
        InFlight::trusted(
            &self.budget.gauge(Store::Ingest),
            crate::ingest::floored(bytes),
        )
    }

    /// A connection's Noise buffers (`ingest::BUFFERS_PER_CONNECTION`), carved for as long as it
    /// is open, waiting for room: a feeder's from `Store::Buffers`, which its reservation planned,
    /// every other connection's from the room the plan sizes to the connection cap
    /// (`budget::Plan::connection_buffers`).
    pub async fn connection_buffers(&self, feeder: bool) -> crate::budget::Charge {
        let gauge = if feeder {
            self.budget.gauge(Store::Buffers)
        } else {
            self.budget.connection_buffers()
        };
        gauge.charge(crate::ingest::BUFFERS_PER_CONNECTION).await
    }

    /// RFC-0174's duties.
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// A record the relay itself originated (a network duty's, or its hosted MLAT's): into the
    /// fan-out as the relay's own, routed by kind exactly as a peer's would be. Positions, clock
    /// models and their parts go through their own forwarding rules, so a duplicate is still
    /// forwarded once.
    pub fn publish_own(&self, record: Record) {
        self.publish_as(RELAY_ITSELF, record);
    }

    /// Whether a record passed on by hash (`passed_on`) is new, remembering it if so.
    fn first_time(&self, hash: Hash) -> bool {
        let now_ms = self.now_ms();
        self.passed_on.lock().is_ok_and(|mut seen| {
            seen.rotate(now_ms);
            if seen.contains(&hash) {
                return false;
            }
            seen.insert(hash);
            true
        })
    }

    /// As `publish_own`, a record that came in on connection `source` and is forwarded unchanged
    /// (a peer's regional batch): never sent back down that connection.
    pub fn publish_as(&self, source: u64, record: Record) {
        match record {
            Record::Positions(positions) => {
                if let Ok(engine) = positions.engine() {
                    self.publish_positions(source, positions, engine);
                }
            }
            Record::Provisional(positions) => {
                if let Ok(engine) = positions.engine() {
                    self.publish_provisional(source, positions, engine);
                }
            }
            Record::ClockModel(model) => {
                if let Ok(engine) = model.engine() {
                    self.publish_clock_model(source, model, engine);
                }
            }
            Record::ClockModelPart(part) => {
                self.publish_clock_model_part(source, part);
            }
            Record::BundleIndex(index) => {
                if !self.first_time(index.hash()) {
                    return;
                }
                let cell = index.content().ok().map(|content| content.parent);
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(Record::BundleIndex(index)),
                    cell,
                    points: None,
                    decoded: None,
                    stamp_ms: self.now_ms(),
                });
            }
            Record::RegionalBatch(regional) => {
                if !self.first_time(regional.hash()) {
                    return;
                }
                let cell = regional.content().ok().map(|content| content.cell);
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(Record::RegionalBatch(regional)),
                    cell,
                    points: None,
                    decoded: None,
                    stamp_ms: self.now_ms(),
                });
            }
            other => {
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(other),
                    cell: None,
                    points: None,
                    decoded: None,
                    stamp_ms: self.now_ms(),
                });
            }
        }
    }

    /// The most the relay sends a second to billed peers (`--max-upload`).
    pub fn max_upload(mut self, cap: Cap) -> Self {
        self.egress = Arc::new(Egress::new(cap));
        self
    }

    pub fn egress(&self) -> &Arc<Egress> {
        &self.egress
    }

    /// How long a forwarded hash is remembered (one to two of `window`), instead of a minute.
    pub fn remembering_hashes_for(mut self, window: Duration) -> Self {
        self.window = window;
        self.raw = (0..SHARDS)
            .map(|_| Mutex::new(RawShard::new(window)))
            .collect();
        self.positions = Mutex::new(Forwarded::new(window));
        self.provisional = Mutex::new(Forwarded::new(window));
        self.clock_models = Mutex::new(Forwarded::new(window));
        self.fault_proofs = Mutex::new(Seen::new(window, HASHES_REMEMBERED));
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

    /// The clients this relay vouches for (RFC-0174 §2.1): each is signed a firehose credential
    /// and this relay's evidence on its sessions here, which it presents to every relay it reads.
    /// The operator's to give, key by key, as a relay's acceptance is.
    pub fn vouching_for(self, clients: impl IntoIterator<Item = PublicKey>) -> Self {
        self.network.credit.vouch_for(clients);
        self
    }

    /// Connections served at once before a new one is closed unanswered.
    pub fn max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        // The connections' buffers are planned in the budget: resized with the cap.
        self.replanned()
    }

    /// Connections from one source (`source_of`) served at once before a new one from it is
    /// closed unanswered.
    pub fn max_connections_per_address(mut self, max: usize) -> Self {
        self.max_connections_per_address = max;
        self
    }

    /// The most bytes a second one connection that dialled in and is not a sharing member or a
    /// directory link may send, beyond its burst.
    pub fn max_feeder_bytes_per_sec(mut self, rate: u64) -> Self {
        self.max_feeder_bytes_per_sec = rate;
        self
    }

    /// The most bytes a second the sharing members may send, all together (their shared pace)
    /// and each alone (its ceiling), beyond the burst. Planned once as the feeders this rate is
    /// worth: the budget is resized with it.
    pub fn max_member_bytes_per_sec(mut self, rate: u64) -> Self {
        self.max_member_bytes_per_sec = rate;
        self.member_pace = Arc::new(crate::ceiling::Pace::new(rate));
        self.replanned()
    }

    /// The pace every member session shares.
    pub fn member_pace(&self) -> Arc<crate::ceiling::Pace> {
        Arc::clone(&self.member_pace)
    }

    pub fn hints(&self) -> &[RelayAddress] {
        &self.hints
    }

    /// How far a key that opens a session as a relay is trusted (RFC-0171 §3.6, RFC-0174 §2.5):
    /// the one rule, read by every session as it opens and again as it runs. A relay whose live
    /// offer this relay holds, verified by a handshake at the address the offer names, is a
    /// member (it exchanges its sharing groups' records and may take raw as an engine); failing
    /// that, a key the operator accepted (`--accept-relay`) is a directory link (the directory
    /// only); any other key is not a relay here.
    pub fn relay_trust(&self, key: &PublicKey) -> Option<RelayTrust> {
        if self.network.directory.knows(key) {
            Some(RelayTrust::Member)
        } else if self.accepted_relays.contains(key) {
            Some(RelayTrust::Directory)
        } else {
            None
        }
    }

    pub fn feeder_bytes_per_sec(&self) -> u64 {
        self.max_feeder_bytes_per_sec
    }

    pub fn member_bytes_per_sec(&self) -> u64 {
        self.max_member_bytes_per_sec
    }

    /// The clock the ingest ceilings read, instead of the system's: a test holds it still.
    pub fn ceiling_clock_from(mut self, clock: crate::ceiling::Clock) -> Self {
        self.ceiling_clock = clock;
        self
    }

    pub fn ceiling_clock(&self) -> crate::ceiling::Clock {
        std::sync::Arc::clone(&self.ceiling_clock)
    }

    /// A place under the connection cap for a session this relay dials itself that holds no place
    /// of its own role (a member link that only sends, an upstream). A one-hop raw link is a
    /// member session, and holds a member's place instead (`link::admit_member`).
    pub fn dialled(&self) -> Option<Slot> {
        Slot::take(&self.connections, self.max_connections)
    }

    /// A place for one more connection from `address`, or `None` when the relay, or that
    /// address's source, holds as many as it will. Taken before the handshake, when nothing says
    /// what the connection is: it holds a place under the connection cap until it takes one of its
    /// role's (`Connection::general`), so the cap bounds the connections not yet identified and
    /// those whose role has no cap of its own (probes, engines, directory links), and a relay full
    /// of feeders, subscribers or members still answers the next peer's handshake, and tells a
    /// member it is full (`Reason::Full`) rather than closing on it unanswered.
    pub fn connection(&self, address: IpAddr) -> Option<Connection> {
        let source = SourceSlot::take(
            &self.per_address,
            source_of(address),
            self.max_connections_per_address,
        )?;
        let general = Slot::take(&self.connections, self.max_connections)?;
        Some(Connection {
            general: Some(general),
            _source: source,
        })
    }

    /// Links in the fan-out now (subscribers, engines, relay links and the BEAST output, each once
    /// it has sent the descriptions it joined with): everything published from now on reaches
    /// every one of them. What a test waits on before publishing, rather than a sleep.
    pub fn listening(&self) -> usize {
        self.fanout.listening()
    }

    /// Subscribers being served now (an engine takes no place among them, `Hub::engine`).
    pub fn subscribers(&self) -> usize {
        self.subscribers.load(Ordering::SeqCst)
    }

    pub fn connection_id(&self) -> u64 {
        self.next_connection.fetch_add(1, Ordering::Relaxed)
    }

    /// Forwards a batch if it is new (see `Forwarded`): handed to the ingest worker that owns its
    /// receiver's shard, which admits, decodes (once, `ingest`), deduplicates and fans it out. On
    /// a hub whose stages run inline this happens before it returns, and the answer is whether it
    /// was new; on threads it is the worker's, and this says only that it was handed over.
    pub fn ingest(self: &Arc<Self>, inbound: Inbound) -> bool {
        let Ok(receiver) = inbound.batch.receiver() else {
            return false;
        };
        if self.stages.is_inline() {
            return self.admit(0, inbound);
        }
        let worker = self.stages.worker_of(raw_shard(&receiver));
        let hub = Arc::clone(self);
        let Inbound {
            source,
            batch,
            origin,
            verify,
            stamp,
            in_flight,
            refusal,
        } = inbound;
        self.stages.run_charged(
            worker,
            in_flight,
            Box::new(move |producer, in_flight| {
                hub.admit(
                    producer,
                    Inbound {
                        source,
                        batch,
                        origin,
                        verify,
                        stamp,
                        in_flight,
                        refusal,
                    },
                );
            }),
        );
        true
    }

    /// A receiver's batch, verified elsewhere, from `source`: as `ingest` with nothing to follow.
    /// What a test, a replay and the relay's own links publish by.
    pub fn publish_batch(self: &Arc<Self>, source: u64, batch: Batch, receiver: PublicKey) -> bool {
        if batch.receiver().ok() != Some(receiver) {
            return false;
        }
        let in_flight = self.in_flight_for(&batch);
        self.ingest(Inbound::trusted(source, batch, in_flight))
    }

    /// One batch on ingest worker `producer` (`ingest`): its signature, its admission by its raw
    /// shard, its one decode, its receptions to the message exchange, the duties, the fan-out,
    /// then what its link asked to follow. True when it was new.
    fn admit(&self, producer: usize, inbound: Inbound) -> bool {
        let Inbound {
            source,
            batch,
            origin,
            verify,
            stamp,
            mut in_flight,
            refusal,
        } = inbound;
        let Ok(receiver) = batch.receiver() else {
            return false;
        };
        // A receiver's signature only: a relay's deduplicated batch never passes as one.
        if verify && let Err(error) = batch.verify() {
            if let Some(refusal) = refusal {
                refusal.refuse(error.to_string());
            }
            return false;
        }
        let stamp = match stamp {
            Some(stamp) => self.stages.stamped(producer, stamp),
            None => self.stages.stamp(producer),
        };
        // A test's delay, between the stamp and everything after it.
        self.stages.pause(Stage::Ingest);
        let shard = &self.raw[usize::from(raw_shard(&receiver).0)];
        let new = shard.lock().is_ok_and(|mut shard| {
            shard.batches.admit(
                batch.hash(),
                receiver,
                batch.boot_id(),
                batch.sequence(),
                stamp.stamp_ms,
            )
        });
        if !new {
            // Not forwarded again, but a member that sent it still sent it (sharing's receipts).
            self.share(&origin, &Record::Batch(batch), stamp.stamp_ms);
            return false;
        }
        // A format this build cannot read is still forwarded raw; it just adds nothing here.
        let (batch, decoded) = match Stages::decode(batch, stamp) {
            Ok(decoded) => (decoded.batch().clone(), Some(decoded)),
            Err(undecodable) => (undecodable.batch, None),
        };
        let observations = decoded
            .as_ref()
            .map_or(0, |decoded| decoded.observations().len() as u64);
        if let Ok(mut shard) = shard.lock() {
            shard.stations.forwarded(
                receiver,
                batch.boot_id(),
                batch.sequence(),
                observations,
                stamp.stamp_ms,
            );
            if matches!(origin, Origin::Feeder(_)) {
                shard.stations.fed_by(&receiver, source);
            }
        }
        // The receiver is publishing, so its description is the last to be forgotten: one lock,
        // its shard's, for the mark and the cell to route by.
        let mut described = self.publishing(&receiver);
        // A feeder's description pushed out while it was not yet publishing comes back now that
        // it is, as one that is, before the batch: a subscriber is told who a receiver is first.
        if described.is_none()
            && let Origin::Feeder(Some(own)) = &origin
        {
            // On the worker that owns the receiver, stamped with its batch: offered to the hosted
            // MLAT here, before the batch, as a description of a receiver is offered.
            if self.keep_info(
                source,
                own.info.clone(),
                receiver,
                own.issued_ms,
                own.place,
                true,
            ) && let Some(mlat) = self.network.mlat()
            {
                mlat.offer_description(&own.info, stamp.stamp_ms);
            }
            described = self.publishing(&receiver);
        }
        let cell = described.flatten();
        if let Some(decoded) = &decoded {
            // Charged for what the decode holds, no more, until the epochs hold it.
            in_flight.shrink_to(decoded.footprint());
            let area = self.network.products.area_for(&receiver);
            self.stages
                .message()
                .route(producer, decoded, area, in_flight);
        }
        self.network.on_batch(decoded.as_ref(), stamp.stamp_ms);
        let record = Record::Batch(batch);
        self.share(&origin, &record, stamp.stamp_ms);
        self.fanout.publish(Item {
            source,
            record: Arc::new(record),
            cell,
            points: None,
            decoded,
            stamp_ms: stamp.stamp_ms,
        });
        true
    }

    /// The network duties see where a batch came from: a feeder's own is seeded into its area's
    /// sharing group by this relay, its origin; a member's is a group piece.
    fn share(&self, origin: &Origin, record: &Record, stamp_ms: u64) {
        match origin {
            Origin::Feeder(_) => self.network.originate(self, record, stamp_ms),
            Origin::Peer(asker) => self.network.from_peer(self, asker, record, stamp_ms),
            Origin::Elsewhere => {}
        }
    }

    /// Connection `source`, a feeder publishing as `receiver`, had a new batch forwarded.
    pub fn fed_by(&self, receiver: &PublicKey, source: u64) {
        if let Ok(mut shard) = self.raw[usize::from(raw_shard(receiver).0)].lock() {
            shard.stations.fed_by(receiver, source);
        }
    }

    /// Connection `source` of a feeder publishing as `receiver` ended.
    pub fn left(&self, receiver: &PublicKey, source: u64) {
        if let Ok(mut shard) = self.raw[usize::from(raw_shard(receiver).0)].lock() {
            shard.stations.left(receiver, source);
        }
    }

    /// Every receiver's report (`stations`), with what its newest description declares.
    pub fn stations(&self) -> StationsReport {
        let now_ms = now_ms();
        let mut reports: Vec<(PublicKey, StationReport)> = self
            .raw
            .iter()
            .filter_map(|shard| {
                shard
                    .lock()
                    .ok()
                    .map(|shard| shard.stations.reports(now_ms))
            })
            .flatten()
            .collect();
        reports.sort_by_key(|(key, _)| *key);
        let stations = match self.directory.lock() {
            Ok(directory) => reports
                .into_iter()
                .map(|(key, report)| described(report, directory.known.get(&key)))
                .collect(),
            Err(_) => reports.into_iter().map(|(_, report)| report).collect(),
        };
        StationsReport { now_ms, stations }
    }

    /// One receiver's report, or `None` when the relay holds none for it.
    pub fn station(&self, receiver: &PublicKey) -> Option<StationReport> {
        let report = self.raw[usize::from(raw_shard(receiver).0)]
            .lock()
            .ok()?
            .stations
            .report(receiver, now_ms())?;
        let directory = self.directory.lock().ok()?;
        Some(described(report, directory.known.get(receiver)))
    }

    /// Where `receiver`'s newest signed description places it: the finest cell, projected once
    /// when the description was kept. `None` when the relay holds no located description of it.
    pub fn point_of(&self, receiver: &PublicKey) -> Option<Region> {
        let directory = self.directory.lock().ok()?;
        directory.known.get(receiver).and_then(|known| known.cell)
    }

    /// Every receiver description the relay holds: what a duty that starts late (the hosted MLAT,
    /// when its areas change) is handed instead of keeping a copy of its own.
    pub fn descriptions(&self) -> Vec<ReceiverInfo> {
        let Ok(directory) = self.directory.lock() else {
            return Vec::new();
        };
        directory
            .known
            .values()
            .filter_map(|known| match &*known.record {
                Record::ReceiverInfo(info) => Some(info.clone()),
                _ => None,
            })
            .collect()
    }

    /// The newest description of `receiver` the relay holds, and when it was issued.
    pub fn description_of(&self, receiver: &PublicKey) -> Option<(Arc<Record>, u64)> {
        let directory = self.directory.lock().ok()?;
        directory
            .known
            .get(receiver)
            .map(|known| (Arc::clone(&known.record), known.issued_ms))
    }

    /// Whether the relay holds a description of `receiver`.
    pub fn describes(&self, receiver: &PublicKey) -> bool {
        self.receivers
            .shard(receiver)
            .lock()
            .is_ok_and(|shard| shard.held.get(receiver).is_some())
    }

    /// `receiver` is publishing: marked so in its shard, and its cell, `None` when it is not
    /// described.
    fn publishing(&self, receiver: &PublicKey) -> Option<Option<Region>> {
        let mut shard = self.receivers.shard(receiver).lock().ok()?;
        shard.held.touch(receiver);
        shard.held.get(receiver).copied()
    }

    /// Keeps a verified receiver description if it is the newest for its key, and forwards it,
    /// as `describe` does, charged from `Store::Ingest` (the relay's own, a test's). `place` is the
    /// location it declares, when this build can read it. `publishing` says the receiver has just
    /// had a batch forwarded, so the description is kept as one that is.
    pub fn publish_info(
        &self,
        source: u64,
        info: ReceiverInfo,
        receiver: PublicKey,
        issued_ms: u64,
        place: Option<Location>,
        publishing: bool,
    ) {
        let in_flight = self.in_flight_of(info.as_bytes().len());
        self.describe(Description {
            source,
            info,
            receiver,
            issued_ms,
            place,
            publishing,
            stamp: None,
            in_flight,
        });
    }

    /// Keeps a verified receiver description if it is the newest for its key and forwards it;
    /// kept, it is offered to the hosted MLAT through the ingest stage: on the worker that owns
    /// its receiver's raw shard, after the batches of that receiver handed in before it, stamped
    /// there as they are (by the trace's stamp, or the ingest clock), so the step it takes effect
    /// at is the trace's (`MlatHost::offer_description`). Its charge is let go once the host holds
    /// it.
    pub fn describe(&self, description: Description) {
        let Description {
            source,
            info,
            receiver,
            issued_ms,
            place,
            publishing,
            stamp,
            in_flight,
        } = description;
        let offered = info.clone();
        if !self.keep_info(source, info, receiver, issued_ms, place, publishing) {
            return;
        }
        let Some(mlat) = self.network.mlat().cloned() else {
            return;
        };
        let worker = self.stages.worker_of(raw_shard(&receiver));
        self.stages.run_stamped(
            worker,
            in_flight,
            stamp,
            Box::new(move |stamp, in_flight| {
                mlat.offer_description(&offered, stamp.stamp_ms);
                drop(in_flight);
            }),
        );
    }

    /// Keeps a verified receiver description if it is the newest for its key, and forwards it.
    /// Whether it was kept.
    fn keep_info(
        &self,
        source: u64,
        info: ReceiverInfo,
        receiver: PublicKey,
        issued_ms: u64,
        place: Option<Location>,
        publishing: bool,
    ) -> bool {
        let Ok(mut directory) = self.directory.lock() else {
            return false;
        };
        let newer = directory
            .known
            .get(&receiver)
            .is_none_or(|known| issued_ms > known.issued_ms);
        if !newer {
            return false;
        }
        let Ok(mut shard) = self.receivers.shard(&receiver).lock() else {
            return false;
        };
        // Projected once, here; every region test after is integer work.
        let cell = place.and_then(|place| Region::point(&place).ok());
        let bytes = info.as_bytes().len();
        let software = info.content().ok().map(|content| content.software);
        self.network.on_info(&info, now_ms());
        let record = Arc::new(Record::ReceiverInfo(info));
        let replaced = directory
            .known
            .get(&receiver)
            .map_or(0, |known| known.bytes);
        shard.bytes = shard.bytes.saturating_sub(replaced) + bytes;
        directory.insert(
            receiver,
            Known {
                issued_ms,
                record: Arc::clone(&record),
                cell,
                bytes,
                place,
                software,
            },
        );
        let forgotten = if publishing {
            shard.held.insert_active(receiver, cell)
        } else {
            shard.held.insert(receiver, cell)
        };
        // What the shard forgets, the directory forgets with it, and its bytes.
        let mut forget = |shard: &mut ReceiverShard, forgotten: &PublicKey| {
            let bytes = directory
                .known
                .get(forgotten)
                .map_or(0, |known| known.bytes);
            shard.bytes = shard.bytes.saturating_sub(bytes);
            directory.remove(forgotten);
        };
        if let Some(forgotten) = forgotten {
            forget(&mut shard, &forgotten);
        }
        // Held to bytes as well as count, forgetting in the same order.
        while shard.bytes > shard.max_bytes {
            let Some(forgotten) = shard.held.forget_first() else {
                break;
            };
            forget(&mut shard, &forgotten);
        }
        drop(shard);
        drop(directory);
        // A link joining reads its descriptions first and takes its place in the fan-out only once
        // it has sent them (see `subscribe`), so one changed in between reaches it at its
        // receiver's next description.
        self.fanout.publish(Item {
            source,
            record,
            cell,
            points: None,
            decoded: None,
            stamp_ms: self.now_ms(),
        });
        true
    }

    /// Forwards verified positions by `engine` if they are new (see `Forwarded`). True when they
    /// were.
    pub fn publish_positions(&self, source: u64, positions: Positions, engine: PublicKey) -> bool {
        let now_ms = self.now_ms();
        let new = self.positions.lock().is_ok_and(|mut forwarded| {
            forwarded.admit(
                positions.hash(),
                engine,
                positions.boot_id(),
                positions.sequence(),
                now_ms,
            )
        });
        if new {
            self.network.on_positions(&positions, self.now_ms());
            self.forward_positions(source, Record::Positions(positions));
        }
        new
    }

    /// Sends positions into the fan-out once every clock model they cite has gone out before them
    /// (one session carries a model before what cites it, but a record that reaches this relay
    /// rebuilt from parity, by a repair or over a link that died between them, may come first);
    /// held meanwhile, for `AWAITING_MS` at most, after which they go anyway (the relay forwards;
    /// it is the reader that cannot check them).
    fn forward_positions(&self, source: u64, record: Record) {
        let cited = cited_models(&record);
        let ready = self
            .clock_models
            .lock()
            .is_ok_and(|forwarded| cited.iter().all(|id| forwarded.seen.contains(id)));
        if ready {
            self.send_positions(source, record);
        } else if let Ok(mut awaiting) = self.awaiting.lock() {
            if awaiting.len() >= AWAITING_MAX
                && let Some(oldest) = awaiting.pop_front()
            {
                self.send_positions(oldest.source, oldest.record);
            }
            awaiting.push_back(Awaiting {
                source,
                record,
                cited,
                since: Instant::now(),
            });
        }
        self.release_awaiting();
    }

    /// Sends the held positions whose models have all gone out, or which waited too long.
    pub fn release_awaiting(&self) {
        let ready: Vec<Awaiting> = {
            let (Ok(mut awaiting), Ok(forwarded)) =
                (self.awaiting.lock(), self.clock_models.lock())
            else {
                return;
            };
            let (ready, held): (VecDeque<Awaiting>, VecDeque<Awaiting>) =
                awaiting.drain(..).partition(|one| {
                    one.since.elapsed() >= AWAITING_MS
                        || one.cited.iter().all(|id| forwarded.seen.contains(id))
                });
            *awaiting = held;
            ready.into_iter().collect()
        };
        for one in ready {
            self.send_positions(one.source, one.record);
        }
    }

    fn send_positions(&self, source: u64, record: Record) {
        let points = crate::network::points_of(&record);
        self.fanout.publish(Item {
            source,
            record: Arc::new(record),
            cell: None,
            points,
            decoded: None,
            stamp_ms: self.now_ms(),
        });
    }

    /// Forwards verified provisional positions by `engine` if they are new, as
    /// `publish_positions` does final ones but in a stream of their own, and only to whoever
    /// asked for them (`Streams::PROVISIONAL`). True when they were.
    pub fn publish_provisional(
        &self,
        source: u64,
        positions: Positions,
        engine: PublicKey,
    ) -> bool {
        let now_ms = self.now_ms();
        let new = self.provisional.lock().is_ok_and(|mut forwarded| {
            forwarded.admit(
                positions.hash(),
                engine,
                positions.boot_id(),
                positions.sequence(),
                now_ms,
            )
        });
        if new {
            self.network.on_positions(&positions, self.now_ms());
            self.forward_positions(source, Record::Provisional(positions));
        }
        new
    }

    /// Forwards a verified clock model manifest by `engine` if it is new: an id not seen, in its
    /// engine boot's window of sequences (see `Forwarded`). The parts held for it that it lists go
    /// out first, in index order, each from the connection it came from (`parts`). True when it
    /// was new.
    pub fn publish_clock_model(&self, source: u64, model: ClockModel, engine: PublicKey) -> bool {
        let now_ms = self.now_ms();
        let new = self.clock_models.lock().is_ok_and(|mut forwarded| {
            forwarded.admit(
                model.id(),
                engine,
                model.boot_id(),
                model.sequence(),
                now_ms,
            )
        });
        if new {
            // A manifest this build cannot read lists nothing: its parts are never forwarded.
            let hashes = model
                .manifest()
                .map(|manifest| manifest.parts)
                .unwrap_or_default();
            let ready = self
                .parts
                .lock()
                .map(|mut parts| parts.manifest(model.id(), hashes, Instant::now()))
                .unwrap_or_default();
            for (from, part) in ready {
                self.fanout.publish(Item {
                    source: from,
                    record: Arc::new(Record::ClockModelPart(part)),
                    cell: None,
                    points: None,
                    decoded: None,
                    stamp_ms: self.now_ms(),
                });
            }
            let record = Record::ClockModel(model);
            self.network.on_clock_model(&record, self.now_ms());
            let points = crate::network::points_of(&record);
            self.fanout.publish(Item {
                source,
                record: Arc::new(record),
                cell: None,
                points,
                decoded: None,
                stamp_ms: self.now_ms(),
            });
            // Positions held for this model go out after it.
            self.release_awaiting();
        }
        new
    }

    /// Takes a clock model part: held until its manifest, forwarded now if its manifest went out
    /// and lists it, or dropped (`parts`). True when it was forwarded now.
    pub fn publish_clock_model_part(&self, source: u64, part: ClockModelPart) -> bool {
        let forward = self
            .parts
            .lock()
            .ok()
            .and_then(|mut parts| parts.part(source, part, Instant::now()));
        let Some(part) = forward else {
            return false;
        };
        self.network
            .on_clock_model(&Record::ClockModelPart(part.clone()), self.now_ms());
        self.fanout.publish(Item {
            source,
            record: Arc::new(Record::ClockModelPart(part)),
            cell: None,
            points: None,
            decoded: None,
            stamp_ms: self.now_ms(),
        });
        true
    }

    /// Bytes of clock model parts held for their manifests.
    pub fn parts_held_bytes(&self) -> usize {
        self.parts.lock().map_or(0, |parts| parts.held_bytes())
    }

    /// Forwards a checked fault proof if its hash is new. True when it was.
    pub fn publish_fault_proof(&self, source: u64, proof: FaultProof) -> bool {
        let now_ms = self.now_ms();
        let new = self.fault_proofs.lock().is_ok_and(|mut seen| {
            seen.rotate(now_ms);
            let hash = proof.hash();
            let new = !seen.contains(&hash);
            if new {
                seen.insert(hash);
            }
            new
        });
        if new {
            self.fanout.publish(Item {
                source,
                record: Arc::new(Record::FaultProof(proof)),
                cell: None,
                points: None,
                decoded: None,
                stamp_ms: self.now_ms(),
            });
        }
        new
    }

    /// A place among the subscribers, with the known receiver descriptions `subscription` covers
    /// to send first, or `None` when the relay is serving as many subscribers as it will.
    ///
    /// The link joins the fan-out (`listen`) only once it has sent these, so its queue does not
    /// fill behind a large first send and let it go as fallen behind. A description that changes
    /// between this read and that join is not in either; it reaches the subscriber when its
    /// receiver next describes itself, which a feeder does every ten minutes
    /// (`INFO_EVERY` in `tally_feed`'s relays).
    pub fn subscribe(&self, subscription: &Subscription) -> Option<(Vec<Item>, Slot)> {
        let slot = Slot::take(&self.subscribers, self.max_subscribers)?;
        Some((self.infos_for(subscription), slot))
    }

    /// As `subscribe`, without a place among the subscribers: for an engine, which is another
    /// relay's MLAT taking its area's raw one hop (RFC-0174 §2.3), a duty of the network the
    /// subscriber cap was never meant to turn away. What it may take is bounded by its grant (the
    /// border band of the areas it solves), never by the cap.
    pub fn engine(&self, subscription: &Subscription) -> Vec<Item> {
        self.infos_for(subscription)
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
    pub fn listen(&self, source: u64, filter: Filter) -> Listener {
        self.fanout.listen(source, filter)
    }

    /// The ingest clock now.
    pub fn now_ms(&self) -> u64 {
        self.stages.now_ms()
    }

    /// Every ingest worker ticks at `stamp_ms`: everything stamped before it has been handed in,
    /// so the epochs before it close (`seal`).
    pub fn advance(&self, stamp_ms: u64) {
        self.stages.advance(stamp_ms);
    }

    /// Waits until every ingest worker has done what was handed to it before this call: every
    /// batch ingested before it is admitted, decoded, routed and offered to the duties.
    pub fn flush(&self) {
        self.stages.flush();
    }

    /// Time passed with nothing ingested: a hub whose stages run on the caller ticks by the
    /// ingest clock now, as an idle worker ticks itself (`ingest::TICK_MS`), so its epochs close
    /// whether or not batches flow. Called by the timed duties (`network::run`).
    pub fn idle(&self) {
        if self.stages.is_inline() {
            self.stages.advance(self.stages.now_ms());
        }
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

/// Unix milliseconds now, as the station reports state times.
/// Each subscriber's queue bounds: `BEHIND_MS` of inbound, and the bytes the budget gives the
/// fan-out (every admitted feeder's share: the queues share each record, so one queue may hold
/// all of it), at least `MIN_QUEUE_BYTES`.
fn queue_bounds(budget: &Budget) -> Bounds {
    Bounds {
        max_bytes: budget.store_bytes(Store::Fanout).max(MIN_QUEUE_BYTES),
        max_age_ms: BEHIND_MS,
    }
}

/// The fan-out, its queues bounded each by `queue_bounds` and together by the budget's gauge.
fn router(budget: &Budget) -> Router {
    Router::charged(queue_bounds(budget), budget.gauge(Store::Fanout))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A station's report with what its description, if held, declares.
fn described(mut report: StationReport, known: Option<&Known>) -> StationReport {
    if let Some(known) = known {
        report.location = known.place.map(Into::into);
        report.software = known.software.clone();
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::batch::ReceiverInfoContent;
    use tally_wire::{BatchContent, Clock, Identity, Observation};

    /// A bundle index a peer sent is passed on once, however often it comes back: three relays
    /// once passed one round a loop of their one-hop raw links for ever, thousands a second.
    #[test]
    fn a_bundle_index_that_comes_back_is_not_passed_on_again() -> Result<(), String> {
        let hub = Hub::new(8);
        let out = hub.listen(u64::MAX, Filter::Everything);
        let parent = Region::containing(
            &tally_wire::Location {
                lat_e7: 337_490_000,
                lon_e7: -843_880_000,
                alt_m: 0,
                precision_m: 0,
            },
            1,
        )
        .map_err(|error| error.to_string())?;
        let index = tally_wire::BundleIndex::sign(
            &Identity::generate().map_err(|error| error.to_string())?,
            &tally_wire::BundleIndexContent {
                parent,
                product: tally_wire::Streams::RAW,
                second: 100,
                children: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        for source in [7, 8, 7] {
            hub.publish_as(source, Record::BundleIndex(index.clone()));
        }
        let mut passed = 0;
        while out.try_recv().is_some() {
            passed += 1;
        }
        assert_eq!(passed, 1);
        Ok(())
    }

    #[test]
    fn a_record_is_forwarded_once_and_never_far_behind_its_stream() {
        let mut forwarded = Forwarded::new(Duration::from_secs(60));
        assert!(forwarded.admit([1; 32], "engine", 0, 100, 0));
        // The same hash again, by another path.
        assert!(!forwarded.admit([1; 32], "engine", 0, 100, 0));
        // Reordered a little: still forwarded.
        assert!(forwarded.admit([2; 32], "engine", 0, 100 - REORDER_ALLOWANCE + 1, 0));
        // Older than the allowance, with a hash never seen: a replay, dropped.
        assert!(!forwarded.admit([3; 32], "engine", 0, 100 - REORDER_ALLOWANCE, 0));
        // Another stream has its own sequence.
        assert!(forwarded.admit([3; 32], "other", 0, 0, 0));
    }

    #[test]
    fn a_replay_inside_the_reorder_allowance_is_dropped_after_its_hash_is_forgotten() {
        let mut forwarded = Forwarded::new(Duration::ZERO);
        assert!(forwarded.admit([1; 32], "receiver", 0, 10, 0));
        assert!(forwarded.admit([2; 32], "receiver", 0, 12, 0));
        // Reordered, never forwarded: still taken.
        assert!(forwarded.admit([3; 32], "receiver", 0, 11, 0));
        assert!(forwarded.admit([4; 32], "receiver", 0, 13, 0));
        assert!(!forwarded.seen.contains(&[1; 32]));
        // Its hash forgotten and only three sequences behind, it was still forwarded once.
        assert!(!forwarded.admit([1; 32], "receiver", 0, 10, 0));
        // Far ahead, the window starts again and the newest is taken once.
        assert!(forwarded.admit([5; 32], "receiver", 0, 1_000, 0));
        assert!(!forwarded.admit([6; 32], "receiver", 0, 1_000, 0));
        assert!(forwarded.admit([7; 32], "receiver", 0, 1_000 - REORDER_ALLOWANCE + 1, 0));
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
        hub.receivers = Receivers::new(1, CAP, DESCRIPTION_BYTES_HELD);
        let hub = Arc::new(hub);
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
        let receivers = hub.receivers.len();
        let directory = hub.directory.lock().map_err(|e| e.to_string())?.known.len();
        Ok((receivers, directory))
    }

    #[test]
    fn when_full_the_receiver_least_recently_active_is_forgotten() -> Result<(), String> {
        let mut hub = Hub::new(8);
        hub.receivers = Receivers::new(1, 2, DESCRIPTION_BYTES_HELD);
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
    fn the_deduplicated_stream_takes_each_message_once_across_receivers_when_its_epoch_closes()
    -> Result<(), String> {
        let clock = Arc::new(AtomicU64::new(10_100));
        let reading = Arc::clone(&clock);
        let hub = Arc::new(Hub::clocked(
            8,
            Arc::new(move || reading.load(Ordering::Relaxed)),
        ));
        for n in 0..4u64 {
            let (receiver, receiver_key) = key()?;
            // Every receiver hears messages 0..5; each also one of its own.
            let mut heard: Vec<Observation> = (0..5).map(observation).collect();
            heard.push(observation(100 + n as u8));
            assert!(hub.publish_batch(1, signed_batch(&receiver, 0, heard)?, receiver_key));
        }
        // The relay's own stream, signed as the relay: the batches it made since the last call.
        let relay = Identity::from_seed([77; 32]);
        hub.network().adopt_identity(relay.clone());
        let stream = || -> Result<Vec<Observation>, String> {
            let mut stream = Vec::new();
            for record in hub.network().products.tick(None) {
                if let Record::RelayBatch(batch) = record {
                    batch.verify_as_relay().map_err(|error| error.to_string())?;
                    assert_eq!(batch.receiver().ok(), Some(relay.public()));
                    stream.extend(batch.content().map_err(|e| e.to_string())?.observations);
                }
            }
            Ok(stream)
        };
        // The epoch is open: nothing yet.
        assert_eq!(stream()?.len(), 0);
        clock.store(11_000, Ordering::Relaxed);
        hub.advance(11_000);
        let stream = stream()?;
        let refused = hub.network().products.report().stream_refused;
        assert_eq!((stream.len(), refused), (5 + 4, 0));
        let mut data: Vec<Vec<u8>> = stream.iter().map(|o| o.data.clone()).collect();
        data.sort_unstable();
        data.dedup();
        assert_eq!(data.len(), 9);
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

    /// RFC-0181 invariant 2: the hashes' windows turn on the stamps they are shown, never on a
    /// clock of their own.
    #[test]
    fn the_hash_window_turns_on_stamps() {
        let mut seen = Seen::new(Duration::from_secs(1), 100);
        seen.rotate(10_000);
        seen.insert([1; 32]);
        seen.rotate(10_999);
        assert!(seen.contains(&[1; 32]));
        // A window on: kept a generation more, then forgotten.
        seen.rotate(11_000);
        assert!(seen.contains(&[1; 32]));
        seen.rotate(12_000);
        assert!(!seen.contains(&[1; 32]));
    }

    /// RFC-0181 §9: a batch handed in is charged to `Store::Ingest` until the epochs hold it.
    #[test]
    fn a_batch_is_charged_until_the_epochs_hold_it() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8));
        let (receiver, receiver_key) = key()?;
        let ingest = hub.budget().gauge(Store::Ingest);
        let epochs = hub.budget().gauge(Store::Epochs);
        assert!(hub.publish_batch(
            1,
            signed_batch(
                &receiver,
                0,
                vec![Observation {
                    format: b'2',
                    timestamp: 1,
                    signal: 0,
                    data: vec![0x5d; 7],
                }]
            )?,
            receiver_key
        ));
        assert_eq!(ingest.held(), 0);
        assert!(epochs.held() > 0);
        Ok(())
    }

    #[test]
    fn a_replay_is_dropped_after_its_hash_is_forgotten() {
        let mut forwarded = Forwarded::new(Duration::ZERO);
        assert!(forwarded.admit([1; 32], "engine", 0, 0, 0));
        assert!(forwarded.admit([2; 32], "engine", 0, 200, 0));
        assert!(forwarded.admit([4; 32], "engine", 0, 201, 0));
        // Two rotations later the first hash is gone, and only its sequence refuses it.
        assert!(!forwarded.seen.contains(&[1; 32]));
        assert!(!forwarded.admit([1; 32], "engine", 0, 0, 0));
    }

    #[test]
    fn descriptions_are_held_to_bytes_as_well_as_count() -> Result<(), String> {
        let mut hub = Hub::new(8);
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        let size = info.as_bytes().len();
        hub.receivers = Receivers::new(1, RECEIVERS_REMEMBERED, 3 * size);
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
            assert!(forwarded.admit(next(), stream, 0, 0, 0));
            assert!(forwarded.admit(next(), stream, 0, 1, 0));
        }
        // A new boot's first batch is remembered, so a replay of it is refused by sequence.
        assert!(forwarded.admit(next(), STREAMS, 0, 5, 0));
        assert!(forwarded.newest.get(&STREAMS).is_some());
        assert!(!forwarded.admit(next(), STREAMS, 0, 5, 0));
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
        assert!(forwarded.admit(next(), "honest", 0, 0, 0));
        assert!(forwarded.admit(next(), "honest", 0, 1, 0));
        // Strangers churning keys, each its own new author, many times the table's size; the
        // honest stream publishing only now and then.
        let strangers: Vec<String> = (0..20 * STREAMS).map(|n| format!("stranger {n}")).collect();
        for (n, stranger) in strangers.iter().enumerate() {
            assert!(forwarded.admit(next(), stranger.as_str(), 0, 0, 0));
            // Publishing once per half a table's worth of new authors.
            if n % (STREAMS / 2) == 0 {
                let sequence = 2 + (n / (STREAMS / 2)) as u64;
                assert!(forwarded.admit(next(), "honest", 0, sequence, 0));
            }
        }
        assert!(forwarded.newest.len() <= STREAMS);
        // Still remembered: a replay of an old sequence, under a hash never seen, is refused.
        assert!(!forwarded.admit(next(), "honest", 0, 1, 0));
    }

    /// RFC-0181 §9 against a churn of boots (the audit's 2.2): one author churning boot ids, each a
    /// new stream, in a table as small as a raw shard's, forgets only its own oldest boots. Every
    /// other author's window stays, however long the churn, so no replay into another stream is
    /// reopened.
    #[test]
    fn a_churn_of_one_authors_boots_forgets_only_its_own() {
        const AUTHORS: usize = 4;
        let mut forwarded = Forwarded::bounded(Duration::from_secs(3_600), AUTHORS, 1_000_000);
        let mut hashes = 0u32;
        let mut next = || {
            hashes += 1;
            let mut hash = [0; 32];
            hash[..4].copy_from_slice(&hashes.to_be_bytes());
            hash
        };
        for honest in 0..AUTHORS - 1 {
            assert!(forwarded.admit(next(), honest, 0, 0, 0));
            assert!(forwarded.admit(next(), honest, 0, 1, 0));
        }
        // The churning author starts after them, so it is the most recently active throughout.
        for boot in 0..10_000u64 {
            assert!(forwarded.admit(next(), AUTHORS, boot, 0, 0));
        }
        assert!(forwarded.streams() <= AUTHORS - 1 + BOOTS_PER_AUTHOR);
        for honest in 0..AUTHORS - 1 {
            // Still remembered: a replay under a hash never seen is refused by its sequence.
            assert!(
                !forwarded.admit(next(), honest, 0, 1, 0),
                "author {honest} forgotten"
            );
        }
        // Its own oldest boots are what it forgot: an old boot starts afresh.
        assert!(forwarded.admit(next(), AUTHORS, 0, 0, 0));
    }

    fn signed_positions(
        engine: &Identity,
        boot_id: u64,
        sequence: u64,
    ) -> Result<Positions, String> {
        Positions::sign_solutions(
            engine,
            &tally_wire::SolutionsContent {
                boot_id,
                sequence,
                issued_ms: 1,
                spec_version: 1,
                solutions: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())
    }

    #[test]
    fn provisional_positions_are_a_stream_of_their_own() -> Result<(), String> {
        let hub = Hub::new(8);
        let (engine, engine_key) = key()?;
        let provisional = |sequence: u64| {
            Positions::sign_provisional(
                &engine,
                &tally_wire::SolutionsContent {
                    boot_id: 1,
                    sequence,
                    issued_ms: 1,
                    spec_version: 1,
                    solutions: Vec::new(),
                },
            )
            .map_err(|error| error.to_string())
        };
        assert!(hub.publish_positions(1, signed_positions(&engine, 1, 500)?, engine_key));
        // Sequenced apart: 0 is new among the engine's provisionals, and only once.
        assert!(hub.publish_provisional(1, provisional(0)?, engine_key));
        assert!(!hub.publish_provisional(1, provisional(0)?, engine_key));
        assert!(hub.publish_provisional(1, provisional(1)?, engine_key));
        Ok(())
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

    fn signed_clock_model(
        engine: &Identity,
        boot_id: u64,
        sequence: u64,
    ) -> Result<tally_wire::ClockModel, String> {
        tally_wire::ClockModel::sign(
            engine,
            &tally_wire::ClockModelContent {
                boot_id,
                sequence,
                issued_ms: 1,
                spec_version: 1,
                inputs: [0; 32],
                model: sequence.to_be_bytes().to_vec(),
            },
        )
        .map(|signed| signed.manifest)
        .map_err(|error| error.to_string())
    }

    #[test]
    fn a_large_models_parts_go_out_ahead_of_its_manifest_and_forged_ones_never()
    -> Result<(), String> {
        let hub = Hub::new(8);
        let out = hub.listen(u64::MAX, Filter::Everything);
        let (engine, engine_key) = key()?;
        let model: Vec<u8> = (0..3 * tally_wire::clock_model::PART_LEN as u64)
            .map(|at| (at.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let signed = tally_wire::ClockModel::sign(
            &engine,
            &tally_wire::ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1,
                spec_version: 1,
                inputs: [0; 32],
                model,
            },
        )
        .map_err(|error| error.to_string())?;
        let id = signed.manifest.id();
        let forged = ClockModelPart::new(id, 1, b"forged");
        // Reordered, repeated and with a forgery: none goes out before the manifest.
        for part in [
            &signed.parts[2],
            &forged,
            &signed.parts[0],
            &signed.parts[2],
        ] {
            assert!(!hub.publish_clock_model_part(5, part.clone()));
        }
        assert!(out.try_recv().is_none());
        assert!(hub.publish_clock_model(6, signed.manifest.clone(), engine_key));
        // The late part goes out on its own, once.
        assert!(hub.publish_clock_model_part(7, signed.parts[1].clone()));
        assert!(!hub.publish_clock_model_part(8, signed.parts[1].clone()));
        let mut heard = Vec::new();
        while let Some(item) = out.try_recv() {
            heard.push((item.source, (*item.record).clone()));
        }
        assert_eq!(
            heard,
            vec![
                (5, Record::ClockModelPart(signed.parts[0].clone())),
                (5, Record::ClockModelPart(signed.parts[2].clone())),
                (6, Record::ClockModel(signed.manifest.clone())),
                (7, Record::ClockModelPart(signed.parts[1].clone())),
            ]
        );
        assert_eq!(hub.parts_held_bytes(), 0);
        Ok(())
    }

    #[test]
    fn clock_models_are_forwarded_once_per_id_and_windowed_apart_from_positions()
    -> Result<(), String> {
        let hub = Hub::new(8);
        let (engine, engine_key) = key()?;
        let model = signed_clock_model(&engine, 1, 1_000)?;
        assert!(hub.publish_clock_model(1, model.clone(), engine_key));
        assert!(!hub.publish_clock_model(2, model, engine_key));
        // Far behind its boot's newest: a replay.
        assert!(!hub.publish_clock_model(1, signed_clock_model(&engine, 1, 0)?, engine_key));
        // The engine's positions keep their own sequence: 0 is new there.
        assert!(hub.publish_positions(1, signed_positions(&engine, 1, 0)?, engine_key));
        assert!(hub.publish_clock_model(1, signed_clock_model(&engine, 2, 0)?, engine_key));
        Ok(())
    }

    /// Positions that reach the hub before the clock model they cite (rebuilt from parity, by a
    /// repair, over a link that died between them) wait for it, and go out after it.
    #[test]
    fn positions_go_out_after_the_model_they_cite() -> Result<(), String> {
        let hub = Hub::new(8);
        let out = hub.listen(u64::MAX, Filter::Everything);
        let (engine, engine_key) = key()?;
        let model = signed_clock_model(&engine, 1, 0)?;
        let receivers: Vec<PublicKey> = throwaways(4);
        let solution = tally_wire::Solution {
            address: 0x00ab_cdef,
            transmitted: tally_wire::TransmitTime::new(1_000, 0).map_err(|e| e.to_string())?,
            lat_e7: 337_000_000,
            lon_e7: -843_000_000,
            alt_hae_mm: Some(9_000_000),
            covariance: tally_wire::EnuCovariance {
                xx: 900.0,
                xy: 0.0,
                xz: 0.0,
                yy: 900.0,
                yz: 0.0,
                zz: 900.0,
            },
            clock_model: model.id(),
            addressed: tally_wire::AddressedCitation::default(),
            observations: tally_wire::ObservationSet::new(
                vec![0x5d, 0xab, 0xcd, 0xef, 0, 0, 0],
                receivers
                    .iter()
                    .map(|receiver| tally_wire::Reception {
                        receiver: *receiver,
                        epoch: 0,
                        counter: 1,
                    })
                    .collect(),
            )
            .map_err(|e| e.to_string())?,
        };
        let positions = Positions::sign_solutions(
            &engine,
            &tally_wire::SolutionsContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1,
                spec_version: 1,
                solutions: vec![solution],
            },
        )
        .map_err(|e| e.to_string())?;
        assert!(hub.publish_positions(1, positions.clone(), engine_key));
        assert!(
            out.try_recv().is_none(),
            "positions went out before their model"
        );
        assert!(hub.publish_clock_model(2, model.clone(), engine_key));
        let mut heard = Vec::new();
        while let Some(item) = out.try_recv() {
            heard.push((*item.record).clone());
        }
        assert_eq!(
            heard,
            vec![Record::ClockModel(model), Record::Positions(positions)]
        );
        Ok(())
    }

    #[test]
    fn a_fault_proof_is_forwarded_once() -> Result<(), String> {
        let hub = Hub::new(8);
        let (engine, _) = key()?;
        let a = signed_positions(&engine, 1, 0)?;
        let b = signed_positions(&engine, 1, 1)?;
        let proof = tally_wire::FaultProof::new(&a, 0, &b, 0).map_err(|error| error.to_string())?;
        assert!(hub.publish_fault_proof(1, proof.clone()));
        assert!(!hub.publish_fault_proof(2, proof));
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
        // One shard of them all, so every one is held.
        let mut hub = Hub::new(8);
        hub.receivers = Receivers::new(1, RECEIVERS, DESCRIPTION_BYTES_HELD);
        let hub = Arc::new(hub);
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
        let batch_lock = hub.receivers.shards[0].lock().map_err(|e| e.to_string())?;
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
        // One shard of them all: the order of forgetting, apart from the sharding.
        let mut hub = Hub::new(8);
        hub.receivers = Receivers::new(1, RECEIVERS_REMEMBERED, DESCRIPTION_BYTES_HELD);
        let hub = Arc::new(hub);
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        // Every receiver held has had batches forwarded.
        // Then more new keys than the table holds, so only its own activity can keep it.
        let full = throwaways(2 * RECEIVERS_REMEMBERED + 1_000);
        let (publishing, churn) = full.split_at(RECEIVERS_REMEMBERED);
        for receiver in publishing {
            hub.publish_info(2, info.clone(), *receiver, 1, None, false);
            hub.receivers
                .shard(receiver)
                .lock()
                .map_err(|e| e.to_string())?
                .held
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
        let out = hub.listen(u64::MAX, Filter::Everything);
        // New keys keep arriving; it publishes once per hundred of them, and stays.
        for (n, receiver) in churn.iter().enumerate() {
            if n % 100 == 0 {
                let sequence = u64::try_from(n / 100).map_err(|e| e.to_string())?;
                assert!(hub.publish_batch(2, signed_batch(&new, sequence, Vec::new())?, new_key));
                let routed = out.try_recv().ok_or("nothing routed")?;
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
}
