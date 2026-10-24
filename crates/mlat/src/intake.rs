//! The receiver side of an engine (RFC-0171 §3.8.1, RFC-0181 §5): which receivers take part, the
//! sequences each has used, their open raw (`tally_mlat_solver::held::Open`) and what each batch
//! says to provisional solving (`provisional::notes_of`). Everything here belongs to one receiver,
//! so it splits by receiver: an engine that holds its own raw keeps one [`Intake`] (`Engine::new`),
//! and a relay keeps one per raw shard, each touched by the ingest worker that owns the shard's
//! receivers, while the engine it feeds (`Engine::hosted`) holds only the sealed bins. One
//! receiver's word decides its part whichever intake holds it, so the same raw split any way
//! seals to the same bins (`held::Bin::seal_from`) and solves to the same bytes.
//!
//! - A receiver takes part on its own signed word only: its newest site-bearing record
//!   ([`SiteRecord`]: its `ReceiverSite`, or an old feeder's format 1 `ReceiverInfo`) verifies,
//!   places it inside the engine's regions, and names a clock the solver specification knows with
//!   a location no coarser than it allows (`tally_mlat_solver::obs::MAX_SITE_PRECISION_M`). A
//!   format 2 `ReceiverInfo` carries no site and places nobody: an engine never takes a site
//!   from anything a client can read. The record also gives the receiver's site id (what a model
//!   names it by) and reception key (what its receptions are tagged under for clients), carried
//!   with its site ([`Sited`]).
//! - A batch is used once: from a receiver that takes part, with a (boot, sequence) not already used
//!   and not too far behind that boot's newest (§3.1).
//! - **Room is shared, refusal is whole, and neither depends on order** (RFC-0181 §9). The
//!   receivers seated across every intake of one engine are bounded by one count ([`Seats`],
//!   `Capacity::receivers`), and who is seated is a function of who is described: the best ranked
//!   (taking part first, then the key-hash rank, [`draw`]), whatever order they came in
//!   and whichever intake took them. A receiver outranked is refused whole (none of its raw held)
//!   and counted, and one that loses its seat to a better ranked one is let go whole. A receiver's
//!   raw of a bin beyond its share is refused whole (`held::Limits`); the holder's bytes are
//!   checked on each whole bin as it is sealed (`held::Bin::seal_within`), never on arrival.
//! - **The rank is the receiver's own word, the same on every relay** (RFC-0181 §9, §10). Taking
//!   part is the bar. Among the receivers over it the seat goes by a hash of the receiver's key
//!   under a fixed fleet-wide seed ([`draw`]), so two relays holding one area seat the same
//!   receivers whatever order the descriptions reached each, and an overloaded host's cut
//!   ([`Seats::set_cutoffs`], a rank threshold published by stamp) leaves the same receivers on
//!   every relay, whatever each has described or has seats for: before, the
//!   seed was a secret each process drew, which no two relays shared, so the receivers one relay
//!   refused another solved and their products could not match. What the secret bought was that a
//!   key could not be ground to outrank honest ones; a key is not free here any more than a seat
//!   is (every feeder is admitted at its connection, per credit and network group, before it can
//!   describe at all, RFC-0181 §5), so grinding costs an admitted connection a rank, and a relay
//!   that wants the rank unpredictable gives all its peers one seed ([`Seats::keyed`]). Neither
//!   The seats of one declared place (a cell, [`SEAT_CELL_RESOLUTION`]) are shared out: at most
//!   [`SEATS_PER_CELL`] of a cell's receivers hold one, the best ranked of them, so a grinder
//!   holding many connections from one place takes no more than a cell's share (the network group
//!   of a connection is a fact only the relay holding it has, which two relays cannot share, so the
//!   share is read from the receiver's own signed place). Neither
//!   tenure nor standing serves instead: tenure (first come) rewards whoever floods first and is
//!   decided by arrival order, which RFC-0181 §9 forbids; receiver standing (RFC-0174 §2.12) is
//!   earned only by receptions the seated engine solves, so ranking by it would keep a receiver
//!   once seated seated forever and one never seated out, and it is a bar the merge applies to
//!   solutions, not an order of who may be heard.
//! - **A batch before its receiver's description** waits for it ([`Intake::hold_orphan`]): a batch
//!   can reach a holder before its receiver's description (a repair, a rebuild from parity, a link
//!   that died between them, or a description that takes effect at the next step), and is forwarded
//!   once, so one turned away is lost to MLAT. It is held, within `ORPHANS_PER_RECEIVER` and the
//!   holder's bytes a receiver (its oldest going first) and its bound on receivers, for
//!   `ORPHAN_MS` of its holder's steps ([`Intake::expire_orphans`]), and taken when the
//!   description comes ([`Intake::take_orphans`]), by whichever holder: an engine holding its own
//!   raw and a relay's raw shards alike ([`Orphans`], one for all of a relay's shards). Who is
//!   held for room is decided by rank, never by arrival: past the bound on receivers the worst
//!   drawn ([`Seats::draw_of`]) is let go for a better drawn one, so the receivers held are the
//!   best drawn of those that came, in any order; and the bounds are the holder's whole room for
//!   them, so nothing else (a store shared with other holders) ever refuses one by when it came.
//! - **Late by the stamp** (`held::Closing`): an intake whose raw arrives on threads of its own
//!   while its holder steps on another ([`Intake::closing`], a relay's raw shards) refuses as late
//!   the raw stamped at or after the step that takes its bin, so a batch that raced ahead of that
//!   step is late exactly as one that came after it.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tally_mlat_solver::held::{Closing, Fragment, Limits, Open};
use tally_mlat_solver::obs::MAX_SITE_PRECISION_M;
use tally_mlat_solver::{Site, Timebase};
use tally_wire::{
    Clock, Decoded, FingerprintKey, Location, PublicKey, ReceiverInfo, ReceiverSite, ReceptionKey,
    Record, Region, Regions, SiteId, WireError,
};

use crate::engine::{Dropped, Ingested};
use crate::provisional::{Note, notes_of};
use tally_wire::clocks::{Moment, Mono};
use tally_wire::footprint::{Deque, Tree};

/// How far behind a boot's newest sequence a batch may still arrive (two relays, or one relay's
/// reordering) and be used; anything older is a replay or too late to matter.
const REORDER: u64 = 64;
/// Boots remembered per receiver, most recent first. A receiver that restarts more often than
/// this within one window only weakens its own replay protection.
const BOOTS_PER_RECEIVER: usize = 8;
/// Batches held for one receiver not yet described, at most (module docs): the oldest goes first.
pub const ORPHANS_PER_RECEIVER: usize = 64;
/// Receivers whose batches an intake holds waiting for a description, at most, unless its holder
/// says otherwise ([`Orphans::new`]): past it the worst drawn is let go, counted.
pub const ORPHAN_RECEIVERS: usize = 4_096;
/// How long, by its holder's steps, a batch waits for its receiver's description: as long as what
/// it says to provisional solving can still be weighed in time and its raw is not yet late (a bin's
/// settling and a step). A description later than that is not coming by the same way.
pub const ORPHAN_MS: u64 = 3_000;

/// A batch waiting for its receiver's description, stamped when it came.
struct Orphan {
    batch: Arc<Decoded>,
}

/// A receiver's batches waiting, oldest first.
type Waiting = Deque<Orphan>;

/// A receiver's place in what is held, as planned ([`Tree::bytes_per_entry`]).
const ORPHAN_PLACE_BYTES: usize = Tree::<PublicKey, Waiting>::bytes_per_entry();

/// What a receiver holding `batches` waiting for its description is held to at most within its
/// bytes ([`Orphans::new`]): their deque, which keeps a quarter again what it holds, and its place.
/// Not the decodes they keep alive, which a relay charges once for their life, however many hold
/// them (`tally_relay::budget::Store::Decoded`); the room bounds how many it holds, and
/// `ORPHAN_MS` how long.
pub const fn orphans_planned(batches: usize) -> usize {
    Waiting::bytes_at_most(batches) + ORPHAN_PLACE_BYTES
}

/// What one more batch waiting adds to [`orphans_planned`], at most: its slot, a quarter again.
pub const ORPHAN_PLANNED_BYTES: usize = tally_wire::footprint::vec::<Orphan>(1) * 5 / 4;

/// What holding batches for their descriptions allocates whatever it holds, as planned: the root
/// of its tree.
pub const ORPHANS_ROOT_BYTES: usize = Tree::<PublicKey, Waiting>::bytes_planned(0);

/// What holding, expiring or taking batches waiting for a description let go.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Orphaned {
    /// Dropped for room: beyond `ORPHANS_PER_RECEIVER` or the intake's bytes a receiver (its
    /// oldest), or beyond the intake's receivers (the worst drawn).
    pub dropped: u64,
    /// Expired: waited `ORPHAN_MS` and no description came.
    pub expired: u64,
}

/// A receiver's site-bearing record: the one thing an engine places a receiver by (module docs).
/// Relay-only, both kinds (`Record::carries_site`): a new feeder's `ReceiverSite`, or an old
/// feeder's format 1 `ReceiverInfo`. A format 2 `ReceiverInfo` is no `SiteRecord` ([`Self::of`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteRecord {
    Site(ReceiverSite),
    /// A `ReceiverInfo` that carries a site (format 1, or a format this build cannot read, which it
    /// then ignores).
    Info(ReceiverInfo),
}

/// What a site-bearing record says, as an engine reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiteContent {
    pub issued_ms: u64,
    /// `None` for an old feeder that declared no location.
    pub location: Option<Location>,
    pub clock: Clock,
}

impl SiteRecord {
    /// The site-bearing record `record` is, if it is one: a `ReceiverSite`, or a `ReceiverInfo`
    /// that carries a site. A format 2 description places nobody.
    pub fn of(record: &Record) -> Option<Self> {
        match record {
            Record::ReceiverSite(site) => Some(Self::Site(site.clone())),
            Record::ReceiverInfo(info) => Self::info(info.clone()),
            _ => None,
        }
    }

    /// `info` as a site-bearing record, if it carries a site.
    pub fn info(info: ReceiverInfo) -> Option<Self> {
        info.carries_site().then_some(Self::Info(info))
    }

    /// The record as the wire carries it (relay-only).
    pub fn record(&self) -> Record {
        match self {
            Self::Site(site) => Record::ReceiverSite(site.clone()),
            Self::Info(info) => Record::ReceiverInfo(info.clone()),
        }
    }

    pub fn receiver(&self) -> Result<PublicKey, WireError> {
        match self {
            Self::Site(site) => site.receiver(),
            Self::Info(info) => info.receiver(),
        }
    }

    pub fn verify(&self) -> Result<(), WireError> {
        match self {
            Self::Site(site) => site.verify(),
            Self::Info(info) => info.verify(),
        }
    }

    /// Its signed bytes: what its site id and reception key are of.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Site(site) => site.as_bytes(),
            Self::Info(info) => info.as_bytes(),
        }
    }

    /// What it says, in a format this build reads.
    pub fn content(&self) -> Result<SiteContent, WireError> {
        match self {
            Self::Site(site) => site.content().map(|content| SiteContent {
                issued_ms: content.issued_ms,
                location: Some(content.location),
                clock: content.clock,
            }),
            Self::Info(info) => info.content().map(|content| SiteContent {
                issued_ms: content.issued_ms,
                location: content.location,
                clock: content.clock,
            }),
        }
    }

    /// The reference a model names the receiver by while this record is current.
    pub fn site_id(&self) -> SiteId {
        SiteId::of_signed(self.as_bytes())
    }

    /// What the receiver's receptions are tagged under while this record is current.
    pub fn reception_key(&self) -> ReceptionKey {
        ReceptionKey::of_signed(self.as_bytes())
    }
}

/// A receiver taking part: its site, and the reception key of the record that placed it (never
/// on any wire), which its receptions are tagged under in what a client is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sited {
    pub site: Site,
    pub key: ReceptionKey,
}

/// Receivers' site-bearing records taking effect at one step, in the order they are applied (a
/// relay's hosted MLAT and the reference drive alike, `replay`): of each receiver only the newest
/// it signed (by `issued_ms`, then bytes), which is what it says as of the step, whatever order
/// they came in and however many came; then by stamp, then by key. So a receiver re-signing within
/// one step holds one record there, and an older one never applies after a newer one.
pub fn taking_effect(
    descriptions: impl IntoIterator<Item = (u64, SiteRecord)>,
) -> Vec<(u64, SiteRecord)> {
    let mut newest: BTreeMap<Vec<u8>, (u64, SiteRecord)> = BTreeMap::new();
    for (stamp_ms, record) in descriptions {
        let key = record
            .receiver()
            .map(|key| key.as_bytes().to_vec())
            .unwrap_or_else(|_| record.as_bytes().to_vec());
        let replace = newest
            .get(&key)
            .is_none_or(|(_, held)| signed_order(held) < signed_order(&record));
        if replace {
            newest.insert(key, (stamp_ms, record));
        }
    }
    let mut due: Vec<(u64, SiteRecord)> = newest.into_values().collect();
    due.sort_by_cached_key(|(stamp_ms, record)| {
        (
            *stamp_ms,
            record.receiver().ok().map(|key| *key.as_bytes()),
            record.as_bytes().to_vec(),
        )
    });
    due
}

/// Which of two site-bearing records of one receiver is the newer: what it signed later
/// (`issued_ms`), then its bytes, so the order is total whichever kinds the two are.
pub fn signed_order(record: &SiteRecord) -> (u64, &[u8]) {
    (
        record.content().map_or(0, |content| content.issued_ms),
        record.as_bytes(),
    )
}

/// Batches waiting for their receivers' descriptions (module docs): at most `receivers` receivers,
/// at most `ORPHANS_PER_RECEIVER` and `bytes_per_receiver` of each. Who is held is decided by rank,
/// never by arrival: the receivers held are the best drawn ([`Seats::draw_of`]) of those that came,
/// each its newest that fit, in any order. So its bounds are its holder's whole room for them: no
/// store shared with anything else ever refuses one by when it came. An engine holding its own raw
/// keeps one in its [`Intake`]; a holder that splits its receivers over many intakes (a relay's raw
/// shards) keeps one for all of them, so the rank is decided across all.
pub struct Orphans {
    seats: Arc<Seats>,
    receivers: usize,
    bytes_per_receiver: usize,
    held: Tree<PublicKey, Waiting>,
    /// What the receivers' deques allocate together.
    lists: usize,
}

impl Orphans {
    /// At most `receivers` receivers, each held to `bytes_per_receiver` ([`orphans_planned`]).
    pub fn new(seats: Arc<Seats>, receivers: usize, bytes_per_receiver: usize) -> Self {
        Self {
            seats,
            receivers,
            bytes_per_receiver,
            held: Tree::new(),
            lists: 0,
        }
    }

    /// Its room is now `bytes` in all: its tree's root, and the rest split evenly over its
    /// receivers. A holder whose room is resized (a relay's `Orphans` store) says so before each
    /// hold. What it holds past a smaller room is let go as the next batches of each receiver come.
    pub fn set_room(&mut self, bytes: usize) {
        self.bytes_per_receiver = bytes.saturating_sub(ORPHANS_ROOT_BYTES) / self.receivers.max(1);
    }

    /// What it allocates now: its tree and its receivers' deques. Not the decodes the batches keep
    /// alive. Within its room ([`Orphans::set_room`]) whatever it holds, so a holder charging it
    /// this, grown before each hold ([`Orphans::hold`]), charges what it allocates.
    pub fn bytes(&self) -> usize {
        self.held.bytes() + self.lists
    }

    /// Holds `batch`, by its own stamp, until its receiver's description comes or `ORPHAN_MS` of
    /// steps pass on the monotonic clock; `grow` is asked, once room for it is made, whether its holder can charge what
    /// it then allocates in all ([`Orphans::bytes`] once held, what was let go for it gone): false
    /// drops it, counted. The receiver's oldest go first beyond
    /// `ORPHANS_PER_RECEIVER` or its bytes; beyond the receivers the worst drawn is let go whole
    /// for a better drawn one, and a worse drawn one is not held: each batch counted. So the
    /// receivers held are the best drawn of those that came, whatever their order, and nothing is
    /// charged past its room.
    pub fn hold(&mut self, batch: &Arc<Decoded>, grow: impl FnOnce(usize) -> bool) -> Orphaned {
        let mut orphaned = Orphaned::default();
        let key = batch.receiver();
        let most = self.bytes_per_receiver;
        if Waiting::new().growth() + ORPHAN_PLACE_BYTES > most || self.receivers == 0 {
            orphaned.dropped += 1;
            return orphaned;
        }
        if !self.held.contains_key(&key) && self.held.len() >= self.receivers {
            let worst = self
                .held
                .keys()
                .map(|held| (self.seats.draw_of(held), *held))
                .max();
            match worst {
                Some(worst) if (self.seats.draw_of(&key), key) < worst => {
                    if let Some(gone) = self.held.remove(&worst.1) {
                        self.lists -= gone.bytes();
                        orphaned.dropped += gone.len() as u64;
                    }
                }
                _ => {
                    orphaned.dropped += 1;
                    return orphaned;
                }
            }
        }
        let mut waiting = self.held.remove(&key).unwrap_or_default();
        self.lists -= waiting.bytes();
        // Its oldest go first, for its newest: within its count, and within its bytes with the
        // newest's slot.
        while waiting.len() >= ORPHANS_PER_RECEIVER
            || waiting.bytes() + waiting.growth() + ORPHAN_PLACE_BYTES > most
        {
            if waiting.pop_front().is_none() {
                break;
            }
            orphaned.dropped += 1;
        }
        // What it allocates in all once it holds it, charged by the holder first: what is held
        // now (after what was let go for it), its slot, and its receiver's place.
        let total = Tree::<PublicKey, Waiting>::bytes_at(self.held.len() + 1)
            + self.lists
            + waiting.bytes()
            + waiting.growth();
        if grow(total) {
            waiting.push_back(Orphan {
                batch: Arc::clone(batch),
            });
        } else {
            orphaned.dropped += 1;
        }
        if !waiting.is_empty() {
            self.lists += waiting.bytes();
            self.held.insert(key, waiting);
        }
        orphaned
    }

    /// Lets go every batch that has waited `ORPHAN_MS` by the step at `now` on the monotonic
    /// clock its stamps are of.
    pub fn expire(&mut self, now: Mono) -> Orphaned {
        let mut orphaned = Orphaned::default();
        let mut lists = 0;
        self.held.retain(|_, waiting| {
            let before = waiting.len();
            waiting.retain(|orphan| {
                orphan
                    .batch
                    .mono()
                    .later(tally_wire::budget::policy::<_, ORPHAN_MS>())
                    > now
            });
            orphaned.expired += (before - waiting.len()) as u64;
            if waiting.is_empty() {
                false
            } else {
                lists += waiting.bytes();
                true
            }
        });
        self.lists = lists;
        orphaned
    }

    /// The batches that waited for `receiver`'s description, oldest first, each with its own
    /// stamp: for their holder to take now that it is described (their holds let go).
    pub fn take(&mut self, receiver: &PublicKey) -> Vec<Arc<Decoded>> {
        self.held
            .remove(receiver)
            .map(|mut waiting| {
                self.lists -= waiting.bytes();
                waiting
                    .take()
                    .into_iter()
                    .map(|orphan| orphan.batch)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Batches held.
    pub fn len(&self) -> usize {
        self.held.values().map(|waiting| waiting.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Lets every batch go (the engine they waited for went).
    pub fn clear(&mut self) {
        self.held.clear();
        self.lists = 0;
    }
}

/// Where a described receiver stands for room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// It has a seat: it takes part if its own word places it inside the engine's regions.
    Seated,
    /// Described, but outranked for a seat: it takes no part, and is seated when it ranks among
    /// the best again.
    Waiting,
    /// Outranked even among the waiting: forgotten (its description too).
    Gone,
}

/// The domain of the seat draw (`tally_wire::decoded::keyed`).
const SEAT_DOMAIN: u8 = tally_wire::decoded::keyed::SEAT_DRAW;

/// The seed of the seat draw every relay shares (module docs): a constant, so the same receivers
/// rank the same on every relay.
const FLEET_SEED: [u8; 32] = *b"tally.mlat.seat.rank.fleet.v1...";

/// The fleet-wide key of the seat draw: what [`Seats::new`] ranks by.
pub fn fleet_key() -> FingerprintKey {
    FingerprintKey::from_bytes(FLEET_SEED)
}

/// A receiver's draw for a seat (module docs): a keyed hash of its key under `secret`, the same for
/// every intake of one engine.
pub fn draw_under(secret: &FingerprintKey, key: &PublicKey) -> u128 {
    secret.fingerprint(SEAT_DOMAIN, key.as_bytes())
}

/// [`draw_under`] the fleet's seed: what [`Seats::new`] ranks by, the same on every relay.
pub fn draw(key: &PublicKey) -> u128 {
    draw_under(&fleet_key(), key)
}

/// What decides who is seated: receivers that take part before those that do not, then by their
/// draw (module docs), then by key (two draws of 128 bits never meet in practice; the key makes
/// the order total). A receiver's rank is its own word and the relay's secret, never when it came.
/// `cell` (its declared place, [`SEAT_CELL_RESOLUTION`], 0 for none) is what the cut and the share
/// of a cell are read from; it follows the key, so it never changes the order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    idle: bool,
    draw: u128,
    key: PublicKey,
    cell: u64,
}

/// The cell a receiver's declared place is held at ([`SEAT_CELL_RESOLUTION`]), if it declared one.
fn seat_cell(location: Option<Location>) -> Option<Region> {
    location.and_then(|location| Region::containing(&location, SEAT_CELL_RESOLUTION).ok())
}

/// The finest cell a receiver's declared place is held at for its share of the seats
/// ([`SEATS_PER_CELL`]): about 36 km², a city's block of towns.
pub const SEAT_CELL_RESOLUTION: u8 = 6;

/// The most seats the receivers of one cell hold. A seat is for geometry, and receivers within a
/// few kilometres of one another add nearly none to the solution of the next, where a grinder
/// holding many connections from one place would otherwise take every seat its keys outrank
/// (RFC-0181 §10, grinding). The receivers beyond it in a cell, by rank, stay described, waiting;
/// their raw still flows. It is a function of the receivers described alone (their own word), so
/// every relay holding them agrees; the network group of a connection is a fact only the relay
/// holding it has, which two relays cannot share.
pub const SEATS_PER_CELL: usize = 8;

/// The best ranked receivers a cut can never unseat: a cut asks for fewer receivers, never none,
/// so one signer cannot stop a relay's MLAT.
pub const CUT_FLOOR_SEATS: usize = 8;

/// The finest resolution a cut names (an area, `tally_wire::rendezvous::AREA_RESOLUTION`).
const CUT_RESOLUTION: u8 = tally_wire::rendezvous::AREA_RESOLUTION;

/// The rank thresholds cuts leave standing: per area cell, the draw a receiver in it must be
/// below to be solved. Applied to every receiver whose cell lies in a named area.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Cutoffs {
    below: HashMap<u64, u128>,
    /// Bit `r` set: some cut names a cell of resolution `r`.
    resolutions: u16,
}

impl Cutoffs {
    fn of(cuts: impl IntoIterator<Item = (Region, u128)>) -> Self {
        let mut cutoffs = Self::default();
        for (area, below) in cuts {
            if below == u128::MAX || area.resolution() > CUT_RESOLUTION {
                continue;
            }
            let entry = cutoffs.below.entry(area.as_u64()).or_insert(below);
            *entry = (*entry).min(below);
            cutoffs.resolutions |= 1 << area.resolution();
        }
        cutoffs
    }

    /// The draw a receiver of `cell` must be below: the least of the cuts naming a cell it lies
    /// in; none (everything) where no cut does.
    fn threshold(&self, cell: u64) -> u128 {
        if self.below.is_empty() || cell == 0 {
            return u128::MAX;
        }
        let Ok(cell) = Region::from_u64(cell) else {
            return u128::MAX;
        };
        (0..=CUT_RESOLUTION)
            .filter(|resolution| self.resolutions & (1 << resolution) != 0)
            .filter_map(|resolution| cell.ancestor(resolution))
            .filter_map(|ancestor| self.below.get(&ancestor.as_u64()).copied())
            .min()
            .unwrap_or(u128::MAX)
    }
}

#[derive(Default)]
struct Places {
    seated: BTreeSet<Rank>,
    /// Described, eligible, outranked for a seat.
    waiting: BTreeSet<Rank>,
    /// Described but not eligible for a seat now: cut by a standing cut, or beyond its cell's
    /// share. Kept (described) so a lifted cut seats them again by rank.
    held: BTreeSet<Rank>,
    ranks: HashMap<PublicKey, Rank>,
    /// The ranks of each cell, for its share.
    cells: HashMap<u64, BTreeSet<Rank>>,
    cutoffs: Cutoffs,
    /// Ranks whose eligibility may have changed since the last settle.
    dirty: Vec<Rank>,
}

impl Places {
    fn place(&self, key: &PublicKey) -> Place {
        match self.ranks.get(key) {
            Some(rank) if self.seated.contains(rank) => Place::Seated,
            Some(_) => Place::Waiting,
            None => Place::Gone,
        }
    }

    /// The `CUT_FLOOR_SEATS` best ranked of every receiver described.
    fn floor(&self) -> Vec<Rank> {
        let mut best: Vec<Rank> = [&self.seated, &self.waiting, &self.held]
            .into_iter()
            .flat_map(|set| set.iter().take(CUT_FLOOR_SEATS).copied())
            .collect();
        best.sort_unstable();
        best.truncate(CUT_FLOOR_SEATS);
        best
    }

    /// Whether `rank` is within its cell's share.
    fn within_share(&self, rank: &Rank) -> bool {
        rank.cell == 0
            || self
                .cells
                .get(&rank.cell)
                .is_none_or(|cell| cell.iter().take(SEATS_PER_CELL).any(|held| held == rank))
    }

    /// Whether `rank` may hold a seat: within its cell's share, and below the cut standing for its
    /// area unless it is among the `floor`.
    fn eligible(&self, rank: &Rank, floor: &[Rank]) -> bool {
        self.within_share(rank)
            && (rank.draw < self.cutoffs.threshold(rank.cell) || floor.contains(rank))
    }

    /// Marks the ranks at the edge of `cell`'s share: what a change to the cell may have moved in
    /// or out.
    fn dirty_edge(&mut self, cell: u64) {
        if let Some(ranks) = self.cells.get(&cell) {
            let edge: Vec<Rank> = ranks
                .iter()
                .skip(SEATS_PER_CELL.saturating_sub(1))
                .take(2)
                .copied()
                .collect();
            self.dirty.extend(edge);
        }
    }

    /// Forgets `rank` entirely.
    fn forget(&mut self, rank: &Rank) {
        self.seated.remove(rank);
        self.waiting.remove(rank);
        self.held.remove(rank);
        self.ranks.remove(&rank.key);
        if rank.cell != 0 {
            if let Some(cell) = self.cells.get_mut(&rank.cell) {
                cell.remove(rank);
                if cell.is_empty() {
                    self.cells.remove(&rank.cell);
                }
            }
            self.dirty_edge(rank.cell);
        }
    }
}

/// The seats for described receivers, shared by every intake of one engine (RFC-0181 §9). Who is
/// seated is a function of who is described, never of the order they came in or of which intake
/// took them: the `limit` best ranked ([`Rank`]: taking part first, then the draw) of those
/// eligible, and up to `limit` more waiting; beyond that the worst ranked are forgotten with their
/// descriptions, which bounds what is remembered. Eligible: within the cell's share
/// ([`SEATS_PER_CELL`]) and below the rank threshold a standing cut asks for in the receiver's
/// area ([`Seats::set_cutoffs`]), the best [`CUT_FLOOR_SEATS`] aside. A change re-settles every
/// place, and says whose place changed, so each intake holding one of them settles it
/// ([`Intake::settle`]). One limit: a receiver forgotten is not brought back when the ranks above
/// it change later (a description moving another out of the regions); only its next description,
/// or the relay's own on a change of areas, ranks it again.
#[derive(Debug)]
pub struct Seats {
    limit: usize,
    /// What the draw is keyed by: this process's secret, or a test's.
    secret: FingerprintKey,
    places: Mutex<Places>,
}

impl std::fmt::Debug for Places {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Places")
            .field("seated", &self.seated.len())
            .field("waiting", &self.waiting.len())
            .field("held", &self.held.len())
            .finish()
    }
}

/// The receivers of some areas as a cut judges them (`Seats::scoped`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scoped {
    /// How many hold a seat.
    pub seated: usize,
    /// The draws of those that take part and are within their cell's share, best first: what a
    /// threshold can choose among.
    pub draws: Vec<u128>,
}

impl Seats {
    /// `limit` seats, drawn for under the fleet's seed ([`draw`]).
    pub fn new(limit: usize) -> Arc<Self> {
        Self::keyed(limit, fleet_key())
    }

    /// `limit` seats, drawn for under `secret`: for a test that needs the same seats twice, or
    /// different secrets to differ.
    pub fn keyed(limit: usize, secret: FingerprintKey) -> Arc<Self> {
        Arc::new(Self {
            limit,
            secret,
            places: Mutex::new(Places::default()),
        })
    }

    /// `key`'s draw under these seats' secret ([`draw_under`]): what ranks it for a seat, and for
    /// room among the batches waiting for a description ([`Intake::hold_orphan`]).
    pub fn draw_of(&self, key: &PublicKey) -> u128 {
        draw_under(&self.secret, key)
    }

    fn places(&self) -> std::sync::MutexGuard<'_, Places> {
        self.places
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ranks `key` (taking part or `idle`, declared at `cell`) among the described and settles
    /// every place. Every other receiver whose place changed (its holder settles `key` itself).
    fn rank(&self, key: PublicKey, idle: bool, cell: Option<Region>) -> Vec<PublicKey> {
        let mut places = self.places();
        let was = places.ranks.get(&key).copied();
        let seated = was.is_some_and(|old| places.seated.contains(&old));
        if let Some(old) = was {
            places.forget(&old);
        }
        let rank = Rank {
            idle,
            draw: draw_under(&self.secret, &key),
            key,
            cell: cell.map_or(0, Region::as_u64),
        };
        places.ranks.insert(key, rank);
        if rank.cell != 0 {
            places.cells.entry(rank.cell).or_default().insert(rank);
            places.dirty_edge(rank.cell);
        }
        if seated {
            places.seated.insert(rank);
        } else {
            places.waiting.insert(rank);
        }
        places.dirty.push(rank);
        let mut changed = self.settle(&mut places);
        changed.retain(|other| *other != key);
        changed
    }

    /// Forgets `keys` (their intake is gone) and settles every place: whose changed.
    fn remove(&self, keys: impl Iterator<Item = PublicKey>) -> Vec<PublicKey> {
        let mut places = self.places();
        for key in keys {
            if let Some(rank) = places.ranks.get(&key).copied() {
                places.forget(&rank);
            }
        }
        self.settle(&mut places)
    }

    /// Moves the ranks marked dirty (and the edge of the floor) to the set their eligibility says,
    /// seats the best ranked eligible waiting while there is a seat or they outrank someone seated,
    /// and forgets the worst beyond `limit` of the waiting and of the held. Whose place changed.
    fn settle(&self, places: &mut Places) -> Vec<PublicKey> {
        let mut changed = Vec::new();
        loop {
            // The edge of each set is always looked at again: the floor is the best ranked of all.
            let edge: Vec<Rank> = [&places.seated, &places.waiting, &places.held]
                .into_iter()
                .flat_map(|set| set.iter().take(CUT_FLOOR_SEATS + 1).copied())
                .collect();
            places.dirty.extend(edge);
            let dirty = std::mem::take(&mut places.dirty);
            let floor = places.floor();
            for rank in dirty {
                let eligible = places.eligible(&rank, &floor);
                if places.seated.contains(&rank) {
                    if !eligible {
                        places.seated.remove(&rank);
                        places.held.insert(rank);
                        changed.push(rank.key);
                    }
                } else if places.waiting.contains(&rank) {
                    if !eligible {
                        places.waiting.remove(&rank);
                        places.held.insert(rank);
                    }
                } else if places.held.contains(&rank) && eligible {
                    places.held.remove(&rank);
                    places.waiting.insert(rank);
                }
            }
            while let Some(best) = places.waiting.first().copied() {
                if places.seated.len() < self.limit {
                    places.waiting.remove(&best);
                    places.seated.insert(best);
                    changed.push(best.key);
                    continue;
                }
                match places.seated.last().copied() {
                    Some(worst) if best < worst => {
                        places.waiting.remove(&best);
                        places.seated.remove(&worst);
                        places.seated.insert(best);
                        places.waiting.insert(worst);
                        changed.extend([best.key, worst.key]);
                    }
                    _ => break,
                }
            }
            while places.waiting.len() > self.limit {
                let Some(worst) = places.waiting.last().copied() else {
                    break;
                };
                places.forget(&worst);
                changed.push(worst.key);
            }
            while places.held.len() > self.limit {
                let Some(worst) = places.held.last().copied() else {
                    break;
                };
                places.forget(&worst);
                changed.push(worst.key);
            }
            if places.dirty.is_empty() {
                break;
            }
        }
        changed.sort_unstable();
        changed.dedup();
        changed
    }

    /// Where `key` stands now.
    pub fn place(&self, key: &PublicKey) -> Place {
        self.places().place(key)
    }

    /// Seats taken now.
    pub fn taken(&self) -> usize {
        self.places().seated.len()
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The seats in use at most now: `limit`, or while a cut stands the receivers eligible for a
    /// seat under it (at most `limit`).
    pub fn cap(&self) -> usize {
        let places = self.places();
        if places.cutoffs.below.is_empty() {
            self.limit
        } else {
            (places.seated.len() + places.waiting.len()).min(self.limit)
        }
    }

    /// Makes `cuts` the cuts standing: a receiver whose declared place lies in an area a cut
    /// names is solved only if its draw is below that cut's threshold (the least of the cuts
    /// naming it), the best [`CUT_FLOOR_SEATS`] aside; a threshold of `u128::MAX` lifts. Settles
    /// every place: whose changed, for each intake holding one to settle ([`Intake::settle`]).
    /// The receivers cut stay described, held, so a lifted cut seats them again by rank. The same
    /// cuts on every relay seat the same receivers (module docs): a threshold is a rank, which
    /// does not depend on which receivers a relay has described or how many seats it has.
    pub fn set_cutoffs(&self, cuts: impl IntoIterator<Item = (Region, u128)>) -> Vec<PublicKey> {
        let cutoffs = Cutoffs::of(cuts);
        let mut places = self.places();
        if places.cutoffs == cutoffs {
            return Vec::new();
        }
        places.cutoffs = cutoffs;
        let all: Vec<Rank> = places.ranks.values().copied().collect();
        places.dirty.extend(all);
        self.settle(&mut places)
    }

    /// The receivers whose declared area `in_scope` accepts, as a cut over them judges them.
    pub fn scoped(&self, in_scope: impl Fn(Region) -> bool) -> Scoped {
        let places = self.places();
        let mut scoped = Scoped::default();
        for rank in places.ranks.values() {
            let Some(area) = Region::from_u64(rank.cell)
                .ok()
                .and_then(|cell| cell.ancestor(CUT_RESOLUTION))
            else {
                continue;
            };
            if rank.idle || !in_scope(area) {
                continue;
            }
            if places.seated.contains(rank) {
                scoped.seated += 1;
            }
            if places.within_share(rank) {
                scoped.draws.push(rank.draw);
            }
        }
        scoped.draws.sort_unstable();
        scoped
    }
}

/// A receiver's newest description: when it was issued, its bytes (which decide between two
/// issued in the same millisecond, so the order they arrive in does not), and its site if it
/// takes part.
struct Described {
    issued_ms: u64,
    bytes: Vec<u8>,
    /// What it declared, so a change of the engine's regions re-decides whether it takes part.
    location: Option<Location>,
    clock: Clock,
    /// Its record's site id and reception key.
    id: SiteId,
    key: ReceptionKey,
    /// Its site, if its own word places it inside the engine's regions with a usable clock.
    site: Option<Site>,
    /// Whether it holds a seat ([`Seats`]): it takes part when it is seated and has a site.
    seated: bool,
    /// The sequences used per boot, most recent boot first.
    boots: VecDeque<(u64, Sequences)>,
}

/// The sequences of one boot already used: the newest, and which of the `REORDER` before it.
struct Sequences {
    newest: u64,
    /// Bit `i` set: sequence `newest - i` was used.
    used: u64,
}

impl Sequences {
    fn new(sequence: u64) -> Self {
        Self {
            newest: sequence,
            used: 1,
        }
    }

    /// True the first time `sequence` is offered, if it is within `REORDER` of the newest.
    fn admit(&mut self, sequence: u64) -> bool {
        if sequence > self.newest {
            let ahead = sequence - self.newest;
            self.used = if ahead >= REORDER {
                0
            } else {
                self.used << ahead
            };
            self.used |= 1;
            self.newest = sequence;
            return true;
        }
        let behind = self.newest - sequence;
        if behind >= REORDER {
            return false;
        }
        let bit = 1 << behind;
        if self.used & bit != 0 {
            return false;
        }
        self.used |= bit;
        true
    }
}

impl Described {
    /// True when the batch numbered `sequence` in `boot` has not been used.
    fn admit(&mut self, boot: u64, sequence: u64) -> bool {
        let found = self
            .boots
            .iter()
            .position(|(id, _)| *id == boot)
            .and_then(|at| self.boots.remove(at));
        let (admitted, sequences) = match found {
            Some((_, mut sequences)) => (sequences.admit(sequence), sequences),
            None => {
                self.boots.truncate(BOOTS_PER_RECEIVER - 1);
                (true, Sequences::new(sequence))
            }
        };
        self.boots.push_front((boot, sequences));
        admitted
    }
}

/// What a description or a change of regions did: what it was, the receivers here that stopped
/// taking part (what they heard is forgotten here, and their holder forgets them in the sealed
/// bins), and the receivers whose seat changed that this intake does not hold (their own intakes
/// settle them, [`Intake::settle`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    pub ingested: Ingested,
    pub left: Vec<PublicKey>,
    pub moved: Vec<PublicKey>,
}

/// One holder's receivers and their open raw (module docs).
pub struct Intake {
    seats: Arc<Seats>,
    /// The engine's regions: a receiver inside one takes part (empty: every receiver with a
    /// location). `None`: no engine runs, and no receiver takes part.
    regions: Option<Regions>,
    receivers: BTreeMap<PublicKey, Described>,
    open: Open,
    /// How lateness is decided by the stamp, if it is (`closing`); kept across a restart.
    closing: Option<Closing>,
    dropped: Dropped,
    /// Batches of receivers not described yet (module docs).
    orphans: Orphans,
}

impl Described {
    fn taking_part(&self) -> bool {
        self.seated && self.site.is_some()
    }
}

impl Intake {
    /// Receivers seated in `seats`, raw bounded by `limits` (its byte bound is the open raw's own;
    /// a holder whose raw is split checks its whole bound when it seals, `Bin::seal_within`),
    /// taking part in `regions`.
    pub fn new(seats: Arc<Seats>, limits: Limits, regions: Option<Regions>) -> Self {
        Self {
            regions,
            receivers: BTreeMap::new(),
            open: Open::new(limits),
            closing: None,
            dropped: Dropped::default(),
            orphans: Orphans::new(Arc::clone(&seats), ORPHAN_RECEIVERS, usize::MAX),
            seats,
        }
    }

    /// Holds `batch`, by its own stamp, of a receiver not described here, until its description
    /// comes or `ORPHAN_MS` of steps pass ([`Orphans::hold`]): for an engine holding its own raw.
    /// A holder that splits its receivers over many intakes keeps one [`Orphans`] for all of them
    /// instead, so room among them is decided by rank across all.
    pub fn hold_orphan(&mut self, batch: &Arc<Decoded>) -> Orphaned {
        if self.receivers.contains_key(&batch.receiver()) {
            return Orphaned::default();
        }
        self.orphans.hold(batch, |_| true)
    }

    /// Lets go every batch that has waited `ORPHAN_MS` by the step at `now` on the monotonic clock.
    pub fn expire_orphans(&mut self, now: Mono) -> Orphaned {
        self.orphans.expire(now)
    }

    /// The batches that waited for `receiver`'s description, oldest first, each with its stamp:
    /// for its holder to take now that it is described.
    pub fn take_orphans(&mut self, receiver: &PublicKey) -> Vec<Arc<Decoded>> {
        self.orphans.take(receiver)
    }

    /// Batches waiting for a description.
    pub fn orphans(&self) -> usize {
        self.orphans.len()
    }

    /// Raw late by its stamp under `closing` (module docs): for an intake whose holder steps on a
    /// thread of its own, by the stamp watermark.
    #[must_use]
    pub fn closing(mut self, closing: Closing) -> Self {
        self.open = Open::new(self.open.limits()).closing(closing);
        self.closing = Some(closing);
        self
    }

    /// Receptions held open (copies included).
    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Bytes of open raw, as allocated.
    pub fn bytes(&self) -> usize {
        self.open.bytes()
    }

    /// Whether `receiver` is described, and whether it takes part (one waiting for a seat is
    /// described, and takes no part).
    pub fn described(&self, receiver: &PublicKey) -> Option<bool> {
        self.receivers.get(receiver).map(Described::taking_part)
    }

    /// Receivers taking part now.
    pub fn taking_part(&self) -> usize {
        self.receivers
            .values()
            .filter(|described| described.taking_part())
            .count()
    }

    /// The receivers taking part, in key order: each site with its reception key.
    pub fn sites(&self) -> impl Iterator<Item = Sited> + '_ {
        self.receivers
            .values()
            .filter(|known| known.seated)
            .filter_map(|known| {
                known.site.map(|site| Sited {
                    site,
                    key: known.key,
                })
            })
    }

    /// What was refused since the last call.
    pub fn take_dropped(&mut self) -> Dropped {
        std::mem::take(&mut self.dropped)
    }

    /// A receiver's site-bearing record (verified here: it is the receiver's own word). An error
    /// is one that does not verify.
    pub fn describe(&mut self, record: &SiteRecord) -> Result<Description, String> {
        self.describe_after(record, None)
    }

    /// As `describe`, at a step of a holder whose earlier steps are not all done: what a receiver
    /// that stops taking part (it, or one whose seat it changed) held in the bins through `kept`
    /// stays for those steps to take, as they would have had they run in their turn
    /// (`held::Open::forget_receiver_after`); its holder forgets it in the sealed bins at this
    /// step. `None`: everything it held here goes now.
    pub fn describe_after(
        &mut self,
        record: &SiteRecord,
        kept: Option<i64>,
    ) -> Result<Description, String> {
        let ignored = Description {
            ingested: Ingested::Ignored,
            left: Vec::new(),
            moved: Vec::new(),
        };
        let key = record.receiver().map_err(|error| error.to_string())?;
        record
            .verify()
            .map_err(|error| format!("site of {key}: {error}"))?;
        // A format this build cannot read says nothing it can use.
        let Ok(content) = record.content() else {
            return Ok(ignored);
        };
        if let Some(known) = self.receivers.get(&key)
            && (known.issued_ms, known.bytes.as_slice()) >= (content.issued_ms, record.as_bytes())
        {
            return Ok(ignored);
        }
        let (id, reception_key) = (record.site_id(), record.reception_key());
        let site = self.site(key, content.location, content.clock, id);
        let fresh = !self.receivers.contains_key(&key);
        let known = self.receivers.entry(key).or_insert_with(|| Described {
            issued_ms: 0,
            bytes: Vec::new(),
            location: None,
            clock: content.clock,
            id,
            key: reception_key,
            site: None,
            seated: false,
            boots: VecDeque::new(),
        });
        let was = known.taking_part();
        known.issued_ms = content.issued_ms;
        known.bytes = record.as_bytes().to_vec();
        known.location = content.location;
        known.clock = content.clock;
        known.id = id;
        known.key = reception_key;
        known.site = site;
        let changed = self
            .seats
            .rank(key, site.is_none(), seat_cell(content.location));
        let mut description = self.settle_all(changed, kept);
        if self.settle_was(&key, was, kept) {
            description.left.push(key);
        }
        let seated = self.receivers.get(&key).is_some_and(|known| known.seated);
        if fresh && !seated {
            // Beyond the seats and outranked: refused whole, and counted.
            self.dropped.receivers += 1;
        }
        description.ingested = if seated {
            Ingested::Described
        } else {
            Ingested::Refused
        };
        Ok(description)
    }

    /// Settles every receiver of `changed` this intake holds; the rest are another intake's.
    fn settle_all(&mut self, changed: Vec<PublicKey>, kept: Option<i64>) -> Description {
        let mut description = Description {
            ingested: Ingested::Ignored,
            left: Vec::new(),
            moved: Vec::new(),
        };
        for other in changed {
            if self.receivers.contains_key(&other) {
                if self.settle_after(&other, kept) {
                    description.left.push(other);
                }
            } else {
                description.moved.push(other);
            }
        }
        description
    }

    /// Brings `receiver` to the place the seats give it now: seated or waiting, or forgotten
    /// with its description. True when it stopped taking part (what it heard is forgotten here,
    /// and its holder forgets it in the sealed bins). A receiver that loses its seat is refused
    /// whole from then on, and counted. Settling twice, or late, is settling once: it reads where
    /// the receiver stands now.
    pub fn settle(&mut self, receiver: &PublicKey) -> bool {
        self.settle_after(receiver, None)
    }

    /// As `settle`, its raw through `kept` left for the steps already due (`describe_after`).
    pub fn settle_after(&mut self, receiver: &PublicKey, kept: Option<i64>) -> bool {
        let was = self
            .receivers
            .get(receiver)
            .is_some_and(Described::taking_part);
        self.settle_was(receiver, was, kept)
    }

    fn settle_was(&mut self, receiver: &PublicKey, was: bool, kept: Option<i64>) -> bool {
        let place = self.seats.place(receiver);
        let Some(known) = self.receivers.get_mut(receiver) else {
            return false;
        };
        let seated = place == Place::Seated;
        if known.seated && !seated {
            self.dropped.receivers += 1;
        }
        known.seated = seated;
        let now = known.taking_part();
        if place == Place::Gone {
            self.receivers.remove(receiver);
        }
        let left = was && !now;
        if left || place == Place::Gone {
            // It stopped taking part: what it heard is no longer used.
            if let Some(known) = self.receivers.get_mut(receiver) {
                known.boots.clear();
            }
            match kept {
                Some(kept) => self.open.forget_receiver_after(receiver, kept),
                None => self.open.forget_receiver(receiver),
            }
        }
        left
    }

    /// The engine's regions are now `regions` (`None`: no engine runs). Every receiver described
    /// is decided again on its own signed word, and ranked again for its seat: the receivers here
    /// that stopped taking part, whose raw here is forgotten (their holder forgets them in the
    /// sealed bins), and those of other intakes whose seat changed.
    pub fn set_scope(&mut self, regions: Option<Regions>) -> Description {
        self.regions = regions;
        let decided: Vec<(PublicKey, Option<Site>, bool)> = self
            .receivers
            .iter()
            .map(|(key, known)| {
                (
                    *key,
                    self.site(*key, known.location, known.clock, known.id),
                    known.taking_part(),
                )
            })
            .collect();
        let mut changed = Vec::new();
        for (key, site, _) in &decided {
            if let Some(known) = self.receivers.get_mut(key) {
                known.site = *site;
            }
            changed.extend(self.seats.rank(
                *key,
                site.is_none(),
                seat_cell(self.receivers.get(key).and_then(|known| known.location)),
            ));
        }
        changed.sort_unstable();
        changed.dedup();
        let mut description = Description {
            ingested: Ingested::Ignored,
            left: Vec::new(),
            moved: Vec::new(),
        };
        for other in changed {
            if !self.receivers.contains_key(&other) {
                description.moved.push(other);
            }
        }
        for (key, _, was) in decided {
            if self.settle_was(&key, was, None) {
                description.left.push(key);
            }
        }
        description
    }

    /// A new engine begins: nothing it holds is the old one's. The descriptions stay (they are the
    /// receivers' word, not the engine's); the sequences used and the open raw go.
    pub fn restart(&mut self, limits: Limits) {
        for known in self.receivers.values_mut() {
            known.boots.clear();
        }
        self.open = match self.closing {
            Some(closing) => Open::new(limits).closing(closing),
            None => Open::new(limits),
        };
        self.dropped = Dropped::default();
        self.orphans.clear();
    }

    /// The site a declared location and clock give, if the receiver takes part, named by its
    /// record's site id.
    fn site(
        &self,
        key: PublicKey,
        location: Option<Location>,
        clock: Clock,
        id: SiteId,
    ) -> Option<Site> {
        let regions = self.regions.as_ref()?;
        let location = location?;
        let inside = regions.is_empty() || regions.covers(&location);
        let usable = Timebase::of(clock).is_some() && location.precision_m <= MAX_SITE_PRECISION_M;
        (inside && usable).then_some(Site {
            receiver: key,
            clock,
            location,
            id,
        })
    }

    /// Takes a batch whose signature its holder verified and which it decoded once: used once per
    /// (boot, sequence), held only from a receiver that takes part, within its own share of a bin
    /// (`Limits::per_receiver_bin`; the holder's whole bound is checked when it seals). What it
    /// did, and what it says to provisional solving (nothing unless it was taken).
    pub fn ingest_verified(&mut self, batch: &Decoded) -> (Ingested, Vec<Note>) {
        self.ingest_verified_taking(batch, None, &mut |_| true)
    }

    /// As `ingest_verified`, every byte of open raw asked of `take` before it is allocated
    /// (`held::Open::add_decoded_taking`): for a holder charged for its open raw as it grows. A
    /// byte refused refuses the batch's raw of its bin, counted with the receiver's raw refused
    /// for its share; what it says to provisional solving is told all the same. `step`: for a
    /// holder that closes by the stamp, the step whose interval its stamp is in, whose two clocks
    /// judge it late (`held::Open::add_decoded_taking`).
    pub fn ingest_verified_taking(
        &mut self,
        batch: &Decoded,
        step: Option<Moment>,
        take: &mut dyn FnMut(usize) -> bool,
    ) -> (Ingested, Vec<Note>) {
        let key = batch.receiver();
        let Some(known) = self.receivers.get_mut(&key) else {
            return (Ingested::Ignored, Vec::new());
        };
        if !known.taking_part() {
            return (Ingested::Ignored, Vec::new());
        }
        if !known.admit(batch.boot_id(), batch.sequence()) {
            return (Ingested::Replayed, Vec::new());
        }
        let notes = notes_of(batch);
        // Judged ahead or late by its own stamp, however late it is taken (a batch that waited for
        // its receiver's description too), late by the clocks of the step its stamp is in: every
        // holder judges the same raw the same way.
        let added = self.open.add_decoded_taking(batch, step, take);
        self.dropped.late += added.late as u64;
        self.dropped.refused += added.refused as u64;
        self.dropped.ahead += added.ahead as u64;
        (
            Ingested::Batch {
                new: added.new,
                filtered: added.filtered,
            },
            notes,
        )
    }

    /// A batch of a format this build cannot read: it uses its sequence and holds nothing.
    pub fn use_sequence(&mut self, receiver: &PublicKey, boot: u64, sequence: u64) -> Ingested {
        match self.receivers.get_mut(receiver) {
            Some(known) if known.taking_part() => {
                if known.admit(boot, sequence) {
                    Ingested::Ignored
                } else {
                    Ingested::Replayed
                }
            }
            _ => Ingested::Ignored,
        }
    }

    /// Takes every open bin up to `bin` for sealing: from here on raw for them is late.
    pub fn take_through(&mut self, bin: i64) -> Vec<Fragment> {
        self.open.take_through(bin)
    }

    /// Forgets every open bin before `bin`.
    pub fn forget_before(&mut self, bin: i64) {
        self.open.forget_before(bin);
    }
}

impl Drop for Intake {
    fn drop(&mut self) {
        // The intakes of one engine go together; the places this frees settle whoever is left.
        let _ = self.seats.remove(self.receivers.keys().copied());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_wire::Identity;
    use tally_wire::clocks::recorded::aligned;

    /// `draw` of `Identity::from_seed([7; 32])`'s key.
    const KNOWN_DRAW: u128 = 0xa152b57161dad4a033a9d8cbfd33dbb0;

    fn secret(seed: u8) -> FingerprintKey {
        FingerprintKey::from_bytes([seed; 32])
    }

    /// Who is seated, waiting and forgotten is a function of who is described: the same in any
    /// order of arrival, taking part ranked before idle, then by the draw. While nobody is
    /// forgotten (at most twice the seats described), changes of rank on the way change nothing
    /// either.
    #[test]
    fn who_is_seated_depends_on_who_is_described_never_on_the_order() {
        let keys: Vec<PublicKey> = (0..12u8)
            .map(|seed| Identity::from_seed([seed; 32]).public())
            .collect();
        // Every third idle.
        let idle = |n: usize| n.is_multiple_of(3);
        let outcome = |order: &[usize], limit: usize, detour: bool| -> Vec<Place> {
            let seats = Seats::keyed(limit, secret(9));
            for n in order {
                if detour {
                    // Described first as taking part, then decided: a change of rank on the way.
                    let _ = seats.rank(keys[*n], !idle(*n), None);
                }
                let _ = seats.rank(keys[*n], idle(*n), None);
            }
            keys.iter().map(|key| seats.place(key)).collect()
        };
        let mut ranked: Vec<(bool, u128, PublicKey)> = (0..keys.len())
            .map(|n| (idle(n), draw_under(&secret(9), &keys[n]), keys[n]))
            .collect();
        ranked.sort_unstable();
        let expected = |limit: usize| -> Vec<Place> {
            keys.iter()
                .map(|key| {
                    let at = ranked.iter().position(|(_, _, k)| k == key).unwrap_or(0);
                    if at < limit {
                        Place::Seated
                    } else if at < 2 * limit {
                        Place::Waiting
                    } else {
                        Place::Gone
                    }
                })
                .collect()
        };
        let mut order: Vec<usize> = (0..keys.len()).collect();
        for round in 0..20u64 {
            // A pseudorandom permutation each round.
            for i in (1..order.len()).rev() {
                let j = ((round + 1) * 2_654_435_761 * (i as u64 + 7) % (i as u64 + 1)) as usize;
                order.swap(i, j);
            }
            let reversed: Vec<usize> = order.iter().rev().copied().collect();
            for order in [&order, &reversed] {
                // Four seats, four waiting, the rest forgotten.
                assert_eq!(outcome(order, 4, false), expected(4), "{order:?}");
                // Seven seats: nobody forgotten, so ranks may change on the way.
                assert_eq!(outcome(order, 7, false), expected(7), "{order:?}");
                assert_eq!(
                    outcome(order, 7, true),
                    expected(7),
                    "{order:?} with detours"
                );
            }
        }
    }

    /// RFC-0181 §9, §10: the rank is the same on every relay. A known answer, so the rank is
    /// pinned to the fleet's seed and not to anything this process drew (before, each relay's own
    /// secret: two relays holding one area seated different receivers, and an overloaded host's
    /// cut left others than the peer's).
    #[test]
    fn the_seat_rank_is_the_same_on_every_relay() {
        let key = Identity::from_seed([7; 32]).public();
        assert_eq!(draw(&key), KNOWN_DRAW, "{:#x}", draw(&key));
        assert_eq!(Seats::new(1).draw_of(&key), draw(&key));
        // And not the process's secret.
        assert_ne!(
            draw(&key),
            draw_under(FingerprintKey::process(), &key),
            "ranked by the process's secret"
        );
    }

    fn place_at(lat_e7: i32, lon_e7: i32) -> Location {
        Location {
            lat_e7,
            lon_e7,
            alt_m: 0,
            precision_m: 0,
        }
    }

    fn keys(count: u8) -> Vec<PublicKey> {
        (0..count)
            .map(|seed| Identity::from_seed([seed; 32]).public())
            .collect()
    }

    fn seated_of(seats: &Seats, keys: &[PublicKey]) -> Vec<PublicKey> {
        let mut seated: Vec<PublicKey> = keys
            .iter()
            .copied()
            .filter(|key| seats.place(key) == Place::Seated)
            .collect();
        seated.sort_unstable();
        seated
    }

    /// Receivers spread over `count` distinct cells (one each), so no cell's share binds.
    fn spread(keys: &[PublicKey]) -> Vec<(PublicKey, Option<Region>)> {
        keys.iter()
            .enumerate()
            .map(|(n, key)| {
                let at = place_at(500_000_000 + n as i32 * 5_000_000, 100_000_000);
                (*key, seat_cell(Some(at)))
            })
            .collect()
    }

    fn area_of_cell(cell: Option<Region>) -> Result<Region, String> {
        cell.and_then(|cell| cell.ancestor(CUT_RESOLUTION))
            .ok_or_else(|| "no area".to_owned())
    }

    /// RFC-0181 §10: the cut is a rank threshold keyed by area, so every relay holding the area
    /// solves exactly the receivers ranked below it, whatever each has described or has seats
    /// for, and whatever order the descriptions came in. A relay with more seats and no cut of its
    /// own, a relay that described more receivers, and a relay that described them last first all
    /// solve the same receivers; a lifted cut seats the rest again by rank.
    #[test]
    fn a_rank_threshold_leaves_the_same_receivers_on_every_relay() -> Result<(), String> {
        let keys = keys(24);
        let receivers = spread(&keys);
        let mut by_draw: Vec<u128> = keys.iter().map(draw).collect();
        by_draw.sort_unstable();
        // The cut asks for the 10 best ranked of the area all these receivers are in.
        let below = by_draw[10];
        let cuts: Vec<(Region, u128)> = receivers
            .iter()
            .map(|(_, cell)| area_of_cell(*cell).map(|area| (area, below)))
            .collect::<Result<_, _>>()?;
        let expected: Vec<PublicKey> = {
            let mut set: Vec<PublicKey> = keys
                .iter()
                .copied()
                .filter(|key| draw(key) < below)
                .collect();
            set.sort_unstable();
            set
        };
        assert_eq!(expected.len(), 10);
        // Relays of different limits, orders and described sets (b described only 16 of them).
        for (limit, count, reversed) in [(16, 24, false), (64, 24, true), (12, 24, false)] {
            let seats = Seats::new(limit);
            let mut order: Vec<&(PublicKey, Option<Region>)> = receivers.iter().collect();
            if reversed {
                order.reverse();
            }
            for (key, cell) in order.into_iter().take(count) {
                let _ = seats.rank(*key, false, *cell);
            }
            seats.set_cutoffs(cuts.clone());
            assert_eq!(seated_of(&seats, &keys), expected, "limit {limit}");
            // The receivers cut are described, held back, not seated; only past the room kept
            // for them (`limit` of them) are the worst forgotten.
            let held = keys.iter().filter(|key| !expected.contains(key));
            let mut waiting = 0;
            for key in held {
                assert_ne!(seats.place(key), Place::Seated, "limit {limit}");
                waiting += usize::from(seats.place(key) == Place::Waiting);
            }
            assert_eq!(waiting, (24 - 10).min(limit), "limit {limit}");
            // Lifted, they are seated again by rank, up to the limit.
            seats.set_cutoffs(Vec::new());
            let lifted = seated_of(&seats, &keys);
            assert_eq!(lifted.len(), limit.min(24), "limit {limit}");
            assert_eq!(seats.cap(), limit);
        }
        // A relay that never described the 6 worst ranked solves the same best 10.
        let seats = Seats::new(64);
        let mut worst: Vec<PublicKey> = keys.clone();
        worst.sort_unstable_by_key(|key| std::cmp::Reverse(draw(key)));
        for (key, cell) in &receivers {
            if !worst[..6].contains(key) {
                let _ = seats.rank(*key, false, *cell);
            }
        }
        seats.set_cutoffs(cuts);
        assert_eq!(seated_of(&seats, &keys), expected);
        Ok(())
    }

    /// A cut is keyed by area: receivers in another area are not touched by it, and the best ranked
    /// few are never cut (a cut asks for fewer receivers, never none).
    #[test]
    fn a_cut_binds_its_area_alone_and_leaves_the_floor() -> Result<(), String> {
        let keys = keys(40);
        let receivers = spread(&keys);
        let seats = Seats::new(64);
        for (key, cell) in &receivers {
            let _ = seats.rank(*key, false, *cell);
        }
        assert_eq!(seated_of(&seats, &keys).len(), 40);
        // Zero asked of the area of the first receiver alone.
        let target = area_of_cell(receivers[0].1)?;
        let in_target = |cell: Option<Region>| area_of_cell(cell) == Ok(target);
        let members: Vec<PublicKey> = receivers
            .iter()
            .filter(|(_, cell)| in_target(*cell))
            .map(|(key, _)| *key)
            .collect();
        seats.set_cutoffs([(target, 0)]);
        let seated = seated_of(&seats, &keys);
        // Everyone outside the area is seated; of the area, only what the floor holds.
        for (key, cell) in &receivers {
            if !in_target(*cell) {
                assert!(seated.contains(key), "outside the area");
            }
        }
        let kept = members.iter().filter(|key| seated.contains(key)).count();
        assert!(kept <= CUT_FLOOR_SEATS, "{kept} of the area kept");
        // The floor: the best ranked of all are seated whatever the cut.
        let mut all: Vec<PublicKey> = keys.clone();
        all.sort_unstable_by_key(draw);
        for key in &all[..CUT_FLOOR_SEATS] {
            assert!(seated.contains(key), "a floor receiver was cut");
        }
        Ok(())
    }

    /// A cell's share of the seats: many receivers declared at one place hold no more than
    /// `SEATS_PER_CELL` of them, the best ranked, and the rest of the world is unaffected.
    #[test]
    fn many_receivers_at_one_place_hold_no_more_than_a_cells_share() {
        let crowd = keys(30);
        let alone = Identity::from_seed([200; 32]).public();
        let seats = Seats::new(64);
        let here = seat_cell(Some(place_at(515_000_000, -1_000_000)));
        for key in &crowd {
            let _ = seats.rank(*key, false, here);
        }
        let there = seat_cell(Some(place_at(480_000_000, 20_000_000)));
        let _ = seats.rank(alone, false, there);
        let seated = seated_of(&seats, &crowd);
        assert_eq!(seated.len(), SEATS_PER_CELL);
        let mut best: Vec<PublicKey> = crowd.clone();
        best.sort_unstable_by_key(draw);
        best.truncate(SEATS_PER_CELL);
        best.sort_unstable();
        assert_eq!(seated, best);
        assert_eq!(seats.place(&alone), Place::Seated);
        // One of the best leaving hands its share to the next, whatever order they came in.
        let gone = seated[0];
        let _ = seats.remove(std::iter::once(gone));
        assert_eq!(seated_of(&seats, &crowd).len(), SEATS_PER_CELL);
    }

    /// RFC-0171 §9 (critic 4) and the audit's grinding attack: a seat is not won by choosing a
    /// key. Keys that sort first win no more seats than any others; who is seated follows the
    /// relay's secret, so the same receivers under another secret are seated differently, and
    /// nobody outside the process can tell in advance which.
    #[test]
    fn a_seat_is_not_won_by_choosing_a_key() {
        let mut keys: Vec<PublicKey> = (0..64u8)
            .map(|seed| Identity::from_seed([seed; 32]).public())
            .collect();
        keys.sort_unstable();
        const LIMIT: usize = 8;
        let seated = |secret: FingerprintKey| -> Vec<PublicKey> {
            let seats = Seats::keyed(LIMIT, secret);
            for key in &keys {
                let _ = seats.rank(*key, false, None);
            }
            keys.iter()
                .filter(|key| seats.place(key) == Place::Seated)
                .copied()
                .collect()
        };
        let first = seated(secret(1));
        let second = seated(secret(2));
        assert_eq!((first.len(), second.len()), (LIMIT, LIMIT));
        // The keys a grinder would choose (the least) are not what is seated.
        assert_ne!(first, keys[..LIMIT].to_vec());
        assert_ne!(second, keys[..LIMIT].to_vec());
        // Another secret, other seats.
        assert_ne!(first, second);
        // Under one secret the seats are the best draws, whatever the keys.
        let mut draws: Vec<(u128, PublicKey)> = keys
            .iter()
            .map(|key| (draw_under(&secret(1), key), *key))
            .collect();
        draws.sort_unstable();
        let mut best: Vec<PublicKey> = draws[..LIMIT].iter().map(|(_, key)| *key).collect();
        best.sort_unstable();
        assert_eq!(first, best);
    }

    /// Who waits for a description, for room, is decided by rank and never by
    /// arrival. Past the intake's receivers the worst drawn is let go for a better drawn one, and
    /// past its bytes a receiver's oldest go first, so the same batches in any order leave the
    /// same batches held, every one let go counted, and the holder is asked for what each batch
    /// allocates only once room is made: what it charges never passes the room it gave, and is
    /// what the batches waiting allocate, read from an allocator counting this thread's bytes.
    #[test]
    fn who_waits_for_a_description_depends_on_who_came_never_on_the_order() -> Result<(), String> {
        const EACH: u64 = 6;
        let senders: Vec<Identity> = (20..26u8)
            .map(|seed| Identity::from_seed([seed; 32]))
            .collect();
        let batch = |sender: usize, sequence: u64| -> Result<Arc<Decoded>, String> {
            let signed = tally_wire::Batch::sign(
                &senders[sender],
                &tally_wire::BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 1,
                    wall_ms: 1_000 + sequence,
                    dropped: 0,
                    previous: [0; 32],
                    observations: Vec::new(),
                },
            )
            .map_err(|error| error.to_string())?;
            Decoded::from_verified(signed, aligned(1_000 + sequence), sequence)
                .map_err(|undecodable| undecodable.error.to_string())
        };
        let mut batches = Vec::new();
        for sender in 0..senders.len() {
            for sequence in 0..EACH {
                batches.push(batch(sender, sequence)?);
            }
        }
        let held = |order: &[usize]| -> (Vec<(PublicKey, u64)>, u64) {
            let seats = Seats::keyed(8, secret(4));
            // Three receivers, four batches each: a full deque of four and its place.
            let room = ORPHANS_ROOT_BYTES
                + 3 * (tally_wire::footprint::vec::<Orphan>(4) + ORPHAN_PLACE_BYTES);
            let mut orphans = Orphans::new(seats, 3, 0);
            orphans.set_room(room);
            let base = tally_counting::Counting::live();
            let mut asked = 0;
            let mut dropped = 0;
            for at in order {
                dropped += orphans
                    .hold(&batches[*at], |total| {
                        asked = asked.max(total);
                        total <= room
                    })
                    .dropped;
                assert!(asked <= room, "asked past the room");
                // What a holder charges once it settles after each hold.
                let charged = orphans.bytes();
                assert!(charged <= room, "charged past the room");
                let live = tally_counting::Counting::since(base);
                assert!(
                    live >= 0 && live as usize <= charged,
                    "{live} allocated, {charged} charged"
                );
            }
            let mut kept = Vec::new();
            for sender in &senders {
                for batch in orphans.take(&sender.public()) {
                    kept.push((batch.receiver(), batch.sequence()));
                }
            }
            kept.sort_unstable();
            (kept, dropped)
        };
        let mut drawn: Vec<(u128, PublicKey)> = senders
            .iter()
            .map(|sender| (draw_under(&secret(4), &sender.public()), sender.public()))
            .collect();
        drawn.sort_unstable();
        // The three best drawn, each its four newest.
        let mut expected: Vec<(PublicKey, u64)> = drawn[..3]
            .iter()
            .flat_map(|(_, key)| (EACH - 4..EACH).map(|sequence| (*key, sequence)))
            .collect();
        expected.sort_unstable();
        let mut order: Vec<usize> = (0..batches.len()).collect();
        for round in 0..20u64 {
            for i in (1..order.len()).rev() {
                let j = ((round + 1) * 2_654_435_761 * (i as u64 + 7) % (i as u64 + 1)) as usize;
                order.swap(i, j);
            }
            // Receivers interleaved anyhow, each one's own batches in its order (one connection,
            // one worker).
            let mut by_sender: Vec<usize> = Vec::new();
            let mut next = vec![0usize; senders.len()];
            for at in &order {
                let sender = at / EACH as usize;
                by_sender.push(sender * EACH as usize + next[sender]);
                next[sender] += 1;
            }
            let (kept, dropped) = held(&by_sender);
            assert_eq!(kept, expected, "{by_sender:?}");
            assert_eq!(
                dropped,
                (batches.len() - expected.len()) as u64,
                "{by_sender:?}"
            );
        }
        Ok(())
    }

    /// Of a receiver's descriptions taking effect at one step only the newest it
    /// signed applies, by `issued_ms` (an older one stamped later never wins), in any order; the
    /// rest are applied by stamp, then key. (One receiver's descriptions are its key, then
    /// `issued_ms` big-endian, so its bytes never order them otherwise: the stamp is the trap.)
    #[test]
    fn of_a_receivers_descriptions_at_one_step_the_newest_signed_takes_effect() -> Result<(), String>
    {
        let one = Identity::from_seed([31; 32]);
        let other = Identity::from_seed([32; 32]);
        // An old feeder's format 1 description and a new feeder's site are ordered alike.
        let described = |identity: &Identity, issued_ms: u64, software: &str| {
            ReceiverInfo::sign(
                identity,
                &tally_wire::batch::ReceiverInfoContent {
                    issued_ms,
                    location: None,
                    clock: Clock::Dump1090,
                    software: software.to_owned(),
                    relays: Vec::new(),
                },
            )
            .map(SiteRecord::Info)
            .map_err(|error| error.to_string())
        };
        let sited = |identity: &Identity, issued_ms: u64| {
            ReceiverSite::sign(
                identity,
                &tally_wire::ReceiverSiteContent {
                    issued_ms,
                    location: place_at(374_100_000, -1_221_000_000),
                    clock: Clock::Dump1090,
                },
            )
            .map(SiteRecord::Site)
            .map_err(|error| error.to_string())
        };
        // The older one is stamped last: by its stamp alone it would apply last, over the newer.
        let older = described(&one, 10, "an older and much longer description")?;
        let newer = sited(&one, 11)?;
        let theirs = sited(&other, 5)?;
        for order in [[0, 1, 2], [1, 0, 2], [2, 1, 0], [2, 0, 1]] {
            let all = [
                (1_400, older.clone()),
                (1_200, newer.clone()),
                (1_300, theirs.clone()),
            ];
            let due = taking_effect(order.iter().map(|at| all[*at].clone()));
            let bytes: Vec<&[u8]> = due.iter().map(|(_, info)| info.as_bytes()).collect();
            assert_eq!(bytes, [newer.as_bytes(), theirs.as_bytes()], "{order:?}");
        }
        Ok(())
    }
}
