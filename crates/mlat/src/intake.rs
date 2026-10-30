//! The receiver side of an engine (RFC-0171 §3.8.1, RFC-0181 §5): which receivers take part and
//! the sequences each has used. Everything here belongs to one receiver, so it splits by receiver:
//! an engine that hears its own batches keeps one [`Intake`] (`Engine::new`), and a relay keeps
//! one per raw shard, each touched by the ingest worker that owns the shard's receivers, and hands
//! the engine it feeds (`Engine::hosted`) what they took and who takes part. One receiver's word
//! decides its part whichever intake holds it, so the same raw split any way solves to the same
//! bytes. What a batch holds that MLAT uses is read where the batch is held ([`receptions_of`]),
//! and the engine's arrived pool (`tally_mlat_solver::Arrived`) holds it.
//!
//! - A receiver takes part on its own signed word only: its newest site-bearing record
//!   ([`SiteRecord`]: its `ReceiverSite`, or an old feeder's format 1 `ReceiverInfo`) verifies,
//!   places it inside the engine's regions, and names a clock the solver specification knows with
//!   a location no coarser than it allows (`tally_mlat_solver::obs::MAX_SITE_PRECISION_M`). A
//!   format 2 `ReceiverInfo` carries no site and places nobody: an engine never takes a site
//!   from anything a client can read. The record also gives the receiver's site id (what a model
//!   names it by) and reception key (what its receptions are tagged under for clients), carried
//!   with its site ([`Sited`]). An area's members are these signed sites alone, never which
//!   receivers' raw arrived.
//! - A batch is used once: from a receiver that takes part (or is not described yet, below), with
//!   a (boot, sequence) not already used and not too far behind that boot's newest (§3.1,
//!   [`Intake::take`]).
//! - **Room is shared, refusal is whole, and neither depends on order** (RFC-0181 §9). The
//!   receivers seated across every intake of one engine are bounded by one count ([`Seats`],
//!   `Capacity::receivers`), and who is seated is a function of who is described: the best ranked
//!   (taking part first, then the key-hash rank, [`draw`]), whatever order they came in
//!   and whichever intake took them. A receiver outranked is refused whole (none of its raw held)
//!   and counted, and one that loses its seat to a better ranked one is let go whole. What a
//!   receiver's raw may hold is the arrived pool's own refusal, whole and counted.
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
//!   that wants the rank unpredictable gives all its peers one seed ([`Seats::keyed`]).
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
//! - **A batch before its receiver's description** is held like any other, so what the pool holds
//!   of a receiver never depends on when its description came. A model cites a member's raw as
//!   every batch at or below its frontier (`tally_mlat_solver::Frontier`), and the pool cites a
//!   member only once its batches are whole over the trailing window (`Arrived::inputs`): a
//!   receiver whose first batches were dropped for coming before its description would be cited
//!   by no model for a whole window, and a holder that dropped them and one that did not would
//!   rebuild different raw under one frontier. Room for receivers not described yet is one count
//!   across the engine's intakes (`Capacity::receivers`, [`Seats`]); one described outside the
//!   engine's regions, or never described, is let go with what it sent ([`Intake::expire`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tally_mlat_solver::obs::MAX_SITE_PRECISION_M;
use tally_mlat_solver::{BatchId, Reception, Site, Timebase};
use tally_wire::{
    Clock, Decoded, FingerprintKey, Location, PublicKey, ReceiverInfo, ReceiverSite, ReceptionKey,
    Record, Region, Regions, SiteId, WireError,
};

use crate::engine::Ingested;

/// How far behind a boot's newest sequence a batch may still arrive (two relays, or one relay's
/// reordering) and be used; anything older is a replay or too late to matter.
const REORDER: u64 = 64;
/// Boots remembered per receiver, most recent first. A receiver that restarts more often than
/// this often while its batches are still held only weakens its own replay protection.
const BOOTS_PER_RECEIVER: usize = 8;

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
    /// Receivers not described yet whose batches are held, across every intake of the engine:
    /// at most `limit` ([`Intake::take`]).
    undescribed: std::sync::atomic::AtomicUsize,
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
            undescribed: std::sync::atomic::AtomicUsize::new(0),
            secret,
            places: Mutex::new(Places::default()),
        })
    }

    /// `key`'s draw under these seats' secret ([`draw_under`]): what ranks it for a seat, and for
    /// room among the receivers not described yet ([`Intake::take`]).
    pub fn draw_of(&self, key: &PublicKey) -> u128 {
        draw_under(&self.secret, key)
    }

    /// Room for one more receiver not described yet: false when `limit` of them are held.
    fn hold_undescribed(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.undescribed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < self.limit).then_some(held + 1)
            })
            .is_ok()
    }

    /// A receiver not described yet was described, or let go.
    fn release_undescribed(&self) {
        use std::sync::atomic::Ordering;
        let _ = self
            .undescribed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_sub(1)
            });
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

/// True when the batch numbered `sequence` in `boot` has not been used, by `boots` (the
/// sequences used per boot, most recent boot first), which it then marks.
fn admit_in(boots: &mut VecDeque<(u64, Sequences)>, boot: u64, sequence: u64) -> bool {
    let found = boots
        .iter()
        .position(|(id, _)| *id == boot)
        .and_then(|at| boots.remove(at));
    let (admitted, sequences) = match found {
        Some((_, mut sequences)) => (sequences.admit(sequence), sequences),
        None => {
            boots.truncate(BOOTS_PER_RECEIVER - 1);
            (true, Sequences::new(sequence))
        }
    };
    boots.push_front((boot, sequences));
    admitted
}

/// A receiver whose batches came before its description (module docs): the sequences it used,
/// and the newest signed wall clock of its batches, which says when nothing of it is held any
/// more ([`Intake::expire`]).
struct Undescribed {
    boots: VecDeque<(u64, Sequences)>,
    newest_wall_ms: u64,
}

/// What a description or a change of regions did: what it was, the receivers here that stopped
/// taking part (their holder forgets what they heard, `Engine::forget_by`), and the receivers
/// whose seat changed that this intake does not hold (their own intakes settle them,
/// [`Intake::settle`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    pub ingested: Ingested,
    pub left: Vec<PublicKey>,
    pub moved: Vec<PublicKey>,
}

/// One holder's receivers (module docs): who takes part and the sequences each has used.
pub struct Intake {
    seats: Arc<Seats>,
    /// The engine's regions: a receiver inside one takes part (empty: every receiver with a
    /// location). `None`: no engine runs, and no receiver takes part.
    regions: Option<Regions>,
    receivers: BTreeMap<PublicKey, Described>,
    /// Receivers not described yet whose batches are held (module docs).
    undescribed: BTreeMap<PublicKey, Undescribed>,
    /// Receivers refused whole for room since the last call ([`Intake::take_refused`]).
    refused: u64,
}

impl Described {
    fn taking_part(&self) -> bool {
        self.seated && self.site.is_some()
    }
}

impl Intake {
    /// Receivers seated in `seats`, taking part in `regions`.
    pub fn new(seats: Arc<Seats>, regions: Option<Regions>) -> Self {
        Self {
            regions,
            receivers: BTreeMap::new(),
            undescribed: BTreeMap::new(),
            refused: 0,
            seats,
        }
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

    /// Receivers refused whole for room (outranked, or unseated by a better ranked one) since the
    /// last call.
    pub fn take_refused(&mut self) -> u64 {
        std::mem::take(&mut self.refused)
    }

    /// A receiver's site-bearing record (verified here: it is the receiver's own word). An error
    /// is one that does not verify.
    pub fn describe(&mut self, record: &SiteRecord) -> Result<Description, String> {
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
        // Batches it sent before it was described are held, and the sequences they used go with
        // its description.
        let early = self.undescribed.remove(&key);
        if early.is_some() {
            self.seats.release_undescribed();
        }
        let held_early = early.is_some();
        let boots = early.map_or_else(VecDeque::new, |early| early.boots);
        let known = self.receivers.entry(key).or_insert_with(|| Described {
            issued_ms: 0,
            bytes: Vec::new(),
            location: None,
            clock: content.clock,
            id,
            key: reception_key,
            site: None,
            seated: false,
            boots,
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
        let mut description = self.settle_all(changed);
        if self.settle_was(&key, was) {
            description.left.push(key);
        }
        let taking_part = self.receivers.get(&key).is_some_and(Described::taking_part);
        if held_early && !taking_part {
            // What it sent before its description is let go: it takes no part.
            description.left.push(key);
        }
        let seated = self.receivers.get(&key).is_some_and(|known| known.seated);
        if fresh && !seated {
            // Beyond the seats and outranked: refused whole, and counted.
            self.refused += 1;
        }
        description.ingested = if seated {
            Ingested::Described
        } else {
            Ingested::Refused
        };
        Ok(description)
    }

    /// Settles every receiver of `changed` this intake holds; the rest are another intake's.
    fn settle_all(&mut self, changed: Vec<PublicKey>) -> Description {
        let mut description = Description {
            ingested: Ingested::Ignored,
            left: Vec::new(),
            moved: Vec::new(),
        };
        for other in changed {
            if self.receivers.contains_key(&other) {
                if self.settle(&other) {
                    description.left.push(other);
                }
            } else {
                description.moved.push(other);
            }
        }
        description
    }

    /// Brings `receiver` to the place the seats give it now: seated or waiting, or forgotten
    /// with its description. True when it stopped taking part (its holder forgets what it heard,
    /// `Engine::forget_by`). A receiver that loses its seat is refused whole from then on, and
    /// counted. Settling twice, or late, is settling once: it reads where the receiver stands now.
    pub fn settle(&mut self, receiver: &PublicKey) -> bool {
        let was = self
            .receivers
            .get(receiver)
            .is_some_and(Described::taking_part);
        self.settle_was(receiver, was)
    }

    fn settle_was(&mut self, receiver: &PublicKey, was: bool) -> bool {
        let place = self.seats.place(receiver);
        let Some(known) = self.receivers.get_mut(receiver) else {
            return false;
        };
        let seated = place == Place::Seated;
        if known.seated && !seated {
            self.refused += 1;
        }
        known.seated = seated;
        let now = known.taking_part();
        if place == Place::Gone {
            self.receivers.remove(receiver);
        }
        let left = was && !now;
        if left && let Some(known) = self.receivers.get_mut(receiver) {
            // It stopped taking part: the sequences it used say nothing of its next part.
            known.boots.clear();
        }
        left
    }

    /// The engine's regions are now `regions` (`None`: no engine runs). Every receiver described
    /// is decided again on its own signed word, and ranked again for its seat: the receivers here
    /// that stopped taking part (their holder forgets what they heard), and those of other intakes
    /// whose seat changed.
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
            if self.settle_was(&key, was) {
                description.left.push(key);
            }
        }
        description
    }

    /// A new engine begins: nothing it used is the old one's. The descriptions stay (they are the
    /// receivers' word, not the engine's); the sequences used go.
    pub fn restart(&mut self) {
        for known in self.receivers.values_mut() {
            known.boots.clear();
        }
        for early in self.undescribed.values_mut() {
            early.boots.clear();
        }
        self.refused = 0;
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

    /// Whether the batch `batch`, signed at `wall_ms`, is to be used (module docs): from a
    /// receiver that takes part or is not described yet (while there is room for it, `Seats`),
    /// with a (boot, sequence) not already used and not too far behind that boot's newest. `Err`
    /// says why not: `Ingested::Ignored` (it takes no part, or there is no room for another
    /// receiver not described) or `Ingested::Replayed`. A batch used is used once, whatever it
    /// holds.
    pub fn take(&mut self, batch: &BatchId, wall_ms: u64) -> Result<(), Ingested> {
        let boots = match self.receivers.get_mut(&batch.receiver) {
            Some(known) if known.taking_part() => &mut known.boots,
            Some(_) => return Err(Ingested::Ignored),
            None => {
                if !self.undescribed.contains_key(&batch.receiver) {
                    if !self.seats.hold_undescribed() {
                        return Err(Ingested::Ignored);
                    }
                    self.undescribed.insert(
                        batch.receiver,
                        Undescribed {
                            boots: VecDeque::new(),
                            newest_wall_ms: wall_ms,
                        },
                    );
                }
                let Some(early) = self.undescribed.get_mut(&batch.receiver) else {
                    return Err(Ingested::Ignored);
                };
                early.newest_wall_ms = early.newest_wall_ms.max(wall_ms);
                &mut early.boots
            }
        };
        if !admit_in(boots, batch.boot_id, batch.sequence) {
            return Err(Ingested::Replayed);
        }
        Ok(())
    }

    /// Lets go of every receiver not described yet none of whose batches was signed within
    /// `held_ms` before `now_ms`: nothing of it is held any more. The ones let go.
    pub fn expire(&mut self, now_ms: u64, held_ms: u64) -> Vec<PublicKey> {
        let gone: Vec<PublicKey> = self
            .undescribed
            .iter()
            .filter(|(_, early)| early.newest_wall_ms.saturating_add(held_ms) < now_ms)
            .map(|(key, _)| *key)
            .collect();
        for key in &gone {
            self.undescribed.remove(key);
            self.seats.release_undescribed();
        }
        gone
    }
}

/// The receptions of a verified, decoded batch MLAT uses (`tally_wire::modes::wanted_reception`),
/// each with the batch's receiver, counter epoch and signed wall clock, in the batch's order;
/// with how many it carried that MLAT never uses. A function of the batch alone, so the thread
/// that holds the batch reads it (a relay's raw shard, RFC-0181 §5) and the engine only weighs
/// what it says.
pub fn receptions_of(batch: &Decoded) -> (Vec<Reception>, usize) {
    let mut filtered = 0;
    let receptions = batch
        .views()
        .filter_map(|view| {
            // A wanted reception is a Mode S message, so it is held inline.
            let message = tally_wire::modes::wanted_reception(view.format, view.data)
                .then(|| tally_mlat_solver::ModeS::new(view.data))
                .flatten();
            filtered += usize::from(message.is_none());
            Some(Reception {
                receiver: batch.receiver(),
                epoch: batch.counter_epoch(),
                timestamp: view.timestamp,
                message: message?,
                wall_ms: batch.wall_ms(),
            })
        })
        .collect();
    (receptions, filtered)
}

/// The batch `batch` is: its receiver, boot and sequence.
pub fn batch_id(batch: &Decoded) -> BatchId {
    BatchId {
        receiver: batch.receiver(),
        boot_id: batch.boot_id(),
        sequence: batch.sequence(),
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
