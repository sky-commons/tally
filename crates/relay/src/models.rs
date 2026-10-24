//! The decoded clock models of one relay (RFC-0181, "The models a relay holds"): one store, keyed
//! by manifest id, that standing (`standing`) and the positions checks (`consistency`) both read.
//! Before, each held its own assembly of parts and manifests and its own room of decoded models,
//! so every model was assembled, decoded and charged twice, and each table planned a decoded
//! model's lists at twice their length.
//!
//! **Fed once.** A model is taken whole where the hub assembles it, as its manifest goes out with
//! the parts it lists (`parts::Parts::manifest`, `Hub::take_clock_model`), and decoded there, once
//! ([`Models::admit`]), each list at exactly the length its encoding states. The hosted engine's
//! own models are the engine's own `Arc` ([`Models::insert_own`]): never decoded again.
//!
//! **Who may be held.** A model is of a tile, and a tile of the area its centre is in. Only a model
//! of a tile one of this relay's areas owns ([`Models::set_areas`]), signed by one of that area's
//! rendezvous MLAT relays (`selection::mlat_relays`, the closure [`Models::admit`] is given), is
//! held: anything else is refused and counted. Each engine holds one slot for each tile and window
//! ([`Slot`]): a second model of the same engine, tile and window is refused, counted, and a model
//! past [`MODEL_WINDOWS`] windows of one engine's tile is too. Three engines of an area each
//! publish their own, which may honestly differ, so all three are held.
//!
//! **How long.** A model is held in its slot until no record that may still come can cite it:
//! [`HELD_PAST_WINDOW_MS`] after its window's last bin (`Models::tick`, by the judging clock). Who
//! cites it (the book's finals, a check) holds a handle ([`Model`]); the bytes it took are charged
//! to `budget::Store::Models` when it is held and given back when its last handle goes. A model
//! whose window ends later than one sent now honestly may ([`HOLD_MS`]) is refused as early, so no
//! model is held longer than the hold its room is planned over.
//!
//! **What drives it** (RFC-0181, "The models a relay holds"). Models do not come from feeders: a
//! receiver of the figure brings none. They come from exactly two sources, each with a room of its
//! own sized by what drives it, the same shape as the positions checks' twins (`consistency`):
//!
//! - **The relay's own engine**, charged per seat ([`BYTES_PER_SEAT`]): what the engine can publish
//!   in a window for a seat ([`OWN_WINDOW_BYTES_PER_SEAT`], derived from what a window step
//!   outputs: a model only of a tile with a solution, whose members are the seats its footprint
//!   holds) over the windows a slot holds ([`MODEL_WINDOWS`]), and its newest window's records in
//!   flight (`mlat_host::publish_owning` charges them to the store as they are queued, each no
//!   larger than its model decoded).
//! - **The members**, whose MLAT records spend the members' pace by their signed bytes
//!   (`ingest::MemberPace`, `link::Admitted::in_flight`): what the pace brings over the hold
//!   ([`MEMBER_SECONDS`], Little's law), decoded at most [`DECODED_PER_WIRE_PERCENT`] of its wire
//!   bytes ([`BYTES_PER_MEMBER_FEEDER`] for each feeder the members' rate is worth). A model that
//!   decodes larger than that is refused as inflated, so the bound holds for anything sent.
//!
//! **Fair, never evicting.** Each source is held to its room ([`Rooms`]): past it a new model is
//! refused and counted (`over_share`), past the store's room too (`room`), and a model held is
//! never let go for room while anything cites it, nor before its time. The members share one room:
//! what a member forwards is a model an area's engine signed, held in that engine's slot (one a
//! tile and window), and the pace it spends is fair between member sessions already.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tally_mlat_solver::ClockModel as Decoded;
use tally_mlat_solver::tile::Tile;
use tally_wire::batch::Hash;
use tally_wire::clocks::Judged;
use tally_wire::{ClockModel, ClockModelContent, PublicKey, Region, Regions};

use crate::budget::{Charge, Gauge, Store};

/// A window step, milliseconds: the engine fits each tile's model once a stride of bins
/// (`scope::STRIDE` of `scope::GRID_MS`).
pub const STEP_MS: u64 =
    tally_mlat_solver::scope::STRIDE as u64 * tally_mlat_solver::scope::GRID_MS;
/// How long past its window's last bin a model is held: until the last final of a transmission in
/// its window is settled (`standing::SETTLE` and the second a solution may come early,
/// `standing::PENDING_SECONDS`), and until a provisional that carried it as far as it may be
/// carried (`clock::MAX_CARRY_PS`) has waited its longest in the hub for it (`hub::AWAITING_MS`),
/// whichever is later.
pub const HELD_PAST_WINDOW_MS: u64 = {
    let settled = crate::standing::PENDING_SECONDS as u64 * 1_000;
    let carried = (tally_mlat_solver::MAX_CARRY_PS / 1_000_000_000) as u64
        + crate::hub::AWAITING_MS.as_millis() as u64;
    if settled > carried { settled } else { carried }
};
/// The windows of one engine's tile held at once, at most: one is published a step, and each is
/// held [`HELD_PAST_WINDOW_MS`] past its last bin, which is before it is published. The models'
/// citation window: what standing's book may still cite.
pub const MODEL_WINDOWS: usize = HELD_PAST_WINDOW_MS.div_ceil(STEP_MS) as usize + 1;
/// The most two relays' judging clocks are apart (`budget::K`): an engine publishes a window once
/// its last bin is past by its own clock, which is at most this ahead of this relay's.
const CLOCKS_APART_MS: u64 = tally_wire::budget::K.span::<Judged>().ms();
/// The longest a model is held from when it comes, milliseconds: the models' citation window
/// ([`MODEL_WINDOWS`] steps). An honest model's window ended before it was published, by a clock
/// at most [`CLOCKS_APART_MS`] ahead of this relay's, so it is let go [`HELD_PAST_WINDOW_MS`] past
/// that at most, inside the hold; a model whose window ends later is refused as early.
pub const HOLD_MS: u64 = MODEL_WINDOWS as u64 * STEP_MS;
const _: () = assert!(HELD_PAST_WINDOW_MS + CLOCKS_APART_MS <= HOLD_MS);
/// The fewest members a model the engine publishes has: it is published only with a solution
/// (`window::Job`, "each tile model with a solution"), which cites a reception of each of
/// `solve::MIN_RECEIVERS_WITH_ALTITUDE` members of its scope at least.
pub const MODEL_MEMBERS_LEAST: usize = tally_mlat_solver::solve::MIN_RECEIVERS_WITH_ALTITUDE;

// The relay's own engine (module docs, "What drives it"). A window step fits a model only of a
// tile some target chose (`tile::assign`), its members the engine's seats whose sites the tile's
// footprint holds (`members_of`), and publishes it only with a solution, so with
// `MODEL_MEMBERS_LEAST` members at least. A seat's site is in the footprint of at most
// `tile::SITE_TILES_MOST` tiles that may be fitted, so in one window a seat is a member of that
// many of its engine's models at most, and the models are no more than the members over the
// fewest each has. Each model's bytes are exact in its members (`standing::model_bytes_most`: its
// fixed part and a member's share for each), so a window's models take at most a member's share
// for each membership and a model's fixed part and entries for each model.

/// The models of its own engine a seat is a member of in one window, at most.
pub const OWN_MEMBERSHIPS_PER_SEAT: usize = tally_mlat_solver::tile::SITE_TILES_MOST;
/// A seat's share of its own engine's models in one window, at most: its memberships over the
/// fewest members a published model has.
pub const OWN_MODELS_PER_SEAT: usize = OWN_MEMBERSHIPS_PER_SEAT.div_ceil(MODEL_MEMBERS_LEAST);
/// What a seat's share of one window of its own engine's models takes held, at most: each
/// membership a member's share, each model its fixed part and its entries.
pub const OWN_WINDOW_BYTES_PER_SEAT: usize = OWN_MEMBERSHIPS_PER_SEAT
    * tally_mlat_solver::standing::MODEL_BYTES_PER_MEMBER
    + OWN_MODELS_PER_SEAT * (tally_mlat_solver::standing::MODEL_FIXED_BYTES + ENTRY_BYTES);
/// The own engine's room for a seat ([`Rooms::own`]): its models held, [`MODEL_WINDOWS`] windows
/// of each slot.
pub const OWN_HELD_BYTES_PER_SEAT: usize = OWN_WINDOW_BYTES_PER_SEAT * MODEL_WINDOWS;
/// What one seat costs the store (`budget::Store::Models`): its own engine's models held
/// ([`OWN_HELD_BYTES_PER_SEAT`]), and its newest window's records queued and not yet taken
/// (`mlat_host::publish_owning`, each record no larger than its model decoded, `tables_bytes`
/// holds it), charged to the store beside the room.
pub const BYTES_PER_SEAT: usize = OWN_HELD_BYTES_PER_SEAT + OWN_WINDOW_BYTES_PER_SEAT;

// The members (module docs, "What drives it"). Their models spend the members' pace by their
// signed bytes, a planned feeder's charged bytes a second for each feeder the members' rate is
// worth (`budget::Plan::member_paced_bytes_per_sec`). A model is held at most `HOLD_MS` from when
// it comes, so by Little's law the members hold at most their pace over the hold, and the second
// of burst the pace allows beside it and its least burst (`ceiling::MIN_BURST`), as the twins do
// (`consistency::MEMBER_SECONDS`). Decoded, a model takes at most `DECODED_PER_WIRE_PERCENT` of
// the bytes it took on the wire.

/// What a model takes held over what it took on the wire, percent, at most: measured by the
/// counting allocator at every shape an engine fits (`tables_bytes`, the most of them, rounded up;
/// the worst is the fewest members with the fewest knots, whose lists' and entries' fixed parts
/// weigh most against their bytes). A model past it is refused as inflated.
pub const DECODED_PER_WIRE_PERCENT: usize = 184;
/// The seconds of the members' pace the members' room holds: the hold, and the second of burst
/// the pace allows beside it.
pub const MEMBER_SECONDS: usize = HOLD_MS.div_ceil(1_000) as usize + 1;
/// What `wire` bytes of models take held at most ([`DECODED_PER_WIRE_PERCENT`]).
pub const fn decoded_of(wire: usize) -> usize {
    (wire * DECODED_PER_WIRE_PERCENT).div_ceil(100)
}
/// What one planned feeder's worth of the members' rate costs the store: the pace it is worth
/// (`budget::PLANNED_CHARGED_BYTES_PER_SEC`) over the members' hold, decoded.
pub const BYTES_PER_MEMBER_FEEDER: usize =
    decoded_of(crate::budget::PLANNED_CHARGED_BYTES_PER_SEC * MEMBER_SECONDS);

/// What a held model's slot takes beside the model: its entry among the ids, its entry among the
/// slots (its engine's tile, with room for every window held), and its handle's own allocation.
const ENTRY_BYTES: usize = tally_wire::footprint::btree_planned::<Hash, (PublicKey, Tile)>(1)
    - tally_wire::footprint::btree_planned::<Hash, (PublicKey, Tile)>(0)
    + tally_wire::footprint::btree_planned::<(PublicKey, Tile), Vec<Model>>(1)
    - tally_wire::footprint::btree_planned::<(PublicKey, Tile), Vec<Model>>(0)
    + tally_wire::footprint::vec::<Model>(MODEL_WINDOWS)
    + tally_wire::footprint::arc::<Held>();

/// What a held model of `members` members takes at most: its lists exactly as decoded
/// (`standing::model_bytes_most`) and its entries ([`ENTRY_BYTES`]).
pub const fn held_bytes_most(members: usize) -> usize {
    tally_mlat_solver::standing::model_bytes_most(members) + ENTRY_BYTES
}

/// What the store holds whatever drives it: its two trees' roots, and where it has members their
/// least burst ([`Rooms::of`]).
pub const fn fixed_bytes(members: bool) -> usize {
    tally_wire::footprint::btree_planned::<Hash, (PublicKey, Tile)>(0)
        + tally_wire::footprint::btree_planned::<(PublicKey, Tile), Vec<Model>>(0)
        + if members {
            decoded_of(crate::ceiling::MIN_BURST as usize)
        } else {
            0
        }
}

/// What the store is sized from (`Budget::models_sizing`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizing {
    /// The hosted engine's seats (`Budget::mlat_seats`); none where MLAT is not hosted.
    pub seats: usize,
    /// The members' pace, the most of their records' signed bytes a second
    /// (`Plan::member_paced_bytes_per_sec`); none without members.
    pub members_bytes_per_sec: usize,
}

/// Each source's room, bytes held (module docs, "Fair, never evicting").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rooms {
    /// The relay's own engine's models held, for its seats ([`OWN_HELD_BYTES_PER_SEAT`]).
    pub own: usize,
    /// The members' models: their pace over [`MEMBER_SECONDS`] and its least burst, decoded.
    pub members: usize,
}

impl Rooms {
    pub const fn of(sizing: Sizing) -> Self {
        Self {
            own: sizing.seats * OWN_HELD_BYTES_PER_SEAT,
            members: if sizing.members_bytes_per_sec == 0 {
                0
            } else {
                decoded_of(
                    sizing.members_bytes_per_sec * MEMBER_SECONDS
                        + crate::ceiling::MIN_BURST as usize,
                )
            },
        }
    }

    /// Rooms that never fill: a store not yet sized (a test's).
    pub const UNSIZED: Self = Self {
        own: usize::MAX,
        members: usize::MAX,
    };
}

/// What the store allocates at most at `sizing`: its fixed part, each seat's models held and in
/// flight, and the members' pace over their hold, decoded. The budget plans no less: a seat at
/// [`BYTES_PER_SEAT`], each feeder the members' rate is worth at [`BYTES_PER_MEMBER_FEEDER`].
pub const fn planned_bytes(sizing: Sizing) -> usize {
    fixed_bytes(sizing.members_bytes_per_sec > 0)
        + sizing.seats * BYTES_PER_SEAT
        + decoded_of(sizing.members_bytes_per_sec * MEMBER_SECONDS)
}

/// What a model held takes: its lists at their capacity (`standing::model_bytes`) and its entries.
pub fn held_bytes(model: &Decoded) -> usize {
    tally_mlat_solver::standing::model_bytes(model) + ENTRY_BYTES
}

/// The slot a model is held in: its engine and tile (each window of it a place in the slot).
pub type Slot = (PublicKey, Tile);

/// Whose a model is: the relay's own engine's ([`Models::insert_own`]), or one the members sent
/// ([`Models::admit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Own,
    Members,
}

/// One source's room: its limit and what its models alive take.
struct Room {
    limit: AtomicUsize,
    held: AtomicUsize,
}

impl Room {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit: AtomicUsize::new(limit),
            held: AtomicUsize::new(0),
        })
    }

    /// `bytes` of the room, or `None` past its limit: never more than the limit, however large
    /// what is asked.
    fn take(self: &Arc<Self>, bytes: usize) -> Option<Taken> {
        let limit = self.limit.load(Ordering::Acquire);
        self.held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                held.checked_add(bytes).filter(|after| *after <= limit)
            })
            .ok()?;
        Some(Taken {
            room: Arc::clone(self),
            bytes,
        })
    }
}

/// What a model took of its source's room, given back when its last handle goes.
struct Taken {
    room: Arc<Room>,
    bytes: usize,
}

impl Drop for Taken {
    fn drop(&mut self) {
        self.room.held.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

/// A model held, and what it took of its room and of the store, given back when its last handle
/// goes.
struct Held {
    id: Hash,
    spec: u16,
    inputs: Hash,
    engine: PublicKey,
    model: Arc<Decoded>,
    bytes: usize,
    _taken: Taken,
    _charge: Charge,
}

/// A handle on a held model: what standing's book and the checks cite it by. Cloned freely; the
/// model's bytes are charged while any handle is alive.
#[derive(Clone)]
pub struct Model(Arc<Held>);

impl Model {
    /// Its manifest's id.
    pub fn id(&self) -> Hash {
        self.0.id
    }

    /// The specification it was encoded and fitted under.
    pub fn spec(&self) -> u16 {
        self.0.spec
    }

    /// The inputs it is the function of (`publish::inputs_id`).
    pub fn inputs(&self) -> &Hash {
        &self.0.inputs
    }

    /// The engine that signed it.
    pub fn engine(&self) -> &PublicKey {
        &self.0.engine
    }

    /// The model, decoded.
    pub fn model(&self) -> &Arc<Decoded> {
        &self.0.model
    }

    /// What it took of the store ([`held_bytes`]).
    pub fn bytes(&self) -> usize {
        self.0.bytes
    }
}

impl std::fmt::Debug for Model {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Model")
            .field("id", &self.0.id)
            .field("bytes", &self.0.bytes)
            .finish_non_exhaustive()
    }
}

impl tally_mlat_solver::standing::ModelRef for Model {
    fn model(&self) -> &Decoded {
        &self.0.model
    }

    fn inputs(&self) -> &Hash {
        &self.0.inputs
    }

    fn engine(&self) -> &PublicKey {
        &self.0.engine
    }
}

/// Why a model was not held, each counted ([`ModelsReport`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Its parts were not all there, or its encoding did not read, or it is not the function of
    /// the inputs it names.
    Unreadable,
    /// Of a tile none of this relay's areas owns.
    Outside,
    /// Signed by a relay that is not one of its area's rendezvous MLAT relays.
    NotAnEngine,
    /// Its window is past what may still cite it ([`HELD_PAST_WINDOW_MS`]).
    Stale,
    /// Its window ends later than a model sent now may honestly: it would be held past
    /// [`HOLD_MS`].
    Early,
    /// Its engine's slot holds a model of that window already, or [`MODEL_WINDOWS`] of them.
    SlotTaken,
    /// Its source's room is full ([`Rooms`]).
    OverShare,
    /// The store's room is full.
    Room,
    /// Larger than the plan holds a model of its members to (`held_bytes_most`): more members than
    /// a tile has, or a list longer than a fit makes.
    Oversized,
    /// A member's, decoding larger than [`DECODED_PER_WIRE_PERCENT`] of its wire bytes.
    Inflated,
}

/// What the store holds now and has refused, since the relay started (`/memory`'s `models`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ModelsReport {
    pub held: usize,
    /// What the models alive take (held, or let go and still cited).
    pub bytes: usize,
    /// What the own engine's and the members' models alive take of their rooms, and the rooms.
    pub own_bytes: usize,
    pub own_room: usize,
    pub members_bytes: usize,
    pub members_room: usize,
    pub admitted: u64,
    pub own: u64,
    pub unreadable: u64,
    pub outside: u64,
    pub not_an_engine: u64,
    pub stale: u64,
    pub early: u64,
    pub slot_taken: u64,
    pub own_over_share: u64,
    pub members_over_share: u64,
    pub room: u64,
    pub oversized: u64,
    pub inflated: u64,
}

#[derive(Default)]
struct Counts {
    admitted: AtomicU64,
    own: AtomicU64,
    unreadable: AtomicU64,
    outside: AtomicU64,
    not_an_engine: AtomicU64,
    stale: AtomicU64,
    early: AtomicU64,
    slot_taken: AtomicU64,
    own_over_share: AtomicU64,
    members_over_share: AtomicU64,
    room: AtomicU64,
    oversized: AtomicU64,
    inflated: AtomicU64,
}

struct Table {
    ids: BTreeMap<Hash, Slot>,
    slots: BTreeMap<Slot, Vec<Model>>,
    /// The areas whose tiles are held; empty, the whole world.
    areas: Regions,
}

/// The relay's decoded clock models (module docs).
pub struct Models {
    table: Mutex<Table>,
    gauge: Mutex<Arc<Gauge>>,
    own: Arc<Room>,
    members: Arc<Room>,
    counts: Counts,
}

impl Default for Models {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a model of `window` stops being held, by the judging clock: [`HELD_PAST_WINDOW_MS`] past
/// its last bin.
fn released_ms(window: &tally_mlat_solver::scope::Window) -> u64 {
    (window.last.max(0) as u64 + 1)
        .saturating_mul(tally_mlat_solver::scope::GRID_MS)
        .saturating_add(HELD_PAST_WINDOW_MS)
}

impl Models {
    /// A store charged to no budget (an unlimited gauge) and its rooms unsized
    /// ([`Rooms::UNSIZED`]) until it is sized ([`Models::size_for`]).
    pub fn new() -> Self {
        Self {
            table: Mutex::new(Table {
                ids: BTreeMap::new(),
                slots: BTreeMap::new(),
                areas: Regions::default(),
            }),
            gauge: Mutex::new(Gauge::unlimited(Store::Models)),
            own: Room::new(Rooms::UNSIZED.own),
            members: Room::new(Rooms::UNSIZED.members),
            counts: Counts::default(),
        }
    }

    /// Charges every model held from now to `gauge` (`budget::Store::Models`), whose limit is the
    /// store's room. Models already held keep the charge they were held under.
    pub fn charge_to(&self, gauge: Arc<Gauge>) {
        *self
            .gauge
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = gauge;
    }

    /// Sizes each source's room from what drives it ([`Rooms::of`]) and charges the store to
    /// `gauge`. A room made smaller than what its models take refuses new ones until they go; none
    /// held is let go for it.
    pub fn size_for(&self, sizing: Sizing, gauge: Arc<Gauge>) {
        self.set_rooms(Rooms::of(sizing));
        self.charge_to(gauge);
    }

    /// Each source's room set to `rooms` (a test's, or [`Models::size_for`]'s).
    pub fn set_rooms(&self, rooms: Rooms) {
        self.own.limit.store(rooms.own, Ordering::Release);
        self.members.limit.store(rooms.members, Ordering::Release);
    }

    /// The areas this relay holds models for: a model of a tile none of them owns is refused. None,
    /// the whole world.
    pub fn set_areas(&self, areas: &Regions) {
        self.table().areas = areas.clone();
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn gauge(&self) -> Arc<Gauge> {
        Arc::clone(
            &self
                .gauge
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    fn room(&self, class: Class) -> &Arc<Room> {
        match class {
            Class::Own => &self.own,
            Class::Members => &self.members,
        }
    }

    fn refuse(&self, why: Refused, class: Class) -> Refused {
        let counter = match why {
            Refused::Unreadable => &self.counts.unreadable,
            Refused::Outside => &self.counts.outside,
            Refused::NotAnEngine => &self.counts.not_an_engine,
            Refused::Stale => &self.counts.stale,
            Refused::Early => &self.counts.early,
            Refused::SlotTaken => &self.counts.slot_taken,
            Refused::OverShare => match class {
                Class::Own => &self.counts.own_over_share,
                Class::Members => &self.counts.members_over_share,
            },
            Refused::Room => &self.counts.room,
            Refused::Oversized => &self.counts.oversized,
            Refused::Inflated => &self.counts.inflated,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        why
    }

    /// The model held under manifest id `id`, if any.
    pub fn get(&self, id: &Hash) -> Option<Model> {
        let table = self.table();
        let slot = table.ids.get(id)?;
        table
            .slots
            .get(slot)?
            .iter()
            .find(|model| model.0.id == *id)
            .cloned()
    }

    /// A whole model the hub assembled from what the members sent (its verified manifest and its
    /// `content`, the parts it lists joined): held, decoded once, in the members' room, when its
    /// tile is of this relay's areas and its signer is one of that area's rendezvous MLAT relays
    /// (`is_engine` of the area and the signer), it decodes no larger than its wire bytes allow
    /// ([`DECODED_PER_WIRE_PERCENT`]), its engine's slot of that window is free and its room and
    /// the store have room; else refused and counted. Read by the judging clock `now`. One held
    /// already is its handle again, decoded nothing.
    pub fn admit(
        &self,
        manifest: &ClockModel,
        content: &ClockModelContent,
        is_engine: impl Fn(Region, &PublicKey) -> bool,
        now: Judged,
    ) -> Result<Model, Refused> {
        let id = manifest.id();
        if let Some(held) = self.get(&id) {
            return Ok(held);
        }
        let class = Class::Members;
        let Ok(engine) = manifest.engine() else {
            return Err(self.refuse(Refused::Unreadable, class));
        };
        // The tile leads the encoding: placed and checked before anything is decoded.
        let Ok(tile) = tally_mlat_solver::publish::tile_of(&content.model) else {
            return Err(self.refuse(Refused::Unreadable, class));
        };
        self.placed(tile, &engine, &is_engine)?;
        let Ok(decoded) = tally_mlat_solver::publish::decode(&content.model, content.spec_version)
        else {
            return Err(self.refuse(Refused::Unreadable, class));
        };
        if tally_mlat_solver::publish::inputs_id(&decoded) != content.inputs {
            return Err(self.refuse(Refused::Unreadable, class));
        }
        // What it spent of the members' pace, at least: its manifest, which carries its encoding
        // inline or lists the parts that do.
        let wire = manifest.as_bytes().len().max(content.model.len());
        if held_bytes(&decoded) > decoded_of(wire) {
            return Err(self.refuse(Refused::Inflated, class));
        }
        let held = self.hold(
            id,
            content.spec_version,
            content.inputs,
            engine,
            Arc::new(decoded),
            class,
            now,
        )?;
        self.counts.admitted.fetch_add(1, Ordering::Relaxed);
        Ok(held)
    }

    /// The hosted engine's own model, signed by `engine` under manifest id `id`: its own `Arc`,
    /// held as [`Models::admit`] holds one but in the own engine's room and never decoded, so the
    /// relay's own models are decoded nowhere. Its inputs are the model's own
    /// (`publish::inputs_id`).
    pub fn insert_own(
        &self,
        id: Hash,
        model: Arc<Decoded>,
        engine: PublicKey,
        now: Judged,
    ) -> Result<Model, Refused> {
        if let Some(held) = self.get(&id) {
            return Ok(held);
        }
        let inputs = tally_mlat_solver::publish::inputs_id(&model);
        let spec = model.spec;
        let held = self.hold(id, spec, inputs, engine, model, Class::Own, now)?;
        self.counts.own.fetch_add(1, Ordering::Relaxed);
        Ok(held)
    }

    /// Whether a model of `tile` signed by `engine` may be held here: its tile of the areas, its
    /// signer one of its area's engines.
    fn placed(
        &self,
        tile: Tile,
        engine: &PublicKey,
        is_engine: &impl Fn(Region, &PublicKey) -> bool,
    ) -> Result<(), Refused> {
        let owned = {
            let table = self.table();
            table.areas.is_empty() || tally_mlat::window::owns(&table.areas, tile)
        };
        if !owned {
            return Err(self.refuse(Refused::Outside, Class::Members));
        }
        let area = Region::containing(
            &tally_mlat::area::centre(tile),
            tally_wire::rendezvous::AREA_RESOLUTION,
        );
        match area {
            Ok(area) if is_engine(area, engine) => Ok(()),
            _ => Err(self.refuse(Refused::NotAnEngine, Class::Members)),
        }
    }

    /// Holds `model` in its engine's slot for its tile and window, in `class`'s room, charged its
    /// bytes.
    #[allow(
        clippy::too_many_arguments,
        reason = "a held model's fields, each once"
    )]
    fn hold(
        &self,
        id: Hash,
        spec: u16,
        inputs: Hash,
        engine: PublicKey,
        model: Arc<Decoded>,
        class: Class,
        now: Judged,
    ) -> Result<Model, Refused> {
        let released = released_ms(&model.window);
        if released <= now.ms() {
            return Err(self.refuse(Refused::Stale, class));
        }
        if released > now.ms().saturating_add(HOLD_MS) {
            return Err(self.refuse(Refused::Early, class));
        }
        let slot = (engine, model.tile);
        let bytes = held_bytes(&model);
        if model.scope.len() > tally_mlat_solver::tile::MEMBERS_MAX
            || bytes > held_bytes_most(model.scope.len())
        {
            return Err(self.refuse(Refused::Oversized, class));
        }
        let gauge = self.gauge();
        let mut table = self.table();
        if let Some(held) = table.ids.get(&id).and_then(|slot| {
            table
                .slots
                .get(slot)
                .and_then(|models| models.iter().find(|held| held.0.id == id).cloned())
        }) {
            return Ok(held);
        }
        let taken = table.slots.get(&slot).is_some_and(|models| {
            models.len() >= MODEL_WINDOWS
                || models
                    .iter()
                    .any(|held| held.0.model.window.first == model.window.first)
        });
        if taken {
            drop(table);
            return Err(self.refuse(Refused::SlotTaken, class));
        }
        let Some(share) = self.room(class).take(bytes) else {
            drop(table);
            return Err(self.refuse(Refused::OverShare, class));
        };
        let Some(charge) = gauge.try_charge(bytes) else {
            drop(table);
            return Err(self.refuse(Refused::Room, class));
        };
        let held = Model(Arc::new(Held {
            id,
            spec,
            inputs,
            engine,
            model,
            bytes,
            _taken: share,
            _charge: charge,
        }));
        table
            .slots
            .entry(slot)
            .or_insert_with(|| Vec::with_capacity(MODEL_WINDOWS))
            .push(held.clone());
        table.ids.insert(id, slot);
        Ok(held)
    }

    /// Lets go of every model no record that may still come can cite, by the judging clock `now`
    /// ([`HELD_PAST_WINDOW_MS`]): its slot's handle goes, and its bytes with the last handle.
    pub fn tick(&self, now: Judged) {
        let now_ms = now.ms();
        let mut table = self.table();
        let Table { ids, slots, .. } = &mut *table;
        slots.retain(|_, models| {
            models.retain(|held| {
                let keep = released_ms(&held.0.model.window) > now_ms;
                if !keep {
                    ids.remove(&held.0.id);
                }
                keep
            });
            !models.is_empty()
        });
    }

    /// What the store holds now and has refused (`/memory`'s `models`).
    pub fn report(&self) -> ModelsReport {
        let held = self.table().ids.len();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ModelsReport {
            held,
            bytes: self.gauge().held(),
            own_bytes: self.own.held.load(Ordering::Acquire),
            own_room: self.own.limit.load(Ordering::Acquire),
            members_bytes: self.members.held.load(Ordering::Acquire),
            members_room: self.members.limit.load(Ordering::Acquire),
            admitted: load(&self.counts.admitted),
            own: load(&self.counts.own),
            unreadable: load(&self.counts.unreadable),
            outside: load(&self.counts.outside),
            not_an_engine: load(&self.counts.not_an_engine),
            stale: load(&self.counts.stale),
            early: load(&self.counts.early),
            slot_taken: load(&self.counts.slot_taken),
            own_over_share: load(&self.counts.own_over_share),
            members_over_share: load(&self.counts.members_over_share),
            room: load(&self.counts.room),
            oversized: load(&self.counts.oversized),
            inflated: load(&self.counts.inflated),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_wire::Identity;
    use tally_wire::clocks::recorded::judged;

    fn key(seed: u8) -> PublicKey {
        Identity::from_seed([seed; 32]).public()
    }

    /// A model of `members` members (each with a clock piece of two knots) of `tile` and the
    /// window of step `step`.
    fn model(tile: Tile, step: i64, members: u8) -> Arc<Decoded> {
        let scope: Vec<tally_mlat_solver::Site> = (0..members)
            .map(|seed| tally_mlat_solver::Site {
                receiver: key(seed),
                clock: tally_wire::Clock::from_byte(0),
                id: tally_wire::SiteId([seed; 32]),
                location: tally_wire::Location {
                    lat_e7: 0,
                    lon_e7: 0,
                    alt_m: 0,
                    precision_m: 0,
                },
            })
            .collect();
        let first = step * tally_mlat_solver::scope::STRIDE;
        let mut model = Decoded {
            spec: tally_mlat_solver::SPEC_VERSION,
            tile,
            window: tally_mlat_solver::scope::Window {
                first,
                last: first + 10,
            },
            scope,
            input: tally_mlat_solver::scope::Citation {
                hash: [7; 32],
                count: 3,
            },
            gauge: tally_mlat_solver::clock::ClockKey {
                receiver: key(0),
                epoch: 1,
                piece: 0,
            },
            origin_unix_ns: 0,
            gauge_rate: 0,
            pieces: Vec::new(),
            biases: Vec::new(),
            jumps: Vec::new(),
            dropped: Vec::new(),
        };
        model.shrink_to_fit();
        Arc::new(model)
    }

    const TILE: Tile = Tile {
        level: 0,
        cube: [1, 2, 3],
    };

    /// The judging clock the tests hold models at: step 0's window (its last bin the 11th) not yet
    /// let go, and a window of each of the next steps a slot holds not past the hold.
    const NOW_MS: u64 = HELD_PAST_WINDOW_MS + 30_000;

    fn now() -> Judged {
        judged(NOW_MS)
    }

    /// `model` as a member sends it: its manifest signed by `engine`, its encoding inline.
    fn sent(model: &Decoded, engine: u8) -> Result<(ClockModel, ClockModelContent), String> {
        let encoded =
            tally_mlat_solver::publish::encode(model).map_err(|error| format!("{error:?}"))?;
        let content = ClockModelContent {
            boot_id: 1,
            sequence: 0,
            issued_ms: 1_000,
            spec_version: model.spec,
            inputs: tally_mlat_solver::publish::inputs_id(model),
            model: encoded,
        };
        let signed = ClockModel::sign(&Identity::from_seed([engine; 32]), &content)
            .map_err(|error| error.to_string())?;
        let content = signed
            .manifest
            .content(&signed.parts)
            .map_err(|error| error.to_string())?;
        Ok((signed.manifest, content))
    }

    /// A model of `members` members as an engine fits it: each member's clock a piece of two knots
    /// (the gauge's all zero), so its encoding reads.
    fn fitted(tile: Tile, step: i64, members: u8) -> Decoded {
        let mut model = Arc::unwrap_or_clone(model(tile, step, members));
        let mut scope = model.scope.clone();
        scope.sort_by_key(|site| site.receiver);
        for site in &mut scope {
            site.clock = tally_wire::Clock::Beast;
        }
        model.scope = scope;
        model.pieces = model
            .scope
            .iter()
            .map(|site| tally_mlat_solver::clock::ClockPiece {
                key: tally_mlat_solver::clock::ClockKey {
                    receiver: site.receiver,
                    epoch: 1,
                    piece: 0,
                },
                timebase: tally_mlat_solver::clock::Timebase::Mhz12,
                begins: None,
                ends: None,
                site_mm: [1, 2, 3],
                site_sigma_mm: 1_000,
                noise_ps: 50_000,
                base: 0,
                first: 0,
                offsets_ps: vec![0, 0],
            })
            .collect();
        model.gauge = model.pieces[0].key;
        let pieces = model.pieces.len();
        for piece in &mut model.pieces[1..pieces] {
            piece.offsets_ps = vec![1, 2];
        }
        model
    }

    /// The engine's own models are held as their own `Arc`, charged as held and given back when
    /// the last handle goes, never before its time and never for room: past the store's room a
    /// new one is refused and counted; a second of a slot's window, or past its windows, is
    /// refused; a model past its time is stale, and let go by the clock.
    #[test]
    fn a_model_is_held_charged_and_let_go_with_its_last_handle() -> Result<(), String> {
        let store = Models::new();
        let one = model(TILE, 0, 3);
        let bytes = held_bytes(&one);
        store.charge_to(crate::budget::Gauge::new(Store::Models, 2 * bytes));
        let held = store
            .insert_own([1; 32], Arc::clone(&one), key(100), now())
            .map_err(|why| format!("{why:?}"))?;
        assert!(Arc::ptr_eq(held.model(), &one), "never decoded again");
        assert_eq!(store.report().bytes, bytes);
        // The same window of the slot again: refused.
        assert_eq!(
            store
                .insert_own([2; 32], model(TILE, 0, 3), key(100), now())
                .err(),
            Some(Refused::SlotTaken)
        );
        // Another engine's of the same tile and window is its own slot.
        let other = store
            .insert_own([3; 32], model(TILE, 0, 3), key(101), now())
            .map_err(|why| format!("{why:?}"))?;
        // Past the room: refused, nothing held let go.
        assert_eq!(
            store
                .insert_own([4; 32], model(TILE, 1, 3), key(100), now())
                .err(),
            Some(Refused::Room)
        );
        assert_eq!(store.report().held, 2);
        assert_eq!(store.report().room, 1);
        // Let go by the clock once nothing may cite it, but its bytes stay while a handle does.
        let late = released_ms(&one.window);
        store.tick(judged(late));
        assert_eq!(store.report().held, 0);
        assert_eq!(store.report().bytes, 2 * bytes);
        drop(other);
        assert_eq!(store.report().bytes, bytes);
        drop(held);
        assert_eq!(store.report().bytes, 0);
        // Past its time: stale.
        assert_eq!(
            store
                .insert_own([5; 32], model(TILE, 0, 3), key(100), judged(late))
                .err(),
            Some(Refused::Stale)
        );
        Ok(())
    }

    /// A slot holds `MODEL_WINDOWS` windows at most: one more is refused and counted, the ones
    /// held kept.
    #[test]
    fn a_slot_holds_its_windows_and_refuses_one_more() -> Result<(), String> {
        let store = Models::new();
        let mut held = Vec::new();
        for step in 0..MODEL_WINDOWS as i64 {
            held.push(
                store
                    .insert_own([step as u8; 32], model(TILE, step, 3), key(100), now())
                    .map_err(|why| format!("{why:?}"))?,
            );
        }
        // Another window, neither stale nor early: its slot is full.
        let mut another = Arc::unwrap_or_clone(model(TILE, 0, 3));
        another.window.first += 1;
        another.window.last += 1;
        assert_eq!(
            store
                .insert_own([200; 32], Arc::new(another), key(100), now())
                .err(),
            Some(Refused::SlotTaken)
        );
        assert_eq!(store.report().held, MODEL_WINDOWS);
        Ok(())
    }

    /// A model whose window ends later than one sent now may honestly is refused as early, from
    /// either source: it would be held past the hold its room is planned over. One at the edge of
    /// the hold is held.
    #[test]
    fn a_model_held_past_the_hold_is_refused_as_early() -> Result<(), String> {
        let store = Models::new();
        // Released the last bin inside `HOLD_MS` from now: held.
        let mut edge = Arc::unwrap_or_clone(model(TILE, 0, 3));
        let bins = (NOW_MS + HOLD_MS - HELD_PAST_WINDOW_MS) / tally_mlat_solver::scope::GRID_MS;
        edge.window.last = bins as i64 - 1;
        let released = released_ms(&edge.window);
        assert!(
            released <= NOW_MS + HOLD_MS
                && released + tally_mlat_solver::scope::GRID_MS > NOW_MS + HOLD_MS
        );
        store
            .insert_own([1; 32], Arc::new(edge.clone()), key(100), now())
            .map_err(|why| format!("{why:?}"))?;
        // A bin later: early, from the own engine and from a member alike.
        let mut early = edge;
        early.window.first += 1;
        early.window.last += 1;
        assert_eq!(
            store
                .insert_own([2; 32], Arc::new(early.clone()), key(101), now())
                .err(),
            Some(Refused::Early)
        );
        let mut sent_early = fitted(TILE, 0, 3);
        sent_early.window = early.window;
        let (manifest, content) = sent(&sent_early, 7)?;
        assert_eq!(
            store.admit(&manifest, &content, |_, _| true, now()).err(),
            Some(Refused::Early)
        );
        assert_eq!(store.report().early, 2);
        Ok(())
    }

    /// Each source is held to its own room (`Rooms`): past it a new model is refused and counted
    /// against that source, nothing held is let go for it, and the other source's room is untouched;
    /// what a model took is given back to its room with its last handle.
    #[test]
    fn each_source_is_held_to_its_room_and_never_evicts() -> Result<(), String> {
        let store = Models::new();
        let member = fitted(TILE, 0, 3);
        let bytes = held_bytes(&model(TILE, 0, 3));
        let member_bytes = held_bytes(&member);
        store.set_rooms(Rooms {
            own: 2 * bytes,
            members: member_bytes,
        });
        let first = store
            .insert_own([1; 32], model(TILE, 0, 3), key(100), now())
            .map_err(|why| format!("{why:?}"))?;
        let _second = store
            .insert_own([2; 32], model(TILE, 0, 3), key(101), now())
            .map_err(|why| format!("{why:?}"))?;
        assert_eq!(
            store
                .insert_own([3; 32], model(TILE, 0, 3), key(102), now())
                .err(),
            Some(Refused::OverShare)
        );
        // The members' room is their own: a member's model is held beside the full own room.
        let (manifest, content) = sent(&member, 7)?;
        let held = store
            .admit(&manifest, &content, |_, _| true, now())
            .map_err(|why| format!("{why:?}"))?;
        let mut more = fitted(TILE, 1, 3);
        more.tile.cube[0] += 1;
        let (manifest, content) = sent(&more, 8)?;
        assert_eq!(
            store.admit(&manifest, &content, |_, _| true, now()).err(),
            Some(Refused::OverShare)
        );
        let report = store.report();
        assert_eq!(
            (
                report.held,
                report.own_over_share,
                report.members_over_share
            ),
            (3, 1, 1),
            "{report:?}"
        );
        assert_eq!(
            (report.own_bytes, report.members_bytes),
            (2 * bytes, member_bytes)
        );
        // Let go by the clock and its last handle gone: its room has it back.
        store.tick(judged(released_ms(&held.model().window)));
        drop((first, held));
        let report = store.report();
        assert_eq!(
            (report.own_bytes, report.members_bytes),
            (bytes, 0),
            "{report:?}"
        );
        store
            .admit(&manifest, &content, |_, _| true, now())
            .map_err(|why| format!("{why:?}"))?;
        Ok(())
    }

    /// A member's model that decodes larger than `DECODED_PER_WIRE_PERCENT` of its wire bytes is
    /// refused as inflated, so the members' room, planned from their pace, holds whatever they
    /// send; one an engine fits is held.
    #[test]
    fn a_members_model_past_its_wire_ratio_is_refused() -> Result<(), String> {
        let store = Models::new();
        let fit = fitted(TILE, 0, 3);
        let (manifest, content) = sent(&fit, 7)?;
        store
            .admit(&manifest, &content, |_, _| true, now())
            .map_err(|why| format!("{why:?}"))?;
        // One member, its piece's knots the fewest: its fixed part weighs past the ratio.
        let mut lone = fitted(TILE, 0, 1);
        lone.tile.cube[0] += 1;
        let (manifest, content) = sent(&lone, 7)?;
        let wire = manifest.as_bytes().len().max(content.model.len());
        let decoded = tally_mlat_solver::publish::decode(&content.model, content.spec_version)
            .map_err(|error| format!("{error:?}"))?;
        assert!(
            held_bytes(&decoded) > decoded_of(wire),
            "{wire} on the wire"
        );
        assert_eq!(
            store.admit(&manifest, &content, |_, _| true, now()).err(),
            Some(Refused::Inflated)
        );
        assert_eq!(store.report().inflated, 1);
        Ok(())
    }

    /// A model larger than the plan holds a model of its members to, or of more members than a tile
    /// has, is refused and counted.
    #[test]
    fn a_model_past_its_planned_size_is_refused() {
        let store = Models::new();
        let mut large = Arc::unwrap_or_clone(model(TILE, 0, 3));
        large
            .biases
            .reserve_exact(4 * tally_mlat_solver::standing::BIASES_MOST);
        assert_eq!(
            store
                .insert_own([1; 32], Arc::new(large), key(100), now())
                .err(),
            Some(Refused::Oversized)
        );
        let crowded = model(TILE, 0, (tally_mlat_solver::tile::MEMBERS_MAX + 1) as u8);
        assert_eq!(
            store.insert_own([2; 32], crowded, key(100), now()).err(),
            Some(Refused::Oversized)
        );
        assert_eq!(store.report().oversized, 2);
    }

    /// Only a model of a tile one of the areas owns, signed by one of that area's engines, is
    /// held: anything else is refused and counted.
    #[test]
    fn only_a_model_of_the_areas_signed_by_their_engine_is_placed() -> Result<(), String> {
        let store = Models::new();
        let centre = tally_mlat::area::centre(TILE);
        let area = Region::containing(&centre, tally_wire::rendezvous::AREA_RESOLUTION)
            .map_err(|error| error.to_string())?;
        store.set_areas(&Regions::new([area]));
        let engine = key(100);
        let is_engine = |at: Region, signer: &PublicKey| at == area && *signer == engine;
        assert_eq!(store.placed(TILE, &engine, &is_engine), Ok(()));
        assert_eq!(
            store.placed(TILE, &key(101), &is_engine),
            Err(Refused::NotAnEngine)
        );
        let elsewhere = Tile {
            level: 0,
            cube: [-100, 200, 50],
        };
        assert_eq!(
            store.placed(elsewhere, &engine, &is_engine),
            Err(Refused::Outside)
        );
        let report = store.report();
        assert_eq!((report.not_an_engine, report.outside), (1, 1));
        Ok(())
    }

    /// A seat's line holds a window of its own engine's models at their most, at every member
    /// count a model may have: its memberships spread over models of that many members each, and
    /// a model's most is exact (its fixed part and a member's share for each member). The rooms
    /// are what drives them, and the plan holds each room and a seat's records in flight.
    #[test]
    fn the_lines_hold_what_drives_them() {
        for members in MODEL_MEMBERS_LEAST..=tally_mlat_solver::tile::MEMBERS_MAX {
            // As many models of `members` members as a seat's memberships fill.
            assert!(
                OWN_MEMBERSHIPS_PER_SEAT / members * held_bytes_most(members)
                    <= OWN_WINDOW_BYTES_PER_SEAT,
                "{members} members"
            );
            assert_eq!(
                tally_mlat_solver::standing::model_bytes_most(members),
                tally_mlat_solver::standing::MODEL_FIXED_BYTES
                    + members * tally_mlat_solver::standing::MODEL_BYTES_PER_MEMBER
            );
        }
        for (seats, rate) in [(0, 0), (1, 0), (0, 1), (7, 65_536), (2_000, 1 << 24)] {
            let sizing = Sizing {
                seats,
                members_bytes_per_sec: rate,
            };
            let rooms = Rooms::of(sizing);
            assert_eq!(rooms.own, seats * OWN_HELD_BYTES_PER_SEAT);
            assert_eq!(rooms.members == 0, rate == 0);
            assert!(
                fixed_bytes(rate > 0) - fixed_bytes(false) + decoded_of(rate * MEMBER_SECONDS)
                    >= rooms.members
            );
            assert!(
                planned_bytes(sizing)
                    >= fixed_bytes(false)
                        + rooms.own
                        + rooms.members
                        + seats * OWN_WINDOW_BYTES_PER_SEAT
            );
        }
    }
}
