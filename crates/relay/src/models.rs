//! The decoded clock models of one relay (RFC-0181, "The models a relay holds"): one store, keyed
//! by pair model id (`publish::pair_model_id`, a content address: the same model signed by two of
//! its area's engines is one entry), that standing (`standing`), the positions checks
//! (`consistency`) and the hosted engine's neighbouring models (`mlat_host`) all read. Before,
//! each held its own assembly of parts and manifests and its own room of decoded models, so every
//! model was assembled, decoded and charged twice.
//!
//! **Fed once.** A model is taken whole where the hub assembles it, as its manifest goes out with
//! the parts it lists (`parts::Parts::manifest`, `Hub::take_clock_model`), and decoded there, once
//! ([`Models::admit`]), into the engine's own form (`tally_mlat::fix::Held`: decoded, identified
//! and prepared), so the hosted engine reads a neighbour's model from the same `Arc`
//! (`Engine::hold`). The hosted engine's own models are the engine's own `Arc`
//! ([`Models::insert_own`]): never decoded again.
//!
//! **Who may be held.** A model is of an area (`tally_mlat_solver` crate docs, § Areas; its
//! encoding leads with it, `publish::area_of`). Only a model of an area this relay's areas or
//! their border band hold ([`Models::set_areas`], `tally_mlat::area::Band`: the areas a fix of
//! this relay's may cite beside its owner's), signed by one of that area's rendezvous MLAT relays
//! (`selection::mlat_relays`, the closure [`Models::admit`] is given), on the refit grid (its edge
//! a multiple of `REFIT_EVERY`, as every engine fits, `Trailing::fitted_at`), is held: anything
//! else is refused and counted. Each area's engines refit it every `REFIT_EVERY` at the same edge;
//! each may honestly fit different bytes (each fits what had arrived at it), so a slot, one area
//! at one edge ([`Slot`]), holds a model for each of its engines ([`MODELS_PER_SLOT`]), and an
//! engine's second, different model of one slot is refused, counted. The same model signed again
//! by another of its engines is one entry, its signers counted ([`Model::signers`]): two
//! distinct engines of an area signing the same bytes corroborate them (`mlat_host`, which holds
//! a neighbour's model it cannot verify itself only so).
//!
//! **How long.** A model is held in its slot until no fix that may still come or still be settled
//! can cite it: [`HELD_PAST_EDGE_MS`] past its trailing edge (`Models::tick`, by the judging
//! clock). Who cites it (the book's fixes, a check, the engine) holds a handle ([`Model`], or the
//! engine's `Arc`); the bytes it took are charged to `budget::Store::Models` when it is held and
//! given back when its last handle goes. A model whose edge is later than one sent now honestly may
//! ([`HOLD_MS`]) is refused as early, so no model is held longer than the hold its room is planned
//! over.
//!
//! **What drives it** (RFC-0181, "The models a relay holds"). Models do not come from feeders: a
//! receiver of the figure brings none. They come from exactly two sources, each with a room of its
//! own sized by what drives it:
//!
//! - **The relay's own engine**, charged per seat ([`BYTES_PER_SEAT`]): every area it owns is
//!   refit every `REFIT_EVERY`, each model at most [`MODEL_BYTES_PER_RECEIVER`] for each of its
//!   area's receivers (measured, `tables_bytes`) and its entries once ([`ENTRY_BYTES`]), so a seat
//!   brings at most that a refit ([`OWN_BYTES_PER_SEAT_PER_SEC`]), over the hold
//!   ([`OWN_SECONDS`]), and the newest step's in flight (`mlat_host` hands them to the store as
//!   they are published). A model larger than that for its area's receivers is refused as
//!   oversized, from either source.
//! - **The members**, whose clock models spend the members' products' pace by their signed bytes
//!   (`budget::Plan::member_models_bytes_per_sec`, `ingest::MemberPace`), which follows the seats
//!   whose products they bring (`budget::Plan::product_seats`): what that pace brings over the
//!   hold ([`MEMBER_SECONDS`], Little's law), decoded at most [`DECODED_PER_WIRE_PERCENT`] of its
//!   wire bytes ([`BYTES_PER_MEMBER_SEAT`] for each of those seats). A
//!   model that decodes larger than that is refused as inflated, so the bound holds for anything
//!   sent. The neighbouring areas' models a fix may cite come this way.
//!
//! **Fair, never evicting.** Each source is held to its room ([`Rooms`]): past it a new model is
//! refused and counted (`over_share`), past the store's room too (`room`), and a model held is
//! never let go for room while anything cites it, nor before its time. The members share one room:
//! what a member forwards is a model an area's engine signed, held in its area's slot (one an edge,
//! a place an engine), and the pace it spends is fair between member sessions already.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tally_mlat::area::Band;
use tally_mlat_solver::pair::Models as PairModels;
use tally_wire::batch::Hash;
use tally_wire::clocks::Judged;
use tally_wire::rendezvous::MLAT_RELAYS_PER_AREA;
use tally_wire::{ClockModel, ClockModelContent, PublicKey, Region, Regions};

use crate::budget::{Charge, Gauge, Store};

/// A model as the store holds it: the engine's own form, decoded, identified and prepared
/// (`tally_mlat::fix::Held`), so the hosted engine reads a neighbour's model from the store's
/// `Arc`.
pub type Decoded = tally_mlat::fix::Held;

/// How often an area's engines refit it: every other step (`tally_wire::budget::REFIT_EVERY`),
/// each on the one grid of edges (`Trailing::fitted_at`).
pub const REFIT_MS: u64 = tally_wire::budget::REFIT_EVERY_MS;
/// How long past its trailing edge a model is held: a fix is solved under its areas' models with
/// receptions at most `tally_wire::budget::MAX_CARRY` past their edge, and is settled by standing
/// at its arrival bound after its transmission (`standing::PENDING_SECONDS`: the bound
/// `FIX_ARRIVED`, and the second a fix may come before its transmission's own time is past); the
/// positions checks pair a fix with its models as both arrive, sooner.
pub const HELD_PAST_EDGE_MS: u64 =
    tally_wire::budget::MAX_CARRY_MS + crate::standing::PENDING_SECONDS as u64 * 1_000;
/// The models of one area at one edge held at most: one for each of its rendezvous MLAT relays.
pub const MODELS_PER_SLOT: usize = MLAT_RELAYS_PER_AREA;
/// The edges of one area held at once, at most: one a refit, each held [`HELD_PAST_EDGE_MS`] past
/// its edge, and the one in flight.
pub const EDGES_PER_AREA: usize = HELD_PAST_EDGE_MS.div_ceil(REFIT_MS) as usize + 1;
/// The most two relays' judging clocks are apart (`budget::K`): an engine fits at an edge no later
/// than its own clock, which is at most this ahead of this relay's.
const CLOCKS_APART_MS: u64 = tally_wire::budget::K.span::<Judged>().ms();
/// The longest a model is held from when it comes, milliseconds: an honest model's edge is no later
/// than its engine's clock when it was published, at most [`CLOCKS_APART_MS`] ahead of this
/// relay's, so it is let go [`HELD_PAST_EDGE_MS`] past that at most; a model whose edge is later is
/// refused as early.
pub const HOLD_MS: u64 = HELD_PAST_EDGE_MS + CLOCKS_APART_MS;

/// What one area's model takes held for each receiver of its area, at most (`Decoded::bytes`: the
/// prepared model and its encoding): measured by the counting test at every world the simulator
/// makes (`tests/tables_bytes.rs`, `an_areas_model_is_within_its_bytes_per_receiver`), the most of
/// them rounded up. An area's model has for members its receivers and those they keep (each a
/// receiver's `PAIR_NEIGHBOURS` nearest at most), so what it holds grows with its receivers.
pub const MODEL_BYTES_PER_RECEIVER: usize = 16_384;

/// What a held model's entry takes beside the model: its entry among the ids, its place among its
/// slot's (with room for every engine of the area), its signers, its slot's entry with room for
/// every edge held, and its handle's own allocation.
pub const ENTRY_BYTES: usize = tally_wire::footprint::btree_planned::<Hash, Slot>(1)
    - tally_wire::footprint::btree_planned::<Hash, Slot>(0)
    + (tally_wire::footprint::btree_planned::<Slot, Vec<Model>>(EDGES_PER_AREA)
        - tally_wire::footprint::btree_planned::<Slot, Vec<Model>>(0))
    .div_ceil(EDGES_PER_AREA)
    + tally_wire::footprint::vec::<Model>(MODELS_PER_SLOT)
    + tally_wire::footprint::vec::<PublicKey>(MODELS_PER_SLOT)
    + tally_wire::footprint::arc::<Entry>()
    + tally_wire::footprint::arc::<Decoded>();

/// What a model of an area of `receivers` receivers takes held at most: its bytes for each of
/// them ([`MODEL_BYTES_PER_RECEIVER`], an area of none planned as one) and its entry.
pub const fn held_bytes_most(receivers: usize) -> usize {
    let receivers = if receivers == 0 { 1 } else { receivers };
    receivers * MODEL_BYTES_PER_RECEIVER + ENTRY_BYTES
}

/// What a seat's share of its own engine's models takes held a second, at most: its area's model
/// refit every [`REFIT_MS`], at most [`MODEL_BYTES_PER_RECEIVER`] for the seat and the model's
/// entry once (an area of one receiver puts it all on that seat).
pub const OWN_BYTES_PER_SEAT_PER_SEC: usize =
    ((MODEL_BYTES_PER_RECEIVER + ENTRY_BYTES) * 1_000).div_ceil(REFIT_MS as usize);
/// The seconds of its own engine's models the store holds: each model from its publication (its
/// edge, by this relay's clock) over [`HELD_PAST_EDGE_MS`], rounded up.
pub const OWN_SECONDS: usize = HELD_PAST_EDGE_MS.div_ceil(1_000) as usize;
/// The own engine's room for a seat ([`Rooms::own`]): its models held over [`OWN_SECONDS`].
pub const OWN_HELD_BYTES_PER_SEAT: usize = OWN_BYTES_PER_SEAT_PER_SEC * OWN_SECONDS;
/// What one seat costs the store (`budget::Store::Models`): its own engine's models held
/// ([`OWN_HELD_BYTES_PER_SEAT`]), and its newest step's in flight, handed to the store as they are
/// published (`mlat_host`), charged beside the room.
pub const BYTES_PER_SEAT: usize = OWN_HELD_BYTES_PER_SEAT + OWN_BYTES_PER_SEAT_PER_SEC;

// The members (module docs, "What drives it"). Each seat whose products the members bring
// (`budget::Plan::product_seats`: each seat hosted, and each feeder the members' raw rate is worth)
// is planned as one seat of another area's engine (`budget::Plan::member_models_bytes_per_sec`), so
// their models spend a pace of that seat's models a second for each. A model
// is held at most `HOLD_MS` from when it comes, so by Little's law the members hold at most their
// pace over the hold and the second of burst the pace allows beside it, and its least burst
// (`ceiling::MIN_BURST`). Decoded, a model takes at most `DECODED_PER_WIRE_PERCENT` of the bytes
// it took on the wire.

/// The members' models' pace for each seat whose products they bring, signed bytes a second:
/// one seat's own models a second ([`OWN_BYTES_PER_SEAT_PER_SEC`], held, which is no less than
/// their signed bytes).
pub const MEMBER_MODEL_BYTES_PER_SEAT_PER_SEC: usize = OWN_BYTES_PER_SEAT_PER_SEC;

/// What a model takes held over what it took on the wire, percent, at most: measured by the
/// counting allocator at every world the simulator makes (`tables_bytes`,
/// `an_areas_model_is_within_its_bytes_per_receiver`, the most of them rounded up). A model past
/// it is refused as inflated (410 before each pair's curve held its anchors' picoseconds, which
/// grouping reads a reception's time against; 420 before the wire named a clock by its index and
/// carried variances in single precision, 2026-10-26, which shrank the wire and left the decode as
/// it was; 480 before the pair blocks of 2026-10-27, measured 519 on 2026-10-30).
pub const DECODED_PER_WIRE_PERCENT: usize = 520;
/// The seconds of the members' pace the members' room holds: the hold, and the second of burst
/// the pace allows beside it.
pub const MEMBER_SECONDS: usize = HOLD_MS.div_ceil(1_000) as usize + 1;
/// What `wire` bytes of models take held at most ([`DECODED_PER_WIRE_PERCENT`]).
pub const fn decoded_of(wire: usize) -> usize {
    (wire * DECODED_PER_WIRE_PERCENT).div_ceil(100)
}
/// What one seat whose products the members bring costs the store: its models' pace
/// ([`MEMBER_MODEL_BYTES_PER_SEAT_PER_SEC`]) over the members' hold, decoded.
pub const BYTES_PER_MEMBER_SEAT: usize =
    decoded_of(MEMBER_MODEL_BYTES_PER_SEAT_PER_SEC * MEMBER_SECONDS);

/// What the store holds whatever drives it: its two trees' roots, and where it has members their
/// least burst ([`Rooms::of`]).
pub const fn fixed_bytes(members: bool) -> usize {
    tally_wire::footprint::btree_planned::<Hash, Slot>(0)
        + tally_wire::footprint::btree_planned::<Slot, Vec<Model>>(0)
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
    /// The members' models' pace, the most of their models' signed bytes a second
    /// (`Plan::member_models_bytes_per_sec`); none without members.
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
/// flight, and the members' models' pace over their hold, decoded. The budget plans no less: a
/// seat at [`BYTES_PER_SEAT`], each seat whose products the members bring at
/// [`BYTES_PER_MEMBER_SEAT`].
pub const fn planned_bytes(sizing: Sizing) -> usize {
    fixed_bytes(sizing.members_bytes_per_sec > 0)
        + sizing.seats * BYTES_PER_SEAT
        + decoded_of(sizing.members_bytes_per_sec * MEMBER_SECONDS)
}

/// What a model held takes: the model as decoded and prepared, with its encoding
/// (`Decoded::bytes`), and its entry.
pub fn held_bytes(model: &Decoded) -> usize {
    model.bytes() + ENTRY_BYTES
}

/// The receivers of a model's own area among its members: what its planned bytes grow with.
pub fn area_receivers(model: &Decoded) -> usize {
    let area = model.area();
    model
        .prepared
        .model
        .scope
        .iter()
        .filter(|site| model.prepared.area_of(&site.receiver) == Some(area))
        .count()
}

/// The slot a model is held in: its area and its trailing edge (each engine of the area a place
/// in it).
pub type Slot = (Region, u64);

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

/// A model held, the engines of its area that signed it, and what it took of its room and of the
/// store, given back when its last handle goes.
struct Entry {
    model: Arc<Decoded>,
    /// Distinct, at most [`MODELS_PER_SLOT`]: each an engine of its area.
    signers: Mutex<Vec<PublicKey>>,
    bytes: usize,
    _taken: Taken,
    _charge: Charge,
}

/// A handle on a held model: what standing's book, the checks and the hosted engine cite it by.
/// Cloned freely; the model's bytes are charged while any handle is alive.
#[derive(Clone)]
pub struct Model(Arc<Entry>);

impl Model {
    /// Its pair model id (`publish::pair_model_id`): what a fix cites it by.
    pub fn id(&self) -> Hash {
        self.0.model.id()
    }

    /// The specification it was encoded and fitted under.
    pub fn spec(&self) -> u16 {
        self.0.model.prepared.model.spec
    }

    /// The inputs it is the function of (`publish::inputs_id`).
    pub fn inputs(&self) -> &Hash {
        &self.0.model.inputs
    }

    /// Its area and trailing edge: its slot.
    pub fn area(&self) -> Region {
        self.0.model.area()
    }

    pub fn edge_ms(&self) -> u64 {
        self.0.model.edge_ms()
    }

    /// The model, decoded and prepared, as the engine holds it.
    pub fn model(&self) -> &Arc<Decoded> {
        &self.0.model
    }

    /// The engines of its area that signed it, distinct: two corroborate it.
    pub fn signers(&self) -> Vec<PublicKey> {
        self.0
            .signers
            .lock()
            .map(|signers| signers.clone())
            .unwrap_or_default()
    }

    /// What it took of the store ([`held_bytes`]).
    pub fn bytes(&self) -> usize {
        self.0.bytes
    }

    /// Adds `engine` to its signers; true when it was not one.
    fn signed_by(&self, engine: PublicKey) -> bool {
        let Ok(mut signers) = self.0.signers.lock() else {
            return false;
        };
        if signers.contains(&engine) || signers.len() >= MODELS_PER_SLOT {
            return false;
        }
        signers.push(engine);
        if signers.len() >= 2 {
            let _ = self.0.model.corroborated.set(());
        }
        true
    }
}

impl std::fmt::Debug for Model {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Model")
            .field("id", &self.id())
            .field("bytes", &self.0.bytes)
            .finish_non_exhaustive()
    }
}

/// The models one fix cites, held, as standing's book holds them (`standing::ModelRef`): one per
/// area of its used hearers, in the order of their ids (the fix's own list), every one of one
/// trailing window (`pair::Models::new` reads them as one), what they are a function of together
/// (`publish::cited_inputs`), and the engine that signed the fix.
#[derive(Clone)]
pub struct Cited {
    models: Arc<[Model]>,
    inputs: Hash,
    engine: PublicKey,
}

impl Cited {
    /// `models`, cited together by a fix `engine` signed: `None` when they cannot be read as one
    /// fix's (`pair::Models::new`: none, two of one area, two of different windows).
    pub fn new(models: Vec<Model>, engine: PublicKey) -> Option<Self> {
        PairModels::new(models.iter().map(|model| &model.0.model.prepared).collect())?;
        let inputs =
            tally_mlat_solver::publish::cited_inputs(models.iter().map(|model| *model.inputs()));
        Some(Self {
            models: models.into(),
            inputs,
            engine,
        })
    }

    /// The models, in the order of their ids.
    pub fn models(&self) -> &[Model] {
        &self.models
    }

    /// The engine's own form of each, for its verifier (`Engine::verify`).
    pub fn decoded(&self) -> Vec<Arc<Decoded>> {
        self.models
            .iter()
            .map(|model| Arc::clone(model.model()))
            .collect()
    }
}

impl tally_mlat_solver::standing::ModelRef for Cited {
    fn models(&self) -> PairModels<'_> {
        PairModels::new(
            self.models
                .iter()
                .map(|model| &model.0.model.prepared)
                .collect(),
        )
        .unwrap_or_else(|| unreachable!("read as one fix's when it was made (`Cited::new`)"))
    }

    fn inputs(&self) -> &Hash {
        &self.inputs
    }

    fn engine(&self) -> &PublicKey {
        &self.engine
    }
}

/// Why a model was not held, each counted ([`ModelsReport`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Its parts were not all there, or its encoding did not read, or it is not the function of
    /// the inputs it names.
    Unreadable,
    /// Of an area neither this relay's areas nor their border band hold.
    Outside,
    /// Signed by a relay that is not one of its area's rendezvous MLAT relays.
    NotAnEngine,
    /// Its edge is not on the refit grid (a multiple of [`REFIT_MS`]), where every engine fits.
    OffGrid,
    /// Its edge is past what may still cite it ([`HELD_PAST_EDGE_MS`]).
    Stale,
    /// Its edge is later than a model sent now may honestly have: it would be held past
    /// [`HOLD_MS`].
    Early,
    /// Its slot holds a different model its signer signed already, or [`MODELS_PER_SLOT`] of
    /// them.
    SlotTaken,
    /// Its source's room is full ([`Rooms`]).
    OverShare,
    /// The store's room is full.
    Room,
    /// Larger than the plan holds a model of its area's receivers to ([`held_bytes_most`]).
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
    /// A model held already, signed again by another engine of its area.
    pub corroborated: u64,
    pub unreadable: u64,
    pub outside: u64,
    pub not_an_engine: u64,
    pub off_grid: u64,
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
    corroborated: AtomicU64,
    unreadable: AtomicU64,
    outside: AtomicU64,
    not_an_engine: AtomicU64,
    off_grid: AtomicU64,
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
    /// The areas whose models are held, with their border band; `None`, the whole world.
    band: Option<Band>,
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

/// Where a model of trailing edge `edge_ms` stops being held, by the judging clock:
/// [`HELD_PAST_EDGE_MS`] past its edge.
fn released_ms(edge_ms: u64) -> u64 {
    edge_ms.saturating_add(HELD_PAST_EDGE_MS)
}

impl Models {
    /// A store charged to no budget (an unlimited gauge) and its rooms unsized
    /// ([`Rooms::UNSIZED`]) until it is sized ([`Models::size_for`]).
    pub fn new() -> Self {
        Self {
            table: Mutex::new(Table {
                ids: BTreeMap::new(),
                slots: BTreeMap::new(),
                band: None,
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

    /// The areas this relay holds models for: a model of an area neither they nor their border
    /// band hold is refused. None, the whole world.
    pub fn set_areas(&self, areas: &Regions) {
        self.table().band = (!areas.is_empty()).then(|| Band::of(areas));
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
            Refused::OffGrid => &self.counts.off_grid,
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

    /// The model held under pair model id `id`, if any.
    pub fn get(&self, id: &Hash) -> Option<Model> {
        let table = self.table();
        Self::find(&table, id)
    }

    fn find(table: &Table, id: &Hash) -> Option<Model> {
        let slot = table.ids.get(id)?;
        table
            .slots
            .get(slot)?
            .iter()
            .find(|model| model.id() == *id)
            .cloned()
    }

    /// The models a fix `engine` signed cites, by their ids (`tally_wire::Fix::models`), held:
    /// `Err` naming the first not held, or `Ok(None)` when they cannot be read as one fix's.
    pub fn cited(&self, ids: &[Hash], engine: PublicKey) -> Result<Option<Cited>, Hash> {
        let models = {
            let table = self.table();
            ids.iter()
                .map(|id| Self::find(&table, id).ok_or(*id))
                .collect::<Result<Vec<Model>, Hash>>()?
        };
        Ok(Cited::new(models, engine))
    }

    /// The models held of `area`, newest edge first: what the hosted engine is offered of a
    /// neighbouring area (`mlat_host`).
    pub fn of_area(&self, area: Region) -> Vec<Model> {
        let table = self.table();
        table
            .slots
            .range((area, 0)..=(area, u64::MAX))
            .rev()
            .flat_map(|(_, models)| models.iter().cloned())
            .collect()
    }

    /// A whole model the hub assembled from what the members sent (its verified manifest and its
    /// `content`, the parts it lists joined): held, decoded once, in the members' room, when its
    /// area is of this relay's areas or their band and its signer is one of that area's
    /// rendezvous MLAT relays (`is_engine` of the area and the signer), its edge on the refit
    /// grid, it decodes no larger than its wire bytes allow ([`DECODED_PER_WIRE_PERCENT`]), its
    /// slot has a place for it and its room and the store have room; else refused and counted.
    /// Read by the judging clock `now`. One held already is its handle again, decoded nothing,
    /// its signer added to its signers.
    pub fn admit(
        &self,
        manifest: &ClockModel,
        content: &ClockModelContent,
        is_engine: impl Fn(Region, &PublicKey) -> bool,
        now: Judged,
    ) -> Result<Model, Refused> {
        let class = Class::Members;
        let Ok(engine) = manifest.engine() else {
            return Err(self.refuse(Refused::Unreadable, class));
        };
        // The area leads the encoding: placed and checked before anything is decoded.
        let Ok(area) = tally_mlat_solver::publish::area_of(&content.model) else {
            return Err(self.refuse(Refused::Unreadable, class));
        };
        self.placed(area, &engine, &is_engine)?;
        let id = tally_mlat_solver::publish::pair_model_id(&content.model);
        if let Some(held) = self.get(&id) {
            if held.signed_by(engine) {
                self.counts.corroborated.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(held);
        }
        let Some(decoded) = Decoded::decoded(content.model.clone()) else {
            return Err(self.refuse(Refused::Unreadable, class));
        };
        if decoded.inputs != content.inputs || decoded.prepared.model.spec != content.spec_version {
            return Err(self.refuse(Refused::Unreadable, class));
        }
        // What it spent of the members' pace, at least: its manifest, which carries its encoding
        // inline or lists the parts that do.
        let wire = manifest.as_bytes().len().max(content.model.len());
        if held_bytes(&decoded) > decoded_of(wire) {
            return Err(self.refuse(Refused::Inflated, class));
        }
        let held = self.hold(Arc::new(decoded), engine, class, now)?;
        self.counts.admitted.fetch_add(1, Ordering::Relaxed);
        Ok(held)
    }

    /// The hosted engine's own model, signed by `engine`: its own `Arc`, held as [`Models::admit`]
    /// holds one but in the own engine's room and never decoded, so the relay's own models are
    /// decoded nowhere.
    pub fn insert_own(
        &self,
        model: Arc<Decoded>,
        engine: PublicKey,
        now: Judged,
    ) -> Result<Model, Refused> {
        if let Some(held) = self.get(&model.id()) {
            held.signed_by(engine);
            return Ok(held);
        }
        let held = self.hold(model, engine, Class::Own, now)?;
        self.counts.own.fetch_add(1, Ordering::Relaxed);
        Ok(held)
    }

    /// Whether a model of `area` signed by `engine` may be held here: its area of the areas or
    /// their band, its signer one of its area's engines.
    fn placed(
        &self,
        area: Region,
        engine: &PublicKey,
        is_engine: &impl Fn(Region, &PublicKey) -> bool,
    ) -> Result<(), Refused> {
        let inside = self
            .table()
            .band
            .as_ref()
            .is_none_or(|band| band.holds(area));
        if !inside {
            return Err(self.refuse(Refused::Outside, Class::Members));
        }
        if is_engine(area, engine) {
            Ok(())
        } else {
            Err(self.refuse(Refused::NotAnEngine, Class::Members))
        }
    }

    /// Holds `model` in its area's slot for its edge, signed by `engine`, in `class`'s room,
    /// charged its bytes.
    fn hold(
        &self,
        model: Arc<Decoded>,
        engine: PublicKey,
        class: Class,
        now: Judged,
    ) -> Result<Model, Refused> {
        let edge_ms = model.edge_ms();
        if !edge_ms.is_multiple_of(REFIT_MS) {
            return Err(self.refuse(Refused::OffGrid, class));
        }
        let released = released_ms(edge_ms);
        if released <= now.ms() {
            return Err(self.refuse(Refused::Stale, class));
        }
        if released > now.ms().saturating_add(HOLD_MS) {
            return Err(self.refuse(Refused::Early, class));
        }
        let bytes = held_bytes(&model);
        if bytes > held_bytes_most(area_receivers(&model)) {
            return Err(self.refuse(Refused::Oversized, class));
        }
        let id = model.id();
        let slot = (model.area(), edge_ms);
        let gauge = self.gauge();
        let mut table = self.table();
        if let Some(held) = Self::find(&table, &id) {
            held.signed_by(engine);
            return Ok(held);
        }
        let taken = table.slots.get(&slot).is_some_and(|models| {
            models.len() >= MODELS_PER_SLOT
                || models.iter().any(|held| held.signers().contains(&engine))
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
        let mut signers = Vec::with_capacity(MODELS_PER_SLOT);
        signers.push(engine);
        let held = Model(Arc::new(Entry {
            model,
            signers: Mutex::new(signers),
            bytes,
            _taken: share,
            _charge: charge,
        }));
        table
            .slots
            .entry(slot)
            .or_insert_with(|| Vec::with_capacity(MODELS_PER_SLOT))
            .push(held.clone());
        table.ids.insert(id, slot);
        Ok(held)
    }

    /// Lets go of every model no fix that may still come or be settled can cite, by the judging
    /// clock `now` ([`HELD_PAST_EDGE_MS`]): its slot's handle goes, and its bytes with the last
    /// handle.
    pub fn tick(&self, now: Judged) {
        let now_ms = now.ms();
        let mut table = self.table();
        let Table { ids, slots, .. } = &mut *table;
        slots.retain(|(_, edge_ms), models| {
            let keep = released_ms(*edge_ms) > now_ms;
            if !keep {
                for model in models.iter() {
                    ids.remove(&model.id());
                }
            }
            keep
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
            corroborated: load(&self.counts.corroborated),
            unreadable: load(&self.counts.unreadable),
            outside: load(&self.counts.outside),
            not_an_engine: load(&self.counts.not_an_engine),
            off_grid: load(&self.counts.off_grid),
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

/// Pair models for the crate's tests: real encodings of models of no clocks, placed anywhere.
#[cfg(test)]
pub(crate) mod testing {
    use tally_mlat_solver::pair::PairModel;
    use tally_wire::{Identity, PublicKey};

    use super::Hash;

    pub(crate) fn key(seed: u8) -> PublicKey {
        Identity::from_seed([seed; 32]).public()
    }

    /// A model of the area at `(lat, lon)` with `receivers` receivers there, its trailing edge at
    /// `edge_ms`, its input count `variant` (so two of one slot can differ): no clocks, no pairs.
    pub(crate) fn pair_model(
        (lat, lon): (f64, f64),
        edge_ms: u64,
        receivers: u8,
        variant: u32,
    ) -> PairModel {
        let area =
            tally_wire::rendezvous::area_at(lat, lon).unwrap_or_else(|error| panic!("{error}"));
        let mut scope: Vec<tally_mlat_solver::Site> = (0..receivers)
            .map(|seed| tally_mlat_solver::Site {
                receiver: key(seed),
                clock: tally_wire::Clock::Beast,
                id: tally_wire::SiteId([seed; 32]),
                location: tally_wire::Location {
                    lat_e7: (lat * 1e7) as i32,
                    lon_e7: (lon * 1e7) as i32,
                    alt_m: 0,
                    precision_m: 0,
                },
            })
            .collect();
        scope.sort_by_key(|site| site.receiver);
        PairModel {
            spec: tally_mlat_solver::SPEC_VERSION,
            area,
            trailing: tally_mlat_solver::scope::Trailing::at(edge_ms),
            scope,
            frontier: Vec::new(),
            input: tally_mlat_solver::scope::Citation {
                hash: [7; 32],
                count: variant,
            },
            kappa: 1.0,
            clocks: Vec::new(),
            pairs: Vec::new(),
        }
    }

    /// `model` encoded, and its pair model id: what a manifest carries and what a fix cites.
    pub(crate) fn encoded(model: &PairModel) -> (Vec<u8>, Hash) {
        let bytes = tally_mlat_solver::publish::encode_pairs(model)
            .unwrap_or_else(|error| panic!("a model of no clocks encodes: {error}"));
        let id = tally_mlat_solver::publish::pair_model_id(&bytes);
        (bytes, id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::testing::key;
    use super::*;
    use tally_mlat_solver::pair::PairModel;
    use tally_wire::Identity;
    use tally_wire::clocks::recorded::judged;

    /// Where the tests' models' area is, and a neighbouring area's place.
    const HERE: (f64, f64) = (52.0, 5.0);
    const NEIGHBOUR: (f64, f64) = (52.0, 8.0);

    /// The area the tests' models are of.
    fn area() -> Region {
        tally_wire::rendezvous::area_at(HERE.0, HERE.1).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Step 0's trailing edge, on the refit grid: each later step's is a refit later.
    const EDGE_MS: u64 = 30_000;

    fn edge_ms(step: i64) -> u64 {
        EDGE_MS.saturating_add_signed(step * REFIT_MS as i64)
    }

    fn pair_model(place: (f64, f64), step: i64, receivers: u8, variant: u32) -> PairModel {
        testing::pair_model(place, edge_ms(step), receivers, variant)
    }

    /// The receivers of the tests' area: enough that a model's sites, not its fixed parts, are
    /// most of what it holds, as an honest model's are (`DECODED_PER_WIRE_PERCENT`).
    const RECEIVERS: u8 = 16;

    fn model(step: i64, variant: u32) -> Arc<Decoded> {
        Arc::new(
            Decoded::fitted(pair_model(HERE, step, RECEIVERS, variant))
                .unwrap_or_else(|| panic!("a model of no clocks encodes")),
        )
    }

    /// The judging clock the tests hold models at: step 0's model a second from being let go, and
    /// a model of each of the next steps not past the hold.
    const NOW_MS: u64 = EDGE_MS + HELD_PAST_EDGE_MS - 1_000;

    fn now() -> Judged {
        judged(NOW_MS)
    }

    /// `model` as a member sends it: its manifest signed by `engine`, its encoding inline.
    fn sent(model: &Decoded, engine: u8) -> Result<(ClockModel, ClockModelContent), String> {
        let content = ClockModelContent {
            boot_id: 1,
            sequence: 0,
            issued_ms: 1_000,
            spec_version: model.prepared.model.spec,
            inputs: model.inputs,
            model: model.bytes.clone(),
        };
        let signed = ClockModel::sign(&Identity::from_seed([engine; 32]), &content)
            .map_err(|error| error.to_string())?;
        let content = signed
            .manifest
            .content(&signed.parts)
            .map_err(|error| error.to_string())?;
        Ok((signed.manifest, content))
    }

    /// The engine's own models are held as their own `Arc`, charged as held and given back when
    /// the last handle goes, never before its time and never for room: past the store's room a
    /// new one is refused and counted; an engine's second model of a slot is refused, another
    /// engine's is held beside it; a model past its time is stale, and let go by the clock.
    #[test]
    fn a_model_is_held_charged_and_let_go_with_its_last_handle() -> Result<(), String> {
        let store = Models::new();
        let one = model(0, 1);
        let bytes = held_bytes(&one);
        store.charge_to(crate::budget::Gauge::new(Store::Models, 2 * bytes));
        let held = store
            .insert_own(Arc::clone(&one), key(100), now())
            .map_err(|why| format!("{why:?}"))?;
        assert!(Arc::ptr_eq(held.model(), &one), "never decoded again");
        assert_eq!(store.report().bytes, bytes);
        // The same engine's different model of the same slot: refused.
        assert_eq!(
            store.insert_own(model(0, 2), key(100), now()).err(),
            Some(Refused::SlotTaken)
        );
        // Another engine's of the same area and edge is its own place in the slot.
        let other = store
            .insert_own(model(0, 3), key(101), now())
            .map_err(|why| format!("{why:?}"))?;
        // Past the room: refused, nothing held let go.
        assert_eq!(
            store.insert_own(model(1, 1), key(100), now()).err(),
            Some(Refused::Room)
        );
        assert_eq!(store.report().held, 2);
        assert_eq!(store.report().room, 1);
        // Let go by the clock once nothing may cite it, but its bytes stay while a handle does.
        let late = released_ms(one.edge_ms());
        store.tick(judged(late));
        assert_eq!(store.report().held, 0);
        assert_eq!(store.report().bytes, 2 * bytes);
        drop(other);
        assert_eq!(store.report().bytes, bytes);
        drop(held);
        assert_eq!(store.report().bytes, 0);
        // Past its time: stale.
        assert_eq!(
            store.insert_own(model(0, 4), key(100), judged(late)).err(),
            Some(Refused::Stale)
        );
        Ok(())
    }

    /// A slot holds one model for each of its area's engines: one more is refused and counted.
    /// The same model signed by a second engine is the one entry, corroborated, nothing more held.
    #[test]
    fn a_slot_holds_its_engines_models_and_the_same_model_once() -> Result<(), String> {
        let store = Models::new();
        let mut held = Vec::new();
        for engine in 0..MODELS_PER_SLOT {
            held.push(
                store
                    .insert_own(model(0, engine as u32), key(100 + engine as u8), now())
                    .map_err(|why| format!("{why:?}"))?,
            );
        }
        assert_eq!(
            store.insert_own(model(0, 99), key(150), now()).err(),
            Some(Refused::SlotTaken)
        );
        // A member sends the first model again, signed by an engine that did not sign it.
        let (manifest, content) = sent(held[0].model(), 101)?;
        let again = store
            .admit(&manifest, &content, |_, _| true, now())
            .map_err(|why| format!("{why:?}"))?;
        assert!(Arc::ptr_eq(again.model(), held[0].model()));
        assert_eq!(again.signers(), vec![key(100), key(101)]);
        let report = store.report();
        assert_eq!(
            (report.held, report.corroborated, report.admitted),
            (MODELS_PER_SLOT, 1, 0),
            "{report:?}"
        );
        Ok(())
    }

    /// A model whose edge is later than one sent now may honestly have is refused as early, from
    /// either source: it would be held past the hold its room is planned over. One at the end of
    /// the hold is held; one off the refit grid is refused.
    #[test]
    fn a_model_held_past_the_hold_or_off_the_grid_is_refused() -> Result<(), String> {
        let store = Models::new();
        // The newest grid edge released by `HOLD_MS` from now: held.
        let last = (NOW_MS + HOLD_MS - HELD_PAST_EDGE_MS) / REFIT_MS;
        let step = |edge: u64| (edge as i64 - EDGE_MS as i64) / REFIT_MS as i64;
        store
            .insert_own(model(step(last * REFIT_MS), 1), key(100), now())
            .map_err(|why| format!("{why:?}"))?;
        // A refit later: early, from the own engine and from a member alike.
        let early = model(step((last + 1) * REFIT_MS), 1);
        assert_eq!(
            store.insert_own(Arc::clone(&early), key(101), now()).err(),
            Some(Refused::Early)
        );
        let (manifest, content) = sent(&early, 7)?;
        assert_eq!(
            store.admit(&manifest, &content, |_, _| true, now()).err(),
            Some(Refused::Early)
        );
        assert_eq!(store.report().early, 2);
        let mut off = pair_model(HERE, 0, RECEIVERS, 1);
        off.trailing.edge_ms += 1;
        let off = Arc::new(Decoded::fitted(off).ok_or("encodes")?);
        assert_eq!(
            store.insert_own(off, key(100), now()).err(),
            Some(Refused::OffGrid)
        );
        Ok(())
    }

    /// Each source is held to its own room (`Rooms`): past it a new model is refused and counted
    /// against that source, nothing held is let go for it, and the other source's room is untouched;
    /// what a model took is given back to its room with its last handle.
    #[test]
    fn each_source_is_held_to_its_room_and_never_evicts() -> Result<(), String> {
        let store = Models::new();
        let bytes = held_bytes(&model(0, 1));
        let member = model(0, 50);
        let (manifest, content) = sent(&member, 7)?;
        let member_bytes = held_bytes(&Decoded::decoded(content.model.clone()).ok_or("decodes")?);
        store.set_rooms(Rooms {
            own: 2 * bytes,
            members: member_bytes,
        });
        let first = store
            .insert_own(model(0, 1), key(100), now())
            .map_err(|why| format!("{why:?}"))?;
        let _second = store
            .insert_own(model(0, 2), key(101), now())
            .map_err(|why| format!("{why:?}"))?;
        assert_eq!(
            store.insert_own(model(1, 3), key(102), now()).err(),
            Some(Refused::OverShare)
        );
        // The members' room is their own: a member's model is held beside the full own room.
        let held = store
            .admit(&manifest, &content, |_, _| true, now())
            .map_err(|why| format!("{why:?}"))?;
        let (more, more_content) = sent(&model(1, 51), 8)?;
        assert_eq!(
            store.admit(&more, &more_content, |_, _| true, now()).err(),
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
        store.tick(judged(released_ms(held.edge_ms())));
        drop((first, held));
        let report = store.report();
        assert_eq!(
            (report.own_bytes, report.members_bytes),
            (bytes, 0),
            "{report:?}"
        );
        Ok(())
    }

    /// A member's model that decodes larger than `DECODED_PER_WIRE_PERCENT` of its wire bytes is
    /// refused as inflated, and one larger than the plan holds a model of its area's receivers to
    /// is refused as oversized: so the rooms, planned from what drives them, hold whatever is sent.
    #[test]
    fn a_model_past_its_planned_size_is_refused() -> Result<(), String> {
        let store = Models::new();
        // A model of none of its area's receivers, as large as the plan holds one.
        let mut far = pair_model(HERE, 0, 3, 1);
        for site in &mut far.scope {
            site.location.lat_e7 = -400_000_000;
        }
        far.scope.sort_by_key(|site| site.receiver);
        let mut held = Decoded::fitted(far).ok_or("encodes")?;
        held.bytes.reserve_exact(2 * MODEL_BYTES_PER_RECEIVER);
        assert_eq!(area_receivers(&held), 0);
        assert_eq!(
            store.insert_own(Arc::new(held), key(100), now()).err(),
            Some(Refused::Oversized)
        );
        assert_eq!(store.report().oversized, 1);
        Ok(())
    }

    /// Only a model of an area the areas or their band hold, signed by one of that area's
    /// engines, is held: anything else is refused and counted.
    #[test]
    fn only_a_model_of_the_band_signed_by_its_areas_engine_is_placed() {
        let store = Models::new();
        let area = area();
        store.set_areas(&Regions::new([area]));
        let engine = key(100);
        let is_engine = |at: Region, signer: &PublicKey| *signer == engine && at.resolution() == 3;
        assert_eq!(store.placed(area, &engine, &is_engine), Ok(()));
        // A neighbouring area, in the band: placed.
        let neighbour = tally_wire::rendezvous::area_at(NEIGHBOUR.0, NEIGHBOUR.1)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_ne!(neighbour, area);
        assert_eq!(store.placed(neighbour, &engine, &is_engine), Ok(()));
        assert_eq!(
            store.placed(area, &key(101), &is_engine),
            Err(Refused::NotAnEngine)
        );
        let elsewhere =
            tally_wire::rendezvous::area_at(-40.0, 120.0).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            store.placed(elsewhere, &engine, &is_engine),
            Err(Refused::Outside)
        );
        let report = store.report();
        assert_eq!((report.not_an_engine, report.outside), (1, 1));
    }

    /// The models a fix cites are found by their ids and read as one fix's; one not held is named.
    #[test]
    fn a_fixes_models_are_cited_together() -> Result<(), String> {
        let store = Models::new();
        let one = store
            .insert_own(model(0, 1), key(100), now())
            .map_err(|why| format!("{why:?}"))?;
        let two = store
            .insert_own(
                Arc::new(Decoded::fitted(pair_model(NEIGHBOUR, 0, 2, 1)).ok_or("encodes")?),
                key(110),
                now(),
            )
            .map_err(|why| format!("{why:?}"))?;
        let mut ids = vec![one.id(), two.id()];
        ids.sort_unstable();
        let cited = store.cited(&ids, key(100)).map_err(|_| "held")?;
        let cited = cited.ok_or("one window, two areas")?;
        assert_eq!(cited.models().len(), 2);
        assert_eq!(store.cited(&[[9; 32]], key(100)).err(), Some([9; 32]));
        // Two of one area are not one fix's.
        let other = store
            .insert_own(model(0, 2), key(101), now())
            .map_err(|why| format!("{why:?}"))?;
        let mut ids = vec![one.id(), other.id()];
        ids.sort_unstable();
        assert!(store.cited(&ids, key(100)).map_err(|_| "held")?.is_none());
        Ok(())
    }

    /// A seat's line holds its area's model refit a second at its most, and the rooms are what
    /// drives them: the plan holds each room and a seat's models in flight.
    #[test]
    fn the_lines_hold_what_drives_them() {
        const {
            assert!(
                OWN_BYTES_PER_SEAT_PER_SEC as u64 * REFIT_MS >= (held_bytes_most(1) as u64) * 1_000
            );
            assert!(OWN_SECONDS as u64 * 1_000 >= HELD_PAST_EDGE_MS);
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
                        + seats * OWN_BYTES_PER_SEAT_PER_SEC
            );
        }
    }
}
