//! The two products (RFC-0174 §2.11): the regional product (each area's receptions deduplicated
//! once, as `RegionalBatch` records this relay signs as their origin, beside the area's raw,
//! positions and clock models) and the world product (one fix per aircraft per second, by
//! `tally_wire::products::world_choice`, offered at the top of the area tree by a relay that has
//! gathered every area's positions), as `WorldPositions`, each second sealed `WORLD_SETTLE_MS`
//! after it ends. There is one kind of MLAT fix, solved within seconds of its transmission
//! (RFC-0171 §3.8.1 as amended 2026-10-24), so there is one world product: the precise one, which
//! waited for the windowed finals, is retired with them.
//!
//! # Who does what (RFC-0181)
//!
//! Nothing here is on the per-reception path. Which reception is an area's first copy is decided
//! by the message exchange's one deduplication (`exchange::MessageShard`), at each epoch's close,
//! in canonical order. The closed epochs come to the [`Sealer`], one thread that owns everything
//! the products decide: it gathers each epoch whole from every message thread
//! (`seal::Coordinator`), signs the regional product area by area, offers its fixes to the world,
//! seals every world second the watermark has settled, and hands what it signed to the hub
//! through an outbox. It decides by stamps, never by a clock: an epoch's records carry its end as
//! their time, and the world seals a second once the judging clock at the watermark (an epoch's
//! end, carried by the newest tick's two readings) has passed it by `WORLD_SETTLE_MS`, so the same
//! stamped trace gives the same records on any number of threads.
//! A sealer that falls behind refuses whole epochs, counted ([`ProductsReport`]); never part of one.
//!
//! The records that are not epochs (positions, clock models, a peer's world or regional records)
//! are stamped as they are handed in and wait in a queue of their own ([`Records`]), never the
//! epochs' queue, so a peer flooding records can refuse only records, never this relay's epochs.
//! The sealer takes them in by stamp: before it seals anything at a watermark it takes every record
//! stamped before it, in the order of their stamps (and their hashes, for one stamp), so whether a
//! world candidate is in time, late or out of its window is decided by its stamp and the
//! watermark's, never by which queue it waited in or which thread's word came first. A record
//! handed in after the sealer has taken in a watermark is stamped no earlier than it.
//!
//! The sealer is one thread that decides, and a pool that works (RFC-0181 §4, "a sealer pool"):
//! each epoch's areas are made into records in parallel (their observations gathered, cut to
//! fit a record, signed, and their ADS-B fixes derived), on threads started with the sealer (so a
//! thread that cannot be started fails the relay at its start, never an epoch), as many as the
//! load planned needs (`cores::threads_for`), then numbered and applied in cell order by the one thread, so the records
//! and their sequence are the same on any number of threads.
//!
//! The deduplicated stream is signed there too (`deduplicated::Stream`), one job of the pool
//! beside the epoch's areas, from the receptions where the epoch's batches hold them, so it copies
//! nothing and outlives none of them; its batches go out first among the epoch's records.
//!
//! What the sealer holds is charged to the relay's budget in two shares that never take each
//! other's room: its own outputs, the signed records the hub has not yet taken (the deduplicated
//! stream's among them), to `budget::Store::Products`; and what others hand it, the records waiting
//! in their queue and the peers' regional batches waiting to be forwarded, to
//! `budget::Store::Records`. An epoch whose products would pass the first is refused whole,
//! counted; a record past the second is refused, counted (`records_refused`), and however many
//! come, no epoch is refused for them. The second is cut by who hands a record in (`From`): this
//! relay's own MLAT output keeps a part no peer's record may take, and each session that hands
//! records in fills a part of its own (the peers' part divided by the sessions open, never by the
//! keys that signed what they send), so which records are taken follows who sent them, never
//! which came first.
//!
//! # The regional product
//!
//! A relay is the origin of the regional product for the receivers that chose it: those whose
//! newest signed description ([`Products::described`]) names this relay among their relays. Their
//! receptions are grouped by the receiver's area (the H3 cell of its signed location at
//! `rendezvous::AREA_RESOLUTION`, [`Products::area_for`]), and each area keeps one copy of each
//! message heard within the deduplication's window (`exchange::DEDUP_WINDOW_MS`, by stamps), as
//! the hub's deduplicated stream does across the whole relay. Once an epoch every area's copies are signed as `RegionalBatch` records: the relay's own
//! stream (one random boot id a process, one sequence from 0 across its areas, in cell order), cut
//! to fit a record. The signature is the origin's and covers the cell, so any relay forwards the
//! record unchanged and a subscriber's regions cut it by the cell it names. A relay forwards a
//! peer's regional batch once, unchanged, when the cell is inside an area it takes (the area's
//! group: every relay that takes it), so regional data travels within its area's relays and no
//! further.
//!
//! # The world product
//!
//! Every relay that gathers the world ([`Products::set_world`]) holds, for each second of
//! transmit time not yet sealed, one fix per aircraft: the best by `world_choice`'s order
//! (`WorldFix::ranks_above`, a total order) of every candidate it was shown, whatever order they
//! came in. The candidates are, from public signed records
//! only:
//!
//! - **ADS-B positions** decoded from regional batches (its own and its peers'), by
//!   [`regional_fixes`]: per aircraft, its newest airborne position in the record decoded globally
//!   (CPR, the solver's own decoder, `tally_mlat_solver::modes`) with the latest airborne position
//!   of the other parity before it in the same record, so one record is all a reader needs to
//!   decode it again. Its time is the record's signed wall clock (a regional batch carries no
//!   receiver's counter a reader could place), its input set `products::adsb_input_set` of the
//!   two messages, its covariance the position's type code's containment radius taken as two
//!   sigma, its altitude the GNSS height when the message carries one (a barometric altitude is
//!   not a height above the ellipsoid, so the fix states none).
//! - **MLAT fixes**, from `Positions` records (format 7), by [`positions_fixes`]: each fix as
//!   published, its input set the merge rule's (`products::input_set`, over the receptions it
//!   considered and the inputs hash of the model it was solved under), so a fix waits here until
//!   its model's manifest has been shown (its engine sends the model first, so it rarely waits).
//!
//! Each fix cites its origin record's hash and its index there, so a reader holding that record
//! derives the same fix ([`check_fix`]). A second is sealed once, [`WORLD_SETTLE_MS`] after it
//! ends by this relay's judging clock, once every honest fix of it has surely arrived
//! (`tally_wire::budget::FIX_ARRIVED`: its receptions signed below their relay's clock, its way
//! out of its engine or a regional batch, and that relay's clock `K` from this one's): its fixes,
//! ascending by address, are signed as `WorldPositions` parts of at most `MAX_WORLD_FIXES`. A
//! candidate for a sealed second is late, dropped and counted, so no aircraft has two fixes in
//! one second. Two relays shown the same records before a second's seal publish the same fixes
//! for it, byte for byte, in any order.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TrySendError, channel, sync_channel};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;

use tally_mlat_solver::modes::{self, AltitudeKind};
use tally_wire::batch::{Hash, format};
use tally_wire::budget::policy;
use tally_wire::clocks::{Judged, Moment, Mono, Span};
use tally_wire::positions::{EnuCovariance, TransmitTime};
use tally_wire::products::{MAX_REGIONAL_OBSERVATIONS, MAX_WORLD_FIXES, adsb_input_set, input_set};
use tally_wire::rendezvous::area_of_public;
use tally_wire::{
    Batch, ClientRegionalBatch, ClockModel, Location, Positions, PublicKey, ReceiverInfo, Record,
    Region, RegionalBatch, RegionalDraft, Signs, WireError, WorldFix, WorldPositions,
    WorldPositionsContent,
};

use crate::bounded::Bounded;
use crate::budget::{Charge, Gauge, Store};
use crate::deduplicated::{Signed, Stream};
use crate::exchange::{Frozen, Sink};
use crate::footprint::{Deque, Tree};
use crate::ingest::Stamp;
use crate::ingest::{Pause, Stage, Threads};
use crate::network::{Asker, AskerRole};
use crate::seal::{Coordinator, Kept, Merged};
use crate::signer::Signer;
use crate::strikes::Deliverer;

/// How often each area's copies are signed: a feeder seals once a second, and so does an origin.
pub const REGIONAL_EVERY_MS: u64 = 1_000;
/// How long after a second of transmit time ends its world fixes are sealed: once every honest fix
/// of it has surely arrived, wherever it was heard (`tally_wire::budget::FIX_ARRIVED`, derived
/// there: its receptions signed up to `E + 2U_m` below the clock of the relay that heard them, its
/// fix's way out of its engine or a regional batch, and that relay's clock up to `K` from this
/// one's). Before, 4 s, a fix's measured way out alone: a fix whose receptions were signed 9.5 s
/// below its relay's clock, or heard on a relay `K` from this one, missed its second, honest and
/// counted late.
pub const WORLD_SETTLE_MS: u64 = tally_wire::budget::FIX_ARRIVED_MS;
/// How far before the watermark a fix's second may be before the first seal.
const WORLD_BEHIND_SECONDS: u64 = 240;
/// The most aircraft held for one second: several times the world's airborne fleet.
pub const MAX_WORLD_AIRCRAFT: usize = 50_000;
/// The aircraft one second of a world product is planned to hold across its open seconds: the
/// world's airborne fleet, a quarter of [`MAX_WORLD_AIRCRAFT`] (which one second may hold at most).
pub const WORLD_FLEET: usize = MAX_WORLD_AIRCRAFT / 4;

/// The seconds the world product settling `settle_ms` after a second ends holds open at most: the
/// ones not yet settled, the one under way, and the ones ahead a fix may still be signed in
/// (`tally_wire::budget::PEER_AHEAD`).
pub const fn world_seconds_open(settle_ms: u64) -> usize {
    (settle_ms.div_ceil(1_000)
        + tally_wire::budget::PEER_AHEAD
            .span::<Judged>()
            .ms()
            .div_ceil(1_000)
        + 1) as usize
}

/// The most fixes the world product settling `settle_ms` after a second ends holds across its open
/// seconds ([`world_seconds_open`]), each the planned fleet ([`WORLD_FLEET`]).
pub const fn world_held(settle_ms: u64) -> usize {
    world_seconds_open(settle_ms) * WORLD_FLEET
}

/// What one more fix held in a second takes at most (`footprint::btree_planned` of a second's
/// aircraft, `Tree::bytes_per_entry`): a fifth of a node of fixes, every node but a second's root
/// holding five at least. Some 450 bytes for a `WorldFix` of some 190.
pub const WORLD_FIX_BYTES: usize = Tree::<u32, WorldFix>::bytes_per_entry();
/// What one more second open takes beside its fixes: its tree's root, a node of fixes, and its
/// entry among the seconds.
pub const WORLD_SECOND_BYTES: usize =
    Tree::<u32, WorldFix>::bytes_planned(0) + Tree::<u64, Tree<u32, WorldFix>>::bytes_per_entry();
/// What the seconds' own tree takes beside its entries: its root.
pub const WORLD_SECONDS_ROOT_BYTES: usize = Tree::<u64, Tree<u32, WorldFix>>::bytes_planned(0);
/// The most seconds a world product holds open: those after the floor, before its first seal
/// ([`WORLD_BEHIND_SECONDS`]) or after it (its settling), and those ahead a fix may be signed in
/// (`tally_wire::budget::PEER_AHEAD`), and the one under way.
const fn world_seconds_held(settle_ms: u64) -> usize {
    let settled = world_seconds_open(settle_ms);
    let behind = WORLD_BEHIND_SECONDS as usize
        + tally_wire::budget::PEER_AHEAD
            .span::<Judged>()
            .ms()
            .div_ceil(1_000) as usize
        + 1;
    if settled > behind { settled } else { behind }
}

/// What the world product settling `settle_ms` after a second ends holds at most: its cap of fixes
/// ([`world_held`]) at [`WORLD_FIX_BYTES`] each, its seconds open ([`world_seconds_held`]) at
/// [`WORLD_SECOND_BYTES`] each, and the seconds' root.
pub const fn world_product_bytes(settle_ms: u64) -> usize {
    world_held(settle_ms) * WORLD_FIX_BYTES
        + world_seconds_held(settle_ms) * WORLD_SECOND_BYTES
        + WORLD_SECONDS_ROOT_BYTES
}

/// What the world product holds at most where a relay gathers it (`--world`,
/// `budget::Store::World`): [`world_product_bytes`] at its settle; nothing on a relay that does
/// not. Before, it was charged to no store: a world relay's fixes at their cap beside a plan that
/// held none of it.
pub const fn world_planned_bytes(world: bool) -> usize {
    if world {
        world_product_bytes(WORLD_SETTLE_MS)
    } else {
        0
    }
}
/// The relays remembered per receiver: a feeder names two, a v1 feeder up to its slots.
const RELAYS_PER_RECEIVER: usize = 8;

/// The receivers' areas products hold before a budget sizes them (`Products::charge_to`): a test's
/// that builds products alone. A relay's are sized to its receiver figure before it starts.
const UNSIZED_RECEIVERS: usize = 50_000;

/// What the receivers' areas take for each receiver the receiver figure holds
/// (`budget::Plan::receivers`, one table at the figure as the station rows are): its entry
/// (`Bounded::bytes_per_key`) and its chosen relays, kept exactly as long as they are.
pub const LOCATED_BYTES_PER_RECEIVER: usize = Bounded::<PublicKey, Located>::bytes_per_key()
    + crate::footprint::vec::<PublicKey>(RELAYS_PER_RECEIVER);

/// What the receivers' areas take beside [`LOCATED_BYTES_PER_RECEIVER`] for each: the table's
/// fixed part and the one entry a figure of none is held at.
pub const LOCATED_FIXED_BYTES: usize =
    Bounded::<PublicKey, Located>::fixed_bytes() + LOCATED_BYTES_PER_RECEIVER;

/// What the receivers' areas allocate at most for `receivers` receivers: one table at the figure
/// (one entry at least), each entry with its relays at the most a receiver keeps. Never more than
/// [`LOCATED_FIXED_BYTES`] and [`LOCATED_BYTES_PER_RECEIVER`] for each (a test holds it). One
/// table, never a share per raw shard: receivers land in shards by a keyed hash, so a shard's are
/// a random draw above an even share on every batch, and a shard's table forgot honest receivers
/// (and their regional routing) within the figure.
pub const fn located_planned_bytes(receivers: usize) -> usize {
    let held = if receivers == 0 { 1 } else { receivers };
    Bounded::<PublicKey, Located>::planned_bytes(held)
        + held * crate::footprint::vec::<PublicKey>(RELAYS_PER_RECEIVER)
}
/// Regional batches remembered by hash, so each is forwarded and decoded once.
pub const REGIONAL_REMEMBERED: usize = 200_000;
/// Peers' regional batches waiting for the next tick to be forwarded.
const FORWARD_HELD: usize = 4_096;
/// The models a world-scale MLAT publishes a second (RFC-0174 §2.3: some 3,800 refits a second;
/// each area's engines refit it every `tally_wire::budget::REFIT_EVERY`, each refit one model).
const WORLD_REFITS_PER_SEC: usize = 3_800;
/// Clock models remembered: their pair model id and inputs hash, for as long as a fix solved under one may
/// still come after it. An engine sends a model before the fixes solved under it, and a fix is
/// solved under a model at most `tally_wire::budget::MAX_CARRY` old; the two may reach this relay
/// by paths up to `K` apart, a repair's transit after: so a model is remembered for
/// `MAX_CARRY + K + REPAIR_TRANSIT` of a world-scale MLAT's refits.
pub const MODELS_REMEMBERED: usize = WORLD_REFITS_PER_SEC
    * ((tally_wire::budget::MAX_CARRY.span::<Judged>().ms()
        + tally_wire::budget::K.span::<Judged>().ms()
        + tally_wire::budget::REPAIR_TRANSIT.span::<Judged>().ms())
    .div_ceil(1_000) as usize);
/// How long positions records wait for a model they cite: charged while they wait to the records'
/// share (`budget::Store::Records`), their only bound.
const WAITING_MS: u64 = 30_000;
/// Positions waiting for one model, oldest first: a deque that grows by one at least, since most
/// models are waited on by a few (`footprint::Deque`).
type Waiting = Deque<(Stamp, Positions, Held), 1>;
/// Fixes derived from origins this relay holds, by (origin, index), to check a peer's world fix
/// that cites one of them.
pub const DERIVED_REMEMBERED: usize = 200_000;
/// What the products' remembered tables allocate at most, at their caps, whatever was written
/// (`Bounded::planned_bytes`): the regional batches seen ([`REGIONAL_REMEMBERED`]), the models'
/// inputs ([`MODELS_REMEMBERED`]) and the fixes derived ([`DERIVED_REMEMBERED`]). Charged whole
/// (`budget::Store::Remembered`), so a flood of distinct records fills them to their caps inside
/// their charge. Before, they were charged to no store and planned in no line: some 68 MiB at
/// their caps that the measured base (`budget::MEASURED_IDLE_BYTES`, an idle relay's) never held.
pub const REMEMBERED_BYTES: usize = Bounded::<Hash, ()>::planned_bytes(REGIONAL_REMEMBERED)
    + Bounded::<Hash, Hash>::planned_bytes(MODELS_REMEMBERED)
    + Bounded::<(Hash, u16), u64>::planned_bytes(DERIVED_REMEMBERED);
/// What the sealer's queue of epochs holds before it refuses one: every message thread's word for
/// many seconds of epochs (a thread sends at most a part and a marker an epoch). Only the message
/// threads and the relay's own settings use it; records wait apart (`Records`), held by the
/// products' gauge alone.
const EPOCH_QUEUE: usize = 4_096;
/// Epochs of products the hub may leave untaken before an epoch's are refused whole, counted: what
/// the products' budget is planned for (`budget::Store::Products`). The hub takes them every
/// `network::TICK`, a tenth of an epoch.
pub const OUTBOX_EPOCHS: usize = 2;
/// Epochs a record waits for the sealer while it keeps up: the sealer takes a record in once its
/// watermark (an epoch's end) passes the record's stamp, and the watermark trails the ingest clock
/// by the epochs the exchange holds (`seal::EPOCHS_HELD`), and the one it is taken in at.
pub const RECORDS_EPOCHS: usize = crate::seal::EPOCHS_HELD as usize + 1;

/// What one feeder's worth of receptions costs the records' share (`budget::Store::Records`) over
/// the epochs a record waits (`RECORDS_EPOCHS`): every reception as an observation of a regional
/// batch, the record that carries the most of them, held twice (waiting for the sealer, and to be
/// forwarded), as if none were a copy. Positions, models and world records are a fraction of that.
pub const fn records_per_feeder(receptions_per_sec: usize) -> usize {
    receptions_per_sec
        * 2
        * (tally_wire::decoded::OBSERVATION_FIXED + 14)
        * RECORDS_EPOCHS
        * crate::seal::EPOCH_MS as usize
        / 1_000
}
/// How often, in the products' time (the watermark), the deduplicated stream's losses since the
/// last word are said, at most.
const STREAM_SAID_EVERY_MS: u64 = 60_000;

/// What the relay's products have done, for operators and tests (served on `--stats-listen`,
/// `GET /products`). Every record or reception the products let go is counted here by why: none
/// is dropped silently, and none is dropped alone (an epoch is refused whole).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProductsReport {
    /// Regional batches signed as origin.
    pub regional_signed: u64,
    /// Peers' regional batches forwarded.
    pub regional_forwarded: u64,
    /// Epochs refused whole, every product of them (the sealer was behind, or its records were
    /// not taken, or the epoch was past the budget): RFC-0181 §10.
    pub epochs_refused: u64,
    /// Epoch parts (one message thread's share of one epoch) lost on the way to the sealer, its
    /// queue full: each refuses its epoch, counted above when another thread held any of it.
    pub epoch_parts_lost: u64,
    /// Epochs of the deduplicated stream refused whole: the epoch was refused, or its records
    /// were (the hub had not taken the ones before, past the products' budget).
    pub stream_refused: u64,
    /// Receptions dropped at a seal because the relay had no key to sign them with yet, or its
    /// judging clock was not synced (`unsynced_seals`).
    pub regional_unsigned: u64,
    /// Receptions too large for any regional batch.
    pub regional_oversized: u64,
    /// Peers' regional batches taken but not forwarded for room (`FORWARD_HELD`).
    pub regional_forward_full: u64,
    /// Records (positions, models, peers' products) not taken for room: the records' share
    /// (their gauge, `budget::Store::Records`) spent. Never an epoch.
    pub records_refused: u64,
    /// Receptions a message thread let go because their epoch had closed before they came: only
    /// a trace can stamp a batch behind its worker's tick.
    #[serde(default)]
    pub receptions_late: u64,
    /// Receptions a message thread let go because their epoch lay past the window the threads
    /// hold open or settling at once (`exchange::EPOCHS_OPEN`): their epoch let go on every
    /// thread. Apart from the late, which are for epochs already closed.
    #[serde(default)]
    pub receptions_past_window: u64,
    /// Observations of the deduplicated stream too large for any `RelayBatch` (`deduplicated`).
    #[serde(default)]
    pub stream_oversized: u64,
    /// Observations of the deduplicated stream dropped at a seal because the relay had no key to
    /// sign them with yet, or its judging clock was not synced (`unsynced_seals`).
    #[serde(default)]
    pub stream_unsigned: u64,
    /// Seals (an epoch's copies, a world second) that signed nothing because the relay's judging
    /// clock was not synced (`signer::Signer::with`, RFC-0171 §3.6).
    #[serde(default)]
    pub unsynced_seals: u64,
    /// World records signed.
    pub world_signed: u64,
    /// Fixes of world seconds sealed but not signed: the relay had no key yet,
    /// or its judging clock stopped judging as they were sealed (`unsynced_seals`).
    #[serde(default)]
    pub world_unsigned: u64,
    /// Fixes offered after their second was sealed.
    pub world_late: u64,
    /// Fixes whose second is too far before or after the watermark to be held.
    pub world_out_of_window: u64,
    /// Fixes taken in by a stamp read while the relay's clock did not judge: never judged, so
    /// never held (RFC-0171 §3.6).
    pub world_unjudged: u64,
    /// Fixes not held for want of room (`world_held`, `MAX_WORLD_AIRCRAFT`).
    pub world_skipped: u64,
    /// Peers' world fixes that disagree with the origin they cite.
    pub world_refuted: u64,
    /// Positions records not held to wait for their model, for room (the records' share,
    /// `budget::Store::Records`).
    pub positions_waiting_full: u64,
    /// Positions records whose model never came within `WAITING_MS`.
    pub positions_waiting_expired: u64,
    /// Positions records whose fixes could not be derived (a malformed fix set).
    pub positions_underivable: u64,
}

/// A receiver's area and the relays it said it publishes to.
struct Located {
    area: Region,
    relays: Vec<PublicKey>,
}

/// The world product being gathered: its open seconds, and when they are sealed.
struct Gatherer {
    /// Whether this relay gathers it.
    on: bool,
    settle: Span<Judged>,
    /// Open seconds, each aircraft's best fix so far.
    fixes: BTreeMap<u64, BTreeMap<u32, WorldFix>>,
    held: usize,
    /// The most fixes it holds across its open seconds, from its span ([`world_held`]).
    cap: usize,
    /// The seconds open, each with a fix at least.
    seconds: usize,
    /// What its fixes and seconds take, charged to `budget::Store::World` before they are held
    /// ([`Gatherer::bytes`]).
    charge: Charge,
    sealed_through: Option<u64>,
}

impl Gatherer {
    fn new(settle: Span<Judged>) -> Self {
        Self {
            on: false,
            settle,
            fixes: BTreeMap::new(),
            held: 0,
            cap: world_held(settle.ms()),
            seconds: 0,
            charge: Charge::none(),
            sealed_through: None,
        }
    }

    /// What its fixes and seconds take at most, as charged: each fix [`WORLD_FIX_BYTES`], each
    /// second open [`WORLD_SECOND_BYTES`], and the seconds' root once any was held (an emptied
    /// tree keeps it).
    fn bytes(&self, rooted: bool) -> usize {
        if rooted {
            WORLD_SECONDS_ROOT_BYTES
                + self.seconds * WORLD_SECOND_BYTES
                + self.held * WORLD_FIX_BYTES
        } else {
            0
        }
    }
}

/// What the hub takes from the sealer, and what it is charged: its own records to
/// `Store::Products`, the peers' regional batches to forward to `Store::Records`, each in the part
/// of the peer that handed it in ([`Held`]).
#[derive(Default)]
struct Outbox {
    /// This relay's own outputs untaken, and what they and their slots allocate
    /// (`Record::allocated`, `footprint::Deque`), charged to `Store::Products` before they are
    /// held.
    records: Deque<Record>,
    records_charge: Charge,
    /// Peers' regional batches to forward, each in the charge it came in (its own bytes, in the
    /// parts of the peer that handed it in), and the slots they take, charged to `Store::Records`
    /// before they grow.
    forward: Deque<(u64, Deliverer, RegionalBatch, Held)>,
    forward_slots: Charge,
}

/// Who a record handed the products is charged to (`Store::Records`): this relay's own output (its
/// MLAT's positions and models, signed with its key, whoever hands them back), or the session that
/// handed it in, by the hub's id of its connection (`network::Asker::source`; the relay's own
/// rebuilding from parity is `hub::RELAY_ITSELF`, one session like any other). Never the key that
/// signed it: a key is free, so a session forwarding records signed by many keys would take as
/// many parts; a session is what a peer is admitted as, and it has one part however many keys
/// sign what it sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum From {
    Own,
    Peer(u64),
}

/// The parts of the records' share (`Store::Records`): every peer's records together may hold all
/// but [`OWN_PART`] of it, which is this relay's own output's alone; each session admitted as a
/// member ([`Products::member`], held beside its member's reservation, `network::Membership`) at
/// most the peers' part divided by how many members are admitted now, and this relay's own
/// rebuilding (`hub::RELAY_ITSELF`) one part like a member's, always. A session that is no member
/// (a directory link, an engine taking raw, a subscriber, a member's session not yet admitted)
/// has no part, and a record it hands in is refused: so the divisor counts only the sessions
/// that send records, a member is admitted on the first data it brings in, and its bound is
/// never less than the peers' part over the members the plan admits (`budget::Plan::members`),
/// however many other sessions are open. What is taken is decided by who sent it, never by
/// which came first: a member flooding records is refused in its own part, every other member
/// keeps its own, and this relay's own positions are never refused for any peer's.
struct RecordsRoom {
    store: Arc<Gauge>,
    peers: Arc<Gauge>,
    /// Each part, with what its records hold now: every member admitted, and this relay's own
    /// rebuilding. A member's goes when its admission ends ([`RecordsPart`]'s drop), and the
    /// parts left divide the peers'.
    sessions: HashMap<u64, Arc<AtomicUsize>>,
    /// How many there are: what each part's bound divides the peers' part by, read by a charge
    /// as it grows.
    open: Arc<AtomicUsize>,
}

/// The records' share this relay's own output keeps from every peer: a quarter.
const OWN_PART: usize = 4;

/// What every peer's records together may hold of a records' share of `limit` bytes.
pub fn peers_part(limit: usize) -> usize {
    limit - limit / OWN_PART
}

/// What one part's records may hold of the peers' part of `limit` bytes, with `open` parts
/// ([`RecordsRoom`]: the members admitted and this relay's own rebuilding).
pub fn session_part(limit: usize, open: usize) -> usize {
    limit / open.max(1)
}

impl RecordsRoom {
    fn new(store: Arc<Gauge>) -> Self {
        let mut room = Self {
            peers: store.share(peers_part),
            store,
            sessions: HashMap::new(),
            open: Arc::new(AtomicUsize::new(0)),
        };
        room.join(crate::hub::RELAY_ITSELF);
        room
    }

    /// Charged to `store` from now on; the parts held stay.
    fn charge_to(&mut self, store: Arc<Gauge>) {
        self.peers = store.share(peers_part);
        self.store = store;
    }

    /// `source` has a part from now on: a member admitted ([`Products::member`]).
    fn join(&mut self, source: u64) {
        self.sessions
            .entry(source)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)));
        self.open.store(self.sessions.len(), Ordering::Release);
    }

    /// `source`'s admission ended: its part is gone, and the others divide the peers' part
    /// without it. What its records hold stays charged until they are let go. This relay's own
    /// rebuilding never leaves.
    fn leave(&mut self, source: u64) {
        if source == crate::hub::RELAY_ITSELF {
            return;
        }
        self.sessions.remove(&source);
        self.open.store(self.sessions.len(), Ordering::Release);
    }

    /// `bytes` charged to the store, and for a peer's record to the peers' part and its
    /// session's; `None` when any is full.
    /// `None` too for a session with no part: one that is no member admitted.
    fn charge(&mut self, from: From, bytes: usize) -> Option<Held> {
        let mut held = self.empty(from)?;
        held.grow(bytes).then_some(held)
    }

    /// A charge of nothing yet in `from`'s parts, to grow ([`Held::grow`]); `None` for a session
    /// with no part.
    fn empty(&mut self, from: From) -> Option<Held> {
        let From::Peer(source) = from else {
            return Some(Held {
                store: self.store.empty(),
                peer: None,
            });
        };
        let session = Arc::clone(self.sessions.get(&source)?);
        Some(Held {
            store: self.store.empty(),
            peer: Some(SessionHeld {
                peers: self.peers.empty(),
                of: Arc::clone(&self.peers),
                open: Arc::clone(&self.open),
                session,
                bytes: 0,
            }),
        })
    }
}

/// What a record handed the products holds while it waits, in each part it is charged to
/// ([`RecordsRoom`]): the store's, and for a peer's the peers' part and its session's. It moves
/// with the record (waiting for the sealer, for a model, to be forwarded) until the record is let
/// go.
#[derive(Debug, Default)]
struct Held {
    store: Charge,
    peer: Option<SessionHeld>,
}

/// A peer's record's charge to the peers' part and to its session's.
#[derive(Debug)]
struct SessionHeld {
    peers: Charge,
    /// The peers' part, whose limit the session's bound divides.
    of: Arc<Gauge>,
    open: Arc<AtomicUsize>,
    /// What the session's records hold now.
    session: Arc<AtomicUsize>,
    bytes: usize,
}

impl SessionHeld {
    /// `bytes` more in the session's part, if they fit under its bound now (the peers' part over
    /// the sessions open), or if the session holds nothing, so one oversized record is never
    /// refused forever (as `budget::Gauge` takes one); and in the peers' part.
    fn try_grow(&mut self, bytes: usize) -> bool {
        let bound = session_part(self.of.limit(), self.open.load(Ordering::Acquire));
        let grown = self
            .session
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                let after = held.checked_add(bytes)?;
                (after <= bound || held == 0).then_some(after)
            })
            .is_ok();
        if !grown {
            return false;
        }
        if !self.peers.try_grow(bytes) {
            self.session.fetch_sub(bytes, Ordering::SeqCst);
            return false;
        }
        self.bytes += bytes;
        true
    }

    fn shrink_to(&mut self, bytes: usize) {
        if bytes < self.bytes {
            self.session.fetch_sub(self.bytes - bytes, Ordering::SeqCst);
            self.bytes = bytes;
        }
        self.peers.shrink_to(bytes);
    }
}

impl Drop for SessionHeld {
    fn drop(&mut self) {
        self.session.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

/// A member session's part of the records' share ([`RecordsRoom`], [`Products::member`]): held
/// for as long as it is admitted, and gone, the others divided by one fewer, when this is
/// dropped, however its admission ends.
#[must_use = "the part is gone as soon as it is dropped"]
pub struct RecordsPart {
    shared: std::sync::Weak<Shared>,
    source: u64,
}

impl Drop for RecordsPart {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade()
            && let Ok(mut room) = shared.room.lock()
        {
            room.leave(self.source);
        }
    }
}

impl Held {
    /// `bytes` more in every part it is charged to, or in none.
    fn grow(&mut self, bytes: usize) -> bool {
        let before = self.peer.as_ref().map(|peer| peer.bytes);
        let peer = self.peer.as_mut().is_none_or(|peer| peer.try_grow(bytes));
        let grown = peer && self.store.try_grow(bytes);
        if !grown && let (Some(peer), Some(was)) = (&mut self.peer, before) {
            peer.shrink_to(was);
        }
        grown
    }
}

/// A record that is not an epoch, for the sealer to take in at its stamp.
enum Input {
    Positions(Positions),
    /// A model's manifest and the pair model id its fixes cite it by (`publish::pair_model_id`).
    ClockModel(ClockModel, Hash),
    World(WorldPositionsContent),
    /// A peer's regional batch, the connection it came in on, and who delivered it; judged usable
    /// by the hub before it came (`Network::take_regional`).
    Regional(u64, Deliverer, RegionalBatch),
}

/// One record waiting: its stamp, its hash (the order of records of one stamp), and what it is
/// charged until it is taken in.
struct Pending {
    stamp: Stamp,
    hash: Hash,
    input: Input,
    held: Held,
}

/// The records waiting for the sealer, and how far it has taken them in: every record stamped
/// before `taken_before` has been, so one handed in now is stamped no earlier.
#[derive(Default)]
struct Records {
    /// Each in the charge it came in (what its record allocates, in its sender's parts), and the
    /// slots they take, charged to `Store::Records` before they grow.
    pending: Deque<Pending>,
    slots: Charge,
    /// Every record stamped before this reading of `M` has been taken in; none before any is.
    taken_before: Option<Mono>,
}

impl Records {
    /// The slots' charge brought down to what they allocate.
    fn settle(&mut self) {
        self.slots.shrink_to(self.pending.bytes());
    }
}

/// The products' watermark: the end of the newest epoch sealed on the monotonic clock, with the
/// judging clock at it by the newest tick sealed by, and whether that tick was read while the
/// clock judged. What the hosted MLAT steps by (its monotonic reading) and signs by (its judging
/// one, and only while it judged), and what standing settles by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watermark {
    /// None before the first epoch is sealed: no reading stands for it.
    at: Option<Moment>,
    judging: bool,
}

impl Watermark {
    /// Before the first epoch is sealed: no readings, and nothing judged by them.
    pub const UNSEALED: Self = Self {
        at: None,
        judging: false,
    };

    /// A watermark a test or a replay recorded: `at`, judging or not.
    pub const fn recorded(at: Moment, judging: bool) -> Self {
        Self {
            at: Some(at),
            judging,
        }
    }

    /// Both readings at the watermark, none before the first epoch is sealed.
    pub const fn at(self) -> Option<Moment> {
        self.at
    }

    /// Both readings at the watermark when the tick it was read by judged: none when it did not
    /// (nothing is stepped or signed by it), and none before the first epoch is sealed.
    pub const fn judging_at(self) -> Option<Moment> {
        if self.judging { self.at } else { None }
    }
}

/// What the sealer shares with the handle: its outbox, its records, its report, its watermark, its
/// gauges.
struct Shared {
    outbox: Mutex<Outbox>,
    records: Mutex<Records>,
    report: Mutex<ProductsReport>,
    /// The end of the newest epoch sealed, the products' time, with the judging clock at it by the
    /// newest tick sealed by (`Sealer::judged`) and whether that tick judged: published together,
    /// so a reader never pairs one watermark with another's offset or judging.
    watermark: Mutex<Watermark>,
    /// This relay's own outputs untaken (`Outbox::records`): `budget::Store::Products`.
    gauge: Mutex<Arc<Gauge>>,
    /// The world products' fixes (`Gatherer::charge`): `budget::Store::World`.
    world: Mutex<Arc<Gauge>>,
    /// What others hand the products, waiting (`Records`, `Outbox::forward`), in the parts of
    /// `budget::Store::Records` ([`RecordsRoom`]).
    room: Mutex<RecordsRoom>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            outbox: Mutex::default(),
            records: Mutex::default(),
            report: Mutex::default(),
            watermark: Mutex::new(Watermark::UNSEALED),
            gauge: Mutex::new(Gauge::unlimited(Store::Products)),
            world: Mutex::new(Gauge::unlimited(Store::World)),
            room: Mutex::new(RecordsRoom::new(Gauge::unlimited(Store::Records))),
        }
    }
}

impl Shared {
    /// The world products' store (`budget::Store::World`) as it is now.
    fn world_gauge(&self) -> Arc<Gauge> {
        self.world.lock().map_or_else(
            |_| Gauge::unlimited(Store::World),
            |gauge| Arc::clone(&gauge),
        )
    }

    fn gauge(&self) -> Arc<Gauge> {
        self.gauge.lock().map_or_else(
            |_| Gauge::unlimited(Store::Products),
            |gauge| Arc::clone(&gauge),
        )
    }

    /// The records' store (`budget::Store::Records`) as it is now: what the structures the
    /// records wait in allocate is charged to it, outside any sender's part.
    fn records_store(&self) -> Arc<Gauge> {
        self.room.lock().map_or_else(
            |_| Gauge::unlimited(Store::Records),
            |room| Arc::clone(&room.store),
        )
    }

    /// `bytes` charged in `from`'s parts of the records' share ([`RecordsRoom`]), or `None`.
    fn charge_records(&self, from: From, bytes: usize) -> Option<Held> {
        self.room
            .lock()
            .ok()
            .and_then(|mut room| room.charge(from, bytes))
    }
}

impl Input {
    /// What it allocates of its own while it waits (`Record::allocated` of its record, a world
    /// content's fixes at their capacity): what it is charged in its sender's parts.
    fn allocated(&self) -> usize {
        match self {
            Self::Positions(positions) => positions.allocated(),
            Self::ClockModel(model, _) => model.allocated(),
            Self::World(content) => {
                crate::footprint::vec::<tally_wire::WorldFix>(content.fixes.capacity())
            }
            Self::Regional(_, _, regional) => regional.allocated(),
        }
    }
}

/// What one sealer owns: everything the products decide.
pub struct Sealing {
    coordinator: Coordinator,
    /// The threads an epoch's areas are made into records on, beside the sealer's own.
    pool: Pool,
    /// The relay's signer (`signer::Signer`): products are signed only while its clock is synced.
    signer: Option<Signer>,
    /// The key of `digest` (a world fix remembered by a 64-bit digest).
    digest_key: RandomState,
    boot_id: u64,
    sequence: u64,
    /// The deduplicated stream's chain.
    stream: Stream,
    /// The deduplicated stream's losses last said, and the watermark they were said at (none
    /// before they were first said).
    stream_said: (Option<Mono>, u64, u64),
    taken: Vec<Region>,
    /// The world product.
    world: Gatherer,
    /// Regional batches seen, own and peers', by hash.
    regional_seen: Bounded<Hash, ()>,
    /// A model's id, and the hash of its inputs.
    models: Bounded<Hash, Hash>,
    /// Positions waiting for the model they cite, by its id: when each arrived, the record, and
    /// what it is charged while it waits.
    waiting: Tree<Hash, Waiting>,
    /// What the waiting lists' slots allocate together, and the tree and the slots' charge to
    /// `Store::Records` (each record's own bytes wait in its own charge, `Held`), taken before
    /// they grow.
    waiting_lists: usize,
    waiting_charge: Charge,
    derived: Bounded<(Hash, u16), u64>,
    report: ProductsReport,
    /// The end of the newest epoch sealed, on the monotonic clock; none before the first.
    watermark: Option<Mono>,
    /// The newest tick any thread closed by (`seal::Ready::judged`): it turns the watermark,
    /// on the monotonic clock, into the judging clock the world's seconds are signed in.
    /// None before any tick.
    judged: Option<Stamp>,
    shared: Arc<Shared>,
}

/// What the sealer is asked to do through its queue: an epoch, or a setting. Records wait in
/// [`Records`] instead.
enum Command {
    Frozen(Frozen),
    Identity(Signer),
    Taken(Vec<Region>),
    World(bool),
    Advance(Stamp),
}

/// Where the sealing runs: its own thread, or for a test the caller, under one lock.
enum Sealer {
    Inline(Box<Mutex<Sealing>>),
    Thread {
        sender: SyncSender<Command>,
        handle: Option<JoinHandle<()>>,
    },
}

/// A regional batch whose signature was checked: made only by [`Verified::of`], so what takes
/// one ([`Products::regional_from`]) never checks it again, and nothing reaches it unchecked.
#[derive(Clone, Debug)]
pub struct Verified(RegionalBatch);

impl Verified {
    /// `regional`, if its signature verifies.
    pub fn of(regional: RegionalBatch) -> Option<Self> {
        regional.verify().ok().map(|()| Self(regional))
    }

    pub fn batch(&self) -> &RegionalBatch {
        &self.0
    }
}

/// The products: the receivers' areas (read per batch by the ingest worker that owns the
/// receiver's shard), and the sealer. Whoever holds them sees the sealer where it runs: moving it
/// onto its thread (`on_thread`) needs no exclusive hold, so it can never be left behind inline.
pub struct Products {
    /// Each receiver's area and chosen relays, by its raw shard, at its share of the receiver
    /// figure (`Products::charge_to`).
    located: Mutex<Bounded<PublicKey, Located>>,
    /// What the areas are charged whole (`budget::Store::Located`), and what they allocate at
    /// most at the figure they were sized to.
    located_charge: Mutex<(usize, crate::budget::Charge)>,
    /// What the remembered tables are charged whole (`budget::Store::Remembered`,
    /// [`REMEMBERED_BYTES`]).
    remembered_charge: Mutex<Charge>,
    own: OnceLock<PublicKey>,
    sealer: RwLock<Sealer>,
    shared: Arc<Shared>,
}

impl Default for Products {
    fn default() -> Self {
        Self::new()
    }
}

impl Products {
    /// Products sealed by the caller (one lock): for tests and for a relay that runs inline.
    pub fn new() -> Self {
        Self::with_boot(random_boot(), 1)
    }

    /// As `new`, the regional stream under `boot_id` (and the deduplicated stream under a random
    /// one), gathered from `threads` message threads.
    pub fn with_boot(boot_id: u64, threads: usize) -> Self {
        Self::with_boots(boot_id, random_boot(), threads)
    }

    /// As `new`, the regional stream under `regional` and the deduplicated stream under `stream`,
    /// gathered from `threads` message threads: what two runs of one trace compare byte for byte
    /// by.
    pub fn with_boots(regional: u64, stream: u64, threads: usize) -> Self {
        let shared = Arc::new(Shared::default());
        Self {
            located: Mutex::new(Bounded::new(UNSIZED_RECEIVERS)),
            located_charge: Mutex::new((0, crate::budget::Charge::none())),
            remembered_charge: Mutex::new(Charge::none()),
            own: OnceLock::new(),
            sealer: RwLock::new(Sealer::Inline(Box::new(Mutex::new(Sealing::new(
                (regional, stream),
                threads,
                Arc::clone(&shared),
            ))))),
            shared,
        }
    }

    /// The sealing on a thread of its own, gathering from `threads.message` message threads, with
    /// a pool of `threads.seal` threads, itself and its helpers, each held up by `pause` (a test's;
    /// none in a relay). What it was told so far (areas taken, the world's switches, its key) is
    /// carried over. Every thread is started or this fails, and the relay with it: an inline sealer
    /// behind a staged exchange would gather from one thread and refuse every epoch.
    pub fn on_thread(&self, threads: Threads, pause: Option<&Pause>) -> Result<(), String> {
        let mut sealer = self
            .sealer
            .write()
            .map_err(|_| "the sealer's lock is poisoned".to_owned())?;
        let Sealer::Inline(sealing) = &*sealer else {
            return Err("the sealer already runs on its own thread".to_owned());
        };
        let mut fresh = {
            let mut held = sealing
                .lock()
                .map_err(|_| "the sealer's lock is poisoned".to_owned())?;
            let mut fresh = Sealing::new(
                (held.boot_id, 0),
                threads.message.max(1),
                Arc::clone(&self.shared),
            );
            fresh.stream = std::mem::take(&mut held.stream);
            fresh.taken = std::mem::take(&mut held.taken);
            fresh.world.on = held.world.on;
            fresh.signer = held.signer.take();
            fresh
        };
        fresh.pool = Pool::start(threads.seal.max(1) - 1, pause)?;
        let (sender, receiver) = sync_channel(EPOCH_QUEUE);
        let pause = pause.cloned();
        let handle = std::thread::Builder::new()
            .name("tally-sealer".to_owned())
            .spawn(move || run(fresh, &receiver, pause.as_ref()))
            .map_err(|error| format!("sealer thread: {error}"))?;
        *sealer = Sealer::Thread {
            sender,
            handle: Some(handle),
        };
        Ok(())
    }

    /// Where the message exchange hands each closed epoch: to the sealer, without waiting; the
    /// epoch back when its queue is full, for the exchange to hold, charged, and offer again.
    pub fn sink(self: &Arc<Self>) -> Sink {
        let products = Arc::clone(self);
        Arc::new(move |frozen| products.frozen(frozen))
    }

    /// An epoch for the sealer, without waiting: back when it could not be taken now.
    fn frozen(&self, frozen: Frozen) -> Result<(), Box<Frozen>> {
        let Ok(sealer) = self.sealer.read() else {
            return Err(Box::new(frozen));
        };
        match &*sealer {
            Sealer::Inline(sealing) => {
                if let Ok(mut sealing) = sealing.lock() {
                    sealing.handle(Command::Frozen(frozen));
                    sealing.publish_report();
                }
                Ok(())
            }
            Sealer::Thread { sender, .. } => match sender.try_send(Command::Frozen(frozen)) {
                Ok(()) => Ok(()),
                Err(
                    TrySendError::Full(Command::Frozen(frozen))
                    | TrySendError::Disconnected(Command::Frozen(frozen)),
                ) => Err(Box::new(frozen)),
                // Only an epoch was sent, so only an epoch comes back.
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => Ok(()),
            },
        }
    }

    /// A record for the sealer, stamped `stamp` (no earlier than what the sealer has taken in, on
    /// the monotonic clock)
    /// and charged while it waits to `from`'s parts of the records' share (`Store::Records`,
    /// [`RecordsRoom`]), its only bound; refused and counted when one is full. It waits apart from the epochs and is charged
    /// apart from what they make, so it never takes an epoch's place or its room.
    fn record(&self, from: From, stamp: Stamp, hash: Hash, input: Input) {
        let taken = self.shared.records.lock().is_ok_and(|mut records| {
            let Some(held) = self.shared.charge_records(from, input.allocated()) else {
                return false;
            };
            // Its slot charged first, to the store outside any part.
            if records.pending.is_empty() && records.slots.bytes() == 0 {
                records.slots = self.shared.records_store().empty();
            }
            let growth = records.pending.growth();
            if !records.slots.try_grow(growth) {
                return false;
            }
            // On the monotonic grid the sealer has taken records in to: stamped no earlier.
            let stamp = records
                .taken_before
                .map_or(stamp, |taken_before| stamp.not_before(taken_before));
            records.pending.push_back(Pending {
                stamp,
                hash,
                input,
                held,
            });
            records.settle();
            true
        });
        if !taken && let Ok(mut report) = self.shared.report.lock() {
            report.records_refused += 1;
        }
    }

    /// What the products hold is charged to `budget` from now on: their own outputs to its
    /// `Store::Products`, what others hand them to its `Store::Records`.
    pub fn charge_to(&self, budget: &crate::budget::Budget) {
        if let Ok(mut held) = self.shared.gauge.lock() {
            *held = budget.gauge(Store::Products);
        }
        if let Ok(mut room) = self.shared.room.lock() {
            room.charge_to(budget.gauge(Store::Records));
        }
        if let Ok(mut world) = self.shared.world.lock() {
            *world = budget.gauge(Store::World);
        }
        self.size_located(budget.receivers(), &budget.gauge(Store::Located));
        self.charge_remembered(&budget.gauge(Store::Remembered));
    }

    /// The remembered tables charged whole to `gauge` ([`REMEMBERED_BYTES`]), what they were
    /// charged before given back first; nothing where its limit is below them, and a start
    /// refuses that (`Products::remembered_charged`).
    pub fn charge_remembered(&self, gauge: &Arc<Gauge>) {
        let mut charged = self
            .remembered_charge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *charged = Charge::none();
        let mut charge = gauge.empty();
        if gauge.limit() >= REMEMBERED_BYTES {
            let _ = charge.try_grow(REMEMBERED_BYTES);
        }
        *charged = charge;
    }

    /// Whether the remembered tables are charged what they allocate at most: a relay whose budget
    /// cannot hold them refuses to start.
    pub fn remembered_charged(&self) -> Result<(), String> {
        let charged = self
            .remembered_charge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bytes();
        if charged == REMEMBERED_BYTES {
            Ok(())
        } else {
            Err(format!(
                "the products' remembered tables need {REMEMBERED_BYTES} bytes and their store \
                 gave them {charged}: give the relay more memory"
            ))
        }
    }

    /// The receivers' areas held to `receivers` receivers from now (one table, the least recently
    /// active forgotten past it), charged whole to `gauge` what they allocate at
    /// most at that figure, what they were charged before given back first. A store whose limit
    /// is below it is charged nothing, and a start refuses it (`Products::located_charged`).
    pub fn size_located(&self, receivers: usize, gauge: &std::sync::Arc<crate::budget::Gauge>) {
        let mut charged = self
            .located_charge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *charged = (0, crate::budget::Charge::none());
        if let Ok(mut located) = self.located.lock() {
            located.set_capacity(receivers.max(1));
        }
        let planned = located_planned_bytes(receivers);
        let mut charge = gauge.empty();
        if gauge.limit() >= planned {
            let _ = charge.try_grow(planned);
        }
        *charged = (planned, charge);
    }

    /// Whether the receivers' areas are charged what they allocate at most: a relay whose budget
    /// cannot hold them refuses to start.
    pub fn located_charged(&self) -> Result<(), String> {
        let charged = self
            .located_charge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if charged.1.bytes() == charged.0 {
            Ok(())
        } else {
            Err(format!(
                "the receivers' areas need {} bytes and their store gave them {}: give the relay \
                 more memory",
                charged.0,
                charged.1.bytes()
            ))
        }
    }

    /// The areas this relay takes (the operator's, as `Selection::set_taken`): a peer's regional
    /// batch for a cell inside one is forwarded.
    pub fn set_taken(&self, areas: Vec<Region>) {
        self.control(Command::Taken(areas));
    }

    /// Whether this relay gathers and publishes the world product: a relay at the top of the
    /// area tree, holding every area's positions and regional data.
    /// Only through `Hub::gathering_world`, so the plan holds its fixes' store whenever it
    /// gathers: a relay told here alone had a store of nothing, and gathered one fix.
    pub(crate) fn set_world(&self, world: bool) {
        self.control(Command::World(world));
    }

    /// A setting: waits for room, never refused.
    fn control(&self, command: Command) {
        let Ok(sealer) = self.sealer.read() else {
            return;
        };
        match &*sealer {
            Sealer::Inline(sealing) => {
                if let Ok(mut sealing) = sealing.lock() {
                    sealing.handle(command);
                    sealing.publish_report();
                }
            }
            Sealer::Thread { sender, .. } => {
                let _ = sender.send(command);
            }
        }
    }

    pub fn report(&self) -> ProductsReport {
        self.shared
            .report
            .lock()
            .map(|report| *report)
            .unwrap_or_default()
    }

    /// The end of the newest epoch the products have sealed: their time, read by nothing that
    /// decides per reception.
    pub fn watermark_ms(&self) -> u64 {
        self.watermark().at.map_or(0, |at| at.mono().ms())
    }

    /// The watermark and the judging clock at it, by the newest tick the sealer took, as one pair
    /// published together (`Shared::watermark`): what the hosted MLAT steps and signs by
    /// (`MlatHost::take_published`), so the same stamped trace gives the same bytes.
    pub fn watermark(&self) -> Watermark {
        self.shared
            .watermark
            .lock()
            .map_or_else(|poisoned| *poisoned.into_inner(), |watermark| *watermark)
    }

    /// A receiver's newest signed description (verified by the hub), with its site as the hub
    /// holds it (`place`: a format 1 description's own, or the `ReceiverSite` paired with a format
    /// 2 one): whether it chose this relay, and its area. The area is its public cell's parent at
    /// `AREA_RESOLUTION` (`area_of_public`), never the area its site lies in: a client reads the
    /// regional product by area, and the two differ where the public cell straddles an area's
    /// edge, so the site's would place it finer than its public cell. A receiver with no site
    /// held has no area and is in no regional product.
    pub fn described(&self, info: &ReceiverInfo, place: Option<Location>) {
        let (Ok(receiver), Ok(described)) = (info.receiver(), info.description()) else {
            return;
        };
        let relays = match described {
            tally_wire::batch::Description::Site(content) => content.relays,
            tally_wire::batch::Description::Public(content) => content.relays,
        };
        let Ok(mut located) = self.located.lock() else {
            return;
        };
        let area = place
            .and_then(|_| info.public_cell().ok().flatten())
            .and_then(area_of_public);
        match area {
            Some(area) => {
                let mut relays = relays;
                relays.truncate(RELAYS_PER_RECEIVER);
                relays.shrink_to_fit();
                located.insert_active(receiver, Located { area, relays });
            }
            _ => {
                located.remove(&receiver);
            }
        }
    }

    /// The area whose regional product a receiver's receptions join: its area, when it chose this
    /// relay. Read once per batch, by the ingest worker that owns the receiver's shard (one lock for
    /// every shard's: a lookup and a touch under it).
    pub fn area_for(&self, receiver: &PublicKey) -> Option<Region> {
        let own = self.own.get()?;
        let mut located = self.located.lock().ok()?;
        let area = match located.get(receiver) {
            Some(located) if located.relays.contains(own) => located.area,
            _ => return None,
        };
        located.touch(receiver);
        Some(area)
    }

    /// The signer this relay signs its products with (`signer::Signer`): while its clock is not
    /// synced the sealer signs nothing (every product's time is that clock's), and counts each
    /// seal it skips (`unsynced_seals`).
    pub fn adopt_signer(&self, signer: &Signer) {
        if self.own.set(signer.public()).is_ok() {
            self.control(Command::Identity(signer.clone()));
        }
    }

    /// A test's: `identity` as a signer on a clock always synced.
    #[cfg(test)]
    pub fn adopt_identity(&self, identity: tally_wire::Identity) {
        self.adopt_signer(&crate::signer::synced(identity));
    }

    /// Who a record the hub forwarded once by its hash is charged to (positions, a clock model),
    /// handed in by session `source`: this relay when its own key signed it, else that session,
    /// whatever key signed it ([`From`]).
    fn handed_by(&self, source: u64, signer: Result<PublicKey, WireError>) -> Option<From> {
        let signer = signer.ok()?;
        Some(if self.own.get() == Some(&signer) {
            From::Own
        } else {
            From::Peer(source)
        })
    }

    /// Session `source` is admitted as a member: it has a part of the peers' share for as long as
    /// the part returned is held, and every other part is divided by one more ([`RecordsRoom`]).
    /// Only a member's admission holds one (`network::Network::admit_member`, beside its
    /// reservation from the members' pool, so the parts are bounded as the members are); a
    /// session that holds none has every record it hands in refused.
    pub fn member(&self, source: u64) -> RecordsPart {
        if let Ok(mut room) = self.shared.room.lock() {
            room.join(source);
        }
        RecordsPart {
            shared: Arc::downgrade(&self.shared),
            source,
        }
    }

    /// A clock model's manifest (verified), handed in by session `source`, with the pair model id
    /// `pair` its encoding is (`publish::pair_model_id`, what fixes cite): the inputs hash its
    /// fixes' input sets are made with. Positions waiting for it are taken now.
    pub fn clock_model(&self, model: &ClockModel, pair: Hash, source: u64, stamp: Stamp) {
        let Some(from) = self.handed_by(source, model.engine()) else {
            return;
        };
        self.record(
            from,
            stamp,
            model.id(),
            Input::ClockModel(model.clone(), pair),
        );
    }

    /// Positions (verified), handed in by session `source`: candidates for the world product.
    pub fn positions(&self, positions: &Positions, source: u64, stamp: Stamp) {
        let Some(from) = self.handed_by(source, positions.engine()) else {
            return;
        };
        self.record(
            from,
            stamp,
            positions.hash(),
            Input::Positions(positions.clone()),
        );
    }

    /// A world record a peer sent. A relay that gathers the world takes its fixes as candidates,
    /// except one that disagrees with an origin this relay holds. Nothing is sent back.
    pub fn world_from(&self, asker: &Asker, world: WorldPositions, stamp: Stamp) {
        if asker.role != AskerRole::Relay || world.verify().is_err() {
            return;
        }
        if let Ok(content) = world.content() {
            self.record(
                From::Peer(asker.source),
                stamp,
                world.hash(),
                Input::World(content),
            );
        }
    }

    /// A regional batch a peer sent, its signature checked once by its intake
    /// (`Network::take_regional`, [`Verified`]): once, its ADS-B positions become world
    /// candidates, and when its cell is inside an area this relay takes it is forwarded unchanged
    /// ([`Products::take_forward`], never down the connection it came in on). Nothing is sent back.
    /// Taken in at `stamp` by the relay's clocks (its monotonic reading the products' order, its
    /// judging one what its fixes are judged by). Its caller has judged it
    /// usable by the relay's one window for what relays sign (`Hub::in_window`,
    /// `tally_wire::budget::Window::relay_signed`) and taken it once (`Hub::take_passed_on`); the
    /// products judge its time no second way.
    pub fn regional_from(&self, asker: &Asker, regional: Verified, stamp: Stamp) {
        if asker.role != AskerRole::Relay {
            return;
        }
        let Verified(regional) = regional;
        self.record(
            From::Peer(asker.source),
            stamp,
            regional.hash(),
            Input::Regional(asker.source, asker.deliverer(), regional),
        );
    }

    /// The watermark passed `at`'s monotonic time with nothing flowing to say so, the tick read
    /// as `at` (both clocks and whether the judging one judged): every record stamped before it
    /// is taken in, then every world second it settles by `at`'s judging clock is sealed, if it
    /// judged. The message exchange's epochs say it as they close; this is for a products of
    /// their own (a test).
    pub fn advance(&self, at: Stamp) {
        self.control(Command::Advance(at));
    }

    /// Peers' regional batches to forward unchanged, each with the connection it came in on and
    /// who delivered it (whose share the hub charges it to, `Hub::publish_as`): the hub's fan-out
    /// sends it to every other.
    pub fn take_forward(&self) -> Vec<(u64, Deliverer, RegionalBatch)> {
        let forward = self
            .shared
            .outbox
            .lock()
            .map(|mut outbox| {
                let forward = outbox.forward.take();
                outbox.forward_slots.shrink_to(0);
                forward
            })
            .unwrap_or_default();
        if let Ok(mut report) = self.shared.report.lock() {
            report.regional_forwarded += forward.len() as u64;
        }
        // Each is let go of its charge as the hub takes it.
        forward
            .into_iter()
            .map(|(source, who, regional, _held)| (source, who, regional))
            .collect()
    }

    /// What the sealer signed since the last call, as this relay's: each area's copies once an
    /// epoch, and every world second whose seal has come.
    pub fn tick(&self) -> Vec<Record> {
        self.shared
            .outbox
            .lock()
            .map(|mut outbox| {
                let records = Vec::from(outbox.records.take());
                outbox.records_charge.shrink_to(0);
                records
            })
            .unwrap_or_default()
    }
}

impl Drop for Products {
    fn drop(&mut self) {
        if let Ok(Sealer::Thread { sender, handle }) = self.sealer.get_mut() {
            // Closing the queue ends the thread.
            let (closed, _) = sync_channel(0);
            drop(std::mem::replace(sender, closed));
            if let Some(handle) = handle.take() {
                let _ = handle.join();
            }
        }
    }
}

fn run(mut sealing: Sealing, receiver: &Receiver<Command>, pause: Option<&Pause>) {
    // A sealer that stopped would publish no epoch again: the relay ends instead
    // (`crate::abort_on_any_panic`).
    let paused = |command| {
        if let Some(pause) = pause {
            pause(Stage::Sealer);
        }
        command
    };
    while let Ok(command) = receiver.recv() {
        sealing.handle(paused(command));
        // Whatever else is waiting, then the report once.
        while let Ok(command) = receiver.try_recv() {
            sealing.handle(paused(command));
        }
        sealing.publish_report();
    }
}

/// A random boot id: the standard library's per-process random keys, which is all a boot id
/// must be (as the hub's deduplicated stream takes its own).
fn random_boot() -> u64 {
    RandomState::new().build_hasher().finish()
}

impl Sealing {
    /// A sealer whose regional stream is under `regional` and whose deduplicated stream is under
    /// `stream`.
    fn new((regional, stream): (u64, u64), threads: usize, shared: Arc<Shared>) -> Self {
        Self {
            coordinator: Coordinator::new(threads),
            pool: Pool::default(),
            signer: None,
            digest_key: RandomState::new(),
            boot_id: regional,
            sequence: 0,
            stream: Stream::new(stream),
            stream_said: (None, 0, 0),
            taken: Vec::new(),
            world: Gatherer::new(policy::<_, WORLD_SETTLE_MS>()),
            regional_seen: Bounded::new(REGIONAL_REMEMBERED),
            models: Bounded::new(MODELS_REMEMBERED),
            waiting: Tree::new(),
            waiting_lists: 0,
            waiting_charge: Charge::none(),
            derived: Bounded::new(DERIVED_REMEMBERED),
            report: ProductsReport::default(),
            watermark: None,
            judged: None,
            shared,
        }
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Frozen(frozen) => {
                let ready = self.coordinator.take(frozen);
                self.report.epoch_parts_lost += ready.parts_lost;
                self.report.receptions_late += ready.late;
                self.report.receptions_past_window += ready.past;
                self.judged = self.judged.max(ready.judged);
                let watermark = ready.watermark;
                for merged in ready.merged {
                    // The records stamped in or before the epoch are candidates beside it.
                    self.take_records(merged.epoch.end());
                    self.seal_epoch(merged);
                }
                // Every epoch before the watermark is closed: the world seals by it, whether or
                // not anything flowed.
                if let Some(watermark) = watermark {
                    self.advance(watermark.start());
                }
            }
            Command::Identity(signer) => self.signer = Some(signer),
            Command::Taken(areas) => self.taken = areas,
            Command::World(on) => self.world.on = on,
            Command::Advance(at) => {
                self.judged = self.judged.max(Some(at));
                self.advance(at.mono());
            }
        }
    }

    fn publish_report(&self) {
        if let Ok(mut report) = self.shared.report.lock() {
            // What the handle counted itself is kept.
            let records_refused = report.records_refused;
            let forwarded = report.regional_forwarded;
            *report = self.report;
            report.records_refused = records_refused;
            report.regional_forwarded = forwarded;
        }
    }

    /// Takes in every record stamped before `before_ms`, in the order of their stamps (then
    /// hashes), and from now on stamps a record handed in no earlier than that. What it is charged
    /// is released as it is taken in: what it leaves held is the gatherers' and the waiting
    /// list's, each bounded by count.
    fn take_records(&mut self, before: Mono) {
        let mut due = match self.shared.records.lock() {
            Ok(mut records) => {
                records.taken_before = records.taken_before.max(Some(before));
                let due = records
                    .pending
                    .take_where(|pending| pending.stamp.mono() < before);
                records.settle();
                due
            }
            Err(_) => return,
        };
        due.sort_by_key(|pending| (pending.stamp.mono(), pending.hash));
        for Pending {
            stamp, input, held, ..
        } in due
        {
            // A record that waits on (for its model, to be forwarded) keeps its charge, in the
            // parts of whoever handed it in; any other lets it go now.
            match input {
                Input::Positions(positions) => self.take_positions(positions, stamp, held),
                Input::ClockModel(model, pair) => self.clock_model(&model, pair, stamp),
                Input::World(content) => self.take_world(content, stamp),
                Input::Regional(source, who, regional) => {
                    self.regional_from((source, who), regional, stamp, held);
                }
            }
        }
    }

    /// One epoch, whole: its stream and its areas signed, its fixes offered, and every world
    /// second its end settles sealed, its records out together or refused together. A refused
    /// epoch is counted, and the world still advances by it.
    fn seal_epoch(&mut self, merged: Merged) {
        let end = merged.epoch.end();
        let signed_at = merged.signed_at();
        let Merged {
            refused,
            stream,
            regional,
            charges,
            ..
        } = merged;
        let mut records = Vec::new();
        let mut streamed = false;
        if refused {
            // Refused whole: the deduplicated stream misses it too, and says so.
            self.report.epochs_refused += 1;
            self.report.stream_refused += 1;
        } else {
            let (stream, regional) = self.seal_copies(signed_at, stream, regional);
            streamed = !stream.is_empty();
            records.extend(stream.into_iter().map(Record::RelayBatch));
            // Each regional batch, then its client form (counters stripped): the one a client
            // is sent (`outbound`).
            for (regional, client) in regional {
                records.push(Record::RegionalBatch(regional));
                records.extend(client.map(Record::ClientRegionalBatch));
            }
        }
        // The epoch's batches, and what they are charged, are let go now: everything it made is
        // signed.
        drop(charges);
        records.extend(self.advance_records(end));
        if !self.out(records) && streamed {
            self.report.stream_refused += 1;
        }
    }

    /// The watermark passed `watermark`: every record stamped before it is taken in, what it
    /// seals goes out, and only then does the handle read the new watermark, so a reader that sees
    /// it finds everything sealed by it.
    fn advance(&mut self, watermark: Mono) {
        self.take_records(watermark);
        let records = self.advance_records(watermark);
        self.out(records);
        self.say_stream_losses();
        self.publish_report();
        let watermark = Watermark {
            at: self
                .judged
                .zip(self.watermark)
                .map(|(judged, watermark)| judged.moment().at(watermark)),
            judging: self.judged.is_some_and(Stamp::judging),
        };
        match self.shared.watermark.lock() {
            Ok(mut published) => *published = watermark,
            Err(poisoned) => *poisoned.into_inner() = watermark,
        }
    }

    /// Hands `records` to the hub, charged, or refuses them whole and counts it: false when they
    /// were refused (or the outbox is lost).
    fn out(&mut self, records: Vec<Record>) -> bool {
        if records.is_empty() {
            return true;
        }
        let Ok(mut outbox) = self.shared.outbox.lock() else {
            return false;
        };
        // What they allocate and the slots they take, charged before they are held.
        let bytes = records.iter().map(Record::allocated).sum::<usize>()
            + outbox.records.growth_by(records.len());
        if outbox.records_charge.bytes() == 0 {
            outbox.records_charge = self.shared.gauge().empty();
        }
        if outbox.records_charge.try_grow(bytes) {
            for record in records {
                outbox.records.push_back(record);
            }
            true
        } else {
            self.report.epochs_refused += 1;
            false
        }
    }

    /// Says what the deduplicated stream lost since it last said, at most once a
    /// `STREAM_SAID_EVERY_MS` of the products' time: every loss is counted in the report as well.
    fn say_stream_losses(&mut self) {
        let (said_ms, refused, oversized) = self.stream_said;
        let (now_refused, now_oversized) =
            (self.report.stream_refused, self.report.stream_oversized);
        if (now_refused, now_oversized) == (refused, oversized)
            || self
                .watermark
                .zip(said_ms)
                .is_some_and(|(now, said)| now.since(said) < policy::<Mono, STREAM_SAID_EVERY_MS>())
        {
            return;
        }
        eprintln!(
            "tally-relay: {} seconds of the deduplicated stream were refused whole since the last \
             report, each with every message first heard in it (their batches were forwarded \
             raw): the products were behind or past their budget (`stream_refused` in GET \
             /products); {} observations were too large for any message (`stream_oversized`)",
            now_refused - refused,
            now_oversized - oversized
        );
        self.stream_said = (self.watermark, now_refused, now_oversized);
    }

    /// The watermark is `watermark`: positions waiting too long expire, and every world second
    /// it settles is sealed and signed.
    fn advance_records(&mut self, watermark: Mono) -> Vec<Record> {
        let now = self
            .watermark
            .map_or(watermark, |held| held.latest(watermark));
        self.watermark = Some(now);
        self.expire_waiting(now);
        // The world's seconds are the signed seconds of its fixes: they settle by the judging
        // clock, at the watermark by the newest tick's two readings, and not at all by a tick read
        // while the clock did not judge (RFC-0171 §3.6): nothing is sealed or signed by it.
        let mut out = Vec::new();
        let Some(stamp) = self.judged.filter(|judged| judged.judging()) else {
            return out;
        };
        let judged = stamp.moment().at(now).judged();
        let sealed = self.seal(judged);
        if !sealed.is_empty() {
            self.count_unsynced();
        }
        let unsigned: u64 = sealed.iter().map(|(_, fixes)| fixes.len() as u64).sum();
        let Some(signer) = self.signer() else {
            self.report.world_unsigned += unsigned;
            return out;
        };
        crate::signer::with(&signer, stamp, |signing| {
            let Some(identity) = signing else {
                self.report.world_unsigned += unsigned;
                return;
            };
            for (second, fixes) in sealed {
                let parts = world_parts(identity, second, fixes);
                self.report.world_signed += parts.len() as u64;
                out.extend(parts.into_iter().map(Record::WorldPositions));
            }
        });
        out
    }

    /// The signer to sign with now: none before the relay has one, or while its judging clock is
    /// not synced (`signer::Signer::signs`). Each signing asks it again (`Signer::with`), so work
    /// that finishes after the clock stopped judging signs nothing.
    fn signer(&self) -> Option<Signer> {
        self.signer.clone().filter(Signer::signs)
    }

    /// A seal skipped for an unsynced clock counted (`unsynced_seals`).
    fn count_unsynced(&mut self) {
        if self.signer.as_ref().is_some_and(|signer| !signer.signs()) {
            self.report.unsynced_seals += 1;
        }
    }

    /// An epoch's copies signed: its deduplicated stream as this relay's batches, in order, and
    /// its areas, in cell order, as regional batches, each with its client form
    /// (`ClientRegionalBatch::sign_draft`, the same receptions with their counters stripped, as
    /// the regional product reaches a client). Their time is the epoch's end on the judging clock
    /// (`seal::Merged::signed_ms`), `wall_ms`. Without an identity, or without a time to sign
    /// at (its tick read while the clock did not judge), the copies are counted and dropped.
    ///
    /// The work is the pool's ([`Pool::map`]), every reception read where its batch holds it:
    /// the stream's chain is signed as one job ([`Stream::sign`]) beside each area's observations
    /// gathered and cut to fit a record ([`cut`]); then, numbered here in cell order, each regional
    /// record is signed and its ADS-B fixes derived. What is decided (the numbering, the fixes
    /// remembered and offered) is decided here, in that order, so the records are the same on any
    /// number of threads.
    fn seal_copies(
        &mut self,
        signed_at: Option<Stamp>,
        stream: Vec<Kept>,
        areas: BTreeMap<u64, (Region, Vec<Kept>)>,
    ) -> (
        Vec<Batch>,
        Vec<(RegionalBatch, Option<ClientRegionalBatch>)>,
    ) {
        let mut sealed = Vec::new();
        self.count_unsynced();
        // None when the epoch's newest tick was stamped while the clock did not judge
        // (`seal::Merged::signed_ms`): nothing is signed from it, as with no signer.
        if signed_at.is_none() && self.signer().is_some() {
            self.report.unsynced_seals += 1;
        }
        let (Some(signer), Some(signed_at)) = (self.signer(), signed_at) else {
            self.report.stream_unsigned += stream.len() as u64;
            self.report.regional_unsigned += areas
                .values()
                .map(|(_, copies)| copies.len() as u64)
                .sum::<u64>();
            return (Vec::new(), sealed);
        };
        let wall_ms = signed_at.judged().ms();
        let boot_id = self.boot_id;
        let mut work = Vec::with_capacity(areas.len() + 1);
        if !stream.is_empty() {
            work.push(Work::Stream(std::mem::take(&mut self.stream), stream));
        }
        work.extend(areas.into_values().map(Work::Area));
        let streaming = signer.clone();
        let done = self.pool.map(work, move |work| match work {
            Work::Stream(mut chain, copies) => {
                let signed = crate::signer::with(&streaming, signed_at, |signing| match signing {
                    Some(identity) => chain.sign(identity, copies, wall_ms),
                    None => crate::deduplicated::Signed::unsigned(copies.len()),
                });
                Done::Stream(chain, signed)
            }
            Work::Area(area) => Done::Area(cut(area, boot_id, wall_ms)),
        });
        let mut streamed = Vec::new();
        let mut chunks = Vec::new();
        for done in done {
            match done {
                Done::Stream(chain, signed) => {
                    self.stream = chain;
                    self.report.stream_oversized += signed.oversized;
                    self.report.stream_unsigned += signed.unsigned;
                    streamed = signed.batches;
                }
                Done::Area(cut) => {
                    self.report.regional_oversized += cut.oversized;
                    for copies in cut.chunks {
                        chunks.push((cut.cell, self.sequence, copies));
                        self.sequence += 1;
                    }
                }
            }
        }
        let signed = self.pool.map(chunks, move |(cell, sequence, copies)| {
            let draft = draft(cell, (boot_id, sequence, wall_ms), &copies);
            crate::signer::with(&signer, signed_at, |signing| {
                // The clock stopped judging while the epoch sealed: its copies are unsigned.
                let Some(identity) = signing else {
                    return Err(Lost::Unsigned(copies.len() as u64));
                };
                match RegionalBatch::sign_draft(identity, &draft) {
                    Ok(regional) => {
                        let fixes = regional_fixes(&regional).ok();
                        // Never larger than the regional batch, so it fits where that did.
                        let client = ClientRegionalBatch::sign_draft(identity, &draft).ok();
                        Ok(((regional, client), fixes))
                    }
                    // `cut` made it fit, so this is never reached; were it, it is counted.
                    Err(_) => Err(Lost::Oversized(copies.len() as u64)),
                }
            })
        });
        for outcome in signed {
            match outcome {
                Ok(((regional, client), fixes)) => {
                    self.report.regional_signed += 1;
                    self.regional_seen.insert(regional.hash(), ());
                    for fix in fixes.into_iter().flatten() {
                        self.remember(&fix);
                        self.offer_fix(fix, signed_at);
                    }
                    sealed.push((regional, client));
                }
                Err(Lost::Oversized(lost)) => self.report.regional_oversized += lost,
                Err(Lost::Unsigned(lost)) => self.report.regional_unsigned += lost,
            }
        }
        (streamed, sealed)
    }

    fn clock_model(&mut self, model: &ClockModel, id: Hash, stamp: Stamp) {
        let Ok(manifest) = model.manifest() else {
            return;
        };
        self.models.insert(id, manifest.inputs);
        if let Some(mut waiting) = self.waiting.remove(&id) {
            self.waiting_lists -= waiting.bytes();
            self.settle_waiting();
            for (arrived, positions, held) in waiting.take() {
                if stamp.mono().since(arrived.mono()) <= policy::<_, WAITING_MS>() {
                    self.take_positions(positions, arrived, held);
                } else {
                    // Its model came too late: as if it expired waiting (`expire_waiting`).
                    self.report.positions_waiting_expired += 1;
                }
            }
        }
    }

    fn take_world(&mut self, content: WorldPositionsContent, stamp: Stamp) {
        if !self.world.on {
            return;
        }
        for fix in content.fixes {
            if fix.transmitted.unix_ms / 1_000 != content.second {
                continue;
            }
            let derived = self.derived.get(&(fix.origin, fix.origin_index)).copied();
            match derived {
                Some(digest) if digest != self.digest(&fix) => self.report.world_refuted += 1,
                _ => self.offer_fix(fix, stamp),
            }
        }
    }

    fn regional_from(
        &mut self,
        (source, who): (u64, Deliverer),
        regional: RegionalBatch,
        stamp: Stamp,
        held: Held,
    ) {
        let Ok(content) = regional.content() else {
            return;
        };
        if self.regional_seen.get(&regional.hash()).is_some() {
            return;
        }
        self.regional_seen.insert(regional.hash(), ());
        self.take_regional(&regional, stamp);
        let taken = self.taken.iter().any(|area| area.contains(content.cell));
        // Forwarded in the charge it waited in: the part of the peer that handed it in.
        if taken && let Ok(mut outbox) = self.shared.outbox.lock() {
            if outbox.forward.is_empty() && outbox.forward_slots.bytes() == 0 {
                outbox.forward_slots = self.shared.records_store().empty();
            }
            let growth = outbox.forward.growth();
            if outbox.forward.len() < FORWARD_HELD && outbox.forward_slots.try_grow(growth) {
                outbox.forward.push_back((source, who, regional, held));
            } else {
                self.report.regional_forward_full += 1;
            }
        }
    }

    /// A regional batch's ADS-B fixes, as candidates and as what a peer's citing fix must equal.
    fn take_regional(&mut self, regional: &RegionalBatch, stamp: Stamp) {
        let Ok(fixes) = regional_fixes(regional) else {
            return;
        };
        for fix in fixes {
            self.remember(&fix);
            self.offer_fix(fix, stamp);
        }
    }

    fn take_positions(&mut self, positions: Positions, stamp: Stamp, held: Held) {
        let models = &self.models;
        match positions_fixes(&positions, |id| models.get(id).copied()) {
            Ok(Derived::Fixes(fixes)) => {
                for fix in fixes {
                    self.remember(&fix);
                    self.offer_fix(fix, stamp);
                }
            }
            // It waits in the charge it came in, in the parts of whoever handed it in, with its
            // place in the list beside it.
            Ok(Derived::NeedsModel(id)) => {
                // Its place in the list, and the list's in the tree, charged to the store first.
                let growth = self.waiting.get(&id).map_or_else(
                    || self.waiting.growth() + Waiting::new().growth(),
                    Waiting::growth,
                );
                if self.waiting.is_empty() && self.waiting_charge.bytes() == 0 {
                    self.waiting_charge = self.shared.records_store().empty();
                }
                if self.waiting_charge.try_grow(growth) {
                    let list = self.waiting.entry(id).or_default();
                    let before = list.bytes();
                    list.push_back((stamp, positions, held));
                    self.waiting_lists = self.waiting_lists - before + list.bytes();
                    self.settle_waiting();
                } else {
                    self.report.positions_waiting_full += 1;
                }
            }
            Err(_) => self.report.positions_underivable += 1,
        }
    }

    fn expire_waiting(&mut self, now: Mono) {
        let mut expired = 0;
        let mut lists = 0;
        self.waiting.retain(|_, records| {
            let before = records.len();
            records.retain(|(arrived, _, _)| {
                now.since(arrived.mono()) <= policy::<Mono, WAITING_MS>()
            });
            expired += (before - records.len()) as u64;
            lists += records.bytes();
            !records.is_empty()
        });
        self.waiting_lists = lists;
        self.settle_waiting();
        self.report.positions_waiting_expired += expired;
    }

    /// What the positions waiting for models allocate beside their own bytes: the tree and the
    /// lists' slots.
    fn waiting_bytes(&self) -> usize {
        self.waiting.bytes() + self.waiting_lists
    }

    /// The waiting's charge brought down to what it allocates.
    fn settle_waiting(&mut self) {
        let bytes = self.waiting_bytes();
        self.waiting_charge.shrink_to(bytes);
    }

    fn digest(&self, fix: &WorldFix) -> u64 {
        let mut hasher = self.digest_key.build_hasher();
        hasher.write_u32(fix.address);
        hasher.write_u64(fix.transmitted.unix_ms);
        hasher.write_u32(fix.transmitted.sub_ms_ps);
        hasher.write_i32(fix.lat_e7);
        hasher.write_i32(fix.lon_e7);
        hasher.write_i32(fix.alt_hae_mm.unwrap_or(i32::MIN));
        hasher.write_u8(u8::from(fix.alt_hae_mm.is_some()));
        hasher.write_i32(fix.pressure_altitude_ft.unwrap_or(i32::MIN));
        hasher.write_u8(u8::from(fix.pressure_altitude_ft.is_some()));
        for term in fix.covariance.terms() {
            hasher.write_u32(term.to_bits());
        }
        hasher.write_u8(u8::from(fix.mlat));
        hasher.write(&fix.input_set);
        hasher.finish()
    }

    fn remember(&mut self, fix: &WorldFix) {
        let digest = self.digest(fix);
        self.derived.insert((fix.origin, fix.origin_index), digest);
    }

    /// One candidate for the world, stamped `stamp`: held when its second is open and it ranks
    /// above the aircraft's best so far. Its window is reckoned from its stamp's judging reading
    /// alone, the clock its signed second is compared with, and whether its second is sealed from
    /// the watermarks before its stamp: a record is taken in as the watermark passes its stamp,
    /// before anything is sealed at that watermark, so the seconds already sealed are those the
    /// watermarks before its stamp settled, never those of when it was handled. One stamped while
    /// the clock did not judge is judged by nothing, and not held.
    fn offer_fix(&mut self, fix: WorldFix, stamp: Stamp) {
        if !stamp.judging() {
            self.report.world_unjudged += 1;
            return;
        }
        let now = stamp.judged();
        let gatherer = &mut self.world;
        if !gatherer.on {
            return;
        }
        let second = fix.transmitted.unix_ms / 1_000;
        let now_second = now.ms() / 1_000;
        let floor = gatherer
            .sealed_through
            .unwrap_or_else(|| now_second.saturating_sub(WORLD_BEHIND_SECONDS));
        if second <= floor && gatherer.sealed_through.is_some() {
            self.report.world_late += 1;
            return;
        }
        // No further ahead than any copy of the batches it was solved from may be used
        // (`tally_wire::budget::PEER_AHEAD`): its transmit time is those receptions' signed time.
        if second < floor || tally_wire::budget::PEER_AHEAD.ahead(second * 1_000, now) {
            self.report.world_out_of_window += 1;
            return;
        }
        if let Some(held) = gatherer
            .fixes
            .get_mut(&second)
            .and_then(|aircraft| aircraft.get_mut(&fix.address))
        {
            if fix.ranks_above(held) {
                *held = fix;
            }
            return;
        }
        // A new fix, and perhaps a new second: charged to the world's store before it is held
        // (`Store::World`), and skipped, counted, past its cap or its store.
        let open = gatherer.fixes.get(&second).map(BTreeMap::len);
        let full = gatherer.held >= gatherer.cap || open.unwrap_or(0) >= MAX_WORLD_AIRCRAFT;
        if !full && gatherer.charge.bytes() == 0 {
            gatherer.charge = self.shared.world_gauge().empty();
        }
        let more = WORLD_FIX_BYTES
            + if open.is_none() {
                WORLD_SECOND_BYTES
            } else {
                0
            }
            + if gatherer.charge.bytes() == 0 {
                WORLD_SECONDS_ROOT_BYTES
            } else {
                0
            };
        if full || !gatherer.charge.try_grow(more) {
            self.report.world_skipped += 1;
            return;
        }
        if open.is_none() {
            gatherer.seconds += 1;
        }
        gatherer
            .fixes
            .entry(second)
            .or_default()
            .insert(fix.address, fix);
        gatherer.held += 1;
    }

    /// Every second of the world whose seal has come by the judging clock `now` (at a watermark),
    /// each with its fixes ascending by address; later candidates for them are late.
    fn seal(&mut self, now: Judged) -> Vec<(u64, Vec<WorldFix>)> {
        let gatherer = &mut self.world;
        // Second `s` is due once `(s + 1) * 1000 + settle` has passed.
        let Some(due) = (now.earlier(gatherer.settle).ms() / 1_000).checked_sub(1) else {
            return Vec::new();
        };
        // Sealed through the furthest it has reached: a judging clock stepped back never opens a
        // second sealed before.
        let through = gatherer
            .sealed_through
            .map_or(due, |through| through.max(due));
        if !gatherer.on {
            gatherer.fixes.clear();
            gatherer.held = 0;
            gatherer.seconds = 0;
            gatherer.charge.shrink_to(0);
            gatherer.sealed_through = Some(through);
            return Vec::new();
        }
        let open = gatherer.fixes.split_off(&(due + 1));
        let sealed = std::mem::replace(&mut gatherer.fixes, open);
        gatherer.sealed_through = Some(through);
        let sealed: Vec<(u64, Vec<WorldFix>)> = sealed
            .into_iter()
            .map(|(second, aircraft)| {
                gatherer.held -= aircraft.len();
                gatherer.seconds -= 1;
                (second, aircraft.into_values().collect())
            })
            .collect();
        // What it holds now, its seconds' root kept (an emptied tree keeps it).
        let rooted = gatherer.charge.bytes() > 0;
        gatherer.charge.shrink_to(gatherer.bytes(rooted));
        sealed
    }
}

/// A job of the sealer's first pass over an epoch: the deduplicated stream's chain with the
/// epoch's first copies, or one area's copies.
enum Work {
    Stream(Stream, Vec<Kept>),
    Area((Region, Vec<Kept>)),
}

/// Why an area's record was not signed: too large for any record, or its signer's clock stopped
/// judging while it sealed.
enum Lost {
    Oversized(u64),
    Unsigned(u64),
}

/// What a [`Work`] made: the chain where it now stands with the batches it signed, or an area cut.
enum Done {
    Stream(Stream, Signed),
    Area(Cut),
}

/// One area's receptions as the records they will be: its cell, its observations cut into lists
/// each of which makes a record that fits, in order, and the copies too large for any record.
struct Cut {
    cell: Region,
    chunks: Vec<Vec<Kept>>,
    oversized: u64,
}

/// The draft of one record of `cell`'s copies: each read where its batch holds it, never copied
/// (`RegionalBatch::sign_draft` writes the bytes its owned copies would).
fn draft(
    cell: Region,
    (boot_id, sequence, wall_ms): (u64, u64, u64),
    copies: &[Kept],
) -> RegionalDraft<'_> {
    RegionalDraft {
        cell,
        boot_id,
        sequence,
        wall_ms,
        observations: copies
            .iter()
            .map(|copy| copy.decoded.view(copy.obs()))
            .collect(),
    }
}

/// Cuts one area's copies (`(cell, copies)`) into records that fit: at most
/// `MAX_REGIONAL_OBSERVATIONS` each, halved until it fits (`RegionalBatch::fits_draft`, decided
/// without signing, and the same whatever the record's sequence, a fixed-width field). A copy too
/// large for any record is not deliverable, and is counted. The copies are moved into their
/// chunks, never their receptions copied.
fn cut((cell, mut copies): (Region, Vec<Kept>), boot_id: u64, wall_ms: u64) -> Cut {
    let mut todo: Vec<Vec<Kept>> = Vec::new();
    while copies.len() > MAX_REGIONAL_OBSERVATIONS {
        let rest = copies.split_off(MAX_REGIONAL_OBSERVATIONS);
        todo.push(std::mem::replace(&mut copies, rest));
    }
    todo.push(copies);
    todo.reverse();
    let mut out = Cut {
        cell,
        chunks: Vec::new(),
        oversized: 0,
    };
    while let Some(mut chunk) = todo.pop() {
        if chunk.is_empty() {
            continue;
        }
        if RegionalBatch::fits_draft(&draft(cell, (boot_id, 0, wall_ms), &chunk)) {
            out.chunks.push(chunk);
        } else if chunk.len() <= 1 {
            out.oversized += chunk.len() as u64;
        } else {
            let second = chunk.split_off(chunk.len() / 2);
            todo.push(second);
            todo.push(chunk);
        }
    }
    out
}

/// A job for the sealer's pool.
type Job = Box<dyn FnOnce() + Send>;

/// The sealer's pool (RFC-0181 §4): threads of its own, started with the sealer and stopped with
/// it, that work beside the sealer's thread. Started whole or not at all (`start`), so a thread
/// that cannot be started fails the relay at its start; none for a sealer that runs inline.
#[derive(Default)]
struct Pool {
    jobs: Option<Sender<Job>>,
    handles: Vec<JoinHandle<()>>,
}

impl Pool {
    /// `helpers` threads beside the caller's, each held up by `pause` before each job.
    fn start(helpers: usize, pause: Option<&Pause>) -> Result<Self, String> {
        if helpers == 0 {
            return Ok(Self::default());
        }
        let (jobs, taken) = channel::<Job>();
        let taken = Arc::new(Mutex::new(taken));
        // Dropping `pool` on a failure stops and joins the threads already started.
        let mut pool = Self {
            jobs: Some(jobs),
            handles: Vec::with_capacity(helpers),
        };
        for helper in 0..helpers {
            let taken = Arc::clone(&taken);
            let pause = pause.cloned();
            let handle = std::thread::Builder::new()
                .name(format!("tally-seal-{helper}"))
                .spawn(move || {
                    loop {
                        let job = taken.lock().ok().and_then(|taken| taken.recv().ok());
                        let Some(job) = job else {
                            break;
                        };
                        if let Some(pause) = &pause {
                            pause(Stage::Sealer);
                        }
                        job();
                    }
                })
                .map_err(|error| format!("sealer pool thread {helper} of {helpers}: {error}"))?;
            pool.handles.push(handle);
        }
        Ok(pool)
    }

    /// `work` over `items` on the pool's threads and the caller's, the results in the items'
    /// order. A pool thread that panicked takes the sealer with it, never a part of an epoch
    /// silently.
    fn map<T, R>(&self, items: Vec<T>, work: impl Fn(T) -> R + Send + Sync + 'static) -> Vec<R>
    where
        T: Send + 'static,
        R: Send + 'static,
    {
        let helpers = self.handles.len().min(items.len().saturating_sub(1));
        let Some(jobs) = self.jobs.as_ref().filter(|_| helpers > 0) else {
            return items.into_iter().map(work).collect();
        };
        let count = items.len();
        let queue: Arc<Mutex<VecDeque<(usize, T)>>> =
            Arc::new(Mutex::new(items.into_iter().enumerate().collect()));
        let work: Arc<dyn Fn(T) -> R + Send + Sync> = Arc::new(work);
        let (done, results) = channel::<(usize, R)>();
        let drain = |queue: &Mutex<VecDeque<(usize, T)>>,
                     work: &(dyn Fn(T) -> R + Send + Sync),
                     done: &Sender<(usize, R)>| {
            loop {
                let next = queue.lock().ok().and_then(|mut queue| queue.pop_front());
                let Some((at, item)) = next else {
                    break;
                };
                if done.send((at, work(item))).is_err() {
                    break;
                }
            }
        };
        for _ in 0..helpers {
            let (queue, work, done) = (Arc::clone(&queue), Arc::clone(&work), done.clone());
            // A job never run (the pool stopping) is dropped, and with it its sender: the caller
            // does its items itself.
            let _ = jobs.send(Box::new(move || drain(&queue, &*work, &done)));
        }
        drain(&queue, &*work, &done);
        drop(done);
        let mut out: Vec<Option<R>> = (0..count).map(|_| None).collect();
        for (at, result) in results {
            if let Some(slot) = out.get_mut(at) {
                *slot = Some(result);
            }
        }
        out.into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    panic!("a sealer pool thread panicked: the epoch is never sealed in part")
                })
            })
            .collect()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // Closing the jobs ends every thread once it is idle.
        self.jobs = None;
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// One second's fixes, ascending by address, as signed parts of at most `MAX_WORLD_FIXES`.
pub fn world_parts(
    identity: &impl Signs,
    second: u64,
    fixes: Vec<WorldFix>,
) -> Vec<WorldPositions> {
    fixes
        .chunks(MAX_WORLD_FIXES)
        .enumerate()
        .filter_map(|(part, chunk)| {
            WorldPositions::sign(
                identity,
                &WorldPositionsContent {
                    second,
                    part: u16::try_from(part).ok()?,
                    fixes: chunk.to_vec(),
                },
            )
            .ok()
        })
        .collect()
}

/// What a `Positions` record yields for the world product.
#[derive(Clone, Debug, PartialEq)]
pub enum Derived {
    /// One world fix per MLAT fix, in the record's order.
    Fixes(Vec<WorldFix>),
    /// A fix was solved under a model whose inputs are not known yet: this one.
    NeedsModel(Hash),
}

/// The world fixes of a `Positions` record (format 7): each fix as published, its input set the
/// merge rule's over the receptions it considered and what the models it was solved under are a
/// function of together (`publish::cited_inputs` over each one's inputs hash, `inputs_of`, by pair
/// model id, in the order the fix lists them).
pub fn positions_fixes(
    positions: &Positions,
    inputs_of: impl Fn(&Hash) -> Option<Hash>,
) -> Result<Derived, WireError> {
    let content = positions.fixes()?;
    let origin = positions.hash();
    let source = positions.engine()?;
    let mut fixes = Vec::with_capacity(content.fixes.len());
    for (index, fix) in content.fixes.iter().enumerate() {
        let mut cited = Vec::with_capacity(fix.models.len());
        for id in &fix.models {
            let Some(inputs) = inputs_of(id) else {
                return Ok(Derived::NeedsModel(*id));
            };
            cited.push(inputs);
        }
        let inputs = tally_mlat_solver::publish::cited_inputs(cited);
        fixes.push(WorldFix {
            address: fix.address,
            transmitted: fix.transmitted,
            lat_e7: fix.lat_e7,
            lon_e7: fix.lon_e7,
            alt_hae_mm: fix.alt_hae_mm,
            pressure_altitude_ft: pressure_ft(fix.considered().message()),
            covariance: fix.covariance,
            mlat: true,
            input_set: input_set(fix.considered(), &inputs),
            considered: u16::try_from(fix.considered().receptions().len()).unwrap_or(u16::MAX),
            source,
            origin,
            origin_index: u16::try_from(index).map_err(|_| WireError::Oversize(index))?,
        });
    }
    Ok(Derived::Fixes(fixes))
}

/// The ADS-B world fixes of a regional batch: per aircraft, its newest airborne position in the
/// record (by index) that decodes globally with the latest airborne position of the other parity
/// before it in the record. Ascending by address.
pub fn regional_fixes(regional: &RegionalBatch) -> Result<Vec<WorldFix>, WireError> {
    let content = regional.content()?;
    let origin = regional.hash();
    let source = regional.signer()?;
    let transmitted = TransmitTime::new(content.wall_ms, 0)?;
    // Each aircraft's latest even and odd airborne position so far, by index.
    let mut latest: HashMap<u32, [Option<usize>; 2]> = HashMap::new();
    let mut fixes: BTreeMap<u32, WorldFix> = BTreeMap::new();
    for (index, observation) in content.observations.iter().enumerate() {
        if observation.format != format::MODE_S_LONG {
            continue;
        }
        let (Some(position), Some(address)) = (
            modes::airborne_position(&observation.data),
            modes::address(&observation.data),
        ) else {
            continue;
        };
        let parity = usize::from(position.odd);
        let slots = latest.entry(address).or_default();
        let pair = slots[1 - parity];
        slots[parity] = Some(index);
        let Some(pair) = pair.and_then(|at| content.observations.get(at)) else {
            continue;
        };
        let Some(paired) = modes::airborne_position(&pair.data) else {
            continue;
        };
        let Ok(origin_index) = u16::try_from(index) else {
            break;
        };
        let decoded =
            adsb_fix(&position, &paired).map(|(lat_e7, lon_e7, alt_hae_mm, covariance)| WorldFix {
                address,
                transmitted,
                lat_e7,
                lon_e7,
                alt_hae_mm,
                pressure_altitude_ft: pressure_ft(&observation.data),
                covariance,
                mlat: false,
                input_set: adsb_input_set(&observation.data, &pair.data),
                considered: 2,
                source,
                origin,
                origin_index,
            });
        if let Some(fix) = decoded {
            fixes.insert(address, fix);
        }
    }
    Ok(fixes.into_values().collect())
}

/// The pressure altitude a message carries, feet (an AC13 reply's, or an airborne position's
/// barometric altitude); none for a GNSS height or no altitude.
fn pressure_ft(message: &[u8]) -> Option<i32> {
    modes::altitude(message)
        .filter(|altitude| altitude.kind == AltitudeKind::Barometric)
        .map(|altitude| altitude.feet)
}

/// Two sigma, as a 95% radius is taken here.
const SIGMAS_IN_CONTAINMENT: f64 = 2.0;
/// A GNSS height's sigma over its horizontal one.
const VERTICAL_OVER_HORIZONTAL: f64 = 1.5;
/// Millimetres in a foot.
const MM_PER_FOOT: f64 = 304.8;

/// A position decoded with its pair: degrees times 10^7, the GNSS height in millimetres when the
/// message carries one, and the covariance its type code's containment radius states. `None`
/// when the pair does not decode or the type code states no containment.
fn adsb_fix(
    position: &modes::AirbornePosition,
    paired: &modes::AirbornePosition,
) -> Option<(i32, i32, Option<i32>, EnuCovariance)> {
    let (even, odd) = if position.odd {
        (paired, position)
    } else {
        (position, paired)
    };
    let decoded = modes::cpr_global(
        (even.lat_cpr, even.lon_cpr),
        (odd.lat_cpr, odd.lon_cpr),
        position.odd,
    )?;
    let containment = modes::containment_m(position.type_code)?;
    let lat_e7 = degrees_e7(decoded.lat_deg, 90.0)?;
    let lon_e7 = degrees_e7(decoded.lon_deg, 180.0)?;
    let alt_hae_mm = match position.altitude {
        Some(altitude) if altitude.kind == AltitudeKind::Gnss => {
            let mm = (f64::from(altitude.feet) * MM_PER_FOOT).round();
            (mm.abs() < f64::from(i32::MAX)).then_some(mm as i32)
        }
        _ => None,
    };
    let sigma = containment / SIGMAS_IN_CONTAINMENT;
    let horizontal = (sigma * sigma) as f32;
    let vertical = if alt_hae_mm.is_some() {
        let up = sigma * VERTICAL_OVER_HORIZONTAL;
        (up * up) as f32
    } else {
        0.0
    };
    Some((
        lat_e7,
        lon_e7,
        alt_hae_mm,
        EnuCovariance {
            xx: horizontal,
            xy: 0.0,
            xz: 0.0,
            yy: horizontal,
            yz: 0.0,
            zz: vertical,
        },
    ))
}

fn degrees_e7(degrees: f64, limit: f64) -> Option<i32> {
    (degrees.is_finite() && degrees.abs() <= limit).then(|| (degrees * 1e7).round() as i32)
}

/// Checks a world fix against the record it cites, as any reader can: the record's hash is the
/// fix's origin, its signature verifies, and the fix is exactly what the record yields at the
/// cited index ([`regional_fixes`], or [`positions_fixes`] with the cited model's inputs from
/// `inputs_of`).
pub fn check_fix(
    fix: &WorldFix,
    origin: &Record,
    inputs_of: impl Fn(&Hash) -> Option<Hash>,
) -> Result<(), WireError> {
    let refuted = |value| WireError::Invalid {
        field: "world fix",
        value,
    };
    let derived = match origin {
        Record::RegionalBatch(regional) => {
            if regional.hash() != fix.origin {
                return Err(refuted(0));
            }
            regional.verify()?;
            regional_fixes(regional)?
                .into_iter()
                .find(|derived| derived.origin_index == fix.origin_index)
        }
        Record::Positions(positions) => {
            if positions.hash() != fix.origin {
                return Err(refuted(0));
            }
            positions.verify()?;
            match positions_fixes(positions, inputs_of)? {
                Derived::Fixes(fixes) => fixes.get(usize::from(fix.origin_index)).copied(),
                Derived::NeedsModel(_) => return Err(refuted(1)),
            }
        }
        _ => return Err(refuted(2)),
    };
    if derived.as_ref() == Some(fix) {
        Ok(())
    } else {
        Err(refuted(3))
    }
}

#[cfg(test)]
#[path = "products_tests.rs"]
mod tests;
