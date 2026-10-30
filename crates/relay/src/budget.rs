//! Capacity is admission, never a silent drop inside a store (RFC-0181 §9). Every store and
//! every queue that holds something per feeder ([`Store`]) states what one feeder costs it
//! ([`PerFeeder::planned`]); a feeder's bytes in every store are reserved together when it is
//! admitted ([`Budget::reserve`]), beside the upload cap's headroom check (RFC-0171, `admission`),
//! and released when it leaves ([`Reservation`] dropped). A sharing member is a session over which
//! another relay's data comes in (a relay whose offer this one verified dialling it, or this relay's
//! own one-hop raw link): the members together are planned once, as the feeders their one shared
//! rate is worth, and each member session holds one of the places planned at start for every
//! member session the protocol lets this relay's areas bring, at most its connections
//! ([`members_for`], [`Plan::with_members`], [`Budget::reserve_member`]): feeders can never take
//! the room members were planned, and a member is never refused because feeders came first. Past
//! the sessions planned a member is turned away as full (`Reason::Full`), and the relay it was
//! routes around this one (RFC-0174 §2.5). The feeder ceiling is
//! what the relay's budget holds of a feeder's cost after its own base ([`Plan::base`]:
//! [`BASE_BYTES`], and [`MLAT_BASE_BYTES`] more when it hosts MLAT) and the members' pool, and no
//! more than its cores carry beside the members' rate ([`Plan::core_feeders`], `cores`), hosted
//! MLAT's steps planned in them beside the stages; its stages' threads, and MLAT's, follow what it
//! admits ([`Budget::threads`], [`Budget::mlat_threads`]). The
//! budget is `--memory`, by default the memory the relay runs in ([`memory_available`]: the lesser
//! of its cgroup's `memory.high` and `memory.max`, else the host's) less its headroom for what no
//! store charges ([`headroom_for`]: [`HEADROOM_BYTES`] and the allocator's share of the plan). A Hello beyond the ceiling is refused ("no spare slot"), and a relay whose
//! budget cannot hold its members' pool and one feeder refuses to start ([`Budget::check`]). The
//! MLAT engine's receiver limit comes from the same ceiling.
//!
//! The reservation is a plan; each store's [`Gauge`] is what holds the plan. Every store and queue
//! that holds bytes beyond one batch at a time charges its gauge ([`Gauge::try_charge`],
//! [`Gauge::charge`]) for what it holds and is released when it lets go ([`Charge`] dropped). A
//! gauge's limit is that store's share at the ceiling (`per feeder x ceiling`), so the stores
//! together never hold more than the relay's memory, whatever arrives and however slow a stage is.
//! A charge is taken before the bytes are held, never after: there is no way to charge a gauge
//! past its limit, so a store whose stage falls behind cannot grow past its share by holding what
//! it already took. What a full gauge does is the store's policy (RFC-0181 §10): raw pushes back (a
//! connection's batch waits for room, its socket unread), derived products refuse whole (an epoch,
//! counted), the fan-out lets its laggard go, and hosted MLAT sheds whole steps it is behind on
//! (`mlat_host`). The gauges are served on `--stats-listen` (`GET /memory`).
//!
//! Each allocation is charged once, by its owner, for its life (RFC-0181, "Memory is charged once,
//! for its life"): a batch's decode and its signed bytes carry their charges inside their own
//! shared allocations ([`Store::Decoded`]), and every other holder charges only what it allocates
//! itself (an epoch's decisions, a queue's slots, a note, an entry). So a store's window is the
//! deadline its holders enforce, the decodes' the longest of theirs ([`decoded_window_ms`]), never
//! a sum, and [`Covered`] holds equality: every decode alive charged exactly once.
//!
//! The per-feeder costs are planning figures at the rate the RFC sizes a feeder to
//! ([`PLANNED_RECEPTIONS_PER_SEC`], and its bytes as charged, [`PLANNED_CHARGED_BYTES_PER_SEC`])
//! times each store's own window, named where the store defines it, so a store that changes its
//! window changes its reservation.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::oneshot;

/// The stores that hold bytes per feeder: every store and queue of the relay whose size grows
/// with what feeders send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Store {
    /// What the sharing groups allocate themselves over the repair horizon (`sharing`): their
    /// parities, the outbox addressed to members, and an entry for each record they hold. Not a
    /// record's signed bytes, which are their batch's own allocation ([`Store::Decoded`]).
    Batches,
    /// MLAT's raw as it arrived (`tally_mlat_solver::arrived::Arrived`, inside the hosted engine),
    /// which the engine fits and solves from and standing verifies against: the receptions kept
    /// after thinning over the hold (`arrived::HELD_MS`), each seat planned at what a holder keeps
    /// of it at most in one pool for the relay (`arrived::Rates::cost`; every receiver is still held to
    /// its own ceiling, so one receiver never takes another's room), the engine's tables of its
    /// receivers and aircraft, and the descriptions waiting for their step (the receptions on their
    /// way in are every feeder's, [`Store::Inbox`]). Charged
    /// after thinning, never at the ceiling a receiver may send before it: before, the sealed raw
    /// (`Held`) was planned at each seat's kept ceiling and the open raw (`Open`) at the 1,800 a
    /// second a receiver may send, which together held three times what the engine keeps.
    Arrived,
    /// MLAT's raw on its way in (`mlat_host::Inbox`): every hosted feeder's wanted receptions over
    /// the inbox's span (`mlat_host::INBOX_MS`), offered before a step's intake decides which of
    /// them take part, so a rate's, never a seat's. Before (2026-10-27) the inboxes were planned
    /// in `Arrived` for each seat while they held what every feeder sent: with 2,000 feeders on
    /// 300 seats they filled the seats' raw, refused batches and left a step's engine no room
    /// (`MlatReport::arrived_over`).
    Inbox,
    /// The hosted engine's working set beside its raw: a step's fits and solutions while it runs
    /// (`mlat_host::STEP_BYTES_PER_SEAT`), and one step's signed records until the relay takes them
    /// (`mlat_host::PUBLISHED_BYTES_PER_SEAT`).
    Engine,
    /// The message exchange's table of fingerprints over its window (`exchange::DEDUP_EPOCHS`).
    Dedup,
    /// What the relay took from its feeders, which decides whether a copy is new (`strikes`,
    /// RFC-0171 §3.6): each record's fingerprint over the window of time it may arrive in
    /// (`strikes::Usable::life_seconds`), in the feeders' ring of every table, and each feeder's
    /// place in the shares. A store of its own (`strikes::Class`), so whatever the feeders hold,
    /// and however their sets grow, never takes the peers' room or the relay's own.
    FeederStrikes,
    /// What the relay took from its peers (members, relays, subscribers' fault proofs), as
    /// [`Store::FeederStrikes`] holds the feeders'.
    PeerStrikes,
    /// What the relay took of its own making (its products, its engine's records, its figures,
    /// what it rebuilt from parity), as [`Store::FeederStrikes`] holds the feeders'.
    OwnStrikes,
    /// Subscriber queues: each item's own allocation and its slot in every queue that takes it
    /// (`fanout::item_charge`), over `fanout::BEHIND_MS`. Not a batch's decode or signed bytes.
    Fanout,
    /// Delivery tags over the audit window, at the most one receiver may hold
    /// (`delivery::PER_RECEIVER_BYTES`).
    Delivery,
    /// The feeder figures' rows (`figures`): each receiver's, charged once for all it may grow to
    /// (`figures::PER_RECEIVER_BYTES`), its share of the tables every row shares included.
    Figures,
    /// Connection buffers: a feeder connection's Noise buffers, reading and writing, for its whole
    /// session (`ingest::BUFFERS_PER_CONNECTION`).
    Buffers,
    /// Records read off connections and waiting for an ingest worker, until they are decoded:
    /// one pool every connection waits for in turn by source (`ingest::Allowance`), in bytes as
    /// charged (`ingest::charge_of`), sized at the rate the workers admit over the time a record
    /// may wait for one (`ingest::INGEST_WAIT_MS`).
    Ingest,
    /// What the epochs allocate themselves between ingest and the sealer: each reception's place
    /// in its epoch's decisions and each batch's in its word (`exchange::DECISION_BYTES_PER_RECEPTION`),
    /// for each epoch open, closing and waiting at the sealer (`seal::EPOCHS_HELD`). Not the
    /// decodes the epochs hold: those are [`Store::Decoded`]'s.
    Epochs,
    /// What the sealer has signed and the hub has not yet taken (the deduplicated stream's
    /// batches and the products): this relay's own outputs, never a peer's record.
    Products,
    /// The records that are not epochs waiting for the sealer (positions, clock models, peers'
    /// world and regional records) and the peers' regional batches waiting to be forwarded
    /// (`products::Records`): a share apart from `Products`, so a flood of them refuses records,
    /// never an epoch (RFC-0181 §4, §10).
    Records,
    /// The ingest rate's table of the sources it tracks (`shed::Shedder`): each source's decayed
    /// use, over the sources a connection can bring (`shed::UNITS_PER_CONNECTION`). Past it the
    /// shedder tracks no more and judges the rest as one (`shed::Unit::Overflow`).
    Shed,
    /// Every connection's pace state (`ingest`): what it holds of its own
    /// (`ingest::OWN_BYTES_PER_CONNECTION`: its record pace, and a feeder's entry in the station
    /// connections, `stations::CONNECTION_BYTES`) and its entries in the pace maps, its receiver's reception bucket
    /// (`ingest::ReceptionCeilings`), its group's burst grant (`ingest::BurstGrants`) and its
    /// group's directory share (`ingest::DirectoryPaces`), each table charged what it allocates
    /// (`ingest::PaceRoom`). The maps take their entries' share alone (`Budget::pace_entries`), so
    /// the own paces planned are always there; past it each map's newcomers share one entry.
    /// Every connection is planned at `ingest::PACE_BYTES_PER_CONNECTION`: a feeder in its floor,
    /// every other the caps allow before any feeder (`Plan::connection_paces`).
    Paces,
    /// Every batch kept at ingest, as two allocations each charged once for its life: its decode
    /// (`tally_wire::Decoded`, the charge inside its shared allocation, `Decoded::from_verified_owned`)
    /// and its signed bytes (`Batch::owned_by`). However many stages hold them, neither is charged
    /// again: each holder charges only what it allocates itself. Its window is the longest any
    /// holder keeps a decode (`decoded_window_ms`), and on a relay with sharing members the time
    /// the signed bytes outlive their decode in the groups (`sharing::Deadlines::horizon_ms`, a
    /// relay's).
    Decoded,
    /// The firehose credit's tables (`credit::Credit`): the evidence it keeps, the descriptions
    /// it resolves references by, what relays' bundles show, the corroborations and the client
    /// sessions it links, each table capped, charged as it allocates. The receivers' copies and
    /// corroborations follow the receiver figure (`Plan::receivers`, `credit::BYTES_PER_RECEIVER`
    /// each); the rest is held at its caps before any feeder (`credit::FIXED_BYTES`).
    Credit,
    /// The cache of freshness anchors verified here (`anchors::Anchors`): its slots, allocated
    /// once whatever it holds, planned before any feeder (`anchors::PLANNED_BYTES`).
    Anchors,
    /// The receivers' station rows (`stations::Stations`, GET /stations): one for each receiver
    /// the receiver figure holds (`Plan::receivers`), charged whole at that figure
    /// (`stations::planned_bytes`), the least recently active forgotten past it (a row lost heals
    /// at its receiver's next batch).
    Stations,
    /// The offer directory (`directory::Directory`): its tables at their caps (the offers held and
    /// every table keyed by them, the hashes acted on, the addresses trusted or shunned), charged
    /// whole, and the evidence bundles held within their room, charged as they are held
    /// (`directory::PLANNED_BYTES`), planned before any feeder.
    Directory,
    /// The receivers' descriptions the hub holds (`hub::Descriptions`): the batch path's table of
    /// each receiver's cells, the directory a joining subscriber is answered from and its two
    /// indexes by cell, the sites waiting for their descriptions, and the descriptions' own
    /// signed bytes; one of each for each receiver the receiver figure holds (`Plan::receivers`,
    /// `hub::DESCRIPTION_BYTES_PER_RECEIVER`), charged whole at that figure, the least recently
    /// active forgotten past it (its feeder's link describes it again at its next batch).
    Descriptions,
    /// The products' table of each receiver's area and chosen relays (`products::Products`), one
    /// for each receiver the receiver figure holds (`products::LOCATED_BYTES_PER_RECEIVER`),
    /// charged whole at that figure, the least recently active forgotten past it (it is read again
    /// from the receiver's next description).
    Located,
    /// Clock model parts waiting for their manifests, and the lists of manifests already forwarded
    /// (`parts::Parts`): what the members' shared rate and the relay's own MLAT may bring while a
    /// part may wait (`parts::HOLD`), charged whole at that room (`Plan::parts_room`), planned
    /// before any feeder.
    Parts,
    /// What the products remember to decide once (`products::Sealing`): the regional batches seen
    /// by hash, the clock models' inputs by id and the fixes derived from origins held, each table
    /// at its cap, charged whole (`products::REMEMBERED_BYTES`), planned before any feeder. They
    /// grow with what the relay is sent, never with what it admits, so they are held at their caps.
    Remembered,
    /// The world products' fixes held for their open seconds (`products::Gatherer`), charged as
    /// they are held (each fix `products::WORLD_FIX_BYTES`, each second open
    /// `products::WORLD_SECOND_BYTES`), at most each product's cap of them
    /// (`products::world_planned_bytes`), planned before any feeder on a relay that gathers the
    /// world (`--world`), and nothing on any other.
    World,
    /// Receiver standing's tables (`standing::Standing`, RFC-0174 §2.12): the solutions handed and
    /// not yet taken in (one step's), and the book's transmissions, settled receptions and
    /// receivers. Each table in a room sized from the MLAT seats (`standing::Caps::of`), held until
    /// a fix is settled at its arrival bound (`tally_wire::budget::FIX_ARRIVED`), charged whole at
    /// the seats admitted (`standing::planned_bytes`); nothing where MLAT is not hosted, since then
    /// standing takes nothing in.
    Standing,
    /// The checks of client positions' sites (`consistency::Consistency`): the site-bearing
    /// records' keys, two for each receiver the receiver figure holds
    /// (`consistency::BYTES_PER_RECEIVER`), the least recently active forgotten past it, charged
    /// whole at that figure (`consistency::planned_bytes`), as the station rows are.
    Consistency,
    /// The raw positions the checks hold for their tagged twins (`consistency::Consistency`): an
    /// engine sends a fix's raw form and then its tagged form back to back on one link, so each
    /// link holds one raw record at most while its twin is on its way (`consistency::Caps::of`):
    /// the relay's own engine's, and each member session's. Planned before any feeder
    /// (`consistency::twins_fixed_bytes`), whatever the seats and the members' rate: before, the
    /// twins were held for the hub's wait (`hub::AWAITING_MS`) at every seat's and every member
    /// feeder's rate, twice for the final and the provisional, a fifth of a seat's plan; and
    /// planned as a seat's and as a member feeder's, so a member's records were charged twice.
    Twins,
    /// The relay's decoded clock models (`models::Models`), which standing and the positions
    /// checks both cite: each charged as it is held, its bytes given back when its last handle
    /// goes, a model past its source's room or the store refused and counted. Models come from no
    /// feeder: from the relay's own engine, planned per seat (`models::BYTES_PER_SEAT`: a seat's
    /// share of its areas' models refitted each refit, by the bytes a model holds a receiver, over
    /// the models' hold), and from the members, per feeder's
    /// worth of their models' pace (`models::BYTES_PER_MEMBER_SEAT`: a seat's models a second,
    /// as another area's engine publishes them, over the hold, decoded), each source in a room of
    /// its own (`models::Rooms::of`); its fixed part is `model-tables` (`models::fixed_bytes`).
    Models,
}

/// What a store's size follows (`Store::driver`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Driver {
    /// One of these per connection, whatever it sends: its floor, reserved when it is admitted.
    Connection,
    /// The window of the relay-wide rate `R_max` (and the members' rate) through the store:
    /// `limit = window x (R_max + members' rate)`.
    Rate,
    /// One per hosted MLAT seat, the seats being their own pool.
    Seat,
    /// Nothing the relay admits: tables held at their caps whatever it carries, planned before
    /// any feeder.
    Fixed,
}

impl Store {
    pub const ALL: [Self; 32] = [
        Self::Batches,
        Self::Arrived,
        Self::Inbox,
        Self::Engine,
        Self::Dedup,
        Self::FeederStrikes,
        Self::PeerStrikes,
        Self::OwnStrikes,
        Self::Fanout,
        Self::Delivery,
        Self::Figures,
        Self::Buffers,
        Self::Ingest,
        Self::Epochs,
        Self::Products,
        Self::Records,
        Self::Shed,
        Self::Paces,
        Self::Decoded,
        Self::Credit,
        Self::Anchors,
        Self::Stations,
        Self::Directory,
        Self::Descriptions,
        Self::Located,
        Self::Parts,
        Self::Remembered,
        Self::World,
        Self::Standing,
        Self::Consistency,
        Self::Twins,
        Self::Models,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// The name the store is served and printed by (`GET /memory`, `tally-relay check`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Batches => "batches",
            Self::Arrived => "arrived",
            Self::Inbox => "inbox",
            Self::Engine => "engine",
            Self::Dedup => "dedup",
            Self::Fanout => "fanout",
            Self::Delivery => "delivery",
            Self::Figures => "figures",
            Self::Buffers => "buffers",
            Self::Ingest => "ingest",
            Self::Epochs => "epochs",
            Self::Products => "products",
            Self::Records => "records",
            Self::Shed => "shed",
            Self::Paces => "paces",
            Self::Decoded => "decoded",
            Self::FeederStrikes => "feeder-strikes",
            Self::PeerStrikes => "peer-strikes",
            Self::OwnStrikes => "own-strikes",
            Self::Credit => "credit",
            Self::Anchors => "anchors",
            Self::Stations => "stations",
            Self::Directory => "directory",
            Self::Descriptions => "descriptions",
            Self::Located => "located",
            Self::Parts => "parts",
            Self::Remembered => "remembered",
            Self::World => "world",
            Self::Standing => "standing",
            Self::Consistency => "consistency",
            Self::Twins => "twins",
            Self::Models => "models",
        }
    }

    /// What drives this store's size: a connection's floor, the relay-wide rate, or a MLAT seat
    /// (RFC-0181 §9, "Admission"). Every store answers, with no default.
    pub const fn driver(self) -> Driver {
        match self {
            Self::Buffers | Self::Delivery | Self::Figures | Self::Shed | Self::Paces => {
                Driver::Connection
            }
            Self::Batches
            | Self::Dedup
            | Self::Fanout
            | Self::Ingest
            | Self::Epochs
            | Self::Products
            | Self::Decoded
            | Self::FeederStrikes
            | Self::PeerStrikes
            | Self::OwnStrikes
            // One entry for each receiver the rate brings (`Plan::receivers`).
            | Self::Credit
            | Self::Stations
            | Self::Descriptions
            | Self::Located
            // Its sites follow the receiver figure (`consistency::Caps::of`).
            | Self::Consistency
            // What every hosted feeder offers MLAT, before a step decides who takes part.
            | Self::Inbox => Driver::Rate,
            // Records are written by the members' sessions and this relay's MLAT, never by a
            // feeder's receptions: the seats, and the members' rate (`Plan::member_unit`).
            Self::Arrived
            | Self::Engine
            | Self::Records
            // Standing is the hosted MLAT's work, its tables sized from the seats.
            | Self::Standing
            // The models are the own engine's, for its seats, and the members' (`models`).
            | Self::Models => Driver::Seat,
            Self::Anchors
            | Self::Directory
            | Self::Parts
            | Self::Remembered
            | Self::World
            // One raw record a link (`consistency`), the links planned before any feeder.
            | Self::Twins => Driver::Fixed,
        }
    }

    /// What a fixed store ([`Driver::Fixed`]) is planned at, whatever the relay carries: its
    /// tables at their caps. Nothing for any other store.
    pub const fn fixed_bytes(self) -> usize {
        match self {
            Self::Anchors => crate::anchors::PLANNED_BYTES,
            Self::Directory => crate::directory::PLANNED_BYTES,
            Self::Remembered => crate::products::REMEMBERED_BYTES,
            _ => 0,
        }
    }

    /// Whether this store is charged for decoded batches (`tally_wire::Decoded`), each its
    /// footprint exactly, once, for its life: what [`Budget::decoded_charged`] reads. Every store
    /// answers here, with no default, so a store added is a decision made, not one forgotten.
    pub const fn holds_decoded(self) -> bool {
        match self {
            Self::Decoded => true,
            // What every other holder of a decode charges is what it allocates itself (an epoch's
            // decisions, a queue's slots, a note, an entry): never the decode it keeps alive.
            Self::Ingest
            | Self::Epochs
            | Self::Fanout
            | Self::Batches
            // Hosted MLAT copies a batch's receptions out of its decode as it is offered
            // (`mlat_host::MlatHost::offer_batch`), so it keeps no decode alive.
            | Self::Arrived
            | Self::Inbox
            | Self::Engine
            | Self::Dedup
            | Self::Delivery
            | Self::Figures
            | Self::Buffers
            | Self::Products
            | Self::Records
            | Self::Shed
            | Self::Paces
            | Self::FeederStrikes
            | Self::PeerStrikes
            | Self::OwnStrikes
            | Self::Credit
            | Self::Anchors
            | Self::Stations
            | Self::Directory
            | Self::Descriptions
            | Self::Located
            | Self::Parts
            | Self::Remembered
            | Self::World
            | Self::Standing
            | Self::Consistency
            | Self::Twins
            | Self::Models => false,
        }
    }
}

impl Store {
    /// The class of deliverer whose takes this store holds (`strikes::Class`), if it is one of
    /// the stores of what is taken.
    pub const fn strike_class(self) -> Option<crate::strikes::Class> {
        match self {
            Self::FeederStrikes => Some(crate::strikes::Class::Feeders),
            Self::PeerStrikes => Some(crate::strikes::Class::Peers),
            Self::OwnStrikes => Some(crate::strikes::Class::Own),
            _ => None,
        }
    }
}

/// What one feeder costs each store, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerFeeder {
    pub batches: usize,
    /// MLAT's raw as it arrived, for each seat (`Store::Arrived`).
    pub arrived: usize,
    /// MLAT's raw on its way in, for a planned feeder's rate (`Store::Inbox`).
    pub inbox: usize,
    pub engine: usize,
    pub dedup: usize,
    pub fanout: usize,
    pub delivery: usize,
    pub figures: usize,
    pub buffers: usize,
    pub ingest: usize,
    pub epochs: usize,
    pub products: usize,
    pub records: usize,
    pub shed: usize,
    pub paces: usize,
    pub feeder_strikes: usize,
    pub peer_strikes: usize,
    pub own_strikes: usize,
    pub decoded: usize,
    /// The credit's receivers' copies and corroborations (`Store::Credit`).
    pub credit: usize,
    /// Always nothing: the anchor cache is planned before any feeder (`Store::Anchors`).
    pub anchors: usize,
    /// The station rows (`Store::Stations`).
    pub stations: usize,
    /// Always nothing: the directory is planned before any feeder (`Store::Directory`).
    pub directory: usize,
    /// The receivers' descriptions (`Store::Descriptions`).
    pub descriptions: usize,
    /// The receivers' areas (`Store::Located`).
    pub located: usize,
    /// Always nothing: the clock model parts are planned before any feeder (`Store::Parts`).
    pub parts: usize,
    /// Always nothing: the products' tables are planned at their caps (`Store::Remembered`).
    pub remembered: usize,
    /// Always nothing: the world's fixes are planned before any feeder (`Store::World`).
    pub world: usize,
    /// Standing's tables for each seat (`Store::Standing`).
    pub standing: usize,
    /// The positions checks' sites for a planned feeder's receivers (`Store::Consistency`).
    pub consistency: usize,
    /// Always nothing: the positions checks' twins are one record a link, planned before any
    /// feeder (`Store::Twins`).
    pub twins: usize,
    /// The decoded clock models for each seat (`Store::Models`).
    pub models: usize,
    /// What the kernel charges a feeder's socket at most, outside any store: its buffers pinned
    /// (`sockets::FEEDER_KERNEL_BYTES`). Part of a connection's floor.
    pub sockets: usize,
}

impl PerFeeder {
    /// Only the stores `driver` sizes: the rest zero.
    pub fn only(&self, driver: Driver) -> Self {
        let mut kept = Self::default();
        for store in Store::ALL {
            if store.driver() == driver {
                kept.set(store, self.of(store));
            }
        }
        if driver == Driver::Connection {
            kept.sockets = self.sockets;
        }
        kept
    }

    /// What a connection costs whatever it sends: its Noise buffers, its kernel socket buffers, its
    /// delivery tags and its pace and shed state.
    pub fn floor(&self) -> Self {
        self.only(Driver::Connection)
    }

    /// What one planned feeder's rate (a planned feeder's receptions a second) costs the
    /// rate-driven stores over their windows.
    pub fn rate(&self) -> Self {
        self.only(Driver::Rate)
    }

    /// What one MLAT seat costs the seat stores.
    pub fn seat(&self) -> Self {
        self.only(Driver::Seat)
    }

    fn set(&mut self, store: Store, bytes: usize) {
        match store {
            Store::Batches => self.batches = bytes,
            Store::Arrived => self.arrived = bytes,
            Store::Inbox => self.inbox = bytes,
            Store::Engine => self.engine = bytes,
            Store::Dedup => self.dedup = bytes,
            Store::Fanout => self.fanout = bytes,
            Store::Delivery => self.delivery = bytes,
            Store::Figures => self.figures = bytes,
            Store::Buffers => self.buffers = bytes,
            Store::Ingest => self.ingest = bytes,
            Store::Epochs => self.epochs = bytes,
            Store::Products => self.products = bytes,
            Store::Records => self.records = bytes,
            Store::Shed => self.shed = bytes,
            Store::Paces => self.paces = bytes,
            Store::FeederStrikes => self.feeder_strikes = bytes,
            Store::PeerStrikes => self.peer_strikes = bytes,
            Store::OwnStrikes => self.own_strikes = bytes,
            Store::Decoded => self.decoded = bytes,
            Store::Credit => self.credit = bytes,
            Store::Anchors => self.anchors = bytes,
            Store::Stations => self.stations = bytes,
            Store::Directory => self.directory = bytes,
            Store::Descriptions => self.descriptions = bytes,
            Store::Located => self.located = bytes,
            Store::Parts => self.parts = bytes,
            Store::Remembered => self.remembered = bytes,
            Store::World => self.world = bytes,
            Store::Standing => self.standing = bytes,
            Store::Consistency => self.consistency = bytes,
            Store::Twins => self.twins = bytes,
            Store::Models => self.models = bytes,
        }
    }

    pub fn of(&self, store: Store) -> usize {
        match store {
            Store::Batches => self.batches,
            Store::Arrived => self.arrived,
            Store::Inbox => self.inbox,
            Store::Engine => self.engine,
            Store::Dedup => self.dedup,
            Store::Fanout => self.fanout,
            Store::Delivery => self.delivery,
            Store::Figures => self.figures,
            Store::Buffers => self.buffers,
            Store::Ingest => self.ingest,
            Store::Epochs => self.epochs,
            Store::Products => self.products,
            Store::Records => self.records,
            Store::Shed => self.shed,
            Store::Paces => self.paces,
            Store::FeederStrikes => self.feeder_strikes,
            Store::PeerStrikes => self.peer_strikes,
            Store::OwnStrikes => self.own_strikes,
            Store::Decoded => self.decoded,
            Store::Credit => self.credit,
            Store::Anchors => self.anchors,
            Store::Stations => self.stations,
            Store::Directory => self.directory,
            Store::Descriptions => self.descriptions,
            Store::Located => self.located,
            Store::Parts => self.parts,
            Store::Remembered => self.remembered,
            Store::World => self.world,
            Store::Standing => self.standing,
            Store::Consistency => self.consistency,
            Store::Twins => self.twins,
            Store::Models => self.models,
        }
    }

    /// What one feeder's worth of the members' shared rate costs each store: a feeder's, but for
    /// the connection's own buffers and sockets, which each member's connection takes from the
    /// connections' room (`Plan::connection_buffers`, `Plan::connection_sockets`,
    /// `Plan::connection_paces`).
    pub fn as_member(&self) -> Self {
        Self {
            buffers: 0,
            paces: 0,
            sockets: 0,
            ..*self
        }
    }

    /// The sum of two costs, store by store.
    pub fn plus(&self, other: &Self) -> Self {
        let mut sum = Self {
            sockets: self.sockets.saturating_add(other.sockets),
            ..Self::default()
        };
        for store in Store::ALL {
            sum.set(store, self.of(store).saturating_add(other.of(store)));
        }
        sum
    }

    /// Every store's cost together: what admitting one feeder reserves.
    pub fn total(&self) -> usize {
        Store::ALL.iter().fold(self.sockets, |sum, store| {
            sum.saturating_add(self.of(*store))
        })
    }

    /// What one feeder at the planned rate costs each store over that store's window, on a relay
    /// with no sharing member and no session listening. `holds_raw`: whether this relay holds
    /// MLAT raw (`Arrived`) at all, which it does only when it hosts MLAT.
    pub fn planned(holds_raw: bool) -> Self {
        Self::planned_for(holds_raw, false, 0, None)
    }

    /// What one feeder at the planned rate costs each store over that store's window
    /// ([`PerFeeder::planned`]), on a relay whose sharing groups hold members' records
    /// (`sharing`: it has sharing members) or not, with `listeners` sessions that may take a batch
    /// from the fan-out (those under the connection cap and the subscribers), on `cores` cores (the
    /// message threads a batch is cut across, `exchange::slicing_threads`; none where they are not
    /// known). A byte-driven store is sized by a planned feeder's charged bytes
    /// (`PLANNED_CHARGED_BYTES_PER_SEC`), the unit `R_max` caps them in, never by an assumed
    /// reception size; a reception-driven one by its receptions; a batch-driven one by the
    /// batches those bytes may be, each charged at least `ingest::CHARGE_FLOOR`.
    pub fn planned_for(
        holds_raw: bool,
        sharing: bool,
        listeners: usize,
        cores: Option<usize>,
    ) -> Self {
        let receptions = PLANNED_RECEPTIONS_PER_SEC;
        let charged = PLANNED_CHARGED_BYTES_PER_SEC;
        // The signed bytes the rate admits with them, at most (`ingest::rate_cost`).
        let signed = charged / crate::ingest::CHARGED_PER_SIGNED;
        let records = crate::cores::RECORDS_PER_PLANNED_FEEDER as usize;
        // The batches those bytes may be at most, each charged at least the floor
        // (`ingest::CHARGE_FLOOR`), and the slices they are cut into across the message threads.
        let batches = charged / crate::ingest::CHARGE_FLOOR;
        let slices =
            crate::exchange::slices_per_sec(batches, crate::exchange::slicing_threads(cores));
        // A relay's horizon: the plan is a relay's. A test hub declaring longer deadlines holds
        // its groups longer than planned, bounded still by the same gauge.
        let horizon_ms = crate::sharing::Deadlines::RELAY.horizon_ms() as usize;
        let decoded_ms = decoded_window_ms() as usize;
        Self {
            // What the sharing groups allocate themselves over the repair horizon, on a relay
            // with sharing members only (`footprint`): a record's entry (its place in its group's
            // tree, its piece and its first sender, `sharing::member::PIECE_ENTRY_BYTES`, the
            // signed bytes being its batch's own allocation, `Store::Decoded`), and its parity,
            // which the groups hold as long. A parity is as long as its manifest's longest stripe
            // slice, at most its records' signed bytes, which the rate holds to its bytes over
            // `ingest::CHARGED_PER_SIGNED` (`ingest::rate_cost`); and its entry
            // (`sharing::member::PARITY_ENTRY_BYTES`) a second. The trees of the group its records
            // go to, at most one more for each feeder (`sharing::member::GROUP_TREES_BYTES`). And
            // the parities addressed to members waiting in the outbox for the next network tick
            // (`network::TICK`), a second's to each child of the stripe trees
            // (`stripes::FANOUT`), a tick of it. (Once handed to a member's link, a send keeps this
            // charge and takes its link's share too, `Plan::member_links`.) Not rounded up: the
            // horizon is in milliseconds.
            batches: if sharing {
                (records * crate::sharing::member::PIECE_ENTRY_BYTES
                    + signed
                    + crate::sharing::member::PARITY_ENTRY_BYTES)
                    * horizon_ms
                    / 1_000
                    + crate::sharing::member::GROUP_TREES_BYTES
                    + crate::sharing::outbox_parity_bytes(signed)
                        * crate::sharing::stripes::FANOUT
                        * crate::network::TICK.as_millis() as usize
                        / 1_000
            } else {
                0
            },
            // MLAT's raw as it arrived (`Arrived`), where MLAT is hosted: a seat's receptions kept
            // after thinning over the hold, at what a holder keeps at most in the relay's one pool
            // (`arrived::Rates::cost`), and its descriptions waiting for their step
            // (`mlat_host::PENDING_BYTES_PER_SEAT`). The engine's tables that hold whatever its
            // seats (its address shards) are held before any feeder (`Plan::mlat_tables`).
            arrived: if holds_raw {
                crate::mlat_host::arrived_bytes_per_seat()
            } else {
                0
            },
            // A planned feeder's wanted receptions on their way into the engine, where MLAT is
            // hosted, whether or not its receiver holds a seat: the step's intake decides that
            // (`mlat_host::INBOX_BYTES_PER_FEEDER`).
            inbox: if holds_raw {
                crate::mlat_host::INBOX_BYTES_PER_FEEDER
            } else {
                0
            },
            // The engine's working set (`Engine`): a seat's share of a step's fits and solutions
            // while it runs (`mlat_host::STEP_BYTES_PER_SEAT`), and of one step's signed records
            // until the relay takes them (`mlat_host::PUBLISHED_BYTES_PER_SEAT`).
            engine: if holds_raw {
                crate::mlat_host::STEP_BYTES_PER_SEAT + crate::mlat_host::PUBLISHED_BYTES_PER_SEAT
            } else {
                0
            },
            // Each message thread's table of fingerprints over `exchange::DEDUP_EPOCHS` epochs, the
            // deduplication's window (`exchange::DEDUP_WINDOW_MS`), as if no reception were a copy
            // of another's, allocated once at its capacity
            // (`exchange::DEDUP_BYTES_PER_RECEPTION_PER_SEC`; what they allocate whatever the rate,
            // `exchange::DEDUP_FIXED_BYTES`, is held before any feeder, `Plan::before_feeders`).
            dedup: receptions * crate::exchange::DEDUP_BYTES_PER_RECEPTION_PER_SEC,
            // A subscriber's queue holds `BEHIND_MS` of inbound: each item's own allocation once
            // (`fanout::item_charge`), and its slot in the queue of every session that may take it,
            // as a queue that keeps a quarter again what it holds allocates it, or its place in
            // that session's hand (`fanout::SLOT_BYTES`); nothing where no session listens (an item
            // no queue takes is not charged). What each session's queue keeps whatever it holds is
            // held before any feeder (`fanout::LISTENER_BYTES`, `Plan::before_feeders`).
            fanout: if listeners == 0 {
                0
            } else {
                records
                    * (crate::fanout::ITEM_BYTES + listeners * crate::fanout::SLOT_BYTES)
                    * crate::fanout::BEHIND_MS as usize
                    / 1_000
            },
            // A delivery tag per batch over the audit window, at the most one receiver may hold,
            // with what its lists, its record and its streams allocate
            // (`delivery::PER_RECEIVER_BYTES`), whatever it sends; the shards' tables as they are
            // kept whatever they hold are held before any feeder (`delivery::FIXED_BYTES`).
            delivery: crate::delivery::PER_RECEIVER_BYTES,
            // A receiver's feeder figures row, whatever it sends (`figures::PER_RECEIVER_BYTES`).
            figures: crate::figures::PER_RECEIVER_BYTES,
            // A feeder's connection: its Noise buffers in both directions, the reader's frame and
            // plaintext and the writer's (`ingest::BUFFERS_PER_CONNECTION`), carved when it is
            // admitted. What the Noise pool keeps idle is the process's (`BASE_BYTES`).
            buffers: crate::ingest::BUFFERS_PER_CONNECTION,
            // The records read and not yet decoded, in one pool every connection waits for in
            // turn (`ingest::Allowance`): what the workers take a second, charged
            // (`ingest::charge_of`, and at least `ingest::CHARGE_FLOOR` a record), over the time a
            // record may wait for a worker (`ingest::INGEST_WAIT_MS`, Little's law).
            ingest: charged.max(records * crate::ingest::CHARGE_FLOOR)
                * crate::ingest::INGEST_WAIT_MS as usize
                / 1_000,
            // What the epochs allocate between ingest and the sealer, over the epochs held: each
            // reception's run and its place in the epoch's decisions
            // (`exchange::EPOCH_BYTES_PER_RECEPTION`), and each slice's place in its epoch's list
            // and its batch's place in the word (`exchange::EPOCH_BYTES_PER_SLICE`), a slice for
            // each message thread a batch is cut across, at the batches' rate. Before, every
            // reception was planned a slice of its own, though a slice holds every reception of
            // its batch on its thread.
            epochs: (receptions * crate::exchange::EPOCH_BYTES_PER_RECEPTION
                + slices * crate::exchange::EPOCH_BYTES_PER_SLICE)
                * crate::seal::EPOCHS_HELD as usize
                * crate::seal::EPOCH_MS as usize
                / 1_000,
            // What the sealer signed of those epochs and the hub has not taken: every reception
            // twice as a signed record's observation, in the deduplicated stream and in its area's
            // regional batch, as if none were a copy (`products::OUTBOX_EPOCHS`). An observation is
            // its bytes inflated, which are at most `INFLATED_PER_CHARGED` of what its batch was
            // charged.
            products: 2 * inflated_of_charged(charged) * crate::products::OUTBOX_EPOCHS,
            // The records waiting for the sealer, and to be forwarded, apart from the outputs:
            // written by MLAT's seats (`seat`) and the members' sessions (`Plan::member_unit`),
            // never by a feeder's receptions.
            records: if holds_raw {
                crate::products::records_per_feeder(receptions)
            } else {
                0
            },
            // The sources the ingest rate tracks (`shed`): the ones a connection brings.
            shed: crate::shed::BYTES_PER_UNIT * crate::shed::UNITS_PER_CONNECTION,
            // What the relay took in (`strikes`): each record's fingerprint for as long as a copy
            // of it may arrive, at the most a table holds an entry at, its set growing
            // (`strikes::PLANNED_ENTRY_BYTES`), whether or not the relay has sharing members (a
            // feeder's batch comes again on its reconnect, a peer's copy by another path). The
            // feeders' store: the feeder's records over the longest one of them lives
            // (`Usable::feeder_life_seconds`), twice, since the feeders together may hold twice
            // their share (`strikes::Shares`), its place in the shares among them
            // (`strikes::feeder_place_bytes`). The relay's own store: its own records for its
            // worth of load over theirs (`own_records_per_feeder`, `Usable::own_life_seconds`)
            // and the feeder figures held for it.
            feeder_strikes: feeder_strikes_bytes(records),
            peer_strikes: 0,
            own_strikes: own_strikes_bytes(
                crate::strikes::own_records_per_feeder(holds_raw) as usize
            ),
            // Every batch kept, its decode and its signed bytes, each charged once for its life,
            // at most what it was charged at ingest: over the longest any holder keeps a decode
            // (`decoded_window_ms`), and where the sharing groups hold its signed bytes, those
            // (the rate's bytes over `ingest::CHARGED_PER_SIGNED`, `ingest::rate_cost`) over the
            // repair horizon, for the time they outlive the decode.
            decoded: charged * decoded_ms / 1_000
                + if sharing {
                    signed * horizon_ms.saturating_sub(decoded_ms) / 1_000
                } else {
                    0
                },
            // Its pace state (`paces`): its own pace and its entries in the pace maps.
            paces: crate::ingest::PACE_BYTES_PER_CONNECTION,
            // The tables of one entry for each receiver the rate brings (`Plan::receivers`): the
            // receivers its records a second may be over the longest an honest receiver goes
            // between batches (`RECEIVERS_PER_PLANNED_FEEDER`), each at what its table plans for
            // an entry.
            credit: crate::credit::BYTES_PER_RECEIVER * RECEIVERS_PER_PLANNED_FEEDER,
            // The anchor cache is planned before any feeder (`Store::Anchors`).
            anchors: 0,
            stations: crate::stations::BYTES_PER_RECEIVER * RECEIVERS_PER_PLANNED_FEEDER,
            // The directory is planned before any feeder (`Store::Directory`).
            directory: 0,
            descriptions: crate::hub::DESCRIPTIONS_BYTES_PER_RECEIVER
                * RECEIVERS_PER_PLANNED_FEEDER,
            located: crate::products::LOCATED_BYTES_PER_RECEIVER * RECEIVERS_PER_PLANNED_FEEDER,
            // The clock model parts are planned before any feeder (`Store::Parts`).
            parts: 0,
            // The products' tables and the world's fixes are planned before any feeder.
            remembered: 0,
            world: 0,
            // Standing's tables for each seat, where MLAT is hosted (`standing::BYTES_PER_SEAT`:
            // what its rooms take for one, `standing::Caps::of`).
            standing: if holds_raw {
                crate::standing::BYTES_PER_SEAT
            } else {
                0
            },
            // The positions checks' sites for the receivers the rate brings, as the station rows
            // are (`consistency::BYTES_PER_RECEIVER`).
            consistency: crate::consistency::BYTES_PER_RECEIVER * RECEIVERS_PER_PLANNED_FEEDER,
            // The twins are one raw record a link, planned before any feeder (`Store::Twins`).
            twins: 0,
            // The clock models its own engine publishes for a seat, held until no fix that may
            // still come or be settled can cite them (`models::BYTES_PER_SEAT`), where MLAT is
            // hosted. A feeder's receptions bring none: the models are what the engines publish.
            models: if holds_raw {
                crate::models::BYTES_PER_SEAT
            } else {
                0
            },
            sockets: crate::sockets::FEEDER_KERNEL_BYTES,
        }
    }
}

/// What `Store::FeederStrikes` holds for a planned feeder's worth of load: the feeders' share for
/// it ([`feeder_share_entries`] of its `records` a second, its place among them), twice (the
/// feeders together may hold twice their share, `strikes::Shares`), each at
/// `strikes::PLANNED_ENTRY_BYTES`.
const fn feeder_strikes_bytes(records: usize) -> usize {
    2 * feeder_share_entries(records as u64) as usize * crate::strikes::PLANNED_ENTRY_BYTES
}

/// What `Store::OwnStrikes` holds for a planned feeder's worth of load: the relay's `own` records
/// for it over theirs (`strikes::Usable::own_life_seconds` of the relay-signed kinds), and the
/// feeder figures held for it (`strikes::FIGURES_HELD_PER_FEEDER`), each at
/// `strikes::PLANNED_ENTRY_BYTES`.
const fn own_strikes_bytes(own: usize) -> usize {
    (own * own_life_seconds() as usize + crate::strikes::FIGURES_HELD_PER_FEEDER as usize)
        * crate::strikes::PLANNED_ENTRY_BYTES
}

/// The feeders' share together for each connection admitted (`strikes::Entries::feeders`), in
/// entries: its `records` a second over the longest a feeder's entry of its batches lives
/// (`strikes::Usable::feeder_life_seconds` of `Usable::BATCHES`), and its place in the shares
/// with its counts, as the shares charge it (`strikes::FEEDER_PLACE_ENTRIES`). The store holds
/// twice it ([`feeder_strikes_bytes`]), as the feeders may hold.
const fn feeder_share_entries(records: u64) -> u64 {
    records * crate::strikes::Usable::BATCHES.feeder_life_seconds()
        + crate::strikes::FEEDER_PLACE_ENTRIES as u64
}

/// A connection's part of the feeders' share is planned in the store twice, the most the
/// feeders may hold together (`strikes::Shares::take`), at the rate the relay-wide rate admits
/// for it (`cores::RECORDS_PER_PLANNED_FEEDER`), its place included.
const _: () = assert!(
    feeder_strikes_bytes(crate::cores::RECORDS_PER_PLANNED_FEEDER as usize)
        >= 2 * (feeder_share_entries(crate::cores::RECORDS_PER_PLANNED_FEEDER) as usize)
            * crate::strikes::PLANNED_ENTRY_BYTES
        && feeder_share_entries(crate::cores::RECORDS_PER_PLANNED_FEEDER) as usize
            * crate::strikes::PLANNED_ENTRY_BYTES
            >= crate::strikes::feeder_place_bytes(crate::strikes::Usable::BATCHES)
);

/// The longest a peer's copy's entry lives, of the kinds a peer delivers at a rate (its batches
/// and the relay-signed kinds; a fault proof is rare, and a flood of them fills the peers' share
/// and no more): a batch's, the longer (`strikes::Usable::life_seconds`).
const fn peer_life_seconds() -> u64 {
    let batches = crate::strikes::Usable::BATCHES.life_seconds();
    let relay =
        crate::strikes::Usable::relay_signed(crate::sharing::Deadlines::RELAY).life_seconds();
    if batches > relay { batches } else { relay }
}

/// The longest the relay's own record's entry lives (`strikes::Usable::own_life_seconds` of the
/// relay-signed kinds).
const fn own_life_seconds() -> u64 {
    crate::strikes::Usable::relay_signed(crate::sharing::Deadlines::RELAY).own_life_seconds()
}

/// What a decode is held for at most, by the holder that keeps it longest, each by a deadline its
/// code enforces: the epochs held between ingest and the sealer (`seal::EPOCHS_HELD`) and a
/// subscriber's queue (`fanout::BEHIND_MS`). A decode alive is younger than this, so the decodes
/// alive are at most the rate over it: the longest, never the sum of the holders' windows, since
/// one decode held by all of them is one decode. Hosted MLAT holds none: it copies a batch's
/// receptions out as it is offered (`mlat_host::MlatHost::offer_batch`). Before, its notes and the
/// batches waiting for a description or a step's descriptions kept decodes alive for seconds,
/// which nearly doubled this window on a relay hosting MLAT.
pub const fn decoded_window_ms() -> u64 {
    let epochs = crate::seal::EPOCHS_HELD * crate::seal::EPOCH_MS;
    if epochs > crate::fanout::BEHIND_MS {
        epochs
    } else {
        crate::fanout::BEHIND_MS
    }
}

/// What a batch charged `charged` bytes holds at most as observations, inflated: a batch is
/// charged a reference for every reception its inflated bytes can hold (`ingest::charge_of`,
/// `Batch::receptions_at_most`), so its inflated bytes are at most the fixed part of an
/// observation over that and a reference.
pub const fn inflated_of_charged(charged: usize) -> usize {
    charged * tally_wire::decoded::OBSERVATION_FIXED
        / (tally_wire::decoded::OBSERVATION_FIXED + std::mem::size_of::<tally_wire::ObsRef>())
}

/// The rate the RFC sizes one feeder to: about 600 receptions and 8 KB of signed batches a second
/// (RFC-0181, "Requirement"), one batch a second, carrying its freshness anchors at the most a
/// batch carries (`tally_wire::batch::ANCHORS_MAX_LEN`, RFC-0171 §3.6) beside them.
pub const PLANNED_RECEPTIONS_PER_SEC: usize = 600;
pub const PLANNED_BYTES_PER_SEC: usize = 8 * 1024 + tally_wire::batch::ANCHORS_MAX_LEN;
/// That feeder's batches as the relay charges them (`ingest::charge_of`: signed, inflated, a
/// reference for each reception they can hold, and the headers of the allocations they make), one
/// batch a second: the unit `R_max`'s bytes are counted in (`Admission::bytes_per_sec`), the
/// shedder judges a batch by, and every byte-driven store is sized from.
pub const PLANNED_CHARGED_BYTES_PER_SEC: usize = crate::ingest::PLANNED_BATCH_CHARGE;

/// `G`, the longest an honest receiver goes between two batches while it publishes, in seconds:
/// its feeder seals one every `SEAL_PERIOD` it has traffic, and its backlog adds at most a burst's
/// second on the way out (`tally_wire::budget::BACKLOG_DRAIN`, 2 s). Every batch is a record, so
/// the receivers that published within `G` are at most the records a second the relay admits
/// (`R_max`'s, `Admission::records_per_sec`, and the members' rate's,
/// `ingest::member_records_per_sec`) times `G`: the receiver figure (`Plan::receivers`), which
/// every table of one entry per receiver holds (the station rows, the descriptions, the receivers'
/// areas, the credit's copies and corroborations). Each is one table for the relay in one order of
/// activity (a share of the figure in each raw shard would not do: receivers land in shards by a
/// keyed hash, so a shard's share is a random draw above an even one on every batch), and forgets
/// the receiver least recently active past it (`Bounded`), a receiver being active when a batch of
/// it is forwarded, so no receiver publishing within `G` is ever forgotten, whatever strangers
/// send. One quiet for longer may be: a feeder's own description is given again by its link at its
/// next batch (`link`), a station row and a receiver's area start again at it, and a receiver
/// known only through a member is described again by the member link that carries its next batch
/// when that link's last batch of it is older than `G` ([`RECEIVER_GAP`], `Hub::to_describe`).
///
/// The descriptions' table is held to `G` too, not to that refresh: a table that kept every
/// receiver heard within ten minutes would hold the records a second over ten minutes, 1,200
/// receivers a planned feeder where it holds four, three hundred times this table, more than the
/// world relay's floor of connections leaves room for (RFC-0181, "Sizing at 20k").
pub const RECEIVER_GAP: tally_wire::budget::Tolerance = tally_wire::budget::BACKLOG_DRAIN;

/// [`RECEIVER_GAP`] in seconds: what the receiver figure multiplies the records a second by.
pub const RECEIVER_GAP_SECONDS: usize = RECEIVER_GAP.duration().as_secs() as usize;

/// The receivers a planned feeder's worth of `R_max` brings within [`RECEIVER_GAP_SECONDS`]: its
/// records a second (`cores::RECORDS_PER_PLANNED_FEEDER`) over that gap.
pub const RECEIVERS_PER_PLANNED_FEEDER: usize =
    crate::cores::RECORDS_PER_PLANNED_FEEDER as usize * RECEIVER_GAP_SECONDS;

/// The receivers one feeder's worth of the members' rate brings within [`RECEIVER_GAP_SECONDS`]:
/// its records a second (`ingest::MEMBER_RECORDS_PER_FEEDER`) over that gap.
pub const RECEIVERS_PER_MEMBER_FEEDER: usize =
    crate::ingest::MEMBER_RECORDS_PER_FEEDER as usize * RECEIVER_GAP_SECONDS;

/// The most receivers the receiver figure names ([`Plan::receivers`]), some two hundred times the
/// world's fleet: only a budget no memory backs (a test's) admits a rate past it, and every
/// table's planned bytes stay a number at it.
pub const RECEIVERS_MOST: usize = 1 << 24;
/// What the relay was resident with no feeder, measured (RFC-0181, "Sizing", "The relay's own
/// base"), the larger of two runs, rounded up: 12 to 13 MiB at the public relay's shape (2026-10-23,
/// `tally-load` built `-c opt`, the relay on one core hosting MLAT with the 122 resolution-0 areas
/// and its caps, 13 threads, `//crates/load:public_relay`'s configuration; 17 MiB there with its
/// judging clock bounded, the same day) and 17.3 MiB on ten cores (2026-10-08). Every table that grows with what the relay is sent is a store of its own,
/// charged before it holds a byte (`Store`); this is what is left: the runtime, the binary's heap
/// and the stages' empty state. Measured on x86-64 with 4 KiB pages only: a Raspberry Pi's kernel
/// of 16 KiB pages rounds every mapping up to four times as much, and has not been measured.
pub const MEASURED_IDLE_BYTES: usize = 18 << 20;
/// The margin above [`MEASURED_IDLE_BYTES`]: as much again, for what an idle run does not touch
/// (each thread's first allocations, the runtime's timers and caches once connections come).
pub const BASE_MARGIN_BYTES: usize = MEASURED_IDLE_BYTES;
/// What the relay holds whatever its feeders, beside what grows with its threads
/// (`Plan::ingest_inflaters`): what it measured idle, its margin, and the connection buffers the
/// Noise pool keeps idle (`noise::POOL_IDLE` messages), which an idle run has not yet filled.
/// Each feeder's reservation (`PerFeeder::planned`) is above what a feeder measured adding over
/// the idle base ([`MEASURED_GROWTH_PER_FEEDER`], the 1,000 feeder run less the idle relay, some
/// 485 KiB; this module's tests hold it), so this base holds at the loads measured.
/// `//crates/load:public_relay` measures the plan against what the relay is resident at the
/// public relay's exact arguments, its judging clock bounded by a ClockBound segment the harness
/// keeps synchronised (2026-10-23, `-c opt`, one core hosting MLAT, `--memory` fitted to each
/// load): peak 17, 61, 144 and 438 MiB at 0, 8, 32 and 128 feeders against budgets of 532, 666,
/// 1,123 and 2,952 MiB, and gathering both world products 17, 83, 233 and 724 MiB against 1,468,
/// 1,601, 2,058 and 3,887 MiB; every feeder held, no record unjudged, products signed, the own
/// strike tables filled, and at 128 feeders (the first load whose simulated receivers hear a
/// transmission in common) MLAT published positions and standing took records in and forgot none.
/// What the allocator served beyond every store's charge stayed below none at every sample: the
/// stores charged whole (the directory, the remembered tables, MLAT's and the checks' tables) were
/// not filled in a run, so that check bounds the base from above only.
/// Before (2026-10-07 to 2026-10-23), 256 MiB and the pool: the 1,000 and
/// 5,000 feeder line taken back to none, an upper bound twenty times what was measured, which
/// left the public relay's 672 MiB no feeder.
pub const BASE_BYTES: usize = MEASURED_IDLE_BYTES
    + BASE_MARGIN_BYTES
    + tally_wire::noise::POOL_IDLE * tally_wire::noise::MAX_MESSAGE;
/// What the relay was resident at 1,000 feeders with no hosted MLAT (RFC-0181, "Sizing", measured
/// 2026-10-07).
pub const MEASURED_RESIDENT_AT_1000_FEEDERS: usize = 502 << 20;
/// What a feeder added to the relay's resident memory over its measured base: the 1,000 feeder
/// run less what the relay was measured idle ([`MEASURED_IDLE_BYTES`]), over its feeders, some
/// 485 KiB. What [`BASE_BYTES`] rests on, held only while every feeder reserves at least this. Not
/// the 247 KiB a feeder added between 1,000 and 5,000 feeders: that slope measured from a base of
/// 260 MiB, where the base is now the idle relay's, so a feeder must cover the whole of what the
/// first thousand added beyond it.
pub const MEASURED_GROWTH_PER_FEEDER: usize =
    (MEASURED_RESIDENT_AT_1000_FEEDERS - MEASURED_IDLE_BYTES) / 1_000;
/// What hosting MLAT adds to the relay's own base, whatever its feeders: the engine's thread, its
/// runners and its empty tables (its raw is `Arrived`'s and its working set `Engine`'s, per seat;
/// the signed records not yet taken are `Engine`'s per seat, `mlat_host::PUBLISHED_BYTES_PER_SEAT`,
/// and their models' `Models`').
/// Measured (RFC-0181, "Sizing", 2026-10-08): a relay hosting MLAT on two areas, before any
/// feeder, was 19.8 MiB resident where the same relay without it was 17.3 MiB. 2.5 MiB measured,
/// held at 4 MiB.
pub const MLAT_BASE_BYTES: usize = 4 << 20;

/// What a relay plans to hold: its own base, each feeder's cost in every store, and the pool its
/// sharing members reserve from. The base and the feeder's cost follow one switch, whether the
/// relay hosts MLAT, so they cannot disagree; a member is planned in the same feeder's cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub base: usize,
    /// What one connection costs whatever it sends: its floor (Noise and kernel socket buffers,
    /// delivery tags at the per-receiver cap, pace and shed state), reserved when it is admitted
    /// ([`Budget::reserve`]). Not the rate-driven stores', which follow the relay-wide rate, nor
    /// MLAT's, which follow its seats.
    pub per_feeder: PerFeeder,
    /// What one planned feeder's rate (600 receptions a second) costs the rate-driven stores over
    /// their windows: a gauge's limit is this over [`PLANNED_RECEPTIONS_PER_SEC`] times the
    /// relay-wide rate `R_max` and the members' rate. It follows whether the relay has sharing
    /// members and how many sessions may listen ([`PerFeeder::planned_for`]), set again by
    /// [`Plan::with_members`] and [`Plan::with_sessions`].
    pub per_rate: PerFeeder,
    /// What one MLAT seat costs the seat stores (all zero where MLAT is not hosted).
    pub per_seat: PerFeeder,
    /// The member sessions the relay holds at once ([`members_for`]), each holding a place of them
    /// ([`Budget::reserve_member`]).
    pub members: usize,
    /// The feeders the members' one shared rate (`--max-member-bytes-per-sec`, all of them
    /// together) is worth: planned once, however many members carry it.
    pub member_feeders: usize,
    /// The connections held at once but a feeder's (whose are its reservation's,
    /// `PerFeeder::buffers`): those under the connection cap, the member sessions and the
    /// subscribers (`Plan::with_sessions`), each carving its Noise buffers from room planned here
    /// (`Plan::connection_buffers`).
    pub connections: usize,
    /// The sessions beside the feeders and the members' rate whose records the cores carry
    /// (`cores::Sessions`): those under the connection cap and the subscribers.
    pub sessions: crate::cores::Sessions,
    /// The cores the relay runs on, whose work bounds the feeders admitted beside the memory
    /// (`cores::feeders_carried`); none for a plan only its memory bounds (a test's).
    pub cores: Option<usize>,
    /// Whether the relay holds MLAT raw (it hosts MLAT): the base, each feeder's cost in the
    /// stores and in the cores (the stages' and MLAT's steps') follow it.
    pub holds_raw: bool,
    /// The records a second a feeder may send (`ingest::records_per_sec` of its byte ceiling,
    /// `--max-feeder-bytes-per-sec`): each costs the ingest workers a verification whatever its
    /// size, so the cores carry fewer feeders the more each may send (`cores::Source`).
    pub feeder_records_per_sec: u64,
    /// The bundle indexes the relay signs a second (`sharing::bundles::planned_indexes_per_sec`):
    /// one for each parent it may offer of the regions it takes and each shared product, at most.
    pub bundle_indexes_per_sec: u64,
    /// Whether the own records' store plans the bundle indexes by the rate (`Plan::with_cheaper_indexes`)
    /// rather than by the parents offered ([`Plan::bundle_indexes_per_sec`], before any feeder).
    pub indexes_by_rate: bool,
    /// Whether the relay gathers the world product (`--world`): it holds its fixes for their open
    /// seconds (`Store::World`). There is one kind of fix, so one world product.
    pub world: bool,
}

/// The bundle indexes a second one record a second the sharing groups take may bring at most: an
/// index is signed for each parent above an origin manifest of that second, one manifest for each
/// group with a record in it (`Sharing::bundle_indexes`), and a manifest's group has a parent at
/// each resolution coarser than an area (`rendezvous::AREA_RESOLUTION`). So the indexes a second
/// are at most the records a second the groups take times that, whatever parents are offered.
pub const INDEXES_PER_RECORD: u64 = tally_wire::rendezvous::AREA_RESOLUTION as u64;

impl Plan {
    /// The plan of a relay that hosts MLAT (`hosts_mlat`) or does not, holding no member.
    pub fn planned(hosts_mlat: bool) -> Self {
        let planned = PerFeeder::planned(hosts_mlat);
        Self {
            base: BASE_BYTES + if hosts_mlat { MLAT_BASE_BYTES } else { 0 },
            per_feeder: planned.floor(),
            per_rate: planned.rate(),
            per_seat: planned.seat(),
            members: 0,
            member_feeders: 0,
            connections: 0,
            sessions: crate::cores::Sessions {
                general: 0,
                subscribers: 0,
            },
            cores: None,
            holds_raw: hosts_mlat,
            feeder_records_per_sec: crate::ingest::records_per_sec(
                crate::hub::DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
            ),
            bundle_indexes_per_sec: 0,
            indexes_by_rate: false,
            world: false,
        }
    }

    /// The same plan gathering the world product (`world`, `--world`) or not: it holds its fixes
    /// for their open seconds, planned before any feeder ([`Plan::world_bytes`]).
    #[must_use]
    pub fn with_world(self, world: bool) -> Self {
        Self { world, ..self }
    }

    /// What the world product's fixes hold at most (`Store::World`,
    /// `products::world_planned_bytes`): at its cap where it is gathered, nothing where it is
    /// not.
    pub fn world_bytes(&self) -> usize {
        crate::products::world_planned_bytes(self.world)
    }

    /// The same plan with each feeder held to `bytes_per_sec` (`--max-feeder-bytes-per-sec`): the
    /// records a second it may send ([`Plan::feeder_records_per_sec`]).
    #[must_use]
    pub fn with_feeder_ceiling(self, bytes_per_sec: u64) -> Self {
        Self {
            feeder_records_per_sec: crate::ingest::records_per_sec(bytes_per_sec),
            ..self
        }
    }

    /// The same plan on `cores` cores (`cores::cores_available`): the connections admitted, the rate
    /// and the MLAT seats are no more than they carry.
    #[must_use]
    pub fn with_cores(self, cores: Option<usize>) -> Self {
        Self { cores, ..self }.rate_replanned()
    }

    /// What the plan admits in `total` bytes, the memory left after what the relay holds before
    /// any feeder (`Plan::before_feeders`). The one derivation (RFC-0181 §10, "Admission"):
    ///
    /// 1. **Connections** first, at their floor and the windows of the planned mean rate: the
    ///    fewer of the memory over a connection's cost and the cores over a session and the stages'
    ///    cost of the mean rate. A relay hosting MLAT plans them from what remains after MLAT's share
    ///    (`cores::MLAT_SHARE_PERCENT` of the memory and of the cores), so it does not give every
    ///    byte to connections and leave its seats none.
    /// 2. **MLAT seats**, where MLAT is hosted, from what the connections leave (the share and
    ///    whatever they did not use): the fewer of the memory left over a seat, the cores left
    ///    over a seat's steps, and the connections. Seats are no more than connections, never the
    ///    reverse; a feeder past them is still a connection, relayed and not solved. What a seat's
    ///    neighbours publish for it (their models and positions, over the member sessions) is
    ///    planned with the seat, apart from the members' rate: each seat brings a products pace of
    ///    one seat's products a second (`Plan::member_products_bytes_per_sec`) and its room in the
    ///    models' store (`models::BYTES_PER_MEMBER_SEAT`), and the members' rate
    ///    (`--max-member-bytes-per-sec`) carries raw alone, so raising the seats plans no more raw
    ///    ingest and no default rate under-carries them. Before (2026-10-27), the products spent
    ///    the members' rate, which the plan then bounded the seats by (125 at the default 1 MiB/s,
    ///    where the cores carried 522), and a rate raised for the products planned as much raw
    ///    ingest beside them.
    /// 3. **`R_max`**: the least of the memory left after the floors and the seats over a
    ///    reception's windows, the cores left after the sessions and the seats over a reception's
    ///    cost through the stages (at `cores::BUSY_PERCENT`). Connections are admitted at the
    ///    planned mean, so `R_max` is at least their mean; what bound the connections bounds it
    ///    too, and the other is the room above.
    pub fn admit(&self, total: usize) -> Admission {
        let floor = self.per_feeder.total();
        let unit = self.per_rate.total();
        let seat = self.per_seat.total();
        let mean = PLANNED_RECEPTIONS_PER_SEC as u128;
        let holds_raw = self.holds_raw;
        let available = self.cores.map(|cores| {
            crate::cores::available_nanos(cores, holds_raw, self.member_feeders, self.sessions)
        });
        let per_connection = floor.saturating_add(unit);
        // Connections.
        let connections_by_memory = crate::cores::after_mlat_share(total, holds_raw)
            .checked_div(per_connection)
            .unwrap_or(usize::MAX);
        let connections_by_cores = available.map(|nanos| {
            crate::cores::connections_carried(
                crate::cores::after_mlat_share(nanos, holds_raw),
                holds_raw,
                0,
            )
        });
        let connections = connections_by_memory.min(connections_by_cores.unwrap_or(usize::MAX));
        let connections_bound =
            if connections_by_cores.is_some_and(|cores| cores < connections_by_memory) {
                Bound::Cores
            } else if per_connection == 0 {
                Bound::Unbounded
            } else {
                Bound::Memory
            };
        // Seats, from what the connections leave.
        let connections_cost = per_connection.saturating_mul(connections);
        let seats_by_memory = if holds_raw {
            total
                .saturating_sub(connections_cost)
                .checked_div(seat)
                .unwrap_or(usize::MAX)
        } else {
            0
        };
        let seats_by_cores =
            available.map(|nanos| crate::cores::seats_carried(nanos, holds_raw, connections));
        let by_resources = seats_by_memory.min(seats_by_cores.unwrap_or(usize::MAX));
        let seats = if holds_raw {
            by_resources.min(connections)
        } else {
            0
        };
        let seats_bound = if !holds_raw {
            Bound::NotHosted
        } else if seats == connections && connections < by_resources {
            Bound::Connections
        } else if seats_by_cores.is_some_and(|cores| cores < seats_by_memory) {
            Bound::Cores
        } else {
            Bound::Memory
        };
        // R_max.
        let rate_by_memory = if unit == 0 {
            u64::MAX
        } else {
            let left = total
                .saturating_sub(floor.saturating_mul(connections))
                .saturating_sub(seat.saturating_mul(seats));
            mul_div(left as u64, mean, unit as u128)
        };
        let rate_by_cores =
            available.map(|nanos| crate::cores::rate_carried(nanos, holds_raw, connections, seats));
        let rate = rate_by_memory.min(rate_by_cores.unwrap_or(u64::MAX));
        let rate_bound = if rate_by_cores.is_some_and(|cores| cores < rate_by_memory) {
            Bound::Cores
        } else if unit == 0 {
            Bound::Unbounded
        } else {
            Bound::Memory
        };
        Admission {
            floor,
            connections,
            connections_by_memory,
            connections_by_cores,
            connections_bound,
            rate,
            rate_by_memory,
            rate_by_cores,
            rate_bound,
            seats,
            seats_by_memory,
            seats_by_cores,
            seats_bound,
        }
    }

    /// The same plan holding `general` sessions under the connection cap (`--max-connections`) and
    /// `subscribers` subscribers (`--max-subscribers`, and the beast-out and acars-out clients,
    /// each planned as one: `Hub::serving_beast`, `Hub::serving_acars`) beside its member sessions:
    /// each with its Noise buffers (`Plan::connections`), and their records in the cores
    /// (`cores::Sessions`). One count for both, so the sessions whose buffers are planned are the
    /// sessions whose records are. Set after `with_members`, whose sessions it counts. Each role
    /// holds its own cap: before, the three shared the one, so the plan counted some 128 members,
    /// 25 feeders and 64 subscribers in 128 connections, and a member past the connections the
    /// others held was closed on before its handshake, with no word to route around it by.
    #[must_use]
    pub fn with_sessions(self, general: usize, subscribers: usize) -> Self {
        Self {
            connections: general
                .saturating_add(self.members)
                .saturating_add(subscribers),
            sessions: crate::cores::Sessions {
                general,
                subscribers,
            },
            ..self
        }
        .rate_replanned()
    }

    /// The rate-driven stores' costs again for what the plan now holds: whether it has sharing
    /// members (its groups then hold their records' signed bytes and parities over the horizon),
    /// how many sessions may take a batch from the fan-out, and the cores (the message threads a
    /// batch is cut across).
    fn rate_replanned(self) -> Self {
        let mut per_rate = PerFeeder::planned_for(
            self.holds_raw,
            self.members > 0,
            self.fanout_listeners(),
            self.cores,
        )
        .rate();
        if self.indexes_by_rate {
            per_rate.own_strikes += Self::indexes_bytes(crate::cores::RECORDS_PER_PLANNED_FEEDER);
        }
        Self { per_rate, ..self }
    }

    /// What the bundle indexes `records` records a second bring take in the relay's own store
    /// over their life, planned by the rate: [`INDEXES_PER_RECORD`] for each, each at
    /// `strikes::PLANNED_ENTRY_BYTES` (`own_life_seconds`).
    const fn indexes_bytes(records: u64) -> usize {
        (records * INDEXES_PER_RECORD * own_life_seconds()) as usize
            * crate::strikes::PLANNED_ENTRY_BYTES
    }

    /// The same plan with its bundle indexes planned the cheaper of the two ways both bound them,
    /// in `memory` bytes: by the parents it may offer ([`Plan::bundle_indexes_per_sec`], held
    /// before any feeder), or by the records a second its groups take (`INDEXES_PER_RECORD` of
    /// them, a rate-driven part of the own records' store). Each is the most the relay signs
    /// (`Sharing::bundle_indexes` never signs more than either), so either is a safe plan; the one
    /// that admits more connections, or as many and more MLAT seats, or as many of both and more
    /// rate (the order `Plan::admit` fills them in: the seats from what the connections leave, the
    /// rate from what both leave) is taken, and on a tie the parents', which holds the same
    /// whatever the load. Before, the seats were left out, so a relay hosting MLAT could take the
    /// rate's plan for its rate and lose its one seat. The own records' store is
    /// never evicted: a new record past it is refused and counted (`strikes::Verdict::Full`), and
    /// one of the relay's own making still goes out (`Hub::publish_own`).
    #[must_use]
    pub fn with_cheaper_indexes(self, memory: usize) -> Self {
        let fixed = self.with_indexes_by_rate(false);
        let rate = self.with_indexes_by_rate(true);
        let admitted = |plan: &Self| {
            let admission = plan.admit(memory.saturating_sub(plan.before_feeders()));
            (admission.connections, admission.seats, admission.rate)
        };
        if admitted(&rate) > admitted(&fixed) {
            rate
        } else {
            fixed
        }
    }

    /// The same plan with its bundle indexes planned by the rate or not: the rate's share of them
    /// (`indexes_bytes` of a planned feeder's records) added to or taken from what a feeder's
    /// worth holds in the relay's own store, every other cost as it was.
    #[must_use]
    pub fn with_indexes_by_rate(self, by_rate: bool) -> Self {
        if self.indexes_by_rate == by_rate {
            return self;
        }
        let share = Self::indexes_bytes(crate::cores::RECORDS_PER_PLANNED_FEEDER);
        let mut per_rate = self.per_rate;
        per_rate.own_strikes = if by_rate {
            per_rate.own_strikes.saturating_add(share)
        } else {
            per_rate.own_strikes.saturating_sub(share)
        };
        Self {
            per_rate,
            indexes_by_rate: by_rate,
            ..self
        }
    }

    /// Every session that joins the fan-out (`Hub::listen`): those under the connection cap (a
    /// relay or engine link, a dialled parent's directory link, `link::serve`), the subscribers,
    /// and the member sessions, which hold places of their own outside the cap and each join it as
    /// a directory link (`Peer::Member`). Before, the member sessions were left out, so a relay
    /// taking base cells with thousands of them charged queues past what `Store::Fanout` was
    /// planned for.
    pub fn fanout_listeners(&self) -> usize {
        self.sessions
            .general
            .saturating_add(self.sessions.subscribers)
            .saturating_add(self.members)
    }

    /// The kernel's socket buffers of every connection but a feeder's (whose are its floor's,
    /// `PerFeeder::sockets`), each place counted once, at what its role pins (`sockets`). Every
    /// connection under the connection cap at a feeder's, since a connection holds more only while
    /// it holds a place counted here. Each member place a member's: a session admitted as a member
    /// and a raw link dialled as an engine (`link::admit_member`) both leave the cap for it. Each
    /// subscriber place a subscriber's, outside the cap as well. Two places are taken by connections
    /// that keep their place under the cap, so they are counted past a feeder's only by what they
    /// pin more: an engine place (`Hub::engine_place`, as many as the member sessions) and a link
    /// dialled to a member that only sends (`Hub::dialled`, at most as many as the member sessions,
    /// `peers`). Both are under the cap together, so at most the cap of them hold either, the
    /// dearer (an engine's) counted first. Before, both were counted whole beside the cap's feeder
    /// buffers, a feeder's twice for each.
    pub fn connection_sockets(&self) -> usize {
        use crate::sockets::{
            ENGINE_KERNEL_BYTES, FEEDER_KERNEL_BYTES, MEMBER_KERNEL_BYTES, SUBSCRIBER_KERNEL_BYTES,
        };
        let general = self.sessions.general;
        // Each of the two holds at most the member sessions' count of places; the dearer is
        // filled first, whichever it is, and the other takes what the cap leaves.
        let (engine, dialled) = (
            ENGINE_KERNEL_BYTES.saturating_sub(FEEDER_KERNEL_BYTES),
            MEMBER_KERNEL_BYTES.saturating_sub(FEEDER_KERNEL_BYTES),
        );
        let (first, second) = (engine.max(dialled), engine.min(dialled));
        let firsts = self.members.min(general);
        let seconds = self.members.min(general - firsts);
        general
            .saturating_mul(FEEDER_KERNEL_BYTES)
            .saturating_add(self.members.saturating_mul(MEMBER_KERNEL_BYTES))
            .saturating_add(
                self.sessions
                    .subscribers
                    .saturating_mul(SUBSCRIBER_KERNEL_BYTES),
            )
            .saturating_add(firsts.saturating_mul(first))
            .saturating_add(seconds.saturating_mul(second))
    }

    /// What the fan-out's queues allocate whatever they hold (`fanout::LISTENER_BYTES` each): every
    /// session that may take a batch from it (`Plan::fanout_listeners`), charged to `Store::Fanout`
    /// beside what its items' slots take for each feeder.
    pub fn fanout_queues(&self) -> usize {
        self.fanout_listeners()
            .saturating_mul(crate::fanout::LISTENER_BYTES)
    }

    /// What the sharing outbox's slots keep beyond what each send takes, on a relay with sharing
    /// members (`sharing::OUTBOX_FIXED_BYTES`), charged to `Store::Batches`.
    pub fn sharing_outbox(&self) -> usize {
        if self.members == 0 {
            0
        } else {
            crate::sharing::OUTBOX_FIXED_BYTES
        }
    }

    /// What hosted MLAT's stores allocate whatever they hold, where MLAT is hosted: the engine's
    /// address shards and the aircraft they keep (`Store::Arrived`,
    /// `tally_mlat::fix::TABLES_PLANNED_BYTES`), and standing's tables' floors (`Store::Standing`,
    /// `standing::FIXED_BYTES`).
    pub fn mlat_tables(&self) -> usize {
        [Store::Arrived, Store::Standing]
            .into_iter()
            .map(|store| self.mlat_tables_of(store))
            .sum()
    }

    /// What [`Plan::mlat_tables`] holds of `store`.
    pub fn mlat_tables_of(&self, store: Store) -> usize {
        if !self.holds_raw {
            return 0;
        }
        match store {
            Store::Arrived => tally_mlat::fix::TABLES_PLANNED_BYTES,
            Store::Standing => crate::standing::FIXED_BYTES,
            _ => 0,
        }
    }

    /// What hosted MLAT's inboxes keep whatever they hold, where MLAT is hosted: each raw shard's
    /// spare (`Store::Inbox`, `mlat_host::INBOX_FIXED_BYTES`).
    pub fn inbox_spare(&self) -> usize {
        if self.holds_raw {
            crate::mlat_host::INBOX_FIXED_BYTES
        } else {
            0
        }
    }

    /// The Noise buffers of every connection but a feeder's the caps allow
    /// (`ingest::BUFFERS_PER_CONNECTION` each, reading and writing): those under the connection
    /// cap, the member sessions and the subscribers (`Hub::plan`), from which each carves its own.
    pub fn connection_buffers(&self) -> usize {
        self.connections
            .saturating_mul(crate::ingest::BUFFERS_PER_CONNECTION)
    }

    /// The pace state of every connection but a feeder's the caps allow
    /// (`ingest::PACE_BYTES_PER_CONNECTION` each): those under the connection cap, the member
    /// sessions and the subscribers (`Hub::plan`), charged to `Store::Paces` beside the feeders'
    /// floors.
    pub fn connection_paces(&self) -> usize {
        self.connections
            .saturating_mul(crate::ingest::PACE_BYTES_PER_CONNECTION)
    }

    /// What waits for the member links this relay dials (`peers`), at most: each member session
    /// planned may be one, and each holds at most its share (`peers::WAITING_PER_LINK_BYTES`), from
    /// this room together (`Budget::member_links`).
    pub fn member_links(&self) -> usize {
        self.members
            .saturating_mul(crate::peers::WAITING_PER_LINK_BYTES)
    }

    /// What the positions checks' twins hold (`consistency::twins_fixed_bytes`): one raw record a
    /// link at most while its tagged twin is on its way, the relay's own engine's where it hosts
    /// MLAT and each member session's, their table and the one record decoded in hand. Whatever
    /// the seats and the members' rate: what drives it is the links, all planned before any
    /// feeder.
    pub fn twins_tables(&self) -> usize {
        crate::consistency::twins_fixed_bytes(self.twin_links())
    }

    /// The links whose raw positions the checks hold a record of at a time
    /// (`consistency::Sizing::links`): the relay's own engine where it hosts MLAT, and every member
    /// session.
    pub fn twin_links(&self) -> usize {
        usize::from(self.holds_raw).saturating_add(self.members)
    }

    /// What the decoded models' store holds whatever the seats and the members' rate
    /// (`models::fixed_bytes`): its trees' roots, and the members' least burst where they have a
    /// rate.
    pub fn models_tables(&self) -> usize {
        crate::models::fixed_bytes(self.member_feeders > 0)
    }

    /// What a seat-driven store holds whatever the seats and the members' rate: the models' tables
    /// ([`Plan::models_tables`]); nothing for any other.
    pub fn seat_tables_of(&self, store: Store) -> usize {
        match store {
            Store::Models => self.models_tables(),
            _ => 0,
        }
    }

    /// The members' pace (`ingest::MemberPace`), all member sessions together, a second: the
    /// feeders the members' shared rate is worth, each at a planned feeder's charged bytes
    /// ([`PLANNED_CHARGED_BYTES_PER_SEC`]). Their batches spend it by their rate cost and their
    /// MLAT records by their signed bytes. What of it may be clock models is held to its own
    /// pace, [`Plan::member_models_bytes_per_sec`]: the models are a small part of what an engine
    /// publishes, so the members' whole pace is never planned as models.
    pub fn member_paced_bytes_per_sec(&self) -> usize {
        self.member_feeders
            .saturating_mul(PLANNED_CHARGED_BYTES_PER_SEC)
    }

    /// The seats whose products the members bring, for `seats` hosted: each seat hosted (what
    /// its neighbours in its areas publish for it), and each feeder the members' raw rate is worth
    /// (a receiver another relay forwards, one seat of that relay's engine); none without members.
    /// Each source is planned once, in its own unit: a seat's room in the seat's
    /// (`PerFeeder::seat` with members, `Plan::with_members`), a member feeder's in the members'
    /// (`Plan::member_unit`).
    pub fn product_seats(&self, seats: usize) -> usize {
        if self.members == 0 {
            0
        } else {
            seats.saturating_add(self.member_feeders)
        }
    }

    /// The members' clock models' pace, all member sessions together, a second, in signed bytes,
    /// for `seats` hosted: the seats whose products they bring ([`Plan::product_seats`]), each at
    /// what one seat's models are a second as an engine publishes them
    /// (`models::MEMBER_MODEL_BYTES_PER_SEAT_PER_SEC`). Held to the products' pace
    /// (`ingest::MemberPace`) with their positions ([`Plan::member_positions_bytes_per_sec`]), and
    /// the models' store holds this pace over the models' hold (`models::Rooms::of`). Before, the
    /// models' store and the twins' were each planned at the members' whole pace, so the same
    /// bytes were planned twice, both as models and as positions, and both at their whole rate.
    pub fn member_models_bytes_per_sec(&self, seats: usize) -> usize {
        self.product_seats(seats)
            .saturating_mul(crate::models::MEMBER_MODEL_BYTES_PER_SEAT_PER_SEC)
    }

    /// The members' positions' pace, all member sessions together, a second, in signed bytes, for
    /// `seats` hosted: the seats whose products they bring ([`Plan::product_seats`]), each at what
    /// one seat's raw and tagged positions are a second
    /// (`consistency::POSITIONS_BYTES_PER_SEAT_PER_SEC`). Nothing is held for it beside the
    /// records' own stores: a raw record waits for its twin one at a time a link
    /// (`Store::Twins`).
    pub fn member_positions_bytes_per_sec(&self, seats: usize) -> usize {
        self.product_seats(seats)
            .saturating_mul(crate::consistency::POSITIONS_BYTES_PER_SEAT_PER_SEC)
    }

    /// The members' products' pace (`ingest::MemberPace`), all member sessions together, a
    /// second, in signed bytes, for `seats` hosted: their models' and their positions'. It follows
    /// the seats, apart from the members' raw rate (`--max-member-bytes-per-sec`), so the seats
    /// never wait on a rate an operator sized for raw.
    pub fn member_products_bytes_per_sec(&self, seats: usize) -> usize {
        self.member_models_bytes_per_sec(seats)
            .saturating_add(self.member_positions_bytes_per_sec(seats))
    }

    /// What the members' shared rate (`--max-member-bytes-per-sec`) brings in a second at most, as
    /// planned: the feeders it is worth, each at the planned rate (no less than the rate itself),
    /// in signed bytes.
    pub fn member_bytes_per_sec(&self) -> usize {
        self.member_feeders.saturating_mul(PLANNED_BYTES_PER_SEC)
    }

    /// The parities being reassembled from their chunks, at most (`sharing::assembly_room`): every
    /// chunk the members' shared rate can bring while one parity may wait to be whole, so the room
    /// is never full for an honest sender (`Budget::parity_assembly`).
    pub fn parity_assembly(&self) -> usize {
        crate::sharing::assembly_room(self.member_bytes_per_sec())
    }

    /// Every part of what the relay holds before any feeder, each under the name `tally-relay
    /// check` prints it by: its base, what the fingerprints' tables allocate whatever the rate
    /// (charged to `Store::Dedup` beside the rate's), what waits for the sealer whatever it holds
    /// (`Store::Epochs`), the tables of what was taken
    /// (`Store::FeederStrikes`, `Store::PeerStrikes`, `Store::OwnStrikes`), the delivery shards' tables as kept whatever they hold
    /// (`Store::Delivery`, beside its connections' floors), the connections' Noise buffers and kernel
    /// socket buffers,
    /// the members' pool, what waits for the member links, the parities being reassembled, the
    /// credit's tables, the cache of verified anchors (`Store::Anchors`), the station rows
    /// (`Store::Stations`), the offer directory (`Store::Directory`), the products' remembered
    /// tables (`Store::Remembered`), the world's fixes where it is gathered (`Store::World`), and
    /// what standing's and the positions checks' tables hold whatever their figures
    /// (`Store::Standing`, `Store::Consistency`). The
    /// one list [`Plan::before_feeders`] sums and `check` prints, so a part planned is a part
    /// printed: a room added here and nowhere else is in both, and the deploy checks that add the
    /// lines up (`before-feeders`) never sum a list of their own.
    pub fn before_feeders_parts(&self) -> [(&'static str, usize); 30] {
        [
            ("base", self.base),
            ("ingest-inflaters", self.ingest_inflaters()),
            ("dedup-tables", crate::exchange::DEDUP_FIXED_BYTES),
            ("epochs-fixed", crate::exchange::EPOCHS_FIXED_BYTES),
            (
                "feeder-strike-tables",
                self.strike_tables_bytes(crate::strikes::Class::Feeders),
            ),
            (
                "peer-strike-tables",
                self.strike_tables_bytes(crate::strikes::Class::Peers),
            ),
            (
                "own-strike-tables",
                self.strike_tables_bytes(crate::strikes::Class::Own),
            ),
            ("delivery-tables", crate::delivery::FIXED_BYTES),
            ("fanout-queues", self.fanout_queues()),
            ("sharing-outbox", self.sharing_outbox()),
            ("mlat-tables", self.mlat_tables()),
            ("inbox-spare", self.inbox_spare()),
            ("connection-buffers", self.connection_buffers()),
            ("connection-sockets", self.connection_sockets()),
            ("connection-paces", self.connection_paces()),
            ("member-pool", self.member_pool()),
            ("member-links", self.member_links()),
            ("parity-assembly", self.parity_assembly()),
            ("credit-tables", self.receiver_tables_of(Store::Credit)),
            ("anchor-cache", crate::anchors::PLANNED_BYTES),
            ("station-tables", self.receiver_tables_of(Store::Stations)),
            ("directory", crate::directory::PLANNED_BYTES),
            (
                "description-tables",
                self.receiver_tables_of(Store::Descriptions),
            ),
            ("located-tables", self.receiver_tables_of(Store::Located)),
            ("clock-model-parts", self.parts_bytes()),
            ("remembered-tables", crate::products::REMEMBERED_BYTES),
            ("world-fixes", self.world_bytes()),
            (
                "consistency-tables",
                self.receiver_tables_of(Store::Consistency),
            ),
            ("twins-tables", self.twins_tables()),
            ("model-tables", self.models_tables()),
        ]
    }

    /// What the ingest workers' inflations hold beside what each decode is charged
    /// (`batch::INFLATER_BYTES` each): a worker for each core at most (`cores::threads_for`), one
    /// where the cores are not known (a test's plan).
    pub fn ingest_inflaters(&self) -> usize {
        tally_wire::batch::INFLATER_BYTES.saturating_mul(self.cores.unwrap_or(1).max(1))
    }

    /// The receiver figure at `admission`: the receivers that may have published within
    /// [`RECEIVER_GAP_SECONDS`], the records a second the relay admits (`R_max`'s and the
    /// members' rate's) over it. What every table of one entry per receiver is sized to
    /// ([`Store::Credit`], [`Store::Stations`], [`Store::Descriptions`], [`Store::Located`]).
    pub fn receivers(&self, admission: &Admission) -> usize {
        let records = admission
            .records_per_sec()
            .saturating_add(crate::ingest::member_records_per_sec(self.member_feeders));
        usize::try_from(records)
            .unwrap_or(usize::MAX)
            .saturating_mul(RECEIVER_GAP_SECONDS)
            .min(RECEIVERS_MOST)
    }

    /// What `store`'s tables of one entry per receiver hold whatever the rate: what they allocate
    /// beside an entry's share at any figure (each module's `FIXED_BYTES`: a page's slack and the
    /// least table of each shard), and the entries of the one record a second the members' rate
    /// is planned at when it plans none (`ingest::member_records_per_sec`), which no feeder's or
    /// member's unit holds. Nothing for any other store.
    pub fn receiver_tables_of(&self, store: Store) -> usize {
        let (fixed, per) = match store {
            Store::Credit => (
                crate::credit::FIXED_BYTES,
                crate::credit::BYTES_PER_RECEIVER,
            ),
            Store::Stations => (
                crate::stations::FIXED_BYTES,
                crate::stations::BYTES_PER_RECEIVER,
            ),
            Store::Descriptions => (
                crate::hub::DESCRIPTIONS_FIXED_BYTES,
                crate::hub::DESCRIPTIONS_BYTES_PER_RECEIVER,
            ),
            Store::Located => (
                crate::products::LOCATED_FIXED_BYTES,
                crate::products::LOCATED_BYTES_PER_RECEIVER,
            ),
            Store::Consistency => (
                crate::consistency::FIXED_BYTES,
                crate::consistency::BYTES_PER_RECEIVER,
            ),
            _ => return 0,
        };
        let unplanned = crate::ingest::member_records_per_sec(self.member_feeders).saturating_sub(
            (self.member_feeders as u64).saturating_mul(crate::ingest::MEMBER_RECORDS_PER_FEEDER),
        ) as usize
            * RECEIVER_GAP_SECONDS;
        fixed.saturating_add(per.saturating_mul(unplanned))
    }

    /// The bytes of clock model parts that may wait for their manifests at once (`parts::Parts`):
    /// what the members' shared rate brings over the longest a part waits (`parts::HOLD`), and
    /// one model's parts whole, so a relay with neither still passes one on. The relay's own
    /// MLAT brings none to wait: its engine signs a model's parts with its manifest, and they go
    /// out one after another, its parts right before its manifest.
    pub fn parts_room(&self) -> usize {
        let hold = crate::parts::HOLD.as_secs() as usize;
        self.member_bytes_per_sec()
            .saturating_mul(hold)
            .saturating_add(crate::parts::ONE_MODEL_BYTES)
    }

    /// What the clock model parts' tables allocate at most at [`Plan::parts_room`]
    /// (`parts::planned_bytes`), charged whole to [`Store::Parts`].
    pub fn parts_bytes(&self) -> usize {
        crate::parts::planned_bytes(self.parts_room())
    }

    /// What the relay holds before any feeder ([`Plan::before_feeders_parts`], together).
    /// Feeders reserve from what is left.
    pub fn before_feeders(&self) -> usize {
        self.before_feeders_parts()
            .iter()
            .fold(0, |sum, (_, bytes)| sum.saturating_add(*bytes))
    }

    /// The same plan holding `members` member sessions at once ([`members_for`]), sending
    /// `members_bytes_per_sec` together (`--max-member-bytes-per-sec`, held by one pace they all
    /// share, `ceiling::Pace`), so planned once as the feeders that rate is worth. A relay that
    /// holds no member plans no rate for them.
    #[must_use]
    pub fn with_members(self, members: usize, members_bytes_per_sec: u64) -> Self {
        // Where MLAT is hosted, each seat holds the clock models its neighbours publish for it as
        // well as its own engine's, once there are members to bring them (`Plan::admit`, 2).
        let mut per_seat = self.per_seat;
        if self.holds_raw {
            per_seat.models = crate::models::BYTES_PER_SEAT
                + if members == 0 {
                    0
                } else {
                    crate::models::BYTES_PER_MEMBER_SEAT
                };
        }
        Self {
            per_seat,
            members,
            member_feeders: if members == 0 {
                0
            } else {
                feeders_for_rate(members_bytes_per_sec)
            },
            ..self
        }
        .rate_replanned()
    }

    /// The feeders the members' shared rate is planned as.
    pub fn member_feeders(&self) -> usize {
        self.member_feeders
    }

    /// What the members' shared rate holds in every store (`PerFeeder::as_member`, the rate's
    /// feeders' worth). A member session holds nothing of its own beside it: what it reads waits
    /// in the one ingest pool (`Store::Ingest`), its records counted by its credit.
    pub fn member_rate_pool(&self) -> usize {
        self.member_unit()
            .total()
            .saturating_mul(self.member_feeders)
    }

    /// What one feeder's worth of the members' shared rate costs every store: the floor's
    /// delivery tags and shed state, the rate-driven stores' windows, and the records the members'
    /// sessions write (positions, models, peers' regional batches; `products::records_per_feeder`).
    /// No seat's raw: hosted MLAT seats every receiver it solves, its own feeders' and those the
    /// raw links bring alike, in the one cap the seats are planned at (`mlat_host::Seats`, over
    /// `Admission::seats`), so the receivers a member's raw link brings take seats already
    /// planned. Before, each of the members' feeders was planned a seat's raw too, held twice.
    pub fn member_unit(&self) -> PerFeeder {
        let mut unit = self.per_feeder.as_member().plus(&self.per_rate);
        unit.records = crate::products::records_per_feeder(PLANNED_RECEPTIONS_PER_SEC);
        // What the relay takes in of its worth (`strikes`), nothing in the feeders' store: in the
        // peers', its records as the peers deliver them, at most twice their rate (a peer below
        // its fair share is taken while another floods the rest, `strikes::Shares`); in the
        // relay's own, as the relay rebuilds them from parity, each over the longest a peer's copy
        // lives (`Usable::life_seconds`), and the relay's own records for its worth of load, and
        // its figures. The members' places in the shares are theirs, before any feeder
        // (`Plan::strike_tables_bytes`).
        let member = crate::ingest::MEMBER_RECORDS_PER_FEEDER * peer_life_seconds();
        // The receivers its records a second bring within the gap (`RECEIVERS_PER_MEMBER_FEEDER`),
        // an entry each in every table of receivers.
        let receivers = RECEIVERS_PER_MEMBER_FEEDER;
        unit.credit = crate::credit::BYTES_PER_RECEIVER * receivers;
        unit.stations = crate::stations::BYTES_PER_RECEIVER * receivers;
        unit.descriptions = crate::hub::DESCRIPTIONS_BYTES_PER_RECEIVER * receivers;
        unit.located = crate::products::LOCATED_BYTES_PER_RECEIVER * receivers;
        unit.consistency = crate::consistency::BYTES_PER_RECEIVER * receivers;
        // The MLAT positions its pace brings wait for their twins one record a link, planned
        // before any feeder (`Plan::twins_tables`): none here. Each is charged in the ingest pool
        // its signed bytes, what it spent of the pace, so the batches' ingest planned for that
        // pace covers it.
        unit.twins = 0;
        // The clock models the products' pace brings for it as one seat of another relay's engine
        // (`Plan::member_models_bytes_per_sec`), held over the models' hold, decoded
        // (`models::BYTES_PER_MEMBER_SEAT`). Its receivers bring none.
        unit.models = crate::models::BYTES_PER_MEMBER_SEAT;
        unit.feeder_strikes = 0;
        unit.peer_strikes = (2 * member) as usize * crate::strikes::PLANNED_ENTRY_BYTES;
        unit.own_strikes = member as usize * crate::strikes::PLANNED_ENTRY_BYTES
            + own_strikes_bytes(crate::strikes::own_records_per_feeder(self.holds_raw) as usize)
            + if self.indexes_by_rate {
                Self::indexes_bytes(crate::ingest::MEMBER_RECORDS_PER_FEEDER)
            } else {
                0
            };
        unit
    }

    /// The same plan with the bundle indexes its relay signs a second (`bundle_indexes_per_sec`,
    /// `sharing::bundles::planned_indexes_per_sec` of the regions it takes).
    #[must_use]
    pub fn with_bundle_indexes(self, per_sec: u64) -> Self {
        Self {
            bundle_indexes_per_sec: per_sec,
            ..self
        }
    }

    /// The records a second the relay signs whatever its feeders: its bundle indexes, and hosting
    /// MLAT its engine's last record of each form a step (`strikes::ENGINE_RECORDS_FIXED`).
    fn own_records_fixed(&self) -> u64 {
        (if self.indexes_by_rate {
            0
        } else {
            self.bundle_indexes_per_sec
        }) + if self.holds_raw {
            crate::strikes::ENGINE_RECORDS_FIXED
        } else {
            0
        }
    }

    /// What each class's store of what is taken holds before any feeder (`strikes::Class`): its
    /// ring of generations in every table it may take in (`strikes::Strikes::fixed_bytes`: the
    /// feeders' in each ingest shard's alone; the peers' and the relay's own in each ingest
    /// shard's, positions', clock models', fault proofs', what is passed on by hash, and feeder
    /// figures'), and its table of places in the shares as it is kept
    /// whatever it holds (`strikes::PLACES_FIXED_BYTES`). Beside them, in the peers' store, the
    /// one record a second the peers' share allows a relay whose members' rate plans none and the
    /// peers' places, twice as the peers may hold; in the relay's own, that record once, the
    /// records the relay signs whatever its load (`own_records_fixed`) over their life, and the
    /// relay's place with its counts (`strikes::place_bytes`).
    pub fn strike_tables_bytes(&self, class: crate::strikes::Class) -> usize {
        use crate::strikes::{Class, PLACES_FIXED_BYTES, PLANNED_ENTRY_BYTES, Strikes, Usable};
        let deadlines = crate::sharing::Deadlines::RELAY;
        let figures = Usable::figures(crate::strikes::relay_signed(deadlines));
        let batches = crate::exchange::SHARDS * Strikes::fixed_bytes(Usable::BATCHES);
        // Positions', clock models' and what is passed on by hash; fault proofs'; feeder figures'.
        let others = 3 * Strikes::fixed_bytes(Usable::relay_signed(deadlines))
            + Strikes::fixed_bytes(Usable::proofs(deadlines))
            + Strikes::fixed_bytes(figures);
        // The one record a second the peers' share allows a relay whose members' rate plans none
        // (`ingest::member_records_per_sec`), held as the members' unit holds theirs: twice as the
        // peers', once as the relay's own.
        let members = self.member_feeders as u64;
        let unplanned = crate::ingest::member_records_per_sec(self.member_feeders)
            .saturating_sub(members * crate::ingest::MEMBER_RECORDS_PER_FEEDER)
            as usize
            * peer_life_seconds() as usize
            * PLANNED_ENTRY_BYTES;
        match class {
            Class::Feeders => batches + PLACES_FIXED_BYTES,
            Class::Peers => {
                // The peers' places, as their share charges them (`strikes::PEER_PLACE_ENTRIES`
                // each, a place for each session on a link and one at least), twice as the peers
                // may hold.
                let places = 2 * self.peer_places() * crate::strikes::PEER_PLACE_ENTRIES;
                batches + others + PLACES_FIXED_BYTES + 2 * unplanned + places * PLANNED_ENTRY_BYTES
            }
            Class::Own => {
                let own = self.own_records_fixed() as usize
                    * own_life_seconds() as usize
                    * PLANNED_ENTRY_BYTES
                    // The bundle indexes the one record a second the members' rate is planned at
                    // when it plans none may bring, planned by the rate.
                    + if self.indexes_by_rate {
                        Self::indexes_bytes(
                            crate::ingest::member_records_per_sec(self.member_feeders)
                                .saturating_sub(members * crate::ingest::MEMBER_RECORDS_PER_FEEDER),
                        )
                    } else {
                        0
                    };
                let place = crate::strikes::place_bytes(Usable::BATCHES, figures);
                batches + others + PLACES_FIXED_BYTES + unplanned + own + place
            }
        }
    }

    /// The peers' places the peers' share holds (`strikes::Entries::peers`): one for each session
    /// that may deliver as a peer (`Origin::Peer`), which is every session on a link
    /// ([`Plan::fanout_listeners`]: those under the connection cap, the subscribers, each of whom
    /// may send a fault proof, and the member sessions), and one at least. Before, only the
    /// member sessions were planned, so on a relay with none a second subscriber's fault proof
    /// found no room for its place and was let go.
    fn peer_places(&self) -> usize {
        self.fanout_listeners().max(1)
    }

    /// The entries each kind of deliverer may hold (`strikes::Entries`), from what the plan
    /// carries at `admission`: a feeder's records a second over the longest a feeder's entry
    /// lives, and the feeders' together what the store holds for each connection admitted, half
    /// of it as they may hold twice their share, their places among their entries
    /// ([`feeder_share_entries`]; so feeders churning fresh keys fill the feeders' part of the
    /// store and no more); the members' records a second over a peer's copy's and the peers'
    /// places, the peers' share together; and
    /// the relay's own, its records for every feeder it admits and every feeder the members' rate
    /// is planned as, and whatever its load over theirs, its figures, and the
    /// members' records it rebuilds from parity over a peer's copy's. What the stores are planned
    /// at for each (`PerFeeder::strikes`, `Plan::member_unit`, `Plan::strike_tables_bytes`).
    pub fn strike_entries(&self, admission: &Admission) -> crate::strikes::Entries {
        let batches = crate::strikes::Usable::BATCHES;
        let members = crate::ingest::member_records_per_sec(self.member_feeders);
        // Its own records follow the feeders it holds, one share each, as the store holds them
        // (`PerFeeder::strikes` for each connection admitted, `Plan::member_unit` for each of
        // the members' feeders).
        let feeders = (admission.connections as u64).saturating_add(self.member_feeders as u64);
        // The bundle indexes, planned by the rate: those the records a second the groups take may
        // bring, `R_max`'s and the members' rate's.
        let indexes = if self.indexes_by_rate {
            admission
                .records_per_sec()
                .saturating_add(members)
                .saturating_mul(INDEXES_PER_RECORD)
        } else {
            0
        };
        let own = feeders
            .saturating_mul(crate::strikes::own_records_per_feeder(self.holds_raw))
            .saturating_add(self.own_records_fixed())
            .saturating_add(indexes);
        let entries = |count: u64| usize::try_from(count).unwrap_or(usize::MAX);
        let feeder = self
            .feeder_records_per_sec
            .saturating_mul(batches.feeder_life_seconds());
        crate::strikes::Entries {
            feeder: entries(feeder),
            // As the store holds them (`PerFeeder::strikes`): the rate the relay-wide rate admits
            // for each connection, not each feeder's own ceiling, its place among them.
            feeders: entries(
                feeder_share_entries(crate::cores::RECORDS_PER_PLANNED_FEEDER)
                    .saturating_mul(admission.connections as u64),
            ),
            peer: entries(members.saturating_mul(peer_life_seconds())),
            // The peers' together, their places among their entries.
            peers: entries(
                members.saturating_mul(peer_life_seconds()).saturating_add(
                    (self.peer_places() * crate::strikes::PEER_PLACE_ENTRIES) as u64,
                ),
            ),
            relay: entries(
                own.saturating_mul(own_life_seconds())
                    .saturating_add(members.saturating_mul(peer_life_seconds()))
                    .saturating_add(
                        feeders.saturating_mul(crate::strikes::FIGURES_HELD_PER_FEEDER),
                    ),
            ),
        }
    }

    /// The members' pool: their shared rate's worth.
    pub fn member_pool(&self) -> usize {
        self.member_rate_pool()
    }
}

/// What bound a figure of the plan (`tally-relay check` prints it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bound {
    /// The memory the plan holds for it.
    Memory,
    /// The cores: their sessions, receptions through the stages, or MLAT's steps.
    Cores,
    /// Nothing bound it (a plan without a cost for it, a test's).
    Unbounded,
    /// Not planned: MLAT is not hosted.
    NotHosted,
    /// The connections: a seat for every connection, and no more.
    Connections,
}

impl Bound {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Cores => "cores",
            Self::Unbounded => "unbounded",
            Self::NotHosted => "not-hosted",
            Self::Connections => "connections",
        }
    }
}

/// What a plan admits in the memory it is given (RFC-0181 §9, §10, "Admission"): one figure each
/// for the connections, the relay-wide rate and the MLAT seats, and what bound it. Derived by
/// [`Plan::admit`], the only place these are decided; the gauges' limits, the ingest rate
/// (`shed`), the stages' threads, MLAT's seats and `tally-relay check` all read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Admission {
    /// What a connection reserves when it is admitted (`Plan::per_feeder`, its floor).
    pub floor: usize,
    /// The feeder connections admitted at most: the fewer of [`Admission::connections_by_memory`]
    /// and [`Admission::connections_by_cores`].
    pub connections: usize,
    pub connections_by_memory: usize,
    pub connections_by_cores: Option<usize>,
    pub connections_bound: Bound,
    /// `R_max`, receptions a second the relay carries for its feeders (not its members'): the
    /// lesser of what the memory left after the floors holds and what the cores carry after the
    /// sessions and the seats.
    pub rate: u64,
    pub rate_by_memory: u64,
    pub rate_by_cores: Option<u64>,
    pub rate_bound: Bound,
    /// MLAT's seats, their own pool: planned from what the connections leave of the memory and the
    /// cores, no more than the connections.
    pub seats: usize,
    pub seats_by_memory: usize,
    pub seats_by_cores: Option<usize>,
    pub seats_bound: Bound,
}

impl Admission {
    /// `R_max` in bytes a second, as batches are charged (`ingest::charge_of`), at the planned
    /// mean's charged bytes to receptions: what every store holding a batch's decode or its bytes
    /// is sized from, and what the shedder judges a batch's bytes by, whatever a feeder puts in
    /// its batches (an inflated one is charged its inflated bytes).
    pub fn bytes_per_sec(&self) -> u64 {
        mul_div(
            self.rate,
            PLANNED_CHARGED_BYTES_PER_SEC as u128,
            PLANNED_RECEPTIONS_PER_SEC as u128,
        )
    }

    /// The records a second the relay-wide rate admits (`cores::RECORDS_PER_PLANNED_FEEDER`
    /// for each planned feeder's worth of it).
    pub fn records_per_sec(&self) -> u64 {
        mul_div(
            self.rate,
            u128::from(crate::cores::RECORDS_PER_PLANNED_FEEDER),
            PLANNED_RECEPTIONS_PER_SEC as u128,
        )
    }

    /// Feeders carried at the planned mean: `R_max` over a planned feeder's receptions.
    pub fn feeders_at_mean(&self) -> u64 {
        self.rate / PLANNED_RECEPTIONS_PER_SEC as u64
    }

    /// Feeders carried if every one sent at the ceiling a source is held to
    /// (`ingest::SOURCE_RECEPTIONS_PER_SEC`).
    pub fn feeders_at_ceiling(&self) -> u64 {
        self.rate
            .checked_div(crate::ingest::SOURCE_RECEPTIONS_PER_SEC)
            .unwrap_or(0)
    }
}

/// `a x b / c` without overflow, saturating at `u64::MAX`; `c` of nothing is nothing to divide by
/// (the result is `u64::MAX`).
fn mul_div(a: u64, b: u128, c: u128) -> u64 {
    (u128::from(a) * b)
        .checked_div(c)
        .map_or(u64::MAX, |value| u64::try_from(value).unwrap_or(u64::MAX))
}

/// The member sessions a relay taking `areas` plans (RFC-0174 §2.3, §2.5, §2.6): every one the
/// protocol lets its areas bring, at most `connections` (every session in or out holds a place
/// under the connection cap, `Hub::connection`, `Hub::dialled`). The protocol bounds a relay's
/// members by its plan, not the plan by the protocol: a relay taking coarse areas may share groups
/// with more relays than it can hold (122 base cells, up to `OFFERS_HELD`), and past its plan it
/// turns a member away with `Reason::Full` (`link::admit_member`), which the relay turned away
/// routes around, to the next members of the area's trees (`peers`, `sharing::member`). So a
/// member past the plan costs the area nothing but a hop. The sessions it plans:
///
/// - **Who shares an area with it.** An area's sharing groups are the relays whose live offers
///   cover it: offers for the area's cell and for each of its ancestors (`Directory::offers_for`),
///   at most `OFFERS_PER_CELL` a cell. A relay taking region `r` shares a group with whoever offers
///   a cell on the path above `r`, `r` itself, or any cell under `r` down to the area's resolution
///   (each such cell's offers cover an area under `r`); at most the directory's whole bound
///   (`OFFERS_HELD`). Each such relay may dial it once to send what its groups address it.
/// - **Its raw links, when it hosts MLAT.** For the areas it solves it dials every other relay that
///   offers their raw, one session for each `MAX_REGIONS` cells of the border band
///   (`selection::raw_sources`): at most the same relays, each that many times.
///
/// A relay taking no area shares no group, so it holds no member.
pub fn members_for(areas: &[tally_wire::Region], hosts_mlat: bool, connections: usize) -> usize {
    use crate::directory::{OFFERS_HELD, OFFERS_PER_CELL};
    use tally_wire::rendezvous::AREA_RESOLUTION;
    // The cells whose offers share a group with a relay taking `region`, at most.
    let covering = |region: &tally_wire::Region| -> usize {
        let resolution = region.resolution().min(AREA_RESOLUTION);
        // Its ancestors and itself, then every cell under it to the area's resolution (at most
        // seven children a cell).
        let below: usize = (1..=u32::from(AREA_RESOLUTION - resolution))
            .map(|depth| 7usize.pow(depth))
            .sum();
        usize::from(resolution) + 1 + below
    };
    let peers = areas
        .iter()
        .map(covering)
        .fold(0usize, usize::saturating_add)
        .saturating_mul(OFFERS_PER_CELL)
        .min(OFFERS_HELD);
    let raw_links = if hosts_mlat && !areas.is_empty() {
        tally_mlat::area::border_band(&tally_wire::Regions::new(areas.to_vec()))
            .cells()
            .len()
            .div_ceil(tally_wire::record::MAX_REGIONS)
    } else {
        0
    };
    peers.saturating_mul(1 + raw_links).min(connections)
}

/// The feeders a connection allowed `bytes_per_sec` is worth: its ceiling over a planned feeder's
/// rate, rounded up.
pub fn feeders_for_rate(bytes_per_sec: u64) -> usize {
    usize::try_from(bytes_per_sec)
        .unwrap_or(usize::MAX)
        .div_ceil(PLANNED_BYTES_PER_SEC)
        .max(1)
}

/// The memory this relay runs in: the least of its cgroup's `memory.high` (past which the kernel
/// throttles it) and `memory.max` (past which it kills it), its own cgroup's and every ancestor's,
/// when any is a number; else the host's memory. The budget is this less its headroom
/// ([`budget_within`], [`headroom_for`]).
pub fn memory_available() -> usize {
    cgroup_limit()
        .or_else(host_memory)
        .unwrap_or(BASE_BYTES * 4)
}

/// What the relay holds that no store charges and no base plans, whatever its load: the threads'
/// stacks, the kernel's socket buffers (charged to the relay's cgroup), the binary's own pages.
/// Measured under 10 MiB at the public relay's shape (RFC-0181, "Sizing"); held at 64 MiB. The
/// allocator's free pages are apart ([`ALLOCATOR_PERCENT`]): they grow with what the relay holds.
pub const HEADROOM_BYTES: usize = 64 << 20;

/// The arenas glibc's allocator may keep (`M_ARENA_MAX`, [`bound_the_allocator`]). Each arena
/// keeps the pages its threads freed for its own reuse, so what the allocator holds beyond what
/// is live grows with the arenas, and glibc makes up to eight a core: at 2,000 feeders hosting MLAT
/// on 16 cores it held up to 1.9 GB beside the 5.2 GB the stores were charged. Eight:
/// four held a fifth less but stood the stages' threads in line for them (raw's p90 29 to 35 ms
/// against 11 to 19 with eight or with glibc's own count; RFC-0181, "MLAT and the allocator").
pub const MALLOC_ARENAS: i32 = 8;

/// What the allocator keeps for reuse beside what is live, as a percent of what it serves the plan
/// (the relay's base and every store), for a relay small enough that this is the lesser of the two
/// bounds on its share ([`ALLOCATOR_CAP_BYTES`]). Measured with [`MALLOC_ARENAS`] (2026-10-09,
/// 2,000 feeders hosting MLAT, `tally-load`): resident less the base and every store's charge at
/// most 973 MiB over 5,452 MiB planned in use, 17.8%, with the base then 256 MiB and the pool.
/// Against the measured base since ([`BASE_BYTES`], 220 MiB less), the same run is 1,193 MiB
/// beyond over 5,232 MiB planned, 22.8% ([`MEASURED_ALLOCATOR_PERCENT`]); planned at 25.
pub const ALLOCATOR_PERCENT: usize = 25;

/// The share measured ([`ALLOCATOR_PERCENT`]) against [`BASE_BYTES`], rounded up, which the plan
/// must hold.
pub const MEASURED_ALLOCATOR_PERCENT: usize = 23;
const _: () = assert!(ALLOCATOR_PERCENT >= MEASURED_ALLOCATOR_PERCENT);

/// What one glibc arena keeps free for its own reuse at most, in a relay hosting MLAT (RFC-0181,
/// "Admission", "The allocator's share"). Read off a running relay: `GET /memory` serves
/// `mallinfo2` (`allocator.free`, bytes freed and kept in the arenas, and `allocator.in_use`),
/// sampled every five seconds under `tally-load`, the relay on cores 0-9 and the harness on 10-31.
/// The free bytes came to 2,037 MiB over the eight arenas at 2,000 feeders hosting MLAT (255 MiB an
/// arena; in use 1.6 to 2.6 GiB, so the free pages were the larger half of the arenas), and the
/// 2,000-feeder runs measured before `GET /memory` served it left 2.2 to 2.4 GiB resident beyond
/// what the stores were charged (about 290 MiB an arena); at 5,000 feeders without MLAT 612 MiB
/// (77 MiB an arena). It follows the arenas, not the plan: the same ~2 GiB sat free after a run that
/// MLAT shed to 392 seats as after one that solved all 2,000. Planned at 320 MiB.
pub const ARENA_RETENTION_BYTES: usize = 320 << 20;

/// The most the allocator's free pages come to, whatever the plan: [`MALLOC_ARENAS`] arenas of
/// [`ARENA_RETENTION_BYTES`] each. Before, the share was a quarter of the plan at any size, which
/// reserved 6.9 GB of a 32 GB relay for pages the measurement says never pass 2.6 GiB.
pub const ALLOCATOR_CAP_BYTES: usize = MALLOC_ARENAS as usize * ARENA_RETENTION_BYTES;

/// The size above which glibc serves an allocation by `mmap` and hands it back on free, fixed so
/// glibc does not raise it as large blocks are freed (it does, up to 32 MiB, until a trim
/// threshold is set): a block this size or larger never joins an arena's free pages.
pub const MMAP_THRESHOLD_BYTES: i32 = 4 << 20;

/// The free space at the top of an arena above which a free gives it back to the kernel at once
/// (`M_TRIM_THRESHOLD`). Glibc's own is 128 KiB until a large free raises it; fixed here so a
/// burst of frees cannot leave an arena holding hundreds of MiB at its top. Free pages inside an
/// arena, below its top, are not reached by this: [`TRIM_PERIOD`] returns those.
pub const TRIM_THRESHOLD_BYTES: i32 = 16 << 20;

/// How often the trimmer thread ([`spawn_allocator_trimmer`]) returns the arenas' interior free
/// pages to the kernel. Nothing waits for it: no stage calls it, and a trim runs on a thread of
/// its own, so the bound on what the allocator keeps does not depend on any hot path.
pub const TRIM_PERIOD: std::time::Duration = std::time::Duration::from_secs(5);

/// Trims taken, the slowest and the latest, in microseconds (`GET /memory`, `allocator`). A trim
/// holds one arena's lock at a time while it walks it, so the slowest bounds how long a stage
/// could have waited on an allocation (RFC-0181, "MLAT and the allocator").
static TRIMS: AtomicU64 = AtomicU64::new(0);
static TRIM_MAX_US: AtomicU64 = AtomicU64::new(0);
static TRIM_LAST_US: AtomicU64 = AtomicU64::new(0);

/// Bounds what the allocator keeps: glibc's arenas capped at [`MALLOC_ARENAS`],
/// and its thresholds fixed ([`MMAP_THRESHOLD_BYTES`], [`TRIM_THRESHOLD_BYTES`]), set before any
/// thread starts, so the pages it keeps for reuse stay within the share the plan holds for them
/// ([`ALLOCATOR_PERCENT`]). What it keeps below an arena's top is returned by
/// [`spawn_allocator_trimmer`]. Nothing trims on a hot path: before, a thread called
/// `malloc_trim(0)` after each window step, which stood every stage's thread in line for seconds;
/// without any trim, glibc's arenas kept up to 1.9 GB beside what was live at 2,000 feeders, which
/// the 64 MiB headroom was documented to cover and did not. Elsewhere than glibc, nothing.
pub fn bound_the_allocator() {
    crate::os::set_allocator(MALLOC_ARENAS, MMAP_THRESHOLD_BYTES, TRIM_THRESHOLD_BYTES);
}

/// Returns every arena's free pages to the kernel (`malloc_trim(0)`), once, and records how long
/// it took. Called only by the trimmer thread, never by a stage.
pub fn trim_the_allocator() -> std::time::Duration {
    let began = std::time::Instant::now();
    crate::os::trim_allocator();
    let took = began.elapsed();
    let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
    TRIMS.fetch_add(1, Ordering::Relaxed);
    TRIM_LAST_US.store(micros, Ordering::Relaxed);
    TRIM_MAX_US.fetch_max(micros, Ordering::Relaxed);
    took
}

/// Starts the thread that trims the allocator every `period` ([`TRIM_PERIOD`] in the relay):
/// what the arenas keep free below their tops is bounded by what is freed in one period, not by
/// the run's history. Its own thread, at the lowest priority, off every stage.
pub fn spawn_allocator_trimmer(period: std::time::Duration) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("tally-malloc-trim".into())
        .spawn(move || {
            let _ = crate::os::run_at_lowest();
            loop {
                std::thread::sleep(period);
                trim_the_allocator();
            }
        })
        .map(drop)
}

/// What the allocator holds now (`os::allocator_holdings`, every arena): the bytes in use, the bytes it has
/// taken from the kernel and keeps free for reuse, and what it maps apart. Served on `GET
/// /memory`, so the allocator's share of the plan ([`ALLOCATOR_PERCENT`]) is read off a running
/// relay rather than guessed: resident memory is these and what no allocation holds (stacks, the
/// binary, the kernel's socket buffers).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct AllocatorReport {
    /// Bytes allocated and not freed (`uordblks`).
    pub in_use: u64,
    /// Bytes freed and kept in the arenas for reuse (`fordblks`).
    pub free: u64,
    /// Bytes served by `mmap` apart from the arenas (`hblkhd`).
    pub mapped: u64,
    /// Bytes the arenas took from the kernel (`arena`).
    pub arenas: u64,
    /// Trims the trimmer thread has taken ([`spawn_allocator_trimmer`]).
    pub trims: u64,
    /// The slowest trim and the latest, in microseconds: what a stage's allocation could wait.
    pub trim_max_us: u64,
    pub trim_last_us: u64,
}

/// The allocator's holdings now ([`AllocatorReport`]); zeros where the allocator is not glibc's.
pub fn allocator_report() -> AllocatorReport {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let [in_use, free, mapped, arenas] = crate::os::allocator_holdings();
        AllocatorReport {
            in_use,
            free,
            mapped,
            arenas,
            trims: TRIMS.load(Ordering::Relaxed),
            trim_max_us: TRIM_MAX_US.load(Ordering::Relaxed),
            trim_last_us: TRIM_LAST_US.load(Ordering::Relaxed),
        }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    AllocatorReport::default()
}

/// The allocator's share of a relay planning `planned` bytes (its base and its stores): the
/// lesser of [`ALLOCATOR_PERCENT`] of it and [`ALLOCATOR_CAP_BYTES`].
pub fn allocator_share(planned: usize) -> usize {
    (planned.saturating_mul(ALLOCATOR_PERCENT) / 100).min(ALLOCATOR_CAP_BYTES)
}

/// What a relay planning `planned` bytes (its base and its stores) keeps below the memory it runs
/// in: [`HEADROOM_BYTES`] and the allocator's share ([`allocator_share`]). A relay holding its
/// whole plan is still within the memory it runs in.
pub fn headroom_for(planned: usize) -> usize {
    HEADROOM_BYTES.saturating_add(allocator_share(planned))
}

/// The budget of a relay that runs in `limit` bytes ([`memory_available`]): the most whose
/// headroom ([`headroom_for`]) still fits beside it.
pub fn budget_within(limit: usize) -> usize {
    let room = limit.saturating_sub(HEADROOM_BYTES);
    // Where a quarter of the budget is the share; else the cap.
    let proportional = room.saturating_mul(100) / (100 + ALLOCATOR_PERCENT);
    if proportional.saturating_mul(ALLOCATOR_PERCENT) / 100 <= ALLOCATOR_CAP_BYTES {
        proportional
    } else {
        room.saturating_sub(ALLOCATOR_CAP_BYTES)
    }
}

/// The least of cgroup v2's `memory.high` and `memory.max` over this process's cgroup and its
/// ancestors, where any is a number (`max` is none).
fn cgroup_limit() -> Option<usize> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim();
    let mut least: Option<usize> = None;
    let mut dir = std::path::PathBuf::from(format!("/sys/fs/cgroup{path}"));
    loop {
        for file in ["memory.high", "memory.max"] {
            if let Some(bytes) = std::fs::read_to_string(dir.join(file))
                .ok()
                .and_then(|text| text.trim().parse::<usize>().ok())
            {
                least = Some(least.map_or(bytes, |least| least.min(bytes)));
            }
        }
        if dir == std::path::Path::new("/sys/fs/cgroup") || !dir.pop() {
            return least;
        }
    }
}

/// `MemTotal` of `/proc/meminfo`.
fn host_memory() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib: usize = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

/// One store's bytes held now, against its limit (its share of the budget at the ceiling).
#[derive(Debug)]
pub struct Gauge {
    store: Store,
    limit: AtomicUsize,
    held: AtomicUsize,
    peak: AtomicUsize,
    /// Charges refused for room (`try_charge`), and charges that waited for it (`charge`).
    refused: AtomicU64,
    waited: AtomicU64,
    /// Charges waiting for room now (those abandoned by a dropped waiter are counted until the
    /// next release sweeps them): a release serves them only when there are any.
    waiting: AtomicUsize,
    /// Who waits for room, by source, served in turn ([`Gauge::charge_for`]).
    queue: Mutex<Queue>,
    /// The shares of this store a part splits it into ([`Gauge::share`]), each with the rule its
    /// limit follows from this one's: set again whenever this one is (`Budget::resize`).
    shares: Mutex<Vec<(Weak<Gauge>, Share)>>,
}

/// How a share's limit follows from its store's ([`Gauge::share`]).
pub type Share = fn(usize) -> usize;

impl Gauge {
    pub fn new(store: Store, limit: usize) -> Arc<Self> {
        Arc::new(Self {
            store,
            limit: AtomicUsize::new(limit),
            held: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            refused: AtomicU64::new(0),
            waited: AtomicU64::new(0),
            waiting: AtomicUsize::new(0),
            queue: Mutex::new(Queue::default()),
            shares: Mutex::new(Vec::new()),
        })
    }

    /// A share of this store, its limit `part` of this one's, now and after every resize: for a
    /// part that splits its store between what it holds (the pace maps' entries, the products'
    /// peers' records), so a share never stays the size the store was when the part was built.
    /// What is charged to a share is charged to the store too, by its holder.
    pub fn share(self: &Arc<Self>, part: Share) -> Arc<Self> {
        let share = Self::new(self.store, part(self.limit()));
        if let Ok(mut shares) = self.shares.lock() {
            shares.retain(|(held, _)| held.strong_count() > 0);
            shares.push((Arc::downgrade(&share), part));
        }
        share
    }

    /// A gauge of no store, never full: for a part built without a budget (a test's).
    pub fn unlimited(store: Store) -> Arc<Self> {
        Self::new(store, usize::MAX)
    }

    pub fn store(&self) -> Store {
        self.store
    }

    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    fn set_limit(self: &Arc<Self>, limit: usize) {
        self.limit.store(limit, Ordering::Release);
        if self.waiting.load(Ordering::SeqCst) > 0 {
            self.serve();
        }
        let shares = self
            .shares
            .lock()
            .map(|shares| shares.clone())
            .unwrap_or_default();
        for (share, part) in shares {
            if let Some(share) = share.upgrade() {
                share.set_limit(part(limit));
            }
        }
    }

    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn waited(&self) -> u64 {
        self.waited.load(Ordering::Relaxed)
    }

    /// Takes `bytes` if they fit under the limit. A charge larger than the whole limit is taken
    /// only while nothing else is held, so one oversized item is never refused forever.
    fn take(self: &Arc<Self>, bytes: usize) -> Option<Charge> {
        let limit = self.limit();
        let taken = self
            .held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                let after = held.checked_add(bytes)?;
                (after <= limit || held == 0).then_some(after)
            })
            .ok()?;
        self.peak.fetch_max(taken + bytes, Ordering::Relaxed);
        Some(Charge {
            gauge: Some(Arc::clone(self)),
            bytes,
        })
    }

    /// A charge of nothing yet on this gauge, to grow (`Charge::try_grow`).
    pub fn empty(self: &Arc<Self>) -> Charge {
        Charge {
            gauge: Some(Arc::clone(self)),
            bytes: 0,
        }
    }

    /// Whether `bytes` more would fit now.
    pub fn fits(&self, bytes: usize) -> bool {
        self.held().saturating_add(bytes) <= self.limit()
    }

    /// `bytes` charged now, or `None` (counted) when the store is full: for a store that refuses
    /// whole.
    pub fn try_charge(self: &Arc<Self>, bytes: usize) -> Option<Charge> {
        let charge = self.take(bytes);
        if charge.is_none() {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        charge
    }

    /// `bytes` charged for `source`, waiting for room while the store is full. Waiters are served
    /// in turn by source, not by who wakes first: each source with a waiter takes its turn in
    /// arrival order, and in its turn is served up to a quantum of bytes (deficit round robin),
    /// so one source with a thousand batches waiting gets a thousandth of a turn's room per
    /// batch while another's one batch is served in its turn. Before, a release woke every
    /// waiter and the race winner took the room (RFC-0181 §10, "Admission"). A newcomer joins the
    /// queue while anyone waits; it never takes room ahead of them.
    pub async fn charge_for(self: &Arc<Self>, source: u64, bytes: usize) -> Charge {
        loop {
            let granted = {
                let mut queue = self
                    .queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if queue.order.is_empty()
                    && let Some(charge) = self.take(bytes)
                {
                    return charge;
                }
                let (grant, granted) = oneshot::channel();
                let turn = queue.turns.entry(source).or_insert_with(|| Turn {
                    waiters: VecDeque::new(),
                    deficit: 0,
                });
                let first = turn.waiters.is_empty();
                turn.waiters.push_back(Waiter { bytes, grant });
                if first {
                    queue.order.push_back(source);
                }
                self.waited.fetch_add(1, Ordering::Relaxed);
                self.waiting.fetch_add(1, Ordering::SeqCst);
                granted
            };
            // Room that came between the failed look and the enqueue is served now.
            self.serve();
            if let Ok(charge) = granted.await {
                return charge;
            }
        }
    }

    /// Serves the waiters in turn while there is room (deficit round robin over sources). The
    /// charges a waiter that has gone cannot take are let go after the queue is unlocked, their
    /// release serving again.
    fn serve(self: &Arc<Self>) {
        let mut undelivered = Vec::new();
        {
            let mut queue = self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            'sources: while let Some(&source) = queue.order.front() {
                if !queue.fresh {
                    if let Some(turn) = queue.turns.get_mut(&source) {
                        turn.deficit = turn.deficit.saturating_add(DRR_QUANTUM);
                    }
                    queue.fresh = true;
                }
                while let Some(turn) = queue.turns.get_mut(&source) {
                    while turn
                        .waiters
                        .front()
                        .is_some_and(|waiter| waiter.grant.is_closed())
                    {
                        turn.waiters.pop_front();
                        self.waiting.fetch_sub(1, Ordering::SeqCst);
                    }
                    let Some(head) = turn.waiters.front() else {
                        break;
                    };
                    if head.bytes > turn.deficit {
                        break;
                    }
                    // No room for the one whose turn it is: nobody behind it takes it. Its turn
                    // (and its quantum, already given) resumes at the next release.
                    let Some(charge) = self.take(head.bytes) else {
                        break 'sources;
                    };
                    turn.deficit -= head.bytes;
                    if let Some(waiter) = turn.waiters.pop_front() {
                        self.waiting.fetch_sub(1, Ordering::SeqCst);
                        if let Err(charge) = waiter.grant.send(charge) {
                            undelivered.push(charge);
                        }
                    }
                }
                // Its turn is over: it goes to the back with what it has not spent, or leaves.
                queue.order.pop_front();
                let empty = queue
                    .turns
                    .get(&source)
                    .is_none_or(|turn| turn.waiters.is_empty());
                if empty {
                    queue.turns.remove(&source);
                } else {
                    queue.order.push_back(source);
                }
                queue.fresh = false;
            }
        }
        drop(undelivered);
    }

    fn release(self: &Arc<Self>, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::SeqCst);
        // A waiter counts itself before it looks for room (all sequentially consistent), so a
        // release its look missed sees it waiting.
        if self.waiting.load(Ordering::SeqCst) > 0 {
            self.serve();
        }
    }

    /// Charges waiting for room now.
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    pub fn report(&self) -> GaugeReport {
        GaugeReport {
            store: self.store,
            held: self.held(),
            limit: self.limit(),
            peak: self.peak(),
            refused: self.refused(),
            waited: self.waited(),
        }
    }
}

/// A charge waiting for room: its bytes and where its charge is delivered.
#[derive(Debug)]
struct Waiter {
    bytes: usize,
    grant: oneshot::Sender<Charge>,
}

/// One source's waiters and what it has not yet spent of its turns (deficit round robin).
#[derive(Debug)]
struct Turn {
    waiters: VecDeque<Waiter>,
    deficit: usize,
}

/// Who waits on a gauge: the sources in the order their turns come, each with its waiters.
#[derive(Debug, Default)]
struct Queue {
    turns: BTreeMap<u64, Turn>,
    order: VecDeque<u64>,
    /// The source at the front of `order` has had its quantum for this turn.
    fresh: bool,
}

/// The bytes a source is given each turn of a gauge's waiters ([`Gauge::charge_for`]): about
/// a planned batch's charge, so a source of planned batches is served about one in its turn.
pub const DRR_QUANTUM: usize = 128 << 10;

/// Bytes a store holds for one thing, released when it is dropped.
#[derive(Debug, Default)]
pub struct Charge {
    gauge: Option<Arc<Gauge>>,
    bytes: usize,
}

/// Every decoded batch alive and the charge made for it (RFC-0181, "Memory is charged once, for
/// its life"): a decode is charged once, by the ingest stage that made it, inside its own shared
/// allocation (`tally_wire::Decoded::from_verified_owned`), and that charge goes when the decode's
/// last holder lets it go. So each decode alive has exactly one charge, of exactly its footprint,
/// however many stores hold it; what [`Budget::decoded_held`] sets beside the decodes alive
/// (`tally_wire::decoded::live`). One a process ([`Covered::process`]), as the decodes alive are
/// counted once a process.
///
/// Before, every store that held a decode charged it, in full or by its slices' shares (the
/// epochs, every subscriber queue's item, MLAT's notes and orphans, the ingest allowance until the
/// epochs took it), and this checked only that the charges were at least the footprint: one
/// decode held by four stores was charged four times, and over-charging was invisible by
/// construction. Equality is the check now: a decode charged twice shows as surely as one charged
/// never.
///
/// A decode is entered when its charge is made, before it is counted alive, and leaves when it
/// is let go, after it stops being counted (`tally_wire::decoded::on_drop`), so with every shard
/// locked a decode `live` counts and this does not is one alive with no charge. Sharded by the
/// decode's address so the stages' threads seldom meet on a lock.
///
/// It also judges every charge as it is made and every decode as it goes: a decode charged a
/// second time while it lives, and a decode let go that was never charged, are each counted there
/// and then ([`Covered::lapses`]), so a lapse between two samples of a watch is seen all the same.
pub struct Covered {
    shards: [Mutex<BTreeMap<usize, CoverEntry>>; COVER_SHARDS],
    /// Charges made for a decode that already had one.
    charged_twice: AtomicU64,
    /// Decodes let go that no charge had ever been made for.
    never_covered: AtomicU64,
}

/// What [`Covered`] counted as charges were made and decodes let go, since the process started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lapses {
    /// A decode charged again while it lived: held once, charged twice.
    pub charged_twice: u64,
    /// A decode alive and let go with no charge ever made for it.
    pub never_covered: u64,
}

const COVER_SHARDS: usize = 64;

static COVERED: Covered = Covered::new();

#[derive(Debug)]
struct CoverEntry {
    /// The charges made for it: one, unless it was charged twice.
    charges: usize,
    /// What they hold for it together.
    charged: usize,
    /// Its footprint, read when it was charged: what it counts for while it is alive.
    footprint: usize,
}

impl std::fmt::Debug for Covered {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Covered")
    }
}

impl Covered {
    const fn new() -> Self {
        Self {
            shards: [const { Mutex::new(BTreeMap::new()) }; COVER_SHARDS],
            charged_twice: AtomicU64::new(0),
            never_covered: AtomicU64::new(0),
        }
    }

    /// What was counted as it happened, since the process started.
    pub fn lapses(&self) -> Lapses {
        Lapses {
            charged_twice: self.charged_twice.load(Ordering::Relaxed),
            never_covered: self.never_covered.load(Ordering::Relaxed),
        }
    }

    /// The process's: every decode's charge ([`Covered::own`]). Told each decode as it leaves
    /// `tally_wire::decoded::live` ([`Covered::gone`]).
    pub fn process() -> &'static Self {
        static TOLD: std::sync::Once = std::sync::Once::new();
        TOLD.call_once(|| {
            tally_wire::decoded::on_drop(|address| COVERED.gone(address));
        });
        &COVERED
    }

    /// `decoded` was charged `charged` bytes for its life, by the charge inside it: called once
    /// it is shared and before it is counted alive (`Decoded::from_verified_owned`'s `held`). A
    /// second charge for a decode that has one is counted ([`Lapses::charged_twice`]).
    pub fn own(&self, decoded: &Arc<tally_wire::Decoded>, charged: usize) {
        let address = Arc::as_ptr(decoded) as usize;
        let mut shard = self.shard(address);
        match shard.get_mut(&address) {
            Some(entry) => {
                entry.charges += 1;
                entry.charged += charged;
                self.charged_twice.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                shard.insert(
                    address,
                    CoverEntry {
                        charges: 1,
                        charged,
                        footprint: decoded.footprint(),
                    },
                );
            }
        }
    }

    /// The decode at `address` was let go and `live` no longer counts it: its entry goes, and its
    /// charge with it as the decode's fields are dropped.
    fn gone(&self, address: usize) {
        if self.shard(address).remove(&address).is_none() {
            self.never_covered.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn shard(&self, address: usize) -> std::sync::MutexGuard<'_, BTreeMap<usize, CoverEntry>> {
        // Allocations are at least 16-byte aligned: the bits above those spread them.
        self.shards[(address >> 4) % COVER_SHARDS]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The bytes charged for `decoded`, together.
    pub fn charged_for(&self, decoded: &Arc<tally_wire::Decoded>) -> usize {
        let address = Arc::as_ptr(decoded) as usize;
        self.shard(address)
            .get(&address)
            .map_or(0, |entry| entry.charged)
    }

    /// How many charges were made for `decoded` while it lives: one, for a decode charged once.
    pub fn charges_of(&self, decoded: &Arc<tally_wire::Decoded>) -> usize {
        let address = Arc::as_ptr(decoded) as usize;
        self.shard(address)
            .get(&address)
            .map_or(0, |entry| entry.charges)
    }

    /// The decoded batches alive charged other than once for exactly their footprint, and the
    /// bytes their charges are off by: a decode charged a byte, or charged twice, is held where the
    /// plan does not say it is.
    pub fn inexact(&self) -> (usize, usize) {
        self.inexact_decodes()
            .iter()
            .fold((0, 0), |(batches, bytes), (_, off)| {
                (batches + 1, bytes + off)
            })
    }

    /// The same, each by its address (which is its own while it is alive) and what its charges
    /// are off by.
    pub fn inexact_decodes(&self) -> Vec<(usize, usize)> {
        let mut inexact = Vec::new();
        for shard in &self.shards {
            let shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (address, entry) in shard.iter() {
                if entry.charges != 1 || entry.charged != entry.footprint {
                    inexact.push((*address, entry.charged.abs_diff(entry.footprint)));
                }
            }
        }
        inexact
    }

    /// The decoded batches charged, each once, and the bytes they hold (`Decoded::footprint`),
    /// beside `live` (the decodes alive, `tally_wire::decoded::live`) read at the same instant:
    /// every shard locked while both are read. A decode is entered before it is counted alive and
    /// leaves after it stops being counted, so with every lock held a decode `live` counts and
    /// none was charged for is one alive uncharged; one caught between the two counts as charged
    /// for that instant.
    pub fn with_live(
        &self,
        live: impl FnOnce() -> (usize, usize),
    ) -> ((usize, usize), (usize, usize)) {
        let shards: Vec<_> = self
            .shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            })
            .collect();
        let live = live();
        let (mut batches, mut bytes) = (0, 0);
        for shard in &shards {
            for entry in shard.values() {
                batches += 1;
                bytes += entry.footprint;
            }
        }
        ((batches, bytes), live)
    }

    /// The decoded batches charged, each once, and the bytes they hold.
    pub fn now(&self) -> (usize, usize) {
        self.with_live(|| (0, 0)).0
    }
}

impl Charge {
    /// Nothing charged.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether `bytes` more would fit on its gauge now (a charge of nothing fits only nothing).
    pub fn fits(&self, bytes: usize) -> bool {
        self.gauge
            .as_ref()
            .map_or(bytes == 0, |gauge| gauge.fits(bytes))
    }

    /// `bytes` more on the same gauge, if they fit (a charge of nothing never grows): false,
    /// counted, when the store is full.
    pub fn try_grow(&mut self, bytes: usize) -> bool {
        let Some(gauge) = &self.gauge else {
            return bytes == 0;
        };
        match gauge.try_charge(bytes) {
            Some(mut more) => {
                more.gauge = None;
                self.bytes += more.bytes;
                true
            }
            None => false,
        }
    }

    /// `bytes` of this charge (all of it, if it holds less) moved into a charge of their own on the
    /// same gauge, nothing taken or released: what a store hands on with the thing it holds (open
    /// raw handed to its seal, bytes going back).
    pub fn split(&mut self, bytes: usize) -> Charge {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        Charge {
            gauge: self.gauge.clone(),
            bytes,
        }
    }

    /// Releases all but `bytes` of this charge.
    pub fn shrink_to(&mut self, bytes: usize) {
        if let Some(gauge) = &self.gauge
            && bytes < self.bytes
        {
            gauge.release(self.bytes - bytes);
            self.bytes = bytes;
        }
    }
}

/// Charges handed on as one (`exchange`'s epoch parts, gathered across message threads): kept
/// apart from the charge's other calls, it moves bytes, taking and releasing nothing.
impl Charge {
    /// `other`'s bytes moved into this charge, nothing taken or released, when both are on one
    /// gauge (or this one holds nothing on any); `other` back, untouched, when they are not.
    pub fn absorb(&mut self, mut other: Charge) -> Result<(), Charge> {
        let same = match (&self.gauge, &other.gauge) {
            (_, None) => true,
            (None, Some(_)) => self.bytes == 0,
            (Some(mine), Some(theirs)) => Arc::ptr_eq(mine, theirs),
        };
        if !same {
            return Err(other);
        }
        if self.gauge.is_none() {
            self.gauge = other.gauge.clone();
        }
        self.bytes += other.bytes;
        other.bytes = 0;
        other.gauge = None;
        Ok(())
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        if let Some(gauge) = self.gauge.take() {
            gauge.release(self.bytes);
        }
    }
}

/// One store as served on `GET /memory`.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct GaugeReport {
    pub store: Store,
    pub held: usize,
    pub limit: usize,
    pub peak: usize,
    pub refused: u64,
    pub waited: u64,
}

/// The relay's budget: its base, the feeders' room and the members' pool, how much of each the
/// admitted hold, and each store's gauge.
#[derive(Debug)]
pub struct Budget {
    memory: usize,
    /// What it was planned by, whole: its base, each feeder's cost, its members, its sessions, its
    /// cores. Held as the one `Plan`, never field by field beside it, so a part the plan gains is
    /// the budget's too. Before, the budget copied each field, and a field added to the plan and
    /// not copied was planned in `check` and lost in the relay.
    plan: Plan,
    /// The bytes feeders reserve from: the budget less what it holds before any feeder
    /// (`Plan::before_feeders`).
    total: usize,
    reserved: Arc<AtomicUsize>,
    /// The member sessions admitted, of those planned (`Plan::members`).
    members_reserved: Arc<AtomicUsize>,
    gauges: Arc<[Arc<Gauge>]>,
    /// Every connection's Noise buffers but a feeder's (`Plan::connection_buffers`).
    connection_buffers: Arc<Gauge>,
    /// What waits for the member links this relay dials (`Plan::member_links`).
    member_links: Arc<Gauge>,
    /// The parities being reassembled (`Plan::parity_assembly`).
    parity_assembly: Arc<Gauge>,
    /// The pace maps' entries' share of `Store::Paces` (`ingest::pace_entries_part`).
    pace_entries: Arc<Gauge>,
}

impl Budget {
    /// The budget of a relay that may use `memory` bytes: what is left after its base, its
    /// members' pool taken first.
    pub fn of_memory(memory: usize, plan: Plan) -> Self {
        let mut budget = Self::new(0, plan.per_feeder);
        budget.resize(memory, plan);
        budget
    }

    /// A budget of `total` bytes for feeders, above a base of `BASE_BYTES`, holding no member.
    pub fn new(total: usize, per_feeder: PerFeeder) -> Self {
        let gauges: Arc<[Arc<Gauge>]> = Store::ALL
            .iter()
            .map(|store| Gauge::new(*store, 0))
            .collect();
        let pace_entries = gauges[Store::Paces.index()].share(crate::ingest::pace_entries_part);
        let budget = Self {
            memory: total.saturating_add(BASE_BYTES),
            plan: Plan {
                base: BASE_BYTES,
                per_feeder,
                per_rate: PerFeeder::default(),
                per_seat: PerFeeder::default(),
                ..Plan::planned(false)
            },
            total,
            reserved: Arc::new(AtomicUsize::new(0)),
            members_reserved: Arc::new(AtomicUsize::new(0)),
            gauges,
            connection_buffers: Gauge::new(Store::Buffers, 0),
            member_links: Gauge::new(Store::Batches, 0),
            parity_assembly: Gauge::new(Store::Batches, 0),
            pace_entries,
        };
        budget.limit_gauges();
        budget
    }

    /// The same gauges (whoever holds one keeps it), resized for `memory` bytes and `plan`: what a
    /// relay is told after its parts were built.
    pub fn resize(&mut self, memory: usize, plan: Plan) {
        let plan = plan.with_cheaper_indexes(memory);
        self.memory = memory;
        self.plan = plan;
        self.total = memory.saturating_sub(plan.before_feeders());
        self.limit_gauges();
    }

    fn limit_gauges(&self) {
        for store in Store::ALL {
            self.gauges[store.index()].set_limit(self.store_bytes(store));
        }
        let plan = self.plan();
        self.connection_buffers.set_limit(plan.connection_buffers());
        self.member_links.set_limit(plan.member_links());
        self.parity_assembly.set_limit(plan.parity_assembly());
    }

    /// The room every connection but a feeder's carves its Noise buffers from: the same gauge for
    /// the budget's life, sized to the connection cap.
    pub fn connection_buffers(&self) -> Arc<Gauge> {
        Arc::clone(&self.connection_buffers)
    }

    /// A pace map's room (`ingest::PaceRoom`): charged to `Store::Paces` and to its entries'
    /// share, which every map shares, so the maps together leave the connections' own paces their
    /// room.
    pub fn pace_room(&self) -> crate::ingest::PaceRoom {
        crate::ingest::PaceRoom::within(&self.gauge(Store::Paces), &self.pace_entries)
    }

    /// The pace maps' entries' share of `Store::Paces`.
    pub fn pace_entries(&self) -> Arc<Gauge> {
        Arc::clone(&self.pace_entries)
    }

    /// The room what waits for the member links comes from, each link's share charged to it too
    /// (`peers`): the same gauge for the budget's life, sized to the member sessions planned.
    pub fn member_links(&self) -> Arc<Gauge> {
        Arc::clone(&self.member_links)
    }

    /// The room parities are reassembled in (`sharing`), apart from the batch store: the same gauge
    /// for the budget's life, sized to the members' shared rate (`Plan::parity_assembly`).
    pub fn parity_assembly(&self) -> Arc<Gauge> {
        Arc::clone(&self.parity_assembly)
    }

    /// The plan this budget was sized from.
    pub fn plan(&self) -> Plan {
        self.plan
    }

    /// What the plan admits in this budget's memory ([`Plan::admit`]): the connections, `R_max`
    /// and the MLAT seats, each with what bound it.
    pub fn admission(&self) -> Admission {
        self.plan.admit(self.total)
    }

    /// Whether the budget holds its members' pool and a connection beside it, and the cores
    /// carry one: a relay that would refuse every Hello, or hold fewer members than it was told,
    /// refuses to start instead, saying what it was given and what it needs.
    pub fn check(&self) -> Result<(), String> {
        let plan = self.plan();
        let admission = self.admission();
        if let Some(cores) = plan.cores {
            let available = crate::cores::available_nanos(
                cores,
                plan.holds_raw,
                plan.member_feeders,
                plan.sessions,
            );
            if crate::cores::connections_carried(available, plan.holds_raw, 0) == 0 {
                return Err(format!(
                    "{cores} cores carry no feeder beside the {} feeders its members' shared rate is \
                     worth (--max-member-bytes-per-sec) and the {} records a minute its {} \
                     connections and {} subscribers may send (--max-connections, \
                     --max-subscribers): planned at {}% busy, a feeder's session and the \
                     stages' work on its receptions (ingest, deduplication and sealing) cost {} \
                     ns of a core a second (RFC-0181 \"Sizing\"); give it more cores (the unit's \
                     CPUQuota, the container's limits.cpu, its CPU affinity), plan a slower \
                     members' rate, fewer connections or subscribers",
                    plan.member_feeders,
                    plan.sessions.records_per_minute(),
                    plan.sessions.general,
                    plan.sessions.subscribers,
                    crate::cores::BUSY_PERCENT,
                    crate::cores::connection_nanos(plan.holds_raw)
                        + crate::cores::stage_nanos(plan.holds_raw),
                ));
            }
        }
        let needed = Self::memory_for(1, plan);
        if self.memory < needed || admission.connections == 0 {
            return Err(format!(
                "{} bytes of memory admit no feeder beside {} member sessions: the relay needs {} \
                 bytes for itself, {} for the Noise buffers and {} for the kernel's socket buffers \
                 of its {} connections (--max-connections), {} for its members' shared rate ({} \
                 feeders' worth at --max-member-bytes-per-sec), {} for what waits for its link to \
                 each member session (as many as its areas bring, at most its connections), {} for \
                 the parities its members' rate reassembles at once (the parity-assembly room), and \
                 {} for each connection ({} of them its floor, the rest the windows of the planned \
                 rate{}), {needed} in all for these and one; give it more (--memory, or the memory \
                 it runs in: the unit's MemoryHigh and MemoryMax, the container's limits.memory), \
                 or plan fewer connections or a slower members' rate (--max-connections, \
                 --max-member-bytes-per-sec)",
                self.memory,
                self.plan.members,
                self.plan.base,
                plan.connection_buffers(),
                plan.connection_sockets(),
                self.plan.connections,
                plan.member_rate_pool(),
                self.plan.member_feeders,
                plan.member_links(),
                plan.parity_assembly(),
                Self::memory_for(1, plan) - plan.before_feeders(),
                plan.per_feeder.total(),
                if plan.holds_raw {
                    " and a MLAT seat"
                } else {
                    ""
                },
            ));
        }
        if plan.holds_raw && admission.seats == 0 {
            return Err(format!(
                "this relay hosts MLAT but its {} bytes of memory and its cores leave no seat for a \
                 receiver beside its connections (a seat costs {} bytes and {} ns of a core a \
                 second): give it more, or host none (--no-mlat)",
                self.memory,
                plan.per_seat.total(),
                crate::cores::mlat_planned_per_feeder(true),
            ));
        }
        Ok(())
    }

    /// The least memory that admits `feeders` connections at the planned mean rate and, where MLAT
    /// is hosted, a MLAT seat for each, beside what the plan holds before any
    /// (`Plan::before_feeders`): the connections' cost out of what MLAT's share leaves, the seats'
    /// out of the share, whichever needs more.
    pub fn memory_for(feeders: usize, plan: Plan) -> usize {
        let connections = plan
            .per_feeder
            .total()
            .saturating_add(plan.per_rate.total())
            .saturating_mul(feeders);
        if !plan.holds_raw {
            return plan.before_feeders().saturating_add(connections);
        }
        let share = crate::cores::MLAT_SHARE_PERCENT;
        let seats = plan.per_seat.total().saturating_mul(feeders);
        // Each side rounded up, and a hundred bytes more for the share's rounding down.
        let by_connections = connections.saturating_mul(100).div_ceil(100 - share);
        let by_seats = seats.saturating_mul(100).div_ceil(share);
        plan.before_feeders()
            .saturating_add(by_connections.max(by_seats))
            .saturating_add(200)
    }

    /// The most feeder connections the budget admits (`Admission::connections`): its memory over a
    /// connection's floor and its mean rate's windows, and its cores' sessions and stages.
    pub fn ceiling(&self) -> usize {
        self.admission().connections
    }

    /// The connection limit by the memory alone.
    pub fn memory_feeders(&self) -> usize {
        self.admission().connections_by_memory
    }

    /// The relay-wide rate `R_max` in receptions a second (RFC-0181 §10, "Admission"): the least
    /// of what the memory and the cores carry ([`Plan::admit`]). What the ingest stage admits
    /// before signing, and what every rate-driven store's window is sized by.
    pub fn max_receptions_per_sec(&self) -> u64 {
        self.admission().rate
    }

    /// `R_max` in bytes a second.
    pub fn max_bytes_per_sec(&self) -> u64 {
        self.admission().bytes_per_sec()
    }

    /// The records a second `R_max` admits (`Admission::records_per_sec`).
    pub fn max_records_per_sec(&self) -> u64 {
        self.admission().records_per_sec()
    }

    /// The MLAT receiver seats the relay hosts at most (its own pool, planned from the memory and
    /// the cores); none where MLAT is not hosted.
    pub fn mlat_seats(&self) -> usize {
        self.admission().seats
    }

    /// The seats hosted: [`Budget::mlat_seats`] where MLAT is hosted, else none.
    pub fn hosted_seats(&self) -> usize {
        if self.plan.holds_raw {
            self.mlat_seats()
        } else {
            0
        }
    }

    /// The members' products' pace (`Plan::member_products_bytes_per_sec`) at the seats hosted:
    /// what every member session's MLAT records share (`ingest::MemberPace`).
    pub fn member_products_bytes_per_sec(&self) -> usize {
        self.plan.member_products_bytes_per_sec(self.hosted_seats())
    }

    /// The load the relay is planned to carry (`cores::Load`): `R_max`, its connections and its
    /// seats. What its stages' threads are sized for.
    pub fn load(&self) -> crate::cores::Load {
        let admission = self.admission();
        crate::cores::Load {
            receptions_per_sec: admission.rate,
            connections: admission.connections,
            seats: admission.seats,
            member_feeders: self.plan.member_feeders,
            sessions: self.plan.sessions,
        }
    }

    /// Each stage's threads for the load admitted ([`Budget::load`], `cores::threads_for`).
    pub fn threads(&self) -> crate::ingest::Threads {
        let plan = self.plan();
        crate::cores::threads_for(self.load(), plan.holds_raw, plan.cores)
    }

    /// The threads hosted MLAT's steps are spread over for the load admitted, in the cores the
    /// stages leave (`cores::mlat_threads_for`): none for a relay that does not host MLAT.
    pub fn mlat_threads(&self) -> usize {
        let plan = self.plan();
        crate::cores::mlat_threads_for(self.load(), plan.holds_raw, plan.cores)
    }

    /// Reserves one connection's floor in the connection stores, or `None` when the connection
    /// limit is reached (the Hello is refused). Connections reserve from their own room, never
    /// from the members' pool; the rate-driven stores are not reserved per connection but sized
    /// for the relay-wide rate ([`Admission::rate`]).
    pub fn reserve(&self) -> Option<Reservation> {
        let floor = self.plan.per_feeder.total();
        Self::take(
            &self.reserved,
            floor,
            floor.saturating_mul(self.ceiling()).min(self.total),
        )
    }

    /// Reserves one of the member sessions planned (`Plan::members`), for as long as it is a
    /// member, or `None` when every one is admitted. The members' shared rate is planned whole at
    /// start; members never reserve from the feeders' room, so a relay full of feeders still takes
    /// the members it was planned for.
    pub fn reserve_member(&self) -> Option<Reservation> {
        Self::take(&self.members_reserved, 1, self.plan().members)
    }

    fn take(reserved: &Arc<AtomicUsize>, needed: usize, room: usize) -> Option<Reservation> {
        reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(needed).filter(|after| *after <= room)
            })
            .ok()?;
        Some(Reservation {
            bytes: needed,
            reserved: Arc::clone(reserved),
        })
    }

    /// Bytes the admitted feeders hold of their room.
    pub fn reserved(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }

    /// The member sessions admitted.
    pub fn members_reserved(&self) -> usize {
        self.members_reserved.load(Ordering::Acquire)
    }

    pub fn per_feeder(&self) -> PerFeeder {
        self.plan.per_feeder
    }

    /// The member sessions the pool holds (`members_for`).
    pub fn members(&self) -> usize {
        self.plan.members
    }

    /// The feeders the members' shared rate is planned as.
    pub fn member_feeders(&self) -> usize {
        self.plan.member_feeders
    }

    pub fn memory(&self) -> usize {
        self.memory
    }

    /// What the relay holds whatever its feeders.
    pub fn base(&self) -> usize {
        self.plan.base
    }

    /// What the relay plans to hold at its limits: what it holds before any feeder
    /// (`Plan::before_feeders`), every admitted connection's floor, the windows of `R_max` and
    /// the seats.
    pub fn planned(&self) -> usize {
        let admission = self.admission();
        self.plan()
            .before_feeders()
            .saturating_add(admission.floor.saturating_mul(admission.connections))
            .saturating_add(Self::rate_bytes(&self.plan, admission.rate))
            .saturating_add(self.plan.per_seat.total().saturating_mul(admission.seats))
    }

    /// What the rate-driven stores hold over their windows at `rate` receptions a second, all
    /// together.
    fn rate_bytes(plan: &Plan, rate: u64) -> usize {
        Store::ALL
            .iter()
            .filter(|store| store.driver() == Driver::Rate)
            .map(|store| Self::window_bytes(plan.per_rate.of(*store), rate))
            .fold(0usize, usize::saturating_add)
    }

    /// `window` bytes a planned feeder's rate holds, at `rate` receptions a second: the store's
    /// limit is its window times the rate.
    fn window_bytes(window: usize, rate: u64) -> usize {
        usize::try_from(
            (window as u128).saturating_mul(u128::from(rate)) / PLANNED_RECEPTIONS_PER_SEC as u128,
        )
        .unwrap_or(usize::MAX)
    }

    /// What every admitted connection, the rate and the members together may hold in `store`:
    /// the connections' floors, the store's window of `R_max` and of the members' rate (RFC-0181
    /// §10: `limit = window x (R_max + members' rate)`), and the seats'.
    pub fn store_bytes(&self, store: Store) -> usize {
        let admission = self.admission();
        let floors = self
            .plan
            .per_feeder
            .of(store)
            .saturating_mul(admission.connections);
        let rate = Self::window_bytes(self.plan.per_rate.of(store), admission.rate);
        let seats = self.plan.per_seat.of(store).saturating_mul(admission.seats);
        let members = self
            .plan
            .member_unit()
            .of(store)
            .saturating_mul(self.plan.member_feeders);
        // The fingerprints' tables, what waits for the sealer, the tables of what was taken, the
        // delivery shards' orders, the
        // fan-out's queues and the notes' inboxes allocate this whatever the rate
        // (`Plan::before_feeders`).
        let fixed = match store {
            Store::Dedup => crate::exchange::DEDUP_FIXED_BYTES,
            Store::Epochs => crate::exchange::EPOCHS_FIXED_BYTES,
            Store::FeederStrikes => self
                .plan
                .strike_tables_bytes(crate::strikes::Class::Feeders),
            Store::PeerStrikes => self.plan.strike_tables_bytes(crate::strikes::Class::Peers),
            Store::OwnStrikes => self.plan.strike_tables_bytes(crate::strikes::Class::Own),
            Store::Delivery => crate::delivery::FIXED_BYTES,
            Store::Fanout => self.plan.fanout_queues(),
            Store::Batches => self.plan.sharing_outbox(),
            Store::Paces => self.plan.connection_paces(),
            Store::Arrived | Store::Standing => self.plan.mlat_tables_of(store),
            Store::Inbox => self.plan.inbox_spare(),
            Store::Anchors | Store::Directory | Store::Remembered => store.fixed_bytes(),
            Store::World => self.plan.world_bytes(),
            Store::Credit
            | Store::Stations
            | Store::Descriptions
            | Store::Located
            | Store::Consistency => self.plan.receiver_tables_of(store),
            Store::Parts => self.plan.parts_bytes(),
            Store::Twins => self.plan.twins_tables(),
            Store::Models => self.plan.seat_tables_of(store),
            _ => 0,
        };
        floors
            .saturating_add(rate)
            .saturating_add(seats)
            .saturating_add(members)
            .saturating_add(fixed)
    }

    /// The receiver figure the budget holds (`Plan::receivers` at its admission): what every table
    /// of one entry per receiver is sized to.
    pub fn receivers(&self) -> usize {
        self.plan.receivers(&self.admission())
    }

    /// What the positions checks are sized from (`consistency::Caps::of`): the receiver figure
    /// (their sites), and the links that may bring raw positions, one record of buffer each
    /// (`Plan::twin_links`).
    pub fn consistency_sizing(&self) -> crate::consistency::Sizing {
        crate::consistency::Sizing {
            receivers: self.receivers(),
            links: self.plan.twin_links(),
        }
    }

    /// What the decoded models' store is sized from (`models::Rooms::of`): the seats its own engine
    /// publishes for, and the members' models' pace (`Plan::member_models_bytes_per_sec`). Nothing a
    /// feeder's receivers bring.
    pub fn models_sizing(&self) -> crate::models::Sizing {
        crate::models::Sizing {
            seats: self.hosted_seats(),
            members_bytes_per_sec: self.plan.member_models_bytes_per_sec(self.hosted_seats()),
        }
    }

    /// The gauge of `store`: the same one for the budget's life, whatever it is resized to.
    pub fn gauge(&self, store: Store) -> Arc<Gauge> {
        Arc::clone(&self.gauges[store.index()])
    }

    /// What the stores holding decoded batches ([`Store::holds_decoded`]) are charged now: the
    /// decodes and the batches' signed bytes.
    pub fn decoded_charged(&self) -> usize {
        Store::ALL
            .iter()
            .filter(|store| store.holds_decoded())
            .map(|store| self.gauges[store.index()].held())
            .fold(0, usize::saturating_add)
    }

    /// The decoded batches alive in this process (`tally_wire::decoded::live`) beside those
    /// charged ([`Covered`], read at the same instant), those charged other than once for exactly
    /// their footprint, and what the store holding decodes is charged
    /// ([`Budget::decoded_charged`]), for the report. Every decode is charged once, inside itself,
    /// by the ingest stage that made it, so a decode alive uncharged, or charged twice or for
    /// other than its footprint, is a decode the plan does not hold as it says: exact to the batch
    /// and to the byte.
    pub fn decoded_held(&self) -> DecodedHeld {
        let (covered, (batches, live)) = Covered::process().with_live(tally_wire::decoded::live);
        let inexact = Covered::process().inexact();
        DecodedHeld {
            batches,
            live,
            covered_batches: covered.0,
            covered: covered.1,
            inexact_batches: inexact.0,
            inexact: inexact.1,
            charged: self.decoded_charged(),
        }
    }

    pub fn report(&self) -> MemoryReport {
        MemoryReport {
            memory: self.memory,
            base: self.plan.base,
            per_feeder: self.plan.per_feeder.total(),
            ceiling: self.ceiling(),
            admission: self.admission(),
            allocator: allocator_report(),
            reserved: self.reserved(),
            members: self.plan.members,
            member_feeders: self.plan.member_feeders,
            members_reserved: self.members_reserved(),
            stores: self.gauges.iter().map(|gauge| gauge.report()).collect(),
            decoded: self.decoded_held(),
            connection_buffers: self.connection_buffers.report(),
            member_links: self.member_links.report(),
            parity_assembly: self.parity_assembly.report(),
        }
    }
}

/// The budget as served on `GET /memory`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MemoryReport {
    pub memory: usize,
    pub base: usize,
    /// A connection's floor.
    pub per_feeder: usize,
    pub ceiling: usize,
    /// What the plan admits: the connections, `R_max` and the MLAT seats, and what bound each.
    pub admission: Admission,
    /// The allocator's holdings (`allocator_report`).
    pub allocator: AllocatorReport,
    pub reserved: usize,
    pub members: usize,
    pub member_feeders: usize,
    pub members_reserved: usize,
    pub stores: Vec<GaugeReport>,
    /// The decoded batches alive beside what the stores holding them are charged
    /// (`Budget::decoded_held`): `live` past `charged` is a holder no gauge sees.
    pub decoded: DecodedHeld,
    /// Every connection's Noise buffers but a feeder's (`Plan::connection_buffers`).
    pub connection_buffers: GaugeReport,
    /// What waits for the member links (`Plan::member_links`).
    pub member_links: GaugeReport,
    /// The parities being reassembled (`Plan::parity_assembly`).
    pub parity_assembly: GaugeReport,
}

/// The decoded batches alive and what the stores holding them are charged, read together
/// (`Budget::decoded_held`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DecodedHeld {
    /// Decoded batches alive in the process, and the bytes they hold (`Decoded::footprint`).
    pub batches: usize,
    pub live: usize,
    /// Of those, the batches charged ([`Covered`]), each once, and their bytes.
    pub covered_batches: usize,
    pub covered: usize,
    /// What the store holding decoded batches is charged: every decode's own charge, and every
    /// batch's signed bytes beside them.
    pub charged: usize,
    /// Of the charged batches, those charged other than once for exactly their footprint, and the
    /// bytes their charges are off by ([`Covered::inexact`]).
    pub inexact_batches: usize,
    pub inexact: usize,
}

impl DecodedHeld {
    /// Decoded bytes alive that no charge holds.
    pub fn uncharged(&self) -> usize {
        self.live.saturating_sub(self.covered)
    }

    /// Decoded batches alive that no charge holds.
    pub fn uncharged_batches(&self) -> usize {
        self.batches.saturating_sub(self.covered_batches)
    }
}

/// Admitted bytes, released when dropped.
#[derive(Debug)]
pub struct Reservation {
    bytes: usize,
    reserved: Arc<AtomicUsize>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.reserved.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signed batch of `receptions` receptions, its own.
    fn signed(receptions: u32) -> Result<tally_wire::Batch, String> {
        let receiver = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        crate::anchors::anchored_with(
            &receiver,
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence: 1,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: (0..receptions)
                    .map(|n| tally_wire::Observation {
                        format: tally_wire::batch::format::MODE_S_LONG,
                        timestamp: u64::from(n),
                        signal: 0,
                        data: n.to_be_bytes().repeat(4),
                    })
                    .collect(),
            },
            tally_wire::batch::Codec::Deflate,
        )
        .map_err(|error| error.to_string())
    }

    /// `batch` decoded as the ingest stage decodes it (`ingest::Stages::decode_owned`), its bytes
    /// and its decode charged to `gauge`, entered in `covered`.
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's batch, stamped at the clocks' origin"
    )]
    fn owned(
        batch: tally_wire::Batch,
        gauge: &Arc<Gauge>,
        covered: &'static Covered,
    ) -> Result<Arc<tally_wire::Decoded>, String> {
        crate::ingest::Stages::decode_owned(batch, crate::ingest::Stamp::at(0, 0), gauge, covered)
            .map_err(|error| format!("{error:?}"))
    }

    /// A batch's decode and its signed bytes are each charged once, inside their own allocations,
    /// for their life: however many stores hold them (the epochs, a subscriber's queue, MLAT's
    /// notes, the sharing groups' copies of the batch), the store is charged the two footprints and
    /// no more, the decode is entered once with its charge equal to its footprint, and the charges
    /// go with the last holder of each, the bytes outliving the decode when something keeps the
    /// batch. A store with no room refuses the batch whole, its bytes and its decode.
    #[test]
    fn a_decode_and_its_bytes_are_each_charged_once_for_their_life() -> Result<(), String> {
        let covered: &'static Covered = Box::leak(Box::new(Covered::new()));
        let gauge = Gauge::new(Store::Decoded, 1 << 20);
        let batch = signed(40)?;
        let charged = crate::ingest::charge_of(&batch);
        let decoded = owned(batch, &gauge, covered)?;
        assert!(decoded.is_owned() && decoded.batch().is_owned());
        let both = decoded.footprint() + decoded.batch().footprint();
        assert_eq!(gauge.held(), both);
        // What ingest charged before the decode bounds what the two are charged for their life.
        assert!(
            both <= charged,
            "{both} past the {charged} charged at ingest"
        );
        assert_eq!(covered.now(), (1, decoded.footprint()));
        assert_eq!(covered.charges_of(&decoded), 1);
        assert_eq!(covered.charged_for(&decoded), decoded.footprint());
        assert_eq!(covered.inexact(), (0, 0));
        // Held by four stores and the groups: still the two charges, once each.
        let holders: Vec<_> = (0..4).map(|_| Arc::clone(&decoded)).collect();
        let kept = decoded.batch().clone();
        assert_eq!(gauge.held(), both);
        assert_eq!(covered.charges_of(&decoded), 1);
        // The decode let go by every holder: its charge goes, the bytes the groups keep stay.
        let address = Arc::as_ptr(&decoded) as usize;
        drop((holders, decoded));
        // (Told by the process's hook in a relay; this test's own is told here.)
        covered.gone(address);
        assert_eq!(gauge.held(), kept.footprint());
        assert_eq!(covered.now(), (0, 0));
        drop(kept);
        assert_eq!(gauge.held(), 0);
        // No room: the batch comes back, nothing charged, nothing entered.
        let full = Gauge::new(Store::Decoded, 64);
        assert!(owned(signed(40)?, &full, covered).is_err());
        assert_eq!((full.held(), covered.now()), (0, (0, 0)));
        assert_eq!(covered.lapses(), Lapses::default());
        Ok(())
    }

    /// A decode charged a second time, and one let go that was never charged, are each counted as
    /// they happen, and the decode charged twice is inexact until it goes: the equality the flood
    /// suite holds is seen to fail both ways.
    #[test]
    fn a_decode_charged_twice_or_never_is_counted() -> Result<(), String> {
        let covered: &'static Covered = Box::leak(Box::new(Covered::new()));
        let gauge = Gauge::unlimited(Store::Decoded);
        let decoded = owned(signed(20)?, &gauge, covered)?;
        covered.own(&decoded, decoded.footprint());
        assert_eq!(covered.charges_of(&decoded), 2);
        assert_eq!(covered.inexact(), (1, decoded.footprint()));
        assert_eq!(covered.lapses().charged_twice, 1);
        // Counted once however many charges it has.
        assert_eq!(covered.now(), (1, decoded.footprint()));
        let address = Arc::as_ptr(&decoded) as usize;
        drop(decoded);
        covered.gone(address);
        assert_eq!(covered.inexact(), (0, 0));
        // One let go that no charge was ever made for.
        covered.gone(address);
        assert_eq!(
            covered.lapses(),
            Lapses {
                charged_twice: 1,
                never_covered: 1,
            }
        );
        Ok(())
    }

    #[test]
    fn a_feeder_is_admitted_only_with_room_in_every_store_and_leaving_frees_it() {
        let per_feeder = PerFeeder {
            batches: 10,
            arrived: 20,
            ..PerFeeder::default()
        };
        let budget = Budget::new(65, per_feeder);
        assert_eq!(budget.ceiling(), 2);
        let first = budget.reserve();
        let second = budget.reserve();
        assert!(first.is_some() && second.is_some());
        assert!(budget.reserve().is_none());
        drop(first);
        assert_eq!(budget.reserved(), 30);
        assert!(budget.reserve().is_some());
    }

    #[test]
    fn the_planned_feeder_reserves_every_store_and_raw_only_where_held() {
        let without = PerFeeder::planned(false);
        let with = PerFeeder::planned(true);
        for store in [
            Store::Arrived,
            Store::Inbox,
            Store::Engine,
            Store::Standing,
            Store::Models,
        ] {
            assert_eq!(without.of(store), 0, "{store:?}");
            assert!(with.of(store) > 0, "{store:?}");
        }
        // The twins are one record a link, planned before any feeder: never a feeder's or a
        // seat's.
        assert_eq!((without.twins, with.twins), (0, 0));
        for store in Store::ALL {
            if !matches!(
                store,
                Store::Arrived
                    | Store::Inbox
                    | Store::Engine
                    | Store::Standing
                    | Store::Twins
                    | Store::Models
                    | Store::Records
                    | Store::Batches
                    | Store::Buffers
                    | Store::Fanout
                    // A fixed store: planned once for the relay, never per feeder.
                    | Store::Anchors
                    | Store::Directory
                    | Store::Parts
                    | Store::Remembered
                    | Store::World
                    // What the peers deliver: the members' rate's, never a feeder's.
                    | Store::PeerStrikes
            ) {
                assert!(without.of(store) > 0, "{store:?}");
            }
        }
        assert_eq!(with.of(Store::PeerStrikes), 0);
        // Every table of one entry per receiver takes the receivers a feeder brings.
        for store in [
            Store::Credit,
            Store::Stations,
            Store::Descriptions,
            Store::Located,
            Store::Consistency,
        ] {
            assert_eq!(store.driver(), Driver::Rate, "{store:?}");
            assert!(without.of(store) > 0, "{store:?}");
        }
        assert_eq!(
            without.stations,
            crate::stations::BYTES_PER_RECEIVER * RECEIVERS_PER_PLANNED_FEEDER
        );
        // Records are written by MLAT's seats and the members, never a feeder: none without MLAT.
        assert_eq!(without.records, 0);
        assert!(with.records > 0);
        // The sharing groups' own bytes only on a relay with sharing members, and a queue's slots
        // only for sessions that may listen.
        assert_eq!((without.batches, without.fanout), (0, 0));
        let shared = PerFeeder::planned_for(false, true, 64, None);
        assert!(shared.batches > 0 && shared.fanout > 0);
        // A relay of 64 GiB holds thousands of planned feeders, never none.
        let budget = Budget::of_memory(64 << 30, Plan::planned(true));
        assert!(budget.ceiling() > 1_000);
        assert!(budget.check().is_ok());
        assert!(memory_available() > 0);
    }

    /// RFC-0181's figures for what a planned feeder's worth holds in the stores of what is taken,
    /// from the constants: its entries' lives (102 s a feeder's batch, 33 s the relay's own, 117 s
    /// a peer's copy), its place in entries, and the bytes: the feeders' store's, and the relay's
    /// own, without and hosting MLAT.
    #[test]
    fn rfc_0181_quotes_the_strike_plan() {
        use crate::strikes::{
            FEEDER_PLACE_ENTRIES, PLANNED_ENTRY_BYTES, Usable, feeder_place_bytes,
        };
        assert_eq!(Usable::BATCHES.feeder_life_seconds(), 102);
        assert_eq!(own_life_seconds(), 33);
        assert_eq!(peer_life_seconds(), 117);
        assert_eq!(PLANNED_ENTRY_BYTES, 32);
        assert_eq!(
            (
                crate::strikes::PLACE_BYTES,
                feeder_place_bytes(Usable::BATCHES)
            ),
            (741, 2_389)
        );
        assert_eq!(FEEDER_PLACE_ENTRIES, 75);
        assert_eq!(feeder_share_entries(2), 279);
        let records = crate::cores::RECORDS_PER_PLANNED_FEEDER as usize;
        let own = |hosts_mlat| {
            own_strikes_bytes(crate::strikes::own_records_per_feeder(hosts_mlat) as usize)
        };
        assert_eq!(
            (feeder_strikes_bytes(records), own(false), own(true)),
            (17_856, 2_176, 3_232)
        );
    }

    /// RFC-0171 §3.6 and RFC-0181 §10: what is taken is planned for every class of deliverer at
    /// once, each in a store of its own (`strikes::Class`), the relay's own records among them
    /// (its products and, hosting MLAT, its engine's, for every planned feeder's worth of load and
    /// whatever its load, its bundle indexes; the members' records it rebuilds): the feeders'
    /// entries at the rate the relay admits from them together (every connection admitted a
    /// planned feeder's records over the longest a feeder's entry lives, and its place: the
    /// relay-wide rate holds the feeders to it together, so one feeder filling its own share,
    /// `Entries::feeder`, takes from that rate and not past it), the feeders and the peers each
    /// twice their share together, their places charged among their entries (a holder below its
    /// fair part is taken while others hold the rest, `Shares::take`), the relay its whole share
    /// and its place, each class's table of places, and each class's ring in every table it takes
    /// in. Each at its peak, a set growing (`strikes::PLANNED_ENTRY_BYTES`). So each store holds
    /// its class's share full, and a flood by any class (feeders churning fresh keys among them)
    /// never reaches another's store.
    #[test]
    fn every_deliverers_share_of_what_is_taken_is_inside_the_store_planned() {
        use crate::strikes::{Class, PLACES_FIXED_BYTES, PLANNED_ENTRY_BYTES, Strikes, Usable};
        let deadlines = crate::sharing::Deadlines::RELAY;
        let figures = Usable::figures(crate::strikes::relay_signed(deadlines));
        for hosts_mlat in [false, true] {
            for members in [0, 4] {
                for bundles in [0, 285] {
                    let plan = Plan::planned(hosts_mlat)
                        .with_members(members, 16 * PLANNED_BYTES_PER_SEC as u64)
                        .with_bundle_indexes(bundles);
                    let budget = Budget::of_memory(Budget::memory_for(1_000, plan), plan);
                    let admission = budget.admission();
                    let entries = plan.strike_entries(&admission);
                    assert!(entries.relay > 0 && entries.peer > 0 && entries.feeder > 0);
                    // The feeders' together, places among their entries, are every connection
                    // admitted at the rate the relay-wide rate admits for it, with its place.
                    assert_eq!(
                        entries.feeders,
                        admission.connections
                            * (crate::cores::RECORDS_PER_PLANNED_FEEDER as usize
                                * Usable::BATCHES.feeder_life_seconds() as usize
                                + crate::strikes::FEEDER_PLACE_ENTRIES)
                    );
                    let batches = crate::exchange::SHARDS * Strikes::fixed_bytes(Usable::BATCHES);
                    let every = batches
                        + 3 * Strikes::fixed_bytes(Usable::relay_signed(deadlines))
                        + Strikes::fixed_bytes(Usable::proofs(deadlines))
                        + Strikes::fixed_bytes(figures);
                    for (class, held) in [
                        // The feeders' share twice, their places among their entries
                        // (`Shares::take`), in the ingest shards' tables alone.
                        (
                            Class::Feeders,
                            2 * entries.feeders * PLANNED_ENTRY_BYTES + batches,
                        ),
                        // The peers' twice, in every table.
                        (
                            Class::Peers,
                            2 * entries.peers * PLANNED_ENTRY_BYTES + every,
                        ),
                        // The relay's own whole, and its place with its counts.
                        (
                            Class::Own,
                            entries.relay * PLANNED_ENTRY_BYTES
                                + every
                                + crate::strikes::place_bytes(Usable::BATCHES, figures),
                        ),
                    ] {
                        let held = held + PLACES_FIXED_BYTES;
                        let store = budget.store_bytes(class.store());
                        assert!(
                            held <= store,
                            "{class:?}, hosting MLAT {hosts_mlat}, {members} members, {bundles} \
                             indexes a second: {held} planned in {store}"
                        );
                    }
                }
            }
        }
    }

    /// The cores bound the connections and the rate as the memory does (`cores`): the limit is
    /// the fewer, a connection past it is refused at its Hello whatever room the memory has, every
    /// store's share follows the rate, and the stages' threads follow the load admitted, the
    /// members' rate in it.
    #[test]
    fn the_cores_bound_the_connections_and_the_threads_follow_the_rate() {
        let members = Plan::planned(false).with_members(4, 16 * PLANNED_BYTES_PER_SEC as u64);
        let memory = Budget::memory_for(10_000, members);
        let unbounded = Budget::of_memory(memory, members);
        assert_eq!(unbounded.ceiling(), 10_000);
        // Memory-bound, the rate is the connections' mean, no slack: the memory left holds no more.
        assert_eq!(
            unbounded.max_receptions_per_sec(),
            10_000 * PLANNED_RECEPTIONS_PER_SEC as u64
        );
        assert_eq!(unbounded.admission().rate_bound, Bound::Memory);
        let one = members.with_cores(Some(1));
        let available =
            crate::cores::available_nanos(1, false, members.member_feeders, members.sessions);
        let carried = crate::cores::connections_carried(available, false, 0);
        assert!(carried > 0 && carried < 10_000, "{carried}");
        let budget = Budget::of_memory(memory, one);
        // One message thread cuts each batch into fewer slices than the plan with no cores named
        // (every thread), so the same memory holds more feeders' epochs.
        assert_eq!(budget.ceiling(), carried);
        assert!(
            budget.memory_feeders() >= 10_000,
            "{}",
            budget.memory_feeders()
        );
        assert_eq!(budget.admission().connections_bound, Bound::Cores);
        assert!(budget.check().is_ok());
        let admitted: Vec<_> = (0..carried).filter_map(|_| budget.reserve()).collect();
        assert_eq!(admitted.len(), carried);
        assert!(
            budget.reserve().is_none(),
            "a connection past the cores was admitted"
        );
        // The rate the cores carry is the connections' mean, and every rate-driven store's limit
        // follows it, not the connections.
        assert!(budget.max_receptions_per_sec() >= carried as u64 * 600);
        assert!(budget.max_receptions_per_sec() < 2 * carried as u64 * 600);
        assert!(budget.store_bytes(Store::Dedup) < unbounded.store_bytes(Store::Dedup));
        assert_eq!(
            budget.load(),
            crate::cores::Load {
                receptions_per_sec: budget.max_receptions_per_sec(),
                connections: carried,
                seats: 0,
                member_feeders: members.member_feeders,
                sessions: members.sessions,
            }
        );
        assert_eq!(
            budget.threads(),
            crate::cores::threads_for(budget.load(), false, Some(1))
        );
        // Thirty-two cores carry the 10,000 the memory planned for them holds: the memory bounds
        // it, and the threads follow that rate: more than one ingest worker, and the message
        // threads its rate needs (one carries 20 M receptions a second,
        // `cores::MESSAGE_RECEPTIONS_PER_THREAD`).
        let thirty_two = members.with_cores(Some(32));
        let ten = Budget::of_memory(Budget::memory_for(10_000, thirty_two), thirty_two);
        assert_eq!(ten.ceiling(), 10_000);
        assert!(ten.threads().message >= 1 && ten.threads().ingest > 1);
        assert_eq!(
            ten.threads(),
            crate::cores::threads_for(ten.load(), false, Some(32))
        );
        // Cores that carry no more than the members' rate start no relay.
        let member_carried =
            1_000_000_000 / crate::cores::planned_per_feeder(crate::cores::Source::Member, false);
        let rate = Plan::planned(false)
            .with_members(4, ((member_carried + 1) * PLANNED_BYTES_PER_SEC) as u64);
        let starved = Budget::of_memory(Budget::memory_for(10, rate), rate.with_cores(Some(1)));
        assert_eq!(starved.ceiling(), 0);
        let refusal = starved.check().err().unwrap_or_default();
        assert!(refusal.contains("cores carry no feeder"), "{refusal}");
    }

    #[test]
    fn a_relay_whose_memory_admits_no_feeder_will_not_start() {
        for hosts_mlat in [false, true] {
            let plan = Plan::planned(hosts_mlat);
            let none = Budget::of_memory(plan.base + plan.per_feeder.total() - 1, plan);
            assert_eq!(none.ceiling(), 0);
            assert!(none.check().is_err());
            let one = Budget::of_memory(Budget::memory_for(1, plan), plan);
            assert!(one.ceiling() >= 1);
            assert!(one.check().is_ok());
        }
        // Hosting MLAT adds its own base, beside each feeder's raw and notes.
        assert_eq!(
            Plan::planned(true).base,
            Plan::planned(false).base + MLAT_BASE_BYTES
        );
    }

    /// The members' shared rate is planned once, as the feeders it is worth, and the member
    /// sessions hold places of their own: feeders filling their room leave the members' pool
    /// whole, and the pool holds exactly the member sessions it was sized for.
    #[test]
    fn members_reserve_from_their_own_pool_sized_at_start() {
        let per_feeder = PerFeeder {
            batches: 10,
            ..PerFeeder::default()
        };
        let plan = Plan {
            base: 0,
            per_feeder,
            per_rate: PerFeeder::default(),
            per_seat: PerFeeder::default(),
            members: 0,
            member_feeders: 0,
            connections: 0,
            sessions: crate::cores::Sessions::default(),
            cores: None,
            holds_raw: false,
            feeder_records_per_sec: 1,
            bundle_indexes_per_sec: 0,
            indexes_by_rate: false,
            world: false,
        }
        .with_members(2, 3 * PLANNED_BYTES_PER_SEC as u64 + 1);
        // Its rate's costs this test's own, not the ones the members would plan.
        let plan = Plan {
            per_rate: PerFeeder::default(),
            ..plan
        };
        // The rate is worth four feeders, planned once for both sessions: each feeder's worth a
        // floor's batches and the records the members' sessions write.
        assert_eq!(plan.member_feeders, 4);
        let records = crate::products::records_per_feeder(PLANNED_RECEPTIONS_PER_SEC);
        // And what is taken of them (`strikes`), planned for the members alone.
        let unit = plan.member_unit();
        let strikes = unit.feeder_strikes + unit.peer_strikes + unit.own_strikes;
        assert!(unit.feeder_strikes == 0 && unit.peer_strikes > 0 && unit.own_strikes > 0);
        // And the receivers its records bring, an entry each in every table of receivers.
        let receivers =
            unit.credit + unit.stations + unit.descriptions + unit.located + unit.consistency;
        assert_eq!(
            receivers,
            RECEIVERS_PER_MEMBER_FEEDER
                * (crate::credit::BYTES_PER_RECEIVER
                    + crate::stations::BYTES_PER_RECEIVER
                    + crate::hub::DESCRIPTIONS_BYTES_PER_RECEIVER
                    + crate::products::LOCATED_BYTES_PER_RECEIVER
                    + crate::consistency::BYTES_PER_RECEIVER)
        );
        // And the clock models the members' pace brings, by their own pace and never by its
        // receivers; their positions' twins are one record a link, planned with the links.
        assert_eq!(unit.twins, 0);
        assert_eq!(unit.models, crate::models::BYTES_PER_MEMBER_SEAT);
        let strikes = strikes + receivers + unit.twins + unit.models;
        assert_eq!(
            (plan.member_rate_pool(), plan.member_pool()),
            (4 * (10 + records + strikes), 4 * (10 + records + strikes))
        );
        // Room for the pool and three feeders.
        let budget = Budget::of_memory(Budget::memory_for(3, plan), plan);
        assert_eq!((budget.ceiling(), budget.members()), (3, 2));
        let feeders: Vec<_> = (0..3).filter_map(|_| budget.reserve()).collect();
        assert_eq!(feeders.len(), 3);
        assert!(budget.reserve().is_none());
        // Every feeder admitted, and both member sessions still are.
        let first = budget.reserve_member();
        let second = budget.reserve_member();
        assert!(first.is_some() && second.is_some());
        assert_eq!(budget.members_reserved(), 2);
        assert!(budget.reserve_member().is_none());
        drop(first);
        assert!(budget.reserve_member().is_some());
        // The gauges are sized for the feeders and the members' rate.
        // And the outbox's slots kept whatever it holds (`Plan::sharing_outbox`).
        assert_eq!(
            budget.gauge(Store::Batches).limit(),
            10 * (3 + 4) + crate::sharing::OUTBOX_FIXED_BYTES
        );
        assert_eq!(budget.gauge(Store::Records).limit(), records * 4);
        // A member's one connection takes its buffers from the connections' room, never from the
        // members' rate.
        let buffered = Plan {
            per_feeder: PerFeeder {
                buffers: 5,
                ..per_feeder
            },
            ..plan
        };
        assert_eq!(buffered.member_pool(), 4 * (10 + records + strikes));
        let budget = Budget::of_memory(Budget::memory_for(3, buffered), buffered);
        assert_eq!(budget.gauge(Store::Buffers).limit(), 5 * 3);
        // A relay holding no member plans no rate for them.
        assert_eq!(plan.with_members(0, 1 << 20).member_pool(), 0);
    }

    /// The members' products follow the seats, apart from their raw rate: the seats a plan admits
    /// are never bounded by the members' rate, raising that rate plans more raw ingest and never
    /// more seats, and the products' pace is one seat's products a second for each seat hosted
    /// and each feeder the raw rate is worth. Before (2026-10-27), the products spent the raw
    /// rate, and the default 1 MiB/s admitted 125 seats where the cores carried 522.
    #[test]
    fn the_members_products_follow_the_seats_not_the_raw_rate() {
        let memory = 32usize << 30;
        let plan = |rate: u64| {
            Plan::planned(true)
                .with_members(8, rate)
                .with_cores(Some(16))
        };
        let (default, raised) = (plan(1 << 20), plan(4 << 20));
        let (low, high) = (default.admit(memory), raised.admit(memory));
        assert!(low.seats > 0);
        // More raw costs cores and memory, so a raised rate admits no more seats.
        assert!(high.seats <= low.seats, "{} > {}", high.seats, low.seats);
        assert!(raised.member_feeders() > default.member_feeders());
        for (plan, admission) in [(&default, &low), (&raised, &high)] {
            let per_seat = crate::models::MEMBER_MODEL_BYTES_PER_SEAT_PER_SEC
                + crate::consistency::POSITIONS_BYTES_PER_SEAT_PER_SEC;
            assert_eq!(
                plan.member_products_bytes_per_sec(admission.seats),
                (admission.seats + plan.member_feeders()) * per_seat
            );
            // Each seat holds its neighbours' models beside its own engine's.
            assert_eq!(
                plan.per_seat.of(Store::Models),
                crate::models::BYTES_PER_SEAT + crate::models::BYTES_PER_MEMBER_SEAT
            );
        }
        // Without members, nothing comes, and nothing is held for it.
        let alone = Plan::planned(true).with_members(0, 1 << 20);
        assert_eq!(alone.member_products_bytes_per_sec(100), 0);
        assert_eq!(
            alone.per_seat.of(Store::Models),
            crate::models::BYTES_PER_SEAT
        );
    }

    /// The member sessions a relay plans follow its areas and the protocol's bounds, never a
    /// number an operator picks: a relay of one area shares it with those offering the area's cell
    /// and its ancestors; a coarser region brings every cell under it; MLAT adds the raw links;
    /// the connection cap bounds them all; no area, no member.
    #[test]
    fn member_sessions_follow_the_areas_and_the_protocol() -> Result<(), String> {
        use crate::directory::{OFFERS_HELD, OFFERS_PER_CELL};
        use tally_wire::rendezvous::AREA_RESOLUTION;
        let here = tally_wire::Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        };
        let area = tally_wire::Region::containing(&here, AREA_RESOLUTION)
            .map_err(|error| error.to_string())?;
        let base = tally_wire::Region::containing(&here, 0).map_err(|error| error.to_string())?;
        let wide = 1 << 20;
        // The area's cell and its three ancestors.
        assert_eq!(members_for(&[area], false, wide), 4 * OFFERS_PER_CELL);
        // A base cell: itself and up to 7 + 49 + 343 cells under it.
        assert_eq!(
            members_for(&[base], false, wide),
            (1 + 7 + 49 + 343) * OFFERS_PER_CELL
        );
        // Hosting MLAT, each relay may also be dialled for raw.
        assert!(members_for(&[area], true, wide) >= 2 * 4 * OFFERS_PER_CELL);
        // Never past the directory, nor the connection cap.
        let many = vec![base; 64];
        assert_eq!(members_for(&many, false, wide), OFFERS_HELD);
        assert_eq!(members_for(&many, true, 128), 128);
        assert_eq!(members_for(&[], true, wide), 0);
        Ok(())
    }

    /// A budget that cannot hold its members' pool and one feeder beside it refuses to start, and
    /// says so; one byte more than both need starts.
    #[test]
    fn a_relay_that_cannot_hold_its_members_and_a_feeder_will_not_start() {
        for hosts_mlat in [false, true] {
            let plan = Plan::planned(hosts_mlat).with_members(2, 512 * 1024);
            let short = Budget::of_memory(Budget::memory_for(1, plan) - 1, plan);
            // (Hosting MLAT, memory short of a seat still admits connections, and the relay will
            // not start without a seat to host.)
            assert!(hosts_mlat || short.ceiling() == 0);
            assert!(hosts_mlat || short.mlat_seats() == 0);
            let refused = short.check().err().unwrap_or_default();
            assert!(refused.contains("beside 2 member sessions"), "{refused}");
            // Memory that would hold the pool but not a feeder, and a feeder but not the pool.
            let pool_only = Budget::of_memory(plan.base + plan.member_pool(), plan);
            assert!(pool_only.check().is_err());
            let feeder_only =
                Budget::of_memory(Budget::memory_for(1, Plan::planned(hosts_mlat)), plan);
            assert!(feeder_only.check().is_err());
            let fits = Budget::of_memory(Budget::memory_for(1, plan), plan);
            assert!(fits.ceiling() >= 1);
            assert!(fits.check().is_ok());
            assert!(fits.reserve_member().is_some() && fits.reserve_member().is_some());
            assert!(fits.reserve().is_some());
        }
    }

    /// The memory a relay runs in holds its whole budget, the fixed headroom and the
    /// allocator's share of the budget (at least what was measured), and no budget larger would.
    /// Before, the budget was the memory less 64 MiB, while glibc's arenas kept up to 35% of what the
    /// stores held beside it.
    #[test]
    fn the_budget_is_the_memory_run_in_less_the_headroom() {
        for limit in [640 << 20, 672 << 20, 2 << 30, 16 << 30, 32 << 30, 64 << 30] {
            let budget = budget_within(limit);
            assert!(budget + headroom_for(budget) <= limit, "{limit}");
            assert!(budget + 1 + headroom_for(budget + 1) > limit - 1, "{limit}");
            // The share is what was measured (a small relay's) or the cap (a large one's).
            assert!(
                limit - budget
                    >= HEADROOM_BYTES
                        + (budget * MEASURED_ALLOCATOR_PERCENT / 100).min(ALLOCATOR_CAP_BYTES),
                "{limit}"
            );
        }
        // A small relay's share is a quarter of its budget; a large one's the cap.
        assert_eq!(allocator_share(1 << 30), (1 << 30) / 4);
        assert_eq!(allocator_share(usize::MAX / 200), ALLOCATOR_CAP_BYTES);
        assert_eq!(allocator_share(24 << 30), ALLOCATOR_CAP_BYTES);
        // At the cap, the 32 GiB relay keeps the cap and not a quarter of its budget.
        assert_eq!(
            (32usize << 30) - budget_within(32 << 30),
            HEADROOM_BYTES + ALLOCATOR_CAP_BYTES
        );
        assert_eq!(budget_within(HEADROOM_BYTES - 1), 0);
    }

    /// Once bounded, the allocator makes no more than [`MALLOC_ARENAS`] arenas
    /// however many threads allocate at once (glibc makes up to eight a core otherwise). In a child
    /// process of its own, which bounds the allocator before its threads allocate, as the relay's
    /// `main` does.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn the_allocator_keeps_no_more_arenas_than_planned() -> Result<(), String> {
        const CHILD: &str = "TALLY_ARENAS_CHILD";
        if std::env::var_os(CHILD).is_some() {
            bound_the_allocator();
            let arenas = arenas_after_threads(64)?;
            // The main arena and the test thread's, made before the bound, beside the bound.
            assert!(arenas <= MALLOC_ARENAS as usize + 2, "{arenas} arenas");
            return Ok(());
        }
        let exe = std::env::current_exe().map_err(|error| error.to_string())?;
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "budget::tests::the_allocator_keeps_no_more_arenas_than_planned",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .map_err(|error| error.to_string())?;
        assert!(status.success(), "the child: {status}");
        Ok(())
    }

    /// The bytes this process has resident now (`/proc/self/statm`).
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn resident_bytes() -> Result<u64, String> {
        let statm = std::fs::read_to_string("/proc/self/statm").map_err(|e| e.to_string())?;
        let pages: u64 = statm
            .split_whitespace()
            .nth(1)
            .and_then(|field| field.parse().ok())
            .ok_or("no resident field")?;
        Ok(pages * 4096)
    }

    /// What the arenas keep free below their tops is returned by the trimmer
    /// thread, not left to the run's history. Eight threads each fill an arena with 4 KiB blocks and
    /// free seven in eight, so every arena is pages of free space between blocks that stay live
    /// (which no top-trim reaches); after one trim begun past the frees, the process is back to a
    /// fraction of its peak. Without the trimmer it stays at the peak. In a child process of its own, so no
    /// other test's memory is in the count.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn the_trimmer_returns_the_arenas_free_pages() -> Result<(), String> {
        const CHILD: &str = "TALLY_TRIM_CHILD";
        if std::env::var_os(CHILD).is_some() {
            bound_the_allocator();
            spawn_allocator_trimmer(std::time::Duration::from_millis(100))
                .map_err(|error| error.to_string())?;
            const THREADS: usize = 8;
            const BLOCKS: usize = 16_384; // 64 MiB a thread, 512 MiB in all
            let filled = Arc::new(std::sync::Barrier::new(THREADS + 1));
            let freed = Arc::new(std::sync::Barrier::new(THREADS + 1));
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let (filled, freed) = (Arc::clone(&filled), Arc::clone(&freed));
                    std::thread::spawn(move || {
                        let mut blocks: Vec<Option<Vec<u8>>> =
                            (0..BLOCKS).map(|n| Some(vec![n as u8; 4096])).collect();
                        filled.wait();
                        for (at, block) in blocks.iter_mut().enumerate() {
                            if at % 8 != 0 {
                                *block = None;
                            }
                        }
                        freed.wait();
                        // Alive until the count is taken.
                        filled.wait();
                        std::hint::black_box(&blocks);
                    })
                })
                .collect();
            filled.wait();
            let peak = resident_bytes()?;
            freed.wait();
            // Every block is freed now. A trim counted two past this one began after the frees, so
            // what it returned is all it can: wait for it by count, not by a clock, since the
            // trimmer runs at the lowest priority and a loaded host may hold it off for seconds.
            let before = allocator_report().trims;
            let hang = std::time::Instant::now() + std::time::Duration::from_secs(120);
            while allocator_report().trims < before + 2 {
                if std::time::Instant::now() > hang {
                    return Err("the trimmer took no trim in 120 s".to_owned());
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let now = resident_bytes()?;
            filled.wait();
            for handle in handles {
                handle.join().map_err(|_| "a thread panicked".to_owned())?;
            }
            assert!(peak > 400 << 20, "peak only {} MiB", peak >> 20);
            assert!(
                now <= peak / 2,
                "{} MiB resident of a {} MiB peak after the trimmer ran",
                now >> 20,
                peak >> 20
            );
            assert!(allocator_report().trims > 0);
            return Ok(());
        }
        let exe = std::env::current_exe().map_err(|error| error.to_string())?;
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "budget::tests::the_trimmer_returns_the_arenas_free_pages",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .map_err(|error| error.to_string())?;
        assert!(status.success(), "the child: {status}");
        Ok(())
    }

    /// The arenas glibc reports (`malloc_info`) once `threads` threads have each allocated while
    /// all are alive.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn arenas_after_threads(threads: usize) -> Result<usize, String> {
        let barrier = Arc::new(std::sync::Barrier::new(threads + 1));
        let done = Arc::new(std::sync::Barrier::new(threads + 1));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let (barrier, done) = (Arc::clone(&barrier), Arc::clone(&done));
                std::thread::spawn(move || {
                    let held: Vec<Vec<u8>> = (0..64).map(|n| vec![n as u8; 4096]).collect();
                    barrier.wait();
                    done.wait();
                    held.len()
                })
            })
            .collect();
        barrier.wait();
        let path = std::env::temp_dir().join(format!("malloc-info-{}", std::process::id()));
        crate::os::write_malloc_info(&path)?;
        done.wait();
        for handle in handles {
            handle.join().map_err(|_| "a thread panicked".to_owned())?;
        }
        let info = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let _ = std::fs::remove_file(&path);
        Ok(info.matches("<heap nr=").count())
    }

    /// Every store's gauge is its share of the budget at the ceiling, and resizing the budget
    /// resizes the gauges whoever holds them; together they never pass the feeders' memory.
    #[test]
    fn the_gauges_are_each_stores_share_and_follow_a_resize() {
        let plan = Plan::planned(false);
        let per_feeder = plan.per_rate;
        let mut budget = Budget::of_memory(Budget::memory_for(10, plan), plan);
        let epochs = budget.gauge(Store::Epochs);
        // Its rate's, and what waits for the sealer whatever it holds.
        let fixed = crate::exchange::EPOCHS_FIXED_BYTES;
        assert_eq!(epochs.limit(), per_feeder.epochs * 10 + fixed);
        // A share a part split the store into follows it too (the pace maps' entries' share).
        let third = epochs.share(|limit| limit / 3);
        assert_eq!(third.limit(), (per_feeder.epochs * 10 + fixed) / 3);
        let all: usize = Store::ALL
            .iter()
            .map(|store| budget.gauge(*store).limit())
            .sum();
        assert!(all <= budget.memory() - budget.base());
        budget.resize(Budget::memory_for(20, plan), plan);
        assert_eq!(epochs.limit(), per_feeder.epochs * 20 + fixed);
        assert_eq!(third.limit(), (per_feeder.epochs * 20 + fixed) / 3);
    }

    #[test]
    fn a_gauge_refuses_past_its_limit_counted_and_frees_what_is_let_go() {
        let gauge = Gauge::new(Store::Products, 100);
        let first = gauge.try_charge(60);
        assert!(first.is_some());
        assert!(gauge.try_charge(50).is_none());
        assert_eq!(gauge.refused(), 1);
        let mut grown = gauge.empty();
        assert!(grown.try_grow(40));
        assert!(!grown.try_grow(1));
        assert_eq!(gauge.held(), 100);
        drop(first);
        grown.shrink_to(10);
        assert_eq!(gauge.held(), 10);
        assert_eq!(gauge.peak(), 100);
        // One item larger than the whole limit is taken only when nothing else is held.
        assert!(gauge.try_charge(500).is_none());
        drop(grown);
        assert!(gauge.try_charge(500).is_some());
        assert_eq!(gauge.held(), 0);
    }

    /// A charge handed on with what it holds moves its bytes, taking and releasing nothing, and
    /// no charge ever takes a gauge past its limit.
    #[test]
    fn a_charge_split_moves_its_bytes_and_none_passes_the_limit() {
        let gauge = Gauge::new(Store::Arrived, 100);
        let mut held = gauge.empty();
        assert!(held.try_grow(70));
        let handed = held.split(30);
        assert_eq!((held.bytes(), handed.bytes(), gauge.held()), (40, 30, 70));
        // More than it holds moves all of it.
        let mut rest = held.split(1_000);
        assert_eq!((held.bytes(), rest.bytes(), gauge.held()), (0, 40, 70));
        drop(handed);
        assert_eq!(gauge.held(), 40);
        assert!(!rest.try_grow(61));
        assert!(rest.try_grow(60));
        assert!(gauge.try_charge(1).is_none());
        assert_eq!(gauge.peak(), 100);
        drop(rest);
        assert_eq!(gauge.held(), 0);
    }

    #[tokio::test]
    async fn a_gauge_that_pushes_back_waits_for_room() {
        let gauge = Gauge::new(Store::Ingest, 100);
        let held = gauge.charge_for(0, 80).await;
        let waiting = tokio::spawn({
            let gauge = Arc::clone(&gauge);
            async move { gauge.charge_for(0, 50).await.bytes() }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(held);
        assert_eq!(waiting.await.ok(), Some(50));
        assert_eq!(gauge.waited(), 1);
        assert_eq!(gauge.held(), 0);
    }

    /// The batch byte store is planned only on a relay with sharing members, and the decodes'
    /// window is the longest holder's deadline, not the sum of the holders': a relay alone plans no
    /// sharing groups and holds a decode for its epochs (the longest of the epochs and a
    /// subscriber's queue); one with members holds the signed bytes over the repair horizon, for
    /// the time they outlive the decode, in milliseconds (not rounded up to whole seconds); one
    /// hosting MLAT holds a decode no longer, as its engine keeps none.
    #[test]
    fn a_relay_with_no_sharing_members_plans_no_batches_and_the_window_is_the_longest() {
        let epochs = crate::seal::EPOCHS_HELD * crate::seal::EPOCH_MS;
        assert_eq!(decoded_window_ms(), epochs.max(crate::fanout::BEHIND_MS));
        assert_eq!(
            PerFeeder::planned(true).decoded,
            PerFeeder::planned(false).decoded
        );
        let alone = Plan::planned(false).with_sessions(1_024, 64);
        assert_eq!(alone.members, 0);
        assert_eq!(alone.per_rate.batches, 0);
        assert_eq!(
            alone.per_rate.decoded,
            PLANNED_CHARGED_BYTES_PER_SEC * decoded_window_ms() as usize / 1_000
        );
        let budget = Budget::of_memory(Budget::memory_for(100, alone), alone);
        assert_eq!(budget.gauge(Store::Batches).limit(), 0);
        let shared = Plan::planned(false)
            .with_members(4, 16 * PLANNED_BYTES_PER_SEC as u64)
            .with_sessions(1_024, 64);
        assert!(shared.per_rate.batches > 0);
        // With members, the decode is held for its window and the signed bytes the rate admits
        // with it (its charged bytes over `CHARGED_PER_SIGNED`) for the rest of the horizon:
        // more than a relay alone, less than the whole decode over the horizon.
        let window = decoded_window_ms() as usize;
        let horizon = crate::sharing::Deadlines::RELAY.horizon_ms() as usize;
        let signed = PLANNED_CHARGED_BYTES_PER_SEC / crate::ingest::CHARGED_PER_SIGNED;
        assert_eq!(
            shared.per_rate.decoded,
            PLANNED_CHARGED_BYTES_PER_SEC * window / 1_000 + signed * (horizon - window) / 1_000
        );
        assert!(shared.per_rate.decoded > alone.per_rate.decoded);
        assert!(
            shared.per_rate.decoded < PLANNED_CHARGED_BYTES_PER_SEC * horizon / 1_000,
            "the decode is not held over the horizon, only its signed bytes"
        );
        // Records are the members' and the seats', never the feeders' rate's.
        assert_eq!(shared.per_rate.records, 0);
        assert!(shared.member_unit().records > 0);
    }

    /// Each connection's kernel buffers are counted once, by the place it holds: the cap's at a
    /// feeder's, the member and subscriber places (which leave the cap) at theirs, and the engine
    /// places and the links dialled to members (which keep their place under the cap) only past a
    /// feeder's, at most the cap of them together.
    #[test]
    fn a_connection_s_sockets_are_counted_once_by_the_place_it_holds() {
        use crate::sockets::{
            ENGINE_KERNEL_BYTES as ENGINE, FEEDER_KERNEL_BYTES as FEEDER,
            MEMBER_KERNEL_BYTES as MEMBER, SUBSCRIBER_KERNEL_BYTES as SUBSCRIBER,
        };
        let with = |members: usize, general: usize| {
            Plan::planned(false)
                .with_members(members, 16 * PLANNED_BYTES_PER_SEC as u64)
                .with_sessions(general, 64)
                .connection_sockets()
        };
        let cap_and_subscribers = |general: usize| general * FEEDER + 64 * SUBSCRIBER;
        assert_eq!(with(0, 100), cap_and_subscribers(100));
        // Fewer members than the cap: every engine place and every dialled link may be held.
        assert_eq!(
            with(10, 100),
            cap_and_subscribers(100)
                + 10 * MEMBER
                + 10 * (ENGINE - FEEDER)
                + 10 * (MEMBER - FEEDER)
        );
        // As many members as the cap: the cap's places are all engines', the dearer, and no link
        // is left a place to dial with.
        const { assert!(ENGINE > MEMBER) };
        assert_eq!(
            with(100, 100),
            cap_and_subscribers(100) + 100 * MEMBER + 100 * (ENGINE - FEEDER)
        );
        assert_eq!(
            with(60, 100),
            cap_and_subscribers(100)
                + 60 * MEMBER
                + 60 * (ENGINE - FEEDER)
                + 40 * (MEMBER - FEEDER)
        );
    }

    /// The ingest pool is the rate the workers take over the time a record waits for one, never
    /// a carve a connection: a connection's floor holds none of it, and the pool follows the rate.
    #[test]
    fn the_ingest_pool_is_the_rate_over_the_wait_not_a_carve_a_connection() {
        let planned = PerFeeder::planned(false);
        assert_eq!(Store::Ingest.driver(), Driver::Rate);
        assert_eq!(planned.floor().ingest, 0);
        assert_eq!(
            planned.ingest,
            PLANNED_CHARGED_BYTES_PER_SEC * crate::ingest::INGEST_WAIT_MS as usize / 1_000
        );
        let plan = Plan::planned(false);
        let small = Budget::of_memory(Budget::memory_for(10, plan), plan);
        let large = Budget::of_memory(Budget::memory_for(1_000, plan), plan);
        assert_eq!(
            large.gauge(Store::Ingest).limit(),
            100 * small.gauge(Store::Ingest).limit()
        );
    }

    /// The base is an upper bound only while a feeder's reservation covers what a feeder was
    /// measured to add (`BASE_BYTES`): the claim the RFC makes, held to the code.
    #[test]
    fn a_feeder_reserves_more_than_a_feeder_was_measured_to_add() {
        for holds_raw in [false, true] {
            let reserved = PerFeeder::planned(holds_raw).total();
            assert!(
                reserved > MEASURED_GROWTH_PER_FEEDER,
                "a feeder reserves {reserved} bytes, under the {MEASURED_GROWTH_PER_FEEDER} \
                 measured"
            );
        }
    }

    /// What the stores holding decoded batches are charged is theirs, never another store's.
    #[test]
    fn the_decoded_charge_is_the_decoded_store_alone() {
        let plan = Plan::planned(false);
        let budget = Budget::of_memory(Budget::memory_for(4, plan), plan);
        let mut charges = Vec::new();
        for (n, store) in Store::ALL.iter().enumerate() {
            charges.extend(budget.gauge(*store).try_charge(1 << n));
        }
        let decoded: usize = Store::ALL
            .iter()
            .enumerate()
            .filter(|(_, store)| store.holds_decoded())
            .map(|(n, _)| 1 << n)
            .sum();
        assert_eq!(decoded, 1 << Store::Decoded.index());
        assert_eq!(budget.decoded_charged(), decoded);
        charges.extend(budget.connection_buffers().try_charge(1 << 21));
        assert_eq!(budget.decoded_charged(), decoded);
        assert_eq!(budget.report().decoded.charged, decoded);
        drop(charges);
        assert_eq!(budget.decoded_charged(), 0);
    }

    /// A connection reserves its floor and nothing the rate drives: the planned feeder's windows
    /// are the relay-wide rate's, not reserved per connection (RFC-0181 §10, "Admission").
    #[test]
    fn a_connection_reserves_only_its_floor() {
        for hosts_mlat in [false, true] {
            let plan = Plan::planned(hosts_mlat);
            let full = PerFeeder::planned(hosts_mlat);
            assert_eq!(plan.per_feeder, full.floor());
            assert_eq!(plan.per_rate, full.rate());
            assert_eq!(plan.per_seat, full.seat());
            // The three views are the planned feeder together, store by store.
            assert_eq!(
                plan.per_feeder.plus(&plan.per_rate).plus(&plan.per_seat),
                full
            );
            for store in Store::ALL {
                let views = [
                    plan.per_feeder.of(store),
                    plan.per_rate.of(store),
                    plan.per_seat.of(store),
                ];
                assert!(
                    views.iter().filter(|bytes| **bytes > 0).count() <= 1,
                    "{store:?}"
                );
            }
            // The floor is the connection stores', its pace and its kernel sockets: nothing it sends.
            assert_eq!(
                plan.per_feeder.total(),
                Store::ALL
                    .iter()
                    .filter(|store| store.driver() == Driver::Connection)
                    .map(|store| full.of(*store))
                    .sum::<usize>()
                    + crate::sockets::FEEDER_KERNEL_BYTES
            );
            let budget = Budget::of_memory(Budget::memory_for(3, plan), plan);
            let one = budget.reserve();
            assert!(one.is_some());
            assert_eq!(budget.reserved(), plan.per_feeder.total());
        }
    }

    /// Every connection's pace state is planned in `Store::Paces` at
    /// `ingest::PACE_BYTES_PER_CONNECTION`: a feeder's in its floor, every other connection the
    /// caps allow before any feeder (`Plan::connection_paces`); and the pace maps' share
    /// (`Budget::pace_entries`) leaves every one of them its own pace. Before, a connection's pace
    /// state was planned at a kibibyte outside any store, and nothing was charged for it.
    #[test]
    fn the_paces_store_holds_every_connections_pace_and_leaves_their_own_apart() {
        let plan = Plan::planned(false).with_sessions(100, 10);
        let budget = Budget::of_memory(Budget::memory_for(3, plan), plan);
        let feeders = budget.admission().connections;
        let others = budget.plan().connections;
        assert!(feeders >= 3 && others >= 110, "{feeders} {others}");
        let per = crate::ingest::PACE_BYTES_PER_CONNECTION;
        assert_eq!(budget.plan().per_feeder.of(Store::Paces), per);
        let store = budget.gauge(Store::Paces);
        assert_eq!(store.limit(), (feeders + others) * per);
        assert_eq!(
            store.limit() - budget.pace_entries().limit(),
            (feeders + others) * crate::ingest::OWN_BYTES_PER_CONNECTION
        );
        assert!(
            budget
                .plan()
                .before_feeders_parts()
                .contains(&("connection-paces", others * per))
        );
    }

    /// RFC-0181 §8: every session that joins the fan-out is planned in it, the member sessions
    /// with the rest: each its queue's fixed allocation, and each its slot for every item the rate
    /// brings. Before, the member sessions were left out of both.
    #[test]
    fn the_fanout_plans_a_queue_for_every_member_session() {
        let plan = Plan::planned(false).with_sessions(100, 10);
        let members = plan
            .with_members(64, 16 * PLANNED_BYTES_PER_SEC as u64)
            .with_sessions(100, 10);
        assert_eq!(members.fanout_listeners(), 174);
        assert_eq!(
            members.fanout_queues() - plan.fanout_queues(),
            64 * crate::fanout::LISTENER_BYTES
        );
        let per_item = |plan: &Plan| {
            PerFeeder::planned_for(
                plan.holds_raw,
                plan.members > 0,
                plan.fanout_listeners(),
                plan.cores,
            )
            .rate()
            .of(Store::Fanout)
        };
        assert_eq!(members.per_rate.of(Store::Fanout), per_item(&members));
        assert!(
            members.per_rate.of(Store::Fanout)
                > PerFeeder::planned_for(false, true, 110, None)
                    .rate()
                    .of(Store::Fanout)
        );
    }

    /// RFC-0181 §10, "Admission": each rate-driven gauge's limit is its window times the rate the
    /// relay carries and the members' rate, each connection store's its floor times the
    /// connections, and together they never pass the memory. The windows are the planned feeder's,
    /// per reception a second.
    #[test]
    fn the_rate_driven_gauges_are_window_times_rate_and_members() {
        let plan = Plan::planned(false).with_members(4, 16 * PLANNED_BYTES_PER_SEC as u64);
        for connections in [10usize, 1_000, 20_000] {
            let budget = Budget::of_memory(Budget::memory_for(connections, plan), plan);
            let admission = budget.admission();
            assert_eq!(admission.connections, connections);
            let rate = admission.rate;
            assert_eq!(rate, connections as u64 * PLANNED_RECEPTIONS_PER_SEC as u64);
            let members = plan.member_feeders;
            for store in Store::ALL {
                let limit = budget.gauge(store).limit();
                let expected = match store.driver() {
                    // The fingerprints' tables' fixed part beside the rate's (`Plan::before_feeders`).
                    Driver::Rate if store == Store::Dedup => {
                        plan.per_rate.of(store) * (rate as usize + members * 600) / 600
                            + crate::exchange::DEDUP_FIXED_BYTES
                    }
                    // What is taken: the members' worth planned apart, and every table's fixed
                    // part (`Plan::strike_tables_bytes`).
                    Driver::Rate if let Some(class) = store.strike_class() => {
                        plan.per_rate.of(store) * rate as usize / 600
                            + plan.member_unit().of(store) * members
                            + plan.strike_tables_bytes(class)
                    }
                    // The fan-out's queues as they keep whatever they hold (`Plan::fanout_queues`).
                    Driver::Rate if store == Store::Fanout => {
                        plan.per_rate.of(store) * (rate as usize + members * 600) / 600
                            + plan.fanout_queues()
                    }
                    // The tables of one entry per receiver: the members' receivers planned apart,
                    // and what they hold whatever the rate (`Plan::receiver_tables_of`).
                    Driver::Rate if plan.receiver_tables_of(store) > 0 => {
                        plan.per_rate.of(store) * rate as usize / 600
                            + plan.member_unit().of(store) * members
                            + plan.receiver_tables_of(store)
                    }
                    Driver::Rate => plan.per_rate.of(store) * (rate as usize + members * 600) / 600,
                    // The delivery shards' orders' roots beside the connections' floors
                    // (`delivery::FIXED_BYTES`).
                    Driver::Connection if store == Store::Delivery => {
                        plan.per_feeder.of(store) * connections
                            + plan.member_unit().of(store) * members
                            + crate::delivery::FIXED_BYTES
                    }
                    Driver::Connection => {
                        plan.per_feeder.of(store) * connections
                            + plan.member_unit().of(store) * members
                    }
                    // No seats without MLAT; the members' records are theirs, and the models'
                    // tables' fixed parts whatever the seats (`Plan::seat_tables_of`).
                    Driver::Seat => {
                        plan.member_unit().of(store) * members + plan.seat_tables_of(store)
                    }
                    // The clock model parts' tables at the room the members' rate sets.
                    Driver::Fixed if store == Store::Parts => plan.parts_bytes(),
                    // One raw record a link (`Plan::twins_tables`).
                    Driver::Fixed if store == Store::Twins => plan.twins_tables(),
                    // The anchors' and the directory's tables at their caps, whatever the relay
                    // carries.
                    Driver::Fixed => store.fixed_bytes(),
                };
                // The sharing outbox's slots as it keeps whatever it holds (`Plan::sharing_outbox`),
                // and what waits for the sealer whatever it holds.
                let expected = expected
                    + match store {
                        Store::Batches => plan.sharing_outbox(),
                        Store::Epochs => crate::exchange::EPOCHS_FIXED_BYTES,
                        _ => 0,
                    };
                assert_eq!(limit, expected, "{store:?} at {connections}");
            }
            let all: usize = Store::ALL
                .iter()
                .map(|store| budget.gauge(*store).limit())
                .sum();
            assert!(all <= budget.memory() - budget.base(), "{connections}");
            // The memory is planned to the byte but for what no whole connection fits in.
            assert!(budget.memory() - budget.planned() < plan.per_feeder.total());
        }
    }

    /// `R_max` is the lesser of what the memory and the cores carry, the connection limit the
    /// fewer of the same, and each is printed with what bound it.
    #[test]
    fn r_max_is_the_lesser_of_memory_and_cores() {
        let plan = Plan::planned(false);
        // Planned at the cores it runs on: the epochs' slices follow the message threads.
        let memory = Budget::memory_for(30_000, plan.with_cores(Some(64)));
        // Plenty of cores: the memory bounds both.
        let many = Budget::of_memory(memory, plan.with_cores(Some(64))).admission();
        assert_eq!(many.connections, 30_000);
        assert_eq!(many.rate, many.rate_by_memory);
        assert_eq!(
            (many.connections_bound, many.rate_bound),
            (Bound::Memory, Bound::Memory)
        );
        // Few cores: the cores bound both, and the rate is what the stages carry beside the
        // sessions, a connection's mean at least.
        let few = Budget::of_memory(memory, plan.with_cores(Some(8))).admission();
        assert!(few.connections < 30_000);
        assert_eq!(few.rate, few.rate_by_cores.unwrap_or(0));
        assert_eq!(
            (few.connections_bound, few.rate_bound),
            (Bound::Cores, Bound::Cores)
        );
        assert!(few.rate >= few.connections as u64 * 600);
        assert!(few.rate < many.rate);
        // The one derivation: what the accessors say is what the plan admits.
        let budget = Budget::of_memory(memory, plan.with_cores(Some(8)));
        assert_eq!(budget.max_receptions_per_sec(), few.rate);
        assert_eq!(budget.max_bytes_per_sec(), few.bytes_per_sec());
        // In charged bytes, the unit the stores are planned in and the shedder judges by.
        assert_eq!(
            budget.max_bytes_per_sec(),
            few.rate * PLANNED_CHARGED_BYTES_PER_SEC as u64 / PLANNED_RECEPTIONS_PER_SEC as u64
        );
        assert_eq!(
            budget.max_records_per_sec(),
            few.rate * crate::cores::RECORDS_PER_PLANNED_FEEDER / 600
        );
        // Feeders carried: at the planned mean, and at the ceiling a source is held to.
        assert_eq!(few.feeders_at_mean(), few.rate / 600);
        assert_eq!(
            few.feeders_at_ceiling(),
            few.rate / crate::ingest::SOURCE_RECEPTIONS_PER_SEC
        );
        assert!(few.feeders_at_ceiling() < few.feeders_at_mean());
        // A smaller memory carries less of each.
        let small = Budget::of_memory(Budget::memory_for(1_000, plan), plan).admission();
        assert!(small.rate < many.rate && small.connections < many.connections);
    }

    /// MLAT's seats are their own pool, planned from what the connections leave: connections first
    /// at their floor and mean rate, seats from MLAT's share and whatever the connections do not
    /// use, never more than the connections.
    #[test]
    fn mlat_seats_are_a_pool_of_their_own() {
        let plan = Plan::planned(true);
        let connection = plan.per_feeder.total() + plan.per_rate.total();
        // Memory for 500 pairs holds them, and connections go on beyond the seats: three times
        // as many connections as before, where a seat for each connection admitted 500.
        let pairs = Budget::of_memory(Budget::memory_for(500, plan), plan).admission();
        assert!(pairs.seats >= 500, "{pairs:?}");
        assert!(pairs.connections > pairs.seats, "{pairs:?}");
        assert_eq!(pairs.seats_bound, Bound::Memory);
        // The connections were planned from the memory the share left, at floor + rate, and the
        // seats from the rest: together within the memory.
        let total = Budget::memory_for(500, plan) - plan.before_feeders();
        assert!(pairs.connections * connection <= total - total / 100 * 25);
        assert!(pairs.connections * connection + pairs.seats * plan.per_seat.total() <= total);
        // A memory-bound relay admits far more connections than the same memory in pairs (the
        // public pod's fifteen).
        let pair = connection + plan.per_seat.total();
        assert!(pairs.connections > 2 * (total / pair), "{pairs:?}");
        // The same relay not hosting MLAT carries more connections in that memory, and no seat.
        let without = Plan::planned(false);
        let none = Budget::of_memory(Budget::memory_for(500, plan), without).admission();
        assert_eq!(none.seats, 0);
        assert!(none.connections > pairs.connections);
        assert_eq!(none.seats_bound, Bound::NotHosted);
        // Cores that carry fewer connections than the memory holds cap them, and the seats are what
        // the connections leave of the memory, never more than the connections.
        let cores = plan.with_cores(Some(2));
        let capped = Budget::of_memory(Budget::memory_for(20_000, plan), cores).admission();
        assert_eq!(capped.connections_bound, Bound::Cores);
        assert!(
            capped.seats > 0 && capped.seats <= capped.connections,
            "{capped:?}"
        );
        // Plenty of memory and few connections: a seat for each connection and no more.
        let roomy = Budget::of_memory(Budget::memory_for(20_000, plan), plan.with_cores(Some(1)))
            .admission();
        assert!(roomy.seats <= roomy.connections, "{roomy:?}");
        // The gauges of the seat stores are the seats' worth, nothing else's.
        let budget = Budget::of_memory(Budget::memory_for(500, plan), plan);
        let seats = budget.mlat_seats();
        assert!(seats >= 500);
        for store in Store::ALL {
            if store.driver() == Driver::Seat {
                assert_eq!(
                    budget.gauge(store).limit(),
                    plan.per_seat.of(store) * seats
                        + plan.member_unit().of(store) * plan.member_feeders
                        + plan.mlat_tables_of(store)
                        // The models' tables' fixed parts, whatever the seats
                        // (`Plan::seat_tables_of`).
                        + plan.seat_tables_of(store),
                    "{store:?}"
                );
            }
        }
        // A hosting relay whose cores or memory leave no seat refuses to start.
        let starved = Budget::of_memory(Budget::memory_for(1, plan) - 1, plan);
        assert!(starved.check().is_err());
    }

    /// The epochs are planned a run and a decision for each reception and a slice for each
    /// message thread a batch is cut across, at the most batches the rate's bytes may be (each
    /// charged at least `ingest::CHARGE_FLOOR`), on the cores the plan names. Before, every
    /// reception was planned a slice of its own and its batch's place in the word, though a slice
    /// holds every reception of its batch on its thread.
    #[test]
    fn the_epochs_are_planned_a_slice_per_thread_for_each_batch() {
        let batches = PLANNED_CHARGED_BYTES_PER_SEC / crate::ingest::CHARGE_FLOOR;
        let held = crate::seal::EPOCHS_HELD as usize * crate::seal::EPOCH_MS as usize / 1_000;
        for cores in [Some(1), Some(4), Some(16), None] {
            let threads = crate::exchange::slicing_threads(cores);
            let planned = PerFeeder::planned_for(true, false, 0, cores).epochs;
            assert_eq!(
                planned,
                (PLANNED_RECEPTIONS_PER_SEC * crate::exchange::EPOCH_BYTES_PER_RECEPTION
                    + batches * threads * crate::exchange::EPOCH_BYTES_PER_SLICE)
                    * held,
                "{cores:?}"
            );
            // The plan's rate follows its cores.
            assert_eq!(
                Plan::planned(true).with_cores(cores).per_rate.epochs,
                planned,
                "{cores:?}"
            );
        }
        assert_eq!(crate::exchange::slicing_threads(Some(0)), 1);
        assert_eq!(
            crate::exchange::slicing_threads(Some(10_000)),
            crate::exchange::SHARDS
        );
        // A planned feeder's receptions far outnumber its batches' slices on a relay's cores.
        assert!(
            PerFeeder::planned_for(true, false, 0, Some(16)).epochs
                < PLANNED_RECEPTIONS_PER_SEC
                    * (crate::exchange::EPOCH_BYTES_PER_RECEPTION
                        + crate::exchange::EPOCH_BYTES_PER_SLICE)
                    * held
        );
    }

    /// The members' rate holds no seat's raw: hosted MLAT seats every receiver it solves, a
    /// member's raw link's as its own feeders', in the one cap the seats are planned at, so a
    /// member's feeders take seats already planned. Before, each of the members' feeders was
    /// planned a seat's raw too, held twice, and a world relay seated a sixth fewer receivers.
    #[test]
    fn the_members_rate_holds_no_seat_the_seats_already_hold() {
        let plan = Plan::planned(true)
            .with_cores(Some(16))
            .with_members(1_024, 16 * PLANNED_BYTES_PER_SEC as u64);
        let unit = plan.member_unit();
        for store in [Store::Arrived, Store::Engine] {
            assert!(plan.per_seat.of(store) > 0, "{store:?}");
            assert_eq!(unit.of(store), 0, "{store:?}");
        }
        // What the members' sessions write is theirs still.
        assert_eq!(
            unit.records,
            crate::products::records_per_feeder(PLANNED_RECEPTIONS_PER_SEC)
        );
        // And every rate-driven store is a feeder's worth of the members' rate: the receivers'
        // tables each the receivers a member feeder's records bring, the rest the planned
        // feeder's.
        for store in Store::ALL {
            if store.driver() == Driver::Rate && store.strike_class().is_none() {
                let expected = if plan.receiver_tables_of(store) > 0 {
                    plan.per_rate.of(store) / RECEIVERS_PER_PLANNED_FEEDER
                        * RECEIVERS_PER_MEMBER_FEEDER
                } else {
                    plan.per_rate.of(store)
                };
                assert_eq!(unit.of(store), expected, "{store:?}");
            }
        }
    }

    /// Waiters are served in turn by source, not by who wakes first: a source with many waiting
    /// takes one turn at a time, so another's one batch is not behind all of them.
    #[tokio::test]
    async fn waiters_are_served_in_turn_by_source() {
        let batch = DRR_QUANTUM * 3 / 4;
        let gauge = Gauge::new(Store::Ingest, batch);
        let held = gauge.charge_for(9, batch).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for (source, count) in [(1u64, 5), (2u64, 1)] {
            for _ in 0..count {
                let (gauge, order) = (Arc::clone(&gauge), Arc::clone(&order));
                tasks.push(tokio::spawn(async move {
                    let charge = gauge.charge_for(source, batch).await;
                    order.lock().map(|mut order| order.push(source)).ok();
                    tokio::task::yield_now().await;
                    drop(charge);
                }));
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(gauge.waiting(), 6);
        drop(held);
        for task in tasks {
            task.await.ok();
        }
        let order = order.lock().map(|order| order.clone()).unwrap_or_default();
        // The late source is served in its turn, second, not after the five before it.
        assert_eq!(order, [1, 2, 1, 1, 1, 1]);
        assert_eq!((gauge.held(), gauge.waiting()), (0, 0));
    }

    /// A newcomer does not take room ahead of a waiter, and a waiter that gives up is no one's
    /// block.
    #[tokio::test]
    async fn a_newcomer_queues_behind_waiters_and_an_abandoned_waiter_blocks_no_one() {
        let gauge = Gauge::new(Store::Ingest, 100);
        let held = gauge.charge_for(0, 100).await;
        let big = tokio::spawn({
            let gauge = Arc::clone(&gauge);
            async move { gauge.charge_for(1, 100).await.bytes() }
        });
        tokio::task::yield_now().await;
        let abandoned = tokio::spawn({
            let gauge = Arc::clone(&gauge);
            async move { gauge.charge_for(2, 50).await.bytes() }
        });
        tokio::task::yield_now().await;
        abandoned.abort();
        tokio::task::yield_now().await;
        let behind = tokio::spawn({
            let gauge = Arc::clone(&gauge);
            async move { gauge.charge_for(3, 10).await.bytes() }
        });
        tokio::task::yield_now().await;
        // Room for the newcomer's 10 only, after 90 are let go: it still waits behind the 100.
        drop(held);
        assert_eq!(big.await.ok(), Some(100));
        assert_eq!(behind.await.ok(), Some(10));
        assert_eq!(gauge.held(), 0);
    }

    /// The receiver figure is the records a second the relay admits (its own and the members')
    /// over the longest an honest receiver goes between batches, and every table of one entry per
    /// receiver is charged what it allocates at that figure within its store's limit. A rate no
    /// memory backs names `RECEIVERS_MOST`, so every table's planned bytes stay a number.
    #[test]
    fn the_receiver_figure_is_the_records_a_second_over_the_gap() {
        let plan = Plan::planned(false).with_members(4, 16 * PLANNED_BYTES_PER_SEC as u64);
        for connections in [1usize, 100, 5_000] {
            let budget = Budget::of_memory(Budget::memory_for(connections, plan), plan);
            let admission = budget.admission();
            let records = admission.records_per_sec()
                + crate::ingest::member_records_per_sec(plan.member_feeders);
            assert_eq!(
                budget.receivers(),
                records as usize * RECEIVER_GAP_SECONDS,
                "{connections}"
            );
            let receivers = budget.receivers();
            for (store, planned) in [
                (Store::Credit, crate::credit::planned_bytes(receivers)),
                (Store::Stations, crate::stations::planned_bytes(receivers)),
                (
                    Store::Descriptions,
                    crate::hub::descriptions_planned_bytes(receivers),
                ),
                (
                    Store::Located,
                    crate::products::located_planned_bytes(receivers),
                ),
                (
                    Store::Consistency,
                    crate::consistency::planned_bytes(receivers),
                ),
            ] {
                assert!(
                    planned <= budget.gauge(store).limit(),
                    "{store:?} at {connections}: {planned} > {}",
                    budget.gauge(store).limit()
                );
            }
        }
        let unbacked = plan.admit(usize::MAX);
        assert_eq!(plan.receivers(&unbacked), RECEIVERS_MOST);
        assert!(crate::hub::descriptions_planned_bytes(RECEIVERS_MOST) < usize::MAX / 4);
    }

    /// The tables that grow with what the relay is sent are each a store of their own, held whole
    /// before any feeder: the products' remembered tables on every relay, the world's fixes only
    /// where a world product is gathered (each at its cap), and standing's tables where MLAT is
    /// hosted, from the seats it admits. Before, none was charged anywhere, and an idle base stood
    /// in for them.
    #[test]
    fn what_the_relay_is_sent_into_is_planned_in_stores_of_its_own() {
        let plan = Plan::planned(false);
        let budget = Budget::of_memory(4 << 30, plan);
        assert_eq!(
            budget.gauge(Store::Remembered).limit(),
            crate::products::REMEMBERED_BYTES
        );
        assert_eq!(budget.gauge(Store::World).limit(), 0);
        assert_eq!(budget.gauge(Store::Standing).limit(), 0);
        let world = plan.with_world(true);
        let planned = crate::products::world_planned_bytes(true);
        assert!(planned > 0);
        assert_eq!(world.world_bytes(), planned);
        assert_eq!(
            Budget::of_memory(4 << 30, world)
                .gauge(Store::World)
                .limit(),
            planned
        );
        assert_eq!(world.before_feeders() - plan.before_feeders(), planned);
        assert_eq!(crate::products::world_planned_bytes(false), 0);
        let hosting = Budget::of_memory(4 << 30, Plan::planned(true));
        let seats = hosting.mlat_seats();
        assert!(seats > 0);
        assert_eq!(
            hosting.gauge(Store::Standing).limit(),
            crate::standing::FIXED_BYTES + seats * crate::standing::BYTES_PER_SEAT
        );
        assert!(
            crate::standing::planned_bytes(seats) <= hosting.gauge(Store::Standing).limit(),
            "standing's tables at the seats admitted pass their store"
        );
    }

    /// RFC-0181 §10: the bundle indexes are planned the cheaper of the two ways both bound them.
    /// A relay offering many parents for its rate plans them by the rate, and admits more for it;
    /// a relay offering none plans none; and the rate's share is added and taken back exactly.
    #[test]
    fn the_bundle_indexes_are_planned_the_cheaper_way() {
        let plan = Plan::planned(false)
            .with_members(4, 16 * PLANNED_BYTES_PER_SEC as u64)
            .with_bundle_indexes(200_000);
        let memory = Budget::memory_for(100, plan);
        let admitted = |plan: &Plan| plan.admit(memory - plan.before_feeders()).connections;
        let cheaper = plan.with_cheaper_indexes(memory);
        assert!(cheaper.indexes_by_rate);
        assert!(admitted(&cheaper) > admitted(&plan));
        assert!(cheaper.before_feeders() < plan.before_feeders());
        assert!(cheaper.per_rate.own_strikes > plan.per_rate.own_strikes);
        // The budget takes the cheaper plan when it sizes its stores.
        assert!(Budget::of_memory(memory, plan).plan().indexes_by_rate);
        let none = Plan::planned(false).with_bundle_indexes(0);
        assert!(!none.with_cheaper_indexes(memory).indexes_by_rate);
        assert_eq!(
            plan.with_indexes_by_rate(true).with_indexes_by_rate(false),
            plan
        );
    }

    /// Every table of one entry per receiver plans within its linear figures: what it allocates
    /// at a figure is never more than its fixed part and its bytes per receiver for each, the
    /// figures the plan charges a feeder's worth and the relay by
    /// (`Plan::receiver_tables_of`, `PerFeeder::planned_for`), at every figure up to the most.
    #[test]
    fn every_receivers_table_plans_within_its_linear_figures() {
        let figures = (0..=24)
            .map(|shift| 1usize << shift)
            .flat_map(|figure| [figure - 1, figure, figure + 1, figure * 3 / 2])
            .filter(|figure| *figure <= RECEIVERS_MOST);
        for receivers in figures {
            for (name, planned, fixed, per) in [
                (
                    "credit",
                    crate::credit::planned_bytes(receivers),
                    crate::credit::FIXED_BYTES,
                    crate::credit::BYTES_PER_RECEIVER,
                ),
                (
                    "stations",
                    crate::stations::planned_bytes(receivers),
                    crate::stations::FIXED_BYTES,
                    crate::stations::BYTES_PER_RECEIVER,
                ),
                (
                    "descriptions",
                    crate::hub::descriptions_planned_bytes(receivers),
                    crate::hub::DESCRIPTIONS_FIXED_BYTES,
                    crate::hub::DESCRIPTIONS_BYTES_PER_RECEIVER,
                ),
                (
                    "located",
                    crate::products::located_planned_bytes(receivers),
                    crate::products::LOCATED_FIXED_BYTES,
                    crate::products::LOCATED_BYTES_PER_RECEIVER,
                ),
            ] {
                assert!(
                    planned <= fixed + per * receivers,
                    "{name} at {receivers}: {planned} > {fixed} + {per} x {receivers}"
                );
            }
        }
    }

    /// The base is what the relay measured idle, its margin and the Noise pool's idle buffers,
    /// and what grows with the threads is planned beside it: an inflater for each core's ingest
    /// worker. Before, 256 MiB and the pool, twenty times what was measured.
    #[test]
    fn the_base_is_the_measured_idle_and_the_inflaters_follow_the_cores() {
        assert_eq!(
            BASE_BYTES,
            MEASURED_IDLE_BYTES
                + BASE_MARGIN_BYTES
                + tally_wire::noise::POOL_IDLE * tally_wire::noise::MAX_MESSAGE
        );
        const { assert!(BASE_BYTES < 64 << 20) };
        let plan = Plan::planned(true);
        assert_eq!(plan.base, BASE_BYTES + MLAT_BASE_BYTES);
        const { assert!(tally_wire::batch::INFLATER_BYTES >= 32 << 10) };
        for cores in [1usize, 4, 16] {
            let cored = plan.with_cores(Some(cores));
            assert_eq!(
                cored.ingest_inflaters(),
                cores * tally_wire::batch::INFLATER_BYTES
            );
            assert!(
                cored
                    .before_feeders_parts()
                    .contains(&("ingest-inflaters", cored.ingest_inflaters()))
            );
        }
        assert_eq!(plan.ingest_inflaters(), tally_wire::batch::INFLATER_BYTES);
    }
}
