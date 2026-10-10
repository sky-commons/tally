//! Capacity is admission, never a silent drop inside a store (RFC-0181 §9). Every store and
//! every queue that holds something per feeder ([`Store`]) states what one feeder costs it
//! ([`PerFeeder::planned`]); a feeder's bytes in every store are reserved together when it is
//! admitted ([`Budget::reserve`]), beside the upload cap's headroom check (RFC-0171, `admission`),
//! and released when it leaves ([`Reservation`] dropped). A sharing member is a session over which
//! another relay's data comes in (a relay whose offer this one verified dialling it, or this relay's
//! own one-hop raw link): the members together are planned once, as the feeders their one shared
//! rate is worth, and each member session carves its ingest allowance from a pool sized at start
//! for every member session the protocol lets this relay's areas bring, at most its connections
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
//! The per-feeder costs are planning figures at the rate the RFC sizes a feeder to
//! ([`PLANNED_RECEPTIONS_PER_SEC`], [`PLANNED_BYTES_PER_SEC`]) times each store's own window,
//! named where the store defines it, so a store that changes its window changes its reservation.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::oneshot;

/// The stores that hold bytes per feeder: every store and queue of the relay whose size grows
/// with what feeders send.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Store {
    /// The one batch byte store, over the sharing repair horizon: the records the sharing groups
    /// hold, their parities, and the parities being reassembled (`sharing`).
    Batches,
    /// MLAT's sealed raw (`Held`'s sealed bins), shared by the engine and standing.
    Held,
    /// MLAT's open raw: the bins not yet sealed, in the raw shards and on their way to sealing,
    /// over a bin, its settling and the seals MLAT may fall behind (`mlat_host::SEALS_BEHIND`).
    Open,
    /// What batches told hosted MLAT's provisional solving and its step has not yet weighed: the
    /// decoded batches the notes keep alive, and the notes (`mlat_host::NOTES_PER_RECEIVER_STEP`),
    /// over the step intervals MLAT may fall behind; and the batches of receivers not yet described.
    Notes,
    /// The hosted engine's own tables that grow with its receivers: the receptions waiting for
    /// provisional solving (`tally_mlat::engine::Capacity::waiting`) and a window step's working
    /// set while it runs (`mlat_host::SOLVE_BYTES_PER_RECEIVER`).
    Engine,
    /// Hosted MLAT's batches waiting for their receiver's description: one not yet come
    /// (`tally_mlat::intake::Intake::hold_orphan`), or one taking effect at a step not yet applied
    /// (`mlat_host`, Descriptions), over `tally_mlat::intake::ORPHAN_MS`.
    Orphans,
    /// The message exchange's generations of fingerprints (`exchange::DEDUP_GENERATIONS`).
    Dedup,
    /// Subscriber queues' share of one feeder's inbound.
    Fanout,
    /// Delivery tags over the audit window.
    Delivery,
    /// Connection buffers: a feeder connection's Noise buffers, reading and writing, for its whole
    /// session (`ingest::BUFFERS_PER_CONNECTION`).
    Buffers,
    /// Batches read off connections and waiting for, or in, the ingest stage, or on their way to
    /// the epochs: each connection's allowance (`ingest::Allowance`), in bytes as charged.
    Ingest,
    /// Decoded batches between ingest and the sealer: each epoch open in the message exchange,
    /// closing, and waiting at the sealer (`seal::EPOCHS_HELD`).
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
}

impl Store {
    pub const ALL: [Self; 15] = [
        Self::Batches,
        Self::Held,
        Self::Open,
        Self::Notes,
        Self::Engine,
        Self::Orphans,
        Self::Dedup,
        Self::Fanout,
        Self::Delivery,
        Self::Buffers,
        Self::Ingest,
        Self::Epochs,
        Self::Products,
        Self::Records,
        Self::Shed,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// The name the store is served and printed by (`GET /memory`, `tally-relay check`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Batches => "batches",
            Self::Held => "held",
            Self::Open => "open",
            Self::Notes => "notes",
            Self::Engine => "engine",
            Self::Orphans => "orphans",
            Self::Dedup => "dedup",
            Self::Fanout => "fanout",
            Self::Delivery => "delivery",
            Self::Buffers => "buffers",
            Self::Ingest => "ingest",
            Self::Epochs => "epochs",
            Self::Products => "products",
            Self::Records => "records",
            Self::Shed => "shed",
        }
    }

    /// What drives this store's size: a connection's floor, the relay-wide rate, or a MLAT seat
    /// (RFC-0181 §9, "Admission"). Every store answers, with no default.
    pub const fn driver(self) -> Driver {
        match self {
            Self::Buffers | Self::Ingest | Self::Delivery | Self::Shed => Driver::Connection,
            Self::Batches
            | Self::Dedup
            | Self::Fanout
            | Self::Epochs
            | Self::Products
            | Self::Records => Driver::Rate,
            Self::Held | Self::Open | Self::Notes | Self::Engine | Self::Orphans => Driver::Seat,
        }
    }

    /// Whether this store holds decoded batches (`tally_wire::Decoded`), each charged at least its
    /// footprint, or its slices' shares of it, for as long as the store holds it: what
    /// [`Budget::decoded_charged`] sums. Every store answers here, with no default, so a store
    /// added is a decision made, not one forgotten.
    pub const fn holds_decoded(self) -> bool {
        match self {
            // A connection's batches read and decoded, the epochs', a subscriber queue's, the
            // batches provisional solving was told and those waiting for a description.
            Self::Ingest | Self::Epochs | Self::Fanout | Self::Notes | Self::Orphans => true,
            // Records and parities, MLAT's own raw and tables, fingerprints, tags, Noise buffers,
            // signed products: bytes of their own, never a decode kept alive.
            Self::Batches
            | Self::Held
            | Self::Open
            | Self::Engine
            | Self::Dedup
            | Self::Delivery
            | Self::Buffers
            | Self::Products
            | Self::Records
            | Self::Shed => false,
        }
    }
}

/// What one feeder costs each store, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerFeeder {
    pub batches: usize,
    pub held: usize,
    pub open: usize,
    pub notes: usize,
    pub engine: usize,
    pub orphans: usize,
    pub dedup: usize,
    pub fanout: usize,
    pub delivery: usize,
    pub buffers: usize,
    pub ingest: usize,
    pub epochs: usize,
    pub products: usize,
    pub records: usize,
    pub shed: usize,
    /// A connection's pace state outside any store: its record pace, its reception bucket and its
    /// share's counters ([`PACE_STATE_BYTES`]). Part of a connection's floor.
    pub pace: usize,
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
            kept.pace = self.pace;
        }
        kept
    }

    /// What a connection costs whatever it sends: its buffers, ingest allowance, delivery tags
    /// and pace state.
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
            Store::Held => self.held = bytes,
            Store::Open => self.open = bytes,
            Store::Notes => self.notes = bytes,
            Store::Engine => self.engine = bytes,
            Store::Orphans => self.orphans = bytes,
            Store::Dedup => self.dedup = bytes,
            Store::Fanout => self.fanout = bytes,
            Store::Delivery => self.delivery = bytes,
            Store::Buffers => self.buffers = bytes,
            Store::Ingest => self.ingest = bytes,
            Store::Epochs => self.epochs = bytes,
            Store::Products => self.products = bytes,
            Store::Records => self.records = bytes,
            Store::Shed => self.shed = bytes,
        }
    }

    pub fn of(&self, store: Store) -> usize {
        match store {
            Store::Batches => self.batches,
            Store::Held => self.held,
            Store::Open => self.open,
            Store::Notes => self.notes,
            Store::Engine => self.engine,
            Store::Orphans => self.orphans,
            Store::Dedup => self.dedup,
            Store::Fanout => self.fanout,
            Store::Delivery => self.delivery,
            Store::Buffers => self.buffers,
            Store::Ingest => self.ingest,
            Store::Epochs => self.epochs,
            Store::Products => self.products,
            Store::Records => self.records,
            Store::Shed => self.shed,
        }
    }

    /// What one feeder's worth of the members' shared rate costs each store: a feeder's, but for
    /// the connection buffers, which each member's connection takes from the connections' room
    /// (`Plan::connection_buffers`), and the ingest allowance, which each member session carves on
    /// its own (`Plan::per_member`), never from the rate's worth.
    pub fn as_member(&self) -> Self {
        Self {
            buffers: 0,
            ingest: 0,
            pace: 0,
            ..*self
        }
    }

    /// The sum of two costs, store by store.
    pub fn plus(&self, other: &Self) -> Self {
        let mut sum = Self {
            pace: self.pace.saturating_add(other.pace),
            ..Self::default()
        };
        for store in Store::ALL {
            sum.set(store, self.of(store).saturating_add(other.of(store)));
        }
        sum
    }

    /// Every store's cost together: what admitting one feeder reserves.
    pub fn total(&self) -> usize {
        Store::ALL
            .iter()
            .fold(self.pace, |sum, store| sum.saturating_add(self.of(*store)))
    }

    /// What one feeder at the planned rate costs each store over that store's window. `holds_raw`:
    /// whether this relay holds MLAT raw (`Held`, `Open`) at all, which it does only when it hosts
    /// MLAT.
    pub fn planned(holds_raw: bool) -> Self {
        let receptions = PLANNED_RECEPTIONS_PER_SEC;
        let bytes = PLANNED_BYTES_PER_SEC;
        // One second of one feeder's batches as the stages hold them: signed, inflated once, each
        // reception referenced (`tally_wire::Decoded::footprint`).
        let decoded = bytes + receptions * DECODED_BYTES_PER_RECEPTION;
        Self {
            // The one batch byte store, over the sharing repair horizon: the records, and their
            // parities, which the groups hold as long and charge to the same gauge. A parity is
            // as long as its manifest's longest stripe slice: a third of its records in a busy
            // area, all of them in one with a record a second (measured 2026-10-08, 5,000
            // feeders: parities 0.72 of the records), so it is planned at the most it can be,
            // its records' bytes and its own overhead (`sharing::parity::OVERHEAD`) a second.
            // And what sharing addresses to members waiting in its outbox for the next network
            // tick (`network::TICK`), charged to the same gauge (`sharing::Addressed`): a second's
            // records and parity sent to each child of its stripe trees (`stripes::FANOUT`), a
            // tick of it. (Once handed to a member's link, a send keeps this charge and takes its
            // link's share too, `Plan::member_links`.)
            batches: (2 * bytes + crate::sharing::parity::OVERHEAD)
                * crate::sharing::member::HORIZON_SECONDS as usize
                + (2 * bytes + crate::sharing::parity::OVERHEAD)
                    * crate::sharing::stripes::FANOUT
                    * crate::network::TICK.as_millis() as usize
                    / 1_000,
            // MLAT's sealed raw (`Held`): the sealed bins a holder keeps, at the rates measured
            // (`held::Rates::MEASURED`).
            held: if holds_raw {
                tally_mlat_solver::held::Rates::MEASURED
                    .cost(crate::mlat_host::SETTLE_MS)
                    .sealed
            } else {
                0
            },
            // MLAT's open raw (`Open`): a receiver's bins open over a bin, the engine's settling
            // and the steps it may fall behind before the oldest is shed
            // (`mlat_host::OPEN_MS`), at its ceiling.
            open: if holds_raw {
                tally_mlat_solver::held::Rates::MEASURED
                    .cost(crate::mlat_host::OPEN_MS)
                    .open
            } else {
                0
            },
            // Provisional solving's notes, where MLAT is hosted: a batch told is held (its decode
            // kept alive, and its notes) until the step after its stamp's interval weighs it, over
            // the intervals a host that sheds nothing holds, at the headroom a step's notes are
            // bounded by (`mlat_host::notes_per_feeder`: the count and the bytes from one figure).
            notes: if holds_raw {
                crate::mlat_host::notes_per_feeder(decoded)
            } else {
                0
            },
            // Hosted MLAT's batches waiting for a description (`Orphans`), over the longest one
            // waits (`mlat_host::orphans_per_feeder`).
            orphans: if holds_raw {
                crate::mlat_host::orphans_per_feeder(decoded)
            } else {
                0
            },
            // The engine's own tables (`Engine`): the receptions a seat may have waiting for
            // provisional solving, and its share of a window step's working set.
            engine: if holds_raw {
                tally_mlat::engine::WAITING_PER_RECEIVER * tally_mlat::provisional::WAITING_BYTES
                    + crate::mlat_host::SOLVE_BYTES_PER_RECEIVER
            } else {
                0
            },
            // `exchange::DEDUP_GENERATIONS` generations of fingerprints, one epoch each, the
            // deduplication's window (`exchange::DEDUP_WINDOW_MS`), as if no reception were a copy
            // of another's, with the tables' room to grow.
            dedup: receptions
                * crate::exchange::DEDUP_SLOTS_PER_RECEPTION
                * crate::exchange::DEDUP_ENTRY_BYTES
                * crate::seal::EPOCH_MS as usize
                / 1_000,
            // A subscriber's queue holds `BEHIND_MS` of inbound: the batches, and while they wait
            // their one decode.
            fanout: decoded * crate::fanout::BEHIND_MS as usize / 1_000,
            // A delivery tag per batch over the audit window (`delivery`).
            delivery: crate::delivery::PER_FEEDER_BYTES,
            // A feeder's connection: its Noise buffers in both directions, the reader's frame and
            // plaintext and the writer's (`ingest::BUFFERS_PER_CONNECTION`), carved when it is
            // admitted. What the Noise pool keeps idle is the process's (`BASE_BYTES`).
            buffers: crate::ingest::BUFFERS_PER_CONNECTION,
            // A feeder connection's allowance of batches read and not yet held by the epochs, in
            // bytes as they are charged (`ingest::charge_of`: signed, inflated and referenced, and
            // at least `ingest::CHARGE_FLOOR` a record), carved from this store when it is admitted
            // (`ingest::FEEDER_ALLOWANCE`, which a planned batch fills unfloored: this module's
            // tests hold it).
            ingest: crate::ingest::FEEDER_ALLOWANCE,
            // The decoded batches of the epochs between ingest and the sealer, and each reception's
            // place in the epoch's decisions while its word waits for the sealer
            // (`exchange::DECISION_BYTES_PER_RECEPTION`).
            epochs: (decoded + receptions * crate::exchange::DECISION_BYTES_PER_RECEPTION)
                * crate::seal::EPOCHS_HELD as usize
                * crate::seal::EPOCH_MS as usize
                / 1_000,
            // What the sealer signed of those epochs and the hub has not taken: every reception
            // twice as a signed record's observation, in the deduplicated stream and in its area's
            // regional batch, as if none were a copy (`products::OUTBOX_EPOCHS`).
            products: receptions * PRODUCT_BYTES_PER_RECEPTION * crate::products::OUTBOX_EPOCHS,
            // The records waiting for the sealer, and to be forwarded, apart from the outputs
            // (`products::records_per_feeder`).
            records: crate::products::records_per_feeder(receptions),
            // The sources the ingest rate tracks (`shed`): the ones a connection brings.
            shed: crate::shed::BYTES_PER_UNIT * crate::shed::UNITS_PER_CONNECTION,
            pace: PACE_STATE_BYTES,
        }
    }
}

/// What a connection's pace state holds outside any store: its record pace (`ingest::RecordPace`,
/// a rate, a burst and a locked token count), its entry in the reception ceilings
/// (`ingest::ReceptionCeilings`, a key and two numbers), each tens of bytes in a map; planned at
/// a kibibyte. (Its share of the ingest rate is a store, `Store::Shed`.)
pub const PACE_STATE_BYTES: usize = 1 << 10;

/// The rate the RFC sizes one feeder to: about 600 receptions and 8 KB of signed batches a second
/// (RFC-0181, "Requirement").
pub const PLANNED_RECEPTIONS_PER_SEC: usize = 600;
pub const PLANNED_BYTES_PER_SEC: usize = 8 * 1024;
/// One reception in a decoded batch: its reference, and its encoded observation in the inflated
/// bytes (the fixed part and a 14-byte Mode S message).
const DECODED_BYTES_PER_RECEPTION: usize =
    std::mem::size_of::<tally_wire::ObsRef>() + tally_wire::decoded::OBSERVATION_FIXED + 14;
/// One reception as the products hold it before the hub takes them: its encoded observation (the
/// fixed part and a 14-byte Mode S message) in two signed records, the deduplicated stream's batch
/// and its area's regional batch. Both are signed from the epoch's batches, so neither holds an
/// owned copy (`deduplicated::Stream::sign`, `tally_wire::RegionalBatch::sign_draft`).
const PRODUCT_BYTES_PER_RECEPTION: usize = 2 * (tally_wire::decoded::OBSERVATION_FIXED + 14);
/// What the relay holds whatever its feeders: descriptions, stream tables, the runtime and the one
/// batch each ingest worker is decoding (256 MiB), and the connection buffers the Noise pool keeps
/// idle (`noise::POOL_IDLE` messages). Measured (RFC-0181, "Sizing", 2026-10-07): resident memory
/// grew [`MEASURED_GROWTH_PER_FEEDER`] a feeder from 1,000 to 5,000 feeders and about 100 KiB from
/// 5,000 to 20,000, so the cost of a feeder falls as feeders are added and the 1k/5k line taken back
/// to no feeders (260 MiB) is an upper bound on the base. A feeder's reservation
/// (`PerFeeder::planned`) is above that measured growth (this module's tests hold it), so this
/// base is safe at any load.
pub const BASE_BYTES: usize =
    (256 << 20) + tally_wire::noise::POOL_IDLE * tally_wire::noise::MAX_MESSAGE;
/// What the relay's resident memory grew a feeder between 1,000 and 5,000 feeders, with no hosted
/// MLAT (RFC-0181, "Sizing", measured 2026-10-07): what [`BASE_BYTES`] rests on, held only while
/// every feeder reserves at least this.
pub const MEASURED_GROWTH_PER_FEEDER: usize = 247 << 10;
/// What hosting MLAT adds to the relay's own base, whatever its feeders: the engine's thread, its
/// pool and its empty tables (its raw is `Held`'s and `Open`'s, its notes `Notes`', its waiting
/// receptions and working set `Engine`'s, per feeder), and the signed records not yet taken
/// (`mlat_host::PUBLISHED_BYTES`). Measured (RFC-0181, "Sizing", 2026-10-08): a relay hosting MLAT
/// on two areas, before any feeder, was 19.8 MiB resident where the same relay without it was
/// 17.3 MiB. 2.5 MiB measured, held at 4 MiB, and the records' bound beside it.
pub const MLAT_BASE_BYTES: usize = (4 << 20) + crate::mlat_host::PUBLISHED_BYTES;

/// What a relay plans to hold: its own base, each feeder's cost in every store, and the pool its
/// sharing members reserve from. The base and the feeder's cost follow one switch, whether the
/// relay hosts MLAT, so they cannot disagree; a member is planned in the same feeder's cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub base: usize,
    /// What one connection costs whatever it sends: its floor (buffers, ingest allowance, delivery
    /// tags, pace state), reserved when it is admitted ([`Budget::reserve`]). Not the rate-driven
    /// stores', which follow the relay-wide rate, nor MLAT's, which follow its seats.
    pub per_feeder: PerFeeder,
    /// What one planned feeder's rate (600 receptions a second) costs the rate-driven stores over
    /// their windows: a gauge's limit is this over [`PLANNED_RECEPTIONS_PER_SEC`] times the
    /// relay-wide rate `R_max` and the members' rate.
    pub per_rate: PerFeeder,
    /// What one MLAT seat costs the seat stores (all zero where MLAT is not hosted).
    pub per_seat: PerFeeder,
    /// The member sessions the relay holds at once ([`members_for`]): each carves its ingest
    /// allowance ([`Plan::per_member`]).
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
}

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
        }
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
        Self { cores, ..self }
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
    ///    reverse; a feeder past them is still a connection, relayed and not solved.
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
        let seats_by_memory = if holds_raw {
            total
                .saturating_sub(per_connection.saturating_mul(connections))
                .checked_div(seat)
                .unwrap_or(usize::MAX)
        } else {
            0
        };
        let seats_by_cores =
            available.map(|nanos| crate::cores::seats_carried(nanos, holds_raw, connections));
        let seats = if holds_raw {
            seats_by_memory
                .min(seats_by_cores.unwrap_or(usize::MAX))
                .min(connections)
        } else {
            0
        };
        let seats_bound = if !holds_raw {
            Bound::NotHosted
        } else if seats == connections
            && connections < seats_by_memory.min(seats_by_cores.unwrap_or(usize::MAX))
        {
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
    /// `subscribers` subscribers (`--max-subscribers`) beside its member sessions: each with its
    /// Noise buffers (`Plan::connections`), and their records in the cores (`cores::Sessions`). One
    /// count for both, so the sessions whose buffers are planned are the sessions whose records
    /// are. Set after `with_members`, whose sessions it counts. Each role holds its own cap: before,
    /// the three shared the one, so the plan counted some 128 members, 25 feeders and 64
    /// subscribers in 128 connections, and a member past the connections the others held was
    /// closed on before its handshake, with no word to route around it by.
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
    }

    /// The room batches past their connection's whole allowance take, one at a time
    /// (`ingest::OVERSIZE_BYTES`).
    pub fn oversize(&self) -> usize {
        crate::ingest::OVERSIZE_BYTES
    }

    /// The Noise buffers of every connection but a feeder's the caps allow
    /// (`ingest::BUFFERS_PER_CONNECTION` each, reading and writing): those under the connection
    /// cap, the member sessions and the subscribers (`Hub::plan`), from which each carves its own.
    pub fn connection_buffers(&self) -> usize {
        self.connections
            .saturating_mul(crate::ingest::BUFFERS_PER_CONNECTION)
    }

    /// What waits for the member links this relay dials (`peers`), at most: each member session
    /// planned may be one, and each holds at most its share (`peers::WAITING_PER_LINK_BYTES`), from
    /// this room together (`Budget::member_links`).
    pub fn member_links(&self) -> usize {
        self.members
            .saturating_mul(crate::peers::WAITING_PER_LINK_BYTES)
    }

    /// What the members' shared rate (`--max-member-bytes-per-sec`) brings in a second at most, as
    /// planned: the feeders it is worth, each at the planned rate (no less than the rate itself).
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
    /// check` prints it by: its base, the oversize room, the connections' buffers, the members'
    /// pool, what waits for the member links and the parities being reassembled. The one list
    /// [`Plan::before_feeders`] sums and `check` prints, so a part planned is a part printed: a
    /// room added here and nowhere else is in both, and the deploy checks that add the lines up
    /// (`before-feeders`) never sum a list of their own.
    pub fn before_feeders_parts(&self) -> [(&'static str, usize); 6] {
        [
            ("base", self.base),
            ("oversize", self.oversize()),
            ("connection-buffers", self.connection_buffers()),
            ("member-pool", self.member_pool()),
            ("member-links", self.member_links()),
            ("parity-assembly", self.parity_assembly()),
        ]
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
        Self {
            members,
            member_feeders: if members == 0 {
                0
            } else {
                feeders_for_rate(members_bytes_per_sec)
            },
            ..self
        }
    }

    /// The feeders the members' shared rate is planned as.
    pub fn member_feeders(&self) -> usize {
        self.member_feeders
    }

    /// One member session's own bytes: its ingest allowance, a feeder's ([`CREDIT`] planned batches,
    /// `ingest::FEEDER_ALLOWANCE`), since what it forwards arrives as feeders' batches.
    ///
    /// [`CREDIT`]: crate::ingest::CREDIT
    pub fn per_member(&self) -> usize {
        self.per_feeder.ingest
    }

    /// What the members' shared rate holds in every store but their sessions' allowances
    /// (`PerFeeder::as_member`, the rate's feeders' worth).
    pub fn member_rate_pool(&self) -> usize {
        self.member_unit()
            .total()
            .saturating_mul(self.member_feeders)
    }

    /// What one feeder's worth of the members' shared rate costs every store but their sessions'
    /// allowances: the floor's delivery tags, the rate-driven stores' windows and, hosting MLAT, a
    /// seat's raw (the raw links bring other relays' feeders').
    pub fn member_unit(&self) -> PerFeeder {
        self.per_feeder
            .as_member()
            .plus(&self.per_rate)
            .plus(&self.per_seat)
    }

    /// The members' pool: their shared rate's worth, and every member session's allowance.
    pub fn member_pool(&self) -> usize {
        self.member_rate_pool()
            .saturating_add(self.per_member().saturating_mul(self.members))
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
    /// `R_max` in bytes a second, at the planned mean's bytes to receptions.
    pub fn bytes_per_sec(&self) -> u64 {
        mul_div(
            self.rate,
            PLANNED_BYTES_PER_SEC as u128,
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
/// most 973 MiB over 5,452 MiB planned in use, 17.8% ([`MEASURED_ALLOCATOR_PERCENT`]); planned at
/// 25.
pub const ALLOCATOR_PERCENT: usize = 25;

/// The share measured ([`ALLOCATOR_PERCENT`]), which the plan must hold.
pub const MEASURED_ALLOCATOR_PERCENT: usize = 18;
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
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `mallopt` only sets a parameter of the allocator; called before any thread starts.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, MALLOC_ARENAS);
        libc::mallopt(libc::M_MMAP_THRESHOLD, MMAP_THRESHOLD_BYTES);
        libc::mallopt(libc::M_TRIM_THRESHOLD, TRIM_THRESHOLD_BYTES);
    }
}

/// Returns every arena's free pages to the kernel (`malloc_trim(0)`), once, and records how long
/// it took. Called only by the trimmer thread, never by a stage.
pub fn trim_the_allocator() -> std::time::Duration {
    let began = std::time::Instant::now();
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `malloc_trim` only returns free pages of the allocator's own arenas.
    unsafe {
        libc::malloc_trim(0);
    }
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
            #[cfg(target_os = "linux")]
            // SAFETY: `setpriority` on this thread's own id touches no memory of ours.
            unsafe {
                libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, 19);
            }
            loop {
                std::thread::sleep(period);
                trim_the_allocator();
            }
        })
        .map(drop)
}

/// What the allocator holds now (`mallinfo2`, every arena): the bytes in use, the bytes it has
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
        // SAFETY: `mallinfo2` only reads the allocator's counters.
        let info = unsafe { libc::mallinfo2() };
        AllocatorReport {
            in_use: info.uordblks as u64,
            free: info.fordblks as u64,
            mapped: info.hblkhd as u64,
            arenas: info.arena as u64,
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
    /// part that splits its store between what it holds (`mlat_host`'s `Orphans` store, the
    /// batches waiting for a description and those waiting for a step), so a share never stays
    /// the size the store was when the part was built. What is charged to a share is charged to
    /// the store too, by its holder.
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
            covers: Vec::new(),
        })
    }

    /// A charge of nothing yet on this gauge, to grow (`Charge::try_grow`).
    pub fn empty(self: &Arc<Self>) -> Charge {
        Charge {
            gauge: Some(Arc::clone(self)),
            bytes: 0,
            covers: Vec::new(),
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

/// Bytes a store holds for one thing, released when it is dropped, and the decoded batches it is
/// charged for holding ([`Charge::cover`]), each counted once in the process's [`Covered`] for as
/// long as any charge covers it.
#[derive(Debug, Default)]
pub struct Charge {
    gauge: Option<Arc<Gauge>>,
    bytes: usize,
    covers: Vec<Cover>,
}

/// The decoded batches alive that some store's charge covers ([`Charge::cover`]), each counted
/// once however many stores and charges hold it: what [`Budget::decoded_held`] sets beside the
/// decodes alive (`tally_wire::decoded::live`), so one decode alive that no charge covers shows,
/// whatever the stores hold beside it. One a process ([`Covered::process`]), as the decodes alive
/// are counted once a process.
///
/// Before, the check summed the gauges of the stores that hold decodes. A connection's allowance
/// is carved whole from `Store::Ingest` when it is admitted (`ingest::Allowance`) and stays
/// carved while it reads nothing, and a decode in the epochs and a subscriber's queue is charged
/// by both: the sum ran about a megabyte past the decodes alive under a flood, and a holder
/// keeping dozens of batches uncharged was inside it.
///
/// Sharded by the decode's address so the stages' threads seldom meet on a lock: each decode's
/// address, how many covers hold it and the decode itself, weakly (a cover keeps no decode alive;
/// its allocation, and so its address, stays the decode's while a cover does).
///
/// It also judges every hand-off as it happens, not only when it is sampled: a
/// cover let go or lessened while its decode lives, leaving the decode's covers holding less than
/// its footprint, is a lapse counted there and then ([`Covered::lapses`]), and so is a decode that
/// lived and was let go with no cover ever made for it. A sample sees what is held at its instant;
/// these counters see every instant a hand-off made, so a holder that keeps a decode uncharged for
/// less than the time between two samples is counted all the same.
pub struct Covered {
    shards: [Mutex<BTreeMap<usize, CoverEntry>>; COVER_SHARDS],
    /// Hand-offs that left a live decode's covers short of its footprint (or none).
    short_hand_offs: AtomicU64,
    /// Decodes let go that no charge had ever covered.
    never_covered: AtomicU64,
}

/// What [`Covered`] counted at the hand-offs since the process started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lapses {
    /// A cover let go or lessened while its decode lived, leaving it covered for less than its
    /// footprint: the decode was held, from then, where no gauge was charged for all of it.
    pub short_hand_offs: u64,
    /// A decode alive and let go with no charge ever covering it.
    pub never_covered: u64,
}

const COVER_SHARDS: usize = 64;

static COVERED: Covered = Covered::new();

#[derive(Debug)]
struct CoverEntry {
    /// Its covers now. An entry whose covers are all let go while its decode lives stays, at
    /// none, until the decode is let go ([`Covered::gone`]): it is a decode alive and uncovered.
    covers: usize,
    /// The bytes its covers' charges hold for it together ([`Cover::bytes`]).
    vouched: usize,
    /// Its footprint, read when it was first covered: what it counts for while it is alive.
    footprint: usize,
    /// Let go (`tally_wire::decoded::on_drop`): no longer counted alive, whatever its covers.
    gone: bool,
    decoded: Weak<tally_wire::Decoded>,
}

impl Covered {
    const fn new() -> Self {
        Self {
            shards: [const { Mutex::new(BTreeMap::new()) }; COVER_SHARDS],
            short_hand_offs: AtomicU64::new(0),
            never_covered: AtomicU64::new(0),
        }
    }

    /// What the hand-offs left short, counted as each happened, since the process started.
    pub fn lapses(&self) -> Lapses {
        Lapses {
            short_hand_offs: self.short_hand_offs.load(Ordering::Relaxed),
            never_covered: self.never_covered.load(Ordering::Relaxed),
        }
    }

    /// Counts the hand-off just made to `entry` if it left a live decode short of its footprint.
    /// A decode whose last strong reference has gone is being let go (its `gone` follows, taking
    /// this lock), so it is not alive; one held anywhere is.
    fn judge(&self, entry: &CoverEntry) {
        let alive = !entry.gone && entry.decoded.strong_count() > 0;
        if alive && entry.vouched < entry.footprint {
            self.short_hand_offs.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The process's: every charge's covers ([`Charge::cover`]). Told each decode as it leaves
    /// `tally_wire::decoded::live` ([`Covered::gone`]).
    pub fn process() -> &'static Self {
        static TOLD: std::sync::Once = std::sync::Once::new();
        TOLD.call_once(|| {
            tally_wire::decoded::on_drop(|address| COVERED.gone(address));
        });
        &COVERED
    }

    /// The decode at `address` was let go and `live` no longer counts it: its covers, until they
    /// go, count for nothing.
    fn gone(&self, address: usize) {
        let mut shard = self.shard(address);
        match shard.get_mut(&address) {
            Some(entry) if entry.covers == 0 => {
                shard.remove(&address);
            }
            Some(entry) => entry.gone = true,
            None => {
                self.never_covered.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn shard(&self, address: usize) -> std::sync::MutexGuard<'_, BTreeMap<usize, CoverEntry>> {
        // Allocations are at least 16-byte aligned: the bits above those spread them.
        self.shards[(address >> 4) % COVER_SHARDS]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add(&self, decoded: &Arc<tally_wire::Decoded>, bytes: usize) -> usize {
        let address = Arc::as_ptr(decoded) as usize;
        let mut shard = self.shard(address);
        let entry = shard.entry(address).or_insert_with(|| CoverEntry {
            covers: 0,
            vouched: 0,
            footprint: decoded.footprint(),
            gone: false,
            decoded: Arc::downgrade(decoded),
        });
        entry.covers += 1;
        entry.vouched += bytes;
        address
    }

    fn remove(&self, address: usize, bytes: usize) {
        let mut shard = self.shard(address);
        if let Some(entry) = shard.get_mut(&address) {
            entry.covers -= 1;
            entry.vouched = entry.vouched.saturating_sub(bytes);
            self.judge(entry);
            // Kept at no covers while its decode may yet be let go (`gone` removes it then), so
            // a decode alive with none is known to have had one.
            if entry.covers == 0 && entry.gone {
                shard.remove(&address);
            }
        }
    }

    /// One cover of the decode at `address` holds `bytes` less for it.
    fn lessen(&self, address: usize, bytes: usize) {
        if bytes == 0 {
            return;
        }
        if let Some(entry) = self.shard(address).get_mut(&address) {
            entry.vouched = entry.vouched.saturating_sub(bytes);
            self.judge(entry);
        }
    }

    /// The bytes the charges covering `decoded` hold for it together.
    pub fn vouched_for(&self, decoded: &Arc<tally_wire::Decoded>) -> usize {
        let address = Arc::as_ptr(decoded) as usize;
        self.shard(address)
            .get(&address)
            .map_or(0, |entry| entry.vouched)
    }

    /// The decoded batches alive whose covers' charges hold less for them together than their
    /// footprint, and the bytes they are short: a decode one charge of a byte
    /// covers is held as surely as one no charge covers, outside every gauge.
    pub fn short(&self) -> (usize, usize) {
        self.short_decodes()
            .iter()
            .fold((0, 0), |(batches, bytes), (_, short)| {
                (batches + 1, bytes + short)
            })
    }

    /// The same, each by its address (which is its own while it is alive) and what it is short:
    /// a check that sees the same decode short twice knows it is held so, not caught in a hand-off.
    pub fn short_decodes(&self) -> Vec<(usize, usize)> {
        let mut short = Vec::new();
        // The decodes looked at are let go once their shard's lock is: one this held last is let
        // go here, and its going takes that lock (`Covered::gone`).
        let mut looked_at = Vec::new();
        for shard in &self.shards {
            let shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Only the covered: one alive with no cover left is what `with_live` counts apart.
            for (address, entry) in shard.iter().filter(|(_, entry)| entry.covers > 0) {
                if let Some(decoded) = entry.decoded.upgrade() {
                    if entry.vouched < decoded.footprint() {
                        short.push((*address, decoded.footprint() - entry.vouched));
                    }
                    looked_at.push(decoded);
                }
            }
            drop(shard);
            looked_at.clear();
        }
        short
    }

    /// How many charges cover `decoded` now.
    pub fn covers_of(&self, decoded: &Arc<tally_wire::Decoded>) -> usize {
        let address = Arc::as_ptr(decoded) as usize;
        self.shard(address)
            .get(&address)
            .map_or(0, |entry| entry.covers)
    }

    /// The decoded batches some charge covers, each once, and the bytes they hold
    /// (`Decoded::footprint`), beside `live` (the decodes alive, `tally_wire::decoded::live`) read
    /// at the same instant: every shard locked while both are read. A decode is covered before it
    /// is counted alive (`Decoded::from_verified_held`, its cover taking its shard's lock), and
    /// marked gone after it stops being counted (`Covered::gone`, taking the lock too), so with
    /// every lock held a decode `live` counts and no charge covers is one no charge covers; one
    /// whose cover outlasts it (a share kept until a sweep) counts for nothing once gone, and one
    /// caught between the two counts as covered for that instant. Before, the two were read at
    /// different instants and a check needed two samples to step over a decode made or dropped
    /// between them.
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
            for entry in shard
                .values()
                .filter(|entry| !entry.gone && entry.covers > 0)
            {
                batches += 1;
                bytes += entry.footprint;
            }
        }
        ((batches, bytes), live)
    }

    /// The decoded batches some charge covers, each once, and the bytes they hold.
    pub fn now(&self) -> (usize, usize) {
        self.with_live(|| (0, 0)).0
    }
}

/// One charge's hold on one decoded batch ([`Charge::cover`]): counted in its [`Covered`] while
/// it lives, with the bytes of its charge it holds for the decode. A charge's covers together hold
/// no more than its bytes (`Charge::settle`), so what the covers of a decode hold is what the
/// stores holding it are charged for it.
#[derive(Debug)]
struct Cover {
    covered: &'static Covered,
    address: usize,
    bytes: usize,
}

impl std::fmt::Debug for Covered {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Covered")
    }
}

impl Cover {
    fn new(covered: &'static Covered, decoded: &Arc<tally_wire::Decoded>, bytes: usize) -> Self {
        Self {
            covered,
            address: covered.add(decoded, bytes),
            bytes,
        }
    }

    /// Holds `bytes` less for its decode.
    fn lessen(&mut self, bytes: usize) {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        self.covered.lessen(self.address, bytes);
    }
}

impl Drop for Cover {
    fn drop(&mut self) {
        self.covered.remove(self.address, self.bytes);
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

    /// This charge is for holding `decoded` (or its share of it): the decode is counted as charged
    /// ([`Covered`]) for as long as this charge, or any part split from it or absorbing it, lives.
    /// Every store that holds decoded batches covers each with the charge it takes for it, so a
    /// decode alive with no cover is one held where no gauge sees it (`Budget::decoded_held`).
    pub fn cover(&mut self, decoded: &Arc<tally_wire::Decoded>) {
        self.cover_in(Covered::process(), decoded);
    }

    /// This charge holds no decode any more: its bytes go back to a pool that holds none (an
    /// allowance's carve, `ingest::Allowance`), which would otherwise count every decode its
    /// charges were lent for as covered for as long as the connection lasts.
    pub fn uncover(&mut self) {
        self.covers.clear();
    }

    /// As [`Charge::cover`], counted in `covered`: a test's own. The cover holds for the decode
    /// what this charge holds and its other covers do not, up to the decode's footprint.
    fn cover_in(&mut self, covered: &'static Covered, decoded: &Arc<tally_wire::Decoded>) {
        let free = self.bytes.saturating_sub(self.vouched());
        self.covers
            .push(Cover::new(covered, decoded, free.min(decoded.footprint())));
    }

    /// What its covers hold for their decodes together.
    fn vouched(&self) -> usize {
        self.covers.iter().map(|cover| cover.bytes).sum()
    }

    /// Its covers made to hold no more than its bytes once they have fallen (split off, released):
    /// the cover of the decode at `first` (one handed on with a part) gives up its hold first, then
    /// the newest. Never more than they hold, so a decode's covers hold what its stores are charged.
    fn settle(&mut self, first: Option<usize>) {
        let mut over = self.vouched().saturating_sub(self.bytes);
        if over == 0 {
            return;
        }
        if let Some(address) = first
            && let Some(cover) = self
                .covers
                .iter_mut()
                .find(|cover| cover.address == address)
        {
            let less = over.min(cover.bytes);
            cover.lessen(less);
            over -= less;
        }
        for cover in self.covers.iter_mut().rev() {
            if over == 0 {
                break;
            }
            let less = over.min(cover.bytes);
            cover.lessen(less);
            over -= less;
        }
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
    /// raw handed to its seal, bytes going back to a carve). The part covers no decode: one handed
    /// on with a decode is split with it ([`Charge::split_covering`]).
    ///
    /// Before, every part cloned every cover of the charge it came from: an epoch refused
    /// whole split a share for each of its slices off a charge covering all of them, each split a
    /// lock taken per cover, so a refused epoch of `n` slices cost `n²` of them on the message
    /// thread. A part covers only the decode it is handed on with, so a split costs one cover at
    /// most, whatever the charge it comes from covers.
    pub fn split(&mut self, bytes: usize) -> Charge {
        let part = self.part(bytes);
        self.settle(None);
        part
    }

    /// `bytes` of this charge moved into a part of their own, its covers not yet settled.
    fn part(&mut self, bytes: usize) -> Charge {
        let bytes = bytes.min(self.bytes);
        self.bytes -= bytes;
        Charge {
            gauge: self.gauge.clone(),
            bytes,
            covers: Vec::new(),
        }
    }

    /// As [`Charge::split`], the part handed on with `decoded` (a batch's slice with its share, a
    /// refused slice's share kept while its decode lives): it covers that decode and no other.
    ///
    /// The part's cover is made before this charge's own cover of the decode gives up what moved,
    /// so the decode's covers never hold less for it than its stores are charged, even for an
    /// instant.
    pub fn split_covering(&mut self, bytes: usize, decoded: &Arc<tally_wire::Decoded>) -> Charge {
        let address = Arc::as_ptr(decoded) as usize;
        // Counted where this charge's own cover of it is (a test's own), else the process's.
        let covered = self
            .covers
            .iter()
            .find(|cover| cover.address == address)
            .map_or_else(Covered::process, |cover| cover.covered);
        let mut part = self.part(bytes);
        part.cover_in(covered, decoded);
        self.settle(Some(address));
        part
    }

    /// Releases all but `bytes` of this charge.
    pub fn shrink_to(&mut self, bytes: usize) {
        if let Some(gauge) = &self.gauge
            && bytes < self.bytes
        {
            gauge.release(self.bytes - bytes);
            self.bytes = bytes;
            self.settle(None);
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
        self.covers.append(&mut other.covers);
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
    /// Bytes the admitted members hold of their pool.
    members_reserved: Arc<AtomicUsize>,
    gauges: Arc<[Arc<Gauge>]>,
    /// Batches past their connection's whole allowance, one at a time (`Plan::oversize`).
    oversize: Arc<Gauge>,
    /// Every connection's Noise buffers but a feeder's (`Plan::connection_buffers`).
    connection_buffers: Arc<Gauge>,
    /// What waits for the member links this relay dials (`Plan::member_links`).
    member_links: Arc<Gauge>,
    /// The parities being reassembled (`Plan::parity_assembly`).
    parity_assembly: Arc<Gauge>,
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
            oversize: Gauge::new(Store::Ingest, 0),
            connection_buffers: Gauge::new(Store::Buffers, 0),
            member_links: Gauge::new(Store::Batches, 0),
            parity_assembly: Gauge::new(Store::Batches, 0),
        };
        budget.limit_gauges();
        budget
    }

    /// The same gauges (whoever holds one keeps it), resized for `memory` bytes and `plan`: what a
    /// relay is told after its parts were built.
    pub fn resize(&mut self, memory: usize, plan: Plan) {
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
        self.oversize.set_limit(plan.oversize());
        self.connection_buffers.set_limit(plan.connection_buffers());
        self.member_links.set_limit(plan.member_links());
        self.parity_assembly.set_limit(plan.parity_assembly());
    }

    /// The room a batch past its connection's whole allowance takes (`ingest::Allowance`), one at
    /// a time: the same gauge for the budget's life.
    pub fn oversize(&self) -> Arc<Gauge> {
        Arc::clone(&self.oversize)
    }

    /// The room every connection but a feeder's carves its Noise buffers from: the same gauge for
    /// the budget's life, sized to the connection cap.
    pub fn connection_buffers(&self) -> Arc<Gauge> {
        Arc::clone(&self.connection_buffers)
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
                 bytes for itself, {} for batches past their connection's allowance, {} for the \
                 Noise buffers of its {} connections (--max-connections), {} for its members' shared \
                 rate ({} feeders' worth at --max-member-bytes-per-sec) and {} for each member \
                 session (as many as its areas bring, at most its connections) and {} more for what \
                 waits for its link to each, {} for the parities its members' rate reassembles at \
                 once (the parity-assembly room), and {} for each connection ({} of them its floor, \
                 the rest the windows of the planned rate{}), {needed} in all for these \
                 and one; give it more (--memory, or the \
                 memory it runs in: the unit's MemoryHigh and MemoryMax, the container's \
                 limits.memory), or plan fewer connections or a slower members' rate \
                 (--max-connections, --max-member-bytes-per-sec)",
                self.memory,
                self.plan.members,
                self.plan.base,
                plan.oversize(),
                plan.connection_buffers(),
                self.plan.connections,
                plan.member_rate_pool(),
                self.plan.member_feeders,
                plan.per_member(),
                crate::peers::WAITING_PER_LINK_BYTES,
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
                crate::cores::mlat_per_feeder(true),
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

    /// Reserves one member session's own bytes (its ingest allowance, `Plan::per_member`) from the
    /// members' pool, for as long as it is a member, or `None` when every member session planned
    /// is admitted. The members' shared rate is planned whole at start; members never reserve from
    /// the feeders' room, so a relay full of feeders still takes the members it was planned for.
    pub fn reserve_member(&self) -> Option<Reservation> {
        let plan = self.plan();
        Self::take(
            &self.members_reserved,
            plan.per_member(),
            plan.per_member().saturating_mul(plan.members),
        )
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

    /// Bytes the admitted members hold of their pool.
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
    /// §10: `limit = window x (R_max + members' rate)`), the seats', and each member session's
    /// allowance.
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
        let sessions = if store == Store::Ingest {
            self.plan().per_member().saturating_mul(self.plan.members)
        } else {
            0
        };
        floors
            .saturating_add(rate)
            .saturating_add(seats)
            .saturating_add(members)
            .saturating_add(sessions)
    }

    /// The gauge of `store`: the same one for the budget's life, whatever it is resized to.
    pub fn gauge(&self, store: Store) -> Arc<Gauge> {
        Arc::clone(&self.gauges[store.index()])
    }

    /// What the stores holding decoded batches ([`Store::holds_decoded`]) and the oversize room
    /// are charged now.
    pub fn decoded_charged(&self) -> usize {
        Store::ALL
            .iter()
            .filter(|store| store.holds_decoded())
            .map(|store| self.gauges[store.index()].held())
            .fold(self.oversize.held(), usize::saturating_add)
    }

    /// The decoded batches alive in this process (`tally_wire::decoded::live`) beside those some
    /// store's charge covers ([`Covered`], each decode once however many hold it), the covers read
    /// on both sides of the count and the larger kept, so a batch handed from one store to the next
    /// while they are read is not taken for one nobody holds; and what the stores holding decodes
    /// are charged ([`Budget::decoded_charged`]), for the report. Every decoded batch is covered
    /// by the charge it is decoded under (its connection's allowance, `ingest::InFlight`) and by
    /// every store's that holds it after, so a decode alive with no cover, other than a hand-off
    /// caught between its release and its drop, is a holder no gauge sees: the bytes that would
    /// grow past the budget. Exact to the batch: no allowance carved and idle, and no decode two
    /// stores hold, stands in for one.
    pub fn decoded_held(&self) -> DecodedHeld {
        let (covered, (batches, live)) = Covered::process().with_live(tally_wire::decoded::live);
        let short = Covered::process().short();
        DecodedHeld {
            batches,
            live,
            covered_batches: covered.0,
            covered: covered.1,
            short_batches: short.0,
            short: short.1,
            charged: self.decoded_charged(),
        }
    }

    pub fn report(&self) -> MemoryReport {
        let plan = self.plan();
        MemoryReport {
            memory: self.memory,
            base: self.plan.base,
            per_feeder: self.plan.per_feeder.total(),
            ceiling: self.ceiling(),
            admission: self.admission(),
            allocator: allocator_report(),
            reserved: self.reserved(),
            members: self.plan.members,
            per_member: plan.per_member(),
            member_feeders: self.plan.member_feeders,
            members_reserved: self.members_reserved(),
            stores: self.gauges.iter().map(|gauge| gauge.report()).collect(),
            decoded: self.decoded_held(),
            oversize: self.oversize.report(),
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
    pub per_member: usize,
    pub member_feeders: usize,
    pub members_reserved: usize,
    pub stores: Vec<GaugeReport>,
    /// The decoded batches alive beside what the stores holding them are charged
    /// (`Budget::decoded_held`): `live` past `charged` is a holder no gauge sees.
    pub decoded: DecodedHeld,
    /// Batches past their connection's whole allowance (`Plan::oversize`).
    pub oversize: GaugeReport,
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
    /// Of those, the batches some store's charge covers ([`Covered`]), each once, and their bytes.
    pub covered_batches: usize,
    pub covered: usize,
    /// What the stores holding decoded batches, and the oversize room, are charged: their room
    /// in use, allowances carved and idle among it, and a decode held twice charged twice.
    pub charged: usize,
    /// Of the covered batches, those whose covers' charges hold less for them together than their
    /// footprint, and the bytes they are short ([`Covered::short`]): held past what any gauge was
    /// charged, however many charges cover them.
    pub short_batches: usize,
    pub short: usize,
}

impl DecodedHeld {
    /// Decoded bytes alive that no store's charge covers.
    pub fn uncharged(&self) -> usize {
        self.live.saturating_sub(self.covered)
    }

    /// Decoded batches alive that no store's charge covers.
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

    /// A decoded batch of `receptions` receptions, its own.
    fn decoded(receptions: u32) -> Result<Arc<tally_wire::Decoded>, String> {
        let receiver = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        let batch = tally_wire::Batch::sign(
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
        )
        .map_err(|error| error.to_string())?;
        tally_wire::Decoded::from_verified(batch, 0, 0).map_err(|error| error.error.to_string())
    }

    /// A decode is counted covered once however many charges and stores hold it, a charge
    /// that covers nothing (an allowance carved and idle) counts for no decode, a cover follows
    /// its charge through a split and an absorb, and a decode no charge covers is counted
    /// uncovered: to the batch, so one leaked batch shows.
    #[test]
    fn each_decode_is_covered_once_and_an_idle_carve_covers_none() -> Result<(), String> {
        let covered: &'static Covered = Box::leak(Box::new(Covered::new()));
        let plan = Plan::planned(false);
        let budget = Budget::of_memory(Budget::memory_for(4, plan), plan);
        // An allowance carved and idle: charged, covering nothing.
        let idle = budget.gauge(Store::Ingest).try_charge(4 << 10);
        assert!(idle.is_some());
        assert_eq!(covered.now(), (0, 0));
        let (one, two, leaked) = (decoded(40)?, decoded(60)?, decoded(80)?);
        // `one` in the epochs and in a subscriber's queue, charged by both: counted once.
        let mut epochs = budget.gauge(Store::Epochs).empty();
        assert!(epochs.try_grow(one.footprint()));
        epochs.cover_in(covered, &one);
        let mut queue = budget.gauge(Store::Fanout).empty();
        assert!(queue.try_grow(one.footprint()));
        queue.cover_in(covered, &one);
        assert_eq!(covered.covers_of(&one), 2);
        assert_eq!(covered.now(), (1, one.footprint()));
        // `two`, charged whole and split across its slices: each part covers it.
        let mut in_flight = budget.gauge(Store::Epochs).empty();
        assert!(in_flight.try_grow(two.footprint()));
        in_flight.cover_in(covered, &two);
        let mut slice = in_flight.split(two.footprint() / 2);
        slice.cover_in(covered, &two);
        assert_eq!(covered.covers_of(&two), 2);
        assert_eq!(covered.now(), (2, one.footprint() + two.footprint()));
        // The slice's charge absorbed into the epoch's: the cover moves with it.
        assert!(epochs.absorb(slice).is_ok());
        assert_eq!(covered.covers_of(&two), 2);
        drop(in_flight);
        assert_eq!(covered.covers_of(&two), 1);
        // `leaked` is alive and covered by nothing: everything else is counted, it is not.
        assert_eq!(covered.covers_of(&leaked), 0);
        assert_eq!(covered.now(), (2, one.footprint() + two.footprint()));
        // Every charge let go: nothing covered, whatever is still alive.
        drop((epochs, queue));
        assert_eq!(covered.now(), (0, 0));
        assert_eq!(covered.covers_of(&one), 0);
        // A cover keeps no decode alive; one whose decode is gone counts as covered until it goes
        // (a dying decode, `Covered::with_live`), and is never short.
        let mut late = budget.gauge(Store::Notes).empty();
        late.cover_in(covered, &leaked);
        let weak = Arc::downgrade(&leaked);
        let footprint = leaked.footprint();
        drop(leaked);
        assert!(weak.upgrade().is_none());
        assert_eq!(covered.now(), (1, footprint));
        assert_eq!(covered.short(), (0, 0));
        drop(late);
        assert_eq!(covered.now(), (0, 0));
        Ok(())
    }

    /// A cover holds for its decode the bytes its charge was charged, never only
    /// its presence: a decode covered by a charge of one byte is short of its footprint, and so is
    /// one whose charge was shrunk below it or split away from it; a decode handed on in parts
    /// (`split_covering`) is held whole by them together at every step, and a charge's covers
    /// together never hold more than its bytes.
    #[test]
    fn a_cover_holds_what_its_charge_was_charged_and_no_more() -> Result<(), String> {
        let covered: &'static Covered = Box::leak(Box::new(Covered::new()));
        let plan = Plan::planned(false);
        let budget = Budget::of_memory(Budget::memory_for(4, plan), plan);
        let (one, two) = (decoded(40)?, decoded(60)?);
        // A byte's charge covering a whole decode: covered, and short of all but that byte.
        let mut token = budget.gauge(Store::Notes).empty();
        assert!(token.try_grow(1));
        token.cover_in(covered, &one);
        assert_eq!(covered.now(), (1, one.footprint()));
        assert_eq!(covered.short(), (1, one.footprint() - 1));
        // Charged its footprint beside it: whole.
        let mut queue = budget.gauge(Store::Fanout).empty();
        assert!(queue.try_grow(one.footprint()));
        queue.cover_in(covered, &one);
        assert_eq!(covered.short(), (0, 0));
        drop(token);
        assert_eq!(covered.short(), (0, 0));
        // Shrunk below it: short by what was released.
        queue.shrink_to(one.footprint() - 10);
        assert_eq!(covered.short(), (1, 10));
        drop(queue);
        // One charge covering two decodes holds each its own bytes, never one's for the other.
        let mut epoch = budget.gauge(Store::Epochs).empty();
        assert!(epoch.try_grow(one.footprint()));
        epoch.cover_in(covered, &one);
        assert!(epoch.try_grow(two.footprint() / 2));
        epoch.cover_in(covered, &two);
        assert_eq!(covered.vouched_for(&one), one.footprint());
        assert_eq!(covered.vouched_for(&two), two.footprint() / 2);
        // Handed on in a part with `one`: the part holds it and the epoch gives up as much for it,
        // never for `two`.
        let part = epoch.split_covering(one.footprint(), &one);
        assert_eq!(covered.vouched_for(&one), one.footprint());
        assert_eq!(covered.vouched_for(&two), two.footprint() / 2);
        assert_eq!(covered.covers_of(&one), 2);
        // A split carrying no decode leaves the charge's covers no more than its bytes.
        let back = epoch.split(two.footprint() / 4);
        assert_eq!(
            covered.vouched_for(&two),
            two.footprint() / 2 - two.footprint() / 4
        );
        // Absorbed, both the bytes and the covers move: nothing is held twice or lost.
        let mut joined = budget.gauge(Store::Epochs).empty();
        assert!(joined.absorb(part).is_ok());
        assert_eq!(covered.vouched_for(&one), one.footprint());
        drop((back, epoch, joined));
        assert_eq!(covered.now(), (0, 0));
        assert_eq!(covered.short(), (0, 0));
        Ok(())
    }

    #[test]
    fn a_feeder_is_admitted_only_with_room_in_every_store_and_leaving_frees_it() {
        let per_feeder = PerFeeder {
            batches: 10,
            held: 20,
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
            Store::Held,
            Store::Open,
            Store::Notes,
            Store::Engine,
            Store::Orphans,
        ] {
            assert_eq!(without.of(store), 0, "{store:?}");
            assert!(with.of(store) > 0, "{store:?}");
        }
        for store in Store::ALL {
            if !matches!(
                store,
                Store::Held
                    | Store::Open
                    | Store::Notes
                    | Store::Engine
                    | Store::Orphans
                    | Store::Buffers
            ) {
                assert!(without.of(store) > 0, "{store:?}");
            }
        }
        // A relay of 64 GiB holds thousands of planned feeders, never none.
        let budget = Budget::of_memory(64 << 30, Plan::planned(true));
        assert!(budget.ceiling() > 1_000);
        assert!(budget.check().is_ok());
        assert!(memory_available() > 0);
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
        assert_eq!(
            (budget.ceiling(), budget.memory_feeders()),
            (carried, 10_000)
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
        // Thirty-two cores carry the 10,000 the memory holds: the memory bounds it, and the
        // threads follow that rate, more than one a stage.
        let ten = Budget::of_memory(memory, members.with_cores(Some(32)));
        assert_eq!(ten.ceiling(), 10_000);
        assert!(ten.threads().message > 1 && ten.threads().ingest > 1);
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

    /// The members' shared rate is planned once, as the feeders it is worth, and each member
    /// session carves its allowance from a pool of its own: feeders filling their room leave the
    /// members' pool whole, and the pool holds exactly the member sessions it was sized for.
    #[test]
    fn members_reserve_from_their_own_pool_sized_at_start() {
        let per_feeder = PerFeeder {
            batches: 10,
            ingest: 3,
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
        }
        .with_members(2, 3 * PLANNED_BYTES_PER_SEC as u64 + 1);
        // The rate is worth four feeders, planned once for both sessions.
        assert_eq!(plan.member_feeders, 4);
        assert_eq!(
            (
                plan.per_member(),
                plan.member_rate_pool(),
                plan.member_pool()
            ),
            (3, 40, 46)
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
        assert_eq!(budget.members_reserved(), 6);
        assert!(budget.reserve_member().is_none());
        drop(first);
        assert!(budget.reserve_member().is_some());
        // The gauges are sized for the feeders, the members' rate and each session's allowance.
        assert_eq!(budget.gauge(Store::Batches).limit(), 10 * (3 + 4));
        assert_eq!(budget.gauge(Store::Ingest).limit(), 3 * 3 + 3 * 2);
        // A member's one connection takes its buffers from the connections' room, never from the
        // members' rate.
        let buffered = Plan {
            per_feeder: PerFeeder {
                buffers: 5,
                ..per_feeder
            },
            ..plan
        };
        assert_eq!(buffered.member_pool(), 46);
        let budget = Budget::of_memory(Budget::memory_for(3, buffered), buffered);
        assert_eq!(budget.gauge(Store::Buffers).limit(), 5 * 3);
        // A relay holding no member plans no rate for them.
        assert_eq!(plan.with_members(0, 1 << 20).member_pool(), 0);
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
    /// (which no top-trim reaches); the process comes back to a fraction of its peak within a few
    /// trim periods. Without the trimmer it stays at the peak. In a child process of its own, so no
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
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut now = resident_bytes()?;
            while now > peak / 2 && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(100));
                now = resident_bytes()?;
            }
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
        // SAFETY: a file opened for writing, handed to glibc's `malloc_info` and closed.
        unsafe {
            let name = std::ffi::CString::new(path.display().to_string())
                .map_err(|error| error.to_string())?;
            let file = libc::fopen(name.as_ptr(), c"w".as_ptr());
            if file.is_null() {
                return Err("fopen".to_owned());
            }
            libc::malloc_info(0, file);
            libc::fclose(file);
        }
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
        assert_eq!(epochs.limit(), per_feeder.epochs * 10);
        // A share a part split the store into follows it too (`mlat_host`'s waiting share).
        let third = epochs.share(|limit| limit / 3);
        assert_eq!(third.limit(), per_feeder.epochs * 10 / 3);
        let all: usize = Store::ALL
            .iter()
            .map(|store| budget.gauge(*store).limit())
            .sum();
        assert!(all <= budget.memory() - budget.base());
        budget.resize(Budget::memory_for(20, plan), plan);
        assert_eq!(epochs.limit(), per_feeder.epochs * 20);
        assert_eq!(third.limit(), per_feeder.epochs * 20 / 3);
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
        let gauge = Gauge::new(Store::Open, 100);
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

    /// A feeder's ingest line is its connection's allowance; that a batch at the planned rate is
    /// charged its bytes, not the floor, so the allowance holds the batches it was sized for, the
    /// compiler holds (`ingest::CHARGE_FLOOR`).
    #[test]
    fn the_ingest_line_is_the_allowance_a_planned_batch_fills() {
        assert_eq!(
            PerFeeder::planned(false).ingest,
            crate::ingest::FEEDER_ALLOWANCE
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

    /// What the stores holding decoded batches are charged is theirs and the oversize room's,
    /// never another store's.
    #[test]
    fn the_decoded_charge_is_the_decoded_stores_and_the_oversize_rooms() {
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
        assert_eq!(budget.decoded_charged(), decoded);
        charges.extend(budget.oversize().try_charge(1 << 20));
        charges.extend(budget.connection_buffers().try_charge(1 << 21));
        assert_eq!(budget.decoded_charged(), decoded + (1 << 20));
        assert_eq!(budget.report().decoded.charged, decoded + (1 << 20));
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
            assert!(plan.per_feeder.total() < full.total() / 2);
            let budget = Budget::of_memory(Budget::memory_for(3, plan), plan);
            let one = budget.reserve();
            assert!(one.is_some());
            assert_eq!(budget.reserved(), plan.per_feeder.total());
        }
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
                    Driver::Rate => plan.per_rate.of(store) * (rate as usize + members * 600) / 600,
                    Driver::Connection => {
                        plan.per_feeder.of(store) * connections
                            + plan.member_unit().of(store) * members
                            + if store == Store::Ingest {
                                plan.per_member() * plan.members
                            } else {
                                0
                            }
                    }
                    Driver::Seat => 0,
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
        let memory = Budget::memory_for(30_000, plan);
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
        assert_eq!(
            budget.max_bytes_per_sec(),
            few.rate * PLANNED_BYTES_PER_SEC as u64 / PLANNED_RECEPTIONS_PER_SEC as u64
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
                    plan.per_seat.of(store) * seats,
                    "{store:?}"
                );
            }
        }
        // A hosting relay whose cores or memory leave no seat refuses to start.
        let starved = Budget::of_memory(Budget::memory_for(1, plan) - 1, plan);
        assert!(starved.check().is_err());
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
}
