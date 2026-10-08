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
//! [`BASE_BYTES`], and [`MLAT_BASE_BYTES`] more when it hosts MLAT) and the members' pool. The
//! budget is `--memory`, by default the memory the relay runs in ([`memory_available`]: the lesser
//! of its cgroup's `memory.high` and `memory.max`, else the host's) less [`HEADROOM_BYTES`], what
//! no store charges. A Hello beyond the ceiling is refused ("no spare slot"), and a relay whose
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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::sync::Notify;

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
    /// over a bin, its settling and the steps MLAT may fall behind (`mlat_host::STEPS_BEHIND`).
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
    /// Connection buffers: a feeder connection's message in hand and its records
    /// (`ingest::BUFFERS_PER_CONNECTION`).
    Buffers,
    /// Batches read off connections and waiting for, or in, the ingest stage, or on their way to
    /// the epochs: each connection's allowance (`ingest::Allowance`), in bytes as charged.
    Ingest,
    /// Decoded batches between ingest and the sealer: each epoch open in the message exchange,
    /// closing, and waiting at the sealer (`seal::EPOCHS_HELD`).
    Epochs,
    /// What the sealer has signed and the hub has not yet taken (the deduplicated stream's
    /// batches and the products), and the peers' records waiting for the sealer.
    Products,
}

impl Store {
    pub const ALL: [Self; 13] = [
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
    ];

    const fn index(self) -> usize {
        self as usize
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
}

impl PerFeeder {
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
            ..*self
        }
    }

    /// Every store's cost together: what admitting one feeder reserves.
    pub fn total(&self) -> usize {
        Store::ALL
            .iter()
            .fold(0usize, |sum, store| sum.saturating_add(self.of(*store)))
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
            batches: (2 * bytes + crate::sharing::parity::OVERHEAD)
                * crate::sharing::member::HORIZON_SECONDS as usize,
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
            // A feeder's connection: the message it is reading and the records decoded from it
            // until each is handed on (`ingest::BUFFERS_PER_CONNECTION`), carved when it is
            // admitted. What the Noise pool keeps idle is the process's (`BASE_BYTES`).
            buffers: crate::ingest::BUFFERS_PER_CONNECTION,
            // A feeder connection's allowance of batches read and not yet held by the epochs, in
            // bytes as they are charged (`ingest::charge_of`: signed, inflated and referenced),
            // carved from this store when it is admitted (`ingest::FEEDER_ALLOWANCE`).
            ingest: crate::ingest::FEEDER_ALLOWANCE,
            // The decoded batches of the epochs between ingest and the sealer.
            epochs: decoded * crate::seal::EPOCHS_HELD as usize * crate::seal::EPOCH_MS as usize
                / 1_000,
            // What the sealer signed of those epochs and the hub has not taken: every reception
            // twice as a signed record's observation, in the deduplicated stream and in its area's
            // regional batch, as if none were a copy (`products::OUTBOX_EPOCHS`).
            products: receptions * PRODUCT_BYTES_PER_RECEPTION * crate::products::OUTBOX_EPOCHS,
        }
    }
}

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
/// grew 247 KiB a feeder from 1,000 to 5,000 feeders and about 100 KiB from 5,000 to 20,000, so the
/// cost of a feeder falls as feeders are added and the 1k/5k line taken back to no feeders (260 MiB)
/// is an upper bound on the base. A feeder's reservation (`PerFeeder::planned`) is several times
/// that measured growth, so this base is safe at any load.
pub const BASE_BYTES: usize =
    (256 << 20) + tally_wire::noise::POOL_IDLE * tally_wire::noise::MAX_MESSAGE;
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
    pub per_feeder: PerFeeder,
    /// The member sessions the relay holds at once ([`members_for`]): each carves its ingest
    /// allowance ([`Plan::per_member`]).
    pub members: usize,
    /// The feeders the members' one shared rate (`--max-member-bytes-per-sec`, all of them
    /// together) is worth: planned once, however many members carry it.
    pub member_feeders: usize,
    /// The connections held at once (`--max-connections`): every one but a feeder's (whose are
    /// its reservation's, `PerFeeder::buffers`) carves its Noise buffers from room planned here
    /// (`Plan::connection_buffers`).
    pub connections: usize,
}

impl Plan {
    /// The plan of a relay that hosts MLAT (`hosts_mlat`) or does not, holding no member.
    pub fn planned(hosts_mlat: bool) -> Self {
        Self {
            base: BASE_BYTES + if hosts_mlat { MLAT_BASE_BYTES } else { 0 },
            per_feeder: PerFeeder::planned(hosts_mlat),
            members: 0,
            member_feeders: 0,
            connections: 0,
        }
    }

    /// The same plan holding `connections` connections at once, each with its Noise buffers.
    #[must_use]
    pub fn with_connections(self, connections: usize) -> Self {
        Self {
            connections,
            ..self
        }
    }

    /// The room batches past their connection's whole allowance take, one at a time
    /// (`ingest::OVERSIZE_BYTES`).
    pub fn oversize(&self) -> usize {
        crate::ingest::OVERSIZE_BYTES
    }

    /// The Noise buffers of every connection the cap allows (`ingest::BUFFERS_PER_CONNECTION`
    /// each), from which every connection but a feeder's carves its own.
    pub fn connection_buffers(&self) -> usize {
        self.connections
            .saturating_mul(crate::ingest::BUFFERS_PER_CONNECTION)
    }

    /// What the relay holds before any feeder: its base, the oversize room, the connections'
    /// buffers and the members' pool. Feeders reserve from what is left.
    pub fn before_feeders(&self) -> usize {
        self.base
            .saturating_add(self.oversize())
            .saturating_add(self.connection_buffers())
            .saturating_add(self.member_pool())
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
        self.per_feeder
            .as_member()
            .total()
            .saturating_mul(self.member_feeders)
    }

    /// The members' pool: their shared rate's worth, and every member session's allowance.
    pub fn member_pool(&self) -> usize {
        self.member_rate_pool()
            .saturating_add(self.per_member().saturating_mul(self.members))
    }
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
fn feeders_for_rate(bytes_per_sec: u64) -> usize {
    usize::try_from(bytes_per_sec)
        .unwrap_or(usize::MAX)
        .div_ceil(PLANNED_BYTES_PER_SEC)
        .max(1)
}

/// The memory this relay runs in: the least of its cgroup's `memory.high` (past which the kernel
/// throttles it) and `memory.max` (past which it kills it), its own cgroup's and every ancestor's,
/// when any is a number; else the host's memory. The budget is this less [`HEADROOM_BYTES`]
/// ([`budget_within`]).
pub fn memory_available() -> usize {
    cgroup_limit()
        .or_else(host_memory)
        .unwrap_or(BASE_BYTES * 4)
}

/// What the relay holds that no store charges and no base plans: the allocator's free pages not
/// yet given back, the threads' stacks, the kernel's socket buffers (charged to the relay's
/// cgroup), the binary's own pages. Measured under 10 MiB at the public relay's shape (RFC-0181,
/// "Sizing"); held at 64 MiB. The budget is the memory the relay runs in less this
/// ([`budget_within`]), so a relay at its plan is still this far from being throttled or killed.
pub const HEADROOM_BYTES: usize = 64 << 20;

/// The budget of a relay that runs in `limit` bytes ([`memory_available`]): all of it but
/// [`HEADROOM_BYTES`].
pub fn budget_within(limit: usize) -> usize {
    limit.saturating_sub(HEADROOM_BYTES)
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
    /// Charges waiting for room now: a release wakes them only when there are any.
    waiting: AtomicUsize,
    released: Notify,
}

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
            released: Notify::new(),
        })
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

    fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Release);
        self.released.notify_waiters();
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

    /// `bytes` charged, waiting for room while the store is full: for a store that pushes back.
    pub async fn charge(self: &Arc<Self>, bytes: usize) -> Charge {
        if let Some(charge) = self.take(bytes) {
            return charge;
        }
        self.waited.fetch_add(1, Ordering::Relaxed);
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let _waiting = Waiting(&self.waiting);
        loop {
            let released = self.released.notified();
            if let Some(charge) = self.take(bytes) {
                return charge;
            }
            released.await;
        }
    }

    fn release(&self, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::SeqCst);
        // A waiter counts itself before it looks for room (all sequentially consistent), so a
        // release its look missed sees it waiting.
        if self.waiting.load(Ordering::SeqCst) > 0 {
            self.released.notify_waiters();
        }
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

/// A charge waiting for room, counted while it waits (however its wait ends).
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Bytes a store holds for one thing, released when it is dropped.
#[derive(Debug, Default)]
pub struct Charge {
    gauge: Option<Arc<Gauge>>,
    bytes: usize,
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
    /// raw handed to its seal).
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
    /// What the relay holds whatever its feeders (`Plan::base`).
    base: usize,
    /// The bytes feeders reserve from: the budget less what it holds before any feeder
    /// (`Plan::before_feeders`).
    total: usize,
    per_feeder: PerFeeder,
    /// The member sessions the pool holds and the feeders their shared rate is worth
    /// (`Plan::with_members`).
    members: usize,
    member_feeders: usize,
    /// The connections whose buffers are planned (`Plan::with_connections`).
    connections: usize,
    reserved: Arc<AtomicUsize>,
    /// Bytes the admitted members hold of their pool.
    members_reserved: Arc<AtomicUsize>,
    gauges: Arc<[Arc<Gauge>]>,
    /// Batches past their connection's whole allowance, one at a time (`Plan::oversize`).
    oversize: Arc<Gauge>,
    /// Every connection's Noise buffers but a feeder's (`Plan::connection_buffers`).
    connection_buffers: Arc<Gauge>,
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
            base: BASE_BYTES,
            total,
            per_feeder,
            members: 0,
            member_feeders: 0,
            connections: 0,
            reserved: Arc::new(AtomicUsize::new(0)),
            members_reserved: Arc::new(AtomicUsize::new(0)),
            gauges,
            oversize: Gauge::new(Store::Ingest, 0),
            connection_buffers: Gauge::new(Store::Buffers, 0),
        };
        budget.limit_gauges();
        budget
    }

    /// The same gauges (whoever holds one keeps it), resized for `memory` bytes and `plan`: what a
    /// relay is told after its parts were built.
    pub fn resize(&mut self, memory: usize, plan: Plan) {
        self.memory = memory;
        self.base = plan.base;
        self.per_feeder = plan.per_feeder;
        self.members = plan.members;
        self.member_feeders = plan.member_feeders;
        self.connections = plan.connections;
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

    /// The plan this budget was sized from.
    pub fn plan(&self) -> Plan {
        Plan {
            base: self.base,
            per_feeder: self.per_feeder,
            members: self.members,
            member_feeders: self.member_feeders,
            connections: self.connections,
        }
    }

    /// Whether the budget holds its members' pool and a feeder beside it: a relay that would refuse
    /// every Hello, or hold fewer members than it was told, refuses to start instead, saying what
    /// it was given and what it needs.
    pub fn check(&self) -> Result<(), String> {
        let plan = self.plan();
        let needed = Self::memory_for(1, plan);
        if self.memory >= needed && self.ceiling() > 0 {
            return Ok(());
        }
        Err(format!(
            "{} bytes of memory admit no feeder beside {} member sessions: the relay needs {} \
             bytes for itself, {} for batches past their connection's allowance, {} for the \
             Noise buffers of its {} connections (--max-connections), {} for its members' shared \
             rate ({} feeders' worth at --max-member-bytes-per-sec) and {} for each member \
             session (as many as its areas bring, at most its connections), and {} for each \
             feeder, {needed} in all for these and one feeder; give it more (--memory, or the \
             memory it runs in: the unit's MemoryHigh and MemoryMax, the container's \
             limits.memory), or plan fewer connections or a slower members' rate \
             (--max-connections, --max-member-bytes-per-sec)",
            self.memory,
            self.members,
            self.base,
            plan.oversize(),
            plan.connection_buffers(),
            self.connections,
            plan.member_rate_pool(),
            self.member_feeders,
            plan.per_member(),
            self.per_feeder.total(),
        ))
    }

    /// The least memory that admits `feeders` beside what the plan holds before any
    /// (`Plan::before_feeders`).
    pub fn memory_for(feeders: usize, plan: Plan) -> usize {
        plan.before_feeders()
            .saturating_add(plan.per_feeder.total().saturating_mul(feeders))
    }

    /// The most feeders the budget admits: the feeder ceiling.
    pub fn ceiling(&self) -> usize {
        self.total
            .checked_div(self.per_feeder.total())
            .unwrap_or(usize::MAX)
    }

    /// Reserves one feeder's bytes in every store, or `None` when they do not fit (the Hello is
    /// refused). Feeders reserve from their own room, never from the members' pool.
    pub fn reserve(&self) -> Option<Reservation> {
        Self::take(&self.reserved, self.per_feeder.total(), self.total)
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
        self.per_feeder
    }

    /// The member sessions the pool holds (`members_for`).
    pub fn members(&self) -> usize {
        self.members
    }

    /// The feeders the members' shared rate is planned as.
    pub fn member_feeders(&self) -> usize {
        self.member_feeders
    }

    pub fn memory(&self) -> usize {
        self.memory
    }

    /// What the relay holds whatever its feeders.
    pub fn base(&self) -> usize {
        self.base
    }

    /// What the relay plans to hold at its ceiling: what it holds before any feeder
    /// (`Plan::before_feeders`) and every admitted feeder's share (`memory`, less what no whole
    /// feeder fits in).
    pub fn planned(&self) -> usize {
        Self::memory_for(self.ceiling(), self.plan())
    }

    /// What every admitted feeder and member together may hold in `store`, at the ceiling: the
    /// feeders' shares, the members' shared rate's, and each member session's allowance.
    pub fn store_bytes(&self, store: Store) -> usize {
        let feeders = self.per_feeder.of(store).saturating_mul(self.ceiling());
        let rate = self
            .per_feeder
            .as_member()
            .of(store)
            .saturating_mul(self.member_feeders);
        let sessions = if store == Store::Ingest {
            self.plan().per_member().saturating_mul(self.members)
        } else {
            0
        };
        feeders.saturating_add(rate).saturating_add(sessions)
    }

    /// The gauge of `store`: the same one for the budget's life, whatever it is resized to.
    pub fn gauge(&self, store: Store) -> Arc<Gauge> {
        Arc::clone(&self.gauges[store.index()])
    }

    pub fn report(&self) -> MemoryReport {
        let plan = self.plan();
        MemoryReport {
            memory: self.memory,
            base: self.base,
            per_feeder: self.per_feeder.total(),
            ceiling: self.ceiling(),
            reserved: self.reserved(),
            members: self.members,
            per_member: plan.per_member(),
            member_feeders: self.member_feeders,
            members_reserved: self.members_reserved(),
            stores: self.gauges.iter().map(|gauge| gauge.report()).collect(),
            oversize: self.oversize.report(),
            connection_buffers: self.connection_buffers.report(),
        }
    }
}

/// The budget as served on `GET /memory`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MemoryReport {
    pub memory: usize,
    pub base: usize,
    pub per_feeder: usize,
    pub ceiling: usize,
    pub reserved: usize,
    pub members: usize,
    pub per_member: usize,
    pub member_feeders: usize,
    pub members_reserved: usize,
    pub stores: Vec<GaugeReport>,
    /// Batches past their connection's whole allowance (`Plan::oversize`).
    pub oversize: GaugeReport,
    /// Every connection's Noise buffers but a feeder's (`Plan::connection_buffers`).
    pub connection_buffers: GaugeReport,
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

    #[test]
    fn a_relay_whose_memory_admits_no_feeder_will_not_start() {
        for hosts_mlat in [false, true] {
            let plan = Plan::planned(hosts_mlat);
            let none = Budget::of_memory(plan.base + plan.per_feeder.total() - 1, plan);
            assert_eq!(none.ceiling(), 0);
            assert!(none.check().is_err());
            let one = Budget::of_memory(Budget::memory_for(1, plan), plan);
            assert_eq!(one.ceiling(), 1);
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
            members: 0,
            member_feeders: 0,
            connections: 0,
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
            assert_eq!(short.ceiling(), 0);
            let refused = short.check().err().unwrap_or_default();
            assert!(refused.contains("beside 2 member sessions"), "{refused}");
            // Memory that would hold the pool but not a feeder, and a feeder but not the pool.
            let pool_only = Budget::of_memory(plan.base + plan.member_pool(), plan);
            assert!(pool_only.check().is_err());
            let feeder_only =
                Budget::of_memory(Budget::memory_for(1, Plan::planned(hosts_mlat)), plan);
            assert!(feeder_only.check().is_err());
            let fits = Budget::of_memory(Budget::memory_for(1, plan), plan);
            assert_eq!(fits.ceiling(), 1);
            assert!(fits.check().is_ok());
            assert!(fits.reserve_member().is_some() && fits.reserve_member().is_some());
            assert!(fits.reserve().is_some());
        }
    }

    #[test]
    fn the_budget_is_the_memory_run_in_less_the_headroom() {
        assert_eq!(budget_within(640 << 20), 576 << 20);
        assert_eq!(budget_within(HEADROOM_BYTES - 1), 0);
    }

    /// Every store's gauge is its share of the budget at the ceiling, and resizing the budget
    /// resizes the gauges whoever holds them; together they never pass the feeders' memory.
    #[test]
    fn the_gauges_are_each_stores_share_and_follow_a_resize() {
        let plan = Plan::planned(false);
        let per_feeder = plan.per_feeder;
        let mut budget = Budget::of_memory(Budget::memory_for(10, plan), plan);
        let epochs = budget.gauge(Store::Epochs);
        assert_eq!(epochs.limit(), per_feeder.epochs * 10);
        let all: usize = Store::ALL
            .iter()
            .map(|store| budget.gauge(*store).limit())
            .sum();
        assert!(all <= budget.memory() - budget.base());
        budget.resize(Budget::memory_for(20, plan), plan);
        assert_eq!(epochs.limit(), per_feeder.epochs * 20);
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
        let held = gauge.charge(80).await;
        let waiting = tokio::spawn({
            let gauge = Arc::clone(&gauge);
            async move { gauge.charge(50).await.bytes() }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(held);
        assert_eq!(waiting.await.ok(), Some(50));
        assert_eq!(gauge.waited(), 1);
        assert_eq!(gauge.held(), 0);
    }
}
