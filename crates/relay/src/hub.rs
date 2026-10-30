//! What every connection of a relay shares: the fan-out (`fanout::Router`), the staged ingest of
//! receivers' batches (`ingest::Stages`, RFC-0181), what it took in of every signed record, which
//! decides whether a copy is new (`strikes`, RFC-0171 §3.6), each receiver's newest
//! self-description, the admission budget (`budget`), and the relays this one offers as hints.
//!
//! A receiver's batch is admitted on the ingest worker that owns its raw shard ([`RawShard`]: what
//! it took in, `strikes`, and its station counters, touched by that worker alone), decoded once,
//! routed to the message exchange (the one deduplication, `exchange`) and offered to the fan-out
//! from there, so its subscribers read it in admitted order.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tally_wire::clocks::{Judged, Mono, Raw};

use tally_wire::batch::Hash;
use tally_wire::{
    Batch, ClientClockModel, ClientRecord, ClockModel, ClockModelPart, Decoded, FaultProof,
    Location, Positions, PublicKey, ReceiverInfo, ReceiverSite, Record, Region, RelayAddress,
};

use tally_mlat::intake::SiteRecord;

use crate::bounded::Bounded;
use crate::budget::{Budget, Plan, Store};
use crate::clock::RelayClock;
use crate::durable::{Durable, Kind, Prior};
use crate::egress::{Cap, Egress};
use crate::exchange::{Gauges, SHARDS, Sink, raw_shard};
use crate::fanout::{BEHIND_MS, Bounds, Filter, Listener, Router};
use crate::ingest::{InFlight, Pause, Refusal, Stage, Stages, Stamp, Threads};
use crate::network::{Asker, Network};
use crate::parts::Parts;
use crate::sharing::Now;
use crate::sharing::Rebuilt;
use crate::shed;
use crate::stations::{StationReport, Stations, StationsReport};
use crate::strikes::{
    Begun, Deliverer, Shares, Start, StrikeStores, Strikes, Usable, Verdict, Window,
};
use crate::subscription::{ClientItem, ClientSubscription, Described, Subscription};

/// The memory a hub is budgeted until it is told its own (`Hub::memory`, which a relay always
/// does from `--memory`): a fixed figure, never the host's, so a hub a test builds behaves the
/// same on any machine.
pub const DEFAULT_MEMORY: usize = 16 << 30;

/// The least a subscriber's queue may hold, whatever the budget: a few seconds of one busy
/// feeder, so a relay sized for few feeders still serves a subscriber a burst.
pub const MIN_QUEUE_BYTES: usize = 64 * 1024 * 1024;

/// What a relay's session is trusted with (`Hub::relay_trust`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayTrust {
    /// A relay whose offer this relay verified: a sharing member.
    Member,
    /// A relay the operator accepted and whose offer is not verified: the directory only.
    Directory,
}

/// How many receivers' descriptions the relay holds: the receiver figure (`budget::Plan::receivers`,
/// the receivers the records a second it admits may be within the longest an honest receiver goes
/// between batches), in one table and one order of activity (`Receivers`), never an even share of
/// it in each raw shard: receivers land in shards by a keyed hash, so a shard's are a random draw
/// and an even share is over full on every batch while another shard has room. When full, the one
/// least recently active is forgotten: a receiver is active when it is first described and
/// whenever a batch of it is forwarded, never by a description alone (`Bounded`). So descriptions
/// from throwaway keys forget each other oldest first, a receiver publishing at least once per
/// table's worth of new keys keeps its place, and a new receiver is described from its first
/// description, however full the table of receivers that publish. A forgotten receiver's batches
/// still flow, to whole-world subscribers only, until it describes itself again (a feeder's link
/// does so at its next batch, see `link`; one known only through a relay link, at its feeder's next
/// periodic description).
///
/// The descriptions are held to bytes as well as to their count: a description is at most one
/// message, so the count alone would let throwaway keys hold a message each. Each receiver is
/// given the most an honest description and its site hold ([`DESCRIPTION_BYTES_PER_RECEIVER`]),
/// so the receivers the figure holds are never forgotten for bytes while they describe themselves
/// honestly.
pub const DESCRIPTION_BYTES_PER_RECEIVER: usize =
    crate::credit::DESCRIPTION_MOST + 255 + ReceiverSite::MAX_LEN;

/// What one entry of each of the descriptions' tables allocates beside its description's counted
/// bytes ([`Known::bytes`]): the cells (`Bounded::bytes_per_key`), what the member links told of
/// it ([`TOLD_PER_RECEIVER`] entries), the directory's entry,
/// its two cell indexes' entries (`footprint::Tree`), the site waiting for it and that site's
/// record, and the two records' shared headers.
const DESCRIPTION_TABLES_PER_RECEIVER: usize = Bounded::<PublicKey, Cells>::bytes_per_key()
    + TOLD_PER_RECEIVER * Bounded::<(u64, PublicKey), Told>::bytes_per_key()
    + Bounded::<PublicKey, Known>::bytes_per_key()
    + 2 * crate::footprint::Tree::<(u64, Edge), ()>::bytes_per_entry()
    + Bounded::<PublicKey, HeldSite>::bytes_per_key()
    + ReceiverSite::MAX_LEN
    + 3 * (crate::footprint::arc::<Record>() + crate::footprint::shared_bytes(0));

/// What the descriptions' store (`budget::Store::Descriptions`) takes for each receiver the
/// figure holds: its tables' entries and its description's bytes.
pub const DESCRIPTIONS_BYTES_PER_RECEIVER: usize =
    DESCRIPTION_TABLES_PER_RECEIVER + DESCRIPTION_BYTES_PER_RECEIVER;

/// What the descriptions' tables take beside [`DESCRIPTIONS_BYTES_PER_RECEIVER`] for each
/// receiver: the cells' fixed part, the directory's, the indexes' and the waiting sites' fixed
/// parts, and the receiver theirs are one past the cells' by and a figure of none is held at.
pub const DESCRIPTIONS_FIXED_BYTES: usize = Bounded::<PublicKey, Cells>::fixed_bytes()
    + Bounded::<(u64, PublicKey), Told>::fixed_bytes()
    + Bounded::<PublicKey, Known>::fixed_bytes()
    + Bounded::<PublicKey, HeldSite>::fixed_bytes()
    + 2 * crate::footprint::Tree::<(u64, Edge), ()>::bytes_planned(0)
    + 2 * DESCRIPTIONS_BYTES_PER_RECEIVER;

/// The descriptions the cells hold for `receivers` receivers: the figure, one at least.
const fn described_count(receivers: usize) -> usize {
    if receivers == 0 { 1 } else { receivers }
}

/// What a member link has told its peer of one receiver (`Hub::to_describe`): the newest time its
/// description was issued as the link last sent it, and when, by `M`, the link last sent a batch
/// of it.
#[derive(Clone, Copy, Debug)]
pub struct Told {
    issued_ms: u64,
    batch: Mono,
}

/// The member links a receiver's batches go down within the gap, as planned: a record goes down
/// its stripe's tree to each child (`sharing::stripes::FANOUT`). A link and receiver forgotten past
/// it (a stripe whose fan-out was raised, repairs) only describe the receiver again on that link.
pub const TOLD_PER_RECEIVER: usize = crate::sharing::stripes::FANOUT;

/// What the descriptions' tables allocate at most for `receivers` receivers: the cells at the
/// figure, what the member links told at [`TOLD_PER_RECEIVER`] for each, the directory and the
/// waiting sites at one more, the two indexes at that many, and
/// every description's bytes at the most the cells hold. Never more than
/// [`DESCRIPTIONS_FIXED_BYTES`] and [`DESCRIPTIONS_BYTES_PER_RECEIVER`] for each (a test holds
/// it).
pub const fn descriptions_planned_bytes(receivers: usize) -> usize {
    let count = described_count(receivers);
    let held = count + 1;
    Bounded::<PublicKey, Cells>::planned_bytes(count)
        + Bounded::<(u64, PublicKey), Told>::planned_bytes(TOLD_PER_RECEIVER * count)
        + Bounded::<PublicKey, Known>::planned_bytes(held)
        + Bounded::<PublicKey, HeldSite>::planned_bytes(held)
        + held
            * (ReceiverSite::MAX_LEN
                + crate::footprint::arc::<Record>()
                + crate::footprint::shared_bytes(0))
        + 2 * crate::footprint::Tree::<(u64, Edge), ()>::bytes_planned(held)
        + held * 2 * (crate::footprint::arc::<Record>() + crate::footprint::shared_bytes(0))
        + count * DESCRIPTION_BYTES_PER_RECEIVER
}

/// The default ceilings an operator may change (`config`).
///
/// What the relay holds is not sized here: the admission budget (`budget`) is, from the memory the
/// relay is given (`--memory`, by default the memory it runs in less `budget::HEADROOM_BYTES`). Every store that
/// grows with what feeders send (subscriber queues, deduplication, the epochs between ingest and
/// the sealer, the products, MLAT's raw, the batch store) is charged to its gauge and held to its
/// share at the feeder ceiling, and a Hello past the ceiling is refused; a relay whose memory
/// admits no feeder refuses to start. No table that grows with what arrives is left to the base
/// (`BASE_BYTES`, the process measured idle): each is a store of its own, sized from what the
/// relay admits. The receivers' descriptions are `budget::Store::Descriptions`, at the receiver
/// figure (`budget::Plan::receivers`); the clock model parts waiting for their manifests are
/// `budget::Store::Parts`, at what the members' rate and the relay's MLAT bring while one waits
/// (`budget::Plan::parts_room`); the streams' tables are the delivery tags'
/// (`budget::Store::Delivery`); and what was taken, by hash, is the strike stores'
/// (`budget::Store::FeederStrikes`, `PeerStrikes`, `OwnStrikes`).
///
/// A connection's Noise buffers come from one pool (`tally_wire::noise`), and each connection
/// carves what it may hold of them, reading and writing (`ingest::BUFFERS_PER_CONNECTION`), for
/// its whole session: a feeder from what it reserved (`Store::Buffers`), every other connection
/// from room the plan sizes to every connection but a feeder's the caps allow (this cap, the
/// member sessions and the subscribers, `Hub::plan`, `budget::Plan::connection_buffers`), so a
/// peer trickling a message, or reading slowly, holds what was planned for it. The kernel's
/// socket buffers are pinned per role (`sockets`) and planned beside them
/// (`budget::Plan::connection_sockets`, and a feeder's floor).
///
/// The members (the sessions over which other relays' data comes in) share one rate
/// (`DEFAULT_MAX_MEMBER_BYTES_PER_SEC`), planned once as the feeders it is worth, and each member
/// session holds one of the places planned at start for every member session the areas taken
/// bring, at most this cap (`budget::members_for`,
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
/// every stripe of every area it takes), so it is also each member's own ceiling. It is their raw:
/// what a neighbour's MLAT publishes for this relay's seats (measured at 7.5 KB a seat a second,
/// 5.4 KB of clock models and 2.05 KB of positions, raw and tagged; `tally-load`, 2,000 feeders,
/// RFC-0171 §3.8.1) comes over the same sessions on a pace of its own that follows the seats the
/// plan admits (`budget::Plan::member_products_bytes_per_sec`, `ingest::MemberPace`), so no rate
/// set for raw bounds the seats, and raising the seats plans no more raw ingest. Before
/// (2026-10-27), the products spent this rate, the plan admitted no more seats than it carried
/// (125 at this default, where the cores carried 522), and an operator raising it for the
/// products planned four times the raw ingest beside them. This is the
/// intended default (since 2026-10-08, when one shared rate replaced 8 MiB/s for each member, which
/// planned every member a feeder budget of its own). A member's place is known from
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
    /// For a receiver's batch, description or site: the finest cell (`Region::point`) of its site
    /// in force, if the relay holds one, computed once when it was kept. Relay-only: a relay link
    /// and an engine route by it, a client never (a client is routed by `client`'s place alone).
    /// For a regional or bundle record, the cell it was signed for.
    pub cell: Option<Region>,
    /// For positions and clock models: the finest cells of the aircraft they place (a full clock
    /// model's, its area; a client clock model's, its full model's area),
    /// computed once when published. `None` is unrouted: whole-world.
    pub points: Option<Arc<[Region]>>,
    /// For a receiver's batch of a format this build reads: its one decode (`ingest`), so no
    /// reader of the fan-out (the BEAST output) inflates or parses it again.
    pub decoded: Option<Arc<Decoded>>,
    /// The monotonic clock when it was taken: a subscriber queue's age is read from this
    /// (`fanout::BEHIND_MS`), so a step of the judging clock ages no queue. A `Mono`, so no
    /// judging reading can be stored here.
    pub stamp: Mono,
    /// What a client may be sent of it, and where a client is routed it (`ClientItem`): made once
    /// by the fan-out when anyone it routes to is a client (`fanout::Router::publish`), `None` for
    /// a relay-only record. A client link sends this and nothing else (`outbound`), and a client
    /// is routed by its place and nothing else (`ClientSubscription::serves`).
    /// Shared, so an item stays as small in every queue slot as before it had a client place.
    pub client: Option<Arc<ClientItem>>,
}

/// Where a piece of a group came from, for what follows the verdict on it (`Hub::take_stream`):
/// `share` takes it into its group, new, a duplicate or late; `let_go` is told it was let go for
/// want of room or its time could not be read, and so is not counted as had.
struct Intake<S, L> {
    share: S,
    let_go: L,
}

/// Positions held until the models they cite have gone out, at most, and for at most how long.
/// Each is charged to the records' store while it waits (`budget::Store::Records`, which the
/// members' rate and the relay's MLAT seats are planned in, as they bring every positions record),
/// what it allocates and its slot in the queue; one the store has no room for goes out at once,
/// as it would once it waited its time (the relay forwards; it is the reader that cannot check it).
const AWAITING_MAX: usize = 4_096;
pub const AWAITING_MS: Duration = Duration::from_secs(10);

/// Positions held for their models (`Hub::forward_positions`).
struct Awaiting {
    source: u64,
    record: Record,
    /// The models it cites that had not gone out when it was held: each struck off as it goes out
    /// (`Hub::release_awaiting`), so none is looked for in the table again.
    missing: Vec<Hash>,
    since: Instant,
    /// What it holds, charged to `budget::Store::Records` while it waits.
    _charge: crate::budget::Charge,
}

impl Awaiting {
    /// What one held allocates: its record's own allocation, the models it waits for, and its
    /// slot in the queue, twice as a full queue grows beside the one it replaces.
    fn bytes_of(record: &Record, missing: &[Hash]) -> usize {
        record.allocated()
            + crate::footprint::vec::<Hash>(missing.len())
            + 2 * std::mem::size_of::<Self>()
    }
}

/// The clock models a positions record cites (their pair model ids), each once.
fn cited_models(record: &Record) -> Vec<Hash> {
    let Record::Positions(positions) = record else {
        return Vec::new();
    };
    let mut cited: Vec<Hash> = crate::network::solved(positions)
        .map(|solved| {
            solved
                .into_iter()
                .flat_map(|one| one.clock_models)
                .collect()
        })
        .unwrap_or_default();
    cited.sort_unstable();
    cited.dedup();
    cited
}

/// A receiver's site (`ReceiverSite`, wire version 3) held beside its format 2 description:
/// relay-only, sent only where `carries_sites` holds (`outbound`).
#[derive(Clone)]
struct HeldSite {
    issued_ms: u64,
    record: Arc<Record>,
    location: Location,
}

impl HeldSite {
    fn of(site: ReceiverSite) -> Option<Self> {
        let content = site.content().ok()?;
        Some(Self {
            issued_ms: content.issued_ms,
            location: content.location,
            record: Arc::new(Record::ReceiverSite(site)),
        })
    }

    fn bytes(&self) -> usize {
        self.record.encoded_len()
    }
}

/// Where a receiver stands in a cell index (`Directory::by_point`, `by_public`): its key, between
/// the two ends every cell's range is read from (`Low` before every key, `High` after), so one
/// ordered set of (cell, receiver) answers a span of cells as one range read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Edge {
    Low,
    Key(PublicKey),
    High,
}

/// One cell index: each receiver once, under its cell's number.
type CellIndex = crate::footprint::Tree<(u64, Edge), ()>;

/// A receiver's newest description, ready to send, its site in force (a format 1 description's
/// own, or the `ReceiverSite` paired with a format 2 one), the finest cell of that site and the
/// public cell its description says.
struct Known {
    issued_ms: u64,
    record: Arc<Record>,
    /// The `ReceiverSite` paired with a format 2 description, when held: its public cell is the
    /// site's, checked when the pair formed (`PublicInfoContent::holds`).
    site: Option<HeldSite>,
    cell: Option<Region>,
    public: Option<Region>,
    bytes: usize,
    /// Its site in force, read once when kept: relay-only (the hosted MLAT, the regional area).
    place: Option<Location>,
    software: Option<String>,
}

impl Known {
    /// What a description of `info` holds of its own, counted against the receivers' bytes
    /// (`Receivers::max_bytes`): its signed bytes, its software's name read out of them, and
    /// its paired site's signed bytes. What its records' headers and its tables' entries take is
    /// planned for each receiver beside it (`DESCRIPTIONS_BYTES_PER_RECEIVER`).
    fn bytes_of(info: &ReceiverInfo, software: Option<&String>, site: Option<&HeldSite>) -> usize {
        info.as_bytes().len()
            + software.map_or(0, String::capacity)
            + site.map_or(0, HeldSite::bytes)
    }

    fn held_site(&self) -> Option<ReceiverSite> {
        match self.site.as_ref().map(|site| &*site.record) {
            Some(Record::ReceiverSite(site)) => Some(site.clone()),
            _ => None,
        }
    }

    /// Its description, and its site when `sites` (a relay's answer; never a client's), stamped
    /// `stamp` (`Item::stamp`).
    fn items(&self, sites: bool, stamp: Mono) -> impl Iterator<Item = Item> + '_ {
        let item = move |record: &Arc<Record>| Item {
            source: RELAY_ITSELF,
            record: Arc::clone(record),
            cell: self.cell,
            points: None,
            decoded: None,
            stamp,
            client: None,
        };
        std::iter::once(item(&self.record)).chain(
            self.site
                .as_ref()
                .filter(|_| sites)
                .map(|site| item(&site.record)),
        )
    }
}

/// One raw shard's state (`exchange::raw_shard`): the batches its receivers' feeders and peers
/// delivered that it took in (`strikes`). Owned by the ingest worker of the shard, which alone
/// takes it on the batch path. Its receivers' station counters are the relay's one table
/// (`Hub::stations`), not the shard's: a shard's receivers are a random draw of the relay's.
struct RawShard {
    batches: Strikes,
    /// Its receivers' wanted receptions against their ceiling, by their batches' stamps.
    ceilings: crate::ingest::ReceptionCeilings,
}

impl RawShard {
    fn new(batches: Strikes, ceilings: crate::ingest::ReceptionCeilings) -> Self {
        Self { batches, ceilings }
    }
}

/// The site-bearing record an engine places `info`'s receiver by (`SiteRecord`): the site paired
/// with it, else the description itself when it carries one (format 1). A format 2 description
/// with no site paired places nobody.
fn site_record(info: &ReceiverInfo, site: Option<ReceiverSite>) -> Option<SiteRecord> {
    site.map(SiteRecord::Site)
        .or_else(|| SiteRecord::info(info.clone()))
}

/// A feeder's own description, as its link last took it: given to the hub again when the hub has
/// forgotten it and the feeder is publishing (see `DESCRIPTION_BYTES_PER_RECEIVER`).
#[derive(Clone, Debug)]
pub struct OwnDescription {
    pub info: ReceiverInfo,
    pub issued_ms: u64,
    /// A format 1 description's site (an old feeder's); `None` for a format 2 one, whose site is
    /// `site`.
    pub place: Option<Location>,
    /// Its own `ReceiverSite`, as its link last took it (wire version 3).
    pub site: Option<ReceiverSite>,
}

/// Where a record's signed time stands against a relay's window of time (`Hub::in_window`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InWindow {
    Inside,
    /// Outside it: late (`strikes::Verdict::Late`).
    Late,
    /// No time to read.
    Unreadable,
}

/// Where a batch came from, for what follows its admission.
#[derive(Clone, Debug)]
pub enum Origin {
    /// The receiver's own feeder, with its description as its link holds it (seeded into the
    /// receiver's sharing group by this relay, its origin), the network group its connection
    /// came from (what the ingest rate gives a share to, `shed`) and the address it came from (its
    /// station report's, `stations`).
    Feeder(
        Option<Arc<OwnDescription>>,
        Option<crate::ingest::Group>,
        Option<IpAddr>,
    ),
    /// A sharing member or a relay link: a piece of a group.
    Peer(Asker),
    /// A piece of a group this relay rebuilt from the group's parity (`sharing::member`'s
    /// rebuild), handed in by the relay itself (`RELAY_ITSELF`, `Hub::take_rebuilt`) with the
    /// group that rebuilt it: taken as a member's piece is, its verdict given back to that group.
    Rebuilt(Rebuilt),
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
    /// What the sharing groups hold (records and parities), by their own count, beside
    /// `Store::Batches`' gauge. The parities being reassembled are not in it: their room is its own
    /// (`budget::MemoryReport::parity_assembly`), which counts them itself.
    pub batches_held: usize,
    /// What the delivery tags hold, by their own count, beside `Store::Delivery`'s gauge.
    pub delivery_held: usize,
    /// Sharing members turned away for want of room in the members' pool.
    pub members_refused: u64,
    /// Records waiting for the ingest workers now, beside `Store::Ingest`'s gauge, and those
    /// refused because the workers' queues held their bound (`ingest::Stages::refused`): none
    /// while every record is charged as it should be, so one counted here is a path that charged
    /// short.
    pub ingest_queued: usize,
    pub ingest_refused: u64,
    /// Batches admitted by the ingest rate and let go before their decode for want of room for it
    /// and their signed bytes (`Store::Decoded`, whose gauge counts each refusal too): none while
    /// every holder keeps a decode no longer than its deadline, the store being planned for the rate
    /// over the longest of them (`budget::decoded_window_ms`).
    pub decoded_refused: u64,
    /// Batches of a format this build reads that did not decode, from a peer (a relay that
    /// predates a format forwards it raw) or any other source but a feeder (whose link ends
    /// instead) and this relay's own rebuilding (counted in `rebuilt_refused`): dropped, never
    /// forwarded on.
    pub malformed_batches: u64,
    /// Records the sharing groups rebuilt from parity that this relay judged and refused, each
    /// counted here alone (`Hub::refuse_rebuilt`): a batch or a piece whose signature or check
    /// failed, a batch with no receiver to read or of a format this build reads that does not
    /// decode, bytes that are no record (`sharing::Ticked::unreadable`). Let go from their group,
    /// never passed on.
    pub rebuilt_refused: u64,
    /// Copies of records this relay may not use (`strikes::Verdict::Late`): signed longer ago than
    /// their window reaches behind this relay's clock, or further ahead of it, or at or below the
    /// floor of what a table may have forgotten, and feeders' batches held too long before they
    /// were sent (`strikes::FeederClock::TooOld`). Never used; held all the same (possession,
    /// `Hub::late`). Copies of records already taken in are duplicates, counted nowhere.
    pub late_records: u64,
    /// Records held while this relay could judge nothing (`strikes::Verdict::Unjudged`): its
    /// clock not yet synced since it started, so no table had a floor to judge by (RFC-0171
    /// §3.6). Possession only: held in their group and credited, never used, and never counted
    /// against a receiver.
    pub unjudged_records: u64,
    /// Leases whose bound was past what the synced clock allows at a start, so their tables use
    /// nothing new until the clock passes it (`Hub::begin_strikes`).
    pub leases_ahead: u64,
    /// The newest such bound (milliseconds since the epoch, 0 for none): the relay's tables use
    /// nothing new until the judging clock passes it.
    pub lease_ahead_until_ms: u64,
    /// Stops' dumps not read back: not trusted, not beside the leases as they are, or not
    /// consumed first (`Hub::restore_dump`).
    pub dumps_refused: u64,
    /// Stops' dumps read back.
    pub dumps_resumed: u64,
    /// Records whose signed time could not be read: in no window, refused in their group.
    pub unreadable_times: u64,
    /// The steps of the judging clock seen (`clock::RelayClock::steps`): each restated to every
    /// feeder session, and nothing ended.
    pub clock_steps: u64,
    /// What the reads of the judging clock's bound said (`clock::RelayClock::bound_health`): the
    /// last read's bound or why it judged nothing (ClockBound missing, unreadable, unknown, free
    /// running, disrupted, or too wide), and every refusal counted by why.
    pub clock_bound: tally_wire::clock_bound::Health,
    /// New records let go for want of room (`strikes::Verdict::Full`): their deliverer's share of
    /// what is taken full, or its class's store (`strikes::StrikeStores`). Not forwarded and not counted had, so
    /// their group asks for them again.
    pub strikes_full: u64,
    /// Feeders' batches signed further ahead of this relay's clock than its window allows as they
    /// arrived (`strikes::FeederClock::Ahead`, `strikes::Verdict::Ahead`), or whose oldest
    /// checked freshness anchor is more than `tally_wire::budget::ANCHOR_AHEAD` ahead of it
    /// (`anchors::Anchoring::Ahead`): held unused
    /// here and counted against nobody (also in `unjudged_records`), passed on to the peers, who
    /// judge them by their own clocks. Nothing is refused for a clock.
    pub ahead_records: u64,
    /// Feeders' batches with no freshness anchor this relay can check (`strikes::Verdict::
    /// Unanchored`, `anchors`): a format without them (an older feeder's), none in it, or one that
    /// does not verify under a relay this relay knows. Held, passed on and credited, never used
    /// here (RFC-0171 §3.6): an older feeder's batches are used nowhere once it is behind its
    /// relays, which is why a feeder's upgrade is required.
    pub unanchored_records: u64,
    /// Records rebuilt from parity let go for want of room (`Hub::take_rebuilt`, which never waits
    /// on the timed duties' thread): `Store::Ingest` full, the ingest workers' queues full, or no
    /// room in `Store::Decoded` for its decode. Each is let go from its group, which asks for it
    /// again or rebuilds it again, so this counts attempts: a record let go twice counts twice.
    pub rebuilt_no_room: u64,
    /// Positions sent on at once, not held for the models they cite, for want of the records'
    /// store's room (`budget::Store::Records`).
    pub awaiting_unheld: u64,
    /// What the ingest rate cut, per source and reason (`shed`): every cut a feeder's batch met,
    /// all at ingest, before it was signed or shared.
    pub shed: crate::shed::ShedReport,
    /// The handshakes in flight and the pace they are planned at (`Hub::handshake`).
    pub handshakes: HandshakeReport,
}

/// The cap on concurrent Noise handshakes and what has met it (`Hub::handshake`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct HandshakeReport {
    /// The most that may run at once, from the runtime's cores (`cores::handshakes_in_flight`).
    pub permits: usize,
    pub in_flight: usize,
    /// The most that ran at once so far.
    pub peak: usize,
    /// Connections waiting for a turn now.
    pub waiting: usize,
    /// Handshakes begun so far.
    pub begun: u64,
    /// The handshakes a second the cap is planned to pass (`cores::handshake_pace_of`).
    pub planned_per_sec: u64,
}

/// A turn at the handshake, held until it is done (`Hub::handshake`).
pub struct HandshakeTurn {
    /// None only if the semaphore were closed, which nothing does.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    running: Arc<AtomicUsize>,
}

impl Drop for HandshakeTurn {
    fn drop(&mut self) {
        self.running.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Feeders' batches the relay dropped for taking their receiver past its wanted receptions a
/// second (`Hub::over_reception_ceiling`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct OverCeiling {
    pub batches: u64,
    /// The wanted receptions those batches carried.
    pub wanted: u64,
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
    /// The raw monotonic clock as its message's bytes reached this relay (`link::Drained`: as it
    /// was read, or, its bytes already waiting in the socket as the link read it, the last moment
    /// the link found its socket empty): what this relay's own anchor in it is aged by
    /// (`Hub::own_anchor_age`), so neither the relay's own pacing of a backlog, nor the time its
    /// bytes waited unread on it, nor a queue on the way ages it. None for a batch the relay
    /// hands in itself, read as it is handed in (`Hub::ingest`).
    pub arrived: Option<Raw>,
    /// Its charge in the ingest stage (`ingest::charge_of`), from its connection's allowance or,
    /// handed in by the relay itself, from `Store::Ingest` (`Hub::in_flight_for`): no batch reaches
    /// the stage uncharged. Released once it is decoded, its decode and its signed bytes then
    /// charged by themselves for their life (`ingest::Stages::decode_owned`), or once it is let go.
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
            arrived: None,
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

/// The receivers described, each with its cell, in the order they are forgotten, and the bytes of
/// their descriptions: held to a count and to bytes, the relay's, in one order of activity. Not
/// split into a share for each raw shard: receivers land in shards by a keyed hash, so a shard's
/// receivers are a random draw, and a shard held to an even share of the figure forgets a receiver
/// that publishes whenever its draw is above the share, which at a small figure is every batch.
/// One order forgets only past the figure, which counts every receiver that published within the
/// gap. The batch path holds its lock for a mark and a copy of two cells, and nothing that checks
/// a signature or tells another stage holds it (`Hub::keep_info`).
struct Receivers {
    held: Bounded<PublicKey, Cells>,
    bytes: usize,
    max_bytes: usize,
}

/// A described receiver's two cells, as the batch path reads them: its site's finest cell, which
/// relay-role links route by (`Item::cell`), and its public cell, which clients and the feeder
/// figures read (`Item::public`, `figures`). Either `None` while unknown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cells {
    pub point: Option<Region>,
    pub public: Option<Region>,
}

impl Receivers {
    /// Of `count` receivers and `bytes` of descriptions at most.
    fn new(count: usize, bytes: usize) -> Self {
        Self {
            held: Bounded::new(count),
            bytes: 0,
            max_bytes: bytes,
        }
    }
}

/// Every description held, for joining subscribers, under a lock the batch path never takes.
/// Which receivers are held, and which is forgotten first, is `Hub::receivers`; this follows it
/// key for key.
struct Directory {
    /// Every description held, as many as the receivers hold and one more (they forget as they
    /// take one past the figure, `Hub::keep_info`): never forgetting of its own.
    known: Bounded<PublicKey, Known>,
    /// The located receivers by their finest cell's number, so the receivers inside a region are
    /// one range read (`Region::span`): a subscription's answer costs its matches and a lookup a
    /// region, never a test of every receiver. One ordered set of (cell, receiver), so taking one
    /// out costs its log however many share the cell (every receiver in a dense city shares a
    /// public cell), and a receiver costs one entry, never a set of its own.
    by_point: CellIndex,
    /// The described receivers by their public cell, keyed by its first finest descendant's number
    /// (`Region::span`): a client's regions (no finer than a public cell, `Region::clamped_to_public`)
    /// are answered by these and never by `by_point`, so no answer tells a client more than the
    /// public cell.
    by_public: CellIndex,
    /// Sites that came before a description they pair with, as many as the directory holds: each
    /// is adopted by its receiver's next description, or forgotten.
    waiting_sites: Bounded<PublicKey, HeldSite>,
    bytes: usize,
}

/// A table sized whole from the budget (`Hub::size_tables`): its store, what it allocates at most
/// at the figure it was sized to, and what its store charged it for that.
struct SizedTable {
    store: Store,
    planned: usize,
    charge: crate::budget::Charge,
}

/// Removes `receiver` from the keys an index holds under `at`.
fn unindex(index: &mut CellIndex, at: u64, receiver: &PublicKey) {
    index.remove(&(at, Edge::Key(*receiver)));
}

/// Where a public cell is keyed in `Directory::by_public`.
fn public_key_of(public: Region) -> u64 {
    *public.span().start()
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
    /// A directory of as many as `held` descriptions and waiting sites.
    fn new(held: usize) -> Self {
        Self {
            known: Bounded::new(held),
            by_point: CellIndex::new(),
            by_public: CellIndex::new(),
            waiting_sites: Bounded::new(held),
            bytes: 0,
        }
    }

    /// Holds as many as `held` from now (`Hub::size_descriptions`): what the receivers hold and
    /// one more. The receivers forget past the figure first, so nothing held by them is forgotten
    /// here.
    fn set_capacity(&mut self, held: usize) {
        for (receiver, old) in self.known.set_capacity(held) {
            self.forget(&receiver, &old);
        }
        self.waiting_sites.set_capacity(held);
    }

    fn insert(&mut self, receiver: PublicKey, known: Known) {
        // The old entry's index entries out first: a description that keeps its cell is indexed
        // again below, once.
        self.remove(&receiver);
        self.bytes += known.bytes;
        if let Some(cell) = known.cell {
            self.by_point
                .insert((cell.as_u64(), Edge::Key(receiver)), ());
        }
        if let Some(public) = known.public {
            self.by_public
                .insert((public_key_of(public), Edge::Key(receiver)), ());
        }
        self.known.insert(receiver, known);
    }

    fn remove(&mut self, receiver: &PublicKey) {
        if let Some(old) = self.known.remove(receiver) {
            self.forget(receiver, &old);
        }
    }

    /// Takes back what `old`, no longer held for `receiver`, added.
    fn forget(&mut self, receiver: &PublicKey, old: &Known) {
        self.bytes -= old.bytes;
        if let Some(cell) = old.cell {
            unindex(&mut self.by_point, cell.as_u64(), receiver);
        }
        if let Some(public) = old.public {
            unindex(&mut self.by_public, public_key_of(public), receiver);
        }
    }

    /// Takes `receiver`'s entry out, its index entries and bytes with it, to be changed and put
    /// back (`insert`).
    fn take(&mut self, receiver: &PublicKey) -> Option<Known> {
        let old = self.known.remove(receiver)?;
        self.forget(receiver, &old);
        Some(old)
    }

    /// Every description, and every site when `sites`, stamped `stamp`.
    fn all(&self, sites: bool, stamp: Mono) -> Vec<Item> {
        self.known
            .values()
            .flat_map(|known| known.items(sites, stamp))
            .collect()
    }

    /// What an engine's `subscription` covers: its receivers by their sites' finest cells,
    /// descriptions and sites.
    fn answer(&self, subscription: &Subscription, stamp: Mono) -> Answer {
        self.answer_by(subscription, &self.by_point, true, stamp)
    }

    /// What a client's `subscription` covers: its receivers by their public cells, descriptions
    /// only. Never by `by_point`, so no answer tells a client more than the public cell.
    fn client_answer(&self, subscription: &ClientSubscription, stamp: Mono) -> Answer {
        self.answer_by(
            subscription.as_subscription(),
            &self.by_public,
            false,
            stamp,
        )
    }

    fn answer_by(
        &self,
        subscription: &Subscription,
        index: &CellIndex,
        sites: bool,
        stamp: Mono,
    ) -> Answer {
        match subscription.described() {
            Described::None => Answer {
                items: Vec::new(),
                visited: 0,
            },
            Described::All => {
                let items = self.all(sites, stamp);
                let visited = self.known.len();
                Answer { items, visited }
            }
            Described::Within(spans) => {
                let mut items = Vec::new();
                let mut visited = 0;
                for span in spans {
                    let range = (*span.start(), Edge::Low)..=(*span.end(), Edge::High);
                    for key in index.range(range).filter_map(|((_, edge), ())| match edge {
                        Edge::Key(key) => Some(key),
                        Edge::Low | Edge::High => None,
                    }) {
                        visited += 1;
                        if let Some(known) = self.known.get(key) {
                            items.extend(known.items(sites, stamp));
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
    /// Each subscriber queue's bytes when named (`Hub::queue_bytes`), else the budget's share: kept
    /// so the router a replan builds (`Hub::memory`) bounds its queues the same.
    queue_bytes: Option<usize>,
    /// The ingest workers and the message exchange (`ingest`, `exchange`).
    stages: Stages,
    /// Each raw shard's batches taken in, `SHARDS` of them.
    raw: Box<[Mutex<RawShard>]>,
    /// Every receiver's station counters, one table at the receiver figure in one order of
    /// activity (`stations`), taken after a raw shard's lock when both are held, never before.
    stations: Mutex<Stations>,
    /// The window of time a relay-signed record's signed time must be in to be used
    /// (`strikes::Window::relay_signed`), from the deadlines its groups keep: what a record judged
    /// by no table of its own is held to (`Hub::in_window`).
    window: Window,
    /// The deadlines its groups keep: what its tables' windows are derived from.
    deadlines: crate::sharing::Deadlines,
    /// What it keeps across a restart (`durable`): its tables' floors and fingerprints.
    durable: Durable,
    /// Each deliverer's entries in every table of what was taken, against its share
    /// (`strikes::Shares`), at the records a second the plan carries for each over their life
    /// (`budget::Plan::strike_entries`).
    shares: Arc<Shares>,
    budget: Budget,
    /// The tables sized whole from the budget as it stands (`Hub::size_tables`): the station rows
    /// and the descriptions at the receiver figure, and the clock model parts at their room, each
    /// with what its store charged it.
    sized: Mutex<Vec<SizedTable>>,
    /// Engines' positions taken in, by hash, each judged by its signed `issued_ms`.
    positions: Mutex<Strikes>,
    /// Engines' clock models taken in, by id, each judged by its signed `issued_ms`; what
    /// positions wait for (`Hub::forward_positions`).
    clock_models: Mutex<Strikes>,
    /// Clock model parts held for their manifests, and forwarded manifests' lists (`parts`).
    parts: Mutex<Parts>,
    /// Positions held until the clock models they cite have gone out (`awaiting`).
    awaiting: Mutex<VecDeque<Awaiting>>,
    /// Fault proofs taken in, by hash, each judged by the later signed `issued_ms` of the two
    /// records it holds (`proof_time`): a proof is anyone's and unsigned, but what it proves was
    /// signed, so a proof is as old as its newer record and no replay of one past the window is
    /// new.
    fault_proofs: Mutex<Strikes>,
    /// Feeder figures taken in, by hash, each judged by its signed `issued_ms` in a window
    /// stretched by the hour it may be signed in (`strikes::Usable::figures`).
    figures: Mutex<Strikes>,
    /// The products a peer's record is passed on as (bundle indexes, regional batches, client clock
    /// models), by hash and each by its own signed time: each into the fan-out once. Without it a
    /// record that comes back round a loop of relays (an index read on a one-hop raw link, passed
    /// on, read back) went round for ever, thousands a second, and every link behind the fan-out
    /// fell behind it.
    passed_on: Mutex<Strikes>,
    /// The receivers described, each with its cell, in the order they are forgotten: what the
    /// batch path reads (a cell to route by) and marks (the receiver is publishing), O(1) under
    /// its lock (`Receivers`).
    receivers: Mutex<Receivers>,
    /// What each member link told its peer of each receiver it carried a batch of, by the link's
    /// connection and the receiver, in the order of their last batch: [`TOLD_PER_RECEIVER`] for
    /// each receiver of the figure (`Hub::to_describe`), charged with the descriptions.
    told: Mutex<Bounded<(u64, PublicKey), Told>>,
    /// Their descriptions. Taken by `publish_info` (then the receivers, in that order) and by
    /// a joining subscriber, never by the batch path, so no scan ever stalls a batch.
    directory: Mutex<Directory>,
    next_connection: AtomicU64,
    subscribers: Arc<AtomicUsize>,
    max_subscribers: usize,
    /// The engines given an engine's socket buffers (`engine_place`), at most the member
    /// sessions planned (`budget::Plan::connection_sockets`).
    engines: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    max_connections: usize,
    /// Connections held per source (`source_of`), each entry removed when its last one ends.
    per_address: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_connections_per_address: usize,
    max_feeder_bytes_per_sec: u64,
    max_member_bytes_per_sec: u64,
    /// The pace every member session shares (`ingest::MemberPace`), at `max_member_bytes_per_sec`.
    member_pace: Arc<crate::ingest::MemberPace>,
    /// The records a second every member session shares, all it sends (`ingest::RecordPace`), at
    /// the feeders `max_member_bytes_per_sec` is worth (`ingest::member_records_per_sec`).
    member_records: Arc<crate::ingest::RecordPace>,
    /// The records a second every directory link's network group is paced at, whoever dialled
    /// (`ingest::DirectoryPaces`): equal shares of `ingest::DIRECTORY_RECORDS`, planned once, as
    /// the gossip it carries is one whatever the links.
    directory_records: Arc<crate::ingest::DirectoryPaces>,
    /// What new sessions are granted of their roles' bursts, by network group
    /// (`ingest::BurstGrants`).
    burst_grants: crate::ingest::BurstGrants,
    /// Feeders' batches dropped for taking their receiver past its wanted receptions a second
    /// (`ingest::ReceptionCeilings`), and the wanted receptions they carried.
    over_ceiling_batches: AtomicU64,
    /// Batches let go before their decode for want of room in `Store::Decoded`.
    decoded_refused: AtomicU64,
    /// A peer's batches of a format this build reads that did not decode (`MemoryReport`).
    malformed_batches: AtomicU64,
    /// Records rebuilt from parity this relay judged and refused (`MemoryReport`).
    rebuilt_refused: AtomicU64,
    /// Copies outside the window of time (`MemoryReport`).
    late_records: AtomicU64,
    unjudged_records: AtomicU64,
    /// Every table begun by a synced clock (`Hub::begin_strikes`).
    strikes_begun: std::sync::atomic::AtomicBool,
    leases_ahead: AtomicU64,
    lease_ahead_until_ms: AtomicU64,
    dumps_refused: AtomicU64,
    dumps_resumed: AtomicU64,
    unreadable_times: AtomicU64,
    /// New records let go for want of room in their deliverer's share or the store
    /// (`MemoryReport`).
    strikes_full: AtomicU64,
    /// Feeders' batches signed more than `F` ahead of this relay's clock (`MemoryReport`).
    ahead_records: AtomicU64,
    /// Feeders' batches with no anchor this relay can check (`MemoryReport`).
    unanchored_records: AtomicU64,
    /// A test's step between a batch judged new and remembered (`Hub::between_fresh_and_take`).
    #[cfg(test)]
    between: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Records rebuilt from parity let go for want of room in `Store::Ingest` (`MemoryReport`).
    rebuilt_no_room: AtomicU64,
    /// Positions sent on at once, not held for the models they cite, for want of the records'
    /// room (`AWAITING_MAX`).
    awaiting_unheld: AtomicU64,
    over_ceiling_receptions: AtomicU64,
    /// The relay-wide ingest rate (`shed`): unbounded until the plan names `R_max`
    /// (`Hub::admitted_rate`).
    shedder: crate::shed::Shedder,
    admitted_rate: Option<crate::shed::Rates>,
    /// Concurrent handshakes, capped from the runtime's cores (`Hub::handshake`).
    handshakes: Arc<tokio::sync::Semaphore>,
    handshake_permits: usize,
    handshaking: Arc<AtomicUsize>,
    handshake_peak: AtomicUsize,
    handshake_waiting: AtomicUsize,
    handshakes_begun: AtomicU64,
    /// The areas taken (RFC-0174 §2.1): what the member sessions are planned from
    /// (`budget::members_for`).
    areas: Vec<Region>,
    /// Whether the relay holds MLAT raw: its plan's base and each feeder's cost (`Hub::memory`).
    holds_raw: bool,
    /// The cores the relay runs on (`Hub::cores`): the feeders they carry bound the ceiling, and
    /// its stages' threads follow the load admitted (`cores`). None for a test's hub, whose
    /// feeders only its memory bounds and whose stages' threads it names.
    cores: Option<usize>,
    /// Whether it gathers the world product (`Hub::gathering_world`): its fixes' store is planned
    /// only then (`Plan::with_world`).
    world: bool,
    /// The time the ingest ceilings read.
    ceiling_clock: crate::ceiling::Clock,
    /// The relay's two clocks (`clock::RelayClock`): the judging clock everything compared across
    /// machines reads, and the monotonic one the stages stamp and every duration runs on.
    clock: RelayClock,
    /// Set once it is stopping (`Hub::stop`): every session says goodbye (`Hub::leaving`).
    leaving: tokio::sync::watch::Sender<bool>,
    accepted_relays: HashSet<PublicKey>,
    hints: Vec<RelayAddress>,
    /// What the relay may send a second, and every byte it has sent (`egress`).
    egress: Arc<Egress>,
    /// RFC-0174's duties (`network`): the one place they meet the hub.
    network: Network,
    /// Sharing members turned away because the members' pool was full (`Budget::reserve_member`).
    members_refused: AtomicU64,
    /// The beast-out clients served at once (`--max-beast-clients`), none where the relay serves
    /// no beast-out (`Hub::serving_beast`): planned as subscribers are.
    beast_clients: usize,
    /// The acars-out clients served at once (`--max-acars-clients`), as `beast_clients`
    /// (`Hub::serving_acars`).
    acars_clients: usize,
    /// Every listener's connections and accepts (`listeners`, `GET /listeners`).
    listeners: crate::listeners::Listeners,
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
    /// The address it came from, as the socket saw it.
    address: IpAddr,
}

impl Connection {
    /// Its place under the relay's connection cap, to hold while the connection has no place of
    /// its own and to let go when it takes one: a feeder once it holds its reservation, a
    /// subscriber its place among the subscribers, a relay its member's place. Each role is
    /// bounded by its own cap, never by another's (`Hub::plan`).
    pub fn general(&mut self) -> Option<Slot> {
        self.general.take()
    }

    /// The address it came from, as the socket saw it (its source slot counts its /64).
    pub fn address(&self) -> IpAddr {
        self.address
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

/// When a fault proof's fault was signed: the later `issued_ms` of the two records it holds (two
/// positions records, or two clock models). None for a proof none of whose records can be read.
fn proof_time(proof: &FaultProof) -> Option<u64> {
    use tally_wire::fault_proof::MODEL_FAULT_PROOF_FORMAT;
    let times: Vec<u64> = if proof.format() == MODEL_FAULT_PROOF_FORMAT {
        proof
            .models_of()
            .ok()?
            .iter()
            .filter_map(|model| model.issued_ms().ok())
            .collect()
    } else {
        proof
            .parts()
            .ok()?
            .iter()
            .filter_map(|(positions, _)| positions.issued_ms().ok())
            .collect()
    };
    times.into_iter().max()
}

/// The records a second the members' rate of `bytes_per_sec` brings: the feeders it is worth, by
/// the budget's one rule (`budget::feeders_for_rate`), each at
/// `ingest::MEMBER_RECORDS_PER_FEEDER`.
/// The records a second the members bring at `bytes_per_sec` of raw and the products of
/// `product_seats` (`budget::Plan::product_seats`): each feeder the raw rate is worth, and each seat
/// whose products they bring beyond those, at a member feeder's records a second
/// (`ingest::MEMBER_RECORDS_PER_FEEDER`), as each of those feeders was planned as one seat of
/// another engine, its batches and its products, before the products had a pace of their own.
fn member_records_for(bytes_per_sec: u64, product_seats: usize) -> u64 {
    crate::ingest::member_records_per_sec(
        crate::budget::feeders_for_rate(bytes_per_sec).max(product_seats),
    )
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
    /// A hub whose stages run on the caller (`ingest::Stages::inline`), by the host's clocks with
    /// their bound stated (`RelayClock::host_stated`: no test host runs ClockBound), its budget
    /// `DEFAULT_MEMORY`: what a test builds. A relay is built `on` the host's own clock
    /// (`RelayClock::system`) and then `staged` onto its threads. Its sharing judges deliverers by
    /// `deadlines` (a relay's `sharing::Deadlines::RELAY`; a test asserting a verdict over real
    /// links declares its own, `sharing::member::Deadlines`).
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's hub: no test host runs ClockBound"
    )]
    pub fn new(max_subscribers: usize, deadlines: crate::sharing::Deadlines) -> Self {
        Self::on(max_subscribers, RelayClock::host_stated(), deadlines)
    }

    /// As `new`, on a clock that reads exactly what `clock` reads (`clock::RelayClock::scripted`):
    /// a test's or a replay's times of its own choosing.
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's hub: no test host runs ClockBound"
    )]
    pub fn clocked(
        max_subscribers: usize,
        clock: crate::clock::Script,
        deadlines: crate::sharing::Deadlines,
    ) -> Self {
        Self::on(max_subscribers, RelayClock::scripted(clock), deadlines)
    }

    /// As `new`, on `clock`. Its budget is sized from its own plan (`Hub::plan`), as every change
    /// to its caps resizes it.
    pub fn on(
        max_subscribers: usize,
        clock: RelayClock,
        deadlines: crate::sharing::Deadlines,
    ) -> Self {
        let network = Network::new(deadlines, clock.clone());
        let budget = Budget::of_memory(
            DEFAULT_MEMORY,
            Plan::planned(false)
                .with_members(0, DEFAULT_MAX_MEMBER_BYTES_PER_SEC)
                .with_sessions(DEFAULT_MAX_CONNECTIONS, max_subscribers),
        );
        network.charge_to(&budget);
        let window = crate::strikes::relay_signed(deadlines);
        let store = StrikeStores::of(&budget);
        let shares = Shares::new(&store, budget.plan().strike_entries(&budget.admission()));
        let relay_signed = Usable::relay_signed(deadlines);
        let table = |usable: Usable| Strikes::new(usable, &store, Arc::clone(&shares));
        // The pace maps, each charged to the paces' store (`Budget::pace_room`).
        let directory_records = crate::ingest::DirectoryPaces::within(
            crate::ingest::DIRECTORY_RECORDS,
            budget.pace_room(),
        );
        let burst_grants = crate::ingest::BurstGrants::default().within(budget.pace_room());
        let stages = Stages::inline(clock.clone(), network.products.sink(), Gauges::of(&budget));
        Self {
            fanout: Arc::new(router(&budget, None)),
            queue_bytes: None,
            stages,
            raw: (0..SHARDS)
                .map(|_| {
                    Mutex::new(RawShard::new(
                        table(Usable::BATCHES),
                        crate::ingest::ReceptionCeilings::within(budget.pace_room()),
                    ))
                })
                .collect(),
            // Sized to the budget's receiver figure as it is planned (`Hub::size_tables`).
            stations: Mutex::new(Stations::new(1)),
            positions: Mutex::new(table(relay_signed)),
            clock_models: Mutex::new(table(relay_signed)),
            parts: Mutex::new(Parts::sized(crate::parts::ONE_MODEL_BYTES)),
            awaiting: Mutex::new(VecDeque::new()),
            fault_proofs: Mutex::new(table(Usable::proofs(deadlines))),
            figures: Mutex::new(table(Usable::figures(window))),
            passed_on: Mutex::new(table(relay_signed)),
            window,
            deadlines,
            durable: Durable::Off,
            shares,
            budget,
            sized: Mutex::new(Vec::new()),
            // Sized to the budget's receiver figure as it is planned (`Hub::size_tables`).
            receivers: Mutex::new(Receivers::new(1, DESCRIPTION_BYTES_PER_RECEIVER)),
            told: Mutex::new(Bounded::new(TOLD_PER_RECEIVER)),
            directory: Mutex::new(Directory::new(2)),
            next_connection: AtomicU64::new(RELAY_ITSELF + 1),
            subscribers: Arc::new(AtomicUsize::new(0)),
            max_subscribers,
            engines: Arc::new(AtomicUsize::new(0)),
            connections: Arc::new(AtomicUsize::new(0)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            per_address: Arc::new(Mutex::new(HashMap::new())),
            max_connections_per_address: DEFAULT_MAX_CONNECTIONS_PER_ADDRESS,
            max_feeder_bytes_per_sec: DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
            max_member_bytes_per_sec: DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
            member_pace: Arc::new(crate::ingest::MemberPace::new(
                DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
                0,
            )),
            member_records: Arc::new(crate::ingest::RecordPace::new(member_records_for(
                DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
                0,
            ))),
            directory_records,
            burst_grants,
            over_ceiling_batches: AtomicU64::new(0),
            decoded_refused: AtomicU64::new(0),
            malformed_batches: AtomicU64::new(0),
            rebuilt_refused: AtomicU64::new(0),
            late_records: AtomicU64::new(0),
            unjudged_records: AtomicU64::new(0),
            strikes_begun: std::sync::atomic::AtomicBool::new(false),
            leases_ahead: AtomicU64::new(0),
            lease_ahead_until_ms: AtomicU64::new(0),
            dumps_refused: AtomicU64::new(0),
            dumps_resumed: AtomicU64::new(0),
            unreadable_times: AtomicU64::new(0),
            strikes_full: AtomicU64::new(0),
            ahead_records: AtomicU64::new(0),
            unanchored_records: AtomicU64::new(0),
            #[cfg(test)]
            between: Mutex::new(None),
            rebuilt_no_room: AtomicU64::new(0),
            awaiting_unheld: AtomicU64::new(0),
            over_ceiling_receptions: AtomicU64::new(0),
            shedder: crate::shed::Shedder::unbounded(),
            admitted_rate: None,
            handshakes: Arc::new(tokio::sync::Semaphore::new(
                crate::cores::handshakes_in_flight(crate::ingest::host_cores()),
            )),
            handshake_permits: crate::cores::handshakes_in_flight(crate::ingest::host_cores()),
            handshaking: Arc::new(AtomicUsize::new(0)),
            handshake_peak: AtomicUsize::new(0),
            handshake_waiting: AtomicUsize::new(0),
            handshakes_begun: AtomicU64::new(0),
            areas: Vec::new(),
            holds_raw: false,
            cores: None,
            world: false,
            ceiling_clock: crate::ceiling::system_clock(),
            clock,
            leaving: tokio::sync::watch::Sender::new(false),
            // A unit test's feeders anchor their batches by one relay, accepted here as an
            // operator accepts one (`anchors::test_relay`).
            #[cfg(not(test))]
            accepted_relays: HashSet::new(),
            #[cfg(test)]
            accepted_relays: HashSet::from([crate::anchors::test_relay().public()]),
            hints: Vec::new(),
            // Until the operator names a cap, nothing billed leaves the host (loopback peers are
            // still served): a hub can never send without one.
            egress: Arc::new(Egress::new(Cap::NONE)),
            network,
            members_refused: AtomicU64::new(0),
            beast_clients: 0,
            acars_clients: 0,
            listeners: crate::listeners::Listeners::default(),
        }
        .replanned()
    }

    /// The stages on as many threads as the load this hub plans to admit needs
    /// (`Budget::threads`): what a relay runs. Built once the budget is final, so the threads
    /// follow the ceiling and the members' rate it was sized to.
    pub fn staged_as_planned(self) -> Result<Self, String> {
        let threads = self.budget.threads();
        self.staged(threads)
    }

    /// The stages on threads of their own (`threads`), the sealer on its own: a test's, which
    /// names its threads.
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
        self.release_stages();
        let gauges = Gauges::of(&self.budget);
        // The sealer moves onto its thread wherever it is held: no exclusive hold is needed, so
        // it can never be left inline behind threaded stages.
        self.network.products.on_thread(threads, pause.as_ref())?;
        self.stages = Stages::threaded(
            clock,
            threads,
            (
                &self.network.products.sink(),
                &gauges,
                crate::ingest::Room::of(&self.budget),
            ),
            pause,
        )?;
        Ok(self)
    }

    /// The relay's own streams under fixed boot ids instead of random ones (the regional product
    /// under `boot_id`, the deduplicated stream under the next): what two runs of one trace
    /// compare byte for byte by. Built before the hub is shared or staged.
    pub fn product_boots(mut self, boot_id: u64) -> Self {
        let clock = self.stages.clock();
        self.release_stages();
        let gauges = Gauges::of(&self.budget);
        self.network.products = Arc::new(crate::products::Products::with_boots(
            boot_id,
            boot_id.wrapping_add(1),
            1,
        ));
        // The world product, if it gathers it (`Hub::gathering_world`), whichever was built first.
        self.network.products.set_world(self.world);
        self.network.charge_to(&self.budget);
        self.size_tables();
        self.stages = Stages::inline(clock, self.network.products.sink(), gauges);
        self
    }

    /// Lets go of the stages, and with them the fingerprints' tables they charged, before new ones
    /// are made: stages allocate their tables at the capacity the plan reserved
    /// (`exchange::Gauges::of`), so the old and the new held at once would be twice the plan and
    /// the new ones refused. What stands in until then holds no table and is charged nothing.
    fn release_stages(&mut self) {
        let unused: Sink = Arc::new(|_| Ok(()));
        let none = Gauges {
            dedup_receptions: 0,
            ..Gauges::unlimited()
        };
        self.stages = Stages::inline(self.stages.clock(), unused, none);
    }

    /// The relay may use `memory` bytes, and holds MLAT raw (`holds_raw`: it hosts MLAT) or not:
    /// the admission budget (`budget`), sized from this hub's plan (`Hub::plan`), and every
    /// store's and queue's share of it (each store's gauge, resized in place). Whatever order the
    /// hub's caps are set in, the budget follows the last of them.
    pub fn memory(mut self, memory: usize, holds_raw: bool) -> Self {
        self.holds_raw = holds_raw;
        self.budget.resize(memory, self.plan());
        // The members' paces follow the plan: their raw at the rate the operator set, their
        // products at the seats the plan admits (`budget::Plan::member_products_bytes_per_sec`),
        // and their records a second at both.
        let products = self.budget.member_products_bytes_per_sec() as u64;
        self.member_pace = Arc::new(crate::ingest::MemberPace::new(
            self.max_member_bytes_per_sec,
            products,
        ));
        self.member_records = Arc::new(crate::ingest::RecordPace::new(member_records_for(
            self.max_member_bytes_per_sec,
            self.budget.plan().product_seats(self.budget.hosted_seats()),
        )));
        // Each deliverer's share of what is taken follows the records a second the plan carries
        // for it, as the stores are planned.
        self.shares
            .set(self.budget.plan().strike_entries(&self.budget.admission()));
        self.fanout = Arc::new(router(&self.budget, self.queue_bytes));
        self.network.charge_to(&self.budget);
        self.size_tables();
        self.inline_restaged().shedder_built()
    }

    /// The tables sized whole from the budget made again for it as it now stands, what they were
    /// charged before given back first, so a budget resized holds them once: the station rows and
    /// the descriptions at its receiver figure (`Budget::receivers`), each one table and each
    /// forgetting the least recently active past it, and the clock model parts at their room
    /// (`Plan::parts_room`). Each is charged whole what it allocates at most at its figure; a store
    /// whose limit is below it is charged nothing, and a start refuses it (`Hub::fixed_charged`).
    fn size_tables(&self) {
        let mut sized = self
            .sized
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sized.clear();
        let receivers = self.budget.receivers();
        self.size_receivers(receivers);
        let room = self.budget.plan().parts_room();
        if let Ok(mut parts) = self.parts.lock() {
            parts.resize(room);
        }
        for (store, planned) in [
            (Store::Stations, crate::stations::planned_bytes(receivers)),
            (Store::Descriptions, descriptions_planned_bytes(receivers)),
            (Store::Parts, crate::parts::planned_bytes(room)),
        ] {
            let gauge = self.budget.gauge(store);
            let mut charge = gauge.empty();
            if gauge.limit() >= planned {
                let _ = charge.try_grow(planned);
            }
            sized.push(SizedTable {
                store,
                planned,
                charge,
            });
        }
    }

    /// The station rows and the descriptions held to `receivers`, the receiver figure: each one
    /// table, forgetting the least recently active past it.
    pub(crate) fn size_receivers(&self, receivers: usize) {
        if let Ok(mut stations) = self.stations.lock() {
            stations.set_capacity(receivers);
        }
        let count = described_count(receivers);
        self.size_descriptions(count, count * DESCRIPTION_BYTES_PER_RECEIVER, count + 1);
        if let Ok(mut told) = self.told.lock() {
            told.set_capacity(TOLD_PER_RECEIVER * count);
        }
    }

    /// The receivers hold at most `count` descriptions and `bytes` of them, and the directory and
    /// the waiting sites `held`, each forgetting the least recently active past it, the directory
    /// what the receivers forget.
    fn size_descriptions(&self, count: usize, bytes: usize, held: usize) {
        let Ok(mut directory) = self.directory.lock() else {
            return;
        };
        let Ok(mut receivers) = self.receivers.lock() else {
            return;
        };
        receivers.max_bytes = bytes;
        let mut forgotten: Vec<PublicKey> = receivers
            .held
            .set_capacity(count)
            .into_iter()
            .map(|(receiver, _)| receiver)
            .collect();
        let mut held_bytes = receivers.bytes;
        for receiver in &forgotten {
            held_bytes -= directory.known.get(receiver).map_or(0, |known| known.bytes);
        }
        while held_bytes > bytes {
            let Some(receiver) = receivers.held.forget_first() else {
                break;
            };
            held_bytes -= directory
                .known
                .get(&receiver)
                .map_or(0, |known| known.bytes);
            forgotten.push(receiver);
        }
        receivers.bytes = held_bytes;
        drop(receivers);
        for receiver in &forgotten {
            directory.remove(receiver);
        }
        directory.set_capacity(held);
    }

    /// A test's descriptions: `count` descriptions and `bytes` of them.
    #[cfg(test)]
    pub(crate) fn described_as(&mut self, count: usize, bytes: usize) {
        self.receivers = Mutex::new(Receivers::new(count, bytes));
        if let Ok(mut directory) = self.directory.lock() {
            *directory = Directory::new(count + 1);
        }
    }

    /// Whether the stores held whole from the start (the anchor cache, the station rows, the
    /// descriptions, the receivers' areas, the clock model parts) are charged in full: a relay
    /// whose budget cannot hold them refuses to start.
    pub fn fixed_charged(&self) -> Result<(), String> {
        self.network.fixed_charged()?;
        let sized = self
            .sized
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for table in sized.iter() {
            let charged = table.charge.bytes();
            if charged != table.planned {
                return Err(format!(
                    "the {} need {} bytes and their store gave them {charged}: give the relay \
                     more memory",
                    table.store.name(),
                    table.planned
                ));
            }
        }
        Ok(())
    }

    /// Stages run by the caller made again for the budget as it now stands: their fingerprints'
    /// tables are allocated at the capacity the plan reserved when they were made
    /// (`exchange::Gauges::of`), so the ones made for an earlier plan would hold what that plan
    /// reserved, not this one's. Threaded stages are made once the budget is final
    /// (`Hub::staged`), and are left as they are.
    fn inline_restaged(mut self) -> Self {
        if self.stages.is_inline() {
            let clock = self.stages.clock();
            self.release_stages();
            self.stages = Stages::inline(
                clock,
                self.network.products.sink(),
                Gauges::of(&self.budget),
            );
        }
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
            .with_feeder_ceiling(self.max_feeder_bytes_per_sec)
            .with_members(members, self.max_member_bytes_per_sec)
            .with_bundle_indexes(crate::sharing::bundles::planned_indexes_per_sec(
                &self.areas,
            ))
            // A beast-out or acars-out client takes from the fan-out, holds a subscriber's kernel
            // buffers and writes from a buffer of its own: a subscriber's session to the plan.
            .with_sessions(
                self.max_connections,
                self.max_subscribers
                    .saturating_add(self.beast_clients)
                    .saturating_add(self.acars_clients),
            )
            .with_cores(self.cores)
            .with_world(self.world)
    }

    /// Gathers the world product (`--world`): the products are told, and the plan holds its
    /// fixes' store.
    pub fn gathering_world(mut self, world: bool) -> Self {
        self.network.products.set_world(world);
        self.world = world;
        self.replanned()
    }

    /// Runs on `cores` cores (`cores::cores_available`, or what `check` is told): the feeders it
    /// admits are no more than they carry beside its members' rate (`cores::feeders_carried`), and
    /// its stages' threads follow what it admits (`Hub::staged_as_planned`).
    pub fn cores(mut self, cores: usize) -> Self {
        self.cores = Some(cores);
        self.handshakes_capped(crate::cores::handshakes_in_flight(cores))
    }

    /// At most `permits` handshakes at once (`cores::handshakes_in_flight` of the cores): a
    /// reconnect storm waits its turn, in the order it arrived, instead of every connection
    /// running its key exchange at once beside the sessions already served. Before the hub is
    /// shared.
    pub fn handshakes_capped(mut self, permits: usize) -> Self {
        let permits = permits.max(1);
        self.handshake_permits = permits;
        self.handshakes = Arc::new(tokio::sync::Semaphore::new(permits));
        self.replanned()
    }

    /// The relay-wide ingest rate `R_max` the plan sizes the stores for (`shed`): past it a
    /// feeder's batches are cut at ingest, each source held to its fair share. A source's
    /// ceiling is one receiver's own pace (`ingest::SOURCE_RECEPTIONS_PER_SEC`, and the feeder
    /// byte ceiling).
    pub fn admitted_rate(mut self, rate: crate::shed::Rates) -> Self {
        self.admitted_rate = Some(rate);
        self.shedder_built()
    }

    /// The rate the plan names (`Budget::max_receptions_per_sec`, `max_bytes_per_sec`) on a hub
    /// that knows its cores, else the one `admitted_rate` pinned, else none.
    fn shedder_built(mut self) -> Self {
        let planned = self.cores.map(|_| crate::shed::Rates {
            receptions_per_s: self.budget.max_receptions_per_sec(),
            bytes_per_s: self.budget.max_bytes_per_sec(),
        });
        self.shedder = match self.admitted_rate.or(planned) {
            Some(rate) => crate::shed::Shedder::new(
                rate,
                crate::shed::Rates {
                    receptions_per_s: crate::ingest::SOURCE_RECEPTIONS_PER_SEC,
                    bytes_per_s: self.max_feeder_bytes_per_sec,
                },
            )
            .within(self.budget.gauge(Store::Shed)),
            None => crate::shed::Shedder::unbounded(),
        };
        self
    }

    /// What the ingest rate has cut (`GET /memory`).
    pub fn shed_report(&self) -> crate::shed::ShedReport {
        self.shedder.report()
    }

    /// The ingest rate's shedder, for a test to read.
    pub fn shedder(&self) -> &crate::shed::Shedder {
        &self.shedder
    }

    /// A turn at a connection's Noise handshake: waits (in arrival order) while the cap of
    /// concurrent handshakes (`handshakes_in_flight`) are running, and is held until the
    /// handshake is done. The handshake's own timeout (`noise::HANDSHAKE_TIMEOUT`) bounds how
    /// long a peer that stalls holds one.
    pub async fn handshake(&self) -> HandshakeTurn {
        self.handshake_waiting.fetch_add(1, Ordering::SeqCst);
        let permit = Arc::clone(&self.handshakes).acquire_owned().await.ok();
        self.handshake_waiting.fetch_sub(1, Ordering::SeqCst);
        let running = self.handshaking.fetch_add(1, Ordering::SeqCst) + 1;
        self.handshake_peak.fetch_max(running, Ordering::SeqCst);
        self.handshakes_begun.fetch_add(1, Ordering::Relaxed);
        HandshakeTurn {
            _permit: permit,
            running: Arc::clone(&self.handshaking),
        }
    }

    pub fn handshake_report(&self) -> HandshakeReport {
        HandshakeReport {
            permits: self.handshake_permits,
            in_flight: self.handshaking.load(Ordering::SeqCst),
            peak: self.handshake_peak.load(Ordering::SeqCst),
            waiting: self.handshake_waiting.load(Ordering::SeqCst),
            begun: self.handshakes_begun.load(Ordering::Relaxed),
            planned_per_sec: crate::cores::handshake_pace_of(self.handshake_permits),
        }
    }

    /// Takes `areas` (RFC-0174 §2.1): the areas its sharing and MLAT choose from
    /// (`Selection::set_taken`) and its regional product gathers (`Products::set_taken`), and the
    /// areas its member sessions are planned from, so the three cannot disagree.
    pub fn taking(mut self, areas: Vec<Region>) -> Self {
        self.network.selection.set_taken(areas.clone());
        self.network.products.set_taken(areas.clone());
        // Clock models are held for the areas it takes and their border band, and no other
        // (`models`).
        self.network
            .clock_models
            .set_areas(&tally_wire::Regions::new(areas.clone()));
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
        self.queue_bytes = Some(bytes);
        self.fanout = Arc::new(router(&self.budget, self.queue_bytes));
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
            ingest_queued: self.stages.queued(),
            ingest_refused: self.stages.refused(),
            decoded_refused: self.decoded_refused.load(Ordering::Relaxed),
            malformed_batches: self.malformed_batches.load(Ordering::Relaxed),
            rebuilt_refused: self.rebuilt_refused.load(Ordering::Relaxed),
            late_records: self.late_records.load(Ordering::Relaxed),
            unjudged_records: self.unjudged_records.load(Ordering::Relaxed),
            leases_ahead: self.leases_ahead.load(Ordering::Relaxed),
            lease_ahead_until_ms: self.lease_ahead_until_ms.load(Ordering::Relaxed),
            dumps_refused: self.dumps_refused.load(Ordering::Relaxed),
            dumps_resumed: self.dumps_resumed.load(Ordering::Relaxed),
            unreadable_times: self.unreadable_times.load(Ordering::Relaxed),
            clock_steps: self.clock.steps(),
            clock_bound: self.clock.bound_health(),
            strikes_full: self.strikes_full.load(Ordering::Relaxed),
            ahead_records: self.ahead_records.load(Ordering::Relaxed),
            unanchored_records: self.unanchored_records.load(Ordering::Relaxed),
            rebuilt_no_room: self.rebuilt_no_room.load(Ordering::Relaxed),
            awaiting_unheld: self.awaiting_unheld.load(Ordering::Relaxed),
            shed: self.shedder.report(),
            handshakes: self.handshake_report(),
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

    /// A connection's ingest allowance (`ingest::Allowance`): `records` records at once
    /// (`ingest::CREDIT` for a feeder, `ingest::RECORDS_IN_FLIGHT` for a member session), each
    /// charged to the one ingest pool (`Store::Ingest`) in `source`'s turn.
    pub fn allowance(&self, records: usize, source: u64) -> crate::ingest::Allowance {
        crate::ingest::Allowance::new(&self.budget.gauge(Store::Ingest), records, source)
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
    pub async fn connection_buffers(&self, feeder: bool, source: u64) -> crate::budget::Charge {
        let gauge = if feeder {
            self.budget.gauge(Store::Buffers)
        } else {
            self.budget.connection_buffers()
        };
        gauge
            .charge_for(source, crate::ingest::BUFFERS_PER_CONNECTION)
            .await
    }

    /// A test's hand on what each deliverer may hold (`strikes::Shares::set`).
    #[cfg(test)]
    pub(crate) fn set_shares_for_test(&self, entries: crate::strikes::Entries) {
        self.shares.set(entries);
    }

    /// What `who` holds of what was taken (`strikes::Shares::held_by`), for a test.
    #[cfg(test)]
    pub(crate) fn held_by_for_test(&self, who: Deliverer) -> usize {
        self.shares.held_by(who)
    }

    /// Hosts `host`, the MLAT this relay runs, on a hub that plans its raw (`Hub::memory(..,
    /// true)`): its seats, and the room the positions checks hold its own engine's twins in, are
    /// planned from that, so a hub that plans none would hold none of its own engine's twins and
    /// send its clients nothing its engine solved. Refused there, the only way to host MLAT.
    pub fn host_mlat(&self, host: Arc<dyn crate::mlat_host::MlatHost>) -> Result<(), String> {
        if !self.holds_raw {
            return Err(
                "a relay hosting MLAT plans its raw: build its hub with `Hub::memory(.., true)`"
                    .to_owned(),
            );
        }
        self.network.host_mlat(host);
        Ok(())
    }

    /// RFC-0174's duties.
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// A record the relay itself originated (a network duty's, or its hosted MLAT's): into the
    /// fan-out as the relay's own, routed by kind exactly as a peer's would be. Positions, clock
    /// models and their parts go through their own forwarding rules, so a duplicate is still
    /// forwarded once.
    ///
    /// The relay's own store of what is taken is never evicted to make room (`strikes`): a record
    /// of its own making past its room is refused there and counted (`strikes_full`), and goes out
    /// all the same, unremembered. A copy of it that comes back is then new to it once more, and
    /// passed on once more: what a full store costs, never a record the relay signed and kept to
    /// itself, which no member could ever repair, since only it holds it.
    pub fn publish_own(&self, record: Record) {
        self.publish_from(RELAY_ITSELF, Deliverer::Relay, record, true);
    }

    /// Whether a record passed on by hash is to go out: new to `passed_on` (`take_passed_on`), or,
    /// for a record of the relay's own making (`originated`), refused there for want of room
    /// (`Verdict::Full`, counted), since a record the relay made is sent whether or not it can be
    /// remembered (`publish_own`).
    fn goes_out(
        &self,
        hash: Hash,
        signed_ms: Option<u64>,
        who: Deliverer,
        originated: bool,
    ) -> bool {
        match self.take_passed_on(hash, signed_ms, who, self.judged_now()) {
            Verdict::New => true,
            Verdict::Full => originated,
            _ => false,
        }
    }

    /// What a record passed on by hash is to `passed_on`, taken in if new and counted
    /// (`goes_out`): by its signed time `signed_ms`, charged to `who` delivered it, so the relay's
    /// own share holds only what it made or rebuilt. What a peer's regional batch is judged by before the products use it
    /// (`Network::take_regional`), so the lease covers it before it is used. One whose time cannot
    /// be read is late.
    pub(crate) fn take_passed_on(
        &self,
        hash: Hash,
        signed_ms: Option<u64>,
        who: Deliverer,
        now: crate::strikes::Now,
    ) -> Verdict {
        let Some(signed_ms) = signed_ms else {
            self.unreadable_times.fetch_add(1, Ordering::Relaxed);
            return Verdict::Late;
        };
        let verdict = self.passed_on.lock().map_or(Verdict::Full, |mut taken| {
            taken.take(&hash, signed_ms, now, who)
        });
        self.counted(verdict)
    }

    /// A peer's record already taken into `passed_on` before it was used (a regional batch the
    /// products forward, `Network::take_regional`): into the fan-out, never sent back down
    /// `source`, and not judged again.
    pub fn forward_taken(&self, source: u64, record: Record) {
        let cell = match &record {
            Record::RegionalBatch(regional) => regional.content().ok().map(|content| content.cell),
            _ => None,
        };
        self.fanout.publish(Item {
            source,
            record: Arc::new(record),
            cell,
            points: None,
            decoded: None,
            stamp: self.clock.mono(),
            client: None,
        });
    }

    /// `verdict`, counted when it is late or let go for want of room.
    fn counted(&self, verdict: Verdict) -> Verdict {
        match verdict {
            Verdict::Late => {
                self.late_records.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Full => {
                self.strikes_full.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Unjudged => {
                self.unjudged_records.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Ahead => {
                self.ahead_records.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Unanchored => {
                self.unanchored_records.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::New | Verdict::Duplicate => {}
        }
        verdict
    }

    /// As `publish_own`, a record that came in on connection `source` from `who` and is forwarded
    /// unchanged (a peer's regional batch, a member's client regional batch or bundle index):
    /// never sent back down that connection, and what is taken of it charged to `who`'s share
    /// (`strikes::Shares`).
    pub fn publish_as(&self, source: u64, who: Deliverer, record: Record) {
        self.publish_from(source, who, record, false);
    }

    /// As `publish_as`, of the relay's own making when `originated` (`publish_own`).
    fn publish_from(&self, source: u64, who: Deliverer, record: Record, originated: bool) {
        match record {
            Record::Positions(positions) => {
                if positions.engine().is_ok() {
                    self.publish_positions(source, positions);
                }
            }
            Record::ClockModel(model) => {
                if model.engine().is_ok() {
                    self.publish_clock_model(source, model);
                }
            }
            Record::ClockModelPart(part) => {
                self.publish_clock_model_part(source, part);
            }
            Record::ClientClockModel(model) => {
                self.publish_client_clock_model(source, model);
            }
            // This relay's own feeder figures, signed by its duties (`Network::tick`): placed by
            // their area, for the clients that read it (`Subscription::serves`). A peer's are
            // never published here: its link takes no figures from it (`link::ingest` passes
            // them by, as it does another relay's deduplicated stream).
            Record::FeederFigures(figures) => {
                // By their signed `issued_ms`, in a window stretched by the hour they may be
                // signed in (`strikes::Window::figures`): an archive's figures re-sent later are
                // late.
                let content = figures.content().ok();
                let Some(issued_ms) = content.as_ref().map(|content| content.issued_ms) else {
                    self.unreadable_times.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let now = self.judged_now();
                let verdict = self.figures.lock().map_or(Verdict::Full, |mut taken| {
                    taken.take(&figures.hash(), issued_ms, now, who)
                });
                match self.counted(verdict) {
                    Verdict::New => {}
                    Verdict::Full if originated => {}
                    _ => return,
                }
                let area = content.and_then(|content| content.area);
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(Record::FeederFigures(figures)),
                    cell: area,
                    points: None,
                    decoded: None,
                    stamp: self.clock.mono(),
                    client: None,
                });
            }
            Record::ClientRegionalBatch(regional) => {
                if !self.goes_out(regional.hash(), regional.wall_ms().ok(), who, originated) {
                    return;
                }
                let cell = regional.content().ok().map(|content| content.cell);
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(Record::ClientRegionalBatch(regional)),
                    cell,
                    points: None,
                    decoded: None,
                    stamp: self.clock.mono(),
                    client: None,
                });
            }
            Record::BundleIndex(index) => {
                let content = index.content().ok();
                let signed_ms = content
                    .as_ref()
                    .map(|content| content.second.saturating_mul(1000));
                if !self.goes_out(index.hash(), signed_ms, who, originated) {
                    return;
                }
                let cell = content.map(|content| content.parent);
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(Record::BundleIndex(index)),
                    cell,
                    points: None,
                    decoded: None,
                    stamp: self.clock.mono(),
                    client: None,
                });
            }
            Record::RegionalBatch(regional) => {
                if !self.goes_out(regional.hash(), regional.wall_ms().ok(), who, originated) {
                    return;
                }
                let cell = regional.content().ok().map(|content| content.cell);
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(Record::RegionalBatch(regional)),
                    cell,
                    points: None,
                    decoded: None,
                    stamp: self.clock.mono(),
                    client: None,
                });
            }
            other => {
                self.fanout.publish(Item {
                    source,
                    record: Arc::new(other),
                    cell: None,
                    points: None,
                    decoded: None,
                    stamp: self.clock.mono(),
                    client: None,
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

    /// The relays this one offers feeders as hints, and names when it turns a subscriber away.
    pub fn advertising(mut self, hints: Vec<RelayAddress>) -> Self {
        self.hints = hints;
        self
    }

    /// Keys accepted as relays when they dial in (`--accept-relay`), beside any accepted already:
    /// a relay forwards anyone's batches and is not held to the subscriber cap, so that trust is
    /// the operator's to give, key by key. Their freshness anchors are trusted too (`anchors`).
    pub fn accepting_relays(mut self, keys: impl IntoIterator<Item = PublicKey>) -> Self {
        self.accepted_relays.extend(keys);
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

    /// Signs the feeder figures every `every_ms` instead of `figures::PUBLISH_EVERY_MS`.
    pub fn figures_every(self, every_ms: u64) -> Self {
        self.network.figures.publish_every(every_ms);
        self
    }

    /// Serves at most `clients` beast-out clients at once (`--max-beast-clients`, where
    /// `--beast-out` is given; none otherwise), each planned as a subscriber's session; one past
    /// them is closed as it is accepted (`link::serve_beast`).
    pub fn serving_beast(mut self, clients: usize) -> Self {
        self.beast_clients = clients;
        self.replanned()
    }

    /// The beast-out clients served at once (`Hub::serving_beast`).
    pub fn beast_clients(&self) -> usize {
        self.beast_clients
    }

    /// Serves at most `clients` acars-out clients at once (`--max-acars-clients`, where
    /// `--acars-out` is given; none otherwise), as `serving_beast` serves beast-out's
    /// (`link::serve_acars`).
    pub fn serving_acars(mut self, clients: usize) -> Self {
        self.acars_clients = clients;
        self.replanned()
    }

    /// The acars-out clients served at once (`Hub::serving_acars`).
    pub fn acars_clients(&self) -> usize {
        self.acars_clients
    }

    /// Every listener's gauge (`listeners`).
    pub fn listeners(&self) -> &crate::listeners::Listeners {
        &self.listeners
    }

    /// The descriptors the relay may hold at once, by its caps: every connection the plan counts
    /// (those under the connection cap, the dials among them; the member sessions; the
    /// subscribers and the beast-out and acars-out clients), every feeder admitted, the stats'
    /// connections, and what the process holds beside them (`listeners::OTHER_DESCRIPTORS`). What
    /// the relay asks the kernel for before it serves (`listeners::raise_open_files`).
    pub fn descriptors(&self) -> usize {
        self.budget
            .plan()
            .connections
            .saturating_add(self.budget.admission().connections)
            .saturating_add(crate::stats::MAX_CONNECTIONS)
            .saturating_add(crate::listeners::OTHER_DESCRIPTORS)
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
        // The records a second it lets a feeder send are planned in the cores.
        self.shedder_built().replanned()
    }

    /// The most bytes a second the sharing members may send, all together (their shared pace)
    /// and each alone (its ceiling), beyond the burst. Planned once as the feeders this rate is
    /// worth: the budget is resized with it.
    pub fn max_member_bytes_per_sec(mut self, rate: u64) -> Self {
        self.max_member_bytes_per_sec = rate;
        // The paces follow the plan (`Hub::memory`).
        self.replanned()
    }

    /// The pace every member session shares, in bytes and receptions, fair between them.
    pub fn member_pace(&self) -> Arc<crate::ingest::MemberPace> {
        Arc::clone(&self.member_pace)
    }

    /// The records a second every member session's data shares (`ingest::RecordPace`).
    pub fn member_records(&self) -> Arc<crate::ingest::RecordPace> {
        Arc::clone(&self.member_records)
    }

    /// The directory links' paces, one share of `ingest::DIRECTORY_RECORDS` per network group
    /// (`ingest::DirectoryPaces`).
    pub fn directory_records(&self) -> &Arc<crate::ingest::DirectoryPaces> {
        &self.directory_records
    }

    /// What new sessions are granted of their roles' bursts (`ingest::BurstGrants`).
    pub fn burst_grants(&self) -> &crate::ingest::BurstGrants {
        &self.burst_grants
    }

    /// Feeders' batches dropped so far for taking their receiver past its wanted receptions a
    /// second (`ingest::FEEDER_RECEPTIONS_PER_SEC`), and the wanted receptions they carried.
    pub fn over_reception_ceiling(&self) -> OverCeiling {
        OverCeiling {
            batches: self.over_ceiling_batches.load(Ordering::Relaxed),
            wanted: self.over_ceiling_receptions.load(Ordering::Relaxed),
        }
    }

    /// The records a second one feeder's session may send (`ingest::records_per_sec` of its byte
    /// ceiling).
    pub fn feeder_records_per_sec(&self) -> u64 {
        crate::ingest::records_per_sec(self.max_feeder_bytes_per_sec)
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

    /// What a member session's socket is read at most (its `Ceiling`): the members' raw rate and
    /// their products' pace, either of which one member may carry all of.
    pub fn member_ceiling_bytes_per_sec(&self) -> u64 {
        self.max_member_bytes_per_sec
            .saturating_add(self.member_pace.products_rate())
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
            address,
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

    /// Forwards a batch if it is new (`strikes`): handed to the ingest worker that owns its
    /// receiver's shard, which admits, decodes (once, `ingest`), deduplicates and fans it out. On
    /// a hub whose stages run inline this happens before it returns, and the answer is whether it
    /// was new; on threads it is the worker's, and this says only that it was handed over (false
    /// when the workers' queues held their bound, `ingest::Stages::refused`).
    pub fn ingest(self: &Arc<Self>, inbound: Inbound) -> bool {
        let Ok(receiver) = inbound.batch.receiver() else {
            return false;
        };
        // Its raw monotonic clock as it reached this relay (`Inbound::arrived`), or as it is handed
        // in here, before any queue: what this relay's own anchor in it is aged by
        // (`own_anchor_age`), so waiting for a worker never ages it.
        let arrived = inbound.arrived.unwrap_or_else(|| self.clock.raw());
        if self.stages.is_inline() {
            return self.admit(0, inbound, arrived);
        }
        let worker = self.stages.worker_of(raw_shard(&receiver));
        let hub = Arc::clone(self);
        let Inbound {
            source,
            batch,
            origin,
            verify,
            stamp,
            arrived: _,
            in_flight,
            refusal,
            ..
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
                        arrived: Some(arrived),
                        in_flight,
                        refusal,
                    },
                    arrived,
                );
            }),
        )
    }

    /// A record this relay rebuilt from its sharing group's parity (`sharing::Ticked::rebuilt`):
    /// taken in through the one intake its kind has, as a member's piece of the group is (a batch
    /// admitted by the ingest stage, `take_piece`, `Network::take_regional`), handed in by the
    /// relay itself (`RELAY_ITSELF`, the session the products charge its rebuilding to), and not
    /// received into its group again, which holds it already (`Origin::Rebuilt`). Never published
    /// straight into the fan-out: a batch rebuilt so was never admitted, so it was not remembered
    /// as kept (a copy arriving after was published again), not counted for its station, not
    /// decoded for the hosted MLAT or the message exchange, and placed for no regional subscriber.
    ///
    /// Every rebuilt record ends in one verdict, given back to the group that rebuilt it by its
    /// handle (`rebuilt`, never reckoned again from the record): passed on (`Network::rebuilt`),
    /// refused (`refuse_rebuilt`, counted in `rebuilt_refused`), or let go: for want of room
    /// (`let_go_rebuilt`, counted in `rebuilt_no_room`, or `strikes_full`), or outside the window
    /// of time (`late_records`), so none stays held unjudged and none outside the window is had.
    pub fn take_rebuilt(self: &Arc<Self>, rebuilt: Rebuilt, record: Record) {
        match record {
            Record::Batch(batch) => {
                // One with no receiver to read is no batch any intake takes.
                if batch.receiver().is_err() {
                    self.refuse_rebuilt(rebuilt);
                    return;
                }
                // Charged as the relay's own, but never waited for: the timed duties' thread
                // hands it in, and sharing's sends and receipts must not queue behind ingest.
                // Without room it is let go from its group, counted, and asked for again.
                let Some(in_flight) = InFlight::try_trusted(
                    &self.budget.gauge(Store::Ingest),
                    crate::ingest::floored(crate::ingest::charge_of(&batch)),
                ) else {
                    self.let_go_rebuilt(rebuilt);
                    return;
                };
                let handed = self.ingest(Inbound {
                    source: RELAY_ITSELF,
                    batch,
                    origin: Origin::Rebuilt(rebuilt),
                    verify: true,
                    stamp: None,
                    arrived: None,
                    in_flight,
                    refusal: None,
                });
                // Inline, `ingest` is the admission's own answer, which gave its verdict; across
                // the workers it is false only when their queues were full and the batch was let
                // go unadmitted (`Stages::run_charged`), which is no room.
                if !handed && !self.stages.is_inline() {
                    self.let_go_rebuilt(rebuilt);
                }
            }
            record @ (Record::RegionalBatch(_) | Record::ClientRegionalBatch(_)) => {
                // A relay with no identity yet is in no group, and has no word to forward as.
                let Some(key) = self.network.signer().map(crate::signer::Signer::public) else {
                    self.refuse_rebuilt(rebuilt);
                    return;
                };
                let asker = Asker {
                    role: crate::network::AskerRole::Relay,
                    key,
                    source: RELAY_ITSELF,
                    loopback: true,
                    address: None,
                };
                let taken = self.network.take_regional(self, &asker, record, |record| {
                    self.network
                        .rebuilt(self, rebuilt, record, self.stamp_now());
                });
                match taken {
                    // A late one is held in its group all the same (`late`).
                    crate::network::Regional::Passed | crate::network::Regional::Late => {}
                    crate::network::Regional::Refused => self.refuse_rebuilt(rebuilt),
                    // No room: let go, never held as had, so its group asks for it again.
                    crate::network::Regional::Full => self.network.sharing.let_go(rebuilt),
                }
            }
            // Anything else its kind's intake judges; one it does not pass on (refused, or a fault
            // proof this relay cannot judge, which it forwards to no one) is refused in its group.
            record => {
                let passed = std::cell::Cell::new(false);
                let no_room = std::cell::Cell::new(false);
                let taken = self.take_piece(
                    RELAY_ITSELF,
                    Deliverer::Relay,
                    record,
                    |record| {
                        passed.set(true);
                        self.network
                            .rebuilt(self, rebuilt, record, self.stamp_now());
                    },
                    || no_room.set(true),
                );
                // No room: let go, never refused, so its group does not count it as had.
                if no_room.get() {
                    self.network.sharing.let_go(rebuilt);
                } else if taken.is_err() || !passed.get() {
                    self.refuse_rebuilt(rebuilt);
                }
            }
        }
    }

    /// A record rebuilt from parity that this relay judged and refused: counted, and refused in
    /// the group that rebuilt it, which lets it go and never passes it on (`Member::refuse`).
    pub fn refuse_rebuilt(&self, rebuilt: Rebuilt) {
        self.rebuilt_refused.fetch_add(1, Ordering::Relaxed);
        self.network
            .sharing
            .refused_rebuilt(rebuilt, self.stamp_now());
    }

    /// Runs the test's step set for the next batch judged new, once.
    #[cfg(test)]
    fn between_judged_and_taken(&self) {
        let step = self.between.lock().ok().and_then(|mut step| step.take());
        if let Some(step) = step {
            step();
        }
    }

    /// A copy this relay may not use ([`Verdict::Late`]): counted (`late_records`), and never
    /// used (forwarded, remembered, given to the products), but held: possession never reads a
    /// clock (`strikes`), so it is taken into its group as where it came from says, as a
    /// duplicate is (seeded by this relay where its feeder published it, `Network::originate`;
    /// held, counted as had, its sender credited and pushed on down its stripe from a member or
    /// from parity). So what the group's receipts compare never turns on any relay's clock: a
    /// member is never short for a copy its receiver may not use, nor a relay for one its own
    /// window refused (RFC-0174 §2.5), whatever version its feeder runs. A feeder's batch too old
    /// to use is counted against its receiver too (`stations::StationReport`'s `late_batches`),
    /// where its owner reads it. A member's or a relay's copy is counted where it was published.
    fn late_from_feeder(
        &self,
        blame: crate::strikes::Blame,
        origin: &Origin,
        receiver: PublicKey,
        stamp: Mono,
    ) {
        if matches!(origin, Origin::Feeder(..))
            && let Ok(mut stations) = self.stations.lock()
        {
            stations.too_old(blame, receiver, stamp);
        }
    }

    fn late(&self, origin: &Origin, record: &Record, now: Now) {
        self.counted(Verdict::Late);
        self.share(origin, record, now);
    }

    /// What a feeder's batch's freshness anchors make of it here, this relay's judging clock
    /// reading `now_ms` (`anchors::judge`, RFC-0171 §3.6): each anchor's relay one this relay
    /// knows (its own key, or `relay_trust`'s), each signature checked once (`anchors::Anchors`).
    fn anchoring(&self, batch: &Batch, now: Judged) -> crate::anchors::Anchoring {
        let Ok(anchors) = batch.anchors() else {
            return crate::anchors::Anchoring::Unanchored;
        };
        let own = self.network.signer().map(crate::signer::Signer::public);
        crate::anchors::judge(
            &anchors,
            now,
            |key| own == Some(*key) || self.relay_trust(key).is_some(),
            |anchor| self.network.anchors.verified(anchor),
        )
    }

    /// How long before it arrived (`arrived`, its raw monotonic reading as it reached this relay's
    /// process: `link::Drained`, never later than its bytes came off the socket, before any pacing
    /// or queueing on the way here ages it), by its raw monotonic clock, this relay issued its own
    /// anchor in a feeder's batch, when the batch carries one that verifies
    /// (`anchors::Anchors::issued_by`, which never overstates it, an anchor the ring let go or an
    /// earlier run's included): what blame is reckoned by where the batch is published
    /// (`strikes::blame`). This relay signed it and timed it on a clock no daemon slews or steps,
    /// so the age is the batch's own, whatever its judging clock did meanwhile. The youngest,
    /// should it carry two. Absent, and so never blamed, when it carries none, or this relay has
    /// no key (it issues no anchor, in this run or any) or has issued none this run.
    fn own_anchor_age(&self, batch: &Batch, arrived: Raw) -> crate::strikes::OwnAnchor {
        use crate::strikes::OwnAnchor;
        let Some(own) = self.network.signer().map(crate::signer::Signer::public) else {
            return OwnAnchor::Absent;
        };
        batch
            .anchors()
            .ok()
            .into_iter()
            .flatten()
            .filter(|anchor| anchor.relay == own && self.network.anchors.verified(anchor))
            .filter_map(|anchor| self.network.anchors.issued_by(anchor.j_ms))
            .map(|issued| arrived.since(issued))
            .min()
            .map_or(OwnAnchor::Absent, OwnAnchor::Aged)
    }

    /// The freshness anchor this relay states to its feeder sessions now (`anchors::Anchors::
    /// issue`): one a period, signed through its signer, so none while its clock is not judging,
    /// not even the one it signed a moment before.
    pub fn anchor(&self) -> Option<tally_wire::Anchor> {
        if !self
            .network
            .signer()
            .is_some_and(crate::signer::Signer::signs)
        {
            return None;
        }
        // Both clocks and whether the judging one judged, read together: an anchor is signed only
        // by a reading taken while it did.
        let stamp = self.clock.stamp(0);
        if !stamp.judging() {
            return None;
        }
        self.network
            .anchors
            .issue(stamp.judged(), stamp.raw(), |judged| {
                self.network.with_signing(stamp, |signing| {
                    signing.map(|signing| tally_wire::Anchor::sign(signing, judged.ms()))
                })
            })
    }

    /// A feeder's batch with no anchor this relay can check ([`Verdict::Unanchored`]): held as a
    /// late one is, and counted apart (`unanchored_records`).
    fn unanchored(&self, origin: &Origin, record: &Record, now: Now) {
        self.counted(Verdict::Unanchored);
        self.share(origin, record, now);
    }

    /// A copy this relay could not judge ([`Verdict::Unjudged`]): held as a late one is, and
    /// counted apart (`unjudged_records`).
    fn unjudged(&self, origin: &Origin, record: &Record, now: Now) {
        self.counted(Verdict::Unjudged);
        self.share(origin, record, now);
    }

    /// A new record let go for want of room ([`Verdict::Full`]): counted (`strikes_full`), and
    /// never taken in (forwarded, remembered) nor held in its group, which so does not count it as
    /// had and asks for it again; but a member that delivered it is credited for it, as for a late
    /// copy (`no_room`), by the clocks it arrived at (`now`). One rebuilt from parity is let go
    /// from its group, not refused.
    fn not_taken(&self, origin: &Origin, record: &Record, now: Now) {
        self.counted(Verdict::Full);
        match origin {
            Origin::Rebuilt(rebuilt) => self.network.sharing.let_go(*rebuilt),
            Origin::Peer(asker) => self.no_room(Deliverer::Peer(asker.key), record, now),
            Origin::Feeder(..) | Origin::Elsewhere => {}
        }
    }

    /// A record `who` delivered that this relay had no room to take in: a peer is credited for it
    /// in its group (`Network::no_room_from_peer`), so this relay's want of room never reports an
    /// honest member short (RFC-0174 §2.5). Nothing else delivers into a group. By the clocks
    /// it arrived at (`now`, its stamp's): the group's schedule runs on `M` as its stamps do.
    fn no_room(&self, who: Deliverer, record: &Record, now: Now) {
        if let Deliverer::Peer(key) = who {
            self.network.no_room_from_peer(self, key, record, now);
        }
    }

    /// A record whose signed time cannot be read (`unreadable_times`): no window can hold it, and
    /// it is malformed, so it is refused in its group as one that fails its check is.
    fn unreadable_time(&self, origin: &Origin, record: &Record) {
        self.unreadable_times.fetch_add(1, Ordering::Relaxed);
        match origin {
            Origin::Peer(asker) => {
                self.network
                    .refused_from_peer(self, asker, record, self.stamp_now());
            }
            Origin::Rebuilt(rebuilt) => self.refuse_rebuilt(*rebuilt),
            Origin::Feeder(..) | Origin::Elsewhere => {}
        }
    }

    /// Where a record signed at `signed_ms` (none: its time could not be read) stands against this
    /// relay's window of time for what relays sign at `now` (`strikes::Window::relay_signed`), one
    /// reading of the judging clock and whether it judged as it was read, and the
    /// floor of what it may have forgotten of them (`passed_on`'s, which outlives a restart),
    /// counted when outside it: what a record judged by no table of its own (a regional batch,
    /// whose copies the products and `passed_on` count) is held to before it is used.
    pub fn in_window(&self, signed_ms: Option<u64>, now: crate::strikes::Now) -> InWindow {
        let Some(signed_ms) = signed_ms else {
            self.unreadable_times.fetch_add(1, Ordering::Relaxed);
            return InWindow::Unreadable;
        };
        if !now.judges()
            || self
                .passed_on
                .lock()
                .map_or(true, |table| table.is_pending())
        {
            // No floor yet to judge by (`Hub::begin_strikes`), or a clock not judging now (its
            // error past `E`): held, never used.
            self.counted(Verdict::Unjudged);
            InWindow::Late
        } else if self.window.holds(signed_ms, now.judged())
            && self.above_passed_on_floor(signed_ms)
        {
            InWindow::Inside
        } else {
            self.counted(Verdict::Late);
            InWindow::Late
        }
    }

    /// A record rebuilt from parity that this relay had no room to take in: counted, and let go
    /// from the group that rebuilt it, which asks for it again (`Member::let_go`).
    fn let_go_rebuilt(&self, rebuilt: Rebuilt) {
        self.rebuilt_no_room.fetch_add(1, Ordering::Relaxed);
        self.network.sharing.let_go(rebuilt);
    }

    /// A piece of a group's data other than a batch or a regional batch (positions, a clock model, its client form, a fault proof), from session `source` and
    /// delivered by `who`: the one intake each kind has, whether a member's link brought it
    /// (`link`) or this relay rebuilt it from parity (`take_rebuilt`). Its signature is checked
    /// and it is judged by what this relay took in (`strikes`): `share` takes a new one, a
    /// duplicate or a late one into its group as where it came from says (a new one is published,
    /// a late one never: `late`); `let_go` is told instead when it was let go for want of room, and
    /// it is not counted had. One whose signed time cannot be read is malformed, an error, as one
    /// with no engine to read is. A fault proof is checked before it is forwarded: one this relay
    /// cannot judge (a proof format or a solver spec version it does not know) is dropped and not
    /// held against the sender; one that proves nothing is an error (a false accusation, which ends
    /// a link's session). Any other record is not a piece, and is an error.
    pub fn take_piece(
        &self,
        source: u64,
        who: Deliverer,
        record: Record,
        share: impl FnOnce(&Record),
        let_go: impl FnOnce(),
    ) -> Result<(), String> {
        use tally_wire::fault_proof::{FAULT_PROOF_FORMAT, MODEL_FAULT_PROOF_FORMAT};
        let intake = Some(Intake { share, let_go });
        match record {
            Record::Positions(positions) => {
                positions.engine().map_err(|error| error.to_string())?;
                positions.issued_ms().map_err(|error| error.to_string())?;
                positions.verify().map_err(|error| error.to_string())?;
                self.take_positions(source, positions, who, intake);
            }
            Record::ClockModel(model) => {
                model.engine().map_err(|error| error.to_string())?;
                model.issued_ms().map_err(|error| error.to_string())?;
                model.verify().map_err(|error| error.to_string())?;
                self.network.hold_model(&model);
                self.take_clock_model(source, model, who, intake);
            }
            // A clock model as a client reads it (no sites, no offsets), published beside its
            // full model by the engine that signed both.
            Record::ClientClockModel(model) => {
                model.verify().map_err(|error| error.to_string())?;
                model.content().map_err(|error| error.to_string())?;
                self.take_client_clock_model(source, model, who, intake);
            }
            Record::FaultProof(proof) => {
                if proof.format() != FAULT_PROOF_FORMAT
                    && proof.format() != MODEL_FAULT_PROOF_FORMAT
                {
                    return Ok(());
                }
                let spec = proof.spec_version().map_err(|error| error.to_string())?;
                let Some(tolerance) = tally_wire::Tolerance::for_spec(spec) else {
                    return Ok(());
                };
                proof
                    .check(&tolerance)
                    .map_err(|error| format!("sent a fault proof that proves nothing: {error}"))?;
                self.take_fault_proof(source, proof, who, intake);
            }
            other => {
                return Err(format!(
                    "a record of kind {} is not a piece of a group",
                    other.kind()
                ));
            }
        }
        Ok(())
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
    fn admit(&self, producer: usize, inbound: Inbound, arrived: Raw) -> bool {
        let Inbound {
            source,
            batch,
            origin,
            verify,
            stamp,
            arrived: _,
            in_flight,
            refusal,
            ..
        } = inbound;
        let Ok(receiver) = batch.receiver() else {
            if let Origin::Rebuilt(rebuilt) = origin {
                self.refuse_rebuilt(rebuilt);
            }
            return false;
        };
        // A receiver's signature only: a relay's deduplicated batch never passes as one.
        if verify && let Err(error) = batch.verify() {
            if let Some(refusal) = refusal {
                refusal.refuse(error.to_string());
            }
            if let Origin::Rebuilt(rebuilt) = origin {
                self.refuse_rebuilt(rebuilt);
            }
            return false;
        }
        // A trace's stamp as it gave it; else the ingest clock's now. Its raw reading as it came
        // off its link is `arrived`, apart.
        let stamp = match stamp {
            Some(stamp) => self.stages.stamped(producer, stamp),
            None => self.stages.stamp(producer),
        };
        // A test's delay, between the stamp and everything after it.
        self.stages.pause(Stage::Ingest);
        let shard = &self.raw[usize::from(raw_shard(&receiver).0)];
        let hash = batch.hash();
        // Judged by its own signed clock (`strikes`). One whose clock cannot be read is malformed
        // (no batch format leaves it out): its feeder's link ends as for one that does not verify,
        // and a member's is refused in its group.
        let Ok(signed_ms) = batch.wall_ms() else {
            if let Some(refusal) = refusal {
                refusal.refuse("sent a batch whose signed clock cannot be read".to_owned());
            }
            self.unreadable_time(&origin, &Record::Batch(batch));
            return false;
        };
        // Usability by the judging clock as it was taken (its stamp's `judged`, with whether it judged); everything
        // else (paces, ceilings, stations, the fan-out) by the monotonic one (`stamp_ms`).
        let judged_at = stamp.judged();
        let feeder = matches!(origin, Origin::Feeder(..));
        // Where a feeder publishes it, its clock decides whether it is usable here and nothing
        // else (`strikes::feeder_clock`, RFC-0171 §3.6): however far ahead or behind, it is
        // possessed (held in its group, tagged, passed on to the peers, who judge it by their own
        // clocks) and charged to its feeder's share and ceiling like any other, and nothing is
        // refused or ended for it.
        let mut too_old = false;
        // Not usable here, and blamed on nobody: this relay's clock not judging, or the batch
        // signed more than `F` ahead of it.
        let mut unjudged = false;
        // Signed further ahead than this hop may use as it arrives here, or its oldest anchor
        // ahead of this relay's clock: counted (`ahead_records`) and blamed on nobody.
        let mut ahead = false;
        if feeder {
            // Whether the clock judged is the stamp's, read with it: a batch stamped while it did
            // not is never judged, nor blamed, whatever the clock says by the time it is admitted.
            match crate::strikes::feeder_clock(signed_ms, crate::strikes::Now::from(stamp)) {
                crate::strikes::FeederClock::Usable => {}
                crate::strikes::FeederClock::TooOld => too_old = true,
                crate::strikes::FeederClock::Unjudged => unjudged = true,
                crate::strikes::FeederClock::Ahead => ahead = true,
            }
            // One somewhat off, too old or too far ahead among them, has its feeder told this
            // relay's clock again at its next heartbeat (`ingest::Refusal::drifted`), if it signed
            // in step since it was last told.
            if let Some(refusal) = &refusal {
                if too_old || tally_wire::budget::RESTATE_BEYOND.apart_from(signed_ms, judged_at) {
                    refusal.drifted();
                } else {
                    refusal.in_step();
                }
            }
        }
        let who = match &origin {
            Origin::Feeder(..) => Deliverer::Feeder(receiver),
            Origin::Peer(asker) => Deliverer::Peer(asker.key),
            Origin::Rebuilt(_) | Origin::Elsewhere => Deliverer::Relay,
        };
        // A copy of a batch this relay already took in (a member's copy of a feeder's, another
        // path's, a feeder's resend) is a duplicate before anything else: neither judged again,
        // counted late, nor charged against anyone's share. Whether a batch is new is asked
        // without remembering it; it is remembered only once it is kept (below), so a batch
        // dropped for load or for its receiver's pace is no batch seen, and the copy a member
        // sends of it is still new, here and on every relay.
        // A feeder's batch is blamed at most once, when it is first judged here: a repeat of one
        // already judged (a resend, an audit's owed batch) is judged as ever but blamed on
        // nobody (`stations::Stations::first_judged`).
        let (judged, first) = shard.lock().map_or((Verdict::Full, false), |mut shard| {
            let judged =
                shard
                    .batches
                    .judge_batch(&hash, signed_ms, crate::strikes::Now::from(stamp), who);
            // The station rows' lock after the shard's, as everywhere both are held.
            let first = feeder
                && judged != Verdict::Duplicate
                && self.stations.lock().is_ok_and(|mut stations| {
                    stations.first_judged(receiver, batch.boot_id(), batch.sequence(), stamp.mono())
                });
            (judged, first)
        });
        if judged == Verdict::Duplicate {
            // Not used again, but a member that sent it still sent it (sharing's receipts).
            self.share(&origin, &Record::Batch(batch), Now::from(stamp));
            return false;
        }
        // The ingest rate (`shed`): every feeder's batch not refused, usable or not, is held to
        // its source's fair share here, before it is seeded into its group, shared, signed over
        // or sent anywhere, so nothing after this point ever refuses it, and a feeder sending
        // batches too old to use fills its group no faster than one sending good ones. By its
        // own stamp, counted per source and reason. A member's or a relay's batch is never cut:
        // it was held to its feeder's share by the relay that took it from its feeder.
        let unit = match &origin {
            Origin::Feeder(_, group, _) => Some(self.shed_unit(&receiver, *group)),
            _ => None,
        };
        // Judged by its cost of the rate (`ingest::rate_cost`: what it is charged, the unit
        // `R_max`'s bytes and every store holding its decode are planned in, or its signed bytes
        // weighed for the groups that hold them longer): a batch inflated past the planned mean, or
        // padded, costs its share what it costs the stores, never only its bytes on the wire.
        let cost = shed::Cost {
            receptions: batch.receptions().map_or(0, |n| n as u64),
            bytes: crate::ingest::rate_cost(&batch) as u64,
        };
        if let Some(unit) = unit
            && self.shedder.judge(unit, cost, stamp.mono_ms()).is_err()
        {
            return false;
        }
        // Usable by its signed time and its table: then by its freshness anchors, wherever it
        // came from (`anchors`, RFC-0171 §3.6). A pure function of its signed bytes and this
        // relay's clock, so the same at every arrival. Stale or ahead by its anchors, or with
        // none this relay can check, it is held unused and blamed on nobody: a lying relay's
        // anchor must never blame an honest feeder.
        let anchoring = if judged == Verdict::New && !too_old && !unjudged && !ahead {
            self.anchoring(&batch, judged_at)
        } else {
            crate::anchors::Anchoring::Fresh
        };
        // Too old by its own signed time where its feeder published it is the one lateness
        // blamed on its receiver, once, and only when this relay's own anchor in it, timed from
        // its issue on a clock no daemon moves, is older than an honest batch's can be: so a
        // batch its feeder held waiting for its first anchor, or signed by a clock behind, is not
        // blamed; and no other relay's anchor moves it (`strikes::blame`).
        let blamed = crate::strikes::blame(too_old, first, self.own_anchor_age(&batch, arrived));
        let ahead =
            ahead || judged == Verdict::Ahead || anchoring == crate::anchors::Anchoring::Ahead;
        let unanchored = anchoring == crate::anchors::Anchoring::Unanchored;
        let stale = anchoring == crate::anchors::Anchoring::Stale;
        let unjudged = unjudged || ahead || judged == Verdict::Unjudged;
        let late = too_old || stale || unjudged || unanchored || judged == Verdict::Late;
        if !late && judged == Verdict::Full {
            self.not_taken(&origin, &Record::Batch(batch), Now::from(stamp));
            return false;
        }
        // A feeder's batch that would take its receiver past its wanted receptions a second is
        // dropped here, counted, never waited for on its read loop: the feeder was told the
        // ceiling and sheds to it before it signs, so only one that predates it, or one that
        // ignores it, meets this. Its wanted receptions read from its signed bytes, with no
        // decode (`Batch::wanted_receptions`), so a batch it may not use (too old, unjudged,
        // unanchored, late) is charged exactly as one it may: whether a batch is kept never
        // depends on this relay's clock. One whose bytes do not hold the receptions they state is
        // charged every reception it states, the most it can want. By the batch's stamp, on the
        // worker that owns the receiver's shard, so the same stamped batches are kept alike on
        // any threads. Read from its plain bytes inflated once, which its decode then reads too
        // (`Batch::inflated`): before (2026-10-27), a compressed batch was inflated twice.
        let mut inflated = None;
        if feeder {
            inflated = batch.inflated().ok();
            let wanted = inflated
                .as_ref()
                .and_then(|inflated| inflated.wanted_receptions().ok())
                .map_or(cost.receptions, |wanted| wanted as u64);
            if !self.within_ceiling(shard, receiver, wanted, stamp.mono_ms(), unit, cost) {
                return false;
            }
        }
        if late {
            if ahead {
                self.ahead_records.fetch_add(1, Ordering::Relaxed);
            }
            if unanchored {
                self.unanchored(&origin, &Record::Batch(batch), Now::from(stamp));
            } else if unjudged {
                self.unjudged(&origin, &Record::Batch(batch), Now::from(stamp));
            } else {
                if let Some(blame) = blamed {
                    self.late_from_feeder(blame, &origin, receiver, stamp.mono());
                }
                self.late(&origin, &Record::Batch(batch), Now::from(stamp));
            }
            return false;
        }
        #[cfg(test)]
        self.between_judged_and_taken();
        // Its signed bytes and its decode each charged once, for their life, to `Store::Decoded`
        // (`Stages::decode_owned`), whichever stages hold them from here: the ingest charge is
        // done. A format this build cannot read never comes here: it carries no anchor this hop
        // can check, so it was held unanchored above, possessed and passed on raw (RFC-0171 §3.6:
        // a relay routes and deduplicates a format it does not otherwise read). One the store
        // has no room for is let go, counted.
        let store = self.budget.gauge(Store::Decoded);
        let covered = crate::budget::Covered::process();
        let mut decoded =
            Stages::decode_inflated_owned(batch, inflated.as_ref(), stamp, &store, covered);
        // No room: the subscribers keeping the most alive are let go, as fallen behind, while
        // that makes room (a decode an epoch or MLAT still holds stays), as the fan-out's own
        // gauge lets them go for an item.
        while let Err(tally_wire::decoded::NotDecoded::NoRoom(batch)) = decoded {
            if !self.fanout.let_go_largest() {
                decoded = Err(tally_wire::decoded::NotDecoded::NoRoom(batch));
                break;
            }
            decoded =
                Stages::decode_inflated_owned(batch, inflated.as_ref(), stamp, &store, covered);
        }
        drop(inflated);
        drop(in_flight);
        let (batch, decoded) = match decoded {
            Ok(decoded) => (decoded.batch().clone(), Some(decoded)),
            // A batch that does not decode is of a format this build reads (one it cannot read
            // was held unanchored above), so it is malformed (an ACARS message in a format 1 or 2
            // batch among them, which a relay that predates format 3 would read): never
            // forwarded raw. Straight from its feeder, the feeder's link ends, as for a batch
            // that does not verify; from a peer (a relay that predates the format forwards it
            // raw), it is dropped, counted, and its group counts it as had, so no repair asks for
            // it again.
            Err(tally_wire::decoded::NotDecoded::Undecodable(undecodable)) => {
                match &origin {
                    Origin::Feeder(..) => {
                        if let Some(refusal) = refusal {
                            refusal.refuse(undecodable.error.to_string());
                        }
                    }
                    Origin::Peer(asker) => {
                        self.malformed_batches.fetch_add(1, Ordering::Relaxed);
                        let record = Record::Batch(undecodable.batch);
                        self.network.refused_from_peer(self, asker, &record, stamp);
                    }
                    // Counted once, as a rebuilt record refused (`rebuilt_refused`).
                    Origin::Rebuilt(rebuilt) => self.refuse_rebuilt(*rebuilt),
                    Origin::Elsewhere => {
                        self.malformed_batches.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return false;
            }
            Err(tally_wire::decoded::NotDecoded::NoRoom(_)) => {
                self.decoded_refused.fetch_add(1, Ordering::Relaxed);
                if let Origin::Rebuilt(rebuilt) = origin {
                    self.let_go_rebuilt(rebuilt);
                }
                return false;
            }
        };
        // Kept: remembered now, in the same step as the receiver's pace was taken from, charged
        // to whoever delivered it. Judged again as it is remembered, and that verdict followed:
        // another copy may have been taken since it was first asked, or the clock moved on.
        let taken = shard.lock().map_or(Verdict::Full, |mut shard| {
            shard
                .batches
                .take_batch(&hash, signed_ms, crate::strikes::Now::from(stamp), who)
        });
        match taken {
            Verdict::New => {}
            Verdict::Duplicate => {
                self.share(&origin, &Record::Batch(batch), Now::from(stamp));
                return false;
            }
            // Usable when it was judged, and late only because its table moved on before it was
            // kept: counted late, never blamed on its receiver (`strikes::blame`).
            Verdict::Late => {
                self.late(&origin, &Record::Batch(batch), Now::from(stamp));
                return false;
            }
            Verdict::Unjudged => {
                self.unjudged(&origin, &Record::Batch(batch), Now::from(stamp));
                return false;
            }
            Verdict::Ahead => {
                self.ahead_records.fetch_add(1, Ordering::Relaxed);
                self.unjudged(&origin, &Record::Batch(batch), Now::from(stamp));
                return false;
            }
            Verdict::Unanchored => {
                self.unanchored(&origin, &Record::Batch(batch), Now::from(stamp));
                return false;
            }
            Verdict::Full => {
                self.not_taken(&origin, &Record::Batch(batch), Now::from(stamp));
                return false;
            }
        }
        // The receptions of the products: an ACARS-family message is none of them.
        let observations = decoded.as_ref().map_or(0, |decoded| {
            decoded
                .observations()
                .iter()
                .filter(|observation| tally_wire::batch::format::in_products(observation.format))
                .count() as u64
        });
        if let Ok(mut stations) = self.stations.lock() {
            stations.forwarded(
                receiver,
                batch.boot_id(),
                batch.sequence(),
                observations,
                stamp.mono(),
            );
            if let Origin::Feeder(_, _, address) = &origin {
                stations.fed_by(&receiver, source, *address);
            }
        }
        // The receiver is publishing, so its description is the last to be forgotten: one lock,
        // the receivers', for the mark and the cell to route by.
        let mut described = self.publishing(&receiver);
        // A feeder's description pushed out while it was not yet publishing comes back now that
        // it is, as one that is, before the batch: a subscriber is told who a receiver is first.
        if described.is_none()
            && let Origin::Feeder(Some(own), ..) = &origin
        {
            // On the worker that owns the receiver, stamped with its batch: offered to the hosted
            // MLAT here, before the batch, as a description of a receiver is offered.
            // Its own site (wire version 3) is offered with it, to pair as it did before.
            if let Some(site) = own.site.clone().and_then(HeldSite::of)
                && let Ok(mut directory) = self.directory.lock()
            {
                directory.waiting_sites.insert(receiver, site);
            }
            if let Some(site) = self.keep_info(
                source,
                own.info.clone(),
                receiver,
                own.issued_ms,
                own.place,
                true,
            ) && let Some(mlat) = self.network.mlat()
                && let Some(record) = site_record(&own.info, site)
            {
                mlat.offer_description(&record, stamp.mono_ms());
            }
            described = self.publishing(&receiver);
        }
        let cells = described.unwrap_or_default();
        let cell = cells.point;
        if let Some(decoded) = &decoded {
            let area = self.network.products.area_for(&receiver);
            self.stages
                .message()
                .route(producer, decoded, area, stamp.raw());
        }
        self.network.on_batch(decoded.as_ref(), cells.public, stamp);
        let record = Record::Batch(batch);
        self.share(&origin, &record, Now::from(stamp));
        self.fanout.publish(Item {
            source,
            record: Arc::new(record),
            cell,
            points: None,
            decoded,
            stamp: stamp.mono(),
            client: None,
        });
        true
    }

    /// Whether a feeder's batch carrying `wanted` wanted receptions stays within its receiver's
    /// ceiling (`ingest::ReceptionCeilings`), by its stamp `stamp_ms`, on the worker that owns the
    /// receiver's shard, so the same stamped batches are kept alike on any threads. One past it is
    /// dropped, counted, and cut from its source's share of the rate (`unit`, at `cost`).
    fn within_ceiling(
        &self,
        shard: &Mutex<RawShard>,
        receiver: PublicKey,
        wanted: u64,
        stamp_ms: u64,
        unit: Option<shed::Unit>,
        cost: shed::Cost,
    ) -> bool {
        let wanted = usize::try_from(wanted).unwrap_or(usize::MAX);
        let within = shard
            .lock()
            .is_ok_and(|mut shard| shard.ceilings.take(receiver, wanted, stamp_ms));
        if !within {
            self.over_ceiling_batches.fetch_add(1, Ordering::Relaxed);
            self.over_ceiling_receptions
                .fetch_add(wanted as u64, Ordering::Relaxed);
            if let Some(unit) = unit {
                self.shedder.cut(unit, shed::Cause::ReceiverCeiling, cost);
            }
        }
        within
    }

    /// Whose share of the ingest rate a feeder's batch is charged to (`shed::Unit`): its
    /// receiver, if this relay corroborated it, else its connection's network group.
    fn shed_unit(&self, receiver: &PublicKey, group: Option<crate::ingest::Group>) -> shed::Unit {
        if self.shedder.is_bounded()
            && self
                .network
                .credit
                .corroborated_receiver(receiver, self.stamp_now())
        {
            shed::Unit::Corroborated(*receiver)
        } else {
            shed::Unit::Group(group)
        }
    }

    /// The network duties see where a batch came from: a feeder's own is seeded into its area's
    /// sharing group by this relay, its origin; a member's is a group piece.
    fn share(&self, origin: &Origin, record: &Record, now: Now) {
        match origin {
            Origin::Feeder(..) => self.network.originate(self, record, now),
            Origin::Peer(asker) => self.network.from_peer(self, asker, record, now),
            Origin::Rebuilt(rebuilt) => {
                self.network.rebuilt(self, *rebuilt, record, now);
            }
            Origin::Elsewhere => {}
        }
    }

    /// Connection `source`, its handshake proving it `receiver`'s feeder, was admitted from
    /// `address`: it is reported connected until it leaves (`left`), whether or not it sends a
    /// batch.
    pub fn opened(&self, receiver: &PublicKey, source: u64, address: Option<IpAddr>) {
        if let Ok(mut stations) = self.stations.lock() {
            stations.opened(*receiver, source, self.clock.mono(), address);
        }
    }

    /// Connection `source`, a feeder publishing as `receiver` from `address`, had a new batch
    /// forwarded.
    pub fn fed_by(&self, receiver: &PublicKey, source: u64, address: Option<IpAddr>) {
        if let Ok(mut stations) = self.stations.lock() {
            stations.fed_by(receiver, source, address);
        }
    }

    /// Connection `source` of a feeder publishing as `receiver` ended.
    pub fn left(&self, receiver: &PublicKey, source: u64) {
        if let Ok(mut stations) = self.stations.lock() {
            stations.left(receiver, source);
        }
    }

    /// Every receiver's report (`stations`), with what its newest description declares: its
    /// instants timed on the monotonic clock, which stamps every batch a report counts, and stated
    /// on the judging clock read with it (`Stations::report`), the Unix time the report serves.
    pub fn stations(&self) -> StationsReport {
        let now = self.clock.read();
        // Copied under the rows' lock, which every batch takes, and stated after it is let go.
        let rows = self.stations.lock().ok().map(|stations| stations.rows());
        let mut reports: Vec<(PublicKey, StationReport)> =
            rows.map(|rows| rows.reports(now)).unwrap_or_default();
        reports.sort_by_key(|(key, _)| *key);
        let stations = match self.directory.lock() {
            Ok(directory) => reports
                .into_iter()
                .map(|(key, report)| described(report, directory.known.get(&key)))
                .collect(),
            Err(_) => reports.into_iter().map(|(_, report)| report).collect(),
        };
        StationsReport {
            now_ms: now.judged().ms(),
            stations,
        }
    }

    /// One receiver's report, or `None` when the relay holds none for it.
    pub fn station(&self, receiver: &PublicKey) -> Option<StationReport> {
        let report = self
            .stations
            .lock()
            .ok()?
            .report(receiver, self.clock.read())?;
        let directory = self.directory.lock().ok()?;
        Some(described(report, directory.known.get(receiver)))
    }

    /// Where `receiver`'s newest signed description places it: the finest cell, projected once
    /// when the description was kept. `None` when the relay holds no located description of it.
    pub fn point_of(&self, receiver: &PublicKey) -> Option<Region> {
        let directory = self.directory.lock().ok()?;
        directory.known.get(receiver).and_then(|known| known.cell)
    }

    /// Every receiver's site-bearing record the relay holds (`site_record`: a format 2
    /// description's paired `ReceiverSite`, or a format 1 description, which carries its own): what
    /// a duty that starts late (the hosted MLAT, when its areas change) is handed instead of
    /// keeping a copy of its own.
    pub fn site_records(&self) -> Vec<SiteRecord> {
        let Ok(directory) = self.directory.lock() else {
            return Vec::new();
        };
        directory
            .known
            .values()
            .filter_map(|known| match &*known.record {
                Record::ReceiverInfo(info) => site_record(info, known.held_site()),
                _ => None,
            })
            .collect()
    }

    /// Whether member link `source` describes `receiver` (as issued at `issued_ms`, the newest
    /// this relay holds) before the batch of it it sends now, and the batch noted as sent. Yes
    /// when the link never told it, when it told an older description, and when its last batch
    /// of it on this link is older than the gap (`budget::RECEIVER_GAP`): the peer holds a
    /// receiver's description only while a batch of it came within the gap (its receiver figure,
    /// `Receivers`), so one this link last carried longer ago may be forgotten there, and its
    /// batches would reach the peer's whole-world subscribers alone, routed to no region, until
    /// its feeder's next description (ten minutes). Its batches since have kept it there, so
    /// within the gap it is not described again.
    pub fn to_describe(&self, source: u64, receiver: PublicKey, issued_ms: u64) -> bool {
        let now = self.clock.mono();
        let Ok(mut told) = self.told.lock() else {
            return true;
        };
        let key = (source, receiver);
        let held = told.get(&key).copied();
        let describe = held.is_none_or(|held| {
            held.issued_ms < issued_ms || now.passed(crate::budget::RECEIVER_GAP.after(held.batch))
        });
        let issued_ms = match held {
            Some(held) if !describe => held.issued_ms,
            _ => issued_ms,
        };
        told.insert_active(
            key,
            Told {
                issued_ms,
                batch: now,
            },
        );
        describe
    }

    /// What the relay holds of `receiver` for a relay to read before its batches: its newest
    /// description and the site paired with it, and the newest time either was issued. Relay-only:
    /// a link's type keeps the site off any link that does not carry sites (`outbound`).
    pub fn description_of(&self, receiver: &PublicKey) -> Option<(Vec<Arc<Record>>, u64)> {
        let directory = self.directory.lock().ok()?;
        directory.known.get(receiver).map(|known| {
            let mut records = vec![Arc::clone(&known.record)];
            let mut issued_ms = known.issued_ms;
            if let Some(site) = &known.site {
                records.push(Arc::clone(&site.record));
                issued_ms = issued_ms.max(site.issued_ms);
            }
            (records, issued_ms)
        })
    }

    /// `receiver`'s public cell, as its newest description says: the finest place anything this
    /// relay publishes or a client reads places it (the station reports, `stats`).
    pub fn public_cell_of(&self, receiver: &PublicKey) -> Option<Region> {
        let directory = self.directory.lock().ok()?;
        directory.known.get(receiver).and_then(|known| known.public)
    }

    /// Whether the relay holds a description of `receiver`.
    pub fn describes(&self, receiver: &PublicKey) -> bool {
        self.receivers
            .lock()
            .is_ok_and(|receivers| receivers.held.get(receiver).is_some())
    }

    /// `receiver` is publishing: marked so in the receivers, and its cell, `None` when it is not
    /// described.
    fn publishing(&self, receiver: &PublicKey) -> Option<Cells> {
        let mut receivers = self.receivers.lock().ok()?;
        receivers.held.touch(receiver);
        receivers.held.get(receiver).copied()
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

    /// Takes a verified `ReceiverSite` (`keep_site`), charged from `Store::Ingest`: the relay's
    /// own, a test's. Whether it was paired.
    pub fn publish_site(&self, source: u64, site: ReceiverSite) -> bool {
        let Ok(receiver) = site.receiver() else {
            return false;
        };
        let in_flight = self.in_flight_of(site.as_bytes().len());
        self.keep_site(source, site, receiver, None, in_flight)
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
        let Some(site) = self.keep_info(source, info, receiver, issued_ms, place, publishing)
        else {
            return;
        };
        self.offer_to_mlat(receiver, offered, site, stamp, in_flight);
    }

    /// Offers the hosted MLAT a receiver as now described: its description and the site paired
    /// with it (a format 1 description carries its own), on the ingest worker that owns its raw
    /// shard, stamped there as its batches are.
    fn offer_to_mlat(
        &self,
        receiver: PublicKey,
        offered: ReceiverInfo,
        site: Option<ReceiverSite>,
        stamp: Option<Stamp>,
        in_flight: InFlight,
    ) {
        let Some(mlat) = self.network.mlat().cloned() else {
            return;
        };
        let worker = self.stages.worker_of(raw_shard(&receiver));
        // Refused only past the workers' bound, counted there (`Stages::refused`).
        let _handed = self.stages.run_stamped(
            worker,
            in_flight,
            stamp,
            Box::new(move |stamp, in_flight| {
                if let Some(record) = site_record(&offered, site) {
                    mlat.offer_description(&record, stamp.mono_ms());
                }
                drop(in_flight);
            }),
        );
    }

    /// Keeps a verified receiver description if it is the newest for its key, and forwards it
    /// (then the site it pairs with, if it adopted one). Whether it was kept.
    ///
    /// The site in force with it is a format 1 description's own (`place`, as the caller read
    /// it), or for a format 2 one the newest `ReceiverSite` held or waiting for it, when the pair
    /// holds (`PublicInfoContent::holds`: the site's public cell is the description's). A pair
    /// that does not hold is never kept: the older of the two is let go, and a description older
    /// than a site it contradicts is refused (its feeder reissues both together, so the newer
    /// description follows).
    fn keep_info(
        &self,
        source: u64,
        info: ReceiverInfo,
        receiver: PublicKey,
        issued_ms: u64,
        place: Option<Location>,
        publishing: bool,
    ) -> Option<Option<ReceiverSite>> {
        let Ok(mut directory) = self.directory.lock() else {
            return None;
        };
        let newer = directory
            .known
            .get(&receiver)
            .is_none_or(|known| issued_ms > known.issued_ms);
        if !newer {
            return None;
        }
        let public = info.public_cell().ok().flatten();
        let (site, place) = if info.carries_site() {
            (None, place)
        } else {
            let held = directory
                .known
                .get(&receiver)
                .and_then(|known| known.site.clone());
            let waiting = directory.waiting_sites.get(&receiver).cloned();
            let candidate = [held, waiting]
                .into_iter()
                .flatten()
                .max_by_key(|site| site.issued_ms);
            let holds = |site: &HeldSite| {
                info.public()
                    .is_ok_and(|content| content.holds(&site.location))
            };
            match candidate {
                Some(site) if holds(&site) => {
                    let location = site.location;
                    (Some(site), Some(location))
                }
                Some(site) if site.issued_ms >= issued_ms => return None,
                _ => (None, None),
            }
        };
        if site.is_some() {
            directory.waiting_sites.remove(&receiver);
        }
        // Projected once, here; every region test after is integer work.
        let cell = place.and_then(|place| Region::point(&place).ok());
        let software = match info.description() {
            Ok(tally_wire::Description::Site(content)) => Some(content.software),
            Ok(tally_wire::Description::Public(content)) => Some(content.software),
            Err(_) => None,
        };
        let bytes = Known::bytes_of(&info, software.as_ref(), site.as_ref());
        let site_record = site.as_ref().map(|site| Arc::clone(&site.record));
        let paired = site.as_ref().and_then(|site| match &*site.record {
            Record::ReceiverSite(site) => Some(site.clone()),
            _ => None,
        });
        self.network.on_info(
            &info,
            self::site_record(&info, paired.clone()).as_ref(),
            place,
            self.judged_now(),
        );
        let record = Arc::new(Record::ReceiverInfo(info));
        // The receivers' lock, which every batch takes, only now: what was told above checks
        // signatures, and none of it is the receivers'. The directory's lock, held since the
        // start, keeps every other description of the receiver out meanwhile.
        let Ok(mut shard) = self.receivers.lock() else {
            return None;
        };
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
                site,
                cell,
                public,
                bytes,
                place,
                software,
            },
        );
        let cells = Cells {
            point: cell,
            public,
        };
        let forgotten = if publishing {
            shard.held.insert_active(receiver, cells)
        } else {
            shard.held.insert(receiver, cells)
        };
        // What the shard forgets, the directory forgets with it, and its bytes.
        let mut forget = |shard: &mut Receivers, forgotten: &PublicKey| {
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
        for record in std::iter::once(record).chain(site_record) {
            self.fanout.publish(Item {
                source,
                record,
                cell,
                points: None,
                decoded: None,
                stamp: self.clock.mono(),
                client: None,
            });
        }
        Some(paired)
    }

    /// Takes a verified `ReceiverSite` (wire version 3) of `receiver` from connection `source`:
    /// paired with its held format 2 description when the pair holds and it is the newest, and
    /// forwarded (relay-only: no client link can carry it, `outbound`); held waiting when no
    /// description it may pair with is held yet; refused when it contradicts a description at
    /// least as new. Kept, it is offered to the hosted MLAT as its receiver's site, through the
    /// ingest stage as a description is (`describe`): stamped `stamp` when a trace gives one, else by
    /// the ingest clock, so the step it takes effect at is the trace's. Whether it was paired.
    pub fn keep_site(
        &self,
        source: u64,
        site: ReceiverSite,
        receiver: PublicKey,
        stamp: Option<Stamp>,
        in_flight: InFlight,
    ) -> bool {
        let Some(held) = HeldSite::of(site) else {
            return false;
        };
        let Ok(mut directory) = self.directory.lock() else {
            return false;
        };
        let wait = |directory: &mut Directory, held: HeldSite| {
            let newer = directory
                .waiting_sites
                .get(&receiver)
                .is_none_or(|waiting| waiting.issued_ms < held.issued_ms);
            if newer {
                directory.waiting_sites.insert(receiver, held);
            }
            false
        };
        let Some(known) = directory.known.get(&receiver) else {
            return wait(&mut directory, held);
        };
        let info = match &*known.record {
            Record::ReceiverInfo(info) if !info.carries_site() => info.clone(),
            // A format 1 description carries its own site: one of the new form waits for the
            // format 2 description its feeder sends with it.
            _ => return wait(&mut directory, held),
        };
        if known
            .site
            .as_ref()
            .is_some_and(|site| site.issued_ms >= held.issued_ms)
        {
            return false;
        }
        let holds = info
            .public()
            .is_ok_and(|content| content.holds(&held.location));
        if !holds {
            // A site newer than the description it contradicts waits for the description its
            // feeder reissued with it; one no newer is refused.
            return if held.issued_ms > known.issued_ms {
                wait(&mut directory, held)
            } else {
                false
            };
        }
        let Some(mut known) = directory.take(&receiver) else {
            return false;
        };
        let Ok(mut shard) = self.receivers.lock() else {
            directory.insert(receiver, known);
            return false;
        };
        let before = known.bytes;
        known.bytes = Known::bytes_of(&info, known.software.as_ref(), Some(&held));
        known.place = Some(held.location);
        known.cell = Region::point(&held.location).ok();
        let record = Arc::clone(&held.record);
        let (cell, public, place) = (known.cell, known.public, known.place);
        known.site = Some(held);
        shard.bytes = shard.bytes.saturating_sub(before) + known.bytes;
        if let Some(entry) = shard.held.get_mut(&receiver) {
            *entry = Cells {
                point: cell,
                public,
            };
        }
        directory.insert(receiver, known);
        directory.waiting_sites.remove(&receiver);
        drop(shard);
        drop(directory);
        self.network.on_info(
            &info,
            SiteRecord::of(&record).as_ref(),
            place,
            self.judged_now(),
        );
        if let Record::ReceiverSite(site) = &*record {
            self.offer_to_mlat(receiver, info, Some(site.clone()), stamp, in_flight);
        }
        self.fanout.publish(Item {
            source,
            record,
            cell,
            points: None,
            decoded: None,
            stamp: self.clock.mono(),
            client: None,
        });
        true
    }

    /// Forwards verified positions by `engine` if they are new (`strikes`), as this relay's own.
    /// True when they were.
    pub fn publish_positions(&self, source: u64, positions: Positions) -> bool {
        self.take_positions(
            source,
            positions,
            Deliverer::Relay,
            None::<Intake<fn(&Record), fn()>>,
        )
    }

    /// As `publish_positions`, delivered by `who` and taken into its group by `intake` as where it
    /// came from says (`take_stream`).
    fn take_positions<S: FnOnce(&Record), L: FnOnce()>(
        &self,
        source: u64,
        positions: Positions,
        who: Deliverer,
        intake: Option<Intake<S, L>>,
    ) -> bool {
        let judged = (positions.hash(), positions.issued_ms().ok());
        let record = Record::Positions(positions);
        let new = self.take_stream(&self.positions, &record, judged, who, intake);
        if new && let Record::Positions(positions) = &record {
            self.network
                .on_positions(positions, source, self.stamp_now());
            self.forward_positions(source, record);
        }
        new
    }

    /// Whether `record`, under `id` and signed at `signed_ms` (none: its time could not be read),
    /// is new in `table`, taken in if so and charged to `who` (`strikes`), judged by the relay's
    /// clock (`Hub::now_ms`). A copy of one taken in is a duplicate. One outside the window of time
    /// is counted late (`late_records`) and, like a new record or a duplicate, taken into its group
    /// by the `intake`'s `share` as where it came from says (`take_piece`): held, counted had and
    /// its deliverer credited, never forwarded or remembered (`late`). Only one let go for want of
    /// room is not given to its group: counted (`strikes_full`), its deliverer credited there all
    /// the same (`no_room`), and its `intake` told to let it go (a rebuilt one is let go from its
    /// group). The relay's own have no `intake`.
    fn take_stream<S: FnOnce(&Record), L: FnOnce()>(
        &self,
        table: &Mutex<Strikes>,
        record: &Record,
        (id, signed_ms): (Hash, Option<u64>),
        who: Deliverer,
        intake: Option<Intake<S, L>>,
    ) -> bool {
        let now = self.judged_now();
        let Some(signed_ms) = signed_ms else {
            self.unreadable_times.fetch_add(1, Ordering::Relaxed);
            if let Some(intake) = intake {
                (intake.let_go)();
            }
            return false;
        };
        let verdict = table.lock().map_or(Verdict::Full, |mut taken| {
            taken.take(&id, signed_ms, now, who)
        });
        // A copy this relay may not use is held all the same, as a duplicate is (`late`): only
        // one let go for want of room is not, its deliverer credited for it all the same
        // (`no_room`).
        match (self.counted(verdict), intake) {
            (Verdict::Full, Some(intake)) => {
                self.no_room(who, record, Now::from(self.stamp_now()));
                (intake.let_go)();
            }
            (
                Verdict::New
                | Verdict::Duplicate
                | Verdict::Late
                | Verdict::Unjudged
                | Verdict::Ahead
                | Verdict::Unanchored,
                Some(intake),
            ) => {
                (intake.share)(record);
            }
            (_, None) => {}
        }
        verdict == Verdict::New
    }

    /// Sends positions into the fan-out once every clock model they cite has gone out before them
    /// (one session carries a model before what cites it, but a record that reaches this relay
    /// rebuilt from parity, by a repair or over a link that died between them, may come first);
    /// held meanwhile, for `AWAITING_MS` at most, after which they go anyway (the relay forwards;
    /// it is the reader that cannot check them).
    ///
    /// A client's form (tagged) waits too while the relay cannot yet check it (`consistency`):
    /// its raw twin, its model or a site its model names not held.
    ///
    /// The models it cites are looked for in the table once, here, under the held positions' lock,
    /// so a model that goes out meanwhile is either found now or struck off after
    /// (`release_awaiting`): never looked for again, whatever is held.
    fn forward_positions(&self, source: u64, record: Record) {
        let cited = cited_models(&record);
        let mut evicted = None;
        let held = {
            let Ok(mut awaiting) = self.awaiting.lock() else {
                return;
            };
            // A model is cited by its pair model id, which no table of forwarded manifests
            // names: it has gone out once it is held here whole (`Network::holds_pair`).
            let missing: Vec<Hash> = cited
                .into_iter()
                .filter(|id| !self.network.holds_pair(id))
                .collect();
            if missing.is_empty() && self.checkable(source, &record) {
                Some(record)
            } else if let Some(charge) = self
                .budget
                .gauge(Store::Records)
                .try_charge(Awaiting::bytes_of(&record, &missing))
            {
                if awaiting.len() >= AWAITING_MAX {
                    evicted = awaiting.pop_front();
                }
                let mut missing = missing;
                missing.shrink_to_fit();
                awaiting.push_back(Awaiting {
                    source,
                    record,
                    missing,
                    since: Instant::now(),
                    _charge: charge,
                });
                None
            } else {
                // No room to wait: out now, as it would go once it waited its time.
                self.awaiting_unheld.fetch_add(1, Ordering::Relaxed);
                Some(record)
            }
        };
        if let Some(oldest) = evicted {
            self.send_positions(oldest.source, oldest.record);
        }
        if let Some(record) = held {
            self.send_positions(source, record);
        }
        self.release_awaiting(None);
    }

    /// Sends the held positions whose models have all gone out, or which waited too long:
    /// `forwarded`, a model that just went out, struck off every one that cites it first. Each
    /// held one is a few comparisons, never a look in the table.
    pub fn release_awaiting(&self, forwarded: Option<Hash>) {
        let mut forwarded = forwarded;
        loop {
            let ready: Vec<Awaiting> = {
                let Ok(mut awaiting) = self.awaiting.lock() else {
                    return;
                };
                if let Some(id) = forwarded.take() {
                    for one in awaiting.iter_mut() {
                        one.missing.retain(|missing| *missing != id);
                    }
                }
                let (ready, held): (VecDeque<Awaiting>, VecDeque<Awaiting>) =
                    awaiting.drain(..).partition(|one| {
                        one.since.elapsed() >= AWAITING_MS
                            || (one.missing.is_empty() && self.checkable(one.source, &one.record))
                    });
                *awaiting = held;
                ready.into_iter().collect()
            };
            // A raw record sent is held as its link's twin (`Consistency::raw`): a client's form
            // held beside it may be checkable now, so the rest are looked at again.
            let raw = ready.iter().any(
                |one| matches!(&one.record, Record::Positions(positions) if !positions.is_tagged()),
            );
            for one in ready {
                self.send_positions(one.source, one.record);
            }
            if !raw {
                return;
            }
        }
    }

    /// Whether the relay can check `record`, from session `source`, for a client now: a raw
    /// record needs no check.
    fn checkable(&self, source: u64, record: &Record) -> bool {
        match record {
            Record::Positions(positions) if positions.is_tagged() => {
                self.network.consistency.check(positions, source)
                    != crate::consistency::Verdict::Unknown
            }
            _ => true,
        }
    }

    /// Into the fan-out. A client's form is checked first (`consistency`): one that passes is
    /// what a client is sent; one that fails is sent to no one; one that could not be checked is
    /// passed on to relays, who check it for their own clients, and to no client. The only place
    /// a client's positions are made (`outbound::client_form` makes none).
    ///
    /// Standing takes raw positions here, as they go out: by now every model they cite that came
    /// went out before them and is held (`Network::admit_model`), or they waited their longest and
    /// go without it (`Standing::positions` counts them unmodelled).
    fn send_positions(&self, source: u64, record: Record) {
        let points = crate::network::points_of(&record);
        if let Record::Positions(positions) = &record
            && !positions.is_tagged()
        {
            self.network
                .standing
                .positions(positions, self.judged_now().judged());
            // Its link's one record for the tagged twin that follows it (`consistency`).
            self.network.consistency.raw(positions, source);
        }
        let client = match &record {
            Record::Positions(positions) if positions.is_tagged() => {
                match self.network.consistency.check(positions, source) {
                    crate::consistency::Verdict::Passes => ClientRecord::try_from(record.clone())
                        .ok()
                        .map(|client| Arc::new(ClientItem::new(Arc::new(client), points.as_ref()))),
                    crate::consistency::Verdict::Fails => {
                        self.network.consistency.refuse();
                        return;
                    }
                    crate::consistency::Verdict::Unknown => {
                        self.network.consistency.refuse();
                        None
                    }
                }
            }
            _ => None,
        };
        self.fanout.publish(Item {
            source,
            record: Arc::new(record),
            cell: None,
            points,
            decoded: None,
            stamp: self.clock.mono(),
            client,
        });
    }

    /// Forwards a verified clock model manifest if it is new: an id not taken, signed within the
    /// window (`strikes`). The parts held for it that it lists go out first, in index order, each
    /// from the connection it came from (`parts`). True when it was new.
    pub fn publish_clock_model(&self, source: u64, model: ClockModel) -> bool {
        self.take_clock_model(
            source,
            model,
            Deliverer::Relay,
            None::<Intake<fn(&Record), fn()>>,
        )
    }

    /// As `publish_clock_model`, delivered by `who` and taken into its group by `intake`
    /// (`take_stream`).
    fn take_clock_model<S: FnOnce(&Record), L: FnOnce()>(
        &self,
        source: u64,
        model: ClockModel,
        who: Deliverer,
        intake: Option<Intake<S, L>>,
    ) -> bool {
        let record_id = model.id();
        let judged = (record_id, model.issued_ms().ok());
        let record = Record::ClockModel(model);
        let new = self.take_stream(&self.clock_models, &record, judged, who, intake);
        if new && let Record::ClockModel(model) = record {
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
            // Its listed parts, checked by it now, held with it for the member links that carry
            // it (`Network::hold_part`), whichever path brought them.
            self.network.hold_model(&model);
            for (_, part) in &ready {
                self.network.hold_part(part);
            }
            // Whole here, its listed parts with it: held once in the relay's store of decoded
            // models (`models`), before anything citing it is released. One whose parts are still
            // to come is held when its last one goes out (`publish_clock_model_part`).
            let listed: Vec<ClockModelPart> = ready.iter().map(|(_, part)| part.clone()).collect();
            let _ = self
                .network
                .admit_model(&model, &listed, self.judged_now().judged());
            drop(listed);
            // What fixes cite it by, once it is whole here (its parts may still be to come).
            let pair = self.network.pair_of(&record_id).map(|(pair, _)| pair);
            for (from, part) in ready {
                self.fanout.publish(Item {
                    source: from,
                    record: Arc::new(Record::ClockModelPart(part)),
                    cell: None,
                    points: None,
                    decoded: None,
                    stamp: self.clock.mono(),
                    client: None,
                });
            }
            let record = Record::ClockModel(model);
            self.network
                .on_clock_model(&record, source, self.stamp_now());
            let points = match &record {
                Record::ClockModel(model) => self
                    .network
                    .model_point_of(model)
                    .map(|area| Arc::from([area].as_slice())),
                _ => None,
            };
            self.fanout.publish(Item {
                source,
                record: Arc::new(record),
                cell: None,
                points,
                decoded: None,
                stamp: self.clock.mono(),
                client: None,
            });
            // Positions held for this model go out after it.
            self.release_awaiting(pair);
        }
        new
    }

    /// Forwards a verified client clock model (a full model's summary for clients: no site, no
    /// offset) if it is new, placed by its full model's area and the areas whose band holds it
    /// (`Network::client_model_places`), the clients whose fixes may cite it. Its boot and
    /// sequence are its full
    /// model's, so it is told apart by its hash alone, judged by its signed `issued_ms`. True when
    /// it was new.
    pub fn publish_client_clock_model(&self, source: u64, model: ClientClockModel) -> bool {
        self.take_client_clock_model(
            source,
            model,
            Deliverer::Relay,
            None::<Intake<fn(&Record), fn()>>,
        )
    }

    /// As `publish_client_clock_model`, delivered by `who` and taken into its group by `intake`
    /// (`take_stream`).
    fn take_client_clock_model<S: FnOnce(&Record), L: FnOnce()>(
        &self,
        source: u64,
        model: ClientClockModel,
        who: Deliverer,
        intake: Option<Intake<S, L>>,
    ) -> bool {
        let judged = (
            model.hash(),
            model.content().ok().map(|content| content.issued_ms),
        );
        let record = Record::ClientClockModel(model);
        if !self.take_stream(&self.passed_on, &record, judged, who, intake) {
            return false;
        }
        let Record::ClientClockModel(model) = record else {
            return false;
        };
        let points = self
            .network
            .client_model_places(&model)
            .map(|places| Arc::from(places.as_slice()));
        self.fanout.publish(Item {
            source,
            record: Arc::new(Record::ClientClockModel(model)),
            cell: None,
            points,
            decoded: None,
            stamp: self.clock.mono(),
            client: None,
        });
        // Tagged positions citing its model may now go.
        self.release_awaiting(None);
        true
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
        // Checked by its manifest now: held with it, and the model held whole in the store of
        // decoded models once this was the last part it lacked (`Network::admit_held`), its pair
        // model id known (what fixes cite it by); what waits for it or to be checked against it
        // may go then.
        let id = part.model().ok();
        let was_whole = id.is_some_and(|id| self.network.is_whole(&id));
        self.network.hold_part(&part);
        self.fanout.publish(Item {
            source,
            record: Arc::new(Record::ClockModelPart(part)),
            cell: None,
            points: None,
            decoded: None,
            stamp: self.clock.mono(),
            client: None,
        });
        if let Some(id) = id
            && !was_whole
            && self.network.is_whole(&id)
        {
            if let Some(Record::ClockModel(manifest)) = self
                .network
                .model_records(&id)
                .and_then(|mut records| records.pop())
            {
                self.network.on_clock_model(
                    &Record::ClockModel(manifest),
                    source,
                    self.stamp_now(),
                );
            }
            let _ = self.network.admit_held(&id, self.judged_now().judged());
            if let Some((pair, _)) = self.network.pair_of(&id) {
                self.release_awaiting(Some(pair));
            }
        }
        true
    }

    /// Bytes of clock model parts held for their manifests.
    pub fn parts_held_bytes(&self) -> usize {
        self.parts.lock().map_or(0, |parts| parts.held_bytes())
    }

    /// Forwards a checked fault proof if its hash is new, as this relay's own. True when it was.
    pub fn publish_fault_proof(&self, source: u64, proof: FaultProof) -> bool {
        self.take_fault_proof(
            source,
            proof,
            Deliverer::Relay,
            None::<Intake<fn(&Record), fn()>>,
        )
    }

    /// As `publish_fault_proof`, delivered by `who` and taken into its group by `intake`
    /// (`take_stream`), judged by the time of the newer record it proves a fault in
    /// (`proof_time`).
    fn take_fault_proof<S: FnOnce(&Record), L: FnOnce()>(
        &self,
        source: u64,
        proof: FaultProof,
        who: Deliverer,
        intake: Option<Intake<S, L>>,
    ) -> bool {
        let judged = (proof.hash(), proof_time(&proof));
        let record = Record::FaultProof(proof);
        let new = self.take_stream(&self.fault_proofs, &record, judged, who, intake);
        if new {
            self.fanout.publish(Item {
                source,
                record: Arc::new(record),
                cell: None,
                points: None,
                decoded: None,
                stamp: self.clock.mono(),
                client: None,
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
    pub fn subscribe(&self, subscription: &ClientSubscription) -> Option<(Vec<Item>, Slot)> {
        let slot = Slot::take(&self.subscribers, self.max_subscribers)?;
        Some((self.client_infos(subscription), slot))
    }

    /// As `subscribe`, without a place among the subscribers: for an engine, which is another
    /// relay's MLAT taking its area's raw one hop (RFC-0174 §2.3), a duty of the network the
    /// subscriber cap was never meant to turn away. What it may take is bounded by its grant (the
    /// border band of the areas it solves), never by the cap.
    pub fn engine(&self, subscription: &Subscription) -> Vec<Item> {
        self.answer(subscription).items
    }

    /// One of the engines' places, which gives an engine its socket buffers
    /// (`sockets::Role::Engine`): as many as the member sessions planned, since an engine is a
    /// member relay's MLAT, so the kernel's buffers for them are planned
    /// (`budget::Plan::connection_sockets`). `None` past them: the engine is served at a feeder's.
    pub fn engine_place(&self) -> Option<Slot> {
        Slot::take(&self.engines, self.budget().members())
    }

    /// Every description, for a link to another relay, which does not count against the
    /// subscriber cap (it carries load as well as takes it). It joins the fan-out after sending
    /// them, as a subscriber does (see `subscribe`).
    pub fn peer(&self) -> Vec<Item> {
        self.directory
            .lock()
            .map(|directory| directory.all(true, self.clock.mono()))
            .unwrap_or_default()
    }

    /// A place in the fan-out from now on, with no descriptions: for the loopback BEAST output, and
    /// for a link once it has sent the descriptions it joined with.
    pub fn listen(&self, source: u64, filter: Filter) -> Listener {
        self.fanout.listen(source, filter)
    }

    /// The relay's judging clock now (`Hub::clock`, `J`): what every signed time is judged by and
    /// signed with, and the clock a relay states to its feeders (`RateLimit`'s `clock_ms`).
    pub fn now(&self) -> Judged {
        self.clock.judged()
    }

    /// Both clocks now, as a stamp (`ingest::Stamp`): what a record the hub takes outside the
    /// ingest stage is handed on with, its monotonic time for the pipeline and its judging time
    /// for what it is compared with.
    pub fn stamp_now(&self) -> Stamp {
        self.clock.stamp(0)
    }

    /// The relay's one clock (`clock::RelayClock`): the network's duties, its links and its
    /// directory read it. A step of it ends nothing: it is counted and restated to every feeder
    /// session (`clock_steps`).
    pub fn clock(&self) -> &RelayClock {
        &self.clock
    }

    /// What it keeps across a restart (`durable`), every table started from it: with a state
    /// directory, each kind's lease of signed time (one for every ingest shard's batches) and the
    /// checkpoints and logs of the tables of few records (fault proofs, feeder figures), all
    /// sealed under the directory's key (`durable::StateDir::seal`), and a graceful stop's dump
    /// read back once when it is trusted and every lease still holds what it was written beside;
    /// with none, every table at the fallback floor (`tally_wire::budget::FALLBACK_FLOOR`). Every table
    /// that starts from the clock judges nothing until it is synced (`Hub::begin_strikes`). Built
    /// before the hub is shared or staged.
    pub fn durable(mut self, durable: Durable) -> Result<Self, String> {
        let store = StrikeStores::of(&self.budget);
        let entries = self.budget.plan().strike_entries(&self.budget.admission());
        let shares = match &durable {
            Durable::Dir(dir) => Shares::keyed(&store, entries, dir.key()),
            Durable::Off | Durable::Fresh => Shares::new(&store, entries),
        };
        let start = |name: &str| Start::of(&durable, name);
        let table = |usable: Usable, start: &Start| {
            Strikes::starting(usable, &store, Arc::clone(&shares), start)
        };
        // A table of few records keeps its fingerprints themselves, with a state directory,
        // through the same sealed open as every other file; with none it starts at the fallback
        // floor as every other does.
        let few = |usable: Usable, name: &str| match &durable {
            Durable::Dir(dir) => Strikes::persisted(usable, &store, Arc::clone(&shares), dir, name),
            Durable::Off | Durable::Fresh => table(usable, &start(name)),
        };
        let relay_signed = Usable::relay_signed(self.deadlines);
        // The old tables let go first, so their charges are not held twice.
        for shard in &self.raw {
            if let Ok(mut shard) = shard.lock() {
                shard.batches = Strikes::new(Usable::BATCHES, &store, Arc::clone(&shares));
            }
        }
        let batches = start("batches");
        for shard in &self.raw {
            if let Ok(mut shard) = shard.lock() {
                shard.batches = table(Usable::BATCHES, &batches);
            }
        }
        self.positions = Mutex::new(table(relay_signed, &start("positions")));
        self.clock_models = Mutex::new(table(relay_signed, &start("clock_models")));
        self.passed_on = Mutex::new(table(relay_signed, &start("passed_on")));
        self.fault_proofs = Mutex::new(few(Usable::proofs(self.deadlines), "fault_proofs"));
        self.figures = Mutex::new(few(Usable::figures(self.window), "figures"));
        self.shares = shares;
        self.durable = durable;
        self.restore_dump();
        self.begin_strikes();
        Ok(self)
    }

    /// Every table begun once the judging clock is synced (`strikes::Strikes::begin`, RFC-0171
    /// §3.6): nothing is derived from the wall clock before. The fallback floor is taken from
    /// the clock then. A lease bound past what that clock allows (a run whose clock ran ahead
    /// unsynced left it) is still the floor, so nothing that run used is used again: said loudly,
    /// with how long until the clock passes it, and counted (`leases_ahead`,
    /// `lease_ahead_until_ms`). Called at the start and by every sweep; a no-op once every table
    /// has begun.
    pub fn begin_strikes(&self) {
        // Whether the clock judged and what it read, taken together.
        let now = self.judged_now();
        if !now.judges() || self.strikes_begun.load(Ordering::Acquire) {
            return;
        }
        let now_ms = now.judged();
        let begun = |name: &str, table: &mut Strikes| {
            if let Begun::LeaseAhead { held_ms, now_ms } = table.begin(now_ms) {
                self.leases_ahead.fetch_add(1, Ordering::Relaxed);
                self.lease_ahead_until_ms
                    .fetch_max(held_ms, Ordering::Relaxed);
                eprintln!(
                    "tally-relay: the {name} lease holds {held_ms} ms, {} ms past the synced \
                     clock, more than the {} ms any record may be signed ahead (a run whose \
                     clock ran ahead left it): {name} uses nothing new for {} s, until the clock \
                     passes it, so nothing that run used is used again",
                    held_ms.saturating_sub(now_ms),
                    tally_wire::budget::PEER_AHEAD
                        .span::<tally_wire::clocks::Judged>()
                        .ms(),
                    held_ms.saturating_sub(now_ms).div_ceil(1_000)
                );
            }
        };
        let _ = self.dumped(|name, table| begun(name, table));
        for (name, table) in [
            ("fault_proofs", &self.fault_proofs),
            ("figures", &self.figures),
        ] {
            if let Ok(mut table) = table.lock() {
                begun(name, &mut table);
            }
        }
        self.strikes_begun.store(true, Ordering::Release);
    }

    /// The tables a stop's dump holds, in its order, each with the lease it is kept by: every
    /// ingest shard's batches, then positions, clock models and what is passed on by hash.
    fn dumped<T>(&self, mut each: impl FnMut(&str, &mut Strikes) -> T) -> Vec<T> {
        let mut out = Vec::new();
        for shard in &self.raw {
            if let Ok(mut shard) = shard.lock() {
                out.push(each("batches", &mut shard.batches));
            }
        }
        for (name, table) in [
            ("positions", &self.positions),
            ("clock_models", &self.clock_models),
            ("passed_on", &self.passed_on),
        ] {
            if let Ok(mut table) = table.lock() {
                out.push(each(name, &mut table));
            }
        }
        out
    }

    /// The dump file a graceful stop writes (`Hub::stop`).
    const DUMP: &'static str = "strikes.dump";

    /// The leases a dump is written beside, in its order.
    const DUMP_LEASES: [&'static str; 4] = ["batches", "positions", "clock_models", "passed_on"];

    /// What a dump's header names as its layout: its tables, in order, the ingest shards' count,
    /// and each table's windows (`strikes::Strikes::layout`: how long it keeps a record, its
    /// bucket, its ring). A dump of another layout (another `SHARDS`, another set of tables,
    /// another window) is not read.
    fn dump_layout(&self) -> String {
        format!(
            "strikes dump: {} shards; {}",
            self.raw.len(),
            self.dumped(|name, table| table.layout(name)).join("; ")
        )
    }

    /// Each lease's bound and the run that wrote it, now, in the dump's order: what a dump is
    /// written beside, and what a start checks before it reads one back.
    fn lease_states(dir: &Arc<crate::durable::StateDir>) -> Vec<(u64, u64)> {
        Self::DUMP_LEASES
            .iter()
            .map(|name| {
                let (lease, _) = dir.lease(name);
                (lease.held_ms(), lease.run())
            })
            .collect()
    }

    /// A graceful stop's dump read back, once: when it is trusted (its seal, key, version and
    /// layout, `durable::StateDir::read_state`) and every lease still holds, as it was read at
    /// this start, the bound and run it was written beside (no process used anything since).
    /// It is consumed first (`durable::StateDir::consume`): one that cannot be is not read, so a
    /// dump is never resumed twice, and the leases' floors stand. The tables then hold again
    /// what was taken before the stop, so a deploy is not deaf for the fallback's window.
    fn restore_dump(&mut self) {
        let Durable::Dir(dir) = self.durable.clone() else {
            return;
        };
        let body = match dir.read_state(Self::DUMP, Kind::Dump, &self.dump_layout()) {
            Prior::Missing => return,
            Prior::Refused(why) => {
                self.dumps_refused.fetch_add(1, Ordering::Relaxed);
                eprintln!("tally-relay: a stop's dump refused, the leases' floors stand: {why}");
                let _ = dir.consume(Self::DUMP);
                return;
            }
            Prior::Valid(written) => written,
        };
        let (dumped_by, body) = body;
        let mut words = body.chunks_exact(8).map(|chunk| {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            u64::from_le_bytes(word)
        });
        let beside = Self::DUMP_LEASES.iter().all(|name| {
            let wanted = (words.next(), words.next());
            // A lease never written (no record of its kind used) is what the stop found too,
            // `(0, 0)`; one not trusted is never beside anything.
            match dir.lease(name).1 {
                Prior::Valid((held, run)) => wanted == (Some(held), Some(run)),
                Prior::Missing => wanted == (Some(0), Some(0)),
                Prior::Refused(_) => false,
            }
        });
        let consumed = dir.consume(Self::DUMP).is_ok();
        if !beside || !consumed {
            self.dumps_refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // What each lease proves on its own: the bound of one another run wrote. The dump's run
        // never moved it, so that run used nothing past it, and the lease's floor stands whatever
        // the dump says (no file lowers a floor a lease proves). A lease the dump's own run wrote
        // proves nothing the dump does not hold: that run held every record it used above the
        // dump's floor.
        let proven: std::collections::HashMap<&str, Option<u64>> = Self::DUMP_LEASES
            .iter()
            .map(|name| {
                let proven = match dir.lease(name).1 {
                    Prior::Valid((held, run)) if run != dumped_by && held > 0 => Some(held),
                    _ => None,
                };
                (*name, proven)
            })
            .collect();
        let mut rest = &body[Self::DUMP_LEASES.len() * 16..];
        let _ = self.dumped(|name, table| {
            if let Ok((read, _)) = table.resume(rest, proven.get(name).copied().flatten()) {
                rest = &rest[read..];
            } else {
                rest = &[];
            }
        });
        self.dumps_resumed.fetch_add(1, Ordering::Relaxed);
    }

    /// Stops the relay gracefully: every session is told goodbye (`Reason::Leaving`,
    /// `Hub::leaving`), and with a state directory every table's fingerprints and floor are
    /// written, sealed, beside the leases' bounds and runs (`strikes.dump`), for the next start to
    /// read back. Nothing is taken after the shares close, and no lease moves after the directory
    /// is quiesced, so the dump holds everything used.
    pub fn stop(&self) -> Result<(), String> {
        self.leaving.send_replace(true);
        self.shares.close();
        let Durable::Dir(dir) = &self.durable else {
            return Ok(());
        };
        dir.quiesce();
        let mut body = Vec::new();
        for (held, run) in Self::lease_states(dir) {
            body.extend_from_slice(&held.to_le_bytes());
            body.extend_from_slice(&run.to_le_bytes());
        }
        // A table that never began (its clock never synced) has no floor of its own to write, and
        // a dump without it would read back as no floor at all beside the leases another run
        // wrote: no dump then, and the next start keeps the leases' floors.
        if !self
            .dumped(|_, table| table.dump(&mut body))
            .into_iter()
            .all(|wrote| wrote)
        {
            eprintln!("tally-relay: no dump: a table never began (the clock never synced)");
            return Ok(());
        }
        dir.write_state(Self::DUMP, Kind::Dump, &self.dump_layout(), &body)
            .map_err(|error| format!("{}: {error}", Self::DUMP))
    }

    /// The connections open now on every listener (`listeners`), of every role.
    pub fn connections_open(&self) -> usize {
        self.listeners
            .report()
            .iter()
            .map(|listener| listener.open)
            .sum()
    }

    /// Resolves once the relay is stopping (`Hub::stop`): what every session's loop waits on
    /// beside its work, to say goodbye.
    pub async fn leaving(&self) {
        let mut leaving = self.leaving.subscribe();
        let _ = leaving.wait_for(|leaving| *leaving).await;
    }

    /// The judging clock now as the strike tables are asked by it (`strikes::Now`): its reading
    /// and whether it judged, read together (`clock::RelayClock::stamp`), so nothing is judged by
    /// a clock that was not judging as it was read (RFC-0171 §3.6).
    pub(crate) fn judged_now(&self) -> crate::strikes::Now {
        crate::strikes::Now::from(self.clock.stamp(0))
    }

    /// Every table swept by the judging clock now (`strikes::Strikes::sweep`): what has passed
    /// is dropped and its deliverers' entries let go even where nothing is taken. The relay's
    /// tick calls it.
    pub fn sweep_strikes(&self) {
        self.begin_strikes();
        // A clock that is not judging forgets nothing by its reading (a floor raised by it could
        // never come down).
        let now = self.judged_now();
        if !now.judges() {
            return;
        }
        let now_ms = now.judged();
        let _ = self.dumped(|_, table| table.sweep(now_ms));
        for table in [&self.fault_proofs, &self.figures] {
            if let Ok(mut table) = table.lock() {
                table.sweep(now_ms);
            }
        }
        // Every table swept: what they all dropped leaves the shares, and nothing a table still
        // holds does (`Shares::expire`).
        self.shares.expire(now_ms);
    }

    /// Whether a relay-signed record signed at `signed_ms` is above the floor of what is passed
    /// on by hash (`passed_on`): none at or below it is used.
    fn above_passed_on_floor(&self, signed_ms: u64) -> bool {
        self.passed_on
            .lock()
            .is_ok_and(|table| table.floor_ms().is_none_or(|floor| signed_ms > floor))
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
    /// whether or not batches flow. Called by the timed duties (`network::start`).
    pub fn idle(&self) {
        if self.stages.is_inline() {
            self.stages.advance(self.stages.now_ms());
        }
    }

    /// Every known receiver description a client's subscription covers, by their public cells,
    /// descriptions alone: what a client is sent when it joins or changes what it wants, so
    /// receivers it newly covers are described before anything placed by them. With them, this
    /// relay's latest feeder figures the subscription covers, so one joining reads them at once
    /// rather than at the next signing (`figures`). Each with its client item made here
    /// (`outbound::client_item`), and only what a client may be sent.
    pub fn client_infos(&self, subscription: &ClientSubscription) -> Vec<Item> {
        let mut items = self
            .directory
            .lock()
            .map(|directory| {
                directory
                    .client_answer(subscription, self.clock.mono())
                    .items
            })
            .unwrap_or_default();
        // Aged on the fan-out by the monotonic clock, as every item is (`Item::stamp`).
        let stamp = self.clock.mono();
        items.extend(self.network.figures.latest().iter().map(|figures| {
            let area = figures.content().ok().and_then(|content| content.area);
            Item {
                source: u64::MAX,
                record: Arc::new(Record::FeederFigures(figures.clone())),
                cell: area,
                points: None,
                decoded: None,
                stamp,
                client: None,
            }
        }));
        items
            .into_iter()
            .filter_map(|mut item| {
                item.client = crate::outbound::client_item(&item);
                let served = item
                    .client
                    .as_ref()
                    .is_some_and(|client| subscription.serves(client));
                served.then_some(item)
            })
            .collect()
    }

    /// What an engine's subscription covers of the directory, by its receivers' sites.
    fn answer(&self, subscription: &Subscription) -> Answer {
        self.directory
            .lock()
            .map(|directory| directory.answer(subscription, self.clock.mono()))
            .unwrap_or(Answer {
                items: Vec::new(),
                visited: 0,
            })
    }
}

/// Unix milliseconds now, as the station reports state times.
/// Each subscriber's queue bounds: `BEHIND_MS` of inbound, and the bytes it may keep alive
/// (`fanout::item_bytes`: the decodes and signed bytes `R_max` and the members' rate bring in
/// over `BEHIND_MS`, as charged; the queues share each, so one queue may hold all of it), at least
/// `MIN_QUEUE_BYTES`.
fn queue_bounds(budget: &Budget) -> Bounds {
    let charged = budget.max_bytes_per_sec().saturating_add(
        (budget.member_feeders() as u64)
            .saturating_mul(crate::budget::PLANNED_CHARGED_BYTES_PER_SEC as u64),
    );
    let behind = usize::try_from(charged.saturating_mul(BEHIND_MS) / 1_000).unwrap_or(usize::MAX);
    Bounds {
        max_bytes: behind.max(MIN_QUEUE_BYTES),
        max_age_ms: BEHIND_MS,
    }
}

/// The fan-out, its queues bounded each by `queue_bounds` and together by the budget's gauge.
/// The fan-out over `budget`'s share for subscriber queues, each queue holding `queue_bytes` when
/// named (`Hub::queue_bytes`), else the budget's share.
fn router(budget: &Budget, queue_bytes: Option<usize>) -> Router {
    let bounds = match queue_bytes {
        Some(max_bytes) => Bounds {
            max_bytes,
            max_age_ms: BEHIND_MS,
        },
        None => queue_bounds(budget),
    };
    Router::charged(bounds, budget.gauge(Store::Fanout))
}

/// A station's report with what its description, if held, declares. A receiver only connected,
/// no batch of it forwarded, is placed nowhere: a connection alone publishes no location.
fn described(mut report: StationReport, known: Option<&Known>) -> StationReport {
    if let Some(known) = known {
        // Its public cell, never its site: the stats endpoint is a client's (`stats`).
        if report.batches > 0 {
            report.cell = known.public.map(crate::stations::cell_name);
        }
        report.software = known.software.clone();
    }
    report
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_wire::batch::ReceiverInfoContent;
    use tally_wire::clocks::recorded::judged;
    use tally_wire::{BatchContent, Clock, Identity, Observation};

    /// A test's descriptions held: one shard of 50,000, the most a relay's figure held once.
    const RECEIVERS_REMEMBERED: usize = 50_000;
    /// A test's descriptions' bytes: an honest description many times over for each of them.
    const DESCRIPTION_BYTES_HELD: usize = 64 * 1024 * 1024;

    /// A bundle index a peer sent is passed on once, however often it comes back: three relays
    /// once passed one round a loop of their one-hop raw links for ever, thousands a second.
    #[test]
    fn a_bundle_index_that_comes_back_is_not_passed_on_again() -> Result<(), String> {
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
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
                second: now_ms() / 1000,
                children: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        for source in [7, 8, 7] {
            hub.publish_as(source, Deliverer::Relay, Record::BundleIndex(index.clone()));
        }
        let mut passed = 0;
        while out.try_recv().is_some() {
            passed += 1;
        }
        assert_eq!(passed, 1);
        Ok(())
    }

    /// The relay's own store of what is taken is never evicted: a bundle index of the relay's own
    /// signing past its room is refused there and counted (`strikes_full`), and goes out all the
    /// same, since only this relay holds it and no member could repair it. A peer's past its
    /// share is let go, counted, and not passed on. Before, an own index refused at Full was
    /// dropped unsent.
    #[test]
    fn an_own_bundle_index_past_its_room_is_counted_and_still_sent() -> Result<(), String> {
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        hub.shares.set(crate::strikes::Entries {
            feeder: 2,
            feeders: 2,
            peer: 2,
            peers: 2 + 2 * crate::strikes::PEER_PLACE_ENTRIES,
            relay: 2,
        });
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
        let signer = Identity::generate().map_err(|error| error.to_string())?;
        let index = |second: u64| -> Result<tally_wire::BundleIndex, String> {
            tally_wire::BundleIndex::sign(
                &signer,
                &tally_wire::BundleIndexContent {
                    parent,
                    product: tally_wire::Streams::RAW,
                    second,
                    children: Vec::new(),
                },
            )
            .map_err(|error| error.to_string())
        };
        let second = now_ms() / 1000;
        let own = (0..5)
            .map(|n| index(second - n))
            .collect::<Result<Vec<_>, _>>()?;
        for index in &own {
            hub.publish_own(Record::BundleIndex(index.clone()));
        }
        let mut sent = Vec::new();
        while let Some(item) = out.try_recv() {
            sent.push((*item.record).clone());
        }
        assert_eq!(
            sent,
            own.iter()
                .cloned()
                .map(Record::BundleIndex)
                .collect::<Vec<_>>(),
            "an own index refused for room was not sent"
        );
        assert_eq!(hub.memory_report().strikes_full, 3);
        // A peer's past its share is let go, counted, and never passed on.
        let peer = Identity::from_seed([73; 32]).public();
        let peers = (10..15)
            .map(|n| index(second - n))
            .collect::<Result<Vec<_>, _>>()?;
        for index in &peers {
            hub.publish_as(9, Deliverer::Peer(peer), Record::BundleIndex(index.clone()));
        }
        let mut passed = 0;
        while out.try_recv().is_some() {
            passed += 1;
        }
        assert_eq!(passed, 2);
        assert_eq!(hub.memory_report().strikes_full, 6);
        Ok(())
    }

    /// A batch of a format this build reads that does not decode is malformed (an ACARS message
    /// relabelled into format 2, which a relay that predates format 3 would put into its
    /// products), and is never forwarded raw. Signed and checked as a link takes it: straight from
    /// its feeder, the link is refused; from a peer (a relay that predates the format forwards it
    /// raw), it is dropped and counted and the link kept. One of a format this build does not read
    /// is a later build's: possessed and passed on in its group, never refused, but not used
    /// here, since this build cannot read the anchors that would prove it fresh (RFC-0171 §3.6,
    /// `unanchored_records`).
    #[test]
    fn a_malformed_batch_ends_its_feeders_link_and_a_peers_copy_is_dropped() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(4, crate::sharing::Deadlines::RELAY));
        let feeder = Identity::generate().map_err(|error| error.to_string())?;
        let relabelled = |sequence: u64, format: u8| -> Result<Batch, String> {
            let signed = crate::anchors::anchored(
                &feeder,
                &BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: now_ms(),
                    dropped: 0,
                    previous: [0; 32],
                    observations: vec![Observation {
                        format: tally_wire::batch::format::ACARS_JSON,
                        timestamp: 5,
                        signal: 0,
                        data: br#"{"kind":"acars","label":"H1","t":1}"#.to_vec(),
                    }],
                },
            )
            .map_err(|error| error.to_string())?;
            let bytes = signed.as_bytes();
            let mut unsigned = bytes[..bytes.len() - tally_wire::key::SIGNATURE_LEN].to_vec();
            unsigned[0] = format;
            // What the receiver signs: the batch domain, a zero, the bytes (`batch::domain`).
            let signature = feeder.sign(&[&b"tally batch\0"[..], &unsigned].concat());
            unsigned.extend_from_slice(&signature);
            Batch::from_bytes(unsigned).map_err(|error| error.to_string())
        };
        let ingest = |batch: Batch, origin: Origin| {
            let refusal = Arc::new(crate::ingest::Refusal::default());
            let kept = hub.ingest(Inbound {
                source: 1,
                batch,
                origin,
                verify: true,
                stamp: None,
                arrived: None,
                in_flight: InFlight::free(),
                refusal: Some(Arc::clone(&refusal)),
            });
            (kept, refusal.now())
        };
        let peer = Origin::Peer(crate::network::Asker {
            role: crate::network::AskerRole::Relay,
            key: Identity::generate()
                .map_err(|error| error.to_string())?
                .public(),
            source: 2,
            loopback: true,
            address: None,
        });
        let deflate = tally_wire::batch::BATCH_FORMAT_ANCHORED_DEFLATE;
        let (kept, refused) = ingest(relabelled(0, deflate)?, Origin::Feeder(None, None, None));
        assert!(!kept && refused.is_some(), "{refused:?}");
        let (kept, refused) = ingest(relabelled(1, deflate)?, peer.clone());
        assert!(!kept && refused.is_none(), "{refused:?}");
        assert_eq!(hub.memory_report().malformed_batches, 1);
        // Signed as it is, it is a batch; and one of a later format is held, not used.
        let (kept, refused) = ingest(relabelled(2, 9)?, peer);
        assert!(!kept && refused.is_none(), "{refused:?}");
        assert_eq!(hub.memory_report().unanchored_records, 1);
        Ok(())
    }

    /// What the ingest workers' queues hold and refuse is served on `GET /memory`
    /// (`MemoryReport::ingest_queued`, `ingest_refused`), read from the queues themselves. The one
    /// worker is held inside its first record while the queues fill to their bound
    /// (`ingest::Room::records`); the next is refused and counted, and the report says so. Before,
    /// the refusals were counted and read by no report.
    #[test]
    fn the_memory_report_counts_what_the_ingest_workers_hold_and_refuse() -> Result<(), String> {
        let threads = crate::ingest::Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        };
        let hub = stamped_hub(1, crate::sharing::Deadlines::RELAY)
            .memory(64 << 20, false)
            .staged(threads)?;
        let bound = crate::ingest::Room::of(hub.budget()).records();
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let (started, running) = std::sync::mpsc::channel::<()>();
        let held = Arc::clone(&gate);
        assert!(hub.stages.run_charged(
            0,
            InFlight::free(),
            Box::new(move |_, _| {
                let _ = started.send(());
                let (open, opened) = &*held;
                let mut open = open
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*open {
                    open = opened
                        .wait(open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            }),
        ));
        running
            .recv_timeout(Duration::from_secs(60))
            .map_err(|_| "the worker never took the first record".to_owned())?;
        let handed: usize = (0..=bound)
            .map(|_| {
                usize::from(
                    hub.stages
                        .run_charged(0, InFlight::free(), Box::new(|_, _| {})),
                )
            })
            .sum();
        assert_eq!(handed, bound);
        let report = hub.memory_report();
        assert_eq!((report.ingest_queued, report.ingest_refused), (bound, 1));
        let (open, opened) = &*gate;
        *open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        opened.notify_all();
        hub.stages.flush();
        let report = hub.memory_report();
        assert_eq!((report.ingest_queued, report.ingest_refused), (0, 1));
        Ok(())
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

    /// 2026-10-04T00:00:00Z.
    pub(super) const BASE_MS: u64 = 1_791_244_800_000;

    /// A hub judged by the stamps a test hands in alone: a batch's window of time is judged at its
    /// stamp, as the stamps these tests give are times of their own choosing.
    fn stamped_hub(max_subscribers: usize, deadlines: crate::sharing::Deadlines) -> Hub {
        Hub::new(max_subscribers, deadlines)
    }

    /// The relay's clock now, as a relay started now reads it: what a test signs its records by.
    fn now_ms() -> u64 {
        RelayClock::system().judged().ms()
    }

    /// A batch of `identity`'s, signed at `BASE_MS`: what a test feeding stamps near it takes.
    fn signed_batch(
        identity: &Identity,
        sequence: u64,
        observations: Vec<Observation>,
    ) -> Result<Batch, String> {
        signed_batch_at(identity, sequence, observations, BASE_MS)
    }

    /// A batch of `identity`'s signed at `wall_ms` by its feeder's clock, anchored then.
    fn signed_batch_at(
        identity: &Identity,
        sequence: u64,
        observations: Vec<Observation>,
        wall_ms: u64,
    ) -> Result<Batch, String> {
        signed_batch_anchored(identity, sequence, observations, wall_ms, wall_ms)
    }

    /// A batch of `identity`'s signed at `wall_ms` by its feeder's clock, anchored by the test
    /// relay's clock reading `anchor_ms` (`anchors::test_relay`).
    fn signed_batch_anchored(
        identity: &Identity,
        sequence: u64,
        observations: Vec<Observation>,
        wall_ms: u64,
        anchor_ms: u64,
    ) -> Result<Batch, String> {
        crate::anchors::anchored_at(
            identity,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms,
                dropped: 0,
                previous: [0; 32],
                observations,
            },
            tally_wire::batch::Codec::Plain,
            anchor_ms,
        )
        .map_err(|error| error.to_string())
    }

    /// A batch the sharing groups rebuilt from parity is taken in as a member's is, through the
    /// ingest stage (`take_rebuilt`): its station counts it, and it is remembered as kept, so the
    /// copy a member sends after is not published again. Before, a rebuilt batch went straight
    /// into the fan-out as the relay's own: its station never counted it (a relay routing around a
    /// full member reported one batch fewer than it had), nothing decoded it for the hosted MLAT,
    /// and the copy that came after was new to the batch path and reached every subscriber twice.
    #[test]
    fn a_batch_rebuilt_from_parity_is_admitted_as_a_members_is() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let out = hub.listen(u64::MAX, Filter::Everything);
        let (receiver, receiver_key) = key()?;
        let batch = signed_batch_at(&receiver, 0, Vec::new(), now_ms())?;
        // A handle to no group this relay holds: the admission alone is under test here (the
        // group's side is `sharing::tests::a_rebuilt_records_verdict_reaches_the_group_that_rebuilt_it`).
        let rebuilt = Rebuilt::of(
            crate::sharing::groups::GroupKey::new(
                tally_wire::Region::containing(
                    &tally_wire::Location {
                        lat_e7: 0,
                        lon_e7: 0,
                        alt_m: 0,
                        precision_m: 0,
                    },
                    3,
                )
                .map_err(|error| error.to_string())?,
                tally_wire::Streams::RAW,
            ),
            batch.hash(),
        );
        hub.take_rebuilt(rebuilt, Record::Batch(batch.clone()));
        // The member's own copy, arriving after the rebuild.
        hub.publish_batch(7, batch, receiver_key);
        let mut published = 0;
        while let Some(item) = out.try_recv() {
            if matches!(&*item.record, Record::Batch(_)) {
                published += 1;
            }
        }
        assert_eq!(
            published, 1,
            "the batch reached the fan-out {published} times"
        );
        assert_eq!(
            hub.station(&receiver_key).map(|station| station.batches),
            Some(1)
        );
        Ok(())
    }

    fn key() -> Result<(Identity, PublicKey), String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let public = identity.public();
        Ok((identity, public))
    }

    #[test]
    fn a_flood_of_descriptions_never_forgets_a_receiver_that_is_publishing() -> Result<(), String> {
        const CAP: usize = 200;
        let mut hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        hub.described_as(CAP, DESCRIPTION_BYTES_HELD);
        let hub = Arc::new(hub);
        let (honest, honest_key) = key()?;
        hub.publish_info(1, signed_info(&honest)?, honest_key, 1, None, false);
        hub.publish_batch(
            1,
            signed_batch_at(&honest, 0, Vec::new(), now_ms())?,
            honest_key,
        );
        // Keys that only ever describe themselves, eleven times the map's size, the honest
        // receiver publishing once per half a map's worth of them.
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        for n in 0..11 * CAP {
            let (_, throwaway) = key()?;
            hub.publish_info(2, info.clone(), throwaway, 1, None, false);
            if n % (CAP / 2) == 0 {
                let sequence = u64::try_from(n / (CAP / 2) + 1).map_err(|e| e.to_string())?;
                let batch = signed_batch_at(&honest, sequence, Vec::new(), now_ms())?;
                hub.publish_batch(1, batch, honest_key);
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

    /// The relay at a receiver figure of `receivers` (its station rows and descriptions held to
    /// it, as a budget sizes them, `Hub::size_receivers`) with exactly that many honest receivers,
    /// each described and publishing a batch a round, every one of the 256 raw shards in use:
    /// none is ever forgotten. Receivers land in raw shards by a keyed hash, so a shard's are a
    /// random draw; before, each shard held an even share of the figure (64 receivers, one row a
    /// shard), every shard drawn above its share forgot a receiver on each of its batches, and its
    /// row (its judged batches with it), its description and its regional routing went with it.
    #[test]
    fn no_receiver_publishing_within_the_figure_is_forgotten_whatever_its_raw_shard()
    -> Result<(), String> {
        for figure in [64, 1_024] {
            let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
            hub.size_receivers(figure);
            let honest = (0..figure)
                .map(|_| key())
                .collect::<Result<Vec<_>, String>>()?;
            // Drawn into many raw shards, some holding more than an even share of the figure.
            let mut shards = HashMap::<u16, usize>::new();
            for (_, receiver) in &honest {
                *shards.entry(raw_shard(receiver).0).or_default() += 1;
            }
            assert!(shards.values().any(|&held| held > figure.div_ceil(SHARDS)));
            const ROUNDS: u64 = 3;
            for round in 0..ROUNDS {
                for (identity, receiver) in &honest {
                    if round == 0 {
                        hub.publish_info(1, signed_info(identity)?, *receiver, 1, None, true);
                    }
                    let batch = signed_batch_at(identity, round, Vec::new(), now_ms())?;
                    assert!(hub.publish_batch(1, batch, *receiver), "{figure}: refused");
                }
            }
            for (_, receiver) in &honest {
                assert!(hub.describes(receiver), "{figure}: a description forgotten");
                let row = hub
                    .station(receiver)
                    .ok_or_else(|| format!("{figure}: a station row forgotten"))?;
                assert_eq!(row.batches, ROUNDS, "{figure}: a station row started again");
            }
            assert_eq!(held(&hub)?, (figure, figure));
        }
        Ok(())
    }

    /// How many receivers the batch path knows, and how many descriptions the directory holds.
    fn held(hub: &Hub) -> Result<(usize, usize), String> {
        let receivers = hub.receivers.lock().map_err(|e| e.to_string())?.held.len();
        let directory = hub.directory.lock().map_err(|e| e.to_string())?.known.len();
        Ok((receivers, directory))
    }

    #[test]
    fn when_full_the_receiver_least_recently_active_is_forgotten() -> Result<(), String> {
        let mut hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        hub.described_as(2, DESCRIPTION_BYTES_HELD);
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
            crate::sharing::Deadlines::RELAY,
        ));
        for n in 0..4u64 {
            let (receiver, receiver_key) = key()?;
            // Every receiver hears messages 0..5; each also one of its own.
            let mut heard: Vec<Observation> = (0..5).map(observation).collect();
            heard.push(observation(100 + n as u8));
            let batch = signed_batch_at(&receiver, 0, heard, 10_100)?;
            assert!(hub.publish_batch(1, batch, receiver_key));
        }
        // The relay's own stream, signed as the relay: the batches it made since the last call.
        let relay = Identity::from_seed([77; 32]);
        hub.network().adopt_identity(crate::signer::twin(&relay));
        let stream = || -> Result<Vec<Observation>, String> {
            let mut stream = Vec::new();
            for record in hub.network().products.tick() {
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
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY).max_connections_per_address(2);
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

    /// Rate shedding is at ingest and nowhere else (RFC-0181 §10): over `R_max`, honest feeders
    /// (a group each) keep every batch, fifty hostile keys behind one group hold one share and are
    /// cut, each cut counted against that group and its reason, a member's batches are all kept
    /// beside them, and nothing downstream (the workers' queue, the epochs) refuses a thing.
    #[test]
    fn over_the_rate_only_a_feeders_batches_are_cut_and_only_at_ingest() -> Result<(), String> {
        let rate = shed::Rates {
            receptions_per_s: 1_000,
            bytes_per_s: 100_000_000,
        };
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY).admitted_rate(rate));
        let honest: Vec<Identity> = (0..5u8).map(|n| Identity::from_seed([n + 1; 32])).collect();
        let hostile: Vec<Identity> = (0..50u8)
            .map(|n| Identity::from_seed([n + 100; 32]))
            .collect();
        let member = Identity::from_seed([250; 32]);
        let batch = |identity: &Identity, sequence: u64, receptions: usize| {
            signed_batch(
                identity,
                sequence,
                (0..receptions)
                    .map(|n| Observation {
                        format: b'2',
                        timestamp: n as u64,
                        signal: 0,
                        data: [
                            &sequence.to_be_bytes()[..],
                            &identity.public().as_bytes()[..4],
                            &[n as u8],
                        ]
                        .concat(),
                    })
                    .collect(),
            )
        };
        let asker = Asker {
            role: crate::network::AskerRole::Relay,
            key: member.public(),
            source: 77,
            loopback: true,
            address: None,
        };
        let mut offered_hostile = 0u64;
        let mut kept_hostile = 0u64;
        let mut seconds = 0u64;
        for tick in 0..60u64 {
            let stamp_ms = BASE_MS + tick * 100;
            seconds = tick / 10;
            for (n, identity) in honest.iter().enumerate() {
                let group = Some(crate::ingest::Group::V4(n as u16 + 1));
                let batch = batch(identity, tick, 10)?;
                let in_flight = hub.in_flight_for(&batch);
                let kept = hub.ingest(Inbound {
                    source: 1 + n as u64,
                    batch,
                    origin: Origin::Feeder(None, group, None),
                    verify: false,
                    stamp: Some(Stamp::recorded(
                        stamp_ms + n as u64,
                        tick,
                        stamp_ms + n as u64,
                        stamp_ms + n as u64,
                        true,
                    )),
                    arrived: None,
                    in_flight,
                    refusal: None,
                });
                assert!(kept, "an honest feeder's batch was cut at tick {tick}");
            }
            for (n, identity) in hostile.iter().enumerate() {
                let batch = batch(identity, tick, 100)?;
                let in_flight = hub.in_flight_for(&batch);
                offered_hostile += 100;
                let kept = hub.ingest(Inbound {
                    source: 100 + n as u64,
                    batch,
                    origin: Origin::Feeder(None, Some(crate::ingest::Group::V4(900)), None),
                    verify: false,
                    stamp: Some(Stamp::recorded(
                        stamp_ms + 10 + n as u64,
                        tick,
                        stamp_ms + 10 + n as u64,
                        stamp_ms + 10 + n as u64,
                        true,
                    )),
                    arrived: None,
                    in_flight,
                    refusal: None,
                });
                if kept {
                    kept_hostile += 100;
                }
            }
            // A member's batch is a feeder's another relay already kept: never cut here.
            let batch = batch(&member, tick, 10)?;
            let in_flight = hub.in_flight_for(&batch);
            assert!(
                hub.ingest(Inbound {
                    source: 77,
                    batch,
                    origin: Origin::Peer(asker),
                    verify: false,
                    stamp: Some(Stamp::recorded(
                        stamp_ms + 99,
                        tick,
                        stamp_ms + 99,
                        stamp_ms + 99,
                        true
                    )),
                    arrived: None,
                    in_flight,
                    refusal: None,
                }),
                "a member's batch was refused at tick {tick}"
            );
        }
        let report = hub.shed_report();
        let cut = report.over_share.receptions + report.relay_rate.receptions;
        assert_eq!(cut, offered_hostile - kept_hostile, "every cut is counted");
        assert!(cut > 0, "the flood was cut");
        // One share of the hostile group: what the honest leave of 1,000 a second, not fifty.
        assert!(kept_hostile <= (seconds + 1) * 1_000, "{kept_hostile} kept");
        assert!(
            report
                .sources
                .iter()
                .all(|cut| cut.source == "v4:3.132.0.0/16"),
            "only the hostile group was cut: {:?}",
            report.sources
        );
        assert_eq!(report.receiver_ceiling.batches, 0);
        let memory = hub.memory_report();
        assert_eq!(
            memory.ingest_refused, 0,
            "nothing was refused past the ingest rate"
        );
        assert_eq!(hub.network().products.report().epochs_refused, 0);
        Ok(())
    }

    /// A feeder's batches too old to use are held to its share of the ingest rate as fresh ones
    /// are, before they are seeded into its group: a flood of old batches fills its group no
    /// faster than a flood of new ones. Before, a batch too old skipped the shedder.
    #[test]
    fn a_flood_of_batches_too_old_to_use_is_cut_at_ingest_as_any_flood_is() -> Result<(), String> {
        let rate = shed::Rates {
            receptions_per_s: 1_000,
            bytes_per_s: 100_000_000,
        };
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY).admitted_rate(rate));
        let hostile: Vec<Identity> = (0..20u8)
            .map(|n| Identity::from_seed([n + 100; 32]))
            .collect();
        let mut offered = 0u64;
        for tick in 0..20u64 {
            // Signed at `BASE_MS`, judged 200 s later: past the 91 s a feeder's own copy is usable.
            let stamp_ms = BASE_MS + 200_000 + tick * 100;
            for (n, identity) in hostile.iter().enumerate() {
                let batch = signed_batch(
                    identity,
                    tick,
                    (0..100usize)
                        .map(|r| Observation {
                            format: b'2',
                            timestamp: r as u64,
                            signal: 0,
                            data: [
                                &tick.to_be_bytes()[..],
                                &identity.public().as_bytes()[..4],
                                &[r as u8],
                            ]
                            .concat(),
                        })
                        .collect(),
                )?;
                offered += 100;
                let in_flight = hub.in_flight_for(&batch);
                let kept = hub.ingest(Inbound {
                    source: 100 + n as u64,
                    batch,
                    origin: Origin::Feeder(None, Some(crate::ingest::Group::V4(900)), None),
                    verify: false,
                    stamp: Some(Stamp::recorded(
                        stamp_ms + n as u64,
                        tick,
                        stamp_ms + n as u64,
                        stamp_ms + n as u64,
                        true,
                    )),
                    arrived: None,
                    in_flight,
                    refusal: None,
                });
                assert!(!kept, "a batch too old to use was used");
            }
        }
        let report = hub.shed_report();
        let cut = report.over_share.receptions + report.relay_rate.receptions;
        assert!(cut > 0, "the flood of old batches was never cut");
        // The rate's two seconds of it and its burst held, of the forty thousand offered: never
        // the flood.
        let held = offered - cut;
        assert!(held <= offered / 5, "{held} held of {offered}");
        Ok(())
    }

    /// RFC-0181, "Memory is charged once, for its life" (model point 1): `R_max`'s bytes are the
    /// bytes a batch is charged (`ingest::charge_of`), and a feeder is judged by them. One feeder,
    /// well within its share of the receptions, sends batches inflated as far as the wire allows
    /// (`MAX_INFLATION`) of the longest receptions (UAT uplinks): on the wire it sends a tenth of
    /// `R_max`'s bytes, so judged by its wire bytes it was admitted whole, and its decodes passed
    /// the stores planned from `R_max`. Judged by what they are charged it is cut to `R_max`'s
    /// bytes, counted, and no store holding its decodes is overrun: none is refused room.
    #[test]
    fn an_inflated_feeder_is_shed_by_its_charged_bytes_and_overruns_no_store() -> Result<(), String>
    {
        let hub = Arc::new(
            stamped_hub(8, crate::sharing::Deadlines::RELAY)
                .cores(64)
                .memory_for_feeders(4, false),
        );
        let rate = hub
            .shed_report()
            .rate
            .ok_or("the hub sheds at the rate it plans")?;
        assert_eq!(rate.bytes_per_s, hub.budget().max_bytes_per_sec());
        let feeder = Identity::from_seed([61; 32]);
        // Ten uplinks a batch, each ten copies of 48 bytes of its own: DEFLATE carries them in
        // about an eighth of their bytes.
        let batch = |sequence: u64| -> Result<Batch, String> {
            let mut state = sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            let observations = (0..10u64)
                .map(|n| {
                    let block: Vec<u8> = (0..48)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            state as u8
                        })
                        .collect();
                    Observation {
                        format: b'U',
                        timestamp: n,
                        signal: 0,
                        data: block.repeat(10),
                    }
                })
                .collect();
            crate::anchors::anchored_with(
                &feeder,
                &BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: BASE_MS,
                    dropped: 0,
                    previous: [0; 32],
                    observations,
                },
                tally_wire::batch::Codec::Deflate,
            )
            .map_err(|error| error.to_string())
        };
        let probe = batch(0)?;
        let inflation = probe.inflated_len().map_err(|error| error.to_string())? as f64
            / probe.as_bytes().len() as f64;
        assert_eq!(
            probe.format(),
            tally_wire::batch::BATCH_FORMAT_ANCHORED_DEFLATE
        );
        assert!(
            inflation > 5.0 && inflation <= tally_wire::batch::MAX_INFLATION as f64,
            "inflated {inflation:.1} times"
        );
        const SECONDS: u64 = 6;
        const PER_SECOND: u64 = 50;
        let (mut wire, mut charged, mut receptions, mut admitted) = (0u64, 0u64, 0u64, 0u64);
        for tick in 0..SECONDS * PER_SECOND {
            let batch = batch(tick + 1)?;
            let cost = crate::ingest::charge_of(&batch) as u64;
            wire += batch.as_bytes().len() as u64;
            charged += cost;
            receptions += 10;
            let kept = feed(
                &hub,
                1,
                batch,
                Origin::Feeder(None, Some(crate::ingest::Group::V4(7)), None),
                BASE_MS + tick * 1_000 / PER_SECOND,
            );
            if kept {
                admitted += cost;
            }
        }
        // Within its share of the receptions, and a fraction of R_max's bytes on the wire: by
        // its wire bytes it was never cut. By what it is charged it is past R_max.
        assert!(
            receptions < SECONDS * rate.receptions_per_s / 4,
            "{receptions}"
        );
        assert!(wire < SECONDS * rate.bytes_per_s / 4, "{wire} on the wire");
        assert!(
            charged > 2 * SECONDS * rate.bytes_per_s,
            "{charged} charged"
        );
        // Cut to R_max's bytes (and its burst), counted.
        let report = hub.shed_report();
        assert!(report.over_share.batches + report.relay_rate.batches > 0);
        assert!(
            admitted <= (SECONDS + 2) * rate.bytes_per_s,
            "{admitted} admitted against {} a second",
            rate.bytes_per_s
        );
        // No store holding its decodes or its bytes was overrun.
        let decoded = hub.budget().gauge(Store::Decoded);
        assert_eq!(hub.memory_report().decoded_refused, 0);
        assert_eq!(decoded.refused(), 0);
        assert!(decoded.peak() <= decoded.limit());
        assert_eq!(hub.network().products.report().epochs_refused, 0);
        Ok(())
    }

    /// A batch of `n` distinct wanted receptions (short Mode S, downlink format 0).
    fn wanted_batch(identity: &Identity, sequence: u64, n: usize) -> Result<Batch, String> {
        signed_batch(
            identity,
            sequence,
            (0..n)
                .map(|n| Observation {
                    format: b'2',
                    timestamp: n as u64,
                    signal: 0,
                    data: vec![
                        0,
                        (sequence >> 8) as u8,
                        sequence as u8,
                        (n >> 8) as u8,
                        n as u8,
                        7,
                        7,
                    ],
                })
                .collect(),
        )
    }

    /// RFC-0174 §2.5 and RFC-0171 §3.6, the real repair path: this relay routes around a full
    /// member and is routed around by one it turned away; in the last moment its manifest is held
    /// it asks the one member that can answer, which answers with pieces of the full origin's
    /// second, a hundred batches behind their receiver's stream. The answer is taken in, counted
    /// for its station and had in its group, however far the stream has moved on: a copy is
    /// judged by its hash and its signed time (`strikes`), never by its place in a stream. A copy
    /// signed longer ago than the window (`strikes::Window`, `A`) is too late: counted apart and
    /// never taken in, but delivered into its group (had, its member credited), so its group's
    /// receipts never turn on this relay's clock. Before, a copy more than 64 sequences behind its
    /// stream was refused whenever it came, and counted had while this relay never took it.
    #[test]
    fn a_members_repair_is_taken_in_however_far_its_stream_has_moved_on() -> Result<(), String> {
        use crate::sharing::member::{Member, Message, Piece};
        let err = |error: tally_wire::WireError| error.to_string();
        let deadlines = crate::sharing::Deadlines::RELAY;
        let horizon = deadlines.horizon_seconds();
        let me = Identity::from_seed([31; 32]);
        let answering = Identity::from_seed([32; 32]);
        let full = Identity::from_seed([33; 32]);
        let refused = Identity::from_seed([34; 32]).public();
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let area = group.cell;
        let second = BASE_MS / 1000;
        let start = second * 1000;
        let hub = Arc::new(stamped_hub(8, deadlines).taking(vec![area]));
        hub.network().adopt_identity(crate::signer::twin(&me));
        let _ = hub.network().tick(&hub, start);
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        let members = [me.public(), answering.public(), full.public(), refused];
        hub.network().sharing.groups.admit(
            group,
            answering.public(),
            crate::sharing::MonoDeadline::NEVER,
            false,
        );
        hub.network()
            .sharing
            .member_for_test(|member| {
                let _ = member.set_members(group, &members, &[], start);
                member.set_full(std::collections::BTreeSet::from([full.public()]));
                member.turned_away(refused, std::time::Duration::from_secs(60), start);
            })
            .ok_or("no member")?;
        // The full origin's second: two of its receiver's batches, listed in its manifest.
        let early = signed_batch(&receiver, 0, Vec::new())?;
        let late = signed_batch(&receiver, 2, Vec::new())?;
        let pieces: Vec<(tally_wire::batch::Hash, Piece)> = [&early, &late]
            .into_iter()
            .map(|batch| {
                let piece = Piece::of(&Record::Batch(batch.clone())).ok_or("no piece")?;
                Ok((piece.hash().ok_or("no hash")?, piece))
            })
            .collect::<Result<_, String>>()?;
        let mut hashes: Vec<_> = pieces.iter().map(|(hash, _)| *hash).collect();
        hashes.sort();
        let manifest = tally_wire::PieceManifest::sign(
            &full,
            &tally_wire::PieceManifestContent {
                cell: group.cell,
                product: group.product,
                second,
                hashes,
            },
        )
        .map_err(err)?;
        // The member that can answer holds the second whole.
        let mut answerer = Member::new(
            crate::signer::synced(crate::signer::twin(&answering)),
            crate::budget::Gauge::unlimited(crate::budget::Store::Batches),
            deadlines,
        );
        let _ = answerer.set_members(group, &members, &[], start);
        let _ = answerer.receive(
            full.public(),
            Message::Manifest(manifest.clone()),
            start + 500,
        );
        for (hash, piece) in &pieces {
            let message = Message::Piece {
                group,
                hash: *hash,
                piece: piece.clone(),
            };
            let _ = answerer.receive(full.public(), message, start + 500);
        }
        // This relay has the manifest, then the rest of the stream, a hundred sequences on.
        let asker = Asker {
            role: crate::network::AskerRole::Relay,
            key: answering.public(),
            source: 77,
            loopback: true,
            address: None,
        };
        hub.network()
            .sharing
            .manifest(&asker, manifest, start + 500);
        for sequence in (1..=100).filter(|sequence| *sequence != 2) {
            let batch = signed_batch(&receiver, sequence, Vec::new())?;
            assert!(feed(&hub, 1, batch, Origin::Elsewhere, start + 600));
        }
        // The last moment its manifest is held: it asks for repair, of the one that can answer,
        // and the answer comes at once.
        let ask_ms = (second + horizon) * 1000 + 999;
        let answered_ms = ask_ms + 1;
        let _ = hub.network().sharing.tick_member_for_test(ask_ms);
        let asks: Vec<_> = hub
            .network()
            .sharing
            .take_outbox()
            .into_iter()
            .filter_map(|sent| match sent.record {
                Record::HaveSummary(have) => Some((sent.to, have)),
                _ => None,
            })
            .collect();
        let [(to, have)] = asks.as_slice() else {
            return Err(format!("{} repair asks", asks.len()));
        };
        assert_eq!(*to, answering.public(), "asked a member that cannot answer");
        let answer: Vec<Batch> = answerer
            .receive(me.public(), Message::Have(have.clone()), ask_ms)
            .into_iter()
            .filter(|sent| sent.to == me.public())
            .filter_map(|sent| match sent.message {
                Message::Piece { piece, .. } => match piece.record() {
                    Some(Record::Batch(batch)) => Some(batch),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let found = |sequence: u64| {
            answer
                .iter()
                .find(|batch| batch.sequence() == sequence)
                .cloned()
                .ok_or(format!("the answer lacks sequence {sequence}"))
        };
        let (repaired, too_late) = (found(0)?, found(2)?);
        let counted = |hub: &Hub| {
            hub.station(&receiver_key)
                .map_or(0, |station| station.batches)
        };
        let before = counted(&hub);
        assert!(
            feed(&hub, 77, repaired.clone(), Origin::Peer(asker), answered_ms),
            "a repaired copy a hundred batches behind its stream was refused"
        );
        assert_eq!(counted(&hub), before + 1, "its station did not count it");
        let had = |hash: tally_wire::batch::Hash| {
            hub.network()
                .sharing
                .member_for_test(|member| member.counts_had(group, &hash))
                .unwrap_or(false)
        };
        assert!(had(repaired.hash()), "the repaired copy is not had");
        // Its copy is a duplicate, not late, and not taken twice.
        assert!(!feed(&hub, 77, repaired, Origin::Peer(asker), answered_ms));
        assert_eq!(counted(&hub), before + 1);
        assert_eq!(hub.memory_report().late_records, 0);
        // A copy signed longer ago than the window is too late: never taken in (not forwarded,
        // not counted), but delivered into its group all the same, its member credited, so no
        // receipt turns on this relay's clock.
        let past_ms = BASE_MS
            + Window::PEER
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1;
        assert!(
            !feed(&hub, 77, too_late.clone(), Origin::Peer(asker), past_ms),
            "a copy past the window was kept"
        );
        assert_eq!(hub.memory_report().late_records, 1);
        assert_eq!(counted(&hub), before + 1);
        assert!(had(too_late.hash()), "a late copy is not had in its group");
        assert!(
            hub.network()
                .sharing
                .member_for_test(|member| member.delivered(group, &too_late.hash(), &asker.key))
                .unwrap_or(false),
            "the member that delivered a late copy is not credited"
        );
        Ok(())
    }

    /// A description of `receiver` placed in London, where it is, and the sharing group its batches
    /// go to (the raw product of its public cell's area).
    fn located(
        receiver: &Identity,
    ) -> Result<(ReceiverInfo, Location, crate::sharing::groups::GroupKey), String> {
        let place = Location {
            lat_e7: 515_000_000,
            lon_e7: -1_000_000,
            alt_m: 0,
            precision_m: 0,
        };
        let info = ReceiverInfo::sign(
            receiver,
            &ReceiverInfoContent {
                issued_ms: 1,
                location: Some(place),
                clock: Clock::Dump1090,
                software: "test".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        let public = info
            .public_cell()
            .map_err(|error| error.to_string())?
            .ok_or("no public cell")?;
        let area = tally_wire::rendezvous::area_of_public(public).ok_or("no area")?;
        let group = crate::sharing::groups::GroupKey::new(area, tally_wire::Streams::RAW);
        Ok((info, place, group))
    }

    /// A batch its group rebuilt from parity is taken in however far its stream has moved on,
    /// while the manifest it was rebuilt from is held: the group holds it only as awaiting this
    /// relay's judgment, which is not had. Before, the rebuilt copy, more than the reorder ring
    /// behind, was taken for one already had and dropped, and its station never counted it.
    #[test]
    fn a_rebuilt_batch_far_behind_its_stream_is_taken_in() -> Result<(), String> {
        let me = Identity::from_seed([41; 32]);
        let signer = Identity::from_seed([42; 32]);
        let parity_from = Identity::from_seed([43; 32]).public();
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let hub =
            Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY).taking(vec![group.cell]));
        hub.network().adopt_identity(crate::signer::twin(&me));
        let now = now_ms();
        let _ = hub.network().tick(&hub, now);
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        let record = Record::Batch(signed_batch_at(&receiver, 0, Vec::new(), now)?);
        let sharing = &hub.network().sharing;
        sharing.fill_for_rebuild(
            group,
            &[me.public(), signer.public(), parity_from],
            (&signer, parity_from),
            std::slice::from_ref(&record),
            now / 1000 - 2,
            now,
        )?;
        // Rebuilt, then the stream moves a hundred sequences on before it is judged.
        let (handle, rebuilt) = sharing
            .tick_member_for_test(now)
            .into_iter()
            .find(|(_, rebuilt)| *rebuilt == record)
            .ok_or("the batch was not rebuilt")?;
        for sequence in 1..=100 {
            let batch = signed_batch_at(&receiver, sequence, Vec::new(), now)?;
            assert!(feed(&hub, 1, batch, Origin::Elsewhere, hub.now().ms()));
        }
        let counted = |hub: &Hub| {
            hub.station(&receiver_key)
                .map_or(0, |station| station.batches)
        };
        let before = counted(&hub);
        hub.take_rebuilt(handle, rebuilt);
        assert_eq!(
            counted(&hub),
            before + 1,
            "the rebuilt batch was not taken in"
        );
        let report = hub.memory_report();
        assert_eq!((report.late_records, report.rebuilt_refused), (0, 0));
        Ok(())
    }

    /// A hub taking `group`'s area as `me`, `member` a member of `group`, in the groups book and
    /// in its member's trees.
    fn member_hub(
        me: &Identity,
        member: &Identity,
        group: crate::sharing::groups::GroupKey,
        start: u64,
    ) -> Result<Arc<Hub>, String> {
        let hub =
            Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY).taking(vec![group.cell]));
        hub.network().adopt_identity(crate::signer::twin(me));
        let _ = hub.network().tick(&hub, start);
        hub.network().sharing.groups.admit(
            group,
            member.public(),
            crate::sharing::MonoDeadline::NEVER,
            false,
        );
        hub.network()
            .sharing
            .member_for_test(|held| {
                let _ = held.set_members(group, &[me.public(), member.public()], &[], start);
            })
            .ok_or("no member")?;
        Ok(hub)
    }

    /// `key`, a relay, as a link names it.
    fn relay(key: PublicKey) -> Asker {
        Asker {
            role: crate::network::AskerRole::Relay,
            key,
            source: 77,
            loopback: true,
            address: None,
        }
    }

    /// `member` lists `batch` in a manifest of `now_ms`'s second, signed and given to `hub`'s
    /// group: a listing well within the window a member holds a manifest for.
    fn listed(
        hub: &Hub,
        member: &Identity,
        group: crate::sharing::groups::GroupKey,
        batch: &Batch,
        now: Judged,
    ) -> Result<(), String> {
        let now_ms = now.ms();
        let hash =
            crate::sharing::member::record_hash(&Record::Batch(batch.clone())).ok_or("no hash")?;
        let manifest = tally_wire::PieceManifest::sign(
            member,
            &tally_wire::PieceManifestContent {
                cell: group.cell,
                product: group.product,
                second: now_ms / 1000,
                hashes: vec![hash],
            },
        )
        .map_err(|error| error.to_string())?;
        hub.network()
            .sharing
            .manifest(&relay(member.public()), manifest, now_ms);
        Ok(())
    }

    /// Batches `from..=to` of `receiver`'s stream, taken from no relay at `stamp_ms`.
    fn stream(
        hub: &Arc<Hub>,
        receiver: &Identity,
        (from, to): (u64, u64),
        stamp_ms: u64,
    ) -> Result<(), String> {
        for sequence in from..=to {
            let batch = signed_batch(receiver, sequence, Vec::new())?;
            if !feed(hub, 1, batch, Origin::Elsewhere, stamp_ms) {
                return Err(format!("batch {sequence} of the stream was refused"));
            }
        }
        Ok(())
    }

    /// A batch this relay took in from no member (from no relay, before its receiver was even
    /// described, so no group could note it) is a duplicate when a member's copy comes later, a
    /// hundred batches behind its stream, with a manifest of its group listing it: this relay's
    /// own memory of what it took in decides (`strikes`), not the group's notes or a member's
    /// listing. Were a group's notes to decide, this copy, which reached no group, would be
    /// forwarded a second time.
    #[test]
    fn a_batch_kept_from_no_member_is_a_duplicate_when_a_member_copies_it() -> Result<(), String> {
        let me = Identity::from_seed([51; 32]);
        let member = Identity::from_seed([52; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let start = BASE_MS;
        let hub = member_hub(&me, &member, group, start)?;
        let kept = signed_batch(&receiver, 0, Vec::new())?;
        assert!(feed(&hub, 1, kept.clone(), Origin::Elsewhere, start));
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        stream(&hub, &receiver, (1, 100), start)?;
        let copied_at = start + 5_000;
        listed(&hub, &member, group, &kept, judged(copied_at))?;
        let before = hub
            .station(&receiver_key)
            .map_or(0, |station| station.batches);
        assert!(
            !feed(
                &hub,
                77,
                kept,
                Origin::Peer(relay(member.public())),
                copied_at
            ),
            "a member's copy of a batch kept from no member was forwarded again"
        );
        assert_eq!(
            hub.station(&receiver_key)
                .map_or(0, |station| station.batches),
            before
        );
        assert_eq!(
            hub.memory_report().late_records,
            0,
            "a duplicate counted late"
        );
        Ok(())
    }

    /// RFC-0174 §2.5: an honest duplicate (a member's copy of a batch this relay took from its
    /// feeder) is not forwarded, but it was delivered: its group counts it as had and notes the
    /// member as its deliverer, the evidence the member's receipt credits it by. A duplicate is
    /// never late and never let go.
    #[test]
    fn an_honest_duplicate_is_counted_had_and_its_deliverer_credited() -> Result<(), String> {
        let me = Identity::from_seed([61; 32]);
        let member = Identity::from_seed([62; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let start = BASE_MS;
        let hub = member_hub(&me, &member, group, start)?;
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        let batch = signed_batch(&receiver, 0, Vec::new())?;
        assert!(feed(
            &hub,
            1,
            batch.clone(),
            Origin::Feeder(None, None, None),
            start
        ));
        let copied_at = start + 1_000;
        listed(&hub, &member, group, &batch, judged(copied_at))?;
        assert!(
            !feed(
                &hub,
                77,
                batch.clone(),
                Origin::Peer(relay(member.public())),
                copied_at
            ),
            "an honest duplicate was forwarded again"
        );
        let (had, credited) = hub
            .network()
            .sharing
            .member_for_test(|held| {
                (
                    held.counts_had(group, &batch.hash()),
                    held.delivered(group, &batch.hash(), &member.public()),
                )
            })
            .ok_or("no member")?;
        assert!(had, "an honest duplicate is not counted had");
        assert!(credited, "an honest duplicate's deliverer is not credited");
        let report = hub.memory_report();
        assert_eq!((report.late_records, report.strikes_full), (0, 0));
        Ok(())
    }

    /// RFC-0171 §3.6: an archive replayed is too late whatever this relay remembers. A batch its
    /// receiver signed longer ago than the window (`strikes::Window`, `A`) comes again from a
    /// member that signed a manifest of the current second listing it: to the relay that took it
    /// in, to one restarted since (its memory empty), and to one whose memory a churn of a
    /// thousand other receivers' streams went through, it is too late: counted apart and never
    /// forwarded (delivered into its group as listed, which forwards nothing to the fan-out). Were
    /// a fresh listing, or a memory of streams that a churn can evict, to decide, a member could
    /// have any old batch forwarded again by listing it.
    #[test]
    fn an_archive_replayed_is_late_after_a_restart_and_after_a_churn_of_streams()
    -> Result<(), String> {
        let me = Identity::from_seed([53; 32]);
        let member = Identity::from_seed([54; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let start = BASE_MS;
        let replayed = signed_batch(&receiver, 0, Vec::new())?;
        let took = |hub: &Arc<Hub>| -> Result<(), String> {
            hub.publish_info(1, info.clone(), receiver_key, 1, Some(place), false);
            assert!(feed(hub, 1, replayed.clone(), Origin::Elsewhere, start));
            stream(hub, &receiver, (1, 100), start)
        };
        let later = start + crate::strikes::Usable::BATCHES.retained_ms() + 1_000;
        // The relay that took it in.
        let same = member_hub(&me, &member, group, start)?;
        took(&same)?;
        // A relay that took it in and restarted: its memory empty.
        let restarted = member_hub(&me, &member, group, later)?;
        restarted.publish_info(1, info.clone(), receiver_key, 1, Some(place), false);
        // A relay that took it in and then a thousand other receivers' streams.
        let churned = member_hub(&me, &member, group, start)?;
        took(&churned)?;
        for n in 0..1_000u64 {
            let other = Identity::from_seed(
                <[u8; 32]>::try_from([&n.to_be_bytes()[..], &[9; 24]].concat())
                    .map_err(|_| "no seed")?,
            );
            let batch = signed_batch_at(&other, 0, Vec::new(), later)?;
            assert!(feed(&churned, 1, batch, Origin::Elsewhere, later));
        }
        for hub in [&same, &restarted, &churned] {
            listed(hub, &member, group, &replayed, judged(later))?;
            assert!(
                !feed(
                    hub,
                    77,
                    replayed.clone(),
                    Origin::Peer(relay(member.public())),
                    later
                ),
                "an archive replayed was forwarded again"
            );
            assert_eq!(
                hub.memory_report().late_records,
                1,
                "the replay was not late"
            );
        }
        Ok(())
    }

    /// RFC-0174 §2.5: a copy this relay judges late is delivered all the same, so the receipt it
    /// signs its deliverer covers what the manifests list whatever its own clock made of it, and
    /// no shortfall is filed against a member that delivered everything. Two ways a listed copy
    /// is late here: its origin is an old relay (0.6.x) that checked no feeder's clock and seeded
    /// a batch its feeder signed an hour behind; or this relay's clock is two minutes behind its
    /// peers' (a test's scripted clock: a relay's own never goes back, `clock::RelayClock`). Before, a late copy was given
    /// to no group, its receipt came up short, and the member was reported for it.
    #[test]
    fn a_late_copy_is_delivered_and_its_deliverer_never_reported_short() -> Result<(), String> {
        let receipt = |signed_ms: u64, stamp_ms: u64| -> Result<(u32, bool), String> {
            let me = Identity::from_seed([61; 32]);
            let member = Identity::from_seed([62; 32]);
            let (receiver, receiver_key) = key()?;
            let (info, place, group) = located(&receiver)?;
            let hub = member_hub(&me, &member, group, BASE_MS)?;
            hub.publish_info(1, info, receiver_key, 1, Some(place), false);
            let batch = signed_batch_at(&receiver, 0, Vec::new(), signed_ms)?;
            listed(&hub, &member, group, &batch, judged(BASE_MS))?;
            let from = relay(member.public());
            assert!(!feed(&hub, 77, batch.clone(), Origin::Peer(from), stamp_ms));
            // Too old, or ahead of this relay's clock (`ahead_records`): unused either way.
            let report = hub.memory_report();
            assert_eq!(
                report.late_records + report.ahead_records,
                1,
                "the copy was used"
            );
            let credited = hub
                .network()
                .sharing
                .member_for_test(|held| held.delivered(group, &batch.hash(), &member.public()))
                .unwrap_or(false);
            let _ = hub.network().sharing.take_outbox();
            let window = BASE_MS / 1000 / crate::sharing::member::RECEIPT_WINDOW_SECONDS;
            let due = (window + 1) * crate::sharing::member::RECEIPT_WINDOW_SECONDS * 1000
                + crate::sharing::Deadlines::RELAY.receipt_grace.ms();
            // The window falls due when the judging clock first passes its end, and its receipts
            // a grace on by the monotonic one (`member::Due`).
            let _ = hub
                .network()
                .sharing
                .tick_member_for_test(due - crate::sharing::Deadlines::RELAY.receipt_grace.ms());
            let _ = hub.network().sharing.tick_member_for_test(due);
            let sent: Vec<_> = hub
                .network()
                .sharing
                .take_outbox()
                .into_iter()
                .filter_map(|sent| match sent.record {
                    Record::StripeReceipt(receipt) => Some((sent.to, receipt)),
                    _ => None,
                })
                .collect();
            // The receipt for the batch's own stripe.
            let stripe = crate::sharing::stripes::data_stripe(&batch.hash());
            let to_member: Vec<u32> = sent
                .iter()
                .filter(|(to, _)| *to == member.public())
                .filter_map(|(_, receipt)| receipt.content().ok())
                .filter(|content| content.stripe == stripe)
                .map(|content| content.records)
                .collect();
            let [records] = to_member.as_slice() else {
                return Err(format!("{} receipts to the member", to_member.len()));
            };
            Ok((*records, credited))
        };
        // An old origin's batch, its feeder's clock an hour behind.
        assert_eq!(
            receipt(BASE_MS - 3_600_000, BASE_MS)?,
            (1, true),
            "the member was reported for an old origin's late batch"
        );
        // This relay's ingest clock stepped two minutes back.
        assert_eq!(
            receipt(BASE_MS, BASE_MS - 120_000)?,
            (1, true),
            "the member was reported for a copy this relay's skewed clock judged late"
        );
        Ok(())
    }

    /// RFC-0171 §3.6 and RFC-0174 §2.5: a feeder's batch too old where it is published
    /// (`strikes::FeederClock::TooOld`: an old feeder, 0.5.2 or 0.6.x, that corrects no clock and
    /// signs 80 s behind) is never taken in there, but it is seeded into its group as a late copy
    /// and tagged, so a member it reached holds it and every relay asked about it answers that it
    /// saw it. The feeder audits the relay it sent it to by asking the others (its batch held back
    /// from them), and none answers "not seen". Before, the origin dropped it at intake, no member
    /// ever had it, and the honest relay was convicted as a swallower and avoided for days.
    #[test]
    fn a_batch_too_old_where_it_is_published_is_seen_by_its_group_and_convicts_no_relay()
    -> Result<(), String> {
        let (a, b) = (Identity::from_seed([66; 32]), Identity::from_seed([67; 32]));
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let hub_a = member_hub(&a, &b, group, BASE_MS)?;
        let hub_b = member_hub(&b, &a, group, BASE_MS)?;
        let fed = |hub: &Arc<Hub>, sequence: u64, signed_ms: u64, stamp_ms: u64| {
            let batch = signed_batch_at(&receiver, sequence, Vec::new(), signed_ms)?;
            let refusal = Arc::new(crate::ingest::Refusal::default());
            let in_flight = hub.in_flight_for(&batch);
            let kept = hub.ingest(Inbound {
                source: 1,
                batch: batch.clone(),
                origin: Origin::Feeder(None, None, None),
                verify: true,
                stamp: Some(Stamp::recorded(
                    stamp_ms, sequence, stamp_ms, stamp_ms, true,
                )),
                arrived: None,
                in_flight,
                refusal: Some(refusal),
            });
            Ok::<_, String>((kept, batch))
        };
        let grant = |member: &PublicKey, now_ms: u64| -> Result<tally_wire::TagKeys, String> {
            let key = |id: u32| {
                let mut key = [0; tally_wire::delivery::TAG_KEY_LEN];
                key[..32].copy_from_slice(member.as_bytes());
                key[..4].copy_from_slice(&id.to_be_bytes());
                tally_wire::TagKey { id, key }
            };
            let id = tally_wire::delivery::key_period(now_ms);
            tally_wire::TagKeys::sign(
                &receiver,
                &tally_wire::TagKeysContent {
                    member: *member,
                    current: key(id),
                    next: key(id + 1),
                    switch_in_ms: tally_wire::delivery::KEY_PERIOD_MS
                        - now_ms % tally_wire::delivery::KEY_PERIOD_MS,
                },
            )
            .map_err(|error| error.to_string())
        };
        let ask = |hub: &Arc<Hub>,
                   me: &Identity,
                   keys: Option<tally_wire::TagKeys>,
                   sequence: u64,
                   now_ms: u64| {
            let query = tally_wire::DeliveryQuery {
                nonce: [sequence as u8; 32],
                receiver: receiver_key,
                boot_id: 1,
                ranges: vec![tally_wire::SequenceRange {
                    first: sequence,
                    last: sequence,
                }],
                keys,
            };
            let network = hub.network();
            network
                .delivery
                .answer_at(
                    &network.selection,
                    Some(&me.signing()),
                    &query,
                    (hub.public_cell_of(&receiver_key), receiver_key, None),
                    now_ms,
                )
                .ok_or_else(|| "no answer".to_owned())?
                .content()
                .map_err(|error| error.to_string())
        };
        // The feeder publishes to both, in step, for longer than a relay watches a receiver
        // before it may say "not seen", and grants each its keys, as it does every minute.
        let later = BASE_MS + tally_wire::delivery::TAG_WINDOW_MS + 60_000;
        for (hub, me) in [(&hub_a, &a), (&hub_b, &b)] {
            hub.publish_info(1, info.clone(), receiver_key, 1, Some(place), false);
            assert!(fed(hub, 0, BASE_MS, BASE_MS)?.0);
            assert!(fed(hub, 1, later - 30_000, later - 30_000)?.0);
            let _ = ask(hub, me, Some(grant(&me.public(), later)?), 1, later)?;
            let _ = hub.network().sharing.take_outbox();
        }
        // Batch 2, signed past `FEEDER_BEHIND` behind, is sent to `a` alone: `b` is held back for
        // the audit.
        let behind = tally_wire::budget::FEEDER_BEHIND
            .span::<tally_wire::clocks::Judged>()
            .ms()
            + 6_000;
        let (kept, old) = fed(&hub_a, 2, later - behind, later)?;
        assert!(!kept, "a batch too old where it is published was taken in");
        assert_eq!(hub_a.memory_report().late_records, 1);
        let to_b: Vec<Record> = hub_a
            .network()
            .sharing
            .take_outbox()
            .into_iter()
            .filter(|sent| sent.to == b.public())
            .map(|sent| sent.record)
            .collect();
        // Sent down its stripe to the member as every copy is: possession never reads a clock.
        assert!(
            to_b.contains(&Record::Batch(old.clone())),
            "not sent down its stripe to the member: {to_b:?}"
        );
        // The member judges it by its own clock: held in its group, never taken in, since a copy
        // too old at its origin (past 91 s) is too old at every relay (past 76 s). No mark says so.
        let out = hub_b.listen(u64::MAX, Filter::Everything);
        assert!(!feed(
            &hub_b,
            77,
            old,
            Origin::Peer(relay(a.public())),
            later
        ));
        assert_eq!(hub_b.memory_report().late_records, 1);
        assert!(out.try_recv().is_none(), "a late copy was forwarded");
        // Asked about it, both relays answer that they saw it.
        for (hub, me) in [(&hub_a, &a), (&hub_b, &b)] {
            let answer = ask(hub, me, None, 2, later + 1_000)?;
            assert!(
                matches!(
                    answer.entries.as_slice(),
                    [(2, tally_wire::Possession::Proved { .. })]
                ),
                "{} answered {:?}",
                if std::ptr::eq(me, &a) { "a" } else { "b" },
                answer.entries
            );
        }
        Ok(())
    }

    /// RFC-0171 §3.6: a feeder signing up to 30 s past `FEEDER_BEHIND` behind, past what its relay
    /// takes in
    /// (`strikes::FeederClock::TooOld`), floods its relay. Every batch is sent down its stripe (a
    /// copy is possession, which never reads a clock), and the member judges each by its own
    /// clock: too old at the origin is too old at every relay, so it forwards none, gives none to
    /// its products, and charges none to the origin's share of its strike tables, with no mark
    /// telling it so.
    #[test]
    fn a_feeder_signing_too_far_behind_reaches_no_members_products_or_share() -> Result<(), String>
    {
        let (a, b) = (Identity::from_seed([68; 32]), Identity::from_seed([69; 32]));
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let hub_a = member_hub(&a, &b, group, BASE_MS)?;
        let hub_b = member_hub(&b, &a, group, BASE_MS)?;
        let now = BASE_MS + 600_000;
        for hub in [&hub_a, &hub_b] {
            hub.publish_info(1, info.clone(), receiver_key, 1, Some(place), false);
        }
        let out = hub_b.listen(u64::MAX, Filter::Everything);
        let flood = 40u64;
        for sequence in 0..flood {
            let behind = tally_wire::budget::FEEDER_BEHIND
                .span::<tally_wire::clocks::Judged>()
                .ms()
                + 1_000
                + sequence * 29_000 / flood;
            let batch = signed_batch_at(&receiver, sequence, Vec::new(), now - behind)?;
            let in_flight = hub_a.in_flight_for(&batch);
            let kept = hub_a.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Feeder(None, None, None),
                verify: true,
                stamp: Some(Stamp::recorded(now, sequence, now, now, true)),
                arrived: None,
                in_flight,
                refusal: Some(Arc::new(crate::ingest::Refusal::default())),
            });
            assert!(!kept, "{behind} ms behind was taken in");
        }
        // What `a` sent `b`, taken in as `b`'s member link takes it.
        let mut copies = 0;
        for sent in hub_a.network().sharing.take_outbox() {
            if sent.to != b.public() {
                continue;
            }
            if let Record::Batch(batch) = sent.record {
                copies += 1;
                assert!(!feed(
                    &hub_b,
                    77,
                    batch,
                    Origin::Peer(relay(a.public())),
                    now
                ));
            }
        }
        assert_eq!(copies, flood);
        assert!(out.try_recv().is_none(), "a late copy was forwarded");
        // Never decoded, routed to the products or counted forwarded for its receiver.
        assert_eq!(
            hub_b
                .station(&receiver_key)
                .map_or(0, |station| station.batches),
            0
        );
        assert_eq!(hub_b.shares.held_by(Deliverer::Peer(a.public())), 0);
        assert_eq!(hub_b.memory_report().late_records, flood);
        Ok(())
    }

    /// RFC-0174 §2.5 and RFC-0171 §3.6: an honest member's copy that this relay has no room to
    /// take in (`Verdict::Full`, another member having flooded the store full) credits the member
    /// all the same, as a late copy does, so its receipt is not short for this relay's want of
    /// room; it is not taken in (forwarded) nor counted as had, so the group still asks for it.
    /// Before, it was dropped, and the honest member was reported short.
    #[test]
    fn an_honest_member_is_never_reported_short_for_this_relays_want_of_room() -> Result<(), String>
    {
        let me = Identity::from_seed([63; 32]);
        let honest = Identity::from_seed([64; 32]);
        let flood = Identity::from_seed([65; 32]).public();
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let hub = member_hub(&me, &honest, group, BASE_MS)?;
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        // Every share wide open: only the store bounds what is taken.
        hub.shares.set(crate::strikes::Entries {
            feeder: 1 << 40,
            feeders: 1 << 40,
            peer: 1 << 40,
            peers: 1 << 40,
            relay: 1 << 40,
        });
        // The store a little room from full, which the flood takes.
        // The peers' store: the flood is a peer's.
        let gauge = hub.budget.gauge(Store::PeerStrikes);
        let _rest = gauge
            .try_charge(gauge.limit() - gauge.held() - (64 << 10))
            .ok_or("the store has no room to fill")?;
        let mut sequence = 0;
        while hub.memory_report().strikes_full == 0 {
            let batch = signed_batch(&receiver, 1_000 + sequence, Vec::new())?;
            let _ = feed(&hub, 78, batch, Origin::Peer(relay(flood)), BASE_MS);
            sequence += 1;
            if sequence > 100_000 {
                return Err("the flood never filled the store".to_owned());
            }
        }
        let batch = signed_batch(&receiver, 0, Vec::new())?;
        listed(&hub, &honest, group, &batch, judged(BASE_MS))?;
        let out = hub.listen(u64::MAX, Filter::Everything);
        assert!(!feed(
            &hub,
            77,
            batch.clone(),
            Origin::Peer(relay(honest.public())),
            BASE_MS
        ));
        assert_eq!(
            hub.memory_report().strikes_full,
            2,
            "the copy was not let go"
        );
        assert!(out.try_recv().is_none(), "a copy let go was forwarded");
        let (credited, had) = hub
            .network()
            .sharing
            .member_for_test(|held| {
                (
                    held.delivered(group, &batch.hash(), &honest.public()),
                    held.counts_had(group, &batch.hash()),
                )
            })
            .ok_or("no member")?;
        assert_eq!((credited, had), (true, false), "(credited, counted as had)");
        let _ = hub.network().sharing.take_outbox();
        let window = BASE_MS / 1000 / crate::sharing::member::RECEIPT_WINDOW_SECONDS;
        let due = (window + 1) * crate::sharing::member::RECEIPT_WINDOW_SECONDS * 1000
            + crate::sharing::Deadlines::RELAY.receipt_grace.ms();
        // The window falls due when the judging clock first passes its end, and its receipts a
        // grace on by the monotonic one (`member::Due`).
        let _ = hub
            .network()
            .sharing
            .tick_member_for_test(due - crate::sharing::Deadlines::RELAY.receipt_grace.ms());
        let _ = hub.network().sharing.tick_member_for_test(due);
        let stripe = crate::sharing::stripes::data_stripe(&batch.hash());
        let records: Vec<u32> = hub
            .network()
            .sharing
            .take_outbox()
            .into_iter()
            .filter(|sent| sent.to == honest.public())
            .filter_map(|sent| match sent.record {
                Record::StripeReceipt(receipt) => receipt.content().ok(),
                _ => None,
            })
            .filter(|content| content.stripe == stripe)
            .map(|content| content.records)
            .collect();
        assert_eq!(records, vec![1], "the honest member's receipt was short");
        Ok(())
    }

    /// A relay that restarts and sends its receiver's backlog again (its own copies, which it
    /// originates afresh, with manifests of the seconds it sends them in) is refused by a member
    /// that already took them in: a duplicate within the window, by the member's memory of what
    /// it took, and too late after it, by the batches' signed time. Were a group's notes and a
    /// fresh listing to decide, the notes would expire with the horizon and the restarted relay's
    /// manifests make every batch of its backlog owed again.
    #[test]
    fn a_restarted_relays_backlog_is_never_forwarded_twice() -> Result<(), String> {
        let me = Identity::from_seed([55; 32]);
        let restarted = Identity::from_seed([56; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let start = BASE_MS;
        let hub = member_hub(&me, &restarted, group, start)?;
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        let from = Origin::Peer(relay(restarted.public()));
        let backlog: Vec<Batch> = (0..4)
            .map(|sequence| signed_batch(&receiver, sequence, Vec::new()))
            .collect::<Result<_, _>>()?;
        for batch in &backlog {
            assert!(feed(&hub, 77, batch.clone(), from.clone(), start));
        }
        stream(&hub, &receiver, (4, 100), start)?;
        // Restarted within the window: its backlog again, listed afresh.
        let soon = start + 5_000;
        for batch in &backlog[..2] {
            listed(&hub, &restarted, group, batch, judged(soon))?;
            assert!(
                !feed(&hub, 77, batch.clone(), from.clone(), soon),
                "a backlog batch was forwarded twice within the window"
            );
        }
        assert_eq!(
            hub.memory_report().late_records,
            0,
            "a duplicate counted late"
        );
        // Restarted after it, once the batches' fingerprints have expired (until then they are
        // duplicates still): too late by their signed time.
        let later = start + Usable::BATCHES.life_seconds() * 1000 + 1_000;
        for batch in &backlog[2..] {
            listed(&hub, &restarted, group, batch, judged(later))?;
            assert!(
                !feed(&hub, 77, batch.clone(), from.clone(), later),
                "a backlog batch was forwarded twice after the window"
            );
        }
        assert_eq!(hub.memory_report().late_records, 2);
        Ok(())
    }

    /// A member's hub, as `member_hub`, on a clock the test sets and keeping its state in `dir`
    /// (`durable`): what a restarted relay is started from.
    fn durable_member_hub(
        members: (&Identity, &Identity),
        group: crate::sharing::groups::GroupKey,
        clock: &Arc<AtomicU64>,
        dir: &Arc<crate::durable::StateDir>,
    ) -> Result<Arc<Hub>, String> {
        let reading = Arc::clone(clock);
        let relay_clock = RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed)));
        let durable = crate::durable::Durable::Dir(Arc::clone(dir));
        member_hub_on(members, group, relay_clock, durable)
    }

    /// As `durable_member_hub`, on `clock` (whose error a test sets) and keeping `durable`.
    fn member_hub_on(
        (me, member): (&Identity, &Identity),
        group: crate::sharing::groups::GroupKey,
        clock: RelayClock,
        durable: crate::durable::Durable,
    ) -> Result<Arc<Hub>, String> {
        let now = clock.judged().ms();
        let hub = Arc::new(
            Hub::on(8, clock, crate::sharing::Deadlines::RELAY)
                .durable(durable)?
                .taking(vec![group.cell]),
        );
        hub.network().adopt_identity(crate::signer::twin(me));
        let _ = hub.network().tick(&hub, now);
        hub.network().sharing.groups.admit(
            group,
            member.public(),
            crate::sharing::MonoDeadline::NEVER,
            false,
        );
        hub.network()
            .sharing
            .member_for_test(|held| {
                let _ = held.set_members(group, &[me.public(), member.public()], &[], now);
            })
            .ok_or("no member")?;
        Ok(hub)
    }

    /// RFC-0171 §3.6, a restart (RFC 4120 §3.2.3, RFC 8446 §8.2): a relay restarted on its state
    /// directory forwards nothing it forwarded before. After a crash its tables start at the lease
    /// each kept synced ahead of use, so a member's repair of what it took (a horizon of copies)
    /// is late, never new again; after a graceful stop they hold the stop's dump, so the same
    /// copies are duplicates, and a batch never seen, signed before the lease's bound, is still new
    /// (a deploy is not deaf). Either way zero re-forwards. Before, a restarted relay started with
    /// an empty memory and forwarded each once more within the window.
    #[test]
    fn a_restarted_relay_forwards_none_of_its_members_repair_of_the_previous_horizon()
    -> Result<(), String> {
        let me = Identity::from_seed([57; 32]);
        let member = Identity::from_seed([58; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let from = Origin::Peer(relay(member.public()));
        // Past the fallback floor a first start on an empty directory begins at.
        let signed = BASE_MS
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 5_000;
        let copies: Vec<Batch> = (96..200)
            .map(|sequence| signed_batch_at(&receiver, sequence, Vec::new(), signed))
            .collect::<Result<_, _>>()?;
        for graceful in [false, true] {
            let scratch = crate::durable::tests::Scratch::new("restart");
            let dir = scratch.dir()?;
            let clock = Arc::new(AtomicU64::new(BASE_MS));
            let hub = durable_member_hub((&me, &member), group, &clock, &dir)?;
            hub.publish_info(1, info.clone(), receiver_key, 1, Some(place), false);
            clock.store(signed + 2_000, Ordering::Relaxed);
            for copy in &copies {
                assert!(feed(&hub, 77, copy.clone(), from.clone(), signed + 2_000));
            }
            if graceful {
                hub.stop()?;
            }
            drop(hub);
            drop(dir);
            clock.store(signed + 3_000, Ordering::Relaxed);
            // A new process: the directory opened again, a run of its own.
            let dir = scratch.dir()?;
            let restarted = durable_member_hub((&me, &member), group, &clock, &dir)?;
            assert_eq!(
                restarted.memory_report().dumps_resumed,
                u64::from(graceful),
                "graceful {graceful}"
            );
            restarted.publish_info(1, info.clone(), receiver_key, 1, Some(place), false);
            let out = restarted.listen(u64::MAX, Filter::Everything);
            for copy in &copies {
                assert!(
                    !feed(&restarted, 77, copy.clone(), from.clone(), signed + 3_000),
                    "graceful {graceful}: batch {} forwarded again",
                    copy.sequence()
                );
            }
            assert!(out.try_recv().is_none(), "graceful {graceful}: forwarded");
            let report = restarted.memory_report();
            // After a crash the copies are below the floor (late); after a stop, duplicates.
            let late = if graceful { 0 } else { copies.len() as u64 };
            assert_eq!(report.late_records, late, "graceful {graceful}");
            // A batch never seen, signed below the crash's floor: new only after a stop's dump.
            let unseen = signed_batch_at(&receiver, 500, Vec::new(), signed + 1_000)?;
            assert_eq!(
                feed(&restarted, 77, unseen, from.clone(), signed + 3_000),
                graceful,
                "graceful {graceful}"
            );
        }
        Ok(())
    }

    /// What a restart test feeds: a member's copies of one receiver's batches, signed at `signed`.
    struct Restart {
        me: Identity,
        member: Identity,
        receiver: Identity,
        receiver_key: PublicKey,
        info: ReceiverInfo,
        place: Location,
        group: crate::sharing::groups::GroupKey,
        from: Origin,
        signed: u64,
        copies: Vec<Batch>,
    }

    impl Restart {
        fn new(seed: u8) -> Result<Self, String> {
            let (receiver, receiver_key) = key()?;
            let (info, place, group) = located(&receiver)?;
            let member = Identity::from_seed([seed + 1; 32]);
            let signed = BASE_MS
                + tally_wire::budget::FALLBACK_FLOOR
                    .span::<tally_wire::clocks::Judged>()
                    .ms()
                + 5_000;
            let copies = (96..120)
                .map(|sequence| signed_batch_at(&receiver, sequence, Vec::new(), signed))
                .collect::<Result<_, _>>()?;
            Ok(Self {
                me: Identity::from_seed([seed; 32]),
                from: Origin::Peer(relay(member.public())),
                member,
                receiver,
                receiver_key,
                info,
                place,
                group,
                signed,
                copies,
            })
        }

        /// A hub of this test on `clock`, keeping `durable`, its receiver described.
        fn hub(
            &self,
            clock: RelayClock,
            durable: crate::durable::Durable,
        ) -> Result<Arc<Hub>, String> {
            let hub = member_hub_on((&self.me, &self.member), self.group, clock, durable)?;
            hub.publish_info(
                1,
                self.info.clone(),
                self.receiver_key,
                1,
                Some(self.place),
                false,
            );
            Ok(hub)
        }

        /// The first run: every copy taken at `signed + 2 s`, then a graceful stop.
        fn first_run(&self, dir: &Arc<crate::durable::StateDir>) -> Result<Arc<Hub>, String> {
            let at = Arc::new(AtomicU64::new(BASE_MS));
            let hub = durable_member_hub((&self.me, &self.member), self.group, &at, dir)?;
            hub.publish_info(
                1,
                self.info.clone(),
                self.receiver_key,
                1,
                Some(self.place),
                false,
            );
            at.store(self.signed + 2_000, Ordering::Relaxed);
            for copy in &self.copies {
                if !feed(
                    &hub,
                    77,
                    copy.clone(),
                    self.from.clone(),
                    self.signed + 2_000,
                ) {
                    return Err(format!("copy {} not taken", copy.sequence()));
                }
            }
            hub.stop()?;
            Ok(hub)
        }

        /// The second run, at `signed + 3 s`, on the directory at `path` opened again.
        fn second_run(&self, scratch: &crate::durable::tests::Scratch) -> Result<Arc<Hub>, String> {
            let at = Arc::new(AtomicU64::new(self.signed + 3_000));
            durable_member_hub((&self.me, &self.member), self.group, &at, &scratch.dir()?).inspect(
                |hub| {
                    hub.publish_info(
                        1,
                        self.info.clone(),
                        self.receiver_key,
                        1,
                        Some(self.place),
                        false,
                    );
                },
            )
        }

        /// How many of the copies the second run forwards again.
        fn forwarded_again(&self, hub: &Arc<Hub>) -> usize {
            self.copies
                .iter()
                .filter(|copy| {
                    feed(
                        hub,
                        77,
                        (*copy).clone(),
                        self.from.clone(),
                        self.signed + 3_000,
                    )
                })
                .count()
        }
    }

    /// RFC-0171 §3.6, finding 1 of the seventh sweep: a stopping relay takes nothing after its
    /// dump, and so moves no lease: a batch its member sends after the stop, signed past every
    /// bound, is let go before its lease is told of it, and the next start reads the dump back.
    /// Before, the lease was made to cover the batch before its share was refused, so the bound
    /// moved past the dump's and the next start, finding them apart, was deaf for the fallback's
    /// window.
    #[test]
    fn a_record_offered_after_a_stop_leaves_the_dump_to_be_read_back() -> Result<(), String> {
        let test = Restart::new(81)?;
        let scratch = crate::durable::tests::Scratch::new("after-stop");
        let dir = scratch.dir()?;
        let hub = test.first_run(&dir)?;
        let past = signed_batch_at(&test.receiver, 500, Vec::new(), test.signed + 20_000)?;
        assert!(!feed(
            &hub,
            77,
            past,
            test.from.clone(),
            test.signed + 2_000
        ));
        drop(hub);
        drop(dir);
        let restarted = test.second_run(&scratch)?;
        let report = restarted.memory_report();
        assert_eq!((report.dumps_resumed, report.dumps_refused), (1, 0));
        assert_eq!(test.forwarded_again(&restarted), 0);
        Ok(())
    }

    /// RFC-0171 §3.6, findings 2 and 3 of the seventh sweep: a stop's dump is a sealed state file
    /// (`durable::StateDir::seal`), read back only when its seal, key and layout are what this
    /// start expects and every lease is what it was written beside, and consumed first, once.
    /// One under another key, of another layout (another `SHARDS`, or a table's windows changed:
    /// sweep 8, B3), with a bit flipped in a table's floor, or found beside no lease it was written
    /// with (a dump copied to a directory that held no state) is refused: the floors stand, so
    /// every copy used before is late, never new. A dump read back once is gone: a second start is
    /// no deploy that resumes it again. Before, a dump had no header and its removal's result was
    /// ignored. And a dump another run wrote beside these leases, stating no floor (sweep 8, B1:
    /// a run that never synced), is read, but never below what the leases prove: the copies used
    /// are still late.
    #[test]
    fn a_dump_is_read_back_once_and_only_as_it_was_written() -> Result<(), String> {
        let test = Restart::new(83)?;
        for case in [
            "whole",
            "key",
            "shards",
            "windows",
            "floor bit",
            "no state",
            "floorless",
        ] {
            let scratch = crate::durable::tests::Scratch::new("dump");
            let mut dir = scratch.dir()?;
            let first = test.first_run(&dir)?;
            let layout = first.dump_layout();
            drop(first);
            let dump = dir.path().join("strikes.dump");
            let elsewhere = crate::durable::tests::Scratch::new("dump-elsewhere");
            let mut scratch = scratch;
            match case {
                "key" => std::fs::write(dir.path().join("strike.key"), [7u8; 32])
                    .map_err(|error| error.to_string())?,
                "shards" => {
                    let crate::durable::Prior::Valid((_, body)) =
                        dir.read_state("strikes.dump", crate::durable::Kind::Dump, &layout)
                    else {
                        return Err("the dump did not read".into());
                    };
                    let other = layout.replacen(&SHARDS.to_string(), &(SHARDS * 2).to_string(), 1);
                    dir.write_state("strikes.dump", crate::durable::Kind::Dump, &other, &body)
                        .map_err(|error| error.to_string())?;
                }
                "windows" => {
                    let crate::durable::Prior::Valid((_, body)) =
                        dir.read_state("strikes.dump", crate::durable::Kind::Dump, &layout)
                    else {
                        return Err("the dump did not read".into());
                    };
                    let other = layout.replacen("retained ", "retained 1", 1);
                    dir.write_state("strikes.dump", crate::durable::Kind::Dump, &other, &body)
                        .map_err(|error| error.to_string())?;
                }
                "floorless" => {
                    // Written by another run (the directory opened again): the leases as they
                    // stand, then every table empty with no floor.
                    let crate::durable::Prior::Valid((_, body)) =
                        dir.read_state("strikes.dump", crate::durable::Kind::Dump, &layout)
                    else {
                        return Err("the dump did not read".into());
                    };
                    drop(dir);
                    dir = scratch.dir()?;
                    let mut floorless = body[..Hub::DUMP_LEASES.len() * 16].to_vec();
                    floorless.resize(floorless.len() + (SHARDS + 4) * 16, 0);
                    dir.write_state(
                        "strikes.dump",
                        crate::durable::Kind::Dump,
                        &layout,
                        &floorless,
                    )
                    .map_err(|error| error.to_string())?;
                }
                "floor bit" => {
                    let mut bytes = std::fs::read(&dump).map_err(|error| error.to_string())?;
                    // Past the header and the five leases' bounds and runs: the first table's
                    // floor.
                    let at = 8 + 2 + 1 + 16 + 2 + layout.len() + 8 + 8 + 5 * 16;
                    bytes[at] ^= 1;
                    std::fs::write(&dump, &bytes).map_err(|error| error.to_string())?;
                }
                "no state" => {
                    std::fs::create_dir_all(&elsewhere.0).map_err(|error| error.to_string())?;
                    for file in ["strike.key", "strikes.dump"] {
                        std::fs::copy(dir.path().join(file), elsewhere.0.join(file))
                            .map_err(|error| error.to_string())?;
                    }
                    scratch = elsewhere;
                }
                _ => {}
            }
            drop(dir);
            let restarted = test.second_run(&scratch)?;
            let report = restarted.memory_report();
            let whole = case == "whole" || case == "floorless";
            assert_eq!(
                (report.dumps_resumed, report.dumps_refused),
                (u64::from(whole), u64::from(!whole)),
                "{case}"
            );
            assert_eq!(test.forwarded_again(&restarted), 0, "{case}");
            if whole {
                // Read back once: the next start finds no dump.
                drop(restarted);
                let again = test.second_run(&scratch)?;
                let report = again.memory_report();
                assert_eq!((report.dumps_resumed, report.dumps_refused), (0, 0));
                assert_eq!(test.forwarded_again(&again), 0);
            }
        }
        Ok(())
    }

    /// RFC-0171 §3.6, sweep 8 B1: a relay whose clock never synced stops writing no dump, since
    /// its tables never began and have no floor of their own to state; the next start keeps the
    /// floors its leases prove, so every copy the run before used is still late. Before, the
    /// unsynced run dumped tables with no floor beside the leases of the run that crashed, and
    /// the start after read every copy that run used as new.
    #[test]
    fn a_relay_that_never_synced_stops_without_a_dump() -> Result<(), String> {
        let test = Restart::new(87)?;
        let scratch = crate::durable::tests::Scratch::new("unsynced-stop");
        let dir = scratch.dir()?;
        drop(test.first_run(&dir)?);
        // As if it had crashed after using every copy: its leases, and no dump.
        std::fs::remove_file(dir.path().join("strikes.dump")).map_err(|error| error.to_string())?;
        drop(dir);
        let dir = scratch.dir()?;
        let clock = RelayClock::scripted(Arc::new(|| BASE_MS));
        clock.set_error(None);
        let unsynced = test.hub(clock, crate::durable::Durable::Dir(Arc::clone(&dir)))?;
        unsynced.stop()?;
        assert!(!dir.path().join("strikes.dump").exists());
        drop(unsynced);
        drop(dir);
        let restarted = test.second_run(&scratch)?;
        assert_eq!(test.forwarded_again(&restarted), 0);
        Ok(())
    }

    /// RFC-0171 §3.6, finding 5 of the seventh sweep: nothing is derived from the wall clock until
    /// it is synced. A relay that starts unsynced with no state takes nothing as new: a member's
    /// copy is held, possession only, counted unjudged, never forwarded and never blamed on
    /// anyone; its fallback floor is taken once the clock is synced, from that clock. So a copy
    /// signed before the synced clock's floor is late, and one past it is new. Before, the floor
    /// was taken at start from the clock unsynced.
    #[test]
    fn a_relay_unsynced_at_start_takes_nothing_and_its_floor_is_the_synced_clocks()
    -> Result<(), String> {
        let test = Restart::new(85)?;
        let at = Arc::new(AtomicU64::new(BASE_MS));
        let reading = Arc::clone(&at);
        let clock = RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed)));
        clock.set_error(None);
        let hub = test.hub(clock.clone(), crate::durable::Durable::Fresh)?;
        at.store(test.signed, Ordering::Relaxed);
        assert!(!feed(
            &hub,
            77,
            test.copies[0].clone(),
            test.from.clone(),
            test.signed
        ));
        let report = hub.memory_report();
        assert_eq!((report.unjudged_records, report.late_records), (1, 0));
        // Synced ten minutes on, the clock having been ten minutes behind: the floor is now's.
        let synced = test.signed + 600_000;
        at.store(synced, Ordering::Relaxed);
        clock.set_error(Some(5));
        hub.sweep_strikes();
        let before = signed_batch_at(&test.receiver, 300, Vec::new(), synced - 1_000)?;
        assert!(!feed(&hub, 77, before, test.from.clone(), synced));
        assert_eq!(hub.memory_report().late_records, 1);
        let past = synced
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000;
        at.store(past, Ordering::Relaxed);
        let after = signed_batch_at(&test.receiver, 301, Vec::new(), past)?;
        assert!(feed(&hub, 77, after, test.from.clone(), past));
        Ok(())
    }

    /// The relay's sweep gives back to the shares what every table dropped, once it has swept
    /// them all (`Hub::sweep_strikes`, `Shares::expire`): a member's copy taken is held in the
    /// share of its class until a sweep past its life, and given back by that sweep with no
    /// record judged. Nothing else lets an entry go, so without it a share stays spent for
    /// records no table holds.
    #[test]
    fn the_relays_sweep_gives_back_what_every_table_dropped() -> Result<(), String> {
        let test = Restart::new(91)?;
        let at = Arc::new(AtomicU64::new(BASE_MS));
        let reading = Arc::clone(&at);
        let clock = RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed)));
        let hub = test.hub(clock, crate::durable::Durable::Fresh)?;
        at.store(test.signed, Ordering::Relaxed);
        assert!(feed(
            &hub,
            77,
            test.copies[2].clone(),
            test.from.clone(),
            test.signed
        ));
        let held = || {
            crate::strikes::Class::ALL
                .iter()
                .map(|class| hub.shares.held_of(*class).0)
                .sum::<usize>()
        };
        assert!(held() > 0);
        hub.sweep_strikes();
        assert!(held() > 0, "given back before any table dropped it");
        // Past every table's life of it: the sweep drops it from every table, then the shares.
        at.store(test.signed + 3_600_000, Ordering::Relaxed);
        hub.sweep_strikes();
        assert_eq!(held(), 0);
        Ok(())
    }

    /// RFC-0171 §3.6, the ninth sweep's finding 4: a relay that synced and began, whose clock's
    /// error then passes `E`, uses nothing: a member's copy is held, possession only, counted
    /// unjudged, never forwarded; a regional batch's window is not judged, and a sweep by its
    /// reading forgets nothing; once the clock judges again the next copy is forwarded. Before,
    /// the tables judged by the clock whatever its error once they had begun.
    #[test]
    fn a_relay_whose_clock_stops_judging_after_the_start_uses_nothing() -> Result<(), String> {
        let test = Restart::new(89)?;
        let at = Arc::new(AtomicU64::new(BASE_MS));
        let reading = Arc::clone(&at);
        let clock = RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed)));
        let hub = test.hub(clock.clone(), crate::durable::Durable::Fresh)?;
        at.store(test.signed, Ordering::Relaxed);
        // One copy taken while it judges, so its table holds a generation a sweep could drop.
        assert!(feed(
            &hub,
            77,
            test.copies[2].clone(),
            test.from.clone(),
            test.signed
        ));
        clock.set_error(None);
        hub.sweep_strikes();
        assert!(!feed(
            &hub,
            77,
            test.copies[0].clone(),
            test.from.clone(),
            test.signed
        ));
        let report = hub.memory_report();
        assert_eq!((report.unjudged_records, report.late_records), (1, 0));
        // A regional batch's window is not judged either.
        assert_eq!(
            hub.in_window(Some(test.signed), hub.judged_now()),
            InWindow::Late
        );
        // Nor does a sweep forget anything by it: a reading an hour ahead raises no floor.
        at.store(test.signed + 3_600_000, Ordering::Relaxed);
        hub.sweep_strikes();
        at.store(test.signed, Ordering::Relaxed);
        clock.set_error(Some(5));
        assert_eq!(
            hub.in_window(Some(test.signed), hub.judged_now()),
            InWindow::Inside
        );
        assert!(feed(
            &hub,
            77,
            test.copies[1].clone(),
            test.from.clone(),
            test.signed
        ));
        Ok(())
    }

    /// RFC-0171 §3.6, the ninth sweep's ruling: a run whose clock ran an hour ahead leaves its
    /// leases an hour ahead of true time, having used records up to them. The next start, on a
    /// synced clock, keeps every such bound as its floor, so the batch that run used is never
    /// forwarded again; it says so, counts it and names when it clears (`leases_ahead`,
    /// `lease_ahead_until_ms`), and a fresh batch is not used until the clock passes the bound.
    /// Before, the bound was refused for the fallback floor and that run's batch was new again.
    #[test]
    fn a_lease_left_by_a_clock_run_ahead_stays_the_floor_at_start() -> Result<(), String> {
        let test = Restart::new(87)?;
        let scratch = crate::durable::tests::Scratch::new("ahead");
        let ahead = 3_600_000;
        let at = Arc::new(AtomicU64::new(BASE_MS + ahead));
        let hub = durable_member_hub((&test.me, &test.member), test.group, &at, &scratch.dir()?)?;
        hub.publish_info(
            1,
            test.info.clone(),
            test.receiver_key,
            1,
            Some(test.place),
            false,
        );
        let used = test.signed + ahead;
        at.store(used, Ordering::Relaxed);
        let batch = signed_batch_at(&test.receiver, 400, Vec::new(), used)?;
        assert!(feed(&hub, 77, batch.clone(), test.from.clone(), used));
        drop(hub);
        let now = test.signed + 3_000;
        let at = Arc::new(AtomicU64::new(now));
        let restarted =
            durable_member_hub((&test.me, &test.member), test.group, &at, &scratch.dir()?)?;
        restarted.publish_info(
            1,
            test.info.clone(),
            test.receiver_key,
            1,
            Some(test.place),
            false,
        );
        let report = restarted.memory_report();
        assert!(report.leases_ahead >= 1);
        assert!(
            report.lease_ahead_until_ms > used,
            "{}",
            report.lease_ahead_until_ms
        );
        // Its clock now where that run's was: the batch it used is not forwarded again.
        at.store(used, Ordering::Relaxed);
        assert!(
            !feed(&restarted, 77, batch, test.from.clone(), used),
            "replayed"
        );
        // A fresh batch before the clock passes the bound is not used either.
        let past = now
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000;
        at.store(past, Ordering::Relaxed);
        let fresh = signed_batch_at(&test.receiver, 401, Vec::new(), past)?;
        assert!(!feed(&restarted, 77, fresh, test.from.clone(), past));
        Ok(())
    }

    /// RFC-0171 §3.6, the window to the millisecond: a member's copy of a batch signed at `t` that
    /// arrives at `t + A` (`strikes::Window`'s `behind_ms`) is taken, once; one signed at `t` that
    /// arrives a millisecond later is too late. Ahead, one signed `S` (`ahead_ms`) past this
    /// relay's clock is taken and one a millisecond further is never used here (`Verdict::Ahead`).
    #[test]
    fn a_copy_is_taken_once_to_the_edge_of_the_window_and_late_past_it() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let (receiver, _) = key()?;
        let from = Origin::Peer(relay(Identity::from_seed([63; 32]).public()));
        let window = Window::PEER;
        let edge = BASE_MS
            + window
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        let at_edge = signed_batch(&receiver, 0, Vec::new())?;
        assert!(
            feed(&hub, 77, at_edge.clone(), from.clone(), edge),
            "a copy at the edge of the window was refused"
        );
        assert!(!feed(&hub, 77, at_edge, from.clone(), edge));
        assert_eq!(hub.memory_report().late_records, 0);
        let past = signed_batch(&receiver, 1, Vec::new())?;
        assert!(
            !feed(&hub, 77, past, from.clone(), edge + 1),
            "a copy past the window was taken"
        );
        assert_eq!(hub.memory_report().late_records, 1);
        let ahead = edge
            + 1
            + window
                .ahead_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        // Anchored by a relay whose clock read this one's: a feeder signing ahead of its relays.
        let farthest = signed_batch_anchored(&receiver, 2, Vec::new(), ahead, edge + 1)?;
        assert!(feed(&hub, 77, farthest, from.clone(), edge + 1));
        // A millisecond further: ahead of what this hop uses at its first arrival, never used
        // here (counted ahead, not late).
        let too_far = signed_batch_anchored(&receiver, 3, Vec::new(), ahead + 1, edge + 1)?;
        assert!(!feed(&hub, 77, too_far, from, edge + 1));
        let report = hub.memory_report();
        assert_eq!((report.late_records, report.ahead_records), (1, 1));
        Ok(())
    }

    /// A batch judged new and, before it is remembered, made too late by its table dropping the
    /// generation it would be held in (a batch stamped far enough on taken meanwhile, which raises
    /// the table's floor past it) follows the verdict given when it is remembered: too late,
    /// counted apart and never taken in, and delivered into its group as any late copy is
    /// (`Hub::late`). Before, the second verdict was read as a duplicate.
    #[test]
    fn a_batch_made_late_between_its_verdict_and_its_keeping_is_late() -> Result<(), String> {
        let me = Identity::from_seed([59; 32]);
        let member = Identity::from_seed([60; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let start = BASE_MS;
        let hub = member_hub(&me, &member, group, start)?;
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        stream(&hub, &receiver, (1, 100), start)?;
        let copied_at = start
            + Window::PEER
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        // Far enough on that the table drops the stream's generation, raising its floor past it.
        let moved_at = start + crate::strikes::Usable::BATCHES.retained_ms() + 2_000;
        let moved_on = signed_batch_at(&receiver, 101, Vec::new(), moved_at)?;
        let weak = Arc::downgrade(&hub);
        *hub.between.lock().map_err(|error| error.to_string())? = Some(Box::new(move || {
            if let Some(hub) = weak.upgrade() {
                let _ = feed(&hub, 1, moved_on, Origin::Elsewhere, moved_at);
            }
        }));
        let copy = signed_batch(&receiver, 0, Vec::new())?;
        assert!(!feed(
            &hub,
            77,
            copy.clone(),
            Origin::Peer(relay(member.public())),
            copied_at
        ));
        assert_eq!(hub.memory_report().late_records, 1);
        let had = hub
            .network()
            .sharing
            .member_for_test(|held| held.counts_had(group, &copy.hash()))
            .unwrap_or(false);
        // Never taken in, but delivered into its group as any late copy is.
        assert!(had, "a batch made late before it was kept is not delivered");
        Ok(())
    }

    /// The same from its feeder: usable when it is judged, made late before it is kept by its
    /// table moving on. It is counted late and held, and never blamed on its receiver
    /// (`strikes::blame`, the one rule a batch is blamed by): its feeder signed it in time.
    /// Before, the late verdict at its keeping counted it in `late_batches` with no rule asked.
    #[test]
    fn a_feeders_batch_made_late_before_its_keeping_is_late_and_blamed_on_no_one()
    -> Result<(), String> {
        let me = Identity::from_seed([61; 32]);
        let member = Identity::from_seed([62; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let start = BASE_MS;
        let hub = member_hub(&me, &member, group, start)?;
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        stream(&hub, &receiver, (1, 100), start)?;
        let arrives = start
            + Window::PEER
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms();
        let moved_at = start + crate::strikes::Usable::BATCHES.retained_ms() + 2_000;
        let moved_on = signed_batch_at(&receiver, 101, Vec::new(), moved_at)?;
        let weak = Arc::downgrade(&hub);
        *hub.between.lock().map_err(|error| error.to_string())? = Some(Box::new(move || {
            if let Some(hub) = weak.upgrade() {
                let _ = feed(&hub, 1, moved_on, Origin::Elsewhere, moved_at);
            }
        }));
        let late = |hub: &Arc<Hub>| {
            hub.station(&receiver_key)
                .map_or(0, |station| station.late_batches)
        };
        let before = late(&hub);
        let batch = signed_batch(&receiver, 0, Vec::new())?;
        assert!(!feed(
            &hub,
            1,
            batch,
            Origin::Feeder(None, None, None),
            arrives
        ));
        assert_eq!(hub.memory_report().late_records, 1, "not counted late");
        assert_eq!(late(&hub), before, "blamed on its receiver");
        Ok(())
    }

    /// RFC-0181 §9 and RFC-0171 §3.6: a member flooding new records fills its own share of the
    /// memory and no more (`strikes::Shares`): past it its records are let go (`strikes_full`),
    /// not forwarded and asked for again later, while another member's are still taken, and
    /// nothing the flood had taken is forgotten to make room, so every copy of it stays a
    /// duplicate. One the flood had let go is new to the other member.
    #[test]
    fn a_flooding_member_fills_only_its_own_share_and_evicts_nothing() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        // One record a second for each member: a share of a peer's copy's whole life.
        let share = usize::try_from(crate::strikes::Usable::BATCHES.life_seconds())
            .map_err(|e| e.to_string())?;
        hub.shares.set(crate::strikes::Entries {
            feeder: share,
            feeders: share,
            peer: share,
            // The peers' share beside two peers' places, as it is planned.
            peers: share + 2 * crate::strikes::PEER_PLACE_ENTRIES,
            relay: share,
        });
        let flood = Identity::from_seed([71; 32]).public();
        let honest = Identity::from_seed([72; 32]).public();
        let (receiver, _) = key()?;
        let batches: Vec<Batch> = (0..share as u64 + 50)
            .map(|sequence| signed_batch(&receiver, sequence, Vec::new()))
            .collect::<Result<_, _>>()?;
        let taken = batches
            .iter()
            .filter(|batch| {
                feed(
                    &hub,
                    77,
                    (*batch).clone(),
                    Origin::Peer(relay(flood)),
                    BASE_MS,
                )
            })
            .count();
        assert_eq!(taken, share);
        assert_eq!(hub.memory_report().strikes_full, 50);
        assert_eq!(hub.shares.held_by(Deliverer::Peer(flood)), share);
        let other = signed_batch(&receiver, 1_000_000, Vec::new())?;
        assert!(
            feed(&hub, 78, other, Origin::Peer(relay(honest)), BASE_MS),
            "another member's record was refused for the flood"
        );
        for batch in &batches[..share] {
            assert!(!feed(
                &hub,
                78,
                batch.clone(),
                Origin::Peer(relay(honest)),
                BASE_MS
            ));
        }
        assert_eq!(
            hub.memory_report().strikes_full,
            50,
            "a record the flood had taken was forgotten"
        );
        assert!(feed(
            &hub,
            78,
            batches[share].clone(),
            Origin::Peer(relay(honest)),
            BASE_MS
        ));
        Ok(())
    }

    /// RFC-0174 §2.5: an engine's stream at ten records a second, each published as late after
    /// its step as an engine may sign it (`strikes::ENGINE_LAG_MS`), takes a member's repair of
    /// every record it missed across the whole horizon, once each, the oldest repaired as the
    /// horizon closes on the newest, more than a hundred records behind the stream: each is
    /// shared into its group and forwarded once, and its copy shared and not forwarded again.
    /// Before, a stream held a ring of 64 sequences and a capped record, and a repair further
    /// behind was refused.
    #[test]
    fn an_engines_stream_takes_its_members_repairs_across_the_horizon() -> Result<(), String> {
        let clock = Arc::new(AtomicU64::new(BASE_MS));
        let reading = Arc::clone(&clock);
        let deadlines = crate::sharing::Deadlines::RELAY;
        let hub = Hub::clocked(
            8,
            Arc::new(move || reading.load(Ordering::Relaxed)),
            deadlines,
        );
        let (engine, _) = key()?;
        let member = Identity::from_seed([73; 32]).public();
        let lag = crate::strikes::ENGINE_LAG_MS;
        let horizon_ms = deadlines.horizon_ms();
        let count = horizon_ms / 100;
        let issued = |sequence: u64| BASE_MS + sequence * 100;
        let mut missed = Vec::new();
        for sequence in 0..count {
            let positions = signed_positions_at(&engine, 1, sequence, issued(sequence))?;
            if sequence % 3 == 0 {
                missed.push(positions);
                continue;
            }
            clock.store(issued(sequence) + lag, Ordering::Relaxed);
            assert!(hub.publish_positions(1, positions));
        }
        clock.store(issued(count) + lag + horizon_ms, Ordering::Relaxed);
        let out = hub.listen(u64::MAX, Filter::Everything);
        let repair = |positions: &Positions| -> Result<(bool, bool), String> {
            let (shared, late) = (std::cell::Cell::new(false), std::cell::Cell::new(false));
            hub.take_piece(
                77,
                Deliverer::Peer(member),
                Record::Positions(positions.clone()),
                |_| shared.set(true),
                || late.set(true),
            )?;
            Ok((shared.get(), late.get()))
        };
        for positions in &missed {
            assert_eq!(repair(positions)?, (true, false), "a repair was refused");
        }
        let mut forwarded = 0;
        while let Some(item) = out.try_recv() {
            if matches!(&*item.record, Record::Positions(_)) {
                forwarded += 1;
            }
        }
        assert_eq!(forwarded, missed.len());
        for positions in &missed {
            assert_eq!(repair(positions)?, (true, false), "a copy was not shared");
        }
        assert!(out.try_recv().is_none(), "a copy was forwarded again");
        assert_eq!(hub.memory_report().late_records, 0);
        Ok(())
    }

    /// A late copy of an engine's record through `take_piece`, as a member's link or this
    /// relay's rebuild hands it in: positions and a clock model signed
    /// longer ago than the window are each counted late and never published, and each is
    /// delivered into its group all the same (shared, its sender credited, `Hub::late`), never let
    /// go (which would have its group ask for it again for ever); a rebuilt one is passed on in
    /// its group, never refused nor let go.
    #[test]
    fn late_engine_records_through_take_piece_are_delivered_and_never_published()
    -> Result<(), String> {
        let (receiver, _) = key()?;
        let (_, _, group) = located(&receiver)?;
        let past = BASE_MS
            + crate::strikes::relay_signed(crate::sharing::Deadlines::RELAY)
                .behind_span()
                .duration()
                .as_millis() as u64
            + 1;
        let hub = Arc::new(
            Hub::clocked(8, Arc::new(move || past), crate::sharing::Deadlines::RELAY)
                .taking(vec![group.cell]),
        );
        let (engine, _) = key()?;
        let member = Identity::from_seed([74; 32]).public();
        let late: [Record; 2] = [
            Record::Positions(signed_positions_at(&engine, 1, 5, BASE_MS)?),
            Record::ClockModel(signed_clock_model_at(&engine, 1, 5, BASE_MS)?),
        ];
        let out = hub.listen(u64::MAX, Filter::Everything);
        for record in &late {
            let (shared, let_go) = (std::cell::Cell::new(false), std::cell::Cell::new(false));
            hub.take_piece(
                77,
                Deliverer::Peer(member),
                record.clone(),
                |_| shared.set(true),
                || let_go.set(true),
            )?;
            assert_eq!(
                (shared.get(), let_go.get()),
                (true, false),
                "a late {} was not delivered, or was let go",
                record.kind()
            );
        }
        assert_eq!(hub.memory_report().late_records, 2);
        assert!(out.try_recv().is_none(), "a late record was published");
        // Rebuilt from parity: passed on in its group, neither refused nor let go.
        let hash = crate::sharing::member::record_hash(&late[0]).ok_or("no hash")?;
        let rebuilt = Rebuilt::of(group, hash);
        hub.take_rebuilt(rebuilt, late[0].clone());
        let report = hub.memory_report();
        assert_eq!(
            (
                report.late_records,
                report.rebuilt_refused,
                report.rebuilt_no_room
            ),
            (3, 0, 0)
        );
        assert!(
            out.try_recv().is_none(),
            "a late rebuilt record was published"
        );
        Ok(())
    }

    /// RFC-0171 §3.6: a feeder's clock decides only whether its batch is usable where it
    /// publishes, and nothing is refused for it. A batch signed more than the tolerance
    /// (`tally_wire::budget::F`) ahead of this relay's ingest stamp, an hour ahead among them,
    /// is held unused, counted against nobody (`ahead_records`), never taken into a table (so it
    /// pins no table's memory or floor), and its feeder is told the relay's clock again; one more
    /// than `tally_wire::budget::FEEDER_BEHIND` behind it is only too old (a
    /// backlog a feeder held over a backoff or a stall, which a clock behind looks the same as):
    /// held and counted late (`late_records`), and never against its receiver (`late_batches`),
    /// since it carries none of this relay's own anchors (`strikes::blame`). The session goes on,
    /// and the
    /// batches after it on it are taken. Before, a batch more than the tolerance ahead was refused
    /// and its feeder sent away for a minute.
    #[test]
    fn a_feeders_batch_off_either_way_is_held_unused_and_nothing_is_refused() -> Result<(), String>
    {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let (receiver, receiver_key) = key()?;
        let tolerance = tally_wire::budget::F
            .span::<tally_wire::clocks::Judged>()
            .ms();
        let behind = tally_wire::budget::FEEDER_BEHIND
            .span::<tally_wire::clocks::Judged>()
            .ms();
        // One session for every batch: a refusal of any would end it.
        let refusal = Arc::new(crate::ingest::Refusal::default());
        let fed = |sequence: u64, wall_ms: u64| -> Result<(bool, bool), String> {
            let batch = signed_batch_at(&receiver, sequence, Vec::new(), wall_ms)?;
            // In step with this relay until this batch, so a drift is told.
            refusal.in_step();
            let in_flight = hub.in_flight_for(&batch);
            let kept = hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Feeder(None, None, None),
                verify: true,
                stamp: Some(Stamp::recorded(BASE_MS, sequence, BASE_MS, BASE_MS, true)),
                arrived: None,
                in_flight,
                refusal: Some(Arc::clone(&refusal)),
            });
            Ok((kept, refusal.take_drift()))
        };
        // Ahead past the tolerance, a little and an hour: held, unused, its clock told again.
        assert_eq!(fed(0, BASE_MS + tolerance + 1_000)?, (false, true));
        assert_eq!(fed(1, BASE_MS + 3_600_000)?, (false, true));
        assert_eq!(fed(2, BASE_MS + tolerance)?, (true, true));
        // Held too long: not taken, late, never refused; its feeder, in step until then, is told
        // the relay's clock again, so a host clock stepped back recovers (`Refusal::take_drift`).
        assert_eq!(fed(3, BASE_MS - behind - 1_000)?, (false, true));
        // A feeder back from a five-minute backoff, its whole backlog that old: none refused.
        for sequence in 4..68 {
            assert_eq!(
                fed(sequence, BASE_MS - 300_000 + sequence * 1_000)?,
                (false, true)
            );
        }
        assert_eq!(fed(68, BASE_MS - behind)?, (true, true));
        assert_eq!(fed(69, BASE_MS - 1_000)?, (true, false));
        // A reconnect's backlog, then a batch signed now, before the next heartbeat asks: a wait,
        // no drift, so the clock is not stated again (to an old feeder that restarts its pace).
        let session = Arc::new(crate::ingest::Refusal::default());
        session.in_step();
        for (sequence, wall_ms) in [(70, BASE_MS - 200_000), (71, BASE_MS - 100), (72, BASE_MS)] {
            let batch = signed_batch_at(&receiver, sequence, Vec::new(), wall_ms)?;
            let in_flight = hub.in_flight_for(&batch);
            hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Feeder(None, None, None),
                verify: true,
                stamp: Some(Stamp::recorded(BASE_MS, sequence, BASE_MS, BASE_MS, true)),
                arrived: None,
                in_flight,
                refusal: Some(Arc::clone(&session)),
            });
        }
        assert!(!session.take_drift(), "a backlog alone restated the clock");
        assert_eq!((refusal.now(), session.now()), (None, None));
        let report = hub.memory_report();
        assert_eq!(
            (
                report.ahead_records,
                report.unjudged_records,
                report.late_records
            ),
            (2, 2, 66)
        );
        // What it took is in its table, and nothing of the batches ahead, however far ahead they
        // were signed: possession pins no table.
        assert_eq!(hub.held_by_for_test(Deliverer::Feeder(receiver_key)), 5);
        // None is counted against its receiver: the ones too old carry none of this relay's own
        // anchors (it has no signer), and the ones ahead are counted against nobody.
        let station = hub.station(&receiver_key).ok_or("no station")?;
        assert_eq!((station.late_batches, station.batches), (0, 5));
        Ok(())
    }

    /// A hub on the relay's two clocks, scripted: the judging clock `wall` and the monotonic one
    /// `monotonic`, both in milliseconds, so a step is the one moving without the other.
    fn apart_hub(wall: &Arc<AtomicU64>, monotonic: &Arc<AtomicU64>) -> Hub {
        let (wall, monotonic) = (Arc::clone(wall), Arc::clone(monotonic));
        Hub::on(
            8,
            RelayClock::scripted_apart(
                Arc::new(move || wall.load(Ordering::Relaxed)),
                Arc::new(move || monotonic.load(Ordering::Relaxed)),
            ),
            crate::sharing::Deadlines::RELAY,
        )
    }

    /// A station's instants are timed on the monotonic clock and served as Unix times
    /// (`StationReport`'s `*_ms`, what `tally-api` serves as `*_at_ms`), so they are stated on the
    /// judging clock as the report is made. A relay started unsynced with its host's clock three
    /// hours behind, whose daemon then stepped it right: a feeder that connected before the step
    /// and fed after it is reported at true time, on the report's own `now_ms`, never three hours
    /// back. Before, the monotonic readings were served as they were, three hours behind the
    /// report's `now_ms` and every other Unix time a client reads.
    #[test]
    fn a_stations_instants_are_stated_on_the_judging_clock() -> Result<(), String> {
        let hours = 3 * 3_600_000;
        let truth = BASE_MS + hours;
        let (wall, monotonic) = (
            Arc::new(AtomicU64::new(BASE_MS)),
            Arc::new(AtomicU64::new(BASE_MS)),
        );
        let hub = Arc::new(apart_hub(&wall, &monotonic));
        hub.clock().set_error(None);
        let (receiver, receiver_key) = key()?;
        hub.opened(&receiver_key, 1, None);
        // A second on, the daemon syncs and steps the clock three hours forward.
        monotonic.fetch_add(1_000, Ordering::Relaxed);
        wall.store(truth + 1_000, Ordering::Relaxed);
        hub.clock().set_error(Some(0));
        let _ = hub.clock().read();
        assert_eq!(hub.clock().steps(), 1);
        let session = Arc::new(crate::ingest::Refusal::default());
        let (taken, _) = feed_session(&hub, &receiver, 0, truth + 1_000, &session)?;
        assert!(taken, "an honest batch after the step is used");
        monotonic.fetch_add(2_000, Ordering::Relaxed);
        wall.fetch_add(2_000, Ordering::Relaxed);
        let station = hub.station(&receiver_key).ok_or("no station")?;
        assert_eq!(
            (
                station.connected_since_ms,
                station.first_seen_ms,
                station.last_seen_ms
            ),
            (Some(truth), truth + 1_000, truth + 1_000)
        );
        let stations = hub.stations();
        assert_eq!(stations.now_ms, truth + 3_000);
        assert_eq!(stations.stations.len(), 1);
        assert_eq!(stations.stations[0].last_seen_ms, truth + 1_000);
        assert!(stations.stations[0].online);
        Ok(())
    }

    /// A feeder's batch signed at `wall_ms` on the session `session`, stamped by the hub's own
    /// clocks: whether it was taken, and whether its feeder was refused.
    fn feed_session(
        hub: &Arc<Hub>,
        receiver: &Identity,
        sequence: u64,
        wall_ms: u64,
        session: &Arc<crate::ingest::Refusal>,
    ) -> Result<(bool, bool), String> {
        let batch = signed_batch_at(receiver, sequence, Vec::new(), wall_ms)?;
        let in_flight = hub.in_flight_for(&batch);
        let kept = hub.ingest(Inbound {
            source: 1,
            batch,
            origin: Origin::Feeder(None, None, None),
            verify: true,
            stamp: Some(hub.clock().stamp(sequence)),
            arrived: None,
            in_flight,
            refusal: Some(Arc::clone(session)),
        });
        Ok((kept, session.now().is_some()))
    }

    /// RFC-0171 §3.6, signed freshness anchors: a feeder whose clock runs an hour ahead signs a
    /// batch with the fresh anchor its relay just stated. Held and passed on where it is
    /// published, unused there (ahead). Released at its signed time, it is used at no hop: its
    /// origin, a peer that was unsynced when it first passed, a brand-new hop with an empty state
    /// directory, the same hop after a kill (dropped with no dump, started again from its
    /// directory), and a hop started with no state at all: by each one's clock its anchor is an
    /// hour old. A batch signed then with an anchor of then is used at each, so the anchor alone
    /// is what keeps the first one unused. Before, usability was a mark a hop kept of a copy's
    /// first arrival, so a hop whose first copy came at its signed time had no evidence.
    #[test]
    fn a_batch_an_hour_ahead_released_at_its_time_is_used_at_no_hop() -> Result<(), String> {
        let hour = 3_600_000;
        let release = BASE_MS
            + hour
            + tally_wire::budget::FALLBACK_FLOOR
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 5_000;
        let at = Arc::new(AtomicU64::new(BASE_MS));
        let clocked = || {
            let reading = Arc::clone(&at);
            RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed)))
        };
        let member = Origin::Peer(relay(Identity::from_seed([64; 32]).public()));
        let (receiver, _) = key()?;
        // Signed an hour ahead, its anchor the relay's clock as it signed.
        let early = signed_batch_anchored(&receiver, 0, Vec::new(), release, BASE_MS)?;
        // Signed at its release, anchored then: what an honest feeder sends then.
        let in_step = |sequence: u64| {
            signed_batch_anchored(&receiver, sequence, Vec::new(), release, release)
        };
        let origin = Arc::new(Hub::on(8, clocked(), crate::sharing::Deadlines::RELAY));
        let unsynced_clock = clocked();
        unsynced_clock.set_error(None);
        let unsynced = Arc::new(Hub::on(
            8,
            unsynced_clock.clone(),
            crate::sharing::Deadlines::RELAY,
        ));
        // Its first arrival: ahead where it is published, unjudged at the unsynced peer.
        let feeder = Origin::Feeder(None, None, None);
        assert!(!feed(&origin, 1, early.clone(), feeder.clone(), BASE_MS));
        assert!(!feed(&unsynced, 77, early.clone(), member.clone(), BASE_MS));
        assert_eq!(origin.memory_report().ahead_records, 1);
        assert_eq!(unsynced.memory_report().unjudged_records, 1);
        // The peer syncs a second later, long before the release.
        at.store(BASE_MS + 1_000, Ordering::Relaxed);
        unsynced_clock.set_error(Some(5));
        unsynced.sweep_strikes();
        // A brand-new hop with an empty state directory, started an hour later, and that hop
        // killed and started again from its directory; and a hop with no state at all.
        at.store(BASE_MS + hour, Ordering::Relaxed);
        let scratch = crate::durable::tests::Scratch::new("anchored-release");
        let durable = || -> Result<Arc<Hub>, String> {
            Ok(Arc::new(
                Hub::on(8, clocked(), crate::sharing::Deadlines::RELAY)
                    .durable(crate::durable::Durable::Dir(scratch.dir()?))?,
            ))
        };
        let fresh_dir = durable()?;
        let stateless = Arc::new(Hub::on(8, clocked(), crate::sharing::Deadlines::RELAY));
        fresh_dir.sweep_strikes();
        stateless.sweep_strikes();
        at.store(release, Ordering::Relaxed);
        for hub in [&origin, &unsynced, &fresh_dir, &stateless] {
            hub.sweep_strikes();
        }
        // Released at its signed time: used nowhere, its anchor an hour old (late).
        assert!(!feed(&origin, 1, early.clone(), feeder, release));
        for hub in [&origin, &unsynced, &fresh_dir, &stateless] {
            assert!(!feed(hub, 77, early.clone(), member.clone(), release));
        }
        // An honest batch of then is used at each.
        for (sequence, hub) in [&origin, &unsynced, &fresh_dir, &stateless]
            .into_iter()
            .enumerate()
        {
            assert!(
                feed(
                    hub,
                    77,
                    in_step(1 + sequence as u64)?,
                    member.clone(),
                    release
                ),
                "hop {sequence}"
            );
        }
        // Killed (no dump) and started again from its directory: still unused there.
        drop(fresh_dir);
        let killed = durable()?;
        killed.sweep_strikes();
        assert!(!feed(&killed, 77, early, member.clone(), release));
        // A batch of then, past the floor its lease proves (what it used, and the lease's reach).
        let then = tally_wire::budget::lease_bound(release) + 1_000;
        let after = signed_batch_anchored(&receiver, 9, Vec::new(), then, then)?;
        assert!(feed(&killed, 77, after, member, then));
        Ok(())
    }

    /// RFC-0171 §3.6: a batch ahead pins nothing. A million boots of a receiver, each a batch
    /// signed a day ahead with a fresh anchor, from a member: each held unused (ahead), and the
    /// stores of what is taken hold what they held before, the member's share of them untouched,
    /// and the anchors' store its planned bytes, however many came and however far ahead. Before,
    /// each such boot pinned a mark charged to its deliverer's share until its signed time.
    #[test]
    fn a_million_boots_a_day_ahead_pin_nothing() -> Result<(), String> {
        const BOOTS: u64 = 1_000_000;
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let member_key = Identity::from_seed([65; 32]).public();
        let member = Origin::Peer(relay(member_key));
        let (receiver, _) = key()?;
        let day = 86_400_000;
        let signed = signed_batch_anchored(&receiver, 0, Vec::new(), BASE_MS + day, BASE_MS)?;
        let stores = [Store::FeederStrikes, Store::PeerStrikes, Store::OwnStrikes];
        let held = |store: Store| hub.budget().gauge(store).held();
        let before = stores.map(held);
        // Each boot its own batch: the same signed bytes but its boot (taken unverified, as a
        // link that verified it hands it on), so its own hash.
        let boot_at = 1 + tally_wire::key::KEY_LEN;
        for boot in 0..BOOTS {
            let mut bytes = signed.as_bytes().to_vec();
            bytes[boot_at..boot_at + 8].copy_from_slice(&boot.to_be_bytes());
            let batch = Batch::from_bytes(bytes).map_err(|error| error.to_string())?;
            assert!(!feed(&hub, 77, batch, member.clone(), BASE_MS));
        }
        let report = hub.memory_report();
        assert_eq!(report.ahead_records, BOOTS);
        assert_eq!(stores.map(held), before);
        assert_eq!(hub.held_by_for_test(Deliverer::Peer(member_key)), 0);
        assert_eq!(
            hub.budget().gauge(Store::Anchors).held(),
            crate::anchors::PLANNED_BYTES
        );
        Ok(())
    }

    /// The tables sized from the budget (the station rows and the descriptions at its receiver
    /// figure, the clock model parts at their room) are charged their whole plan from the start
    /// (`stations::planned_bytes`, `descriptions_planned_bytes`, `parts::planned_bytes`), and once
    /// however often the budget is resized: each at the figure the budget holds then, its tables
    /// held to it.
    #[test]
    fn a_relay_charges_its_sized_tables_once_from_the_start() -> Result<(), String> {
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        let held = |hub: &Hub, store: Store| hub.budget().gauge(store).held();
        let planned = |hub: &Hub| {
            let receivers = hub.budget().receivers();
            (
                crate::stations::planned_bytes(receivers),
                descriptions_planned_bytes(receivers),
                crate::parts::planned_bytes(hub.budget().plan().parts_room()),
            )
        };
        let charged = |hub: &Hub| {
            (
                held(hub, Store::Stations),
                held(hub, Store::Descriptions),
                held(hub, Store::Parts),
            )
        };
        assert_eq!(charged(&hub), planned(&hub));
        hub.fixed_charged()?;
        let small = hub.budget().receivers();
        let hub = hub.memory(4 << 30, false).memory(2 << 30, true);
        assert_eq!(charged(&hub), planned(&hub));
        assert_ne!(
            hub.budget().receivers(),
            small,
            "the figure did not follow the budget"
        );
        let figure = hub.budget().receivers();
        assert_eq!(
            hub.stations.lock().map_err(|e| e.to_string())?.capacity(),
            figure
        );
        assert_eq!(
            hub.receivers
                .lock()
                .map_err(|e| e.to_string())?
                .held
                .capacity(),
            figure
        );
        hub.fixed_charged()
    }

    /// A batch of `identity`'s signed at `wall_ms`, carrying `anchors` as they are.
    fn signed_with_anchors(
        identity: &Identity,
        sequence: u64,
        wall_ms: u64,
        anchors: &[tally_wire::Anchor],
    ) -> Result<Batch, String> {
        Batch::sign_anchored(
            identity,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
            tally_wire::batch::Codec::Plain,
            anchors,
        )
        .map_err(|error| error.to_string())
    }

    /// RFC-0171 §3.6: an honest feeder's batch is used at its origin at the worst the world makes
    /// it, the anchor window (`tally_wire::budget::ANCHOR_BEHIND`) no tighter than that. In true
    /// time: the feeder signs at its trusted reference's low end, `2(E + U_m)` behind true time;
    /// by an anchor heard `2P` before, at the bottom of the band an honest relay's may be below that
    /// end as it stood then (`E + P + δ`); sends it `B` after signing and `δ` on its way, to an
    /// origin whose clock is `E` ahead. Every figure a source of the world, none derived. Then an
    /// anchor exactly `W_a` old is used and one a millisecond older is held unused, blamed on
    /// nobody. In step and late after a glitch, a backlog's batches are used to the edge. Before,
    /// this test fed a batch 101 s after it was signed, which no honest feeder sends, and
    /// asserted the window equal to its own derivation.
    #[test]
    fn an_honest_batch_at_its_worst_is_used_to_the_anchor_windows_edge() -> Result<(), String> {
        use tally_wire::budget::{ANCHOR_HELD, ANCHOR_PERIOD, B, E, TRANSIT, U_M};
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let (receiver, receiver_key) = key()?;
        let relay = crate::anchors::test_relay();
        let feeder = Origin::Feeder(None, None, None);
        let truth = BASE_MS + 600_000;
        let t = truth
            - 2 * (E.span::<tally_wire::clocks::Judged>().ms()
                + U_M.span::<tally_wire::clocks::Judged>().ms());
        let anchor_ms = t
            - ANCHOR_HELD.span::<tally_wire::clocks::Judged>().ms()
            - (E.span::<tally_wire::clocks::Judged>().ms()
                + ANCHOR_PERIOD.span::<tally_wire::clocks::Judged>().ms()
                + TRANSIT.span::<tally_wire::clocks::Judged>().ms());
        let arrives = truth
            + B.span::<tally_wire::clocks::Judged>().ms()
            + TRANSIT.span::<tally_wire::clocks::Judged>().ms()
            + E.span::<tally_wire::clocks::Judged>().ms();
        let worst = signed_with_anchors(
            &receiver,
            0,
            t,
            &[tally_wire::Anchor::sign(&relay, anchor_ms)],
        )?;
        assert!(
            feed(&hub, 1, worst, feeder.clone(), arrives),
            "the worst honest batch unused"
        );
        // The window's edge: an anchor exactly `W_a` old is used, one older is not.
        let behind = crate::strikes::Window::ANCHOR
            .behind_span()
            .duration()
            .as_millis() as u64;
        let edge = signed_with_anchors(
            &receiver,
            1,
            t,
            &[tally_wire::Anchor::sign(&relay, arrives - behind)],
        )?;
        assert!(feed(&hub, 1, edge, feeder.clone(), arrives));
        let older = signed_with_anchors(
            &receiver,
            2,
            t,
            &[tally_wire::Anchor::sign(&relay, arrives - behind - 1)],
        )?;
        assert!(!feed(&hub, 1, older, feeder.clone(), arrives));
        assert_eq!(hub.memory_report().late_records, 1);
        // A backlog after a glitch: every batch of the last minute, in step, anchored as it was
        // signed, all arriving at once.
        for second in 0..60 {
            let signed = arrives - 60_000 + second * 1_000;
            let anchor = tally_wire::Anchor::sign(&relay, signed - 2_000);
            let batch = signed_with_anchors(&receiver, 3 + second, signed, &[anchor])?;
            assert!(feed(&hub, 1, batch, feeder.clone(), arrives), "{second}");
        }
        hub.stages.flush();
        assert_eq!(hub.memory_report().late_records, 1);
        let late = hub
            .station(&receiver_key)
            .map_or(0, |station| station.late_batches);
        assert_eq!(late, 0);
        Ok(())
    }

    /// RFC-0171 §3.6: an anchor an honest feeder carries is never ahead at an honest hop. Its
    /// reference's interval from true time to `2(E + U_m)` above it (`SELECTION_LAG`), it signs
    /// at the low end; a relay's anchor as far above the high end as one that agrees may be
    /// (`ANCHOR_ABOVE_REFERENCE`), and a peer `E` behind true time: the anchor is
    /// `tally_wire::budget::ANCHOR_AHEAD` ahead of the peer, and the batch is used there. A
    /// millisecond further, no relay a trusted reference agrees with could have read it, and it is
    /// held unused, blamed on nobody.
    #[test]
    fn an_agreeing_anchor_is_never_ahead_at_an_honest_hop() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let member = Origin::Peer(relay_of(93));
        let (receiver, _) = key()?;
        let error = tally_wire::budget::E
            .span::<tally_wire::clocks::Judged>()
            .ms();
        let truth = BASE_MS + 600_000;
        let feeder_ms = truth;
        let hop_ms = truth - error;
        let anchor_ms = truth
            + tally_wire::budget::SELECTION_LAG
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + tally_wire::budget::ANCHOR_ABOVE_REFERENCE
                .duration()
                .as_millis() as u64;
        assert_eq!(
            anchor_ms - hop_ms,
            tally_wire::budget::ANCHOR_AHEAD
                .span::<tally_wire::clocks::Judged>()
                .ms()
        );
        let relay = crate::anchors::test_relay();
        let edge = signed_with_anchors(
            &receiver,
            0,
            feeder_ms,
            &[tally_wire::Anchor::sign(&relay, anchor_ms)],
        )?;
        assert!(feed(&hub, 77, edge, member.clone(), hop_ms));
        let past = signed_with_anchors(
            &receiver,
            1,
            feeder_ms,
            &[tally_wire::Anchor::sign(&relay, anchor_ms + 1)],
        )?;
        assert!(!feed(&hub, 77, past, member, hop_ms));
        assert_eq!(hub.memory_report().ahead_records, 1);
        Ok(())
    }

    /// A hub taking `group`'s cell with its own signing key of seed `seed`, accepting `relays`'
    /// anchors, `receiver`'s description published to it: a hop of a sharing group whose
    /// possession a test can see.
    fn group_hop(
        seed: u8,
        info: &ReceiverInfo,
        receiver_key: PublicKey,
        place: Location,
        group: crate::sharing::groups::GroupKey,
        relays: &[PublicKey],
    ) -> Arc<Hub> {
        let hub = Arc::new(
            stamped_hub(8, crate::sharing::Deadlines::RELAY)
                .taking(vec![group.cell])
                .accepting_relays(relays.iter().copied()),
        );
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([seed; 32])));
        let _ = hub.network().tick(&hub, hub.stamp_now());
        hub.publish_info(1, info.clone(), receiver_key, 1, Some(place), false);
        hub
    }

    /// Whether `hub` holds `batch` in `group`: possessed, so its group counts it had, receipts
    /// it and passes it on.
    fn possesses(
        hub: &Arc<Hub>,
        group: crate::sharing::groups::GroupKey,
        batch: &Batch,
    ) -> Result<bool, String> {
        hub.stages.flush();
        let hash =
            crate::sharing::member::record_hash(&Record::Batch(batch.clone())).ok_or("no hash")?;
        Ok(hub
            .network()
            .sharing
            .member_for_test(|member| member.holds(group, &hash))
            .unwrap_or(false))
    }

    /// RFC-0171 §3.6: one relay states an anchor older than the window, `W_a` and more behind an
    /// honest one. An honest feeder leaves it out (it disagrees with its clock by more than an honest
    /// relay's can, `tally_feed`'s `RelayClocks::anchors`), so its batch carries the honest anchor
    /// alone and is used where it is published and at a peer. A feeder that carried it anyway
    /// would have its batch held unused at both hops, possessed in its group where it was
    /// published (so passed on, no batch lost to the network), and blamed on nobody: a stale or ahead anchor is never its receiver's lateness, so
    /// `late_batches` does not move; nor does it on the same batch arriving again. Before, the
    /// stale anchor counted the batch late against its receiver.
    #[test]
    fn a_lying_relays_old_anchor_blames_no_one_and_loses_nothing() -> Result<(), String> {
        let liar = Identity::from_seed([90; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let honest = crate::anchors::test_relay();
        let relays = [liar.public(), honest.public()];
        let origin = group_hop(91, &info, receiver_key, place, group, &relays);
        let peer = group_hop(92, &info, receiver_key, place, group, &relays);
        let member = Origin::Peer(relay(Identity::from_seed([91; 32]).public()));
        let feeder = Origin::Feeder(None, None, None);
        let late = |hub: &Arc<Hub>| {
            hub.station(&receiver_key)
                .map_or(0, |station| station.late_batches)
        };
        let now = BASE_MS;
        let fresh = tally_wire::Anchor::sign(&honest, now);
        let stale = tally_wire::Anchor::sign(
            &liar,
            now - crate::strikes::Window::ANCHOR
                .behind_span()
                .duration()
                .as_millis() as u64
                - 1_000,
        );
        // What an honest feeder carries: the honest anchor alone. Used at both hops.
        let carried = signed_with_anchors(&receiver, 0, now, &[fresh])?;
        assert!(feed(&origin, 1, carried.clone(), feeder.clone(), now));
        assert!(feed(&peer, 77, carried, member.clone(), now));
        // Had it carried the stale one too: unused at both, held at both, blamed on nobody,
        // however often it comes.
        let poisoned = signed_with_anchors(&receiver, 1, now, &[fresh, stale])?;
        for _ in 0..3 {
            assert!(!feed(
                &origin,
                1,
                poisoned.clone(),
                feeder.clone(),
                now + 100
            ));
            assert!(!feed(
                &peer,
                77,
                poisoned.clone(),
                member.clone(),
                now + 100
            ));
        }
        assert!(possesses(&origin, group, &poisoned)?);
        // The liar states one in the future instead: ahead, held, blamed on nobody.
        let future = tally_wire::Anchor::sign(&liar, now + 3_600_000);
        let ahead = signed_with_anchors(&receiver, 2, now, &[future])?;
        assert!(!feed(&origin, 1, ahead.clone(), feeder, now + 200));
        assert!(possesses(&origin, group, &ahead)?);
        assert_eq!((late(&origin), late(&peer)), (0, 0));
        Ok(())
    }

    /// RFC-0171 §3.6: a known relay's anchor can only make a batch less usable, and a lie or an
    /// anchor this hop cannot check costs nobody blame and the network nothing. A feeder an hour
    /// ahead whose one relay states a clock an hour ahead too, beside an honest anchor of then:
    /// the honest one decides, and it is unused at its release. Both fresh: used. An old anchor
    /// beside a fresh one makes it unused sooner. An anchor that does not verify, or of a relay
    /// nobody accepted, is no evidence: beside an honest one it changes nothing, alone it leaves
    /// the batch unanchored. Every batch is possessed where its feeder published it, and none is
    /// blamed on its receiver.
    #[test]
    fn a_lying_relays_anchor_never_makes_a_batch_usable() -> Result<(), String> {
        let liar = Identity::from_seed([66; 32]);
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let honest = crate::anchors::test_relay();
        let hub = group_hop(
            67,
            &info,
            receiver_key,
            place,
            group,
            &[liar.public(), honest.public()],
        );
        let feeder = Origin::Feeder(None, None, None);
        let hour = 3_600_000;
        let release = BASE_MS + hour;
        let mut batches = Vec::new();
        let mut judged = |anchors: &[tally_wire::Anchor], at: u64| -> Result<bool, String> {
            let batch = signed_with_anchors(&receiver, batches.len() as u64, release, anchors)?;
            batches.push(batch.clone());
            Ok(feed(&hub, 1, batch, feeder.clone(), at))
        };
        let early = [
            tally_wire::Anchor::sign(&honest, BASE_MS),
            tally_wire::Anchor::sign(&liar, release),
        ];
        assert!(!judged(&early, release)?);
        let both = [
            tally_wire::Anchor::sign(&honest, release),
            tally_wire::Anchor::sign(&liar, release),
        ];
        assert!(judged(&both, release)?);
        let aged = [
            tally_wire::Anchor::sign(&honest, release),
            tally_wire::Anchor::sign(
                &liar,
                release
                    - crate::strikes::Window::ANCHOR
                        .behind_span()
                        .duration()
                        .as_millis() as u64
                    - 1,
            ),
        ];
        assert!(!judged(&aged, release)?);
        assert_eq!(hub.memory_report().late_records, 2);
        // A forged anchor (its reading moved) and one of a relay nobody accepted: alone,
        // unanchored; beside an honest one, nothing.
        let mut forged = tally_wire::Anchor::sign(&honest, release);
        forged.j_ms += 1;
        let stranger = tally_wire::Anchor::sign(&Identity::from_seed([68; 32]), BASE_MS);
        let fresh = tally_wire::Anchor::sign(&honest, release);
        assert!(!judged(&[forged], release)?);
        assert!(!judged(&[stranger], release)?);
        assert!(judged(&[forged, fresh], release)?);
        assert!(judged(&[stranger, fresh], release)?);
        assert_eq!(hub.memory_report().unanchored_records, 2);
        for batch in &batches {
            assert!(possesses(&hub, group, batch)?, "a batch was lost");
        }
        let late = hub
            .station(&receiver_key)
            .map_or(0, |station| station.late_batches);
        assert_eq!(late, 0);
        Ok(())
    }

    /// A feeder's clocks as `tally_feed` keeps them, on a host whose wall clock reads `wall_ms`
    /// and whose kernel reports it synced within `bound` (none: unsynced), configured with
    /// `configured`; its monotonic clock reads `monotonic_ms`.
    pub(super) struct FeederClocks {
        wall: Arc<AtomicU64>,
        monotonic: Arc<AtomicU64>,
        pub(super) clocks: Arc<tally_feed::source::RelayClocks>,
    }

    impl FeederClocks {
        fn new(wall_ms: u64, bound: Option<u64>, configured: &[PublicKey]) -> Self {
            Self::at(wall_ms, 0, bound, configured)
        }

        pub(super) fn at(
            wall_ms: u64,
            monotonic_ms: u64,
            bound: Option<u64>,
            configured: &[PublicKey],
        ) -> Self {
            let wall = Arc::new(AtomicU64::new(wall_ms));
            let monotonic = Arc::new(AtomicU64::new(monotonic_ms));
            let host = tally_feed::source::HostClock {
                synced: Arc::new(move || bound),
                ..tally_feed::source::HostClock::set_by(&wall, &monotonic)
            };
            let clocks = Arc::new(
                tally_feed::source::RelayClocks::on(host).configured(configured.iter().copied()),
            );
            Self {
                wall,
                monotonic,
                clocks,
            }
        }

        /// Both host clocks moved on by `ms`.
        pub(super) fn wait(&self, ms: u64) {
            self.wall.fetch_add(ms, Ordering::Relaxed);
            self.monotonic.fetch_add(ms, Ordering::Relaxed);
        }
    }

    /// A member's origin of key seed `seed`.
    pub(super) fn relay_of(seed: u8) -> crate::network::Asker {
        relay(Identity::from_seed([seed; 32]).public())
    }

    /// RFC-0171 §3.6, the residual, pinned so a change to it is a decision, every batch's anchors
    /// and signed time chosen by the feeder's own clocks (`tally_feed`'s `RelayClocks`). An honest
    /// feeder whose host clock is an hour ahead and unsynced is not protected:
    /// - with a configured selection, when its configured relay lies: the relay states the
    ///   feeder's wrong clock and signs anchors at it, so the honest hinted relay's anchor
    ///   disagrees with the selection and is left out (operator trust);
    /// - with no configured selection, when every relay it anchors with lies.
    ///
    /// In both, a member that holds its batch an hour and releases it at its signed time has it
    /// used. With no configured selection, one honest relay among its sessions, known at the hop,
    /// makes it unused.
    #[test]
    fn the_residual_an_honest_feeder_whose_trusted_or_every_anchoring_relay_lies()
    -> Result<(), String> {
        let liars = [Identity::from_seed([70; 32]), Identity::from_seed([72; 32])];
        let honest = crate::anchors::test_relay();
        let keys = [liars[0].public(), liars[1].public(), honest.public()];
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).accepting_relays(keys));
        let member = Origin::Peer(relay_of(71));
        let (receiver, _) = key()?;
        let release = BASE_MS + 3_600_000;
        // The feeder's batch made at `BASE_MS`, by a host that reads `release`, configured with
        // `configured`, in sessions with `relays` each anchoring at the reading they are given.
        let made = |configured: &[PublicKey],
                    relays: &[(&Identity, u64)],
                    sequence: u64|
         -> Result<(Batch, Vec<tally_wire::Anchor>), String> {
            let feeder = FeederClocks::new(release, None, configured);
            let sessions: Vec<_> = relays
                .iter()
                .map(|(relay, reading)| {
                    let telling = feeder.clocks.session(relay.public());
                    if configured.contains(&relay.public()) {
                        telling.stated(
                            Some(*reading),
                            Some(5),
                            feeder.clocks.stamp_ms().saturating_sub(1),
                        );
                    }
                    telling.anchored(tally_wire::Anchor::sign(*relay, *reading));
                    telling
                })
                .collect();
            let anchors = feeder.clocks.anchors();
            let batch = signed_with_anchors(&receiver, sequence, feeder.clocks.now_ms(), &anchors);
            drop(sessions);
            Ok((batch?, anchors))
        };
        // A configured relay that lies, beside an honest hinted one.
        let (trusted, anchors) = made(&keys[..1], &[(&liars[0], release), (&honest, BASE_MS)], 0)?;
        assert_eq!(anchors, [tally_wire::Anchor::sign(&liars[0], release)]);
        assert!(feed(&hub, 77, trusted, member.clone(), release));
        // No configured selection, every anchoring relay lying.
        let (every, anchors) = made(&[], &[(&liars[0], release), (&liars[1], release)], 1)?;
        assert_eq!(anchors.len(), 2);
        assert!(feed(&hub, 77, every, member.clone(), release));
        // No configured selection, one honest relay among them: caught.
        let (caught, anchors) = made(&[], &[(&liars[0], release), (&honest, BASE_MS)], 2)?;
        assert_eq!(anchors.len(), 2);
        assert!(!feed(&hub, 77, caught, member, release));
        Ok(())
    }

    /// RFC-0171 §3.6, the threat model, pinned: a malicious feeder is out of the anchors' scope.
    /// It can hold receptions it heard an hour ago and sign them now, with a fresh anchor from an
    /// honest relay, and they are used, as receptions it made up now would be: a far-ahead or a
    /// late release of its own adds it nothing it lacked. Answering it is the untrusted-feeder
    /// problem's, which MLAT and consensus answer, not the anchors'.
    #[test]
    fn a_malicious_feeder_is_out_of_the_anchors_scope() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let (receiver, _) = key()?;
        let now = BASE_MS + 3_600_000;
        let fresh = tally_wire::Anchor::sign(&crate::anchors::test_relay(), now);
        // Receptions an hour old, signed as of now: indistinguishable from fresh ones.
        let replayed = signed_with_anchors(&receiver, 0, now, &[fresh])?;
        assert!(feed(
            &hub,
            1,
            replayed,
            Origin::Feeder(None, None, None),
            now
        ));
        Ok(())
    }

    /// RFC-0171 §3.6: a feeder's batch too old by its signed time where it publishes is blamed on
    /// its receiver once, when it first comes: the same batch sent again (a resend, an audit's
    /// owed batch) is judged as ever, unused, and not blamed again, nor is an earlier one of the
    /// same boot first seen after a later one. Before, each copy counted again.
    #[test]
    fn a_late_batch_is_blamed_once_however_often_it_comes() -> Result<(), String> {
        let now = BASE_MS + 600_000;
        let (hub, own) = aged_own_anchor(96, now)?;
        let (receiver, receiver_key) = key()?;
        let feeder = Origin::Feeder(None, None, None);
        let old = now
            - tally_wire::budget::FEEDER_BEHIND
                .span::<tally_wire::clocks::Judged>()
                .ms()
            - 1;
        let batch = |sequence: u64| signed_with_anchors(&receiver, sequence, old, &[own]);
        let late = || {
            hub.station(&receiver_key)
                .map_or(0, |station| station.late_batches)
        };
        let fifth = batch(5)?;
        for _ in 0..3 {
            assert!(!feed(&hub, 1, fifth.clone(), feeder.clone(), now));
            hub.stages.flush();
        }
        assert_eq!(late(), 1);
        // An earlier one of the boot, first seen after it: not blamed.
        assert!(!feed(&hub, 1, batch(4)?, feeder.clone(), now));
        assert_eq!(late(), 1);
        // A later one: blamed, once.
        let sixth = batch(6)?;
        assert!(!feed(&hub, 1, sixth.clone(), feeder.clone(), now));
        assert!(!feed(&hub, 1, sixth, feeder.clone(), now));
        assert_eq!(late(), 2);
        // Its feeder restarted: the new boot's first batch is blamed whatever its sequence, and
        // the new boot is then the last judged.
        let rebooted = Batch::sign_anchored(
            &receiver,
            &BatchContent {
                boot_id: 2,
                sequence: 1,
                counter_epoch: 0,
                wall_ms: old,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
            tally_wire::batch::Codec::Plain,
            &[own],
        )
        .map_err(|error| error.to_string())?;
        assert!(!feed(&hub, 1, rebooted.clone(), feeder.clone(), now));
        assert!(!feed(&hub, 1, rebooted, feeder, now));
        assert_eq!(late(), 3);
        // Every copy is still counted relay-wide, against nobody.
        assert_eq!(hub.memory_report().late_records, 8);
        Ok(())
    }

    /// RFC-0171 §3.6, the twenty-third sweep's finding 2: whether the clock judged is the stamp's,
    /// read with its readings, never the clock read again as the batch is admitted. A feeder's
    /// batch too old by its signed time, stamped while the relay's clock did not judge and
    /// admitted just after the clock synced, is unjudged and its receiver is never blamed; the
    /// same batch's successor stamped once the clock judges is blamed. Before, the judging bit
    /// was read at admit time, so the synced clock blamed a batch stamped before it judged.
    #[test]
    fn a_batch_stamped_before_the_clock_judged_is_never_blamed_though_it_judges_at_admit()
    -> Result<(), String> {
        let now = BASE_MS + 600_000;
        let oldest = tally_wire::budget::OWN_ANCHOR_OLDEST
            .span::<tally_wire::clocks::Judged>()
            .ms();
        let truth = Arc::new(AtomicU64::new(now - oldest - 1_000));
        let reading = Arc::clone(&truth);
        let clock = RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed)));
        let hub = Arc::new(Hub::on(8, clock.clone(), crate::sharing::Deadlines::RELAY));
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([97; 32])));
        hub.begin_strikes();
        // Its own anchor, older than an honest batch's by the time the batches come.
        let own = hub.anchor().ok_or("no anchor issued")?;
        truth.store(now, Ordering::Relaxed);
        let (receiver, receiver_key) = key()?;
        let old = now
            - tally_wire::budget::FEEDER_BEHIND
                .span::<tally_wire::clocks::Judged>()
                .ms()
            - 1;
        let batch = |sequence: u64| signed_with_anchors(&receiver, sequence, old, &[own]);
        let late = || {
            hub.station(&receiver_key)
                .map_or(0, |station| station.late_batches)
        };
        let admit = |batch: Batch, stamp: Stamp| {
            let in_flight = hub.in_flight_for(&batch);
            hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Feeder(None, None, None),
                verify: false,
                stamp: Some(stamp),
                arrived: None,
                in_flight,
                refusal: None,
            })
        };
        clock.set_error(None);
        let unsynced = hub.stamp_now();
        assert!(!unsynced.judging());
        // Synced just after the stamp, before the batch is admitted.
        clock.set_error(Some(5));
        assert!(hub.clock().judging());
        assert!(!admit(batch(5)?, unsynced));
        hub.stages.flush();
        assert_eq!(
            late(),
            0,
            "blamed by a stamp taken while the clock did not judge"
        );
        assert_eq!(hub.memory_report().unjudged_records, 1);
        assert!(!admit(batch(6)?, hub.stamp_now()));
        hub.stages.flush();
        assert_eq!(late(), 1);
        Ok(())
    }

    /// A hub of signing key `seed` whose clocks read `now`, and the anchor it issued a second past
    /// `OWN_ANCHOR_OLDEST` before: the own anchor of a batch too old by it, so a batch too old by
    /// its signed time that carries it is blamed (`strikes::blame`).
    fn aged_own_anchor(seed: u8, now: u64) -> Result<(Arc<Hub>, tally_wire::Anchor), String> {
        let oldest = tally_wire::budget::OWN_ANCHOR_OLDEST
            .span::<tally_wire::clocks::Judged>()
            .ms();
        let truth = Arc::new(AtomicU64::new(now - oldest - 1_000));
        let hub = issuing_hub(seed, &truth);
        let own = hub.anchor().ok_or("no anchor issued")?;
        truth.store(now, Ordering::Relaxed);
        Ok((hub, own))
    }

    /// A hub whose clocks are all `truth`'s, its own signing key of seed `seed`: one that issues
    /// its own anchors ([`Hub::anchor`]) at the times a test sets, and so remembers them.
    fn issuing_hub(seed: u8, truth: &Arc<AtomicU64>) -> Arc<Hub> {
        let reading = Arc::clone(truth);
        let hub = Arc::new(Hub::on(
            8,
            RelayClock::scripted(Arc::new(move || reading.load(Ordering::Relaxed))),
            crate::sharing::Deadlines::RELAY,
        ));
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([seed; 32])));
        hub
    }

    /// RFC-0171 §3.6: a batch its feeder held waiting for its first anchor is never blamed for the
    /// hold, and the blame is the origin's own, by its own anchor alone. Gathered at `t`, held a
    /// minute before this relay issued its first anchor, then stalled on its way, arriving 6 s
    /// past `FEEDER_BEHIND` after `t`: too old by `t`, so unused, but blamed on nobody, since this
    /// relay timed its own anchor's issue and it was a minute after `t`. A batch sent at once and
    /// as late is blamed as ever. Another relay's anchor moves nothing either way: a newer one
    /// beside an old own one does not excuse it, and an older one beside a new own one does not
    /// blame it; one alone, without this relay's, is never blamed, since an honest backlog
    /// anchored by another relay is such a batch. An anchor in this relay's name it does not
    /// remember issuing (an earlier run's, or one its ring let go) is aged from this run's first
    /// issue, or the newest one the ring let go, which it was issued no later than
    /// (`anchors::Anchors::issued_by`): so it is aged, never overstated, and blamed by that age.
    #[test]
    fn a_batch_held_for_its_anchor_is_not_blamed_for_the_hold() -> Result<(), String> {
        let t = BASE_MS + 600_000;
        let truth = Arc::new(AtomicU64::new(t - 1_000));
        let hub = issuing_hub(94, &truth);
        let (receiver, receiver_key) = key()?;
        let feeder = Origin::Feeder(None, None, None);
        let other = crate::anchors::test_relay();
        let sent_own = hub.anchor().ok_or("no anchor issued")?;
        truth.store(t + 60_000, Ordering::Relaxed);
        let held_own = hub.anchor().ok_or("no anchor issued")?;
        let arrives = t
            + tally_wire::budget::FEEDER_BEHIND
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 6_000;
        truth.store(arrives, Ordering::Relaxed);
        let blamed = |sequence: u64, anchors: &[tally_wire::Anchor]| -> Result<bool, String> {
            let before = hub
                .station(&receiver_key)
                .map_or(0, |station| station.late_batches);
            let batch = signed_with_anchors(&receiver, sequence, t, anchors)?;
            assert!(!feed(&hub, 1, batch, feeder.clone(), arrives));
            hub.stages.flush();
            let after = hub
                .station(&receiver_key)
                .map_or(0, |station| station.late_batches);
            Ok(after > before)
        };
        let new_other = tally_wire::Anchor::sign(&other, t + 60_000);
        let old_other = tally_wire::Anchor::sign(&other, t - 1_000);
        let never_issued = tally_wire::Anchor::sign(&Identity::from_seed([94; 32]), t + 59_000);
        assert!(!blamed(0, &[held_own])?, "blamed for the hold");
        assert!(blamed(1, &[sent_own])?, "a stall not blamed");
        assert!(
            blamed(2, &[sent_own, new_other])?,
            "another relay's anchor excused it"
        );
        assert!(
            !blamed(3, &[held_own, old_other])?,
            "another relay's anchor blamed it"
        );
        assert!(
            !blamed(4, &[new_other])?,
            "blamed with no anchor of this relay's"
        );
        assert!(
            blamed(5, &[never_issued])?,
            "an own anchor this relay does not remember issuing excused it"
        );
        Ok(())
    }

    /// RFC-0171 §3.6: the origin's own anchor is aged as its batch arrived (`ingest::Stamp::
    /// raw_ms`, read before any queue), never as a worker gets to it. A staged relay's ingest
    /// worker is held up 5 s on the raw clock between a batch's arrival and its judging (a queue
    /// behind a busy shard): a batch whose own anchor was a second inside `OWN_ANCHOR_OLDEST` as it
    /// arrived is not blamed, and one a second past it is. Before, the age was read as the batch
    /// was judged, so the queue aged it past the allowance and its honest feeder was blamed.
    #[test]
    fn a_batch_queued_before_its_judging_is_aged_as_it_arrived() -> Result<(), String> {
        use tally_wire::budget::{FEEDER_BEHIND, OWN_ANCHOR_OLDEST};
        let t = BASE_MS + 600_000;
        let truth = Arc::new(AtomicU64::new(
            t + FEEDER_BEHIND.span::<tally_wire::clocks::Judged>().ms() + 6_000,
        ));
        let raw = Arc::new(AtomicU64::new(BASE_MS));
        let (judging, monotonic, raw_reading) =
            (Arc::clone(&truth), Arc::clone(&truth), Arc::clone(&raw));
        let hub = Hub::on(
            8,
            RelayClock::scripted_raw(
                Arc::new(move || judging.load(Ordering::Relaxed)),
                Arc::new(move || monotonic.load(Ordering::Relaxed)),
                Arc::new(move || raw_reading.load(Ordering::Relaxed)),
            ),
            crate::sharing::Deadlines::RELAY,
        );
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([95; 32])));
        let queued = Arc::clone(&raw);
        let pause: Pause = Arc::new(move |stage| {
            if stage == Stage::Ingest {
                queued.fetch_add(5_000, Ordering::Relaxed);
            }
        });
        let threads = crate::ingest::Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        };
        let hub = Arc::new(hub.staged_pausing(threads, Some(pause))?);
        let own = hub.anchor().ok_or("no anchor issued")?;
        let issued = raw.load(Ordering::Relaxed);
        let (receiver, receiver_key) = key()?;
        let blamed = |sequence: u64, age_ms: u64| -> Result<bool, String> {
            let late = |hub: &Arc<Hub>| {
                hub.station(&receiver_key)
                    .map_or(0, |station| station.late_batches)
            };
            let before = late(&hub);
            raw.store(issued + age_ms, Ordering::Relaxed);
            let batch = signed_with_anchors(&receiver, sequence, t, &[own])?;
            let in_flight = hub.in_flight_for(&batch);
            hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Feeder(None, None, None),
                verify: false,
                stamp: None,
                arrived: None,
                in_flight,
                refusal: None,
            });
            hub.stages.flush();
            Ok(late(&hub) > before)
        };
        assert!(
            !blamed(
                0,
                OWN_ANCHOR_OLDEST.span::<tally_wire::clocks::Judged>().ms() - 1_000
            )?,
            "aged by its queue"
        );
        assert!(
            blamed(
                1,
                OWN_ANCHOR_OLDEST.span::<tally_wire::clocks::Judged>().ms() + 1_000
            )?,
            "an old own anchor not blamed"
        );
        Ok(())
    }

    /// A batch carrying two of the origin's own anchors is aged by the younger: its feeder heard
    /// that one last, so the batch was signed no earlier than it. One whose older anchor is past
    /// `OWN_ANCHOR_OLDEST` as it arrives, and whose younger is inside it, is not blamed; the same
    /// batch with the older alone is. Before, taking the older would blame an honest feeder that
    /// carried both.
    #[test]
    fn a_batch_is_aged_by_the_younger_of_its_own_anchors() -> Result<(), String> {
        use tally_wire::budget::{ANCHOR_PERIOD, OWN_ANCHOR_OLDEST};
        let start = BASE_MS + 600_000;
        let truth = Arc::new(AtomicU64::new(start));
        let (judging, monotonic, raw) =
            (Arc::clone(&truth), Arc::clone(&truth), Arc::clone(&truth));
        let hub = Arc::new(Hub::on(
            8,
            RelayClock::scripted_raw(
                Arc::new(move || judging.load(Ordering::Relaxed)),
                Arc::new(move || monotonic.load(Ordering::Relaxed)),
                Arc::new(move || raw.load(Ordering::Relaxed)),
            ),
            crate::sharing::Deadlines::RELAY,
        ));
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([96; 32])));
        let older = hub.anchor().ok_or("no anchor issued")?;
        truth.store(
            start + 2 * ANCHOR_PERIOD.span::<tally_wire::clocks::Judged>().ms(),
            Ordering::Relaxed,
        );
        let younger = hub.anchor().ok_or("no anchor issued")?;
        assert_ne!(older.j_ms, younger.j_ms);
        // The older a half second past the allowance as the batches arrive; the younger inside it.
        let arrives = start + OWN_ANCHOR_OLDEST.span::<tally_wire::clocks::Judged>().ms() + 500;
        truth.store(arrives, Ordering::Relaxed);
        let t = start - 3_600_000;
        let (receiver, receiver_key) = key()?;
        let blamed = |sequence: u64, anchors: &[tally_wire::Anchor]| -> Result<bool, String> {
            let late = |hub: &Arc<Hub>| {
                hub.station(&receiver_key)
                    .map_or(0, |station| station.late_batches)
            };
            let before = late(&hub);
            let batch = signed_with_anchors(&receiver, sequence, t, anchors)?;
            assert!(!feed(
                &hub,
                1,
                batch,
                Origin::Feeder(None, None, None),
                arrives
            ));
            hub.stages.flush();
            Ok(late(&hub) > before)
        };
        assert!(
            !blamed(0, &[older, younger])?,
            "aged by its older own anchor"
        );
        assert!(
            blamed(1, &[older])?,
            "its older own anchor alone not blamed"
        );
        Ok(())
    }

    /// RFC-0171 §3.6 (`tally_wire::budget::OWN_ANCHOR_OLDEST`): blame at the origin is reckoned on
    /// the age of its own anchor as its raw monotonic clock timed it, so whatever a daemon does to
    /// its judging clock meanwhile, an honest feeder is never blamed. The origin's clock is slewed
    /// from 5 s behind to true time over 69 s (chrony's fastest rate makes that in seconds; this
    /// is the whole of it), and stepped by `E` either way halfway, its monotonic clock slewed
    /// with it and not stepped. A feeder with no reference, its host an hour behind, signs by the
    /// origin's anchor and sends the batch `B + δ` later, the longest an honest feeder takes: never
    /// blamed. Before, the age was read as `J - A`, which the slew and a forward step stretched
    /// past the allowance, and the feeder was blamed.
    #[test]
    fn the_origins_slewing_or_stepping_clock_blames_no_honest_feeder() -> Result<(), String> {
        use tally_wire::budget::{B, E, TRANSIT};
        for step in [
            0_i64,
            (E.span::<tally_wire::clocks::Judged>().ms()) as i64,
            -((E.span::<tally_wire::clocks::Judged>().ms()) as i64),
        ] {
            let start = BASE_MS as i64 + 600_000;
            let truth = Arc::new(AtomicU64::new(start as u64));
            // Slewed from 5 s behind to true time over 69 s, then stepped by `step` at 35 s.
            let slew = move |at: i64| {
                let into = (at - start).clamp(0, 69_000);
                -5_000 + 5_000 * into / 69_000
            };
            let (judging, monotonic, raw) =
                (Arc::clone(&truth), Arc::clone(&truth), Arc::clone(&truth));
            let hub = Arc::new(Hub::on(
                8,
                RelayClock::scripted_raw(
                    Arc::new(move || {
                        let at = judging.load(Ordering::Relaxed) as i64;
                        let stepped = if at - start >= 35_000 { step } else { 0 };
                        (at + slew(at) + stepped) as u64
                    }),
                    Arc::new(move || {
                        let at = monotonic.load(Ordering::Relaxed) as i64;
                        (at + slew(at)) as u64
                    }),
                    Arc::new(move || raw.load(Ordering::Relaxed)),
                ),
                crate::sharing::Deadlines::RELAY,
            ));
            hub.network()
                .adopt_identity(crate::signer::twin(&Identity::from_seed([95; 32])));
            let (receiver, receiver_key) = key()?;
            let anchor = hub.anchor().ok_or("no anchor issued")?;
            let t = (start - 3_600_000) as u64;
            let batch = signed_with_anchors(&receiver, 0, t, &[anchor])?;
            let arrives = start
                + (B.span::<tally_wire::clocks::Judged>().ms()
                    + TRANSIT.span::<tally_wire::clocks::Judged>().ms()) as i64;
            truth.store(arrives as u64, Ordering::Relaxed);
            let judged = hub.clock.judged().ms();
            assert!(!feed(
                &hub,
                1,
                batch,
                Origin::Feeder(None, None, None),
                judged
            ));
            hub.stages.flush();
            let late = hub
                .station(&receiver_key)
                .map_or(0, |station| station.late_batches);
            assert_eq!(late, 0, "an honest feeder blamed (step {step} ms)");
        }
        Ok(())
    }

    /// RFC-0171 §3.6: a batch with no anchor (an older feeder's format, or one signed before its
    /// feeder had any), or of a format this build cannot read (whose anchors it cannot check), is
    /// possessed as every batch is: held in its group, so its group counts it had and receipts it,
    /// and passed on down its stripe raw; and never used here, counted apart
    /// (`unanchored_records`), never against its receiver.
    #[test]
    fn an_unanchored_batch_is_held_and_receipted_but_never_used() -> Result<(), String> {
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let hub =
            Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY).taking(vec![group.cell]));
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([72; 32])));
        let _ = hub.network().tick(&hub, hub.stamp_now());
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        let content = BatchContent {
            boot_id: 1,
            sequence: 0,
            counter_epoch: 0,
            wall_ms: BASE_MS,
            dropped: 0,
            previous: [0; 32],
            observations: Vec::new(),
        };
        let legacy = Batch::sign(&receiver, &content).map_err(|error| error.to_string())?;
        let none = Batch::sign_anchored(
            &receiver,
            &BatchContent {
                sequence: 1,
                ..content.clone()
            },
            tally_wire::batch::Codec::Plain,
            &[],
        )
        .map_err(|error| error.to_string())?;
        // A format this build does not read: the same fixed prefix, an unknown format byte.
        let mut unread = Batch::sign(
            &receiver,
            &BatchContent {
                sequence: 2,
                ..content
            },
        )
        .map_err(|error| error.to_string())?
        .as_bytes()
        .to_vec();
        unread[0] = 0xEE;
        assert!(!tally_wire::batch::BATCH_FORMATS.contains(&unread[0]));
        let unread = Batch::from_bytes(unread).map_err(|error| error.to_string())?;
        for batch in [legacy, none, unread] {
            let hash = crate::sharing::member::record_hash(&Record::Batch(batch.clone()))
                .ok_or("no hash")?;
            assert!(!feed(
                &hub,
                1,
                batch,
                Origin::Feeder(None, None, None),
                BASE_MS
            ));
            hub.stages.flush();
            assert!(
                hub.network()
                    .sharing
                    .member_for_test(|member| member.holds(group, &hash))
                    .unwrap_or(false),
                "not held in its group"
            );
        }
        let report = hub.memory_report();
        assert_eq!((report.unanchored_records, report.late_records), (3, 0));
        assert_eq!(report.malformed_batches, 0);
        let late = hub
            .station(&receiver_key)
            .map_or(0, |station| station.late_batches);
        assert_eq!(late, 0);
        Ok(())
    }

    /// A feeder's batch signed at `wall_ms` on a session of its own that was stated nothing.
    fn feed_feeder_at(
        hub: &Arc<Hub>,
        receiver: &Identity,
        sequence: u64,
        wall_ms: u64,
    ) -> Result<(bool, bool), String> {
        let session = Arc::new(crate::ingest::Refusal::default());
        feed_session(hub, receiver, sequence, wall_ms, &session)
    }

    /// RFC-0171 §3.6: what the relay keeps of a feeder's batch, its place in its sharing group
    /// and its delivery tag (what a delivery check is answered from), is kept by the monotonic
    /// clock: a step of the judging clock a minute back keeps neither past its window. A batch a
    /// second, the judging clock stepped back a minute after thirty: every batch is seeded and
    /// tagged, held unused while it is ahead; a horizon after the step, by the monotonic clock,
    /// the group holds none from before it; and the tags held never pass a window's batches.
    /// Before, both were kept by the judging clock, a minute too long after a step back, so a
    /// store planned on the window overfilled and batches went unseeded and untagged, and a
    /// feeder's audit of them failed.
    #[test]
    fn a_step_back_keeps_no_batch_past_its_window_by_the_monotonic_clock() -> Result<(), String> {
        use tally_wire::delivery::TAG_WINDOW_MS;
        let monotonic = Arc::new(AtomicU64::new(BASE_MS));
        let wall = Arc::new(AtomicU64::new(BASE_MS));
        let (receiver, receiver_key) = key()?;
        let (info, place, group) = located(&receiver)?;
        let hub = Arc::new(apart_hub(&wall, &monotonic).taking(vec![group.cell]));
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([44; 32])));
        let _ = hub.network().tick(&hub, hub.stamp_now());
        hub.publish_info(1, info, receiver_key, 1, Some(place), false);
        let session = Arc::new(crate::ingest::Refusal::default());
        let horizon_s = crate::sharing::Deadlines::RELAY.horizon_seconds();
        let window_s = TAG_WINDOW_MS / 1000;
        let mut before_step = Vec::new();
        for second in 0..window_s + 60 {
            let real = BASE_MS + second * 1_000;
            monotonic.store(real, Ordering::Relaxed);
            wall.store(
                if second >= 30 { real - 60_000 } else { real },
                Ordering::Relaxed,
            );
            let batch = signed_batch_at(&receiver, second, Vec::new(), real)?;
            let hash =
                crate::sharing::member::record_hash(&Record::Batch(batch)).ok_or("no hash")?;
            let _ = feed_session(&hub, &receiver, second, real, &session)?;
            hub.stages.flush();
            let _ = hub.network().tick(&hub, hub.stamp_now());
            let holds = |hash: &tally_wire::batch::Hash| {
                hub.network()
                    .sharing
                    .member_for_test(|member| member.holds(group, hash))
                    .unwrap_or(false)
            };
            assert!(holds(&hash), "second {second}: unseeded");
            if second < 30 {
                before_step.push(hash);
            }
            if second == 30 + horizon_s + 2 {
                assert!(
                    !before_step.iter().any(holds),
                    "held past its horizon by the monotonic clock"
                );
            }
            let tags = hub.network().delivery.tags() as u64;
            assert!(
                tags <= window_s + 2,
                "second {second}: {tags} tags held in a window of {window_s}"
            );
        }
        Ok(())
    }

    /// RFC-0171 §3.6: a step of the host's clock, an hour either way, held for fifty seconds and
    /// stepped back, ends nothing and makes nothing new twice. The relay judges by the host's
    /// clock as it is (`clock::RelayClock`), so a feeder signing by real time is too old or too
    /// far ahead to use while the step lasts: held and never refused, since nothing is refused
    /// for a clock. Too old (a step ahead) is counted late; ahead (a step back) is held unused
    /// and counted against nobody. Both steps are seen; a batch taken before is no new record
    /// after, whether the step forward dropped it from its table (raising the
    /// floor past it) or the step back left it held. Before, a step was slewed in the relay and
    /// ended it once it had stayed.
    #[test]
    fn a_step_either_way_ends_nothing_refuses_no_one_and_makes_nothing_new_twice()
    -> Result<(), String> {
        const HOUR_MS: i64 = 3_600_000;
        for step in [HOUR_MS, -HOUR_MS] {
            let monotonic = Arc::new(AtomicU64::new(BASE_MS));
            let wall = Arc::new(AtomicU64::new(BASE_MS));
            let hub = Arc::new(apart_hub(&wall, &monotonic));
            let (receiver, receiver_key) = key()?;
            let session = Arc::new(crate::ingest::Refusal::default());
            let mut taken_before = None;
            for second in 0..120_u64 {
                let real = BASE_MS + second * 1_000;
                monotonic.store(real, Ordering::Relaxed);
                let stepped = (30..80).contains(&second);
                wall.store(
                    if stepped {
                        real.saturating_add_signed(step)
                    } else {
                        real
                    },
                    Ordering::Relaxed,
                );
                assert_eq!(
                    feed_session(&hub, &receiver, second, real, &session)?,
                    (!stepped, false),
                    "{step} ms step, second {second}"
                );
                if second == 25 {
                    taken_before = Some(real);
                }
                // Back in step: the batch taken before the step, again, is no new record.
                if second == 85 {
                    let signed = taken_before.ok_or("nothing taken before")?;
                    assert_eq!(
                        feed_session(&hub, &receiver, 25, signed, &session)?,
                        (false, false),
                        "{step} ms step: taken twice"
                    );
                }
            }
            assert_eq!(hub.clock().steps(), 2, "{step}");
            let report = hub.memory_report();
            let station = hub.station(&receiver_key).ok_or("no station")?;
            assert_eq!(station.batches, 70, "{step}");
            if step > 0 {
                // Stepped ahead, the relay finds real time too old: held and counted late, and
                // never blamed on the feeder, whose batches carry none of this relay's anchors
                // (it has no signer): the step is the relay's.
                assert!(report.late_records >= 50, "{step}: {report:?}");
                assert_eq!(station.late_batches, 0, "{step}");
            } else {
                // Stepped back, real time is ahead of the relay: held unused, counted against
                // nobody.
                assert_eq!(station.late_batches, 0, "{step}");
                assert!(
                    report.unjudged_records >= 50 && report.ahead_records >= 50,
                    "{step}: {report:?}"
                );
            }
        }
        Ok(())
    }

    /// RFC-0171 §3.6: everything the relay judges and signs reads its one judging clock
    /// (`clock::RelayClock`): an offer signed in step stays live in the directory, a member's
    /// manifests and receipts signed in step are taken, and the evidence this relay signs carries
    /// the receipts. The hub's time is a fixed date in the past, so a part reading any other clock
    /// (the host's, a clock of its own) would find the offer long expired and every manifest and
    /// receipt out of its window.
    #[test]
    fn offers_manifests_and_receipts_are_judged_by_the_relays_one_clock() -> Result<(), String> {
        {
            let monotonic = Arc::new(AtomicU64::new(BASE_MS));
            let wall = Arc::new(AtomicU64::new(BASE_MS));
            let me = Identity::from_seed([71; 32]);
            let member = Identity::from_seed([72; 32]);
            let (receiver, _) = key()?;
            let (_, _, group) = located(&receiver)?;
            let hub = Arc::new(apart_hub(&wall, &monotonic).taking(vec![group.cell]));
            let network = hub.network();
            network.adopt_identity(crate::signer::twin(&me));
            let _ = network.tick(&hub, hub.stamp_now());
            network.sharing.groups.admit(
                group,
                member.public(),
                crate::sharing::MonoDeadline::NEVER,
                false,
            );
            network
                .sharing
                .member_for_test(|held| {
                    let _ = held.set_members(
                        group,
                        &[me.public(), member.public()],
                        &[],
                        hub.stamp_now(),
                    );
                })
                .ok_or("no member")?;
            let offer = tally_wire::ProviderOffer::sign(
                &member,
                &tally_wire::ProviderOfferContent {
                    address: "203.0.113.7:10900".to_owned(),
                    cell: group.cell,
                    products: tally_wire::Streams::RAW,
                    stripes_of: 1,
                    stripes: 1,
                    mlat_cores: 0,
                    feeder_slots: 10,
                    network: 1,
                    issued_ms: BASE_MS,
                    expires_ms: BASE_MS + 600_000,
                },
            )
            .map_err(|error| error.to_string())?;
            network
                .directory
                .hold_verified(offer, crate::directory::Group::V4(1), hub.now())
                .map_err(|error| error.to_string())?;
            let asker = relay(member.public());
            for second in 0..120_u64 {
                let real = BASE_MS + second * 1_000;
                monotonic.store(real, Ordering::Relaxed);
                wall.store(real, Ordering::Relaxed);
                let now = hub.stamp_now();
                assert!(
                    network.directory.address_of(&member.public()).is_some(),
                    "the offer expired at {second}"
                );
                if second % 5 != 0 {
                    continue;
                }
                let manifest = tally_wire::PieceManifest::sign(
                    &member,
                    &tally_wire::PieceManifestContent {
                        cell: group.cell,
                        product: group.product,
                        second: real / 1000,
                        hashes: vec![[second as u8; 32]],
                    },
                )
                .map_err(|error| error.to_string())?;
                let _ = network.handle(&hub, &asker, Record::PieceManifest(manifest), now, None);
                let taken = network
                    .sharing
                    .member_for_test(|held| held.manifests(group, real / 1000).len())
                    .ok_or("no member")?;
                assert_eq!(taken, 1, "the manifest of {second} was refused");
                let receipt = tally_wire::StripeReceipt::sign(
                    &member,
                    &tally_wire::StripeReceiptContent {
                        parent: me.public(),
                        cell: group.cell,
                        product: group.product,
                        stripe: (second / 5 % 4) as u8,
                        stripes_of: 4,
                        first_second: real / 1000,
                        last_second: real / 1000 + 4,
                        records: 0,
                        bytes: 0,
                        digest: [0; 32],
                        issued_ms: real,
                    },
                )
                .map_err(|error| error.to_string())?;
                let _ = network.handle(&hub, &asker, Record::StripeReceipt(receipt), now, None);
            }
            let bundle = network
                .credit
                .bundle(&me, hub.now())
                .map_err(|error| error.to_string())?;
            let receipts = match bundle.evidence().map_err(|error| error.to_string())? {
                tally_wire::credit::Evidence::Carried(content) => content.receipts.len(),
                tally_wire::credit::Evidence::Referenced(content) => content.receipts.len(),
            };
            assert_eq!(receipts, 4, "receipts were refused");
        }
        Ok(())
    }

    /// RFC-0171 §3.6: whatever the relay's clock, it refuses no feeder for its own. While the
    /// host reports its clock unsynchronised (or its error past `E`) the relay judges nothing: a
    /// batch an hour ahead is held unjudged. Bounded again, the same batch an hour ahead is held
    /// unused as too far ahead, counted against nobody, and still nobody is refused. Before, a
    /// synced relay refused it.
    #[test]
    fn no_relay_refuses_a_feeder_for_its_clock_synced_or_not() -> Result<(), String> {
        let hub = Arc::new(Hub::clocked(
            8,
            Arc::new(|| BASE_MS),
            crate::sharing::Deadlines::RELAY,
        ));
        let (receiver, _) = key()?;
        hub.clock().set_error(None);
        assert_eq!(
            feed_feeder_at(&hub, &receiver, 0, BASE_MS + 3_600_000)?,
            (false, false)
        );
        assert_eq!(hub.memory_report().ahead_records, 0);
        hub.clock().set_error(Some(10));
        assert_eq!(
            feed_feeder_at(&hub, &receiver, 1, BASE_MS + 3_600_000)?,
            (false, false)
        );
        let report = hub.memory_report();
        assert_eq!((report.ahead_records, report.unjudged_records), (1, 2));
        Ok(())
    }

    /// A feeder's batch below a strike table's floor (the table having dropped a generation at a
    /// clock since stepped back) is late, never new twice, and counted (`late_records`), but
    /// against nobody: the floor is this relay's clock's doing, and only a batch too old by its
    /// own signed time where it is published is blamed on its receiver (RFC-0171 §3.6).
    #[test]
    fn a_feeders_batch_late_to_the_tables_is_blamed_on_nobody() -> Result<(), String> {
        let clock = Arc::new(AtomicU64::new(BASE_MS));
        let hub = {
            let clock = Arc::clone(&clock);
            Arc::new(Hub::clocked(
                8,
                Arc::new(move || clock.load(Ordering::Relaxed)),
                crate::sharing::Deadlines::RELAY,
            ))
        };
        let (receiver, receiver_key) = key()?;
        assert_eq!(feed_feeder_at(&hub, &receiver, 0, BASE_MS)?, (true, false));
        // An hour on, the tables are swept and their floors raised past it; then back again.
        clock.store(BASE_MS + 3_600_000, Ordering::Relaxed);
        hub.sweep_strikes();
        clock.store(BASE_MS + 1_000, Ordering::Relaxed);
        assert_eq!(feed_feeder_at(&hub, &receiver, 1, BASE_MS)?, (false, false));
        let station = hub.station(&receiver_key).ok_or("no station")?;
        assert_eq!(station.late_batches, 0);
        assert_eq!(hub.memory_report().late_records, 1);
        Ok(())
    }

    pub(super) fn feed(
        hub: &Arc<Hub>,
        source: u64,
        batch: Batch,
        origin: Origin,
        stamp_ms: u64,
    ) -> bool {
        let in_flight = hub.in_flight_for(&batch);
        hub.ingest(Inbound {
            source,
            batch,
            origin,
            verify: false,
            // Its raw clock read as it arrives, and whether the judging clock judged then, as the
            // ingest stage reads them (`ingest::Stamp`).
            stamp: Some(Stamp::recorded(
                stamp_ms,
                0,
                stamp_ms,
                hub.clock().raw().ms(),
                hub.clock().judging(),
            )),
            arrived: None,
            in_flight,
            refusal: None,
        })
    }

    /// The feeder figures judge a batch's own clock by the relay's clock, as every record's time is
    /// judged (`tally_wire::budget::Window::FIGURES`): a member's copy signed 130 s before it was
    /// stamped is past the relay's window and past what the figures count, so it is late, counted, and
    /// makes its receiver no row. In step, the same copy is taken and counted.
    #[test]
    fn the_feeder_figures_judge_a_batchs_clock_by_the_relays_clock() -> Result<(), String> {
        let peer = || -> Result<Origin, String> {
            Ok(Origin::Peer(crate::network::Asker {
                role: crate::network::AskerRole::Relay,
                key: Identity::generate()
                    .map_err(|error| error.to_string())?
                    .public(),
                source: 2,
                loopback: true,
                address: None,
            }))
        };
        let (receiver, _) = key()?;
        let batch = signed_batch(&receiver, 0, vec![observation(1)])?;
        for (ahead_ms, rows) in [(130_000, 0), (0, 1)] {
            let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
            let taken = rows == 1;
            assert_eq!(
                feed(&hub, 7, batch.clone(), peer()?, BASE_MS + ahead_ms),
                taken
            );
            assert_eq!(hub.network().figures.rows(), rows, "{ahead_ms} ms ahead");
            assert_eq!(hub.memory_report().late_records, u64::from(!taken));
        }
        Ok(())
    }

    /// A batch dropped for its receiver's pace is no batch seen: the copy a member sends of it
    /// is still new, so every relay holding the area ends with the same batches whichever one a
    /// feeder's pace happened to cut (before, the drop came after the batch was remembered, and a
    /// member's copy was refused as a duplicate).
    #[test]
    fn a_batch_dropped_for_its_receivers_pace_is_still_new_to_a_member() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let receiver = Identity::from_seed([5; 32]);
        let member = Identity::from_seed([250; 32]);
        let asker = Asker {
            role: crate::network::AskerRole::Relay,
            key: member.public(),
            source: 77,
            loopback: true,
            address: None,
        };
        let burst =
            crate::ingest::FEEDER_RECEPTIONS_PER_SEC * crate::ingest::FEEDER_RECEPTIONS_BURST_SECS;
        let per = 500usize;
        let count = burst as usize / per + 1;
        let group = Some(crate::ingest::Group::V4(1));
        let mut cut = None;
        for sequence in 0..count as u64 {
            let batch = wanted_batch(&receiver, sequence, per)?;
            let again = batch.clone();
            if !feed(&hub, 1, batch, Origin::Feeder(None, group, None), BASE_MS) {
                cut = Some(again);
            }
        }
        assert_eq!(
            hub.over_reception_ceiling().batches,
            1,
            "one batch was past the pace"
        );
        let cut = cut.ok_or("the last batch is past the receiver's pace")?;
        assert!(
            feed(&hub, 77, cut, Origin::Peer(asker), BASE_MS + 1),
            "a member's copy of a batch this relay dropped for load is new"
        );
        Ok(())
    }

    /// A receiver's ceiling charges a batch its wanted receptions whether this relay can use it or
    /// not (`Batch::wanted_receptions`, read with no decode): a feeder that has spent its ceiling
    /// keeps every batch of only unwanted receptions (Mode A/C here), usable or too old by its
    /// signed time, and none is over the ceiling. Before, a batch the relay could not use was
    /// charged every reception it carried and one it could only its wanted ones, so whether a
    /// batch was kept turned on this relay's clock.
    #[test]
    fn a_feeder_at_its_ceiling_keeps_its_unwanted_receptions_usable_or_late() -> Result<(), String>
    {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let receiver = Identity::from_seed([7; 32]);
        let feeder = || Origin::Feeder(None, Some(crate::ingest::Group::V4(1)), None);
        let burst =
            crate::ingest::FEEDER_RECEPTIONS_PER_SEC * crate::ingest::FEEDER_RECEPTIONS_BURST_SECS;
        let mut spent = 0;
        let mut sequence = 0;
        while spent < burst {
            let per = (burst - spent).min(500);
            assert!(feed(
                &hub,
                1,
                wanted_batch(&receiver, sequence, per as usize)?,
                feeder(),
                BASE_MS
            ));
            spent += per;
            sequence += 1;
        }
        assert_eq!(hub.over_reception_ceiling().batches, 0);
        let mode_ac = |n: usize| -> Vec<Observation> {
            (0..n)
                .map(|n| Observation {
                    format: tally_wire::batch::format::MODE_AC,
                    timestamp: n as u64,
                    signal: 0,
                    data: vec![(n >> 8) as u8, n as u8],
                })
                .collect()
        };
        let old = BASE_MS
            - tally_wire::budget::FEEDER_BEHIND
                .span::<tally_wire::clocks::Judged>()
                .ms()
            - 1;
        let unwanted = burst as usize + 1;
        assert!(
            feed(
                &hub,
                1,
                signed_batch(&receiver, sequence, mode_ac(unwanted))?,
                feeder(),
                BASE_MS
            ),
            "a usable batch of unwanted receptions was not kept"
        );
        assert!(!feed(
            &hub,
            1,
            signed_batch_at(&receiver, sequence + 1, mode_ac(unwanted), old)?,
            feeder(),
            BASE_MS
        ));
        assert_eq!(
            hub.memory_report().late_records,
            1,
            "the late one not held late"
        );
        assert_eq!(
            hub.over_reception_ceiling().batches,
            0,
            "a batch of unwanted receptions charged to the ceiling"
        );
        Ok(())
    }

    /// A copy of a batch this relay already kept is neither judged nor charged: a feeder that
    /// reconnects and resends its backlog spends its group's share once, and the next group's
    /// batch is not cut for the tokens the copies would have taken.
    #[test]
    fn copies_of_a_kept_batch_spend_no_share() -> Result<(), String> {
        let rate = shed::Rates {
            receptions_per_s: 3_000,
            bytes_per_s: 100_000_000,
        };
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY).admitted_rate(rate));
        let resender = Identity::from_seed([5; 32]);
        let other = Identity::from_seed([6; 32]);
        let first = wanted_batch(&resender, 0, 300)?;
        let group = Some(crate::ingest::Group::V4(1));
        assert!(feed(
            &hub,
            1,
            first.clone(),
            Origin::Feeder(None, group, None),
            BASE_MS
        ));
        for _ in 0..30 {
            assert!(!feed(
                &hub,
                1,
                first.clone(),
                Origin::Feeder(None, group, None),
                BASE_MS
            ));
        }
        let fresh = wanted_batch(&other, 0, 300)?;
        assert!(
            feed(
                &hub,
                2,
                fresh,
                Origin::Feeder(None, Some(crate::ingest::Group::V4(2)), None),
                BASE_MS
            ),
            "thirty copies took nothing from the bucket"
        );
        let report = hub.shed_report();
        assert_eq!(report.over_share.batches + report.relay_rate.batches, 0);
        Ok(())
    }

    /// A receiver this relay corroborated has a share of its own even inside a flooded group:
    /// fifty hostile keys behind one network are cut to one share while the corroborated key in
    /// the same network keeps every batch.
    #[test]
    fn a_corroborated_receiver_keeps_its_share_inside_a_flooded_group() -> Result<(), String> {
        let rate = shed::Rates {
            receptions_per_s: 1_000,
            bytes_per_s: 100_000_000,
        };
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY).admitted_rate(rate));
        let proven = Identity::from_seed([9; 32]);
        hub.network()
            .credit
            .corroborate_receiver(proven.public(), crate::sharing::Now::from(now_ms()));
        let hostile: Vec<Identity> = (0..50u8)
            .map(|n| Identity::from_seed([n + 100; 32]))
            .collect();
        let group = Some(crate::ingest::Group::V4(900));
        let mut cut_hostile = 0;
        for tick in 0..60u64 {
            let stamp_ms = BASE_MS + tick * 100;
            let batch = wanted_batch(&proven, tick, 10)?;
            assert!(
                feed(&hub, 1, batch, Origin::Feeder(None, group, None), stamp_ms),
                "the corroborated receiver's batch was cut at tick {tick}"
            );
            for (n, identity) in hostile.iter().enumerate() {
                let batch = wanted_batch(identity, tick, 100)?;
                if !feed(
                    &hub,
                    100 + n as u64,
                    batch,
                    Origin::Feeder(None, group, None),
                    stamp_ms + 1 + n as u64,
                ) {
                    cut_hostile += 1;
                }
            }
        }
        assert!(cut_hostile > 0, "the flood was cut");
        let report = hub.shed_report();
        assert!(
            report
                .sources
                .iter()
                .all(|cut| cut.source.starts_with("v4:")),
            "only the network was cut, never the corroborated key: {:?}",
            report.sources
        );
        Ok(())
    }

    /// RFC-0181 §9: a batch handed in is charged to `Store::Ingest` until the epochs hold it.
    #[test]
    fn a_batch_is_charged_until_the_epochs_hold_it() -> Result<(), String> {
        let hub = Arc::new(stamped_hub(8, crate::sharing::Deadlines::RELAY));
        let (receiver, receiver_key) = key()?;
        let ingest = hub.budget().gauge(Store::Ingest);
        let epochs = hub.budget().gauge(Store::Epochs);
        assert!(hub.publish_batch(
            1,
            signed_batch_at(
                &receiver,
                0,
                vec![Observation {
                    format: b'2',
                    timestamp: 1,
                    signal: 0,
                    data: vec![0x5d; 7],
                }],
                now_ms(),
            )?,
            receiver_key
        ));
        assert_eq!(ingest.held(), 0);
        assert!(epochs.held() > 0);
        Ok(())
    }

    #[test]
    fn descriptions_are_held_to_bytes_as_well_as_count() -> Result<(), String> {
        let mut hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        let (stranger, _) = key()?;
        let info = signed_info(&stranger)?;
        // What one description is charged, read from a relay holding just it.
        let one = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        one.publish_info(2, info.clone(), stranger.public(), 1, None, false);
        let size = one.directory.lock().map_err(|e| e.to_string())?.bytes;
        assert!(size > info.as_bytes().len());
        hub.described_as(RECEIVERS_REMEMBERED, 3 * size);
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

    /// The descriptions' tables sized to a receiver figure, churned past it by more receivers
    /// than it holds, each described with a site, allocate no more than they are charged
    /// (`descriptions_planned_bytes`, and the receivers' areas the products keep beside them,
    /// `products::located_planned_bytes`). Measured by the allocator, on this thread.
    #[test]
    fn the_descriptions_tables_stay_within_their_plan_at_a_figure() -> Result<(), String> {
        use tally_counting::Counting;
        const RECEIVERS: usize = 512;
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        hub.size_descriptions(
            RECEIVERS,
            RECEIVERS * DESCRIPTION_BYTES_PER_RECEIVER,
            RECEIVERS + 1,
        );
        let located = crate::budget::Gauge::new(Store::Located, usize::MAX);
        hub.network().products.size_located(RECEIVERS, &located);
        let described: Vec<(ReceiverInfo, PublicKey, Location)> = (0..2 * (RECEIVERS + 1) as u64)
            .map(|n| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&n.to_be_bytes());
                let receiver = Identity::from_seed(seed);
                let place = Location {
                    lat_e7: 515_000_000 + (n as i32 % 100) * 1_000_000,
                    lon_e7: -1_000_000 + (n as i32 / 100) * 1_000_000,
                    alt_m: 0,
                    precision_m: 0,
                };
                let info = ReceiverInfo::sign(
                    &receiver,
                    &ReceiverInfoContent {
                        issued_ms: 1,
                        location: Some(place),
                        clock: Clock::Dump1090,
                        software: "test".repeat(16),
                        relays: Vec::new(),
                    },
                )
                .map_err(|error| error.to_string())?;
                Ok((info, receiver.public(), place))
            })
            .collect::<Result<_, String>>()?;
        let base = Counting::peak_base();
        for (info, receiver, place) in described {
            hub.publish_info(2, info, receiver, 1, Some(place), true);
        }
        let peak = usize::try_from(Counting::peak_since(base)).unwrap_or(0);
        let planned = descriptions_planned_bytes(RECEIVERS)
            + crate::products::located_planned_bytes(RECEIVERS);
        assert!(hub.receivers.lock().map_err(|e| e.to_string())?.held.len() <= RECEIVERS);
        assert!(peak <= planned, "{peak} at the peak, {planned} planned");
        Ok(())
    }

    /// Positions of `engine`'s, issued now.
    fn signed_positions(
        engine: &Identity,
        boot_id: u64,
        sequence: u64,
    ) -> Result<Positions, String> {
        signed_positions_at(engine, boot_id, sequence, now_ms())
    }

    /// Positions of `engine`'s, issued at `issued_ms` by its clock.
    fn signed_positions_at(
        engine: &Identity,
        boot_id: u64,
        sequence: u64,
        issued_ms: u64,
    ) -> Result<Positions, String> {
        Positions::sign_fix(
            engine,
            &tally_wire::FixesContent {
                boot_id,
                sequence,
                issued_ms,
                spec_version: 1,
                fixes: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())
    }

    /// An engine's records are judged by their hash and signed time alone: a restarted engine's
    /// (a new boot, its sequence from 0) are new, a record never taken is new whatever its boot
    /// and sequence, a copy of one taken is a duplicate, and one signed longer ago than the window
    /// is too late.
    #[test]
    fn an_engines_records_are_judged_by_their_hash_and_signed_time() -> Result<(), String> {
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        let (engine, _) = key()?;
        let taken = signed_positions(&engine, 1, 1_000)?;
        assert!(hub.publish_positions(1, taken.clone()));
        assert!(hub.publish_positions(1, signed_positions(&engine, 2, 0)?));
        assert!(hub.publish_positions(1, signed_positions(&engine, 1, 0)?));
        assert!(!hub.publish_positions(1, taken));
        let archived = now_ms()
            - hub
                .window
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms()
            - 1_000;
        assert!(!hub.publish_positions(1, signed_positions_at(&engine, 1, 2, archived)?));
        assert_eq!(hub.memory_report().late_records, 1);
        Ok(())
    }

    /// A clock model of `engine`'s, issued now.
    fn signed_clock_model(
        engine: &Identity,
        boot_id: u64,
        sequence: u64,
    ) -> Result<tally_wire::ClockModel, String> {
        signed_clock_model_at(engine, boot_id, sequence, now_ms())
    }

    /// A clock model of `engine`'s, issued at `issued_ms` by its clock.
    fn signed_clock_model_at(
        engine: &Identity,
        boot_id: u64,
        sequence: u64,
        issued_ms: u64,
    ) -> Result<tally_wire::ClockModel, String> {
        tally_wire::ClockModel::sign(
            engine,
            &tally_wire::ClockModelContent {
                boot_id,
                sequence,
                issued_ms,
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
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        // Room for the model's three parts, as a relay with members' rate sizes it.
        hub.parts
            .lock()
            .map_err(|e| e.to_string())?
            .resize(4 * crate::parts::ONE_PART_BYTES);
        let out = hub.listen(u64::MAX, Filter::Everything);
        let (engine, _) = key()?;
        let model: Vec<u8> = (0..3 * tally_wire::clock_model::PART_LEN as u64)
            .map(|at| (at.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let signed = tally_wire::ClockModel::sign(
            &engine,
            &tally_wire::ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: now_ms(),
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
        assert!(hub.publish_clock_model(6, signed.manifest.clone()));
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

    /// A large model reaches the relay's store of decoded models whole whichever came first, its
    /// manifest or its parts (a part rebuilt from parity, or carried by another path, may come
    /// after): one whose parts came first is taken whole as its manifest goes out, one whose
    /// manifest came first as its last part does. Before, the second never reached the store, so
    /// nothing citing it was ever checked for a client. Each taking is counted by the store (this
    /// model is no model it holds: its bytes are not a fit's, and its engine is no area's).
    #[test]
    fn a_large_model_reaches_the_store_whole_whichever_came_first() -> Result<(), String> {
        // An area taken: the members it brings carry the models whole (`Network::hold_part`).
        let (receiver, _) = key()?;
        let (_, _, group) = located(&receiver)?;
        for manifest_first in [false, true] {
            let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY).taking(vec![group.cell]);
            hub.parts
                .lock()
                .map_err(|e| e.to_string())?
                .resize(4 * crate::parts::ONE_PART_BYTES);
            let (engine, _) = key()?;
            let model: Vec<u8> = (0..3 * tally_wire::clock_model::PART_LEN as u64)
                .map(|at| (at.wrapping_mul(2_654_435_761) >> 11) as u8)
                .collect();
            let signed = tally_wire::ClockModel::sign(
                &engine,
                &tally_wire::ClockModelContent {
                    boot_id: 1,
                    sequence: 0,
                    issued_ms: now_ms(),
                    spec_version: 1,
                    inputs: [0; 32],
                    model,
                },
            )
            .map_err(|error| error.to_string())?;
            let taken = || {
                let report = hub.network().clock_models.report();
                report.admitted
                    + report.unreadable
                    + report.outside
                    + report.not_an_engine
                    + report.stale
                    + report.slot_taken
                    + report.room
            };
            if manifest_first {
                assert!(hub.publish_clock_model(6, signed.manifest.clone()));
                for part in &signed.parts {
                    assert_eq!(taken(), 0, "taken before it was whole");
                    assert!(hub.publish_clock_model_part(7, part.clone()));
                }
            } else {
                for part in &signed.parts {
                    assert!(!hub.publish_clock_model_part(5, part.clone()));
                }
                assert_eq!(taken(), 0);
                assert!(hub.publish_clock_model(6, signed.manifest.clone()));
            }
            assert_eq!(
                taken(),
                1,
                "never taken whole, its {} first",
                if manifest_first { "manifest" } else { "parts" }
            );
            // And the member links carry it whole either way.
            assert_eq!(
                hub.network()
                    .model_records(&signed.manifest.id())
                    .map(|r| r.len()),
                Some(signed.parts.len() + 1),
                "its {} first",
                if manifest_first { "manifest" } else { "parts" }
            );
        }
        Ok(())
    }

    /// A relay hosting MLAT holds its own engine's twins: its raw is planned (seats, and the
    /// checks' room for its own engine's raw), and a hub that plans none is refused the engine.
    /// Before, a hub built without its raw hosted the engine anyway, its own room was empty, every
    /// twin of its own was refused for room, and its clients were sent nothing its engine solved.
    #[test]
    fn only_a_hub_that_plans_its_raw_hosts_mlat_and_holds_its_own_twins() -> Result<(), String> {
        let hosted = || -> Result<Arc<dyn crate::mlat_host::MlatHost>, String> {
            Ok(Arc::new(
                crate::mlat_host::HostedMlat::new(
                    tally_wire::Signer::new(Identity::from_seed([3; 32]), Arc::new(|| true)),
                    1,
                    tally_mlat::engine::Settings {
                        regions: tally_wire::Regions::default(),
                        threads: 1,
                        capacity: tally_mlat::engine::Capacity::default(),
                    },
                    crate::mlat_host::StepClock::KEEPING_UP,
                )
                .map_err(|error| error.to_string())?,
            ))
        };
        let unplanned = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        assert!(unplanned.host_mlat(hosted()?).is_err());
        assert!(unplanned.network().mlat().is_none());
        let planned = stamped_hub(8, crate::sharing::Deadlines::RELAY).memory(DEFAULT_MEMORY, true);
        let caps = planned.network().consistency.caps();
        assert!(caps.sites > 0 && caps.links > 0, "{caps:?}");
        planned.host_mlat(hosted()?)?;
        assert!(planned.network().mlat().is_some());
        Ok(())
    }

    #[test]
    fn clock_models_are_forwarded_once_per_id_and_late_past_the_window() -> Result<(), String> {
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        let (engine, _) = key()?;
        let model = signed_clock_model(&engine, 1, 1_000)?;
        assert!(hub.publish_clock_model(1, model.clone()));
        assert!(!hub.publish_clock_model(2, model));
        // Signed longer ago than the window: too late.
        let archived = now_ms()
            - hub
                .window
                .behind_span()
                .span::<tally_wire::clocks::Judged>()
                .ms()
            - 1_000;
        assert!(!hub.publish_clock_model(1, signed_clock_model_at(&engine, 1, 0, archived)?));
        assert_eq!(hub.memory_report().late_records, 1);
        // Positions are a table of their own, and a new boot's model is new.
        assert!(hub.publish_positions(1, signed_positions(&engine, 1, 0)?));
        assert!(hub.publish_clock_model(1, signed_clock_model(&engine, 2, 0)?));
        Ok(())
    }

    /// Positions that reach the hub before the clock model they cite (rebuilt from parity, by a
    /// repair, over a link that died between them) wait for it, and go out after it.
    #[test]
    fn positions_go_out_after_the_model_they_cite() -> Result<(), String> {
        let hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        let out = hub.listen(u64::MAX, Filter::Everything);
        let (engine, _) = key()?;
        // A real pair model's encoding, of the area the fix is in: what the fix cites is its
        // pair model id, known once the model is held whole.
        let (bytes, pair) = crate::models::testing::encoded(&crate::models::testing::pair_model(
            (33.7, -84.3),
            30_000,
            3,
            1,
        ));
        let model = tally_wire::ClockModel::sign(
            &engine,
            &tally_wire::ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: now_ms(),
                spec_version: tally_mlat_solver::SPEC_VERSION,
                inputs: [0; 32],
                model: bytes,
            },
        )
        .map(|signed| signed.manifest)
        .map_err(|error| error.to_string())?;
        let receivers: Vec<PublicKey> = throwaways(4);
        let considered = tally_wire::ObservationSet::new(
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
        .map_err(|e| e.to_string())?;
        let fix = tally_wire::Fix {
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
            models: vec![pair],
            sets: tally_wire::FixSets::new(considered.clone(), considered)
                .map_err(|e| e.to_string())?,
        };
        let positions = Positions::sign_fix(
            &engine,
            &tally_wire::FixesContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: now_ms(),
                spec_version: 1,
                fixes: vec![fix],
            },
        )
        .map_err(|e| e.to_string())?;
        assert!(hub.publish_positions(1, positions.clone()));
        assert!(
            out.try_recv().is_none(),
            "positions went out before their model"
        );
        // While they wait, the model they cite is looked for once, when they came, however often
        // what is held is released: struck off as it goes out, never looked for again. What a
        // fix cites is a pair model id, looked for among the models held whole
        // (`Network::holds_pair`), so the stream's table of manifests is never scanned for it.
        // Before, every release looked for every held record's models in every generation.
        for _ in 0..10 {
            hub.release_awaiting(None);
        }
        assert_eq!(
            hub.clock_models.lock().map_err(|e| e.to_string())?.scans(),
            0
        );
        assert!(hub.publish_clock_model(2, model.clone()));
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

    /// RFC-0171 §3.6: a fault proof is judged by the signed time of the newer record it proves a
    /// fault in (`proof_time`): forwarded once while that is in the window, a duplicate to its
    /// edge, and an archived one re-sent later is late, never forwarded again. Before, a proof
    /// was remembered for the window from when it came, so one re-sent after that was new again.
    #[test]
    fn a_fault_proof_is_forwarded_once_and_an_archived_one_never_again() -> Result<(), String> {
        let at = Arc::new(AtomicU64::new(BASE_MS + 1_000));
        let clock = Arc::clone(&at);
        let hub = Hub::clocked(
            8,
            Arc::new(move || clock.load(Ordering::Relaxed)),
            crate::sharing::Deadlines::RELAY,
        );
        let (engine, _) = key()?;
        let a = signed_positions_at(&engine, 1, 0, BASE_MS)?;
        let b = signed_positions_at(&engine, 1, 1, BASE_MS + 1_000)?;
        let proof = tally_wire::FaultProof::new(&a, 0, &b, 0).map_err(|error| error.to_string())?;
        assert!(hub.publish_fault_proof(1, proof.clone()));
        assert!(!hub.publish_fault_proof(2, proof.clone()));
        // Its newer record's window, to the millisecond: a duplicate still, later than a window
        // after it first came.
        let edge = BASE_MS
            + 1_000
            + crate::strikes::proofs(crate::sharing::Deadlines::RELAY)
                .behind_span()
                .duration()
                .as_millis() as u64;
        at.store(edge, Ordering::Relaxed);
        assert!(!hub.publish_fault_proof(3, proof.clone()));
        assert_eq!(hub.memory_report().late_records, 0);
        // Past it, the archive re-sent: late.
        at.store(edge + 1, Ordering::Relaxed);
        assert!(!hub.publish_fault_proof(4, proof));
        assert_eq!(hub.memory_report().late_records, 1);
        // An archived proof never seen: late at first sight.
        let c = signed_positions_at(&engine, 1, 2, BASE_MS)?;
        let unseen =
            tally_wire::FaultProof::new(&a, 0, &c, 0).map_err(|error| error.to_string())?;
        assert!(!hub.publish_fault_proof(5, unseen));
        assert_eq!(hub.memory_report().late_records, 2);
        Ok(())
    }

    /// RFC-0171 §3.6: feeder figures are judged by their signed `issued_ms`, in a window stretched
    /// by the hour they may be signed in (`strikes::Window::figures`): forwarded once, a duplicate
    /// for as long as that window holds them (well past a relay's window after they came), and an
    /// archive's figures re-sent later are late, never forwarded again. Before, figures were
    /// remembered by hash for a relay's window from when they came, so the same figures re-sent
    /// every few minutes were forwarded every time.
    #[test]
    fn feeder_figures_are_forwarded_once_and_an_archives_never_again() -> Result<(), String> {
        let hour = tally_wire::FIGURES_BUCKET_MS;
        let issued = BASE_MS / hour * hour;
        let at = Arc::new(AtomicU64::new(issued + 600_000));
        let clock = Arc::clone(&at);
        let hub = Hub::clocked(
            8,
            Arc::new(move || clock.load(Ordering::Relaxed)),
            crate::sharing::Deadlines::RELAY,
        );
        let out = hub.listen(u64::MAX, Filter::Everything);
        let relay = Identity::from_seed([66; 32]);
        let signed = |issued_ms: u64| {
            tally_wire::FeederFigures::sign(
                &relay,
                &tally_wire::FeederFiguresContent {
                    issued_ms,
                    window_for_ms: hour,
                    area: None,
                    feeders: vec![tally_wire::FeederFigure {
                        receiver: Identity::from_seed([67; 32]).public(),
                        cell: None,
                        uptime_permille: 1000,
                        messages: 1,
                        aircraft: 1,
                        range_m: None,
                        coverage_dkm2: 0,
                        unique_coverage_dkm2: 0,
                        mlat_positions: 0,
                        standing: false,
                    }],
                },
            )
            .map_err(|error| error.to_string())
        };
        let figures = signed(issued)?;
        let forwarded =
            |out: &crate::fanout::Listener| std::iter::from_fn(|| out.try_recv()).count();
        hub.publish_as(7, Deliverer::Relay, Record::FeederFigures(figures.clone()));
        assert_eq!(forwarded(&out), 1);
        hub.publish_as(8, Deliverer::Relay, Record::FeederFigures(figures.clone()));
        // Three relay windows after they came, within the hour: a duplicate.
        at.store(
            issued
                + 600_000
                + 3 * crate::strikes::relay_signed(crate::sharing::Deadlines::RELAY)
                    .behind_span()
                    .duration()
                    .as_millis() as u64,
            Ordering::Relaxed,
        );
        hub.publish_as(9, Deliverer::Relay, Record::FeederFigures(figures.clone()));
        assert_eq!(forwarded(&out), 0, "the same figures were forwarded again");
        // Past the hour and a relay's window, and past the minute its fingerprint expires in:
        // late (within that minute it is still a duplicate).
        at.store(
            (issued
                + hour
                + crate::strikes::relay_signed(crate::sharing::Deadlines::RELAY)
                    .behind_span()
                    .duration()
                    .as_millis() as u64)
                .div_ceil(60_000)
                * 60_000
                + 60_001,
            Ordering::Relaxed,
        );
        hub.publish_as(10, Deliverer::Relay, Record::FeederFigures(figures));
        // An archive's figures never seen: late at first sight.
        hub.publish_as(
            11,
            Deliverer::Relay,
            Record::FeederFigures(signed(issued - hour)?),
        );
        assert_eq!(forwarded(&out), 0, "an archive's figures were forwarded");
        assert_eq!(hub.memory_report().late_records, 2);
        // This hour's are taken.
        hub.publish_as(
            12,
            Deliverer::Relay,
            Record::FeederFigures(signed(issued + hour)?),
        );
        assert_eq!(forwarded(&out), 1);
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
        let all = directory.all(true, hub.clock().mono());
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
        // A table of them all, so every one is held.
        let mut hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        hub.described_as(RECEIVERS, DESCRIPTION_BYTES_HELD);
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
            let indexed: usize = directory.by_point.len();
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
        let batch_lock = hub.receivers.lock().map_err(|e| e.to_string())?;
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
        // A table of them all: the order of forgetting.
        let mut hub = stamped_hub(8, crate::sharing::Deadlines::RELAY);
        hub.described_as(RECEIVERS_REMEMBERED, DESCRIPTION_BYTES_HELD);
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
                assert!(hub.publish_batch(
                    2,
                    signed_batch_at(&new, sequence, Vec::new(), now_ms())?,
                    new_key
                ));
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

/// The clocks' error budget end to end, its own module and so its own build target
/// (`crates/relay/BUILD.bazel`, `hub::honest_end_to_end::`): the one test of this file that runs
/// past a small target's time, so the rest of the file's tests stay small.
#[cfg(test)]
mod honest_end_to_end {
    use super::tests::{BASE_MS, FeederClocks, feed, relay_of};
    use super::*;
    use tally_wire::Identity;

    /// RFC-0171 §3.6, the clocks' error budget end to end (`tally_wire::budget`), every batch
    /// made by the feeder's own code: its clocks (`tally_feed`'s `RelayClocks`: the selection of
    /// its configured relays, its host, its sessions' anchors and the filter by its reference) and
    /// its batcher (`Batcher::seal`: the signed time taken as the batch is gathered, held for its
    /// first anchor when it has none), and every anchor issued by its relay's own hub
    /// (`Hub::anchor`), which remembers it for blame. Four relays, each a hop whose clock stays
    /// within `E` of true time: one at `-E`, one at `E`, one a daemon slews from `-5 s` to `0` and
    /// back over 69 s (chrony's rate), one that steps by `E` either way halfway through each case
    /// (its monotonic clock does not); knowing different relays, beside a lying relay with no hop.
    /// Each case is an honest feeder:
    /// - with a trusted reference: its host synced; or its host hours off and unsynced, its
    ///   configured relays selected; or one configured relay beside a hinted honest one; or one
    ///   configured relay it probes, a hinted honest relay and a hinted liar whose anchor sits at
    ///   the bottom of the band an honest one may (or anywhere a minute either way);
    /// - with none: its host hours off, or near but unsynced; alone, or beside a liar colluding
    ///   with its clock, or one stating a day-old anchor.
    ///
    /// Each batch is gathered, maybe held up to `B` waiting for its first anchor, sent within `B`
    /// of being signed and `δ` on its way; every hop judges it then, its origins as their
    /// feeder's copy, the rest as a member's. Members also release it later to hops that never saw
    /// it: at the edge of a member's window, at its signed time, or up to two hours on. Half the
    /// cases are corners, every draw at an edge of its range.
    ///
    /// The oracle is the world, never the budget: every assertion reads the world's own figures
    /// (the relays' `E`, a measurement's `U_m`, a transit's `δ`, a feeder's backlog `B`, a
    /// member's first copy within 50 s, two minutes of freshness), so a window derived too tight
    /// or too loose fails here. For every case:
    /// - its feeder is never blamed, whatever the origin's clock did meanwhile;
    /// - with a trusted reference, every honest relay's anchor is carried, and the batch is used
    ///   at its origin when it arrives within `B + δ` of being gathered, and at a member whose
    ///   first copy comes within 50 s, wherever the hop knows an anchor it carries;
    /// - used at its origin, it is used at a member that knows only honest anchors of it and has
    ///   its first copy within 50 s;
    /// - with none, a lying relay's day-old anchor makes it unusable wherever the liar is known
    ///   (the stated loss of liveness);
    /// - wherever it is used and the hop knows an honest anchor it carries, it was signed no more
    ///   than two minutes before, in true time; used where the hop knows only the liar's is the
    ///   stated residual.
    #[test]
    fn the_error_budget_holds_end_to_end_for_honest_feeders() -> Result<(), String> {
        use tally_wire::budget;
        // The world the protocol promises, played as it is, not read from the budget: relays'
        // and synced hosts' clocks within 7.5 s of true time, a measurement's half round trip
        // within 1 s (its drift included), a transit within 1 s, a feeder's backlog of 64 s, a
        // member's first copy of a batch within 50 s of its making, and nothing used more than
        // two minutes after it was made. A budget that allows less or more than this fails here.
        let (e, u_m, transit, backlog) = (7_500_i64, 1_000_i64, 1_000_i64, 64_000_i64);
        let (member_within, fresh_within) = (50_000_i64, 120_000_i64);
        let hour = 3_600_000_i64;
        let day = 24 * hour;
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        // Half the cases are corners: every draw at one edge of its range or the other, so each
        // error source reaches its bound, together, where the budget is tight.
        let corner = std::cell::Cell::new(false);
        let mut draw = |range: i64| -> i64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if corner.get() {
                if state & 1 == 0 { range } else { -range }
            } else {
                (state % (2 * range.unsigned_abs() + 1)) as i64 - range
            }
        };
        // Each case has a slot of its own, and every hop's clock is a function of true time: its
        // judging clock's and its monotonic clock's offsets. The slewed one moves both alike, by
        // up to 5 s over 69 s; the stepped one moves its judging clock alone.
        let (first_slot, slot) = (BASE_MS as i64 + 300_000, 300_000_i64);
        let offset = move |hop: usize, at: i64| -> (i64, i64) {
            let (case, into) = (
                (at - first_slot).div_euclid(slot),
                (at - first_slot).rem_euclid(slot),
            );
            match hop {
                0 => (-e, -e),
                1 => (e, e),
                2 => {
                    let slewed = 5_000 * into.min(69_000) / 69_000;
                    let off = if case % 2 == 0 {
                        slewed - 5_000
                    } else {
                        -slewed
                    };
                    (off, off)
                }
                _ => {
                    let step = match (into >= 35_000, case % 2 == 0) {
                        (false, _) => 0,
                        (true, true) => e,
                        (true, false) => -e,
                    };
                    (step, 0)
                }
            }
        };
        let relay_clock = move |hop: usize, at: i64| (at + offset(hop, at).0) as u64;
        let seeds = [111u8, 112, 113, 114];
        let keys: Vec<PublicKey> = seeds
            .iter()
            .map(|seed| Identity::from_seed([*seed; 32]).public())
            .collect();
        let liar = Identity::from_seed([120; 32]);
        let knows: [Vec<PublicKey>; 4] = [
            [&keys[..], &[liar.public()]].concat(),
            [&keys[..], &[liar.public()]].concat(),
            keys.clone(),
            vec![liar.public()],
        ];
        let truth = Arc::new(AtomicU64::new(first_slot as u64));
        // The hops, and the hops a member releases to later, which have never seen the batch.
        #[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
        let hub_of = |hop: usize| {
            let (judging, monotonic, raw) =
                (Arc::clone(&truth), Arc::clone(&truth), Arc::clone(&truth));
            let hub = Arc::new(
                Hub::on(
                    8,
                    RelayClock::scripted_raw(
                        Arc::new(move || relay_clock(hop, judging.load(Ordering::Relaxed) as i64)),
                        Arc::new(move || {
                            let at = monotonic.load(Ordering::Relaxed) as i64;
                            (at + offset(hop, at).1) as u64
                        }),
                        Arc::new(move || raw.load(Ordering::Relaxed)),
                    ),
                    crate::sharing::Deadlines::RELAY,
                )
                .accepting_relays(knows[hop].iter().copied()),
            );
            hub.network()
                .adopt_identity(crate::signer::twin(&Identity::from_seed([seeds[hop]; 32])));
            hub
        };
        let hops: Vec<Arc<Hub>> = (0..4).map(hub_of).collect();
        let later_hops: Vec<Arc<Hub>> = (0..4).map(hub_of).collect();
        let member = Origin::Peer(relay_of(69));
        // A hop's anchor as its hub states it at `at`.
        let issue = |hop: usize, at: i64| -> Result<tally_wire::Anchor, String> {
            truth.store(at as u64, Ordering::Relaxed);
            hops[hop]
                .anchor()
                .ok_or(format!("hop {hop} issued no anchor"))
        };
        struct Case {
            kind: i64,
            receiver: PublicKey,
            batch: Batch,
            gathered: i64,
            signed: i64,
            anchors: Vec<tally_wire::Anchor>,
            origins: Vec<usize>,
        }
        #[derive(Clone, Copy)]
        struct Judged {
            at: i64,
            case: usize,
            hop: usize,
            origin: bool,
            later: bool,
        }
        let mut cases: Vec<Case> = Vec::new();
        let mut later_events: Vec<Judged> = Vec::new();
        let (mut used, mut residual, mut lost, mut promised, mut consistent) = (0, 0, 0, 0, 0);
        let mut oldest_anchor_used = 0_i64;
        let (mut seen, mut taken) = (
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        // What a hop made of a case's copy at `event`, asserted against the world.
        let mut judge =
            |cases: &[Case],
             event: Judged,
             first_fed: &mut std::collections::HashMap<usize, (bool, i64, bool)>| {
                let case = &cases[event.case];
                let hub = if event.later {
                    &later_hops[event.hop]
                } else {
                    &hops[event.hop]
                };
                truth.store(event.at as u64, Ordering::Relaxed);
                hub.sweep_strikes();
                let key = (event.case, event.hop, event.later);
                let first = !seen.contains(&key);
                let reading = relay_clock(event.hop, event.at);
                let origin = if event.origin {
                    Origin::Feeder(None, None, None)
                } else {
                    member.clone()
                };
                let fed = feed(hub, 77, case.batch.clone(), origin, reading);
                let said = format!(
                    "case {} (kind {}) at hop {}{}{}",
                    event.case,
                    case.kind,
                    event.hop,
                    if event.origin { ", its origin" } else { "" },
                    if event.later { ", released later" } else { "" }
                );
                let known: Vec<&tally_wire::Anchor> = case
                    .anchors
                    .iter()
                    .filter(|anchor| {
                        anchor.relay == keys[event.hop] || knows[event.hop].contains(&anchor.relay)
                    })
                    .collect();
                let honest_known = known.iter().any(|anchor| anchor.relay != liar.public());
                let liar_known = known.iter().any(|anchor| anchor.relay == liar.public());
                if fed {
                    used += 1;
                    if honest_known {
                        assert!(
                            event.at - case.signed <= fresh_within,
                            "{said}: used {} ms after it was signed",
                            event.at - case.signed
                        );
                    } else {
                        residual += 1;
                    }
                    if let Some(oldest) = known.iter().map(|anchor| anchor.j_ms).min() {
                        oldest_anchor_used = oldest_anchor_used.max(reading as i64 - oldest as i64);
                    }
                }
                assert!(!(fed && taken.contains(&key)), "{said}: taken twice");
                seen.insert(key);
                if fed {
                    taken.insert(key);
                }
                if !first || event.later {
                    return;
                }
                let delay = event.at - case.gathered;
                first_fed.insert(event.hop, (fed, delay, honest_known && !liar_known));
                match case.kind {
                    0..=3 => {
                        // What the world promises a batch with a trusted reference: used at its
                        // origin when it arrives within `B + δ` of being gathered, at a member whose
                        // first copy comes within its promise.
                        let within = if event.origin {
                            backlog + transit
                        } else {
                            member_within
                        };
                        if !known.is_empty() && delay <= within {
                            promised += 1;
                            assert!(
                                fed,
                                "{said}: unused {delay} ms after it was gathered (t {} ms behind the \
                             hop)",
                                reading as i64 - case.batch.wall_ms().unwrap_or(0) as i64
                            );
                        }
                    }
                    7 if liar_known => {
                        assert!(!fed, "{said}: a day-old anchor did not age it");
                        lost += 1;
                    }
                    _ => {}
                }
            };
        for n in 0..640_i64 {
            let kind = n % 8;
            let start = first_slot + n * slot;
            corner.set(false);
            let (mut a, mut b) = {
                let a = (draw(1_000).unsigned_abs() % 4) as usize;
                (a, (a + 1 + (draw(1_000).unsigned_abs() % 3) as usize) % 4)
            };
            corner.set((n / 8) % 2 == 1);
            if kind == 3 && corner.get() {
                // The tightest the world makes it: its origin `E` ahead, its reference `E` behind.
                (a, b) = (1, 0);
            }
            // The liar takes the second session where there is one.
            let with_liar = matches!(kind, 3 | 6 | 7);
            let configured: Vec<PublicKey> = match kind {
                0 => [a, b]
                    .into_iter()
                    .filter(|_| draw(1) > 0)
                    .map(|hop| keys[hop])
                    .collect(),
                1 => vec![keys[a], keys[b]],
                2 => vec![keys[a]],
                3 => vec![keys[b]],
                _ => Vec::new(),
            };
            let (host_off, bound) = match kind {
                0 => {
                    let bound = 5 + draw(e - 5).unsigned_abs();
                    (draw(bound as i64), Some(bound))
                }
                // Unsynced, as read, near: within `E` and `F` of true time.
                5 => (
                    draw(e + (budget::F.span::<tally_wire::clocks::Judged>().ms()) as i64),
                    None,
                ),
                7 => (draw(e), None),
                _ => {
                    let off = hour + draw(5 * hour).abs();
                    (if draw(1) < 0 { -off } else { off }, None)
                }
            };
            let feeder =
                FeederClocks::at((start + host_off) as u64, start as u64, bound, &configured);
            let clocks = &feeder.clocks;
            let mut sessions = Vec::new();
            // Each configured relay measured by an echo whose round trip is up to `2U_m` (less
            // the drift its sample gathers before it is used), the relay's reading taken anywhere
            // in it; kind 3's by a probe of it, which is no session.
            let mut now = start;
            let round_trip = |draw: &mut dyn FnMut(i64) -> i64| {
                let round_trip = draw(2 * (u_m - 50)).abs();
                (round_trip, round_trip / 2 + draw(round_trip / 2))
            };
            if kind == 3 {
                let (took, at) = round_trip(&mut draw);
                let heard = clocks.stamp_ms();
                let asked = heard.saturating_sub(took as u64);
                let clock = relay_clock(b, now - took + at);
                clocks.probed(keys[b], (asked, clock, clock), Some(e as u64), heard);
            }
            for (place, hop) in [a, b].into_iter().enumerate() {
                if place == 1 && with_liar {
                    sessions.push((None, clocks.session(liar.public())));
                    continue;
                }
                let telling = clocks.session(keys[hop]);
                if kind != 3 && configured.contains(&keys[hop]) {
                    let asked = telling.asking_ms();
                    let (took, at) = round_trip(&mut draw);
                    let clock = relay_clock(hop, now + at);
                    feeder.wait(took as u64);
                    now += took;
                    telling.echoed(asked, clock, clock, Some(e as u64));
                }
                sessions.push((Some(hop), telling));
            }
            // Each session's newest anchor, heard at `heard`: issued by its relay's hub up to `P`
            // before it is stated and `δ` on its way; the liar's as its kind lies.
            let hear = |heard: i64, draw: &mut dyn FnMut(i64) -> i64| -> Result<(), String> {
                for (hop, telling) in &sessions {
                    let anchor = match hop {
                        Some(hop) => {
                            let age = (budget::ANCHOR_PERIOD
                                .span::<tally_wire::clocks::Judged>()
                                .ms()) as i64
                                + transit;
                            issue(*hop, heard - draw(age).abs())?
                        }
                        None => {
                            let lie = match kind {
                                // Hinted, beside a trusted reference: at the bottom of the band
                                // an honest relay's anchor may be (its error, its age as stated
                                // and its way), or anywhere a minute either way.
                                3 if corner.get() => clocks.now_ms() as i64 - (e + 1_000 + transit),
                                3 => heard + draw(60_000),
                                // Colluding with the feeder's wrong clock.
                                6 => heard + host_off,
                                _ => heard - day,
                            };
                            tally_wire::Anchor::sign(&liar, lie as u64)
                        }
                    };
                    telling.anchored(anchor);
                }
                truth.store(heard as u64, Ordering::Relaxed);
                Ok(())
            };
            let seed = |tag: u8| {
                let mut seed = [7u8; 32];
                seed[0] = (n % 251) as u8;
                seed[1] = (n / 251) as u8;
                seed[2] = tag;
                Identity::from_seed(seed)
            };
            let mut batcher =
                tally_feed::source::Batcher::new(seed(7), u32::MAX, tally_wire::Clock::Dump1090)
                    .signing_by(Arc::clone(clocks));
            let receiver = seed(7).public();
            feeder.wait(1_000);
            let pending = draw(1) > 0;
            // Otherwise an anchor heard up to `2P` before the batch is gathered and signed.
            let held = if pending {
                0
            } else {
                let held = draw(
                    (budget::ANCHOR_HELD
                        .span::<tally_wire::clocks::Judged>()
                        .ms()) as i64,
                )
                .abs();
                hear(now + 1_000, &mut draw)?;
                feeder.wait(held as u64);
                held
            };
            let gathered = now + 1_000 + held;
            let (batch, signed) = if pending {
                // Gathered with no anchor yet: held, then signed by the first that comes, at a
                // seal up to `2P` after it is heard.
                batcher.add_dropped(1);
                if batcher.seal()?.is_some() {
                    return Err(format!("case {n}: signed with no anchor"));
                }
                let wait = draw(backlog - 5_000).abs();
                feeder.wait(wait as u64);
                hear(gathered + wait, &mut draw)?;
                let sealed = draw(
                    (budget::ANCHOR_HELD
                        .span::<tally_wire::clocks::Judged>()
                        .ms()) as i64,
                )
                .abs();
                feeder.wait(sealed as u64);
                let batch = batcher.seal()?.ok_or(format!("case {n}: not released"))?;
                (batch, gathered + wait + sealed)
            } else {
                batcher.add_dropped(1);
                let batch = batcher.seal()?.ok_or(format!("case {n}: not signed"))?;
                (batch, gathered)
            };
            let t = batch.wall_ms().map_err(|error| error.to_string())? as i64;
            let anchors = batch.anchors().map_err(|error| error.to_string())?;
            if anchors.is_empty() {
                return Err(format!("case {n} (kind {kind}): signed unanchored"));
            }
            // With a trusted reference, every honest relay's anchor agrees with it and is
            // carried, and so is a liar's at the bottom of the band.
            if kind <= 3 {
                for hop in sessions.iter().filter_map(|(hop, _)| *hop) {
                    if !anchors.iter().any(|anchor| anchor.relay == keys[hop]) {
                        return Err(format!(
                            "case {n} (kind {kind}): relay {hop}'s honest anchor left out"
                        ));
                    }
                }
                if kind == 3
                    && corner.get()
                    && !anchors.iter().any(|anchor| anchor.relay == liar.public())
                {
                    return Err(format!(
                        "case {n}: the liar's anchor at the band's bottom left out"
                    ));
                }
            }
            drop(sessions);
            // Sent within `B` of being signed, or within a member's promise of being gathered,
            // and `δ` on its way.
            let span = if draw(1) > 0 {
                backlog
            } else {
                member_within - transit - (signed - gathered)
            };
            let sent = signed + draw(span.max(0)).abs();
            let arrives = sent + draw(transit).abs();
            let origins: Vec<usize> = if with_liar { vec![a] } else { vec![a, b] };
            let mut events = Vec::new();
            let at_case = cases.len();
            for hop in 0..4 {
                let origin = origins.contains(&hop);
                events.push(Judged {
                    at: arrives,
                    case: at_case,
                    hop,
                    origin,
                    later: false,
                });
                if origin {
                    continue;
                }
                // A member releases it later to a hop that never saw it: at the edge of a
                // member's window by that hop's clock, at its signed time, or up to two hours on.
                let edge = t
                    + (budget::PEER_BEHIND
                        .span::<tally_wire::clocks::Judged>()
                        .ms()) as i64;
                let release = match draw(1) {
                    -1 => edge - offset(hop, edge).0,
                    0 => t - offset(hop, t).0,
                    _ => arrives + draw(2 * hour).abs(),
                };
                later_events.push(Judged {
                    at: release.max(arrives),
                    case: at_case,
                    hop,
                    origin: false,
                    later: true,
                });
            }
            cases.push(Case {
                kind,
                receiver,
                batch,
                gathered,
                signed,
                anchors,
                origins,
            });
            // Its first copies judged now, in the order the hops' clocks reach them, while each
            // origin still remembers the anchors it issued.
            events.sort_by_key(|event| event.at);
            let mut first_fed = std::collections::HashMap::new();
            for event in events {
                judge(&cases, event, &mut first_fed);
            }
            // Usable at an origin is usable at a member that knows only honest anchors of it and
            // has its first copy within its promise.
            let case = &cases[at_case];
            let used_at_origin = case
                .origins
                .iter()
                .any(|origin| first_fed.get(origin).is_some_and(|(fed, _, _)| *fed));
            if case.kind <= 5 && used_at_origin {
                for hop in (0..4).filter(|hop| !case.origins.contains(hop)) {
                    if let Some(&(fed, delay, honest)) = first_fed.get(&hop)
                        && honest
                        && delay <= member_within
                    {
                        assert!(
                            fed,
                            "case {n} (kind {}): used at its origin, not at member {hop} {delay} \
                             ms on",
                            case.kind
                        );
                        consistent += 1;
                    }
                }
            }
            // Never blamed at an origin, whatever its clock did meanwhile.
            for &hop in &case.origins {
                hops[hop].stages.flush();
                let late = hops[hop]
                    .station(&case.receiver)
                    .map_or(0, |station| station.late_batches);
                assert_eq!(
                    late, 0,
                    "case {n} (kind {kind}): an honest feeder blamed at {hop}"
                );
            }
        }
        // The later releases, in the order the hops' clocks reach them, each to a hop that never
        // saw the batch: safety alone is promised there.
        later_events.sort_by_key(|event| event.at);
        let mut unused = std::collections::HashMap::new();
        for event in later_events {
            judge(&cases, event, &mut unused);
        }
        assert!(
            consistent >= 200,
            "{consistent} members checked against their origin"
        );
        assert!(promised >= 400, "{promised} promised");
        assert!(used >= promised, "{used} used");
        assert!(residual > 0, "the residual was never met");
        assert!(lost > 0, "no liveness was lost to a lying relay");
        // The tightest the world makes it reaches the anchors' window: a batch used at an honest
        // hop by an anchor older than 95 s there.
        assert!(
            oldest_anchor_used > 95_000,
            "no batch was used by an anchor older than {oldest_anchor_used} ms"
        );
        Ok(())
    }
}
