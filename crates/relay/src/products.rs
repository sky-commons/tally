//! The two products (RFC-0174 §2.11): the regional product (each area's receptions deduplicated
//! once, as `RegionalBatch` records this relay signs as their origin, beside the area's raw,
//! positions and clock models) and the world product in its two feeds (one fix per aircraft per
//! second, by `tally_wire::products::world_choice`, offered at the top of the area tree by a relay
//! that has gathered every area's positions): live as `WorldPositions`, sealed `WORLD_SETTLE_MS`
//! after its second with MLAT by provisional fixes, and precise as `WorldPrecise`, sealed
//! `WORLD_PRECISE_SETTLE_MS` after with MLAT by final fixes only.
//!
//! # Who does what (RFC-0178)
//!
//! Nothing here is on the per-reception path. Which reception is an area's first copy is decided
//! by the message exchange's one deduplication (`exchange::MessageShard`), at each epoch's close,
//! in canonical order. The closed epochs come to the [`Sealer`], one thread that owns everything
//! the products decide: it gathers each epoch whole from every message thread
//! (`seal::Coordinator`), signs the regional product area by area, offers its fixes to the world,
//! seals every world second the watermark has settled, and hands what it signed to the hub
//! through an outbox. It decides by stamps, never by a clock: an epoch's records carry its end as
//! their time, and the world seals when the watermark (an epoch's end) passes a second plus
//! `WORLD_SETTLE_MS`, so the same stamped trace gives the same records on any number of threads.
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
//! The sealer is one thread that decides, and a pool that works (RFC-0178 §4, "a sealer pool"):
//! each epoch's areas are made into records in parallel (their observations gathered, cut to
//! fit a record, signed, and their ADS-B fixes derived), on threads started with the sealer (so a
//! thread that cannot be started fails the relay at its start, never an epoch), as many as the
//! message exchange has, then numbered and applied in cell order by the one thread, so the records
//! and their sequence are the same on any number of threads.
//!
//! What the sealer holds is charged to the relay's budget (`budget::Store::Products`): the
//! deduplicated stream and the signed records the hub has not yet taken, and the records waiting
//! in their queue. An epoch whose products would pass it is refused whole, counted; a record is
//! refused, counted (`records_refused`).
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
//! - **MLAT finals and provisionals**, from `Positions` records (final, format 3) and
//!   `Provisional` ones (format 4), by [`positions_fixes`]: each solution as published, its input
//!   set the merge rule's (`products::input_set`, over the observation set and the cited model's
//!   inputs hash), so a solution waits here until its model's manifest has been shown.
//!
//! Each fix cites its origin record's hash and its index there, so a reader holding that record
//! derives the same fix ([`check_fix`]). A second is sealed once, [`WORLD_SETTLE_MS`] after it
//! ends (a provisional arrives at most about 3 s after its transmission, RFC-0171 §3.8.1): its
//! fixes, ascending by address, are signed as `WorldPositions` parts of at most
//! `MAX_WORLD_FIXES`. A candidate for a sealed second is late and dropped, so no aircraft has two
//! fixes in one second. A final MLAT fix comes 7 to 47 s after its transmission, after its second
//! is sealed, so in the world product an MLAT target is drawn by its provisional fix; its final
//! fix is in the positions stream the world fix's origin belongs to. Two relays shown the same
//! records before a second's seal publish the same fixes for it, byte for byte, in any order.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TrySendError, channel, sync_channel};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;

use tally_mlat_solver::modes::{self, AltitudeKind};
use tally_wire::batch::{Hash, format};
use tally_wire::positions::{EnuCovariance, TransmitTime};
use tally_wire::products::{MAX_REGIONAL_OBSERVATIONS, MAX_WORLD_FIXES, adsb_input_set, input_set};
use tally_wire::rendezvous::area_of;
use tally_wire::{
    ClockModel, Identity, Observation, Positions, PublicKey, ReceiverInfo, Record, Region,
    RegionalBatch, RegionalDraft, WireError, WorldFix, WorldPositions, WorldPositionsContent,
    WorldPrecise,
};

use crate::bounded::Bounded;
use crate::budget::{Charge, Gauge, Store};
use crate::exchange::{Frozen, SHARDS, Sink, raw_shard};
use crate::ingest::{Pause, Stage};
use crate::network::{Asker, AskerRole};
use crate::seal::{Coordinator, Epoch, Merged, end_of};

/// How often each area's copies are signed: a feeder seals once a second, and so does an origin.
pub const REGIONAL_EVERY_MS: u64 = 1_000;
/// How long after a second of transmit time ends its world fixes are sealed: a provisional fix is
/// published at most about 3.0 s after its transmission (RFC-0171 §3.8.1, measured), and a
/// regional batch within a second of its receptions.
pub const WORLD_SETTLE_MS: u64 = 4_000;
/// How long after a second of transmit time ends its precise world fixes are sealed: once every
/// final fix of it has surely arrived (`tally_wire::products::FINAL_FIX_ARRIVED_MS`, derived
/// there).
pub const WORLD_PRECISE_SETTLE_MS: u64 = tally_wire::products::FINAL_FIX_ARRIVED_MS;
/// How far past the watermark a fix's second may be and still be held.
const WORLD_AHEAD_SECONDS: u64 = 2;
/// How far before the watermark a fix's second may be before the first seal.
const WORLD_BEHIND_SECONDS: u64 = 240;
/// The most aircraft held for one second: several times the world's airborne fleet.
pub const MAX_WORLD_AIRCRAFT: usize = 50_000;
/// The most fixes held across every open second.
pub const MAX_WORLD_HELD: usize = 400_000;
/// The receivers' areas remembered (the hub's own count of receivers held), split across the raw
/// shards that own them.
const RECEIVERS_LOCATED: usize = crate::hub::RECEIVERS_REMEMBERED;
/// The relays remembered per receiver: a feeder names two, a v1 feeder up to its slots.
const RELAYS_PER_RECEIVER: usize = 8;
/// Regional batches remembered by hash, so each is forwarded and decoded once.
const REGIONAL_REMEMBERED: usize = 200_000;
/// How old, or how far ahead, a peer's regional batch may be by its signed wall clock.
const REGIONAL_MAX_AGE_MS: u64 = 60_000;
const REGIONAL_MAX_AHEAD_MS: u64 = 10_000;
/// Peers' regional batches waiting for the next tick to be forwarded.
const FORWARD_HELD: usize = 4_096;
/// Clock models remembered: their id and inputs hash. A world-scale relay publishes some 3,800
/// a 40 s stride, and a provisional cites one up to 90 s old.
const MODELS_REMEMBERED: usize = 50_000;
/// Positions records waiting for a model they cite, and for how long.
const WAITING_HELD: usize = 4_096;
const WAITING_MS: u64 = 30_000;
/// Fixes derived from origins this relay holds, by (origin, index), to check a peer's world fix
/// that cites one of them.
const DERIVED_REMEMBERED: usize = 200_000;
/// What the sealer's queue of epochs holds before it refuses one: every message thread's word for
/// many seconds of epochs (a thread sends at most a part and a marker an epoch). Only the message
/// threads and the relay's own settings use it; records wait in their own queue (`RECORDS_HELD`).
const EPOCH_QUEUE: usize = 4_096;
/// Records (positions, clock models, peers' world and regional records) waiting for the sealer to
/// take them in by stamp, at most: their bytes are charged too. A record arrives at most about an
/// epoch before the watermark passes its stamp, and a world-scale relay is handed some thousands a
/// second, so this is seconds of them.
const RECORDS_HELD: usize = 16_384;
/// Epochs of products the hub may leave untaken before an epoch's are refused whole, counted: what
/// the products' budget is planned for (`budget::Store::Products`). The hub takes them every
/// `network::TICK`, a tenth of an epoch.
pub const OUTBOX_EPOCHS: usize = 2;

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
    /// not taken, or the epoch was past the budget): RFC-0178 §10.
    pub epochs_refused: u64,
    /// Epoch parts (one message thread's share of one epoch) lost on the way to the sealer, its
    /// queue full: each refuses its epoch, counted above when another thread held any of it.
    pub epoch_parts_lost: u64,
    /// Epochs of the deduplicated stream refused whole because the hub had not taken the ones
    /// before.
    pub stream_refused: u64,
    /// Receptions dropped at a seal because the relay had no key to sign them with yet.
    pub regional_unsigned: u64,
    /// Receptions too large for any regional batch.
    pub regional_oversized: u64,
    /// Peers' regional batches older or further ahead than a regional batch may be.
    pub regional_stale: u64,
    /// Peers' regional batches taken but not forwarded for room (`FORWARD_HELD`).
    pub regional_forward_full: u64,
    /// Records (positions, models, peers' products) not taken for room: their own queue full
    /// (`RECORDS_HELD`) or the products' budget spent. Never an epoch.
    pub records_refused: u64,
    /// Receptions a message thread let go because their epoch had closed before they came: only
    /// a trace can stamp a batch behind its worker's tick.
    #[serde(default)]
    pub receptions_late: u64,
    /// Observations of the deduplicated stream too large for any `RelayBatch` (`deduplicated`).
    #[serde(default)]
    pub stream_oversized: u64,
    /// World records signed (live).
    pub world_signed: u64,
    /// Precise world records signed.
    pub precise_signed: u64,
    /// Fixes offered after their second was sealed.
    pub world_late: u64,
    /// Fixes whose second is too far before or after the watermark to be held.
    pub world_out_of_window: u64,
    /// Fixes not held for want of room (`MAX_WORLD_HELD`, `MAX_WORLD_AIRCRAFT`).
    pub world_skipped: u64,
    /// Peers' world fixes that disagree with the origin they cite.
    pub world_refuted: u64,
    /// Positions records not held to wait for their model, for room (`WAITING_HELD`).
    pub positions_waiting_full: u64,
    /// Positions records whose model never came within `WAITING_MS`.
    pub positions_waiting_expired: u64,
    /// Positions records whose fixes could not be derived (a malformed solution set).
    pub positions_underivable: u64,
}

/// A receiver's area and the relays it said it publishes to.
struct Located {
    area: Region,
    relays: Vec<PublicKey>,
}

/// One world product being gathered: its open seconds, and when they are sealed.
struct Gatherer {
    /// Whether this relay gathers it.
    on: bool,
    settle_ms: u64,
    /// The precise product takes no provisional fix.
    finals_only: bool,
    /// Open seconds, each aircraft's best fix so far.
    fixes: BTreeMap<u64, BTreeMap<u32, WorldFix>>,
    held: usize,
    sealed_through: Option<u64>,
}

impl Gatherer {
    fn new(settle_ms: u64, finals_only: bool) -> Self {
        Self {
            on: false,
            settle_ms,
            finals_only,
            fixes: BTreeMap::new(),
            held: 0,
            sealed_through: None,
        }
    }
}

/// What the hub takes from the sealer, and what it is charged (`Store::Products`).
#[derive(Default)]
struct Outbox {
    records: Vec<Record>,
    records_charge: Charge,
    forward: Vec<(u64, RegionalBatch)>,
    forward_charge: Charge,
    stream: VecDeque<(Vec<Observation>, Charge)>,
    stream_refused: u64,
}

/// A record that is not an epoch, for the sealer to take in at its stamp.
enum Input {
    Positions(Positions),
    ClockModel(ClockModel),
    World(WorldPositionsContent, bool),
    Regional(u64, RegionalBatch),
}

/// One record waiting: its stamp, its hash (the order of records of one stamp), and what it is
/// charged until it is taken in.
struct Pending {
    stamp_ms: u64,
    hash: Hash,
    input: Input,
    _charge: Charge,
}

/// The records waiting for the sealer, and how far it has taken them in: every record stamped
/// before `taken_before` has been, so one handed in now is stamped no earlier.
#[derive(Default)]
struct Records {
    pending: Vec<Pending>,
    taken_before: u64,
}

/// What the sealer shares with the handle: its outbox, its records, its report, its watermark, its
/// gauge.
struct Shared {
    outbox: Mutex<Outbox>,
    records: Mutex<Records>,
    report: Mutex<ProductsReport>,
    /// The end of the newest epoch sealed: the products' time.
    watermark_ms: AtomicU64,
    gauge: Mutex<Arc<Gauge>>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            outbox: Mutex::default(),
            records: Mutex::default(),
            report: Mutex::default(),
            watermark_ms: AtomicU64::new(0),
            gauge: Mutex::new(Gauge::unlimited(Store::Products)),
        }
    }
}

impl Shared {
    fn gauge(&self) -> Arc<Gauge> {
        self.gauge.lock().map_or_else(
            |_| Gauge::unlimited(Store::Products),
            |gauge| Arc::clone(&gauge),
        )
    }
}

/// What a record costs the products' budget while it waits: its bytes.
fn record_bytes(record: &Record) -> usize {
    record.encoded_len()
}

/// What a peer's world content costs while it waits: its fixes.
fn world_bytes(content: &WorldPositionsContent) -> usize {
    std::mem::size_of_val(content.fixes.as_slice())
}

/// What a list of observations costs while it waits: each one and its message.
fn observations_bytes(observations: &[Observation]) -> usize {
    observations
        .iter()
        .map(|observation| std::mem::size_of::<Observation>() + observation.data.len())
        .sum()
}

/// What one sealer owns: everything the products decide.
pub struct Sealing {
    coordinator: Coordinator,
    /// The threads an epoch's areas are made into records on, beside the sealer's own.
    pool: Pool,
    identity: Option<Identity>,
    /// The key of `digest` (a world fix remembered by a 64-bit digest).
    digest_key: RandomState,
    boot_id: u64,
    sequence: u64,
    taken: Vec<Region>,
    /// The live world product and the precise one.
    live: Gatherer,
    precise: Gatherer,
    /// Regional batches seen, own and peers', by hash.
    regional_seen: Bounded<Hash, ()>,
    /// A model's id, and the hash of its inputs.
    models: Bounded<Hash, Hash>,
    /// Positions waiting for the model they cite, by its id: when each arrived, and the record.
    waiting: HashMap<Hash, Vec<(u64, Positions)>>,
    waiting_count: usize,
    derived: Bounded<(Hash, u16), u64>,
    report: ProductsReport,
    /// The end of the newest epoch sealed.
    watermark_ms: u64,
    shared: Arc<Shared>,
}

/// What the sealer is asked to do through its queue: an epoch, or a setting. Records wait in
/// [`Records`] instead.
enum Command {
    Frozen(Frozen),
    Identity(Identity),
    Taken(Vec<Region>),
    Live(bool),
    Precise(bool),
    Advance(u64),
}

/// Where the sealing runs: its own thread, or for a test the caller, under one lock.
enum Sealer {
    Inline(Box<Mutex<Sealing>>),
    Thread {
        sender: SyncSender<Command>,
        handle: Option<JoinHandle<()>>,
    },
}

/// The products: the receivers' areas (read per batch by the ingest worker that owns the
/// receiver's shard), and the sealer. Whoever holds them sees the sealer where it runs: moving it
/// onto its thread (`on_thread`) needs no exclusive hold, so it can never be left behind inline.
pub struct Products {
    /// Each receiver's area and chosen relays, by its raw shard.
    located: Box<[Mutex<Bounded<PublicKey, Located>>]>,
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

    /// As `new`, the regional stream under `boot_id`, gathered from `threads` message threads.
    pub fn with_boot(boot_id: u64, threads: usize) -> Self {
        let shared = Arc::new(Shared::default());
        Self {
            located: (0..SHARDS)
                .map(|_| Mutex::new(Bounded::new(RECEIVERS_LOCATED / SHARDS)))
                .collect(),
            own: OnceLock::new(),
            sealer: RwLock::new(Sealer::Inline(Box::new(Mutex::new(Sealing::new(
                boot_id,
                threads,
                Arc::clone(&shared),
            ))))),
            shared,
        }
    }

    /// The sealing on a thread of its own, gathering from `threads` message threads, with a pool
    /// of as many threads, each held up by `pause` (a test's; none in a relay). What it was told
    /// so far (areas taken, the world's switches, its key) is carried over. Every thread is started
    /// or this fails, and the relay with it: an inline sealer behind a staged exchange would gather
    /// from one thread and refuse every epoch.
    pub fn on_thread(&self, threads: usize, pause: Option<&Pause>) -> Result<(), String> {
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
            let mut fresh = Sealing::new(held.boot_id, threads, Arc::clone(&self.shared));
            fresh.taken = std::mem::take(&mut held.taken);
            fresh.live.on = held.live.on;
            fresh.precise.on = held.precise.on;
            fresh.identity = held.identity.take();
            fresh
        };
        fresh.pool = Pool::start(threads.max(1) - 1, pause)?;
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

    /// Where the message exchange hands each closed epoch: to the sealer, without waiting; false
    /// when its queue is full (the epoch is then refused whole).
    pub fn sink(self: &Arc<Self>) -> Sink {
        let products = Arc::clone(self);
        Arc::new(move |frozen| products.command(Command::Frozen(frozen)))
    }

    fn command(&self, command: Command) -> bool {
        let Ok(sealer) = self.sealer.read() else {
            return false;
        };
        match &*sealer {
            Sealer::Inline(sealing) => {
                if let Ok(mut sealing) = sealing.lock() {
                    sealing.handle(command);
                    sealing.publish_report();
                }
                true
            }
            Sealer::Thread { sender, .. } => match sender.try_send(command) {
                Ok(()) => true,
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
            },
        }
    }

    /// A record for the sealer, stamped `stamp_ms` (no earlier than what the sealer has taken in)
    /// and charged while it waits; refused and counted when the records' queue or the products'
    /// budget is full. It waits apart from the epochs, so it never takes an epoch's place.
    fn record(&self, stamp_ms: u64, hash: Hash, bytes: usize, input: Input) {
        let taken = self.shared.records.lock().is_ok_and(|mut records| {
            if records.pending.len() >= RECORDS_HELD {
                return false;
            }
            let Some(charge) = self.shared.gauge().try_charge(bytes) else {
                return false;
            };
            let stamp_ms = stamp_ms.max(records.taken_before);
            records.pending.push(Pending {
                stamp_ms,
                hash,
                input,
                _charge: charge,
            });
            true
        });
        if !taken && let Ok(mut report) = self.shared.report.lock() {
            report.records_refused += 1;
        }
    }

    /// `count` observations of the deduplicated stream were too large for any batch, counted.
    pub fn stream_oversized(&self, count: u64) {
        if count > 0
            && let Ok(mut report) = self.shared.report.lock()
        {
            report.stream_oversized += count;
        }
    }

    /// What the products hold is charged to `gauge` (the budget's `Store::Products`) from now on.
    pub fn charge_to(&self, gauge: Arc<Gauge>) {
        if let Ok(mut held) = self.shared.gauge.lock() {
            *held = gauge;
        }
    }

    /// The areas this relay takes (the operator's, as `Selection::set_taken`): a peer's regional
    /// batch for a cell inside one is forwarded.
    pub fn set_taken(&self, areas: Vec<Region>) {
        self.control(Command::Taken(areas));
    }

    /// Whether this relay gathers and publishes the live world product: a relay at the top of the
    /// area tree, holding every area's positions and regional data.
    pub fn set_world(&self, world: bool) {
        self.control(Command::Live(world));
    }

    /// Whether this relay gathers and publishes the precise world product.
    pub fn set_world_precise(&self, precise: bool) {
        self.control(Command::Precise(precise));
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
        self.shared.watermark_ms.load(Ordering::Acquire)
    }

    /// A receiver's newest signed description (verified by the hub): where its area is, and
    /// whether it chose this relay. A receiver that declares no location has no area and is in
    /// no regional product.
    pub fn described(&self, info: &ReceiverInfo) {
        let (Ok(receiver), Ok(content)) = (info.receiver(), info.content()) else {
            return;
        };
        let Ok(mut located) = self.located[usize::from(raw_shard(&receiver).0)].lock() else {
            return;
        };
        match content.location.map(|location| area_of(&location)) {
            Some(Ok(area)) => {
                let mut relays = content.relays;
                relays.truncate(RELAYS_PER_RECEIVER);
                located.insert_active(receiver, Located { area, relays });
            }
            _ => {
                located.remove(&receiver);
            }
        }
    }

    /// The area whose regional product a receiver's receptions join: its area, when it chose this
    /// relay. Read once per batch, by the ingest worker that owns the receiver's shard.
    pub fn area_for(&self, receiver: &PublicKey) -> Option<Region> {
        let own = self.own.get()?;
        let mut located = self.located[usize::from(raw_shard(receiver).0)]
            .lock()
            .ok()?;
        let area = match located.get(receiver) {
            Some(located) if located.relays.contains(own) => located.area,
            _ => return None,
        };
        located.touch(receiver);
        Some(area)
    }

    /// The key this relay signs its products with.
    pub fn adopt_identity(&self, identity: &Identity) {
        if self.own.set(identity.public()).is_ok() {
            self.control(Command::Identity(identity.clone()));
        }
    }

    /// A clock model's manifest (verified): the inputs hash its solutions' input sets are made
    /// with. Positions waiting for it are taken now.
    pub fn clock_model(&self, model: &ClockModel, stamp_ms: u64) {
        let bytes = model.as_bytes().len();
        self.record(
            stamp_ms,
            model.id(),
            bytes,
            Input::ClockModel(model.clone()),
        );
    }

    /// Final or provisional positions (verified): candidates for the world product.
    pub fn positions(&self, positions: &Positions, stamp_ms: u64) {
        let bytes = positions.as_bytes().len();
        self.record(
            stamp_ms,
            positions.hash(),
            bytes,
            Input::Positions(positions.clone()),
        );
    }

    /// A world record a peer sent. A relay that gathers the world takes its fixes as candidates,
    /// except one that disagrees with an origin this relay holds. Nothing is sent back.
    pub fn world_from(&self, asker: &Asker, world: WorldPositions, stamp_ms: u64) -> Vec<Record> {
        if asker.role != AskerRole::Relay || world.verify().is_err() {
            return Vec::new();
        }
        if let Ok(content) = world.content() {
            let bytes = world_bytes(&content);
            self.record(stamp_ms, world.hash(), bytes, Input::World(content, false));
        }
        Vec::new()
    }

    /// A precise world record a peer sent: as `world_from`, into the precise product.
    pub fn precise_from(&self, asker: &Asker, world: WorldPrecise, stamp_ms: u64) -> Vec<Record> {
        if asker.role != AskerRole::Relay || world.verify().is_err() {
            return Vec::new();
        }
        if let Ok(content) = world.content() {
            let bytes = world_bytes(&content);
            self.record(stamp_ms, world.hash(), bytes, Input::World(content, true));
        }
        Vec::new()
    }

    /// A regional batch a peer sent: once, its ADS-B positions become world candidates, and when
    /// its cell is inside an area this relay takes it is forwarded unchanged
    /// ([`Products::take_forward`], never down the connection it came in on). Nothing is sent back.
    pub fn regional_from(
        &self,
        asker: &Asker,
        regional: RegionalBatch,
        stamp_ms: u64,
    ) -> Vec<Record> {
        if asker.role != AskerRole::Relay || regional.verify().is_err() {
            return Vec::new();
        }
        let bytes = regional.as_bytes().len();
        self.record(
            stamp_ms,
            regional.hash(),
            bytes,
            Input::Regional(asker.source, regional),
        );
        Vec::new()
    }

    /// The watermark passed `watermark_ms` with nothing flowing to say so: every record stamped
    /// before it is taken in, then every world second it settles is sealed. The message
    /// exchange's epochs say it as they close; this is for a products of their own (a test).
    pub fn advance(&self, watermark_ms: u64) {
        self.control(Command::Advance(watermark_ms));
    }

    /// Peers' regional batches to forward unchanged, each with the connection it came in on: the
    /// hub's fan-out sends it to every other.
    pub fn take_forward(&self) -> Vec<(u64, RegionalBatch)> {
        let forward = self
            .shared
            .outbox
            .lock()
            .map(|mut outbox| {
                outbox.forward_charge.shrink_to(0);
                std::mem::take(&mut outbox.forward)
            })
            .unwrap_or_default();
        if let Ok(mut report) = self.shared.report.lock() {
            report.regional_forwarded += forward.len() as u64;
        }
        forward
    }

    /// What the sealer signed since the last call, as this relay's: each area's copies once an
    /// epoch, and every world second whose seal has come. With `identity` the products sign as it
    /// from now on.
    pub fn tick(&self, identity: Option<&Identity>) -> Vec<Record> {
        if let Some(identity) = identity {
            self.adopt_identity(identity);
        }
        self.shared
            .outbox
            .lock()
            .map(|mut outbox| {
                outbox.records_charge.shrink_to(0);
                std::mem::take(&mut outbox.records)
            })
            .unwrap_or_default()
    }

    /// The deduplicated stream's epochs sealed since the last call, in order, and how many were
    /// refused whole since then.
    pub fn take_stream(&self) -> (Vec<Observation>, u64) {
        let Ok(mut outbox) = self.shared.outbox.lock() else {
            return (Vec::new(), 0);
        };
        let stream = outbox
            .stream
            .drain(..)
            .flat_map(|(stream, _charge)| stream)
            .collect();
        (stream, std::mem::take(&mut outbox.stream_refused))
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
    fn new(boot_id: u64, threads: usize, shared: Arc<Shared>) -> Self {
        Self {
            coordinator: Coordinator::new(threads),
            pool: Pool::default(),
            identity: None,
            digest_key: RandomState::new(),
            boot_id,
            sequence: 0,
            taken: Vec::new(),
            live: Gatherer::new(WORLD_SETTLE_MS, false),
            precise: Gatherer::new(WORLD_PRECISE_SETTLE_MS, true),
            regional_seen: Bounded::new(REGIONAL_REMEMBERED),
            models: Bounded::new(MODELS_REMEMBERED),
            waiting: HashMap::new(),
            waiting_count: 0,
            derived: Bounded::new(DERIVED_REMEMBERED),
            report: ProductsReport::default(),
            watermark_ms: 0,
            shared,
        }
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Frozen(frozen) => {
                let ready = self.coordinator.take(frozen);
                self.report.epoch_parts_lost += ready.parts_lost;
                self.report.receptions_late += ready.late;
                let watermark = ready.watermark;
                for merged in ready.merged {
                    // The records stamped in or before the epoch are candidates beside it.
                    self.take_records(end_of(merged.epoch));
                    self.seal_epoch(merged);
                }
                // Every epoch before the watermark is closed: the world seals by it, whether or
                // not anything flowed.
                if let Some(watermark) = watermark {
                    self.advance(watermark * crate::seal::EPOCH_MS);
                }
            }
            Command::Identity(identity) => self.identity = Some(identity),
            Command::Taken(areas) => self.taken = areas,
            Command::Live(on) => self.live.on = on,
            Command::Precise(on) => self.precise.on = on,
            Command::Advance(watermark_ms) => self.advance(watermark_ms),
        }
    }

    fn publish_report(&self) {
        if let Ok(mut report) = self.shared.report.lock() {
            // What the handle counted itself is kept.
            let records_refused = report.records_refused;
            let forwarded = report.regional_forwarded;
            let stream_oversized = report.stream_oversized;
            *report = self.report;
            report.records_refused = records_refused;
            report.regional_forwarded = forwarded;
            report.stream_oversized = stream_oversized;
        }
    }

    /// Takes in every record stamped before `before_ms`, in the order of their stamps (then
    /// hashes), and from now on stamps a record handed in no earlier than that. What it is charged
    /// is released as it is taken in: what it leaves held is the gatherers' and the waiting
    /// list's, each bounded by count.
    fn take_records(&mut self, before_ms: u64) {
        let mut due = match self.shared.records.lock() {
            Ok(mut records) => {
                records.taken_before = records.taken_before.max(before_ms);
                let (due, waiting): (Vec<Pending>, Vec<Pending>) =
                    std::mem::take(&mut records.pending)
                        .into_iter()
                        .partition(|pending| pending.stamp_ms < before_ms);
                records.pending = waiting;
                due
            }
            Err(_) => return,
        };
        due.sort_by_key(|pending| (pending.stamp_ms, pending.hash));
        for Pending {
            stamp_ms, input, ..
        } in due
        {
            match input {
                Input::Positions(positions) => self.take_positions(positions, stamp_ms),
                Input::ClockModel(model) => self.clock_model(&model, stamp_ms),
                Input::World(content, precise) => self.take_world(content, precise, stamp_ms),
                Input::Regional(source, regional) => {
                    self.regional_from(source, regional, stamp_ms);
                }
            }
        }
    }

    /// One epoch, whole: its stream to the hub, its areas signed, its fixes offered, and every
    /// world second its end settles sealed. A refused epoch is counted, and the world still
    /// advances by it.
    fn seal_epoch(&mut self, merged: Merged) {
        let end_ms = end_of(merged.epoch);
        let mut records = Vec::new();
        if merged.refused {
            // Refused whole: the deduplicated stream misses it too, and says so.
            self.report.epochs_refused += 1;
            self.report.stream_refused += 1;
            if let Ok(mut outbox) = self.shared.outbox.lock() {
                outbox.stream_refused += 1;
            }
        } else {
            let stream: Vec<Observation> = merged
                .stream
                .iter()
                .map(|copy| copy.decoded.view(copy.obs()).to_observation())
                .collect();
            if !stream.is_empty()
                && let Ok(mut outbox) = self.shared.outbox.lock()
            {
                match self.shared.gauge().try_charge(observations_bytes(&stream)) {
                    Some(charge) => outbox.stream.push_back((stream, charge)),
                    None => {
                        outbox.stream_refused += 1;
                        self.report.stream_refused += 1;
                    }
                }
            }
            for regional in self.seal_regional(merged.epoch, merged.regional) {
                records.push(Record::RegionalBatch(regional));
            }
        }
        // The epoch's batches, and what they are charged, are let go now.
        drop(merged.charges);
        records.extend(self.advance_records(end_ms));
        self.out(records);
    }

    /// The watermark passed `watermark_ms`: every record stamped before it is taken in, what it
    /// seals goes out, and only then does the handle read the new watermark, so a reader that sees
    /// it finds everything sealed by it.
    fn advance(&mut self, watermark_ms: u64) {
        self.take_records(watermark_ms);
        let records = self.advance_records(watermark_ms);
        self.out(records);
        self.publish_report();
        self.shared
            .watermark_ms
            .store(self.watermark_ms, Ordering::Release);
    }

    fn out(&mut self, records: Vec<Record>) {
        if records.is_empty() {
            return;
        }
        let bytes = records.iter().map(record_bytes).sum();
        if let Ok(mut outbox) = self.shared.outbox.lock() {
            if outbox.records_charge.bytes() == 0 {
                outbox.records_charge = self.shared.gauge().empty();
            }
            if outbox.records_charge.try_grow(bytes) {
                outbox.records.extend(records);
            } else {
                self.report.epochs_refused += 1;
            }
        }
    }

    /// The watermark is `watermark_ms`: positions waiting too long expire, and every world second
    /// it settles is sealed and signed.
    fn advance_records(&mut self, watermark_ms: u64) -> Vec<Record> {
        self.watermark_ms = self.watermark_ms.max(watermark_ms);
        let now_ms = self.watermark_ms;
        self.expire_waiting(now_ms);
        let mut out = Vec::new();
        let live = self.seal(false, now_ms);
        let precise = self.seal(true, now_ms);
        if let Some(identity) = &self.identity {
            for (second, fixes) in live {
                let parts = world_parts(identity, second, fixes);
                self.report.world_signed += parts.len() as u64;
                out.extend(parts.into_iter().map(Record::WorldPositions));
            }
            for (second, fixes) in precise {
                let parts = precise_parts(identity, second, fixes);
                self.report.precise_signed += parts.len() as u64;
                out.extend(parts.into_iter().map(Record::WorldPrecise));
            }
        }
        out
    }

    /// An epoch's copies, area by area in cell order, as signed regional batches. Their time is
    /// the epoch's end. Without an identity the copies are counted and dropped.
    ///
    /// The work is the pool's ([`Pool::map`]): each area's observations are
    /// gathered and cut to fit a record ([`cut`]), then, numbered here in cell order, each record is
    /// signed and its ADS-B fixes derived. What is decided (the numbering, the fixes remembered and
    /// offered) is decided here, in that order, so the records are the same on any number of
    /// threads.
    fn seal_regional(
        &mut self,
        epoch: Epoch,
        areas: BTreeMap<u64, (Region, Vec<crate::seal::Copy>)>,
    ) -> Vec<RegionalBatch> {
        let mut sealed = Vec::new();
        let wall_ms = end_of(epoch);
        let Some(identity) = self.identity.clone() else {
            self.report.regional_unsigned += areas
                .values()
                .map(|(_, copies)| copies.len() as u64)
                .sum::<u64>();
            return sealed;
        };
        let boot_id = self.boot_id;
        let cuts = self.pool.map(areas.into_values().collect(), move |area| {
            cut(area, boot_id, wall_ms)
        });
        let mut chunks = Vec::new();
        for cut in cuts {
            self.report.regional_oversized += cut.oversized;
            for copies in cut.chunks {
                chunks.push((cut.cell, self.sequence, copies));
                self.sequence += 1;
            }
        }
        let signed = self.pool.map(chunks, move |(cell, sequence, copies)| {
            match RegionalBatch::sign_draft(
                &identity,
                &draft(cell, (boot_id, sequence, wall_ms), &copies),
            ) {
                Ok(regional) => {
                    let fixes = regional_fixes(&regional).ok();
                    Ok((regional, fixes))
                }
                // `cut` made it fit, so this is never reached; were it, it is counted.
                Err(_) => Err(copies.len() as u64),
            }
        });
        for outcome in signed {
            match outcome {
                Ok((regional, fixes)) => {
                    self.report.regional_signed += 1;
                    self.regional_seen.insert(regional.hash(), ());
                    for fix in fixes.into_iter().flatten() {
                        self.remember(&fix);
                        self.offer_fix(fix, wall_ms);
                    }
                    sealed.push(regional);
                }
                Err(lost) => self.report.regional_oversized += lost,
            }
        }
        sealed
    }

    fn clock_model(&mut self, model: &ClockModel, stamp_ms: u64) {
        let Ok(manifest) = model.manifest() else {
            return;
        };
        let id = model.id();
        self.models.insert(id, manifest.inputs);
        if let Some(waiting) = self.waiting.remove(&id) {
            self.waiting_count -= waiting.len();
            for (arrived, positions) in waiting {
                if stamp_ms.saturating_sub(arrived) <= WAITING_MS {
                    self.take_positions(positions, arrived);
                }
            }
        }
    }

    fn take_world(&mut self, content: WorldPositionsContent, precise: bool, stamp_ms: u64) {
        let on = if precise {
            self.precise.on
        } else {
            self.live.on
        };
        if !on {
            return;
        }
        for fix in content.fixes {
            if fix.transmitted.unix_ms / 1_000 != content.second || (precise && fix.provisional) {
                continue;
            }
            let derived = self.derived.get(&(fix.origin, fix.origin_index)).copied();
            match derived {
                Some(digest) if digest != self.digest(&fix) => self.report.world_refuted += 1,
                _ => self.offer_to(fix, precise, stamp_ms),
            }
        }
    }

    fn regional_from(&mut self, source: u64, regional: RegionalBatch, stamp_ms: u64) {
        let Ok(content) = regional.content() else {
            return;
        };
        let fresh = content.wall_ms.saturating_add(REGIONAL_MAX_AGE_MS) >= stamp_ms
            && content.wall_ms <= stamp_ms.saturating_add(REGIONAL_MAX_AHEAD_MS);
        if !fresh {
            self.report.regional_stale += 1;
            return;
        }
        if self.regional_seen.get(&regional.hash()).is_some() {
            return;
        }
        self.regional_seen.insert(regional.hash(), ());
        self.take_regional(&regional, stamp_ms);
        let taken = self.taken.iter().any(|area| area.contains(content.cell));
        if taken && let Ok(mut outbox) = self.shared.outbox.lock() {
            if outbox.forward_charge.bytes() == 0 {
                outbox.forward_charge = self.shared.gauge().empty();
            }
            if outbox.forward.len() < FORWARD_HELD
                && outbox.forward_charge.try_grow(regional.as_bytes().len())
            {
                outbox.forward.push((source, regional));
            } else {
                self.report.regional_forward_full += 1;
            }
        }
    }

    /// A regional batch's ADS-B fixes, as candidates and as what a peer's citing fix must equal.
    fn take_regional(&mut self, regional: &RegionalBatch, stamp_ms: u64) {
        let Ok(fixes) = regional_fixes(regional) else {
            return;
        };
        for fix in fixes {
            self.remember(&fix);
            self.offer_fix(fix, stamp_ms);
        }
    }

    fn take_positions(&mut self, positions: Positions, stamp_ms: u64) {
        let models = &self.models;
        match positions_fixes(&positions, |id| models.get(id).copied()) {
            Ok(Derived::Fixes(fixes)) => {
                for fix in fixes {
                    self.remember(&fix);
                    self.offer_fix(fix, stamp_ms);
                }
            }
            Ok(Derived::NeedsModel(id)) => {
                if self.waiting_count < WAITING_HELD {
                    self.waiting
                        .entry(id)
                        .or_default()
                        .push((stamp_ms, positions));
                    self.waiting_count += 1;
                } else {
                    self.report.positions_waiting_full += 1;
                }
            }
            Err(_) => self.report.positions_underivable += 1,
        }
    }

    fn expire_waiting(&mut self, now_ms: u64) {
        let mut count = 0;
        let mut expired = 0;
        self.waiting.retain(|_, records| {
            let before = records.len();
            records.retain(|(arrived, _)| now_ms.saturating_sub(*arrived) <= WAITING_MS);
            expired += (before - records.len()) as u64;
            count += records.len();
            !records.is_empty()
        });
        self.waiting_count = count;
        self.report.positions_waiting_expired += expired;
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
        hasher.write_u8(u8::from(fix.provisional));
        hasher.write_u8(u8::from(fix.mlat));
        hasher.write(&fix.input_set);
        hasher.finish()
    }

    fn remember(&mut self, fix: &WorldFix) {
        let digest = self.digest(fix);
        self.derived.insert((fix.origin, fix.origin_index), digest);
    }

    /// One candidate, for each world product that takes it.
    fn offer_fix(&mut self, fix: WorldFix, stamp_ms: u64) {
        self.offer_to(fix, false, stamp_ms);
        if !fix.provisional {
            self.offer_to(fix, true, stamp_ms);
        }
    }

    /// One candidate for one product, stamped `stamp_ms`: held when its second is open and it
    /// ranks above the aircraft's best so far. Its window is reckoned from its stamp alone (a
    /// record is taken in before the watermark passes its stamp, so the two agree), and whether
    /// its second is sealed from the watermarks before its stamp: never from when it was handled.
    fn offer_to(&mut self, fix: WorldFix, precise: bool, stamp_ms: u64) {
        let now_ms = stamp_ms;
        let gatherer = if precise {
            &mut self.precise
        } else {
            &mut self.live
        };
        if !gatherer.on || (gatherer.finals_only && fix.provisional) {
            return;
        }
        let second = fix.transmitted.unix_ms / 1_000;
        let now_second = now_ms / 1_000;
        let floor = gatherer
            .sealed_through
            .unwrap_or_else(|| now_second.saturating_sub(WORLD_BEHIND_SECONDS));
        if second <= floor && gatherer.sealed_through.is_some() {
            self.report.world_late += 1;
            return;
        }
        if second < floor || second > now_second + WORLD_AHEAD_SECONDS {
            self.report.world_out_of_window += 1;
            return;
        }
        let held_total = self.live.held + self.precise.held;
        let gatherer = if precise {
            &mut self.precise
        } else {
            &mut self.live
        };
        let aircraft = gatherer.fixes.entry(second).or_default();
        let full = held_total >= MAX_WORLD_HELD || aircraft.len() >= MAX_WORLD_AIRCRAFT;
        match aircraft.get_mut(&fix.address) {
            Some(held) => {
                if fix.ranks_above(held) {
                    *held = fix;
                }
            }
            None if full => {
                self.report.world_skipped += 1;
            }
            None => {
                aircraft.insert(fix.address, fix);
                gatherer.held += 1;
            }
        }
    }

    /// Every second of one product whose seal has come by `now_ms` (a watermark), each with its
    /// fixes ascending by address; later candidates for them are late.
    fn seal(&mut self, precise: bool, now_ms: u64) -> Vec<(u64, Vec<WorldFix>)> {
        let gatherer = if precise {
            &mut self.precise
        } else {
            &mut self.live
        };
        // Second `s` is due once `(s + 1) * 1000 + settle` has passed.
        let Some(due) = (now_ms.saturating_sub(gatherer.settle_ms) / 1_000).checked_sub(1) else {
            return Vec::new();
        };
        if !gatherer.on {
            gatherer.fixes.clear();
            gatherer.held = 0;
            gatherer.sealed_through = Some(due);
            return Vec::new();
        }
        let open = gatherer.fixes.split_off(&(due + 1));
        let sealed = std::mem::replace(&mut gatherer.fixes, open);
        gatherer.sealed_through = Some(
            gatherer
                .sealed_through
                .map_or(due, |through| through.max(due)),
        );
        sealed
            .into_iter()
            .map(|(second, aircraft)| {
                gatherer.held -= aircraft.len();
                (second, aircraft.into_values().collect())
            })
            .collect()
    }
}

/// One area's receptions as the records they will be: its cell, its observations cut into lists
/// each of which makes a record that fits, in order, and the copies too large for any record.
struct Cut {
    cell: Region,
    chunks: Vec<Vec<crate::seal::Copy>>,
    oversized: u64,
}

/// The draft of one record of `cell`'s copies: each read where its batch holds it, never copied
/// (`RegionalBatch::sign_draft` writes the bytes its owned copies would).
fn draft(
    cell: Region,
    (boot_id, sequence, wall_ms): (u64, u64, u64),
    copies: &[crate::seal::Copy],
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
fn cut((cell, mut copies): (Region, Vec<crate::seal::Copy>), boot_id: u64, wall_ms: u64) -> Cut {
    let mut todo: Vec<Vec<crate::seal::Copy>> = Vec::new();
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

/// The sealer's pool (RFC-0178 §4): threads of its own, started with the sealer and stopped with
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

/// One second's final fixes, ascending by address, as signed precise parts of at most
/// `MAX_WORLD_FIXES`.
pub fn precise_parts(identity: &Identity, second: u64, fixes: Vec<WorldFix>) -> Vec<WorldPrecise> {
    fixes
        .chunks(MAX_WORLD_FIXES)
        .enumerate()
        .filter_map(|(part, chunk)| {
            WorldPrecise::sign(
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

/// One second's fixes, ascending by address, as signed parts of at most `MAX_WORLD_FIXES`.
pub fn world_parts(identity: &Identity, second: u64, fixes: Vec<WorldFix>) -> Vec<WorldPositions> {
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
    /// One fix per solution, in the record's order.
    Fixes(Vec<WorldFix>),
    /// A solution cites a model whose inputs are not known yet: this one.
    NeedsModel(Hash),
}

/// The world fixes of a final (`Positions`) or provisional (`Provisional`) record: each solution
/// as published, its input set the merge rule's over its observations and the inputs hash of the
/// model it cites (`inputs_of`, by model id).
pub fn positions_fixes(
    positions: &Positions,
    inputs_of: impl Fn(&Hash) -> Option<Hash>,
) -> Result<Derived, WireError> {
    let content = positions.solutions()?;
    let origin = positions.hash();
    let source = positions.engine()?;
    let provisional = positions.is_provisional();
    let mut fixes = Vec::with_capacity(content.solutions.len());
    for (index, solution) in content.solutions.iter().enumerate() {
        let Some(inputs) = inputs_of(&solution.clock_model) else {
            return Ok(Derived::NeedsModel(solution.clock_model));
        };
        fixes.push(WorldFix {
            address: solution.address,
            transmitted: solution.transmitted,
            lat_e7: solution.lat_e7,
            lon_e7: solution.lon_e7,
            alt_hae_mm: solution.alt_hae_mm,
            pressure_altitude_ft: pressure_ft(solution.observations.message()),
            covariance: solution.covariance,
            provisional,
            mlat: true,
            input_set: input_set(&solution.observations, &inputs),
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
                provisional: false,
                mlat: false,
                input_set: adsb_input_set(&observation.data, &pair.data),
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
        Record::Positions(positions) | Record::Provisional(positions) => {
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
