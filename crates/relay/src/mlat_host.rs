//! One program (RFC-0174 §2.1, §2.3): the relay runs MLAT for the areas it is an MLAT relay for,
//! in-process, through this seam. The hub offers every receiver batch and description it forwards
//! ([`MlatHost::offer`]): its own feeders' and the raw other relays pass it one hop for those
//! areas and their border band. The network task tells the host its areas ([`MlatHost::set_areas`],
//! `selection` decides them) and takes what it signed ([`MlatHost::take_published`]) into the
//! fan-out as the relay's own, through `Hub::publish_own`. The host is `tally-mlat`'s engine
//! (`tally_mlat::engine::Engine`) under the relay's key, the same library and the same bytes as
//! the reference drive of it (`tally_mlat::replay`), with no network between the raw and the
//! solver. There is no engine program apart from a relay.
//!
//! - **Areas.** For areas `A` the engine holds the receivers of `A` and its border band
//!   (`tally_mlat::area::border_band`, the cells `selection` subscribes to) and fits only the
//!   tiles whose centre is in `A` (`tally_mlat::window::owns`), so an area's k relays fit its
//!   tiles and no others. A change of areas re-scopes the engine in place (`Engine::set_scope`);
//!   no area at all drops the engine and every byte of raw it held, and the next area starts a new
//!   one under a new boot id, so the relay's records never reuse a (key, boot, sequence).
//! - **One store of raw, held where it arrives** (RFC-0178 §5). The receivers and their open raw
//!   are held in raw shards keyed by receiver (`exchange::raw_shard`, one `tally_mlat::intake::Intake`
//!   each), and a batch is taken into its shard by the ingest worker that decoded it
//!   ([`MlatHost::offer_batch`]), in parallel, never on the engine's thread, which neither
//!   verifies, decodes nor holds a batch. At each step the engine's thread takes the bins that are
//!   complete out of every shard (a move, under each shard's lock in turn), and they are sealed off
//!   that thread with no lock held (`Bin::seal_from`, byte for byte what one holder of all the raw
//!   seals); the engine (`Engine::hosted`) solves the sealed bins, shared (`Arc`), and the relay's
//!   standing reads the same bins ([`MlatHost::sealed_bins`]), so raw later than settling is
//!   missing for both alike. The handle outlives each engine (emptied when one is dropped). How
//!   many receivers and how much raw it holds is configuration (`tally_mlat::engine::Capacity`),
//!   from the receivers the relay admits.
//! - **Provisional state sharded by aircraft** (RFC-0178 §3). What a batch says to provisional
//!   solving (`provisional::notes_of`, read in its raw shard by the ingest worker that took it) is
//!   split by ICAO address (`provisional::shard_of`, a hash keyed by the process's secret) into
//!   `provisional::SHARDS` address shards, each holding its aircraft's state (`provisional::Shard`)
//!   and what it was told and has not weighed yet. Each provisional step weighs every shard's notes
//!   stamped before it in the batches' order (`provisional::Order`), keeps or refuses each batch's
//!   replies whole across every shard, finds what is due, all shards in parallel over
//!   `--mlat-threads`, and solves the due work of all of them, ascending by aircraft
//!   (`provisional::Plan::job`): the same stamped trace solves the same provisionals on any number
//!   of ingest workers and step threads. The engine's thread holds only the models carried and the
//!   sequences.
//! - **Stepped by the stamp watermark, never by a clock** (RFC-0178 §4, invariants 1 to 3). The
//!   relay asks with its stamp watermark ([`MlatHost::take_published`]: every batch stamped before
//!   it has been offered), the one the products seal by. The host steps at every multiple of
//!   `STEP_MS` the watermark passes, each once and in order: step `t` weighs exactly the batches
//!   stamped before `t`, and takes for sealing every bin complete by `t`. A batch's raw stamped at or
//!   after the step that takes its bin is late by its stamp (`held::Closing`), whether it raced
//!   ahead of that step or came after it; its notes wait for the step of their stamp whatever
//!   thread told them. So a batch held up on its way here (an ingest worker blocked on the message
//!   exchange's back-pressure) is weighed exactly where its stamp says, and the same stamped trace
//!   makes the same bytes however the threads interleave or how long any stage takes.
//! - **Threads.** One thread owns the engine and runs the steps one at a time, in order. A step's
//!   provisional solving (weighing every address shard, then solving what is due) and its seal and
//!   window step run off that thread, at once, each spread over `--mlat-threads`; the next step
//!   starts when both have reported, so a step's provisional solving carries the models of every
//!   window step before it, as the engine solving in line does. A step that falls behind waits;
//!   nothing is coalesced or skipped.
//! - **Capacity** (RFC-0178 §9). The receivers seated are the best ranked of those described
//!   (`tally_mlat::intake::Seats`: taking part first, then a draw under the relay's secret no
//!   feeder can choose), whichever raw shard took them and in whatever order, as many as the
//!   relay's feeder ceiling admits (`capacity`, the same F every store is sized by); a shard's open
//!   raw is bounded by each receiver's share of a bin, and the engine's whole bytes are checked on
//!   each complete bin as it is sealed (`tally_mlat::engine::seal`), within the relay's `Held` store
//!   ([`host_for`]), which the host charges at every step for what it really holds. What batches tell
//!   provisional solving is bounded per step, `NOTES_PER_RECEIVER_STEP` a seat: a step's notes
//!   beyond it are refused whole, the step's every batch, and a batch's replies that do not fit the
//!   provisional state are refused in every address shard at once (`provisional::admit`). Signed
//!   records not yet taken are bounded in bytes, a step's refused whole, so a part never goes
//!   without its manifest. None of it depends on arrival order or on the number of threads; all of
//!   it is counted.
//! - **Counted.** Nothing offered or solved is let go silently: every drop is counted by why, and
//!   every step's report kept ([`MlatReport`], served on `--stats-listen` as `GET /mlat`).
//! - **Time.** Nothing here reads a clock: a batch carries its stamp and `take_published` the
//!   watermark, so the same stamped records publish the same bytes as the engine driven in line on
//!   the same steps.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};

use tally_mlat::engine::{Capacity, Dropped, Engine, Ingested, Settings};
use tally_mlat::intake::{Description, Intake, Seats};
use tally_mlat::provisional::{self as provisional_, Due, Note, Order, Taken};
use tally_mlat::{area, provisional, window};
use tally_mlat_solver::Site;
use tally_mlat_solver::held::{Bin, Closing, Fragment, Limits, SealedBins};
use tally_wire::{Decoded, Identity, PublicKey, ReceiverInfo, Record, Region};

use crate::budget::{Budget, Charge, Gauge, Store};
use crate::config::Config;
use crate::exchange::{SHARDS, raw_shard};

/// The MLAT a relay hosts.
pub trait MlatHost: Send + Sync {
    /// The areas to solve (plus their border band): the receivers it holds are theirs.
    /// `descriptions` are every receiver description the relay holds (`Hub::descriptions`), for
    /// a host that has not been offered them. The relay calls this when the areas change.
    fn set_areas(&self, areas: Vec<Region>, descriptions: Vec<ReceiverInfo>);
    /// A receiver's description the relay kept. A batch reaches the host only as the relay's one
    /// decode of it (`offer_batch`): there is no second way in, so none decodes it again.
    fn offer_description(&self, info: &ReceiverInfo);
    /// A receiver's batch the relay forwarded, verified and decoded once by its ingest, on the
    /// ingest worker that owns the receiver's raw shard, stamped `now_ms` (its `stamp_ms`): taken
    /// into that shard, never verified or decoded again.
    fn offer_batch(&self, batch: &Arc<Decoded>, now_ms: u64);
    /// What it signed since the last call (clock models and their parts, positions, provisional
    /// positions), in the order to publish. `watermark_ms` is the relay's stamp watermark: every
    /// batch stamped before it has been offered (`offer_batch` returned), the one the products
    /// seal by (`Products::watermark_ms`). The host steps by it (module docs), never by a clock.
    fn take_published(&self, watermark_ms: u64) -> Vec<Record>;
    /// The cores it offers (what `ProviderOffer.mlat_cores` declares).
    fn cores(&self) -> u16;
    /// What it has done and let go, since it started.
    fn report(&self) -> MlatReport;
    /// The sealed bins of the raw it holds, shared: what the relay's standing reads (one store of
    /// raw per relay). None when it holds no raw of its own.
    fn sealed_bins(&self) -> Option<SealedBins>;
}

/// One window step's report, as served: `tally_mlat::window::Report`, times in milliseconds.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepReport {
    pub windows: u64,
    pub bins: u64,
    pub targets: u64,
    pub tiles: u64,
    /// Tiles whose footprint the relay's areas do not wholly cover: not fitted.
    pub uncovered: u64,
    pub fits: u64,
    pub unfitted: u64,
    pub unfitted_reason: Option<String>,
    pub transmissions: u64,
    pub solved: u64,
    pub unsolved: u64,
    /// Solutions the verifier refused (and were not published).
    pub rejected: u64,
    pub clock_models: u64,
    pub clock_model_bytes: u64,
    pub positions: u64,
    pub positions_bytes: u64,
    pub fit_ms: u64,
    pub solve_ms: u64,
    pub elapsed_ms: u64,
}

impl StepReport {
    fn of(report: &window::Report) -> Self {
        let n = |count: usize| count as u64;
        let ms = |time: std::time::Duration| u64::try_from(time.as_millis()).unwrap_or(u64::MAX);
        Self {
            windows: n(report.windows),
            bins: n(report.bins),
            targets: n(report.targets),
            tiles: n(report.tiles),
            uncovered: n(report.uncovered),
            fits: n(report.fits),
            unfitted: n(report.unfitted),
            unfitted_reason: report.unfitted_reason.clone(),
            transmissions: n(report.transmissions),
            solved: n(report.solved),
            unsolved: n(report.unsolved),
            rejected: n(report.rejected),
            clock_models: n(report.clock_models),
            clock_model_bytes: n(report.clock_model_bytes),
            positions: n(report.positions),
            positions_bytes: n(report.positions_bytes),
            fit_ms: ms(report.fit_time),
            solve_ms: ms(report.solve_time),
            elapsed_ms: ms(report.elapsed),
        }
    }

    fn add(&mut self, other: &Self) {
        self.windows += other.windows;
        self.bins += other.bins;
        self.targets += other.targets;
        self.tiles += other.tiles;
        self.uncovered += other.uncovered;
        self.fits += other.fits;
        self.unfitted += other.unfitted;
        if self.unfitted_reason.is_none() {
            self.unfitted_reason.clone_from(&other.unfitted_reason);
        }
        self.transmissions += other.transmissions;
        self.solved += other.solved;
        self.unsolved += other.unsolved;
        self.rejected += other.rejected;
        self.clock_models += other.clock_models;
        self.clock_model_bytes += other.clock_model_bytes;
        self.positions += other.positions;
        self.positions_bytes += other.positions_bytes;
        self.fit_ms += other.fit_ms;
        self.solve_ms += other.solve_ms;
        self.elapsed_ms += other.elapsed_ms;
    }
}

/// Provisional solving, summed since the host started (`tally_mlat::provisional::Report`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvisionalReport {
    pub transmissions: u64,
    pub solved: u64,
    pub unsolved: u64,
    pub rejected: u64,
    /// Receptions no model held could map, given up on.
    pub unmodelled: u64,
    /// Receptions refused for room: a batch's replies that did not fit, whole
    /// (`provisional::admit`).
    pub dropped: u64,
    pub records: u64,
}

impl ProvisionalReport {
    fn add(&mut self, report: &provisional::Report) {
        self.transmissions += report.transmissions as u64;
        self.solved += report.solved as u64;
        self.unsolved += report.unsolved as u64;
        self.rejected += report.rejected as u64;
        self.unmodelled += report.unmodelled as u64;
        self.dropped += report.dropped as u64;
        self.records += report.records as u64;
    }
}

/// What a hosted MLAT has done and let go since it started, every drop by why (`GET /mlat`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlatReport {
    /// Batches taken (new, from a receiver taking part).
    pub ingested: u64,
    /// Batches whose notes to provisional solving were refused whole with their step's: the
    /// notes stamped in one step passed `NOTES_PER_RECEIVER_STEP` a seat. Counted when the step is
    /// weighed, so the count is the trace's, whatever the interleaving.
    pub refused: u64,
    /// Signed records refused whole with their step's because those not yet taken held
    /// `PUBLISHED_BYTES`.
    pub overflowed: u64,
    /// Batches whose (boot, sequence) was already used or too far behind.
    pub replayed: u64,
    /// Receiver descriptions refused as not signed as they claim.
    pub ingest_errors: u64,
    /// Batches of undescribed receivers not held, for room, and held too long.
    pub orphans_dropped: u64,
    pub orphans_expired: u64,
    /// Observations of a bin already taken for sealing: stamped at or after the step that took it.
    pub observations_late: u64,
    /// Observations refused with their receiver's whole raw of a bin, beyond its share or beyond
    /// the raw the engine holds (`tally_mlat_solver::held::Limits`).
    pub observations_refused: u64,
    /// New receivers refused whole, beyond the receivers the engine holds
    /// (`tally_mlat::engine::Capacity`).
    pub receivers_refused: u64,
    /// Seals, window and provisional steps whose engine was dropped before they reported: not
    /// published.
    pub steps_discarded: u64,
    /// Window steps applied.
    pub steps: u64,
    /// The newest step's report, and every step's summed.
    pub last_step: Option<StepReport>,
    pub steps_total: StepReport,
    pub provisional: ProvisionalReport,
}

/// The step clock's grid: the host steps at every multiple of it the watermark passes.
pub const STEP_MS: u64 = 1_000;
/// How long after a bin's canonical window ends it is solved, so the raw of its last bin is in.
pub const SETTLE_MS: u64 = 2_000;
/// Commands for the engine's thread not yet taken: a few seconds of asks and changes. An ask
/// beyond it is dropped; the next carries a watermark at least as new, which steps everything the
/// dropped one would have.
const COMMANDS_WAITING: usize = 1 << 12;
/// What batches may tell provisional solving in one step, a seat: four times RFC-0178's planned
/// rate of about 300 replies and positions a feeder a second. Beyond it the step's notes are
/// refused whole (`MlatReport::refused`), so a step holds at most this times the seats, and which
/// batches are refused is a function of the trace, never of the interleaving.
pub const NOTES_PER_RECEIVER_STEP: usize = 1_200;
/// Batches held for a receiver whose description has not come, at most, and receivers (in each raw
/// shard), and for how long: a window's worth (a description later than that is not coming by the
/// same way).
const ORPHANS_PER_RECEIVER: usize = 64;
const ORPHAN_RECEIVERS_PER_SHARD: usize = 4_096 / SHARDS;
const ORPHAN_MS: u64 = 60_000;
/// Bytes of signed records not yet taken (`Record::encoded_len`): many steps of a busy area, taken
/// by the network task every tick. A step's records that would pass it are refused whole, counted,
/// so a clock model's parts never wait without their manifest; a step's records larger than the
/// whole bound are taken only into an empty queue, so one is never refused forever.
pub const PUBLISHED_BYTES: usize = 64 << 20;

/// The hosted MLAT a relay runs, if any: none when its relay duties are off (`--no-relay-duties`)
/// or it offers no MLAT threads (`--mlat-threads 0`). Sized and charged by the relay's `budget`:
/// its seats are the feeder ceiling ([`capacity`]), its raw is the `Held` store's and its
/// provisional notes the `Notes` store's. An error when its thread cannot start.
pub fn host_for(
    config: &Config,
    identity: Identity,
    boot_id: u64,
    budget: &Budget,
) -> Result<Option<HostedMlat>, String> {
    if !config.relay_duties || config.mlat_threads == 0 {
        return Ok(None);
    }
    HostedMlat::charging(
        identity,
        boot_id,
        Settings {
            regions: Vec::new(),
            settle_ms: SETTLE_MS,
            threads: config.mlat_threads,
            capacity: capacity(budget),
        },
        budget.gauge(Store::Held),
        budget.gauge(Store::Notes),
    )
    .map(Some)
}

/// What the hosted engine holds: a seat for every feeder the relay's memory admits (the budget's
/// ceiling, RFC-0178 §9: "MLAT receiver limit comes from the same F"), and the raw of that many at
/// the measured rates, which is what the budget reserved for `Held` (`PerFeeder::planned`). No
/// floor: seats beyond the ceiling would be raw the budget never reserved.
pub fn capacity(budget: &Budget) -> Capacity {
    Capacity::for_receivers(budget.ceiling())
}

/// Where in the host a test injects a delay ([`HostedMlat::delaying`]): every stage that may run
/// late with respect to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// An offer, before it is taken into its raw shard (what an ingest worker blocked on its way
    /// here does).
    Offer,
    /// A provisional step, before it weighs.
    Provisional,
    /// A seal, before it seals.
    Seal,
    /// A window step, before it solves.
    Window,
}

/// A test's delay at a stage ([`HostedMlat::delaying`]).
pub type Delay = Arc<dyn Fn(Stage) + Send + Sync>;

/// What the engine's thread is handed.
enum Command {
    /// A receiver stopped taking part under engine generation `.0`: forgotten in the sealed bins.
    Left(u64, PublicKey),
    /// The areas changed (`set_areas` re-scoped every shard first): engine generation, areas.
    Areas(u64, Vec<Region>),
    /// The stamp watermark passed this.
    Tick(u64),
}

/// What a seal or a step reports to the engine's thread, for the engine of its generation.
enum Finished {
    /// The bins complete by step `step_ms` (through `settled`), sealed, with the sites taking part
    /// and what the shards refused.
    Sealed {
        generation: u64,
        step_ms: u64,
        settled: i64,
        bins: Vec<Bin>,
        sites: Vec<Site>,
        dropped: Dropped,
    },
    /// A window step's outcome, boxed: it is far larger than the others.
    Stepped(u64, Box<window::Outcome>),
    /// A provisional step's outcome, and the batches whose notes it refused with their step's.
    Solved(u64, provisional::Outcome, u64),
}

/// Everything the engine's thread is told, in one queue.
enum Message {
    Command(Command),
    Finished(Finished),
}

/// How long the engine's thread waits for a message before it looks whether it should stop.
const POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// One raw shard of the hosted MLAT: the intake of the receivers whose raw shard it is, and their
/// batches waiting for a description.
struct Shard {
    intake: Intake,
    /// The engine generation its intake holds raw for, and whether one runs.
    generation: u64,
    active: bool,
    /// Batches of receivers not described yet, by receiver, oldest first, with when each came:
    /// taken when the description comes. A batch can reach a relay before its receiver's
    /// description (a repair, a rebuild from parity, a link that died between them), and the hub
    /// forwards each batch once, so a batch turned away would be lost to MLAT.
    orphans: BTreeMap<PublicKey, VecDeque<(Arc<Decoded>, u64)>>,
}

/// What one batch said to one address shard, not yet weighed: the step interval it belongs to (the
/// step at the end of that interval weighs it), the batch at its place in the order, its notes
/// sorted by shard (shared by every shard it spoke to) and this shard's run of them, and the engine
/// generation of the raw shard that read them.
struct Heard {
    interval: u64,
    order: Order,
    batch: Arc<Decoded>,
    notes: Arc<[Note]>,
    range: std::ops::Range<usize>,
    generation: u64,
}

/// What a batch says to provisional solving as its raw shard read it: the batch, its notes, and the
/// raw shard's engine generation then. Handed to the address shards once the raw shard is let go.
type Told = (Arc<Decoded>, Vec<Note>, u64);

/// One address shard of provisional solving (`provisional::Shard`), with what it was told and has
/// not weighed yet.
#[derive(Default)]
struct Listening {
    heard: Vec<Heard>,
    /// The engine generation `state` is of.
    generation: u64,
    state: provisional_::Shard,
}

impl Listening {
    /// Reads, for the engine of `generation` (what an older one heard is dropped, a newer one's
    /// kept), everything heard in an interval before `through` that `refused` does not refuse, in
    /// the batches' order: the receptions waiting here, and each batch's replies to keep or refuse
    /// (`provisional::admit`).
    fn read(
        &mut self,
        generation: u64,
        through: u64,
        refused: &BTreeSet<u64>,
    ) -> (usize, Vec<Taken>) {
        if self.generation != generation {
            self.state = provisional_::Shard::default();
            self.generation = generation;
        }
        let (mut due, rest): (Vec<Heard>, Vec<Heard>) = std::mem::take(&mut self.heard)
            .into_iter()
            .partition(|heard| heard.interval < through);
        self.heard = rest;
        due.sort_unstable_by_key(|heard| heard.order);
        let mut taken = Vec::new();
        for heard in due {
            if heard.generation == generation {
                if !refused.contains(&heard.interval) {
                    taken.push(self.state.read(
                        &heard.batch,
                        &heard.notes[heard.range.clone()],
                        heard.order,
                    ));
                }
            } else if heard.generation > generation {
                // Read by a raw shard already re-scoped for the engine about to start: kept for it.
                self.heard.push(heard);
            }
        }
        (self.state.waiting(), taken)
    }

    /// Keeps or refuses what `read` handed out, as `refused` decided for every shard, and hands
    /// out what is due at `now_ms` under `book`.
    fn settle(
        &mut self,
        taken: Vec<Taken>,
        refused: &BTreeSet<Order>,
        now_ms: u64,
        book: &provisional_::Book,
    ) -> Due {
        for one in taken {
            if refused.contains(&one.order) {
                self.state.refuse(one);
            } else {
                self.state.keep(one);
            }
        }
        self.state.due(now_ms, book)
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// The notes told for one step interval: how many, of how many batches, and whether the interval
/// is refused whole.
#[derive(Default)]
struct Interval {
    notes: usize,
    batches: u64,
    refused: bool,
    /// The bytes it holds (each batch's decode and its notes), charged to the `Notes` store until
    /// the interval is weighed or refused.
    charge: Charge,
}

/// The step intervals told and not yet weighed (by interval: stamps `k * STEP_MS` to
/// `(k + 1) * STEP_MS`, weighed by the step at the end), and the last step weighed.
#[derive(Default)]
struct Intervals {
    weighed_ms: u64,
    open: BTreeMap<u64, Interval>,
}

/// The areas as `set_areas` last set them, and the engine generation they started.
#[derive(Default)]
struct Scope {
    areas: Vec<Region>,
    generation: u64,
}

/// Signed records not yet taken, and their bytes.
#[derive(Default)]
struct Published {
    records: VecDeque<Record>,
    bytes: usize,
}

/// What the relay's side and the engine's thread share.
struct Shared {
    scope: Mutex<Scope>,
    /// The raw shards, `SHARDS` of them, each locked by the ingest worker that owns its receivers
    /// (one batch at a time), and by the engine's thread to take what is complete or re-scope.
    shards: Box<[Mutex<Shard>]>,
    /// The address shards of provisional solving, `provisional::SHARDS` of them, each locked by
    /// an ingest worker to hand it a batch's notes and by a provisional step to weigh and step it.
    listening: Box<[Mutex<Listening>]>,
    /// The notes told per step interval, and the bound on one interval's.
    intervals: Mutex<Intervals>,
    notes_per_step: usize,
    /// What each shard's open raw is bounded by.
    limits: Limits,
    published: Mutex<Published>,
    /// Commands sent and not yet done with; steps queued or running.
    commands: AtomicUsize,
    steps: AtomicUsize,
    /// The last step every part of which has reported.
    stepped_ms: AtomicU64,
    /// The least stamp of a batch offered to the engine running: where its steps begin.
    earliest_ms: AtomicU64,
    /// Counted by the shards as batches come.
    ingested: AtomicU64,
    replayed: AtomicU64,
    ingest_errors: AtomicU64,
    orphans_dropped: AtomicU64,
    orphans_expired: AtomicU64,
    /// Records refused whole because those not yet taken were full.
    overflowed: AtomicU64,
    /// Everything else counted, by the engine's thread.
    counts: Mutex<MlatReport>,
    /// The sealed bins of whichever engine runs: one handle for the host's life.
    sealed: SealedBins,
    /// A test's delays (`HostedMlat::delaying`).
    delay: OnceLock<Delay>,
    /// The relay's `Notes` store: what each open interval told provisional solving.
    notes: Arc<Gauge>,
    stop: AtomicBool,
}

impl Shared {
    fn shard(&self, receiver: &PublicKey) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[usize::from(raw_shard(receiver).0)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn listening(&self, shard: usize) -> std::sync::MutexGuard<'_, Listening> {
        self.listening[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn intervals(&self) -> std::sync::MutexGuard<'_, Intervals> {
        self.intervals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn delay(&self, stage: Stage) {
        if let Some(delay) = self.delay.get() {
            delay(stage);
        }
    }

    /// Hands what `batch` said to provisional solving to the address shards it speaks of, read in
    /// its raw shard under engine `generation`, for the step of its stamp. A step interval whose
    /// notes pass `notes_per_step` is refused whole: what it held is let go now, and nothing more
    /// of it is held; the step that weighs it counts its every batch.
    fn tell(&self, batch: &Arc<Decoded>, mut notes: Vec<Note>, generation: u64) {
        let order = Order::of(batch, batch.stamp_ms());
        let interval = {
            let mut intervals = self.intervals();
            // Stamped before a step already weighed (a batch that waited for its description, which
            // carries no stamp): the next step's.
            let interval = (order.stamp_ms / STEP_MS).max(intervals.weighed_ms / STEP_MS);
            let cap = self.notes_per_step;
            let entry = intervals.open.entry(interval).or_default();
            entry.batches += 1;
            if entry.refused {
                return;
            }
            entry.notes = entry.notes.saturating_add(notes.len());
            if entry.notes > cap {
                entry.refused = true;
                entry.charge = Charge::none();
                drop(intervals);
                for shard in 0..provisional_::SHARDS {
                    self.listening(shard)
                        .heard
                        .retain(|heard| heard.interval != interval);
                }
                return;
            }
            // Charged, never refused by bytes: which steps are refused is the notes' count, a
            // function of the trace, and the count bounds what an interval holds.
            let bytes = entry
                .charge
                .bytes()
                .saturating_add(batch.footprint())
                .saturating_add(std::mem::size_of_val(notes.as_slice()));
            entry.charge.shrink_to(0);
            entry.charge = self.notes.force(bytes);
            interval
        };
        let runs = provisional_::by_shard(&mut notes);
        let notes: Arc<[Note]> = notes.into();
        for (shard, range) in runs {
            self.listening(shard).heard.push(Heard {
                interval,
                order,
                batch: Arc::clone(batch),
                notes: Arc::clone(&notes),
                range,
                generation,
            });
        }
    }

    /// The step of `step_ms` weighs every interval before it: the intervals refused, and their
    /// batches.
    fn weigh_intervals(&self, step_ms: u64) -> (BTreeSet<u64>, u64) {
        let mut intervals = self.intervals();
        intervals.weighed_ms = intervals.weighed_ms.max(step_ms);
        let later = intervals.open.split_off(&(step_ms / STEP_MS));
        let due = std::mem::replace(&mut intervals.open, later);
        let mut refused = BTreeSet::new();
        let mut batches = 0;
        for (interval, told) in due {
            if told.refused {
                refused.insert(interval);
                batches += told.batches;
            }
        }
        (refused, batches)
    }

    /// Settles each receiver of `moved` (whose seat changed while another raw shard took a
    /// description) in its own raw shard: those that stopped taking part, with their generation.
    fn settle(&self, moved: &[PublicKey]) -> Vec<(u64, PublicKey)> {
        let mut left = Vec::new();
        for key in moved {
            let mut shard = self.shard(key);
            if shard.intake.settle(key) {
                left.push((shard.generation, *key));
            }
        }
        left
    }

    fn count(&self, change: impl FnOnce(&mut MlatReport)) {
        if let Ok(mut counts) = self.counts.lock() {
            change(&mut counts);
        }
    }

    /// A step's records (a part always with its manifest), queued whole, or refused whole and
    /// counted when those not yet taken would pass `limit` bytes. Into an empty queue they are
    /// taken whatever their size, so no step is refused forever.
    fn publish(&self, records: Vec<Record>, limit: usize) {
        if records.is_empty() {
            return;
        }
        let bytes: usize = records.iter().map(Record::encoded_len).sum();
        if let Ok(mut published) = self.published.lock() {
            if published.bytes > 0 && published.bytes.saturating_add(bytes) > limit {
                self.overflowed
                    .fetch_add(records.len() as u64, Ordering::Relaxed);
                return;
            }
            published.bytes = published.bytes.saturating_add(bytes);
            published.records.extend(records);
        }
    }
}

/// `tally-mlat`'s engine as a relay's hosted MLAT.
pub struct HostedMlat {
    messages: Sender<Message>,
    shared: Arc<Shared>,
    cores: u16,
}

impl HostedMlat {
    /// The engine signs as `identity` (the relay's key); `boot_id` is its first engine's boot.
    /// `settings.regions` is ignored: the areas are `set_areas`'s. Its raw and notes are charged to
    /// gauges of no budget: for a host built apart from a relay (a test's). An error when its
    /// thread cannot start.
    pub fn new(identity: Identity, boot_id: u64, settings: Settings) -> Result<Self, String> {
        Self::charging(
            identity,
            boot_id,
            settings,
            Gauge::unlimited(Store::Held),
            Gauge::unlimited(Store::Notes),
        )
    }

    /// As `new`, its raw (open and sealed) charged to `held`, the relay's `Held` store, at every
    /// step, and its sealed bins held within that store's limit; what batches told provisional
    /// solving charged to `notes`, the relay's `Notes` store, until the step that weighs it.
    pub fn charging(
        identity: Identity,
        boot_id: u64,
        settings: Settings,
        held: Arc<Gauge>,
        notes: Arc<Gauge>,
    ) -> Result<Self, String> {
        let cores = u16::try_from(settings.threads).unwrap_or(u16::MAX);
        let (messages, received) = std::sync::mpsc::channel();
        let limits = Limits {
            bytes: usize::MAX,
            ..settings.limits()
        };
        let closing = Closing {
            step_ms: STEP_MS,
            settle_ms: settings.settle_ms,
        };
        let seats = Seats::new(settings.capacity.receivers);
        let shared = Arc::new(Shared {
            scope: Mutex::new(Scope::default()),
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        intake: Intake::new(Arc::clone(&seats), limits, None).closing(closing),
                        generation: 0,
                        active: false,
                        orphans: BTreeMap::new(),
                    })
                })
                .collect(),
            listening: (0..provisional_::SHARDS)
                .map(|_| Mutex::new(Listening::default()))
                .collect(),
            intervals: Mutex::new(Intervals::default()),
            notes_per_step: settings
                .capacity
                .receivers
                .max(1)
                .saturating_mul(NOTES_PER_RECEIVER_STEP),
            limits,
            published: Mutex::new(Published::default()),
            commands: AtomicUsize::new(0),
            steps: AtomicUsize::new(0),
            stepped_ms: AtomicU64::new(0),
            earliest_ms: AtomicU64::new(u64::MAX),
            ingested: AtomicU64::new(0),
            replayed: AtomicU64::new(0),
            ingest_errors: AtomicU64::new(0),
            orphans_dropped: AtomicU64::new(0),
            orphans_expired: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            counts: Mutex::new(MlatReport::default()),
            sealed: SealedBins::new(),
            delay: OnceLock::new(),
            notes,
            stop: AtomicBool::new(false),
        });
        let host = Host {
            identity,
            boot_id,
            engines: 0,
            generation: 0,
            settings,
            engine: None,
            queued: VecDeque::new(),
            through_ms: None,
            running: None,
            open_bytes: 0,
            held_charge: held.empty(),
            held,
            messages: messages.clone(),
            shared: Arc::clone(&shared),
        };
        let spawned = std::thread::Builder::new()
            .name("tally-mlat".to_owned())
            .spawn(move || host.run(&received));
        spawned.map_err(|error| format!("the hosted MLAT did not start: {error}"))?;
        Ok(Self {
            messages,
            shared,
            cores,
        })
    }

    /// Delays injected at every stage (`Stage`), for a test that shows they change nothing (RFC-0178
    /// invariant 2). Set once; later calls are ignored.
    pub fn delaying(&self, delay: Delay) {
        let _ = self.shared.delay.set(delay);
    }

    /// Commands handed to the engine's thread and not yet done with, and steps queued or running:
    /// zero when everything offered and asked so far is published.
    pub fn in_flight(&self) -> usize {
        self.shared.commands.load(Ordering::SeqCst) + self.shared.steps.load(Ordering::SeqCst)
    }

    /// The last step every part of which has reported (zero before the first).
    pub fn stepped_ms(&self) -> u64 {
        self.shared.stepped_ms.load(Ordering::SeqCst)
    }

    /// Batches taken: new, and from a receiver of its areas or their band.
    pub fn ingested(&self) -> u64 {
        self.shared.ingested.load(Ordering::SeqCst)
    }

    /// Batches whose notes to provisional solving were refused whole with their step's.
    pub fn refused(&self) -> u64 {
        self.shared
            .counts
            .lock()
            .map(|counts| counts.refused)
            .unwrap_or_default()
    }

    /// Records refused whole because those not yet taken were full.
    pub fn overflowed(&self) -> u64 {
        self.shared.overflowed.load(Ordering::Relaxed)
    }

    /// What was signed and not yet taken, asking for nothing more: for a caller that waited for
    /// `in_flight` to reach zero.
    pub fn take_signed(&self) -> Vec<Record> {
        self.shared
            .published
            .lock()
            .map(|mut published| {
                published.bytes = 0;
                published.records.drain(..).collect()
            })
            .unwrap_or_default()
    }

    /// Hands `command` to the engine's thread.
    fn send(&self, command: Command) {
        self.shared.commands.fetch_add(1, Ordering::SeqCst);
        if self.messages.send(Message::Command(command)).is_err() {
            self.shared.commands.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A description, into its receiver's shard: the batches that waited for it are taken now.
    /// A receiver of another shard whose seat it changed is settled in its own shard after.
    fn describe(&self, info: &ReceiverInfo) {
        let Ok(key) = info.receiver() else {
            return;
        };
        let mut told = Vec::new();
        let (mut left, moved) = {
            let mut shard = self.shared.shard(&key);
            let described = match shard.intake.describe(info) {
                Ok(described) => described,
                Err(_) => {
                    self.shared.ingest_errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            if described.ingested == Ingested::Described
                && let Some(waiting) = shard.orphans.remove(&key)
            {
                for (batch, _) in waiting {
                    let (_, heard) = self.take(&mut shard, &batch);
                    told.extend(heard);
                }
            }
            let Description { left, moved, .. } = described;
            let generation = shard.generation;
            (
                left.into_iter()
                    .map(|key| (generation, key))
                    .collect::<Vec<_>>(),
                moved,
            )
        };
        for (batch, notes, generation) in told {
            self.shared.tell(&batch, notes, generation);
        }
        // Each shard let go before the next is taken: the engine's thread may be waiting for one.
        left.extend(self.shared.settle(&moved));
        for (generation, key) in left {
            self.send(Command::Left(generation, key));
        }
    }

    /// One batch into `shard`, its receiver's: what it did, and what it says to provisional
    /// solving with the shard's engine generation, to hand to the address shards once `shard` is
    /// let go (`Shared::tell`).
    fn take(&self, shard: &mut Shard, batch: &Arc<Decoded>) -> (Ingested, Option<Told>) {
        let (ingested, notes) = shard.intake.ingest_verified(batch);
        match ingested {
            Ingested::Batch { .. } => {
                self.shared.ingested.fetch_add(1, Ordering::SeqCst);
                if !notes.is_empty() {
                    return (ingested, Some((Arc::clone(batch), notes, shard.generation)));
                }
            }
            Ingested::Replayed => {
                self.shared.replayed.fetch_add(1, Ordering::Relaxed);
            }
            Ingested::Described | Ingested::Ignored | Ingested::Refused => {}
        }
        (ingested, None)
    }

    /// Holds a batch of an undescribed receiver in its shard, within `ORPHANS_PER_RECEIVER` a
    /// receiver and `ORPHAN_RECEIVERS_PER_SHARD` receivers (the oldest out first), for `ORPHAN_MS`.
    fn hold_orphan(&self, shard: &mut Shard, batch: &Arc<Decoded>, now_ms: u64) {
        let key = batch.receiver();
        let mut expired = 0;
        shard.orphans.retain(|_, waiting| {
            let before = waiting.len();
            waiting.retain(|(_, at)| now_ms.saturating_sub(*at) <= ORPHAN_MS);
            expired += (before - waiting.len()) as u64;
            !waiting.is_empty()
        });
        let mut dropped = 0;
        if !shard.orphans.contains_key(&key) && shard.orphans.len() >= ORPHAN_RECEIVERS_PER_SHARD {
            dropped += 1;
        } else {
            let waiting = shard.orphans.entry(key).or_default();
            if waiting.len() >= ORPHANS_PER_RECEIVER {
                waiting.pop_front();
                dropped += 1;
            }
            waiting.push_back((Arc::clone(batch), now_ms));
        }
        self.shared
            .orphans_expired
            .fetch_add(expired, Ordering::Relaxed);
        self.shared
            .orphans_dropped
            .fetch_add(dropped, Ordering::Relaxed);
    }
}

impl Drop for HostedMlat {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // The thread sees the flag within `POLL`.
    }
}

impl MlatHost for HostedMlat {
    fn set_areas(&self, areas: Vec<Region>, descriptions: Vec<ReceiverInfo>) {
        for info in &descriptions {
            self.describe(info);
        }
        let mut areas = areas;
        areas.sort_unstable_by_key(|area| area.as_u64());
        areas.dedup();
        let mut scope = self
            .shared
            .scope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if scope.areas == areas {
            return;
        }
        // No area at all drops the engine and its raw; the first area after none starts a new one.
        let restart = areas.is_empty() || scope.areas.is_empty();
        if restart {
            scope.generation += 1;
            // The new engine's steps begin where its own raw does.
            self.shared.earliest_ms.store(u64::MAX, Ordering::SeqCst);
        }
        let band = (!areas.is_empty()).then(|| area::border_band(&areas));
        let mut left = Vec::new();
        let mut moved = Vec::new();
        for shard in &self.shared.shards {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if restart {
                shard.intake.restart(self.shared.limits);
                shard.orphans.clear();
            }
            let described = shard.intake.set_scope(band.clone());
            left.extend(described.left);
            moved.extend(described.moved);
            shard.generation = scope.generation;
            shard.active = band.is_some();
        }
        // Every shard re-scoped: a seat that changed in a shard taken earlier is settled now, by
        // where its receiver stands after all of them.
        moved.sort_unstable();
        moved.dedup();
        left.extend(self.shared.settle(&moved).into_iter().map(|(_, key)| key));
        scope.areas.clone_from(&areas);
        let generation = scope.generation;
        drop(scope);
        if !restart {
            for key in left {
                self.send(Command::Left(generation, key));
            }
        }
        self.send(Command::Areas(generation, areas));
    }

    fn offer_description(&self, info: &ReceiverInfo) {
        self.describe(info);
    }

    fn offer_batch(&self, batch: &Arc<Decoded>, now_ms: u64) {
        self.shared.delay(Stage::Offer);
        let heard = {
            let mut shard = self.shared.shard(&batch.receiver());
            if !shard.active {
                return;
            }
            self.shared
                .earliest_ms
                .fetch_min(batch.stamp_ms(), Ordering::SeqCst);
            let (ingested, heard) = self.take(&mut shard, batch);
            if ingested == Ingested::Ignored && shard.intake.described(&batch.receiver()).is_none()
            {
                self.hold_orphan(&mut shard, batch, now_ms);
            }
            heard
        };
        if let Some((batch, notes, generation)) = heard {
            self.shared.tell(&batch, notes, generation);
        }
    }

    fn take_published(&self, watermark_ms: u64) -> Vec<Record> {
        // An ask dropped while the queue is full is the next one's: its watermark is no older.
        if self.shared.commands.load(Ordering::SeqCst) < COMMANDS_WAITING {
            self.send(Command::Tick(watermark_ms));
        }
        self.take_signed()
    }

    fn cores(&self) -> u16 {
        self.cores
    }

    fn sealed_bins(&self) -> Option<SealedBins> {
        Some(self.shared.sealed.clone())
    }

    fn report(&self) -> MlatReport {
        let mut report = self
            .shared
            .counts
            .lock()
            .map(|counts| counts.clone())
            .unwrap_or_default();
        let shared = &self.shared;
        report.ingested = self.ingested();
        report.overflowed = self.overflowed();
        report.replayed = shared.replayed.load(Ordering::Relaxed);
        report.ingest_errors = shared.ingest_errors.load(Ordering::Relaxed);
        report.orphans_dropped = shared.orphans_dropped.load(Ordering::Relaxed);
        report.orphans_expired = shared.orphans_expired.load(Ordering::Relaxed);
        report
    }
}

/// The step running: its clock, and which of its parts have not reported.
struct Running {
    step_ms: u64,
    provisional: bool,
    window: bool,
}

/// The engine's thread.
struct Host {
    identity: Identity,
    /// The first engine's boot id; each later one adds one.
    boot_id: u64,
    /// Engines started.
    engines: u64,
    /// The generation of the engine running (`Scope::generation`): a seal or step reports to the
    /// generation that started it, and is discarded if that engine is gone.
    generation: u64,
    settings: Settings,
    engine: Option<Engine>,
    /// Steps the watermark has passed and that have not started, in order, and the last queued.
    queued: VecDeque<u64>,
    through_ms: Option<u64>,
    running: Option<Running>,
    /// The open raw the shards held at the last step, and the charge of all the raw held.
    open_bytes: usize,
    held_charge: Charge,
    held: Arc<Gauge>,
    messages: Sender<Message>,
    shared: Arc<Shared>,
}

impl Host {
    fn run(mut self, received: &Receiver<Message>) {
        loop {
            if self.shared.stop.load(Ordering::SeqCst) {
                return;
            }
            let message = match received.recv_timeout(POLL) {
                Ok(message) => message,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            if self.shared.stop.load(Ordering::SeqCst) {
                return;
            }
            match message {
                Message::Command(command) => {
                    match command {
                        Command::Left(generation, key) => {
                            if generation == self.generation
                                && let Some(engine) = self.engine.as_mut()
                            {
                                engine.forget_receiver(&key);
                            }
                        }
                        Command::Areas(generation, areas) => self.rescope(generation, areas),
                        Command::Tick(watermark_ms) => self.enqueue(watermark_ms),
                    }
                    self.advance();
                    self.shared.commands.fetch_sub(1, Ordering::SeqCst);
                }
                Message::Finished(finished) => {
                    self.finished(finished);
                    self.advance();
                }
            }
        }
    }

    /// The watermark passed `watermark_ms`: every multiple of `STEP_MS` it passed and that is not
    /// queued yet is, in order. The first step of an engine is the first multiple after the least
    /// stamp of its raw, which every batch stamped before the watermark has said by now.
    fn enqueue(&mut self, watermark_ms: u64) {
        if self.engine.is_none() {
            return;
        }
        let through = match self.through_ms {
            Some(through) => through,
            None => {
                let earliest = self.shared.earliest_ms.load(Ordering::SeqCst);
                if earliest >= watermark_ms {
                    // Nothing stamped before the watermark: every step to it has nothing to do.
                    return;
                }
                earliest / STEP_MS * STEP_MS
            }
        };
        let mut through = through;
        while through.saturating_add(STEP_MS) <= watermark_ms {
            through += STEP_MS;
            self.queued.push_back(through);
        }
        self.through_ms = Some(through);
    }

    /// Starts the next step queued, unless one runs; publishes the count of steps in hand.
    fn advance(&mut self) {
        while self.running.is_none() {
            let Some(step_ms) = self.queued.pop_front() else {
                break;
            };
            self.start(step_ms);
        }
        let steps = self.queued.len() + usize::from(self.running.is_some());
        self.shared.steps.store(steps, Ordering::SeqCst);
    }

    /// Step `step_ms`: its provisional solving and its seal and window step, off this thread at
    /// once. Done when both have reported.
    fn start(&mut self, step_ms: u64) {
        let generation = self.generation;
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        // Carries the models of every window step before this one: the last one reported before
        // this step started.
        let plan = engine.provisional_plan(step_ms, step_ms);
        self.running = Some(Running {
            step_ms,
            provisional: true,
            window: true,
        });
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        spawn_or_run(Urgency::Prompt, move || {
            shared.delay(Stage::Provisional);
            let (refused_intervals, refused_batches) = shared.weigh_intervals(step_ms);
            let through = step_ms / STEP_MS;
            let shards: Vec<usize> = (0..provisional_::SHARDS).collect();
            // Read every shard in the batches' order, then decide every batch whole across all of
            // them, then keep and find what is due: each pass all shards in parallel.
            let (read, _) = window::parallel(
                plan.threads,
                &shards,
                |shard, _: &mut provisional::Report| {
                    shared
                        .listening(*shard)
                        .read(generation, through, &refused_intervals)
                },
            );
            let waiting: usize = read.iter().map(|(waiting, _)| *waiting).sum();
            let refused = provisional_::admit(
                waiting,
                provisional_::sizes(read.iter().flat_map(|(_, taken)| taken)),
            );
            let work: Vec<(usize, Mutex<Vec<Taken>>)> = read
                .into_iter()
                .enumerate()
                .map(|(shard, (_, taken))| (shard, Mutex::new(taken)))
                .collect();
            let (parts, _) = window::parallel(
                plan.threads,
                &work,
                |(shard, taken), _: &mut provisional::Report| {
                    let taken = taken
                        .lock()
                        .map(|mut taken| std::mem::take(&mut *taken))
                        .unwrap_or_default();
                    shared
                        .listening(*shard)
                        .settle(taken, &refused, plan.now_ms, &plan.book)
                },
            );
            let job = plan.job(parts);
            let _ = messages.send(Message::Finished(Finished::Solved(
                generation,
                job.run(),
                refused_batches,
            )));
        });
        self.close(step_ms);
    }

    /// One part of the running step reported (`provisional` or the window): when both have, the
    /// step is done.
    fn part_done(&mut self, provisional: bool) {
        let Some(running) = self.running.as_mut() else {
            return;
        };
        if provisional {
            running.provisional = false;
        } else {
            running.window = false;
        }
        if !running.provisional && !running.window {
            self.shared
                .stepped_ms
                .fetch_max(running.step_ms, Ordering::SeqCst);
            self.running = None;
        }
    }

    /// A seal's or a step's outcome, applied if its engine is still the one running; its report
    /// kept.
    fn finished(&mut self, finished: Finished) {
        match finished {
            Finished::Sealed {
                generation,
                step_ms,
                settled,
                bins,
                sites,
                dropped,
            } if generation == self.generation => {
                for bin in bins {
                    self.shared.sealed.insert(bin);
                }
                self.step(step_ms, settled, sites, dropped);
            }
            Finished::Stepped(generation, outcome) if generation == self.generation => {
                if let Some(engine) = self.engine.as_mut() {
                    let (records, report, dropped) = engine.apply(*outcome);
                    let step = StepReport::of(&report);
                    self.shared.count(|counts| {
                        counts.steps += 1;
                        counts.observations_late += dropped.late;
                        counts.observations_refused += dropped.refused;
                        counts.receivers_refused += dropped.receivers;
                        counts.steps_total.add(&step);
                        counts.last_step = Some(step);
                    });
                    self.publish(records);
                }
                self.part_done(false);
            }
            Finished::Solved(generation, outcome, refused) if generation == self.generation => {
                if let Some(engine) = self.engine.as_mut() {
                    let records = engine.apply_provisional(outcome);
                    let report = engine.provisional_report();
                    self.shared.count(|counts| {
                        counts.refused += refused;
                        counts.provisional.add(&report);
                    });
                    self.publish(records);
                }
                self.part_done(true);
            }
            // An engine since dropped: what it sealed or solved is not published, and counted.
            Finished::Sealed { .. } | Finished::Stepped(..) | Finished::Solved(..) => {
                self.shared.count(|counts| counts.steps_discarded += 1);
            }
        }
    }

    /// Charges the relay's `Held` store for the raw held now: the shards' open raw at the last
    /// step and the sealed bins.
    fn charge_held(&mut self) {
        let bytes = self.open_bytes.saturating_add(self.shared.sealed.bytes());
        self.held_charge.shrink_to(0);
        self.held_charge = self.held.force(bytes);
    }

    /// Takes every bin complete by step `step_ms` out of every shard (a move under each shard's
    /// lock in turn: raw stamped at or after the step is late by its stamp, so what is taken is the
    /// same whenever this runs), with the sites taking part and what the shards refused, and seals
    /// them off this thread.
    fn close(&mut self, step_ms: u64) {
        let Some(engine) = self.engine.as_ref() else {
            self.part_done(false);
            return;
        };
        let settled = engine.settled(step_ms);
        // Within the engine's own bound and the relay's `Held` store, both less what is sealed:
        // functions of what was sealed, never of what is open now.
        let room = engine
            .room()
            .min(self.held.limit().saturating_sub(self.shared.sealed.bytes()));
        let threads = self.settings.threads.max(1);
        let mut fragments: Vec<Fragment> = Vec::new();
        let mut sites: Vec<Site> = Vec::new();
        let mut dropped = Dropped::default();
        let mut open_bytes = 0usize;
        for shard in &self.shared.shards {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A shard re-scoped for a newer engine than this one holds that engine's raw.
            if shard.generation != self.generation {
                continue;
            }
            fragments.extend(shard.intake.take_through(settled));
            sites.extend(shard.intake.sites());
            let more = shard.intake.take_dropped();
            dropped.late += more.late;
            dropped.refused += more.refused;
            dropped.receivers += more.receivers;
            open_bytes = open_bytes.saturating_add(shard.intake.bytes());
        }
        self.open_bytes = open_bytes;
        sites.sort_unstable_by_key(|site| site.receiver);
        let generation = self.generation;
        if fragments.is_empty() {
            self.step(step_ms, settled, sites, dropped);
            return;
        }
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        spawn_or_run(Urgency::Background, move || {
            shared.delay(Stage::Seal);
            let (bins, refused) = tally_mlat::engine::seal(fragments, threads, room);
            let mut dropped = dropped;
            dropped.refused += refused as u64;
            let _ = messages.send(Message::Finished(Finished::Sealed {
                generation,
                step_ms,
                settled,
                bins,
                sites,
                dropped,
            }));
        });
    }

    /// The window step of `step_ms`, every bin through `settled` sealed: run off this thread when
    /// there is a window to solve.
    fn step(&mut self, step_ms: u64, settled: i64, sites: Vec<Site>, dropped: Dropped) {
        let generation = self.generation;
        let Some(engine) = self.engine.as_mut() else {
            self.part_done(false);
            return;
        };
        engine.add_dropped(dropped);
        let job = engine.prepare_sealed(step_ms, step_ms, settled, sites);
        // Sealed and forgotten: what the raw holds now.
        self.charge_held();
        let Some(job) = job else {
            self.part_done(false);
            return;
        };
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        spawn_or_run(Urgency::Background, move || {
            shared.delay(Stage::Window);
            let _ = messages.send(Message::Finished(Finished::Stepped(
                generation,
                Box::new(job.run()),
            )));
        });
    }

    /// The areas `set_areas` named (every shard already re-scoped to them, under `generation`):
    /// none drops the engine and its raw; the first after none starts a new engine under a new
    /// boot id; otherwise the engine's scope changes in place.
    fn rescope(&mut self, generation: u64, areas: Vec<Region>) {
        if areas.is_empty() {
            // No longer an MLAT relay for anything: the engine and its raw go, and whatever it
            // is still sealing or solving is discarded when it reports.
            self.engine = None;
            self.drop_steps();
            self.generation = generation;
            self.charge_held();
            return;
        }
        let band = area::border_band(&areas);
        match self.engine.as_mut() {
            Some(engine) if generation == self.generation => {
                engine.set_scope(band, areas);
            }
            _ => {
                self.drop_steps();
                let mut engine = Engine::hosted(
                    self.identity.clone(),
                    self.boot_id.wrapping_add(self.engines),
                    self.settings.clone(),
                    self.shared.sealed.clone(),
                );
                self.engines += 1;
                self.generation = generation;
                engine.set_scope(band, areas);
                self.engine = Some(engine);
            }
        }
    }

    /// An engine goes: its raw, what it was told, and its steps with it.
    fn drop_steps(&mut self) {
        self.shared.sealed.clear();
        for shard in 0..provisional_::SHARDS {
            self.shared.listening(shard).clear();
        }
        self.shared.intervals().open.clear();
        self.queued.clear();
        self.running = None;
        self.through_ms = None;
        self.open_bytes = 0;
    }

    fn publish(&self, records: Vec<Record>) {
        self.shared.publish(records, PUBLISHED_BYTES);
    }
}

/// How a piece of the engine's work is scheduled against the rest of the relay's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Urgency {
    /// Provisional solving: a provisional is due within seconds of its transmission (RFC-0174
    /// §2.4), so it runs at the relay's own priority.
    Prompt,
    /// Seals and window steps: a final position comes 7 to 47 s after its transmission (the
    /// stride), and a window's fits take seconds of every core they are spread over. They run
    /// below the relay's priority (`BACKGROUND_NICE`, inherited by the threads they spread over),
    /// so on a busy host they yield the cores to provisional solving and to ingest, never the
    /// other way round.
    Background,
}

/// How far below the relay's priority background work runs: a nice value, which Linux gives each
/// thread its own and a thread's children inherit.
const BACKGROUND_NICE: libc::c_int = 10;

/// Lowers the calling thread's priority to `BACKGROUND_NICE` (a thread may always lower its own).
fn run_in_background() {
    // SAFETY: `gettid` and `setpriority` read and write no memory of this process; on Linux a
    // thread is addressed by its id as a process, so this changes this thread's nice value alone.
    // A failure leaves it at the relay's priority, which is only slower to yield.
    #[cfg(target_os = "linux")]
    unsafe {
        let tid = libc::gettid();
        let _ = libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, BACKGROUND_NICE);
    }
}

/// Runs `work` on a thread of its own at `urgency`, or here if no thread can be had.
fn spawn_or_run(urgency: Urgency, work: impl FnOnce() + Send + 'static) {
    let work = Arc::new(Mutex::new(Some(work)));
    let theirs = Arc::clone(&work);
    let spawned = std::thread::Builder::new()
        .name("tally-mlat-step".to_owned())
        .spawn(move || {
            if urgency == Urgency::Background {
                run_in_background();
            }
            if let Some(work) = theirs.lock().ok().and_then(|mut work| work.take()) {
                work();
            }
        });
    if spawned.is_err()
        && let Some(work) = work.lock().ok().and_then(|mut work| work.take())
    {
        work();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::PerFeeder;
    use tally_mlat::replay::{arrivals, replay, scenario};
    use tally_mlat_solver::publish;
    use tally_mlat_solver::sim;
    use tally_wire::Location;
    use tally_wire::rendezvous::AREA_RESOLUTION;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    const BOOT: u64 = 0xb007;

    fn settings() -> Settings {
        Settings {
            regions: Vec::new(),
            settle_ms: SETTLE_MS,
            threads: 2,
            capacity: Capacity::default(),
        }
    }

    fn identity() -> Identity {
        Identity::from_seed([5; 32])
    }

    /// The areas within about 150 km of the simulator's centre, where its receivers and aircraft
    /// are.
    fn areas() -> Result<Vec<Region>, String> {
        let (lat, lon) = sim::CENTRE;
        let mut areas = Vec::new();
        for north in -2..=2 {
            for east in -2..=2 {
                let location = Location {
                    lat_e7: ((lat + f64::from(north) * 0.6) * 1e7) as i32,
                    lon_e7: ((lon + f64::from(east) * 1.0) * 1e7) as i32,
                    alt_m: 0,
                    precision_m: 0,
                };
                let area = Region::containing(&location, AREA_RESOLUTION).map_err(text)?;
                if !areas.contains(&area) {
                    areas.push(area);
                }
            }
        }
        Ok(areas)
    }

    /// Waits until everything handed to the host is done with: the test runner's deadline fails a
    /// host that never settles.
    fn quiet(host: &HostedMlat) {
        while host.in_flight() > 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// The steps from `from_ms` to `until_ms`: every multiple of `STEP_MS` after the first.
    fn steps(from_ms: u64, until_ms: u64) -> impl Iterator<Item = u64> {
        (from_ms / STEP_MS + 1..=until_ms / STEP_MS).map(|step| step * STEP_MS)
    }

    /// A record arriving at `at_ms`, as the relay hands it on: a batch as its one decode stamped
    /// `at_ms` (one this build cannot read holds nothing), a description as it is.
    fn offer(host: &HostedMlat, record: &Record, at_ms: u64) {
        match record {
            Record::Batch(batch) => {
                if let Ok(decoded) = Decoded::from_verified(batch.clone(), at_ms, 0) {
                    host.offer_batch(&decoded, at_ms);
                }
            }
            Record::ReceiverInfo(info) => host.offer_description(info),
            _ => {}
        }
    }

    /// Drives the host in line: for each step, what arrived before it is offered stamped when it
    /// arrived, then the host is asked with the step as the watermark, then waited on. Every record
    /// it published, with the step. (The concurrent path, unwaited, is `tests/staged_mlat.rs`'s.)
    fn drive(
        host: &HostedMlat,
        arrivals: &[(u64, Record)],
        from_ms: u64,
        until_ms: u64,
    ) -> Vec<(u64, Record)> {
        let mut published = Vec::new();
        let mut next = arrivals.partition_point(|(at, _)| *at < from_ms);
        for step in steps(from_ms, until_ms) {
            while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at < step) {
                offer(host, record, *at);
                next += 1;
            }
            let early = host.take_published(step);
            quiet(host);
            published.extend(
                early
                    .into_iter()
                    .chain(host.take_signed())
                    .map(|r| (step, r)),
            );
        }
        published
    }

    fn encoded(records: &[&Record]) -> Result<Vec<Vec<u8>>, String> {
        records
            .iter()
            .map(|record| {
                let mut bytes = Vec::new();
                record.encode(&mut bytes).map_err(text)?;
                Ok(bytes)
            })
            .collect()
    }

    /// The provisional stream and everything else, each in its order.
    fn streams(records: &[(u64, Record)]) -> (Vec<&Record>, Vec<&Record>) {
        records
            .iter()
            .map(|(_, record)| record)
            .partition(|record| matches!(record, Record::Provisional(_)))
    }

    /// THE POINT of one program: the relay's hosted MLAT, fed a feeder's raw as the hub offers it,
    /// publishes byte for byte what the reference engine publishes from the same raw on the same
    /// steps (`tally_mlat::replay`, the engine driven in line): the same clock models, positions and
    /// provisional positions, signed by the relay's key. And every model it fits is of a tile whose
    /// centre is in one of its areas.
    #[test]
    fn a_hosted_engine_publishes_what_the_reference_engine_publishes_from_the_same_raw()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let areas = areas()?;

        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas.clone(), Vec::new());
        let hosted = drive(&host, &delivered, first, until);

        let mut engine = Engine::new(identity(), BOOT, settings());
        engine.set_scope(area::border_band(&areas), areas.clone());
        let reference = replay(&mut engine, &delivered, STEP_MS, until)?;

        let (hosted_provisional, hosted_final) = streams(&hosted);
        let (reference_provisional, reference_final) = streams(&reference);
        assert!(
            hosted_final
                .iter()
                .any(|record| matches!(record, Record::Positions(_))),
            "no positions"
        );
        assert!(!hosted_provisional.is_empty(), "no provisional positions");
        assert_eq!(encoded(&hosted_final)?, encoded(&reference_final)?);
        assert_eq!(
            encoded(&hosted_provisional)?,
            encoded(&reference_provisional)?
        );
        for record in &hosted_final {
            if let Record::ClockModel(manifest) = record {
                assert_eq!(manifest.engine().map_err(text)?, identity().public());
                let content = manifest.content(&[]).map_err(text)?;
                let model = publish::decode(&content.model, content.spec_version).map_err(text)?;
                assert!(window::owns(&areas, model.tile), "{:?}", model.tile);
            }
        }
        assert_eq!(host.refused(), 0);
        // The relay's other readers of the raw see the bins the engine holds, the reference's.
        let sealed = host.sealed_bins().ok_or("no sealed bins")?;
        let numbers = sealed.numbers();
        assert!(!numbers.is_empty());
        let reference = engine.sealed_bins();
        assert_eq!(numbers, reference.numbers());
        for bin in &numbers {
            assert!(sealed.get(*bin) == reference.get(*bin), "bin {bin}");
        }
        // Every step's report is kept, and nothing was let go.
        let report = host.report();
        assert!(report.steps > 0 && report.last_step.is_some(), "{report:?}");
        assert!(report.steps_total.solved > 0, "{report:?}");
        assert!(report.provisional.solved > 0, "{report:?}");
        assert_eq!(
            (
                report.refused,
                report.overflowed,
                report.steps_discarded,
                report.ingest_errors
            ),
            (0, 0, 0, 0),
            "{report:?}"
        );
        Ok(())
    }

    /// Batches of a receiver never described are held up to their bound and the rest counted,
    /// never let go silently.
    #[test]
    fn batches_beyond_the_orphan_bound_are_counted() -> Result<(), String> {
        let simulation = sim::run(&scenario(17, 120.0));
        let feed = simulation
            .feeds()
            .map_err(text)?
            .into_iter()
            .next()
            .ok_or("no feed")?;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        let now = feed.batches[0].content().map_err(text)?.wall_ms;
        quiet(&host);
        let offered = feed.batches.len().min(ORPHANS_PER_RECEIVER + 10);
        assert!(offered > ORPHANS_PER_RECEIVER);
        for batch in &feed.batches[..offered] {
            offer(&host, &Record::Batch(batch.clone()), now);
        }
        quiet(&host);
        let report = host.report();
        assert_eq!(report.ingested, 0);
        assert_eq!(
            report.orphans_dropped,
            (offered - ORPHANS_PER_RECEIVER) as u64,
            "{report:?}"
        );
        Ok(())
    }

    /// A relay that is an MLAT relay for no area holds no raw and publishes nothing, however much
    /// raw its feeders offer.
    #[test]
    fn a_relay_that_solves_no_area_publishes_nothing() -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 30.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(Vec::new(), Vec::new());
        assert!(drive(&host, &delivered, first, until).is_empty());
        assert_eq!(host.ingested(), 0);
        Ok(())
    }

    /// A batch that reaches the engine before its receiver's description (a repair, a rebuild, a
    /// link that died between them) is held, and taken when the description comes: the hub
    /// forwards each batch once, so one turned away would never come again.
    #[test]
    fn a_batch_before_its_receivers_description_is_taken_when_the_description_comes()
    -> Result<(), String> {
        let simulation = sim::run(&scenario(17, 30.0));
        let feed = simulation
            .feeds()
            .map_err(text)?
            .into_iter()
            .next()
            .ok_or("no feed")?;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        let now = feed.batches[0].content().map_err(text)?.wall_ms;
        let early = feed.batches.len().min(5);
        for batch in &feed.batches[..early] {
            offer(&host, &Record::Batch(batch.clone()), now);
        }
        while host.in_flight() > 0 {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(host.ingested(), 0);
        host.offer_description(&feed.info);
        while host.in_flight() > 0 {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(host.ingested(), early as u64);
        Ok(())
    }

    /// When selection says the relay no longer solves its areas, it stops: what it held is gone and
    /// nothing more is published. Given an area again, it starts a new engine under a new boot.
    #[test]
    fn a_relay_that_stops_solving_an_area_publishes_nothing_more_and_starts_afresh()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(23, 60.0));
        let delivered = arrivals(&mut simulation, 5)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let last = delivered.last().map_or(0, |(at, _)| *at);
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        // Every receiver describes itself at the start: before the areas are withdrawn.
        let half = first + (last - first) / 2;
        drive(&host, &delivered, first, half);
        let taken = host.ingested();
        assert!(taken > 0);
        let sealed = host.sealed_bins().ok_or("no sealed bins")?;
        host.set_areas(Vec::new(), Vec::new());
        let after = drive(&host, &delivered, half + STEP_MS, last + 60_000);
        assert!(after.is_empty(), "{} records after", after.len());
        // Its raw went with it, for every reader.
        assert!(sealed.is_empty() && sealed.numbers().is_empty());
        assert_eq!(host.ingested(), taken);
        // Taken again: the same raw, from the start, under a new boot id, the engine starting
        // from the descriptions the relay holds (`Hub::descriptions`).
        let held: Vec<ReceiverInfo> = delivered
            .iter()
            .filter_map(|(_, record)| match record {
                Record::ReceiverInfo(info) => Some(info.clone()),
                _ => None,
            })
            .collect();
        host.set_areas(areas()?, held);
        let again = drive(&host, &delivered, first, last + 60_000);
        let boots: std::collections::BTreeSet<u64> = again
            .iter()
            .filter_map(|(_, record)| match record {
                Record::Positions(positions) | Record::Provisional(positions) => {
                    Some(positions.boot_id())
                }
                Record::ClockModel(model) => Some(model.boot_id()),
                _ => None,
            })
            .collect();
        assert_eq!(boots, [BOOT + 1].into_iter().collect());
        Ok(())
    }

    fn config(line: &str) -> Result<Config, String> {
        Config::from_args(line.split_whitespace().map(str::to_owned))?
            .ok_or_else(|| "no config".to_owned())
    }

    /// The relay hosts MLAT when its duties are on and it offers threads, and never with
    /// `--no-relay-duties`.
    #[test]
    fn mlat_is_hosted_with_relay_duties_and_threads_and_never_without_duties() -> Result<(), String>
    {
        let base = "--key k --max-upload 8Mbit/s";
        let budget = Budget::of_memory(64 << 30, PerFeeder::planned(true));
        let host = |line: &str| -> Result<Option<HostedMlat>, String> {
            host_for(&config(line)?, identity(), 1, &budget)
        };
        let hosted = host(&format!("{base} --mlat-threads 3"))?.ok_or("not hosted")?;
        assert_eq!(hosted.cores(), 3);
        // Duties are on by default, so a relay offers every core unless told otherwise.
        assert!(host(base)?.is_some());
        assert!(host(&format!("{base} --mlat-threads 0"))?.is_none());
        assert!(host(&format!("{base} --mlat-threads 3 --no-relay-duties"))?.is_none());
        Ok(())
    }

    /// RFC-0178 §9, "MLAT receiver limit comes from the same F": the engine seats exactly the
    /// feeders the relay's budget admits, no floor beside it, and so holds the raw the budget
    /// reserved for `Held` and no more.
    #[test]
    fn the_seats_are_the_feeder_ceiling_and_the_raw_is_the_held_store() {
        let per_feeder = PerFeeder::planned(true);
        for feeders in [1, 7, 30_000] {
            let budget = Budget::new(per_feeder.total() * feeders, per_feeder);
            assert_eq!(budget.ceiling(), feeders);
            let capacity = capacity(&budget);
            assert_eq!(capacity.receivers, feeders);
            let settings = Settings {
                regions: Vec::new(),
                settle_ms: SETTLE_MS,
                threads: 1,
                capacity,
            };
            assert_eq!(settings.limits().bytes, budget.store_bytes(Store::Held));
        }
    }

    /// An empty batch of receiver `seed`, stamped `stamp_ms`: what `tell` orders by.
    fn told(seed: u8, sequence: u64, stamp_ms: u64) -> Result<Arc<Decoded>, String> {
        let batch = tally_wire::Batch::sign(
            &Identity::from_seed([seed; 32]),
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 1,
                wall_ms: stamp_ms,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(text)?;
        Decoded::from_verified(batch, stamp_ms, sequence)
            .map_err(|undecodable| undecodable.error.to_string())
    }

    /// Audit 1.3: what batches tell provisional solving is refused whole per step and never by
    /// timing. A step whose notes pass the bound is refused with its every batch, whichever batch
    /// came first and whatever shard each landed in, nothing of it is held, and the step that
    /// weighs it counts every batch; a step under the bound is untouched.
    #[test]
    fn a_steps_notes_beyond_the_bound_are_refused_whole_whatever_the_order() -> Result<(), String> {
        let settings = Settings {
            capacity: Capacity::for_receivers(1),
            ..settings()
        };
        let notes = |count: u32| -> Vec<Note> {
            (0..count).map(|n| Note::Position(0x40_0000 + n)).collect()
        };
        let most = NOTES_PER_RECEIVER_STEP as u32 * 3 / 5;
        let busy = [told(1, 0, 10_100)?, told(2, 0, 10_900)?];
        let calm = told(3, 0, 11_500)?;
        for order in [[0, 1], [1, 0]] {
            let host = HostedMlat::new(identity(), BOOT, settings.clone())?;
            let shared = &host.shared;
            for at in order {
                shared.tell(&busy[at], notes(most), 1);
            }
            shared.tell(&calm, notes(most), 1);
            // Nothing of the refused step is held, in any shard.
            for shard in 0..provisional_::SHARDS {
                let listening = shared.listening(shard);
                assert!(
                    listening.heard.iter().all(|heard| heard.interval == 11),
                    "{order:?}"
                );
            }
            // The step at 11 s weighs the 10th second: refused, both its batches counted.
            let (refused, batches) = shared.weigh_intervals(11_000);
            assert_eq!(refused, [10].into_iter().collect(), "{order:?}");
            assert_eq!(batches, 2, "{order:?}");
            // The next step's is not.
            let (refused, batches) = shared.weigh_intervals(12_000);
            assert!(refused.is_empty() && batches == 0, "{order:?}");
        }
        Ok(())
    }

    /// Audit 3.2: a step's signed records are queued whole or refused whole, so a clock model's
    /// parts never wait without their manifest; one step larger than the whole bound still goes
    /// into an empty queue.
    #[test]
    fn a_steps_records_are_published_whole_or_refused_whole() -> Result<(), String> {
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        let step: Vec<Record> = (0..3).map(|_| Record::Heartbeat).collect();
        let bytes: usize = step.iter().map(Record::encoded_len).sum();
        host.shared.publish(step.clone(), bytes * 2);
        host.shared.publish(step.clone(), bytes * 2);
        // A third would pass the bound: refused, all of it, counted.
        host.shared.publish(step.clone(), bytes * 2);
        assert_eq!(host.overflowed(), 3);
        assert_eq!(host.take_signed().len(), 6);
        // Larger than the whole bound, into an empty queue: taken.
        let large: Vec<Record> = (0..5).map(|_| Record::Heartbeat).collect();
        host.shared.publish(large, bytes * 2);
        assert_eq!(host.take_signed().len(), 5);
        assert_eq!(host.overflowed(), 3);
        Ok(())
    }
}
