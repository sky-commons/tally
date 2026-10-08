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
//! - **One store of raw, held where it arrives** (RFC-0181 §5). The receivers and their open raw
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
//! - **Provisional state sharded by aircraft** (RFC-0181 §3). What a batch says to provisional
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
//! - **Stepped by the stamp watermark, never by a clock** (RFC-0181 §4, invariants 1 to 3). The
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
//!   window step before it, as the engine solving in line does. A step that falls behind waits,
//!   up to `STEPS_BEHIND` steps; past them MLAT sheds, whole and counted, never by growing (below,
//!   Behind).
//! - **Behind** (RFC-0181 §9, §10). While the watermark passes more than `STEPS_BEHIND` steps that
//!   have not started, the oldest of them is shed: what batches told its provisional solving is
//!   let go, every batch of it counted (`MlatReport::shed`), and the bins it would take are taken
//!   and sealed now, so its window step is the next step's (which solves every window due, as one
//!   that ran late would). What MLAT holds therefore never waits on more than `STEPS_BEHIND` steps,
//!   which is what the budget reserves for it (`OPEN_MS`, `INTERVALS_HELD`). A host that keeps up
//!   never sheds, so the same stamped trace still makes the same bytes; one that does not loses
//!   provisional positions, counted, and never a window.
//! - **Capacity** (RFC-0181 §9). The receivers seated are the best ranked of those described
//!   (`tally_mlat::intake::Seats`: taking part first, then a draw under the relay's secret no
//!   feeder can choose), whichever raw shard took them and in whatever order, as many as the
//!   relay's feeder ceiling admits (`capacity`, the same F every store is sized by). Every byte it
//!   holds is charged to a store of the relay's budget before it is held ([`host_for`]), and none is
//!   charged past its store's limit. A shard's open raw is bounded by each receiver's share of a
//!   bin, and charged to `Open` as it grows: a byte refused refuses the batch's raw of the bin,
//!   counted. Sealed raw is checked on each complete bin as it is sealed
//!   (`tally_mlat::engine::seal`), within `Held`, a function of what was sealed, and charged to it
//!   as it is inserted. What batches tell provisional solving is bounded per step,
//!   `NOTES_PER_RECEIVER_STEP` a seat: a step's notes beyond it are refused whole, the step's every
//!   batch; it is charged to `Notes` until the step reads it, and a step whose notes `Notes` cannot
//!   hold is let go whole, as a shed one is. A batch's replies that do not fit the provisional state
//!   (`Capacity::waiting`, charged to `Engine`) are refused in every address shard at once
//!   (`provisional::admit`), and a window step's working set is reserved in `Engine` while it runs.
//!   Signed records not yet taken are bounded in bytes (`PUBLISHED_BYTES`, in the relay's base), a
//!   step's refused whole, so a part never goes without its manifest. Batches of receivers not yet
//!   described are charged to `Notes`, and one that does not fit is dropped, counted. Which steps'
//!   notes and which batches' replies are refused for their count depends on neither arrival order
//!   nor the number of threads; what is shed for a host that falls behind is whole; all of it is
//!   counted.
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
use tally_wire::{Decoded, Identity, PublicKey, ReceiverInfo, Record, Regions};

use crate::budget::{Budget, Charge, Gauge, Store};
use crate::config::Config;
use crate::exchange::{SHARDS, raw_shard};

/// The MLAT a relay hosts.
pub trait MlatHost: Send + Sync {
    /// The areas to solve (plus their border band), as `selection` holds them (the fewest cells
    /// that cover them, never expanded): the receivers it holds are theirs. `descriptions` are
    /// every receiver description the relay holds (`Hub::descriptions`), for a host that has not
    /// been offered them. The relay calls this when the areas change.
    fn set_areas(&self, areas: Regions, descriptions: Vec<ReceiverInfo>);
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
    /// Batches whose notes to provisional solving were let go because MLAT fell behind: their
    /// step was shed, or the `Notes` store could not hold their step's.
    pub shed: u64,
    /// Steps shed because the watermark passed more than `STEPS_BEHIND` steps not started: their
    /// provisional solving let go, their bins sealed at once, their window step the next one's.
    pub steps_shed: u64,
    /// Window steps put off because the `Engine` store could not reserve their working set: their
    /// windows are the next step's.
    pub windows_deferred: u64,
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
    /// the raw the engine holds (`tally_mlat_solver::held::Limits`), or with their batch's for room
    /// in the `Open` or `Held` store.
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
/// Steps the watermark may pass that have not started (one is running) before the oldest is shed
/// (module docs, Behind): a window step's fits at the deployed sizes take seconds, and this many
/// seconds of what MLAT holds is what the budget reserves for it falling behind.
pub const STEPS_BEHIND: usize = 4;
/// How long after a bin ends its raw is held open at most: its settling, the steps MLAT may fall
/// behind, and the step running. What the budget reserves for open raw (`Store::Open`).
pub const OPEN_MS: u64 = SETTLE_MS + (STEPS_BEHIND as u64 + 1) * STEP_MS;
/// Step intervals whose notes are held at most: the one the watermark is in and the next, the
/// steps MLAT may fall behind, and the step running until it reads its own. What the budget
/// reserves for notes (`Store::Notes`).
pub const INTERVALS_HELD: usize = STEPS_BEHIND + 3;
/// A seat's share of a window step's working set (its scope, its fits and its solutions), reserved
/// in the `Engine` store while the step runs. Measured (RFC-0181, "Sizing", 2026-10-08): a window
/// step at 500 feeders allocated at most 79 MiB beyond what it read, about 160 KiB a feeder.
pub const SOLVE_BYTES_PER_RECEIVER: usize = 192 << 10;
/// Commands for the engine's thread not yet taken: a few seconds of asks and changes. An ask
/// beyond it is dropped; the next carries a watermark at least as new, which steps everything the
/// dropped one would have.
const COMMANDS_WAITING: usize = 1 << 12;
/// What batches may tell provisional solving in one step, a seat: four times RFC-0181's planned
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
pub const PUBLISHED_BYTES: usize = 4 << 20;

/// The stores of the relay's budget hosted MLAT is charged to.
#[derive(Clone)]
pub struct Gauges {
    /// Sealed raw.
    pub held: Arc<Gauge>,
    /// Open raw: the raw shards' bins, and those on their way to sealing.
    pub open: Arc<Gauge>,
    /// What batches told provisional solving, until the step that weighs it reads it; and the
    /// batches of receivers not yet described.
    pub notes: Arc<Gauge>,
    /// The engine's own tables: the receptions waiting for provisional solving, and a window
    /// step's working set while it runs.
    pub engine: Arc<Gauge>,
}

impl Gauges {
    /// The budget's.
    pub fn of(budget: &Budget) -> Self {
        Self {
            held: budget.gauge(Store::Held),
            open: budget.gauge(Store::Open),
            notes: budget.gauge(Store::Notes),
            engine: budget.gauge(Store::Engine),
        }
    }

    /// Of no budget: for a host built apart from a relay (a test's).
    pub fn unlimited() -> Self {
        Self {
            held: Gauge::unlimited(Store::Held),
            open: Gauge::unlimited(Store::Open),
            notes: Gauge::unlimited(Store::Notes),
            engine: Gauge::unlimited(Store::Engine),
        }
    }
}

/// The hosted MLAT a relay runs, if any: none when its relay duties are off (`--no-relay-duties`)
/// or it offers no MLAT threads (`--mlat-threads 0`). Sized and charged by the relay's `budget`:
/// its seats are the feeder ceiling ([`capacity`]), its sealed and open raw are the `Held` and
/// `Open` stores', its provisional notes the `Notes` store's and its own tables the `Engine`
/// store's ([`Gauges::of`]). An error when its thread cannot start.
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
            regions: Regions::default(),
            settle_ms: SETTLE_MS,
            threads: config.mlat_threads,
            capacity: capacity(budget),
        },
        Gauges::of(budget),
    )
    .map(Some)
}

/// What the hosted engine holds: a seat for every feeder the relay's memory admits (the budget's
/// ceiling, RFC-0181 §9: "MLAT receiver limit comes from the same F"), and the raw of that many at
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
    Areas(u64, Regions, Regions),
    /// The stamp watermark passed this.
    Tick(u64),
}

/// What a seal or a step reports to the engine's thread, for the engine of its generation.
enum Finished {
    /// The bins complete by step `step_ms` (through `settled`), sealed, with the sites taking part
    /// and what the shards refused; and the `Open` charge of the raw they were sealed from, let go
    /// once they are held.
    Sealed {
        generation: u64,
        step_ms: u64,
        settled: i64,
        bins: Vec<Bin>,
        sites: Vec<Site>,
        dropped: Dropped,
        open: Vec<Charge>,
    },
    /// A window step's outcome, boxed: it is far larger than the others.
    Stepped(u64, Box<window::Outcome>),
    /// A provisional step's outcome, and the batches whose notes it refused with their step's
    /// for their count, and let go as shed.
    Solved {
        generation: u64,
        outcome: provisional::Outcome,
        refused: u64,
        shed: u64,
    },
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
    /// What its intake's open raw is charged to the `Open` store: always its bytes, taken before
    /// they are allocated.
    open: Charge,
    /// The engine generation its intake holds raw for, and whether one runs.
    generation: u64,
    active: bool,
    /// Batches of receivers not described yet, by receiver, oldest first, with when each came and
    /// its charge to the `Notes` store: taken when the description comes. A batch can reach a
    /// relay before its receiver's description (a repair, a rebuild from parity, a link that died
    /// between them), and the hub forwards each batch once, so a batch turned away would be lost
    /// to MLAT.
    orphans: BTreeMap<PublicKey, VecDeque<(Arc<Decoded>, u64, Charge)>>,
}

impl Shard {
    /// A batch into the intake, every byte of open raw it takes charged to `Open` before it is
    /// held (`Intake::ingest_verified_taking`).
    fn ingest(&mut self, batch: &Decoded) -> (Ingested, Vec<Note>) {
        let Self { intake, open, .. } = self;
        let ingested = intake.ingest_verified_taking(batch, &mut |bytes| open.try_grow(bytes));
        self.settle_open();
        ingested
    }

    /// The `Open` charge brought down to what the intake holds now (it lets go of raw, or took
    /// less than it was granted).
    fn settle_open(&mut self) {
        self.open.shrink_to(self.intake.bytes());
    }

    /// Takes every bin through `settled` out of the intake, with the `Open` charge of what it
    /// held, to be let go once they are sealed.
    fn take_through(&mut self, settled: i64) -> (Vec<Fragment>, Charge) {
        let fragments = self.intake.take_through(settled);
        let left = self.intake.bytes();
        let taken = self.open.bytes().saturating_sub(left);
        (fragments, self.open.split(taken))
    }
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
    /// out what is due at `now_ms` under `book`: with the receptions left waiting here.
    fn settle(
        &mut self,
        taken: Vec<Taken>,
        refused: &BTreeSet<Order>,
        now_ms: u64,
        book: &provisional_::Book,
    ) -> (usize, Due) {
        for one in taken {
            if refused.contains(&one.order) {
                self.state.refuse(one);
            } else {
                self.state.keep(one);
            }
        }
        let due = self.state.due(now_ms, book);
        (self.state.waiting(), due)
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// The notes told for one step interval: how many, of how many batches, and whether the interval
/// is refused whole, for its count or let go (shed) because MLAT fell behind.
#[derive(Default)]
struct Interval {
    notes: usize,
    batches: u64,
    refused: bool,
    shed: bool,
    /// The bytes it holds (each batch's decode and its notes), charged to the `Notes` store before
    /// they are held, until the step that weighs the interval has read it, or it is refused.
    charge: Charge,
}

/// What a step weighs of the intervals before it: those refused for their count, and their
/// batches; the batches of those shed; and the charges of the rest, held until the step has read
/// them.
#[derive(Default)]
struct Weighed {
    refused: BTreeSet<u64>,
    refused_batches: u64,
    shed_batches: u64,
    charges: Vec<Charge>,
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
    areas: Regions,
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
    /// The relay's `Notes` store: what each open interval told provisional solving, and the
    /// batches waiting for a description.
    notes: Arc<Gauge>,
    /// What the receptions waiting for provisional solving are charged to the `Engine` store:
    /// `provisional::WAITING_BYTES` each, taken before a step keeps them.
    waiting: Mutex<Charge>,
    /// Receptions waiting, at most (`Capacity::waiting`).
    most_waiting: usize,
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
    /// of it is held; the step that weighs it counts its every batch. One whose bytes the `Notes`
    /// store cannot hold is let go whole the same way, and counted shed: which steps are refused
    /// for their count is a function of the trace, and only a host behind on its steps fills the
    /// store (module docs, Behind).
    fn tell(&self, batch: &Arc<Decoded>, mut notes: Vec<Note>, generation: u64) {
        let order = Order::of(batch, batch.stamp_ms());
        let interval = {
            let mut intervals = self.intervals();
            // Stamped before a step already weighed (a batch that waited for its description, which
            // carries no stamp): the next step's.
            let interval = (order.stamp_ms / STEP_MS).max(intervals.weighed_ms / STEP_MS);
            let cap = self.notes_per_step;
            let entry = intervals.open.entry(interval).or_insert_with(|| Interval {
                charge: self.notes.empty(),
                ..Interval::default()
            });
            entry.batches += 1;
            if entry.refused {
                return;
            }
            entry.notes = entry.notes.saturating_add(notes.len());
            let bytes = batch
                .footprint()
                .saturating_add(std::mem::size_of_val(notes.as_slice()));
            if entry.notes > cap || !entry.charge.try_grow(bytes) {
                entry.shed = entry.notes <= cap;
                entry.refused = true;
                entry.charge = Charge::none();
                drop(intervals);
                self.forget_heard(&BTreeSet::from([interval]));
                return;
            }
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

    /// What the address shards heard of `intervals`, let go.
    fn forget_heard(&self, intervals: &BTreeSet<u64>) {
        if intervals.is_empty() {
            return;
        }
        for shard in 0..provisional_::SHARDS {
            self.listening(shard)
                .heard
                .retain(|heard| !intervals.contains(&heard.interval));
        }
    }

    /// The step of `step_ms` weighs every interval before it: the intervals refused for their
    /// count, and their batches; the batches of those shed; and the charges of the rest, which the
    /// step holds until it has read them.
    fn weigh_intervals(&self, step_ms: u64) -> Weighed {
        let mut intervals = self.intervals();
        intervals.weighed_ms = intervals.weighed_ms.max(step_ms);
        let later = intervals.open.split_off(&(step_ms / STEP_MS));
        let due = std::mem::replace(&mut intervals.open, later);
        let mut weighed = Weighed::default();
        for (interval, told) in due {
            if told.shed {
                weighed.shed_batches += told.batches;
            } else if told.refused {
                weighed.refused.insert(interval);
                weighed.refused_batches += told.batches;
            }
            weighed.charges.push(told.charge);
        }
        weighed
    }

    /// The step of `step_ms` is shed (module docs, Behind): every interval before it not yet
    /// weighed is let go whole, its notes forgotten in every address shard. As `weigh_intervals`
    /// counts them, with every batch not refused for its step's count counted shed.
    fn shed_intervals(&self, step_ms: u64) -> Weighed {
        let due = {
            let mut intervals = self.intervals();
            intervals.weighed_ms = intervals.weighed_ms.max(step_ms);
            let later = intervals.open.split_off(&(step_ms / STEP_MS));
            std::mem::replace(&mut intervals.open, later)
        };
        let mut weighed = Weighed::default();
        let mut forgotten = BTreeSet::new();
        for (interval, told) in due {
            if told.refused && !told.shed {
                weighed.refused_batches += told.batches;
            } else {
                weighed.shed_batches += told.batches;
            }
            forgotten.insert(interval);
        }
        self.forget_heard(&forgotten);
        weighed
    }

    /// Settles each receiver of `moved` (whose seat changed while another raw shard took a
    /// description) in its own raw shard: those that stopped taking part, with their generation.
    fn settle(&self, moved: &[PublicKey]) -> Vec<(u64, PublicKey)> {
        let mut left = Vec::new();
        for key in moved {
            let mut shard = self.shard(key);
            let stopped = shard.intake.settle(key);
            shard.settle_open();
            if stopped {
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
    /// `settings.regions` is ignored: the areas are `set_areas`'s. What it holds is charged to
    /// gauges of no budget: for a host built apart from a relay (a test's). An error when its
    /// thread cannot start.
    pub fn new(identity: Identity, boot_id: u64, settings: Settings) -> Result<Self, String> {
        Self::charging(identity, boot_id, settings, Gauges::unlimited())
    }

    /// As `new`, everything it holds charged to the relay's stores before it is held (`gauges`,
    /// module docs, Capacity): its sealed raw to `Held`, within that store's limit; its open raw
    /// to `Open` as it grows; what batches told provisional solving to `Notes` until the step that
    /// weighs it has read it; the receptions waiting for provisional solving and a window step's
    /// working set to `Engine`.
    pub fn charging(
        identity: Identity,
        boot_id: u64,
        settings: Settings,
        gauges: Gauges,
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
                        open: gauges.open.empty(),
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
            notes: Arc::clone(&gauges.notes),
            waiting: Mutex::new(gauges.engine.empty()),
            most_waiting: settings.capacity.waiting(),
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
            sealing: None,
            sealed_charge: gauges.held.empty(),
            held: gauges.held,
            engine_gauge: gauges.engine,
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

    /// Delays injected at every stage (`Stage`), for a test that shows they change nothing (RFC-0181
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
                for (batch, _, _) in waiting {
                    let (_, heard) = self.take(&mut shard, &batch);
                    told.extend(heard);
                }
            }
            let Description { left, moved, .. } = described;
            // Receivers that stopped taking part here let go of their open raw.
            shard.settle_open();
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
        let (ingested, notes) = shard.ingest(batch);
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
    /// receiver and `ORPHAN_RECEIVERS_PER_SHARD` receivers (the oldest out first), for `ORPHAN_MS`,
    /// charged to the `Notes` store before it is held: one it cannot hold is dropped, counted.
    fn hold_orphan(&self, shard: &mut Shard, batch: &Arc<Decoded>, now_ms: u64) {
        let key = batch.receiver();
        let mut expired = 0;
        shard.orphans.retain(|_, waiting| {
            let before = waiting.len();
            waiting.retain(|(_, at, _)| now_ms.saturating_sub(*at) <= ORPHAN_MS);
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
            match self.shared.notes.try_charge(batch.footprint()) {
                Some(charge) => waiting.push_back((Arc::clone(batch), now_ms, charge)),
                None => dropped += 1,
            }
            if waiting.is_empty() {
                shard.orphans.remove(&key);
            }
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
    fn set_areas(&self, areas: Regions, descriptions: Vec<ReceiverInfo>) {
        for info in &descriptions {
            self.describe(info);
        }
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
        // The band once, for the shards here and the engine's scope (`rescope`).
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
            shard.settle_open();
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
        self.send(Command::Areas(generation, areas, band.unwrap_or_default()));
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
    /// The engine generation whose seal is off this thread, if one is: the bins it seals are not
    /// held yet, so no other seal starts until it reports (each is sealed within what the ones
    /// before it left).
    sealing: Option<u64>,
    /// What the sealed bins are charged to the `Held` store, taken before each is held.
    sealed_charge: Charge,
    held: Arc<Gauge>,
    /// The `Engine` store, where a window step's working set is reserved while it runs.
    engine_gauge: Arc<Gauge>,
    messages: Sender<Message>,
    shared: Arc<Shared>,
}

impl Host {
    fn run(mut self, received: &Receiver<Message>) {
        self.settle_sealed();
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
                                self.settle_sealed();
                            }
                        }
                        Command::Areas(generation, areas, band) => {
                            self.rescope(generation, areas, band);
                        }
                        Command::Tick(watermark_ms) => self.enqueue(watermark_ms),
                    }
                    self.advance();
                    self.shared.commands.fetch_sub(1, Ordering::SeqCst);
                }
                Message::Finished(finished) => {
                    let window = matches!(finished, Finished::Stepped(..));
                    self.finished(finished);
                    self.advance();
                    if window {
                        give_back_freed();
                    }
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

    /// Starts the next step queued, unless one runs, and sheds the oldest queued while more than
    /// `STEPS_BEHIND` wait behind the one running (module docs, Behind); publishes the count of
    /// steps in hand.
    fn advance(&mut self) {
        while self.running.is_none() {
            let Some(step_ms) = self.queued.pop_front() else {
                break;
            };
            self.start(step_ms);
        }
        // A seal off this thread reports first: the shed step's bins are sealed within what it
        // left, as they would have been in their turn.
        while self.queued.len() > STEPS_BEHIND && self.running.is_some() && self.sealing.is_none() {
            let Some(step_ms) = self.queued.pop_front() else {
                break;
            };
            self.shed(step_ms);
        }
        let steps = self.queued.len() + usize::from(self.running.is_some());
        self.shared.steps.store(steps, Ordering::SeqCst);
    }

    /// Sheds step `step_ms` (module docs, Behind): its provisional solving let go, whole and
    /// counted; the bins complete by it taken and sealed now, on this thread; its window step the
    /// next one's.
    fn shed(&mut self, step_ms: u64) {
        let weighed = self.shared.shed_intervals(step_ms);
        drop(weighed.charges);
        self.shared.count(|counts| {
            counts.steps_shed += 1;
            counts.shed += weighed.shed_batches;
            counts.refused += weighed.refused_batches;
        });
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        let settled = engine.settled(step_ms);
        let room = self.room();
        let threads = self.settings.threads.max(1);
        let (fragments, _, mut dropped, open) = self.take_complete(settled);
        if !fragments.is_empty() {
            let (bins, refused) = tally_mlat::engine::seal(fragments, threads, room);
            dropped.refused += refused as u64;
            dropped.refused += self.hold(bins);
        }
        drop(open);
        if let Some(engine) = self.engine.as_mut() {
            engine.add_dropped(dropped);
        }
    }

    /// Step `step_ms`: its provisional solving and its seal and window step, off this thread at
    /// once. Done when both have reported.
    fn start(&mut self, step_ms: u64) {
        let generation = self.generation;
        let most_waiting = self.shared.most_waiting;
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
        // Weighed here, as it starts: a step shed after it never takes what is this step's.
        let weighed = self.shared.weigh_intervals(step_ms);
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        spawn_or_run(Urgency::Prompt, move || {
            shared.delay(Stage::Provisional);
            let Weighed {
                refused: refused_intervals,
                refused_batches,
                shed_batches,
                charges,
            } = weighed;
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
            // Read: the batches the notes kept alive are let go.
            drop(charges);
            let waiting: usize = read.iter().map(|(waiting, _)| *waiting).sum();
            let sizes = provisional_::sizes(read.iter().flat_map(|(_, taken)| taken));
            let mut refused = provisional_::admit(waiting, sizes.clone(), most_waiting);
            // Charged before they are kept: the count admitted fits the `Engine` store's share
            // for them (`Capacity::waiting`), so the charge is refused only past the budget,
            // and then every batch's replies are, whole.
            let kept: usize = sizes
                .iter()
                .filter(|(order, _)| !refused.contains(order))
                .map(|(_, size)| *size)
                .sum();
            let mut charge = shared
                .waiting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !charge.try_grow(kept.saturating_mul(provisional_::WAITING_BYTES)) {
                refused.extend(sizes.keys().copied());
            }
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
            let waiting: usize = parts.iter().map(|(waiting, _)| *waiting).sum();
            charge.shrink_to(waiting.saturating_mul(provisional_::WAITING_BYTES));
            drop(charge);
            let job = plan.job(parts.into_iter().map(|(_, due)| due).collect());
            let _ = messages.send(Message::Finished(Finished::Solved {
                generation,
                outcome: job.run(),
                refused: refused_batches,
                shed: shed_batches,
            }));
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
                mut dropped,
                open,
            } if generation == self.generation => {
                self.sealing = None;
                dropped.refused += self.hold(bins);
                drop(open);
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
            Finished::Solved {
                generation,
                outcome,
                refused,
                shed,
            } if generation == self.generation => {
                if let Some(engine) = self.engine.as_mut() {
                    let records = engine.apply_provisional(outcome);
                    let report = engine.provisional_report();
                    self.shared.count(|counts| {
                        counts.refused += refused;
                        counts.shed += shed;
                        counts.provisional.add(&report);
                    });
                    self.publish(records);
                }
                self.part_done(true);
            }
            // An engine since dropped: what it sealed or solved is not published, and counted.
            Finished::Sealed { generation, .. } => {
                if self.sealing == Some(generation) {
                    self.sealing = None;
                }
                self.shared.count(|counts| counts.steps_discarded += 1);
            }
            Finished::Stepped(..) | Finished::Solved { .. } => {
                self.shared.count(|counts| counts.steps_discarded += 1);
            }
        }
    }

    /// The bytes the sealed bins may still grow by: within the engine's own bound and the relay's
    /// `Held` store, both less what is sealed, functions of what was sealed and never of what is
    /// open now.
    fn room(&self) -> usize {
        let sealed = self.shared.sealed.bytes();
        let engine = self.engine.as_ref().map_or(0, Engine::room);
        engine.min(self.held.limit().saturating_sub(sealed))
    }

    /// Makes sealed `bins` readable, each charged to the `Held` store before it is held: one the
    /// store cannot hold (sealed within the room left, it never is) is refused whole. The
    /// observations refused.
    fn hold(&mut self, bins: Vec<Bin>) -> u64 {
        let mut refused = 0;
        for bin in bins {
            if self.sealed_charge.try_grow(SealedBins::cost(&bin)) {
                self.shared.sealed.insert(bin);
            } else {
                refused += bin.records.len() as u64;
            }
            // One in place of a bin of its number let that one go.
            self.settle_sealed();
        }
        refused
    }

    /// The `Held` charge brought to what the sealed bins hold now: down when bins were forgotten,
    /// up for the handle's own bytes. A receiver forgotten in a bin seals it again without it
    /// (`SealedBins::forget_receiver`), never larger; were it larger and past the store, the
    /// oldest bins are forgotten until it fits, counted refused.
    fn settle_sealed(&mut self) {
        loop {
            let bytes = self.shared.sealed.bytes();
            let held = self.sealed_charge.bytes();
            if bytes <= held {
                self.sealed_charge.shrink_to(bytes);
                return;
            }
            if self.sealed_charge.try_grow(bytes - held) {
                return;
            }
            let Some(oldest) = self.shared.sealed.numbers().first().copied() else {
                return;
            };
            let records = self
                .shared
                .sealed
                .get(oldest)
                .map_or(0, |bin| bin.records.len() as u64);
            self.shared.sealed.forget_before(oldest + 1);
            self.shared
                .count(|counts| counts.observations_refused += records);
        }
    }

    /// Takes every bin complete through `settled` out of every shard (a move under each shard's
    /// lock in turn: raw stamped at or after the step that takes it is late by its stamp, so what
    /// is taken is the same whenever this runs), with the sites taking part, what the shards
    /// refused, and the `Open` charge of what was taken.
    fn take_complete(&mut self, settled: i64) -> (Vec<Fragment>, Vec<Site>, Dropped, Vec<Charge>) {
        let mut fragments: Vec<Fragment> = Vec::new();
        let mut sites: Vec<Site> = Vec::new();
        let mut dropped = Dropped::default();
        let mut open = Vec::new();
        for shard in &self.shared.shards {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A shard re-scoped for a newer engine than this one holds that engine's raw.
            if shard.generation != self.generation {
                continue;
            }
            let (taken, charge) = shard.take_through(settled);
            fragments.extend(taken);
            open.push(charge);
            sites.extend(shard.intake.sites());
            let more = shard.intake.take_dropped();
            dropped.late += more.late;
            dropped.refused += more.refused;
            dropped.receivers += more.receivers;
        }
        sites.sort_unstable_by_key(|site| site.receiver);
        (fragments, sites, dropped, open)
    }

    /// Takes every bin complete by step `step_ms` out of every shard, with the sites taking part
    /// and what the shards refused, and seals them off this thread.
    fn close(&mut self, step_ms: u64) {
        let Some(engine) = self.engine.as_ref() else {
            self.part_done(false);
            return;
        };
        let settled = engine.settled(step_ms);
        let room = self.room();
        let threads = self.settings.threads.max(1);
        let (fragments, sites, dropped, open) = self.take_complete(settled);
        let generation = self.generation;
        if fragments.is_empty() {
            drop(open);
            self.step(step_ms, settled, sites, dropped);
            return;
        }
        self.sealing = Some(generation);
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
                open,
            }));
        });
    }

    /// The window step of `step_ms`, every bin through `settled` sealed: run off this thread when
    /// there is a window to solve, its working set reserved in the `Engine` store while it runs
    /// (a seat's `SOLVE_BYTES_PER_RECEIVER`). One the store cannot reserve (it always can: the
    /// store's share is that and the receptions waiting, each admitted within its own) is put off,
    /// counted, and its windows are the next step's.
    fn step(&mut self, step_ms: u64, settled: i64, sites: Vec<Site>, dropped: Dropped) {
        let generation = self.generation;
        let seats = self.settings.capacity.receivers;
        let Some(engine) = self.engine.as_mut() else {
            self.part_done(false);
            return;
        };
        engine.add_dropped(dropped);
        let job = engine.prepare_sealed(step_ms, step_ms, settled, sites);
        // Sealed and forgotten: what the raw holds now.
        self.settle_sealed();
        let Some(job) = job else {
            self.part_done(false);
            return;
        };
        let Some(working) = self
            .engine_gauge
            .try_charge(seats.saturating_mul(SOLVE_BYTES_PER_RECEIVER))
        else {
            self.shared.count(|counts| counts.windows_deferred += 1);
            self.part_done(false);
            return;
        };
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        spawn_or_run(Urgency::Background, move || {
            shared.delay(Stage::Window);
            let outcome = job.run();
            drop(working);
            let _ = messages.send(Message::Finished(Finished::Stepped(
                generation,
                Box::new(outcome),
            )));
        });
    }

    /// The areas `set_areas` named and their band (every shard already re-scoped to them, under
    /// `generation`): none drops the engine and its raw; the first after none starts a new engine
    /// under a new boot id; otherwise the engine's scope changes in place.
    fn rescope(&mut self, generation: u64, areas: Regions, band: Regions) {
        if areas.is_empty() {
            // No longer an MLAT relay for anything: the engine and its raw go, and whatever it
            // is still sealing or solving is discarded when it reports.
            self.engine = None;
            self.drop_steps();
            self.generation = generation;
            return;
        }
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
        self.settle_sealed();
        for shard in 0..provisional_::SHARDS {
            self.shared.listening(shard).clear();
        }
        self.shared
            .waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .shrink_to(0);
        self.shared.intervals().open.clear();
        self.queued.clear();
        self.running = None;
        self.sealing = None;
        self.through_ms = None;
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

/// Hands the memory the allocator holds free back to the system. A window step's working set is
/// allocated on many short-lived threads (`window::parallel`), each served by one of the
/// allocator's arenas, and freed when the step ends; glibc keeps what an arena freed for that arena
/// to reuse, so without this the relay's resident memory is its stores' peak working sets summed
/// over every arena, not what its stores hold (RFC-0181, "Sizing": at 500 feeders, about twice what
/// was allocated). Called after each window step, on the engine's thread.
fn give_back_freed() {
    // SAFETY: `malloc_trim` takes no pointer and only returns free pages of the allocator's own
    // arenas to the system; it is safe to call from any thread at any time.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        let _ = libc::malloc_trim(0);
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
    use tally_wire::rendezvous::AREA_RESOLUTION;
    use tally_wire::{Location, Region};

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    const BOOT: u64 = 0xb007;

    fn settings() -> Settings {
        Settings {
            regions: Regions::default(),
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
    fn areas() -> Result<Regions, String> {
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
                areas.push(area);
            }
        }
        Ok(Regions::new(areas))
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
        // A host that keeps up sheds nothing.
        assert_eq!(
            (report.steps_shed, report.shed, report.windows_deferred),
            (0, 0, 0),
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
        host.set_areas(Regions::default(), Vec::new());
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
        host.set_areas(Regions::default(), Vec::new());
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
        let budget = Budget::of_memory(64 << 30, crate::budget::Plan::planned(true));
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

    /// RFC-0181 §9, "MLAT receiver limit comes from the same F": the engine seats exactly the
    /// feeders the relay's budget admits, no floor beside it, and so holds the raw the budget
    /// reserved for `Held` and `Open`, and the waiting receptions and window working set it
    /// reserved for `Engine`, and no more.
    #[test]
    fn the_seats_are_the_feeder_ceiling_and_what_they_hold_is_the_stores() {
        use tally_mlat_solver::held::Rates;
        let per_feeder = PerFeeder::planned(true);
        for feeders in [1, 7, 30_000] {
            let budget = Budget::new(per_feeder.total() * feeders, per_feeder);
            assert_eq!(budget.ceiling(), feeders);
            let capacity = capacity(&budget);
            assert_eq!(capacity.receivers, feeders);
            let cost = Rates::MEASURED.cost(SETTLE_MS);
            assert_eq!(budget.store_bytes(Store::Held), feeders * cost.sealed);
            // Open raw over its settling and the steps MLAT may fall behind, at its ceiling.
            assert_eq!(
                budget.store_bytes(Store::Open),
                feeders * Rates::MEASURED.cost(OPEN_MS).open
            );
            assert!(Rates::MEASURED.cost(OPEN_MS).open > cost.open);
            // The receptions waiting and a window step's working set: exactly the store.
            assert_eq!(
                budget.store_bytes(Store::Engine),
                capacity.waiting() * provisional_::WAITING_BYTES
                    + feeders * SOLVE_BYTES_PER_RECEIVER
            );
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
            let weighed = shared.weigh_intervals(11_000);
            assert_eq!(weighed.refused, [10].into_iter().collect(), "{order:?}");
            assert_eq!(weighed.refused_batches, 2, "{order:?}");
            // The next step's is not.
            let weighed = shared.weigh_intervals(12_000);
            assert!(
                weighed.refused.is_empty() && weighed.refused_batches == 0,
                "{order:?}"
            );
        }
        Ok(())
    }

    /// A host whose `Notes` store cannot hold a step's notes lets that step go whole, as one
    /// refused for its count: nothing of it is held, in any shard, the store is never charged past
    /// its limit, and the step that weighs it counts its every batch shed.
    #[test]
    fn a_steps_notes_the_store_cannot_hold_are_let_go_whole_and_counted() -> Result<(), String> {
        let notes = |count: u32| -> Vec<Note> {
            (0..count).map(|n| Note::Position(0x40_0000 + n)).collect()
        };
        let batches = [
            told(1, 0, 10_100)?,
            told(2, 0, 10_500)?,
            told(3, 0, 10_900)?,
        ];
        let one = batches[0].footprint() + 10 * std::mem::size_of::<Note>();
        let gauges = Gauges {
            notes: Gauge::new(Store::Notes, one * 2 + one / 2),
            ..Gauges::unlimited()
        };
        let host = HostedMlat::charging(identity(), BOOT, settings(), gauges.clone())?;
        let shared = &host.shared;
        for batch in &batches {
            shared.tell(batch, notes(10), 1);
        }
        // A later step's batch is held as before.
        shared.tell(&told(4, 0, 11_200)?, notes(10), 1);
        for shard in 0..provisional_::SHARDS {
            assert!(
                shared
                    .listening(shard)
                    .heard
                    .iter()
                    .all(|heard| heard.interval == 11)
            );
        }
        assert!(gauges.notes.peak() <= gauges.notes.limit());
        assert_eq!(gauges.notes.held(), one);
        let weighed = shared.weigh_intervals(11_000);
        assert!(weighed.refused.is_empty());
        assert_eq!((weighed.refused_batches, weighed.shed_batches), (0, 3));
        Ok(())
    }

    /// RFC-0181 §9, §10: a host that falls behind its steps (its window steps slowed, the watermark
    /// passing a step every call, nothing waited for) sheds whole steps, counted, and never grows a
    /// store past its limit; it still solves its windows, each the next step's; and once caught up
    /// it has nothing in hand.
    #[test]
    fn a_host_that_falls_behind_sheds_whole_steps_counted_and_holds_every_store()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 90.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let receivers = delivered
            .iter()
            .filter(|(_, record)| matches!(record, Record::ReceiverInfo(_)))
            .count();
        let plan = crate::budget::Plan::planned(true);
        let budget = Budget::of_memory(Budget::memory_for(receivers, plan), plan);
        let gauges = Gauges::of(&budget);
        let host = HostedMlat::charging(
            identity(),
            BOOT,
            Settings {
                capacity: capacity(&budget),
                ..settings()
            },
            gauges.clone(),
        )?;
        host.set_areas(areas()?, Vec::new());
        // Every window step takes far longer than the steps the watermark passes meanwhile.
        host.delaying(Arc::new(|stage: Stage| {
            if stage == Stage::Window {
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }));
        let mut next = 0;
        let mut published = Vec::new();
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            published.extend(host.take_published(step));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        quiet(&host);
        published.extend(host.take_signed());
        let report = host.report();
        assert!(report.steps_shed > 0, "{report:?}");
        assert!(report.shed > 0, "{report:?}");
        // Shed steps' windows are solved by the steps after them.
        assert!(report.steps > 0, "{report:?}");
        assert!(
            published
                .iter()
                .any(|record| matches!(record, Record::ClockModel(_))),
            "no models"
        );
        for gauge in [&gauges.held, &gauges.open, &gauges.notes, &gauges.engine] {
            assert!(
                gauge.peak() <= gauge.limit(),
                "{:?}: {} past {}",
                gauge.store(),
                gauge.peak(),
                gauge.limit()
            );
            assert!(gauge.peak() > 0, "{:?} never charged", gauge.store());
        }
        // Caught up: nothing waits but the raw and receptions still held.
        assert_eq!(host.in_flight(), 0);
        assert_eq!(gauges.notes.held(), 0);
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
