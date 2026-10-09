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
//!   replies whole across every shard, finds what is due, all shards in parallel over the threads
//!   the cores' plan leaves MLAT (`Budget::mlat_threads`), and solves the due work of all of them,
//!   ascending by aircraft (`provisional::Plan::job`): the same stamped trace solves the same provisionals on any number
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
//! - **Descriptions, at their step** (RFC-0181 §4). A receiver's description is stamped too, by
//!   the watermark when the relay kept it ([`MlatHost::offer_description`], never before one the
//!   host was asked with), and takes effect at the step after its stamp, applied as the watermark
//!   passes that step, before anything of the step runs: every description of the interval in
//!   the order of their stamps and keys, of each receiver only the newest it signed for that step
//!   (`tally_mlat::intake::taking_effect`: one pending a receiver a step, charged, so a receiver
//!   re-signing in a loop holds one, and an older one never applies after a newer). A batch is
//!   taken as its receiver stood at the step
//!   its interval began, so one stamped in an interval whose descriptions are not applied yet waits
//!   in its raw shard until they are, and one stamped before them is taken as the receiver stood
//!   before. A batch of a receiver not described waits for its description (one store for every
//!   raw shard, `tally_mlat::intake::Orphans`), and is taken when the description is applied, as
//!   the last thing of the interval before its step (its raw judged by its own stamp, its notes
//!   weighed at that step), or let go after `tally_mlat::intake::ORPHAN_MS` of steps. A receiver that stops
//!   taking part is forgotten in the open bins after those earlier steps take, and in the sealed
//!   bins at its step, every bin sealed before included: one still being sealed then forgets it
//!   once it is held; the sites a window step fits with are the ones its step's descriptions left. So a seat that changes, a receiver that leaves and one described after its
//!   batches came all make the same bytes however the threads interleave, as the reference drive
//!   applies them (`tally_mlat::replay`). Before an engine's first step, and when the areas change,
//!   a description is applied as it comes.
//! - **Threads.** One thread owns the engine and does nothing that takes long, and wakes for a
//!   message alone, and for an ask only when the watermark passed a step no ask handed it yet and
//!   an engine runs. MLAT's work runs on its runners, started with the host and living as long as
//!   it does: one for the seals and forgets, one for the window steps, one for the provisional
//!   steps, each doing its work one piece at a time, in order (`Runners`), so no piece of it ever
//!   runs on the engine's thread for want of a thread. Every step the watermark passes is sealed
//!   in its turn, whatever the window steps are doing, each within what the seals and forgets
//!   before it left (receivers that left together forgotten in one pass, each bin re-sealed once,
//!   bin by bin, each charged before it is built); once a step's seal is held, a window step is
//!   queued if a window falls due at it (`Engine::falls_due`: about once a stride, 40 s), and what
//!   no window still to be solved needs is forgotten by the step's stamp (`Engine::forget_by`),
//!   so the room the next seal has is the stamps' alone. Window steps (a window's fits and
//!   solutions, as of the step it fell due at) run one at a time, in order, and provisional steps
//!   (weighing every address shard, then solving what is due) one at a time, in order, the two
//!   kinds apart: a slow window never holds a provisional position up. A provisional step with
//!   nothing to weigh is done on the engine's thread, at once, on no runner. Every kind of work
//!   together, and the relay's standing, which MLAT's positions bring (`standing::Standing::start`,
//!   on this gate, [`MlatHost::gate`]), runs on the threads the plan gives MLAT
//!   (`Budget::mlat_threads`), never more
//!   (`tally_mlat_solver::gate`: each thread at work holds one of them; provisional work is let in
//!   before background work, between two of its items, and keeps one of them to itself). Every
//!   runner runs below the relay's own priority, whatever it was started at, provisional steps
//!   above window steps, seals and forgets (`Urgency`; one that could not be lowered all the way
//!   is counted), and no step holds a lock a stage or the engine's thread waits on while it works,
//!   so a host short of cores delays MLAT, which sheds, and never raw. A provisional step carries
//!   exactly the models of the windows that fell due `tally_mlat::engine::MODELS_RIPEN_MS` before
//!   it, each ripening by its own window's step however late it was solved, as the engine
//!   solving in line does, and is shed at its turn, counted
//!   (`MlatReport::provisional_models_late`), if one of them has not been solved: it never runs
//!   with other models, so every provisional step that runs makes the reference's bytes however
//!   long a window step ran or waited. The ripening covers a window step on the planned threads,
//!   so a host within its plan never sheds one so. MLAT work that panics ends the process, as a
//!   panic anywhere in the relay does (`EndOnUnwind`). Each kind that falls behind on its own
//!   steps waits, up to its own limit; past it MLAT sheds, whole and counted, never by growing
//!   (below, Behind).
//! - **Behind** (RFC-0181 §9, §10). While more than `WINDOW_STEPS_BEHIND` window steps (steps a
//!   window fell due at) wait not started, the oldest is shed, counted, its windows the next one's
//!   (which solves every window due, as one that ran late would); nothing a window step queued
//!   or running has still to solve is forgotten by the stamps while it waits (`Engine::forget_by`'s
//!   floor). The bins only that floor keeps live in the room the stamps' bins leave in the `Held`
//!   store, and yield it to them, oldest first, counted (`MlatReport::waiting_bins_forgotten`),
//!   so what a seal or a forget refuses is the stamps' alone (`Host::room`), however long a window
//!   step ran or waited, and a window that waits is solved with the bins it began with whenever
//!   the store has room for them. A host within its plan holds none: its window steps finish
//!   before the stamps forget their first bin. While the watermark
//!   passes more than `PROVISIONAL_BEHIND` (none) provisional steps that have not started, the
//!   oldest of those is shed: what batches told it is let go, every batch of it counted
//!   (`MlatReport::shed`), so a provisional step starts at its turn and its positions reach the
//!   live world before its second is sealed (`PROVISIONAL_PUBLISH_MS`, checked against
//!   `products::WORLD_SETTLE_MS`); its records taken once the watermark has passed
//!   `PROVISIONAL_PUBLISH_MS` after its step are refused whole, counted
//!   (`MlatReport::provisional_steps_late`), its state applied all the same. What MLAT holds
//!   therefore never waits on more steps than that, which is what the budget reserves for it
//!   (`OPEN_MS`, `INTERVALS_HELD`, `WAITING_MS`). A host whose window steps start when their window
//!   falls due and finish within the forgetting's grace never sheds, so the same stamped trace
//!   still makes the same bytes; one that does not loses provisional positions, counted, and
//!   never a window.
//! - **Overload** (RFC-0181 §10). A window step that runs past `WINDOW_BUDGET_MS` (the models'
//!   ripening less the steps a seal waits) is MLAT overloaded: the host cuts its seats to what
//!   that run carries within the budget (`Host::judge`), a [`Cut`] from `CUT_LEAD_STEPS` past the
//!   watermark, published for the relays holding the same areas ([`MlatHost::take_cuts`],
//!   [`MlatHost::offer_cut`]). The seats at a step are the least any origin's newest cut at or
//!   before it asks for, applied at the step like a description (`Host::apply`,
//!   `Seats::set_cap`), and the receivers solved are the best ranked by key hash, so every relay
//!   offered the same cuts solves the same receivers from the same step and makes the same
//!   bytes: the cut is decided by rank and by stamp, never by how far behind one host was. The
//!   receivers cut stay described and are counted refused (`MlatReport::receivers_refused`); a
//!   host that cut lifts its cut the same way when its window steps run well within the budget.
//!   The sheds of Behind remain beneath it, a bound on what is held and no longer the policy: a
//!   host the cut keeps within its budget sheds nothing.
//! - **Capacity** (RFC-0181 §9). MLAT has its own pool of receiver seats, the count the budget
//!   plans from the cores and memory the stages leave (`capacity`, `Budget::mlat_seats`). The
//!   receivers seated are the best ranked of those described (`tally_mlat::intake::Seats`:
//!   taking part first, then a hash of the receiver's key under the fleet's seed, the same on
//!   every relay), whichever raw shard took them and in whatever order. A receiver past the seats
//!   is not hosted for MLAT (its raw still flows), refused at its description and counted. Every byte it
//!   holds is charged to a store of the relay's budget before it is held ([`host_for`]), and none is
//!   charged past its store's limit. A shard's open raw is bounded by each receiver's share of a
//!   bin, and charged to `Open` as it grows: a byte refused refuses the batch's raw of the bin,
//!   counted. Sealed raw is checked on each complete bin as it is sealed
//!   (`tally_mlat::engine::seal`), within `Held`, a function of what was sealed, and charged to it
//!   as it is inserted. What batches tell provisional solving is bounded per step,
//!   `NOTES_PER_RECEIVER_STEP` a seat: a step's notes beyond it are refused whole, the step's every
//!   batch, and so is a step whose notes' bytes pass its share of the `Notes` store (the store over
//!   `INTERVALS_HELD`, both bounds from `NOTES_HEADROOM`); it is charged to `Notes` until the step
//!   reads it, so a host that sheds nothing never fills the store, and a step whose notes the store
//!   cannot hold is let go whole, as a shed one is. A batch's replies that do not fit the provisional state
//!   (`Capacity::waiting`, charged to `Engine`) are refused in every address shard at once
//!   (`provisional::admit`), and a window step's working set is reserved in `Engine` while it runs.
//!   Signed records not yet taken are bounded in bytes (`PUBLISHED_BYTES`, in the relay's base), a
//!   step's refused whole, so a part never goes without its manifest. The `Orphans` store is split
//!   in two shares, each whole (`Room`): batches waiting for a description that has not come
//!   (`intake::ORPHAN_MS` of a feeder's), in one store for every raw shard whose receivers are the
//!   best drawn of those that came, each its newest within its bytes, so who is held never
//!   depends on arrival and the share is never charged past; and what waits for a step's
//!   descriptions, batches and descriptions alike (`WAITING_MS`), which only a host behind on its
//!   watermark passes, its excess let go, counted: each receiver within its share of it and the
//!   receivers held by rank (`WaitingRoom`), so who is held never depends on arrival there either.
//!   Raw of a bin that begins more than `held::AHEAD_MS` past its batch's own stamp is refused,
//!   counted (`MlatReport::observations_ahead`), however late the batch is taken (one that waited
//!   for its description too, as the reference engine judges it), so no bin opens that the steps
//!   never reach. Which steps'
//!   notes and which batches' replies are refused for their count depends on neither arrival order
//!   nor the number of threads; what is shed for a host that falls behind is whole; all of it is
//!   counted.
//! - **Counted.** Nothing offered or solved is let go silently: every drop is counted by why, and
//!   every step's report kept ([`MlatReport`], served on `--stats-listen` as `GET /mlat`).
//! - **Time.** Nothing here reads a clock: a batch carries its stamp and `take_published` the
//!   watermark, so the same stamped records publish the same bytes as the engine driven in line on
//!   the same steps, and whether a provisional step's records are late is the watermark they are
//!   taken at against their step (`PROVISIONAL_PUBLISH_MS`), the stamps the live world is sealed
//!   by.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};

use tally_mlat::engine::{
    Capacity, Dropped, Engine, Ingested, MODELS_RIPEN_MS, Settings, kept_by_stamps,
};
use tally_mlat::intake::{
    Description, Intake, ORPHAN_MS, Orphans, Seats, signed_order, taking_effect,
};
use tally_mlat::provisional::{self as provisional_, Due, Note, Order, Taken};
use tally_mlat::{area, provisional, window};
use tally_mlat_solver::Site;
use tally_mlat_solver::gate::{self, Gate};
use tally_mlat_solver::held::{Bin, Closing, Fragment, Limits, Resealed, SealedBins};
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
    /// A receiver's description the relay kept, stamped `stamp_ms` by the relay's stamp watermark
    /// when it kept it (`Products::watermark_ms`): it takes effect at the step after its stamp
    /// (module docs, Descriptions). A batch reaches the host only as the relay's one decode of it
    /// (`offer_batch`): there is no second way in, so none decodes it again.
    fn offer_description(&self, info: &ReceiverInfo, stamp_ms: u64);
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
    /// The threads the plan gives MLAT (`tally_mlat_solver::gate`), which work it brings beside
    /// its own (the relay's standing) runs on too. None when it has no gate of its own.
    fn gate(&self) -> Option<Arc<Gate>> {
        None
    }
    /// A cut another relay holding the same areas published (module docs, Overload): the seats
    /// MLAT keeps from the step it names. Offered in any order; the same cuts make the same bytes.
    fn offer_cut(&self, _cut: Cut) {}
    /// The cuts this host decided since the last call, in the order decided: the relay publishes
    /// each, stamped, to every relay holding the same areas, which offer it to their hosts.
    fn take_cuts(&self) -> Vec<Cut> {
        Vec::new()
    }
}

/// An overload cut (module docs, Overload): from step `from_ms` (a multiple of `STEP_MS`), the
/// relay `origin` asks that MLAT seat only the `seats` best ranked receivers
/// (`tally_mlat::intake::Seats`). It is a fact of the stamps, not of a clock: the seats at a step
/// are the least any origin's newest cut at or before that step asks for, so every relay offered
/// the same cuts seats the same receivers at the same steps and makes the same bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cut {
    pub from_ms: u64,
    pub origin: PublicKey,
    pub seats: u32,
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
    /// Clocks the fits dropped as cut off from their gauge (`FitError::Disconnected`).
    pub disconnected: u64,
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
            disconnected: n(report.disconnected),
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
        self.disconnected += other.disconnected;
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
    /// Window steps shed because more than `WINDOW_STEPS_BEHIND` of them (steps a window fell due
    /// at) waited not started: their windows the next one's. A step's seal is never shed.
    pub steps_shed: u64,
    /// Provisional steps shed because the watermark passed more than `PROVISIONAL_BEHIND` of them
    /// not started: what batches told them let go (`shed`).
    pub provisional_steps_shed: u64,
    /// Window steps put off because the `Engine` store could not reserve their working set: each
    /// waits, and starts once it can, its windows as of its own step.
    pub windows_deferred: u64,
    /// Sealed bins a waiting window step's floor kept past the stamps (module docs, Behind) let go,
    /// oldest first, because the stamps' bins needed their room in the `Held` store: that window
    /// step solves without them. Only a host behind its plan holds such a bin at all (a planned
    /// window step finishes before the stamps forget its first bin).
    pub waiting_bins_forgotten: u64,
    /// Signed records refused whole with their step's because those not yet taken held
    /// `PUBLISHED_BYTES`.
    pub overflowed: u64,
    /// Batches whose (boot, sequence) was already used or too far behind.
    pub replayed: u64,
    /// Receiver descriptions refused as not signed as they claim.
    pub ingest_errors: u64,
    /// Batches waiting for their receiver's description (one not yet come, or one taking effect at
    /// a step not yet applied) not held, for room; and those of a description that never came,
    /// let go after `tally_mlat::intake::ORPHAN_MS` of steps.
    pub orphans_dropped: u64,
    pub orphans_expired: u64,
    /// Batches and descriptions waiting for a step's descriptions to be applied not held, for
    /// room: the watermark fell further behind their stamps than `WAITING_MS` (module docs,
    /// Behind).
    pub waiting_dropped: u64,
    /// Provisional steps shed at their turn because a window that fell due `MODELS_RIPEN_MS` before
    /// them, whose models they carry, had not been solved (module docs, Threads): a provisional
    /// step never runs with other models than the reference's. Counted in `provisional_steps_shed`
    /// too.
    pub provisional_models_late: u64,
    /// Provisional steps whose records were taken once the watermark had passed
    /// `PROVISIONAL_PUBLISH_MS` after their step: refused whole, counted, and their records with
    /// them (`provisional_records_late`), as they would reach the live world after its second is
    /// sealed. By the stamps alone.
    pub provisional_steps_late: u64,
    pub provisional_records_late: u64,
    /// MLAT's runners whose priority could not be lowered as far below the stages' as planned
    /// (`Urgency`): at the relay's own, or nearer it (a relay already near the lowest).
    pub priority_unset: u64,
    /// Observations of a bin already taken for sealing: stamped at or after the step that took it.
    pub observations_late: u64,
    /// Observations of a bin that begins more than `tally_mlat_solver::held::AHEAD_MS` past their
    /// batch's stamp, refused.
    pub observations_ahead: u64,
    /// Observations refused with their receiver's whole raw of a bin, beyond its share or beyond
    /// the raw the engine holds (`tally_mlat_solver::held::Limits`), or with their batch's for room
    /// in the `Open` or `Held` store, or with a bin no room was left to seal again without a
    /// receiver that left. Counted as the shards take a step's bins and as its seal finishes,
    /// never lost with an engine that goes.
    pub observations_refused: u64,
    /// New receivers refused whole, beyond the receivers the engine holds
    /// (`tally_mlat::engine::Capacity`).
    pub receivers_refused: u64,
    /// Overload cuts this host decided (module docs, Overload), and cuts offered too late to take
    /// effect at their step (the step was applied already: they take effect at the next).
    pub cuts_decided: u64,
    pub cuts_late: u64,
    /// Cuts this relay addressed to the relays holding its areas, took from them, and refused
    /// (`Network`; filled when the report is served).
    pub cuts_sent: u64,
    pub cuts_received: u64,
    pub cuts_refused: u64,
    /// The seats in force now: the cap an overload cut left on the seats MLAT was given.
    pub seat_cap: u64,
    /// The seats MLAT holds at most, and those taken now.
    pub seat_limit: u64,
    pub seats_taken: u64,
    /// Seals, window and provisional steps whose engine was dropped before they reported: not
    /// published.
    pub steps_discarded: u64,
    /// Window steps applied.
    pub steps: u64,
    /// Provisional steps applied: beside `provisional_steps_shed`, what MLAT ran of the steps the
    /// watermark passed, and what it shed.
    pub provisional_steps: u64,
    /// The newest step's report, and every step's summed.
    pub last_step: Option<StepReport>,
    pub steps_total: StepReport,
    pub provisional: ProvisionalReport,
}

/// What a window step may run for (module docs, Overload): the models' ripening less the steps a
/// seal may wait before it, so a window step that runs no longer is solved before the provisional
/// step that carries its models. A longer one is overload: MLAT cuts its seats.
pub const WINDOW_BUDGET_MS: u64 = MODELS_RIPEN_MS - 3 * STEP_MS;
/// What a cut aims a window step at: three quarters of the budget, so the step after it has room.
pub const WINDOW_TARGET_MS: u64 = WINDOW_BUDGET_MS * 3 / 4;
/// Steps ahead of the watermark a cut takes effect, for the relay to publish it to its peers
/// before any of them reaches the step.
pub const CUT_LEAD_STEPS: u64 = 5;
/// The fewest seats a cut leaves.
pub const MIN_CUT_SEATS: usize = 8;
/// Origins whose cuts are kept, and cuts kept of each: a relay's peers are few, and a cut is
/// superseded by its origin's next.
const CUT_ORIGINS: usize = 64;
const CUTS_PER_ORIGIN: usize = 16;

/// The step clock's grid: the host steps at every multiple of it the watermark passes.
pub const STEP_MS: u64 = 1_000;
/// How long after a bin's canonical window ends it is solved, so the raw of its last bin is in.
pub const SETTLE_MS: u64 = 2_000;
/// Window steps (the steps a window fell due at, one a stride: `STRIDE` bins, 40 s) that may wait
/// not started (one is running) before the oldest is shed (module docs, Behind). A count of window
/// steps, never of the 1 s steps the watermark passes: nothing sized by the step clock reads it
/// (sweep 6, F10: before, one `STEPS_BEHIND` was this and the seals' bound below, so the window
/// queue's length set the open raw the budget reserves and the ripening checked against it).
pub const WINDOW_STEPS_BEHIND: usize = 4;
/// Steps' seals (one a step, 1 s each, a seal taking milliseconds) a host within its plan falls
/// behind by at most: what the budget reserves open raw for (`OPEN_MS`) and what the ripening
/// covers (`MODELS_RIPEN_MS`, below). Not a count anything sheds by: a seal is never shed (its
/// bins are the windows'), so a host further behind holds its taken raw in the `Open` store, and
/// past the store the shards refuse new raw, whole and counted (`observations_refused`), the store
/// never past its limit.
pub const SEALS_BEHIND: usize = 4;
/// How long after a bin ends its raw is held open at most by a host within its plan: its settling,
/// the seals it may fall behind (`SEALS_BEHIND`), and the seal running. What the budget reserves
/// for open raw (`Store::Open`); past it the shards refuse raw, counted.
pub const OPEN_MS: u64 = SETTLE_MS + (SEALS_BEHIND as u64 + 1) * STEP_MS;
/// Provisional steps the watermark may pass that have not started (one may be running) before the
/// oldest is shed (module docs, Behind): none. A provisional step starts at its turn, or, if the
/// one before it is still running then, is let go when the next one's turn comes. The budget below
/// leaves no step for one to start late.
pub const PROVISIONAL_BEHIND: usize = 0;
/// A provisional step's own run, and its records' way to the relay that gathers the live world:
/// what is left of `products::WORLD_SETTLE_MS` once a transmission's provisional is due and its
/// step starts (below). Held by the stamps: a step whose records are taken once the watermark is
/// this far past it has them refused whole, counted (`MlatReport::provisional_steps_late`; sweep
/// 4, R-P16: before, a step running 900 to 1,000 ms missed the world second unseen; sweep 5, R2:
/// before, it was the wall clock from its turn to its run's end, which left out the watermark's
/// lag and the wait to be taken), and one that overruns its whole step has its next step shed
/// (`PROVISIONAL_BEHIND`). The records' way on from here is `tally-load`'s provisional latency to
/// measure (a bed).
pub const PROVISIONAL_PUBLISH_MS: u64 = 900;
// A transmission's provisional, from its first reception's stamp: due `provisional::SETTLE_MS`
// after it, or kept past that while too few receivers have come, and weighed by the first step at
// or after (`provisional::WAITING_MS`, all three); that step starts within `PROVISIONAL_BEHIND`
// steps of its turn, and publishes within `PROVISIONAL_PUBLISH_MS`. Its world second is sealed
// `WORLD_SETTLE_MS` after the second ends, so the provisional is in the world before it is. (The
// way from the transmission to that stamp, the feeder's batching and its link, is the world
// product's to allow for.)
const _: () = assert!(
    provisional_::WAITING_MS + PROVISIONAL_BEHIND as u64 * STEP_MS + PROVISIONAL_PUBLISH_MS
        <= crate::products::WORLD_SETTLE_MS
);
// A provisional step carries exactly the models of the windows that fell due `MODELS_RIPEN_MS` before
// it, and is shed at its turn if one of them has not been solved (module docs, Threads): the
// ripening is at least the steps a seal may fall behind and the one running (`SEALS_BEHIND`, in
// steps of the step clock), and it is a window step's run on the planned threads besides
// (`MODELS_RIPEN_MS`), so a planned host's window steps never shed one.
const _: () = assert!(MODELS_RIPEN_MS >= (SEALS_BEHIND as u64 + 1) * STEP_MS);
/// Step intervals whose notes are held at most: the one the watermark is in and the next, the
/// provisional steps that may wait (`PROVISIONAL_BEHIND`), and the step running until it reads its
/// own. What the budget reserves for notes (`Store::Notes`, `notes_per_feeder`), and what each
/// interval may hold of it (`Shared::tell`), so a host that sheds nothing never fills the store.
pub const INTERVALS_HELD: usize = PROVISIONAL_BEHIND + 3;
/// A seat's share of a window step's working set (its scope, its fits and its solutions), reserved
/// in the `Engine` store while the step runs. Measured (RFC-0181, "Sizing", 2026-10-08): a window
/// step at 500 feeders allocated at most 79 MiB beyond what it read, about 160 KiB a feeder.
pub const SOLVE_BYTES_PER_RECEIVER: usize = 192 << 10;
/// Commands for the engine's thread not yet taken: a few seconds of asks and changes. An ask
/// beyond it is dropped; the next carries a watermark at least as new, which steps everything the
/// dropped one would have.
const COMMANDS_WAITING: usize = 1 << 12;
/// What batches tell provisional solving a second, a feeder, as RFC-0181 plans it: about 300 replies
/// and positions.
pub const PLANNED_NOTES_PER_SEC: usize = 300;
/// How far past the planned rate one step's notes may go before the step's are refused whole: the
/// count (`NOTES_PER_RECEIVER_STEP`) and the bytes (`notes_per_feeder`) alike, from this one
/// figure, so the store is sized for what a step admits.
pub const NOTES_HEADROOM: usize = 4;
/// What batches may tell provisional solving in one step, a seat: `NOTES_HEADROOM` times the
/// planned rate. Beyond it the step's notes are refused whole (`MlatReport::refused`), so a step
/// holds at most this times the seats, and which batches are refused is a function of the trace,
/// never of the interleaving.
pub const NOTES_PER_RECEIVER_STEP: usize =
    NOTES_HEADROOM * PLANNED_NOTES_PER_SEC * STEP_MS as usize / 1_000;
/// Bytes of signed records not yet taken (`Record::encoded_len`): many steps of a busy area, taken
/// by the network task every tick. A step's records that would pass it are refused whole, counted,
/// so a clock model's parts never wait without their manifest; a step's records larger than the
/// whole bound are taken only into an empty queue, so one is never refused forever.
pub const PUBLISHED_BYTES: usize = 4 << 20;

/// What one feeder's notes to provisional solving cost the `Notes` store, given what a second of
/// its batches costs decoded (`decoded_per_sec`, at the planned rate): every interval held
/// (`INTERVALS_HELD`) of the batches the notes keep alive and the notes, at `NOTES_HEADROOM` times
/// the planned rate, the same figure that bounds a step's count. Each interval may hold this over
/// `INTERVALS_HELD` a seat; past it the interval's notes are refused whole, by the trace.
pub fn notes_per_feeder(decoded_per_sec: usize) -> usize {
    let step = STEP_MS as usize;
    INTERVALS_HELD
        * NOTES_HEADROOM
        * (decoded_per_sec * step / 1_000
            + PLANNED_NOTES_PER_SEC * step / 1_000 * std::mem::size_of::<Note>())
}

/// How far past the last step whose descriptions are applied a batch may be stamped and wait for
/// them in its raw shard (module docs, Descriptions): the epochs the relay holds ahead of its
/// watermark (`seal::EPOCHS_HELD` of `seal::EPOCH_MS`: a batch stamped further ahead of the
/// watermark is refused by the message exchange's epochs, which push back on ingest) and the step
/// in progress. Further behind than that, the host is behind (module docs, Behind): a batch past
/// the share it reserves is let go, counted (`MlatReport::waiting_dropped`).
pub const WAITING_MS: u64 = crate::seal::EPOCHS_HELD * crate::seal::EPOCH_MS + STEP_MS;
/// A receiver's description as planned in the `Orphans` store: one a second, a feeder, over what
/// the store holds (descriptions are charged by their bytes; a few hundred is usual).
pub const PLANNED_DESCRIPTION_BYTES: usize = 512;

/// What one feeder costs the `Orphans` store, given what a second of its batches costs decoded:
/// its batches waiting for a description that has not come, `intake::ORPHAN_MS` of them, the
/// longest one waits; and its batches and description waiting for a step's descriptions to be
/// applied, `WAITING_MS` of them. The host splits the store between the two by those times
/// (`Room::of`), and neither share is ever charged past.
pub fn orphans_per_feeder(decoded_per_sec: usize) -> usize {
    (decoded_per_sec + PLANNED_DESCRIPTION_BYTES) * (ORPHAN_MS + WAITING_MS) as usize / 1_000
}

/// The `Orphans` store split (`orphans_per_feeder`): the batches waiting for a description that has
/// not come, and those (and descriptions) waiting for a step's descriptions to be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Room {
    orphans: usize,
    waiting: usize,
}

impl Room {
    /// The store's `limit` split by the times each share holds.
    fn of(limit: usize) -> Self {
        let orphans =
            (limit as u128 * u128::from(ORPHAN_MS) / u128::from(ORPHAN_MS + WAITING_MS)) as usize;
        Self {
            orphans,
            waiting: limit - orphans,
        }
    }
}

/// The stores of the relay's budget hosted MLAT is charged to.
#[derive(Clone)]
pub struct Gauges {
    /// Sealed raw.
    pub held: Arc<Gauge>,
    /// Open raw: the raw shards' bins, and those on their way to sealing.
    pub open: Arc<Gauge>,
    /// What batches told provisional solving, until the step that weighs it reads it.
    pub notes: Arc<Gauge>,
    /// The engine's own tables: the receptions waiting for provisional solving, and a window
    /// step's working set while it runs.
    pub engine: Arc<Gauge>,
    /// Batches waiting for their receiver's description: one not yet come, or one that takes
    /// effect at a step not yet applied.
    pub orphans: Arc<Gauge>,
}

impl Gauges {
    /// The budget's.
    pub fn of(budget: &Budget) -> Self {
        Self {
            held: budget.gauge(Store::Held),
            open: budget.gauge(Store::Open),
            notes: budget.gauge(Store::Notes),
            engine: budget.gauge(Store::Engine),
            orphans: budget.gauge(Store::Orphans),
        }
    }

    /// Of no budget: for a host built apart from a relay (a test's).
    pub fn unlimited() -> Self {
        Self {
            held: Gauge::unlimited(Store::Held),
            open: Gauge::unlimited(Store::Open),
            notes: Gauge::unlimited(Store::Notes),
            engine: Gauge::unlimited(Store::Engine),
            orphans: Gauge::unlimited(Store::Orphans),
        }
    }
}

/// The hosted MLAT a relay runs, if any: none when its relay duties are off (`--no-relay-duties`)
/// or it runs no MLAT (`--no-mlat`). Its steps are spread over the threads its cores' plan leaves
/// them (`Budget::mlat_threads`), and sized and charged by the relay's `budget`:
/// its seats are the feeder ceiling ([`capacity`]), its sealed and open raw are the `Held` and
/// `Open` stores', its provisional notes the `Notes` store's, its own tables the `Engine` store's
/// and the batches waiting for a description the `Orphans` store's ([`Gauges::of`]). An error when
/// its thread cannot start.
pub fn host_for(
    config: &Config,
    identity: Identity,
    boot_id: u64,
    budget: &Budget,
) -> Result<Option<HostedMlat>, String> {
    if !config.relay_duties || !config.mlat {
        return Ok(None);
    }
    HostedMlat::charging(
        identity,
        boot_id,
        Settings {
            regions: Regions::default(),
            settle_ms: SETTLE_MS,
            threads: budget.mlat_threads().max(1),
            capacity: capacity(budget),
        },
        Gauges::of(budget),
    )
    .map(Some)
}

/// What the hosted engine holds: MLAT's own pool of receiver seats (RFC-0181 §9, §10), the count
/// the budget plans from the cores and memory the stages leave (`Budget::mlat_seats`), and the raw
/// of that many at the measured rates, which is what the budget reserved for `Held`
/// (`PerFeeder::planned`). A receiver past the seats is not hosted for MLAT (its raw still flows)
/// and is refused at its description, counted (`MlatReport::receivers_refused`); which receivers
/// hold the seats is decided by key-hash rank (`tally_mlat::intake::Seats`), the same on every
/// relay holding the area. No floor: seats beyond the plan would be cores and raw it never reserved.
pub fn capacity(budget: &Budget) -> Capacity {
    Capacity::for_receivers(budget.mlat_seats())
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
    /// A provisional step reading an address shard, holding it.
    Reading,
    /// A provisional step, between deciding what it keeps and keeping it.
    Weighing,
    /// A seal, before it seals.
    Seal,
    /// A window step, before it solves.
    Window,
    /// Receivers that stopped taking part forgotten in the sealed bins, before they are.
    Forget,
    /// The engine's thread, before it applies a window step's outcome.
    Apply,
}

/// A test's delay at a stage ([`HostedMlat::delaying`]).
pub type Delay = Arc<dyn Fn(Stage) + Send + Sync>;

/// What the engine's thread is handed.
enum Command {
    /// Receivers stopped taking part under engine generation `.0` (the areas changed, or a
    /// description applied as it came): forgotten in the sealed bins together, each bin re-sealed
    /// once for all of them, as the engine in line forgets them (`Engine::forget_receivers`).
    Left(u64, Vec<PublicKey>),
    /// The areas changed (`set_areas` re-scoped every shard first): engine generation, areas.
    Areas(u64, Regions, Regions),
    /// The stamp watermark passed this.
    Tick(u64),
}

/// The step whose seal it is: its clock, the last bin it settles, and the sites taking part as its
/// descriptions left them, for a window that falls due at it.
struct Closed {
    step_ms: u64,
    settled: i64,
    sites: Vec<Site>,
}

/// What the engine's thread does to the sealed bins, in the order it was decided, one seal at a
/// time (module docs, Threads): a step's bins sealed off this thread, within what the seals before
/// them left; or receivers that stopped taking part forgotten in every bin sealed before, those
/// still being sealed included, once they are held.
enum Sealing {
    Seal {
        fragments: Vec<Fragment>,
        open: Vec<Charge>,
        closed: Closed,
    },
    Forget(Vec<PublicKey>),
}

/// A step at which a window fell due, its window step not started (module docs, Behind): the step,
/// the last bin it settled and the sites its descriptions left, as its window step is prepared;
/// and the earliest step whose windows it solves and the first bin of their earliest window (the
/// same, unless a window step shed before it handed it its windows).
struct WindowStep {
    step_ms: u64,
    settled: i64,
    sites: Vec<Site>,
    due_ms: u64,
    first_bin: i64,
    /// Put off once already for want of the `Engine` store (counted once).
    deferred: bool,
}

/// The window step running: the earliest step whose windows it solves, and the first bin of their
/// earliest window, which no step forgets while it runs.
#[derive(Clone, Copy)]
struct Running {
    due_ms: u64,
    first_bin: i64,
}

/// What a seal or a step reports to the engine's thread, for the engine of its generation.
enum Finished {
    /// A step's bins, sealed, with the observations the seal refused for room, and the `Open`
    /// charge of the raw they were sealed from, let go once they are held; and the step it is the
    /// seal of.
    Sealed {
        generation: u64,
        closed: Closed,
        bins: Vec<Bin>,
        refused: u64,
        open: Vec<Charge>,
    },
    /// One bin sealed again without receivers that stopped taking part, with the `Held` charge it
    /// was built under (or refused that charge, to forget whole), and the forget waiting for it to
    /// be held before it asks for the next (`Host::forget`).
    Resealed {
        generation: u64,
        resealed: Resealed<Charge>,
        done: Sender<()>,
    },
    /// Receivers that stopped taking part, forgotten in every bin sealed before.
    Forgotten { generation: u64 },
    /// A window step's outcome, boxed (it is far larger than the others), with the `Engine` charge
    /// of the step's working set, which holds it until it is applied (sweep 4, N17).
    Stepped(u64, Box<window::Outcome>, Charge, u64),
    /// Provisional step `step_ms`'s outcome, and the batches whose notes it refused with their
    /// step's for their count, and let go as shed.
    Solved {
        generation: u64,
        step_ms: u64,
        outcome: provisional::Outcome,
        refused: u64,
        shed: u64,
    },
}

/// Everything the engine's thread is told, in one queue: it wakes for nothing else.
enum Message {
    Command(Command),
    Finished(Finished),
    /// The host was dropped: the thread ends.
    Stop,
}

/// The step of a stamp: the step that weighs its interval, at the end of it. A description stamped
/// `stamp_ms` takes effect at it (module docs, Descriptions).
fn step_of(stamp_ms: u64) -> u64 {
    (stamp_ms / STEP_MS + 1) * STEP_MS
}

/// The step whose interval a stamp is in begins at this one: a batch stamped `stamp_ms` is taken as
/// its receiver stood once every description taking effect at or before it was applied.
fn floor_step(stamp_ms: u64) -> u64 {
    stamp_ms / STEP_MS * STEP_MS
}

/// One raw shard of the hosted MLAT: the intake of the receivers whose raw shard it is (and their
/// batches waiting for a description, `Intake::hold_orphan`), and the batches stamped past the
/// last step whose descriptions it has applied.
struct Shard {
    intake: Intake,
    /// What its intake's open raw is charged to the `Open` store: always its bytes, taken before
    /// they are allocated.
    open: Charge,
    /// The engine generation its intake holds raw for, and whether one runs.
    generation: u64,
    active: bool,
    /// The last step whose descriptions it has applied (module docs, Descriptions), `None` before
    /// the engine's first step (a description then is applied as it comes). A batch stamped in an
    /// interval past it waits in the `WaitingRoom` until that step's descriptions are applied.
    applied_ms: Option<u64>,
}

/// A charge to the `Orphans` store's share for what waits for a step's descriptions
/// (`Room::waiting`), and to the store itself, of `bytes`.
struct Waiting {
    bytes: usize,
    _share: Charge,
    _store: Charge,
}

impl Shard {
    /// A batch into the intake, judged ahead or late by its own stamp however late it is taken
    /// (one that waited for its description too, as the reference engine judges it: sweep 4,
    /// R-P5), every byte of open raw it takes charged to `Open` before it is held
    /// (`Intake::ingest_verified_taking`).
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

/// What a batch says to provisional solving as its raw shard read it: the batch, its notes, the raw
/// shard's engine generation then, and the stamp it is weighed by (its own, or the step that took
/// it after it waited for its description). Handed to the address shards once the raw shard is let
/// go.
struct Told {
    batch: Arc<Decoded>,
    notes: Vec<Note>,
    generation: u64,
    at_ms: u64,
}

/// One address shard of provisional solving (`provisional::Shard`). What it was told and has not
/// weighed yet is apart (`Shared::heard`), under a lock of its own: an ingest worker hands a batch's
/// notes only to that, and never waits on this, which a provisional step holds while it weighs
/// and steps the shard below the stages' priority (`PROVISIONAL_NICE`).
#[derive(Default)]
struct Listening {
    /// The engine generation `state` is of.
    generation: u64,
    state: provisional_::Shard,
}

impl Listening {
    /// Reads `due`, what was heard in an interval before the step (`Shared::due`), for the engine
    /// of `generation` (what an older one heard is dropped), everything `refused` does not refuse,
    /// in the batches' order: the receptions waiting here, and each batch's replies to keep or
    /// refuse (`provisional::admit`).
    fn read(
        &mut self,
        generation: u64,
        mut due: Vec<Heard>,
        refused: &BTreeSet<u64>,
    ) -> (usize, Vec<Taken>) {
        if self.generation != generation {
            self.state = provisional_::Shard::default();
            self.generation = generation;
        }
        due.sort_unstable_by_key(|heard| heard.order);
        let mut taken = Vec::new();
        for heard in due {
            if heard.generation == generation && !refused.contains(&heard.interval) {
                taken.push(self.state.read(
                    &heard.batch,
                    &heard.notes[heard.range.clone()],
                    heard.order,
                ));
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

/// The notes told for one step interval: how many, their bytes, of how many batches, and whether
/// the interval is refused whole, for its count or its bytes, or let go (shed) because MLAT fell
/// behind.
#[derive(Default)]
struct Interval {
    notes: usize,
    bytes: usize,
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

/// The descriptions' steps: the last step whose descriptions were applied (`None` before an
/// engine's first step), and the newest watermark the host was asked with, below which no
/// description is stamped. The descriptions themselves wait in the `WaitingRoom`. Its lock is
/// taken before any shard's, never after one.
#[derive(Default)]
struct Descriptions {
    applied_ms: Option<u64>,
    asked_ms: u64,
}

/// The overload cuts known (module docs, Overload), by the relay that decided each.
#[derive(Default)]
struct Cuts {
    by_origin: BTreeMap<PublicKey, BTreeMap<u64, u32>>,
    /// Decided here and not yet taken for publishing.
    decided: Vec<Cut>,
    /// The seats of the newest cut this host decided, while it holds one under the limit: only a
    /// host that cut lifts its cut (a cut offered by a peer is the peer's to lift).
    own: Option<u32>,
    /// The last step whose cut was applied: one for a step at or before it takes effect at the
    /// next (counted).
    applied_ms: Option<u64>,
}

impl Cuts {
    /// Takes `cut`; false when it was too late for its step (it takes effect at the next), or was
    /// not kept for want of room.
    fn offer(&mut self, mut cut: Cut) -> bool {
        let mut on_time = true;
        if let Some(applied) = self.applied_ms.filter(|applied| cut.from_ms <= *applied) {
            cut.from_ms = applied + STEP_MS;
            on_time = false;
        }
        cut.from_ms = cut.from_ms.div_ceil(STEP_MS) * STEP_MS;
        if !self.by_origin.contains_key(&cut.origin) && self.by_origin.len() >= CUT_ORIGINS {
            return false;
        }
        let entries = self.by_origin.entry(cut.origin).or_default();
        entries.insert(cut.from_ms, cut.seats);
        while entries.len() > CUTS_PER_ORIGIN {
            entries.pop_first();
        }
        on_time
    }

    /// The seats asked for at `step_ms`: the least of each origin's newest cut at or before it,
    /// none asking for any beyond `limit`.
    fn seats_at(&self, step_ms: u64, limit: usize) -> usize {
        self.by_origin
            .values()
            .filter_map(|entries| {
                entries
                    .range(..=step_ms)
                    .next_back()
                    .map(|(_, seats)| *seats)
            })
            .map(|seats| seats as usize)
            .fold(limit, usize::min)
            .max(MIN_CUT_SEATS.min(limit))
    }

    /// `origin`'s newest cut, if any.
    fn newest(&self, origin: &PublicKey) -> Option<(u64, u32)> {
        self.by_origin
            .get(origin)
            .and_then(|entries| entries.iter().next_back().map(|(at, seats)| (*at, *seats)))
    }

    /// Forgets what a step at `step_ms` no longer needs: each origin's cuts before its newest at
    /// or before the step.
    fn applied(&mut self, step_ms: u64) {
        self.applied_ms = Some(step_ms);
        for entries in self.by_origin.values_mut() {
            let keep = entries.range(..=step_ms).next_back().map(|(at, _)| *at);
            if let Some(keep) = keep {
                *entries = entries.split_off(&keep);
            }
        }
    }
}

/// A description waiting for its step, with its stamp and its charge.
struct Pending {
    stamp_ms: u64,
    info: ReceiverInfo,
    charge: Waiting,
}

/// The batches of one raw shard waiting in the `WaitingRoom`, by receiver, oldest first.
type Waiters = BTreeMap<PublicKey, VecDeque<(Arc<Decoded>, Waiting)>>;

/// A receiver holding something in the `WaitingRoom`: its raw shard, the bytes it holds, and the
/// steps it has a description pending at.
struct Holder {
    shard: u16,
    bytes: usize,
    steps: BTreeSet<u64>,
}

/// What waits for a step's descriptions to be applied (module docs, Descriptions): the batches of
/// every raw shard stamped in an interval past the last step that shard applied, and the
/// descriptions not yet applied, one a receiver a step (the newest it signed,
/// `intake::signed_order`), all charged to the `Orphans` store's share for what waits
/// (`Room::waiting`). Only a host behind on its watermark fills it (`WAITING_MS`). Within it, each
/// receiver holds at most `NOTES_HEADROOM` times its even share (the share over the seats), its
/// oldest batches going first for its newest; and when the share is full, receivers that rank
/// below the one offering (`Seats::draw_of`) give way, their oldest first, and one that ranks below
/// every receiver holding is not held. So who is held never depends on arrival or on which thread
/// offered first, and the share is never charged past (sweep 4, R-P15: before, one pool refused each
/// batch past it in arrival order). Its lock is taken last, under a raw shard's or the
/// descriptions', never before either.
struct WaitingRoom {
    seats: Arc<Seats>,
    receivers: usize,
    /// The store's share for what waits (`Room::waiting`), and the store.
    share: Arc<Gauge>,
    store: Arc<Gauge>,
    /// The batches, by raw shard and receiver, oldest first.
    batches: BTreeMap<u16, Waiters>,
    /// The descriptions, by the step they take effect at and their receiver.
    pending: BTreeMap<u64, BTreeMap<PublicKey, Pending>>,
    holders: BTreeMap<PublicKey, Holder>,
}

impl WaitingRoom {
    fn new(seats: Arc<Seats>, receivers: usize, share: Arc<Gauge>, store: Arc<Gauge>) -> Self {
        Self {
            seats,
            receivers: receivers.max(1),
            share,
            store,
            batches: BTreeMap::new(),
            pending: BTreeMap::new(),
            holders: BTreeMap::new(),
        }
    }

    /// Lets go everything `key` holds; the batches and descriptions let go.
    fn evict(&mut self, key: &PublicKey) -> u64 {
        let Some(holder) = self.holders.remove(key) else {
            return 0;
        };
        let mut gone = 0;
        if let Some(shard) = self.batches.get_mut(&holder.shard) {
            gone += shard.remove(key).map_or(0, |batches| batches.len() as u64);
            if shard.is_empty() {
                self.batches.remove(&holder.shard);
            }
        }
        for step in holder.steps {
            if let Some(at) = self.pending.get_mut(&step) {
                gone += u64::from(at.remove(key).is_some());
                if at.is_empty() {
                    self.pending.remove(&step);
                }
            }
        }
        gone
    }

    /// The most one receiver may hold: `NOTES_HEADROOM` times its even share of the whole (a busy
    /// receiver past the planned rate keeps its batches while the room has them), and never more
    /// than the whole.
    fn most(&self) -> usize {
        let share = self.share.limit();
        (share / self.receivers)
            .saturating_mul(NOTES_HEADROOM)
            .min(share)
    }

    /// The receiver holding anything that ranks worst (`Seats::draw_of`, then the key), other than
    /// `key`, if it ranks below `key`.
    fn worse_than(&self, key: &PublicKey) -> Option<PublicKey> {
        let rank = (self.seats.draw_of(key), *key);
        self.holders
            .keys()
            .filter(|held| *held != key)
            .map(|held| (self.seats.draw_of(held), *held))
            .max()
            .filter(|worst| *worst > rank)
            .map(|(_, worst)| worst)
    }

    /// Lets go `key`'s oldest batch, or, holding none, everything it holds; what it let go.
    fn give_way(&mut self, key: &PublicKey) -> u64 {
        let holder = self.holders.get_mut(key);
        let oldest = holder.and_then(|holder| {
            self.batches
                .get_mut(&holder.shard)
                .and_then(|shard| shard.get_mut(key))
                .and_then(VecDeque::pop_front)
                .map(|(_, oldest)| {
                    holder.bytes = holder.bytes.saturating_sub(oldest.bytes);
                })
        });
        if oldest.is_some() {
            self.tidy(key);
            1
        } else {
            self.evict(key)
        }
    }

    /// Makes room for `bytes` more of `key` (whose raw shard is `shard`), less `replacing` bytes
    /// it gives up for them: within its own bound (`most`, its oldest batches going first for its
    /// newest) and within the share, receivers that rank below it giving way, oldest first, and
    /// none above it (type docs); charges what they add to what is held, `bytes` less `replacing`
    /// (the caller lets the `replacing` bytes go only once this is charged, so what it replaces is
    /// never charged twice: sweep 5, N13), and counts what it let go in `dropped`. `None` when it
    /// is not held: past its own bound, or with the share held by receivers that rank above it.
    fn admit(
        &mut self,
        key: PublicKey,
        shard: u16,
        bytes: usize,
        replacing: usize,
        dropped: &mut u64,
    ) -> Option<Waiting> {
        let most = self.most();
        if bytes > most {
            *dropped += 1;
            return None;
        }
        let holder = self.holders.entry(key).or_insert_with(|| Holder {
            shard,
            bytes: 0,
            steps: BTreeSet::new(),
        });
        // Its own oldest batches go first, for its newest.
        while holder.bytes.saturating_sub(replacing).saturating_add(bytes) > most {
            let Some((_, oldest)) = self
                .batches
                .get_mut(&holder.shard)
                .and_then(|shard| shard.get_mut(&key))
                .and_then(VecDeque::pop_front)
            else {
                break;
            };
            holder.bytes = holder.bytes.saturating_sub(oldest.bytes);
            *dropped += 1;
        }
        let mut fits = holder.bytes.saturating_sub(replacing).saturating_add(bytes) <= most;
        // The share: those ranked below it give way, never one above.
        while fits
            && self
                .share
                .held()
                .saturating_sub(replacing)
                .saturating_add(bytes)
                > self.share.limit()
        {
            match self.worse_than(&key) {
                Some(worse) => *dropped += self.give_way(&worse),
                None => fits = false,
            }
        }
        let more = bytes.saturating_sub(replacing);
        let charge = fits
            .then(|| {
                self.share.try_charge(more).and_then(|share| {
                    self.store.try_charge(more).map(|store| Waiting {
                        bytes: more,
                        _share: share,
                        _store: store,
                    })
                })
            })
            .flatten();
        if charge.is_none() {
            *dropped += 1;
            // A place made for nothing is let go; one admitted is the caller's to fill.
            self.tidy(&key);
        }
        charge
    }

    /// Forgets `key`'s place once it holds nothing.
    fn tidy(&mut self, key: &PublicKey) {
        if self
            .holders
            .get(key)
            .is_some_and(|holder| holder.bytes == 0 && holder.steps.is_empty())
        {
            self.holders.remove(key);
            for shard in self.batches.values_mut() {
                shard.remove(key);
            }
            self.batches.retain(|_, shard| !shard.is_empty());
        }
    }

    /// Holds `batch` of raw shard `shard` until its step's descriptions are applied; what it let
    /// go for room.
    fn hold_batch(&mut self, shard: u16, batch: &Arc<Decoded>) -> u64 {
        let key = batch.receiver();
        let mut dropped = 0;
        if let Some(mut charge) = self.admit(key, shard, batch.footprint(), 0, &mut dropped) {
            charge._store.cover(batch);
            if let Some(holder) = self.holders.get_mut(&key) {
                holder.bytes += charge.bytes;
            }
            self.batches
                .entry(shard)
                .or_default()
                .entry(key)
                .or_default()
                .push_back((Arc::clone(batch), charge));
        }
        dropped
    }

    /// The batches of raw shard `shard` stamped in an interval that begins at or before `step_ms`,
    /// taken with their charges.
    fn take_batches(&mut self, shard: u16, step_ms: u64) -> Vec<(Arc<Decoded>, Waiting)> {
        let Some(held) = self.batches.get_mut(&shard) else {
            return Vec::new();
        };
        let mut taken = Vec::new();
        let mut freed = Vec::new();
        for (key, batches) in held.iter_mut() {
            let (now, later): (VecDeque<_>, VecDeque<_>) = std::mem::take(batches)
                .into_iter()
                .partition(|(batch, _)| floor_step(batch.stamp_ms()) <= step_ms);
            *batches = later;
            let bytes: usize = now.iter().map(|(_, charge)| charge.bytes).sum();
            freed.push((*key, bytes));
            taken.extend(now);
        }
        for (key, bytes) in freed {
            if let Some(holder) = self.holders.get_mut(&key) {
                holder.bytes = holder.bytes.saturating_sub(bytes);
            }
            self.tidy(&key);
        }
        if self.batches.get(&shard).is_some_and(BTreeMap::is_empty) {
            self.batches.remove(&shard);
        }
        taken
    }

    /// Holds `info`, of `receiver`, stamped `stamp_ms`, until step `step_ms` applies it: in place
    /// of an older one it signed for that step, and not at all if the one held is as new; what it
    /// let go for room.
    fn hold_description(
        &mut self,
        step_ms: u64,
        receiver: PublicKey,
        stamp_ms: u64,
        info: &ReceiverInfo,
    ) -> u64 {
        let held = self
            .pending
            .get(&step_ms)
            .and_then(|step| step.get(&receiver));
        if held.is_some_and(|held| signed_order(&held.info) >= signed_order(info)) {
            return 0;
        }
        let replacing = held.map_or(0, |held| held.charge.bytes);
        let mut dropped = 0;
        let shard = raw_shard(&receiver).0;
        let bytes = info.as_bytes().len();
        let Some(mut charge) = self.admit(receiver, shard, bytes, replacing, &mut dropped) else {
            return dropped;
        };
        // A newer one in place of the older: it takes the older's charge, grown by the difference
        // (`admit`) or brought down to its own bytes, never both charged at once.
        let older = self
            .pending
            .get_mut(&step_ms)
            .and_then(|step| step.remove(&receiver));
        if let Some(older) = older {
            let Waiting { _share, _store, .. } = older.charge;
            for (into, from) in [(&mut charge._share, _share), (&mut charge._store, _store)] {
                if let Err(from) = into.absorb(from) {
                    drop(from);
                }
                into.shrink_to(bytes);
            }
            charge.bytes = bytes;
            if let Some(holder) = self.holders.get_mut(&receiver) {
                holder.bytes = holder.bytes.saturating_sub(replacing);
            }
        }
        let old = self.pending.entry(step_ms).or_default().insert(
            receiver,
            Pending {
                stamp_ms,
                info: info.clone(),
                charge,
            },
        );
        if let Some(holder) = self.holders.get_mut(&receiver) {
            holder.bytes = holder
                .bytes
                .saturating_sub(old.map_or(0, |old| old.charge.bytes))
                .saturating_add(bytes);
            holder.steps.insert(step_ms);
        }
        dropped
    }

    /// The descriptions taking effect at or before step `step_ms`, taken, step by step in the order
    /// they are applied (`intake::taking_effect`).
    fn take_descriptions(&mut self, step_ms: u64) -> Vec<(u64, ReceiverInfo)> {
        let later = self.pending.split_off(&(step_ms.saturating_add(1)));
        let due = std::mem::replace(&mut self.pending, later);
        let mut taken = Vec::new();
        for (step, at) in due {
            for (key, pending) in &at {
                if let Some(holder) = self.holders.get_mut(key) {
                    holder.bytes = holder.bytes.saturating_sub(pending.charge.bytes);
                    holder.steps.remove(&step);
                }
            }
            let keys: Vec<PublicKey> = at.keys().copied().collect();
            taken.extend(taking_effect(
                at.into_values()
                    .map(|pending| (pending.stamp_ms, pending.info)),
            ));
            for key in keys {
                self.tidy(&key);
            }
        }
        taken
    }

    /// Every description pending, taken, in the order they take effect at each step.
    fn take_all_descriptions(&mut self) -> Vec<ReceiverInfo> {
        self.take_descriptions(u64::MAX - 1)
            .into_iter()
            .map(|(_, info)| info)
            .collect()
    }

    /// Lets everything go (the engine it waited for went).
    fn clear(&mut self) {
        self.batches.clear();
        self.pending.clear();
        self.holders.clear();
    }
}

/// One step's signed records, queued whole: a provisional step's with the watermark at which they
/// are late, its own step and `PROVISIONAL_PUBLISH_MS` (they would reach the live world after the
/// second of a transmission they solve is sealed).
struct Signed {
    records: Vec<Record>,
    late_ms: Option<u64>,
}

/// Signed records not yet taken, step by step, and their bytes.
#[derive(Default)]
struct Published {
    steps: VecDeque<Signed>,
    bytes: usize,
}

/// What the relay's side and the engine's thread share.
struct Shared {
    scope: Mutex<Scope>,
    /// The raw shards, `SHARDS` of them, each locked by the ingest worker that owns its receivers
    /// (one batch at a time), and by the engine's thread to take what is complete, apply a step's
    /// descriptions or re-scope.
    shards: Box<[Mutex<Shard>]>,
    /// The descriptions' steps. Taken before any shard's lock, never after one.
    descriptions: Mutex<Descriptions>,
    /// What waits for a step's descriptions, batches and descriptions. Taken last.
    waiting_room: Mutex<WaitingRoom>,
    /// The address shards of provisional solving, `provisional::SHARDS` of them, each locked by
    /// the provisional step that weighs and steps it, and by no stage.
    listening: Box<[Mutex<Listening>]>,
    /// What each address shard was told and has not weighed yet: locked by an ingest worker to
    /// hand it a batch's notes, and by a step only to take what is due (`Shared::due`), never
    /// while it weighs.
    heard: Box<[Mutex<Vec<Heard>>]>,
    /// The notes told per step interval, and the bounds on one interval's count and bytes.
    intervals: Mutex<Intervals>,
    notes_per_step: usize,
    notes_bytes_per_step: usize,
    /// What each shard's open raw is bounded by.
    limits: Limits,
    /// The seats, shared by every raw shard, and the overload cuts that cap them (module docs).
    seats: Arc<Seats>,
    cuts: Mutex<Cuts>,
    cuts_late: AtomicU64,
    /// What a window step may run for before MLAT is overloaded: `WINDOW_BUDGET_MS`, or a test's.
    window_budget_ms: OnceLock<u64>,
    published: Mutex<Published>,
    /// Commands sent and not yet done with; steps queued or running; asks taken.
    commands: AtomicUsize,
    asks: AtomicU64,
    steps: AtomicUsize,
    /// The last step every part of which has reported; and the last every window step through
    /// which, and every provisional step through which, has reported or was shed; and the last
    /// whose seal is held.
    stepped_ms: AtomicU64,
    windows_ms: AtomicU64,
    provisionals_ms: AtomicU64,
    sealed_ms: AtomicU64,
    /// Whether an engine runs (the areas are not empty), and the last step an ask handed the
    /// engine's thread: an ask wakes it only when it passes a step not handed yet, and never with
    /// no engine to step (sweep 5, R10).
    solving: AtomicBool,
    ticked_ms: AtomicU64,
    /// The least stamp of a batch offered to the engine running: where its steps begin.
    earliest_ms: AtomicU64,
    /// Counted by the shards as batches come: offered to a shard of an engine running, and taken.
    offered: AtomicU64,
    ingested: AtomicU64,
    replayed: AtomicU64,
    ingest_errors: AtomicU64,
    orphans_dropped: AtomicU64,
    orphans_expired: AtomicU64,
    waiting_dropped: AtomicU64,
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
    /// The relay's `Orphans` store: the batches waiting for a description, and what waits for a
    /// step's descriptions.
    orphans: Arc<Gauge>,
    /// The batches waiting for a description that has not come, of every raw shard: one store,
    /// so who is held for room is decided by rank across all of them (`intake::Orphans`), within
    /// the store's share for them (`Room::orphans`), which is therefore never charged past.
    orphan_batches: Mutex<Orphans>,
    /// What the receptions waiting for provisional solving are charged to the `Engine` store:
    /// `provisional::WAITING_BYTES` each, taken before a step keeps them. Locked only to grow or
    /// shrink it, never across a step's work (sweep 4, N16).
    waiting: Mutex<Charge>,
    /// Receptions waiting for provisional solving, as the last provisional step left them: none,
    /// and nothing heard, is a step with nothing to weigh, which takes no thread (sweep 4, N18).
    receptions_waiting: AtomicUsize,
    /// Receptions waiting, at most (`Capacity::waiting`).
    most_waiting: usize,
    /// The threads the plan gives MLAT, every kind of its work together (`tally_mlat_solver::gate`).
    gate: Arc<Gate>,
    /// Steps, seals and forgets handed to MLAT's runners, and the times the engine's thread woke.
    handed: AtomicU64,
    wakeups: AtomicU64,
    /// MLAT threads whose priority could not be lowered.
    priority_unset: AtomicU64,
}

impl Shared {
    fn shard(&self, receiver: &PublicKey) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[usize::from(raw_shard(receiver).0)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn descriptions(&self) -> std::sync::MutexGuard<'_, Descriptions> {
        self.descriptions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn listening(&self, shard: usize) -> std::sync::MutexGuard<'_, Listening> {
        self.listening[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn heard(&self, shard: usize) -> std::sync::MutexGuard<'_, Vec<Heard>> {
        self.heard[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What address shard `shard` heard in an interval before `through` for the engine of
    /// `generation` or an older one, taken: the inbox is held only to swap it out and to put back
    /// what is not due (later intervals, and a newer engine's, heard by a raw shard already
    /// re-scoped for the engine about to start), so an ingest worker telling it never waits on a
    /// step's weighing.
    fn due(&self, shard: usize, generation: u64, through: u64) -> Vec<Heard> {
        let heard = std::mem::take(&mut *self.heard(shard));
        let (due, rest): (Vec<Heard>, Vec<Heard>) = heard
            .into_iter()
            .partition(|heard| heard.interval < through && heard.generation <= generation);
        if !rest.is_empty() {
            self.heard(shard).extend(rest);
        }
        due
    }

    /// Taken under a raw shard's lock, never before one.
    fn orphan_batches(&self) -> std::sync::MutexGuard<'_, Orphans> {
        self.orphan_batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Taken under a raw shard's lock or the descriptions', never before either.
    fn waiting_room(&self) -> std::sync::MutexGuard<'_, WaitingRoom> {
        self.waiting_room
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

    /// One batch into `shard`, its receiver's, its raw judged by its own stamp, its notes weighed
    /// by the step of `at_ms` when given (one that waited for its description, taken as the last
    /// thing of the interval before the step that applied it): what it says to provisional
    /// solving, to hand to the address shards once `shard` is let go (`tell`). A batch of a receiver not described waits for its description
    /// (`orphan_batches`, `intake::Orphans::hold`), charged to the `Orphans` store once room is made
    /// for it by rank; one not held is dropped, counted.
    fn take(&self, shard: &mut Shard, batch: &Arc<Decoded>, at_ms: Option<u64>) -> Option<Told> {
        let (ingested, notes) = shard.ingest(batch);
        match ingested {
            Ingested::Batch { .. } => {
                self.ingested.fetch_add(1, Ordering::SeqCst);
                if !notes.is_empty() {
                    return Some(Told {
                        batch: Arc::clone(batch),
                        notes,
                        generation: shard.generation,
                        at_ms: at_ms.unwrap_or(0).max(batch.stamp_ms()),
                    });
                }
            }
            Ingested::Replayed => {
                self.replayed.fetch_add(1, Ordering::Relaxed);
            }
            Ingested::Ignored if shard.intake.described(&batch.receiver()).is_none() => {
                let orphans = &self.orphans;
                let mut orphan_batches = self.orphan_batches();
                // Its share of the store as the store is now, resized or not.
                orphan_batches.set_room(Room::of(orphans.limit()).orphans);
                let dropped = orphan_batches
                    .hold(batch, batch.stamp_ms(), |bytes| {
                        orphans.try_charge(bytes).map(|mut charge| {
                            charge.cover(batch);
                            Box::new(charge) as Box<dyn Any + Send>
                        })
                    })
                    .dropped;
                self.orphans_dropped.fetch_add(dropped, Ordering::Relaxed);
            }
            Ingested::Described | Ingested::Ignored | Ingested::Refused => {}
        }
        None
    }

    /// Describes a receiver in its shard: the batches that waited for it are taken now, as stamped
    /// `at_ms` when given (the step that applies it, less a millisecond: as the last thing of the
    /// interval before it), and what a receiver that stops taking part held through `kept` is left
    /// for the steps already due. What they tell provisional solving, the receivers that stopped
    /// taking part here with their generation, and those of other shards whose seat changed.
    #[allow(clippy::type_complexity)]
    fn describe(
        &self,
        info: &ReceiverInfo,
        at_ms: Option<u64>,
        kept: Option<i64>,
    ) -> (Vec<Told>, Vec<(u64, PublicKey)>, Vec<PublicKey>) {
        let Ok(key) = info.receiver() else {
            return (Vec::new(), Vec::new(), Vec::new());
        };
        let mut shard = self.shard(&key);
        let described = match shard.intake.describe_after(info, kept) {
            Ok(described) => described,
            Err(_) => {
                self.ingest_errors.fetch_add(1, Ordering::Relaxed);
                return (Vec::new(), Vec::new(), Vec::new());
            }
        };
        let mut told = Vec::new();
        let orphans = self.orphan_batches().take(&key);
        for (batch, _) in orphans {
            told.extend(self.take(&mut shard, &batch, at_ms));
        }
        let Description { left, moved, .. } = described;
        // Receivers that stopped taking part here let go of their open raw.
        shard.settle_open();
        let generation = shard.generation;
        (
            told,
            left.into_iter().map(|key| (generation, key)).collect(),
            moved,
        )
    }

    /// Hands what a batch said to provisional solving to the address shards it speaks of, read in
    /// its raw shard under its engine generation, for the step of `at_ms` (its stamp, or the step
    /// that took it after it waited for its description). A step interval whose notes pass
    /// `notes_per_step`, or whose bytes pass `notes_bytes_per_step`, is refused whole: what it
    /// held is let go now, and nothing more of it is held; the step that weighs it counts its every
    /// batch. Which intervals are refused is a function of the trace. Within those bounds the
    /// `Notes` store holds every interval a host that sheds nothing holds (`INTERVALS_HELD`), so
    /// one whose bytes it cannot hold is let go whole the same way and counted shed: only a host
    /// behind on its steps fills it (module docs, Behind).
    fn tell(&self, told: Told) {
        let Told {
            batch,
            mut notes,
            generation,
            at_ms,
        } = told;
        let order = Order::of(&batch, batch.stamp_ms());
        let interval = {
            let mut intervals = self.intervals();
            // Never before a step already weighed: no batch is told after the step of its stamp
            // starts (the watermark contract, and descriptions applied at their step), so this
            // only keeps a broken contract from reaching back.
            let interval = (at_ms / STEP_MS).max(intervals.weighed_ms / STEP_MS);
            let entry = intervals.open.entry(interval).or_insert_with(|| Interval {
                charge: self.notes.empty(),
                ..Interval::default()
            });
            entry.batches += 1;
            if entry.refused {
                return;
            }
            let bytes = batch
                .footprint()
                .saturating_add(std::mem::size_of_val(notes.as_slice()));
            entry.notes = entry.notes.saturating_add(notes.len());
            entry.bytes = entry.bytes.saturating_add(bytes);
            let over = entry.notes > self.notes_per_step || entry.bytes > self.notes_bytes_per_step;
            let grown = !over && entry.charge.try_grow(bytes);
            if grown {
                entry.charge.cover(&batch);
            } else {
                entry.shed = !over;
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
            self.heard(shard).push(Heard {
                interval,
                order,
                batch: Arc::clone(&batch),
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
            self.heard(shard)
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

    /// The provisional step of `step_ms` is shed (module docs, Behind): every interval before it
    /// not yet weighed is let go whole, its notes forgotten in every address shard. As
    /// `weigh_intervals` counts them, with every batch not refused for its step's bounds counted
    /// shed.
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
    /// description) in its own raw shard, its raw through `kept` left for the steps already due:
    /// those that stopped taking part, with their generation.
    fn settle(&self, moved: &[PublicKey], kept: Option<i64>) -> Vec<(u64, PublicKey)> {
        let mut left = Vec::new();
        for key in moved {
            let mut shard = self.shard(key);
            let stopped = shard.intake.settle_after(key, kept);
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
    /// taken whatever their size, so no step is refused forever. `late_ms`: the watermark from
    /// which they are late (a provisional step's, `Signed`).
    fn publish(&self, records: Vec<Record>, limit: usize, late_ms: Option<u64>) {
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
            published.steps.push_back(Signed { records, late_ms });
        }
    }

    /// Every step's records not yet taken, in order, as the relay takes them at watermark
    /// `watermark_ms`: a provisional step's that are late by then are refused whole and counted
    /// (`MlatReport::provisional_steps_late`), by the stamps alone (sweep 5, R2: before, by the
    /// wall clock from its turn to its run's end, which left out the watermark's lag and the wait
    /// to be taken, and made a test's verdict its machine's speed). `None`: taken as they are, by
    /// a caller that waited for the host (`HostedMlat::take_signed`).
    fn take_signed(&self, watermark_ms: Option<u64>) -> Vec<Record> {
        let steps = self
            .published
            .lock()
            .map(|mut published| {
                published.bytes = 0;
                std::mem::take(&mut published.steps)
            })
            .unwrap_or_default();
        let mut taken = Vec::new();
        let (mut late, mut records_late) = (0, 0);
        for step in steps {
            let is_late = step
                .late_ms
                .zip(watermark_ms)
                .is_some_and(|(late_ms, watermark_ms)| watermark_ms >= late_ms);
            if is_late {
                late += 1;
                records_late += step.records.len() as u64;
            } else {
                taken.extend(step.records);
            }
        }
        if late > 0 {
            self.count(|counts| {
                counts.provisional_steps_late += late;
                counts.provisional_records_late += records_late;
            });
        }
        taken
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
    /// working set to `Engine`; and the batches waiting for a description to `Orphans`.
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
        // The `Orphans` store split, each share whole: who is held is decided by rank within
        // them, never by the store refusing whichever came last. Both follow the store's limit
        // through a resize: the batches' room is read from it at each hold (`Shared::take`), the
        // waiting share is a share of its gauge (`Gauge::share`).
        let orphan_receivers = settings.capacity.receivers.max(1);
        let orphan_batches = Orphans::new(
            Arc::clone(&seats),
            orphan_receivers,
            Room::of(gauges.orphans.limit()).orphans / orphan_receivers,
        );
        let waiting_share = gauges.orphans.share(|limit| Room::of(limit).waiting);
        let shared = Arc::new(Shared {
            scope: Mutex::new(Scope::default()),
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        intake: Intake::new(Arc::clone(&seats), limits, None).closing(closing),
                        open: gauges.open.empty(),
                        generation: 0,
                        active: false,
                        applied_ms: None,
                    })
                })
                .collect(),
            descriptions: Mutex::new(Descriptions::default()),
            waiting_room: Mutex::new(WaitingRoom::new(
                Arc::clone(&seats),
                settings.capacity.receivers,
                waiting_share,
                Arc::clone(&gauges.orphans),
            )),
            listening: (0..provisional_::SHARDS)
                .map(|_| Mutex::new(Listening::default()))
                .collect(),
            heard: (0..provisional_::SHARDS)
                .map(|_| Mutex::new(Vec::new()))
                .collect(),
            intervals: Mutex::new(Intervals::default()),
            notes_per_step: settings
                .capacity
                .receivers
                .max(1)
                .saturating_mul(NOTES_PER_RECEIVER_STEP),
            notes_bytes_per_step: gauges.notes.limit() / INTERVALS_HELD,
            limits,
            seats: Arc::clone(&seats),
            cuts: Mutex::new(Cuts::default()),
            cuts_late: AtomicU64::new(0),
            window_budget_ms: OnceLock::new(),
            published: Mutex::new(Published::default()),
            commands: AtomicUsize::new(0),
            asks: AtomicU64::new(0),
            steps: AtomicUsize::new(0),
            stepped_ms: AtomicU64::new(0),
            windows_ms: AtomicU64::new(0),
            provisionals_ms: AtomicU64::new(0),
            sealed_ms: AtomicU64::new(0),
            solving: AtomicBool::new(false),
            ticked_ms: AtomicU64::new(0),
            earliest_ms: AtomicU64::new(u64::MAX),
            offered: AtomicU64::new(0),
            ingested: AtomicU64::new(0),
            replayed: AtomicU64::new(0),
            ingest_errors: AtomicU64::new(0),
            orphans_dropped: AtomicU64::new(0),
            orphans_expired: AtomicU64::new(0),
            waiting_dropped: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            counts: Mutex::new(MlatReport::default()),
            sealed: SealedBins::new(),
            delay: OnceLock::new(),
            notes: Arc::clone(&gauges.notes),
            orphans: Arc::clone(&gauges.orphans),
            orphan_batches: Mutex::new(orphan_batches),
            waiting: Mutex::new(gauges.engine.empty()),
            receptions_waiting: AtomicUsize::new(0),
            most_waiting: settings.capacity.waiting(),
            gate: Gate::new(settings.threads.max(1)),
            handed: AtomicU64::new(0),
            wakeups: AtomicU64::new(0),
            priority_unset: AtomicU64::new(0),
        });
        let runners = Runners::start(&shared)?;
        let host = Host {
            identity,
            boot_id,
            engines: 0,
            generation: 0,
            settings,
            engine: None,
            through_ms: None,
            sealed_through: None,
            windows: VecDeque::new(),
            window: None,
            sealing: None,
            seals: VecDeque::new(),
            proposed: VecDeque::new(),
            provisional: None,
            kept_from: i64::MIN,
            sealed_charge: gauges.held.empty(),
            held: gauges.held,
            engine_gauge: gauges.engine,
            messages: messages.clone(),
            shared: Arc::clone(&shared),
            runners,
        };
        let spawned = std::thread::Builder::new()
            .name("tally-mlat".to_owned())
            .spawn(move || {
                // A panic on the engine's thread ends the process (sweep 5, N7).
                let _ends = EndOnUnwind;
                host.run(&received);
            });
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

    /// What a window step may run for before MLAT is overloaded (module docs, Overload), in place
    /// of `WINDOW_BUDGET_MS`: for a test that shows the cut without a window step of seconds.
    /// Set once; later calls are ignored.
    pub fn budgeting(&self, window_budget_ms: u64) {
        let _ = self.shared.window_budget_ms.set(window_budget_ms);
    }

    /// Commands handed to the engine's thread and not yet done with, and steps queued or running:
    /// zero when everything offered and asked so far is published.
    pub fn in_flight(&self) -> usize {
        self.shared.commands.load(Ordering::SeqCst) + self.shared.steps.load(Ordering::SeqCst)
    }

    /// The last step every part of which (its provisional solving, its seal and its window step)
    /// has reported or was shed (zero before the first).
    pub fn stepped_ms(&self) -> u64 {
        self.shared.stepped_ms.load(Ordering::SeqCst)
    }

    /// The last step through which every window that fell due has been solved or shed.
    pub fn windows_stepped_ms(&self) -> u64 {
        self.shared.windows_ms.load(Ordering::SeqCst)
    }

    /// The last step every provisional step through which has reported or was shed.
    pub fn provisionals_stepped_ms(&self) -> u64 {
        self.shared.provisionals_ms.load(Ordering::SeqCst)
    }

    /// The last step whose seal is held: its bins sealed, and what it forgets forgotten.
    pub fn sealed_stepped_ms(&self) -> u64 {
        self.shared.sealed_ms.load(Ordering::SeqCst)
    }

    /// The most threads that ever did MLAT work at once (`tally_mlat_solver::gate`): never more
    /// than the plan gave it.
    pub fn busiest(&self) -> usize {
        self.shared.gate.peak()
    }

    /// Batches offered while an engine runs, of a receiver of its areas or their band: taken, or
    /// waiting for a description.
    pub fn offered(&self) -> u64 {
        self.shared.offered.load(Ordering::SeqCst)
    }

    /// How many times the host was asked (`MlatHost::take_published`): one more means the asker
    /// is done with what the ask before took.
    pub fn asks(&self) -> u64 {
        self.shared.asks.load(Ordering::SeqCst)
    }

    /// The newest watermark the host was asked with (`MlatHost::take_published`).
    pub fn asked_ms(&self) -> u64 {
        self.shared.descriptions().asked_ms
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

    /// Records signed and not yet taken.
    pub fn untaken(&self) -> usize {
        self.shared
            .published
            .lock()
            .map(|published| published.steps.iter().map(|step| step.records.len()).sum())
            .unwrap_or_default()
    }

    /// What was signed and not yet taken, asking for nothing more and judging nothing late: for a
    /// caller that waited for `in_flight` to reach zero, with the watermark where it was.
    pub fn take_signed(&self) -> Vec<Record> {
        self.shared.take_signed(None)
    }

    /// Hands `command` to the engine's thread.
    fn send(&self, command: Command) {
        self.shared.commands.fetch_add(1, Ordering::SeqCst);
        if self.messages.send(Message::Command(command)).is_err() {
            self.shared.commands.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A description applied as it comes, with no step to wait for (the engine has none yet, or the
    /// areas changed): its receiver's waiting batches taken as stamped, a receiver of another shard
    /// whose seat it changed settled in its own shard after, and a receiver that stopped taking
    /// part forgotten in the sealed bins.
    fn describe_now(&self, info: &ReceiverInfo) {
        let (told, mut left, moved) = self.shared.describe(info, None, None);
        for told in told {
            self.shared.tell(told);
        }
        // Each shard let go before the next is taken: the engine's thread may be waiting for one.
        left.extend(self.shared.settle(&moved, None));
        let mut by_generation: BTreeMap<u64, Vec<PublicKey>> = BTreeMap::new();
        for (generation, key) in left {
            by_generation.entry(generation).or_default().push(key);
        }
        for (generation, left) in by_generation {
            self.send(Command::Left(generation, left));
        }
    }
}

impl Drop for HostedMlat {
    fn drop(&mut self) {
        // The engine's thread wakes for messages alone (sweep 4, N18): this is its last.
        let _ = self.messages.send(Message::Stop);
    }
}

impl MlatHost for HostedMlat {
    fn set_areas(&self, areas: Regions, descriptions: Vec<ReceiverInfo>) {
        for info in &descriptions {
            self.describe_now(info);
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
        let mut pending = Vec::new();
        if restart {
            scope.generation += 1;
            // The new engine's steps begin where its own raw does, and until its first step a
            // description is applied as it comes.
            self.shared.earliest_ms.store(u64::MAX, Ordering::SeqCst);
            let mut descriptions = self.shared.descriptions();
            descriptions.applied_ms = None;
            let mut room = self.shared.waiting_room();
            pending = room.take_all_descriptions();
            // The raw of the engine that goes goes with it.
            room.clear();
            drop(room);
            drop(descriptions);
            // The batches that waited for a description go with the engine they waited for.
            self.shared.orphan_batches().clear();
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
                shard.applied_ms = None;
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
        left.extend(
            self.shared
                .settle(&moved, None)
                .into_iter()
                .map(|(_, key)| key),
        );
        scope.areas.clone_from(&areas);
        let generation = scope.generation;
        drop(scope);
        if !restart && !left.is_empty() {
            // Every receiver the change let go, together (sweep 5, R6).
            self.send(Command::Left(generation, left));
        }
        let solving = !areas.is_empty();
        self.send(Command::Areas(generation, areas, band.unwrap_or_default()));
        // Asks step it from the next one on: an engine started now has stepped nothing yet.
        self.shared.ticked_ms.store(0, Ordering::SeqCst);
        self.shared.solving.store(solving, Ordering::SeqCst);
        for info in pending {
            self.describe_now(&info);
        }
    }

    fn offer_description(&self, info: &ReceiverInfo, stamp_ms: u64) {
        let descriptions = self.shared.descriptions();
        if descriptions.applied_ms.is_none() {
            // No step yet: applied as it comes, under the lock the first step takes.
            self.describe_now(info);
            return;
        }
        // Never before a watermark the host was asked with: a step it may have applied already.
        let stamp_ms = stamp_ms.max(descriptions.asked_ms);
        let Ok(receiver) = info.receiver() else {
            self.shared.ingest_errors.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // One a receiver a step, the newest it signed (`intake::taking_effect`): an older one, or
        // the same again, changes nothing, and a newer one takes the older's place and charge,
        // within the receiver's share by rank (`WaitingRoom`).
        let dropped = self.shared.waiting_room().hold_description(
            step_of(stamp_ms),
            receiver,
            stamp_ms,
            info,
        );
        drop(descriptions);
        self.shared
            .waiting_dropped
            .fetch_add(dropped, Ordering::Relaxed);
    }

    fn offer_batch(&self, batch: &Arc<Decoded>, _now_ms: u64) {
        self.shared.delay(Stage::Offer);
        let told = {
            let mut shard = self.shared.shard(&batch.receiver());
            if !shard.active {
                return;
            }
            self.shared.offered.fetch_add(1, Ordering::SeqCst);
            self.shared
                .earliest_ms
                .fetch_min(batch.stamp_ms(), Ordering::SeqCst);
            if shard
                .applied_ms
                .is_some_and(|applied| floor_step(batch.stamp_ms()) > applied)
            {
                // Its receiver stands, at its stamp, as the descriptions of a step not yet applied
                // say: it waits for them, within its share of what waits by rank (`WaitingRoom`).
                let dropped = self
                    .shared
                    .waiting_room()
                    .hold_batch(raw_shard(&batch.receiver()).0, batch);
                self.shared
                    .waiting_dropped
                    .fetch_add(dropped, Ordering::Relaxed);
                return;
            }
            self.shared.take(&mut shard, batch, None)
        };
        if let Some(told) = told {
            self.shared.tell(told);
        }
    }

    fn take_published(&self, watermark_ms: u64) -> Vec<Record> {
        self.shared.asks.fetch_add(1, Ordering::SeqCst);
        // Recorded before the ask is sent, so no description offered after a step is applied is
        // stamped before it (`offer_description`).
        {
            let mut descriptions = self.shared.descriptions();
            descriptions.asked_ms = descriptions.asked_ms.max(watermark_ms);
        }
        // The engine's thread is woken only for a step the watermark passed and no ask handed it
        // yet, and never with no engine to step (sweep 5, R10: before, every ask woke it, ten
        // times a second, areas or none). An ask dropped while the queue is full is the next
        // one's: its watermark is no older.
        let step = floor_step(watermark_ms);
        if self.shared.solving.load(Ordering::SeqCst)
            && step > self.shared.ticked_ms.load(Ordering::SeqCst)
            && self.shared.commands.load(Ordering::SeqCst) < COMMANDS_WAITING
        {
            self.shared.ticked_ms.fetch_max(step, Ordering::SeqCst);
            self.send(Command::Tick(watermark_ms));
        }
        self.shared.take_signed(Some(watermark_ms))
    }

    fn cores(&self) -> u16 {
        self.cores
    }

    fn sealed_bins(&self) -> Option<SealedBins> {
        Some(self.shared.sealed.clone())
    }

    fn gate(&self) -> Option<Arc<Gate>> {
        Some(Arc::clone(&self.shared.gate))
    }

    fn offer_cut(&self, cut: Cut) {
        let mut cuts = self
            .shared
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !cuts.offer(cut) {
            self.shared.cuts_late.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn take_cuts(&self) -> Vec<Cut> {
        std::mem::take(
            &mut self
                .shared
                .cuts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .decided,
        )
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
        report.waiting_dropped = shared.waiting_dropped.load(Ordering::Relaxed);
        report.priority_unset = shared.priority_unset.load(Ordering::Relaxed);
        report.cuts_late = shared.cuts_late.load(Ordering::Relaxed);
        report.seat_cap = shared.seats.cap() as u64;
        report.seat_limit = shared.seats.limit() as u64;
        report.seats_taken = shared.seats.taken() as u64;
        report
    }
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
    /// The last step the watermark passed: its descriptions applied, its seal queued.
    through_ms: Option<u64>,
    /// The last step whose seal is held, and the last bin it settled: where the next looks for a
    /// window falling due.
    sealed_through: Option<(u64, i64)>,
    /// Window steps: the steps at which a window fell due, not started, oldest first.
    windows: VecDeque<WindowStep>,
    /// The window step running.
    window: Option<Running>,
    /// The seal or forget off this thread, if one is: the engine generation it is for, and the
    /// step it seals (none for a forget). The bins it seals are not held yet, so nothing more of
    /// `seals` is done until it reports (each seal within what the ones before it left, each
    /// forget after the bins sealed before it are held).
    sealing: Option<(u64, Option<u64>)>,
    seals: VecDeque<Sealing>,
    /// Provisional steps the watermark has passed and that have not started, and the one running.
    proposed: VecDeque<u64>,
    provisional: Option<u64>,
    /// The first bin the stamps keep, as of the last step whose seal is held
    /// (`kept_by_stamps`): the sealed bins from it on are the stamps' alone, and those before it
    /// are kept only by the floor of a window step still to be solved (`Engine::forget_by`).
    kept_from: i64,
    /// What the sealed bins are charged to the `Held` store, taken before each is held.
    sealed_charge: Charge,
    held: Arc<Gauge>,
    /// The `Engine` store, where a window step's working set is reserved while it runs.
    engine_gauge: Arc<Gauge>,
    messages: Sender<Message>,
    shared: Arc<Shared>,
    runners: Runners,
}

impl Host {
    fn run(mut self, received: &Receiver<Message>) {
        self.settle_sealed();
        // It wakes for a message and for nothing else: idle, it costs nothing (sweep 4, N18;
        // before, it woke ten times a second to look whether it should stop).
        while let Ok(message) = received.recv() {
            self.shared.wakeups.fetch_add(1, Ordering::Relaxed);
            match message {
                Message::Stop => return,
                Message::Command(command) => {
                    match command {
                        Command::Left(generation, left) => {
                            if generation == self.generation && self.engine.is_some() {
                                self.forget_left(left);
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
                // Nothing hands the allocator's free pages back here (RFC-0181, "Sizing", "MLAT
                // and the allocator"): before, `malloc_trim(0)` after each window step walked every
                // arena with its lock held, and every stage thread allocating meanwhile waited on
                // it, MLAT below the stages stopping them for seconds.
                Message::Finished(finished) => {
                    self.finished(finished);
                    self.advance();
                }
            }
        }
    }

    /// The watermark passed `watermark_ms`: every multiple of `STEP_MS` it passed and that is not
    /// stepped yet is, in order: its descriptions applied (`apply`), the receivers they let go
    /// forgotten in the sealed bins, and its complete bins taken and sealed in their turn
    /// (`close`), every step whether or not a window falls due at it (sweep 5, H-c: before, a
    /// step's seal waited for the window step before it, so every step a window step ran past was
    /// queued as one, and shed); and its provisional step proposed. The first step of an engine is
    /// the first multiple after the least stamp of its raw, which every batch stamped before the
    /// watermark has said by now.
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
            let (sites, left) = self.apply(through);
            self.forget_left(left);
            self.close(through, sites);
            self.proposed.push_back(through);
        }
        self.through_ms = Some(through);
    }

    /// The descriptions taking effect at step `step_ms` (module docs, Descriptions), applied as the
    /// watermark passes it, whatever the window and provisional steps are doing: first the batches
    /// that waited `ORPHAN_MS` for a description are let go, then every description stamped in the
    /// interval before it (and any not yet applied before that) in the order of their stamps, keys
    /// and bytes, the batches of each receiver that waited taken as of the end of that interval;
    /// then each shard takes, in order, the batches stamped in the interval that begins here, which
    /// waited for this. What a receiver that stops taking part held is left in the bins earlier
    /// steps take (`Intake::describe_after`). The sites taking part and the receivers that stopped,
    /// for the step's seal and its window step, if one falls due at it.
    fn apply(&mut self, step_ms: u64) -> (Vec<Site>, Vec<PublicKey>) {
        let generation = self.generation;
        let kept = self
            .engine
            .as_ref()
            .map(|engine| engine.settled(step_ms.saturating_sub(STEP_MS)));
        let shared = Arc::clone(&self.shared);
        let mut descriptions = shared.descriptions();
        descriptions.applied_ms = Some(step_ms);
        let due = shared.waiting_room().take_descriptions(step_ms);
        let expired = shared.orphan_batches().expire(step_ms).expired;
        shared.orphans_expired.fetch_add(expired, Ordering::Relaxed);
        let mut told = Vec::new();
        let mut left = Vec::new();
        // The cut in force at this step (module docs, Overload): the same on every relay offered
        // the same cuts. The receivers it seats or unseats settle with the descriptions'.
        let mut moved = {
            let mut cuts = shared
                .cuts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let seats = cuts.seats_at(step_ms, shared.seats.limit());
            cuts.applied(step_ms);
            drop(cuts);
            if seats == shared.seats.cap() {
                Vec::new()
            } else {
                shared.seats.set_cap(seats)
            }
        };
        let at = Some(step_ms.saturating_sub(1));
        for (_, info) in &due {
            let (heard, gone, changed) = shared.describe(info, at, kept);
            told.extend(heard);
            left.extend(gone);
            moved.extend(changed);
        }
        moved.sort_unstable();
        moved.dedup();
        left.extend(shared.settle(&moved, kept));
        let mut sites = Vec::new();
        for (index, shard) in shared.shards.iter().enumerate() {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            shard.applied_ms = Some(step_ms);
            let mut now = shared
                .waiting_room()
                .take_batches(u16::try_from(index).unwrap_or(u16::MAX), step_ms);
            now.sort_by_key(|(batch, _)| Order::of(batch, batch.stamp_ms()));
            for (batch, charge) in now {
                told.extend(shared.take(&mut shard, &batch, None));
                drop(charge);
            }
            if shard.generation == generation {
                sites.extend(shard.intake.sites());
            }
        }
        drop(descriptions);
        for told in told {
            shared.tell(told);
        }
        sites.sort_unstable_by_key(|site| site.receiver);
        let left = left
            .into_iter()
            .filter(|(of, _)| *of == generation)
            .map(|(_, key)| key)
            .collect();
        (sites, left)
    }

    /// Starts the window step queued, unless one runs, and sheds the oldest queued past
    /// `WINDOW_STEPS_BEHIND`; starts the next provisional step unless one runs, and sheds the oldest past
    /// `PROVISIONAL_BEHIND` (module docs, Behind); a provisional step whose models (the windows
    /// that fell due `MODELS_RIPEN_MS` before it) have not all been solved at its turn is shed,
    /// counted, never started with others; publishes the count of steps in hand and the last step
    /// every part of which is done.
    fn advance(&mut self) {
        self.start_window();
        while self.windows.len() > WINDOW_STEPS_BEHIND {
            self.shed_window();
        }
        while self.provisional.is_none() {
            let Some(step_ms) = self.proposed.pop_front() else {
                break;
            };
            // It carries exactly the models of the windows that fell due `MODELS_RIPEN_MS` before
            // it, as the engine solving in line does: one of them not solved at its turn, it is
            // shed whole and counted, never started with other models, so a step that runs makes
            // the reference's bytes however long a window step ran or waited (module docs,
            // Threads; sweep 4, N6; sweep 5, N8: a window step that waited or was put off counts
            // as solved only once it is).
            if self.windows_through() < step_ms.saturating_sub(MODELS_RIPEN_MS) {
                self.shared
                    .count(|counts| counts.provisional_models_late += 1);
                self.shed_provisional(step_ms);
                continue;
            }
            self.start_provisional(step_ms);
        }
        while self.proposed.len() > PROVISIONAL_BEHIND {
            let Some(step_ms) = self.proposed.pop_front() else {
                break;
            };
            self.shed_provisional(step_ms);
        }
        let steps = self.seals.len()
            + usize::from(self.sealing.is_some())
            + self.windows.len()
            + usize::from(self.window.is_some())
            + self.proposed.len()
            + usize::from(self.provisional.is_some());
        self.shared.steps.store(steps, Ordering::SeqCst);
        let (windows, provisionals) = (self.windows_through(), self.provisionals_through());
        self.shared.windows_ms.fetch_max(windows, Ordering::SeqCst);
        self.shared
            .provisionals_ms
            .fetch_max(provisionals, Ordering::SeqCst);
        self.shared
            .stepped_ms
            .fetch_max(windows.min(provisionals), Ordering::SeqCst);
    }

    /// The last step through which every window that fell due has been solved or shed: the step
    /// before the earliest whose seal is not held yet (whether a window falls due at it is not
    /// known before), and before the earliest whose windows a window step queued or running has
    /// still to solve.
    fn windows_through(&self) -> u64 {
        let unsealed = self.sealing.and_then(|(_, step)| step).or_else(|| {
            self.seals.iter().find_map(|sealing| match sealing {
                Sealing::Seal { closed, .. } => Some(closed.step_ms),
                Sealing::Forget(_) => None,
            })
        });
        let outstanding = unsealed
            .into_iter()
            .chain(self.window.map(|running| running.due_ms))
            .chain(self.windows.iter().map(|step| step.due_ms))
            .min();
        outstanding.map_or(self.through_ms.unwrap_or(0), |step| {
            step.saturating_sub(STEP_MS)
        })
    }

    /// The last provisional step every one through which has reported or was shed: they run in
    /// order, so it is the one before the first still running or proposed.
    fn provisionals_through(&self) -> u64 {
        let outstanding = self.provisional.or_else(|| self.proposed.front().copied());
        outstanding.map_or(self.through_ms.unwrap_or(0), |step| {
            step.saturating_sub(STEP_MS)
        })
    }

    /// Receivers that stopped taking part (as of a step's descriptions, or when the areas
    /// changed), forgotten in every bin sealed before: at once, or, while a seal is off this
    /// thread or waiting, once the bins sealed before it are held (`seals`), so a bin being sealed
    /// when a receiver leaves never keeps it.
    fn forget_left(&mut self, left: Vec<PublicKey>) {
        if left.is_empty() {
            return;
        }
        self.seals.push_back(Sealing::Forget(left));
        self.next_seal();
    }

    /// Does what `seals` holds, in order, while no seal or forget is off this thread: the next
    /// seal started off it, within what the bins before it left; receivers that left forgotten off
    /// it too, every forget queued together in one pass (each bin re-sealed once for all of them).
    fn next_seal(&mut self) {
        while self.sealing.is_none() {
            let Some(next) = self.seals.pop_front() else {
                return;
            };
            match next {
                Sealing::Forget(mut left) => {
                    while let Some(Sealing::Forget(more)) = self.seals.front_mut() {
                        left.append(more);
                        self.seals.pop_front();
                    }
                    left.sort_unstable();
                    left.dedup();
                    self.forget(left);
                }
                Sealing::Seal {
                    fragments,
                    open,
                    closed,
                } if fragments.is_empty() => {
                    drop(open);
                    self.sealed_step(closed);
                }
                Sealing::Seal {
                    fragments,
                    open,
                    closed,
                } => self.seal(fragments, open, closed),
            }
        }
    }

    /// Step `closed`'s bins are sealed and held: a window step is queued if a window falls due at
    /// it (and started, if none runs), and what no window still to be solved needs is forgotten
    /// by its stamp, every step's seal alike, before the next seal reads the room it left (sweep 5,
    /// N1: before, only a window step that ran forgot, so the room a seal had, and which receivers
    /// it refused, was how long the window steps ran). Nothing a window step queued or running has
    /// still to solve is forgotten (`Engine::forget_by`'s floor): a host whose window steps start
    /// and finish within the grace the forgetting leaves them forgets exactly what the engine in
    /// line does.
    fn sealed_step(&mut self, closed: Closed) {
        let Closed {
            step_ms,
            settled,
            sites,
        } = closed;
        let before = self.sealed_through.map_or(i64::MIN, |(_, settled)| settled);
        self.sealed_through = Some((step_ms, settled));
        self.shared.sealed_ms.fetch_max(step_ms, Ordering::SeqCst);
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        if let Some(first_bin) = engine.falls_due(before, settled) {
            self.windows.push_back(WindowStep {
                step_ms,
                settled,
                sites,
                due_ms: step_ms,
                first_bin,
                deferred: false,
            });
            self.start_window();
        }
        let floor = self
            .window
            .map(|running| running.first_bin)
            .into_iter()
            .chain(self.windows.iter().map(|step| step.first_bin))
            .min()
            .unwrap_or(i64::MAX);
        if let Some(engine) = self.engine.as_mut() {
            engine.forget_by(step_ms, settled, floor);
        }
        self.kept_from = kept_by_stamps(step_ms, settled);
        self.settle_sealed();
    }

    /// Forgets receivers that left in every sealed bin off this thread, as background work (each
    /// bin that held any of them re-sealed once for all of them, `SealedBins::without_each`),
    /// below the stages' priority and within MLAT's threads like a seal (sweep 4, N3: before, the
    /// engine's thread re-sealed every bin once a receiver, at the stages' priority): no seal and
    /// no other forget is done until it reports. Bin by bin (sweep 5, N2): each re-sealed bin is
    /// charged to the `Held` store before it is built, and held in place of the old one on this
    /// thread before the next is asked for, so the re-sealing holds at most one bin beyond the
    /// sealed bins, charged, and whether one is refused is what the bins held decide; one refused
    /// is forgotten whole and its records counted refused.
    fn forget(&mut self, left: Vec<PublicKey>) {
        if self.engine.is_none() || left.is_empty() {
            return;
        }
        self.room_to_reseal();
        let generation = self.generation;
        let threads = self.settings.threads.max(1);
        self.sealing = Some((generation, None));
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        let held = Arc::clone(&self.held);
        self.runners.hand(&self.shared, Kind::Seal, move || {
            shared.delay(Stage::Forget);
            shared.sealed.without_each(
                &left,
                threads,
                |bytes| held.try_charge(bytes),
                |resealed| {
                    let (done, handled) = std::sync::mpsc::channel();
                    let sent = messages.send(Message::Finished(Finished::Resealed {
                        generation,
                        resealed,
                        done,
                    }));
                    // Held (or forgotten) before the next is asked for.
                    if sent.is_ok() {
                        let _ = handled.recv();
                    }
                },
            );
            let _ = messages.send(Message::Finished(Finished::Forgotten { generation }));
        });
    }

    /// Seals `fragments`, step `closed`'s, off this thread, within the room the bins held before
    /// them left: no other seal and no forget is done until it reports.
    fn seal(&mut self, fragments: Vec<Fragment>, open: Vec<Charge>, closed: Closed) {
        let generation = self.generation;
        let room = self.room();
        let threads = self.settings.threads.max(1);
        self.sealing = Some((generation, Some(closed.step_ms)));
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        self.runners.hand(&self.shared, Kind::Seal, move || {
            shared.delay(Stage::Seal);
            let (bins, refused) = tally_mlat::engine::seal(fragments, threads, room);
            let _ = messages.send(Message::Finished(Finished::Sealed {
                generation,
                closed,
                bins,
                refused: refused as u64,
                open,
            }));
        });
    }

    /// A window step ran `ran_ms` (module docs, Overload): longer than `WINDOW_BUDGET_MS`, MLAT
    /// is overloaded, and cuts its seats to what that run says it carries in `WINDOW_TARGET_MS`;
    /// seats cut and a run well within the budget, it lifts the cut the same way. Either is a cut
    /// from `CUT_LEAD_STEPS` past the watermark, published for the relays holding the same areas
    /// ([`MlatHost::take_cuts`]): the receivers solved are decided by rank and the stamp of the
    /// cut, never by how far behind this host happened to be.
    fn judge(&mut self, ran_ms: u64) {
        let (Some(through), Some(_)) = (self.through_ms, self.engine.as_ref()) else {
            return;
        };
        let seats = &self.shared.seats;
        let (cap, taken, limit) = (seats.cap(), seats.taken(), seats.limit());
        let own_cut = self
            .shared
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .own
            .is_some();
        let budget = self
            .shared
            .window_budget_ms
            .get()
            .copied()
            .unwrap_or(WINDOW_BUDGET_MS);
        let target = budget / 4 * 3;
        let wanted = if ran_ms > budget {
            let carried = (taken as u128 * u128::from(target) / u128::from(ran_ms.max(1))) as usize;
            let floor = MIN_CUT_SEATS.min(limit);
            if taken <= floor {
                return;
            }
            // At most half of them a cut: a step's cost is not in proportion to its seats (a
            // part of it is the aircraft's, whatever the receivers), so a cut aimed at the
            // budget in one go would undershoot; the next window step judges again.
            carried.max(floor).max(taken / 2).min(taken - 1)
        } else if own_cut && cap < limit && taken >= cap && ran_ms < budget / 2 {
            let carried = (cap as u128 * u128::from(target) / u128::from(ran_ms.max(1))) as usize;
            carried.min(limit).min(cap + cap / 4 + 1)
        } else {
            return;
        };
        if wanted == cap {
            return;
        }
        let origin = self.identity.public();
        let from_ms = (through / STEP_MS + CUT_LEAD_STEPS) * STEP_MS;
        let cut = Cut {
            from_ms,
            origin,
            seats: u32::try_from(wanted).unwrap_or(u32::MAX),
        };
        let mut cuts = self
            .shared
            .cuts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // One cut in flight at a time: the next decision waits for this one to take effect.
        if cuts.newest(&origin).is_some_and(|(at, _)| at > through) {
            return;
        }
        cuts.offer(cut);
        cuts.decided.push(cut);
        cuts.own = (wanted < limit).then_some(cut.seats);
        drop(cuts);
        self.shared.count(|counts| counts.cuts_decided += 1);
    }

    /// Sheds the oldest window step queued (module docs, Behind): counted, its windows the next
    /// queued one's, which solves every window due as one that ran late would.
    fn shed_window(&mut self) {
        let Some(shed) = self.windows.pop_front() else {
            return;
        };
        self.shared.count(|counts| counts.steps_shed += 1);
        if let Some(next) = self.windows.front_mut() {
            next.due_ms = next.due_ms.min(shed.due_ms);
            next.first_bin = next.first_bin.min(shed.first_bin);
        }
    }

    /// Sheds provisional step `step_ms` (module docs, Behind): what batches told it let go, whole
    /// and counted.
    fn shed_provisional(&mut self, step_ms: u64) {
        let weighed = self.shared.shed_intervals(step_ms);
        drop(weighed.charges);
        self.shared.count(|counts| {
            counts.provisional_steps_shed += 1;
            counts.shed += weighed.shed_batches;
            counts.refused += weighed.refused_batches;
        });
    }

    /// Provisional step `step_ms` on its runner: it weighs what batches stamped before it told
    /// provisional solving and solves what is due, carrying the models of the windows that fell due
    /// `MODELS_RIPEN_MS` before it. Done when it reports; its records are late from
    /// `PROVISIONAL_PUBLISH_MS` past it (`Shared::take_signed`). A step with nothing to weigh (nothing
    /// heard, nothing waiting) is done here, on no thread (sweep 4, N18).
    fn start_provisional(&mut self, step_ms: u64) {
        let generation = self.generation;
        let most_waiting = self.shared.most_waiting;
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let plan = engine.provisional_plan(step_ms, step_ms);
        self.provisional = Some(step_ms);
        // Weighed here, as it starts: a step shed after it never takes what is this step's.
        let weighed = self.shared.weigh_intervals(step_ms);
        let through = step_ms / STEP_MS;
        let idle = self.shared.receptions_waiting.load(Ordering::SeqCst) == 0
            && (0..provisional_::SHARDS).all(|shard| {
                !self
                    .shared
                    .heard(shard)
                    .iter()
                    .any(|heard| heard.interval < through && heard.generation <= generation)
            });
        if idle {
            // Nothing to weigh and nothing waiting: its passes would find nothing, so it is done
            // here, at once, on no thread.
            drop(weighed.charges);
            let outcome = plan.job(Vec::new()).run();
            self.finished(Finished::Solved {
                generation,
                step_ms,
                outcome,
                refused: weighed.refused_batches,
                shed: weighed.shed_batches,
            });
            return;
        }
        let messages = self.messages.clone();
        let shared = Arc::clone(&self.shared);
        let work = move || {
            shared.delay(Stage::Provisional);
            let Weighed {
                refused: refused_intervals,
                refused_batches,
                shed_batches,
                charges,
            } = weighed;
            let shards: Vec<usize> = (0..provisional_::SHARDS).collect();
            // Read every shard in the batches' order, then decide every batch whole across all of
            // them, then keep and find what is due: each pass all shards in parallel. An address
            // shard is held by its pass alone: no stage and not the engine's thread ever waits on
            // it (sweep 5, R9).
            let (read, _) = window::parallel(
                plan.threads,
                &shards,
                |shard, _: &mut provisional::Report| {
                    let due = shared.due(*shard, generation, through);
                    let mut listening = shared.listening(*shard);
                    shared.delay(Stage::Reading);
                    listening.read(generation, due, &refused_intervals)
                },
            );
            // Read: the batches the notes kept alive are let go.
            drop(charges);
            let waiting: usize = read.iter().map(|(waiting, _)| *waiting).sum();
            let sizes = provisional_::sizes(read.iter().flat_map(|(_, taken)| taken));
            let mut refused = provisional_::admit(waiting, sizes.clone(), most_waiting);
            // Charged before they are kept: the count admitted fits the `Engine` store's share
            // for them (`Capacity::waiting`), so the charge is refused only past the budget,
            // and then every batch's replies are, whole. The charge is locked only to grow it here
            // and to bring it to what is left after, never across the pass (sweep 4, N16).
            let kept: usize = sizes
                .iter()
                .filter(|(order, _)| !refused.contains(order))
                .map(|(_, size)| *size)
                .sum();
            let grown = shared
                .waiting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .try_grow(kept.saturating_mul(provisional_::WAITING_BYTES));
            if !grown {
                refused.extend(sizes.keys().copied());
            }
            shared.delay(Stage::Weighing);
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
            shared
                .waiting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shrink_to(waiting.saturating_mul(provisional_::WAITING_BYTES));
            shared.receptions_waiting.store(waiting, Ordering::SeqCst);
            let job = plan.job(parts.into_iter().map(|(_, due)| due).collect());
            let outcome = job.run();
            let _ = messages.send(Message::Finished(Finished::Solved {
                generation,
                step_ms,
                outcome,
                refused: refused_batches,
                shed: shed_batches,
            }));
        };
        self.runners.hand(&self.shared, Kind::Provisional, work);
    }

    /// Starts the oldest window step queued, unless one runs: its working set reserved in the
    /// `Engine` store while it runs and until its outcome is applied (a seat's
    /// `SOLVE_BYTES_PER_RECEIVER`), its windows handed out as at its own step (so its models ripen
    /// by its own stamp, however long it waited, `Engine::apply`), and run on the window runner.
    /// One the store cannot reserve (it always can: the store's share is that and the receptions
    /// waiting, each admitted within its own) waits, counted once, and starts once it can.
    fn start_window(&mut self) {
        while self.window.is_none() {
            let generation = self.generation;
            let seats = self.settings.capacity.receivers;
            let Some(front) = self.windows.front_mut() else {
                return;
            };
            let Some(working) = self
                .engine_gauge
                .try_charge(seats.saturating_mul(SOLVE_BYTES_PER_RECEIVER))
            else {
                if !front.deferred {
                    front.deferred = true;
                    self.shared.count(|counts| counts.windows_deferred += 1);
                }
                return;
            };
            let Some(WindowStep {
                step_ms,
                settled,
                sites,
                due_ms,
                first_bin,
                ..
            }) = self.windows.pop_front()
            else {
                return;
            };
            let Some(engine) = self.engine.as_mut() else {
                return;
            };
            let job = engine.prepare_sealed(step_ms, step_ms, settled, sites);
            // What it forgot as it handed the windows out.
            self.settle_sealed();
            let Some(job) = job else {
                continue;
            };
            self.window = Some(Running { due_ms, first_bin });
            let messages = self.messages.clone();
            let shared = Arc::clone(&self.shared);
            self.runners.hand(&self.shared, Kind::Window, move || {
                let started = std::time::Instant::now();
                shared.delay(Stage::Window);
                let outcome = job.run();
                let ran_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                // The working set's charge travels with the outcome until it is applied, so a
                // finished window waiting for the engine's thread is never outside every store
                // (sweep 4, N17).
                let _ = messages.send(Message::Finished(Finished::Stepped(
                    generation,
                    Box::new(outcome),
                    working,
                    ran_ms,
                )));
            });
        }
    }

    /// A seal's or a step's outcome, applied if its engine is still the one running; its report
    /// kept. What a seal refused is counted when it finishes, whichever engine it was for (sweep 5,
    /// H-b: before, it waited in the engine for its next window step, and went with the engine).
    fn finished(&mut self, finished: Finished) {
        match finished {
            Finished::Sealed {
                generation,
                closed,
                bins,
                refused,
                open,
            } if generation == self.generation => {
                self.sealing = None;
                let refused = refused + self.hold(bins);
                drop(open);
                self.shared
                    .count(|counts| counts.observations_refused += refused);
                self.sealed_step(closed);
                // What waited for this seal, in its turn.
                self.next_seal();
            }
            Finished::Resealed {
                generation,
                resealed,
                done,
            } => {
                if generation == self.generation {
                    match resealed {
                        // In place of the old one, then the `Held` charge settled to what is
                        // held, and only then the charge it was built under let go.
                        Resealed::Bin(bin, charge) => {
                            self.shared.sealed.insert(*bin);
                            self.settle_sealed();
                            drop(charge);
                        }
                        Resealed::Refused { bin, .. } => {
                            let records = self.shared.sealed.forget(bin) as u64;
                            self.settle_sealed();
                            if bin < self.kept_from {
                                self.shared
                                    .count(|counts| counts.waiting_bins_forgotten += 1);
                            } else {
                                self.shared
                                    .count(|counts| counts.observations_refused += records);
                            }
                        }
                    }
                }
                let _ = done.send(());
            }
            Finished::Forgotten { generation } if generation == self.generation => {
                self.sealing = None;
                self.settle_sealed();
                self.next_seal();
            }
            Finished::Stepped(generation, outcome, working, ran_ms)
                if generation == self.generation =>
            {
                self.shared.delay(Stage::Apply);
                if let Some(engine) = self.engine.as_mut() {
                    let (records, report, _) = engine.apply(*outcome);
                    // The outcome is the engine's now: the working set's charge goes.
                    drop(working);
                    let step = StepReport::of(&report);
                    self.shared.count(|counts| {
                        counts.steps += 1;
                        counts.steps_total.add(&step);
                        counts.last_step = Some(step);
                    });
                    self.publish(records, None);
                    self.judge(ran_ms);
                }
                self.window = None;
            }
            Finished::Solved {
                generation,
                step_ms,
                outcome,
                refused,
                shed,
            } if generation == self.generation => {
                if let Some(engine) = self.engine.as_mut() {
                    let records = engine.apply_provisional(outcome);
                    let report = engine.provisional_report();
                    self.shared.count(|counts| {
                        counts.provisional_steps += 1;
                        counts.refused += refused;
                        counts.shed += shed;
                        counts.provisional.add(&report);
                    });
                    // Taken once the watermark is past its publish slot, they would reach the live
                    // world after its second is sealed: refused whole then, counted (sweep 4,
                    // R-P16; sweep 5, R2). Its state is applied all the same, so the steps after
                    // it weigh what the reference does.
                    self.publish(
                        records,
                        Some(step_ms.saturating_add(PROVISIONAL_PUBLISH_MS)),
                    );
                }
                self.provisional = None;
            }
            // An engine since dropped: what it sealed, forgot or solved is not published, and
            // counted, and what its seal refused with it.
            Finished::Sealed {
                generation,
                refused,
                ..
            } => {
                if self.sealing.is_some_and(|(of, _)| of == generation) {
                    self.sealing = None;
                }
                self.shared.count(|counts| {
                    counts.steps_discarded += 1;
                    counts.observations_refused += refused;
                });
            }
            Finished::Forgotten { generation, .. } => {
                if self.sealing.is_some_and(|(of, _)| of == generation) {
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
    /// `Held` store, both less what the stamps keep sealed (`stamps_bytes`), so a function of what
    /// was sealed and forgotten by the steps' stamps alone: never of what is open now, nor of how
    /// long a window step ran or waited, nor of the bins its floor keeps (sweep 6, N1/F7: before,
    /// the room was the store less every sealed bin, those a waiting window's floor kept
    /// included, so a relay whose window steps ran long sealed receivers out of a bin that a
    /// relay keeping up held, and the room passed the `SEALED_BINS_HELD` the store reserves).
    fn room(&self) -> usize {
        let kept = self.stamps_bytes();
        let engine = self.engine.as_ref().map_or(0, |engine| {
            engine.settings().limits().bytes.saturating_sub(kept)
        });
        engine.min(self.held.limit().saturating_sub(kept))
    }

    /// What the sealed bins the stamps keep cost (those from `kept_from` on, and the handle's own
    /// bytes): every sealed byte but the bins only a waiting window step's floor keeps.
    fn stamps_bytes(&self) -> usize {
        let waiting: usize = self
            .shared
            .sealed
            .bins(i64::MIN, self.kept_from.saturating_sub(1))
            .iter()
            .map(|bin| SealedBins::cost(bin))
            .sum();
        self.shared.sealed.bytes().saturating_sub(waiting)
    }

    /// Lets go of the oldest sealed bin only a waiting window step's floor keeps (one the stamps
    /// forgot), counted (`MlatReport::waiting_bins_forgotten`): such a bin lives in the room the
    /// stamps leave in the `Held` store, and yields it to the stamps' bins whenever they need it,
    /// so it never decides what a seal or a forget refuses. False when there is none.
    fn forget_waiting_bin(&mut self) -> bool {
        let Some(oldest) = self.shared.sealed.numbers().first().copied() else {
            return false;
        };
        if oldest >= self.kept_from {
            return false;
        }
        self.shared.sealed.forget(oldest);
        self.shared
            .count(|counts| counts.waiting_bins_forgotten += 1);
        self.settle_sealed();
        true
    }

    /// Makes sealed `bins` readable, each charged to the `Held` store before it is held, the bins
    /// only a waiting window step's floor keeps let go, oldest first, for room it needs: one the
    /// store cannot hold even then (sealed within the room the stamps left, it never is) is
    /// refused whole. The observations refused.
    fn hold(&mut self, bins: Vec<Bin>) -> u64 {
        let mut refused = 0;
        for bin in bins {
            let cost = SealedBins::cost(&bin);
            let mut held = self.sealed_charge.try_grow(cost);
            while !held && self.forget_waiting_bin() {
                held = self.sealed_charge.try_grow(cost);
            }
            if held {
                self.shared.sealed.insert(bin);
            } else {
                refused += bin.records.len() as u64;
            }
            // One in place of a bin of its number let that one go.
            self.settle_sealed();
        }
        refused
    }

    /// Room for a forget's re-sealing before it starts: each bin it seals again is charged before
    /// it is built and the old one let go after (`SealedBins::without_each`), so it needs a bin's
    /// room beyond the sealed bins. The bins only a waiting window step's floor keeps are let go,
    /// oldest first, until the store has that room beside the stamps' bins or none is left, so
    /// whether one of the stamps' bins is refused is what the stamps' bins decide alone.
    fn room_to_reseal(&mut self) {
        let largest = self
            .shared
            .sealed
            .bins(self.kept_from, i64::MAX)
            .iter()
            .map(|bin| SealedBins::cost(bin))
            .max()
            .unwrap_or(0);
        while self.held.limit().saturating_sub(self.held.held()) < largest
            && self.forget_waiting_bin()
        {}
    }

    /// The `Held` charge brought to what the sealed bins hold now: down when bins were forgotten,
    /// up for the handle's own bytes. A receiver forgotten in a bin seals it again without it
    /// (`SealedBins::forget_receiver`), never larger; were it larger and past the store, the
    /// oldest bins are forgotten until it fits: first those only a waiting window step's floor
    /// keeps (`waiting_bins_forgotten`), then the stamps' (counted refused).
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
            let records = self.shared.sealed.forget(oldest) as u64;
            if oldest < self.kept_from {
                self.shared
                    .count(|counts| counts.waiting_bins_forgotten += 1);
            } else {
                self.shared
                    .count(|counts| counts.observations_refused += records);
            }
        }
    }

    /// Takes every bin complete through `settled` out of every shard (a move under each shard's
    /// lock in turn: raw stamped at or after the step that takes it is late by its stamp, so what
    /// is taken is the same whenever this runs), with the `Open` charge of what was taken. What the
    /// shards refused is counted now, as it was decided (sweep 5, H-b).
    fn take_complete(&mut self, settled: i64) -> (Vec<Fragment>, Vec<Charge>) {
        let mut fragments: Vec<Fragment> = Vec::new();
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
            let more = shard.intake.take_dropped();
            dropped.late += more.late;
            dropped.refused += more.refused;
            dropped.receivers += more.receivers;
            dropped.ahead += more.ahead;
        }
        self.shared.count(|counts| {
            counts.observations_late += dropped.late;
            counts.observations_refused += dropped.refused;
            counts.observations_ahead += dropped.ahead;
            counts.receivers_refused += dropped.receivers;
        });
        (fragments, open)
    }

    /// Takes every bin complete by step `step_ms` out of every shard and seals them off this
    /// thread in their turn (`seals`); `sites` are the receivers taking part as the step's
    /// descriptions left them, for a window that falls due at it.
    fn close(&mut self, step_ms: u64, sites: Vec<Site>) {
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        let settled = engine.settled(step_ms);
        let (fragments, open) = self.take_complete(settled);
        self.seals.push_back(Sealing::Seal {
            fragments,
            open,
            closed: Closed {
                step_ms,
                settled,
                sites,
            },
        });
        self.next_seal();
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

    /// An engine goes: its raw, what it was told, and its steps with it. The address shards'
    /// state and what it charged are let go on the provisional runner, after the step it may be
    /// running: this thread never waits on an address shard (sweep 5, R9: before, it cleared
    /// them here, waiting on a provisional step's every read and settle).
    fn drop_steps(&mut self) {
        self.shared.sealed.clear();
        self.kept_from = i64::MIN;
        self.settle_sealed();
        for shard in 0..provisional_::SHARDS {
            self.shared.heard(shard).clear();
        }
        let shared = Arc::clone(&self.shared);
        self.runners.clear(move || {
            for shard in 0..provisional_::SHARDS {
                shared.listening(shard).clear();
            }
            shared
                .waiting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shrink_to(0);
            shared.receptions_waiting.store(0, Ordering::SeqCst);
        });
        self.shared.intervals().open.clear();
        self.proposed.clear();
        self.windows.clear();
        self.window = None;
        self.provisional = None;
        self.sealing = None;
        self.seals.clear();
        self.through_ms = None;
        self.sealed_through = None;
    }

    fn publish(&self, records: Vec<Record>, late_ms: Option<u64>) {
        self.shared.publish(records, PUBLISHED_BYTES, late_ms);
    }
}

/// The stamp clock of a test that runs relays hosting MLAT over sockets (this crate's
/// `tests/mlat_host.rs`, the API's end to end): one clock for every relay of the test, moved a step
/// at a time ([`stepping::step`]) only once every relay has been offered what was fed by it and its
/// hosted MLAT has stepped to it and published, and never past the wall clock. So a batch fed once
/// the clock reaches its own wall clock is stamped within a step after it (never late for its bin,
/// never ahead of the stamp, `held::AHEAD_MS`), a scenario in the past is walked as fast as the
/// relays keep up, and nothing a test asserts depends on how fast its machine is: it asserts in
/// stamps.
pub mod stepping {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::sync::watch;

    use super::{HostedMlat, STEP_MS};

    /// The clock: at a stamp the test moves, or the wall clock.
    pub struct Clock {
        wall: bool,
        now: watch::Sender<u64>,
    }

    impl Clock {
        /// At `start_ms`, moved only forward, by [`step`] or [`Clock::set`].
        pub fn at(start_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                wall: false,
                now: watch::channel(start_ms).0,
            })
        }

        /// The wall clock: for a test that feeds nothing of a scenario.
        pub fn wall() -> Arc<Self> {
            Arc::new(Self {
                wall: true,
                now: watch::channel(0).0,
            })
        }

        pub fn now(&self) -> u64 {
            if self.wall {
                crate::network::wall_ms()
            } else {
                *self.now.borrow()
            }
        }

        /// Moves the clock to `at_ms`, if that is ahead of it.
        pub fn set(&self, at_ms: u64) {
            self.now.send_if_modified(|now| {
                let ahead = at_ms > *now;
                if ahead {
                    *now = at_ms;
                }
                ahead
            });
        }

        /// As a relay's ingest clock (`Hub::clocked`).
        pub fn clock(self: &Arc<Self>) -> crate::ingest::Clock {
            let clock = Arc::clone(self);
            Arc::new(move || clock.now())
        }

        /// Waits until the clock reaches `at_ms`.
        pub async fn reached(&self, at_ms: u64) {
            let mut now = self.now.subscribe();
            let _ = now.wait_for(|now| *now >= at_ms).await;
        }
    }

    /// A relay's hosted MLAT, as a test wraps it.
    pub trait Hosting: Send + Sync {
        fn host(&self) -> &HostedMlat;
    }

    impl Hosting for HostedMlat {
        fn host(&self) -> &HostedMlat {
            self
        }
    }

    /// Moves `clock` a step at a time for as long as the test runs: each step once every host of
    /// `hosts` has been offered every batch fed to it by then (its batches' wall clocks, each fed
    /// once the clock reaches it), has been asked by the watermark to the clock, has nothing in
    /// hand, has had what it signed taken, and has been asked once more after that (so its relay
    /// has published what the ask before took, into its products by the clock as it stood); and
    /// never past the wall clock. An error, saying where each host stood, once nothing has moved
    /// for `stood`.
    pub fn step(
        clock: Arc<Clock>,
        hosts: Vec<(Arc<dyn Hosting>, Vec<u64>)>,
        stood: Duration,
    ) -> tokio::task::JoinHandle<Result<(), String>> {
        let hosts: Vec<(Arc<dyn Hosting>, Vec<u64>)> = hosts
            .into_iter()
            .map(|(host, mut walls)| {
                walls.sort_unstable();
                (host, walls)
            })
            .collect();
        tokio::spawn(async move {
            let mut since = Instant::now();
            // The asks each host had taken when it was first seen caught up at this clock.
            let mut asked: Option<Vec<u64>> = None;
            loop {
                let now = clock.now();
                let caught_up = hosts.iter().all(|(hosting, walls)| {
                    let host = hosting.host();
                    host.offered() >= walls.partition_point(|wall| *wall <= now) as u64
                        && host.asked_ms() >= now
                        && host.in_flight() == 0
                        && host.untaken() == 0
                });
                if !caught_up {
                    asked = None;
                } else if asked.is_none() {
                    asked = Some(
                        hosts
                            .iter()
                            .map(|(hosting, _)| hosting.host().asks())
                            .collect(),
                    );
                }
                let published = asked.as_ref().is_some_and(|asked| {
                    hosts
                        .iter()
                        .zip(asked)
                        .all(|((hosting, _), asks)| hosting.host().asks() > *asks)
                });
                if published && now + STEP_MS <= crate::network::wall_ms() {
                    clock.set(now + STEP_MS);
                    asked = None;
                    since = Instant::now();
                } else if since.elapsed() > stood {
                    let state: Vec<_> = hosts
                        .iter()
                        .map(|(hosting, walls)| {
                            let host = hosting.host();
                            (
                                walls.partition_point(|wall| *wall <= now),
                                host.offered(),
                                host.asked_ms(),
                                host.in_flight(),
                                host.untaken(),
                            )
                        })
                        .collect();
                    return Err(format!(
                        "the clock stood at {now}: (fed, offered, asked, in flight, untaken) per \
                         host {state:?}"
                    ));
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    }
}

/// How a piece of the engine's work is scheduled against the rest of the relay's. Every step runs
/// below the stages' priority (RFC-0181 §10, "The cores"): the cores are planned so the stages'
/// half-busy share and MLAT's fit together (`cores::mlat_threads_for`), and when MLAT needs more
/// than its share it is MLAT that waits, and sheds the steps it falls behind on (counted), never
/// raw that is delayed. Nothing a stage waits on is held by a step: a step takes the raw shards'
/// complete bins and the address shards' notes on the engine's thread or by a swap
/// (`Shared::due`), and weighs and solves with no stage's lock held. The engine's own thread does
/// nothing that takes long and does take the raw shards' locks, so it stays at the stages'
/// priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Urgency {
    /// Provisional solving: a provisional is due within seconds of its transmission (RFC-0174
    /// §2.4), so it runs below the stages and above the window steps (`PROVISIONAL_NICE`).
    Prompt,
    /// Seals, window steps and forgetting receivers that left: a final position comes 7 to 47 s
    /// after its transmission (the stride), and a window's fits take seconds of every core they
    /// are spread over. They run lowest (`BACKGROUND_NICE`), so on a busy host they yield the cores
    /// to the stages and to provisional solving, never the other way round.
    Background,
}

impl Urgency {
    /// How far below the relay's own priority (the stages', whatever nice the relay was started
    /// at) its threads run, in nice steps. Linux gives each thread its own, and the threads a step
    /// spreads its work over (`window::parallel`) inherit it. Each step of nice is about 1.25 times
    /// less weight against a thread at the one above (the kernel's `sched_prio_to_weight`): 5
    /// below, a stage's thread outweighs a provisional step's about 3 to 1, 10 below a window
    /// step's about 9 to 1.
    const fn below(self) -> libc::c_int {
        match self {
            Self::Prompt => PROVISIONAL_NICE,
            Self::Background => BACKGROUND_NICE,
        }
    }

    /// The gate's urgency (`tally_mlat_solver::gate`): provisional work is let in first.
    const fn gate(self) -> gate::Urgency {
        match self {
            Self::Prompt => gate::Urgency::Prompt,
            Self::Background => gate::Urgency::Background,
        }
    }
}

/// Lowers the calling thread to the priority of MLAT's background work (`Urgency::Background`):
/// what a thread doing work the hosted MLAT brings beside its own runners (the relay's standing)
/// runs at. False when it could not be lowered all the way (`run_at`).
pub fn run_as_background() -> bool {
    run_at(Urgency::Background.below())
}

/// How far below the stages' priority provisional steps run: nice steps.
const PROVISIONAL_NICE: libc::c_int = 5;
/// How far below the stages' priority seals, window steps and forgets run: nice steps.
const BACKGROUND_NICE: libc::c_int = 10;
/// The lowest priority Linux has: a thread already there stays, and is still below the stages
/// unless they are there too.
const LOWEST_NICE: libc::c_int = 19;
const _: () = assert!(0 < PROVISIONAL_NICE && PROVISIONAL_NICE < BACKGROUND_NICE);

/// Lowers the calling thread's priority `below` nice steps under its own (what the thread that
/// started it had: the relay's), at most to the lowest; false when it could not be lowered all of
/// them (sweep 4, N9: before, it set 5 or 10 outright, which on a relay started at nice 5 or more
/// left MLAT level with the stages, or failed unseen; sweep 5, R7: a relay already near the lowest,
/// at nice 19 none, has MLAT level with or less far below its stages than planned, counted). A
/// thread may always lower its own.
fn run_at(below: libc::c_int) -> bool {
    // SAFETY: `gettid`, `getpriority`, `setpriority` and `__errno_location` read and write no
    // memory of this process but this thread's errno; on Linux a thread is addressed by its id as
    // a process, so this changes this thread's nice value alone.
    #[cfg(target_os = "linux")]
    unsafe {
        let tid = libc::gettid() as libc::id_t;
        // `getpriority` may return -1 as a value: errno, cleared first, tells a failure.
        *libc::__errno_location() = 0;
        let own = libc::getpriority(libc::PRIO_PROCESS, tid);
        if own == -1 && *libc::__errno_location() != 0 {
            return false;
        }
        let target = own.saturating_add(below).min(LOWEST_NICE);
        libc::setpriority(libc::PRIO_PROCESS, tid, target) == 0 && target - own == below
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = below;
        true
    }
}

/// A piece of MLAT's work for one of its runners.
type Work = Box<dyn FnOnce() + Send>;

/// Which runner a piece of work is for.
#[derive(Clone, Copy)]
enum Kind {
    Seal,
    Window,
    Provisional,
}

/// MLAT's runners (sweep 5, R7): one thread each for the seals and forgets, the window steps and
/// the provisional steps, started with the host, each at its urgency below the stages (`Urgency`,
/// counted in `priority_unset` when it could not be), and living as long as the host does, each
/// doing what it is handed one piece at a time, in the order handed, as one of the threads the
/// plan gives MLAT (`Shared::gate`: the three together never work on more of them). A host whose
/// runners cannot start is an error; once it runs, no piece of MLAT's work needs a thread it may
/// not get, so none ever runs on the engine's thread, ungated and at the stages' priority (before,
/// a step whose thread could not be spawned ran there).
struct Runners {
    seal: Sender<Work>,
    window: Sender<Work>,
    provisional: Sender<Work>,
}

impl Runners {
    fn start(shared: &Arc<Shared>) -> Result<Self, String> {
        Ok(Self {
            seal: runner("tally-mlat-seal", Urgency::Background, shared)?,
            window: runner("tally-mlat-window", Urgency::Background, shared)?,
            provisional: runner("tally-mlat-prov", Urgency::Prompt, shared)?,
        })
    }

    /// Hands a step, a seal or a forget to its runner, counted.
    fn hand(&self, shared: &Shared, kind: Kind, work: impl FnOnce() + Send + 'static) {
        shared.handed.fetch_add(1, Ordering::Relaxed);
        let runner = match kind {
            Kind::Seal => &self.seal,
            Kind::Window => &self.window,
            Kind::Provisional => &self.provisional,
        };
        // A runner gone has ended the process (`EndOnUnwind`).
        let _ = runner.send(Box::new(work));
    }

    /// Hands the provisional runner what an engine that went left in the address shards, to let
    /// go after the step it may be running (`Host::drop_steps`); not a step, so not counted.
    fn clear(&self, work: impl FnOnce() + Send + 'static) {
        let _ = self.provisional.send(Box::new(work));
    }
}

/// Starts runner `name` at `urgency`: once it has lowered its priority, its work queue.
fn runner(name: &str, urgency: Urgency, shared: &Arc<Shared>) -> Result<Sender<Work>, String> {
    let (handing, handed) = std::sync::mpsc::channel::<Work>();
    let (starting, started) = std::sync::mpsc::channel();
    let shared = Arc::clone(shared);
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _ends = EndOnUnwind;
            if !run_at(urgency.below()) {
                shared.priority_unset.fetch_add(1, Ordering::SeqCst);
            }
            let _ = starting.send(());
            while let Ok(work) = handed.recv() {
                gate::enter(&shared.gate, urgency.gate(), work);
            }
        })
        .map_err(|error| format!("the hosted MLAT's {name} did not start: {error}"))?;
    started
        .recv()
        .map_err(|_| format!("the hosted MLAT's {name} ended as it started"))?;
    Ok(handing)
}

/// Ends the process when the thread it is held on unwinds (sweep 5, N7, decided): hosted MLAT that
/// panics ends the relay like every other part of it (`crate::abort_on_any_panic`, which the
/// relay's program sets and which ends it before anything unwinds; a worker's panic inside a step
/// is its step's, `gate::on_threads`). Held by the engine's thread and every runner, so a host
/// built apart from the relay's program (a test's) is held to the same: MLAT never runs on without
/// the part that panicked, its steps waiting for a report that never comes. Before, a runner's
/// panic left no `Finished`, and MLAT stalled for good, silently.
struct EndOnUnwind;

impl Drop for EndOnUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "tally-relay: hosted MLAT panicked; ending the process rather than running without it"
            );
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::PerFeeder;
    use std::sync::atomic::AtomicBool;
    use tally_mlat::replay::{arrivals, replay, scenario};
    use tally_mlat_solver::publish;
    use tally_mlat_solver::scope::{AFTER, BEFORE, STRIDE, Window, bin_of};
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
            Record::ReceiverInfo(info) => host.offer_description(info, at_ms),
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
        let most = tally_mlat::intake::ORPHANS_PER_RECEIVER;
        let offered = feed.batches.len().min(most + 10);
        assert!(offered > most);
        for batch in &feed.batches[..offered] {
            offer(&host, &Record::Batch(batch.clone()), now);
        }
        quiet(&host);
        let report = host.report();
        assert_eq!(report.ingested, 0);
        assert_eq!(
            report.orphans_dropped,
            (offered - most) as u64,
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
        host.offer_description(&feed.info, now);
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

    /// The relay hosts MLAT when its duties are on, unless told `--no-mlat`, on the threads its
    /// cores' plan gives MLAT, and never with `--no-relay-duties`.
    #[test]
    fn mlat_is_hosted_with_relay_duties_on_the_planned_threads_and_never_without_duties()
    -> Result<(), String> {
        let base = "--key k --max-upload 8Mbit/s";
        let budget = Budget::of_memory(
            64 << 30,
            crate::budget::Plan::planned(true).with_cores(Some(32)),
        );
        let host = |line: &str| -> Result<Option<HostedMlat>, String> {
            host_for(&config(line)?, identity(), 1, &budget)
        };
        // Duties and MLAT are on by default.
        let hosted = host(base)?.ok_or("not hosted")?;
        assert_eq!(usize::from(hosted.cores()), budget.mlat_threads());
        assert!(budget.mlat_threads() > 1, "{}", budget.mlat_threads());
        assert!(host(&format!("{base} --no-mlat"))?.is_none());
        assert!(host(&format!("{base} --no-relay-duties"))?.is_none());
        // The thread count is the plan's, not an operator's.
        assert!(config(&format!("{base} --mlat-threads 3")).is_err());
        Ok(())
    }

    /// RFC-0181 §9, §10: the engine seats exactly the pool the relay's budget plans for MLAT
    /// (`Budget::mlat_seats`, at most the feeders it admits), no floor beside it, and what the
    /// stores reserved for `Held`, `Open` and `Engine` covers the raw, waiting receptions and
    /// window working set of the ceiling, and so of any pool within it.
    #[test]
    fn the_seats_are_the_feeder_ceiling_and_what_they_hold_is_the_stores() {
        use tally_mlat_solver::held::Rates;
        let per_feeder = PerFeeder::planned(true);
        for feeders in [1, 7, 30_000] {
            let budget = Budget::new(per_feeder.total() * feeders, per_feeder);
            assert_eq!(budget.ceiling(), feeders);
            let capacity = capacity(&budget);
            // MLAT's own pool (`Budget::mlat_seats`): never more seats than feeders.
            assert_eq!(capacity.receivers, budget.mlat_seats());
            assert!(capacity.receivers <= feeders);
            // The stores cover what the pool holds, at the rates the budget planned for it (the
            // planned rate may be above the pool's: a store is sized by the rate admitted).
            let seats = capacity.receivers.max(1);
            let cost = Rates::MEASURED.cost(SETTLE_MS);
            assert!(budget.store_bytes(Store::Held) >= seats * cost.sealed);
            // Open raw over its settling and the steps MLAT may fall behind, at its seats.
            assert!(budget.store_bytes(Store::Open) >= seats * Rates::MEASURED.cost(OPEN_MS).open);
            assert!(Rates::MEASURED.cost(OPEN_MS).open > cost.open);
            // The receptions waiting and a window step's working set.
            assert!(
                budget.store_bytes(Store::Engine)
                    >= capacity.waiting() * provisional_::WAITING_BYTES
                        + seats * SOLVE_BYTES_PER_RECEIVER
            );
            // Each interval's share of the notes is what a step's count admits at the same
            // headroom: the store is every interval a host that sheds nothing holds.
            let notes = budget.store_bytes(Store::Notes);
            assert_eq!(notes % INTERVALS_HELD, 0);
            assert!(
                notes / INTERVALS_HELD
                    >= seats * NOTES_PER_RECEIVER_STEP * std::mem::size_of::<Note>()
            );
            // The batches waiting for a description have their own store, split whole between
            // those waiting for one that has not come (a seat's share each, by rank) and what
            // waits for a step's descriptions: neither share is charged past, so the store never
            // refuses one by when it came.
            let orphans = budget.store_bytes(Store::Orphans);
            assert!(per_feeder.orphans > 0);
            let room = Room::of(orphans);
            assert_eq!(room.orphans + room.waiting, orphans);
            assert!(room.orphans / seats * seats <= room.orphans);
        }
    }

    /// What `batch` says to provisional solving, told for the step of its stamp (engine generation
    /// 1).
    fn tell(shared: &Shared, batch: &Arc<Decoded>, notes: Vec<Note>) {
        shared.tell(Told {
            batch: Arc::clone(batch),
            notes,
            generation: 1,
            at_ms: batch.stamp_ms(),
        });
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
                tell(shared, &busy[at], notes(most));
            }
            tell(shared, &calm, notes(most));
            // Nothing of the refused step is held, in any shard.
            for shard in 0..provisional_::SHARDS {
                let heard = shared.heard(shard);
                assert!(heard.iter().all(|heard| heard.interval == 11), "{order:?}");
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

    /// RFC-0181 §9: a step's notes past its share of the `Notes` store (the store over
    /// `INTERVALS_HELD`) are refused whole, for the trace, as for their count: whichever batch came
    /// first, nothing of the step is held, and the step that weighs it counts its every batch
    /// refused, not shed. A step within its share is held.
    #[test]
    fn a_steps_notes_past_its_share_of_the_store_are_refused_whole_whatever_the_order()
    -> Result<(), String> {
        let notes = |count: u32| -> Vec<Note> {
            (0..count).map(|n| Note::Position(0x40_0000 + n)).collect()
        };
        let batches = [
            told(1, 0, 10_100)?,
            told(2, 0, 10_500)?,
            told(3, 0, 10_900)?,
        ];
        let one = batches[0].footprint() + 10 * std::mem::size_of::<Note>();
        for order in [[0, 1, 2], [2, 0, 1], [1, 2, 0]] {
            // Two and a half batches a step.
            let gauges = Gauges {
                notes: Gauge::new(Store::Notes, INTERVALS_HELD * (one * 2 + one / 2)),
                ..Gauges::unlimited()
            };
            let host = HostedMlat::charging(identity(), BOOT, settings(), gauges.clone())?;
            let shared = &host.shared;
            for at in order {
                tell(shared, &batches[at], notes(10));
            }
            tell(shared, &told(4, 0, 11_200)?, notes(10));
            for shard in 0..provisional_::SHARDS {
                assert!(
                    shared.heard(shard).iter().all(|heard| heard.interval == 11),
                    "{order:?}"
                );
            }
            assert_eq!(gauges.notes.held(), one, "{order:?}");
            let weighed = shared.weigh_intervals(11_000);
            assert_eq!(weighed.refused, [10].into_iter().collect(), "{order:?}");
            assert_eq!(
                (weighed.refused_batches, weighed.shed_batches),
                (3, 0),
                "{order:?}"
            );
        }
        Ok(())
    }

    /// A host behind on its provisional steps, whose `Notes` store holds every interval it may
    /// (each within its share), lets the next interval go whole: nothing of it is held, in any
    /// shard, the store is never charged past its limit, and the step that weighs it counts its
    /// every batch shed. A host that sheds nothing never gets here.
    #[test]
    fn a_steps_notes_the_full_store_cannot_hold_are_let_go_whole_and_counted() -> Result<(), String>
    {
        let notes = |count: u32| -> Vec<Note> {
            (0..count).map(|n| Note::Position(0x40_0000 + n)).collect()
        };
        let probe = told(1, 0, 10_100)?;
        let one = probe.footprint() + 10 * std::mem::size_of::<Note>();
        // Each interval may hold two; the store holds `INTERVALS_HELD` of them.
        let gauges = Gauges {
            notes: Gauge::new(Store::Notes, INTERVALS_HELD * 2 * one),
            ..Gauges::unlimited()
        };
        let host = HostedMlat::charging(identity(), BOOT, settings(), gauges.clone())?;
        let shared = &host.shared;
        let held = INTERVALS_HELD as u64;
        for interval in 10..10 + held {
            for seed in 0..2u8 {
                let batch = told(
                    seed + 1,
                    interval,
                    interval * STEP_MS + 100 + u64::from(seed),
                )?;
                tell(shared, &batch, notes(10));
            }
        }
        assert_eq!(gauges.notes.held(), gauges.notes.limit());
        // One interval more than a host that keeps up holds: let go whole.
        let late = 10 + held;
        for seed in 0..2u8 {
            let batch = told(seed + 1, late, late * STEP_MS + 100 + u64::from(seed))?;
            tell(shared, &batch, notes(10));
        }
        for shard in 0..provisional_::SHARDS {
            assert!(
                shared
                    .heard(shard)
                    .iter()
                    .all(|heard| heard.interval != late)
            );
        }
        assert!(gauges.notes.peak() <= gauges.notes.limit());
        let weighed = shared.weigh_intervals((late + 1) * STEP_MS);
        assert!(weighed.refused.is_empty());
        assert_eq!((weighed.refused_batches, weighed.shed_batches), (0, 2));
        Ok(())
    }

    /// Waits until the engine's thread has done every command handed to it so far.
    fn handled(host: &HostedMlat) {
        while host.shared.commands.load(Ordering::SeqCst) > 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Waits until `host` has `steps` steps queued or running, a test's deadline failing one that
    /// never does.
    fn holding(host: &HostedMlat, steps: usize) -> Result<(), String> {
        let since = std::time::Instant::now();
        loop {
            handled(host);
            let now = host.shared.steps.load(Ordering::SeqCst);
            if now == steps {
                return Ok(());
            }
            if since.elapsed() > std::time::Duration::from_secs(60) {
                return Err(format!("{now} steps in hand, not {steps}"));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// A stage held shut until the test opens it, telling the test when something waits there.
    struct Gate {
        open: Mutex<bool>,
        opened: std::sync::Condvar,
    }

    impl Gate {
        fn shut() -> Arc<Self> {
            Arc::new(Self {
                open: Mutex::new(false),
                opened: std::sync::Condvar::new(),
            })
        }

        fn pass(&self) {
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            while !*open {
                open = self.opened.wait(open).unwrap_or_else(|e| e.into_inner());
            }
        }

        fn open(&self) {
            *self.open.lock().unwrap_or_else(|e| e.into_inner()) = true;
            self.opened.notify_all();
        }
    }

    /// The first bin any batch of `arrivals` holds raw MLAT uses for.
    fn first_bin(arrivals: &[(u64, Record)]) -> Result<i64, String> {
        let mut first = i64::MAX;
        for (_, record) in arrivals {
            if let Record::Batch(batch) = record {
                let content = batch.content().map_err(text)?;
                let used = content.observations.iter().any(|observation| {
                    observation.data.len() <= 14
                        && tally_mlat_solver::held::wanted(&observation.data)
                });
                if used {
                    first = first.min(tally_mlat_solver::scope::bin_of(content.wall_ms));
                }
            }
        }
        Ok(first)
    }

    /// RFC-0181 §9, §10, items 8 and 16 of the sweep (and N16 of sweep 3): a host whose seal is
    /// held (shut on a gate) takes every later step's bins as the watermark passes it, each sealed
    /// in its turn once the held seal reports, and sheds no window step (whether a window falls due
    /// at a step is known once its seal is held, sweep 5, H-c); its provisional steps keep running
    /// apart from the held seal, every one at its turn, until those from `MODELS_RIPEN_MS` after
    /// the held step, whose models it may not have, each of which is shed at its turn and counted,
    /// never run with other models (sweep 4, N6). Opened, it catches up: every bin sealed, windows
    /// solved, no store ever past its limit, nothing left in hand.
    #[test]
    fn a_host_whose_seal_is_held_seals_every_step_in_turn_and_holds_every_store()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 90.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
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
        let gate = Gate::shut();
        let shut = Arc::clone(&gate);
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == Stage::Seal {
                shut.pass();
            }
        }));
        // The first step that takes a bin seals it, and is held there.
        let held_at = Closing {
            step_ms: STEP_MS,
            settle_ms: SETTLE_MS,
        }
        .close_at(first_bin(&delivered)?);
        let ripen = tally_mlat::engine::MODELS_RIPEN_MS;
        let last = held_at + (SEALS_BEHIND as u64 + 3) * STEP_MS + ripen;
        let mut next = 0;
        let mut published = Vec::new();
        for step in steps(first, last) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            published.extend(host.take_published(step));
            // In hand: before the held step, nothing once every step has reported. After it, the
            // held seal and every step's behind it, each waiting its turn; the provisional steps
            // run (and report) at their turn.
            let behind = ((step.saturating_sub(held_at)) / STEP_MS) as usize;
            let seals = if step < held_at { 0 } else { 1 + behind };
            holding(&host, seals)?;
            let report = host.report();
            assert_eq!(report.steps_shed, 0, "at {step}: {report:?}");
            // Seals `SEALS_BEHIND` steps behind are within what the budget reserves open raw for
            // (`OPEN_MS`): no raw refused for room (sweep 6, F10).
            if step <= held_at + SEALS_BEHIND as u64 * STEP_MS {
                assert_eq!(report.observations_refused, 0, "at {step}: {report:?}");
            }
            // Every provisional step runs at its turn until its models are the held window
            // step's: from `MODELS_RIPEN_MS` after it, each is shed at its turn, counted.
            let late = (step.saturating_sub(held_at + ripen) / STEP_MS) as usize
                + usize::from(step >= held_at + ripen);
            assert_eq!(
                (
                    report.provisional_steps_shed,
                    report.provisional_models_late
                ),
                (late as u64, late as u64),
                "at {step}: {report:?}"
            );
        }
        gate.open();
        quiet(&host);
        published.extend(host.take_signed());
        // Every bin the shed steps took is sealed, the newest the last step's.
        let engine_settled = tally_mlat_solver::scope::bin_of(last - SETTLE_MS) - 1;
        assert_eq!(
            host.sealed_bins()
                .ok_or("no sealed bins")?
                .numbers()
                .last()
                .copied(),
            Some(engine_settled)
        );
        // Asked on, it solves its windows.
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        for step in steps(last, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            published.extend(host.take_published(step));
            quiet(&host);
        }
        published.extend(host.take_signed());
        let report = host.report();
        assert!(report.steps > 0, "{report:?}");
        assert!(
            published
                .iter()
                .any(|record| matches!(record, Record::ClockModel(_))),
            "no models"
        );
        for gauge in [
            &gauges.held,
            &gauges.open,
            &gauges.notes,
            &gauges.engine,
            &gauges.orphans,
        ] {
            assert!(
                gauge.peak() <= gauge.limit(),
                "{:?}: {} past {}",
                gauge.store(),
                gauge.peak(),
                gauge.limit()
            );
        }
        for gauge in [&gauges.held, &gauges.open, &gauges.notes, &gauges.engine] {
            assert!(gauge.peak() > 0, "{:?} never charged", gauge.store());
        }
        // Caught up: nothing waits but the raw and receptions still held.
        assert_eq!(host.in_flight(), 0);
        assert_eq!(gauges.notes.held(), 0);
        Ok(())
    }

    /// A batch stamped long before the bin its own wall clock names (a receiver whose clock runs
    /// far ahead, or one stamping its batches in the future) opens no bin: its raw is refused and
    /// counted, and the same raw stamped in time is held.
    #[test]
    fn raw_far_ahead_of_its_stamp_is_refused_and_counted() -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let mut delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        // The last batch of the trace, also offered at the start, a minute ahead of its stamp.
        let (_, last) = delivered
            .iter()
            .rev()
            .find(|(_, record)| matches!(record, Record::Batch(_)))
            .cloned()
            .ok_or("no batch")?;
        let at = delivered
            .iter()
            .position(|(_, record)| matches!(record, Record::Batch(_)))
            .ok_or("no batch")?;
        delivered.insert(at, (delivered[at].0, last));
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        drive(&host, &delivered, first, until);
        let report = host.report();
        assert!(report.observations_ahead > 0, "{report:?}");
        // Offered again in its turn, it is the same batch: used once.
        assert_eq!(report.replayed, 1, "{report:?}");
        Ok(())
    }

    /// Item 15 of the sweep: batches of a receiver never described wait in their own store
    /// (`Orphans`), never in `Notes`, and are let go by the steps, `ORPHAN_MS` after their stamps,
    /// whether or not another batch comes.
    #[test]
    fn batches_waiting_for_a_description_are_let_go_by_the_steps_from_their_own_store()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 30.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let gauges = Gauges::unlimited();
        let host = HostedMlat::charging(identity(), BOOT, settings(), gauges.clone())?;
        host.set_areas(areas()?, Vec::new());
        // Every receiver's batches of the first two seconds, and no description at all.
        let early: Vec<&(u64, Record)> = delivered
            .iter()
            .filter(|(at, record)| matches!(record, Record::Batch(_)) && *at < first + 2_000)
            .collect();
        assert!(!early.is_empty());
        for (at, record) in &early {
            offer(&host, record, *at);
        }
        assert!(gauges.orphans.held() > 0);
        assert_eq!(gauges.notes.held(), 0);
        let last = early.iter().map(|(at, _)| *at).max().unwrap_or(first);
        // Steps run, and nothing more comes: once every batch has waited `ORPHAN_MS`, none is held.
        for step in steps(first, last + tally_mlat::intake::ORPHAN_MS + STEP_MS) {
            host.take_published(step);
            quiet(&host);
        }
        let report = host.report();
        assert_eq!(report.orphans_expired, early.len() as u64, "{report:?}");
        assert_eq!(gauges.orphans.held(), 0);
        assert_eq!(report.ingested, 0);
        Ok(())
    }

    /// Item 13 of the sweep: descriptions take effect at the step after their stamps, wherever they
    /// fall. A receiver described again midway (out of the areas, so it stops taking part, and back
    /// a few seconds later) and one whose first description comes midway (its batches before it
    /// waiting, those that waited too long let go) make the same bytes in the hosted MLAT as in the
    /// reference engine driven in line (`tally_mlat::replay`), and other bytes than with no change.
    #[test]
    fn descriptions_midway_take_effect_at_their_step_as_in_the_reference_engine()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let plain = arrivals(&mut simulation, 3)?;
        let changed = tally_mlat::replay::described_midway(&simulation, &plain)?;
        let first = plain.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = plain.last().map_or(0, |(at, _)| *at) + 60_000;
        let areas = areas()?;
        let run = |delivered: &[(u64, Record)]| -> Result<_, String> {
            let host = HostedMlat::new(identity(), BOOT, settings())?;
            host.set_areas(areas.clone(), Vec::new());
            let hosted = drive(&host, delivered, first, until);
            let mut engine = Engine::new(identity(), BOOT, settings());
            engine.set_scope(area::border_band(&areas), areas.clone());
            let reference = replay(&mut engine, delivered, STEP_MS, until)?;
            let (hosted_provisional, hosted_final) = streams(&hosted);
            let (reference_provisional, reference_final) = streams(&reference);
            assert_eq!(encoded(&hosted_final)?, encoded(&reference_final)?);
            assert_eq!(
                encoded(&hosted_provisional)?,
                encoded(&reference_provisional)?
            );
            Ok((encoded(&hosted_final)?, host.report()))
        };
        let (before, _) = run(&plain)?;
        let (after, report) = run(&changed)?;
        assert_ne!(before, after, "the descriptions midway changed nothing");
        assert!(report.orphans_expired > 0, "{report:?}");
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
        host.shared.publish(step.clone(), bytes * 2, None);
        host.shared.publish(step.clone(), bytes * 2, None);
        // A third would pass the bound: refused, all of it, counted.
        host.shared.publish(step.clone(), bytes * 2, None);
        assert_eq!(host.overflowed(), 3);
        assert_eq!(host.take_signed().len(), 6);
        // Larger than the whole bound, into an empty queue: taken.
        let large: Vec<Record> = (0..5).map(|_| Record::Heartbeat).collect();
        host.shared.publish(large, bytes * 2, None);
        assert_eq!(host.take_signed().len(), 5);
        assert_eq!(host.overflowed(), 3);
        Ok(())
    }

    /// Sweep 3, N7: a receiver that stops taking part while a seal is off the engine's thread (a
    /// later step's descriptions let it go while an earlier step's seal is held) is forgotten in
    /// the bins that seal was sealing and in the bins of the steps sealed after it, as the
    /// reference engine forgets it in every bin sealed before its step: the sealed bins are the
    /// reference's, byte for byte.
    #[test]
    fn a_receiver_that_leaves_while_a_seal_is_held_is_forgotten_in_every_bin_sealed_before()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let plain = arrivals(&mut simulation, 3)?;
        let changed = tally_mlat::replay::described_midway(&simulation, &plain)?;
        let first = changed.first().map(|(at, _)| *at).ok_or("no raw")?;
        let moved = simulation
            .feeds()
            .map_err(text)?
            .first()
            .map(|feed| feed.identity.public())
            .ok_or("no feed")?;
        // The step at which the moved receiver's leaving takes effect.
        let away = changed
            .iter()
            .find(|(at, record)| {
                *at > first
                    && matches!(record, Record::ReceiverInfo(info) if info.receiver().ok() == Some(moved))
            })
            .map(|(at, _)| step_of(*at))
            .ok_or("no leaving")?;
        let areas = areas()?;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas.clone(), Vec::new());
        let gate = Gate::shut();
        let shut = Arc::clone(&gate);
        let armed = Arc::new(AtomicBool::new(false));
        let arming = Arc::clone(&armed);
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == Stage::Seal && arming.load(Ordering::SeqCst) {
                shut.pass();
            }
        }));
        // The last bin of the receiver's raw before it leaves (what the steps already due take,
        // `Intake::describe_after`): the seal of the step that takes it is held, and the watermark
        // passes the leaving, so the leaving's step comes while that seal is off the engine's
        // thread.
        let closing = Closing {
            step_ms: STEP_MS,
            settle_ms: SETTLE_MS,
        };
        let kept = tally_mlat_solver::scope::bin_of(away - STEP_MS - SETTLE_MS) - 1;
        let hold_from = closing.close_at(kept);
        assert!(hold_from < away);
        let last = away + (SEALS_BEHIND as u64 + 3) * STEP_MS;
        let mut next = 0;
        for step in steps(first, last) {
            if step >= hold_from {
                armed.store(true, Ordering::SeqCst);
            }
            while let Some((at, record)) = changed.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            host.take_published(step);
            if step < hold_from {
                quiet(&host);
            } else {
                handled(&host);
            }
        }
        // The seal held when the receiver left still is.
        assert!(
            host.sealed_stepped_ms() < away,
            "{}",
            host.sealed_stepped_ms()
        );
        gate.open();
        quiet(&host);
        let mut engine = Engine::new(identity(), BOOT, settings());
        engine.set_scope(area::border_band(&areas), areas.clone());
        replay(&mut engine, &changed, STEP_MS, last)?;
        let hosted = host.sealed_bins().ok_or("no sealed bins")?;
        let reference = engine.sealed_bins();
        let numbers: BTreeSet<i64> = hosted.numbers().into_iter().collect();
        let common: Vec<i64> = reference
            .numbers()
            .into_iter()
            .filter(|bin| numbers.contains(bin))
            .collect();
        // The bin the held seal was sealing when the receiver left is among them, and held its raw
        // before it left.
        assert!(common.contains(&kept), "{common:?}");
        let mut unchanged = Engine::new(identity(), BOOT, settings());
        unchanged.set_scope(area::border_band(&areas), areas.clone());
        replay(&mut unchanged, &plain, STEP_MS, last)?;
        assert!(
            unchanged
                .sealed_bins()
                .get(kept)
                .is_some_and(|bin| bin.receivers.contains(&moved)),
            "the receiver held no raw in bin {kept}"
        );
        for bin in &common {
            assert!(hosted.get(*bin) == reference.get(*bin), "bin {bin}");
        }
        Ok(())
    }

    /// The nice value of the calling thread.
    fn own_nice() -> libc::c_int {
        // SAFETY: `gettid` and `getpriority` read and write no memory of this process.
        unsafe { libc::getpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t) }
    }

    /// Lowers the calling thread's priority by `by` nice steps.
    fn lower_own(by: libc::c_int) {
        let target = (own_nice() + by).min(LOWEST_NICE);
        // SAFETY: as `own_nice`; `setpriority` changes this thread's nice value alone.
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, target);
        }
    }

    /// RFC-0181 §10, "The cores": every MLAT step runs below the stages' priority, provisional
    /// steps above seals and window steps, so a host short of cores delays MLAT, which sheds,
    /// and never raw. Below the relay's own priority, whatever it was started at (sweep 4, N9: a
    /// relay started at nice 3 runs its provisional steps at 8, not 5).
    #[test]
    fn every_step_runs_below_the_stages() -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 30.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        // The relay started below the default: the engine's thread, started here, inherits it.
        lower_own(3);
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        let seen: Arc<Mutex<Vec<(Stage, libc::c_int)>>> = Arc::new(Mutex::new(Vec::new()));
        let seeing = Arc::clone(&seen);
        host.delaying(Arc::new(move |stage: Stage| {
            if let Ok(mut seen) = seeing.lock() {
                seen.push((stage, own_nice()));
            }
        }));
        let until = delivered.last().map_or(0, |(at, _)| *at);
        let mut next = 0;
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            host.take_published(step);
            handled(&host);
        }
        quiet(&host);
        let base = own_nice();
        let seen = seen.lock().map(|seen| seen.clone()).unwrap_or_default();
        for (stage, nice) in [
            (Stage::Provisional, PROVISIONAL_NICE),
            (Stage::Seal, BACKGROUND_NICE),
            (Stage::Window, BACKGROUND_NICE),
        ] {
            let at: Vec<_> = seen.iter().filter(|(of, _)| *of == stage).collect();
            assert!(!at.is_empty(), "no {stage:?} step ran: {seen:?}");
            assert!(
                at.iter()
                    .all(|(_, was)| *was == (base + nice).min(LOWEST_NICE)),
                "{stage:?} at {at:?}, the stages at {base}"
            );
        }
        assert_eq!(host.report().priority_unset, 0);
        Ok(())
    }

    /// Sweep 5, H-c and N1: while a window step runs long (held shut on a gate past many steps,
    /// within the ripening), every step the watermark passes is still sealed, in its turn, on the
    /// seal runner and never on the engine's thread, and no step is shed (before, each step it ran
    /// past queued as a window step behind it, and every one past `WINDOW_STEPS_BEHIND` was shed); and
    /// each forgets by its own stamp what no window still to be solved needs, so the sealed bins
    /// are the reference engine's at the same step, byte for byte, however long the window step
    /// runs (before, only a window step that ran forgot, so the room a seal had was how long the
    /// window steps ran).
    #[test]
    fn a_window_step_that_runs_long_sheds_no_step_and_every_step_seals_and_forgets_by_its_stamp()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 240.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at);
        let areas = areas()?;
        // Three threads: one kept for provisional work (`gate::Gate::reserved`), one the held
        // window step holds, and one the seals take.
        let threads = Settings {
            threads: 3,
            ..settings()
        };
        let host = HostedMlat::new(identity(), BOOT, threads.clone())?;
        host.set_areas(areas.clone(), Vec::new());
        let gate = Gate::shut();
        let shut = Arc::clone(&gate);
        // The window steps that ran so far, whether one is held (the fourth: by then the steps
        // forget raw; it may start late, behind the ones before it, and then its floor keeps its
        // bins), and the threads of the seals after it.
        let windows = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicBool::new(false));
        let seals: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let (counting, holding_window, sealing) =
            (Arc::clone(&windows), Arc::clone(&held), Arc::clone(&seals));
        host.delaying(Arc::new(move |stage: Stage| match stage {
            Stage::Window if counting.fetch_add(1, Ordering::SeqCst) == 3 => {
                holding_window.store(true, Ordering::SeqCst);
                shut.pass();
            }
            Stage::Seal if holding_window.load(Ordering::SeqCst) => {
                if let Ok(mut seals) = sealing.lock() {
                    seals.push(std::thread::current().name().map(str::to_owned));
                }
            }
            _ => {}
        }));
        const HELD_STEPS: u64 = 12;
        const { assert!(HELD_STEPS > WINDOW_STEPS_BEHIND as u64 + 1) };
        let mut next = 0;
        let mut held_at: Option<(u64, Option<i64>)> = None;
        let mut last = first;
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            host.take_published(step);
            handled(&host);
            // Every step's seal is held in its turn, the window step running or not.
            let since = std::time::Instant::now();
            while host.sealed_stepped_ms() < step {
                assert!(
                    since.elapsed() < std::time::Duration::from_secs(60),
                    "step {step} not sealed: {:?}",
                    host.report()
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            last = step;
            match held_at {
                None if held.load(Ordering::SeqCst) => {
                    let oldest = host
                        .sealed_bins()
                        .and_then(|sealed| sealed.numbers().first().copied());
                    held_at = Some((step, oldest));
                }
                Some((at, _)) if step >= at + HELD_STEPS * STEP_MS => break,
                _ => {}
            }
        }
        let (held_from, oldest) = held_at.ok_or("no window step was held")?;
        assert!(last >= held_from + HELD_STEPS * STEP_MS, "the raw ran out");
        let report = host.report();
        assert_eq!(report.steps_shed, 0, "{report:?}");
        let names = seals.lock().map(|seals| seals.clone()).unwrap_or_default();
        assert!(!names.is_empty());
        assert!(
            names
                .iter()
                .all(|name| name.as_deref() == Some("tally-mlat-seal")),
            "{names:?}"
        );
        // The sealed bins are the reference's at the same step, by their stamps, but for those of
        // the window still held, which its floor keeps (`Engine::forget_by`): the steps forgot
        // older bins while it was held, and kept no bin the held window does not need.
        let mut engine = Engine::new(identity(), BOOT, threads);
        engine.set_scope(area::border_band(&areas), areas.clone());
        replay(&mut engine, &delivered, STEP_MS, last)?;
        let hosted = host.sealed_bins().ok_or("no sealed bins")?;
        let reference = engine.sealed_bins();
        let (hosted_first, reference_first) = (
            hosted
                .numbers()
                .first()
                .copied()
                .ok_or("the host holds no bin")?,
            reference
                .numbers()
                .first()
                .copied()
                .ok_or("the reference holds no bin")?,
        );
        // Forgotten by the stamps up to the held window's first bin at least, whatever was held
        // when the hold began.
        assert!(
            Some(hosted_first) >= oldest && hosted_first > bin_of(first),
            "nothing forgotten: {oldest:?}"
        );
        // Every bin the reference holds, the host holds alike; any more it holds are the held
        // window's, from its first bin on (a canonical window's first).
        for bin in reference.numbers() {
            assert!(hosted.get(bin) == reference.get(bin), "bin {bin}");
        }
        let extra: Vec<i64> = hosted
            .numbers()
            .into_iter()
            .filter(|bin| reference.get(*bin).is_none())
            .collect();
        assert!(
            extra.is_empty()
                || (Window::canonical(hosted_first + BEFORE + STRIDE - 1).first == hosted_first
                    && extra == (hosted_first..reference_first).collect::<Vec<_>>()),
            "held from {held_from} to {last}: the host holds {extra:?} past the reference"
        );
        gate.open();
        quiet(&host);
        Ok(())
    }

    /// Sweep 3, N8: batches waiting for a description are held in one store for every raw shard,
    /// by rank: past the receivers it holds, the best drawn of those that came are held whatever
    /// the order they came in, and the store's share is never charged past (no charge refused).
    #[test]
    fn batches_waiting_for_a_description_are_held_by_rank_whatever_the_order() -> Result<(), String>
    {
        let simulation = sim::run(&scenario(17, 30.0));
        let feeds = simulation.feeds().map_err(text)?;
        let three: Vec<_> = feeds.iter().take(3).collect();
        assert_eq!(three.len(), 3);
        let mut drawn: Vec<(u128, PublicKey)> = three
            .iter()
            .map(|feed| {
                let key = feed.identity.public();
                (tally_mlat::intake::draw(&key), key)
            })
            .collect();
        drawn.sort_unstable();
        let best: BTreeSet<PublicKey> = drawn[..2].iter().map(|(_, key)| *key).collect();
        let held_by = |order: &[usize]| -> Result<(BTreeSet<PublicKey>, u64), String> {
            let gauges = Gauges {
                orphans: Gauge::new(Store::Orphans, 64 << 20),
                ..Gauges::unlimited()
            };
            let host = HostedMlat::charging(
                identity(),
                BOOT,
                Settings {
                    capacity: Capacity::for_receivers(2),
                    ..settings()
                },
                gauges.clone(),
            )?;
            host.set_areas(areas()?, Vec::new());
            for at in order {
                for batch in three[*at].batches.iter().take(3) {
                    let stamp = batch.content().map_err(text)?.wall_ms;
                    offer(&host, &Record::Batch(batch.clone()), stamp);
                }
            }
            let mut held = BTreeSet::new();
            for feed in &three {
                let key = feed.identity.public();
                if !host.shared.orphan_batches().take(&key).is_empty() {
                    held.insert(key);
                }
            }
            Ok((held, gauges.orphans.refused()))
        };
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            assert_eq!(held_by(&order)?, (best.clone(), 0), "{order:?}");
        }
        Ok(())
    }

    /// Sweep 3, N17: a receiver re-signing its description in a loop holds one description a step,
    /// the newest it signed, charged by its bytes and let go when it is applied; an older one
    /// offered after it changes nothing, and the one applied is the newest.
    #[test]
    fn a_receiver_re_signing_in_a_loop_holds_one_description_a_step_and_the_newest_applies()
    -> Result<(), String> {
        let simulation = sim::run(&scenario(17, 30.0));
        let feed = simulation
            .feeds()
            .map_err(text)?
            .into_iter()
            .next()
            .ok_or("no feed")?;
        let key = feed.identity.public();
        let gauges = Gauges {
            orphans: Gauge::new(Store::Orphans, 64 << 20),
            ..Gauges::unlimited()
        };
        let host = HostedMlat::charging(identity(), BOOT, settings(), gauges.clone())?;
        host.set_areas(areas()?, Vec::new());
        // The engine's first step: from it on, a description waits for its own.
        let now = feed.batches[0].content().map_err(text)?.wall_ms;
        offer(&host, &Record::Batch(feed.batches[0].clone()), now);
        let step = step_of(now);
        host.take_published(step);
        handled(&host);
        let content = feed.info.content().map_err(text)?;
        let signed = |issued_ms: u64| -> Result<ReceiverInfo, String> {
            ReceiverInfo::sign(
                &feed.identity,
                &tally_wire::batch::ReceiverInfoContent {
                    issued_ms,
                    ..content.clone()
                },
            )
            .map_err(text)
        };
        let base = content.issued_ms;
        for n in 1..=50 {
            host.offer_description(&signed(base + n)?, step + 100);
        }
        let newest = signed(base + 50)?;
        // Older, after it: nothing changes.
        host.offer_description(&signed(base + 10)?, step + 200);
        {
            let room = host.shared.waiting_room();
            let pending: Vec<&Pending> = room.pending.values().flat_map(BTreeMap::values).collect();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].info.as_bytes(), newest.as_bytes());
        }
        assert_eq!(
            host.shared.waiting_room().share.held(),
            newest.as_bytes().len()
        );
        // Applied at its step: let go, and the receiver stands as the newest says.
        host.take_published(step + STEP_MS);
        handled(&host);
        assert!(host.shared.waiting_room().pending.is_empty());
        assert_eq!(host.shared.waiting_room().share.held(), 0);
        assert_eq!(host.shared.shard(&key).intake.described(&key), Some(true));
        Ok(())
    }

    /// The receiver of a record a feeder signed, if it is a batch or a description.
    fn receiver_of(record: &Record) -> Option<PublicKey> {
        match record {
            Record::Batch(batch) => batch.receiver().ok(),
            Record::ReceiverInfo(info) => info.receiver().ok(),
            _ => None,
        }
    }

    /// Sweep 4, R-P5: a batch that waited for its receiver's description is judged ahead or late by
    /// its own stamp, as the reference engine judges it, not by the stamp of the step that took
    /// it: a receiver whose clock runs a second and a half ahead of its stamp, described only
    /// after its batch came, has that batch's raw refused as ahead by both, and the bin it names is
    /// the reference's, byte for byte.
    #[test]
    fn a_batch_that_waited_for_its_description_is_judged_by_its_own_stamp() -> Result<(), String> {
        use tally_mlat_solver::scope::{GRID_MS, bin_of};
        let mut simulation = sim::run(&scenario(17, 60.0));
        let plain = arrivals(&mut simulation, 3)?;
        let first = plain.first().map(|(at, _)| *at).ok_or("no raw")?;
        let feed = simulation
            .feeds()
            .map_err(text)?
            .into_iter()
            .next()
            .ok_or("no feed")?;
        let key = feed.identity.public();
        // One batch of its, midway, with raw MLAT holds.
        let mut chosen = None;
        for batch in &feed.batches {
            let content = batch.content().map_err(text)?;
            let used = content.observations.iter().any(|observation| {
                observation.data.len() <= 14 && tally_mlat_solver::held::wanted(&observation.data)
            });
            if used && content.wall_ms > first + 20_000 {
                chosen = Some((batch.clone(), content.wall_ms));
                break;
            }
        }
        let (batch, wall) = chosen.ok_or("no batch midway")?;
        // Stamped 1.5 s before its bin begins (ahead by its own stamp, `held::AHEAD_MS`), and
        // described half a second before it: the step that applies the description, at the bin's
        // start, would take it as not ahead.
        let start = wall / GRID_MS * GRID_MS;
        let mut changed: Vec<(u64, Record)> = plain
            .iter()
            .filter(|(_, record)| receiver_of(record) != Some(key))
            .cloned()
            .collect();
        changed.push((start - 1_500, Record::Batch(batch)));
        changed.push((start - 500, Record::ReceiverInfo(feed.info.clone())));
        changed.sort_by_key(|(at, _)| *at);
        // Past the next window step that solves, which reports what the shards refused.
        let until = start + 45_000;
        let areas = areas()?;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas.clone(), Vec::new());
        drive(&host, &changed, first, until);
        let mut engine = Engine::new(identity(), BOOT, settings());
        engine.set_scope(area::border_band(&areas), areas.clone());
        replay(&mut engine, &changed, STEP_MS, until)?;
        let bin = bin_of(wall);
        let hosted = host.sealed_bins().ok_or("no sealed bins")?.get(bin);
        let reference = engine.sealed_bins().get(bin);
        assert!(reference.is_some(), "bin {bin} not sealed");
        assert!(
            hosted
                .as_ref()
                .is_some_and(|held| held.receiver(&key).is_none()),
            "the batch's raw was held"
        );
        assert!(hosted == reference, "bin {bin}");
        assert!(host.report().observations_ahead > 0, "{:?}", host.report());
        Ok(())
    }

    /// Sweep 4, R-P15: batches waiting for a step's descriptions (a host behind on its watermark)
    /// are held by rank: with room for two receivers' batches, those of the two best drawn of three
    /// are held whatever the order they came in, the third's let go (counted), and the share is
    /// never charged past.
    #[test]
    fn batches_waiting_for_a_steps_descriptions_are_held_by_rank_whatever_the_order()
    -> Result<(), String> {
        const SEEDS: [u8; 3] = [21, 22, 23];
        const EACH: u64 = 3;
        let key = |seed: u8| Identity::from_seed([seed; 32]).public();
        let mut drawn: Vec<(u128, PublicKey)> = SEEDS
            .iter()
            .map(|seed| (tally_mlat::intake::draw(&key(*seed)), key(*seed)))
            .collect();
        drawn.sort_unstable();
        let best: BTreeSet<PublicKey> = drawn[..2].iter().map(|(_, key)| *key).collect();
        let footprint = told(SEEDS[0], 1, 0)?.footprint();
        // A store whose share for what waits holds two receivers' batches and not a third's.
        let mut limit = 7 * EACH as usize * footprint;
        while Room::of(limit).waiting >= (2 * EACH as usize + 1) * footprint {
            limit -= 1;
        }
        let room = Room::of(limit).waiting;
        assert!(
            room >= 2 * EACH as usize * footprint,
            "{room} of {footprint}"
        );
        let held_by = |order: &[usize]| -> Result<(BTreeSet<PublicKey>, u64, u64), String> {
            let gauges = Gauges {
                orphans: Gauge::new(Store::Orphans, limit),
                ..Gauges::unlimited()
            };
            let host = HostedMlat::charging(
                identity(),
                BOOT,
                Settings {
                    capacity: Capacity::for_receivers(2),
                    ..settings()
                },
                gauges.clone(),
            )?;
            host.set_areas(areas()?, Vec::new());
            // The engine's first step: from it on, a batch stamped past it waits for its step.
            let now = 1_000 * STEP_MS + 300;
            host.offer_batch(&told(9, 1, now)?, now);
            let step = step_of(now);
            host.take_published(step);
            handled(&host);
            for at in order {
                for sequence in 1..=EACH {
                    let stamp = step + 1_500;
                    host.offer_batch(&told(SEEDS[*at], sequence, stamp)?, stamp);
                }
            }
            let held = host.shared.waiting_room().holders.keys().copied().collect();
            let share = host.shared.waiting_room().share.clone();
            assert!(share.peak() <= share.limit());
            Ok((held, share.refused(), host.report().waiting_dropped))
        };
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            assert_eq!(held_by(&order)?, (best.clone(), 0, EACH), "{order:?}");
        }
        Ok(())
    }

    /// Sweep 4, R-P16, and sweep 5, R2: a provisional step's records are late by the stamps alone,
    /// as the live world they are for is sealed. Taken while the watermark is short of
    /// `PROVISIONAL_PUBLISH_MS` past their step, they are published however long the step ran on
    /// the wall clock (one here slowed past the publish slot); taken once the watermark has passed
    /// it, they would reach the live world after its second is sealed, and are refused whole and
    /// counted; every other step's are the reference's, byte for byte (the late step's state
    /// applied all the same). Before, a step was late by the wall clock from its turn to its run's
    /// end: the watermark's lag and the wait to be taken went unseen, and a test's verdict was its
    /// machine's speed.
    #[test]
    fn a_provisional_steps_records_taken_past_their_slot_are_refused_whole_by_the_stamps()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let areas = areas()?;
        let mut engine = Engine::new(identity(), BOOT, settings());
        engine.set_scope(area::border_band(&areas), areas.clone());
        let reference = replay(&mut engine, &delivered, STEP_MS, until)?;
        let solving: BTreeSet<u64> = reference
            .iter()
            .filter(|(_, record)| matches!(record, Record::Provisional(_)))
            .map(|(at, _)| *at)
            .collect();
        // The first step that solves provisionals runs slow; the second's are taken late.
        let mut solving = solving.into_iter();
        let (slow, late) = solving
            .next()
            .zip(solving.next())
            .ok_or("too few provisionals")?;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas, Vec::new());
        let armed = Arc::new(AtomicBool::new(false));
        let arming = Arc::clone(&armed);
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == Stage::Provisional && arming.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(
                    PROVISIONAL_PUBLISH_MS + 600,
                ));
            }
        }));
        let mut next = 0;
        let mut hosted = Vec::new();
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            armed.store(step == slow, Ordering::SeqCst);
            hosted.extend(host.take_published(step));
            quiet(&host);
            if step == late {
                // Asked again only once the watermark is at its slot's end.
                hosted.extend(host.take_published(step + PROVISIONAL_PUBLISH_MS));
            }
            hosted.extend(host.take_published(step));
        }
        let refused = reference
            .iter()
            .filter(|(at, record)| *at == late && matches!(record, Record::Provisional(_)))
            .count();
        let expected: Vec<&Record> = reference
            .iter()
            .filter(|(at, record)| *at != late && matches!(record, Record::Provisional(_)))
            .map(|(_, record)| record)
            .collect();
        let made: Vec<&Record> = hosted
            .iter()
            .filter(|record| matches!(record, Record::Provisional(_)))
            .collect();
        assert_eq!(encoded(&made)?, encoded(&expected)?);
        let report = host.report();
        assert_eq!(
            (
                report.provisional_steps_late,
                report.provisional_records_late
            ),
            (1, refused as u64),
            "{report:?}"
        );
        Ok(())
    }

    /// Sweep 4, N3: receivers that leave are forgotten in the sealed bins off the engine's thread,
    /// as background work below the stages (each bin re-sealed once for all of them), and the bins
    /// are the reference's, byte for byte.
    #[test]
    fn receivers_that_leave_are_forgotten_off_the_engines_thread_below_the_stages()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let plain = arrivals(&mut simulation, 3)?;
        let changed = tally_mlat::replay::described_midway(&simulation, &plain)?;
        let first = changed.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = changed.last().map_or(0, |(at, _)| *at) + 30_000;
        let areas = areas()?;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas.clone(), Vec::new());
        // Each forget's nice value and thread name.
        type Seen = Arc<Mutex<Vec<(libc::c_int, Option<String>)>>>;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let seeing = Arc::clone(&seen);
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == Stage::Forget
                && let Ok(mut seen) = seeing.lock()
            {
                seen.push((own_nice(), std::thread::current().name().map(str::to_owned)));
            }
        }));
        drive(&host, &changed, first, until);
        let base = own_nice();
        let seen = seen.lock().map(|seen| seen.clone()).unwrap_or_default();
        assert!(!seen.is_empty(), "no receiver was forgotten");
        for (nice, name) in &seen {
            assert_eq!(*nice, (base + BACKGROUND_NICE).min(LOWEST_NICE), "{seen:?}");
            assert_eq!(name.as_deref(), Some("tally-mlat-seal"), "{seen:?}");
        }
        let mut engine = Engine::new(identity(), BOOT, settings());
        engine.set_scope(area::border_band(&areas), areas.clone());
        replay(&mut engine, &changed, STEP_MS, until)?;
        let hosted = host.sealed_bins().ok_or("no sealed bins")?;
        let reference = engine.sealed_bins();
        assert_eq!(hosted.numbers(), reference.numbers());
        for bin in reference.numbers() {
            assert!(hosted.get(bin) == reference.get(bin), "bin {bin}");
        }
        Ok(())
    }

    /// Sweep 4, N9: seals, window steps, forgets and provisional steps together never work on more
    /// threads than the plan gives MLAT: on one, no two of them are ever at work at once, however
    /// the watermark runs ahead of them (before, each kind took the plan's threads of its own).
    #[test]
    fn every_kind_of_mlat_work_together_runs_on_the_planned_threads() -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let plain = arrivals(&mut simulation, 3)?;
        let changed = tally_mlat::replay::described_midway(&simulation, &plain)?;
        let first = changed.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = changed.last().map_or(0, |(at, _)| *at) + 30_000;
        let host = HostedMlat::new(
            identity(),
            BOOT,
            Settings {
                threads: 1,
                ..settings()
            },
        )?;
        host.set_areas(areas()?, Vec::new());
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let (counting, peak) = (Arc::clone(&running), Arc::clone(&most));
        host.delaying(Arc::new(move |stage: Stage| {
            if matches!(
                stage,
                Stage::Seal | Stage::Window | Stage::Provisional | Stage::Forget
            ) {
                let now = counting.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(5));
                counting.fetch_sub(1, Ordering::SeqCst);
            }
        }));
        let mut next = 0;
        for step in steps(first, until) {
            while let Some((at, record)) = changed.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            host.take_published(step);
            handled(&host);
        }
        quiet(&host);
        let report = host.report();
        assert!(
            report.steps > 0 && report.provisional_steps > 0,
            "{report:?}"
        );
        assert_eq!(most.load(Ordering::SeqCst), 1, "{report:?}");
        assert_eq!(host.busiest(), 1);
        Ok(())
    }

    /// A gate a test opens once, telling it when something waits there.
    struct Held {
        gate: Arc<Gate>,
        waiting: AtomicBool,
    }

    /// Sweep 4, N16: a provisional step holds no lock the engine's thread waits on while it works:
    /// held between deciding what it keeps and keeping it, the engine's thread still drops the
    /// engine (which empties what the step charged) at once.
    #[test]
    fn a_provisional_step_at_work_holds_no_lock_the_engines_thread_waits_on() -> Result<(), String>
    {
        a_provisional_step_held_at(Stage::Weighing)
    }

    /// Sweep 5, R9: nor while it reads an address shard, holding it: the engine's thread drops the
    /// engine without waiting on the shard (before, it cleared every shard itself, so it waited
    /// on each pass a provisional step made over them).
    #[test]
    fn a_provisional_step_reading_an_address_shard_holds_up_no_engine_drop() -> Result<(), String> {
        a_provisional_step_held_at(Stage::Reading)
    }

    /// A provisional step held at `at`, once receptions wait, while the areas are withdrawn: the
    /// engine's thread does that at once.
    fn a_provisional_step_held_at(at: Stage) -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 30.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at);
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        let held = Arc::new(Held {
            gate: Gate::shut(),
            waiting: AtomicBool::new(false),
        });
        let armed = Arc::new(AtomicBool::new(false));
        let (holding, arming) = (Arc::clone(&held), Arc::clone(&armed));
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == at && arming.load(Ordering::SeqCst) {
                holding.waiting.store(true, Ordering::SeqCst);
                holding.gate.pass();
            }
        }));
        let mut next = 0;
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            // Once receptions wait, every provisional step weighs: the next is held.
            if host.shared.receptions_waiting.load(Ordering::SeqCst) > 0 {
                armed.store(true, Ordering::SeqCst);
            }
            host.take_published(step);
            // Until it is done, or the step armed is held.
            while host.in_flight() > 0 && !held.waiting.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            if held.waiting.load(Ordering::SeqCst) {
                break;
            }
        }
        let since = std::time::Instant::now();
        while !held.waiting.load(Ordering::SeqCst) {
            assert!(
                since.elapsed() < std::time::Duration::from_secs(60),
                "none held"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // No area: the engine and everything it charged go, on the engine's thread.
        host.set_areas(Regions::default(), Vec::new());
        let since = std::time::Instant::now();
        while host.shared.commands.load(Ordering::SeqCst) > 0 {
            assert!(
                since.elapsed() < std::time::Duration::from_secs(10),
                "the engine's thread waits on the provisional step"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        held.gate.open();
        quiet(&host);
        Ok(())
    }

    /// Sweep 4, N17: a window step's outcome is charged until it is applied: the working set's
    /// charge travels with it, so one waiting for the engine's thread is never outside every store.
    #[test]
    fn a_window_steps_outcome_is_charged_until_it_is_applied() -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 30_000;
        let gauges = Gauges {
            engine: Gauge::new(Store::Engine, usize::MAX),
            ..Gauges::unlimited()
        };
        let host = HostedMlat::charging(identity(), BOOT, settings(), gauges.clone())?;
        host.set_areas(areas()?, Vec::new());
        let seen: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let (seeing, engine) = (Arc::clone(&seen), Arc::clone(&gauges.engine));
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == Stage::Apply
                && let Ok(mut seen) = seeing.lock()
            {
                seen.push(engine.held());
            }
        }));
        drive(&host, &delivered, first, until);
        let working = Capacity::default()
            .receivers
            .saturating_mul(SOLVE_BYTES_PER_RECEIVER);
        let seen = seen.lock().map(|seen| seen.clone()).unwrap_or_default();
        assert!(!seen.is_empty(), "no window step was applied");
        assert!(
            seen.iter().all(|held| *held >= working),
            "{seen:?} of {working}"
        );
        Ok(())
    }

    /// Sweep 4, N18: an idle host costs nothing: its engine's thread wakes for no message, and a
    /// step with nothing to weigh, seal or solve takes no thread.
    #[test]
    fn an_idle_host_wakes_for_nothing_and_steps_with_nothing_on_no_thread() -> Result<(), String> {
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        handled(&host);
        let woke = host.shared.wakeups.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert_eq!(host.shared.wakeups.load(Ordering::SeqCst), woke);
        // A batch with nothing MLAT holds sets where its steps begin; each step finds nothing.
        let stamp = 1_000 * STEP_MS + 300;
        host.offer_batch(&told(9, 1, stamp)?, stamp);
        for step in steps(stamp, stamp + 10 * STEP_MS) {
            host.take_published(step);
            quiet(&host);
        }
        let report = host.report();
        assert!(report.provisional_steps >= 10, "{report:?}");
        assert_eq!(host.shared.handed.load(Ordering::SeqCst), 0, "{report:?}");
        Ok(())
    }

    /// Sweep 5, R10: an ask wakes the engine's thread only for a step the watermark passed that no
    /// ask handed it yet, and never with no area to solve: a relay asking ten times a step, or an
    /// MLAT relay for nothing, costs it nothing (before, every ask woke it).
    #[test]
    fn asks_wake_the_engines_thread_once_a_step_and_never_with_no_area() -> Result<(), String> {
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        let wakeups = || host.shared.wakeups.load(Ordering::SeqCst);
        handled(&host);
        let woke = wakeups();
        for ask in 0..50 {
            host.take_published(1_000 * STEP_MS + ask * 100);
        }
        handled(&host);
        assert_eq!(wakeups(), woke);
        host.set_areas(areas()?, Vec::new());
        handled(&host);
        let woke = wakeups();
        // Fifty asks over five steps.
        for ask in 0..50 {
            host.take_published(2_000 * STEP_MS + ask * 100);
        }
        handled(&host);
        assert_eq!(wakeups() - woke, 5);
        Ok(())
    }

    /// Sweep 5, R7: MLAT's work runs on runners started with the host, each lowered below the
    /// stages as it starts; a relay already at the lowest priority, where nothing goes lower, has
    /// every one of them counted (before, a step's thread set nice 19 and called it lowered).
    #[test]
    fn a_relay_at_the_lowest_priority_counts_every_mlat_runner_level_with_its_stages()
    -> Result<(), String> {
        // On a thread of its own, whose nice value is its own to lower.
        let unset = std::thread::spawn(|| -> Result<u64, String> {
            lower_own(LOWEST_NICE);
            assert_eq!(own_nice(), LOWEST_NICE);
            let host = HostedMlat::new(identity(), BOOT, settings())?;
            Ok(host.report().priority_unset)
        })
        .join()
        .map_err(|_| "the relay's thread panicked".to_owned())??;
        assert_eq!(unset, 3);
        Ok(())
    }

    /// The part of MLAT a panic test's child makes panic.
    const PANIC_CHILD: &str = "TALLY_MLAT_PANIC_CHILD";

    /// In the child of a panic test: a host fed a scenario past its first windows' steps, with a
    /// panic injected at `part` (`panics_at`). It returns only if the host ran on with the part
    /// that panicked gone, its steps in hand for ever; then the child ends cleanly, which the
    /// parent refuses.
    fn panicking_host(part: &str) -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        let part = part.to_owned();
        host.delaying(Arc::new(move |stage: Stage| {
            let thread = std::thread::current();
            match part.as_str() {
                // A seal's runner.
                "seal" => assert!(stage != Stage::Seal, "a seal panics"),
                // A worker a provisional step's pass spreads its address shards over
                // (`gate::on_threads`): a thread of no name, never the runner itself.
                "worker" => assert!(
                    !(stage == Stage::Reading && thread.name().is_none()),
                    "a gate worker panics"
                ),
                // The engine's thread, applying a window step's outcome.
                "engine" => assert!(
                    !(stage == Stage::Apply && thread.name() == Some("tally-mlat")),
                    "the engine's thread panics"
                ),
                _ => {}
            }
        }));
        let mut next = 0;
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            host.take_published(step);
            handled(&host);
        }
        let since = std::time::Instant::now();
        while host.in_flight() > 0 && since.elapsed() < std::time::Duration::from_secs(20) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }

    /// Runs `test` again as a child whose host panics at `part`, and holds that the child ended by
    /// `SIGABRT`: MLAT that panicked ended the process rather than running on without the part.
    fn ends_the_process(test: &str, part: &str) -> Result<(), String> {
        if let Some(part) = std::env::var_os(PANIC_CHILD) {
            return panicking_host(&part.to_string_lossy());
        }
        let status = std::process::Command::new(std::env::current_exe().map_err(text)?)
            .args(["--exact", test, "--test-threads=1"])
            .env(PANIC_CHILD, part)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(text)?;
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGABRT), "{part}: {status:?}");
        Ok(())
    }

    /// Sweep 5, N7: MLAT work that panics ends the process, as a panic anywhere in the relay does
    /// (`crate::abort_on_any_panic`), whether or not the relay's hook is set: a host whose seal
    /// panicked never runs on with its steps waiting for a report that never comes (before, the
    /// seal's thread ended and MLAT stalled for good, silently). Run in a child of this test.
    #[test]
    fn a_panic_in_mlat_work_ends_the_process() -> Result<(), String> {
        ends_the_process(
            "mlat_host::tests::a_panic_in_mlat_work_ends_the_process",
            "seal",
        )
    }

    /// Sweep 6, F13 (N7): a panic on a worker a step's pass spreads its items over is its step's
    /// (`gate::on_threads` resumes it on the runner), so it ends the process as the runner's own
    /// would: no pass swallows a worker's panic and reports a step it did not finish.
    #[test]
    fn a_panic_on_a_gate_worker_ends_the_process() -> Result<(), String> {
        ends_the_process(
            "mlat_host::tests::a_panic_on_a_gate_worker_ends_the_process",
            "worker",
        )
    }

    /// Sweep 6, F13 (N7): a panic on the engine's thread ends the process: before nothing would
    /// show it, every later ask going to a thread that was gone and MLAT publishing nothing more.
    #[test]
    fn a_panic_on_the_engines_thread_ends_the_process() -> Result<(), String> {
        ends_the_process(
            "mlat_host::tests::a_panic_on_the_engines_thread_ends_the_process",
            "engine",
        )
    }

    /// Sweep 5, H-b: what a seal refuses for room is counted when the seal finishes, never held
    /// for the next window step to report, so none is lost when the engine goes before one runs
    /// (before, it waited in the engine, and went with it).
    #[test]
    fn what_a_seal_refuses_is_counted_when_it_finishes_whatever_becomes_of_its_engine()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 30.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at);
        // A `Held` store with room for nothing: every bin a seal makes is refused.
        let gauges = Gauges {
            held: Gauge::new(Store::Held, 1),
            ..Gauges::unlimited()
        };
        let host = HostedMlat::charging(identity(), BOOT, settings(), gauges)?;
        host.set_areas(areas()?, Vec::new());
        drive(&host, &delivered, first, until);
        let report = host.report();
        assert_eq!(report.steps, 0, "{report:?}");
        assert!(report.observations_refused > 0, "{report:?}");
        host.set_areas(Regions::default(), Vec::new());
        quiet(&host);
        assert_eq!(
            host.report().observations_refused,
            report.observations_refused
        );
        Ok(())
    }

    /// Sweep 5, N13: a receiver's newer description in place of its older one for the same step
    /// is charged what it adds, never both at once: in a share that holds the older and the newer
    /// but not the two together, the newer is held and the older let go, as the reference applies
    /// the newer (before, the newer was charged whole beside the older, refused, and the older
    /// applied).
    #[test]
    fn a_newer_description_in_place_of_an_older_is_charged_only_what_it_adds() -> Result<(), String>
    {
        let simulation = sim::run(&scenario(17, 30.0));
        let feed = simulation
            .feeds()
            .map_err(text)?
            .into_iter()
            .next()
            .ok_or("no feed")?;
        let key = feed.identity.public();
        let content = feed.info.content().map_err(text)?;
        let signed = |issued_ms: u64| -> Result<ReceiverInfo, String> {
            ReceiverInfo::sign(
                &feed.identity,
                &tally_wire::batch::ReceiverInfoContent {
                    issued_ms,
                    ..content.clone()
                },
            )
            .map_err(text)
        };
        let older = signed(content.issued_ms + 1)?;
        let newer = signed(content.issued_ms + 2)?;
        let (old_bytes, new_bytes) = (older.as_bytes().len(), newer.as_bytes().len());
        let share = Gauge::new(Store::Orphans, new_bytes.max(old_bytes) + old_bytes / 2);
        let mut room = WaitingRoom::new(
            Seats::new(1),
            1,
            Arc::clone(&share),
            Gauge::unlimited(Store::Orphans),
        );
        let step = 1_000 * STEP_MS;
        assert_eq!(room.hold_description(step, key, step - 500, &older), 0);
        assert_eq!(room.hold_description(step, key, step - 400, &newer), 0);
        let pending: Vec<&Pending> = room.pending.values().flat_map(BTreeMap::values).collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].info.as_bytes(), newer.as_bytes());
        assert_eq!(share.held(), new_bytes);
        assert_eq!(
            room.holders.get(&key).map(|holder| holder.bytes),
            Some(new_bytes)
        );
        drop(room);
        assert_eq!(share.held(), 0);
        Ok(())
    }

    /// Sweep 5, N8: a window step put off at the step its window falls due (the `Engine` store
    /// full then) waits and starts once it can, its windows handed out as of its own step: no
    /// provisional step runs before they are solved as though they had been, and the models ripen
    /// by their own window's step, so every byte is the reference's (before, the step put off was
    /// counted done, its windows solved by the next step's and ripened by it, and a provisional
    /// step between ran without models the reference has).
    #[test]
    fn a_window_step_put_off_solves_its_windows_as_of_its_own_step() -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let areas = areas()?;
        let mut engine = Engine::new(identity(), BOOT, settings());
        engine.set_scope(area::border_band(&areas), areas.clone());
        let reference = replay(&mut engine, &delivered, STEP_MS, until)?;
        // The step the first window that publishes falls due at.
        let due = reference
            .iter()
            .find(|(_, record)| matches!(record, Record::ClockModel(_) | Record::Positions(_)))
            .map(|(at, _)| *at)
            .ok_or("no window solved")?;
        let gauges = Gauges {
            engine: Gauge::new(Store::Engine, usize::MAX / 2),
            ..Gauges::unlimited()
        };
        let host = HostedMlat::charging(identity(), BOOT, settings(), gauges.clone())?;
        host.set_areas(areas, Vec::new());
        let working = Capacity::default()
            .receivers
            .saturating_mul(SOLVE_BYTES_PER_RECEIVER);
        let mut next = 0;
        let mut hosted = Vec::new();
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            // At the due step the store has room for anything but a window step's working set.
            let block = (step == due)
                .then(|| {
                    let free = gauges.engine.limit() - gauges.engine.held();
                    gauges.engine.try_charge(free - working + 1)
                })
                .flatten();
            hosted.extend(
                host.take_published(step)
                    .into_iter()
                    .map(|record| (step, record)),
            );
            if block.is_some() {
                let since = std::time::Instant::now();
                while host.report().windows_deferred == 0 {
                    assert!(
                        since.elapsed() < std::time::Duration::from_secs(60),
                        "nothing put off"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                handled(&host);
                drop(block);
            } else {
                quiet(&host);
            }
            hosted.extend(host.take_signed().into_iter().map(|record| (step, record)));
        }
        quiet(&host);
        hosted.extend(host.take_signed().into_iter().map(|record| (until, record)));
        let (hosted_provisional, hosted_final) = streams(&hosted);
        let (reference_provisional, reference_final) = streams(&reference);
        assert_eq!(encoded(&hosted_final)?, encoded(&reference_final)?);
        assert_eq!(
            encoded(&hosted_provisional)?,
            encoded(&reference_provisional)?
        );
        let report = host.report();
        assert_eq!(
            (
                report.windows_deferred,
                report.steps_shed,
                report.provisional_models_late,
                report.provisional_steps_shed
            ),
            (1, 0, 0, 0),
            "{report:?}"
        );
        Ok(())
    }

    /// Sweep 6, N1/F7: the stamps' keep (`kept_by_stamps`) is what `Engine::forget_by` keeps with
    /// no floor, at every step; and it keeps every bin of a window until `MODELS_RIPEN_MS` after
    /// the window falls due, so a window step that starts at its turn and finishes within the
    /// ripening (a host within its plan) never leaves a bin to its floor alone.
    #[test]
    fn the_stamps_keep_what_the_engine_keeps_with_no_floor_and_a_planned_window_its_bins() {
        let engine_at =
            |sealed: &SealedBins| Engine::hosted(identity(), BOOT, settings(), sealed.clone());
        let base = 1_000_000 * STEP_MS;
        for n in 0..200 {
            let step = base + n * STEP_MS;
            let sealed = SealedBins::new();
            for bin in bin_of(step) - 80..=bin_of(step) {
                sealed.insert(Bin::seal_from(bin, vec![Fragment::new(bin)], 1));
            }
            let mut engine = engine_at(&sealed);
            let settled = engine.settled(step);
            engine.forget_by(step, settled, i64::MAX);
            assert_eq!(
                sealed.numbers().first().copied(),
                Some(kept_by_stamps(step, settled)),
                "at {step}"
            );
        }
        let engine = engine_at(&SealedBins::new());
        let mut before = engine.settled(base);
        for n in 1..400 {
            let step = base + n * STEP_MS;
            let settled = engine.settled(step);
            // Each window whose last bin this step settles (`AFTER` past a multiple of the stride).
            for last in (before + 1..=settled).filter(|bin| (bin - AFTER).rem_euclid(STRIDE) == 0) {
                let window = Window::canonical(last - AFTER);
                assert_eq!(window.last, last);
                let ripe = step + MODELS_RIPEN_MS;
                assert!(
                    kept_by_stamps(ripe, engine.settled(ripe)) <= window.first,
                    "{window:?} due at {step}"
                );
            }
            before = settled;
        }
    }

    /// Sweep 6, N1/F7: what a seal refuses for room is the stamps' alone. A host whose window step
    /// is held long past its turn (its floor keeping the bins the stamps forgot, `Engine::forget_by`)
    /// in a `Held` store exactly as large as a host keeping up ever filled seals every bin as that
    /// host does, byte for byte, step by step, and refuses nothing it does not: the bins only the
    /// floor keeps yield their room to the stamps', oldest first, counted. Before, a seal's room was
    /// the store less every sealed bin, the floor's included, so the held host sealed receivers out
    /// of bins the other held, and two relays of one area sealed different raw.
    #[test]
    fn a_seals_room_is_the_stamps_whatever_a_waiting_window_steps_floor_keeps() -> Result<(), String>
    {
        let mut simulation = sim::run(&scenario(17, 240.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at);
        let areas = areas()?;
        let threads = Settings {
            threads: 3,
            ..settings()
        };
        // A host keeping up: its sealed bins at every step, and the most its `Held` store held.
        let keeping = Gauges::unlimited();
        let reference = HostedMlat::charging(identity(), BOOT, threads.clone(), keeping.clone())?;
        reference.set_areas(areas.clone(), Vec::new());
        let mut at_step: BTreeMap<u64, Vec<Arc<Bin>>> = BTreeMap::new();
        let mut next = 0;
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&reference, record, *at);
                next += 1;
            }
            reference.take_published(step);
            quiet(&reference);
            let sealed = reference.sealed_bins().ok_or("no sealed bins")?;
            at_step.insert(step, sealed.bins(i64::MIN, i64::MAX));
        }
        let kept = reference.report();
        assert_eq!(kept.waiting_bins_forgotten, 0, "{kept:?}");
        let limit = keeping.held.peak();
        // The same, its second window step held shut for `HELD` steps, in a store of that size.
        let gauges = Gauges {
            held: Gauge::new(Store::Held, limit),
            ..Gauges::unlimited()
        };
        let host = HostedMlat::charging(identity(), BOOT, threads, gauges.clone())?;
        host.set_areas(areas, Vec::new());
        let gate = Gate::shut();
        let shut = Arc::clone(&gate);
        let windows = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicBool::new(false));
        let (counting, holding_window) = (Arc::clone(&windows), Arc::clone(&held));
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == Stage::Window && counting.fetch_add(1, Ordering::SeqCst) == 1 {
                holding_window.store(true, Ordering::SeqCst);
                shut.pass();
            }
        }));
        const HELD: u64 = 90;
        let mut held_from = None;
        let mut compared = 0;
        let mut next = 0;
        for step in steps(first, until) {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
                offer(&host, record, *at);
                next += 1;
            }
            host.take_published(step);
            handled(&host);
            let since = std::time::Instant::now();
            while host.sealed_stepped_ms() < step {
                assert!(
                    since.elapsed() < std::time::Duration::from_secs(60),
                    "step {step} not sealed: {:?}",
                    host.report()
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            if held_from.is_none() && held.load(Ordering::SeqCst) {
                held_from = Some(step);
            }
            // Every bin the host keeping up holds, the held host holds alike.
            let hosted = host.sealed_bins().ok_or("no sealed bins")?;
            for bin in at_step.get(&step).ok_or("no reference step")? {
                assert!(
                    hosted.get(bin.bin).as_deref() == Some(&**bin),
                    "bin {} at {step}: {:?}",
                    bin.bin,
                    host.report()
                );
                compared += 1;
            }
            if held_from.is_some_and(|from| step >= from + HELD * STEP_MS) {
                break;
            }
        }
        let held_from = held_from.ok_or("no window step was held")?;
        let report = host.report();
        assert!(compared > 0);
        assert_eq!(
            report.observations_refused, kept.observations_refused,
            "held from {held_from}: {report:?}"
        );
        // The floor kept bins, and they yielded.
        assert!(report.waiting_bins_forgotten > 0, "{report:?}");
        assert!(gauges.held.peak() <= limit);
        gate.open();
        quiet(&host);
        Ok(())
    }

    /// Sweep 6, R6: the receivers one change of areas lets go are forgotten together, in one
    /// forget pass (`Command::Left` of all of them), each sealed bin that held any of them sealed
    /// again once for all of them. Before, one `Left` a receiver had the first forgotten alone in
    /// a pass of its own, every bin it held sealed twice.
    #[test]
    fn the_receivers_a_change_of_areas_lets_go_are_forgotten_in_one_pass() -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at);
        let host = HostedMlat::new(identity(), BOOT, settings())?;
        host.set_areas(areas()?, Vec::new());
        let passes = Arc::new(AtomicUsize::new(0));
        let counting = Arc::clone(&passes);
        host.delaying(Arc::new(move |stage: Stage| {
            if stage == Stage::Forget {
                counting.fetch_add(1, Ordering::SeqCst);
            }
        }));
        drive(&host, &delivered, first, until);
        let sealed = host.sealed_bins().ok_or("no sealed bins")?;
        let held = |sealed: &SealedBins| -> BTreeSet<PublicKey> {
            sealed
                .bins(i64::MIN, i64::MAX)
                .iter()
                .flat_map(|bin| bin.receivers.clone())
                .collect()
        };
        let before = held(&sealed);
        passes.store(0, Ordering::SeqCst);
        // One cell far from the receivers, outside its band: every one of them leaves, the
        // engine staying (areas remain).
        let (lat, lon) = sim::CENTRE;
        let corner = Location {
            lat_e7: ((lat - 10.0) * 1e7) as i32,
            lon_e7: ((lon - 10.0) * 1e7) as i32,
            alt_m: 0,
            precision_m: 0,
        };
        let corner = Region::containing(&corner, AREA_RESOLUTION).map_err(text)?;
        host.set_areas(Regions::new(vec![corner]), Vec::new());
        quiet(&host);
        let after = held(&sealed);
        let left = before.difference(&after).count();
        assert!(left >= 2, "{left} receivers left");
        assert_eq!(passes.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
