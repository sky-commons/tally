//! One program (RFC-0174 §2.1, §2.3): the relay runs MLAT for the areas it is an MLAT relay for,
//! in-process, through this seam. The hub offers every receiver batch and description it forwards
//! ([`MlatHost::offer_batch`], [`MlatHost::offer_description`]): its own feeders' and the raw other
//! relays pass it one hop for those areas and their border band. The network task tells the host
//! its areas ([`MlatHost::set_areas`], `selection` decides them) and takes what it signed
//! ([`MlatHost::take_published`]) into the fan-out as the relay's own, through `Hub::publish_own`.
//! The host is `tally-mlat`'s engine (`tally_mlat::engine::Engine`, RFC-0171 §3.8.1 as amended
//! 2026-10-24, "MLAT in seconds") under the relay's key, the same library and the same bytes as the
//! reference drive of it (`tally_mlat::replay`), with no network between the raw and the solver.
//! There is no engine program apart from a relay.
//!
//! - **Areas.** For areas `A` the engine holds the receivers of `A` and its border band
//!   (`tally_mlat::area::border_band`, the cells `selection` subscribes to), fits the pair model of
//!   each area of `A` and takes up only the transmissions most of whose hearers are in `A`
//!   (`tally_mlat::area::owner`), so an area's k relays fit its model and solve its transmissions
//!   and no others. A fix whose hearers are also in a neighbouring area cites that area's model,
//!   which its own relays publish: the relay's store holds it (`models::Models`, the band's
//!   models come with the band's raw), offers it here ([`MlatHost::offer_model`]), and the host
//!   hands it to the engine (`Engine::hold`) at the next step. The engine judges it only once a
//!   fix it would publish cites it: verified over the raw it holds (`Engine::verify_model`, once,
//!   the verdict kept on the model), or, where that raw cannot judge it, corroborated (two of its
//!   area's engines signed the same bytes, `models::Model::signers`); so the engine publishes a fix
//!   only when every model it cites stands so, and counts the rest
//!   (`tally_mlat::fix::Report::untrusted`), and a model no fix cites costs no verification
//!   (`models_unneeded`).
//!   A change of areas re-scopes the engine in place (`Engine::set_scope`); no area
//!   at all drops the engine and every byte of raw it held, and the next area starts a new one
//!   under a new boot id, so the relay's records never reuse a (key, boot, sequence).
//! - **One store of raw** (RFC-0181 §5). The receivers are the host's one `Intake` (who is
//!   described, who takes part, the sequences each used) over the seats (`tally_mlat::intake::Seats`),
//!   and the raw that arrived is the engine's arrived pool (`Engine::hosted`), which the relay's
//!   standing reads too ([`MlatHost::raw`]). A batch reaches the host as the relay's one decode of
//!   it: the ingest worker that decoded it reads the receptions MLAT uses out of it
//!   (`tally_mlat::intake::receptions_of`, a function of the batch alone) into the inbox of its raw
//!   shard (`exchange::raw_shard`), charged, and keeps no decode alive. Nothing on an ingest
//!   worker waits on the engine.
//! - **One step a second, by the stamp watermark, never by a clock** (RFC-0181 §4, invariants 1 to
//!   3). The relay asks with its stamp watermark ([`MlatHost::take_published`]: every batch stamped
//!   before it has been offered), the one the products seal by. The host steps at every multiple of
//!   [`STEP_MS`] the watermark passes, in order. Step `t`: first every batch stamped before `t`
//!   still in an inbox is taken, in the batches' order (`tally_mlat::fix::Order`: stamp, receiver,
//!   boot, sequence), each used once if its receiver takes part as the descriptions before it left
//!   it (`Intake::take`) and handed to the engine at its own stamp (`Engine::ingest`); then the cut
//!   in force at `t` is applied (below, Overload); then every description stamped before `t`, of
//!   each receiver only the newest it signed (`tally_mlat::intake::taking_effect`), and a receiver
//!   that stopped taking part is forgotten (`Engine::forget_by`); then the engine steps at `t`
//!   (`Engine::step`): every owned area whose turn it is refit at its edge on the refit grid
//!   (`tally_mlat::area::refit_turn`, a function of the cell: half the areas a step, so no step
//!   carries every refit), every
//!   transmission whose first reception arrived `SETTLE_MS` before solved, and the step's records published
//!   at once, the models first, then each fix raw and tagged back to back (`tally_mlat::engine::Step::records`).
//!   This is exactly what the reference drive does on the same stamps, so the same stamped trace
//!   makes the same bytes however the threads interleave or how long any stage takes.
//! - **Descriptions, at their step** (RFC-0181 §4). A receiver's description is stamped by the
//!   watermark when the relay kept it ([`MlatHost::offer_description`], never before a watermark the
//!   host was asked with) and takes effect at the step after its stamp. A batch of a receiver not
//!   described yet is held like any other (`tally_mlat::intake`, "A batch before its receiver's
//!   description"), within the room for receivers not described, so what the pool holds of a
//!   receiver never depends on when its description came; one described outside the areas lets
//!   it go, and one never described is let go once none of its batches is held any more
//!   (`Intake::expire`, each step). Before, those batches were not used, and a receiver lost its
//!   first 20 s. Before an engine runs, and when the areas change, the descriptions the relay
//!   holds are applied as they come (`set_areas`).
//! - **Threads.** One runner does MLAT's work, started with the host and living as long as it does:
//!   each step's taking, describing, refitting, solving and signing, one step at a time, in order,
//!   spread over the threads the plan gives MLAT (`Budget::mlat_threads`, `tally_mlat_solver::gate`)
//!   and below the relay's own priority (`Urgency`; one that could not be lowered all the way is
//!   counted). The relay's standing, which MLAT's positions bring (`standing::Standing::start`, on
//!   this gate, [`MlatHost::gate`]), runs on the same threads below the steps. No step holds a lock
//!   an ingest worker or the network task waits on while it works, so a host short of cores delays
//!   MLAT, which falls behind and collapses its steps (below), and never raw. MLAT work that panics
//!   ends the process, as a panic anywhere in the relay does (`EndOnUnwind`).
//! - **Behind** (RFC-0181 §9, §10). When the watermark has passed more than one step not yet run
//!   (the step before ran past its second), every one of them is taken and described in its turn,
//!   and only the newest is stepped: the others are collapsed into it, counted
//!   (`MlatReport::steps_collapsed`), and the transmissions they would have solved are solved by it,
//!   as a step that ran late solves them. Each collapsed step lets go of the raw it would have
//!   (`Engine::forget_older`) and settles the pool's charge before the next is taken, so a host
//!   behind holds what stepping each would; before (2026-10-26), a run of collapsed steps took
//!   seconds of raw in before any was let go, filled the pool, and refused batches whole. What
//!   waits to be taken is held in the inboxes, charged to the `Inbox` store (the plan holds the
//!   inbox's span, [`INBOX_MS`], of every hosted feeder's rate, seated or not: the step decides),
//!   and past the store an inbox refuses a batch's receptions whole, counted. A host falls behind only for the
//!   steps it takes to be judged (Overload): each step is judged on its taking as well as its
//!   stepping, and as every step it took in, so a backlog is cut short before it fills the store
//!   the engine's tables need. A host within its plan never collapses, so the
//!   same stamped trace still makes the same bytes; one that does not loses a second of latency,
//!   counted, and never a fix it would have solved in time.
//! - **Overload** (RFC-0181 §10). Steps that run past [`STEP_BUDGET_MS`], by the host's
//!   [`StepClock`] (a relay's the wall clock, a test's what it declares), the middle of the last
//!   [`JUDGED_STEPS`] or one alone past them all, are MLAT overloaded. A step's run is its own
//!   taking (its batches into the engine's pool, one at a time on the runner) and its stepping, and
//!   a step that took in the steps collapsed into it is judged as each of them; before
//!   (2026-10-26), only the stepping was judged, while the taking ran 0.3 to 1.8 s a step at 2,000
//!   seats, and the steps collapsed were never judged, so the host cut late and collapsed 106
//!   steps. The host cuts the receivers
//!   it solves in its areas to what that run carries within the target, at most half of them a
//!   cut, once the last change has taken effect and been refit ([`Governor`], `Host::judge`); and
//!   it lifts, a quarter at most, only once a change's seats are fitted ([`SEATS_SETTLE_MS`]) and
//!   its last [`JUDGED_STEPS`] steps all ran within seven eighths of the target. So one dear step
//!   cuts nothing, and the seats settle where steps fit rather than cutting by half and climbing
//!   back: at the target, where the plan fills MLAT's threads (`cores::MLAT_BUSY_PERCENT`), or
//!   within an eighth below it. Before (2026-10-26), it lifted only below half the budget, so a cut
//!   on one dear start-up step that landed between half the budget and the target stayed there:
//!   the world relay's load settled at 425 of 489 planned seats, its steps at 619 ms.
//!   The cut is a rank threshold, the draw of the first receiver cut
//!   (`tally_mlat::intake::draw`), never a count of seats: a [`Cut`] per area, from
//!   `CUT_LEAD_STEPS` past the watermark, published for the relays holding the same areas
//!   ([`MlatHost::take_cuts`], [`MlatHost::offer_cut`]) and announced again every `CUT_REFRESH_MS`
//!   while it stands, standing `CUT_TTL_MS` from each announcement's step, so a relay that was
//!   down, or whose link was, learns a standing cut at the next, and a cut its signer stopped
//!   announcing expires. The cut in force at a step is the least threshold of each origin's newest
//!   announcement at or before it that has not expired, per area, applied at the step like a
//!   description (`Seats::set_cutoffs`), and the best ranked few (`MIN_CUT_SEATS`) are never cut.
//!   Every relay holding an area solves exactly the receivers ranked below the threshold whatever
//!   it has described or has seats for, from the same stamped step, and makes the same bytes. A cut
//!   that arrives after its step keeps its stamp (and so its end): it takes effect at the next
//!   step, counted (`cuts_late`). The receivers cut stay described and are counted refused; a host
//!   that cut lifts its cut the same way. What a cut may
//!   say is bounded where it is taken: only the area's own MLAT relays may cut it
//!   (`Network::take_cut`), a stamp is on the step grid, unexpired and no further ahead than
//!   `CUT_AHEAD_MS`, and the table of cuts keeps the origins of the best rank and the lowest areas
//!   (`Cuts::offer`), never the first to arrive.
//! - **Capacity** (RFC-0181 §9). MLAT has its own pool of receiver seats, the count the budget
//!   plans from the cores and memory the stages leave (`capacity`, `Budget::mlat_seats`). The
//!   receivers seated are the best ranked of those described (`tally_mlat::intake::Seats`), in
//!   whatever order they came. A receiver past the seats is not hosted for MLAT (its raw still
//!   flows), refused at its description and counted. Every byte the host holds is charged to a
//!   store of the relay's budget before it is held ([`host_for`], [`Gauges`]): the inboxes to
//!   `Inbox`; the descriptions waiting for their step, and the engine's arrived pool and tables, to `Arrived`
//!   (the pool is sized relay-wide at what a holder keeps of each seat at most,
//!   `arrived::Limits::for_receivers`, with every receiver still held to its own ceiling); a step's working set while it runs, and its
//!   signed records until the relay takes them, to `Engine`; the clock models' records to
//!   `Models`. Past a store, what would grow it is refused whole and counted, never the store
//!   charged past its limit.
//! - **Counted.** Nothing offered or solved is let go silently: every drop is counted by why, and
//!   every step's report kept ([`MlatReport`], served on `--stats-listen` as `GET /mlat`).
//! - **Time.** Nothing here reads a clock but the step's own run time for overload: a batch carries
//!   its stamp and `take_published` the watermark, so the same stamped records publish the same
//!   bytes as the engine driven in line on the same steps. A watermark taken while the clock did
//!   not judge steps nothing: the steps it passed are collapsed into the one it resyncs at, counted
//!   (`MlatReport::steps_unsynced`).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tally_mlat::area;
use tally_mlat::engine::{Capacity, Engine, Ingested, Settings, Step};
use tally_mlat::fix::Order;
use tally_mlat::intake::{Intake, Seats, SiteRecord, batch_id, receptions_of, signed_order};
use tally_mlat_solver::arrived::{BYTES_PER_KEPT, BYTES_PER_RECEIVER_SLICE, Rates};
use tally_mlat_solver::gate::{self, Gate};
use tally_mlat_solver::{BatchId, Reception};
use tally_wire::budget::policy;
use tally_wire::clocks::{Moment, Mono};
use tally_wire::{Decoded, PublicKey, Record, Region, Regions, Signer};

use crate::budget::{Budget, Charge, Gauge, Store};
use crate::config::Config;
use crate::exchange::{SHARDS, raw_shard};
use crate::footprint::{Deque, Tree};

/// The MLAT a relay hosts.
pub trait MlatHost: Send + Sync {
    /// The areas to solve (plus their border band), as `selection` holds them (the fewest cells
    /// that cover them, never expanded): the receivers it holds are theirs. `descriptions` are
    /// every receiver's site-bearing record the relay holds (`Hub::site_records`), applied as they
    /// come. The relay calls this when the areas change.
    fn set_areas(&self, areas: Regions, descriptions: Vec<SiteRecord>);
    /// A receiver's site-bearing record the relay kept (its `ReceiverSite` paired with its
    /// description, or an old feeder's format 1 description: `SiteRecord`; a format 2 description
    /// alone places nobody), stamped `stamp_ms` by the relay's stamp watermark when it kept it
    /// (`Products::watermark_ms`): it takes effect at the step after its stamp (module docs,
    /// Descriptions).
    fn offer_description(&self, record: &SiteRecord, stamp_ms: u64);
    /// A receiver's batch the relay forwarded, verified and decoded once by its ingest, on the
    /// ingest worker that owns the receiver's raw shard, stamped `now_ms` (its `stamp_ms`): the
    /// receptions MLAT uses read out of it into the shard's inbox, never verified or decoded again.
    fn offer_batch(&self, batch: &Arc<Decoded>, now_ms: u64);
    /// What it signed since the last call (clock models and their parts, positions raw and tagged),
    /// in the order to publish. `watermark` is the relay's stamp watermark: every batch stamped
    /// before its monotonic time has been offered (`offer_batch` returned), the one the products
    /// seal by (`Products::watermark`), with the judging clock read with it, the two published
    /// together as one pair. The host steps by its monotonic time (module docs), never by a clock
    /// read of its own, and each step signs by the judging clock that pair names.
    fn take_published(&self, watermark: crate::products::Watermark) -> Vec<Record>;
    /// The cores it offers (what `ProviderOffer.mlat_cores` declares).
    fn cores(&self) -> u16;
    /// What it has done and let go, since it started.
    fn report(&self) -> MlatReport;
    /// The raw it holds as the relay's standing reads it (one store of raw per relay): none when
    /// it holds no raw of its own.
    fn raw(&self) -> Option<Arc<dyn crate::standing::Raw>>;
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
    /// The models it published since the last call, each its own `Arc`: the relay holds them in its
    /// store of decoded models before their manifests go out (`models::Models::insert_own`), so
    /// its own models are never decoded again.
    /// Taken before the records that carry them (`take_published`). No default: a host that
    /// publishes models and returns none of them here has its own models held nowhere (the
    /// store admits a model from the wire only from one of its area's engines), so its raw has
    /// no model to check against and its clients are sent nothing it solved.
    fn take_own_models(&self) -> Vec<OwnModel>;
    /// A model the relay's store holds (`models::Models::admit`), another engine's: a neighbouring
    /// area's, which the engine's fixes may cite once it is verified or corroborated (module docs,
    /// Areas). Offered again when another of its area's engines signs it.
    fn offer_model(&self, _model: crate::models::Model) {}
}

/// A model the hosted engine published (`MlatHost::take_own_models`): the engine's own decoded
/// model and the key that signed it.
#[derive(Clone)]
pub struct OwnModel {
    pub engine: PublicKey,
    pub model: Arc<tally_mlat::fix::Held>,
}

/// An overload cut (module docs, Overload): from step `from_ms` (a multiple of `STEP_MS`), the
/// relay `origin` asks that MLAT solve, in the `areas` named, only the receivers whose rank draw
/// (`tally_mlat::intake::draw`) is below `below`; `u128::MAX` lifts. A rank, not a count of seats:
/// every relay holding an area solves exactly the receivers ranked below it. It stands for
/// `CUT_TTL_STEPS` steps from `from_ms` and is announced again while it stands
/// (`CUT_REFRESH_STEPS`). It is a fact of the stamps, not of a clock: the cut in force at a step
/// is the least of each origin's newest announcement at or before the step that has not expired,
/// so every relay offered the same announcements solves the same receivers at the same steps and
/// makes the same bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cut {
    pub from_ms: u64,
    pub origin: PublicKey,
    pub below: u128,
    pub areas: Vec<Region>,
}

/// One step's report, as served: `tally_mlat::fix::Report`, times in milliseconds.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepReport {
    /// Transmissions taken up (due targets, new or with more receptions), and of them those taken
    /// up again with more.
    pub due: u64,
    pub grown: u64,
    /// Due targets heard by too few receivers, past their bound to leave, owned by another area's
    /// relays, of no area, or with no model of their owner to judge them.
    pub too_few: u64,
    pub late: u64,
    pub unowned: u64,
    pub unassigned: u64,
    pub unjudged: u64,
    /// Owned areas refit.
    pub refits: u64,
    /// Clock fits tried (warm and cold together, and each), and those that failed.
    pub fits: u64,
    pub fits_warm: u64,
    pub fits_cold: u64,
    pub unfitted: u64,
    pub unfitted_reason: Option<String>,
    /// Of the fits that failed, those that did not converge (`FitError::NotConverged`).
    pub not_converged: u64,
    /// Fixes whose used hearers are in an area of which no model is held verified at their edge:
    /// not published (`tally_mlat::fix::Report::unheld`).
    pub unheld: u64,
    /// Fixes past their models' edge by more than `MAX_CARRY`: not published.
    pub overcarried: u64,
    /// Neighbouring areas' models judged at the step (`tally_mlat::fix::Report::models_verified`),
    /// and those let go uncited; and the fixes not published because a model they cite was refuted
    /// or could be neither judged nor corroborated.
    pub models_verified: u64,
    pub models_refuted: u64,
    pub models_corroborated: u64,
    pub models_unneeded: u64,
    pub untrusted: u64,
    /// The models the fixes published cite, together (`tally_mlat::fix::Report::cited`).
    pub cited: u64,
    pub solved: u64,
    /// Sets grouped into no transmission, and transmissions no fix was found for.
    pub ungrouped: u64,
    pub unsolved: u64,
    /// Fixes solved and not published (`tally_mlat::fix::Report::unpublished`): never expected but
    /// for a step signed out of sync.
    pub unpublished: u64,
    pub repeated: u64,
    /// Transmissions the due sets were grouped into, and of them those never solved: another of
    /// their slot was chosen (`tally_mlat::fix::Report::backed_off`).
    pub transmissions: u64,
    pub backed_off: u64,
    /// How far past their model's edge the fixes published were (`tally_mlat::fix::CARRY_BOUNDS_MS`).
    pub carry: [u64; tally_mlat::fix::CARRY_BOUNDS_MS.len()],
    pub clock_models: u64,
    pub clock_model_parts: u64,
    pub clock_model_bytes: u64,
    /// Raw positions records (relay-only) and their tagged twins, and their bytes.
    pub positions: u64,
    pub positions_bytes: u64,
    pub tagged_positions: u64,
    pub tagged_positions_bytes: u64,
    pub fit_ms: u64,
    pub solve_ms: u64,
    pub elapsed_ms: u64,
    /// What the governor judges the step by (`Host::judge`): its own taking and its stepping, on
    /// the host's clock (`elapsed_ms` is the stepping alone).
    pub ran_ms: u64,
}

impl StepReport {
    fn of(report: &tally_mlat::fix::Report) -> Self {
        let n = |count: usize| count as u64;
        let ms = |nanos: u64| nanos / 1_000_000;
        Self {
            due: n(report.due),
            grown: n(report.grown),
            too_few: n(report.too_few),
            late: n(report.late),
            unowned: n(report.unowned),
            unassigned: n(report.unassigned),
            unjudged: n(report.unjudged),
            refits: n(report.refits),
            fits: n(report.fits_warm + report.fits_cold),
            fits_warm: n(report.fits_warm),
            fits_cold: n(report.fits_cold),
            unfitted: n(report.unfitted),
            unfitted_reason: report.unfitted_reason.clone(),
            not_converged: n(report.not_converged),
            unheld: n(report.unheld),
            overcarried: n(report.overcarried),
            models_verified: n(report.models_verified),
            models_refuted: n(report.models_refuted),
            models_corroborated: n(report.models_corroborated),
            models_unneeded: n(report.models_unneeded),
            untrusted: n(report.untrusted),
            cited: n(report.cited),
            solved: n(report.solved),
            ungrouped: n(report.ungrouped),
            unsolved: n(report.unsolved),
            unpublished: n(report.unpublished),
            repeated: n(report.repeated),
            transmissions: n(report.transmissions),
            backed_off: n(report.backed_off),
            carry: report.carry.map(n),
            clock_models: n(report.models),
            clock_model_parts: n(report.model_parts),
            clock_model_bytes: n(report.model_bytes),
            positions: n(report.positions),
            positions_bytes: n(report.positions_bytes),
            tagged_positions: n(report.tagged_positions),
            tagged_positions_bytes: n(report.tagged_positions_bytes),
            fit_ms: ms(report.fit_ns),
            solve_ms: ms(report.solve_ns),
            elapsed_ms: u64::try_from(report.elapsed.as_millis()).unwrap_or(u64::MAX),
            ran_ms: 0,
        }
    }

    fn add(&mut self, other: &Self) {
        self.due += other.due;
        self.grown += other.grown;
        self.too_few += other.too_few;
        self.late += other.late;
        self.unowned += other.unowned;
        self.unassigned += other.unassigned;
        self.unjudged += other.unjudged;
        self.refits += other.refits;
        self.fits += other.fits;
        self.fits_warm += other.fits_warm;
        self.fits_cold += other.fits_cold;
        self.unfitted += other.unfitted;
        if self.unfitted_reason.is_none() {
            self.unfitted_reason.clone_from(&other.unfitted_reason);
        }
        self.not_converged += other.not_converged;
        self.unheld += other.unheld;
        self.overcarried += other.overcarried;
        self.models_verified += other.models_verified;
        self.models_refuted += other.models_refuted;
        self.models_corroborated += other.models_corroborated;
        self.models_unneeded += other.models_unneeded;
        self.untrusted += other.untrusted;
        self.cited += other.cited;
        self.solved += other.solved;
        self.ungrouped += other.ungrouped;
        self.unsolved += other.unsolved;
        self.unpublished += other.unpublished;
        self.repeated += other.repeated;
        self.transmissions += other.transmissions;
        self.backed_off += other.backed_off;
        for (mine, theirs) in self.carry.iter_mut().zip(other.carry) {
            *mine += theirs;
        }
        self.clock_models += other.clock_models;
        self.clock_model_parts += other.clock_model_parts;
        self.clock_model_bytes += other.clock_model_bytes;
        self.positions += other.positions;
        self.positions_bytes += other.positions_bytes;
        self.tagged_positions += other.tagged_positions;
        self.tagged_positions_bytes += other.tagged_positions_bytes;
        self.fit_ms += other.fit_ms;
        self.solve_ms += other.solve_ms;
        self.elapsed_ms += other.elapsed_ms;
        self.ran_ms += other.ran_ms;
    }
}

/// What a hosted MLAT has done and let go since it started, every drop by why (`GET /mlat`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlatReport {
    /// Batches offered while an engine runs, and of them those used (new, from a receiver taking
    /// part or not described yet) and those of a receiver taking no part (refused a seat, outside
    /// the areas, or not described with no room left for another), not used.
    pub offered: u64,
    pub ingested: u64,
    pub unused: u64,
    /// Batches whose receptions were refused whole for room: in the `Inbox` store as offered, or
    /// in the `Arrived` store as a step took them into the engine's pool (and while its tables were
    /// past it, `arrived_over`).
    pub refused: u64,
    /// Times the engine's tables grew past what the `Arrived` store holds (which a host within its
    /// plan never does): until they came down, every batch was refused (`refused`).
    pub arrived_over: u64,
    /// Receptions a threshold thinned, and those the arrived pool refused with their batch past one
    /// of its caps (`tally_mlat_solver::arrived::Refused`), with the batches.
    pub thinned: u64,
    pub observations_refused: u64,
    pub batches_refused: u64,
    /// Batches whose (boot, sequence) was already used or too far behind.
    pub replayed: u64,
    /// Receiver descriptions refused as not signed as they claim, and those not held while they
    /// waited for their step, for room (more than one a step pending for every seat, or past their
    /// share of the `Arrived` store).
    pub ingest_errors: u64,
    pub descriptions_dropped: u64,
    /// Signed records refused whole with their step's because their stores (`Engine`, `Models`)
    /// could not hold them beside those not yet taken (`PUBLISHED_BYTES_PER_SEAT`).
    pub overflowed: u64,
    /// Steps the watermark passed while the step before ran: taken and described in their turn,
    /// and stepped as one with the newest (module docs, Behind).
    pub steps_collapsed: u64,
    /// Steps the watermark passed while the relay's clock was not judging, collapsed into the one
    /// it resynced at.
    pub steps_unsynced: u64,
    /// Steps not run because the `Engine` store could not reserve their working set: their due
    /// transmissions are the next step's.
    pub steps_unreserved: u64,
    /// MLAT's runner, whose priority could not be lowered as far below the stages' as planned
    /// (`Urgency`): at the relay's own, or nearer it (a relay already near the lowest).
    pub priority_unset: u64,
    /// New receivers refused whole, beyond the receivers the engine seats
    /// (`tally_mlat::engine::Capacity`), and seated ones a better ranked one or a cut unseated.
    pub receivers_refused: u64,
    /// Overload cuts this host decided (module docs, Overload), and cuts offered too late to take
    /// effect at their step (the step was applied already: they take effect at the next).
    pub cuts_decided: u64,
    pub cuts_late: u64,
    /// Cuts offered that were not kept: expired, stamped off the grid or too far ahead, or beyond
    /// what the table holds (`Cuts::offer`).
    pub cuts_unkept: u64,
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
    /// Steps whose engine was dropped (the areas went) before they published: not published.
    pub steps_discarded: u64,
    /// Neighbouring areas' models the engine judged, each the first time a fix it would publish
    /// cited it (`tally_mlat::fix::Report::models_verified`): verified over the raw it holds,
    /// refuted, or standing on two of their area's engines' signatures where that raw cannot
    /// judge them; and those let go that no fix cited, never judged.
    pub models_verified: u64,
    pub models_corroborated: u64,
    pub models_refuted: u64,
    pub models_unneeded: u64,
    /// Steps run.
    pub steps: u64,
    /// The newest step's report, and every step's summed.
    pub last_step: Option<StepReport>,
    pub steps_total: StepReport,
}

/// The step clock's grid: the host steps at every multiple of it the watermark passes, the
/// engine's own (`tally_mlat::engine::STEP_MS`).
pub const STEP_MS: u64 = tally_mlat::engine::STEP_MS;
/// How long after the first of a transmission's receptions arrives it is solved
/// (`tally_mlat::engine::SETTLE_MS`).
pub const SETTLE_MS: u64 = tally_mlat::engine::SETTLE_MS;
/// What a step may run for (module docs, Overload): a step, so the next one starts on its turn.
/// A longer one is overload: MLAT cuts its seats.
pub const STEP_BUDGET_MS: u64 = STEP_MS;
/// What a cut aims a step at: three quarters of the budget, so the step after it has room.
pub const STEP_TARGET_MS: u64 = STEP_BUDGET_MS * 3 / 4;
// A fix's way out of its engine, from its first reception's arrival: due `SETTLE_MS` after it, taken
// up by the first step at or after that (one step at most, the watermark passing it), and published
// as that step ends, within its budget. All of that is the engine's share of the error budget,
// `FIX_SOLVE`, so a host within its budget publishes every fix within it.
const _: () = assert!(
    SETTLE_MS + STEP_MS + STEP_BUDGET_MS
        <= tally_wire::budget::FIX_SOLVE
            .span::<tally_wire::clocks::Mono>()
            .ms()
);

/// What a step's run is judged by for overload (module docs, Overload; `Host::judge`): chosen by
/// whoever builds the host, so a host's verdicts never follow how fast the machine running it
/// happens to be unless it said so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepClock {
    /// The time a step ran on the machine's clock, against [`STEP_BUDGET_MS`]: a relay's
    /// (`host_for`).
    Wall,
    /// Every step ran `ran_ms`, against a budget of `budget_ms`: a test's, whose host keeps up or
    /// is overloaded as it declares, however loaded the machine running it is.
    Declared { ran_ms: u64, budget_ms: u64 },
}

impl StepClock {
    /// A host that always keeps up: every step well within its budget, so it never cuts.
    pub const KEEPING_UP: Self = Self::Declared {
        ran_ms: 0,
        budget_ms: STEP_BUDGET_MS,
    };

    /// What a step started at `started` ran for, by this clock.
    fn ran_ms(self, started: std::time::Instant) -> u64 {
        match self {
            Self::Wall => u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            Self::Declared { ran_ms, .. } => ran_ms,
        }
    }

    /// What a step may run for before MLAT is overloaded.
    fn budget_ms(self) -> u64 {
        match self {
            Self::Wall => STEP_BUDGET_MS,
            Self::Declared { budget_ms, .. } => budget_ms,
        }
    }
}

/// Steps ahead of the watermark a cut takes effect, for the relay to publish it to its peers
/// before any of them reaches the step.
pub const CUT_LEAD_STEPS: u64 = 5;
/// The fewest receivers a cut leaves solved: the best ranked of the relay's described, which no
/// cut can unseat (`tally_mlat::intake::CUT_FLOOR_SEATS`).
pub const MIN_CUT_SEATS: usize = tally_mlat::intake::CUT_FLOOR_SEATS;
/// How long a cut stands from its step unless announced again, and the steps between a standing
/// cut's announcements (`tally_wire::cut`).
pub const CUT_TTL_MS: u64 = tally_wire::CUT_TTL_STEPS * STEP_MS;
pub const CUT_REFRESH_MS: u64 = tally_wire::CUT_REFRESH_STEPS * STEP_MS;
/// How far past the watermark a cut may be stamped: a cut for a later step is refused, so a
/// signer cannot leave a cut waiting in the table for a step far ahead.
pub const CUT_AHEAD_MS: u64 = CUT_TTL_MS;
/// What the cut table holds, a bound on memory and not a policy: origins (those of the best rank,
/// `tally_mlat::intake::draw`, are kept, never the first to come), the areas of each (the lowest
/// cells), and announcements of one area not yet in force. A cut is accepted only from an area's
/// own MLAT relays (`Network::take_cut`), which are few, so these bind nothing an honest network
/// reaches.
const CUT_ORIGINS: usize = 64;
const CUT_AREAS_PER_ORIGIN: usize = 256;
const CUTS_AHEAD_PER_AREA: usize = 8;

/// Commands for the runner not yet taken: a few seconds of asks and changes. An ask beyond it is
/// dropped; the next carries a watermark at least as new, which steps everything the dropped one
/// would have.
const COMMANDS_WAITING: usize = 1 << 12;

// What the host holds, per seat (RFC-0181, "Sizing"; module docs, Capacity). Every figure is a
// rate the plan admits over the time the host holds it, at the mean the relay's one pool is sized
// at (`tally_mlat_solver::arrived::Rates::MEASURED`), never each seat at its ceiling: the pools
// refuse past them, whole and counted, and every receiver is still held to its own ceiling.

/// The wanted receptions a seat sends a second, as planned: what its batches bring the inbox
/// before the pool thins them.
pub const PLANNED_WANTED_PER_SEC: usize = Rates::MEASURED.wanted_per_s;
/// How long a batch's receptions wait in their inbox at most for a host within its plan: the step
/// of its stamp's interval, and the one before it running. A host further behind holds more, up to
/// the room the `Arrived` store has; past it a batch is refused whole, counted.
pub const INBOX_MS: u64 = 2 * STEP_MS;
/// A receiver's description as planned while it waits for its step: descriptions are charged by
/// their bytes, what their clones allocate; a few hundred is usual. A planned size, as a feeder's
/// records are planned at `cores::RECORDS_PER_PLANNED_FEEDER`: never what a description is charged.
pub const PLANNED_DESCRIPTION_BYTES: usize = 512;
/// Descriptions a seat may have waiting for their step at once: one a step over the inbox's span
/// (`taking_effect` keeps one a receiver a step). Past it, for all the seats together, a new one is
/// refused, counted (`MlatReport::descriptions_dropped`).
pub const PENDING_PER_SEAT: usize = INBOX_MS.div_ceil(STEP_MS) as usize;

/// The batches a planned feeder sends over `ms` (`cores::RECORDS_PER_PLANNED_FEEDER` a second).
const fn planned_batches(ms: u64) -> usize {
    (crate::cores::RECORDS_PER_PLANNED_FEEDER * ms).div_ceil(1_000) as usize
}

/// What one batch's entry takes in its inbox beside its receptions: the entry, and its share of
/// the inbox's spare (`Deque::SPARE_PER_ENTRY`).
const INBOX_ENTRY_BYTES: usize = size_of::<Heard>() + Deque::<Heard>::SPARE_PER_ENTRY;
/// What one description waiting for its step takes: its entry, and its bytes at the planned size.
const PENDING_ENTRY_BYTES: usize =
    Tree::<(u64, PublicKey), Pending>::bytes_per_entry() + PLANNED_DESCRIPTION_BYTES;

/// What one planned feeder's receptions on their way in take (`Store::Inbox`): its wanted
/// receptions over [`INBOX_MS`], each list made at its length with each reception's message at a
/// long one's length (`tally_wire::modes::LONG`), and its batches' entries. Every hosted feeder's,
/// seated or not: which take part is the step's intake's to say, on the seats as that step leaves
/// them, so the same stamped trace takes the same batches whenever each was offered. Before
/// (2026-10-27) this was planned for each seat, in `Arrived`, while the inboxes held every
/// feeder's: at 2,000 feeders on 300 seats they took the seats' raw and refused 24,727 batches.
pub const INBOX_BYTES_PER_FEEDER: usize = PLANNED_WANTED_PER_SEC * INBOX_MS as usize / 1_000
    * (size_of::<Reception>() + tally_wire::modes::LONG)
    + planned_batches(INBOX_MS) * INBOX_ENTRY_BYTES;
/// What one seat's descriptions waiting for their step take, in `Arrived`: they are held for the
/// seats at most (`Descriptions::most`).
pub const PENDING_BYTES_PER_SEAT: usize = PENDING_PER_SEAT * PENDING_ENTRY_BYTES;
/// What the inboxes and the descriptions waiting hold whatever they hold: each inbox's spare
/// (`Deque::SPARE_FIXED`) and the descriptions' tree's root.
pub const INBOX_FIXED_BYTES: usize =
    SHARDS * Deque::<Heard>::SPARE_FIXED + Tree::<(u64, PublicKey), Pending>::bytes_planned(0);

/// The hashes of the considered sets solved one remembered set holds at most, beside the four a
/// vector of them first takes (`tally_mlat::fix::Solved::attempted`, one pushed for each solve of
/// a transmission of the set, [`crate::standing::FIXES_PER_TRANSMISSION`] at most a
/// transmission), for a thousand of a seat's seconds: twice those solved, as a vector grown by
/// pushing holds at most twice its length.
const ATTEMPTED_PER_SEAT_PER_KS: usize =
    2 * crate::standing::FIXES_PER_TRANSMISSION * crate::standing::PUBLISHED.solved_per_ks;
/// The marks of receptions solved the remembered sets hold for a seat a second at most
/// (`tally_mlat::fix::Solved::seen`): a mark of each reception a solve considered, each a kept
/// reception (`arrived::Rates::MEASURED`) of one set and one transmission of it, for each of the
/// transmission's solves (`standing::FIXES_PER_TRANSMISSION`), and twice that, as a vector
/// extended before it is deduplicated holds at most twice what it took.
const MARKS_PER_SEAT_PER_SEC: usize = 2
    * crate::standing::FIXES_PER_TRANSMISSION
    * tally_mlat_solver::arrived::Rates::MEASURED.kept_per_s;
/// What the engine remembers of the sets a seat's receptions fell due in
/// (`tally_mlat::fix::Solved`, one an entry for each set taken up, `backoff::Published::due_per_ks`,
/// with the hashes of what it solved of it, [`ATTEMPTED_PER_SEAT_PER_KS`], and the marks of the
/// receptions solved, [`MARKS_PER_SEAT_PER_SEC`]), over the pool's hold
/// (`tally_mlat_solver::arrived::HELD_MS`), so only a bigger set is solved again and the same set
/// never twice. Before, every kept reception was planned in a set of the fewest receivers a fix
/// cites (50 a seat a second, where 2 are taken up) and its marks not at all.
pub const SOLVED_BYTES_PER_SEAT: usize = {
    let entry =
        Tree::<tally_mlat_solver::TransmissionKey, tally_mlat::fix::Solved>::bytes_per_entry()
            + 4 * size_of::<tally_wire::batch::Hash>();
    let per_ks = crate::standing::PUBLISHED.due_per_ks * entry
        + ATTEMPTED_PER_SEAT_PER_KS * size_of::<tally_wire::batch::Hash>();
    (tally_mlat_solver::arrived::HELD_MS as usize).div_ceil(1_000)
        * (per_ks.div_ceil(1_000) + MARKS_PER_SEAT_PER_SEC * size_of::<u64>())
};
/// The edges of an owned area's models the engine holds at once: every edge a fix may still be
/// solved under (`tally_mlat::fix::usable`: `MAX_CARRY` past it), one a refit, and the newest.
pub const ENGINE_EDGES: usize =
    (tally_wire::budget::MAX_CARRY_MS / tally_wire::budget::REFIT_EVERY_MS) as usize + 1;
/// What an area's memos take for each receiver of it, at most (`tally_mlat_solver::PairCache`: what
/// its fit read last time and its network): measured with `models::MODEL_BYTES_PER_RECEIVER`
/// (`tests/tables_bytes.rs`, `an_areas_model_is_within_its_bytes_per_receiver`), the most of
/// them rounded up (212,268 on 2026-10-30, with the pair blocks of 2026-10-27). Before them
/// 130,048, and 128,000 when the read's memo hashed message hashes again
/// (`tally_mlat_solver::obs::ByDigest`): the table grows at other points.
pub const AREA_CACHE_BYTES_PER_RECEIVER: usize = 212_992;
/// What a seat's share of the engine's own models takes: its area's model at every edge it holds
/// ([`ENGINE_EDGES`]), each at most `models::MODEL_BYTES_PER_RECEIVER` for the seat, and its
/// area's memos ([`AREA_CACHE_BYTES_PER_RECEIVER`]). The models are the allocation the relay's
/// store holds too (`models::Models::insert_own`), counted here as `Engine::bytes` counts them, so
/// the `Arrived` charge is the engine's own figure; a neighbour's model it holds is the store's
/// alone (`Engine::bytes` counts only its own).
pub const WARM_MODELS_BYTES_PER_SEAT: usize =
    ENGINE_EDGES * crate::models::MODEL_BYTES_PER_RECEIVER + AREA_CACHE_BYTES_PER_RECEIVER;

/// What one seat costs the `Arrived` store: its kept receptions over the hold at the mean, in the
/// relay's one pool (`arrived::Rates::cost`), what its transmissions solved
/// ([`SOLVED_BYTES_PER_SEAT`]), its share of the warm models ([`WARM_MODELS_BYTES_PER_SEAT`]), and
/// its descriptions waiting for their step ([`PENDING_BYTES_PER_SEAT`]; the receptions on their
/// way in are every feeder's, `Store::Inbox`, [`INBOX_BYTES_PER_FEEDER`]). The engine's tables that hold
/// whatever its seats (its address shards and the aircraft they keep) are held before any feeder
/// (`budget::Plan::mlat_tables_of`). Before, the sealed raw (`Held`) was planned at each seat's kept
/// ceiling and the open raw (`Open`) at the 1,800 a second a receiver may send, which together held
/// three times what the engine keeps.
pub fn arrived_bytes_per_seat() -> usize {
    Rates::MEASURED.cost()
        + SOLVED_BYTES_PER_SEAT
        + WARM_MODELS_BYTES_PER_SEAT
        + PENDING_BYTES_PER_SEAT
}

/// A seat's share of a step's working set (its refits' inputs and pair fits, and its solutions),
/// reserved in the `Engine` store while the step runs: what a step allocates at its height above
/// what the engine held before it, less what it leaves held, for each receiver taking part, the
/// most measured by the counting allocator over the reference simulation and a dense one whose
/// every receiver keeps its full 40 neighbours (`tests/tables_bytes.rs`, `step_bytes_per_seat`,
/// 565,702 bytes on 2026-10-30 with the pair blocks of 2026-10-27, rounded up to the KiB; 212,816
/// before them, the reference scene alone then 131,981). Before, 192 KiB, an upper bound from the
/// window steps it replaced (RFC-0181, "Sizing", 2026-10-08), which the dense scene's step
/// exceeds.
pub const STEP_BYTES_PER_SEAT: usize = 553 << 10;
/// What one seat makes its own engine publish in positions over a step, at most, which is what of
/// them may wait untaken (the network task takes them every tick): its fixes raw and tagged
/// (`consistency::POSITIONS_BYTES_PER_SEAT_PER_SEC`). Charged to `Engine` as they are queued, by
/// their encoded bytes; the clock models' records beside them to `Models` (`models::BYTES_PER_SEAT`,
/// its newest step's in flight). Before, two of each transmission (a final and a provisional) were
/// planned.
pub const PUBLISHED_BYTES_PER_SEAT: usize =
    crate::consistency::POSITIONS_BYTES_PER_SEAT_PER_SEC * STEP_MS.div_ceil(1_000) as usize;

/// The stores of the relay's budget hosted MLAT is charged to.
#[derive(Clone)]
pub struct Gauges {
    /// The raw as it arrived: the descriptions waiting for their step, and the engine's arrived
    /// pool and tables (`Engine::bytes`).
    pub arrived: Arc<Gauge>,
    /// The raw on its way in: the inboxes, every hosted feeder's batches offered and not yet
    /// taken by a step.
    pub inbox: Arc<Gauge>,
    /// A step's working set while it runs, and its positions until the relay takes them.
    pub engine: Arc<Gauge>,
    /// The relay's decoded clock models (`models::Models`): the engine's own models' records while
    /// they wait to be taken.
    pub models: Arc<Gauge>,
}

impl Gauges {
    /// The budget's.
    pub fn of(budget: &Budget) -> Self {
        Self {
            arrived: budget.gauge(Store::Arrived),
            inbox: budget.gauge(Store::Inbox),
            engine: budget.gauge(Store::Engine),
            models: budget.gauge(Store::Models),
        }
    }

    /// Of no budget: for a host built apart from a relay (a test's).
    pub fn unlimited() -> Self {
        Self {
            arrived: Gauge::unlimited(Store::Arrived),
            inbox: Gauge::unlimited(Store::Inbox),
            engine: Gauge::unlimited(Store::Engine),
            models: Gauge::unlimited(Store::Models),
        }
    }
}

/// The hosted MLAT a relay runs, if any: none when its relay duties are off (`--no-relay-duties`)
/// or it runs no MLAT (`--no-mlat`). Its steps are spread over the threads its cores' plan leaves
/// them (`Budget::mlat_threads`), and sized and charged by the relay's `budget`: its seats are the
/// pool the budget plans ([`capacity`]), and what it holds the `Arrived`, `Engine` and `Models`
/// stores' ([`Gauges::of`]). An error when its runner cannot start.
pub fn host_for(
    config: &Config,
    signer: Signer,
    boot_id: u64,
    budget: &Budget,
) -> Result<Option<HostedMlat>, String> {
    if !config.relay_duties || !config.mlat {
        return Ok(None);
    }
    HostedMlat::charging(
        signer,
        boot_id,
        Settings {
            regions: Regions::default(),
            threads: budget.mlat_threads().max(1),
            capacity: capacity(budget),
        },
        Gauges::of(budget),
        StepClock::Wall,
    )
    .map(Some)
}

/// What the hosted engine holds: MLAT's own pool of receiver seats (RFC-0181 §9, §10), the count
/// the budget plans from the cores and memory the stages leave (`Budget::mlat_seats`), the raw of
/// that many in one pool at the measured rates, which is what the budget reserved
/// (`Capacity::for_receivers`); every owned area is refit every `REFIT_EVERY` whatever its
/// receivers, its cost planned per receiver (`cores::MLAT_REFIT_NANOS_PER_FEEDER`). A receiver past the seats is not hosted for MLAT (its raw still
/// flows) and is refused at its description, counted (`MlatReport::receivers_refused`); which
/// receivers hold the seats is decided by key-hash rank (`tally_mlat::intake::Seats`), the same on
/// every relay holding the area. No floor: seats beyond the plan would be cores and raw it never
/// reserved.
pub fn capacity(budget: &Budget) -> Capacity {
    Capacity::for_receivers(budget.mlat_seats())
}

/// Where in the host a test injects a delay ([`HostedMlat::delaying`]): every stage that may run
/// late with respect to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// An offer, before its receptions reach their inbox (what an ingest worker blocked on its way
    /// here does).
    Offer,
    /// A description offered, before it is held for its step.
    Describe,
    /// A step, after its batches and descriptions are taken and before the engine steps.
    Step,
    /// A step's records, before they are published.
    Publish,
}

/// A test's delay at a stage ([`HostedMlat::delaying`]).
pub type Delay = Arc<dyn Fn(Stage) + Send + Sync>;

/// What the runner is handed, in one queue: it wakes for nothing else.
enum Message {
    /// The areas changed: the areas, the engine generation they are for (a new one when the engine
    /// goes or a first one starts), and the descriptions to apply as they come.
    Areas(Regions, u64, Vec<SiteRecord>),
    /// The stamp watermark passed a step no ask handed it yet.
    Tick,
    /// The host was dropped: the runner ends.
    Stop,
}

/// The step that takes a description stamped `stamp_ms` (module docs, Descriptions): the end of
/// its stamp's interval.
fn step_of(stamp_ms: u64) -> u64 {
    (stamp_ms / STEP_MS + 1) * STEP_MS
}

/// The step whose interval a stamp is in begins at this one.
fn floor_step(stamp_ms: u64) -> u64 {
    stamp_ms / STEP_MS * STEP_MS
}

/// One batch's receptions on their way into the engine: the engine generation it was offered to,
/// its place in the batches' order (its stamp first), which batch it is, its stamp on both clocks,
/// and the receptions MLAT uses of it (made at their length).
struct Heard {
    generation: u64,
    order: Order,
    batch: BatchId,
    /// The wall clock its receiver signed it at: how long a receiver not described yet is held
    /// (`Intake::take`, `Intake::expire`).
    wall_ms: u64,
    at: Moment,
    receptions: Vec<Reception>,
}

impl Heard {
    /// What its receptions allocate: their list, each message held in its reception
    /// (`tally_mlat_solver::ModeS`). Before (2026-10-26), each message was a `Vec` of its own,
    /// some 14 bytes a reception, first left out of the charge and then charged.
    fn bytes(&self) -> usize {
        crate::footprint::vec::<Reception>(self.receptions.capacity())
    }
}

/// One raw shard's inbox: the batches offered and not yet taken by a step, and what they are
/// charged to the `Inbox` store, always what the deque and the receptions allocate, taken before
/// they are.
struct Inbox {
    heard: Deque<Heard>,
    /// What the entries' receptions allocate, together.
    receptions: usize,
    charge: Charge,
}

impl Inbox {
    /// Holds `heard`, charged first; false (nothing held) when the store cannot hold it.
    fn push(&mut self, heard: Heard) -> bool {
        let more = self.heard.growth().saturating_add(heard.bytes());
        if !self.charge.try_grow(more) {
            return false;
        }
        self.receptions += heard.bytes();
        self.heard.push_back(heard);
        self.settle();
        true
    }

    /// Takes every entry of `generation` stamped before `step_ms`, and lets go of any of another
    /// generation (an engine that went).
    fn take_before(&mut self, generation: u64, step_ms: u64) -> Vec<Heard> {
        let mut taken = self
            .heard
            .take_where(|heard| heard.generation != generation || heard.order.stamp.ms() < step_ms);
        taken.retain(|heard| heard.generation == generation);
        self.receptions = self.heard.iter().map(Heard::bytes).sum();
        self.settle();
        taken
    }

    /// Lets go of every entry offered to an engine before `generation`.
    fn forget_before(&mut self, generation: u64) {
        self.heard.retain(|heard| heard.generation >= generation);
        self.receptions = self.heard.iter().map(Heard::bytes).sum();
        self.settle();
    }

    /// Its charge brought down to what it allocates.
    fn settle(&mut self) {
        self.charge
            .shrink_to(self.heard.bytes().saturating_add(self.receptions));
    }
}

/// A description waiting for its step, with its stamp.
struct Pending {
    stamp_ms: u64,
    record: SiteRecord,
}

impl Pending {
    fn bytes(&self) -> usize {
        self.record.as_bytes().len()
    }
}

/// The descriptions waiting for their step (module docs, Descriptions): one a receiver a step, the
/// newest it signed, by the step that takes it; the newest watermark the host was asked with,
/// below which none is stamped; and what they are charged to the `Arrived` store.
struct Descriptions {
    pending: Tree<(u64, PublicKey), Pending>,
    /// What the records' bytes allocate, together.
    records: usize,
    /// The most held at once: one a step over the inbox's span for every seat.
    most: usize,
    asked_ms: u64,
    charge: Charge,
}

impl Descriptions {
    /// Holds `record` of `receiver` for step `step_ms`, in place of an older one of the same
    /// receiver for that step: false when it is not held for room.
    fn hold(
        &mut self,
        step_ms: u64,
        receiver: PublicKey,
        stamp_ms: u64,
        record: &SiteRecord,
    ) -> bool {
        let key = (step_ms, receiver);
        let held = self
            .pending
            .get(&key)
            .map(|held| signed_order(&held.record) >= signed_order(record));
        if held == Some(true) {
            // An older one, or the same again, changes nothing.
            return true;
        }
        if held.is_none() && self.pending.len() >= self.most {
            return false;
        }
        let pending = Pending {
            stamp_ms,
            record: record.clone(),
        };
        let more = self.pending.growth().saturating_add(pending.bytes());
        if !self.charge.try_grow(more) {
            return false;
        }
        self.records += pending.bytes();
        if let Some(replaced) = self.pending.insert(key, pending) {
            self.records -= replaced.bytes();
        }
        self.settle();
        true
    }

    /// Takes every description for a step at or before `step_ms`, with its stamp.
    fn take_through(&mut self, step_ms: u64) -> Vec<(u64, SiteRecord)> {
        let mut taken = Vec::new();
        for ((step, receiver), pending) in self.pending.take() {
            if step <= step_ms {
                taken.push((pending.stamp_ms, pending.record));
            } else {
                self.pending.insert((step, receiver), pending);
            }
        }
        self.records = self.pending.values().map(Pending::bytes).sum();
        self.settle();
        taken
    }

    fn settle(&mut self) {
        self.charge
            .shrink_to(self.pending.bytes().saturating_add(self.records));
    }
}

/// The overload cuts known (module docs, Overload): per relay that announced them, per area, by
/// the step each takes effect from.
#[derive(Default)]
struct Cuts {
    by_origin: BTreeMap<PublicKey, BTreeMap<u64, BTreeMap<u64, u128>>>,
    /// Decided here and not yet taken for publishing.
    decided: Vec<Cut>,
    /// The cut this host decided and announces again while it stands: only a host that cut lifts
    /// its cut (a cut offered by a peer is the peer's to lift).
    own: Option<Standing>,
    /// The last step whose cut was applied: one for a step at or before it takes effect at the
    /// next (counted late), with the expiry its stamp gave it.
    applied_ms: Option<u64>,
}

/// The cut this host stands by: its rank threshold and the step of its newest announcement.
#[derive(Clone)]
struct Standing {
    below: u128,
    last_from_ms: u64,
    areas: Vec<Region>,
}

/// What became of a cut offered (`Cuts::offer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Offered {
    Kept,
    /// Kept, for a step applied already: it takes effect at the next, and counts late.
    Late,
    /// Not kept: malformed, expired, too far ahead, or beyond what the table holds.
    Refused,
}

impl Cuts {
    /// The step the stamps have reached, as far as the host knows: the newest watermark it was
    /// asked with (`asked_ms`), or the last step applied.
    fn now_ms(&self, asked_ms: u64) -> u64 {
        asked_ms.max(self.applied_ms.unwrap_or(0))
    }

    /// Takes `cut`. A cut whose step is not on the grid or is past `MAX_CUT_FROM_MS`, one that
    /// expired already, and one stamped further ahead than `CUT_AHEAD_MS` are refused (checked
    /// arithmetic throughout: no stamp a peer signs can overflow it); the table's bounds keep the
    /// origins of the best rank and the lowest areas.
    fn offer(&mut self, cut: &Cut, asked_ms: u64) -> Offered {
        if !cut.from_ms.is_multiple_of(STEP_MS) || cut.from_ms > tally_wire::MAX_CUT_FROM_MS {
            return Offered::Refused;
        }
        let Some(expires_ms) = cut.from_ms.checked_add(CUT_TTL_MS) else {
            return Offered::Refused;
        };
        let now = self.now_ms(asked_ms);
        if now > 0 && (expires_ms <= now || cut.from_ms > now.saturating_add(CUT_AHEAD_MS)) {
            return Offered::Refused;
        }
        if !self.by_origin.contains_key(&cut.origin) && self.by_origin.len() >= CUT_ORIGINS {
            let rank = |key: &PublicKey| (tally_mlat::intake::draw(key), *key);
            let Some(worst) = self.by_origin.keys().max_by_key(|key| rank(key)).copied() else {
                return Offered::Refused;
            };
            if rank(&cut.origin) >= rank(&worst) {
                return Offered::Refused;
            }
            self.by_origin.remove(&worst);
        }
        let areas = self.by_origin.entry(cut.origin).or_default();
        let mut kept = false;
        for area in &cut.areas {
            let cell = area.as_u64();
            if !areas.contains_key(&cell) && areas.len() >= CUT_AREAS_PER_ORIGIN {
                let Some(highest) = areas.keys().next_back().copied() else {
                    continue;
                };
                if cell >= highest {
                    continue;
                }
                areas.remove(&highest);
            }
            let entries = areas.entry(cell).or_default();
            entries.insert(cut.from_ms, cut.below);
            // Those in force are one; the rest are ahead, bounded by their step.
            while entries.range(now..).count() > CUTS_AHEAD_PER_AREA {
                entries.pop_last();
            }
            kept = true;
        }
        if !kept {
            return Offered::Refused;
        }
        match self.applied_ms {
            Some(applied) if cut.from_ms <= applied => Offered::Late,
            _ => Offered::Kept,
        }
    }

    /// The cuts in force at `step_ms`: per area, the least threshold of each origin's newest
    /// announcement at or before the step that has not expired by it. A lifting announcement
    /// (`u128::MAX`) asks for nothing.
    fn cutoffs_at(&self, step_ms: u64) -> Vec<(Region, u128)> {
        let mut least: BTreeMap<u64, u128> = BTreeMap::new();
        for areas in self.by_origin.values() {
            for (cell, entries) in areas {
                let Some((from_ms, below)) = entries.range(..=step_ms).next_back() else {
                    continue;
                };
                if from_ms
                    .checked_add(CUT_TTL_MS)
                    .is_none_or(|end| end <= step_ms)
                {
                    continue;
                }
                let entry = least.entry(*cell).or_insert(*below);
                *entry = (*entry).min(*below);
            }
        }
        least
            .into_iter()
            .filter(|(_, below)| *below != u128::MAX)
            .filter_map(|(cell, below)| Region::from_u64(cell).ok().map(|area| (area, below)))
            .collect()
    }

    /// Notes that the step at `step_ms` was applied, and forgets what it no longer needs: each
    /// area's announcements before its newest at or before the step, those expired, and any
    /// stamped past what `CUT_AHEAD_MS` allows (offered before the host knew the watermark).
    fn applied(&mut self, step_ms: u64) {
        self.applied_ms = Some(step_ms);
        let ahead = step_ms.saturating_add(CUT_AHEAD_MS);
        for areas in self.by_origin.values_mut() {
            for entries in areas.values_mut() {
                let keep = entries.range(..=step_ms).next_back().map(|(at, _)| *at);
                if let Some(keep) = keep {
                    *entries = entries.split_off(&keep);
                }
                entries.retain(|at, _| {
                    *at <= ahead && at.checked_add(CUT_TTL_MS).is_some_and(|end| end > step_ms)
                });
            }
            areas.retain(|_, entries| !entries.is_empty());
        }
        self.by_origin.retain(|_, areas| !areas.is_empty());
    }

    /// Announces `below` for `areas` from `from_ms`: offered to this table and kept to be taken
    /// for publishing (`MlatHost::take_cuts`), a record for each `MAX_CUT_AREAS` of the areas.
    fn announce(
        &mut self,
        origin: PublicKey,
        from_ms: u64,
        below: u128,
        areas: &[Region],
        asked_ms: u64,
    ) {
        for chunk in areas.chunks(tally_wire::MAX_CUT_AREAS) {
            let cut = Cut {
                from_ms,
                origin,
                below,
                areas: chunk.to_vec(),
            };
            self.offer(&cut, asked_ms);
            self.decided.push(cut);
        }
    }
}

/// One step's signed records, published at once: queued whole until the relay takes them, with the
/// engine's own models they carry, and what they are charged.
#[derive(Default)]
struct Published {
    records: Vec<Record>,
    own: Vec<OwnModel>,
    bytes: usize,
    /// What they are charged until taken: the positions' to `Engine`, the models' to `Models`.
    charges: Vec<Charge>,
}

/// Whether `record` is a clock model (its manifest, a part of it, or a client's summary of it):
/// charged to `Models`, the rest of a step's records to `Engine`.
fn is_model(record: &Record) -> bool {
    matches!(
        record,
        Record::ClockModel(_) | Record::ClockModelPart(_) | Record::ClientClockModel(_)
    )
}

/// The engine of whichever generation runs, shared by the runner (which steps it) and the relay's
/// standing (which reads its raw, [`MlatHost::raw`]).
type Running = Arc<Mutex<Option<Engine>>>;

/// The raw the hosted engine holds, as standing reads it (`standing::Raw`): whichever engine runs,
/// none while none does.
struct RunningRaw(Running);

impl crate::standing::Raw for RunningRaw {
    fn heard(&self, id: &tally_mlat_solver::ObservationId, transmitted_ms: u64) -> Option<u64> {
        lock(&self.0).as_ref()?.heard(id, transmitted_ms)
    }

    fn verify(
        &self,
        models: &[Arc<tally_mlat::fix::Held>],
        stated: &tally_mlat_solver::Stated<'_>,
    ) -> Option<bool> {
        lock(&self.0).as_mut()?.verify(models, stated)
    }
}

/// A lock held through a poisoning: a panic in MLAT ends the process (`EndOnUnwind`), so a
/// poisoned lock is never seen running on.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the relay's side and the runner share.
struct Shared {
    /// The raw shards' inboxes, `SHARDS` of them, each locked by the ingest worker that owns its
    /// receivers to push a batch, and by a step to take what is due.
    inboxes: Box<[Mutex<Inbox>]>,
    /// The descriptions waiting for their step, and the newest watermark asked.
    descriptions: Mutex<Descriptions>,
    /// The engine running, if any.
    engine: Running,
    /// The generation of the engine running: what an offer is tagged with, so a batch offered to
    /// an engine that went is never handed to the next.
    generation: AtomicU64,
    /// Whether an engine runs (the areas are not empty), the areas as `set_areas` last set them, and
    /// the engine generation they started.
    solving: AtomicBool,
    scope: Mutex<Regions>,
    /// The newest judging watermark asked with, the last step an ask handed the runner, and the
    /// last step the engine running stepped (zero before its first).
    latest: Mutex<Option<Moment>>,
    ticked_ms: AtomicU64,
    stepped_ms: AtomicU64,
    /// Whether an ask came while the relay's clock was not judging since the runner last stepped.
    unsynced: AtomicBool,
    /// The least stamp of a batch or description offered to the engine running, and of a batch
    /// alone: where its steps begin (`Host::steps`).
    earliest_ms: AtomicU64,
    earliest_batch_ms: AtomicU64,
    /// Messages sent and not yet done with, and asks taken.
    commands: AtomicUsize,
    asks: AtomicU64,
    /// Counted as batches and descriptions come.
    offered: AtomicU64,
    refused: AtomicU64,
    ingest_errors: AtomicU64,
    descriptions_dropped: AtomicU64,
    cuts_late: AtomicU64,
    cuts_unkept: AtomicU64,
    priority_unset: AtomicU64,
    /// Everything else counted, by the runner.
    counts: Mutex<MlatReport>,
    seats: Arc<Seats>,
    cuts: Mutex<Cuts>,
    published: Mutex<Published>,
    /// What the records not yet taken are charged to: the positions' store (`Engine`) and the
    /// clock models' (`Models`).
    published_gauges: (Arc<Gauge>, Arc<Gauge>),
    /// The neighbouring areas' models the relay's store offered, by pair model id, not yet handed
    /// to the engine (`MlatHost::offer_model`): each a handle on the store's, handed at the next
    /// step.
    neighbours: Mutex<BTreeMap<tally_wire::batch::Hash, crate::models::Model>>,
    /// The threads the plan gives MLAT, every kind of its work together.
    gate: Arc<Gate>,
    /// What a step's run is judged by for overload.
    clock: StepClock,
    /// A test's delays (`HostedMlat::delaying`).
    delay: OnceLock<Delay>,
}

impl Shared {
    fn delay(&self, stage: Stage) {
        if let Some(delay) = self.delay.get() {
            delay(stage);
        }
    }

    fn count(&self, change: impl FnOnce(&mut MlatReport)) {
        change(&mut lock(&self.counts));
    }

    /// A step's records (a part always with its manifest), queued whole, or refused whole and
    /// counted when their stores cannot hold them beside those not yet taken. Into an empty queue
    /// they are taken whatever their stores hold, so no step is refused forever. Whether they were
    /// queued.
    fn publish(&self, records: Vec<Record>, own: Vec<OwnModel>) -> bool {
        if records.is_empty() {
            return true;
        }
        let bytes: usize = records.iter().map(Record::encoded_len).sum();
        let model_bytes: usize = records
            .iter()
            .filter(|record| is_model(record))
            .map(Record::encoded_len)
            .sum();
        let mut published = lock(&self.published);
        let charges = (
            self.published_gauges.0.try_charge(bytes - model_bytes),
            self.published_gauges.1.try_charge(model_bytes),
        );
        let (Some(positions), Some(models)) = charges else {
            if published.bytes > 0 {
                lock(&self.counts).overflowed += records.len() as u64;
                return false;
            }
            published.bytes = bytes;
            published.records = records;
            published.own = own;
            return true;
        };
        published.bytes = published.bytes.saturating_add(bytes);
        published.records.extend(records);
        published.own.extend(own);
        published.charges.extend([positions, models]);
        true
    }

    /// Every record not yet taken, in order.
    fn take_signed(&self) -> Vec<Record> {
        let mut published = lock(&self.published);
        published.bytes = 0;
        published.charges.clear();
        std::mem::take(&mut published.records)
    }
}

/// `tally-mlat`'s engine as a relay's hosted MLAT.
pub struct HostedMlat {
    messages: Sender<Message>,
    shared: Arc<Shared>,
    cores: u16,
}

impl HostedMlat {
    /// The engine signs through `signer` (the relay's key, only while its clock is judging);
    /// `boot_id` is its first engine's boot. `settings.regions` is ignored: the areas are
    /// `set_areas`'s. What it holds is charged to gauges of no budget: for a host built apart from
    /// a relay (a test's). Its steps are judged for overload by `clock`: a relay's by the wall
    /// clock (`host_for`), a test's as it declares, so that its verdict is not the machine's speed.
    /// An error when its runner cannot start.
    pub fn new(
        signer: Signer,
        boot_id: u64,
        settings: Settings,
        clock: StepClock,
    ) -> Result<Self, String> {
        Self::charging(signer, boot_id, settings, Gauges::unlimited(), clock)
    }

    /// As `new`, everything it holds charged to the relay's stores before it is held (`gauges`,
    /// module docs, Capacity).
    pub fn charging(
        signer: Signer,
        boot_id: u64,
        settings: Settings,
        gauges: Gauges,
        clock: StepClock,
    ) -> Result<Self, String> {
        let cores = u16::try_from(settings.threads).unwrap_or(u16::MAX);
        let (messages, received) = std::sync::mpsc::channel();
        let seats = Seats::new(settings.capacity.receivers);
        let shared = Arc::new(Shared {
            inboxes: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Inbox {
                        heard: Deque::new(),
                        receptions: 0,
                        charge: gauges.inbox.empty(),
                    })
                })
                .collect(),
            descriptions: Mutex::new(Descriptions {
                pending: Tree::new(),
                records: 0,
                most: settings
                    .capacity
                    .receivers
                    .max(1)
                    .saturating_mul(PENDING_PER_SEAT),
                asked_ms: 0,
                charge: gauges.arrived.empty(),
            }),
            engine: Arc::new(Mutex::new(None)),
            generation: AtomicU64::new(0),
            solving: AtomicBool::new(false),
            scope: Mutex::new(Regions::default()),
            latest: Mutex::new(None),
            ticked_ms: AtomicU64::new(0),
            stepped_ms: AtomicU64::new(0),
            unsynced: AtomicBool::new(false),
            earliest_ms: AtomicU64::new(u64::MAX),
            earliest_batch_ms: AtomicU64::new(u64::MAX),
            commands: AtomicUsize::new(0),
            asks: AtomicU64::new(0),
            offered: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            ingest_errors: AtomicU64::new(0),
            descriptions_dropped: AtomicU64::new(0),
            cuts_late: AtomicU64::new(0),
            cuts_unkept: AtomicU64::new(0),
            priority_unset: AtomicU64::new(0),
            counts: Mutex::new(MlatReport::default()),
            seats: Arc::clone(&seats),
            cuts: Mutex::new(Cuts::default()),
            published: Mutex::new(Published::default()),
            published_gauges: (Arc::clone(&gauges.engine), Arc::clone(&gauges.models)),
            neighbours: Mutex::new(BTreeMap::new()),
            gate: Gate::new(settings.threads.max(1)),
            clock,
            delay: OnceLock::new(),
        });
        let host = Host {
            signer,
            boot_id,
            engines: 0,
            generation: 0,
            settings,
            intake: Intake::new(seats, None),
            areas: Regions::default(),
            through: None,
            arrived: gauges.arrived.empty(),
            engine_gauge: gauges.engine,
            governor: Governor::default(),
            shared: Arc::clone(&shared),
        };
        let (starting, started) = std::sync::mpsc::channel();
        let runner = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("tally-mlat".to_owned())
            .spawn(move || {
                // A panic on the runner ends the process.
                let _ends = EndOnUnwind;
                if !run_at(Urgency::Steps.below()) {
                    runner.priority_unset.fetch_add(1, Ordering::SeqCst);
                }
                let _ = starting.send(());
                host.run(&received);
            })
            .map_err(|error| format!("the hosted MLAT did not start: {error}"))?;
        started
            .recv()
            .map_err(|_| "the hosted MLAT ended as it started".to_owned())?;
        Ok(Self {
            messages,
            shared,
            cores,
        })
    }

    /// Delays injected at every stage (`Stage`), for a test that shows they change nothing
    /// (RFC-0181 invariant 2). Set once; later calls are ignored.
    pub fn delaying(&self, delay: Delay) {
        let _ = self.shared.delay.set(delay);
    }

    /// Messages handed to the runner and not yet done with: zero when everything offered and asked
    /// so far is published.
    pub fn in_flight(&self) -> usize {
        self.shared.commands.load(Ordering::SeqCst)
    }

    /// The most threads that ever did MLAT work at once (`tally_mlat_solver::gate`): never more
    /// than the plan gave it.
    pub fn busiest(&self) -> usize {
        self.shared.gate.peak()
    }

    /// Batches offered while an engine runs.
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
        lock(&self.shared.descriptions).asked_ms
    }

    /// The last step the engine running stepped, its monotonic milliseconds: zero before its first.
    pub fn stepped_ms(&self) -> u64 {
        self.shared.stepped_ms.load(Ordering::SeqCst)
    }

    /// The receivers taking part now (seated, described and inside the areas), in key order: whose
    /// raw the engine holds.
    pub fn seated(&self) -> Vec<PublicKey> {
        lock(&self.shared.engine)
            .as_ref()
            .map(|engine| {
                engine
                    .sites()
                    .into_iter()
                    .map(|sited| sited.site.receiver)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Records signed and not yet taken.
    pub fn untaken(&self) -> usize {
        lock(&self.shared.published).records.len()
    }

    /// What was signed and not yet taken, asking for nothing more: for a caller that waited for
    /// `in_flight` to reach zero, with the watermark where it was.
    pub fn take_signed(&self) -> Vec<Record> {
        self.shared.take_signed()
    }

    /// Hands `message` to the runner.
    fn send(&self, message: Message) {
        self.shared.commands.fetch_add(1, Ordering::SeqCst);
        if self.messages.send(message).is_err() {
            self.shared.commands.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for HostedMlat {
    fn drop(&mut self) {
        // The runner wakes for messages alone: this is its last.
        let _ = self.messages.send(Message::Stop);
    }
}

impl MlatHost for HostedMlat {
    fn set_areas(&self, areas: Regions, mut descriptions: Vec<SiteRecord>) {
        // Whether an engine will run, and of which generation, is decided here, so a batch or
        // description offered after this call is held for that engine (or not) at once; the runner
        // starts it, in order, before any step the next ask hands it. No area at all drops the
        // engine, and the first area after none starts a new one: what waited for a step of the
        // engine that goes is applied as it comes, before the relay's own (a receiver's word
        // outlives the engine; of two, the newest it signed stands).
        let mut scope = lock(&self.shared.scope);
        if areas.is_empty() || scope.is_empty() {
            let waiting = lock(&self.shared.descriptions).take_through(u64::MAX);
            descriptions.splice(0..0, waiting.into_iter().map(|(_, record)| record));
            self.shared.generation.fetch_add(1, Ordering::SeqCst);
            self.shared.earliest_ms.store(u64::MAX, Ordering::SeqCst);
            self.shared
                .earliest_batch_ms
                .store(u64::MAX, Ordering::SeqCst);
            // Asks step it from the next one on: an engine started now has stepped nothing yet.
            self.shared.ticked_ms.store(0, Ordering::SeqCst);
        }
        let generation = self.shared.generation.load(Ordering::SeqCst);
        self.shared
            .solving
            .store(!areas.is_empty(), Ordering::SeqCst);
        scope.clone_from(&areas);
        drop(scope);
        self.send(Message::Areas(areas, generation, descriptions));
    }

    fn offer_description(&self, record: &SiteRecord, stamp_ms: u64) {
        self.shared.delay(Stage::Describe);
        if !self.shared.solving.load(Ordering::SeqCst) {
            // No engine: the relay hands every description it holds again when one starts
            // (`set_areas`).
            return;
        }
        let Ok(receiver) = record.receiver() else {
            self.shared.ingest_errors.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut descriptions = lock(&self.shared.descriptions);
        // Never before a watermark the host was asked with: a step it may have taken already.
        let stamp_ms = stamp_ms.max(descriptions.asked_ms);
        // The engine's steps begin where its first stamp is, a description's or a batch's.
        self.shared
            .earliest_ms
            .fetch_min(stamp_ms, Ordering::SeqCst);
        if !descriptions.hold(step_of(stamp_ms), receiver, stamp_ms, record) {
            self.shared
                .descriptions_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn offer_batch(&self, batch: &Arc<Decoded>, _now_ms: u64) {
        self.shared.delay(Stage::Offer);
        if !self.shared.solving.load(Ordering::SeqCst) {
            return;
        }
        let generation = self.shared.generation.load(Ordering::SeqCst);
        // The receptions MLAT uses, read here on the ingest worker that holds the decode, once,
        // and made at their length: the decode is not kept alive past this call.
        let (mut receptions, _unused) = receptions_of(batch);
        receptions.shrink_to_fit();
        let heard = Heard {
            generation,
            order: Order::of(batch),
            batch: batch_id(batch),
            wall_ms: batch.wall_ms(),
            at: batch.at(),
            receptions,
        };
        self.shared.offered.fetch_add(1, Ordering::SeqCst);
        self.shared
            .earliest_ms
            .fetch_min(batch.stamp_ms(), Ordering::SeqCst);
        self.shared
            .earliest_batch_ms
            .fetch_min(batch.stamp_ms(), Ordering::SeqCst);
        let shard = usize::from(raw_shard(&batch.receiver()).0);
        if !lock(&self.shared.inboxes[shard]).push(heard) {
            self.shared.refused.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn take_published(&self, watermark: crate::products::Watermark) -> Vec<Record> {
        // Nothing is stepped or signed by a clock that is not judging. The steps the watermark
        // passes meanwhile are collapsed once it judges again (`Host::steps`).
        let Some(watermark) = watermark.judging_at() else {
            self.shared.unsynced.store(true, Ordering::SeqCst);
            return Vec::new();
        };
        let watermark_ms = watermark.mono().ms();
        self.shared.asks.fetch_add(1, Ordering::SeqCst);
        // Recorded under the descriptions' lock before the runner can step by it, so no
        // description offered after a step is taken is stamped before it (`offer_description`).
        {
            let mut descriptions = lock(&self.shared.descriptions);
            descriptions.asked_ms = descriptions.asked_ms.max(watermark_ms);
        }
        {
            let mut latest = lock(&self.shared.latest);
            if latest.is_none_or(|latest| latest.mono() < watermark.mono()) {
                *latest = Some(watermark);
            }
        }
        // The runner is woken only for a step the watermark passed and no ask handed it yet, and
        // never with no engine to step. An ask dropped while the queue is full is the next one's:
        // its watermark is no older.
        let step = floor_step(watermark_ms);
        if self.shared.solving.load(Ordering::SeqCst)
            && step > self.shared.ticked_ms.load(Ordering::SeqCst)
            && self.shared.commands.load(Ordering::SeqCst) < COMMANDS_WAITING
        {
            self.shared.ticked_ms.fetch_max(step, Ordering::SeqCst);
            self.send(Message::Tick);
        }
        self.shared.take_signed()
    }

    fn cores(&self) -> u16 {
        self.cores
    }

    fn raw(&self) -> Option<Arc<dyn crate::standing::Raw>> {
        Some(Arc::new(RunningRaw(Arc::clone(&self.shared.engine))))
    }

    fn take_own_models(&self) -> Vec<OwnModel> {
        std::mem::take(&mut lock(&self.shared.published).own)
    }

    fn offer_model(&self, model: crate::models::Model) {
        lock(&self.shared.neighbours)
            .entry(model.id())
            .or_insert(model);
    }

    fn gate(&self) -> Option<Arc<Gate>> {
        Some(Arc::clone(&self.shared.gate))
    }

    fn offer_cut(&self, cut: Cut) {
        let asked_ms = self.asked_ms();
        match lock(&self.shared.cuts).offer(&cut, asked_ms) {
            Offered::Kept => {}
            Offered::Late => {
                self.shared.cuts_late.fetch_add(1, Ordering::Relaxed);
            }
            Offered::Refused => {
                self.shared.cuts_unkept.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn take_cuts(&self) -> Vec<Cut> {
        std::mem::take(&mut lock(&self.shared.cuts).decided)
    }

    fn report(&self) -> MlatReport {
        let shared = &self.shared;
        let mut report = lock(&shared.counts).clone();
        report.offered = shared.offered.load(Ordering::Relaxed);
        report.refused += shared.refused.load(Ordering::Relaxed);
        report.ingest_errors += shared.ingest_errors.load(Ordering::Relaxed);
        report.descriptions_dropped = shared.descriptions_dropped.load(Ordering::Relaxed);
        report.priority_unset = shared.priority_unset.load(Ordering::Relaxed);
        report.cuts_late = shared.cuts_late.load(Ordering::Relaxed);
        report.cuts_unkept = shared.cuts_unkept.load(Ordering::Relaxed);
        report.seat_cap = shared.seats.cap() as u64;
        report.seat_limit = shared.seats.limit() as u64;
        report.seats_taken = shared.seats.taken() as u64;
        report
    }
}

/// The runner: the receivers, the areas, the engine's generations and its steps.
struct Host {
    /// The relay's key as the engine signs with it: only while the relay's clock is judging.
    signer: Signer,
    /// The first engine's boot id; each later one adds one.
    boot_id: u64,
    /// Engines started, and the generation of the one running (or of none).
    engines: u64,
    generation: u64,
    settings: Settings,
    /// The receivers (module docs, One store of raw): their descriptions outlive an engine.
    intake: Intake,
    areas: Regions,
    /// The last step taken, for the engine running.
    through: Option<Mono>,
    /// What the engine's arrived pool and tables are charged to the `Arrived` store: its bytes as
    /// of the last change, grown before each batch by the most it may add.
    arrived: Charge,
    /// The `Engine` store, where a step's working set is reserved while it runs.
    engine_gauge: Arc<Gauge>,
    /// What the seats are judged by since they last changed (module docs, Overload).
    governor: Governor,
    shared: Arc<Shared>,
}

impl Host {
    fn run(mut self, received: &Receiver<Message>) {
        // It wakes for a message and for nothing else: idle, it costs nothing.
        while let Ok(message) = received.recv() {
            match message {
                Message::Stop => return,
                Message::Areas(areas, generation, descriptions) => {
                    let gate = Arc::clone(&self.shared.gate);
                    gate::enter(&gate, Urgency::Steps.gate(), || {
                        self.rescope(areas, generation, &descriptions);
                    });
                }
                Message::Tick => {
                    let gate = Arc::clone(&self.shared.gate);
                    gate::enter(&gate, Urgency::Steps.gate(), || self.steps());
                }
            }
            self.shared.commands.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// The areas are now `areas`, for engine `generation` (module docs, Areas), and `descriptions`
    /// are applied as they come. A new generation drops the engine and its raw, and starts a new
    /// one under a new boot id if there are areas; any other change re-scopes it in place.
    fn rescope(&mut self, areas: Regions, generation: u64, descriptions: &[SiteRecord]) {
        for record in descriptions {
            self.describe(record);
        }
        if generation != self.generation {
            self.drop_engine(generation);
        } else if areas == self.areas {
            self.set_sites();
            return;
        }
        let band = (!areas.is_empty()).then(|| area::border_band(&areas));
        let described = self.intake.set_scope(band.clone());
        self.count_refused();
        self.forget(described.left);
        self.areas = areas.clone();
        let Some(band) = band else {
            return;
        };
        let mut running = lock(&self.shared.engine);
        let engine = running.get_or_insert_with(|| {
            let engine = Engine::hosted(
                self.boot_id.wrapping_add(self.engines),
                Settings {
                    regions: band.clone(),
                    ..self.settings.clone()
                },
            );
            self.engines += 1;
            engine
        });
        engine.set_scope(band, areas);
        drop(running);
        self.set_sites();
        self.settle_arrived();
    }

    fn running(&self) -> bool {
        lock(&self.shared.engine).is_some()
    }

    /// The engine goes with its raw, and what was offered to it with it: the next engine is
    /// `generation`'s, and its steps start where its own raw does.
    fn drop_engine(&mut self, generation: u64) {
        *lock(&self.shared.engine) = None;
        self.generation = generation;
        for inbox in &self.shared.inboxes {
            lock(inbox).forget_before(generation);
        }
        self.intake.restart();
        self.through = None;
        self.shared.stepped_ms.store(0, Ordering::SeqCst);
        self.arrived.shrink_to(0);
    }

    /// A receiver's description, applied now: counted when it does not verify, and a receiver
    /// that stopped taking part forgotten in the engine's raw.
    fn describe(&mut self, record: &SiteRecord) {
        match self.intake.describe(record) {
            Ok(described) => {
                self.count_refused();
                self.forget(described.left);
                // One intake holds every receiver: none of another moved.
                for other in described.moved {
                    if self.intake.settle(&other) {
                        self.forget(vec![other]);
                    }
                }
            }
            Err(_) => {
                self.shared.ingest_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn count_refused(&mut self) {
        let refused = self.intake.take_refused();
        if refused > 0 {
            self.shared
                .count(|counts| counts.receivers_refused += refused);
        }
    }

    /// Receivers that stopped taking part: what they heard is never read again.
    fn forget(&mut self, left: Vec<PublicKey>) {
        if left.is_empty() {
            return;
        }
        if let Some(engine) = lock(&self.shared.engine).as_mut() {
            for receiver in left {
                engine.forget_by(receiver);
            }
        }
    }

    /// Who takes part now, for the engine.
    fn set_sites(&mut self) {
        let sites = self.intake.sites().collect();
        if let Some(engine) = lock(&self.shared.engine).as_mut() {
            engine.set_sites(sites);
        }
    }

    /// A batch's charge of `most` brought to the `grown` bytes its ingest added to the pool: down
    /// to them, or, should a batch outgrow the most it was charged (which its plan says it never
    /// does), up to them when the store has room, else counted (`MlatReport::arrived_over`).
    fn true_up(&mut self, most: usize, grown: usize) {
        let held = self.arrived.bytes();
        if grown <= most {
            self.arrived.shrink_to(held - (most - grown));
        } else if !self.arrived.try_grow(grown - most) {
            self.shared.count(|counts| counts.arrived_over += 1);
        }
    }

    /// The `Arrived` charge brought to what the engine holds now: down to it, or up to it when the
    /// store has room. Past the store (the engine's tables grew beyond what its seats plan, which a
    /// host within its plan never does), the charge stays at what it could take and every batch is
    /// refused until it comes down, counted (`MlatReport::arrived_over`).
    fn settle_arrived(&mut self) {
        let bytes = lock(&self.shared.engine).as_ref().map_or(0, Engine::bytes);
        let held = self.arrived.bytes();
        if bytes <= held {
            self.arrived.shrink_to(bytes);
        } else if !self.arrived.try_grow(bytes - held) {
            self.shared.count(|counts| counts.arrived_over += 1);
        }
    }

    /// Every step the watermark passed and that is not taken yet (module docs, One step a
    /// second): each in order taken and described, and the newest stepped, the ones before it
    /// collapsed into it when there are more than one (module docs, Behind). The first step of an
    /// engine is the first multiple after the least stamp offered to it, which every batch and
    /// description stamped before the watermark has said by now, but never more than one step
    /// before the step that takes its first batch, and none before a batch is due: the steps
    /// before it hold descriptions alone, which the engine takes in their order in that one step
    /// as it would one a second, and with no raw a step makes nothing. Before, a description
    /// stamped long before any batch (a receiver that described itself and sent nothing for an
    /// hour, or a stamp clock that starts at zero) walked every second since, one at a time, and
    /// counted each one collapsed.
    fn steps(&mut self) {
        let Some(watermark) = *lock(&self.shared.latest) else {
            return;
        };
        if !self.running() {
            return;
        }
        let step_span = policy::<Mono, STEP_MS>();
        let last_due = watermark.mono().floor(step_span);
        let mut through = match self.through {
            Some(through) => through,
            None => {
                let batch = self.shared.earliest_batch_ms.load(Ordering::SeqCst);
                if batch >= watermark.mono().ms() {
                    // No batch stamped before the watermark: every step to it has nothing to do.
                    return;
                }
                let earliest = self.shared.earliest_ms.load(Ordering::SeqCst);
                let first = floor_step(earliest).max(floor_step(batch).saturating_sub(STEP_MS));
                let mut through = last_due;
                while through.ms() > first {
                    through = through.earlier(step_span);
                }
                through
            }
        };
        if through >= last_due {
            return;
        }
        // The steps due that take a batch: the ones up to the first batch's hold descriptions
        // alone, and are no step collapsed.
        let quiet_ms = floor_step(self.shared.earliest_batch_ms.load(Ordering::SeqCst));
        let due = last_due.ms().saturating_sub(through.ms().max(quiet_ms)) / STEP_MS;
        // Steps passed while the clock did not judge are collapsed as steps passed while the one
        // before ran are: taken and described in their turn, stepped as one.
        let unsynced = self.shared.unsynced.swap(false, Ordering::SeqCst);
        if due > 1 {
            self.shared.count(|counts| {
                if unsynced {
                    counts.steps_unsynced += due - 1;
                } else {
                    counts.steps_collapsed += due - 1;
                }
            });
        }
        // The newest step's cost is judged from its own taking (module docs, Overload), and as
        // many of the judged steps as it took steps in.
        let mut started = std::time::Instant::now();
        let mut taken = 0u64;
        while through < last_due {
            through = through.later(step_span);
            started = std::time::Instant::now();
            taken += 1;
            // The step by the watermark's own pair: its judging clock is the watermark's offset
            // carried to it, never a clock read here.
            self.take(watermark.at(through));
            // A step collapsed lets go of the raw it would have before the next is taken, so the
            // pool holds what stepping each would (module docs, Behind).
            if through < last_due {
                if let Some(engine) = lock(&self.shared.engine).as_mut() {
                    engine.forget_older(watermark.at(through));
                }
                self.settle_arrived();
            }
        }
        self.through = Some(through);
        self.step(watermark.at(through), started, taken);
        self.shared.stepped_ms.store(through.ms(), Ordering::SeqCst);
    }

    /// What step `step` takes before it steps (module docs, One step a second): every batch stamped
    /// before it, in order, then the cut in force at it, then the descriptions stamped before it.
    fn take(&mut self, step: Moment) {
        let step_ms = step.mono().ms();
        let generation = self.generation;
        let mut due: Vec<Heard> = self
            .shared
            .inboxes
            .iter()
            .flat_map(|inbox| lock(inbox).take_before(generation, step_ms))
            .collect();
        due.sort_unstable_by_key(|heard| heard.order);
        // A receiver never described none of whose batches is still held is let go, with its raw
        // (`Intake::expire`), as the engine's own intake does each step.
        let expired = self
            .intake
            .expire(step.judged().ms(), tally_mlat_solver::HELD_MS);
        self.forget(expired);
        // Each batch is classified (its messages hashed, its positions found) on MLAT's threads,
        // a piece of the batches each, and admitted here in order, one at a time: classifying is a
        // function of the batch alone (`tally_mlat::engine::classify`), so the pool holds the same
        // bytes however the pieces fell. Before, this thread classified every batch itself, and at
        // 2,000 feeders hashing alone was a fifth of its work, the serial part every step waited
        // on (2026-10-26).
        // Which batches are used is the intake's, in order, before any is classified: it reads
        // the batch's receiver and sequence alone, never what the engine holds, so only those
        // used are classified. Before (2026-10-27), every batch offered was, and at 2,000 feeders
        // on 457 seats three in four were hashed to be thrown away.
        let (mut ingested, mut unused, mut replayed, mut refused) = (0u64, 0u64, 0u64, 0u64);
        let mut used: Vec<&Heard> = Vec::with_capacity(due.len());
        for heard in &due {
            match self.intake.take(&heard.batch, heard.wall_ms) {
                Ok(()) => used.push(heard),
                Err(Ingested::Replayed) => replayed += 1,
                Err(_) => unused += 1,
            }
        }
        let threads = self.settings.threads.max(1);
        let classified: Vec<tally_mlat::engine::Classified<'_>> = gate::on_threads(
            threads,
            used.chunks(gate::piece(used.len(), threads)).collect(),
            |piece: &[&Heard]| {
                piece
                    .iter()
                    .map(|heard| tally_mlat::engine::classify(&heard.receptions))
                    .collect::<Vec<_>>()
            },
        )
        .into_iter()
        .flatten()
        .collect();
        for (heard, classified) in used.iter().zip(&classified) {
            // Charged before it is held: the most a batch adds to the pool is its receptions kept
            // and its place in a slice.
            let most = heard
                .receptions
                .len()
                .saturating_mul(BYTES_PER_KEPT)
                .saturating_add(BYTES_PER_RECEIVER_SLICE);
            if !self.arrived.try_grow(most) {
                refused += 1;
                continue;
            }
            // What the batch grew the pool by replaces its charge at most: the pool's own count,
            // read before and after, never the engine's whole footprint, which is walked once a
            // step (`settle_arrived`). Before, that walk ran after every batch, over every
            // transmission solved and every memo, so a step's taking grew with what the engine
            // held and passed its second at 400 seats (2026-10-26).
            let grown = lock(&self.shared.engine).as_mut().map_or(0, |engine| {
                let before = engine.arrived_bytes();
                let admitted = engine.ingest_classified(heard.batch, heard.at, classified);
                if admitted.refused.is_none() {
                    ingested += 1;
                }
                engine.arrived_bytes().saturating_sub(before)
            });
            self.true_up(most, grown);
        }
        // What was taken let go of on MLAT's threads, not this one (`gate::drop_on_threads`).
        gate::drop_on_threads(threads, classified);
        gate::drop_on_threads(threads, due);
        self.settle_arrived();
        self.shared.count(|counts| {
            counts.ingested += ingested;
            counts.unused += unused;
            counts.replayed += replayed;
            counts.refused += refused;
        });
        self.apply_cuts(step_ms);
        let descriptions = lock(&self.shared.descriptions).take_through(step_ms);
        for (_, record) in tally_mlat::intake::taking_effect(descriptions) {
            self.describe(&record);
        }
        self.set_sites();
    }

    /// The cuts in force at step `step_ms` (module docs, Overload): the same on every relay offered
    /// the same announcements. A cut this host stands by is announced again once its refresh is
    /// due. The receivers it seats or unseats are settled, and one that stopped taking part
    /// forgotten.
    fn apply_cuts(&mut self, step_ms: u64) {
        let mut cuts = lock(&self.shared.cuts);
        cuts.applied(step_ms);
        if let Some(standing) = cuts.own.clone() {
            let due = standing.last_from_ms.saturating_add(CUT_REFRESH_MS);
            let from_ms = (step_ms / STEP_MS + CUT_LEAD_STEPS) * STEP_MS;
            if from_ms >= due {
                let origin = self.signer.public();
                cuts.announce(origin, from_ms, standing.below, &standing.areas, step_ms);
                if let Some(own) = cuts.own.as_mut() {
                    own.last_from_ms = from_ms;
                }
            }
        }
        let cutoffs = cuts.cutoffs_at(step_ms);
        drop(cuts);
        let moved = self.shared.seats.set_cutoffs(cutoffs);
        let left: Vec<PublicKey> = moved
            .into_iter()
            .filter(|key| self.intake.settle(key))
            .collect();
        self.count_refused();
        self.forget(left);
    }

    /// The engine steps at `step` (module docs): its working set reserved in the `Engine` store
    /// while it runs, its records published at once, its run judged for overload from `started`,
    /// when its own taking began, as the `taken` steps it took in (the ones collapsed into it, and
    /// itself).
    fn step(&mut self, step: Moment, started: std::time::Instant, taken: u64) {
        let seats = lock(&self.shared.engine)
            .as_ref()
            .map_or(0, Engine::taking_part);
        let Some(reserved) = self
            .engine_gauge
            .try_charge(seats.max(1).saturating_mul(STEP_BYTES_PER_SEAT))
        else {
            self.shared.count(|counts| counts.steps_unreserved += 1);
            return;
        };
        self.shared.delay(Stage::Step);
        self.hold_neighbours(step);
        let stepped: Option<Step> = lock(&self.shared.engine)
            .as_mut()
            .map(|engine| engine.step(step, &self.signer));
        let ran_ms = self.shared.clock.ran_ms(started);
        drop(reserved);
        self.settle_arrived();
        let Some(stepped) = stepped else {
            self.shared.count(|counts| counts.steps_discarded += 1);
            return;
        };
        let report = StepReport {
            ran_ms,
            ..StepReport::of(&stepped.report)
        };
        let dropped = stepped.report.dropped;
        self.shared.count(|counts| {
            counts.steps += 1;
            counts.thinned += dropped.thinned;
            counts.observations_refused += dropped.refused;
            counts.batches_refused += dropped.refused_batches;
            counts.receivers_refused += dropped.receivers;
            counts.replayed += dropped.replayed;
            counts.models_verified += report.models_verified;
            counts.models_corroborated += report.models_corroborated;
            counts.models_refuted += report.models_refuted;
            counts.models_unneeded += report.models_unneeded;
            counts.steps_total.add(&report);
            counts.last_step = Some(report);
        });
        let origin = self.signer.public();
        let own = stepped
            .models
            .iter()
            .map(|model| OwnModel {
                engine: origin,
                model: Arc::clone(&model.model),
            })
            .collect();
        let records = stepped.records();
        self.shared.delay(Stage::Publish);
        self.shared.publish(records, own);
        self.judge(ran_ms, taken);
    }

    /// Hands the engine the neighbouring areas' models offered (module docs, Areas), before it
    /// steps at `step`: each one of an area it does not fit and still usable, unjudged. The engine
    /// judges one over the raw it holds only once a fix it would publish cites it
    /// (`Engine::step`), and where that raw cannot judge it, it stands on two of its area's
    /// engines' signatures (`Held::corroborated`, which the store sets as the second signs).
    fn hold_neighbours(&mut self, step: Moment) {
        let judged = step.judged();
        let offered: Vec<crate::models::Model> =
            std::mem::take(&mut *lock(&self.shared.neighbours))
                .into_values()
                .filter(|model| tally_mlat::fix::usable(model.model(), judged))
                .collect();
        let mut engine = lock(&self.shared.engine);
        let Some(engine) = engine.as_mut() else {
            return;
        };
        for model in offered {
            if !self.areas.contains(model.area()) {
                engine.hold(Arc::clone(model.model()));
            }
        }
    }

    /// Judges a step's run of `ran_ms`, its taking and its stepping, for the `taken` steps it took in
    /// for overload (module docs, Overload; [`Governor`]): the last steps' middle
    /// past the budget, a cut to the receivers it carries within the target, never below the floor;
    /// a host that cut and whose last steps all ran well within the budget once its seats settled
    /// lifts its cut as far as the worst of them allows. One change in flight at a time.
    fn judge(&mut self, ran_ms: u64, taken: u64) {
        let Some(through) = self.through.map(Mono::ms) else {
            return;
        };
        if self.areas.is_empty() {
            return;
        }
        let seats = &self.shared.seats;
        let limit = seats.limit();
        let scoped = seats.scoped(|area| self.areas.contains(area));
        let own = lock(&self.shared.cuts).own.clone();
        // One change in flight at a time: the next decision waits for this one to take effect.
        if own.as_ref().is_some_and(|own| own.last_from_ms > through) {
            return;
        }
        let seated = Seated {
            taken: scoped.seated,
            total: scoped.draws.len(),
            floor: MIN_CUT_SEATS.min(limit),
            cut: own.is_some(),
        };
        let budget = self.shared.clock.budget_ms();
        let Some(wanted) = self.governor.judge(through, ran_ms, taken, budget, seated) else {
            return;
        };
        // The first receiver cut, by rank: everything below its draw stays.
        let below = scoped.draws.get(wanted).copied().unwrap_or(u128::MAX);
        if own
            .as_ref()
            .map_or(below == u128::MAX, |own| own.below == below)
        {
            return;
        }
        let from_ms = (through / STEP_MS + CUT_LEAD_STEPS) * STEP_MS;
        let mut cuts = lock(&self.shared.cuts);
        let cells = self.areas.cells();
        cuts.announce(self.signer.public(), from_ms, below, cells, through);
        cuts.own = (below != u128::MAX).then(|| Standing {
            below,
            last_from_ms: from_ms,
            areas: cells.to_vec(),
        });
        drop(cuts);
        self.governor.changed(from_ms);
        self.shared.count(|counts| counts.cuts_decided += 1);
    }
}

/// How long after a change of seats takes effect its cost is a step's: a receiver seated then has
/// its raw held over a trailing window, fitted at the refit after its edge is `FIT_LAG` past it,
/// before a fix is solved under its pairs. A lift judged sooner sees steps that do not carry the
/// receivers it seated yet, lifts again on them, and overshoots: the sawtooth a run at 500 feeders
/// showed on 2026-10-26 (seats 500, 250, 313, 392, 491, 500, each lift judged on one step a new
/// seat had not reached).
pub const SEATS_SETTLE_MS: u64 = tally_wire::budget::TRAILING_WINDOW_MS
    + tally_wire::budget::FIT_LAG_MS
    + tally_wire::budget::REFIT_EVERY_MS;
/// How long after a change takes effect before another cut is judged: one refit without the
/// receivers it unseated (`REFIT_EVERY`) and the step that solves under it. A cut judged sooner
/// is judged on steps still carrying the receivers the last one unseated.
pub const CUT_SETTLE_MS: u64 = tally_wire::budget::REFIT_EVERY_MS + STEP_MS;
/// The steps a change of seats is judged over: every turn of the refit grid twice (`REFIT_EVERY` is
/// two steps, `tally_mlat::area::refit_turn` refitting half the areas at each), so no one step,
/// dear or cheap, moves the seats. Before (2026-10-26), one step past the budget cut by up to
/// half, and at 2,000 feeders the seats went 2000, 1157, 614, 750, 475, 577, 704, 513 on the
/// occasional step of twice the others' cost.
pub const JUDGED_STEPS: u64 = 2 * tally_wire::budget::REFIT_EVERY_MS / STEP_MS;

/// The seats a judgment is of (`Host::judge`): those seated of the receivers in the host's areas,
/// those within their share (seated or not), the fewest a cut leaves, and whether the host's own
/// cut stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seated {
    pub taken: usize,
    pub total: usize,
    pub floor: usize,
    pub cut: bool,
}

/// The overload controller (module docs, Overload), apart from the seats it moves so it is judged
/// on its own. It judges the last [`JUDGED_STEPS`] steps run once the last change has taken
/// effect and been refit ([`CUT_SETTLE_MS`]): when their middle runs past the budget (or one step
/// alone runs past all of theirs), it cuts to the seats that run carries within the target (three
/// quarters of the budget), at most half of them a cut; and once the change's seats are fitted
/// ([`SEATS_SETTLE_MS`]) and every one of them ran within seven eighths of the target, it lifts to
/// the seats the worst of them carries within the target, a quarter more at most. So steps between
/// seven eighths of the target and the budget change nothing, and the seats settle there: a step's
/// cost has a part that is not the seats' (the aircraft's), so a lift aimed at the target from
/// below lands at it or under it, never past it. The steps are the last few,
/// not every one since the change: a host whose load fell lifts once it is cheap, where one that
/// remembered its dearest step since its last cut never would.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Governor {
    /// When the last change took effect (its cut's first step), if any.
    changed_ms: Option<u64>,
    /// The last steps run since the last change was refit, by their count, that count, and how
    /// many of them ran once its seats were fitted.
    recent_ms: [u64; JUDGED_STEPS as usize],
    steps: u64,
    fitted: u64,
}

impl Governor {
    /// A change of seats takes effect at `from_ms`.
    pub fn changed(&mut self, from_ms: u64) {
        self.changed_ms = Some(from_ms);
        self.recent_ms = [0; JUDGED_STEPS as usize];
        self.steps = 0;
        self.fitted = 0;
    }

    /// The step at `through_ms` ran `ran_ms` of a budget of `budget_ms`, its own taking and its
    /// stepping, and took in `taken` steps (itself and the ones collapsed into it), with `seated`:
    /// the seats to cut or lift to, by rank (the count to keep), or `None` to hold them. A step that
    /// took in several is judged as each of them: they passed while the one before it ran, so a
    /// host behind fills the steps it is judged over as fast as it falls behind.
    pub fn judge(
        &mut self,
        through_ms: u64,
        ran_ms: u64,
        taken: u64,
        budget_ms: u64,
        seated: Seated,
    ) -> Option<usize> {
        let target = budget_ms / 4 * 3;
        let since = |settle_ms: u64| {
            self.changed_ms
                .is_none_or(|changed| through_ms >= changed.saturating_add(settle_ms))
        };
        let carried = |ran_ms: u64| {
            (seated.taken as u128 * u128::from(target) / u128::from(ran_ms.max(1))) as usize
        };
        if !since(CUT_SETTLE_MS) {
            return None;
        }
        let judged = JUDGED_STEPS as usize;
        let taken = taken.clamp(1, JUDGED_STEPS);
        for _ in 0..taken {
            self.recent_ms[self.steps as usize % judged] = ran_ms;
            self.steps += 1;
        }
        if since(SEATS_SETTLE_MS) {
            self.fitted += taken;
        }
        let alone = ran_ms > JUDGED_STEPS * budget_ms;
        if self.steps < JUDGED_STEPS && !alone {
            return None;
        }
        let mut sorted = self.recent_ms;
        sorted.sort_unstable();
        let middle = if alone {
            ran_ms
        } else {
            (sorted[judged / 2 - 1] + sorted[judged / 2]) / 2
        };
        if middle > budget_ms {
            if seated.taken <= seated.floor {
                return None;
            }
            // At most half of them a cut: a step's cost is not in proportion to its seats (a part
            // of it is the aircraft's, whatever the receivers), so a cut aimed at the target in one
            // go would undershoot; the next judges again once it has taken effect.
            return Some(
                carried(middle)
                    .max(seated.floor)
                    .max(seated.taken / 2)
                    .min(seated.taken - 1),
            );
        }
        let worst_ms = sorted[judged - 1];
        if seated.cut
            && seated.total > seated.taken
            && self.fitted >= JUDGED_STEPS
            && worst_ms < target / 8 * 7
        {
            return Some(
                carried(worst_ms)
                    .min(seated.taken + seated.taken / 4 + 1)
                    .max(seated.taken + 1),
            );
        }
        None
    }
}

/// The stamp clock of a test that runs relays hosting MLAT over sockets (this crate's
/// `tests/mlat_host.rs`, the API's end to end): one clock for every relay of the test, moved a step
/// at a time ([`stepping::step`]) only once every relay has been offered what was fed by it and its
/// hosted MLAT has stepped to it and published, and never past the wall clock. So a batch fed once
/// the clock reaches its own wall clock is stamped within a step after it (never ahead of the
/// stamp, `arrived::AHEAD_MS`), a scenario in the past is walked as fast as the relays keep up, and
/// nothing a test asserts depends on how fast its machine is: it asserts in stamps.
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
                crate::clock::RelayClock::system().judged().ms()
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
        pub fn clock(self: &Arc<Self>) -> crate::clock::Script {
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
                if published && now + STEP_MS <= crate::clock::RelayClock::system().judged().ms() {
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

/// How a piece of MLAT's work is scheduled against the rest of the relay's. Every piece runs below
/// the stages' priority (RFC-0181 §10, "The cores"): the cores are planned so the stages' half-busy
/// share and MLAT's fit together (`cores::mlat_threads_for`), and when MLAT needs more than its
/// share it is MLAT that waits, and collapses the steps it falls behind on (counted), never raw
/// that is delayed. Nothing a stage waits on is held by a step: an inbox is locked only to push a
/// batch or to take a step's out of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Urgency {
    /// The steps: a fix is due within seconds of its transmission (`tally_wire::budget::FIX_SOLVE`),
    /// so they run below the stages and above standing (`STEPS_NICE`), and are let in to the gate
    /// first.
    Steps,
    /// Standing's settling, which MLAT's positions bring: settled at their arrival bound, half a
    /// minute after a transmission (`tally_wire::budget::FIX_ARRIVED`), so it runs lowest
    /// (`BACKGROUND_NICE`) and yields the cores to the stages and the steps.
    Background,
}

impl Urgency {
    /// How far below the relay's own priority (the stages', whatever nice the relay was started
    /// at) its threads run, in nice steps. Linux gives each thread its own, and the threads a step
    /// spreads its work over (`tally_mlat::fix::parallel`) inherit it. Each step of nice is about
    /// 1.25 times less weight against a thread at the one above (the kernel's
    /// `sched_prio_to_weight`): 5 below, a stage's thread outweighs a step's about 3 to 1, 10 below
    /// standing's about 9 to 1.
    const fn below(self) -> libc::c_int {
        match self {
            Self::Steps => STEPS_NICE,
            Self::Background => BACKGROUND_NICE,
        }
    }

    /// The gate's urgency (`tally_mlat_solver::gate`): the steps are let in first.
    const fn gate(self) -> gate::Urgency {
        match self {
            Self::Steps => gate::Urgency::Prompt,
            Self::Background => gate::Urgency::Background,
        }
    }
}

/// Lowers the calling thread to the priority of MLAT's background work (`Urgency::Background`):
/// what a thread doing work the hosted MLAT brings beside its steps (the relay's standing) runs
/// at. False when it could not be lowered all the way (`run_at`).
pub fn run_as_background() -> bool {
    run_at(Urgency::Background.below())
}

/// How far below the stages' priority the steps run: nice steps.
const STEPS_NICE: libc::c_int = 5;
/// How far below the stages' priority standing runs: nice steps.
const BACKGROUND_NICE: libc::c_int = 10;
const _: () = assert!(0 < STEPS_NICE && STEPS_NICE < BACKGROUND_NICE);

/// Lowers the calling thread's priority `below` nice steps under its own (what the thread that
/// started it had: the relay's), at most to the lowest; false when it could not be lowered all of
/// them (a relay already near the lowest, at nice 19 none, has MLAT level with or less far below
/// its stages than planned, counted). A thread may always lower its own. The system calls are
/// `os`'s, the one module here that holds `unsafe` for them and no key.
fn run_at(below: libc::c_int) -> bool {
    crate::os::lower_own_nice(below)
}

/// Ends the process when the thread it is held on unwinds (decided): hosted MLAT that panics ends
/// the relay like every other part of it (`crate::abort_on_any_panic`, which the relay's program
/// sets and which ends it before anything unwinds; a worker's panic inside a step is its step's,
/// `gate::on_threads`). Held by the runner, so a host built apart from the relay's program (a
/// test's) is held to the same: MLAT never runs on without the part that panicked.
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
mod tests;
