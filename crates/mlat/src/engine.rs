//! The engine's state (RFC-0171 §3.8, §3.8.1): the receivers it multilaterates for, the raw
//! observations it holds (`tally_mlat_solver::held`, compact, per bin), and which windows it has
//! solved. The receivers and their open raw are its [`Intake`] (`intake`): an engine holds its
//! own ([`Engine::new`]), or its host holds them split by receiver and hands it the sealed bins
//! and what each batch says to provisional solving ([`Engine::hosted`]: a relay's raw shards,
//! RFC-0181 §5), and the same raw solves to the same bytes either way. Nothing here reads a clock or a socket: the caller says what time it is, so the same
//! records in any order leave the same state, and the same state solves to the same bytes
//! (`window`).
//!
//! - A receiver takes part on its own signed word only: its newest site-bearing record (its
//!   `ReceiverSite`, or an old feeder's format 1 `ReceiverInfo`, `intake::SiteRecord`) verifies,
//!   places it inside the engine's regions, and names a clock the solver specification knows with a
//!   location no coarser than it allows (`tally_mlat_solver::obs::MAX_SITE_PRECISION_M`). A
//!   format 2 description carries no site and places nobody.
//! - A batch is used once: it must verify, be from a receiver that takes part, and carry a
//!   (boot, sequence) not already used and not too far behind that boot's newest (§3.1), so a batch
//!   two relays deliver, or a relay replays, adds nothing.
//! - An observation is held once (the G-Set of §3.8.1): its identity is (receiver key, counter
//!   epoch, raw counter, message hash), the same however many paths delivered it, so the held set
//!   is the union of everything delivered. Only what MLAT uses is held (the solver's ingest
//!   prefilter and, when a bin is sealed, its canonical thinning), in 24 bytes an observation. The
//!   raw it holds is the one store its host keeps (`Engine::sealed_bins` is what the host's other
//!   readers, a relay's standing, share), sealed on `Settings::threads` threads.
//! - **Capacity is configuration, and refusal is whole and never by order** (RFC-0181 §9). How many
//!   receivers it seats and what its raw may hold come from `Settings::capacity`, which a relay
//!   derives from the receivers it admits. Who is seated is the best ranked of those described
//!   (`intake::Seats`), whatever order they came in; one outranked is refused whole (its raw never
//!   held) and counted. A receiver's raw of a bin beyond its share is refused whole, and the bytes
//!   are checked on each whole bin as it is sealed (`held::Bin::seal_within`): both counted, never
//!   decided by arrival order.
//! - Which window an observation is in is decided by its content alone: its grid bin is its
//!   signed batch wall clock's, never when it arrived (`tally_mlat_solver::scope`). A bin is
//!   sealed once it has ended and a settling time has passed by the engine's clock, and a window
//!   (strided: one fit per tile per `STRIDE` bins) is solved once its last bin is sealed; when
//!   decides only whether late raw makes it in, never what the same raw solves to.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tally_mlat_solver::held::{Bin, Fragment, Limits, RAW_SPARE_BINS, Rates, SealedBins};
use tally_mlat_solver::scope::{AFTER, BEFORE, STRIDE, Window, bin_of};
use tally_wire::clocks::{Judged, Moment, Mono, Span};
use tally_wire::{Batch, Decoded, PublicKey, Record, Regions, Signer};

use crate::intake::{Intake, Orphaned, Seats, SiteRecord, Sited};
use crate::provisional::{self, Provisional};
use crate::window::{Job, Outcome, Report};

/// What an engine is sized for when its host does not say (`Capacity::default`, an engine run on
/// its own or in a test): a region's whole receiver population at the founder's requirement
/// (RFC-0181: one relay, 20,000 feeders). A relay's hosted engine is sized by the relay's feeder
/// ceiling instead (`Capacity::for_receivers`), with no floor: its seats come from the same budget
/// as everything else it holds.
pub const MIN_RECEIVERS: usize = 20_000;

/// Receptions one receiver at the measured rates may have waiting for provisional solving: its
/// wanted receptions over the longest a reception waits (`provisional::WAITING_MS`).
pub const WAITING_PER_RECEIVER: usize =
    Rates::MEASURED.wanted_per_s * provisional::WAITING_MS as usize / 1_000;
/// How long after the window step that published a model provisional solving takes it up: by the
/// step's stamp, never by when it reported, so the provisional step at `t` carries exactly the
/// models of the window steps at or before `t - MODELS_RIPEN_MS`, in line and hosted alike, and
/// the same stamped trace solves the same provisionals however long its window steps ran. A host
/// that runs its provisional steps apart from its window steps (a relay's,
/// `tally_relay::mlat_host`) so that a slow window step never holds a provisional one up, starts a
/// provisional step only once every window step this long before it has reported, and sheds it,
/// counted, when one has not: never starts it with other models than these. So this is at least a
/// window step's run on the threads its host plans (measured on a relay's planned threads, RFC-0181
/// "MLAT in the cores", 9 to 11 s at 2,000 feeders; it was 5 s, and every window step past it made
/// the provisional bytes depend on thread timing), and at least the window steps a host may fall
/// behind. Its delay is part of how far a model is carried (`tally_mlat_solver::MAX_CARRY_PS`,
/// held to it below).
pub const MODELS_RIPEN_MS: u64 = 15_000;

// How far a provisional carries a model past its last knot, at most: a tile's model is refitted
// every stride, so the newest one's window ended up to `STRIDE + AFTER` bins before the bin a
// reception falls in, and that bin's own length on; the window was solved once settled
// (`MLAT_SETTLE`), its model ripens `MODELS_RIPEN_MS` later, and a reception may be stamped up to
// `MLAT_AHEAD` past the judging clock that sealed it, plus one bin of rounding. 84 s, inside the
// spec's 90 s.
const _: () = {
    use tally_mlat_solver::scope::GRID_MS;
    use tally_wire::budget::{MLAT_AHEAD, MLAT_SETTLE};
    let carried_ms = (STRIDE + AFTER) as u64 * GRID_MS
        + MLAT_SETTLE.span::<Judged>().ms()
        + MODELS_RIPEN_MS
        + MLAT_AHEAD.span::<Judged>().ms()
        + GRID_MS;
    assert!(tally_mlat_solver::MAX_CARRY_PS >= carried_ms as i128 * 1_000_000_000);
};

/// How much an engine holds, derived from what its host admits (RFC-0181 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// Receivers described at once, taking part or not: every receiver whose raw reaches it (a
    /// relay's admitted feeders and the border band its raw links carry). A new one beyond them
    /// is refused whole and counted.
    pub receivers: usize,
    /// The rates each receiver is admitted at, which size the raw held
    /// (`tally_mlat_solver::held::Limits::for_receivers`).
    pub rates: Rates,
}

impl Capacity {
    /// Sized for exactly `receivers` at the measured rates: a relay's feeder ceiling (RFC-0181 §9,
    /// "MLAT receiver limit comes from the same F"), so the raw it may hold (`Settings::limits`)
    /// is what the budget reserved for it, and never more.
    pub fn for_receivers(receivers: usize) -> Self {
        Self {
            receivers,
            rates: Rates::MEASURED,
        }
    }
}

impl Capacity {
    /// Receptions waiting for provisional solving, at most: each receiver's wanted receptions over
    /// the longest one waits (`provisional::WAITING_MS`). Beyond it a batch's replies are refused
    /// whole (`provisional::admit`).
    pub fn waiting(&self) -> usize {
        self.receivers
            .saturating_mul(self.rates.wanted_per_s)
            .saturating_mul(provisional::WAITING_MS as usize)
            / 1_000
    }
}

impl Default for Capacity {
    fn default() -> Self {
        Self::for_receivers(MIN_RECEIVERS)
    }
}

/// What the operator chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The H3 cells whose receivers take part; empty is every receiver with a location.
    pub regions: Regions,
    /// How long after a bin's canonical window ends (by the engine's judging clock) it is solved,
    /// so the raw of the window's last bin is in.
    pub settle: Span<Judged>,
    /// The threads one step's work, and a bin's sealing, are spread over. Any number gives the
    /// same bytes.
    pub threads: usize,
    /// How much it holds.
    pub capacity: Capacity,
}

impl Settings {
    /// The raw it may hold.
    pub fn limits(&self) -> Limits {
        Limits::for_receivers(
            self.capacity.receivers,
            self.capacity.rates,
            self.settle.ms(),
        )
    }
}

/// What one record did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingested {
    /// A receiver description, newer than the one held.
    Described,
    /// A batch: observations taken, and those MLAT never uses (not held).
    Batch { new: usize, filtered: usize },
    /// A batch whose (boot, sequence) was already used or is too far behind.
    Replayed,
    /// Anything else, or a record of a receiver that takes no part.
    Ignored,
    /// A new receiver's description beyond `Capacity::receivers`: refused whole, and counted.
    Refused,
}

/// A window passed over unsolved (`Engine::pass_sealed`), by the judging times between which the
/// engine solving in line carries its model in provisional solving: from when it would ripen
/// (`MODELS_RIPEN_MS` after its window fell due) to when it is spent (`MAX_CARRY_PS` past its
/// window). A provisional step judged in between would have carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Passed {
    pub ripe_ms: u64,
    pub spent_ms: u64,
}

impl Passed {
    /// Whether a provisional step judged at `judged` would have carried it.
    pub fn carried_at(&self, judged: Judged) -> bool {
        tally_wire::budget::reached(self.ripe_ms, judged)
            && !tally_wire::budget::passed(self.spent_ms, judged)
    }
}

/// What was refused since the last step, every refusal whole.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    /// Observations of a bin already sealed: later than its settling.
    pub late: u64,
    /// Observations refused with their receiver's whole raw of a bin (`Limits`).
    pub refused: u64,
    /// Receivers refused whole for room (`intake::Seats`): new ones outranked, and seated ones a
    /// better ranked one took the seat of.
    pub receivers: u64,
    /// Observations of a bin that begins too far past their batch's stamp
    /// (`tally_mlat_solver::held::AHEAD_MS`), refused.
    pub ahead: u64,
}

pub struct Engine {
    /// The relay's key as everything the engine signs reaches it: only while its clock is
    /// judging (`tally_wire::Signer`), so a step that finishes after it lost sync signs nothing.
    signer: Signer,
    boot_id: u64,
    settings: Settings,
    /// The areas whose tiles it fits (`set_scope`): a tile is fitted only if its centre is in one.
    /// Empty: every tile its regions cover.
    owned: Regions,
    /// Its receivers and their open raw, when it holds them itself; `None` when its host does
    /// (`hosted`).
    intake: Option<Intake>,
    /// The sealed bins: its own, or its host's, shared with the host's other readers.
    sealed: SealedBins,
    /// The windows solved, by their last bin.
    processed: BTreeSet<i64>,
    positions_sequence: u64,
    models_sequence: u64,
    dropped: Dropped,
    provisional: Provisional,
    /// Batches waiting for a description let go, since it started.
    orphaned: Orphaned,
    /// The models window steps published, each with the judging time on the bin grid from which
    /// provisional solving takes it up (`MODELS_RIPEN_MS` after its window's due step).
    ripening: Vec<(u64, provisional::Carried)>,
}

impl Engine {
    /// `boot_id` is this process's: relays number an engine's records per (engine, boot), so a
    /// restart starts its sequences again at 0 without colliding with what the last boot sent.
    pub fn new(signer: Signer, boot_id: u64, settings: Settings) -> Self {
        Self::sharing(signer, boot_id, settings, SealedBins::new())
    }

    /// As `new`, sealing into `sealed`: the handle its host's other readers of the raw keep (a
    /// relay's standing), so the raw is held once.
    pub fn sharing(signer: Signer, boot_id: u64, settings: Settings, sealed: SealedBins) -> Self {
        let intake = Intake::new(
            Seats::new(settings.capacity.receivers),
            Limits {
                bytes: usize::MAX,
                ..settings.limits()
            },
            Some(settings.regions.clone()),
        );
        let mut engine = Self::hosted(signer, boot_id, settings, sealed);
        engine.intake = Some(intake);
        engine.provisional = Provisional::new(engine.settings.capacity.waiting());
        engine
    }

    /// An engine whose host holds its receivers and their raw (`intake::Intake`, split by
    /// receiver) and seals it into `sealed`: its host weighs what each batch says to provisional
    /// solving (`provisional::Shard::read`) and hands it the sites and the sealed bins at each
    /// step (`prepare_sealed`), and it solves them as `new`'s engine solves the same raw.
    pub fn hosted(signer: Signer, boot_id: u64, settings: Settings, sealed: SealedBins) -> Self {
        Self {
            signer,
            boot_id,
            settings,
            owned: Regions::default(),
            intake: None,
            sealed,
            processed: BTreeSet::new(),
            positions_sequence: 0,
            models_sequence: 0,
            dropped: Dropped::default(),
            provisional: Provisional::hosted(),
            orphaned: Orphaned::default(),
            ripening: Vec::new(),
        }
    }

    pub fn boot_id(&self) -> u64 {
        self.boot_id
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Observations held now (an open bin's copies included until it is sealed).
    pub fn held(&self) -> usize {
        self.sealed.len() + self.intake.as_ref().map_or(0, Intake::len)
    }

    /// Bytes of raw held now, as allocated.
    pub fn held_bytes(&self) -> usize {
        self.sealed.bytes() + self.intake.as_ref().map_or(0, Intake::bytes)
    }

    /// The sealed bins it holds, shared: a cheap handle that sees every bin it seals and forgets.
    pub fn sealed_bins(&self) -> SealedBins {
        self.sealed.clone()
    }

    /// Whether `receiver` is described, and whether it takes part (one refused for room is
    /// described, and takes no part). Always `None` for a hosted engine.
    pub fn described(&self, receiver: &PublicKey) -> Option<bool> {
        self.intake.as_ref()?.described(receiver)
    }

    /// Receivers taking part now (of its own intake).
    pub fn taking_part(&self) -> usize {
        self.intake.as_ref().map_or(0, Intake::taking_part)
    }

    /// Takes a record a relay delivered, at `at` by the engine's clocks (which decide only when a
    /// reception is solved provisionally and how far ahead raw may open, never what anything
    /// solves to). An error is a
    /// record that claimed to be signed and is not. A hosted engine takes nothing this way: its
    /// host's intakes do.
    pub fn ingest(&mut self, record: &Record, at: Moment) -> Result<Ingested, String> {
        match record {
            Record::ReceiverSite(_) | Record::ReceiverInfo(_) => {
                // A format 2 description carries no site: it places nobody.
                let (Some(intake), Some(site)) = (self.intake.as_mut(), SiteRecord::of(record))
                else {
                    return Ok(Ingested::Ignored);
                };
                // One intake holds every receiver, so no other intake's receiver moves.
                let described = intake.describe(&site)?;
                let key = site.receiver().map_err(|error| error.to_string())?;
                // The batches that waited for it, taken now as they would have been then.
                for batch in intake.take_orphans(&key) {
                    let (_, notes) = intake.ingest_verified(&batch);
                    self.provisional.hear_notes(&batch, notes);
                }
                self.forget_receivers(&described.left);
                Ok(described.ingested)
            }
            Record::Batch(batch) => self.receive(batch, at),
            // A relay's deduplicated stream is the relay's word, not a receiver's: it carries no
            // receiver's counter and is never multilaterated.
            _ => Ok(Ingested::Ignored),
        }
    }

    /// Forgets `receiver` in the sealed bins: it stopped taking part (its intake forgot its open
    /// raw).
    pub fn forget_receiver(&mut self, receiver: &PublicKey) {
        self.forget_receivers(std::slice::from_ref(receiver));
    }

    /// Forgets every one of `receivers` in the sealed bins at once: each bin that held any of
    /// them sealed again once, however many left together (`SealedBins::forget_receivers`), never
    /// once a receiver.
    pub fn forget_receivers(&mut self, receivers: &[PublicKey]) {
        self.sealed
            .forget_receivers(receivers, self.settings.threads.max(1));
    }

    /// Changes what the engine covers, as a relay hosting it does when the areas it is an MLAT
    /// relay for change (RFC-0174 §2.3): `regions` as `Settings::regions` (the receivers that take
    /// part, and the footprints a fitted tile must lie inside: an area and its border band), and
    /// `owned` the areas whose tiles it fits (a tile's centre in one; empty, every tile `regions`
    /// cover). Every receiver described is decided again on its own signed word: one now outside
    /// takes no part and what it heard is forgotten, as when its own description moves it out; one
    /// now inside takes part from its next batch. The same records under the same scope solve to
    /// the same bytes whatever scopes came before. A hosted engine's host re-scopes its intakes.
    pub fn set_scope(&mut self, regions: Regions, owned: Regions) {
        self.settings.regions.clone_from(&regions);
        self.owned = owned;
        if let Some(intake) = self.intake.as_mut() {
            let left = intake.set_scope(Some(regions)).left;
            self.forget_receivers(&left);
        }
    }

    fn receive(&mut self, batch: &Batch, at: Moment) -> Result<Ingested, String> {
        let key = batch.receiver().map_err(|error| error.to_string())?;
        // Described and taking no part: nothing of it is held. Not described: it waits for the
        // description (`intake::Intake::hold_orphan`), verified first.
        if self.described(&key) == Some(false) {
            return Ok(Ingested::Ignored);
        }
        batch
            .verify()
            .map_err(|error| format!("batch of {key}: {error}"))?;
        match Decoded::from_verified(batch.clone(), at, 0) {
            Ok(decoded) => Ok(self.ingest_verified(&decoded)),
            // A format this build cannot read uses its sequence and holds nothing.
            Err(_) => Ok(self.intake.as_mut().map_or(Ingested::Ignored, |intake| {
                intake.use_sequence(&key, batch.boot_id(), batch.sequence())
            })),
        }
    }

    /// Takes a batch whose signature the caller already verified and which it decoded once
    /// (`tally_wire::Decoded`), at its own stamp: a relay hosting this engine
    /// hands it what its own ingest checked, so nothing is verified or decoded twice. As `ingest`
    /// otherwise: used once per (boot, sequence), held only from a receiver that takes part.
    pub fn ingest_verified(&mut self, batch: &Arc<Decoded>) -> Ingested {
        let Some(intake) = self.intake.as_mut() else {
            return Ingested::Ignored;
        };
        let (ingested, notes) = intake.ingest_verified(batch);
        if ingested == Ingested::Ignored && intake.described(&batch.receiver()).is_none() {
            let orphaned = intake.hold_orphan(batch);
            self.orphaned.dropped += orphaned.dropped;
        }
        self.provisional.hear_notes(batch, notes);
        ingested
    }

    /// Lets go the batches that waited `intake::ORPHAN_MS` for a description by the step at
    /// `now` on the monotonic clock. What batches waiting for a description were let go since it
    /// started.
    pub fn expire_orphans(&mut self, now: Mono) -> Orphaned {
        if let Some(intake) = self.intake.as_mut() {
            self.orphaned.expired += intake.expire_orphans(now).expired;
        }
        self.orphaned
    }

    /// Refusals its host's intakes counted, reported with the next step.
    pub fn add_dropped(&mut self, dropped: Dropped) {
        self.dropped.late += dropped.late;
        self.dropped.refused += dropped.refused;
        self.dropped.receivers += dropped.receivers;
        self.dropped.ahead += dropped.ahead;
    }

    /// The latest bin complete by the judging clock reading `judged`: it ended, and the settling
    /// time after it passed. The bins are the feeders' signed times, so the judging clock, never
    /// the monotonic one (a type: `tally_wire::clocks`).
    pub fn settled(&self, judged: Judged) -> i64 {
        bin_of(judged.earlier(self.settings.settle).ms()) - 1
    }

    /// The last bin through which every window's model has ripened by the judging clock reading
    /// `judged` (`MODELS_RIPEN_MS` after the window fell due, [`Engine::ripen`]'s rule): a
    /// provisional step judged at `judged` carries the model of every window whose last bin is at
    /// or before it, so a host starts one only once every such window is solved or passed over.
    pub fn ripe_through(&self, judged: Judged) -> i64 {
        self.settled(judged.earlier(tally_wire::budget::policy::<_, MODELS_RIPEN_MS>()))
    }

    /// Seals every bin that is complete, hands out the work of every window whose bins are all
    /// sealed and that is not solved yet (owned: the sealed bins are shared, not copied), so it
    /// runs off the thread that keeps ingesting; and forgets the bins no window still to be solved
    /// needs. `None` when there is nothing to solve. `at` is the step: its judging clock settles
    /// the bins and is what the records it signs carry. A hosted engine's host seals instead and
    /// calls `prepare_sealed`.
    pub fn prepare(&mut self, at: Moment) -> Option<Job> {
        let settled = self.settled(at.judged());
        let threads = self.settings.threads.max(1);
        let intake = self.intake.as_mut()?;
        let fragments = intake.take_through(settled);
        let sites: Vec<Sited> = intake.sites().collect();
        let dropped = intake.take_dropped();
        self.add_dropped(dropped);
        let (bins, refused) = seal(fragments, threads, self.room());
        self.dropped.refused += refused as u64;
        for bin in bins {
            self.sealed.insert(bin);
        }
        self.prepare_sealed(at.judged(), settled, sites)
    }

    /// The bytes of raw the sealed bins may still grow by: `Settings::limits` less what is sealed.
    pub fn room(&self) -> usize {
        self.settings
            .limits()
            .bytes
            .saturating_sub(self.sealed.bytes())
    }

    /// As `prepare`, for an engine whose host sealed every bin through `settled` (the latest bin
    /// complete at its step) and holds the receivers taking part, `sites`, in key order
    /// (`intake::Intake::sites`: each with its reception key).
    pub fn prepare_sealed(
        &mut self,
        issued: Judged,
        settled: i64,
        sites: Vec<Sited>,
    ) -> Option<Job> {
        let windows: Vec<Window> = self
            .sealed
            .numbers()
            .into_iter()
            .map(Window::canonical)
            .filter(|window| window.last <= settled && !self.processed.contains(&window.last))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let job = match (windows.first(), windows.last()) {
            (Some(first), Some(last)) => Some(Job {
                signer: self.signer.clone(),
                boot_id: self.boot_id,
                issued_ms: issued.ms(),
                threads: self.settings.threads.max(1),
                regions: self.settings.regions.clone(),
                owned: self.owned.clone(),
                windows: windows.clone(),
                sites,
                bins: self.sealed.bins(first.first, last.last),
                positions_sequence: self.positions_sequence,
                models_sequence: self.models_sequence,
            }),
            _ => None,
        };
        self.forget_by(settled, i64::MAX);
        job
    }

    /// Forgets what no window still to be solved needs as of the step whose bins are sealed
    /// through `settled`, and nothing from bin `floor` on: what `prepare_sealed` forgets
    /// once it has handed its windows out. A host that seals at every step and prepares windows
    /// only at the steps where one falls due (`falls_due`; a relay's, `tally_relay::mlat_host`)
    /// forgets so at every step, its `floor` the first bin of a window it has not solved yet, so
    /// what the sealed bins hold, and the room the next seal has, is the stamps' alone, as in line,
    /// and a window that waits is never solved without the bins it began with.
    pub fn forget_by(&mut self, settled: i64, floor: i64) {
        let keep = kept_by_stamps(settled).min(floor);
        self.sealed.forget_before(keep);
        if let Some(intake) = self.intake.as_mut() {
            intake.forget_before(keep);
        }
        self.processed.retain(|last| *last >= keep);
    }

    /// The first bin of the earliest window of the sealed bins that falls due at the step whose
    /// bins are sealed through `settled`, the step before it having sealed through `before`: of
    /// those whose last bin is in `(before, settled]`, which `prepare_sealed` at that step hands
    /// out. `None` when none does.
    pub fn falls_due(&self, before: i64, settled: i64) -> Option<i64> {
        self.sealed
            .numbers()
            .into_iter()
            .map(Window::canonical)
            .filter(|window| before < window.last && window.last <= settled)
            .map(|window| window.first)
            .min()
    }

    /// The judging time a window falls due at, on the bin grid: the first at which its last bin is complete
    /// (`settled`). A model it published ripens `MODELS_RIPEN_MS` after it, whenever the window
    /// was solved. On the bin grid, so the judging clock's.
    fn due(&self, window: &Window) -> u64 {
        (window.last.max(-1) + 1) as u64 * tally_mlat_solver::scope::GRID_MS
            + self.settings.settle.ms()
    }

    /// Takes a finished job's outcome: what it solved is not solved again, and its records are
    /// the next in this boot's sequences. The records to publish, in order, and what the step did.
    /// Its models ripen for provisional solving (`MODELS_RIPEN_MS`), so its caller publishes every
    /// model record among them: a provisional fix cites only a model its readers received. A
    /// caller that refuses the records is [`Engine::apply_unpublished`]'s.
    pub fn apply(&mut self, outcome: Outcome) -> (Vec<Record>, Report, Dropped) {
        self.apply_as(outcome, true)
    }

    /// As [`Engine::apply`], for an outcome whose records were refused before any reader received
    /// them (a host's queue of records not yet taken was full): what it solved is still not solved
    /// again and its sequences still advance, but none of its models ripens, so no provisional fix
    /// ever cites a model nobody received. What the step did, and each model's window as
    /// [`Engine::pass_sealed`] gives a window passed over ([`Passed`]): the provisional steps the
    /// engine solving in line would have carried it in carry what that engine would not, and the
    /// host sheds them. Before, it returned none, and those steps ran with fewer models than the
    /// engine in line.
    pub fn apply_unpublished(&mut self, outcome: Outcome) -> (Report, Dropped, Vec<Passed>) {
        let passed = outcome
            .carried
            .iter()
            .map(|carried| self.passed(&carried.window))
            .collect();
        let (_, report, dropped) = self.apply_as(outcome, false);
        (report, dropped, passed)
    }

    /// When `window`'s model would ripen and when it is spent, by the judging clock.
    fn passed(&self, window: &Window) -> Passed {
        Passed {
            ripe_ms: self.due(window).saturating_add(MODELS_RIPEN_MS),
            spent_ms: provisional::spent_ms(window),
        }
    }

    fn apply_as(&mut self, outcome: Outcome, published: bool) -> (Vec<Record>, Report, Dropped) {
        self.processed
            .extend(outcome.windows.iter().map(|window| window.last));
        self.positions_sequence = outcome.positions_sequence;
        self.models_sequence = outcome.models_sequence;
        // Each model ripens by its own window's due step, however late the step that solved it ran
        // (a host's window step that waited, or took up a window shed or put off before it).
        if published {
            let ripening: Vec<(u64, provisional::Carried)> = outcome
                .carried
                .into_iter()
                .map(|carried| (self.passed(&carried.window).ripe_ms, carried))
                .collect();
            self.ripening.extend(ripening);
        }
        let dropped = std::mem::take(&mut self.dropped);
        (outcome.records, outcome.report, dropped)
    }

    /// Passes over the windows of the sealed bins that fall due at the step whose bins are sealed
    /// through `settled`, unsolved: those `prepare_sealed` would hand out at that step, for a host
    /// whose step is already too late for any reader to take its final fixes. They are not solved
    /// again, and what they held is forgotten as `prepare_sealed` forgets it. None of them publishes
    /// a model, so the provisional steps that would have carried one ([`Passed`]) carry what the
    /// engine solving in line would not: the host sheds them. What was passed over, window by
    /// window.
    pub fn pass_sealed(&mut self, settled: i64) -> Vec<Passed> {
        let windows: BTreeSet<Window> = self
            .sealed
            .numbers()
            .into_iter()
            .map(Window::canonical)
            .filter(|window| window.last <= settled && !self.processed.contains(&window.last))
            .collect();
        let passed = windows.iter().map(|window| self.passed(window)).collect();
        self.processed
            .extend(windows.iter().map(|window| window.last));
        self.forget_by(settled, i64::MAX);
        passed
    }

    /// What a provisional step at `at` needs of the engine (`crate::provisional::Plan`), for a
    /// host that holds the address shards: the models carried, spent ones forgotten first, and the
    /// next sequence. At most one step at a time; its outcome is `apply_provisional`'s.
    pub fn provisional_plan(&mut self, at: Moment) -> provisional::Plan {
        self.ripen(at.judged());
        self.provisional
            .plan(at, &self.signer, self.boot_id, self.settings.threads)
    }

    /// The provisional work due at `at` (`crate::provisional`), owned, to run off the ingesting
    /// thread; `None` when nothing is due.
    pub fn provisional(&mut self, at: Moment) -> Option<provisional::Job> {
        self.ripen(at.judged());
        self.provisional
            .due(at, &self.signer, self.boot_id, self.settings.threads)
    }

    /// Provisional solving takes up the models published `MODELS_RIPEN_MS` or more before the
    /// judging clock reads `judged`, in the order they were published: a model ripens on the bin
    /// grid its window fell due on, so by the judging clock, never the monotonic one.
    fn ripen(&mut self, judged: Judged) {
        let ripening = std::mem::take(&mut self.ripening);
        for (ripe, carried) in ripening {
            if tally_wire::budget::reached(ripe, judged) {
                self.provisional.adopt(carried);
            } else {
                self.ripening.push((ripe, carried));
            }
        }
    }

    /// Takes a finished provisional job's outcome: its records are the next in this boot's
    /// provisional sequence. The records to publish.
    pub fn apply_provisional(&mut self, outcome: provisional::Outcome) -> Vec<Record> {
        self.provisional.apply(&outcome);
        outcome.records
    }

    /// `provisional`, run and `apply_provisional` in one, on this thread.
    pub fn provisional_step(&mut self, at: Moment) -> Vec<Record> {
        match self.provisional(at) {
            Some(job) => {
                let outcome = job.run();
                self.apply_provisional(outcome)
            }
            None => Vec::new(),
        }
    }

    /// What provisional solving did since the last call.
    pub fn provisional_report(&mut self) -> provisional::Report {
        self.provisional.take_report()
    }

    /// Tile models held for provisional solutions.
    pub fn carried_models(&self) -> usize {
        self.provisional.models()
    }

    /// `prepare`, run and `apply` in one, on this thread.
    pub fn step(&mut self, at: Moment) -> (Vec<Record>, Report) {
        match self.prepare(at) {
            Some(job) => {
                let (records, report, _) = self.apply(job.run());
                (records, report)
            }
            None => (Vec::new(), Report::default()),
        }
    }
}

/// Seals the open raw `fragments` hold, any split of it by receiver (one holder's, or every raw
/// shard's of a relay), bin by bin ascending, on up to `threads` threads, the bins together within
/// `room` bytes (`Engine::room`): each bin byte for byte what one holder of all of it seals
/// within what the bins before it left (`held::Bin::seal_within`), so what is refused for room is
/// decided on whole bins, the same whatever order the raw came in. The bins, ascending, and the
/// observations refused.
pub fn seal(fragments: Vec<Fragment>, threads: usize, room: usize) -> (Vec<Bin>, usize) {
    let mut by_bin: BTreeMap<i64, Vec<Fragment>> = BTreeMap::new();
    for fragment in fragments {
        by_bin.entry(fragment.bin()).or_default().push(fragment);
    }
    let mut room = room;
    let mut refused = 0;
    let bins = by_bin
        .into_iter()
        .map(|(bin, fragments)| {
            let (sealed, more) = Bin::seal_within(bin, fragments, threads, room);
            room = room.saturating_sub(SealedBins::cost(&sealed));
            refused += more;
            sealed
        })
        .collect();
    (bins, refused)
}

/// The first bin the stamps alone keep at the step whose bins are sealed through `settled`
/// (`Engine::forget_by` keeps no less, and from a waiting window's `floor` on as well): a window
/// still to be solved solves bins after `settled - STRIDE`, so nothing before its history is
/// needed by the engine; and its raw is its host's one store, so it keeps what standing settles
/// against too: a window and its stride behind the last bin settled, and the spare bins
/// (`held::RAW_SPARE_BINS`), within the sealed bins a holder plans (`held::SEALED_BINS_HELD`). A
/// host that charges the bins a waiting window holds beyond these to that window reads the line
/// here. Reckoned from `settled`, never from the clock: the bins are the feeders' signed times,
/// so a settling that grows (`tally_wire::budget::MLAT_SETTLE`) or a judging clock stepped moves
/// what is kept with what is sealed. Before, it was reckoned from the step's clock, so a longer
/// settling forgot a window's first bins before its models ripened.
pub fn kept_by_stamps(settled: i64) -> i64 {
    Window::canonical(settled + 1)
        .first
        .min(settled + 1 - BEFORE - AFTER - STRIDE - RAW_SPARE_BINS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_mlat_solver::obs::MAX_SITE_PRECISION_M;
    use tally_wire::batch::{ReceiverInfoContent, format};
    use tally_wire::clocks::recorded::aligned;
    use tally_wire::{BatchContent, Clock, Location, Observation, Region};
    use tally_wire::{Identity, ReceiverInfo};

    fn settings() -> Settings {
        Settings {
            regions: Regions::default(),
            settle: tally_wire::budget::policy::<_, 1_000>(),
            threads: 1,
            capacity: Capacity::default(),
        }
    }

    fn engine() -> Result<Engine, String> {
        Ok(Engine::new(
            tally_wire::Signer::new(
                Identity::generate().map_err(|e| e.to_string())?,
                std::sync::Arc::new(|| true),
            ),
            7,
            settings(),
        ))
    }

    fn location() -> Location {
        Location {
            lat_e7: 521_000_000,
            lon_e7: 51_000_000,
            alt_m: 10,
            precision_m: 0,
        }
    }

    /// A new feeder's site.
    fn info(receiver: &Identity, issued_ms: u64, location: Location, clock: Clock) -> Record {
        let content = tally_wire::ReceiverSiteContent {
            issued_ms,
            location,
            clock,
        };
        match tally_wire::ReceiverSite::sign(receiver, &content) {
            Ok(site) => Record::ReceiverSite(site),
            Err(_) => Record::Heartbeat,
        }
    }

    /// An old feeder's format 1 description, its site in it.
    fn old_info(receiver: &Identity, issued_ms: u64, location: Location, clock: Clock) -> Record {
        let content = ReceiverInfoContent {
            issued_ms,
            location: Some(location),
            clock,
            software: "test".to_owned(),
            relays: Vec::new(),
        };
        match ReceiverInfo::sign(receiver, &content) {
            Ok(info) => Record::ReceiverInfo(info),
            Err(_) => Record::Heartbeat,
        }
    }

    /// A new feeder's format 2 description: its public cell, no site.
    fn public_info(
        receiver: &Identity,
        issued_ms: u64,
        location: Location,
    ) -> Result<Record, String> {
        ReceiverInfo::sign_public(
            receiver,
            &tally_wire::batch::PublicInfoContent {
                issued_ms,
                cell: Some(Region::public_cell(&location).map_err(text)?),
                clock: Clock::Dump1090,
                software: "test".to_owned(),
                relays: Vec::new(),
            },
        )
        .map(Record::ReceiverInfo)
        .map_err(text)
    }

    /// Sites come from site-bearing records only: a `ReceiverSite`, or an old feeder's format 1
    /// description; a format 2 description places nobody, and a site's reissue (a new record, so
    /// a new site id and reception key) is what the engine then holds.
    #[test]
    fn a_receiver_is_placed_by_its_site_bearing_record_alone() -> Result<(), String> {
        let mut engine = engine()?;
        let (new, old, public) = (
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
        );
        assert_eq!(
            engine.ingest(&public_info(&public, 1, location())?, aligned(0))?,
            Ingested::Ignored
        );
        assert_eq!(engine.described(&public.public()), None);
        assert_eq!(
            engine.ingest(&public_info(&new, 1, location())?, aligned(0))?,
            Ingested::Ignored
        );
        let site = info(&new, 1, location(), Clock::Dump1090);
        assert_eq!(engine.ingest(&site, aligned(0))?, Ingested::Described);
        let described = old_info(&old, 1, location(), Clock::Dump1090);
        assert_eq!(engine.ingest(&described, aligned(0))?, Ingested::Described);
        assert_eq!(engine.taking_part(), 2);
        let intake = engine.intake.as_ref().ok_or("no intake")?;
        let sites: Vec<Sited> = intake.sites().collect();
        let of = |record: &Record| SiteRecord::of(record).ok_or("not site-bearing");
        for (key, record) in [(new.public(), &site), (old.public(), &described)] {
            let held = sites
                .iter()
                .find(|sited| sited.site.receiver == key)
                .ok_or("not taking part")?;
            assert_eq!(held.site.id, of(record)?.site_id());
            assert_eq!(held.key, of(record)?.reception_key());
            assert_eq!(held.site.location, location());
        }
        // Reissued: the newer record's id and key.
        let reissued = info(&new, 2, location(), Clock::Dump1090);
        engine.ingest(&reissued, aligned(0))?;
        let intake = engine.intake.as_ref().ok_or("no intake")?;
        let held = intake
            .sites()
            .find(|sited| sited.site.receiver == new.public())
            .ok_or("not taking part")?;
        assert_eq!(held.site.id, of(&reissued)?.site_id());
        assert_ne!(held.site.id, of(&site)?.site_id());
        Ok(())
    }

    fn observation(timestamp: u64, format: u8) -> Observation {
        Observation {
            format,
            timestamp,
            signal: 100,
            // A DF11 all-call reply with a valid parity: what MLAT holds.
            data: tally_mlat_solver::modes::with_parity(&[0x5d, 0x48, 0x01, 0x23], 0),
        }
    }

    fn batch(
        receiver: &Identity,
        boot_id: u64,
        sequence: u64,
        wall_ms: u64,
        observations: Vec<Observation>,
    ) -> Result<Record, String> {
        Batch::sign(
            receiver,
            &BatchContent {
                boot_id,
                sequence,
                counter_epoch: 1,
                wall_ms,
                dropped: 0,
                previous: [0; 32],
                observations,
            },
        )
        .map(Record::Batch)
        .map_err(|error| error.to_string())
    }

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    #[test]
    fn an_observation_delivered_twice_is_held_once_with_its_earliest_wall_clock()
    -> Result<(), String> {
        use tally_mlat_solver::scope::GRID_MS;
        let mut engine = engine()?;
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), aligned(0))?;
        let base = 1_000 * GRID_MS;
        let first = vec![observation(1_000, format::MODE_S_SHORT)];
        // The same observation in a second batch (a different sequence): one identity.
        let second = vec![
            observation(1_000, format::MODE_S_SHORT),
            observation(2_000, format::MODE_S_SHORT),
        ];
        assert_eq!(
            engine.ingest(
                &batch(&receiver, 1, 1, base + 900, second)?,
                aligned(base + 900)
            )?,
            Ingested::Batch {
                new: 2,
                filtered: 0
            }
        );
        engine.ingest(
            &batch(&receiver, 1, 0, base + 500, first)?,
            aligned(base + 500),
        )?;
        // Sealed (its bin complete), the copy is gone and the earliest wall clock kept.
        let _ = engine.prepare(tally_wire::clocks::recorded::aligned(
            base + GRID_MS + 1_000,
        ));
        assert_eq!(engine.held(), 2);
        Ok(())
    }

    #[test]
    fn a_batch_two_relays_deliver_or_one_replays_is_used_once() -> Result<(), String> {
        let mut engine = engine()?;
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest(&info(&receiver, 1, location(), Clock::Beast), aligned(0))?;
        let record = batch(
            &receiver,
            3,
            100,
            0,
            vec![observation(5, format::MODE_S_SHORT)],
        )?;
        assert!(matches!(
            engine.ingest(&record, aligned(0))?,
            Ingested::Batch { new: 1, .. }
        ));
        assert_eq!(engine.ingest(&record, aligned(0))?, Ingested::Replayed);
        // Far behind the boot's newest: a replay, though never seen.
        let old = batch(
            &receiver,
            3,
            10,
            0,
            vec![observation(6, format::MODE_S_SHORT)],
        )?;
        assert_eq!(engine.ingest(&old, aligned(0))?, Ingested::Replayed);
        // A new boot starts its own sequence.
        let restarted = batch(
            &receiver,
            4,
            0,
            0,
            vec![observation(7, format::MODE_S_SHORT)],
        )?;
        assert!(matches!(
            engine.ingest(&restarted, aligned(0))?,
            Ingested::Batch { new: 1, .. }
        ));
        Ok(())
    }

    #[test]
    fn only_what_mlat_uses_from_receivers_that_take_part_is_held() -> Result<(), String> {
        let mut engine = engine()?;
        let receiver = Identity::generate().map_err(text)?;
        let stranger = Identity::generate().map_err(text)?;
        let unknown_clock = Identity::generate().map_err(text)?;
        let coarse = Identity::generate().map_err(text)?;
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), aligned(0))?;
        engine.ingest(
            &info(&unknown_clock, 1, location(), Clock::Unknown),
            aligned(0),
        )?;
        let mut rounded = location();
        rounded.precision_m = MAX_SITE_PRECISION_M + 1;
        engine.ingest(&info(&coarse, 1, rounded, Clock::Dump1090), aligned(0))?;
        let mixed = vec![
            observation(1, format::MODE_AC),
            observation(2, format::MODE_S_SHORT),
            observation(3, format::UAT_DOWNLINK),
            observation(4, format::MODE_S_LONG),
        ];
        assert!(matches!(
            engine.ingest(&batch(&receiver, 1, 0, 0, mixed)?, aligned(0))?,
            Ingested::Batch { new: 2, .. }
        ));
        for other in [&stranger, &unknown_clock, &coarse] {
            let record = batch(other, 1, 0, 0, vec![observation(9, format::MODE_S_SHORT)])?;
            assert_eq!(engine.ingest(&record, aligned(0))?, Ingested::Ignored);
        }
        assert_eq!(engine.held(), 2);
        assert_eq!(engine.taking_part(), 1);
        Ok(())
    }

    #[test]
    fn a_forged_batch_is_an_error_and_holds_nothing() -> Result<(), String> {
        let mut engine = engine()?;
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), aligned(0))?;
        let Record::Batch(signed) = batch(
            &receiver,
            1,
            0,
            0,
            vec![observation(1, format::MODE_S_SHORT)],
        )?
        else {
            return Err("not a batch".to_owned());
        };
        let mut bytes = signed.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let forged = Batch::from_bytes(bytes).map_err(text)?;
        assert!(engine.ingest(&Record::Batch(forged), aligned(0)).is_err());
        assert_eq!(engine.held(), 0);
        Ok(())
    }

    #[test]
    fn the_newest_description_wins_whatever_order_they_arrive_in_and_leaving_drops_what_was_heard()
    -> Result<(), String> {
        let receiver = Identity::generate().map_err(text)?;
        let elsewhere = Location {
            lat_e7: -335_000_000,
            ..location()
        };
        let region = Region::containing(&location(), 2).map_err(text)?;
        let older = info(&receiver, 1, location(), Clock::Dump1090);
        let newer = info(&receiver, 2, elsewhere, Clock::Dump1090);
        for order in [[&older, &newer], [&newer, &older]] {
            let mut engine = Engine::new(
                tally_wire::Signer::new(
                    Identity::generate().map_err(text)?,
                    std::sync::Arc::new(|| true),
                ),
                1,
                Settings {
                    regions: Regions::new([region]),
                    ..settings()
                },
            );
            for record in order {
                engine.ingest(record, aligned(0))?;
            }
            assert_eq!(engine.taking_part(), 0, "the newer description is outside");
        }
        let mut engine = Engine::new(
            tally_wire::Signer::new(
                Identity::generate().map_err(text)?,
                std::sync::Arc::new(|| true),
            ),
            1,
            Settings {
                regions: Regions::new([region]),
                ..settings()
            },
        );
        engine.ingest(&older, aligned(0))?;
        engine.ingest(
            &batch(
                &receiver,
                1,
                0,
                0,
                vec![observation(1, format::MODE_S_SHORT)],
            )?,
            aligned(0),
        )?;
        assert_eq!(engine.held(), 1);
        engine.ingest(&newer, aligned(0))?;
        assert_eq!(engine.held(), 0);
        Ok(())
    }

    /// What is held is forgotten by its wall clock's bin, once no window still to be solved
    /// spans it.
    #[test]
    fn what_is_held_is_forgotten_by_its_bin_once_no_window_needs_it() -> Result<(), String> {
        use tally_mlat_solver::scope::{GRID_MS, Window};
        let mut engine = engine()?;
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), aligned(0))?;
        let base = 1_000 * GRID_MS;
        engine.ingest(
            &batch(
                &receiver,
                1,
                0,
                base,
                vec![observation(1, format::MODE_S_SHORT)],
            )?,
            aligned(base),
        )?;
        // A second, far enough on that windows long after the first's still need it.
        let later = 1_000 + BEFORE + 3 * STRIDE;
        engine.ingest(
            &batch(
                &receiver,
                1,
                1,
                later as u64 * GRID_MS,
                vec![observation(2, format::MODE_S_SHORT)],
            )?,
            aligned(later as u64 * GRID_MS),
        )?;
        assert_eq!(engine.held(), 2);
        // A window is due once its last bin has ended and the settling time passed.
        let due = |window: Window| (window.last + 1) as u64 * GRID_MS + 1_000;
        let first = Window::canonical(1_000);
        assert!(
            engine
                .prepare(tally_wire::clocks::recorded::aligned(due(first) - 1))
                .is_none()
        );
        assert!(
            engine
                .prepare(tally_wire::clocks::recorded::aligned(due(first)))
                .is_some()
        );
        assert_eq!(engine.held(), 2);
        // Once every window spanning bin 1000 is solved, it goes; then the later one.
        // Standing reads the same store, so the spare bins it settles in are kept too.
        let gone = |bin: i64| Window::canonical(bin + BEFORE + STRIDE + RAW_SPARE_BINS);
        let _ = engine.prepare(tally_wire::clocks::recorded::aligned(due(gone(1_000))));
        assert_eq!(engine.held(), 1);
        let _ = engine.prepare(tally_wire::clocks::recorded::aligned(due(gone(later))));
        assert_eq!(engine.held(), 0);
        Ok(())
    }

    /// A window step whose records were refused unpublished gives each of its models' windows as
    /// passed over (`Passed`, as `pass_sealed` gives one), ripening at its due step and spent with
    /// its window, so the host sheds the provisional steps that would have carried them; and none
    /// of them ripens here. Before, it gave none, and those steps ran with fewer models than the
    /// engine solving in line.
    #[test]
    fn a_window_step_refused_unpublished_gives_its_models_as_passed() -> Result<(), String> {
        use crate::replay::{arrivals, scenario};
        let mut simulation = tally_mlat_solver::sim::run(&scenario(23, 40.0));
        let delivered = arrivals(&mut simulation, 5)?;
        let first = delivered.first().map_or(0, |(at, _)| *at);
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let mut engine = engine()?;
        let mut next = 0;
        let mut now = (first / 100 + 1) * 100;
        let mut descriptions = Vec::new();
        while now <= until {
            while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < now) {
                match SiteRecord::of(record) {
                    Some(site) => descriptions.push((*at, site)),
                    None if matches!(record, Record::ReceiverInfo(_)) => {}
                    None => {
                        engine.ingest(record, aligned(*at))?;
                    }
                }
                next += 1;
            }
            for (at, site) in crate::intake::taking_effect(descriptions.drain(..)) {
                engine.ingest(&site.record(), aligned(at))?;
            }
            if let Some(job) = engine.prepare(aligned(now)) {
                let outcome = job.run();
                if !outcome.carried.is_empty() {
                    let windows: Vec<Window> = outcome
                        .carried
                        .iter()
                        .map(|carried| carried.window)
                        .collect();
                    let (_, _, passed) = engine.apply_unpublished(outcome);
                    assert_eq!(passed.len(), windows.len());
                    for (passed, window) in passed.iter().zip(&windows) {
                        assert_eq!(passed.ripe_ms, engine.due(window) + MODELS_RIPEN_MS);
                        assert_eq!(passed.spent_ms, provisional::spent_ms(window));
                        assert!(passed.carried_at(aligned(passed.ripe_ms).judged()));
                    }
                    let ripe = passed
                        .iter()
                        .map(|passed| passed.ripe_ms)
                        .max()
                        .unwrap_or(0);
                    let _ = engine.provisional_plan(aligned(ripe));
                    assert_eq!(engine.carried_models(), 0, "a model refused ripened");
                    return Ok(());
                }
                let _ = engine.apply(outcome);
            }
            now += 100;
        }
        Err("no window step published a model".into())
    }
}
