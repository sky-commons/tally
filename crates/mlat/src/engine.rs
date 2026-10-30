//! The engine's state (RFC-0171 §3.8, §3.8.1 as amended 2026-10-24, "MLAT in seconds"): the
//! receivers it multilaterates for, the raw that has arrived (`tally_mlat_solver::Arrived`, held
//! in one-second slices and indexed by transmission), the pair models of its areas and of their
//! neighbours, and what it has solved. The receivers are its [`Intake`] (`intake`): an engine holds its own
//! ([`Engine::new`]), or its host holds them split by receiver and hands it what they took and who
//! takes part ([`Engine::hosted`]: a relay's raw shards, RFC-0181 §5), and the same raw arriving
//! at the same times solves to the same bytes either way. Nothing here reads a clock or a socket:
//! the caller says what time it is, so the same arrivals leave the same state, and the same state
//! steps to the same bytes on any number of threads (`fix`).
//!
//! - A receiver takes part on its own signed word only: its newest site-bearing record (its
//!   `ReceiverSite`, or an old feeder's format 1 `ReceiverInfo`, `intake::SiteRecord`) verifies,
//!   places it inside the engine's regions, and names a clock the solver specification knows with a
//!   location no coarser than it allows (`tally_mlat_solver::obs::MAX_SITE_PRECISION_M`). A
//!   format 2 description carries no site and places nobody.
//! - A batch is used once: it must verify, be from a receiver that takes part, and carry a
//!   (boot, sequence) not already used and not too far behind that boot's newest (§3.1), so a batch
//!   two relays deliver, or a relay replays, adds nothing.
//! - An observation is held once: its identity is (receiver key, counter epoch, raw counter,
//!   message hash), the same however many paths delivered it. What MLAT uses of a batch is chosen
//!   by hash thresholds over the batch alone (`tally_mlat_solver::threshold`), never top-k, so what
//!   a holder of less keeps is exactly what a holder of more keeps, restricted.
//! - **Capacity is configuration, and refusal is whole and never by order** (RFC-0181 §9). How many
//!   receivers it seats and what its arrived pool may hold come from `Settings::capacity`, which a
//!   relay derives from the receivers it admits. Who is seated is the best ranked of those
//!   described (`intake::Seats`), whatever order they came in; one outranked is refused whole and
//!   counted. The pool refuses past its caps, whole and counted
//!   (`tally_mlat_solver::arrived::Refused`). The models it fits are its owned areas' (RFC-0174
//!   §2.3), one each a refit, bounded by its areas and their members, never by demand.
//! - **One step a second** ([`Engine::step`], [`STEP_MS`], `tally_wire::budget::REFIT_EVERY`): the
//!   pool is sealed; each owned area with a receiver taking part is refit, once each
//!   `REFIT_EVERY`, at the edge of the refit grid `FIT_LAG` below the step's clock
//!   (`Trailing::fitted_at`, one grid for every relay, so neighbouring areas' models share edges),
//!   warm from its previous model, at its turn of the grid's steps (`area::refit_turn`, a function
//!   of its cell, so every relay refits it at the same step and half the areas are refit each
//!   step: its edge is the grid's whatever its turn, so its bytes are too); every transmission whose first reception arrived [`SETTLE_MS`]
//!   ago is due, from the receptions that had arrived (its considered set), and taken up when its
//!   owner area (`area::owner`) is one of the engine's; each is solved under the models of the
//!   areas its hearers are in (its own and those its host hands it, [`Engine::hold`]), checked
//!   with the verifier anyone else would use, and published once every neighbour's model it cites
//!   stands here (verified over the raw the engine holds the first time a fix cites it, or, where
//!   that raw cannot judge it, corroborated): the engine's own models first, then each fix raw and
//!   tagged, back to back. A reception that
//!   arrives after its transmission was solved makes a bigger considered set at a later step,
//!   solved and published again: the merge's superset rule takes the bigger one (`tally_merge`),
//!   so nothing waits for the slowest receiver.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use tally_mlat_solver::arrived::{Limits, Rates};
use tally_mlat_solver::pair::{Models, PairCache, PairModel};
use tally_mlat_solver::{
    Admitted, Arrived, BatchId, ObservationId, Reception, Sites, Trailing, TransmissionKey,
};
use tally_wire::batch::Hash;
use tally_wire::budget::{
    ARRIVED_SLICE, FIT_LAG, FIX_SETTLE, MLAT_AHEAD, REFIT_EVERY_MS, TRAILING_WINDOW,
};
use tally_wire::clocks::{Judged, Moment};
use tally_wire::footprint::Tree;
use tally_wire::{Batch, Decoded, PublicKey, Record, Region, Regions, Signer};

use tally_mlat_solver::backoff::Slots;

use crate::fix::{self, Held, Report, SHARDS, Shard, Solved};
use crate::intake::{Intake, Seats, SiteRecord, Sited, batch_id, receptions_of};

/// What an engine is sized for when its host does not say (`Capacity::default`, an engine run on
/// its own or in a test): a region's whole receiver population at the founder's requirement
/// (RFC-0181: one relay, 20,000 feeders). A relay's hosted engine is sized by the relay's feeder
/// ceiling instead (`Capacity::for_receivers`), with no floor: its seats come from the same budget
/// as everything else it holds.
pub const MIN_RECEIVERS: usize = 20_000;

/// How long after the first of a transmission's receptions arrives it is solved, from what had
/// arrived by then: a feeder seals a batch once a second, so a transmission's receptions reach the
/// engine spread over that second by the receivers' sealing phases, plus the network's spread;
/// mlat-server's 0.9 s (adsb.lol's `MLAT_DELAY`) is for clients that stream, and a second and a
/// tenth collects what a second's batching spreads. What arrives later is not waited for: a later
/// step solves the bigger set.
pub const SETTLE_MS: u64 = 1_100;
/// How often the engine steps, and so how often it solves what fell due: each owned area is refit
/// at every other step (`REFIT_EVERY`, when the refit grid's edge moves on), its fixes solved at
/// each under its newest model.
pub const STEP_MS: u64 = 1_000;

const _: () = assert!(
    FIX_SETTLE.span::<Judged>().ms() == SETTLE_MS
        && ARRIVED_SLICE.span::<Judged>().ms() == STEP_MS
        && REFIT_EVERY_MS.is_multiple_of(STEP_MS)
);

// How far a fix carries its models past their edge, at most: the newest edge of the refit grid
// is less than `REFIT_EVERY + FIT_LAG` below the step's clock (`Trailing::fitted_at`, whatever the
// step's phase); a fix citing an area whose model of the newest edge is not held yet is solved one
// edge further back (`fix::models_for`), one more `REFIT_EVERY`: an area of the later turn
// (`area::refit_turn`), refit a step after its edge moved on, so at the step before it the newest
// edge is less than `FIT_LAG` and a step below the clock and one edge back is within the bound;
// or a neighbour's model of the newest edge still on its way, which the bound covers while it
// reaches the engine within the step after its area's turn (a relay hands an engine what it was
// offered at its next step, `Engine::hold`, and a model is published at the step it is fitted); the fix's
// receptions are signed at most `MLAT_AHEAD` above the judging clock they arrive by, no later than
// the step; and its first reception arrived `SETTLE_MS` before that. The solver's `MAX_CARRY_PS`
// (`tally_wire::budget::MAX_CARRY`) is this, so no fix the engine solves is ever past it.
const _: () = {
    let carried_ms = 2 * REFIT_EVERY_MS
        + FIT_LAG.span::<Judged>().ms()
        + MLAT_AHEAD.span::<Judged>().ms()
        + SETTLE_MS;
    assert!(tally_mlat_solver::MAX_CARRY_PS >= carried_ms as i128 * 1_000_000_000);
};

/// How much an engine holds and does, derived from what its host admits (RFC-0181 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// Receivers described at once, taking part or not: every receiver whose raw reaches it (a
    /// relay's admitted feeders and the border band its raw links carry). A new one beyond them
    /// is refused whole and counted.
    pub receivers: usize,
    /// The rates each receiver is admitted at, which size the arrived pool
    /// (`tally_mlat_solver::arrived::Limits::for_receivers`).
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
    /// The threads one step's refits and solves are spread over. Any number gives the same bytes.
    pub threads: usize,
    /// How much it holds.
    pub capacity: Capacity,
}

impl Settings {
    /// What its arrived pool may hold.
    pub fn limits(&self) -> Limits {
        Limits::for_receivers(self.capacity.receivers, self.capacity.rates)
    }
}

/// What one record did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingested {
    /// A receiver description, newer than the one held.
    Described,
    /// A batch: receptions the pool kept, and those MLAT never uses (not held).
    Batch { new: usize, filtered: usize },
    /// A batch whose (boot, sequence) was already used or is too far behind.
    Replayed,
    /// Anything else, or a record of a receiver that takes no part.
    Ignored,
    /// A new receiver's description beyond `Capacity::receivers`: refused whole, and counted.
    Refused,
}

/// What ingest refused or thinned since the last step, every refusal whole.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    /// Receptions a threshold dropped (`tally_mlat_solver::Admitted::thinned`).
    pub thinned: u64,
    /// Batches the pool refused past a cap, and their receptions.
    pub refused_batches: u64,
    pub refused: u64,
    /// Receivers refused whole for room (`intake::Seats`): new ones outranked, and seated ones a
    /// better ranked one took the seat of.
    pub receivers: u64,
    /// Batches already used.
    pub replayed: u64,
}

impl Dropped {
    /// What admitting a batch of `offered` receptions did.
    fn add(&mut self, admitted: &Admitted, offered: usize) {
        self.thinned += u64::from(admitted.thinned);
        if admitted.refused.is_some() {
            self.refused_batches += 1;
            self.refused += (offered as u64)
                .saturating_sub(u64::from(admitted.kept) + u64::from(admitted.thinned));
        }
    }
}

/// A pair model of the engine's own the step published: what its fixes cite (`id`, the model's
/// `publish::pair_model_id`), its area and edge, the model itself (shared with the relay's store of
/// models, `tally-relay`'s `models::Models`, never decoded again), and its records in the order
/// they are sent: its parts (none when it fits its manifest, the normal case), its manifest, then
/// its summary for clients (`tally_wire::ClientClockModel`: no member, no site, no pair). The raw
/// form is relay-only.
#[derive(Clone)]
pub struct SignedModel {
    pub area: Region,
    pub edge_ms: u64,
    pub id: Hash,
    pub model: Arc<Held>,
    pub records: Vec<Record>,
}

impl std::fmt::Debug for SignedModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedModel")
            .field("area", &self.area)
            .field("edge_ms", &self.edge_ms)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// One positions record of fixes and its twin (RFC-0174 §2.4): `raw` (format 7, relay-only) and
/// `tagged` (format 8, what a client is sent), the same fixes in the same order, numbered back to
/// back in the engine's positions sequence, citing between them `models` (ascending: every model
/// any of their fixes lists). A relay pairs them with one record of buffer on a link.
#[derive(Clone, Debug)]
pub struct Fix {
    pub models: Vec<Hash>,
    pub raw: tally_wire::Positions,
    pub tagged: tally_wire::Positions,
}

/// What one step published and did.
#[derive(Clone, Debug, Default)]
pub struct Step {
    /// Every model of the engine's own a fix of the step cites first, in the order first cited.
    pub models: Vec<SignedModel>,
    /// The fixes.
    pub fixes: Vec<Fix>,
    pub report: Report,
}

impl Step {
    /// The records to send, in order: every model's first, so a fix never arrives before the
    /// model it cites, then each fix record raw and tagged, back to back.
    pub fn records(&self) -> Vec<Record> {
        let models = self
            .models
            .iter()
            .flat_map(|model| model.records.iter().cloned());
        let fixes = self.fixes.iter().flat_map(|fix| {
            [
                Record::Positions(fix.raw.clone()),
                Record::Positions(fix.tagged.clone()),
            ]
        });
        models.chain(fixes).collect()
    }
}

/// One batch's receptions classified for an engine ([`classify`]): what its pool keeps of them,
/// with each message's hash, and each ADS-B position heard, with its aircraft's shard. A function
/// of the receptions alone, so a host makes it on any thread, and an engine admits it
/// ([`Engine::ingest_classified`]) exactly as it would have the receptions themselves.
#[derive(Debug)]
pub struct Classified<'a> {
    pool: tally_mlat_solver::arrived::Classified<'a>,
    /// Each position heard: its aircraft's shard, its address and when it was heard.
    positions: Vec<(usize, u32, u64)>,
}

/// Classifies one batch's receptions for an engine ([`Classified`]): the hashing and decoding an
/// admission does, apart from the engine.
pub fn classify(receptions: &[Reception]) -> Classified<'_> {
    let positions = receptions
        .iter()
        .filter_map(|reception| {
            fix::position_of(reception)
                .map(|address| (fix::shard_of(address), address, reception.wall_ms))
        })
        .collect();
    Classified {
        pool: tally_mlat_solver::arrived::classify(receptions),
        positions,
    }
}

pub struct Engine {
    boot_id: u64,
    settings: Settings,
    /// The areas it fits and takes transmissions up for (`set_scope`, `fix::Scope::owns`). Empty:
    /// every area with a receiver taking part.
    owned: Regions,
    /// Its receivers, when it holds them itself; `None` when its host does (`hosted`), and says
    /// who takes part with `set_sites`.
    intake: Option<Intake>,
    /// The receivers taking part, for a hosted engine.
    sited: Vec<Sited>,
    /// The sites indexed (`Sites`, which remembers each area's members), with the sites it was
    /// built from: built again only when who takes part, or where, has changed since, which is
    /// compared whole at each use ([`Engine::indexed_sites`]), so no change can leave it stale.
    indexed: Option<(Vec<tally_mlat_solver::Site>, Arc<Sites>)>,
    /// The raw that has arrived.
    arrived: Arrived,
    /// Each aircraft's newest ADS-B position, by address shard (`fix::shard_of`).
    shards: Vec<Shard>,
    /// The pair models it solves under, by area and edge: its own areas', refit at each edge of
    /// the grid, and its neighbours' its host hands it (`hold`), each judged here the first time a
    /// fix cites it (`Held::verdict`), one refuted let go. An own area's newest is
    /// what its next refit starts warm from. Forgotten once no fix may cite it (`fix::usable`).
    models: Tree<(Region, u64), Arc<Held>>,
    /// Each area's memos (`PairCache`), for fitting its model and verifying a peer's model of it,
    /// with the edge it was last fitted at (attempted, fitted or not) and the newest edge it was
    /// used at, forgotten once that is a trailing window old. One an area, kept apart from
    /// nothing a verdict rests on: the memos change no result.
    caches: Tree<Region, AreaCache>,
    /// The transmissions published, by key: how many receptions the last fix of each considered,
    /// so only a bigger set is solved again.
    solved: Tree<TransmissionKey, Solved>,
    /// Each aircraft's slots of its transmit timeline (`tally_mlat_solver::backoff`): those being
    /// decided with their best transmission, and those decided while a candidate may still fall
    /// due.
    slots: Slots<fix::Work>,
    positions_sequence: u64,
    models_sequence: u64,
    dropped: Dropped,
}

impl Engine {
    /// An engine holding its own receivers. `boot_id` is this process's: relays number an engine's
    /// records per (engine, boot), so a restart starts its sequences again at 0 without colliding
    /// with what the last boot sent.
    pub fn new(boot_id: u64, settings: Settings) -> Self {
        let intake = Intake::new(
            Seats::new(settings.capacity.receivers),
            Some(settings.regions.clone()),
        );
        let mut engine = Self::hosted(boot_id, settings);
        engine.intake = Some(intake);
        engine
    }

    /// An engine whose host holds its receivers (`intake::Intake`, split by receiver), checks each
    /// batch's use there, says who takes part (`set_sites`) and hands it each batch taken
    /// (`ingest`): it solves them as `new`'s engine solves the same arrivals.
    pub fn hosted(boot_id: u64, settings: Settings) -> Self {
        let arrived = Arrived::new(settings.limits());
        Self {
            boot_id,
            settings,
            owned: Regions::default(),
            intake: None,
            sited: Vec::new(),
            indexed: None,
            arrived,
            shards: (0..SHARDS).map(|_| Shard::default()).collect(),
            models: Tree::new(),
            caches: Tree::new(),
            solved: Tree::new(),
            slots: Slots::default(),
            positions_sequence: 0,
            models_sequence: 0,
            dropped: Dropped::default(),
        }
    }

    pub fn boot_id(&self) -> u64 {
        self.boot_id
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Bytes it holds, as allocated: the arrived pool, the address shards, its own models, the
    /// areas' memos, what it solved and its slots. Not its intake's descriptions, which its host plans with
    /// its receivers, nor a neighbour's model it was handed (`hold`), which its host holds
    /// already and charges there (a relay's store of models).
    pub fn bytes(&self) -> usize {
        self.arrived.bytes()
            + self.shards.iter().map(Shard::bytes).sum::<usize>()
            + self.shards.capacity() * size_of::<Shard>()
            + self.models.bytes()
            + self
                .models
                .values()
                .filter(|held| held.own)
                .map(|held| held.bytes())
                .sum::<usize>()
            + self.caches.bytes()
            + self
                .caches
                .values()
                .map(|area| area.cache.bytes())
                .sum::<usize>()
            + self.solved.bytes()
            + self.solved.values().map(Solved::bytes).sum::<usize>()
            + self.slots.bytes(fix::Work::bytes)
            + self.sited.capacity() * size_of::<Sited>()
            + self.indexed.as_ref().map_or(0, |(built_from, sites)| {
                built_from.capacity() * size_of::<tally_mlat_solver::Site>()
                    + tally_wire::footprint::arc::<Sites>()
                    + sites.bytes()
            })
    }

    /// Lets go of the raw a step at `at` would let go of before it solves (`Arrived::forget_older`),
    /// solving nothing: what its host does at each step it collapses (`tally-relay`'s
    /// `mlat_host`, Behind), so the steps taken at once hold what the steps would.
    pub fn forget_older(&mut self, at: Moment) {
        self.arrived.forget_older(at.mono().ms());
    }

    /// Bytes its arrived pool holds, as allocated: what ingesting a batch grows, read in constant
    /// time, where [`Engine::bytes`] walks every table.
    pub fn arrived_bytes(&self) -> usize {
        self.arrived.bytes()
    }

    /// Models held: its own and its neighbours', every edge any fix may still cite.
    pub fn models(&self) -> usize {
        self.models.len()
    }

    /// Each owned area's memos (what its next refit starts from), with what they hold
    /// (`PairCache::bytes`): what a host plans the warm areas by.
    pub fn area_caches(&self) -> Vec<(Region, usize)> {
        self.caches
            .iter()
            .map(|(area, cached)| (*area, cached.cache.bytes()))
            .collect()
    }

    /// The model of `area` at `edge_ms` it holds, if any: its own, or one its host handed it.
    pub fn model(&self, area: Region, edge_ms: u64) -> Option<&Arc<Held>> {
        self.models.get(&(area, edge_ms))
    }

    /// Takes a neighbouring area's model its host holds, unjudged (module docs): solved under from
    /// the next step, beside its own areas' of the same edge, while any fix may cite it, and judged
    /// over the raw here only once a fix to publish cites it (`Engine::step`). A model
    /// of an area and edge it holds one of already is not taken: its own is never replaced.
    pub fn hold(&mut self, held: Arc<Held>) {
        let key = (held.area(), held.edge_ms());
        if !self.models.contains_key(&key) {
            self.models.insert(key, held);
        }
    }

    /// Whether `receiver` is described, and whether it takes part (one refused for room is
    /// described, and takes no part). Always `None` for a hosted engine.
    pub fn described(&self, receiver: &PublicKey) -> Option<bool> {
        self.intake.as_ref()?.described(receiver)
    }

    /// Receivers taking part now.
    pub fn taking_part(&self) -> usize {
        self.intake
            .as_ref()
            .map_or(self.sited.len(), Intake::taking_part)
    }

    /// The receivers taking part, in key order, each with its reception key.
    pub fn sites(&self) -> Vec<Sited> {
        match self.intake.as_ref() {
            Some(intake) => intake.sites().collect(),
            None => self.sited.clone(),
        }
    }

    /// Who takes part now, for a hosted engine: its host's intakes' sites, in any order. An engine
    /// that holds its own receivers ignores it.
    pub fn set_sites(&mut self, mut sites: Vec<Sited>) {
        if self.intake.is_some() {
            return;
        }
        sites.sort_unstable_by_key(|sited| sited.site.receiver);
        sites.dedup_by_key(|sited| sited.site.receiver);
        self.sited = sites;
    }

    /// Takes a record a relay delivered, at `at` by the engine's clocks (which decide only when a
    /// transmission falls due, never what anything solves to). An error is a record that claimed
    /// to be signed and is not. A hosted engine takes no description this way: its host's
    /// intakes do.
    pub fn ingest_record(&mut self, record: &Record, at: Moment) -> Result<Ingested, String> {
        match record {
            Record::ReceiverSite(_) | Record::ReceiverInfo(_) => {
                // A format 2 description carries no site: it places nobody.
                let (Some(intake), Some(site)) = (self.intake.as_mut(), SiteRecord::of(record))
                else {
                    return Ok(Ingested::Ignored);
                };
                // One intake holds every receiver, so no other intake's receiver moves.
                let described = intake.describe(&site)?;
                self.dropped.receivers += intake.take_refused();
                for receiver in described.left {
                    self.forget_by(receiver);
                }
                Ok(described.ingested)
            }
            Record::Batch(batch) => self.receive(batch, at),
            // A relay's deduplicated stream is the relay's word, not a receiver's: it carries no
            // receiver's counter and is never multilaterated.
            _ => Ok(Ingested::Ignored),
        }
    }

    fn receive(&mut self, batch: &Batch, at: Moment) -> Result<Ingested, String> {
        let key = batch.receiver().map_err(|error| error.to_string())?;
        // Described and taking no part: nothing of it is held. One not described yet is held
        // until its description says (`intake` module docs).
        if self.described(&key) == Some(false) {
            return Ok(Ingested::Ignored);
        }
        batch
            .verify()
            .map_err(|error| format!("batch of {key}: {error}"))?;
        match Decoded::from_verified(batch.clone(), at, 0) {
            Ok(decoded) => Ok(self.ingest_decoded(&decoded)),
            // A format this build cannot read uses its sequence and holds nothing.
            Err(_) => Ok(self
                .use_batch(
                    &BatchId {
                        receiver: key,
                        boot_id: batch.boot_id(),
                        sequence: batch.sequence(),
                    },
                    batch.content().map_or(0, |content| content.wall_ms),
                )
                .map_or_else(|refused| refused, |()| Ingested::Ignored)),
        }
    }

    /// Takes a batch whose signature the caller already verified and which it decoded once
    /// (`tally_wire::Decoded`), at its own stamp: used once per (boot, sequence), held only from a
    /// receiver that takes part or is not described yet.
    pub fn ingest_decoded(&mut self, batch: &Decoded) -> Ingested {
        let id = batch_id(batch);
        if let Err(refused) = self.use_batch(&id, batch.wall_ms()) {
            return refused;
        }
        let (receptions, filtered) = receptions_of(batch);
        let admitted = self.admit(id, batch.at(), &classify(&receptions));
        Ingested::Batch {
            new: admitted.kept as usize,
            filtered,
        }
    }

    /// Whether its own intake uses `batch`, signed at `wall_ms` (a hosted engine's host has
    /// decided).
    fn use_batch(&mut self, batch: &BatchId, wall_ms: u64) -> Result<(), Ingested> {
        let Some(intake) = self.intake.as_mut() else {
            return Ok(());
        };
        let used = intake.take(batch, wall_ms);
        if used == Err(Ingested::Replayed) {
            self.dropped.replayed += 1;
        }
        used
    }

    /// Takes the receptions MLAT uses of one batch (`intake::receptions_of`), arrived at `at`:
    /// what the pool keeps of them, and each ADS-B position heard, which makes its aircraft no
    /// target for a while. An engine holding its own receivers uses the batch only if its intake
    /// does (a receiver that takes part or is not described yet, a sequence not used); a hosted
    /// engine's host has checked.
    pub fn ingest(&mut self, batch: BatchId, at: Moment, receptions: &[Reception]) -> Admitted {
        let wall_ms = receptions.first().map_or(0, |reception| reception.wall_ms);
        if self.use_batch(&batch, wall_ms).is_err() {
            return Admitted::default();
        }
        self.admit(batch, at, &classify(receptions))
    }

    /// Takes one batch's receptions classified apart ([`classify`]), on a host that has checked
    /// the batch is to be used: what [`Engine::ingest`] does with them. A host classifies a step's
    /// batches on its MLAT threads and admits them here, one at a time, in its order.
    pub fn ingest_classified(
        &mut self,
        batch: BatchId,
        at: Moment,
        classified: &Classified<'_>,
    ) -> Admitted {
        self.admit(batch, at, classified)
    }

    fn admit(&mut self, batch: BatchId, at: Moment, classified: &Classified<'_>) -> Admitted {
        for &(shard, address, wall_ms) in &classified.positions {
            self.shards[shard].hear(address, wall_ms);
        }
        let admitted = self
            .arrived
            .admit_classified(batch, at.mono().ms(), &classified.pool);
        self.dropped
            .add(&admitted, classified.pool.receptions().len());
        admitted
    }

    /// When the reception `id` of a transmission at `transmitted_ms` arrived here, by the arrival
    /// clock its batch was admitted at (`Arrived::held`): `None` when it is not held (it never
    /// came, its receiver was forgotten, or it is older than anything held). How a relay judges a
    /// peer's fix that considered a reception: whether it had arrived here, and when.
    pub fn heard(&self, id: &ObservationId, transmitted_ms: u64) -> Option<u64> {
        self.arrived
            .held(std::slice::from_ref(id), transmitted_ms)
            .first()
            .map(|(_, arrived_ms)| *arrived_ms)
    }

    /// Verifies a pair model another engine published against what has arrived here
    /// (`verify_pair_model_held`, by this engine's sites): `None` when it cannot be judged here
    /// (it cites a batch not held, or names a specification this build does not implement).
    pub fn verify_model(&mut self, model: &PairModel) -> Option<bool> {
        let sites = self.indexed_sites(&self.sites());
        let edge_ms = model.trailing.edge_ms;
        let area = self.caches.entry(model.area).or_insert_with(|| AreaCache {
            fitted_ms: None,
            used_ms: edge_ms,
            cache: PairCache::default(),
        });
        area.used_ms = area.used_ms.max(edge_ms);
        let verdict = tally_mlat_solver::verify_pair_model_held(
            &sites,
            model,
            &self.arrived,
            &mut area.cache,
        );
        verdict.judged().then(|| verdict.passed())
    }

    /// A held model's verdict over the raw here, judged once and kept (`Held::verdict`): an own
    /// model is this engine's fit, never judged; `None` while the raw here cannot judge it.
    /// Returns whether this call judged it.
    fn judge(&mut self, held: &Held) -> (Option<bool>, bool) {
        if held.own {
            return (Some(true), false);
        }
        if let Some(verdict) = held.verdict.get() {
            return (Some(*verdict), false);
        }
        match self.verify_model(&held.prepared.model) {
            Some(verdict) => {
                let _ = held.verdict.set(verdict);
                (Some(verdict), true)
            }
            None => (None, false),
        }
    }

    /// Keeps of the step's fixes those every model of which stands here (module docs, Models):
    /// its own, or a neighbour's verified over the raw here the first time a fix cites it
    /// ([`Engine::judge`]), or, where that raw cannot judge it, corroborated. A neighbour's model
    /// no fix cites is never judged; one refuted is let go.
    fn trust(&mut self, solves: &mut [fix::Solves], report: &mut Report) {
        let mut stands: BTreeMap<Hash, bool> = BTreeMap::new();
        for solved in solves.iter_mut() {
            let before = solved.fixes.len();
            solved.fixes.retain(|solve| {
                solve.cited.iter().all(|held| {
                    if held.own {
                        return true;
                    }
                    if let Some(stood) = stands.get(&held.id()) {
                        return *stood;
                    }
                    let _ = held.cited.set(());
                    let stood = match self.judge(held) {
                        (Some(verdict), judged) => {
                            if judged && verdict {
                                report.models_verified += 1;
                            } else if judged {
                                report.models_refuted += 1;
                            }
                            verdict
                        }
                        (None, _) => {
                            let corroborated = held.corroborated.get().is_some();
                            report.models_corroborated += usize::from(corroborated);
                            corroborated
                        }
                    };
                    stands.insert(held.id(), stood);
                    stood
                })
            });
            report.untrusted += before - solved.fixes.len();
        }
        self.models
            .retain(|_, held| held.own || held.verdict.get() != Some(&false));
    }

    /// Verifies what a fix another engine published states (`Stated`) under `models`, the models
    /// it lists, as any checker would, against what has arrived here: each model against the raw
    /// it cites ([`Engine::verify_model`]), then the fix under them over the receptions of it held
    /// here (`verify_pair_fix`). `None` when either cannot be judged here: a model cites a batch not
    /// held, or names a specification this build does not implement, or the fix considered a
    /// reception not held. Run only when a fix needs judging (a superset that disagrees), never for
    /// every fix.
    pub fn verify(
        &mut self,
        models: &[Arc<Held>],
        stated: &tally_mlat_solver::Stated<'_>,
    ) -> Option<bool> {
        for held in models {
            if !self.judge(held).0? {
                return Some(false);
            }
        }
        let spec = models.first()?.prepared.model.spec;
        let Some(under) = Models::new(models.iter().map(|held| &held.prepared).collect()) else {
            return Some(false);
        };
        let hash = tally_mlat_solver::obs::message_hash(stated.message);
        let ids: Vec<ObservationId> = stated
            .considered
            .iter()
            .map(|reception| ObservationId {
                receiver: reception.receiver,
                epoch: reception.epoch,
                timestamp: reception.counter,
                message: hash,
            })
            .collect();
        let held: Vec<Reception> = self
            .arrived
            .held(&ids, stated.claimed.transmitted.unix_ms)
            .into_iter()
            .map(|(reception, _)| reception)
            .collect();
        let verdict = tally_mlat_solver::verify_pair_fix(&under, stated, spec, &held);
        let unheld = verdict
            .failures
            .iter()
            .all(|failure| matches!(failure, tally_mlat_solver::Failure::Unknown(_)));
        if !verdict.judged() || (!verdict.passed() && unheld) {
            return None;
        }
        Some(verdict.passed())
    }

    /// `sited` indexed: the one kept while they are the sites it was built from, else built
    /// again from them and kept.
    fn indexed_sites(&mut self, sited: &[Sited]) -> Arc<Sites> {
        let plain: Vec<tally_mlat_solver::Site> = sited.iter().map(|sited| sited.site).collect();
        match &self.indexed {
            Some((built_from, sites)) if *built_from == plain => Arc::clone(sites),
            _ => {
                let sites = Arc::new(Sites::new(&plain));
                self.indexed = Some((plain, Arc::clone(&sites)));
                sites
            }
        }
    }

    /// Forgets `receiver`: it stopped taking part. A hosted engine's host says so when its intake
    /// lets the receiver go; an engine holding its own intake, when a description moves it out.
    /// What it heard is never read again (`tally_mlat_solver::Arrived::forget`), and goes with its
    /// slices.
    pub fn forget_by(&mut self, receiver: PublicKey) {
        self.sited.retain(|sited| sited.site.receiver != receiver);
        self.arrived.forget(receiver);
    }

    /// Changes what the engine covers, as a relay hosting it does when the areas it is an MLAT
    /// relay for change (RFC-0174 §2.3): `regions` as `Settings::regions` (the receivers that take
    /// part: its areas and their border band, `area::border_band`), and `owned` the areas it fits
    /// and takes transmissions up for (empty, every area with a receiver taking part). Every receiver described is decided again on its own signed word: one now outside
    /// takes no part, as when its own description moves it out; one now inside takes part from
    /// its next batch. The same records under the same scope solve to the same bytes whatever
    /// scopes came before. A hosted engine's host re-scopes its intakes.
    pub fn set_scope(&mut self, regions: Regions, owned: Regions) {
        self.settings.regions.clone_from(&regions);
        self.owned = owned;
        if let Some(intake) = self.intake.as_mut() {
            let described = intake.set_scope(Some(regions));
            self.dropped.receivers += intake.take_refused();
            for receiver in described.left {
                self.forget_by(receiver);
            }
        }
    }

    /// One step at `at` (module docs): the pool sealed by its monotonic clock, every owned area
    /// refit when the refit grid's edge moved on, what fell due by it solved, and the models and
    /// fixes signed by `signer`, numbered in this boot's sequences. A step whose signer's clock is
    /// not judging signs nothing, and its fixes are counted unpublished.
    pub fn step(&mut self, at: Moment, signer: &Signer) -> Step {
        let started = Instant::now();
        let judged = at.judged();
        let arrived_ms = at.mono().ms();
        self.arrived.seal(arrived_ms);
        for shard in &mut self.shards {
            shard.forget(judged);
        }
        // Receivers never described whose raw is older than anything held.
        if let Some(intake) = self.intake.as_mut() {
            for receiver in intake.expire(judged.ms(), tally_mlat_solver::HELD_MS) {
                self.arrived.forget(receiver);
            }
        }
        self.solved
            .retain(|_, solved| !solved.spent(arrived_ms, tally_mlat_solver::HELD_MS));
        // A slot's candidates fall due within `JOIN_MS` of its first's arrival, its last due as
        // its set closes.
        self.slots.forget(
            arrived_ms,
            tally_mlat_solver::arrived::JOIN_MS + tally_mlat_solver::backoff::SLOT_MS,
        );
        let mut unneeded = 0;
        self.models.retain(|_, held| {
            let keep = fix::usable(held, judged);
            unneeded += usize::from(!keep && !held.own && held.cited.get().is_none());
            keep
        });
        self.caches
            .retain(|_, area| !TRAILING_WINDOW.older(area.used_ms, judged));
        let sited = self.sites();
        let sites = self.indexed_sites(&sited);
        let keys: BTreeMap<PublicKey, tally_wire::ReceptionKey> = sited
            .iter()
            .map(|sited| (sited.site.receiver, sited.key))
            .collect();
        let mut report = Report {
            dropped: std::mem::take(&mut self.dropped),
            models_unneeded: unneeded,
            ..Report::default()
        };
        let edge_ms = Trailing::fitted_at(judged.ms()).edge_ms;
        // Steps since the edge moved on: an area is refit at its turn, and only then.
        let turn = (judged.ms() - FIT_LAG.span::<Judged>().ms() - edge_ms) / STEP_MS;
        self.refit(&sites, edge_ms, turn, &mut report);
        let chosen = fix::choose(
            self.settings.threads.max(1),
            &self.arrived,
            arrived_ms,
            &sites,
            fix::Scope {
                regions: &self.settings.regions,
                owned: &self.owned,
            },
            judged,
            &self.shards,
            &self.solved,
            &mut report,
        );
        let threads = self.settings.threads.max(1);
        let started_indexes = std::time::Instant::now();
        let indexes = fix::Indexes::of(&self.models);
        report.solve_ns += u64::try_from(started_indexes.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let weighed = fix::weigh(
            threads,
            &sites,
            (&self.models, &indexes),
            &self.slots,
            &chosen,
            arrived_ms,
            &mut report,
        );
        let work = fix::back_off(&chosen, weighed, &mut self.slots, arrived_ms, &mut report);
        let mut solves = fix::solve(threads, &indexes, &work, &mut report);
        drop(indexes);
        self.trust(&mut solves, &mut report);
        let job = fix::Job {
            boot_id: self.boot_id,
            issued_ms: judged.ms(),
            positions_sequence: self.positions_sequence,
            models_sequence: self.models_sequence,
            threads,
        };
        let outcome = job.run(signer, &keys, &chosen, &work, solves, report);
        tally_mlat_solver::gate::drop_on_threads(threads, chosen);
        self.positions_sequence = outcome.positions_sequence;
        self.models_sequence = outcome.models_sequence;
        for (key, solved) in outcome.solved {
            match self.solved.get_mut(&key) {
                Some(held) => held.fold(solved),
                None => {
                    self.solved.insert(key, solved);
                }
            }
        }
        let mut step = outcome.step;
        step.report.elapsed = started.elapsed();
        step
    }

    /// Refits every owned area with a receiver taking part (`fix::Scope::owns`) not fitted at
    /// `edge_ms` yet whose turn (`area::refit_turn`) is `turn`, the steps since the edge moved on,
    /// each warm from its newest own model, and keeps each fitted one as its area's model at the
    /// edge. An area whose fit failed at an edge, or whose turn a step behind took in (`mlat_host`,
    /// collapsed), is tried again at its turn of the next edge, its fixes meanwhile carried on its
    /// model of the edge before (`fix::models_for`) as far as the carry allows. So no step refits
    /// more than its own turn's areas. Before (2026-10-26), an area was refit once its turn was at
    /// most `turn`, so a step that took in the one before it refit both turns' areas, ran past its
    /// second, and the next was taken in in turn: at 1,326 seats on 16 cores every third step was
    /// collapsed, 178 refits where its neighbours ran 87, until the governor cut to 698.
    fn refit(&mut self, sites: &Sites, edge_ms: u64, turn: u64, report: &mut Report) {
        let scope = fix::Scope {
            regions: &self.settings.regions,
            owned: &self.owned,
        };
        let due: Vec<Region> = sites
            .areas()
            .map(|(area, _)| *area)
            .filter(|area| scope.owns(*area))
            .filter(|area| crate::area::refit_turn(*area) == turn)
            .filter(|area| {
                self.caches
                    .get(area)
                    .is_none_or(|cache| cache.fitted_ms != Some(edge_ms))
                    && !self.models.contains_key(&(*area, edge_ms))
            })
            .collect();
        let refits: Vec<fix::Refit> = due
            .into_iter()
            .map(|area| fix::Refit {
                area,
                warm: self
                    .models
                    .range((area, 0)..=(area, u64::MAX))
                    .rev()
                    .map(|(_, held)| held)
                    .find(|held| held.own)
                    .cloned(),
                cache: std::sync::Mutex::new(
                    self.caches
                        .remove(&area)
                        .map(|area| area.cache)
                        .unwrap_or_default(),
                ),
            })
            .collect();
        if refits.is_empty() {
            return;
        }
        let fitted = fix::refit(
            &self.arrived,
            sites,
            edge_ms,
            self.settings.threads,
            &refits,
            report,
        );
        for held in fitted {
            self.models.insert((held.area(), held.edge_ms()), held);
        }
        for refit in refits {
            self.caches.insert(
                refit.area,
                AreaCache {
                    fitted_ms: Some(edge_ms),
                    used_ms: edge_ms,
                    cache: refit
                        .cache
                        .into_inner()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                },
            );
        }
    }
}

/// An area's memos (`Engine::caches`): what fitting or verifying its models read last, the edge
/// it was last fitted at, and the newest edge it was used at.
struct AreaCache {
    fitted_ms: Option<u64>,
    used_ms: u64,
    cache: PairCache,
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
            threads: 1,
            capacity: Capacity::default(),
        }
    }

    fn engine() -> Engine {
        Engine::new(7, settings())
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
        let mut engine = engine();
        let (new, old, public) = (
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
        );
        assert_eq!(
            engine.ingest_record(&public_info(&public, 1, location())?, aligned(0))?,
            Ingested::Ignored
        );
        assert_eq!(engine.described(&public.public()), None);
        assert_eq!(
            engine.ingest_record(&public_info(&new, 1, location())?, aligned(0))?,
            Ingested::Ignored
        );
        let site = info(&new, 1, location(), Clock::Dump1090);
        assert_eq!(
            engine.ingest_record(&site, aligned(0))?,
            Ingested::Described
        );
        let described = old_info(&old, 1, location(), Clock::Dump1090);
        assert_eq!(
            engine.ingest_record(&described, aligned(0))?,
            Ingested::Described
        );
        assert_eq!(engine.taking_part(), 2);
        let sites = engine.sites();
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
        engine.ingest_record(&reissued, aligned(0))?;
        let held = engine
            .sites()
            .into_iter()
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
    fn a_batch_two_relays_deliver_or_one_replays_is_used_once() -> Result<(), String> {
        let mut engine = engine();
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest_record(&info(&receiver, 1, location(), Clock::Beast), aligned(0))?;
        let record = batch(
            &receiver,
            3,
            100,
            0,
            vec![observation(5, format::MODE_S_SHORT)],
        )?;
        assert!(matches!(
            engine.ingest_record(&record, aligned(0))?,
            Ingested::Batch { .. }
        ));
        assert_eq!(
            engine.ingest_record(&record, aligned(0))?,
            Ingested::Replayed
        );
        // Far behind the boot's newest: a replay, though never seen.
        let old = batch(
            &receiver,
            3,
            10,
            0,
            vec![observation(6, format::MODE_S_SHORT)],
        )?;
        assert_eq!(engine.ingest_record(&old, aligned(0))?, Ingested::Replayed);
        // A new boot starts its own sequence.
        let restarted = batch(
            &receiver,
            4,
            0,
            0,
            vec![observation(7, format::MODE_S_SHORT)],
        )?;
        assert!(matches!(
            engine.ingest_record(&restarted, aligned(0))?,
            Ingested::Batch { .. }
        ));
        Ok(())
    }

    #[test]
    fn only_what_mlat_uses_from_receivers_that_take_part_is_taken() -> Result<(), String> {
        let mut engine = engine();
        let receiver = Identity::generate().map_err(text)?;
        let stranger = Identity::generate().map_err(text)?;
        let unknown_clock = Identity::generate().map_err(text)?;
        let coarse = Identity::generate().map_err(text)?;
        engine.ingest_record(&info(&receiver, 1, location(), Clock::Dump1090), aligned(0))?;
        engine.ingest_record(
            &info(&unknown_clock, 1, location(), Clock::Unknown),
            aligned(0),
        )?;
        let mut rounded = location();
        rounded.precision_m = MAX_SITE_PRECISION_M + 1;
        engine.ingest_record(&info(&coarse, 1, rounded, Clock::Dump1090), aligned(0))?;
        let mixed = vec![
            observation(1, format::MODE_AC),
            observation(2, format::MODE_S_SHORT),
            observation(3, format::UAT_DOWNLINK),
            observation(4, format::MODE_S_LONG),
        ];
        assert!(matches!(
            engine.ingest_record(&batch(&receiver, 1, 0, 0, mixed)?, aligned(0))?,
            Ingested::Batch { filtered: 2, .. }
        ));
        for other in [&unknown_clock, &coarse] {
            let record = batch(other, 1, 0, 0, vec![observation(9, format::MODE_S_SHORT)])?;
            assert_eq!(
                engine.ingest_record(&record, aligned(0))?,
                Ingested::Ignored
            );
        }
        // Not described yet: held until its description says whether it takes part.
        let early = batch(
            &stranger,
            1,
            0,
            0,
            vec![observation(9, format::MODE_S_SHORT)],
        )?;
        assert!(matches!(
            engine.ingest_record(&early, aligned(0))?,
            Ingested::Batch { .. }
        ));
        assert_eq!(engine.taking_part(), 1);
        Ok(())
    }

    /// A batch that comes before its receiver's description is held, and its sequence goes with
    /// the description: the same batch again is a replay. One described outside every region the
    /// engine covers takes no part, and what it sent before is let go with it.
    #[test]
    fn a_batch_before_its_description_is_held_until_the_description_says() -> Result<(), String> {
        let inside = Region::containing(&location(), 2).map_err(text)?;
        let mut engine = Engine::new(
            1,
            Settings {
                regions: Regions::new([inside]),
                ..settings()
            },
        );
        let (early, outside) = (
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
        );
        let elsewhere = Location {
            lat_e7: -335_000_000,
            ..location()
        };
        let first = batch(&early, 1, 0, 0, vec![observation(5, format::MODE_S_SHORT)])?;
        let away = batch(
            &outside,
            1,
            0,
            0,
            vec![observation(6, format::MODE_S_SHORT)],
        )?;
        for record in [&first, &away] {
            assert!(matches!(
                engine.ingest_record(record, aligned(0))?,
                Ingested::Batch { .. }
            ));
        }
        engine.ingest_record(&info(&early, 1, location(), Clock::Dump1090), aligned(0))?;
        engine.ingest_record(&info(&outside, 1, elsewhere, Clock::Dump1090), aligned(0))?;
        assert_eq!(
            engine.ingest_record(&first, aligned(0))?,
            Ingested::Replayed
        );
        assert_eq!(engine.taking_part(), 1);
        assert_eq!(engine.ingest_record(&away, aligned(0))?, Ingested::Ignored);
        Ok(())
    }

    #[test]
    fn a_forged_batch_is_an_error_and_holds_nothing() -> Result<(), String> {
        let mut engine = engine();
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest_record(&info(&receiver, 1, location(), Clock::Dump1090), aligned(0))?;
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
        let before = engine.bytes();
        let mut bytes = signed.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let forged = Batch::from_bytes(bytes).map_err(text)?;
        assert!(
            engine
                .ingest_record(&Record::Batch(forged), aligned(0))
                .is_err()
        );
        assert_eq!(engine.bytes(), before);
        Ok(())
    }

    #[test]
    fn the_newest_description_wins_whatever_order_they_arrive_in() -> Result<(), String> {
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
                1,
                Settings {
                    regions: Regions::new([region]),
                    ..settings()
                },
            );
            for record in order {
                engine.ingest_record(record, aligned(0))?;
            }
            assert_eq!(engine.taking_part(), 0, "the newer description is outside");
        }
        Ok(())
    }
}
