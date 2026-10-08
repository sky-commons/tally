//! The engine's state (RFC-0171 §3.8, §3.8.1): the receivers it multilaterates for, the raw
//! observations it holds (`tally_mlat_solver::held`, compact, per bin), and which windows it has
//! solved. The receivers and their open raw are its [`Intake`] (`intake`): an engine holds its
//! own ([`Engine::new`]), or its host holds them split by receiver and hands it the sealed bins
//! and what each batch says to provisional solving ([`Engine::hosted`]: a relay's raw shards,
//! RFC-0177 §5), and the same raw solves to the same bytes either way. Nothing here reads a clock or a socket: the caller says what time it is, so the same
//! records in any order leave the same state, and the same state solves to the same bytes
//! (`window`).
//!
//! - A receiver takes part on its own signed word only: its newest `ReceiverInfo` verifies, places
//!   it inside the engine's regions, and names a clock the solver specification knows with a
//!   location no coarser than it allows (`tally_mlat_solver::obs::MAX_SITE_PRECISION_M`).
//! - A batch is used once: it must verify, be from a receiver that takes part, and carry a
//!   (boot, sequence) not already used and not too far behind that boot's newest (§3.1), so a batch
//!   two relays deliver, or a relay replays, adds nothing.
//! - An observation is held once (the G-Set of §3.8.1): its identity is (receiver key, counter
//!   epoch, raw counter, message hash), the same however many paths delivered it, so the held set
//!   is the union of everything delivered. Only what MLAT uses is held (the solver's ingest
//!   prefilter and, when a bin is sealed, its canonical thinning), in 24 bytes an observation. The
//!   raw it holds is the one store its host keeps (`Engine::sealed_bins` is what the host's other
//!   readers, a relay's standing, share), sealed on `Settings::threads` threads.
//! - **Capacity is configuration, and refusal is whole** (RFC-0177 §9). How many receivers it
//!   describes and what its raw may hold come from `Settings::capacity`, which a relay derives from
//!   the receivers it admits; a receiver beyond them is refused whole (never remembered, its raw
//!   never held) and counted, and a receiver's raw of a bin beyond its share is refused whole and
//!   counted (`tally_mlat_solver::held::Limits`), never partly by arrival order.
//! - Which window an observation is in is decided by its content alone: its grid bin is its
//!   signed batch wall clock's, never when it arrived (`tally_mlat_solver::scope`). A bin is
//!   sealed once it has ended and a settling time has passed by the engine's clock, and a window
//!   (strided: one fit per tile per `STRIDE` bins) is solved once its last bin is sealed; when
//!   decides only whether late raw makes it in, never what the same raw solves to.

use std::collections::{BTreeMap, BTreeSet};

use tally_mlat_solver::Site;
use tally_mlat_solver::held::{Bin, Fragment, Limits, RAW_SPARE_BINS, Rates, SealedBins};
use tally_mlat_solver::scope::{AFTER, BEFORE, STRIDE, Window, bin_of};
use tally_wire::{Batch, Decoded, Identity, PublicKey, Record, Region};

use crate::intake::{Intake, Seats};
use crate::provisional::{self, Note, Provisional};
use crate::window::{Job, Outcome, Report};

/// The fewest receivers an engine is sized for: a region's whole receiver population at the
/// founder's requirement (RFC-0177: one relay, 20,000 feeders).
pub const MIN_RECEIVERS: usize = 20_000;

/// How much an engine holds, derived from what its host admits (RFC-0177 §9).
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
    /// Sized for `receivers` at the measured rates, never fewer than `MIN_RECEIVERS`.
    pub fn for_receivers(receivers: usize) -> Self {
        Self {
            receivers: receivers.max(MIN_RECEIVERS),
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
    pub regions: Vec<Region>,
    /// How long after a bin's canonical window ends (by the engine's clock) it is solved, so the
    /// raw of the window's last bin is in.
    pub settle_ms: u64,
    /// The threads one step's work, and a bin's sealing, are spread over. Any number gives the
    /// same bytes.
    pub threads: usize,
    /// How much it holds.
    pub capacity: Capacity,
}

impl Settings {
    /// The raw it may hold.
    pub fn limits(&self) -> Limits {
        Limits::for_receivers(self.capacity.receivers, self.capacity.rates, self.settle_ms)
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

/// What was refused since the last step, every refusal whole.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    /// Observations of a bin already sealed: later than its settling.
    pub late: u64,
    /// Observations refused with their receiver's whole raw of a bin (`Limits`).
    pub refused: u64,
    /// Descriptions of new receivers refused whole, beyond `Capacity::receivers`.
    pub receivers: u64,
}

pub struct Engine {
    identity: Identity,
    boot_id: u64,
    settings: Settings,
    /// The areas whose tiles it fits (`set_scope`): a tile is fitted only if its centre is in one.
    /// Empty: every tile its regions cover.
    owned: Vec<Region>,
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
}

impl Engine {
    /// `boot_id` is this process's: relays number an engine's records per (engine, boot), so a
    /// restart starts its sequences again at 0 without colliding with what the last boot sent.
    pub fn new(identity: Identity, boot_id: u64, settings: Settings) -> Self {
        Self::sharing(identity, boot_id, settings, SealedBins::new())
    }

    /// As `new`, sealing into `sealed`: the handle its host's other readers of the raw keep (a
    /// relay's standing), so the raw is held once.
    pub fn sharing(
        identity: Identity,
        boot_id: u64,
        settings: Settings,
        sealed: SealedBins,
    ) -> Self {
        let intake = Intake::new(
            Seats::new(settings.capacity.receivers),
            Limits {
                bytes: usize::MAX,
                ..settings.limits()
            },
            Some(settings.regions.clone()),
        );
        let mut engine = Self::hosted(identity, boot_id, settings, sealed);
        engine.intake = Some(intake);
        engine
    }

    /// An engine whose host holds its receivers and their raw (`intake::Intake`, split by
    /// receiver) and seals it into `sealed`: it is handed what each batch says to provisional
    /// solving (`hear`), the sites and the sealed bins at each step (`prepare_sealed`), and solves
    /// them as `new`'s engine solves the same raw.
    pub fn hosted(
        identity: Identity,
        boot_id: u64,
        settings: Settings,
        sealed: SealedBins,
    ) -> Self {
        Self {
            identity,
            boot_id,
            settings,
            owned: Vec::new(),
            intake: None,
            sealed,
            processed: BTreeSet::new(),
            positions_sequence: 0,
            models_sequence: 0,
            dropped: Dropped::default(),
            provisional: Provisional::default(),
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

    /// Takes a record a relay delivered, at `now_ms` by the engine's clock (which decides only
    /// when a reception is solved provisionally, never what anything solves to). An error is a
    /// record that claimed to be signed and is not. A hosted engine takes nothing this way: its
    /// host's intakes do.
    pub fn ingest(&mut self, record: &Record, now_ms: u64) -> Result<Ingested, String> {
        match record {
            Record::ReceiverInfo(info) => {
                let Some(intake) = self.intake.as_mut() else {
                    return Ok(Ingested::Ignored);
                };
                let described = intake.describe(info)?;
                if described.left
                    && let Ok(key) = info.receiver()
                {
                    self.forget_receiver(&key);
                }
                Ok(described.ingested)
            }
            Record::Batch(batch) => self.receive(batch, now_ms),
            // A relay's deduplicated stream is the relay's word, not a receiver's: it carries no
            // receiver's counter and is never multilaterated.
            _ => Ok(Ingested::Ignored),
        }
    }

    /// Forgets `receiver` in the sealed bins: it stopped taking part (its intake forgot its open
    /// raw).
    pub fn forget_receiver(&mut self, receiver: &PublicKey) {
        self.sealed
            .forget_receiver(receiver, self.settings.threads.max(1));
    }

    /// Changes what the engine covers, as a relay hosting it does when the areas it is an MLAT
    /// relay for change (RFC-0174 §2.3): `regions` as `Settings::regions` (the receivers that take
    /// part, and the footprints a fitted tile must lie inside: an area and its border band), and
    /// `owned` the areas whose tiles it fits (a tile's centre in one; empty, every tile `regions`
    /// cover). Every receiver described is decided again on its own signed word: one now outside
    /// takes no part and what it heard is forgotten, as when its own description moves it out; one
    /// now inside takes part from its next batch. The same records under the same scope solve to
    /// the same bytes whatever scopes came before. A hosted engine's host re-scopes its intakes.
    pub fn set_scope(&mut self, regions: Vec<Region>, owned: Vec<Region>) {
        self.settings.regions.clone_from(&regions);
        self.owned = owned;
        if let Some(intake) = self.intake.as_mut() {
            for key in intake.set_scope(Some(regions)) {
                self.sealed
                    .forget_receiver(&key, self.settings.threads.max(1));
            }
        }
    }

    fn receive(&mut self, batch: &Batch, now_ms: u64) -> Result<Ingested, String> {
        let key = batch.receiver().map_err(|error| error.to_string())?;
        if self.described(&key) != Some(true) {
            return Ok(Ingested::Ignored);
        }
        batch
            .verify()
            .map_err(|error| format!("batch of {key}: {error}"))?;
        match Decoded::from_verified(batch.clone(), now_ms, 0) {
            Ok(decoded) => Ok(self.ingest_verified(&decoded, now_ms)),
            // A format this build cannot read uses its sequence and holds nothing.
            Err(_) => Ok(self.intake.as_mut().map_or(Ingested::Ignored, |intake| {
                intake.use_sequence(&key, batch.boot_id(), batch.sequence())
            })),
        }
    }

    /// Takes a batch whose signature the caller already verified and which it decoded once
    /// (`tally_wire::Decoded`), at `now_ms` by the engine's clock: a relay hosting this engine
    /// hands it what its own ingest checked, so nothing is verified or decoded twice. As `ingest`
    /// otherwise: used once per (boot, sequence), held only from a receiver that takes part.
    pub fn ingest_verified(&mut self, batch: &Decoded, now_ms: u64) -> Ingested {
        let room = self
            .settings
            .limits()
            .bytes
            .saturating_sub(self.sealed.bytes());
        let Some(intake) = self.intake.as_mut() else {
            return Ingested::Ignored;
        };
        let (ingested, notes) = intake.ingest_verified(batch, room);
        self.provisional.hear_notes(batch, &notes, now_ms);
        ingested
    }

    /// What a batch said to provisional solving (`provisional::notes_of`), read by the intake
    /// that took it, arrived at `now_ms`: for a hosted engine, in the order the batches arrived.
    pub fn hear(&mut self, batch: &Decoded, notes: &[Note], now_ms: u64) {
        self.provisional.hear_notes(batch, notes, now_ms);
    }

    /// Refusals its host's intakes counted, reported with the next step.
    pub fn add_dropped(&mut self, dropped: Dropped) {
        self.dropped.late += dropped.late;
        self.dropped.refused += dropped.refused;
        self.dropped.receivers += dropped.receivers;
    }

    /// The latest bin complete by `now_ms`: it ended, and the settling time after it passed.
    pub fn settled(&self, now_ms: u64) -> i64 {
        bin_of(now_ms.saturating_sub(self.settings.settle_ms)) - 1
    }

    /// Seals every bin that is complete, hands out the work of every window whose bins are all
    /// sealed and that is not solved yet (owned: the sealed bins are shared, not copied), so it
    /// runs off the thread that keeps ingesting; and forgets the bins no window still to be solved
    /// needs. `None` when there is nothing to solve. `now_ms` is the engine's wall clock;
    /// `issued_ms` the wall clock the records it signs carry. A hosted engine's host seals instead
    /// and calls `prepare_sealed`.
    pub fn prepare(&mut self, now_ms: u64, issued_ms: u64) -> Option<Job> {
        let settled = self.settled(now_ms);
        let threads = self.settings.threads.max(1);
        let intake = self.intake.as_mut()?;
        let fragments = intake.take_through(settled);
        let sites: Vec<Site> = intake.sites().collect();
        let dropped = intake.take_dropped();
        self.add_dropped(dropped);
        for bin in seal(fragments, threads) {
            self.sealed.insert(bin);
        }
        self.prepare_sealed(now_ms, issued_ms, settled, sites)
    }

    /// As `prepare`, for an engine whose host sealed every bin through `settled` (the latest bin
    /// complete by `now_ms`, `settled`) and holds the receivers taking part, `sites`, in key order.
    pub fn prepare_sealed(
        &mut self,
        now_ms: u64,
        issued_ms: u64,
        settled: i64,
        sites: Vec<Site>,
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
                identity: self.identity.clone(),
                boot_id: self.boot_id,
                issued_ms,
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
        // A window still to be solved solves bins after `settled - STRIDE`; nothing before its
        // history is needed by the engine. Its raw is its host's one store, so it keeps what
        // standing settles against too: a window and its stride behind the clock, and the spare
        // bins (`held::RAW_SPARE_BINS`).
        let keep = Window::canonical(settled + 1)
            .first
            .min(settled + 1 - BEFORE - STRIDE)
            .min(bin_of(now_ms) - BEFORE - AFTER - STRIDE - RAW_SPARE_BINS);
        self.sealed.forget_before(keep);
        if let Some(intake) = self.intake.as_mut() {
            intake.forget_before(keep);
        }
        self.processed.retain(|last| *last >= keep);
        job
    }

    /// Takes a finished job's outcome: what it solved is not solved again, and its records are
    /// the next in this boot's sequences. The records to publish, in order, and what the step did.
    pub fn apply(&mut self, outcome: Outcome) -> (Vec<Record>, Report, Dropped) {
        self.processed
            .extend(outcome.windows.iter().map(|window| window.last));
        self.positions_sequence = outcome.positions_sequence;
        self.models_sequence = outcome.models_sequence;
        for carried in outcome.carried {
            self.provisional.adopt(carried);
        }
        let dropped = std::mem::take(&mut self.dropped);
        (outcome.records, outcome.report, dropped)
    }

    /// The provisional work due by `now_ms` (`crate::provisional`), owned, to run off the
    /// ingesting thread; `None` when nothing is due.
    pub fn provisional(&mut self, now_ms: u64, issued_ms: u64) -> Option<provisional::Job> {
        self.provisional.due(
            now_ms,
            &self.identity,
            self.boot_id,
            issued_ms,
            self.settings.threads,
        )
    }

    /// Takes a finished provisional job's outcome: its records are the next in this boot's
    /// provisional sequence. The records to publish.
    pub fn apply_provisional(&mut self, outcome: provisional::Outcome) -> Vec<Record> {
        self.provisional.apply(&outcome);
        outcome.records
    }

    /// `provisional`, run and `apply_provisional` in one, on this thread.
    pub fn provisional_step(&mut self, now_ms: u64, issued_ms: u64) -> Vec<Record> {
        match self.provisional(now_ms, issued_ms) {
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
    pub fn step(&mut self, now_ms: u64, issued_ms: u64) -> (Vec<Record>, Report) {
        match self.prepare(now_ms, issued_ms) {
            Some(job) => {
                let (records, report, _) = self.apply(job.run());
                (records, report)
            }
            None => (Vec::new(), Report::default()),
        }
    }
}

/// Seals the open raw `fragments` hold, any split of it by receiver (one holder's, or every raw
/// shard's of a relay), bin by bin, on up to `threads` threads: each bin byte for byte what one
/// holder of all of it seals (`held::Bin::seal_from`). The bins, ascending.
pub fn seal(fragments: Vec<Fragment>, threads: usize) -> Vec<Bin> {
    let mut by_bin: BTreeMap<i64, Vec<Fragment>> = BTreeMap::new();
    for fragment in fragments {
        by_bin.entry(fragment.bin()).or_default().push(fragment);
    }
    by_bin
        .into_iter()
        .map(|(bin, fragments)| Bin::seal_from(bin, fragments, threads))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_mlat_solver::obs::MAX_SITE_PRECISION_M;
    use tally_wire::ReceiverInfo;
    use tally_wire::batch::{ReceiverInfoContent, format};
    use tally_wire::{BatchContent, Clock, Location, Observation};

    fn settings() -> Settings {
        Settings {
            regions: Vec::new(),
            settle_ms: 1_000,
            threads: 1,
            capacity: Capacity::default(),
        }
    }

    fn engine() -> Result<Engine, String> {
        Ok(Engine::new(
            Identity::generate().map_err(|e| e.to_string())?,
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

    fn info(receiver: &Identity, issued_ms: u64, location: Location, clock: Clock) -> Record {
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
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), 0)?;
        let base = 1_000 * GRID_MS;
        let first = vec![observation(1_000, format::MODE_S_SHORT)];
        // The same observation in a second batch (a different sequence): one identity.
        let second = vec![
            observation(1_000, format::MODE_S_SHORT),
            observation(2_000, format::MODE_S_SHORT),
        ];
        assert_eq!(
            engine.ingest(&batch(&receiver, 1, 1, base + 900, second)?, 0)?,
            Ingested::Batch {
                new: 2,
                filtered: 0
            }
        );
        engine.ingest(&batch(&receiver, 1, 0, base + 500, first)?, 0)?;
        // Sealed (its bin complete), the copy is gone and the earliest wall clock kept.
        let _ = engine.prepare(base + GRID_MS + 1_000, 0);
        assert_eq!(engine.held(), 2);
        Ok(())
    }

    #[test]
    fn a_batch_two_relays_deliver_or_one_replays_is_used_once() -> Result<(), String> {
        let mut engine = engine()?;
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest(&info(&receiver, 1, location(), Clock::Beast), 0)?;
        let record = batch(
            &receiver,
            3,
            100,
            0,
            vec![observation(5, format::MODE_S_SHORT)],
        )?;
        assert!(matches!(
            engine.ingest(&record, 0)?,
            Ingested::Batch { new: 1, .. }
        ));
        assert_eq!(engine.ingest(&record, 0)?, Ingested::Replayed);
        // Far behind the boot's newest: a replay, though never seen.
        let old = batch(
            &receiver,
            3,
            10,
            0,
            vec![observation(6, format::MODE_S_SHORT)],
        )?;
        assert_eq!(engine.ingest(&old, 0)?, Ingested::Replayed);
        // A new boot starts its own sequence.
        let restarted = batch(
            &receiver,
            4,
            0,
            0,
            vec![observation(7, format::MODE_S_SHORT)],
        )?;
        assert!(matches!(
            engine.ingest(&restarted, 0)?,
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
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), 0)?;
        engine.ingest(&info(&unknown_clock, 1, location(), Clock::Unknown), 0)?;
        let mut rounded = location();
        rounded.precision_m = MAX_SITE_PRECISION_M + 1;
        engine.ingest(&info(&coarse, 1, rounded, Clock::Dump1090), 0)?;
        let mixed = vec![
            observation(1, format::MODE_AC),
            observation(2, format::MODE_S_SHORT),
            observation(3, format::UAT_DOWNLINK),
            observation(4, format::MODE_S_LONG),
        ];
        assert!(matches!(
            engine.ingest(&batch(&receiver, 1, 0, 0, mixed)?, 0)?,
            Ingested::Batch { new: 2, .. }
        ));
        for other in [&stranger, &unknown_clock, &coarse] {
            let record = batch(other, 1, 0, 0, vec![observation(9, format::MODE_S_SHORT)])?;
            assert_eq!(engine.ingest(&record, 0)?, Ingested::Ignored);
        }
        assert_eq!(engine.held(), 2);
        assert_eq!(engine.taking_part(), 1);
        Ok(())
    }

    #[test]
    fn a_forged_batch_is_an_error_and_holds_nothing() -> Result<(), String> {
        let mut engine = engine()?;
        let receiver = Identity::generate().map_err(text)?;
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), 0)?;
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
        assert!(engine.ingest(&Record::Batch(forged), 0).is_err());
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
                Identity::generate().map_err(text)?,
                1,
                Settings {
                    regions: vec![region],
                    ..settings()
                },
            );
            for record in order {
                engine.ingest(record, 0)?;
            }
            assert_eq!(engine.taking_part(), 0, "the newer description is outside");
        }
        let mut engine = Engine::new(
            Identity::generate().map_err(text)?,
            1,
            Settings {
                regions: vec![region],
                ..settings()
            },
        );
        engine.ingest(&older, 0)?;
        engine.ingest(
            &batch(
                &receiver,
                1,
                0,
                0,
                vec![observation(1, format::MODE_S_SHORT)],
            )?,
            0,
        )?;
        assert_eq!(engine.held(), 1);
        engine.ingest(&newer, 0)?;
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
        engine.ingest(&info(&receiver, 1, location(), Clock::Dump1090), 0)?;
        let base = 1_000 * GRID_MS;
        engine.ingest(
            &batch(
                &receiver,
                1,
                0,
                base,
                vec![observation(1, format::MODE_S_SHORT)],
            )?,
            0,
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
            0,
        )?;
        assert_eq!(engine.held(), 2);
        // A window is due once its last bin has ended and the settling time passed.
        let due = |window: Window| (window.last + 1) as u64 * GRID_MS + 1_000;
        let first = Window::canonical(1_000);
        assert!(engine.prepare(due(first) - 1, 0).is_none());
        assert!(engine.prepare(due(first), 0).is_some());
        assert_eq!(engine.held(), 2);
        // Once every window spanning bin 1000 is solved, it goes; then the later one.
        // Standing reads the same store, so the spare bins it settles in are kept too.
        let gone = |bin: i64| Window::canonical(bin + BEFORE + STRIDE + RAW_SPARE_BINS);
        let _ = engine.prepare(due(gone(1_000)), 0);
        assert_eq!(engine.held(), 1);
        let _ = engine.prepare(due(gone(later)), 0);
        assert_eq!(engine.held(), 0);
        Ok(())
    }
}
