//! The engine's state (RFC-0171 §3.8, §3.8.1): the receivers it multilaterates for, the raw
//! observations it holds (`tally_mlat_solver::held`, compact, per bin), and which windows it has
//! solved. Nothing here reads a clock or a socket: the caller says what time it is, so the same
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
//!   prefilter and, when a bin is sealed, its canonical thinning), in 24 bytes an observation, the
//!   whole bounded by bytes (`MAX_HELD_BYTES`).
//! - Which window an observation is in is decided by its content alone: its grid bin is its
//!   signed batch wall clock's, never when it arrived (`tally_mlat_solver::scope`). A bin is
//!   sealed once it has ended and a settling time has passed by the engine's clock, and a window
//!   (strided: one fit per tile per `STRIDE` bins) is solved once its last bin is sealed; when
//!   decides only whether late raw makes it in, never what the same raw solves to.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tally_mlat_solver::held::Held;
use tally_mlat_solver::obs::MAX_SITE_PRECISION_M;
use tally_mlat_solver::scope::{BEFORE, STRIDE, Window, bin_of};
use tally_mlat_solver::{Site, Timebase};
use tally_wire::{Batch, Clock, Identity, Location, PublicKey, ReceiverInfo, Record, Region};

use crate::provisional::{self, Provisional};
use crate::window::{Job, Outcome, Report};

/// How far behind a boot's newest sequence a batch may still arrive (two relays, or one relay's
/// reordering) and be used; anything older is a replay or too late to matter.
const REORDER: u64 = 64;
/// Boots remembered per receiver, most recent first. A receiver that restarts more often than
/// this within one window only weakens its own replay protection.
const BOOTS_PER_RECEIVER: usize = 8;
/// Receivers described at once, taking part or not. A region's relays bound what reaches the
/// engine; this bounds what the engine keeps if they do not.
pub const MAX_RECEIVERS: usize = 16_384;
/// Bytes of raw held at once (`tally_mlat_solver::held`, about 24 bytes an observation and its
/// share of the bin's index and messages). Sized for the whole world on one node: 20,000
/// feeders, at the few hundred observations a second each that survive ingest thinning, over
/// the 85 s a window at stride 4 and its settling span (RFC-0171 §3.8.1). Beyond it new raw is
/// refused (and counted) until a bin is forgotten.
pub const MAX_HELD_BYTES: usize = 48 << 30;

/// What the operator chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The H3 cells whose receivers take part; empty is every receiver with a location.
    pub regions: Vec<Region>,
    /// How long after a bin's canonical window ends (by the engine's clock) it is solved, so the
    /// raw of the window's last bin is in.
    pub settle_ms: u64,
    /// The threads one step's work is spread over. Any number gives the same bytes.
    pub threads: usize,
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
}

/// Observations dropped for room since the last step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    pub observations: u64,
}

/// A receiver's newest description: when it was issued, its bytes (which decide between two
/// issued in the same millisecond, so the order they arrive in does not), and its site if it
/// takes part.
struct Described {
    issued_ms: u64,
    bytes: Vec<u8>,
    /// What it declared, so a change of the engine's regions re-decides whether it takes part.
    location: Option<Location>,
    clock: Clock,
    site: Option<Site>,
    /// The sequences used per boot, most recent boot first.
    boots: VecDeque<(u64, Sequences)>,
}

/// The sequences of one boot already used: the newest, and which of the `REORDER` before it.
struct Sequences {
    newest: u64,
    /// Bit `i` set: sequence `newest - i` was used.
    used: u64,
}

impl Sequences {
    fn new(sequence: u64) -> Self {
        Self {
            newest: sequence,
            used: 1,
        }
    }

    /// True the first time `sequence` is offered, if it is within `REORDER` of the newest.
    fn admit(&mut self, sequence: u64) -> bool {
        if sequence > self.newest {
            let ahead = sequence - self.newest;
            self.used = if ahead >= REORDER {
                0
            } else {
                self.used << ahead
            };
            self.used |= 1;
            self.newest = sequence;
            return true;
        }
        let behind = self.newest - sequence;
        if behind >= REORDER {
            return false;
        }
        let bit = 1 << behind;
        if self.used & bit != 0 {
            return false;
        }
        self.used |= bit;
        true
    }
}

impl Described {
    /// True when the batch numbered `sequence` in `boot` has not been used.
    fn admit(&mut self, boot: u64, sequence: u64) -> bool {
        let found = self
            .boots
            .iter()
            .position(|(id, _)| *id == boot)
            .and_then(|at| self.boots.remove(at));
        let (admitted, sequences) = match found {
            Some((_, mut sequences)) => (sequences.admit(sequence), sequences),
            None => {
                self.boots.truncate(BOOTS_PER_RECEIVER - 1);
                (true, Sequences::new(sequence))
            }
        };
        self.boots.push_front((boot, sequences));
        admitted
    }
}

pub struct Engine {
    identity: Identity,
    boot_id: u64,
    settings: Settings,
    receivers: BTreeMap<PublicKey, Described>,
    /// The areas whose tiles it fits (`set_scope`): a tile is fitted only if its centre is in one.
    /// Empty: every tile its regions cover.
    owned: Vec<Region>,
    held: Held,
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
        Self {
            identity,
            boot_id,
            settings,
            receivers: BTreeMap::new(),
            owned: Vec::new(),
            held: Held::new(MAX_HELD_BYTES),
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

    /// Observations held now (an open bin's copies included until it is sealed).
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Bytes of raw held now.
    pub fn held_bytes(&self) -> usize {
        self.held.bytes()
    }

    /// Whether `receiver` is described, and whether it takes part.
    pub fn described(&self, receiver: &PublicKey) -> Option<bool> {
        self.receivers
            .get(receiver)
            .map(|described| described.site.is_some())
    }

    /// Receivers taking part now.
    pub fn taking_part(&self) -> usize {
        self.receivers
            .values()
            .filter(|described| described.site.is_some())
            .count()
    }

    /// Takes a record a relay delivered, at `now_ms` by the engine's clock (which decides only
    /// when a reception is solved provisionally, never what anything solves to). An error is a
    /// record that claimed to be signed and is not.
    pub fn ingest(&mut self, record: &Record, now_ms: u64) -> Result<Ingested, String> {
        match record {
            Record::ReceiverInfo(info) => self.describe(info),
            Record::Batch(batch) => self.receive(batch, now_ms),
            // A relay's deduplicated stream is the relay's word, not a receiver's: it carries no
            // receiver's counter and is never multilaterated.
            _ => Ok(Ingested::Ignored),
        }
    }

    fn describe(&mut self, info: &ReceiverInfo) -> Result<Ingested, String> {
        let key = info.receiver().map_err(|error| error.to_string())?;
        info.verify()
            .map_err(|error| format!("receiver info of {key}: {error}"))?;
        // A format this build cannot read says nothing it can use.
        let Ok(content) = info.content() else {
            return Ok(Ingested::Ignored);
        };
        if let Some(known) = self.receivers.get(&key)
            && (known.issued_ms, known.bytes.as_slice()) >= (content.issued_ms, info.as_bytes())
        {
            return Ok(Ingested::Ignored);
        }
        let site = self.site(key, content.location, content.clock);
        if !self.receivers.contains_key(&key) && self.receivers.len() >= MAX_RECEIVERS {
            // Full: a receiver that takes part displaces the first that does not; one that does
            // not take part is not remembered.
            let Some(idle) = self
                .receivers
                .iter()
                .find(|(_, known)| known.site.is_none())
                .map(|(key, _)| *key)
                .filter(|_| site.is_some())
            else {
                return Ok(Ingested::Ignored);
            };
            self.receivers.remove(&idle);
        }
        let known = self.receivers.entry(key).or_insert_with(|| Described {
            issued_ms: 0,
            bytes: Vec::new(),
            location: None,
            clock: content.clock,
            site: None,
            boots: VecDeque::new(),
        });
        known.issued_ms = content.issued_ms;
        known.bytes = info.as_bytes().to_vec();
        known.location = content.location;
        known.clock = content.clock;
        let left = known.site.is_some() && site.is_none();
        known.site = site;
        if left {
            // It left the regions or became unusable: what it heard is no longer used.
            known.boots.clear();
            self.held.forget_receiver(&key);
        }
        Ok(Ingested::Described)
    }

    /// Changes what the engine covers, as a relay hosting it does when the areas it is an MLAT
    /// relay for change (RFC-0174 §2.3): `regions` as `Settings::regions` (the receivers that take
    /// part, and the footprints a fitted tile must lie inside: an area and its border band), and
    /// `owned` the areas whose tiles it fits (a tile's centre in one; empty, every tile `regions`
    /// cover). Every receiver described is decided again on its own signed word: one now outside
    /// takes no part and what it heard is forgotten, as when its own description moves it out; one
    /// now inside takes part from its next batch. The same records under the same scope solve to
    /// the same bytes whatever scopes came before.
    pub fn set_scope(&mut self, regions: Vec<Region>, owned: Vec<Region>) {
        self.settings.regions = regions;
        self.owned = owned;
        let decided: Vec<(PublicKey, Option<Site>)> = self
            .receivers
            .iter()
            .map(|(key, known)| (*key, self.site(*key, known.location, known.clock)))
            .collect();
        for (key, site) in decided {
            let Some(known) = self.receivers.get_mut(&key) else {
                continue;
            };
            let left = known.site.is_some() && site.is_none();
            known.site = site;
            if left {
                known.boots.clear();
                self.held.forget_receiver(&key);
            }
        }
    }

    /// The site a declared location and clock give, if the receiver takes part.
    fn site(&self, key: PublicKey, location: Option<Location>, clock: Clock) -> Option<Site> {
        let location = location?;
        let inside = self.settings.regions.is_empty()
            || self
                .settings
                .regions
                .iter()
                .any(|region| region.covers(&location));
        let usable = Timebase::of(clock).is_some() && location.precision_m <= MAX_SITE_PRECISION_M;
        (inside && usable).then_some(Site {
            receiver: key,
            clock,
            location,
        })
    }

    fn receive(&mut self, batch: &Batch, now_ms: u64) -> Result<Ingested, String> {
        let key = batch.receiver().map_err(|error| error.to_string())?;
        let Some(known) = self.receivers.get_mut(&key) else {
            return Ok(Ingested::Ignored);
        };
        if known.site.is_none() {
            return Ok(Ingested::Ignored);
        }
        batch
            .verify()
            .map_err(|error| format!("batch of {key}: {error}"))?;
        if !known.admit(batch.boot_id(), batch.sequence()) {
            return Ok(Ingested::Replayed);
        }
        let Ok(content) = batch.content() else {
            return Ok(Ingested::Ignored);
        };
        self.provisional.hear(key, &content, now_ms);
        let added = self.held.add(key, &content);
        self.dropped.observations += added.dropped as u64;
        Ok(Ingested::Batch {
            new: added.new,
            filtered: added.filtered,
        })
    }

    /// The latest bin complete by `now_ms`: it ended, and the settling time after it passed.
    fn settled(&self, now_ms: u64) -> i64 {
        bin_of(now_ms.saturating_sub(self.settings.settle_ms)) - 1
    }

    /// Seals every bin that is complete, hands out the work of every window whose bins are all
    /// sealed and that is not solved yet (owned: the sealed bins are shared, not copied), so it
    /// runs off the thread that keeps ingesting; and forgets the bins no window still to be solved
    /// needs. `None` when there is nothing to solve. `now_ms` is the engine's wall clock;
    /// `issued_ms` the wall clock the records it signs carry.
    pub fn prepare(&mut self, now_ms: u64, issued_ms: u64) -> Option<Job> {
        let settled = self.settled(now_ms);
        self.held.seal_through(settled);
        let windows: Vec<Window> = self
            .held
            .sealed()
            .into_iter()
            .map(Window::canonical)
            .filter(|window| window.last <= settled && !self.processed.contains(&window.last))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let job = match (windows.first(), windows.last()) {
            (Some(first), Some(last)) => {
                let sites = self
                    .receivers
                    .values()
                    .filter_map(|known| known.site)
                    .collect();
                Some(Job {
                    identity: self.identity.clone(),
                    boot_id: self.boot_id,
                    issued_ms,
                    threads: self.settings.threads.max(1),
                    regions: self.settings.regions.clone(),
                    owned: self.owned.clone(),
                    windows: windows.clone(),
                    sites,
                    bins: self.held.bins(first.first, last.last),
                    positions_sequence: self.positions_sequence,
                    models_sequence: self.models_sequence,
                })
            }
            _ => None,
        };
        // A window still to be solved solves bins after `settled - STRIDE`; nothing before its
        // history is needed.
        let keep = Window::canonical(settled + 1)
            .first
            .min(settled + 1 - BEFORE - STRIDE);
        self.held.forget_before(keep);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::batch::{ReceiverInfoContent, format};
    use tally_wire::{BatchContent, Clock, Location, Observation};

    fn settings() -> Settings {
        Settings {
            regions: Vec::new(),
            settle_ms: 1_000,
            threads: 1,
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
        let _ = engine.prepare(due(Window::canonical(1_000 + BEFORE + STRIDE)), 0);
        assert_eq!(engine.held(), 1);
        let _ = engine.prepare(due(Window::canonical(later + BEFORE + STRIDE)), 0);
        assert_eq!(engine.held(), 0);
        Ok(())
    }
}
