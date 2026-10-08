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
//! - **Threads.** One thread owns the engine. `offer` never waits: it hands the record to that
//!   thread through a bounded queue, and a full queue drops the record (counted). Window steps and
//!   provisional steps run off that thread (`prepare`/`run`/`apply`,
//!   `provisional`/`apply_provisional`), each on threads of its own, at most one of each at a time,
//!   spread over `--mlat-threads`.
//! - **Counted.** Nothing offered or solved is let go silently: every drop is counted by why, and
//!   every step's report kept ([`MlatReport`], served on `--stats-listen` as `GET /mlat`).
//! - **Time.** Nothing here reads a clock: an offer carries when it arrived and `take_published`
//!   when it is asked, so the same records offered and asked at the same times publish the same
//!   bytes as `tally_mlat::replay` driving the engine itself.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use tally_mlat::engine::{Engine, Ingested, Settings};
use tally_mlat::{area, provisional, window};
use tally_wire::{Identity, PublicKey, ReceiverInfo, Record, Region};

use crate::config::Config;

/// The MLAT a relay hosts.
pub trait MlatHost: Send + Sync {
    /// The areas to solve (plus their border band): the receivers it holds are theirs.
    /// `descriptions` are every receiver description the relay holds (`Hub::descriptions`), for
    /// an engine that starts with these areas: the relay keeps the descriptions, not the host. The
    /// relay calls this when the areas change.
    fn set_areas(&self, areas: Vec<Region>, descriptions: Vec<ReceiverInfo>);
    /// A receiver's batch or description the relay forwarded.
    fn offer(&self, record: &Record, now_ms: u64);
    /// What it signed since the last call (clock models and their parts, positions, provisional
    /// positions), in the order to publish.
    fn take_published(&self, now_ms: u64) -> Vec<Record>;
    /// The cores it offers (what `ProviderOffer.mlat_cores` declares).
    fn cores(&self) -> u16;
    /// What it has done and let go, since it started.
    fn report(&self) -> MlatReport;
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
    /// Receptions dropped for room.
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
    /// Batches the engine took (new, from a receiver taking part).
    pub ingested: u64,
    /// Offers dropped because the engine's queue was full.
    pub refused: u64,
    /// Signed records dropped because nobody took them in time.
    pub overflowed: u64,
    /// Batches whose (boot, sequence) was already used or too far behind.
    pub replayed: u64,
    /// Records the engine refused as not signed as they claim.
    pub ingest_errors: u64,
    /// Receiver descriptions not held for an engine about to start, for room.
    pub descriptions_dropped: u64,
    /// Batches of undescribed receivers not held, for room, and held too long.
    pub orphans_dropped: u64,
    pub orphans_expired: u64,
    /// Observations the engine dropped for room (`tally_mlat::engine::MAX_HELD_BYTES`).
    pub observations_dropped: u64,
    /// Window and provisional steps whose engine was dropped before they reported: not published.
    pub steps_discarded: u64,
    /// Window steps applied.
    pub steps: u64,
    /// The newest step's report, and every step's summed.
    pub last_step: Option<StepReport>,
    pub steps_total: StepReport,
    pub provisional: ProvisionalReport,
}

/// How often a due window is looked for and stepped.
pub const STEP_MS: u64 = 1_000;
/// How long after a bin's canonical window ends it is solved, so the raw of its last bin is in.
pub const SETTLE_MS: u64 = 2_000;
/// Records offered and not yet taken by the engine's thread. A world's worth of feeders offer a
/// few thousand batches a second; this is several seconds of them.
const OFFERS_WAITING: usize = 1 << 16;
/// Batches held for a receiver whose description has not come, at most, and receivers, and for how
/// long: a window's worth (a description later than that is not coming by the same way).
const ORPHANS_PER_RECEIVER: usize = 64;
const ORPHAN_RECEIVERS: usize = 4_096;
const ORPHAN_MS: u64 = 60_000;
/// Descriptions held for an engine about to start, at most (the engine's own bound).
const DESCRIPTIONS_WAITING: usize = 65_536;
/// Records signed and not yet taken: a few steps of a busy area. Beyond it the oldest are dropped.
const PUBLISHED_WAITING: usize = 1 << 16;

/// The hosted MLAT a relay runs, if any: none when its relay duties are off (`--no-relay-duties`)
/// or it offers no MLAT threads (`--mlat-threads 0`).
pub fn host_for(config: &Config, identity: Identity, boot_id: u64) -> Option<HostedMlat> {
    (config.relay_duties && config.mlat_threads > 0).then(|| {
        HostedMlat::new(
            identity,
            boot_id,
            Settings {
                regions: Vec::new(),
                settle_ms: SETTLE_MS,
                threads: config.mlat_threads,
            },
        )
    })
}

/// What the engine's thread is handed by the relay.
enum Command {
    Offer(Record, u64),
    Tick(u64),
}

/// What a step reports to the engine's thread, for the engine of its generation.
enum Finished {
    Stepped(u64, window::Outcome),
    Solved(u64, provisional::Outcome),
}

/// How long the engine's thread waits for the relay before it looks for finished steps.
const POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// What the relay's side and the engine's thread share.
struct Shared {
    areas: Mutex<Vec<Region>>,
    /// The relay's receiver descriptions as of the last `set_areas`, for an engine started then.
    descriptions: Mutex<Vec<ReceiverInfo>>,
    /// Bumped by every `set_areas`, so the engine's thread looks at `areas` only when it changed.
    areas_version: AtomicU64,
    published: Mutex<VecDeque<Record>>,
    /// Commands sent and not yet done with, and steps running.
    in_flight: AtomicUsize,
    /// Batches the engine took (new, from a receiver taking part).
    ingested: AtomicU64,
    /// Offers dropped because the queue was full.
    refused: AtomicU64,
    /// Records dropped because nobody took them in time.
    overflowed: AtomicU64,
    /// Everything else counted, by the engine's thread.
    counts: Mutex<MlatReport>,
    stop: AtomicBool,
}

/// `tally-mlat`'s engine as a relay's hosted MLAT.
pub struct HostedMlat {
    commands: SyncSender<Command>,
    shared: Arc<Shared>,
    cores: u16,
}

impl HostedMlat {
    /// The engine signs as `identity` (the relay's key); `boot_id` is its first engine's boot.
    /// `settings.regions` is ignored: the areas are `set_areas`'s.
    pub fn new(identity: Identity, boot_id: u64, settings: Settings) -> Self {
        let cores = u16::try_from(settings.threads).unwrap_or(u16::MAX);
        let (commands, received) = std::sync::mpsc::sync_channel(OFFERS_WAITING);
        let (finished, reported) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared {
            areas: Mutex::new(Vec::new()),
            descriptions: Mutex::new(Vec::new()),
            areas_version: AtomicU64::new(0),
            published: Mutex::new(VecDeque::new()),
            in_flight: AtomicUsize::new(0),
            ingested: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            counts: Mutex::new(MlatReport::default()),
            stop: AtomicBool::new(false),
        });
        let host = Host {
            identity,
            boot_id,
            engines: 0,
            generation: 0,
            settings,
            engine: None,
            areas: Vec::new(),
            areas_version: 0,
            next_step_ms: 0,
            stepping: false,
            solving: false,
            finished,
            shared: Arc::clone(&shared),
            orphans: BTreeMap::new(),
        };
        let spawned = std::thread::Builder::new()
            .name("tally-mlat".to_owned())
            .spawn(move || host.run(&received, &reported));
        if let Err(error) = spawned {
            eprintln!("tally-relay: the hosted MLAT did not start: {error}");
        }
        Self {
            commands,
            shared,
            cores,
        }
    }

    /// Commands handed to the engine's thread and not yet done with, steps running included: zero
    /// when everything offered and asked so far is published.
    pub fn in_flight(&self) -> usize {
        self.shared.in_flight.load(Ordering::SeqCst)
    }

    /// Batches the engine has taken: new, and from a receiver of its areas or their band.
    pub fn ingested(&self) -> u64 {
        self.shared.ingested.load(Ordering::SeqCst)
    }

    /// Offers dropped because the engine's queue was full.
    pub fn refused(&self) -> u64 {
        self.shared.refused.load(Ordering::Relaxed)
    }

    /// Records signed and dropped because nobody took them.
    pub fn overflowed(&self) -> u64 {
        self.shared.overflowed.load(Ordering::Relaxed)
    }

    /// What was signed and not yet taken.
    fn drain(&self) -> Vec<Record> {
        self.shared
            .published
            .lock()
            .map(|mut published| published.drain(..).collect())
            .unwrap_or_default()
    }

    /// Hands `command` to the engine's thread without waiting; false when its queue is full.
    fn send(&self, command: Command) -> bool {
        self.shared.in_flight.fetch_add(1, Ordering::SeqCst);
        match self.commands.try_send(command) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
                false
            }
        }
    }
}

impl Drop for HostedMlat {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // The thread sees the flag within `POLL`, or at once when this drops the queue's sender.
    }
}

impl MlatHost for HostedMlat {
    fn set_areas(&self, areas: Vec<Region>, descriptions: Vec<ReceiverInfo>) {
        let mut areas = areas;
        areas.sort_unstable_by_key(|area| area.as_u64());
        areas.dedup();
        if let Ok(mut wanted) = self.shared.areas.lock()
            && *wanted != areas
        {
            // Added to, never replaced: a description offered between the hub reading these and
            // the engine starting is held there too (`offered`).
            if let Ok(mut held) = self.shared.descriptions.lock() {
                held.extend(descriptions);
            }
            *wanted = areas;
            self.shared.areas_version.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn offer(&self, record: &Record, now_ms: u64) {
        if !matches!(record, Record::Batch(_) | Record::ReceiverInfo(_)) {
            return;
        }
        if !self.send(Command::Offer(record.clone(), now_ms)) {
            self.shared.refused.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn take_published(&self, now_ms: u64) -> Vec<Record> {
        // A tick lost to a full queue is the next call's.
        self.send(Command::Tick(now_ms));
        self.drain()
    }

    fn cores(&self) -> u16 {
        self.cores
    }

    fn report(&self) -> MlatReport {
        let mut report = self
            .shared
            .counts
            .lock()
            .map(|counts| counts.clone())
            .unwrap_or_default();
        report.ingested = self.ingested();
        report.refused = self.refused();
        report.overflowed = self.overflowed();
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
    /// Bumped whenever the engine is dropped or started: a step reports to the generation that
    /// started it, and is discarded if that engine is gone.
    generation: u64,
    settings: Settings,
    engine: Option<Engine>,
    /// The areas the engine solves now, sorted, as of `set_areas`'s `areas_version`.
    areas: Vec<Region>,
    areas_version: u64,
    next_step_ms: u64,
    stepping: bool,
    solving: bool,
    finished: Sender<Finished>,
    shared: Arc<Shared>,
    /// Batches of receivers the engine has no description of yet, by receiver, oldest first:
    /// taken when the description comes. A batch can reach a relay before its receiver's
    /// description (a repair, a rebuild from parity, a link that died between them), and the hub
    /// forwards each batch once, so a batch the engine turned away would be lost to it.
    orphans: BTreeMap<PublicKey, VecDeque<(Record, u64)>>,
}

impl Host {
    fn run(mut self, received: &Receiver<Command>, reported: &Receiver<Finished>) {
        loop {
            if self.shared.stop.load(Ordering::SeqCst) {
                return;
            }
            while let Ok(finished) = reported.try_recv() {
                self.finished(finished);
                self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
            }
            let command = match received.recv_timeout(POLL) {
                Ok(command) => command,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            if self.shared.stop.load(Ordering::SeqCst) {
                return;
            }
            let now_ms = match &command {
                Command::Offer(_, now_ms) | Command::Tick(now_ms) => *now_ms,
            };
            // New areas take effect before whatever comes after them, offers included.
            self.rescope(now_ms);
            let started = match command {
                Command::Offer(record, now_ms) => {
                    self.offered(&record, now_ms);
                    0
                }
                Command::Tick(now_ms) => self.tick(now_ms),
            };
            // This command is done with; the steps it started are in flight until they report.
            self.shared.in_flight.fetch_add(started, Ordering::SeqCst);
            self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A step's outcome, applied if its engine is still the one running; its report kept.
    fn finished(&mut self, finished: Finished) {
        let records = match finished {
            Finished::Stepped(generation, outcome) if generation == self.generation => {
                self.stepping = false;
                match self.engine.as_mut() {
                    Some(engine) => {
                        let (records, report, dropped) = engine.apply(outcome);
                        let step = StepReport::of(&report);
                        self.count(|counts| {
                            counts.steps += 1;
                            counts.observations_dropped += dropped.observations;
                            counts.steps_total.add(&step);
                            counts.last_step = Some(step);
                        });
                        records
                    }
                    None => Vec::new(),
                }
            }
            Finished::Solved(generation, outcome) if generation == self.generation => {
                self.solving = false;
                match self.engine.as_mut() {
                    Some(engine) => {
                        let records = engine.apply_provisional(outcome);
                        let report = engine.provisional_report();
                        self.count(|counts| counts.provisional.add(&report));
                        records
                    }
                    None => Vec::new(),
                }
            }
            // An engine since dropped: what it solved is not published, and counted.
            Finished::Stepped(..) | Finished::Solved(..) => {
                self.count(|counts| counts.steps_discarded += 1);
                Vec::new()
            }
        };
        self.publish(records);
    }

    fn count(&self, change: impl FnOnce(&mut MlatReport)) {
        if let Ok(mut counts) = self.shared.counts.lock() {
            change(&mut counts);
        }
    }

    fn offered(&mut self, record: &Record, now_ms: u64) {
        // A description that comes while an engine is about to start (areas named, none running
        // yet) is kept for it: the hub's descriptions it is handed with the areas were read before
        // this one may have come. With no areas named the next `set_areas` hands them all.
        if self.engine.is_none()
            && let Record::ReceiverInfo(info) = record
        {
            let starting = self
                .shared
                .areas
                .lock()
                .is_ok_and(|areas| !areas.is_empty());
            if starting && let Ok(mut held) = self.shared.descriptions.lock() {
                if held.len() < DESCRIPTIONS_WAITING {
                    held.push(info.clone());
                } else {
                    drop(held);
                    self.count(|counts| counts.descriptions_dropped += 1);
                }
            }
            return;
        }
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        // An error is a record that does not verify; the hub verified it, so none should come.
        let outcome = match engine.ingest(record, now_ms) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.count(|counts| counts.ingest_errors += 1);
                return;
            }
        };
        if let Some(engine) = self.engine.as_mut() {
            match (outcome, record) {
                (Ingested::Batch { .. }, _) => {
                    self.shared.ingested.fetch_add(1, Ordering::SeqCst);
                }
                (Ingested::Replayed, _) => self.count(|counts| counts.replayed += 1),
                (Ingested::Ignored, Record::Batch(batch)) => {
                    if let Ok(key) = batch.receiver()
                        && engine.described(&key).is_none()
                    {
                        self.hold_orphan(key, record.clone(), now_ms);
                    }
                }
                (Ingested::Described, Record::ReceiverInfo(info)) => {
                    if let Ok(key) = info.receiver()
                        && let Some(waiting) = self.orphans.remove(&key)
                    {
                        for (batch, _) in waiting {
                            if let Ok(Ingested::Batch { .. }) = engine.ingest(&batch, now_ms) {
                                self.shared.ingested.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Holds a batch of an undescribed receiver, within `ORPHANS_PER_RECEIVER` a receiver and
    /// `ORPHAN_RECEIVERS` receivers (the oldest out first), for `ORPHAN_MS`.
    fn hold_orphan(&mut self, key: PublicKey, batch: Record, now_ms: u64) {
        let mut expired = 0;
        self.orphans.retain(|_, waiting| {
            let before = waiting.len();
            waiting.retain(|(_, at)| now_ms.saturating_sub(*at) <= ORPHAN_MS);
            expired += (before - waiting.len()) as u64;
            !waiting.is_empty()
        });
        let mut dropped = 0;
        if !self.orphans.contains_key(&key) && self.orphans.len() >= ORPHAN_RECEIVERS {
            dropped += 1;
        } else {
            let waiting = self.orphans.entry(key).or_default();
            if waiting.len() >= ORPHANS_PER_RECEIVER {
                waiting.pop_front();
                dropped += 1;
            }
            waiting.push_back((batch, now_ms));
        }
        if expired + dropped > 0 {
            self.count(|counts| {
                counts.orphans_expired += expired;
                counts.orphans_dropped += dropped;
            });
        }
    }

    /// Starts whatever work is due. The steps started.
    fn tick(&mut self, now_ms: u64) -> usize {
        let generation = self.generation;
        let Some(engine) = self.engine.as_mut() else {
            return 0;
        };
        let mut started = 0;
        if !self.solving
            && let Some(job) = engine.provisional(now_ms, now_ms)
        {
            self.solving = true;
            started += 1;
            let finished = self.finished.clone();
            spawn_or_run(move || {
                let _ = finished.send(Finished::Solved(generation, job.run()));
            });
        }
        if !self.stepping && now_ms >= self.next_step_ms {
            self.next_step_ms = now_ms.saturating_add(STEP_MS);
            if let Some(job) = engine.prepare(now_ms, now_ms) {
                self.stepping = true;
                started += 1;
                let finished = self.finished.clone();
                spawn_or_run(move || {
                    let _ = finished.send(Finished::Stepped(generation, job.run()));
                });
            }
        }
        started
    }

    /// The areas `set_areas` last named, made the engine's.
    fn rescope(&mut self, now_ms: u64) {
        let version = self.shared.areas_version.load(Ordering::SeqCst);
        if version == self.areas_version {
            return;
        }
        self.areas_version = version;
        let wanted = self
            .shared
            .areas
            .lock()
            .map(|areas| areas.clone())
            .unwrap_or_default();
        if wanted == self.areas {
            return;
        }
        if wanted.is_empty() {
            // No longer an MLAT relay for anything: the engine and its raw go, and whatever it
            // is still solving is discarded when it reports.
            self.engine = None;
            self.generation += 1;
            self.stepping = false;
            self.solving = false;
        } else {
            let band = area::border_band(&wanted);
            match self.engine.as_mut() {
                Some(engine) => engine.set_scope(band, wanted.clone()),
                None => {
                    let mut engine = Engine::new(
                        self.identity.clone(),
                        self.boot_id.wrapping_add(self.engines),
                        self.settings.clone(),
                    );
                    self.engines += 1;
                    self.generation += 1;
                    engine.set_scope(band, wanted.clone());
                    let descriptions = self
                        .shared
                        .descriptions
                        .lock()
                        .map(|mut held| std::mem::take(&mut *held))
                        .unwrap_or_default();
                    for info in descriptions {
                        let _ = engine.ingest(&Record::ReceiverInfo(info), now_ms);
                    }
                    self.engine = Some(engine);
                    self.next_step_ms = now_ms;
                    self.stepping = false;
                    self.solving = false;
                }
            }
        }
        self.areas = wanted;
    }

    fn publish(&self, records: Vec<Record>) {
        if records.is_empty() {
            return;
        }
        if let Ok(mut published) = self.shared.published.lock() {
            published.extend(records);
            let over = published.len().saturating_sub(PUBLISHED_WAITING);
            if over > 0 {
                published.drain(..over);
                self.shared
                    .overflowed
                    .fetch_add(over as u64, Ordering::Relaxed);
            }
        }
    }
}

/// Runs `work` on a thread of its own, or here if no thread can be had.
fn spawn_or_run(work: impl FnOnce() + Send + 'static) {
    let work = Arc::new(Mutex::new(Some(work)));
    let theirs = Arc::clone(&work);
    let spawned = std::thread::Builder::new()
        .name("tally-mlat-step".to_owned())
        .spawn(move || {
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

    /// Drives the host as `tally_mlat::replay::replay` drives an engine: every `STEP_MS` of the
    /// virtual clock what has arrived is offered, then the host is asked, then waited on. Every
    /// record it published, with the clock it was asked at.
    fn drive(
        host: &HostedMlat,
        arrivals: &[(u64, Record)],
        from_ms: u64,
        until_ms: u64,
    ) -> Vec<(u64, Record)> {
        let mut published = Vec::new();
        let mut now = from_ms;
        let mut next = arrivals.partition_point(|(at, _)| *at < from_ms);
        while now <= until_ms {
            while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at <= now) {
                host.offer(record, *at);
                next += 1;
            }
            let early = host.take_published(now);
            quiet(host);
            published.extend(early.into_iter().chain(host.drain()).map(|r| (now, r)));
            now += STEP_MS;
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
    /// publishes byte for byte what the reference engine publishes from the same raw at the same
    /// clocks (`tally_mlat::replay`, the engine driven in line on a virtual clock): the same clock
    /// models, positions and provisional positions, signed by the relay's key. And every model it
    /// fits is of a tile whose centre is in one of its areas.
    #[test]
    fn a_hosted_engine_publishes_what_the_reference_engine_publishes_from_the_same_raw()
    -> Result<(), String> {
        let mut simulation = sim::run(&scenario(17, 60.0));
        let delivered = arrivals(&mut simulation, 3)?;
        let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
        let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
        let areas = areas()?;

        let host = HostedMlat::new(identity(), BOOT, settings());
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
        let host = HostedMlat::new(identity(), BOOT, settings());
        host.set_areas(areas()?, Vec::new());
        // The engine starts with the first command after its areas: a tick.
        let now = feed.batches[0].content().map_err(text)?.wall_ms;
        host.take_published(now);
        quiet(&host);
        let offered = feed.batches.len().min(ORPHANS_PER_RECEIVER + 10);
        assert!(offered > ORPHANS_PER_RECEIVER);
        for batch in &feed.batches[..offered] {
            host.offer(&Record::Batch(batch.clone()), now);
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
        let host = HostedMlat::new(identity(), BOOT, settings());
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
        let host = HostedMlat::new(identity(), BOOT, settings());
        host.set_areas(areas()?, Vec::new());
        let now = feed.batches[0].content().map_err(text)?.wall_ms;
        let early = feed.batches.len().min(5);
        for batch in &feed.batches[..early] {
            host.offer(&Record::Batch(batch.clone()), now);
        }
        while host.in_flight() > 0 {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(host.ingested(), 0);
        host.offer(&Record::ReceiverInfo(feed.info.clone()), now);
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
        let host = HostedMlat::new(identity(), BOOT, settings());
        host.set_areas(areas()?, Vec::new());
        // Every receiver describes itself at the start: before the areas are withdrawn.
        let half = first + (last - first) / 2;
        drive(&host, &delivered, first, half);
        let taken = host.ingested();
        assert!(taken > 0);
        host.set_areas(Vec::new(), Vec::new());
        let after = drive(&host, &delivered, half + STEP_MS, last + 60_000);
        assert!(after.is_empty(), "{} records after", after.len());
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
        let hosted = host_for(&config(&format!("{base} --mlat-threads 3"))?, identity(), 1)
            .ok_or("not hosted")?;
        assert_eq!(hosted.cores(), 3);
        // Duties are on by default, so a relay offers every core unless told otherwise.
        assert!(host_for(&config(base)?, identity(), 1).is_some());
        assert!(host_for(&config(&format!("{base} --mlat-threads 0"))?, identity(), 1).is_none());
        assert!(
            host_for(
                &config(&format!("{base} --mlat-threads 3 --no-relay-duties"))?,
                identity(),
                1
            )
            .is_none()
        );
        Ok(())
    }
}
