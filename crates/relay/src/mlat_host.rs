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
//! - **One store of raw, held where it arrives** (RFC-0177 §5). The receivers and their open raw
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
//! - **Threads.** One thread owns the engine. What a batch says to provisional solving
//!   (`provisional::notes_of`, read in its shard) reaches that thread through a bounded queue that
//!   never waits (full: counted), and is weighed there in the order of the batches' stamps, so the
//!   same stamped trace solves the same provisionals on any number of ingest workers. Seals, window
//!   steps and provisional steps run off that thread, each on threads of its own, at most one step
//!   of each kind at a time, spread over `--mlat-threads`.
//! - **Counted.** Nothing offered or solved is let go silently: every drop is counted by why, and
//!   every step's report kept ([`MlatReport`], served on `--stats-listen` as `GET /mlat`).
//! - **Time.** Nothing here reads a clock: an offer carries when it arrived and `take_published`
//!   when it is asked, so the same records offered and asked at the same times publish the same
//!   bytes as `tally_mlat::replay` driving the engine itself.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use tally_mlat::engine::{Capacity, Dropped, Engine, Ingested, Settings};
use tally_mlat::intake::{Intake, Seats};
use tally_mlat::provisional::Note;
use tally_mlat::{area, provisional, window};
use tally_mlat_solver::Site;
use tally_mlat_solver::held::{Bin, Fragment, Limits, SealedBins};
use tally_wire::{Decoded, Identity, PublicKey, ReceiverInfo, Record, Region};

use crate::config::Config;
use crate::exchange::{SHARDS, raw_shard};

/// The MLAT a relay hosts.
pub trait MlatHost: Send + Sync {
    /// The areas to solve (plus their border band): the receivers it holds are theirs.
    /// `descriptions` are every receiver description the relay holds (`Hub::descriptions`), for
    /// a host that has not been offered them. The relay calls this when the areas change.
    fn set_areas(&self, areas: Vec<Region>, descriptions: Vec<ReceiverInfo>);
    /// A receiver's description the relay forwarded, or a batch it has not decoded.
    fn offer(&self, record: &Record, now_ms: u64);
    /// A receiver's batch the relay forwarded, verified and decoded once by its ingest, on the
    /// ingest worker that owns the receiver's raw shard, stamped `now_ms`: taken into that shard,
    /// never verified or decoded again.
    fn offer_batch(&self, batch: &Arc<Decoded>, now_ms: u64);
    /// What it signed since the last call (clock models and their parts, positions, provisional
    /// positions), in the order to publish.
    fn take_published(&self, now_ms: u64) -> Vec<Record>;
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
    /// Batches taken (new, from a receiver taking part).
    pub ingested: u64,
    /// What batches said to provisional solving, dropped because the engine's queue was full.
    pub refused: u64,
    /// Signed records dropped because nobody took them in time.
    pub overflowed: u64,
    /// Batches whose (boot, sequence) was already used or too far behind.
    pub replayed: u64,
    /// Receiver descriptions refused as not signed as they claim.
    pub ingest_errors: u64,
    /// Batches of undescribed receivers not held, for room, and held too long.
    pub orphans_dropped: u64,
    pub orphans_expired: u64,
    /// Observations of a bin already sealed: later than its settling.
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

/// How often a due window is looked for and stepped.
pub const STEP_MS: u64 = 1_000;
/// How long after a bin's canonical window ends it is solved, so the raw of its last bin is in.
pub const SETTLE_MS: u64 = 2_000;
/// What batches said to provisional solving and not yet weighed by the engine's thread. A world's
/// worth of feeders offer a few thousand batches a second; this is several seconds of them.
const OFFERS_WAITING: usize = 1 << 16;
/// Batches held for a receiver whose description has not come, at most, and receivers (in each raw
/// shard), and for how long: a window's worth (a description later than that is not coming by the
/// same way).
const ORPHANS_PER_RECEIVER: usize = 64;
const ORPHAN_RECEIVERS_PER_SHARD: usize = 4_096 / SHARDS;
const ORPHAN_MS: u64 = 60_000;
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
                capacity: capacity(config),
            },
        )
    })
}

/// What the hosted engine holds: sized for every feeder the relay's memory admits (the admission
/// budget's ceiling, `budget`, RFC-0177 §9), never fewer than `tally_mlat::engine::MIN_RECEIVERS`.
pub fn capacity(config: &Config) -> Capacity {
    let budget =
        crate::budget::Budget::of_memory(config.memory, crate::budget::PerFeeder::planned(true));
    Capacity::for_receivers(budget.ceiling())
}

/// What the engine's thread is handed.
enum Command {
    /// What one batch said to provisional solving, read in its raw shard: the batch (which
    /// carries when it arrived, its stamp), the notes, and the shard's engine generation then.
    Heard(Arc<Decoded>, Vec<Note>, u64),
    /// A receiver stopped taking part under engine generation `.0`: forgotten in the sealed bins.
    Left(u64, PublicKey),
    /// The areas changed (`set_areas` re-scoped every shard first): engine generation, areas.
    Areas(u64, Vec<Region>),
    Tick(u64),
}

/// What a seal or a step reports to the engine's thread, for the engine of its generation.
enum Finished {
    /// The bins complete by `now_ms` (through `settled`), sealed, with the sites taking part and
    /// what the shards refused.
    Sealed {
        generation: u64,
        now_ms: u64,
        settled: i64,
        bins: Vec<Bin>,
        sites: Vec<Site>,
        dropped: Dropped,
    },
    Stepped(u64, window::Outcome),
    Solved(u64, provisional::Outcome),
}

/// How long the engine's thread waits for the relay before it looks for finished steps.
const POLL: std::time::Duration = std::time::Duration::from_millis(20);

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

/// The areas as `set_areas` last set them, and the engine generation they started.
#[derive(Default)]
struct Scope {
    areas: Vec<Region>,
    generation: u64,
}

/// What the relay's side and the engine's thread share.
struct Shared {
    scope: Mutex<Scope>,
    /// The raw shards, `SHARDS` of them, each locked by the ingest worker that owns its receivers
    /// (one batch at a time), and by the engine's thread to take what is complete or re-scope.
    shards: Box<[Mutex<Shard>]>,
    /// What each shard's open raw is bounded by.
    limits: Limits,
    published: Mutex<VecDeque<Record>>,
    /// Commands sent and not yet done with, and seals and steps running.
    in_flight: AtomicUsize,
    /// Counted by the shards as batches come.
    ingested: AtomicU64,
    refused: AtomicU64,
    replayed: AtomicU64,
    ingest_errors: AtomicU64,
    orphans_dropped: AtomicU64,
    orphans_expired: AtomicU64,
    /// Records dropped because nobody took them in time.
    overflowed: AtomicU64,
    /// Everything else counted, by the engine's thread.
    counts: Mutex<MlatReport>,
    /// The sealed bins of whichever engine runs: one handle for the host's life.
    sealed: SealedBins,
    stop: AtomicBool,
}

impl Shared {
    fn shard(&self, receiver: &PublicKey) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[usize::from(raw_shard(receiver).0)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
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
        let limits = Limits {
            bytes: usize::MAX,
            ..settings.limits()
        };
        let seats = Seats::new(settings.capacity.receivers);
        let shared = Arc::new(Shared {
            scope: Mutex::new(Scope::default()),
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        intake: Intake::new(Arc::clone(&seats), limits, None),
                        generation: 0,
                        active: false,
                        orphans: BTreeMap::new(),
                    })
                })
                .collect(),
            limits,
            published: Mutex::new(VecDeque::new()),
            in_flight: AtomicUsize::new(0),
            ingested: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            replayed: AtomicU64::new(0),
            ingest_errors: AtomicU64::new(0),
            orphans_dropped: AtomicU64::new(0),
            orphans_expired: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            counts: Mutex::new(MlatReport::default()),
            sealed: SealedBins::new(),
            stop: AtomicBool::new(false),
        });
        let host = Host {
            identity,
            boot_id,
            engines: 0,
            generation: 0,
            settings,
            engine: None,
            next_step_ms: 0,
            stepping: false,
            solving: false,
            heard: BTreeMap::new(),
            next_heard: 0,
            finished,
            shared: Arc::clone(&shared),
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

    /// Commands handed to the engine's thread and not yet done with, seals and steps running
    /// included: zero when everything offered and asked so far is published.
    pub fn in_flight(&self) -> usize {
        self.shared.in_flight.load(Ordering::SeqCst)
    }

    /// Batches taken: new, and from a receiver of its areas or their band.
    pub fn ingested(&self) -> u64 {
        self.shared.ingested.load(Ordering::SeqCst)
    }

    /// What batches said to provisional solving, dropped because the engine's queue was full.
    pub fn refused(&self) -> u64 {
        self.shared.refused.load(Ordering::Relaxed)
    }

    /// Records signed and dropped because nobody took them.
    pub fn overflowed(&self) -> u64 {
        self.shared.overflowed.load(Ordering::Relaxed)
    }

    /// What was signed and not yet taken, asking for nothing more: for a caller that waited for
    /// `in_flight` to reach zero.
    pub fn take_signed(&self) -> Vec<Record> {
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

    /// Hands `command` to the engine's thread, waiting for room: what must not be lost (a change
    /// of areas, a receiver to forget).
    fn send_waiting(&self, command: Command) {
        self.shared.in_flight.fetch_add(1, Ordering::SeqCst);
        if self.commands.send(command).is_err() {
            self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A description, into its receiver's shard: the batches that waited for it are taken now.
    fn describe(&self, info: &ReceiverInfo) {
        let Ok(key) = info.receiver() else {
            return;
        };
        let left = {
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
                    self.take(&mut shard, &batch);
                }
            }
            described.left.then_some(shard.generation)
        };
        // Sent with the shard let go: the engine's thread may be waiting for it.
        if let Some(generation) = left {
            self.send_waiting(Command::Left(generation, key));
        }
    }

    /// One batch into `shard`, its receiver's: what it says to provisional solving goes to the
    /// engine's thread.
    fn take(&self, shard: &mut Shard, batch: &Arc<Decoded>) -> Ingested {
        let (ingested, notes) = shard.intake.ingest_verified(batch, usize::MAX);
        match ingested {
            Ingested::Batch { .. } => {
                self.shared.ingested.fetch_add(1, Ordering::SeqCst);
                if !notes.is_empty()
                    && !self.send(Command::Heard(Arc::clone(batch), notes, shard.generation))
                {
                    self.shared.refused.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ingested::Replayed => {
                self.shared.replayed.fetch_add(1, Ordering::Relaxed);
            }
            Ingested::Described | Ingested::Ignored | Ingested::Refused => {}
        }
        ingested
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
        // The thread sees the flag within `POLL`, or at once when this drops the queue's sender.
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
        }
        let band = (!areas.is_empty()).then(|| area::border_band(&areas));
        let mut left = Vec::new();
        for shard in &self.shared.shards {
            let mut shard = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if restart {
                shard.intake.restart(self.shared.limits);
                shard.orphans.clear();
            }
            left.extend(shard.intake.set_scope(band.clone()));
            shard.generation = scope.generation;
            shard.active = band.is_some();
        }
        scope.areas.clone_from(&areas);
        let generation = scope.generation;
        drop(scope);
        if !restart {
            for key in left {
                self.send_waiting(Command::Left(generation, key));
            }
        }
        self.send_waiting(Command::Areas(generation, areas));
    }

    fn offer(&self, record: &Record, now_ms: u64) {
        match record {
            // The relay verified it before offering it: decoded once here, it takes the same path
            // as the hub's own decode. One this build cannot read holds nothing.
            Record::Batch(batch) => {
                if let Ok(decoded) = Decoded::from_verified(batch.clone(), now_ms, 0) {
                    self.offer_batch(&decoded, now_ms);
                }
            }
            Record::ReceiverInfo(info) => self.describe(info),
            _ => {}
        }
    }

    fn offer_batch(&self, batch: &Arc<Decoded>, now_ms: u64) {
        let mut shard = self.shared.shard(&batch.receiver());
        if !shard.active {
            return;
        }
        if self.take(&mut shard, batch) == Ingested::Ignored
            && shard.intake.described(&batch.receiver()).is_none()
        {
            self.hold_orphan(&mut shard, batch, now_ms);
        }
    }

    fn take_published(&self, now_ms: u64) -> Vec<Record> {
        // A tick lost to a full queue is the next call's.
        self.send(Command::Tick(now_ms));
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
        report.refused = self.refused();
        report.overflowed = self.overflowed();
        report.replayed = shared.replayed.load(Ordering::Relaxed);
        report.ingest_errors = shared.ingest_errors.load(Ordering::Relaxed);
        report.orphans_dropped = shared.orphans_dropped.load(Ordering::Relaxed);
        report.orphans_expired = shared.orphans_expired.load(Ordering::Relaxed);
        report
    }
}

/// What one batch said to provisional solving, waiting to be weighed: the batch, its notes, and
/// the engine generation of the shard that read them.
type Heard = (Arc<Decoded>, Vec<Note>, u64);

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
    next_step_ms: u64,
    stepping: bool,
    solving: bool,
    /// What batches said to provisional solving, by (stamp, place in the ingest order, arrival
    /// here), weighed once the engine's clock passes them: in that order whatever worker read them.
    heard: BTreeMap<(u64, u64, u64), Heard>,
    next_heard: u64,
    finished: Sender<Finished>,
    shared: Arc<Shared>,
}

impl Host {
    fn run(mut self, received: &Receiver<Command>, reported: &Receiver<Finished>) {
        loop {
            if self.shared.stop.load(Ordering::SeqCst) {
                return;
            }
            while let Ok(finished) = reported.try_recv() {
                let started = self.finished(finished);
                self.shared.in_flight.fetch_add(started, Ordering::SeqCst);
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
            let started = match command {
                Command::Heard(batch, notes, generation) => {
                    if generation >= self.generation {
                        let at = (batch.stamp_ms(), batch.ingest_seq(), self.next_heard);
                        self.next_heard += 1;
                        self.heard.insert(at, (batch, notes, generation));
                    }
                    0
                }
                Command::Left(generation, key) => {
                    if generation == self.generation
                        && let Some(engine) = self.engine.as_mut()
                    {
                        engine.forget_receiver(&key);
                    }
                    0
                }
                Command::Areas(generation, areas) => {
                    self.rescope(generation, areas);
                    0
                }
                Command::Tick(now_ms) => self.tick(now_ms),
            };
            // This command is done with; the work it started is in flight until it reports.
            self.shared.in_flight.fetch_add(started, Ordering::SeqCst);
            self.shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A seal's or a step's outcome, applied if its engine is still the one running; its report
    /// kept. The work it started.
    fn finished(&mut self, finished: Finished) -> usize {
        let (records, started) = match finished {
            Finished::Sealed {
                generation,
                now_ms,
                settled,
                bins,
                sites,
                dropped,
            } if generation == self.generation => {
                for bin in bins {
                    self.shared.sealed.insert(bin);
                }
                (Vec::new(), self.step(now_ms, settled, sites, dropped))
            }
            Finished::Stepped(generation, outcome) if generation == self.generation => {
                self.stepping = false;
                match self.engine.as_mut() {
                    Some(engine) => {
                        let (records, report, dropped) = engine.apply(outcome);
                        let step = StepReport::of(&report);
                        self.count(|counts| {
                            counts.steps += 1;
                            counts.observations_late += dropped.late;
                            counts.observations_refused += dropped.refused;
                            counts.receivers_refused += dropped.receivers;
                            counts.steps_total.add(&step);
                            counts.last_step = Some(step);
                        });
                        (records, 0)
                    }
                    None => (Vec::new(), 0),
                }
            }
            Finished::Solved(generation, outcome) if generation == self.generation => {
                self.solving = false;
                match self.engine.as_mut() {
                    Some(engine) => {
                        let records = engine.apply_provisional(outcome);
                        let report = engine.provisional_report();
                        self.count(|counts| counts.provisional.add(&report));
                        (records, 0)
                    }
                    None => (Vec::new(), 0),
                }
            }
            // An engine since dropped: what it sealed or solved is not published, and counted.
            Finished::Sealed { .. } | Finished::Stepped(..) | Finished::Solved(..) => {
                self.count(|counts| counts.steps_discarded += 1);
                (Vec::new(), 0)
            }
        };
        self.publish(records);
        started
    }

    fn count(&self, change: impl FnOnce(&mut MlatReport)) {
        if let Ok(mut counts) = self.shared.counts.lock() {
            change(&mut counts);
        }
    }

    /// Starts whatever work is due by `now_ms`. The work started.
    fn tick(&mut self, now_ms: u64) -> usize {
        let generation = self.generation;
        if self.engine.is_none() {
            return 0;
        }
        self.hear_through(now_ms);
        let mut started = 0;
        if let Some(engine) = self.engine.as_mut()
            && !self.solving
            && let Some(job) = engine.provisional(now_ms, now_ms)
        {
            self.solving = true;
            started += 1;
            let finished = self.finished.clone();
            spawn_or_run(Urgency::Prompt, move || {
                let _ = finished.send(Finished::Solved(generation, job.run()));
            });
        }
        if !self.stepping && now_ms >= self.next_step_ms {
            self.next_step_ms = now_ms.saturating_add(STEP_MS);
            self.stepping = true;
            started += self.close(now_ms);
        }
        started
    }

    /// Weighs what batches stamped by `now_ms` said to provisional solving, in stamp order.
    fn hear_through(&mut self, now_ms: u64) {
        let later = self.heard.split_off(&(now_ms.saturating_add(1), 0, 0));
        let due = std::mem::replace(&mut self.heard, later);
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        for (at, (batch, notes, generation)) in due {
            if generation == self.generation {
                engine.hear(&batch, &notes, batch.stamp_ms());
            } else if generation > self.generation {
                // Read by a shard already re-scoped for the engine about to start: kept for it.
                self.heard.insert(at, (batch, notes, generation));
            }
        }
    }

    /// Takes every bin complete by `now_ms` out of every shard (a move under each shard's lock in
    /// turn), with the sites taking part and what the shards refused, and seals them off this
    /// thread. The work started.
    fn close(&mut self, now_ms: u64) -> usize {
        let Some(engine) = self.engine.as_ref() else {
            self.stepping = false;
            return 0;
        };
        let settled = engine.settled(now_ms);
        let threads = self.settings.threads.max(1);
        let mut fragments: Vec<Fragment> = Vec::new();
        let mut sites: Vec<Site> = Vec::new();
        let mut dropped = Dropped::default();
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
        }
        sites.sort_unstable_by_key(|site| site.receiver);
        let generation = self.generation;
        if fragments.is_empty() {
            return self.step(now_ms, settled, sites, dropped);
        }
        let finished = self.finished.clone();
        spawn_or_run(Urgency::Background, move || {
            let bins = tally_mlat::engine::seal(fragments, threads);
            let _ = finished.send(Finished::Sealed {
                generation,
                now_ms,
                settled,
                bins,
                sites,
                dropped,
            });
        });
        1
    }

    /// The window step of `now_ms`, every bin through `settled` sealed: run off this thread when
    /// there is a window to solve. The work started.
    fn step(&mut self, now_ms: u64, settled: i64, sites: Vec<Site>, dropped: Dropped) -> usize {
        let generation = self.generation;
        let Some(engine) = self.engine.as_mut() else {
            self.stepping = false;
            return 0;
        };
        engine.add_dropped(dropped);
        let Some(job) = engine.prepare_sealed(now_ms, now_ms, settled, sites) else {
            self.stepping = false;
            return 0;
        };
        let finished = self.finished.clone();
        spawn_or_run(Urgency::Background, move || {
            let _ = finished.send(Finished::Stepped(generation, job.run()));
        });
        1
    }

    /// The areas `set_areas` named (every shard already re-scoped to them, under `generation`):
    /// none drops the engine and its raw; the first after none starts a new engine under a new
    /// boot id; otherwise the engine's scope changes in place.
    fn rescope(&mut self, generation: u64, areas: Vec<Region>) {
        if areas.is_empty() {
            // No longer an MLAT relay for anything: the engine and its raw go, and whatever it
            // is still sealing or solving is discarded when it reports.
            self.engine = None;
            self.shared.sealed.clear();
            self.heard.clear();
            self.generation = generation;
            self.stepping = false;
            self.solving = false;
            return;
        }
        let band = area::border_band(&areas);
        match self.engine.as_mut() {
            Some(engine) if generation == self.generation => {
                engine.set_scope(band, areas);
            }
            _ => {
                self.shared.sealed.clear();
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
                self.heard.retain(|_, (_, _, heard)| *heard == generation);
                self.next_step_ms = 0;
                self.stepping = false;
                self.solving = false;
            }
        }
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
            published.extend(
                early
                    .into_iter()
                    .chain(host.take_signed())
                    .map(|r| (now, r)),
            );
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
