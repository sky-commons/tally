//! Receiver standing at this relay (RFC-0174 §2.12): a [`Book`] of it, kept by the rule
//! `tally_mlat_solver::standing` states (the same for every relay and client), from the public
//! signed records the relay forwards: receivers' batches ([`Standing::batch`]), clock models
//! ([`Standing::model`]) and final and provisional positions ([`Standing::positions`]). A relay
//! that reads the same records as a client holds the same standing as it.
//!
//! It holds no raw of its own: it reads the hosted MLAT engine's sealed bins
//! ([`Standing::read_bins`], one store of raw per relay, RFC-0181 §5), so raw later than the
//! engine's settling is missing for both alike. It is scoped to the areas this relay holds raw for
//! (the hosted MLAT's areas and their border band, [`Standing::set_areas`]): a relay cannot hold
//! the world's raw, and relays are regional. A receiver outside them, or any receiver of a relay
//! that hosts no MLAT, has no standing here, not a bad one: it is unknown ([`Standing::of`] says
//! `None`).
//!
//! It weighs which of a transmission's solutions stands (`Book::settle`, by `decide`) and which
//! receivers have standing (`credit` corroborates them). Gating a receiver out of the solver
//! (`ReceiverStanding::gated`) is not wired: the verifier refuses a solution that omits a
//! reception that fits (`Failure::Omitted`), so a relay that gated alone would publish solutions
//! every client refutes. It needs the gate in the specification, on both sides.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tally_mlat::area::Band;
use tally_mlat_solver::ClockModel as Model;
use tally_mlat_solver::gate::{self, Gate, Urgency};
use tally_mlat_solver::held::SealedBins;
use tally_mlat_solver::publish;
use tally_mlat_solver::standing::{Book, ReceiverStanding, Solved, heard_in};
use tally_wire::batch::Hash;
use tally_wire::clock_model::Assembler;
use tally_wire::{ClockModel, Positions, PublicKey, Record, Region, Regions, Solution};

use crate::bounded::Bounded;

/// Models held, the most recently cited kept.
pub const MAX_MODELS: usize = 16_384;
/// Bytes of clock model parts waiting for their manifest.
pub const MAX_MODEL_BYTES: usize = 64 << 20;
/// Models solutions wait for, and solutions each.
pub const MAX_WAITING: usize = 1_024;
pub const WAITING_PER_MODEL: usize = 4_096;
/// Transmissions waiting to be settled.
pub const MAX_TRANSMISSIONS: usize = 262_144;
/// Receivers whose standing is kept.
pub const MAX_RECEIVERS: usize = 65_536;
/// Bytes of records handed to standing and not yet taken in by its thread (`Standing::positions`,
/// `Standing::model`): more is refused, counted (`Standing::refused`). A window step's positions
/// and models together are some 45 MB at 2,000 feeders, taken in well before the next.
pub const MAX_INTAKE_BYTES: usize = 64 << 20;
/// Transmissions settled under one hold of the book (`Book::settle_up_to`): what anyone asking of
/// the book (`Standing::agreeing`) waits behind at most.
pub const SETTLE_PIECE: usize = 512;

struct HeldModel {
    spec: u16,
    inputs: Hash,
    model: Arc<Model>,
}

type Waiting = Vec<(u16, u64, bool, Solution)>;

struct Inner {
    assembler: Assembler,
    models: Bounded<Hash, HeldModel>,
    waiting: Bounded<Hash, Waiting>,
    /// The hosted engine's sealed bins: when a reception was heard. None, nothing is known.
    sealed: Option<SealedBins>,
    book: Book,
    /// The areas this relay holds raw for, with their border band.
    scope: Option<Band>,
}

/// A record handed to standing, waiting for its thread.
enum Handed {
    Model(Record),
    Positions(Positions),
}

/// What waits for standing's thread: records in the order handed, their bytes, the latest time
/// asked to settle by, and what was refused for room.
#[derive(Default)]
struct Intake {
    records: VecDeque<(Handed, usize)>,
    bytes: usize,
    settle_ms: u64,
    settled_ms: u64,
    /// Whether the thread holds a record or a piece it has taken and not finished.
    working: bool,
}

/// Every receiver's standing as this relay reads the records it forwards.
///
/// A stage of its own. Taking a record in and settling cost the book's work for every
/// solution (decoding each record, weighing each transmission against the sealed raw): some ten
/// seconds of a core for one window step's solutions at 2,000 feeders. Done where a record was
/// published, that was the timed duties' thread, then on the async runtime: the duties stood still
/// and so did every runtime task they had woken. So a record handed here is queued and returns at
/// once (bounded in bytes, `MAX_INTAKE_BYTES`, the rest refused and counted), and one thread of
/// standing's own takes the records in, in the order handed, and settles, in pieces
/// (`SETTLE_PIECE`), below the stages' priority and on the hosted MLAT's gate as background work
/// (`Standing::start`): standing is work the hosted MLAT brings, and runs on the threads the plan
/// gives MLAT, never beside them. A relay that hosts no MLAT keeps no standing, so takes nothing in.
pub struct Standing {
    inner: Mutex<Inner>,
    intake: Mutex<Intake>,
    handed: Condvar,
    refused: AtomicU64,
    /// Whether standing's thread runs (`Standing::start`): until it does, nothing is taken in.
    running: std::sync::atomic::AtomicBool,
}

impl Default for Standing {
    fn default() -> Self {
        Self::new()
    }
}

impl Standing {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                assembler: Assembler::new(MAX_MODEL_BYTES, MAX_WAITING),
                models: Bounded::new(MAX_MODELS),
                waiting: Bounded::new(MAX_WAITING),
                sealed: None,
                book: Book::new(MAX_TRANSMISSIONS, MAX_RECEIVERS),
                scope: None,
            }),
            intake: Mutex::new(Intake::default()),
            handed: Condvar::new(),
            refused: AtomicU64::new(0),
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn intake(&self) -> MutexGuard<'_, Intake> {
        self.intake
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The hosted MLAT engine's sealed bins: the raw standing reads (`MlatHost::sealed_bins`).
    pub fn read_bins(&self, sealed: SealedBins) {
        self.inner().sealed = Some(sealed);
    }

    /// Starts standing's thread, on `gate` (the hosted MLAT's, `MlatHost::gate`) as background
    /// work when there is one, below the stages' priority: from now on what is handed is taken in.
    /// It ends once standing is dropped.
    pub fn start(standing: &Arc<Self>, gate: Option<Arc<Gate>>) -> Result<(), String> {
        if standing.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let weak = Arc::downgrade(standing);
        std::thread::Builder::new()
            .name("tally-standing".to_owned())
            .spawn(move || {
                crate::mlat_host::run_as_background();
                while let Some(standing) = Weak::upgrade(&weak) {
                    standing.work_once(gate.as_ref());
                }
            })
            .map(|_| ())
            .map_err(|error| format!("the relay's standing did not start: {error}"))
    }

    /// One piece of standing's work, or a wait of a second for some: the oldest record handed,
    /// else a piece of settling, under `gate` if any.
    fn work_once(&self, gate: Option<&Arc<Gate>>) {
        let next = {
            let mut intake = self.intake();
            if intake.records.is_empty() && intake.settled_ms >= intake.settle_ms {
                intake = self
                    .handed
                    .wait_timeout(intake, Duration::from_secs(1))
                    .map_or_else(|poisoned| poisoned.into_inner().0, |(intake, _)| intake);
            }
            match intake.records.pop_front() {
                Some((record, bytes)) => {
                    intake.bytes -= bytes;
                    intake.working = true;
                    Some(Ok(record))
                }
                None if intake.settled_ms < intake.settle_ms => {
                    intake.working = true;
                    Some(Err(intake.settle_ms))
                }
                None => None,
            }
        };
        let busy = next.is_some();
        let work = || match next {
            Some(Ok(Handed::Model(record))) => self.inner().model(&record),
            Some(Ok(Handed::Positions(positions))) => self.inner().positions(&positions),
            Some(Err(settle_ms)) => {
                let more = self.inner().settle_piece(settle_ms);
                if !more {
                    let mut intake = self.intake();
                    intake.settled_ms = intake.settled_ms.max(settle_ms);
                }
            }
            None => {}
        };
        match gate {
            Some(gate) if busy => gate::enter(gate, Urgency::Background, work),
            _ => work(),
        }
        if busy {
            self.intake().working = false;
        }
    }

    /// Waits up to `within` until standing's thread has taken in everything handed and settled by
    /// the latest time asked; false if it had not by then. What a test or tool reads after handing
    /// records, as the thread would have left them.
    pub fn wait_idle(&self, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        loop {
            {
                let intake = self.intake();
                if intake.records.is_empty()
                    && !intake.working
                    && intake.settled_ms >= intake.settle_ms
                {
                    return true;
                }
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Hands `record` to standing's thread, or refuses it, counted, past `MAX_INTAKE_BYTES`.
    fn hand(&self, record: Handed, bytes: usize) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }
        let mut intake = self.intake();
        if intake.bytes + bytes > MAX_INTAKE_BYTES {
            drop(intake);
            self.refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        intake.bytes += bytes;
        intake.records.push_back((record, bytes));
        drop(intake);
        self.handed.notify_one();
    }

    /// Records handed and refused for want of room in the intake, since the relay started.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// The areas this relay holds raw for (its hosted MLAT's): standing is kept for receivers in
    /// them and their border band, and for no other.
    pub fn set_areas(&self, areas: &Regions) {
        self.inner().scope = (!areas.is_empty()).then(|| Band::of(areas));
    }

    /// A clock model manifest or part the relay forwarded: held once whole, read under the
    /// specification it names, and only when it is a function of what it says. Taken in by
    /// standing's thread (`Standing::start`), in the order handed.
    pub fn model(&self, record: &Record, now_ms: u64) {
        let bytes = match record {
            Record::ClockModel(manifest) => manifest.as_bytes().len(),
            Record::ClockModelPart(part) => part.as_bytes().len(),
            _ => return,
        };
        self.hand(Handed::Model(record.clone()), bytes);
        self.tick(now_ms);
    }

    /// Final or provisional positions the relay forwarded (verified): each solution under a held
    /// model, consistent with its own receptions, joins its transmission until it is settled.
    /// Taken in by standing's thread (`Standing::start`), in the order handed.
    pub fn positions(&self, positions: &Positions, now_ms: u64) {
        self.hand(
            Handed::Positions(positions.clone()),
            positions.as_bytes().len(),
        );
        self.tick(now_ms);
    }

    /// Settles what is due by `now_ms`, on standing's thread.
    pub fn tick(&self, now_ms: u64) {
        let mut intake = self.intake();
        if now_ms > intake.settle_ms {
            intake.settle_ms = now_ms;
            drop(intake);
            self.handed.notify_one();
        }
    }

    /// Takes in everything handed and settles by the latest time asked, here, ungated: what a test
    /// reads after handing records, as standing's thread would have left it.
    #[cfg(test)]
    pub fn drain(&self) {
        loop {
            let (next, settle_ms) = {
                let mut intake = self.intake();
                let next = intake.records.pop_front().map(|(record, bytes)| {
                    intake.bytes -= bytes;
                    record
                });
                (next, intake.settle_ms)
            };
            match next {
                Some(Handed::Model(record)) => self.inner().model(&record),
                Some(Handed::Positions(positions)) => self.inner().positions(&positions),
                None => {
                    while self.inner().settle_piece(settle_ms) {}
                    return;
                }
            }
        }
    }

    /// A receiver's standing now, for a receiver declared at `cell`: a new key's, none; one
    /// outside the areas this relay holds raw for, unknown (`None`).
    pub fn of(&self, receiver: &PublicKey, cell: Option<Region>) -> Option<ReceiverStanding> {
        let inner = self.inner();
        inner.sealed.as_ref()?;
        let band = inner.scope.as_ref()?;
        cell.filter(|cell| band.holds(*cell))?;
        Some(inner.book.of(receiver))
    }

    /// The receivers with standing now (their receptions kept agreeing with verified fixes):
    /// corroborated first-hand, which is what `credit` counts a feeder's description by.
    pub fn agreeing(&self, now_ms: u64) -> Vec<PublicKey> {
        let period = tally_mlat_solver::standing::period_of(now_ms);
        self.inner()
            .book
            .receivers()
            .iter()
            .filter(|(_, standing)| standing.has_standing(period))
            .map(|(key, _)| *key)
            .collect()
    }
}

impl Inner {
    fn hold(&mut self, manifest: &ClockModel, content: tally_wire::ClockModelContent) {
        let Ok(decoded) = publish::decode(&content.model, content.spec_version) else {
            return;
        };
        if publish::inputs_id(&decoded) != content.inputs {
            return;
        }
        let id = manifest.id();
        self.models.insert_active(
            id,
            HeldModel {
                spec: content.spec_version,
                inputs: content.inputs,
                model: Arc::new(decoded),
            },
        );
        if let Some(waiting) = self.waiting.remove(&id) {
            for (spec, issued_ms, provisional, solution) in waiting {
                self.solution(spec, issued_ms, provisional, solution);
            }
        }
    }

    fn solution(&mut self, spec: u16, issued_ms: u64, provisional: bool, solution: Solution) {
        let id = solution.clock_model;
        self.models.touch(&id);
        let Some(model) = self.models.get(&id) else {
            match self.waiting.get_mut(&id) {
                Some(waiting) if waiting.len() < WAITING_PER_MODEL => {
                    waiting.push((spec, issued_ms, provisional, solution));
                }
                Some(_) => {}
                None => {
                    self.waiting
                        .insert_active(id, vec![(spec, issued_ms, provisional, solution)]);
                }
            }
            return;
        };
        if model.spec != spec {
            return;
        }
        if let Some(solved) = Solved::new(
            &solution,
            spec,
            issued_ms,
            provisional,
            Arc::clone(&model.model),
            model.inputs,
        ) {
            self.book.add(solved);
        }
    }

    /// A clock model manifest or part: held once whole (`Standing::model`).
    fn model(&mut self, record: &Record) {
        let done = match record {
            Record::ClockModel(manifest) => {
                self.assembler.manifest(manifest.clone()).ok().flatten()
            }
            Record::ClockModelPart(part) => self.assembler.part(part.clone()),
            _ => None,
        };
        if let Some((manifest, content)) = done {
            self.hold(&manifest, content);
        }
    }

    /// Final or provisional positions: each solution in (`Standing::positions`).
    fn positions(&mut self, positions: &Positions) {
        let Ok(content) = positions.solutions() else {
            return;
        };
        let provisional = positions.is_provisional();
        for solution in content.solutions {
            self.solution(
                content.spec_version,
                content.issued_ms,
                provisional,
                solution,
            );
        }
    }

    /// Settles a piece of what is due by `now_ms` (`SETTLE_PIECE`); true while any is left.
    fn settle_piece(&mut self, now_ms: u64) -> bool {
        let Some(sealed) = &self.sealed else {
            return false;
        };
        self.book
            .settle_up_to(
                now_ms,
                |id, transmitted_ms| heard_in(sealed, id, transmitted_ms),
                SETTLE_PIECE,
            )
            .1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    /// What standing is handed returns at once, whatever its thread is doing with the book
    /// (here, the book held for the whole test), and is taken in by that thread; past its intake's
    /// bytes, refused and counted. Before, a record was taken in on the thread that handed it, under
    /// the book's lock: a window step's solutions held the relay's timed duties ten seconds.
    #[test]
    fn a_record_handed_returns_at_once_and_is_taken_in_on_standings_thread() -> Result<(), String> {
        let identity = Identity::from_seed([5; 32]);
        let positions = Positions::sign_solutions(
            &identity,
            &tally_wire::SolutionsContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 0,
                spec_version: tally_mlat_solver::SPEC_VERSION,
                solutions: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        let standing = Arc::new(Standing::new());
        // No thread yet (no hosted MLAT): nothing is kept, nothing refused.
        standing.positions(&positions, 0);
        assert!(standing.intake().records.is_empty());
        Standing::start(&standing, None)?;
        let held = standing.inner();
        let (done, finished) = std::sync::mpsc::channel();
        {
            let standing = Arc::clone(&standing);
            let positions = positions.clone();
            std::thread::spawn(move || {
                standing.positions(&positions, 1);
                let _ = done.send(());
            });
        }
        finished
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "handing a record waited for the book")?;
        drop(held);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !standing.intake().records.is_empty() {
            assert!(std::time::Instant::now() < deadline, "never taken in");
            std::thread::sleep(Duration::from_millis(5));
        }
        // Past its bytes, refused, counted.
        let many = MAX_INTAKE_BYTES / positions.as_bytes().len() + 2;
        let blocked = standing.inner();
        for _ in 0..many {
            standing.positions(&positions, 2);
        }
        assert!(standing.refused() > 0);
        drop(blocked);
        Ok(())
    }

    #[test]
    fn a_new_key_has_no_standing_and_records_it_cannot_read_change_nothing() {
        let standing = Standing::new();
        let key = Identity::from_seed([3; 32]).public();
        let atlanta = Region::point(&tally_wire::Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        })
        .ok();
        let area = atlanta.and_then(|cell| cell.ancestor(tally_wire::rendezvous::AREA_RESOLUTION));
        standing.set_areas(&area.into_iter().collect());
        // No hosted MLAT, no raw: unknown, even in the areas.
        assert_eq!(standing.of(&key, atlanta), None);
        standing.read_bins(SealedBins::new());
        assert_eq!(standing.of(&key, atlanta), Some(ReceiverStanding::NEW));
        standing.model(&Record::Heartbeat, 0);
        standing.tick(u64::MAX / 2);
        standing.drain();
        assert_eq!(standing.of(&key, atlanta), Some(ReceiverStanding::NEW));
        // Outside the areas held: unknown.
        assert_eq!(standing.of(&key, None), None);
    }
}
