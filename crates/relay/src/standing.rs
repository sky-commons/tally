//! Receiver standing at this relay (RFC-0174 §2.12): a [`Book`] of it, kept by the rule
//! `tally_mlat_solver::standing` states (the same for every relay and client), from the public
//! signed records the relay forwards: fixes ([`Standing::positions`]), under the clock models the
//! relay's one store holds (`models::Models`). A relay that reads the same records as a client
//! holds the same standing as it.
//!
//! It holds no raw of its own: it reads the hosted MLAT engine's arrived raw ([`Standing::read_raw`],
//! one store of raw per relay, RFC-0181 §5, through [`Raw`]), so a reception the engine does not
//! hold is missing for both alike. The engine holds raw for `arrived::HELD_MS` (32.5 s) after it
//! arrived, and a transmission is settled `standing::SETTLE` (`budget::FIX_ARRIVED`, 32.5 s) after
//! it was sent, so every reception of it that arrived is still held when it is settled. It is
//! scoped to the areas this relay holds raw for (the hosted MLAT's areas and their border band,
//! [`Standing::set_areas`]): a relay cannot hold the world's raw, and relays are regional. A
//! receiver outside them, or any receiver of a relay that hosts no MLAT, has no standing here, not
//! a bad one: it is unknown ([`Standing::of`] says `None`).
//!
//! It holds no model either. Positions are taken as the hub sends them (`Hub::send_positions`),
//! once every model they cite went out before them and is in the relay's store, or they waited
//! their longest (`hub::AWAITING_MS`): a fix whose model is not held then is dropped and counted
//! (`StandingReport::unmodelled`), never waited for again here.
//!
//! It weighs which of a transmission's fixes stands (`Book::settle`, by `decide`) and which
//! receivers have standing (`credit` corroborates them). A fix that considered more than a
//! consistent one and disagrees with it supersedes it only when verified against the raw and of
//! more standing (`Candidate::verified`, RFC-0171 §3.8.1 as amended 2026-10-24, decision D6).
//! The book asks the hosted engine's verifier over its raw (`Raw::verify`), at most
//! [`VERIFIES_PER_ENGINE_PER_SEC`] of each publishing engine's fixes a second (decision D6), so an
//! engine that publishes disagreeing supersets in a flood costs the relay a bounded share of its
//! verifying, never all of it; one past the cap is not judged, counted, and stays contested, as it
//! does for a client. Gating a receiver out of the solver
//! (`ReceiverStanding::gated`) is not wired: the verifier refuses a fix that omits a considered
//! reception that fits (`Failure::Omitted`), so a relay that gated alone would publish fixes every
//! client refutes. It needs the gate in the specification, on both sides.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;
use tally_wire::clocks::Judged;

use tally_mlat::area::Band;
use tally_mlat_solver::ObservationId;
use tally_mlat_solver::gate::{self, Gate, Urgency};
use tally_mlat_solver::standing::{Book, ReceiverStanding, Solved};
use tally_wire::{Positions, PublicKey, Region, Regions};

use crate::budget::{Charge, Gauge};
use crate::models::{Cited, Models};

/// The work of settling under one hold of the book (`Book::settle_up_to`: each transmission's
/// receptions weighed under each of its fixes, and once more), at least one transmission: what
/// anyone asking of the book (`Standing::agreeing`, the positions the hub hands it) waits behind
/// at most, however many transmissions fall due at once. Some five hundred transmissions of an
/// area's three engines' fixes over four receptions each.
pub const SETTLE_PIECE: usize = 8_192;

// What an honest load can make standing hold at most, for each MLAT seat (RFC-0181, "Sizing",
// "What MLAT's tables hold"). The book is one pool for the relay, as the arrived pool is: it is
// planned at the kept rate the load test measured (`arrived::Rates::MEASURED`), and every engine is still held to
// its own share of it (`BookCaps::source_share`), so a receiver at its ceiling for a while takes
// the room of others below the mean and never another engine's.
//
// A transmission is solved by the relays of the area most of its hearers are in
// (`tally_mlat::area::owner`, `MLAT_RELAYS_PER_AREA` of them), each publishing its fix of each
// transmission (its complete fix once its raw has come takes its own's place, `Book::add`), under the
// models of the areas its used hearers are in. Only one transmission an aircraft a slot is solved
// (`tally_mlat_solver::backoff`), so the book is planned at the fixes published and the receptions
// they considered for each seat (`backoff::Published::MEASURED`, at world density, the dearest a
// seat), never at every kept reception (standing takes only the fixes that cite a model of one of
// its areas and none of an area outside their band, so whose receivers' raw it holds:
// `Standing::set_areas`). The relays of an area hold the same band's raw and seat the same
// receivers (RFC-0174 §2.3); a peer seating receivers this relay does not would bring more, and is
// not planned.

/// The fewest receptions a fix cites (`solve::MIN_RECEIVERS_WITH_ALTITUDE`).
pub const CITED_LEAST: usize = tally_mlat_solver::solve::MIN_RECEIVERS_WITH_ALTITUDE;
/// What a seat's engines solve and publish, a thousand seconds of the seat's at a time
/// (`backoff::Published::MEASURED`): what every table sized by the fixes is planned at.
pub const PUBLISHED: tally_mlat_solver::backoff::Published =
    tally_mlat_solver::backoff::Published::MEASURED;
/// The fixes an engine publishes of one transmission, at most: its fast fix when the transmission
/// is first chosen, and its complete one once its raw has come or its set closes, if it grew
/// (`tally_mlat::fix::again`, held by
/// `a_transmission_is_solved_twice_at_most`: no reception is considered by more than two; the
/// engine's seed 31 runs publish 1.5 to 1.7 a transmission, 2026-10-26). The book holds one fix of
/// each engine of a transmission (`standing::Book::add`), so the second costs it no room; it costs
/// what carries and decodes it (`consistency::POSITIONS_BYTES_PER_SEAT_PER_SEC`) and what its
/// engine remembers it solved (`mlat_host::SOLVED_BYTES_PER_SEAT`). Before, five superseded fixes
/// were planned for every one that stood, from before one transmission a slot was solved.
pub const FIXES_PER_TRANSMISSION: usize = 2;
/// The engines that solve a transmission: the relays of the area most of its hearers are in.
pub const ENGINES_PER_TRANSMISSION: usize = tally_wire::rendezvous::MLAT_RELAYS_PER_AREA;

/// How long the book holds a transmission: until it is settled (`standing::SETTLE`,
/// `budget::FIX_ARRIVED`: every reader's fix of it has arrived), and the second a fix may come
/// before its transmission's own time is past. Before, the windowed finals' 110 s.
pub const PENDING_SECONDS: usize = tally_mlat_solver::standing::SETTLE
    .span::<Judged>()
    .ms()
    .div_ceil(1_000) as usize
    + 1;
/// The seconds of settled receptions the book remembers: the slack past their due time
/// (`standing::SETTLED_SLACK_MS`), and the bin that goes whole (`standing::SETTLED_BIN_MS`).
pub const SETTLED_SECONDS: usize = (tally_mlat_solver::standing::SETTLED_SLACK_MS
    + tally_mlat_solver::standing::SETTLED_BIN_MS)
    .div_ceil(1_000) as usize;

/// What one distinct reception adds to a transmission held (`standing::transmission_bytes_most`):
/// its entry and its entry of the index.
pub const RECEPTION_HELD_BYTES: usize =
    tally_mlat_solver::standing::transmission_bytes_most::<Cited>(0, 1)
        - tally_mlat_solver::standing::transmission_bytes_most::<Cited>(0, 0);
/// What one engine's fix of a transmission takes held beside its receptions, as though it alone
/// solved it: the transmission's entries and its fix.
pub const ENGINE_HELD_BYTES: usize =
    tally_mlat_solver::standing::transmission_bytes_most::<Cited>(1, 0);

/// A seat's part of an engine's share of the book: its fix of every transmission held over
/// [`PENDING_SECONDS`], and every reception they considered, as though it alone solved them (each
/// transmission's bytes are shared among the engines that solved it, `Book::add`), so an honest
/// engine fits its share however many of its area's engines solve, and one that floods takes no
/// other's.
pub const SHARE_BYTES_PER_SEAT: usize = (PENDING_SECONDS
    * (PUBLISHED.published_per_ks * ENGINE_HELD_BYTES
        + PUBLISHED.considered_per_ks * RECEPTION_HELD_BYTES))
    .div_ceil(1_000);
/// The settled receptions a seat's fixes leave the book remembering: each reception considered,
/// over its slack past its due time ([`SETTLED_SECONDS`]).
pub const SETTLED_PER_SEAT: usize = (PUBLISHED.considered_per_ks * SETTLED_SECONDS).div_ceil(1_000);

/// What the one positions record standing reads at a time takes decoded (`Positions::fixes`),
/// while its fixes are taken in: some multiples of the largest record body
/// (`tally_wire::record::MAX_BODY`), held by the counting test (`tests/tables_bytes.rs`): each fix
/// decoded holds both its sets (what it considered and what it used), each reception decoded
/// (its receiver's key, epoch and counter) four times its twelve bytes on the wire, so a record of
/// fixes of many receptions decodes to a little over four times its bytes. Standing reads one
/// record at a time (`Standing::positions`, under its own lock).
pub const DECODED_BYTES: usize = 5 * tally_wire::record::MAX_BODY;

/// How many of one publishing engine's fixes the book has verified against the raw in a second of
/// the judging clock, at most (decision D6): a verify rebuilds the fix's model from the raw it
/// cites (`Engine::verify`, each model's check over the raw), about a refit's work, so one a
/// second an engine
/// keeps an engine that floods disagreeing supersets to one refit's work a second of this relay's.
pub const VERIFIES_PER_ENGINE_PER_SEC: u32 = 1;

/// The hosted engine's raw as standing reads it (`MlatHost::raw`): what its book needs of the
/// receptions it weighs, and the verifier over them.
pub trait Raw: Send + Sync {
    /// The signed wall clock of the batch that carried reception `id` of a transmission sent at
    /// `transmitted_ms` (Unix milliseconds), when the engine holds it in its receiver's own signed
    /// raw (the earliest of copies); `None` when it does not.
    fn heard(&self, id: &ObservationId, transmitted_ms: u64) -> Option<u64>;
    /// Whether what a fix states verifies under `models` (the ones it cites) against the raw held
    /// (`Engine::verify`: each model's check, then the fix's): `None` when the raw does not hold
    /// every reception it considered, or a model's.
    fn verify(
        &self,
        models: &[Arc<tally_mlat::fix::Held>],
        stated: &tally_mlat_solver::Stated<'_>,
    ) -> Option<bool>;
}

/// What standing holds at most, every table sized from the MLAT seats (`Caps::of`): what its
/// store is charged whole (`budget::Store::Standing`, [`Caps::planned_bytes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub book: tally_mlat_solver::standing::BookCaps,
}

impl Caps {
    /// Every table for `seats` seats: each seat's share of what an honest load brings.
    pub const fn of(seats: usize) -> Self {
        let share = seats * SHARE_BYTES_PER_SEAT;
        Self {
            book: tally_mlat_solver::standing::BookCaps {
                pending_bytes: ENGINES_PER_TRANSMISSION * share,
                source_share: share,
                // Every receiver a held fix cites is a seat's (above).
                receivers: seats,
                settled: seats * SETTLED_PER_SEAT,
            },
        }
    }

    /// What standing allocates at most at these caps: the book (`BookCaps::planned_bytes`) and
    /// the one record decoded in hand.
    pub const fn planned_bytes(&self) -> usize {
        self.book.planned_bytes::<Cited>() + DECODED_BYTES
    }
}

/// What one seat costs standing's store beside [`FIXED_BYTES`] (`budget::PerFeeder::standing`):
/// every table is linear in the seats ([`Caps::of`]), so this is exact.
pub const BYTES_PER_SEAT: usize = planned_bytes(1) - planned_bytes(0);
/// What standing's store holds whatever the seats, where MLAT is hosted: the book's roots and the
/// one record decoded in hand.
pub const FIXED_BYTES: usize = planned_bytes(0);

/// What standing allocates at most for `seats` seats ([`Caps::planned_bytes`]).
pub const fn planned_bytes(seats: usize) -> usize {
    Caps::of(seats).planned_bytes()
}

struct Inner {
    /// The hosted engine's raw. None, nothing is known.
    raw: Option<Arc<dyn Raw>>,
    book: Book<Cited>,
    /// The areas this relay holds raw for, with their border band.
    scope: Option<Band>,
    /// What the book's verifier was asked this second, by engine ([`VERIFIES_PER_ENGINE_PER_SEC`]).
    verifying: Verifying,
}

/// The verifies of the second now, by the engine whose fix was asked: forgotten as the second
/// passes, so it holds at most the engines of the book's fixes.
#[derive(Default)]
struct Verifying {
    second: u64,
    by_engine: std::collections::BTreeMap<PublicKey, u32>,
    /// Judged against the raw, and refused past their engine's cap, since the relay started.
    verified: u64,
    capped: u64,
}

impl Verifying {
    /// Whether one more of `engine`'s fixes may be verified at `now`, counting it if so.
    fn admit(&mut self, engine: &PublicKey, now: Judged) -> bool {
        let second = now.ms() / 1_000;
        if second != self.second {
            self.second = second;
            self.by_engine.clear();
        }
        let asked = self.by_engine.entry(*engine).or_default();
        if *asked >= VERIFIES_PER_ENGINE_PER_SEC {
            self.capped += 1;
            return false;
        }
        *asked += 1;
        self.verified += 1;
        true
    }
}

/// What standing counts of the fixes it was handed, since the relay started.
#[derive(Default)]
struct Counts {
    /// Taken into the book.
    taken: AtomicU64,
    /// Citing a model the relay's store did not hold when the hub sent them.
    unmodelled: AtomicU64,
    /// Citing no model of the areas, or one of an area outside their band.
    outside: AtomicU64,
    /// Not a fix under the models they cite (`standing::under`), or of another specification.
    unsolved: AtomicU64,
}

/// What standing's thread is asked to settle by: the latest judging clock asked, and the latest
/// settled through. Transmissions are settled by their signed transmit time.
#[derive(Default)]
struct Settling {
    settle: Option<Judged>,
    settled: Option<Judged>,
    /// Whether the thread holds a piece it has taken and not finished.
    working: bool,
}

/// Every receiver's standing as this relay reads the records it forwards.
///
/// A fix the hub hands here is taken into the book at once (`Book::add`, a decode and a compact
/// insert), so the hub waits at most one piece of settling. Settling costs the book's work for
/// every transmission (weighing it against the raw), so one thread of standing's own settles, in
/// pieces (`SETTLE_PIECE`), below the stages' priority and on the hosted MLAT's gate as
/// background work (`Standing::start`): standing is work the hosted MLAT brings, and runs on the
/// threads the plan gives MLAT, never beside them. Before, a hand-off held a window step's finals
/// for standing's thread (41 s of every engine's), because a window step published 40 s of fixes
/// at once; a step now publishes a second's. A relay that hosts no MLAT keeps no standing, so
/// takes nothing in.
pub struct Standing {
    inner: Mutex<Inner>,
    settling: Mutex<Settling>,
    wake: Condvar,
    /// Held while a record is read: one decoded at a time ([`DECODED_BYTES`]).
    reading: Mutex<()>,
    /// The relay's one store of decoded models (`Network::clock_models`).
    models: Arc<Models>,
    /// The areas this relay holds raw for: a fix is taken only when it cites a model of one of
    /// them and none of an area outside their band.
    areas: Mutex<Regions>,
    counts: Counts,
    /// The tables' caps now, and what they are charged to their store (`Standing::size_for`).
    /// Whether they must be charged: only where MLAT is hosted (some seats).
    caps: Mutex<(Caps, Charge, bool)>,
    /// Whether standing's thread runs (`Standing::start`): until it does, nothing is taken in.
    running: std::sync::atomic::AtomicBool,
}

impl Default for Standing {
    fn default() -> Self {
        Self::new()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Standing {
    /// Standing at its floors (`Caps::of(0)`) over a store of models of its own, charged to no
    /// store until it is sized (`Standing::size_for`).
    pub fn new() -> Self {
        Self::with_models(Arc::new(Models::new()))
    }

    /// Standing reading the relay's store of models.
    pub fn with_models(models: Arc<Models>) -> Self {
        let caps = Caps::of(0);
        Self {
            inner: Mutex::new(Inner {
                raw: None,
                book: Book::new(caps.book),
                scope: None,
                verifying: Verifying::default(),
            }),
            settling: Mutex::new(Settling::default()),
            wake: Condvar::new(),
            reading: Mutex::new(()),
            models,
            areas: Mutex::new(Regions::default()),
            counts: Counts::default(),
            caps: Mutex::new((caps, Charge::none(), false)),
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Sizes every table for `seats` MLAT seats (`Caps::of`) and charges what they hold at most
    /// to `gauge` whole (`budget::Store::Standing`), as the directory and the parts are: false,
    /// the tables left as they were and charged nothing, when the store refuses it (the relay's
    /// start then fails, `Network::fixed_charged`). What a smaller book holds stays held (it
    /// refuses what would add to it), its settled receptions and receivers past their caps
    /// forgotten at once.
    pub fn size_for(&self, seats: usize, gauge: &Arc<Gauge>) -> bool {
        if seats == 0 {
            // No MLAT hosted: standing's thread never starts, so nothing is ever taken in.
            let mut held = lock(&self.caps);
            held.1 = Charge::none();
            held.2 = false;
            return true;
        }
        self.size_to(Caps::of(seats), gauge)
    }

    /// As `size_for`, to `caps` (a test's, smaller than any seats').
    pub fn size_to(&self, caps: Caps, gauge: &Arc<Gauge>) -> bool {
        let mut held = lock(&self.caps);
        held.1 = Charge::none();
        held.2 = true;
        let mut charge = gauge.empty();
        // A first charge is admitted past an empty store's limit (`Gauge::take`), so the plan is
        // asked whether it fits first: tables charged whole either fit or the relay does not start.
        if !charge.fits(caps.planned_bytes()) || !charge.try_grow(caps.planned_bytes()) {
            return false;
        }
        self.inner().book.set_caps(caps.book);
        *held = (caps, charge, true);
        true
    }

    /// Whether what standing holds at most is charged to its store in full: what the relay's
    /// checks of its fixed charges ask (`Network::fixed_charged`).
    pub fn charged_in_full(&self) -> bool {
        let held = lock(&self.caps);
        !held.2 || held.1.bytes() >= held.0.planned_bytes()
    }

    /// What standing holds now and has done (`/memory`'s `standing`).
    pub fn report(&self) -> StandingReport {
        let planned = lock(&self.caps).0.planned_bytes();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let inner = self.inner();
        let book = inner.book.counts();
        StandingReport {
            planned_bytes: planned,
            taken: load(&self.counts.taken),
            unmodelled: load(&self.counts.unmodelled),
            outside: load(&self.counts.outside),
            unsolved: load(&self.counts.unsolved),
            pending_bytes: inner.book.pending_bytes(),
            receivers: inner.book.receivers().len(),
            interned: inner.book.interned(),
            settled_remembered: inner.book.settled_remembered(),
            transmissions_pending: inner.book.pending(),
            late: book.late,
            slots: book.slots,
            share: book.share,
            merged_out: book.merged_out,
            forgotten: book.room + book.receivers,
            verified: inner.verifying.verified,
            verify_capped: inner.verifying.capped,
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    fn settling(&self) -> MutexGuard<'_, Settling> {
        lock(&self.settling)
    }

    /// The hosted MLAT engine's raw: what standing reads (`MlatHost::raw`).
    pub fn read_raw(&self, raw: Arc<dyn Raw>) {
        self.inner().raw = Some(raw);
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

    /// One piece of settling, or a wait of a second for some, under `gate` if any.
    fn work_once(&self, gate: Option<&Arc<Gate>>) {
        let next = {
            let mut settling = self.settling();
            if settling.settled >= settling.settle {
                settling = self
                    .wake
                    .wait_timeout(settling, Duration::from_secs(1))
                    .map_or_else(|poisoned| poisoned.into_inner().0, |(held, _)| held);
            }
            match settling.settle {
                Some(settle) if settling.settled < Some(settle) => {
                    settling.working = true;
                    Some(settle)
                }
                _ => None,
            }
        };
        let Some(settle) = next else {
            return;
        };
        let work = || {
            let more = self.inner().settle_piece(settle);
            if !more {
                let mut settling = self.settling();
                settling.settled = settling.settled.max(Some(settle));
            }
        };
        match gate {
            Some(gate) => gate::enter(gate, Urgency::Background, work),
            None => work(),
        }
        self.settling().working = false;
    }

    /// Waits up to `within` until standing's thread has settled by the latest time asked; false
    /// if it had not by then. What a test or tool reads after handing records, as the thread
    /// would have left them.
    pub fn wait_idle(&self, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        loop {
            {
                let settling = self.settling();
                if !settling.working && settling.settled >= settling.settle {
                    return true;
                }
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// The areas this relay holds raw for (its hosted MLAT's): standing is kept for receivers in
    /// them and their border band, and for no other.
    pub fn set_areas(&self, areas: &Regions) {
        self.inner().scope = (!areas.is_empty()).then(|| Band::of(areas));
        *lock(&self.areas) = areas.clone();
    }

    /// Raw fixes the hub sent (format 7, verified; `Hub::send_positions`): each fix under models
    /// the relay's store holds (`Models::cited`), one of them of the areas and none of an area
    /// outside their band, and a fix under them (`Solved::new`), taken into the book at once to
    /// join its transmission until it is settled (the book refuses what is past its room, counted
    /// there). A fix whose models are not all held is dropped and counted: the hub waited for them
    /// already.
    pub fn positions(&self, positions: &Positions, now: Judged) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }
        {
            let _reading = lock(&self.reading);
            let (Ok(content), Ok(engine)) = (positions.fixes(), positions.engine()) else {
                return;
            };
            let areas = lock(&self.areas).clone();
            let scope = self.inner().scope.clone();
            let mut taken = Vec::with_capacity(content.fixes.len());
            for fix in &content.fixes {
                let cited = match self.models.cited(&fix.models, engine) {
                    Ok(cited) => cited,
                    Err(_) => {
                        self.counts.unmodelled.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                // Only a fix citing a model of this relay's areas and none of an area outside
                // their band: every receiver it cites is one whose raw this relay holds, and what
                // standing holds is a share of its seats (`Caps::of`).
                let placed = cited.as_ref().is_none_or(|cited| {
                    scope.as_ref().is_some_and(|band| {
                        cited.models().iter().all(|model| band.holds(model.area()))
                    }) && cited
                        .models()
                        .iter()
                        .any(|model| areas.contains(model.area()))
                });
                if !placed {
                    self.counts.outside.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Some(solved) = cited
                    .filter(|cited| {
                        cited
                            .models()
                            .iter()
                            .all(|model| model.spec() == content.spec_version)
                    })
                    .and_then(|cited| {
                        Solved::new(fix, content.spec_version, content.issued_ms, cited)
                    })
                else {
                    self.counts.unsolved.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                taken.push(solved);
            }
            let mut inner = self.inner();
            for solved in taken {
                // A fix the book refuses is counted there (`Settled`).
                if inner.book.add(solved).is_ok() {
                    self.counts.taken.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.tick(now);
    }

    /// Settles what is due by the judging clock `now`, on standing's thread.
    pub fn tick(&self, now: Judged) {
        let mut settling = self.settling();
        if Some(now) > settling.settle {
            settling.settle = Some(now);
            drop(settling);
            self.wake.notify_one();
        }
    }

    /// Settles by the latest time asked, here, ungated: what a test reads after handing records,
    /// as standing's thread would have left it.
    #[cfg(test)]
    pub fn drain(&self) {
        let settle = self.settling().settle;
        if let Some(settle) = settle {
            while self.inner().settle_piece(settle) {}
        }
    }

    /// A receiver's standing now, for a receiver declared at `cell`: a new key's, none; one
    /// outside the areas this relay holds raw for, unknown (`None`).
    pub fn of(&self, receiver: &PublicKey, cell: Option<Region>) -> Option<ReceiverStanding> {
        let inner = self.inner();
        inner.raw.as_ref()?;
        let band = inner.scope.as_ref()?;
        cell.filter(|cell| band.holds(*cell))?;
        Some(inner.book.of(receiver))
    }

    /// The receivers with standing now (their receptions kept agreeing with verified fixes):
    /// corroborated first-hand, which is what `credit` counts a feeder's description by.
    pub fn agreeing(&self, now: Judged) -> Vec<PublicKey> {
        let now_ms = now.ms();
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

/// What standing holds now and has done, for `/memory` (`Standing::report`): what the load
/// harness asserts ran, and what its store holds against its plan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct StandingReport {
    pub planned_bytes: usize,
    /// Fixes taken into the book; citing a model the store did not hold; citing no model of the
    /// areas, or one outside their band; not a fix under their models.
    pub taken: u64,
    pub unmodelled: u64,
    pub outside: u64,
    pub unsolved: u64,
    pub pending_bytes: usize,
    pub receivers: usize,
    /// The receivers the transmissions held cite.
    pub interned: usize,
    pub settled_remembered: usize,
    /// The transmissions the book holds now, and fixes it refused as late, past a transmission's
    /// slots, past their engine's share, or let go as two transmissions joined.
    pub transmissions_pending: usize,
    pub late: u64,
    pub slots: u64,
    pub share: u64,
    pub merged_out: u64,
    /// The fixes refused for room (the book's, its receivers'): none while the plan holds what the
    /// relay is sent. Nothing held is ever forgotten for room.
    pub forgotten: u64,
    /// Fixes the book's verifier judged against the raw, and those it did not for their engine's
    /// cap ([`VERIFIES_PER_ENGINE_PER_SEC`]), since the relay started.
    pub verified: u64,
    pub verify_capped: u64,
}

impl Inner {
    /// Settles a piece of what is due by `now` (`SETTLE_PIECE`); true while any is left.
    fn settle_piece(&mut self, now: Judged) -> bool {
        let Some(raw) = self.raw.clone() else {
            return false;
        };
        let verifying = std::cell::RefCell::new(&mut self.verifying);
        self.book
            .settle_up_to(
                now,
                |id, transmitted_ms| raw.heard(id, transmitted_ms),
                |asked| {
                    if !verifying.borrow_mut().admit(asked.engine, now) {
                        return None;
                    }
                    raw.verify(&asked.model.decoded(), &asked.stated())
                },
                SETTLE_PIECE,
            )
            .1
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_wire::batch::Hash;
    use tally_wire::clocks::recorded::judged;
    use tally_wire::{EnuCovariance, Identity, TransmitTime};

    const AT_MS: u64 = 1_791_288_000_000;

    fn key(seed: u8) -> PublicKey {
        Identity::from_seed([seed; 32]).public()
    }

    /// Raw that holds nothing: every reception unheard, every fix unjudged.
    struct NoRaw;

    impl Raw for NoRaw {
        fn heard(&self, _: &ObservationId, _: u64) -> Option<u64> {
            None
        }

        fn verify(
            &self,
            _: &[Arc<tally_mlat::fix::Held>],
            _: &tally_mlat_solver::Stated<'_>,
        ) -> Option<bool> {
            None
        }
    }

    /// A model of nothing of the area at Atlanta, the hosted engine's own, held in `models` for
    /// the test's day.
    fn held_model(models: &Models) -> Result<crate::models::Model, String> {
        let model = tally_mlat_solver::pair::PairModel {
            spec: tally_mlat_solver::SPEC_VERSION,
            area: tally_wire::rendezvous::area_at(33.749, -84.388)
                .map_err(|error| error.to_string())?,
            // Its edge the test's day, so it is neither stale nor early there (`models::HOLD_MS`).
            trailing: tally_mlat_solver::Trailing::at(AT_MS),
            scope: Vec::new(),
            frontier: Vec::new(),
            input: tally_mlat_solver::Citation {
                hash: [7; 32],
                count: 3,
            },
            kappa: 1.0,
            clocks: Vec::new(),
            pairs: Vec::new(),
        };
        let held = tally_mlat::fix::Held::fitted(model).ok_or("a model of nothing encodes")?;
        models
            .insert_own(Arc::new(held), key(100), judged(AT_MS))
            .map_err(|why| format!("{why:?}"))
    }

    /// `model` cited alone by a fix engine `engine` signed.
    fn cited(model: &crate::models::Model, engine: u8) -> Cited {
        Cited::new(vec![model.clone()], key(engine))
            .unwrap_or_else(|| panic!("one model is one fix's"))
    }

    /// A fix of transmission `n` heard by three receivers, under `model`.
    fn solved(n: u8, model: &crate::models::Model) -> Solved<Cited> {
        let observations = tally_wire::ObservationSet::new(
            vec![0x58, 0xab, 0xcd, n, 0, 0, 0],
            (0..3)
                .map(|at| tally_wire::Reception {
                    receiver: key(10 + at),
                    epoch: 1,
                    counter: u64::from(n) * 10 + u64::from(at),
                })
                .collect(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        Solved {
            issued_ms: AT_MS + 1_000,
            claimed: tally_mlat_solver::standing::Claimed {
                lat_e7: 337_000_000,
                lon_e7: -844_000_000,
                alt_hae_mm: Some(10_000_000),
                covariance: EnuCovariance {
                    xx: 900.0,
                    xy: 0.0,
                    xz: 0.0,
                    yy: 900.0,
                    yz: 0.0,
                    zz: 2_500.0,
                },
                transmitted: TransmitTime {
                    unix_ms: AT_MS + u64::from(n),
                    sub_ms_ps: 0,
                },
            },
            weight: 3,
            identity: [n; 32],
            considered: observations.clone(),
            used: observations,
            model: cited(model, 5),
        }
    }

    /// Positions citing a model the relay's store does not hold when the hub sends them are
    /// dropped and counted: nothing waits for a model here.
    #[test]
    fn a_fix_whose_model_is_not_held_is_dropped_and_counted() -> Result<(), String> {
        let models = Arc::new(Models::new());
        let model = held_model(&models)?;
        let standing = Arc::new(Standing::with_models(models));
        let gauge = crate::budget::Gauge::new(crate::budget::Store::Standing, usize::MAX);
        assert!(standing.size_for(1, &gauge));
        Standing::start(&standing, None)?;
        let fix = |model_id: Hash| -> Result<tally_wire::Fix, String> {
            let solved = solved(1, &model);
            Ok(tally_wire::Fix {
                address: 0x00ab_cdef,
                transmitted: solved.claimed.transmitted,
                lat_e7: solved.claimed.lat_e7,
                lon_e7: solved.claimed.lon_e7,
                alt_hae_mm: solved.claimed.alt_hae_mm,
                covariance: solved.claimed.covariance,
                models: vec![model_id],
                sets: tally_wire::FixSets::new(solved.considered, solved.used)
                    .map_err(|error| error.to_string())?,
            })
        };
        let positions = Positions::sign_fix(
            &Identity::from_seed([5; 32]),
            &tally_wire::FixesContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: AT_MS,
                spec_version: tally_mlat_solver::SPEC_VERSION,
                fixes: vec![fix([1; 32])?, fix(model.id())?],
            },
        )
        .map_err(|error| error.to_string())?;
        standing.positions(&positions, judged(AT_MS));
        let report = standing.report();
        assert_eq!(report.unmodelled, 1);
        // The held one is of an area none of the (no) areas is.
        assert_eq!(report.outside, 1);
        Ok(())
    }

    /// A burst of transmissions falling due at once is settled in pieces held to their work
    /// (`SETTLE_PIECE`): between two pieces the book is free, so the fixes the hub hands meanwhile
    /// are taken in and anyone asking is answered, however large the burst. Before, a piece was a
    /// count of transmissions, whatever each cost.
    #[test]
    fn a_burst_falling_due_at_once_is_settled_in_pieces_held_to_their_work() -> Result<(), String> {
        let models = Arc::new(Models::new());
        let model = held_model(&models)?;
        let standing = Standing::with_models(models);
        let gauge = crate::budget::Gauge::new(crate::budget::Store::Standing, usize::MAX);
        assert!(standing.size_for(100, &gauge));
        standing.read_raw(Arc::new(NoRaw));
        let burst = 2_000usize;
        {
            let mut inner = standing.inner();
            for n in 0..burst {
                let mut one = solved((n % 250) as u8, &model);
                // Each its own transmission: its own receivers' counters.
                let receptions: Vec<tally_wire::Reception> = one
                    .considered
                    .receptions()
                    .iter()
                    .map(|reception| tally_wire::Reception {
                        counter: n as u64 * 10 + reception.counter % 10,
                        ..*reception
                    })
                    .collect();
                one.considered =
                    tally_wire::ObservationSet::new(one.considered.message().to_vec(), receptions)
                        .map_err(|error| error.to_string())?;
                one.used = one.considered.clone();
                inner.book.add(one).map_err(|why| format!("{why:?}"))?;
            }
            assert_eq!(inner.book.pending(), burst);
        }
        // Every one is due; a piece settles what its work allows (three receptions under one
        // fix, and once more, each), and the book is free after it.
        let due = judged(AT_MS + 600_000);
        let work = 3 * 2 + 1;
        let mut pieces = 0;
        loop {
            let before = standing.inner().book.pending();
            let more = standing.inner().settle_piece(due);
            let after = standing.inner().book.pending();
            assert!(before - after <= SETTLE_PIECE / work, "{before} to {after}");
            pieces += 1;
            if !more {
                break;
            }
        }
        assert!(pieces >= burst * work / SETTLE_PIECE, "{pieces} pieces");
        assert_eq!(standing.inner().book.pending(), 0);
        Ok(())
    }

    /// The book holds a transmission until every reader's fix of it has arrived and no longer:
    /// `FIX_ARRIVED` and the second a fix may come before its own time is past, not the windowed
    /// finals' 110 s; and the raw is still held when it is settled.
    #[test]
    fn a_transmission_is_held_until_its_fixes_have_arrived() {
        assert_eq!(
            PENDING_SECONDS as u64,
            tally_wire::budget::FIX_ARRIVED_MS.div_ceil(1_000) + 1
        );
        assert!(
            tally_mlat_solver::HELD_MS >= tally_mlat_solver::standing::SETTLE.span::<Judged>().ms(),
            "the raw outlives the settling"
        );
    }

    /// Standing's tables are sized from the seats and charged whole to their store; a store that
    /// cannot hold them is charged nothing and the relay does not start; a relay hosting no MLAT
    /// (no seat) keeps none to charge. The figures are linear in the seats as the budget plans
    /// them (`FIXED_BYTES`, `BYTES_PER_SEAT`), exactly.
    #[test]
    fn standing_is_sized_from_the_seats_and_charged_whole() {
        for seats in [0, 1, 7, 100, 2_000, 20_000] {
            assert_eq!(
                planned_bytes(seats),
                FIXED_BYTES + seats * BYTES_PER_SEAT,
                "{seats} seats"
            );
        }
        let standing = Standing::new();
        let gauge = crate::budget::Gauge::new(crate::budget::Store::Standing, usize::MAX);
        assert!(standing.size_for(0, &gauge));
        assert_eq!(gauge.held(), 0);
        assert!(standing.charged_in_full());
        assert!(standing.size_for(100, &gauge));
        assert_eq!(gauge.held(), planned_bytes(100));
        assert!(standing.charged_in_full());
        let short =
            crate::budget::Gauge::new(crate::budget::Store::Standing, planned_bytes(100) - 1);
        assert!(!standing.size_for(100, &short));
        assert_eq!(gauge.held(), 0, "what it held is given back");
        assert!(!standing.charged_in_full());
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
        standing.read_raw(Arc::new(NoRaw));
        assert_eq!(standing.of(&key, atlanta), Some(ReceiverStanding::NEW));
        standing.tick(judged(u64::MAX / 2));
        standing.drain();
        assert_eq!(standing.of(&key, atlanta), Some(ReceiverStanding::NEW));
        // Outside the areas held: unknown.
        assert_eq!(standing.of(&key, None), None);
    }
}
