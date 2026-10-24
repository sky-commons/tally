//! Receiver standing at this relay (RFC-0174 §2.12): a [`Book`] of it, kept by the rule
//! `tally_mlat_solver::standing` states (the same for every relay and client), from the public
//! signed records the relay forwards: final and provisional positions ([`Standing::positions`]),
//! under the clock models the relay's one store holds (`models::Models`). A relay that reads the
//! same records as a client holds the same standing as it.
//!
//! It holds no raw of its own: it reads the hosted MLAT engine's sealed bins
//! ([`Standing::read_bins`], one store of raw per relay, RFC-0181 §5), so raw later than the
//! engine's settling is missing for both alike. It is scoped to the areas this relay holds raw for
//! (the hosted MLAT's areas and their border band, [`Standing::set_areas`]): a relay cannot hold
//! the world's raw, and relays are regional. A receiver outside them, or any receiver of a relay
//! that hosts no MLAT, has no standing here, not a bad one: it is unknown ([`Standing::of`] says
//! `None`).
//!
//! It holds no model either. Positions are taken as the hub sends them (`Hub::send_positions`),
//! once every model they cite went out before them and is in the relay's store, or they waited
//! their longest (`hub::AWAITING_MS`): a solution whose model is not held then is dropped and
//! counted (`StandingReport::unmodelled`), never waited for again here. Before, standing assembled
//! and decoded every model a second time, held each in a room of its own, and held solutions in a
//! waiting room of its own for models the hub had already waited for.
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
use tally_wire::clocks::Judged;

use tally_mlat::area::Band;
use tally_mlat_solver::gate::{self, Gate, Urgency};
use tally_mlat_solver::held::SealedBins;
use tally_mlat_solver::standing::{Book, ReceiverStanding, Solved, heard_in};
use tally_wire::{Positions, PublicKey, Region, Regions};

use crate::budget::{Charge, Gauge};
use crate::models::{Model, Models};

/// The work of settling under one hold of the book (`Book::settle_up_to`: each transmission's
/// receptions weighed under each of its finals, and once more), at least one transmission: what
/// anyone asking of the book (`Standing::agreeing`, the solutions taken in) waits behind at most,
/// however many transmissions fall due at once. Some five hundred transmissions of an area's three
/// engines' finals over four receptions each.
pub const SETTLE_PIECE: usize = 8_192;
/// Solutions taken from the hand-off into the book under one hold of it.
pub const ADD_PIECE: usize = 1_024;

// What an honest load can make standing hold at most, for each MLAT seat, derived from the
// protocol's own bounds (RFC-0181, "Sizing", "What MLAT's tables hold"). Nothing here is a
// guess at a rate: each figure is a bound the code keeps, and each table is sized from them.
//
// A seat's raw keeps at most `held::KEPT_CEILING_PER_S` receptions a second, so no engine solves
// more of them. An aircraft is solved under one tile (`tile::assign`, the same for every engine),
// fitted by the relays of the area its centre is in (`MLAT_RELAYS_PER_AREA`), each publishing a
// final and a provisional, and the book keeps one of each kind for each engine (`Book::add`).
// A solution cites at least `MIN_RECEIVERS_WITH_ALTITUDE` receptions, each a different seat's
// (standing takes only the solutions of tiles its areas own, whose footprint is in its band,
// whose receivers' raw it holds: `Standing::set_areas`), so a seat's share of the transmissions
// solved is its kept receptions over that. The relays of an area hold the same band's raw and
// seat the same receivers (RFC-0174 §2.3); a peer seating receivers this relay does not would
// bring more, and is not planned.

/// The receptions a seat's raw keeps a second at most (`held::KEPT_CEILING_PER_S`).
pub const KEPT_PER_SEAT_PER_SEC: usize = tally_mlat_solver::held::KEPT_CEILING_PER_S;
/// The fewest receptions a solution cites (`solve::MIN_RECEIVERS_WITH_ALTITUDE`).
pub const CITED_LEAST: usize = tally_mlat_solver::solve::MIN_RECEIVERS_WITH_ALTITUDE;
/// A seat's share of the transmissions solved a second at most: its kept receptions, each in a
/// transmission of [`CITED_LEAST`] seats' at least.
pub const TRANSMISSIONS_PER_SEAT_PER_SEC: usize = KEPT_PER_SEAT_PER_SEC.div_ceil(CITED_LEAST);
/// The engines that solve a transmission: the relays of the area its tile's centre is in.
pub const ENGINES_PER_TRANSMISSION: usize = tally_wire::rendezvous::MLAT_RELAYS_PER_AREA;
/// The solutions of a transmission the book holds at most: each engine's final and provisional
/// (`standing::SOLUTIONS_MOST`).
pub const SOLUTIONS_PER_TRANSMISSION: usize = tally_mlat_solver::standing::SOLUTIONS_MOST;
/// The longest message a solution carries: a long Mode S reply.
pub const MESSAGE_BYTES: usize = tally_wire::modes::LONG;

/// How long the book holds a transmission: until it is settled (`standing::SETTLE`), and the
/// second a solution may come before its transmission's own time is past.
pub const PENDING_SECONDS: usize = tally_mlat_solver::standing::SETTLE
    .span::<Judged>()
    .ms()
    .div_ceil(1_000) as usize
    + 1;
/// A window step: the engine fits each tile's model once a stride of bins
/// (`scope::STRIDE` of `scope::GRID_MS`), and publishes the step's records together.
pub const STEP_SECONDS: usize =
    (tally_mlat_solver::scope::STRIDE as u64 * tally_mlat_solver::scope::GRID_MS / 1_000) as usize;
/// The seconds of solutions the hand-off holds for standing's thread, of each engine: a window
/// step's finals, published at once (every engine of an area steps on the same grid), and a second
/// of provisionals, published as they are solved. Standing's thread takes the hand-off in before
/// it settles anything (`Standing::work_once`).
pub const HANDED_SECONDS: usize = STEP_SECONDS + 1;
/// The seconds of settled receptions the book remembers: the slack past their due time
/// (`standing::SETTLED_SLACK_MS`), and the grid bin that goes whole.
pub const SETTLED_SECONDS: usize = (tally_mlat_solver::standing::SETTLED_SLACK_MS
    + tally_mlat_solver::scope::GRID_MS)
    .div_ceil(1_000) as usize;

/// What one distinct reception adds to a transmission held (`standing::transmission_bytes_most`):
/// its entry and its entry of the index.
pub const RECEPTION_HELD_BYTES: usize =
    tally_mlat_solver::standing::transmission_bytes_most::<Model>(0, 0, 1)
        - tally_mlat_solver::standing::transmission_bytes_most::<Model>(0, 0, 0);
/// What one engine's solutions of a transmission take held beside its receptions, as though it
/// alone solved it: the transmission's entries, its final and its provisional.
pub const ENGINE_HELD_BYTES: usize =
    tally_mlat_solver::standing::transmission_bytes_most::<Model>(1, 1, 0);
/// What a solution handed to standing's thread takes beside its slot in the hand-off: its message
/// and its receptions (`Solved::allocated`).
pub const HANDED_RECEPTION_BYTES: usize = std::mem::size_of::<tally_wire::Reception>();

/// What the one positions record standing reads at a time takes decoded (`Positions::solutions`),
/// while its solutions are taken in: some multiples of the largest record body
/// (`tally_wire::record::MAX_BODY`), held by the counting test (`tests/tables_bytes.rs`). Standing
/// reads one record at a time (`Standing::positions`, under its own lock).
pub const DECODED_BYTES: usize = 2 * tally_wire::record::MAX_BODY;

/// What one table holds at most: its keys and the bytes their values allocate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sized {
    pub count: usize,
    pub room: usize,
}

/// What standing holds at most, every table sized from the MLAT seats (`Caps::of`): what its
/// store is charged whole (`budget::Store::Standing`, [`Caps::planned_bytes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// Solutions handed to standing's thread and not yet in the book: their slots (`count`, the
    /// hand-off's list made at that length once) and their messages and receptions (`room`).
    pub handed: Sized,
    pub book: tally_mlat_solver::standing::BookCaps,
}

impl Caps {
    /// Every table for `seats` seats: each seat's share of what an honest load brings.
    pub const fn of(seats: usize) -> Self {
        let transmissions = seats * TRANSMISSIONS_PER_SEAT_PER_SEC;
        let receptions = seats * KEPT_PER_SEAT_PER_SEC;
        // An engine's share of the book: its final and provisional of every transmission held, and
        // every reception, as though it alone solved them (each transmission's bytes are shared
        // among the engines that solved it, `Book::add`), so an honest engine fits its share
        // however many of its area's engines solve, and one that floods takes no other's.
        let share = PENDING_SECONDS
            * (transmissions * ENGINE_HELD_BYTES + receptions * RECEPTION_HELD_BYTES);
        Self {
            handed: Sized {
                count: HANDED_SECONDS * transmissions * ENGINES_PER_TRANSMISSION,
                room: HANDED_SECONDS
                    * ENGINES_PER_TRANSMISSION
                    * (transmissions * MESSAGE_BYTES + receptions * HANDED_RECEPTION_BYTES),
            },
            book: tally_mlat_solver::standing::BookCaps {
                pending_bytes: ENGINES_PER_TRANSMISSION * share,
                source_share: share,
                // Every receiver a held solution cites is a seat's (above).
                receivers: seats,
                // Each reception settled, remembered its slack past its due time.
                settled: receptions * SETTLED_SECONDS,
            },
        }
    }

    /// What standing allocates at most at these caps: the hand-off's slots and what its solutions
    /// hold, the book (`BookCaps::planned_bytes`), and the one record decoded in hand.
    pub const fn planned_bytes(&self) -> usize {
        tally_wire::footprint::vec::<Solved<Model>>(self.handed.count)
            + self.handed.room
            + self.book.planned_bytes::<Model>()
            + DECODED_BYTES
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
    /// The hosted engine's sealed bins: when a reception was heard. None, nothing is known.
    sealed: Option<SealedBins>,
    book: Book<Model>,
    /// The areas this relay holds raw for, with their border band.
    scope: Option<Band>,
}

/// What a solution handed takes beside its slot: its message and receptions.
fn handed_bytes(solved: &Solved<Model>) -> usize {
    solved.allocated() - std::mem::size_of::<Solved<Model>>()
}

/// What waits for standing's thread: the solutions handed, in order, made once at the length
/// planned (`Caps::handed`) so it never grows; the latest time asked to settle by.
#[derive(Default)]
struct Handed {
    solutions: VecDeque<Solved<Model>>,
    /// What its solutions hold beside their slots ([`handed_bytes`]).
    bytes: usize,
    caps: Option<Sized>,
    /// On the judging clock: transmissions are settled by their signed transmit time. None before
    /// any was asked, or any settled.
    settle: Option<Judged>,
    settled: Option<Judged>,
    /// Whether the thread holds a piece it has taken and not finished.
    working: bool,
}

/// What standing counts of the solutions it was handed, since the relay started.
#[derive(Default)]
struct Counts {
    /// Taken into the book.
    taken: AtomicU64,
    /// Refused for want of room in the hand-off.
    refused: AtomicU64,
    /// Citing a model the relay's store did not hold when the hub sent them.
    unmodelled: AtomicU64,
    /// Under a model of a tile none of the areas owns.
    outside: AtomicU64,
    /// Not a solution under the model they cite (`standing::under`), or of another specification.
    unsolved: AtomicU64,
}

/// Every receiver's standing as this relay reads the records it forwards.
///
/// A stage of its own. Settling costs the book's work for every transmission (weighing it against
/// the sealed raw): done where a record was published, that was the timed duties' thread, then on
/// the async runtime, and the duties stood still and so did every runtime task they had woken. So
/// a record handed here is decoded and its solutions put in the hand-off at once (bounded,
/// `Caps::handed`, the rest refused and counted), never waiting on the book, and one thread of
/// standing's own takes them into the book, in the order handed, and settles, in pieces
/// (`SETTLE_PIECE`, `ADD_PIECE`), below the stages' priority and on the hosted MLAT's gate as
/// background work (`Standing::start`): standing is work the hosted MLAT brings, and runs on the
/// threads the plan gives MLAT, never beside them. A relay that hosts no MLAT keeps no standing,
/// so takes nothing in.
pub struct Standing {
    inner: Mutex<Inner>,
    handed: Mutex<Handed>,
    wake: Condvar,
    /// Held while a record is read: one decoded at a time ([`DECODED_BYTES`]).
    reading: Mutex<()>,
    /// The relay's one store of decoded models (`Network::clock_models`).
    models: Arc<Models>,
    /// The areas this relay holds raw for: a solution is taken only under a model of a tile one
    /// of them owns (`window::owns`).
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
                sealed: None,
                book: Book::new(caps.book),
                scope: None,
            }),
            handed: Mutex::new(Handed::default()),
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
        {
            let mut handed = self.handed();
            let mut solutions = VecDeque::with_capacity(caps.handed.count);
            let mut bytes = 0;
            for solved in handed.solutions.drain(..) {
                if solutions.len() < caps.handed.count
                    && bytes + handed_bytes(&solved) <= caps.handed.room
                {
                    bytes += handed_bytes(&solved);
                    solutions.push_back(solved);
                }
            }
            handed.solutions = solutions;
            handed.bytes = bytes;
            handed.caps = Some(caps.handed);
        }
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
        let (handed_bytes, handed_solutions) = {
            let handed = self.handed();
            (handed.bytes, handed.solutions.len())
        };
        let planned = lock(&self.caps).0.planned_bytes();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let inner = self.inner();
        let book = inner.book.counts();
        let refused = load(&self.counts.refused);
        StandingReport {
            planned_bytes: planned,
            handed_bytes,
            handed_solutions,
            taken: load(&self.counts.taken),
            refused,
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
            forgotten: refused + book.room + book.receivers,
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    fn handed(&self) -> MutexGuard<'_, Handed> {
        lock(&self.handed)
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

    /// One piece of standing's work, or a wait of a second for some: the solutions handed into the
    /// book ([`ADD_PIECE`] at most), else a piece of settling, under `gate` if any.
    fn work_once(&self, gate: Option<&Arc<Gate>>) {
        let next = {
            let mut handed = self.handed();
            if handed.solutions.is_empty() && handed.settled >= handed.settle {
                handed = self
                    .wake
                    .wait_timeout(handed, Duration::from_secs(1))
                    .map_or_else(|poisoned| poisoned.into_inner().0, |(handed, _)| handed);
            }
            if !handed.solutions.is_empty() {
                handed.working = true;
                Some(None)
            } else {
                match handed.settle {
                    Some(settle) if handed.settled < Some(settle) => {
                        handed.working = true;
                        Some(Some(settle))
                    }
                    _ => None,
                }
            }
        };
        let busy = next.is_some();
        let work = || match next {
            Some(None) => self.take_in(),
            Some(Some(settle)) => {
                let more = self.inner().settle_piece(settle);
                if !more {
                    let mut handed = self.handed();
                    handed.settled = handed.settled.max(Some(settle));
                }
            }
            None => {}
        };
        match gate {
            Some(gate) if busy => gate::enter(gate, Urgency::Background, work),
            _ => work(),
        }
        if busy {
            self.handed().working = false;
        }
    }

    /// Takes the oldest solutions handed into the book, [`ADD_PIECE`] at most under one hold.
    fn take_in(&self) {
        let mut inner = self.inner();
        for _ in 0..ADD_PIECE {
            let next = {
                let mut handed = self.handed();
                let next = handed.solutions.pop_front();
                if let Some(solved) = &next {
                    handed.bytes -= handed_bytes(solved);
                }
                next
            };
            let Some(solved) = next else {
                break;
            };
            // A solution the book refuses is counted there (`Settled`).
            if inner.book.add(solved).is_ok() {
                self.counts.taken.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Waits up to `within` until standing's thread has taken in everything handed and settled by
    /// the latest time asked; false if it had not by then. What a test or tool reads after handing
    /// records, as the thread would have left them.
    pub fn wait_idle(&self, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        loop {
            {
                let handed = self.handed();
                if handed.solutions.is_empty() && !handed.working && handed.settled >= handed.settle
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

    /// The areas this relay holds raw for (its hosted MLAT's): standing is kept for receivers in
    /// them and their border band, and for no other.
    pub fn set_areas(&self, areas: &Regions) {
        self.inner().scope = (!areas.is_empty()).then(|| Band::of(areas));
        *lock(&self.areas) = areas.clone();
    }

    /// Final or provisional positions the hub sent (raw, verified; `Hub::send_positions`): each
    /// solution under a model the relay's store holds, of a tile the areas own, and a solution
    /// under it (`Solved::new`), handed to standing's thread at once, in order, to join its
    /// transmission until it is settled; past the hand-off's room, refused and counted. A solution
    /// whose model is not held is dropped and counted: the hub waited for it already.
    pub fn positions(&self, positions: &Positions, now: Judged) {
        if !self.running.load(Ordering::Relaxed) {
            return;
        }
        {
            let _reading = lock(&self.reading);
            let Ok(content) = positions.solutions() else {
                return;
            };
            let provisional = positions.is_provisional();
            let areas = lock(&self.areas);
            for solution in &content.solutions {
                let Some(model) = self.models.get(&solution.clock_model) else {
                    self.counts.unmodelled.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                // Only a model of a tile this relay's areas own: its footprint is in the band, so
                // every receiver its solutions cite is one whose raw this relay holds, and what
                // standing holds is a share of its seats (`Caps::of`).
                if areas.is_empty() || !tally_mlat::window::owns(&areas, model.model().tile) {
                    self.counts.outside.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Some(solved) = (model.spec() == content.spec_version)
                    .then(|| {
                        Solved::new(
                            solution,
                            content.spec_version,
                            content.issued_ms,
                            provisional,
                            model,
                        )
                    })
                    .flatten()
                else {
                    self.counts.unsolved.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                self.hand(solved);
            }
        }
        self.wake.notify_one();
        self.tick(now);
    }

    /// One solution into the hand-off, or refused, counted, past its caps.
    fn hand(&self, solved: Solved<Model>) {
        let bytes = handed_bytes(&solved);
        let mut handed = self.handed();
        let caps = handed.caps.unwrap_or(Caps::of(0).handed);
        if handed.solutions.len() >= caps.count || handed.bytes + bytes > caps.room {
            drop(handed);
            self.counts.refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        handed.bytes += bytes;
        handed.solutions.push_back(solved);
    }

    /// Solutions handed and refused for want of room in the hand-off, since the relay started.
    pub fn refused(&self) -> u64 {
        self.counts.refused.load(Ordering::Relaxed)
    }

    /// Settles what is due by the judging clock `now`, on standing's thread.
    pub fn tick(&self, now: Judged) {
        let mut handed = self.handed();
        if Some(now) > handed.settle {
            handed.settle = Some(now);
            drop(handed);
            self.wake.notify_one();
        }
    }

    /// Takes in everything handed and settles by the latest time asked, here, ungated: what a test
    /// reads after handing records, as standing's thread would have left it.
    #[cfg(test)]
    pub fn drain(&self) {
        while !self.handed().solutions.is_empty() {
            self.take_in();
        }
        let settle = self.handed().settle;
        if let Some(settle) = settle {
            while self.inner().settle_piece(settle) {}
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
    /// What the hand-off's solutions hold beside their slots, and how many wait in it.
    pub handed_bytes: usize,
    pub handed_solutions: usize,
    /// Solutions taken into the book; refused for room in the hand-off; citing a model the store
    /// did not hold; of a tile outside the areas; not a solution under their model.
    pub taken: u64,
    pub refused: u64,
    pub unmodelled: u64,
    pub outside: u64,
    pub unsolved: u64,
    pub pending_bytes: usize,
    pub receivers: usize,
    /// The receivers the transmissions held cite.
    pub interned: usize,
    pub settled_remembered: usize,
    /// The transmissions the book holds now, and solutions it refused as late, past a
    /// transmission's slots, past their engine's share, or let go as two transmissions joined.
    pub transmissions_pending: usize,
    pub late: u64,
    pub slots: u64,
    pub share: u64,
    pub merged_out: u64,
    /// The solutions refused for room (the hand-off's, the book's, its receivers'): none while
    /// the plan holds what the relay is sent. Nothing held is ever forgotten for room.
    pub forgotten: u64,
}

impl Inner {
    /// Settles a piece of what is due by `now` (`SETTLE_PIECE`); true while any is left.
    fn settle_piece(&mut self, now: Judged) -> bool {
        let Some(sealed) = &self.sealed else {
            return false;
        };
        self.book
            .settle_up_to(
                now,
                |id, transmitted_ms| heard_in(sealed, id, transmitted_ms),
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

    /// A model of nothing, the hosted engine's own, held in `models` for the test's day.
    fn held_model(models: &Models) -> Result<Model, String> {
        let model = tally_mlat_solver::ClockModel {
            spec: tally_mlat_solver::SPEC_VERSION,
            tile: tally_mlat_solver::tile::Tile {
                level: 0,
                cube: [0; 3],
            },
            // Its window's last bin the one the test's day starts in, so it is neither stale
            // nor early there (`models::HOLD_MS`).
            window: tally_mlat_solver::scope::Window {
                first: (AT_MS / tally_mlat_solver::scope::GRID_MS) as i64,
                last: (AT_MS / tally_mlat_solver::scope::GRID_MS) as i64,
            },
            scope: Vec::new(),
            input: tally_mlat_solver::scope::Citation {
                hash: [7; 32],
                count: 3,
            },
            gauge: tally_mlat_solver::clock::ClockKey {
                receiver: key(1),
                epoch: 1,
                piece: 0,
            },
            origin_unix_ns: 0,
            gauge_rate: 0,
            pieces: Vec::new(),
            biases: Vec::new(),
            jumps: Vec::new(),
            dropped: Vec::new(),
        };
        models
            .insert_own([9; 32], Arc::new(model), key(100), judged(AT_MS))
            .map_err(|why| format!("{why:?}"))
    }

    /// A final of transmission `n` heard by three receivers, under `model`.
    fn solved(n: u8, model: &Model) -> Solved<Model> {
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
            provisional: false,
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
            observations,
            model: model.clone(),
            consistent: None,
        }
    }

    /// What standing is handed goes into the hand-off at once, whatever its thread is doing with
    /// the book (here, the book held), and is taken in by that thread; past the hand-off's caps,
    /// refused and counted. Before, a record waited for the book on the thread that handed it, and
    /// a window step's solutions held the relay's timed duties ten seconds.
    #[test]
    fn a_solution_handed_returns_at_once_and_is_taken_in_on_standings_thread() -> Result<(), String>
    {
        let models = Arc::new(Models::new());
        let model = held_model(&models)?;
        let standing = Arc::new(Standing::with_models(Arc::clone(&models)));
        let gauge = crate::budget::Gauge::new(crate::budget::Store::Standing, usize::MAX);
        // Three seats: the book keeps the three receivers each solution cites.
        assert!(standing.size_for(3, &gauge));
        Standing::start(&standing, None)?;
        let held = standing.inner();
        let (done, finished) = std::sync::mpsc::channel();
        {
            let standing = Arc::clone(&standing);
            let solved = solved(1, &model);
            std::thread::spawn(move || {
                standing.hand(solved);
                standing.wake.notify_one();
                let _ = done.send(());
            });
        }
        // Handed while the book is held: a hand that waited for the book never returns while it
        // is held, so this waits only on a hang (120 s), never on the machine's speed.
        finished
            .recv_timeout(Duration::from_secs(120))
            .map_err(|_| "handing a solution waited for the book")?;
        drop(held);
        assert!(
            standing.wait_idle(Duration::from_secs(120)),
            "never taken in"
        );
        assert_eq!(standing.inner().book.pending(), 1);
        assert_eq!(standing.report().taken, 1);
        // Past its caps, refused, counted.
        let caps = Caps::of(3).handed;
        let blocked = standing.inner();
        for n in 0..caps.count + 2 {
            standing.hand(solved((n % 200) as u8, &model));
        }
        assert!(standing.refused() >= 2);
        assert!(standing.handed().bytes <= caps.room);
        assert_eq!(
            standing.handed().solutions.capacity(),
            caps.count,
            "the hand-off never grows"
        );
        drop(blocked);
        Ok(())
    }

    /// Positions citing a model the relay's store does not hold when the hub sends them are
    /// dropped and counted: nothing waits for a model here.
    #[test]
    fn a_solution_whose_model_is_not_held_is_dropped_and_counted() -> Result<(), String> {
        let models = Arc::new(Models::new());
        let model = held_model(&models)?;
        let standing = Arc::new(Standing::with_models(models));
        let gauge = crate::budget::Gauge::new(crate::budget::Store::Standing, usize::MAX);
        assert!(standing.size_for(1, &gauge));
        Standing::start(&standing, None)?;
        let solution = |clock_model: Hash| {
            let solved = solved(1, &model);
            tally_wire::Solution {
                address: 0x00ab_cdef,
                transmitted: solved.claimed.transmitted,
                lat_e7: solved.claimed.lat_e7,
                lon_e7: solved.claimed.lon_e7,
                alt_hae_mm: solved.claimed.alt_hae_mm,
                covariance: solved.claimed.covariance,
                clock_model,
                addressed: tally_wire::AddressedCitation::default(),
                observations: solved.observations,
            }
        };
        let positions = Positions::sign_solutions(
            &Identity::from_seed([5; 32]),
            &tally_wire::SolutionsContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: AT_MS,
                spec_version: tally_mlat_solver::SPEC_VERSION,
                solutions: vec![solution([1; 32]), solution(model.id())],
            },
        )
        .map_err(|error| error.to_string())?;
        standing.positions(&positions, judged(AT_MS));
        let report = standing.report();
        assert_eq!(report.unmodelled, 1);
        // The held one is of a tile none of the (no) areas owns.
        assert_eq!(report.outside, 1);
        Ok(())
    }

    /// A burst of transmissions falling due at once is settled in pieces held to their work
    /// (`SETTLE_PIECE`): between two pieces the book is free, so the solutions handed meanwhile are
    /// taken in and anyone asking is answered, however large the burst. Before, a piece was a count
    /// of transmissions, whatever each cost.
    #[test]
    fn a_burst_falling_due_at_a_step_is_settled_in_pieces_held_to_their_work() -> Result<(), String>
    {
        let models = Arc::new(Models::new());
        let model = held_model(&models)?;
        let standing = Standing::with_models(models);
        let gauge = crate::budget::Gauge::new(crate::budget::Store::Standing, usize::MAX);
        assert!(standing.size_for(100, &gauge));
        standing.read_bins(SealedBins::new());
        let burst = 2_000usize;
        {
            let mut inner = standing.inner();
            for n in 0..burst {
                let mut one = solved((n % 250) as u8, &model);
                // Each its own transmission: its own receivers' counters.
                let receptions: Vec<tally_wire::Reception> = one
                    .observations
                    .receptions()
                    .iter()
                    .map(|reception| tally_wire::Reception {
                        counter: n as u64 * 10 + reception.counter % 10,
                        ..*reception
                    })
                    .collect();
                one.observations = tally_wire::ObservationSet::new(
                    one.observations.message().to_vec(),
                    receptions,
                )
                .map_err(|error| error.to_string())?;
                inner.book.add(one).map_err(|why| format!("{why:?}"))?;
            }
            assert_eq!(inner.book.pending(), burst);
        }
        // Every one is due; a piece settles what its work allows (three receptions under one
        // final, and once more, each), and the book is free after it.
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
        assert_eq!(standing.handed().caps, Some(Caps::of(100).handed));
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
        standing.read_bins(SealedBins::new());
        assert_eq!(standing.of(&key, atlanta), Some(ReceiverStanding::NEW));
        standing.tick(judged(u64::MAX / 2));
        standing.drain();
        assert_eq!(standing.of(&key, atlanta), Some(ReceiverStanding::NEW));
        // Outside the areas held: unknown.
        assert_eq!(standing.of(&key, None), None);
    }
}
