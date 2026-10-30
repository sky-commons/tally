//! Fixes (RFC-0171 §3.8.1 as amended 2026-10-24, "MLAT in seconds"; RFC-0174 §2.4): one class of
//! position, solved about a second after its transmission's first reception arrived, under the
//! pair models of the areas its hearers are in (`tally_mlat_solver` crate docs, § Areas), from the
//! receptions that had arrived (its considered set). There is nothing provisional and nothing
//! final: a later step that holds more receptions of the same transmission solves the bigger set,
//! and the merge's superset rule takes it (`tally_merge`).
//!
//! - **What is solved**: the replies (never the ADS-B positions, which sync clocks) of an aircraft
//!   no ADS-B position of which was heard within [`ADSB_HORIZON_MS`] before them, or which is in
//!   the calibration sample (`tally_mlat_solver::arrived::sampled`), heard by enough receivers
//!   taking part, while the fix would still leave in time (`tally_wire::budget::FIX_LEAVES`).
//! - **By whom**: the relays of the area most of its hearers are in (`area::owner`), only an area
//!   the engine owns (`Scope::owned`). Which relay takes a set up is the engine's division of
//!   work, not part of what a fix is: a verifier judges a fix by the models it cites and its own
//!   receptions, whoever solved it.
//! - **Under which models**: each owned area's pair model is refit every `REFIT_EVERY` at the
//!   step's edge on the refit grid (`Trailing::fitted_at`, [`refit`]), warm from its previous
//!   model, in parallel; the models of the neighbouring areas its hearers are in are their own
//!   relays', which the host hands the engine (`Engine::hold`) and the engine judges over the raw
//!   it holds the first time a fix to publish cites one (a fix citing one refuted, or one neither
//!   judged nor corroborated, is not published: `Report::untrusted`). A set
//!   is solved under the models of the newest edge at which every area its hearers are in has a
//!   model held, else the owner's newest ([`models_for`]); a fix whose used hearers need an area
//!   with no model held there is not published, counted (`Report::unheld`), and a fix carried past
//!   its models' edge by more than `MAX_CARRY` is not published either.
//! - **How many**: one transmission an aircraft a slot of its transmit timeline, mlat-server's
//!   resolve backoff as a rule of the transmissions (`tally_mlat_solver::backoff`, crate docs
//!   § Solving, how many). Every due set is grouped into its transmissions (a Mode S reply repeats
//!   its bytes, so a set holds several over its `JOIN_MS`; [`weigh`]); each new one is offered to
//!   its slot, and a slot decided a slot's length after its earliest candidate fell due gives the
//!   one of most receivers ([`back_off`]), its own fix (`publish::solve_transmission`). The others
//!   are never solved, counted (`Report::backed_off`). A chosen transmission is published twice at
//!   most: once when its slot chooses it (the fast fix), and once more once its raw has come
//!   (`MLAT_BATCHING` after its first reception arrived) or as its set closes (`Arrived::seal`),
//!   whichever is first, if it grew (the complete fix, a superset of the first), never on the
//!   same receptions twice. Which transmission is which across seals is told by its receptions' marks
//!   ([`mark`], [`Solved`]), so a transmission is one that shares a reception. A set is taken up
//!   only when more of it arrived. What bounds the work is what the arrived pool holds
//!   (`Capacity`) and the slots, at most one fix an aircraft each 0.7 s and its complete one.
//! - **Checked**: every fix is read back and verified as any checker holding its models and its
//!   set would (`publish::solve_transmission`, the verifier over the normalisation it was solved
//!   on, which a checker's regrouping of the set rebuilds exactly), once; one that fails is
//!   dropped and counted.
//! - **Published twice, back to back**: each model of this engine's own a fix cites first (once:
//!   a model refit at one step and cited at the next is not sent again; a neighbour's was sent by
//!   its own relays), then the fixes in as few records as hold them, each raw (format 7,
//!   relay-only) and at once tagged (format 8, what a client is sent), each reception's tag under
//!   its receiver's reception key (`intake::Sited`). A fix that cannot be tagged is not published at
//!   all, so the two records are twins.
//! - **Sharded by aircraft** (RFC-0181 §3): what the engine remembers of an aircraft (its newest
//!   ADS-B position, the second it was last solved in) is held in [`SHARDS`] address shards over a
//!   keyed hash of the address ([`shard_of`]). The hash is keyed by this process's secret
//!   (`tally_wire::FingerprintKey::process`, the message fingerprint's), because a feeder chooses
//!   the addresses it reports: under a fixed hash it could craft addresses that all fall in one
//!   shard and make it the hot one.
//! - **The same bytes on any threads**: the refits and the solves are each spread over the step's
//!   threads ([`parallel`]) and put back in their items' order; everything chosen, signed or
//!   numbered is decided on one thread, in an order of the items alone.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use tally_mlat_solver::backoff::{Slot, Slots};
use tally_mlat_solver::pair::{self, Models, PairCache, PairModel, Prepared};
use tally_mlat_solver::{
    Arrived, Considered, ObservationId, SPEC_VERSION, Sites, Transmission, TransmissionKey,
    Unpublished, modes, publish,
};
use tally_wire::batch::Hash;
use tally_wire::budget::{ADSB_HORIZON, ADSB_REMEMBERED, FIX_LEAVES, MAX_CARRY_MS};
use tally_wire::clocks::{Judged, Mono};
use tally_wire::footprint::Tree;
use tally_wire::{
    ClockModel, ClockModelContent, FixesContent, Positions, PublicKey, ReceptionKey, Record,
    Region, Regions, Signer, TaggedFix, WireError,
};

use crate::engine::{Dropped, Fix, SignedModel, Step};

/// How long after an aircraft's last ADS-B position it is a target again: the span of the window
/// the solver specification measured it over, the error budget's exemption
/// `tally_wire::budget::ADSB_HORIZON` (it is compared with the judging clock to forget what an
/// aircraft solved, so it is stated there).
pub const ADSB_HORIZON_MS: u64 = 65_000;

const _: () = assert!(
    ADSB_HORIZON.span::<Judged>().ms() == ADSB_HORIZON_MS
        && ADSB_REMEMBERED.span::<Judged>().ms() == 2 * ADSB_HORIZON_MS
);

/// The aircraft a relay's engine keeps the newest ADS-B position of, as planned: about every
/// aircraft in the air at once worldwide.
pub const PLANNED_AIRCRAFT: usize = 20_000;

/// What the address shards allocate whatever they hold, as planned: each one's tree's root
/// ([`Shard`]'s ADS-B positions), and each aircraft's place in it at [`PLANNED_AIRCRAFT`].
pub const TABLES_PLANNED_BYTES: usize = SHARDS * Tree::<u32, u64>::bytes_planned(0)
    + PLANNED_AIRCRAFT * Tree::<u32, u64>::bytes_per_entry();

/// Address shards: fixed, so an aircraft's shard never depends on how many threads run. Equal to
/// a relay's exchange shards (`tally_relay::exchange::SHARDS`).
pub const SHARDS: usize = 256;

/// The domain of the address shard under the process key (`tally_wire::decoded::keyed`).
const SHARD_DOMAIN: u8 = tally_wire::decoded::keyed::ADDRESS_SHARD;

/// The address shard of an ICAO address: a keyed hash under this process's secret (module docs),
/// uniform whatever addresses a feeder chooses, never geography, so neither a dense sky nor a
/// crafted one makes a hot shard. The same for every thread of one process, so an aircraft's shard
/// never depends on who asks.
pub fn shard_of(address: u32) -> usize {
    let mixed =
        tally_wire::FingerprintKey::process().fingerprint(SHARD_DOMAIN, &address.to_le_bytes());
    (mixed % SHARDS as u128) as usize
}

/// Where a batch stands in the order a host hands the batches of one step to the engine: its
/// stamp (when its holder took it), then its receiver, boot and sequence, which a receiver uses
/// once. A function of the batch, never of which thread took it or when, so batches stamped
/// between two steps are admitted in one order however they raced, and what the arrived pool
/// refuses past its caps ([`admit`]) is the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Order {
    pub stamp: Mono,
    pub receiver: PublicKey,
    pub boot: u64,
    pub sequence: u64,
}

impl Order {
    /// `batch`, by its own stamp on its holder's monotonic clock.
    pub fn of(batch: &tally_wire::Decoded) -> Self {
        Self {
            stamp: batch.mono(),
            receiver: batch.receiver(),
            boot: batch.boot_id(),
            sequence: batch.sequence(),
        }
    }
}

/// Which batches are refused, whole, against one count shared by every holder of a split: in
/// `order`, each batch's `sizes` (ascending by [`Order`]) is kept while what is held already
/// (`held`) and what was kept before it fit `most`; a batch that does not fit is refused, all of
/// it. A function of the batches, their order and the count alone, so a host whose raw shards
/// share one budget refuses the same batches however its shards were stepped.
pub fn admit(
    held: usize,
    sizes: impl IntoIterator<Item = (Order, usize)>,
    most: usize,
) -> BTreeSet<Order> {
    let mut total = held;
    let mut refused = BTreeSet::new();
    for (order, size) in sizes {
        if total.saturating_add(size) > most {
            refused.insert(order);
        } else {
            total += size;
        }
    }
    refused
}

/// One address shard (module docs): when each of its aircraft was last heard with an ADS-B
/// position. Everything here belongs to one aircraft, so it splits by address ([`shard_of`]).
#[derive(Default)]
pub struct Shard {
    /// The newest wall clock of each aircraft's ADS-B position.
    adsb: Tree<u32, u64>,
}

impl Shard {
    /// An ADS-B position of `address` signed at `wall_ms` was heard.
    pub fn hear(&mut self, address: u32, wall_ms: u64) {
        let newest = self.adsb.entry(address).or_insert(wall_ms);
        *newest = (*newest).max(wall_ms);
    }

    /// Whether a reply of `address` heard at `wall_ms` is a target's (module docs).
    pub fn target(&self, address: u32, wall_ms: u64) -> bool {
        let quiet = self
            .adsb
            .get(&address)
            .is_none_or(|newest| ADSB_HORIZON.beyond(*newest, wall_ms));
        quiet || tally_mlat_solver::arrived::sampled(address, wall_ms)
    }

    /// Forgets what says nothing more by the judging clock reading `judged`: positions older than
    /// [`ADSB_REMEMBERED`], by their signed times.
    pub fn forget(&mut self, judged: Judged) {
        self.adsb
            .retain(|_, newest| !ADSB_REMEMBERED.older(*newest, judged));
    }

    /// What it allocates now: its tree.
    pub fn bytes(&self) -> usize {
        self.adsb.bytes()
    }
}

/// The aircraft of an ADS-B airborne position, if `reception` is one: what makes its aircraft no
/// target for a while.
pub fn position_of(reception: &tally_mlat_solver::Reception) -> Option<u32> {
    let data = &reception.message;
    match modes::downlink_format(data) {
        Some(17 | 18) if modes::airborne_position(data).is_some() => modes::address(data),
        _ => None,
    }
}

/// The aircraft of a reply MLAT solves, if the message `data` is one.
fn reply_address(data: &[u8]) -> Option<u32> {
    match modes::downlink_format(data) {
        Some(0 | 4 | 5 | 11 | 16 | 20 | 21) => modes::address(data),
        _ => None,
    }
}

/// A transmission set the engine took up: how many receptions it was last solved from (the sited
/// ones of its considered set, published or not), so only a bigger set is taken up again, and of
/// the transmissions its set holds (a Mode S reply repeats its bytes, `publish::transmissions`
/// splits them): the hashes of the considered sets solved (`attempted`), so the same transmission's
/// set is never solved twice, a mark of each reception of them (`seen`, [`mark`], sorted), so a
/// transmission once solved is solved again only once its raw has come (module docs, How many),
/// and a mark of each reception of those solved again so (`completed`, sorted), so none is solved
/// a third time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Solved {
    pub first_arrival_ms: u64,
    pub considered: u32,
    pub attempted: Vec<Hash>,
    pub seen: Vec<u64>,
    pub completed: Vec<u64>,
}

impl Solved {
    /// Whether it is older than anything the pool holds, by the arrival clock reading `now_ms`.
    pub fn spent(&self, now_ms: u64, held_ms: u64) -> bool {
        self.first_arrival_ms.saturating_add(held_ms) < now_ms
    }

    /// What it allocates beyond its place in its tree.
    pub fn bytes(&self) -> usize {
        self.attempted.capacity() * size_of::<Hash>()
            + (self.seen.capacity() + self.completed.capacity()) * size_of::<u64>()
    }

    /// Takes in what a later step solved of the same set: its biggest considered count, every
    /// attempted set and every mark of both kinds.
    pub fn fold(&mut self, later: Solved) {
        self.first_arrival_ms = self.first_arrival_ms.min(later.first_arrival_ms);
        self.considered = self.considered.max(later.considered);
        for set in later.attempted {
            if !self.attempted.contains(&set) {
                self.attempted.push(set);
            }
        }
        self.seen.extend(later.seen);
        self.seen.sort_unstable();
        self.seen.dedup();
        self.completed.extend(later.completed);
        self.completed.sort_unstable();
        self.completed.dedup();
    }
}

/// A reception of a due set, marked by its receiver, counter epoch and counter (the set's message
/// is one): what tells a transmission solved before from a new one of the same bytes. Two
/// receptions of one set share a mark only if one receiver's key agrees with another's in its
/// first eight bytes and their counters agree too; such a pair is solved with the first.
pub fn mark(id: &ObservationId) -> u64 {
    marked(&id.receiver, id.epoch, id.timestamp)
}

/// [`mark`] of a reception, read from its own fields: its message is not hashed, since the mark
/// does not read it. Before (2026-10-27), every mark of a reception built its identity first,
/// a Blake2s of its message each time.
pub fn mark_of(reception: &tally_mlat_solver::Reception) -> u64 {
    marked(&reception.receiver, reception.epoch, reception.timestamp)
}

fn marked(receiver: &tally_wire::PublicKey, epoch: u32, timestamp: u64) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&receiver.as_bytes()[..8]);
    u64::from_le_bytes(head) ^ (u64::from(epoch) << 48) ^ timestamp
}

/// What a step did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    /// What ingest refused or thinned since the last step.
    pub dropped: Dropped,
    /// Transmissions taken up: due targets, new or with more receptions than last time.
    pub due: usize,
    /// Of them, the ones taken up again with more receptions.
    pub grown: usize,
    /// Due targets heard by fewer receivers taking part than any solve takes.
    pub too_few: usize,
    /// Due targets whose fix could no longer leave in time (`FIX_LEAVES`).
    pub late: usize,
    /// Due targets another area's relays take up: most of their hearers are in an area the engine
    /// does not own (`area::owner`).
    pub unowned: usize,
    /// Due targets with no hearer in any area (`area::owner` names none).
    pub unassigned: usize,
    /// Due targets no model of their owner area was held for within `MAX_CARRY`: never solved.
    pub unjudged: usize,
    /// Owned areas refit at the step, and of them those refit warm (from the area's previous
    /// model) and cold, and their time over every thread.
    pub refits: usize,
    pub fits_warm: usize,
    pub fits_cold: usize,
    pub fit_ns: u64,
    /// Areas with no model at the step: why, the first time it happened. Of them, the fits that
    /// did not converge (`pair::PairError::NotConverged`).
    pub unfitted: usize,
    pub unfitted_reason: Option<String>,
    pub not_converged: usize,
    /// Fixes whose used hearers are in an area with no model held at their edge
    /// (`Unpublished::Unheld`): not published until the model is held.
    pub unheld: usize,
    /// Fixes whose transmission was past their models' edge by more than `MAX_CARRY`: not
    /// published.
    pub overcarried: usize,
    /// Neighbouring areas' models judged at the step, each the first time a fix to publish cited
    /// it (`Engine::verify_model` over the raw the engine holds): verified, refuted, and those the
    /// raw cannot judge that stood on two signers (`Held::corroborated`); and those let go at the
    /// step that no fix ever cited, never judged.
    pub models_verified: usize,
    pub models_refuted: usize,
    pub models_corroborated: usize,
    pub models_unneeded: usize,
    /// Fixes not published because a neighbouring model they cite was refuted, or could be
    /// neither judged nor corroborated.
    pub untrusted: usize,
    /// Fixes published.
    pub solved: usize,
    /// Sets the models group into no transmission (every reception unmapped or ambiguous), and
    /// transmissions the solver found no fix for.
    pub ungrouped: usize,
    pub unsolved: usize,
    /// Fixes solved and not published: refused by the verifier, unwritable, untaggable, or citing
    /// a model of this engine's that could not be signed. A fix the engine solves is never refused
    /// by its own verifier, so anything here but an unsigned step is a defect.
    pub unpublished: usize,
    /// Transmissions solved before whose set grew while it was open, held back until it closes,
    /// and fixes of a bigger set that solved to a set attempted before: not solved again.
    pub repeated: usize,
    /// Transmissions the due sets were grouped into, and of them those never solved: another of
    /// their slot was chosen (`tally_mlat_solver::backoff`, module docs, How many).
    pub transmissions: usize,
    pub backed_off: usize,
    /// How far past their models' edge the published fixes' transmissions were, by
    /// [`CARRY_BOUNDS_MS`]: the first bound each is within.
    pub carry: [usize; CARRY_BOUNDS_MS.len()],
    /// The models the published fixes cite, summed over the fixes.
    pub cited: usize,
    /// Sets grouped into their transmissions (`publish::transmissions`, one a set) and the
    /// receptions they considered, the transmissions solved (`publish::solve_transmission`, a
    /// solution sought, found or not), and the time spent grouping and solving, over every
    /// thread.
    pub solve_calls: usize,
    pub solve_receptions: usize,
    pub solves: usize,
    pub solve_ns: u64,
    /// This engine's models published, their parts too large for their manifests, and their bytes.
    pub models: usize,
    pub model_parts: usize,
    pub model_bytes: usize,
    /// Raw positions records (relay-only) and their bytes, and their tagged twins (what a client
    /// is sent).
    pub positions: usize,
    pub positions_bytes: usize,
    pub tagged_positions: usize,
    pub tagged_positions_bytes: usize,
    /// Time the step took.
    pub elapsed: std::time::Duration,
}

/// The bounds of [`Report::carry`]'s histogram, milliseconds a fix's transmission is past its
/// models' edge: none, a second, two and a half, five, and the hard bound (`MAX_CARRY`).
pub const CARRY_BOUNDS_MS: [u64; 5] = [0, 1_000, 2_500, 5_000, MAX_CARRY_MS];

/// What one thread's share of a step reports, and how two shares add up.
pub trait Part: Default + Send {
    fn add(&mut self, other: &Self);
}

impl Part for Report {
    /// Every count summed, by a pattern naming every field, so a count added to the report
    /// is summed here or the crate does not compile. Before (2026-10-26), the counts no part
    /// had yet made were left out, and the step that first judged its due sets on threads
    /// reported none due.
    fn add(&mut self, other: &Report) {
        let Report {
            dropped,
            due,
            grown,
            too_few,
            late,
            unowned,
            unassigned,
            unjudged,
            refits,
            fits_warm,
            fits_cold,
            fit_ns,
            unfitted,
            not_converged,
            unheld,
            overcarried,
            models_verified,
            models_refuted,
            models_corroborated,
            models_unneeded,
            untrusted,
            solved,
            ungrouped,
            unsolved,
            unpublished,
            repeated,
            transmissions,
            backed_off,
            cited,
            solve_calls,
            solve_receptions,
            solves,
            solve_ns,
            models,
            model_parts,
            model_bytes,
            positions,
            positions_bytes,
            tagged_positions,
            tagged_positions_bytes,
            unfitted_reason,
            carry,
            // A step's whole run, set once it ends: no part has one.
            elapsed: _,
        } = other;
        let Dropped {
            thinned,
            refused_batches,
            refused,
            receivers,
            replayed,
        } = dropped;
        self.dropped.thinned += thinned;
        self.dropped.refused_batches += refused_batches;
        self.dropped.refused += refused;
        self.dropped.receivers += receivers;
        self.dropped.replayed += replayed;
        self.due += due;
        self.grown += grown;
        self.too_few += too_few;
        self.late += late;
        self.unowned += unowned;
        self.unassigned += unassigned;
        self.unjudged += unjudged;
        self.refits += refits;
        self.fits_warm += fits_warm;
        self.fits_cold += fits_cold;
        self.fit_ns += fit_ns;
        self.unfitted += unfitted;
        self.not_converged += not_converged;
        self.unheld += unheld;
        self.overcarried += overcarried;
        self.models_verified += models_verified;
        self.models_refuted += models_refuted;
        self.models_corroborated += models_corroborated;
        self.models_unneeded += models_unneeded;
        self.untrusted += untrusted;
        self.solved += solved;
        self.ungrouped += ungrouped;
        self.unsolved += unsolved;
        self.unpublished += unpublished;
        self.repeated += repeated;
        self.transmissions += transmissions;
        self.backed_off += backed_off;
        self.cited += cited;
        self.solve_calls += solve_calls;
        self.solve_receptions += solve_receptions;
        self.solves += solves;
        self.solve_ns += solve_ns;
        self.models += models;
        self.model_parts += model_parts;
        self.model_bytes += model_bytes;
        self.positions += positions;
        self.positions_bytes += positions_bytes;
        self.tagged_positions += tagged_positions;
        self.tagged_positions_bytes += tagged_positions_bytes;
        if self.unfitted_reason.is_none() {
            self.unfitted_reason.clone_from(unfitted_reason);
        }
        for (mine, theirs) in self.carry.iter_mut().zip(carry) {
            *mine += theirs;
        }
    }
}

/// Runs `run` on every item of `work` on up to `threads` threads, each item with a report of its
/// own, and puts the results and reports back in the items' order: the same whatever the threads.
/// The threads pull the items one at a time (`tally_mlat_solver::gate::on_threads`), under the
/// gate of the thread asking, if any: a host's MLAT work spread over no more threads than its plan
/// gave MLAT, and a pass ending in about its work over the permits it holds, however few. With one
/// thread the items run here.
pub fn parallel<T: Sync, R: Send, P: Part>(
    threads: usize,
    work: &[T],
    run: impl Fn(&T, &mut P) -> R + Sync,
) -> (Vec<R>, P) {
    let runs: Vec<(R, P)> =
        tally_mlat_solver::gate::on_threads(threads, work.iter().collect(), |item| {
            let mut report = P::default();
            let out = run(item, &mut report);
            (out, report)
        });
    let mut report = P::default();
    let mut out = Vec::with_capacity(work.len());
    for (result, part) in runs {
        report.add(&part);
        out.push(result);
    }
    (out, report)
}

/// The engine's coverage: the regions whose receivers take part (its areas and their border band,
/// `area::border_band`), and the areas it fits and takes transmissions up for (empty: every area
/// with a receiver taking part).
#[derive(Clone, Copy)]
pub struct Scope<'a> {
    pub regions: &'a Regions,
    pub owned: &'a Regions,
}

impl Scope<'_> {
    /// Whether the engine fits `area`'s model and takes up the transmissions it owns.
    pub fn owns(&self, area: Region) -> bool {
        self.owned.is_empty() || self.owned.contains(area)
    }
}

/// A due target taken up: the area that owns it (`area::owner`), and what it considered, its
/// receivers' all taking part.
pub struct Chosen {
    pub area: Region,
    pub address: u32,
    pub considered: Considered,
    /// What was solved of it before ([`Solved`]): a transmission solved before is solved again
    /// once, only once its raw has come ([`back_off`]).
    pub attempted: Vec<Hash>,
    pub seen: Vec<u64>,
    pub completed: Vec<u64>,
}

/// The due transmissions taken up at a step (module docs, What is solved and How many), in the
/// order of their first arrival, then their key: each a target, its receptions narrowed to the
/// receivers taking part, new or bigger than the set last taken up, owned by an area the engine
/// owns. Each set is built from the pool (`Arrived::considered`) and judged on its own, spread
/// over `threads` ([`parallel`]), then put in that order, so the sets taken are the same whatever
/// the threads. Before (2026-10-26), one thread built and judged every set, a fifth of a step's
/// second at 500 seats.
#[allow(
    clippy::too_many_arguments,
    reason = "a step's inputs, each read where it is held"
)]
pub fn choose(
    threads: usize,
    arrived: &Arrived,
    arrived_ms: u64,
    sites: &Sites,
    scope: Scope<'_>,
    judged: Judged,
    shards: &[Shard],
    solved: &Tree<TransmissionKey, Solved>,
    report: &mut Report,
) -> Vec<Chosen> {
    let (chosen, part) = parallel(
        threads.max(1),
        arrived.due_numbers(),
        |number, report: &mut Report| {
            let due = arrived.due_set(*number, arrived_ms)?;
            choose_one(due, sites, scope, judged, shards, solved, report)
        },
    );
    report.add(&part);
    let mut chosen: Vec<Chosen> = chosen.into_iter().flatten().collect();
    chosen.sort_by_key(|one| (one.considered.first_arrival_ms, one.considered.key));
    chosen
}

/// One due set judged ([`choose`]): taken up, or counted why not. It is judged as the pool holds
/// it, and its receptions made only once it is taken up: before (2026-10-27), every due set's
/// receptions were made first, each with its message's bytes, and most sets were not taken up.
fn choose_one(
    mut due: tally_mlat_solver::arrived::Due<'_>,
    sites: &Sites,
    scope: Scope<'_>,
    judged: Judged,
    shards: &[Shard],
    solved: &Tree<TransmissionKey, Solved>,
    report: &mut Report,
) -> Option<Chosen> {
    let address = due.message().and_then(reply_address)?;
    due.retain_receivers(|receiver| sites.get(receiver).is_some());
    let count = u32::try_from(due.len()).unwrap_or(u32::MAX);
    let previous = solved.get(&due.key);
    if previous.is_some_and(|previous| previous.considered >= count) {
        return None;
    }
    let earliest = due.earliest_wall_ms()?;
    if !shards[shard_of(address)].target(address, earliest) {
        return None;
    }
    if due.receivers().count() < tally_mlat_solver::solve::MIN_RECEIVERS_WITH_ALTITUDE {
        report.too_few += 1;
        return None;
    }
    if FIX_LEAVES.older(earliest, judged) {
        report.late += 1;
        return None;
    }
    let Some(area) = crate::area::owner(sites, due.receivers().copied()) else {
        report.unassigned += 1;
        return None;
    };
    if !scope.owns(area) {
        report.unowned += 1;
        return None;
    }
    let considered = due.considered()?;
    report.due += 1;
    report.grown += usize::from(previous.is_some());
    Some(Chosen {
        area,
        address,
        attempted: previous.map_or_else(Vec::new, |previous| previous.attempted.clone()),
        seen: previous.map_or_else(Vec::new, |previous| previous.seen.clone()),
        completed: previous.map_or_else(Vec::new, |previous| previous.completed.clone()),
        considered,
    })
}

/// A pair model the engine solves under: one it fitted itself (`own`, fitted at a step and
/// published by it), or a neighbouring area's, fitted and published by that area's relays and
/// handed to the engine by its host (`Engine::hold`), judged here only once a fix it would publish
/// or a peer's fix it judges cites it (`verdict`, `Engine::verify_model`). Its id
/// (`publish::pair_model_id`, what fixes cite), inputs id (`publish::inputs_id`, what its manifest
/// carries) and encoding. Kept as its area's model at its edge: an own one is what the area's next
/// refit starts warm from, and any one is solved under while its edge is within `MAX_CARRY`
/// ([`usable`]). An own one is signed and published once, at the first step any fix cites it
/// (`Job::run`): a later step's fixes under it cite that publication, so a model is never sent
/// twice under two signatures.
pub struct Held {
    pub prepared: Prepared,
    pub inputs: Hash,
    pub bytes: Vec<u8>,
    pub own: bool,
    /// Set once a step published it (an own model).
    pub published: OnceLock<()>,
    /// A neighbour's model's verdict over the raw the engine holds, set the first time a fix cites
    /// it and that raw can judge it (`Engine::verify_model`): never for an own model, and never for
    /// one no fix cited.
    pub verdict: OnceLock<bool>,
    /// Set once two of its area's engines signed these bytes (the host's store, `models::Model`):
    /// what a fix may cite it on where the raw the engine holds cannot judge it.
    pub corroborated: OnceLock<()>,
    /// Set the first time a fix the engine would publish cites it.
    pub cited: OnceLock<()>,
}

impl Held {
    /// A model fitted here: encoded, identified and prepared, every list at its length
    /// (`PairModel::shrink_to_fit`), as a relay that decodes it holds it. `None` for one the wire
    /// cannot carry.
    pub fn fitted(mut model: PairModel) -> Option<Self> {
        model.shrink_to_fit();
        let mut bytes = publish::encode_pairs(&model).ok()?;
        bytes.shrink_to_fit();
        let inputs = publish::inputs_id(&model)?;
        let id = publish::pair_model_id(&bytes);
        Some(Self {
            prepared: Prepared::of(model, id)?,
            inputs,
            bytes,
            own: true,
            published: OnceLock::new(),
            verdict: OnceLock::new(),
            corroborated: OnceLock::new(),
            cited: OnceLock::new(),
        })
    }

    /// A model another engine published, from its bytes (`ClockModelContent::model`): decoded,
    /// identified and prepared. `None` for bytes that do not decode, or a model that cannot be
    /// prepared.
    pub fn decoded(mut bytes: Vec<u8>) -> Option<Self> {
        bytes.shrink_to_fit();
        let mut model = publish::decode_pairs(&bytes).ok()?;
        model.shrink_to_fit();
        let inputs = publish::inputs_id(&model)?;
        let id = publish::pair_model_id(&bytes);
        Some(Self {
            prepared: Prepared::of(model, id)?,
            inputs,
            bytes,
            own: false,
            published: OnceLock::new(),
            verdict: OnceLock::new(),
            corroborated: OnceLock::new(),
            cited: OnceLock::new(),
        })
    }

    pub fn id(&self) -> Hash {
        self.prepared.id
    }

    pub fn area(&self) -> Region {
        self.prepared.model.area
    }

    pub fn edge_ms(&self) -> u64 {
        self.prepared.model.trailing.edge_ms
    }

    /// What it allocates: itself, the prepared model and its encoding.
    pub fn bytes(&self) -> usize {
        size_of::<Self>() + self.prepared.bytes() + self.bytes.capacity()
    }
}

/// Whether a model may still judge transmissions at the judging clock's `judged`: no fix is
/// carried past its models' edge by more than `MAX_CARRY`, and what falls due was transmitted
/// before the step.
pub fn usable(held: &Held, judged: Judged) -> bool {
    held.edge_ms().saturating_add(MAX_CARRY_MS) >= judged.ms()
}

/// One owned area to refit, its previous model to start warm from, and its memos (`PairCache`:
/// what the fit read last time and the area's network, which change no result). Each refit is run
/// on one thread, so its cache's lock is never contended.
pub struct Refit {
    pub area: Region,
    pub warm: Option<Arc<Held>>,
    pub cache: Mutex<PairCache>,
}

/// Refits every area of `refits` at `edge_ms` over its trailing window of what has arrived
/// (`Arrived::area_inputs`, `pair::fit`), on up to `threads` threads: the fitted ones, in
/// `refits`' order.
pub fn refit(
    arrived: &Arrived,
    sites: &Sites,
    edge_ms: u64,
    threads: usize,
    refits: &[Refit],
    report: &mut Report,
) -> Vec<Arc<Held>> {
    let (fitted, part) = parallel(threads.max(1), refits, |refit, report: &mut Report| {
        let inputs = arrived.area_inputs(refit.area, sites, edge_ms)?;
        let started = Instant::now();
        let warm = refit.warm.as_ref().map(|warm| &warm.prepared.model);
        let mut cache = refit
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fitted = pair::fit(&inputs, warm, &mut cache);
        drop(cache);
        report.fit_ns += u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if refit.warm.is_some() {
            report.fits_warm += 1;
        } else {
            report.fits_cold += 1;
        }
        let fitted = match fitted {
            Ok(fitted) => fitted,
            Err(error) => {
                report.unfitted += 1;
                if matches!(error, pair::PairError::NotConverged) {
                    report.not_converged += 1;
                }
                report
                    .unfitted_reason
                    .get_or_insert_with(|| error.to_string());
                return None;
            }
        };
        let held = Held::fitted(fitted.model);
        if held.is_none() {
            report.unfitted += 1;
            report
                .unfitted_reason
                .get_or_insert_with(|| "a model the wire cannot carry".to_owned());
        }
        held.map(Arc::new)
    });
    report.add(&part);
    report.refits += refits.len();
    fitted.into_iter().flatten().collect()
}

/// The models a set owned by `owner` whose hearers are in `areas` is solved under (module docs,
/// Under which models): of `held`, the models of every area of `areas` (the owner's among them) at
/// the newest edge at which all of them are held; else, at the owner's newest edge, those of them
/// held there. `None` when no model of the owner is held. Every model of `held` is usable.
pub fn models_for<'a>(
    held: &'a BTreeMap<(Region, u64), Arc<Held>>,
    owner: Region,
    areas: &[Region],
) -> Option<Vec<&'a Arc<Held>>> {
    let at = |edge_ms: u64| -> Vec<&'a Arc<Held>> {
        areas
            .iter()
            .filter_map(|area| held.get(&(*area, edge_ms)))
            .collect()
    };
    let mut edges = held
        .range((owner, 0)..=(owner, u64::MAX))
        .rev()
        .map(|((_, edge_ms), _)| *edge_ms);
    let newest = edges.next()?;
    let whole = std::iter::once(newest)
        .chain(edges)
        .map(at)
        .find(|models| models.len() == areas.len());
    Some(whole.unwrap_or_else(|| at(newest)))
}

/// A step's numbering: who it is and where its sequences stand.
pub struct Job {
    pub boot_id: u64,
    pub issued_ms: u64,
    pub positions_sequence: u64,
    pub models_sequence: u64,
    /// The threads its passes over the step's transmissions and fixes are spread over (the
    /// marks of what was solved again, each fix's tagging): the engine's, so they are not serial
    /// work the step waits on.
    pub threads: usize,
}

/// A finished step: what it published, what it took up (for the engine to remember), and where
/// its sequences now stand.
pub struct Outcome {
    pub step: Step,
    pub solved: Vec<(TransmissionKey, Solved)>,
    pub positions_sequence: u64,
    pub models_sequence: u64,
}

/// One transmission solved: the fix, unpublished yet, the models it cites, and how far its
/// transmission was past their edge.
pub struct Solve {
    pub fix: tally_wire::Fix,
    pub cited: Vec<Arc<Held>>,
    pub carried_ms: u64,
}

/// What one chosen set solved to: a fix for each of its transmissions that solved and may be
/// published, and what this step solved of the set ([`Solved`]): each considered set's hash, and
/// the published ones' receptions' marks.
#[derive(Default)]
pub struct Solves {
    pub fixes: Vec<Solve>,
    pub attempted: Vec<Hash>,
    pub seen: Vec<u64>,
}

/// A chosen set grouped into its transmissions under its models (`models_for`): what the backoff
/// weighs ([`back_off`]).
pub struct Weighed {
    pub models: Vec<Arc<Held>>,
    pub transmissions: Vec<Transmission>,
}

/// Every model held, one index for each trailing window they are of (`pair::Models::index`):
/// what each set's models are read from without a rebuild ([`Indexes::under`]), built once a step.
pub struct Indexes<'a>(BTreeMap<(u64, u32), Models<'a>>);

impl<'a> Indexes<'a> {
    pub fn of(held: &'a BTreeMap<(Region, u64), Arc<Held>>) -> Self {
        let mut windows: BTreeMap<(u64, u32), Vec<&'a Prepared>> = BTreeMap::new();
        for one in held.values() {
            let trailing = one.prepared.model.trailing;
            windows
                .entry((trailing.edge_ms, trailing.span_ms))
                .or_default()
                .push(&one.prepared);
        }
        Self(
            windows
                .into_iter()
                .filter_map(|(window, parts)| Some((window, Models::index(parts)?)))
                .collect(),
        )
    }

    /// `models` as one fix reads them (`Models::new`): from their window's index when it holds
    /// them, the same models either way.
    pub fn under<'b>(&self, models: &[&'b Held]) -> Option<Models<'b>>
    where
        'a: 'b,
    {
        let parts: Vec<&'b Prepared> = models.iter().map(|held| &held.prepared).collect();
        let trailing = parts.first()?.model.trailing;
        match self.0.get(&(trailing.edge_ms, trailing.span_ms)) {
            Some(index) => index.of(&parts),
            None => Models::new(parts),
        }
    }
}

/// Groups every chosen set into its transmissions under its models (`models_for` of `held`, read
/// from `indexes`; `unjudged` when its owner has none, `ungrouped` when they group none), on up to
/// `threads` threads: one for each, in `chosen`'s order. A part of a set whose slot is decided
/// (`backoff::Slots::is_decided`) would be backed off whatever it split into, unless it is a
/// transmission solved before that is solved again at the step its arrival clock reads `now_ms`
/// ([`again`]), so it is not split (`publish::transmissions_unless`).
pub fn weigh(
    threads: usize,
    sites: &Sites,
    (held, indexes): (&BTreeMap<(Region, u64), Arc<Held>>, &Indexes<'_>),
    slots: &Slots<Work>,
    chosen: &[Chosen],
    now_ms: u64,
    report: &mut Report,
) -> Vec<Option<Weighed>> {
    let (weighed, part) = parallel(threads.max(1), chosen, |one, report: &mut Report| {
        let started = Instant::now();
        let areas = sites.areas_of(one.considered.receptions.iter().map(|r| r.receiver));
        let weighed = weigh_under(
            models_for(held, one.area, &areas),
            indexes,
            slots,
            one,
            now_ms,
            report,
        );
        report.solve_ns += u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        weighed
    });
    report.add(&part);
    weighed
}

fn weigh_under(
    models: Option<Vec<&Arc<Held>>>,
    indexes: &Indexes<'_>,
    slots: &Slots<Work>,
    one: &Chosen,
    now_ms: u64,
    report: &mut Report,
) -> Option<Weighed> {
    let Some(models) = models else {
        report.unjudged += 1;
        return None;
    };
    let held: Vec<&Held> = models.iter().map(|held| &***held).collect();
    let Some(under) = indexes.under(&held) else {
        report.unjudged += 1;
        return None;
    };
    report.solve_calls += 1;
    report.solve_receptions += one.considered.receptions.len();
    let decided = |part: &[&tally_mlat_solver::Reception]| {
        under.heard_unix_ns(part).is_some_and(|heard| {
            slots.is_decided(Slot::of(one.address, heard)) && !again(one, part, now_ms)
        })
    };
    match publish::transmissions_unless(&under, &one.considered.receptions, decided) {
        Ok(transmissions) => {
            report.transmissions += transmissions.len();
            Some(Weighed {
                models: models.into_iter().cloned().collect(),
                transmissions,
            })
        }
        Err(_) => {
            report.ungrouped += 1;
            None
        }
    }
}

/// A transmission to solve (module docs, How many): the one of its slot chosen
/// (`tally_mlat_solver::backoff`), or a transmission solved before as its set closes bigger;
/// under the models its set was weighed under, with what its set solved before.
pub struct Work {
    pub key: TransmissionKey,
    pub address: u32,
    pub first_arrival_ms: u64,
    pub models: Vec<Arc<Held>>,
    pub group: Vec<tally_mlat_solver::Reception>,
    /// The considered sets of its set solved before ([`Solved::attempted`]): none is solved again.
    pub attempted: Vec<Hash>,
    /// Whether it is a transmission solved before, solved again once its raw has come
    /// ([`back_off`]): its receptions are marked [`Solved::completed`].
    pub again: bool,
}

impl Work {
    /// What it allocates beyond itself: its lists (its receptions hold their messages).
    pub fn bytes(&self) -> usize {
        self.models.capacity() * size_of::<Arc<Held>>()
            + self.attempted.capacity() * size_of::<Hash>()
            + self.group.capacity() * size_of::<tally_mlat_solver::Reception>()
    }
}

/// Whether a transmission of `one` whose receptions are `group` is solved again at the step its
/// arrival clock reads `now_ms` (module docs, How many): it was solved before (a reception of it
/// marked in [`Solved::seen`]), not solved again yet (none marked in [`Solved::completed`]), and
/// its raw has come (`Considered::come_ms`) or its set closes.
pub fn again<R: std::borrow::Borrow<tally_mlat_solver::Reception>>(
    one: &Chosen,
    group: &[R],
    now_ms: u64,
) -> bool {
    let marked = |marks: &[u64]| {
        group
            .iter()
            .any(|reception| marks.binary_search(&mark_of(reception.borrow())).is_ok())
    };
    marked(&one.seen)
        && !marked(&one.completed)
        && (one.considered.closing || one.considered.come_ms(group) <= now_ms)
}

/// Which transmissions of the weighed sets are solved at the step its arrival clock reads
/// `now_ms` (module docs, How many), on one thread in `chosen`'s order: a transmission solved
/// before (a reception of it marked in its set's [`Solved::seen`]) once more, at the first step
/// its set is due at once its raw has come (`Considered::come_ms`), or as its set closes if that is sooner,
/// and never again ([`Solved::completed`]); any other offered to its slot
/// (`backoff::Slots::offer`, due at its set's first arrival and `SETTLE_MS`), and the slots
/// decided by `now_ms` give theirs. Every candidate a slot did not choose is counted
/// (`Report::backed_off`) and never solved. Before (2026-10-26), a transmission solved before was
/// solved again only as its set closed, `JOIN_MS` after the set first arrived: a Mode S reply
/// repeats its bytes, so one set holds an aircraft's replies for its whole `JOIN_MS`, each new
/// set opening as the last closes, and the sets an engine opened together at its start closed
/// together every 11.5 s for as long as it ran, every transmission of each solved again at once
/// (2,000 feeders on 16 cores: such a step published 6,300 fixes where the others published
/// 1,000, its solves 2.5 s of threads where theirs took 0.5, so it passed its second and the
/// seats were cut from 1,503 to 787). A transmission's raw has come within `MLAT_BATCHING` of its
/// first reception, so its second fix now comes seconds after its first, not up to `JOIN_MS`.
pub fn back_off(
    chosen: &[Chosen],
    weighed: Vec<Option<Weighed>>,
    slots: &mut Slots<Work>,
    now_ms: u64,
    report: &mut Report,
) -> Vec<Work> {
    let mut work = Vec::new();
    for (one, weighed) in chosen.iter().zip(weighed) {
        let Some(weighed) = weighed else {
            continue;
        };
        for transmission in weighed.transmissions {
            let before = transmission
                .group
                .iter()
                .any(|reception| one.seen.binary_search(&mark_of(reception)).is_ok());
            let slot = transmission.slot(one.address);
            let item = Work {
                key: one.considered.key,
                address: one.address,
                first_arrival_ms: one.considered.first_arrival_ms,
                models: weighed.models.clone(),
                group: transmission.group,
                attempted: one.attempted.clone(),
                again: false,
            };
            if before {
                if again(one, &item.group, now_ms) {
                    work.push(Work {
                        again: true,
                        ..item
                    });
                } else {
                    report.repeated += 1;
                }
                continue;
            }
            let marks: BTreeSet<u64> = item.group.iter().map(mark_of).collect();
            let due_ms = one
                .considered
                .first_arrival_ms
                .saturating_add(tally_mlat_solver::arrived::SETTLE_MS);
            if let Some(out) = slots.offer(slot, transmission.rank, due_ms, item) {
                // The same transmission again, grown, displaces itself: not a candidate lost.
                let same = out.group.iter().any(|r| marks.contains(&mark_of(r)));
                report.backed_off += usize::from(!same);
            }
        }
    }
    work.extend(slots.decide(now_ms));
    work
}

/// Solves every transmission of `work` under its models (read from `indexes`), on up to `threads`
/// threads: one [`Solves`] for each, in `work`'s order.
pub fn solve(
    threads: usize,
    indexes: &Indexes<'_>,
    work: &[Work],
    report: &mut Report,
) -> Vec<Solves> {
    let (solves, part) = parallel(threads.max(1), work, |one, report: &mut Report| {
        solve_under(one, indexes, report)
    });
    report.add(&part);
    solves
}

/// The hash of the considered set of `message` that `cited` identifies (`ObservationSet::hash`,
/// what a published fix's considered set hashes to): how the engine knows a transmission it
/// published already.
fn set_hash(message: &[u8], cited: &[ObservationId]) -> Option<Hash> {
    let receptions = cited
        .iter()
        .map(|id| tally_wire::observation_set::Reception {
            receiver: id.receiver,
            epoch: id.epoch,
            counter: id.timestamp,
        })
        .collect();
    tally_wire::ObservationSet::new(message.to_vec(), receptions)
        .ok()
        .map(|set| set.hash())
}

/// Solves one transmission under its models (`publish::solve_transmission`: written to the wire
/// and verified as any checker holding the models and its receptions would), its fix of the
/// aircraft its set was chosen for. A considered set attempted already is not solved again
/// (`Unpublished::Published`), and no fix carried past `MAX_CARRY` is published.
fn solve_under(one: &Work, indexes: &Indexes<'_>, report: &mut Report) -> Solves {
    let started = Instant::now();
    let mut solves = Solves::default();
    let held: Vec<&Held> = one.models.iter().map(|held| &**held).collect();
    let Some(under) = indexes.under(&held) else {
        report.unjudged += 1;
        return solves;
    };
    let message = one
        .group
        .first()
        .map_or_else(Vec::new, |reception| reception.message.to_vec());
    // Never a considered set attempted already; every one asked of and not held back is
    // attempted.
    let asked = std::cell::RefCell::new(Vec::<Hash>::new());
    let held_back = |cited: &[ObservationId]| {
        let Some(set) = set_hash(&message, cited) else {
            return true;
        };
        let back = one.attempted.contains(&set);
        if !back {
            asked.borrow_mut().push(set);
        }
        back
    };
    let result = publish::solve_transmission(&under, one.group.clone(), held_back);
    solves.attempted = asked.into_inner();
    report.solves += usize::from(matches!(
        result,
        Ok(_)
            | Err(Unpublished::Unsolved(_) | Unpublished::Refuted(_) | Unpublished::Unwritable(_))
    ));
    match result {
        Ok((solution, fix)) => 'published: {
            if fix.address != one.address {
                report.unpublished += 1;
                break 'published;
            }
            let cited: Option<Vec<Arc<Held>>> = fix
                .models
                .iter()
                .map(|id| {
                    one.models
                        .iter()
                        .find(|held| held.id() == *id)
                        .map(Arc::clone)
                })
                .collect();
            let Some(cited) = cited else {
                report.unpublished += 1;
                break 'published;
            };
            let edge_ms = cited.iter().map(|held| held.edge_ms()).min().unwrap_or(0);
            let carried_ms = fix.transmitted.unix_ms.saturating_sub(edge_ms);
            if carried_ms > MAX_CARRY_MS {
                report.overcarried += 1;
                break 'published;
            }
            solves.seen.extend(solution.considered.iter().map(mark));
            solves.fixes.push(Solve {
                fix,
                cited,
                carried_ms,
            });
        }
        Err(Unpublished::Unheld(_)) => report.unheld += 1,
        Err(Unpublished::Published) => report.repeated += 1,
        Err(Unpublished::Refuted(_) | Unpublished::Unwritable(_)) => report.unpublished += 1,
        Err(Unpublished::Ungrouped | Unpublished::Unnormalised(_)) => report.ungrouped += 1,
        Err(Unpublished::Unsolved(_)) => report.unsolved += 1,
    }
    report.solve_ns += u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    solves
}

impl Job {
    /// Signs what the step solved, in order: each own model a fix cites not yet published (a model
    /// is published once, `Held::published`), then the fixes, raw and tagged back to back (module
    /// docs). `solves` is one for each of `work`, in its order; what each set of `chosen` and each
    /// transmission of `work` solved is in the outcome, for the engine to fold into what it
    /// remembers ([`Solved::fold`]). One thread, in an order of the items alone. Signed by
    /// `signer`, which lends its key only while its clock judges: a step that finishes after it
    /// lost sync signs nothing.
    #[allow(
        clippy::disallowed_methods,
        reason = "stepped only by a judging watermark (`MlatHost::take_published`)"
    )]
    pub fn run(
        self,
        signer: &Signer,
        keys: &BTreeMap<PublicKey, ReceptionKey>,
        chosen: &[Chosen],
        work: &[Work],
        solves: Vec<Solves>,
        mut report: Report,
    ) -> Outcome {
        let mut outcome = Outcome {
            step: Step::default(),
            solved: Vec::new(),
            positions_sequence: self.positions_sequence,
            models_sequence: self.models_sequence,
        };
        let mut fixes: Vec<Solve> = Vec::new();
        for one in chosen {
            outcome.solved.push((
                one.considered.key,
                Solved {
                    first_arrival_ms: one.considered.first_arrival_ms,
                    considered: u32::try_from(one.considered.receptions.len()).unwrap_or(u32::MAX),
                    attempted: Vec::new(),
                    seen: Vec::new(),
                    completed: Vec::new(),
                },
            ));
        }
        // Solved again: no transmission sharing a reception with it is solved a third time. A
        // mark reads a reception's own fields (`mark_of`), so they are made here.
        let completed: Vec<Vec<u64>> = work
            .iter()
            .map(|one| {
                let mut completed: Vec<u64> = if one.again {
                    one.group.iter().map(mark_of).collect()
                } else {
                    Vec::new()
                };
                completed.sort_unstable();
                completed.dedup();
                completed
            })
            .collect();
        for ((one, solved), completed) in work.iter().zip(solves).zip(completed) {
            let mut seen = solved.seen;
            seen.sort_unstable();
            seen.dedup();
            outcome.solved.push((
                one.key,
                Solved {
                    first_arrival_ms: one.first_arrival_ms,
                    considered: 0,
                    attempted: solved.attempted,
                    seen,
                    completed,
                },
            ));
            fixes.extend(solved.fixes);
        }
        // The own models the fixes cite and no step published yet, each signed once, in the order
        // the fixes first cite them; a fix citing one that could not be signed is not published.
        let mut unsigned: BTreeSet<Hash> = BTreeSet::new();
        for solve in &fixes {
            for held in &solve.cited {
                if !held.own || held.published.get().is_some() || unsigned.contains(&held.id()) {
                    continue;
                }
                // A model's signing and encoding is one item of the step.
                tally_mlat_solver::gate::checkpoint();
                match self.sign_model(signer, held, outcome.models_sequence) {
                    Some(model) => {
                        outcome.models_sequence += 1;
                        let _ = held.published.set(());
                        report.models += 1;
                        // Beside its parts, a model's records are its manifest and its summary.
                        report.model_parts += model.records.len().saturating_sub(2);
                        report.model_bytes += model.records.iter().map(encoded_len).sum::<usize>();
                        outcome.step.models.push(model);
                    }
                    None => {
                        unsigned.insert(held.id());
                    }
                }
            }
        }
        // Each fix with its twin, the receptions tagged under their receivers' keys: one that
        // cannot be tagged is not published at all.
        // Tagging hashes each reception under its receiver's key, so the fixes are tagged on the
        // step's threads, each a function of its fix and the keys alone.
        let tagged: Vec<Result<TaggedFix, tally_wire::WireError>> =
            tally_mlat_solver::gate::on_threads(self.threads, fixes.iter().collect(), |solve| {
                solve.fix.tagged(|receiver| keys.get(receiver).copied())
            });
        let mut pairs: Vec<(tally_wire::Fix, TaggedFix)> = Vec::new();
        let mut kept: Vec<u64> = Vec::new();
        for (solve, tagged) in fixes.into_iter().zip(tagged) {
            if solve.cited.iter().any(|held| unsigned.contains(&held.id())) {
                report.unpublished += 1;
                continue;
            }
            match tagged {
                Ok(tagged) => {
                    report.cited += solve.fix.models.len();
                    pairs.push((solve.fix, tagged));
                    kept.push(solve.carried_ms);
                }
                Err(_) => report.unpublished += 1,
            }
        }
        // Fixes that cite the same models go together, in solve order among them: such fixes are
        // of one stretch of receivers, so each record's receiver and model tables name each of
        // them once rather than once a record (the tables were most of a record's bytes when
        // fixes were packed in solve order across the whole world, 2026-10-26).
        let mut both: Vec<((tally_wire::Fix, TaggedFix), u64)> =
            pairs.into_iter().zip(kept).collect();
        both.sort_by(|x, y| x.0.0.models.cmp(&y.0.0.models));
        let (pairs, kept): (Vec<(tally_wire::Fix, TaggedFix)>, Vec<u64>) = both.into_iter().unzip();
        let content = |sequence: u64| (self.boot_id, sequence, self.issued_ms);
        let records = pack_with(
            outcome.positions_sequence,
            pairs,
            2,
            // Measured in place: the rest is never copied to be measured. Before, each record
            // cloned every fix still to pack, so packing a step's fixes grew with their square
            // and took most of a step at 500 seats (2026-10-26).
            |run: &[(tally_wire::Fix, TaggedFix)]| {
                Positions::fitting_fixes(run.iter().map(|(fix, _)| fix)).min(
                    Positions::fitting_tagged_fixes(run.iter().map(|(_, fix)| fix)),
                )
            },
            |sequence, run: &[(tally_wire::Fix, TaggedFix)]| {
                let models: BTreeSet<Hash> = run
                    .iter()
                    .flat_map(|(fix, _)| fix.models.iter().copied())
                    .collect();
                sign_pair(signer, content(sequence), run).map(|signed| (signed, models))
            },
        );
        let mut published = vec![false; kept.len()];
        for (_, range) in &records {
            for at in range.clone() {
                published[at] = true;
            }
        }
        for (carried_ms, published) in kept.iter().zip(published) {
            if !published {
                report.unpublished += 1;
                continue;
            }
            report.solved += 1;
            let bucket = CARRY_BOUNDS_MS
                .iter()
                .position(|bound| carried_ms <= bound)
                .unwrap_or(CARRY_BOUNDS_MS.len() - 1);
            report.carry[bucket] += 1;
        }
        outcome.positions_sequence += 2 * records.len() as u64;
        for (((raw, tagged), models), _) in records {
            report.positions += 1;
            report.positions_bytes += encoded_len(&Record::Positions(raw.clone()));
            report.tagged_positions += 1;
            report.tagged_positions_bytes += encoded_len(&Record::Positions(tagged.clone()));
            outcome.step.fixes.push(Fix {
                models: models.into_iter().collect(),
                raw,
                tagged,
            });
        }
        outcome.step.report = report;
        outcome
    }

    /// Signs `held`'s model numbered `sequence`: its manifest (and parts), then its summary for
    /// clients, numbered with it. `None` when either cannot be signed: no client is sent a fix
    /// citing a model it cannot hold.
    #[allow(
        clippy::disallowed_methods,
        reason = "stepped only by a judging watermark (`MlatHost::take_published`)"
    )]
    fn sign_model(&self, signer: &Signer, held: &Arc<Held>, sequence: u64) -> Option<SignedModel> {
        let signed = signer
            .sign_with(|identity| {
                ClockModel::sign(
                    identity,
                    &ClockModelContent {
                        boot_id: self.boot_id,
                        sequence,
                        issued_ms: self.issued_ms,
                        spec_version: SPEC_VERSION,
                        inputs: held.inputs,
                        model: held.bytes.clone(),
                    },
                )
            })
            .ok()?;
        let summary = signer
            .sign_with(|identity| {
                publish::client_model(
                    identity,
                    &held.prepared.model,
                    held.id(),
                    held.inputs,
                    (self.boot_id, sequence, self.issued_ms),
                )
            })
            .ok()?;
        let mut records = signed.records();
        records.push(Record::ClientClockModel(summary));
        Some(SignedModel {
            area: held.area(),
            edge_ms: held.edge_ms(),
            id: held.id(),
            model: Arc::clone(held),
            records,
        })
    }
}

/// Signs `run`'s fixes raw (numbered `sequence`) and tagged (the next), as one pair of twins.
#[allow(
    clippy::disallowed_methods,
    reason = "stepped only by a judging watermark (`MlatHost::take_published`)"
)]
fn sign_pair(
    signer: &Signer,
    (boot_id, sequence, issued_ms): (u64, u64, u64),
    run: &[(tally_wire::Fix, TaggedFix)],
) -> Result<(Positions, Positions), WireError> {
    let raw = signer.sign_with(|identity| {
        Positions::sign_fix(
            identity,
            &FixesContent {
                boot_id,
                sequence,
                issued_ms,
                spec_version: SPEC_VERSION,
                fixes: run.iter().map(|(fix, _)| fix.clone()).collect(),
            },
        )
    })?;
    let tagged = signer.sign_with(|identity| {
        Positions::sign_tagged_fix(
            identity,
            &FixesContent {
                boot_id,
                sequence: sequence + 1,
                issued_ms,
                spec_version: SPEC_VERSION,
                fixes: run.iter().map(|(_, fix)| fix.clone()).collect(),
            },
        )
    })?;
    Ok((raw, tagged))
}

/// A record's bytes on the wire, header included.
fn encoded_len(record: &Record) -> usize {
    let mut bytes = Vec::new();
    record.encode(&mut bytes).map_or(0, |()| bytes.len())
}

/// Signs `items` into as few records as hold them, in order, numbered from `sequence` and
/// `per_record` apart (a pair of twins takes two numbers), each signed by `sign`: each takes the
/// longest run that signs within the wire's size limit, measured by `fitting`. Each record with
/// the items it holds, by their places in `items`. An item the wire refuses outright is left out; once the signer's clock
/// is not judging, nothing more is signed.
pub fn pack_with<S, R>(
    mut sequence: u64,
    items: Vec<S>,
    per_record: u64,
    fitting: impl Fn(&[S]) -> usize,
    sign: impl Fn(u64, &[S]) -> Result<R, WireError>,
) -> Vec<(R, std::ops::Range<usize>)> {
    let mut records = Vec::new();
    let mut rest = items.as_slice();
    let mut first = 0;
    while !rest.is_empty() {
        // The longest prefix one record holds, measured (`fitting`), signed once. Only when that
        // prefix is refused for an item's content is it searched below, between none and the
        // length refused.
        let mut take = fitting(rest);
        let (mut fits, mut fails) = (0, take + 1);
        let mut signed = None;
        while fits + 1 < fails {
            // Each signing is one item: on a gate of one permit other work waits for one at most,
            // never the whole packing.
            tally_mlat_solver::gate::checkpoint();
            match sign(sequence, &rest[..take]) {
                Ok(record) => {
                    fits = take;
                    signed = Some(record);
                }
                Err(WireError::Oversize(_)) => fails = take,
                // Its signer's clock is not judging: nothing more is signed.
                Err(WireError::Unsynced) => return records,
                // An item the wire refuses outright: leave it out.
                Err(_) if take == 1 => break,
                Err(_) => fails = take,
            }
            take = (fits + fails) / 2;
        }
        let Some(record) = signed.filter(|_| fits > 0) else {
            rest = &rest[1..];
            first += 1;
            continue;
        };
        records.push((record, first..first + fits));
        sequence += per_record;
        rest = &rest[fits..];
        first += fits;
    }
    records
}

#[cfg(test)]
#[path = "fix_tests.rs"]
mod tests;
