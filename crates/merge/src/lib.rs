//! THE CLIENT MERGE RULE (RFC-0171 §3.8.1), implemented once for every client: whoever reads
//! the positions and clock model streams of any number of engines, through any number of relays,
//! holds one current solution per aircraft here, and holds it the same whatever order the records
//! arrived in and however many copies of each did.
//!
//! What it takes is what a client is sent ([`ClientRecord`], wire version 3): tagged `Positions`
//! (format 5), tagged provisional positions (format 6), engines' `ClientClockModel`s (a model's
//! summary: its id, inputs hash and window, nothing of which receivers it is of) and tagged
//! `FaultProof`s. A client is never sent a receiver's site, its raw counters, a full model or a
//! model's members, so
//! it holds no raw and solves nothing itself: what checks and joins solutions here works on tag
//! sets (`TaggedSet`), each reception a 16-byte tag only a relay holding the receiver's site and
//! the raw can rematch (`tally_mlat_solver::publish::rematch`). What it holds per aircraft is a
//! [`Track`]: its latest transmissions, each with the [`Fix`] kept and the alternatives it was
//! preferred to.
//!
//! - **Every solution is checked against the model it cites before it counts**, by signatures
//!   and content addresses: the record verifies under its engine's key; the model summary it cites
//!   is held, signed by the same engine, and of the specification the record names; and the
//!   solution's message names its aircraft. A client cannot verify a model or a solution from raw
//!   (it holds neither the raw nor the sites): a relay does (`tally_relay`'s standing).
//! - **Solutions merge per transmission, and only on evidence** (`Merge::same_transmission`). Two
//!   solutions are of one transmission when they name one aircraft with the same message bytes
//!   and share a tag: a tag is one receiver's one reception of those bytes, so two sets that share
//!   one are of one transmission. Nothing else joins: not transmit times, which two models state on
//!   origins that agree only as well as their gauges' wall clocks (0.9 s apart in the simulator),
//!   and not the bytes, which a Mode S reply (DF4, 5, 11, 20, 21) repeats exactly milliseconds
//!   apart to another interrogator (a false join is invisible to any chi-square: each side fits
//!   itself). A solution sharing a tag with more than one held transmission joins none. What is
//!   lost: two engines whose solutions share no reception are never merged, and the aircraft's
//!   track holds both as separate transmissions (its current position is then the latest by
//!   transmit time, which is the one place a transmit time across models is compared). A tie
//!   through a model (mapping one solution's receptions through the other's clocks) needs the
//!   receivers' sites and offsets, which a client is not sent. An aircraft's track holds its latest
//!   `TRANSMISSIONS` transmissions; its current position is the latest one's fix.
//! - **Within one transmission, by the full input set** (the tag set and the cited model's inputs
//!   hash together, `tally_wire::products::input_set`): the same set is a duplicate, dropped, its
//!   signer added to the fix's engines; a superset of tags wins only if it agrees with the smaller
//!   fix within the smaller's covariance (RFC-0174 §2.12, `tally_mlat_solver::standing::decide`):
//!   one that does not is contested, a fault, never the answer, kept as evidence
//!   (`Transmission::refused`, `Transmission::contests`, `Merge::contested`) while the smaller
//!   stands; with the same model inputs, an agreeing superset drops the subset; anything else is
//!   incomparable and never averaged: the one that ranks first is kept and the other recorded as an
//!   alternative.
//! - **The rule ranks by the tie rule** (the rule's `rank` with no standing, which is a relay's):
//!   by weight (the tags the solution cites), then by the lowest input set hash (`input_set`). A
//!   client cannot tell whether a smaller fix agrees with its own receptions (that needs its
//!   model's sites), so every fix here may refuse a disagreeing superset; a relay, which can, drops
//!   one that does not before it forwards it.
//! - **A fault proof convicts its signers.** A checked tagged `FaultProof` (two solutions of one
//!   tag set under one model that disagree) marks each engine it names as faulted: what it signed
//!   is dropped from every track (a fix any other engine also signed stands on that engine's word;
//!   a transmission whose fix is dropped keeps its best alternative), its models are forgotten,
//!   and nothing it signs later counts.
//! - **Provisional fixes** (`ClientRecord::Provisional`) are checked as a final solution is and
//!   held apart from the final transmissions, per aircraft, at most `PROVISIONAL_PER_SECOND` a
//!   signer a second of transmit time and `PROVISIONALS_PER_AIRCRAFT` in all. What is served
//!   ([`Track::served`]) is the latest final fix, unless a provisional one is later by transmit
//!   time. A final fix of the same transmission (`same_transmission`) supersedes a provisional one,
//!   which is then forgotten (one arriving after it is not held); a final fix of the aircraft
//!   within `CONFIRM_WITHIN_MS` that puts it inside `CONFIRM_GATE` (both horizontal covariances and
//!   `CONFIRM_SPEED_M_PER_S` of motion) confirms it. A client learns of a retraction by the
//!   deadline rule, needing no message: one neither superseded nor confirmed
//!   `PROVISIONAL_DEADLINE_MS` after it arrived, by the client's clock, is retracted, forgotten and
//!   counted against its signers ([`Merge::retractions`]). Each fix held ends superseded,
//!   confirmed, retracted or forgotten ([`ProvisionalCounts`]).
//! - **Memory is bounded**, every table least-recently-active first (the relay's `Bounded`):
//!   tracks, models, solutions waiting for their model and faulted keys by count.

// It reaches keys (`tally_wire::Identity`): no `unsafe` code at all, forbidden, so no module
// can allow it.
#![forbid(unsafe_code)]

pub mod contest;
pub mod link;

pub use contest::{Contest, SupersetVerdict, superset_verdict};

use std::collections::BTreeSet;

use tally_mlat_solver::modes;
use tally_mlat_solver::standing::{Candidate, Claimed, decide};
use tally_relay::bounded::Bounded;
use tally_wire::batch::Hash;
use tally_wire::{
    ClientClockModel, ClientFaultProof, ClientRecord, Positions, PublicKey, TaggedSet,
    TaggedSolution, Tolerance, TransmitTime,
};

/// Transmissions kept per aircraft, the latest. Two engines' transmit times are on their models'
/// own time origins, which agree only as well as the gauges' wall clocks when neither is GNSS
/// disciplined, so one aircraft's transmissions are held a few at a time and a solution joins the
/// one it is of, rather than being judged older or newer than another engine's.
pub const TRANSMISSIONS: usize = 8;
/// Alternatives kept per transmission, the best ranked first.
pub const ALTERNATIVES: usize = 4;
/// Solutions held per model while it has not arrived.
pub const PENDING_PER_MODEL: usize = 4_096;
/// How long after a provisional fix arrives (by the client's clock) a final one must have
/// superseded or confirmed it, else it is retracted: once a final fix has surely arrived
/// (`tally_wire::products::FINAL_FIX_ARRIVED_MS`, derived there). A provisional arrives after its
/// transmission, so waiting this long from its arrival is enough.
pub const PROVISIONAL_DEADLINE_MS: u64 = tally_wire::products::FINAL_FIX_ARRIVED_MS;
/// Provisional fixes taken per signer per aircraft per second of transmit time, at most: an engine
/// solves one an aircraft a second, and a second's boundary on two models' time origins may fall
/// between two.
pub const PROVISIONAL_PER_SECOND: usize = 2;
/// Provisional fixes held per aircraft, the latest.
pub const PROVISIONALS_PER_AIRCRAFT: usize = 128;
/// How far apart in transmit time a final fix may be from a provisional one and confirm it.
pub const CONFIRM_WITHIN_MS: u64 = 2_000;
/// How fast an aircraft MLAT tracks may move, for confirming a provisional fix by a final one
/// at another moment: 300 m/s, faster than any airliner, over the two transmit times' difference
/// plus a second for the two models' time origins.
pub const CONFIRM_SPEED_M_PER_S: f64 = 300.0;
/// The gate a final fix must put a provisional one inside to confirm it: chi-square with two
/// degrees of freedom at 0.999.
pub const CONFIRM_GATE: f64 = 13.815_51;

/// How much the client holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub max_aircraft: usize,
    pub max_models: usize,
    /// Models solutions are waiting for.
    pub max_pending: usize,
    pub max_faulted: usize,
    /// Provisional fixes held in all, waiting for a final one.
    pub max_provisional: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_aircraft: 65_536,
            max_models: 16_384,
            max_pending: 1_024,
            max_faulted: 4_096,
            max_provisional: 262_144,
        }
    }
}

/// Whether a fix is final or provisional.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Solved under a model of the window that holds its transmission.
    Final,
    /// Solved about a second after its transmission under an older model carried forward, and
    /// superseded by a final fix of the same transmission (crate docs, § Provisional fixes).
    Provisional,
}

/// One solution as the merge holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Fix {
    pub kind: Kind,
    pub address: u32,
    pub transmitted: TransmitTime,
    pub lat_e7: i32,
    pub lon_e7: i32,
    /// Millimetres above the WGS84 ellipsoid.
    pub alt_hae_mm: Option<i32>,
    /// The barometric altitude the message itself carries, feet.
    pub altitude_ft: Option<i32>,
    /// One standard deviation of the horizontal position, metres: the root of half the trace of
    /// the east-north covariance, clock component included.
    pub horizontal_sigma_m: f64,
    /// The position's covariance as published, east-north-up metres squared.
    pub covariance: tally_wire::EnuCovariance,
    /// The message and its receptions' tags.
    pub observations: TaggedSet,
    /// The cited model's id (`ClockModel::id`, as its `ClientClockModel` names it).
    pub model: Hash,
    /// The cited model's inputs hash.
    pub model_inputs: Hash,
    /// BLAKE2s-256 over `"tally merge input set" 0x00`, the tag set hash and the model inputs
    /// hash: the full input set's identity.
    pub input_set: Hash,
    /// The tags cited: the tie rule's weight.
    pub weight: u64,
    /// The engines that signed it (and the model it cites).
    pub engines: BTreeSet<PublicKey>,
}

impl Fix {
    /// The rule's order (`tally_mlat_solver::standing::rank`): the tie rule's weight, then the
    /// lowest input set hash. The less ranks first.
    #[cfg(test)]
    fn rank(&self) -> (bool, std::cmp::Reverse<u64>, std::cmp::Reverse<u64>, Hash) {
        tally_mlat_solver::standing::rank(self)
    }
}

impl Candidate for Fix {
    type Set = TaggedSet;

    fn observations(&self) -> &TaggedSet {
        &self.observations
    }

    fn model_inputs(&self) -> &Hash {
        &self.model_inputs
    }

    fn claimed(&self) -> Claimed {
        contest::claimed(self)
    }

    /// Standing is a relay's: a client cannot tell who heard what when.
    fn standing(&self) -> u64 {
        0
    }

    fn weight(&self) -> u64 {
        self.weight
    }

    fn identity(&self) -> Hash {
        self.input_set
    }

    /// Whether it agrees with its own receptions under its own model needs the model's sites,
    /// which a client is not sent: a relay drops one that does not before it forwards it.
    fn consistent(&self) -> bool {
        true
    }
}

/// Whether the two share a tag: a reception in common.
fn in_common(a: &TaggedSet, b: &TaggedSet) -> bool {
    let theirs = b.tags();
    a.tags().iter().any(|tag| theirs.binary_search(tag).is_ok())
}

/// The solutions of one transmission the merge holds, as the rule decides them
/// (`tally_mlat_solver::standing::decide`, RFC-0174 §2.12): none dominated by another (the same
/// model's inputs and a subset of an agreeing superset's tags), none refused (a superset that
/// disagrees with a smaller fix: contested, a fault, never the answer), best first by `order`,
/// at most `ALTERNATIVES` after the first. A function of the set of solutions taken, whatever order
/// they came in.
#[derive(Clone, Debug, PartialEq)]
pub struct Transmission {
    pub fixes: Vec<Fix>,
    /// Supersets refused for disagreeing with a smaller fix: kept as evidence, never served, at
    /// most `ALTERNATIVES`.
    pub refused: Vec<Fix>,
    /// What each refusal found.
    pub contests: Vec<Contest>,
}

impl Transmission {
    fn new(fix: Fix) -> Self {
        let mut transmission = Self {
            fixes: vec![fix],
            refused: Vec::new(),
            contests: Vec::new(),
        };
        transmission.normalize();
        transmission
    }

    /// Whether the transmission is contested: a superset of one of its fixes disagreed with it.
    pub fn is_contested(&self) -> bool {
        !self.contests.is_empty()
    }

    /// The fix kept: the best.
    pub fn current(&self) -> &Fix {
        &self.fixes[0]
    }

    /// The fixes it was preferred to, best first.
    pub fn alternatives(&self) -> &[Fix] {
        &self.fixes[1..]
    }

    /// Puts the fixes in their canonical form, by the rule, so the same fixes rank the same in any
    /// arrival order.
    fn normalize(&mut self) {
        let mut fixes = std::mem::take(&mut self.fixes);
        fixes.append(&mut self.refused);
        let mut kept: Vec<Fix> = Vec::with_capacity(fixes.len());
        for fix in fixes {
            match kept.iter_mut().find(|held| held.input_set == fix.input_set) {
                Some(held) => held.engines.extend(fix.engines),
                None => kept.push(fix),
            }
        }
        let decision = decide(&kept);
        let mut contests: Vec<Contest> = decision
            .refusals
            .iter()
            .filter_map(|refusal| {
                match superset_verdict(&kept[refusal.kept], &kept[refusal.refused]) {
                    SupersetVerdict::Contested(contest) => Some(contest),
                    SupersetVerdict::Agrees => None,
                }
            })
            .collect();
        contests.sort_by_key(|contest| (contest.refused, contest.kept));
        contests.truncate(ALTERNATIVES);
        let mut refused: Vec<Fix> = decision
            .refusals
            .iter()
            .map(|refusal| kept[refusal.refused].clone())
            .collect();
        refused.sort_by_key(|fix| fix.input_set);
        refused.truncate(ALTERNATIVES);
        self.contests = contests;
        self.refused = refused;
        self.fixes = decision
            .ranked
            .iter()
            .take(ALTERNATIVES + 1)
            .map(|at| kept[*at].clone())
            .collect();
    }
}

/// Where a provisional fix stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// No final fix has confirmed it yet.
    Waiting,
    /// A final fix of the aircraft near it in time puts it inside its gate.
    Confirmed,
}

/// A provisional fix held, and where it stands.
#[derive(Clone, Debug, PartialEq)]
pub struct Provisional {
    pub fix: Fix,
    pub standing: Standing,
    /// The client's clock past which, still waiting, it is retracted.
    pub deadline_ms: u64,
}

/// An aircraft's most recent final transmissions, oldest first by their current fix's transmit
/// time, at most `TRANSMISSIONS`, and its provisional fixes not yet superseded, oldest first, at
/// most `PROVISIONALS_PER_AIRCRAFT`. Never both empty.
#[derive(Clone, Debug, PartialEq)]
pub struct Track {
    pub address: u32,
    pub transmissions: Vec<Transmission>,
    pub provisional: Vec<Provisional>,
}

impl Track {
    fn new(address: u32) -> Self {
        Self {
            address,
            transmissions: Vec::new(),
            provisional: Vec::new(),
        }
    }

    /// The aircraft's latest final position: the latest transmission's fix.
    pub fn current(&self) -> Option<&Fix> {
        self.latest().map(Transmission::current)
    }

    pub fn latest(&self) -> Option<&Transmission> {
        self.transmissions.last()
    }

    /// What is served for the aircraft: its latest final fix, unless a provisional one not
    /// superseded is later by transmit time.
    pub fn served(&self) -> Option<&Fix> {
        let provisional = self.provisional.last().map(|held| &held.fix);
        match (self.current(), provisional) {
            (Some(done), Some(early)) if early.transmitted > done.transmitted => Some(early),
            (Some(done), _) => Some(done),
            (None, early) => early,
        }
    }

    fn is_empty(&self) -> bool {
        self.transmissions.is_empty() && self.provisional.is_empty()
    }

    fn arrange(&mut self) {
        self.transmissions
            .retain(|transmission| !transmission.fixes.is_empty());
        self.transmissions.sort_by_key(|transmission| {
            (
                transmission.current().transmitted,
                transmission.current().input_set,
            )
        });
        let extra = self.transmissions.len().saturating_sub(TRANSMISSIONS);
        self.transmissions.drain(..extra);
    }
}

/// What one record did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingested {
    /// Solutions taken: how many changed a track, were duplicates, were dropped (failed a check,
    /// an earlier transmission, a subset), or wait for their model.
    Solutions {
        accepted: usize,
        duplicate: usize,
        dropped: usize,
        pending: usize,
    },
    /// A model summary held.
    Model,
    /// A checked fault proof.
    Fault,
    /// Provisional solutions taken: how many are held, and how many were not (failed a check,
    /// already superseded, a duplicate, over the signer's rate or the bound).
    Provisional {
        accepted: usize,
        dropped: usize,
    },
    Ignored,
}

/// What became of provisional fixes, since the merge began. Every one held ends in exactly one
/// of superseded, confirmed, retracted and forgotten.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProvisionalCounts {
    /// Held.
    pub accepted: u64,
    /// Arrived after a final fix of its transmission: not held.
    pub late: u64,
    /// Replaced by a final fix of the same transmission.
    pub superseded: u64,
    /// By its deadline, put inside its gate by a final fix of the aircraft near it in time.
    pub confirmed: u64,
    /// Neither by its deadline: retracted.
    pub retracted: u64,
    /// Forgotten for room (the aircraft's bound, its track forgotten) or with a faulted engine.
    pub forgotten: u64,
}

/// What a held model summary says, as the merge needs it.
struct Model {
    spec: u16,
    inputs: Hash,
}

/// A model is held by its id and the engine that signed its summary: a summary another key signs
/// naming the same id is that key's claim alone, and counts only for that key's own solutions.
type ModelKey = (Hash, PublicKey);

/// Solutions waiting for their model: specification and solution.
type Waiting = Vec<(u16, TaggedSolution)>;

pub struct Merge {
    settings: Settings,
    tracks: Bounded<u32, Track>,
    models: Bounded<ModelKey, Model>,
    pending: Bounded<ModelKey, Waiting>,
    faulted: Bounded<PublicKey, ()>,
    /// Every provisional fix held, by (deadline, aircraft, input set): what `expire` walks.
    deadlines: BTreeSet<(u64, u32, Hash)>,
    /// Provisional fixes each signer had retracted.
    retracted: Bounded<PublicKey, u64>,
    counts: ProvisionalCounts,
    /// Supersets refused for disagreeing with a smaller fix, since the merge began.
    contested: u64,
}

#[derive(Default)]
struct Tally {
    accepted: usize,
    duplicate: usize,
    dropped: usize,
    pending: usize,
}

enum Merged {
    Changed,
    /// A superset that disagreed with a smaller fix: refused, kept as evidence.
    Contested,
    Duplicate,
    Dropped,
}

impl Merge {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            tracks: Bounded::new(settings.max_aircraft),
            models: Bounded::new(settings.max_models),
            pending: Bounded::new(settings.max_pending),
            faulted: Bounded::new(settings.max_faulted),
            deadlines: BTreeSet::new(),
            retracted: Bounded::new(settings.max_faulted),
            counts: ProvisionalCounts::default(),
            contested: 0,
        }
    }

    /// What became of provisional fixes so far.
    pub fn provisional_counts(&self) -> ProvisionalCounts {
        self.counts
    }

    /// Lets the caller's clock move to `now_ms` with no record: provisional fixes past their
    /// deadline are retracted.
    pub fn tick(&mut self, now_ms: u64) {
        self.expire(now_ms);
    }

    /// Supersets refused for disagreeing with a smaller fix of their transmission, since the merge
    /// began: each a fault, kept as evidence (`Transmission::contests`).
    pub fn contested(&self) -> u64 {
        self.contested
    }

    /// How many of `engine`'s provisional fixes were retracted: what a client may weigh an
    /// engine's provisionals by.
    pub fn retractions(&self, engine: &PublicKey) -> u64 {
        self.retracted.get(engine).copied().unwrap_or(0)
    }

    pub fn settings(&self) -> Settings {
        self.settings
    }

    pub fn track(&self, address: u32) -> Option<&Track> {
        self.tracks.get(&address)
    }

    /// Every track, in address order.
    pub fn tracks(&self) -> Vec<&Track> {
        let mut tracks: Vec<&Track> = self.tracks.values().collect();
        tracks.sort_by_key(|track| track.address);
        tracks
    }

    /// Whether the merge holds `solution` as a final fix of its aircraft: it passed every check
    /// and the rule keeps it (ranked, not refused, dominated or dropped). A client that credits
    /// anyone for a published position asks this, never the record alone.
    pub fn holds(&self, solution: &TaggedSolution) -> bool {
        self.tracks.get(&solution.address).is_some_and(|track| {
            track.transmissions.iter().any(|transmission| {
                transmission.fixes.iter().any(|fix| {
                    fix.kind == Kind::Final
                        && fix.model == solution.clock_model
                        && fix.observations == solution.observations
                })
            })
        })
    }

    pub fn is_faulted(&self, engine: &PublicKey) -> bool {
        self.faulted.get(engine).is_some()
    }

    /// Models held.
    pub fn models(&self) -> usize {
        self.models.len()
    }

    /// Takes one record a relay delivered. `now_ms` is the client's wall clock, which decides
    /// only when a provisional fix's deadline has passed. An error is a record that claimed to be
    /// signed and is not.
    pub fn ingest(&mut self, record: &ClientRecord, now_ms: u64) -> Result<Ingested, String> {
        self.tick(now_ms);
        match record {
            ClientRecord::ClockModel(model) => self.model(model),
            ClientRecord::Positions(positions) => self.positions(positions.get()),
            ClientRecord::Provisional(positions) => {
                self.provisional_positions(positions.get(), now_ms)
            }
            ClientRecord::FaultProof(proof) => Ok(self.fault_proof(proof)),
            _ => Ok(Ingested::Ignored),
        }
    }

    fn model(&mut self, model: &ClientClockModel) -> Result<Ingested, String> {
        let engine = model.signer().map_err(|error| error.to_string())?;
        model
            .verify()
            .map_err(|error| format!("clock model of {engine}: {error}"))?;
        if self.is_faulted(&engine) {
            return Ok(Ingested::Ignored);
        }
        let Ok(content) = model.content() else {
            return Ok(Ingested::Ignored);
        };
        let key = (content.model, engine);
        self.models.insert_active(
            key,
            Model {
                spec: content.spec_version,
                inputs: content.inputs,
            },
        );
        if let Some(waiting) = self.pending.remove(&key) {
            for (spec, solution) in waiting {
                self.solution(engine, spec, solution, &mut Tally::default());
            }
        }
        Ok(Ingested::Model)
    }

    fn positions(&mut self, positions: &Positions) -> Result<Ingested, String> {
        let engine = positions.engine().map_err(|error| error.to_string())?;
        positions
            .verify()
            .map_err(|error| format!("positions of {engine}: {error}"))?;
        if self.is_faulted(&engine) || positions.is_provisional() {
            return Ok(Ingested::Ignored);
        }
        let Ok(content) = positions.tagged_solutions() else {
            return Ok(Ingested::Ignored);
        };
        let mut tally = Tally::default();
        for solution in content.solutions {
            self.solution(engine, content.spec_version, solution, &mut tally);
        }
        Ok(Ingested::Solutions {
            accepted: tally.accepted,
            duplicate: tally.duplicate,
            dropped: tally.dropped,
            pending: tally.pending,
        })
    }

    fn solution(
        &mut self,
        engine: PublicKey,
        spec: u16,
        solution: TaggedSolution,
        tally: &mut Tally,
    ) {
        let key = (solution.clock_model, engine);
        if self.models.get(&key).is_none() {
            // Its model is on its way by another path, or never coming: held a while, bounded.
            match self.pending.get_mut(&key) {
                Some(waiting) if waiting.len() < PENDING_PER_MODEL => {
                    waiting.push((spec, solution))
                }
                Some(_) => {
                    tally.dropped += 1;
                    return;
                }
                None => {
                    self.pending.insert_active(key, vec![(spec, solution)]);
                }
            }
            tally.pending += 1;
            return;
        }
        match self.check(engine, spec, &solution, Kind::Final) {
            Some(fix) => {
                let settled = fix.clone();
                match self.merge(fix) {
                    Merged::Changed => tally.accepted += 1,
                    Merged::Duplicate => tally.duplicate += 1,
                    Merged::Dropped => tally.dropped += 1,
                    Merged::Contested => {
                        // Refused: it supersedes and confirms nothing.
                        tally.dropped += 1;
                        return;
                    }
                }
                self.supersede(&settled);
            }
            None => tally.dropped += 1,
        }
    }

    fn provisional_positions(
        &mut self,
        positions: &Positions,
        now_ms: u64,
    ) -> Result<Ingested, String> {
        let engine = positions.engine().map_err(|error| error.to_string())?;
        positions
            .verify()
            .map_err(|error| format!("provisional positions of {engine}: {error}"))?;
        if self.is_faulted(&engine) || !positions.is_provisional() {
            return Ok(Ingested::Ignored);
        }
        let Ok(content) = positions.tagged_solutions() else {
            return Ok(Ingested::Ignored);
        };
        let (mut accepted, mut dropped) = (0, 0);
        for solution in content.solutions {
            let checked = self.check(engine, content.spec_version, &solution, Kind::Provisional);
            let held = checked.is_some_and(|fix| self.hold_provisional(fix, engine, now_ms));
            if held {
                accepted += 1;
            } else {
                dropped += 1;
            }
        }
        Ok(Ingested::Provisional { accepted, dropped })
    }

    /// Holds a checked provisional fix (crate docs, § Provisional fixes). True when it is held.
    fn hold_provisional(&mut self, fix: Fix, engine: PublicKey, now_ms: u64) -> bool {
        if self.deadlines.len() >= self.settings.max_provisional {
            return false;
        }
        let address = fix.address;
        let (superseded, confirmed) = match self.tracks.get(&address) {
            Some(track) => {
                let finals = || track.transmissions.iter().flat_map(|held| &held.fixes);
                (
                    finals().any(|held| same_transmission(held, &fix)),
                    finals().any(|held| agree(held, &fix)),
                )
            }
            None => (false, false),
        };
        if superseded {
            self.counts.late += 1;
            return false;
        }
        if self.tracks.get(&address).is_none() {
            self.tracks.insert_active(address, Track::new(address));
        }
        let Some(track) = self.tracks.get_mut(&address) else {
            return false;
        };
        if let Some(same) = track
            .provisional
            .iter_mut()
            .find(|held| held.fix.input_set == fix.input_set)
        {
            same.fix.engines.extend(fix.engines);
            return false;
        }
        let second = fix.transmitted.unix_ms / 1000;
        let from_signer = track
            .provisional
            .iter()
            .filter(|held| {
                held.fix.engines.contains(&engine) && held.fix.transmitted.unix_ms / 1000 == second
            })
            .count();
        if from_signer >= PROVISIONAL_PER_SECOND {
            if track.is_empty() {
                self.tracks.remove(&address);
            }
            return false;
        }
        let deadline_ms = now_ms.saturating_add(PROVISIONAL_DEADLINE_MS);
        let input_set = fix.input_set;
        track.provisional.push(Provisional {
            fix,
            standing: if confirmed {
                Standing::Confirmed
            } else {
                Standing::Waiting
            },
            deadline_ms,
        });
        track
            .provisional
            .sort_by_key(|held| (held.fix.transmitted, held.fix.input_set));
        let extra = track
            .provisional
            .len()
            .saturating_sub(PROVISIONALS_PER_AIRCRAFT);
        let forgotten: Vec<Provisional> = track.provisional.drain(..extra).collect();
        self.counts.accepted += 1;
        let kept = forgotten.iter().all(|gone| gone.fix.input_set != input_set);
        for gone in forgotten {
            self.deadlines
                .remove(&(gone.deadline_ms, address, gone.fix.input_set));
            self.counts.forgotten += 1;
        }
        self.tracks.touch(&address);
        if kept {
            self.deadlines.insert((deadline_ms, address, input_set));
        }
        kept
    }

    /// A final fix arrived: the provisional fixes of its transmission are superseded, and those of
    /// its aircraft it agrees with confirmed.
    fn supersede(&mut self, settled: &Fix) {
        let address = settled.address;
        let Some(track) = self.tracks.get_mut(&address) else {
            return;
        };
        let mut superseded = Vec::new();
        for (at, held) in track.provisional.iter_mut().enumerate() {
            if same_transmission(settled, &held.fix) {
                superseded.push(at);
            } else if held.standing == Standing::Waiting && agree(settled, &held.fix) {
                held.standing = Standing::Confirmed;
            }
        }
        for at in superseded.into_iter().rev() {
            let gone = track.provisional.remove(at);
            self.deadlines
                .remove(&(gone.deadline_ms, address, gone.fix.input_set));
            self.counts.superseded += 1;
        }
    }

    /// Provisional fixes whose deadline has passed by `now_ms`: one still waiting is retracted,
    /// and counted against its signers; one confirmed is let go.
    fn expire(&mut self, now_ms: u64) {
        while let Some(first) = self.deadlines.first().copied() {
            let (deadline_ms, address, input_set) = first;
            if deadline_ms > now_ms {
                return;
            }
            self.deadlines.remove(&first);
            let found = self.tracks.get_mut(&address).and_then(|track| {
                let at = track
                    .provisional
                    .iter()
                    .position(|held| held.fix.input_set == input_set)?;
                Some((track.provisional.remove(at), track.is_empty()))
            });
            let Some((gone, empty)) = found else {
                // Its track was forgotten for room.
                self.counts.forgotten += 1;
                continue;
            };
            if empty {
                self.tracks.remove(&address);
            }
            if gone.standing == Standing::Confirmed {
                self.counts.confirmed += 1;
                continue;
            }
            self.counts.retracted += 1;
            for engine in gone.fix.engines {
                let count = self.retracted.get(&engine).copied().unwrap_or(0) + 1;
                self.retracted.insert_active(engine, count);
            }
        }
    }

    /// The solution as a fix, if it passes every check a client can make (crate docs): its model
    /// summary held, signed by its own engine and of its specification, and its message naming its
    /// aircraft.
    fn check(
        &mut self,
        engine: PublicKey,
        spec: u16,
        wire: &TaggedSolution,
        kind: Kind,
    ) -> Option<Fix> {
        let key = (wire.clock_model, engine);
        self.models.touch(&key);
        let model = self.models.get(&key)?;
        if model.spec != spec {
            return None;
        }
        let message = wire.observations.message();
        if modes::address(message) != Some(wire.address) {
            return None;
        }
        let inputs = model.inputs;
        Some(Fix {
            kind,
            address: wire.address,
            transmitted: wire.transmitted,
            lat_e7: wire.lat_e7,
            lon_e7: wire.lon_e7,
            alt_hae_mm: wire.alt_hae_mm,
            altitude_ft: barometric_ft(message),
            horizontal_sigma_m: horizontal_sigma_m(&wire.covariance),
            covariance: wire.covariance,
            input_set: input_set(&wire.observations, &inputs),
            observations: wire.observations.clone(),
            model: wire.clock_model,
            model_inputs: inputs,
            weight: wire.observations.tags().len() as u64,
            engines: [engine].into_iter().collect(),
        })
    }

    fn merge(&mut self, fix: Fix) -> Merged {
        let address = fix.address;
        let Some(track) = self.tracks.get_mut(&address) else {
            let mut track = Track::new(address);
            track.transmissions.push(Transmission::new(fix));
            self.tracks.insert_active(address, track);
            return Merged::Changed;
        };
        // The held transmissions it shares a tag with; it joins one only when exactly one.
        let tied: Vec<usize> = track
            .transmissions
            .iter()
            .enumerate()
            .filter(|(_, transmission)| {
                transmission
                    .fixes
                    .iter()
                    .any(|held| same_transmission(held, &fix))
            })
            .map(|(at, _)| at)
            .collect();
        let [at] = tied.as_slice() else {
            // A transmission not held: one more, the oldest forgotten beyond the bound.
            let input_set = fix.input_set;
            track.transmissions.push(Transmission::new(fix));
            track.arrange();
            let kept = track
                .transmissions
                .iter()
                .any(|transmission| transmission.current().input_set == input_set);
            self.tracks.touch(&address);
            return if kept {
                Merged::Changed
            } else {
                Merged::Dropped
            };
        };
        let transmission = &mut track.transmissions[*at];
        if let Some(same) = transmission
            .fixes
            .iter_mut()
            .find(|held| held.input_set == fix.input_set)
        {
            same.engines.extend(fix.engines);
            return Merged::Duplicate;
        }
        let before = transmission.current().input_set;
        let input_set = fix.input_set;
        let was_refused: BTreeSet<Hash> = transmission
            .refused
            .iter()
            .map(|held| held.input_set)
            .collect();
        transmission.fixes.push(fix);
        transmission.normalize();
        self.contested += transmission
            .refused
            .iter()
            .filter(|held| !was_refused.contains(&held.input_set))
            .count() as u64;
        let changed = transmission.current().input_set != before;
        let kept = transmission
            .fixes
            .iter()
            .any(|held| held.input_set == input_set);
        let refused = transmission
            .refused
            .iter()
            .any(|held| held.input_set == input_set);
        track.arrange();
        self.tracks.touch(&address);
        if refused {
            Merged::Contested
        } else if changed || kept {
            Merged::Changed
        } else {
            Merged::Dropped
        }
    }

    /// Whether two fixes are of one transmission (crate docs, § Solutions merge per
    /// transmission): one aircraft, the same bytes, and a tag in common.
    pub fn same_transmission(&self, a: &Fix, b: &Fix) -> bool {
        same_transmission(a, b)
    }

    fn fault_proof(&mut self, proof: &ClientFaultProof) -> Ingested {
        let proof = proof.get();
        let Some(tolerance) = proof.spec_version().ok().and_then(Tolerance::for_spec) else {
            return Ingested::Ignored;
        };
        let Ok(fault) = proof.check(&tolerance) else {
            return Ingested::Ignored;
        };
        for engine in fault.engines() {
            self.convict(engine);
        }
        Ingested::Fault
    }

    /// Marks `engine` faulted and drops everything that stands on its word alone.
    fn convict(&mut self, engine: PublicKey) {
        self.faulted.insert_active(engine, ());
        let models: Vec<ModelKey> = self
            .models
            .iter()
            .filter(|((_, signer), _)| *signer == engine)
            .map(|(key, _)| *key)
            .collect();
        for key in models {
            self.models.remove(&key);
        }
        let addresses: Vec<u32> = self.tracks.iter().map(|(address, _)| *address).collect();
        for address in addresses {
            let Some(track) = self.tracks.get_mut(&address) else {
                continue;
            };
            for transmission in &mut track.transmissions {
                let stands = |fix: &mut Fix| {
                    fix.engines.remove(&engine);
                    !fix.engines.is_empty()
                };
                transmission.fixes.retain_mut(stands);
                transmission.refused.retain_mut(stands);
                transmission.normalize();
            }
            let before = track.provisional.len();
            let deadlines = &mut self.deadlines;
            track.provisional.retain_mut(|held| {
                held.fix.engines.remove(&engine);
                let stands = !held.fix.engines.is_empty();
                if !stands {
                    deadlines.remove(&(held.deadline_ms, address, held.fix.input_set));
                }
                stands
            });
            self.counts.forgotten += (before - track.provisional.len()) as u64;
            track.arrange();
            if track.is_empty() {
                self.tracks.remove(&address);
            }
        }
    }
}

/// Whether two fixes are of one transmission: one aircraft, the same bytes, a tag in common.
fn same_transmission(a: &Fix, b: &Fix) -> bool {
    a.address == b.address
        && a.observations.message() == b.observations.message()
        && in_common(&a.observations, &b.observations)
}

/// Which of two fixes of one transmission ranks first, by the rule
/// (`tally_mlat_solver::standing::rank`).
#[cfg(test)]
fn order(a: &Fix, b: &Fix) -> std::cmp::Ordering {
    a.rank().cmp(&b.rank())
}

/// Whether a final fix confirms a provisional one (crate docs, § Provisional fixes): one aircraft,
/// transmit times within `CONFIRM_WITHIN_MS`, and the provisional inside the final's gate:
/// `CONFIRM_GATE` under the two horizontal covariances summed plus the distance the aircraft may
/// have moved.
fn agree(settled: &Fix, early: &Fix) -> bool {
    if settled.address != early.address {
        return false;
    }
    let apart_ms = settled
        .transmitted
        .unix_ms
        .abs_diff(early.transmitted.unix_ms);
    if apart_ms > CONFIRM_WITHIN_MS {
        return false;
    }
    let lat = f64::from(settled.lat_e7) * 1e-7;
    let north = f64::from(early.lat_e7 - settled.lat_e7) * 1e-7 * 111_132.0;
    let mut lon = (i64::from(early.lon_e7) - i64::from(settled.lon_e7)) as f64 * 1e-7;
    if lon > 180.0 {
        lon -= 360.0;
    } else if lon < -180.0 {
        lon += 360.0;
    }
    let east = lon * 111_320.0 * libm::cos(lat.to_radians());
    let moved = CONFIRM_SPEED_M_PER_S * (apart_ms as f64 / 1000.0 + 1.0);
    let (a, b) = (&settled.covariance, &early.covariance);
    let xx = f64::from(a.xx) + f64::from(b.xx) + moved * moved;
    let yy = f64::from(a.yy) + f64::from(b.yy) + moved * moved;
    let xy = f64::from(a.xy) + f64::from(b.xy);
    let determinant = xx * yy - xy * xy;
    if determinant <= 0.0 {
        return false;
    }
    let distance = (yy * east * east - 2.0 * xy * east * north + xx * north * north) / determinant;
    distance <= CONFIRM_GATE
}

/// The full input set's identity: BLAKE2s-256 over `"tally merge input set" 0x00`, the tag set
/// hash and the model inputs hash (the rule's).
pub fn input_set(observations: &TaggedSet, model_inputs: &Hash) -> Hash {
    tally_wire::products::input_set(observations, model_inputs)
}

/// The root of half the trace of the east-north covariance, metres.
pub fn horizontal_sigma_m(covariance: &tally_wire::EnuCovariance) -> f64 {
    (0.5 * (f64::from(covariance.xx) + f64::from(covariance.yy)))
        .max(0.0)
        .sqrt()
}

fn barometric_ft(message: &[u8]) -> Option<i32> {
    modes::altitude(message)
        .filter(|altitude| altitude.kind == modes::AltitudeKind::Barometric)
        .map(|altitude| altitude.feet)
}

#[cfg(test)]
mod tests;
