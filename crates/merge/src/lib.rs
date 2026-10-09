//! THE CLIENT MERGE RULE (RFC-0171 §3.8.1), implemented once for every client: whoever reads
//! the positions and clock model streams of any number of engines, through any number of relays,
//! holds one current solution per aircraft here, and holds it the same whatever order the records
//! arrived in and however many copies of each did.
//!
//! What it takes: `Positions` (format 3), provisional positions (`Record::Provisional`), tile
//! `ClockModel` manifests and their
//! `ClockModelPart`s, `FaultProof`s, and, when the client subscribes raw (`Settings::raw`),
//! receivers' signed `Batch`es and `ReceiverInfo`s. What it holds per aircraft is a [`Track`]: its latest transmissions, each with the
//! [`Fix`] kept and the alternatives it was preferred to.
//!
//! - **Every solution is checked against the model it cites before it counts.** The model must be
//!   held, reassembled and checked part by part against its signed manifest (`Assembler`), read
//!   under the specification it names, and its manifest's inputs hash must be the hash of what the
//!   decoded model says it is a function of. The solution's message must name its aircraft,
//!   every reception it cites must be of a member of the model's tile, and it must read back as a
//!   claim under the model. That is the check without raw: signatures and content addresses
//!   only, and the fix says so ([`Check::Signature`]). When the client holds the raw the model
//!   was fitted from (it rebuilds the tile's members and input citation from its own raw and the
//!   receivers' descriptions, and they are the model's exactly), the model is verified by the
//!   model verifier, once; every solution under it by the solution verifier against the
//!   client's own receptions, and by the assignment check (its tile is the one the rule gives
//!   the aircraft, from the client's raw); a model or a solution that fails is dropped
//!   ([`Check::Model`]). A client whose raw does not reproduce the citation (or the solution's
//!   addressed citation) does not hold that raw, and falls back to the signature check. Bins are
//!   sealed when a model of their window is checked: its engine solved it, so its raw is in.
//! - **Solutions merge per transmission, and only on evidence** (`Merge::same_transmission`). Two
//!   solutions are of one transmission when they name one aircraft with the same message bytes
//!   and either share a reception, or are tied through a clock model: a receiver one solution
//!   cites is a clock of the other's model, which maps that reception to its own model time, and
//!   less the range from the other's position that is the other's transmit time within
//!   `TIE_NS` (every such receiver agreeing). A receiver in both with no reception in common heard
//!   two transmissions. Nothing else joins: not transmit times, which two models state on origins
//!   that agree only as well as their gauges' wall clocks (0.9 s apart in the simulator), and not
//!   the bytes, which a Mode S reply (DF4, 5, 11, 20, 21) repeats exactly milliseconds apart to
//!   another interrogator (a false join is invisible to any chi-square: each side fits itself).
//!   A solution tied to more than one held transmission joins none. What is lost: two engines
//!   whose solutions share no reception and no receiver of either's model are never merged, and
//!   the aircraft's track holds both as separate transmissions (its current position is then the
//!   latest by transmit time, which is the one place a transmit time across models is compared).
//!   An aircraft's track holds its latest `TRANSMISSIONS` transmissions; its current position is
//!   the latest one's fix.
//! - **Within one transmission, by the full input set** (the observation set and the cited model's
//!   inputs hash together): the same set is a duplicate, dropped, its signer added to the fix's
//!   engines; a superset of observations wins only if it agrees with the smaller fix within the
//!   smaller's covariance (RFC-0174 §2.12, `tally_mlat_solver::standing::decide`): one that does
//!   not is contested, a fault, never the answer, kept as evidence (`Transmission::refused`,
//!   `Transmission::contests`, `Merge::contested`) while the smaller stands, and only a smaller fix
//!   consistent with its own receptions refuses anything (`Fix::consistent`); with the same model
//!   inputs, an agreeing superset drops the subset; anything else is incomparable and never
//!   averaged. Holding the raw of both, the client solves
//!   the transmission itself from its raw, the aircraft's tile by the assignment rule
//!   ([`Check::Resolved`]). Otherwise the one
//!   that ranks first is kept and the other recorded as an alternative.
//! - **The rule ranks by standing, then the tie rule** (RFC-0174 §2.12): first by the standing of
//!   the solution's receivers (`Fix::standing`, from the client's `StandingLedger`, so ten new
//!   keys add nothing), then by weight (the observations the solution cites plus the input count
//!   of its model's citation), then by the lowest input set hash (`input_set`). A position fewer
//!   than the solver's minimum of whose receivers have standing is labelled
//!   `Confidence::Unconfirmed`. Standing is a function of the public records, so clients holding
//!   the same records keep the same one.
//! - **A fault proof convicts its signers.** A checked `FaultProof` (two solutions of one
//!   observation set under one model that disagree; two different models of one inputs are no
//!   fault from specification version 3, where optimality, not bytes, is the rule) marks each
//!   engine it names as
//!   faulted: what it signed is dropped from every track (a fix any other engine also signed
//!   stands on that engine's word; a transmission whose fix is dropped keeps its best alternative), its
//!   models are forgotten, and nothing it signs later counts.
//! - **Provisional fixes** (`Record::Provisional`) are checked as a final solution is without raw
//!   (their model held and whole, their receptions its members, a claim under it read back:
//!   [`Check::Signature`]; the raw the model was fitted from cannot reach receptions newer than
//!   its window) and held apart from the final transmissions, per aircraft, at most
//!   `PROVISIONAL_PER_SECOND` a signer a second of transmit time and `PROVISIONALS_PER_AIRCRAFT`
//!   in all. What is served ([`Track::served`]) is the latest final fix, unless a provisional one
//!   is later by transmit time. A final fix of the same transmission (`same_transmission`)
//!   supersedes a provisional one, which is then forgotten (one arriving after it is not held); a
//!   final fix of the aircraft within `CONFIRM_WITHIN_MS` that puts it inside `CONFIRM_GATE` (both
//!   horizontal covariances and `CONFIRM_SPEED_M_PER_S` of motion) confirms it. A client learns
//!   of a retraction by the deadline rule, needing no message: one neither superseded nor
//!   confirmed `PROVISIONAL_DEADLINE_MS` after it arrived, by the client's clock, is retracted,
//!   forgotten and counted against its signers ([`Merge::retractions`]). Each fix held ends
//!   superseded, confirmed, retracted or forgotten ([`ProvisionalCounts`]).
//! - **Memory is bounded**, every table least-recently-active first (the relay's `Bounded`):
//!   tracks, models, solutions waiting for their model, faulted keys, receiver descriptions and
//!   resolved fits by count, and raw (`Held`) by bytes, forgotten by bin as the caller's clock
//!   moves on.

pub mod link;
pub mod standing;

pub use standing::{Confidence, Contest, StandingLedger, SupersetVerdict, superset_verdict};

use std::collections::BTreeSet;
use std::sync::Arc;

use tally_mlat_solver::held::Held;
use tally_mlat_solver::obs::message_hash;
use tally_mlat_solver::scope::{AFTER, BEFORE, STRIDE, Sites, Window, WindowIndex, bin_of};
use tally_mlat_solver::standing::{Candidate, Claimed, Solved, consistent, decide};
use tally_mlat_solver::{
    Calibrated, ObservationId, Reach, Site, Tile, modes, publish, verify, verify_model,
};
use tally_relay::bounded::Bounded;
use tally_wire::batch::Hash;
use tally_wire::clock_model::Assembler;
use tally_wire::{
    ClockModel, FaultProof, ObservationSet, Positions, PublicKey, Record, Relation, Tolerance,
    TransmitTime,
};

/// How closely a reception mapped through another solution's clock model must put that solution's
/// transmit time for the two to be tied: well above two honest models' disagreement (clock error
/// of tens of nanoseconds, and the two positions' difference in range, a few hundred metres),
/// and a thousandth of the closest two Mode S replies to different interrogators come.
pub const TIE_NS: u64 = 2_000;
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
/// Bins of raw kept behind the caller's clock beyond a canonical window, for the settling time and
/// a relay's delay.
const RAW_SPARE_BINS: i64 = 4;

/// How much the client holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The client also subscribes raw, and verifies and re-solves from it.
    pub raw: bool,
    pub max_aircraft: usize,
    pub max_models: usize,
    /// Bytes of clock model parts waiting for their manifest.
    pub max_model_bytes: usize,
    /// Models solutions are waiting for.
    pub max_pending: usize,
    pub max_faulted: usize,
    /// Bytes of raw held, when `raw` (`tally_mlat_solver::held`).
    pub max_held: usize,
    /// Receivers whose descriptions are held, when `raw`.
    pub max_receivers: usize,
    /// Fits of unions the client solved itself, remembered.
    pub max_resolved: usize,
    /// Provisional fixes held in all, waiting for a final one.
    pub max_provisional: usize,
}

impl Settings {
    pub fn new(raw: bool) -> Self {
        Self {
            raw,
            max_aircraft: 65_536,
            max_models: 16_384,
            max_model_bytes: 64 << 20,
            max_pending: 1_024,
            max_faulted: 4_096,
            max_held: 4 << 30,
            max_receivers: 32_768,
            max_resolved: 1_024,
            max_provisional: 262_144,
        }
    }
}

/// How a fix was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Check {
    /// The model by the model verifier and the solution by the solution verifier, from the
    /// client's own raw.
    Model,
    /// Signatures and content addresses only: the client does not hold the model's raw.
    Signature,
    /// The client solved the union of incomparable solutions itself, from its own raw.
    Resolved,
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
    pub observations: ObservationSet,
    /// The cited model's id (`ClockModel::id`); a resolved fix's own model's inputs hash.
    pub model: Hash,
    /// The cited model's inputs hash (`Manifest::inputs`).
    pub model_inputs: Hash,
    /// BLAKE2s-256 over `"tally merge input set" 0x00`, the observation set hash and the model
    /// inputs hash: the full input set's identity.
    pub input_set: Hash,
    /// Observations cited plus the model citation's input count.
    pub weight: u64,
    pub check: Check,
    /// The engines that signed it (and the model it cites); none for a resolved fix.
    pub engines: BTreeSet<PublicKey>,
    /// Its receptions' receivers' standing at its transmit time, thousandths summed, as the
    /// merge's ledger holds it now (re-read whenever a receiver it cites changes standing, never
    /// frozen when the fix arrived): what it ranks by before its count (RFC-0174 §2.12).
    pub standing: u64,
    /// Whether its receivers carry it, as the ledger holds it now: an `Unconfirmed` position is
    /// drawn labelled so. A fix not consistent with its own receptions is always unconfirmed.
    pub confidence: Confidence,
    /// Whether it agrees with its own receptions under its own model, which anyone can tell
    /// without raw (`tally_mlat_solver::standing::consistent`). Only a consistent fix refuses a
    /// superset that disagrees with it.
    pub consistent: bool,
}

impl Fix {
    /// The rule's order (`tally_mlat_solver::standing::rank`): resolved first, then standing,
    /// then the tie rule's weight, then the lowest input set hash. The less ranks first.
    #[cfg(test)]
    fn rank(&self) -> (bool, std::cmp::Reverse<u64>, std::cmp::Reverse<u64>, Hash) {
        tally_mlat_solver::standing::rank(self)
    }

    /// Whether it cites a reception of one of `receivers`.
    fn cites(&self, receivers: &BTreeSet<PublicKey>) -> bool {
        self.observations
            .receptions()
            .iter()
            .any(|reception| receivers.contains(&reception.receiver))
    }

    /// Its position, ECEF metres, when it states a height.
    fn ecef(&self) -> Option<[f64; 3]> {
        Some(tally_mlat_solver::geo::to_ecef(
            tally_mlat_solver::geo::Geodetic {
                lat_deg: f64::from(self.lat_e7) * 1e-7,
                lon_deg: f64::from(self.lon_e7) * 1e-7,
                height_m: f64::from(self.alt_hae_mm?) / 1000.0,
            },
        ))
    }
}

impl Candidate for Fix {
    fn observations(&self) -> &ObservationSet {
        &self.observations
    }

    fn model_inputs(&self) -> &Hash {
        &self.model_inputs
    }

    fn claimed(&self) -> Claimed {
        standing::claimed(self)
    }

    fn standing(&self) -> u64 {
        self.standing
    }

    fn weight(&self) -> u64 {
        self.weight
    }

    fn identity(&self) -> Hash {
        self.input_set
    }

    fn consistent(&self) -> bool {
        self.consistent
    }

    fn preferred(&self) -> bool {
        self.check == Check::Resolved
    }
}

/// Whether the two share a reception, and whether a receiver is in both.
fn in_common(a: &ObservationSet, b: &ObservationSet) -> (bool, bool) {
    let theirs = b.receptions();
    let mut receiver = false;
    for reception in a.receptions() {
        if theirs.contains(reception) {
            return (true, true);
        }
        receiver |= theirs
            .iter()
            .any(|other| other.receiver == reception.receiver && other.epoch == reception.epoch);
    }
    (false, receiver)
}

/// The solutions of one transmission the merge holds, as the rule decides them
/// (`tally_mlat_solver::standing::decide`, RFC-0174 §2.12): none dominated by another (the same
/// model's inputs and a subset of an agreeing superset's observations), none refused (a superset
/// that disagrees with a smaller fix: contested, a fault, never the answer), best first by `order`,
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
    fn new(fix: Fix, ledger: &StandingLedger) -> Self {
        let mut transmission = Self {
            fixes: vec![fix],
            refused: Vec::new(),
            contests: Vec::new(),
        };
        transmission.normalize(ledger);
        transmission
    }

    /// Whether a fix it holds (kept or refused) cites a reception of one of `receivers`.
    fn cites(&self, receivers: &BTreeSet<PublicKey>) -> bool {
        self.fixes
            .iter()
            .chain(&self.refused)
            .any(|fix| fix.cites(receivers))
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

    /// Puts the fixes in their canonical form, by the rule, each weighed by its receivers'
    /// standing as `ledger` holds it now (never as it was when the fix arrived), so the same fixes
    /// under the same ledger rank the same in any arrival order.
    fn normalize(&mut self, ledger: &StandingLedger) {
        let mut fixes = std::mem::take(&mut self.fixes);
        fixes.append(&mut self.refused);
        let mut kept: Vec<Fix> = Vec::with_capacity(fixes.len());
        for fix in fixes {
            match kept.iter_mut().find(|held| held.input_set == fix.input_set) {
                Some(held) => held.engines.extend(fix.engines),
                None => kept.push(fix),
            }
        }
        for fix in &mut kept {
            ledger.weigh(fix);
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
    /// A model completed and held.
    Model,
    /// Raw observations new to the held set.
    Raw {
        new: usize,
    },
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

/// What a held model is and what checking it showed.
struct Model {
    engine: PublicKey,
    spec: u16,
    inputs: Hash,
    decoded: Arc<tally_mlat_solver::ClockModel>,
    raw: RawCheck,
}

enum RawCheck {
    /// Not looked at yet (the raw it needs may still be arriving).
    Unchecked,
    /// The client's raw reproduces the model's inputs and the model verifier passed it.
    Verified(Box<Calibrated>),
    /// The client's raw does not reproduce its inputs.
    NotHeld,
    /// The model verifier failed it: nothing under it counts.
    Failed,
}

/// A tile the client fitted itself from its raw, and what solving under it needs.
struct Resolver {
    model: tally_mlat_solver::ClockModel,
    inputs: Hash,
    calibrated: Calibrated,
}

/// What a resolved fit is keyed by: the tile, its window, and its input citation.
type ResolveKey = (Tile, Window, Hash);

/// Solutions waiting for their model: signer, specification, issue time, solution.
type Waiting = Vec<(PublicKey, u16, u64, tally_wire::Solution)>;

pub struct Merge {
    settings: Settings,
    tracks: Bounded<u32, Track>,
    models: Bounded<Hash, Model>,
    assembler: Assembler,
    pending: Bounded<Hash, Waiting>,
    faulted: Bounded<PublicKey, ()>,
    held: Held,
    /// The receivers described, raw mode only: their newest description's issue time and site.
    sites: Bounded<PublicKey, (u64, Site)>,
    resolved: Bounded<ResolveKey, Option<Resolver>>,
    /// Every provisional fix held, by (deadline, aircraft, input set): what `expire` walks.
    deadlines: BTreeSet<(u64, u32, Hash)>,
    /// Provisional fixes each signer had retracted.
    retracted: Bounded<PublicKey, u64>,
    counts: ProvisionalCounts,
    /// Receivers' standing (RFC-0174 §2.12).
    ledger: StandingLedger,
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
            assembler: Assembler::new(settings.max_model_bytes, settings.max_pending),
            pending: Bounded::new(settings.max_pending),
            faulted: Bounded::new(settings.max_faulted),
            held: Held::new(if settings.raw { settings.max_held } else { 0 }),
            sites: Bounded::new(settings.max_receivers),
            resolved: Bounded::new(settings.max_resolved),
            deadlines: BTreeSet::new(),
            retracted: Bounded::new(settings.max_faulted),
            counts: ProvisionalCounts::default(),
            ledger: StandingLedger::new(settings.max_provisional, settings.max_receivers),
            contested: 0,
        }
    }

    /// What became of provisional fixes so far.
    pub fn provisional_counts(&self) -> ProvisionalCounts {
        self.counts
    }

    /// Lets the caller's clock move to `now_ms` with no record: provisional fixes past their
    /// deadline are retracted, and transmissions due are settled for standing.
    pub fn tick(&mut self, now_ms: u64) {
        self.expire(now_ms);
        let changed = self.ledger.settle(now_ms, &self.held);
        if !changed.is_empty() {
            self.reweigh(&changed);
        }
    }

    /// Every held fix citing one of `receivers`, whose standing just changed, weighed again and
    /// its transmission ranked again: the ranking is a function of the fixes held and the ledger,
    /// never of when either arrived.
    fn reweigh(&mut self, receivers: &BTreeSet<PublicKey>) {
        let addresses: Vec<u32> = self.tracks.iter().map(|(address, _)| *address).collect();
        for address in addresses {
            let Some(track) = self.tracks.get_mut(&address) else {
                continue;
            };
            let mut ranked = false;
            for transmission in &mut track.transmissions {
                if transmission.cites(receivers) {
                    transmission.normalize(&self.ledger);
                    ranked = true;
                }
            }
            for held in &mut track.provisional {
                if held.fix.cites(receivers) {
                    self.ledger.weigh(&mut held.fix);
                }
            }
            if ranked {
                track.arrange();
            }
        }
    }

    /// Receivers' standing as this client reads the records (RFC-0174 §2.12).
    pub fn standing(&self) -> &StandingLedger {
        &self.ledger
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
    pub fn holds(&self, solution: &tally_wire::Solution) -> bool {
        self.tracks.get(&solution.address).is_some_and(|track| {
            track.transmissions.iter().any(|transmission| {
                transmission.fixes.iter().any(|fix| {
                    fix.kind == Kind::Final
                        && fix.check != Check::Resolved
                        && fix.model == solution.clock_model
                        && fix.observations == solution.observations
                })
            })
        })
    }

    /// Whether `reception` of `message`, transmitted at `transmitted_ms`, is in its receiver's
    /// own signed raw as the merge holds it (`Settings::raw`; without raw, never).
    pub fn heard(
        &self,
        reception: &tally_wire::Reception,
        message: &[u8],
        transmitted_ms: u64,
    ) -> bool {
        let id = ObservationId {
            receiver: reception.receiver,
            epoch: reception.epoch,
            timestamp: reception.counter,
            message: message_hash(message),
        };
        tally_mlat_solver::standing::heard_in(&self.held, &id, transmitted_ms).is_some()
    }

    pub fn is_faulted(&self, engine: &PublicKey) -> bool {
        self.faulted.get(engine).is_some()
    }

    /// Raw observations held.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Models held.
    pub fn models(&self) -> usize {
        self.models.len()
    }

    /// Takes one record a relay delivered. `now_ms` is the client's wall clock, which decides
    /// only when raw is forgotten and when a provisional fix's deadline has passed. An error is a record that claimed to be signed and is not.
    pub fn ingest(&mut self, record: &Record, now_ms: u64) -> Result<Ingested, String> {
        self.tick(now_ms);
        match record {
            Record::Batch(batch) if self.settings.raw => {
                let key = batch.receiver().map_err(|error| error.to_string())?;
                batch
                    .verify()
                    .map_err(|error| format!("batch of {key}: {error}"))?;
                let Ok(content) = batch.content() else {
                    return Ok(Ingested::Ignored);
                };
                // Taken in at the client's clock: raw of a bin further ahead of it than
                // `held::AHEAD_MS` is refused here as every relay refuses it by its stamp.
                let added = self.held.add(key, &content, now_ms);
                // Bins are sealed when a model of their window is checked (its engine solved it,
                // so its raw is in); what no window can still need is forgotten.
                self.held
                    .forget_before(bin_of(now_ms) - BEFORE - AFTER - STRIDE - RAW_SPARE_BINS);
                Ok(Ingested::Raw { new: added.new })
            }
            Record::ReceiverInfo(info) if self.settings.raw => {
                let key = info.receiver().map_err(|error| error.to_string())?;
                info.verify()
                    .map_err(|error| format!("receiver info of {key}: {error}"))?;
                let Ok(content) = info.content() else {
                    return Ok(Ingested::Ignored);
                };
                let Some(location) = content.location else {
                    return Ok(Ingested::Ignored);
                };
                if self
                    .sites
                    .get(&key)
                    .is_some_and(|(issued, _)| *issued >= content.issued_ms)
                {
                    return Ok(Ingested::Ignored);
                }
                self.sites.insert_active(
                    key,
                    (
                        content.issued_ms,
                        Site {
                            receiver: key,
                            clock: content.clock,
                            location,
                        },
                    ),
                );
                Ok(Ingested::Ignored)
            }
            Record::ClockModel(model) => {
                let engine = model.engine().map_err(|error| error.to_string())?;
                if self.is_faulted(&engine) {
                    return Ok(Ingested::Ignored);
                }
                match self
                    .assembler
                    .manifest(model.clone())
                    .map_err(|error| format!("clock model of {engine}: {error}"))?
                {
                    Some((manifest, content)) => Ok(self.hold_model(&manifest, content)),
                    None => Ok(Ingested::Ignored),
                }
            }
            Record::ClockModelPart(part) => match self.assembler.part(part.clone()) {
                Some((manifest, content)) => Ok(self.hold_model(&manifest, content)),
                None => Ok(Ingested::Ignored),
            },
            Record::Positions(positions) => self.positions(positions),
            Record::Provisional(positions) => self.provisional_positions(positions, now_ms),
            Record::FaultProof(proof) => Ok(self.fault_proof(proof)),
            _ => Ok(Ingested::Ignored),
        }
    }

    fn hold_model(
        &mut self,
        manifest: &ClockModel,
        content: tally_wire::ClockModelContent,
    ) -> Ingested {
        let Ok(engine) = manifest.engine() else {
            return Ingested::Ignored;
        };
        if self.is_faulted(&engine) {
            return Ingested::Ignored;
        }
        // Read under the specification it names, and it must be a function of what it says.
        let Ok(decoded) = publish::decode(&content.model, content.spec_version) else {
            return Ingested::Ignored;
        };
        if publish::inputs_id(&decoded) != content.inputs {
            return Ingested::Ignored;
        }
        let id = manifest.id();
        self.models.insert_active(
            id,
            Model {
                engine,
                spec: content.spec_version,
                inputs: content.inputs,
                decoded: Arc::new(decoded),
                raw: RawCheck::Unchecked,
            },
        );
        if let Some(waiting) = self.pending.remove(&id) {
            for (engine, spec, issued_ms, solution) in waiting {
                self.solution(engine, spec, issued_ms, solution, &mut Tally::default());
            }
        }
        Ingested::Model
    }

    fn positions(&mut self, positions: &Positions) -> Result<Ingested, String> {
        let engine = positions.engine().map_err(|error| error.to_string())?;
        positions
            .verify()
            .map_err(|error| format!("positions of {engine}: {error}"))?;
        if self.is_faulted(&engine) {
            return Ok(Ingested::Ignored);
        }
        let Ok(content) = positions.solutions() else {
            return Ok(Ingested::Ignored);
        };
        let mut tally = Tally::default();
        for solution in content.solutions {
            self.solution(
                engine,
                content.spec_version,
                content.issued_ms,
                solution,
                &mut tally,
            );
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
        issued_ms: u64,
        solution: tally_wire::Solution,
        tally: &mut Tally,
    ) {
        let id = solution.clock_model;
        if self.models.get(&id).is_none() {
            // Its model is on its way by another path, or never coming: held a while, bounded.
            match self.pending.get_mut(&id) {
                Some(waiting) if waiting.len() < PENDING_PER_MODEL => {
                    waiting.push((engine, spec, issued_ms, solution))
                }
                Some(_) => {
                    tally.dropped += 1;
                    return;
                }
                None => {
                    self.pending
                        .insert_active(id, vec![(engine, spec, issued_ms, solution)]);
                }
            }
            tally.pending += 1;
            return;
        }
        match self.check(engine, spec, &solution, Kind::Final) {
            Some(fix) => {
                self.ledger_takes(spec, issued_ms, &solution, Kind::Final);
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

    /// A checked solution, to the standing ledger: every solution of a transmission, final or
    /// provisional, held or not, is evidence of who heard it first and who agreed.
    fn ledger_takes(&mut self, spec: u16, issued_ms: u64, wire: &tally_wire::Solution, kind: Kind) {
        let Some(model) = self.models.get(&wire.clock_model) else {
            return;
        };
        let (decoded, inputs) = (Arc::clone(&model.decoded), model.inputs);
        if let Some(solved) = Solved::new(
            wire,
            spec,
            issued_ms,
            kind == Kind::Provisional,
            decoded,
            inputs,
        ) {
            self.ledger.solved(solved);
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
        let Ok(content) = positions.solutions() else {
            return Ok(Ingested::Ignored);
        };
        let (mut accepted, mut dropped) = (0, 0);
        for solution in content.solutions {
            let checked = self.check(engine, content.spec_version, &solution, Kind::Provisional);
            if checked.is_some() {
                self.ledger_takes(
                    content.spec_version,
                    content.issued_ms,
                    &solution,
                    Kind::Provisional,
                );
            }
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
                    finals().any(|held| {
                        Self::same_transmission_in(&self.models, &self.resolved, held, &fix)
                    }),
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
            if Self::same_transmission_in(&self.models, &self.resolved, settled, &held.fix) {
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

    /// The solution as a fix, if it passes every check the client can make.
    fn check(
        &mut self,
        engine: PublicKey,
        spec: u16,
        wire: &tally_wire::Solution,
        kind: Kind,
    ) -> Option<Fix> {
        // A provisional is checked by signatures and content addresses: the raw its model was
        // fitted from does not reach its receptions, which are newer than the model's window.
        let raw = self.settings.raw && kind == Kind::Final;
        self.models.touch(&wire.clock_model);
        let model = self.models.get(&wire.clock_model)?;
        if self.is_faulted(&model.engine) || model.spec != spec {
            return None;
        }
        let decoded = Arc::clone(&model.decoded);
        let decoded = &*decoded;
        let message = wire.observations.message();
        if modes::address(message) != Some(wire.address) {
            return None;
        }
        let scope: BTreeSet<PublicKey> = decoded.scope.iter().map(|site| site.receiver).collect();
        if !wire
            .observations
            .receptions()
            .iter()
            .all(|reception| scope.contains(&reception.receiver))
        {
            return None;
        }
        let claim = publish::claim(decoded, wire, spec).ok()?;
        let reach = match kind {
            Kind::Final => Reach::Window,
            Kind::Provisional => Reach::Carried,
        };
        let consistent = consistent(decoded, reach, &wire.observations, &Claimed::of(wire));
        let model_engine = model.engine;
        let inputs = model.inputs;
        let weight = wire.observations.receptions().len() as u64 + u64::from(decoded.input.count);
        let check = if raw {
            self.raw_check(&wire.clock_model);
            let model = self.models.get(&wire.clock_model)?;
            match &model.raw {
                RawCheck::Verified(calibrated) => {
                    // The tile must be the one the assignment rule gives the aircraft, recomputed
                    // from the client's raw; when the client's raw is not the solution's
                    // (its addressed citation differs), it cannot say.
                    let sites = self.site_table();
                    let bins = self.held.bins(decoded.window.first, decoded.window.last);
                    let index = WindowIndex::new(decoded.window, &bins, &sites);
                    match tally_mlat_solver::verify_assignment(
                        &index,
                        wire.address,
                        decoded,
                        &wire.addressed,
                    ) {
                        Err(tally_mlat_solver::Failure::Tile) => return None,
                        Err(_) => Check::Signature,
                        Ok(()) => {
                            let mut members = std::collections::BTreeMap::new();
                            let assignment = index.assign(wire.address, &mut members)?;
                            let candidates = index.receptions(wire.address, &assignment.scope);
                            let known: BTreeSet<ObservationId> =
                                candidates.iter().map(|reception| reception.id()).collect();
                            if claim.observations.iter().all(|id| known.contains(id)) {
                                if !verify(calibrated, &candidates, &claim).passed() {
                                    return None;
                                }
                                Check::Model
                            } else {
                                Check::Signature
                            }
                        }
                    }
                }
                RawCheck::Failed => return None,
                RawCheck::NotHeld | RawCheck::Unchecked => Check::Signature,
            }
        } else {
            Check::Signature
        };
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
            weight,
            check,
            engines: [engine, model_engine].into_iter().collect(),
            standing: self
                .ledger
                .standing_of(&wire.observations, wire.transmitted),
            confidence: if consistent {
                self.ledger.confidence(&wire.observations, wire.transmitted)
            } else {
                Confidence::Unconfirmed
            },
            consistent,
        })
    }

    /// Every receiver the client has a description of.
    fn site_table(&self) -> Sites {
        let sites: Vec<Site> = self.sites.values().map(|(_, site)| *site).collect();
        Sites::new(&sites)
    }

    /// Checks a held model against the client's own raw, once: the tile's members and input
    /// citation rebuilt from it must be the model's exactly, and the model verifier must pass it.
    fn raw_check(&mut self, id: &Hash) {
        let Some(model) = self.models.get(id) else {
            return;
        };
        if !matches!(model.raw, RawCheck::Unchecked) {
            return;
        }
        let decoded = Arc::clone(&model.decoded);
        let decoded = &*decoded;
        // An engine solved the window, so its raw is in: sealed, it is what the engine held.
        self.held.seal_through(decoded.window.last);
        let sites = self.site_table();
        let bins = self.held.bins(decoded.window.first, decoded.window.last);
        let index = WindowIndex::new(decoded.window, &bins, &sites);
        let members = index.members(decoded.tile);
        let outcome = match index.inputs(decoded.tile, &members) {
            Some(inputs) if inputs.scope == decoded.scope && inputs.citation == decoded.input => {
                match verify_model(decoded, &inputs) {
                    (verdict, Some(calibrated)) if verdict.passed() => {
                        RawCheck::Verified(Box::new(calibrated))
                    }
                    _ => RawCheck::Failed,
                }
            }
            _ => RawCheck::NotHeld,
        };
        if let Some(model) = self.models.get_mut(id) {
            model.raw = outcome;
        }
    }

    fn merge(&mut self, fix: Fix) -> Merged {
        let address = fix.address;
        let Some(track) = self.tracks.get(&address) else {
            let mut track = Track::new(address);
            track
                .transmissions
                .push(Transmission::new(fix, &self.ledger));
            self.tracks.insert_active(address, track);
            return Merged::Changed;
        };
        // The held transmissions it is tied to; it joins one only when exactly one.
        let tied: Vec<usize> = track
            .transmissions
            .iter()
            .enumerate()
            .filter(|(_, transmission)| {
                transmission.fixes.iter().any(|held| {
                    Self::same_transmission_in(&self.models, &self.resolved, held, &fix)
                })
            })
            .map(|(at, _)| at)
            .collect();
        let Some(track) = self.tracks.get_mut(&address) else {
            return Merged::Dropped;
        };
        let at = match tied.as_slice() {
            [at] => Some(*at),
            _ => None,
        };
        let Some(at) = at else {
            // A transmission not held: one more, the oldest forgotten beyond the bound.
            let input_set = fix.input_set;
            track
                .transmissions
                .push(Transmission::new(fix, &self.ledger));
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
        let transmission = &mut track.transmissions[at];
        if let Some(same) = transmission
            .fixes
            .iter_mut()
            .find(|held| held.input_set == fix.input_set)
        {
            same.engines.extend(fix.engines);
            return Merged::Duplicate;
        }
        let before = transmission.current().input_set;
        // Incomparable with what is kept: never averaged. Solved over the union by whoever holds
        // its raw.
        let comparable = |held: &Fix| {
            held.model_inputs == fix.model_inputs
                && fix.observations.relation(&held.observations) != Relation::Incomparable
        };
        let partner = transmission
            .fixes
            .iter()
            .find(|held| !comparable(held))
            .cloned();
        let resolved = match partner {
            Some(partner) if self.settings.raw => self.resolve(&partner, &fix),
            _ => None,
        };
        let Some(track) = self.tracks.get_mut(&address) else {
            return Merged::Dropped;
        };
        let transmission = &mut track.transmissions[at];
        let input_set = fix.input_set;
        let was_refused: BTreeSet<Hash> = transmission
            .refused
            .iter()
            .map(|held| held.input_set)
            .collect();
        transmission.fixes.push(fix);
        transmission.fixes.extend(resolved);
        transmission.normalize(&self.ledger);
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

    /// The client's own solution of a transmission two incomparable solutions are of, from its
    /// raw: the aircraft's tile by the assignment rule, fitted, and the transmission (the group
    /// holding either solution's receptions) solved and verified as an engine would. `None` when
    /// the client does not hold every cited observation, or the solutions are of different
    /// windows, or nothing solves.
    fn resolve(&mut self, a: &Fix, b: &Fix) -> Option<Fix> {
        let (first, second) = (self.model_of(a)?, self.model_of(b)?);
        if first.window != second.window {
            return None;
        }
        let window = first.window;
        let message = a.observations.message();
        let hash = message_hash(message);
        let union = a.observations.union(&b.observations)?.ok()?;
        let all_held = union.receptions().iter().all(|reception| {
            self.held.contains(&ObservationId {
                receiver: reception.receiver,
                epoch: reception.epoch,
                timestamp: reception.counter,
                message: hash,
            })
        });
        if !all_held {
            return None;
        }
        self.held.seal_through(window.last);
        let sites = self.site_table();
        let bins = self.held.bins(window.first, window.last);
        let index = WindowIndex::new(window, &bins, &sites);
        let mut members = std::collections::BTreeMap::new();
        let assignment = index.assign(a.address, &mut members)?;
        let inputs = index.inputs(assignment.tile, &members[&assignment.tile])?;
        let key: ResolveKey = (assignment.tile, window, inputs.citation.hash);
        if self.resolved.get(&key).is_none() {
            let fitted =
                tally_mlat_solver::fit_calibrated(&inputs)
                    .ok()
                    .map(|(model, calibrated)| Resolver {
                        inputs: publish::inputs_id(&model),
                        model,
                        calibrated,
                    });
            self.resolved.insert_active(key, fitted);
        }
        let resolver = self.resolved.get(&key)?.as_ref()?;
        let candidates = index.receptions(a.address, &assignment.scope);
        let cited: BTreeSet<(PublicKey, u32, u64)> = union
            .receptions()
            .iter()
            .map(|reception| (reception.receiver, reception.epoch, reception.counter))
            .collect();
        let grouping = tally_mlat_solver::group(&resolver.model, &candidates);
        let transmission = grouping.transmissions.iter().find(|transmission| {
            transmission.data == message
                && transmission.receptions.iter().any(|timed| {
                    cited.contains(&(timed.id.receiver, timed.id.epoch, timed.id.timestamp))
                })
        })?;
        let addressed = index.addressed_citation(a.address);
        let (solution, wire) =
            publish::solve_published(&resolver.calibrated, transmission, [0; 32], addressed)
                .ok()?;
        let standing = self
            .ledger
            .standing_of(&wire.observations, wire.transmitted);
        let confidence = self.ledger.confidence(&wire.observations, wire.transmitted);
        Some(Fix {
            kind: Kind::Final,
            address: wire.address,
            transmitted: wire.transmitted,
            lat_e7: wire.lat_e7,
            lon_e7: wire.lon_e7,
            alt_hae_mm: wire.alt_hae_mm,
            altitude_ft: barometric_ft(message),
            horizontal_sigma_m: solution.horizontal_sigma_m(),
            covariance: wire.covariance,
            input_set: input_set(&wire.observations, &resolver.inputs),
            weight: wire.observations.receptions().len() as u64
                + u64::from(resolver.model.input.count),
            observations: wire.observations,
            model: resolver.inputs,
            model_inputs: resolver.inputs,
            check: Check::Resolved,
            engines: BTreeSet::new(),
            standing,
            confidence,
            consistent: true,
        })
    }

    /// The model a fix was solved under: an engine's held model, or a union the client fitted.
    fn model_of(&self, fix: &Fix) -> Option<tally_mlat_solver::ClockModel> {
        Self::model_in(&self.models, &self.resolved, fix).cloned()
    }

    fn model_in<'a>(
        models: &'a Bounded<Hash, Model>,
        resolved: &'a Bounded<ResolveKey, Option<Resolver>>,
        fix: &Fix,
    ) -> Option<&'a tally_mlat_solver::ClockModel> {
        match fix.check {
            Check::Resolved => resolved
                .values()
                .flatten()
                .find(|resolver| resolver.inputs == fix.model)
                .map(|resolver| &resolver.model),
            _ => models.get(&fix.model).map(|model| &*model.decoded),
        }
    }

    /// Whether two solutions are of one transmission (crate docs, § Solutions merge per
    /// transmission): one aircraft, the same bytes, and a reception in common or a tie through
    /// either's clock model; never when a receiver is in both without a reception in common.
    pub fn same_transmission(&self, a: &Fix, b: &Fix) -> bool {
        Self::same_transmission_in(&self.models, &self.resolved, a, b)
    }

    fn same_transmission_in(
        models: &Bounded<Hash, Model>,
        resolved: &Bounded<ResolveKey, Option<Resolver>>,
        a: &Fix,
        b: &Fix,
    ) -> bool {
        if a.address != b.address || a.observations.message() != b.observations.message() {
            return false;
        }
        match in_common(&a.observations, &b.observations) {
            (true, _) => true,
            (false, true) => false,
            (false, false) => {
                let tie = |from: &Fix, onto: &Fix| {
                    Self::model_in(models, resolved, onto).and_then(|model| tied(model, from, onto))
                };
                // Every model that can say must say yes, and one at least must.
                match (tie(a, b), tie(b, a)) {
                    (None, None) => false,
                    (one, other) => one.unwrap_or(true) && other.unwrap_or(true),
                }
            }
        }
    }

    fn fault_proof(&mut self, proof: &FaultProof) -> Ingested {
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
        let models: Vec<Hash> = self
            .models
            .iter()
            .filter(|(_, model)| model.engine == engine)
            .map(|(id, _)| *id)
            .collect();
        for id in models {
            self.models.remove(&id);
        }
        let addresses: Vec<u32> = self.tracks.iter().map(|(address, _)| *address).collect();
        for address in addresses {
            let Some(track) = self.tracks.get_mut(&address) else {
                continue;
            };
            for transmission in &mut track.transmissions {
                let stands = |fix: &mut Fix| {
                    // A fix the client solved itself stands on the receivers' signed raw.
                    if fix.check == Check::Resolved {
                        return true;
                    }
                    fix.engines.remove(&engine);
                    !fix.engines.is_empty()
                };
                transmission.fixes.retain_mut(stands);
                transmission.refused.retain_mut(stands);
                transmission.normalize(&self.ledger);
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

/// Which of two fixes of one transmission ranks first, by the rule
/// (`tally_mlat_solver::standing::rank`).
#[cfg(test)]
fn order(a: &Fix, b: &Fix) -> std::cmp::Ordering {
    a.rank().cmp(&b.rank())
}

/// Whether `from`'s receptions, mapped through `model` (the model `onto` was solved under), put
/// `onto`'s transmit time where it is: `None` when no receiver `from` cites is a clock of the
/// model (or `onto` states no height), else whether every one that is agrees within `TIE_NS`.
fn tied(model: &tally_mlat_solver::ClockModel, from: &Fix, onto: &Fix) -> Option<bool> {
    let position = onto.ecef()?;
    let transmitted = i128::try_from(onto.transmitted.unix_ps()).ok()?;
    let origin_ps = i128::from(model.origin_unix_ns) * 1_000;
    let mut any = None;
    for reception in from.observations.receptions() {
        let Some(time) = model.time(&reception.receiver, reception.epoch, reception.counter) else {
            continue;
        };
        let site = tally_mlat_solver::geo::from_mm(model.pieces[time.piece].site_mm);
        let range = tally_mlat_solver::linalg::norm(tally_mlat_solver::linalg::sub(position, site));
        let range_ps = (range / tally_mlat_solver::geo::C * 1e12).round() as i128;
        let predicted = origin_ps + time.ps - range_ps;
        let agrees = predicted.abs_diff(transmitted) <= u128::from(TIE_NS) * 1_000;
        if !agrees {
            return Some(false);
        }
        any = Some(true);
    }
    any
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

/// The full input set's identity: BLAKE2s-256 over `"tally merge input set" 0x00`, the
/// observation set hash and the model inputs hash (the rule's).
pub fn input_set(observations: &ObservationSet, model_inputs: &Hash) -> Hash {
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
