//! THE CLIENT MERGE RULE (RFC-0171 §3.8.1), implemented once for every client: whoever reads
//! the positions and clock model streams of any number of engines, through any number of relays,
//! holds one current fix per aircraft here, and holds it the same whatever order the records
//! arrived in and however many copies of each did.
//!
//! What it takes is what a client is sent ([`ClientRecord`], wire version 4): tagged `Positions`
//! (format 8, MLAT fixes), engines' `ClientClockModel`s (a model's summary: its id, inputs hash
//! and window, nothing of which receivers it is of) and tagged `FaultProof`s. A client is never
//! sent a receiver's site, its raw counters, a full model or a model's members, so it holds no
//! raw and solves nothing itself: what checks and joins fixes here works on tag sets
//! (`TaggedSet`), each reception a 16-byte tag only a relay holding the receiver's site and the
//! raw can rematch (`tally_mlat_solver::publish::rematch`). Every fix names two of them: what it
//! considered (every reception of its transmission that had arrived when it was solved) and what
//! it used of that. What the merge holds per aircraft is a [`Track`]: its latest transmissions,
//! each with the [`Fix`] kept and the alternatives it was preferred to.
//!
//! - **Every fix is checked against the models it cites before it counts**, by signatures and
//!   content addresses: the record verifies under its engine's key; each model it cites (one per
//!   area of its used hearers, `tally_wire::Fix::models`) has a summary held, signed by any
//!   engine not faulted (a neighbouring area's model is its own relays'), every summary held of
//!   that id agreeing and of the specification the record names; and the fix's message names its
//!   aircraft. A model's id is a content address, so honest summaries of one id agree; summaries
//!   that disagree dispute it, and every fix citing it is dropped until a conviction settles it. A
//!   fix waits, bounded, for the first model it cites that has not arrived. A client cannot verify a model or a fix from raw (it holds
//!   neither the raw nor the sites): a relay does (`tally_relay`'s standing and its consistency
//!   gate), and drops what fails before it forwards it.
//! - **Fixes merge per transmission, and only on evidence** (`Merge::same_transmission`). Two
//!   fixes are of one transmission when they name one aircraft with the same message bytes and
//!   their considered sets share a tag: a tag is one receiver's one reception of those bytes, so
//!   two sets that share one are of one transmission. Nothing else joins: not transmit times,
//!   which two models state on origins that agree only as well as their gauges' wall clocks (0.9 s
//!   apart in the simulator), and not the bytes, which a Mode S reply (DF4, 5, 11, 20, 21) repeats
//!   exactly milliseconds apart to another interrogator (a false join is invisible to any
//!   chi-square: each side fits itself). A fix sharing a tag with more than one held transmission
//!   joins none. What is lost: two engines whose fixes share no reception are never merged, and
//!   the aircraft's track holds both as separate transmissions (its current position is then the
//!   latest by transmit time, which is the one place a transmit time across models is compared).
//!   A tie through a model (mapping one fix's receptions through the other's clocks) needs the
//!   receivers' sites and offsets, which a client is not sent. An aircraft's track holds its
//!   latest `TRANSMISSIONS` transmissions; its current position is the latest one's fix.
//! - **Within one transmission, by the full input set** (the considered tag set and the cited
//!   models' inputs together, `tally_mlat_solver::publish::cited_inputs`, hashed by
//!   `tally_wire::products::input_set`): the same set is a
//!   duplicate, dropped, its signer added to the fix's engines. An engine publishes a fix as soon
//!   as it can solve one and again when more receptions of the transmission arrive, so a bigger
//!   fix of one transmission, over a superset of a smaller one's considered tags, is the ordinary
//!   case and needs no other mechanism: one that agrees with the smaller fix within the smaller's
//!   covariance (RFC-0174 §2.12, `tally_mlat_solver::standing::decide`) supersedes it, and with the
//!   same model inputs drops it. One that disagrees supersedes only when a holder of its raw
//!   verified it and its receivers carry more standing (the rule's, mlat-shape §5); a client
//!   holds neither, so for it every disagreeing superset is unjudged ([`Fix`]'s `verified` is
//!   `None`) and stays contested, a fault, never the answer, kept as evidence
//!   (`Transmission::refused`, `Transmission::contests`, `Merge::contested`) while the smaller
//!   stands. The client trusts the relay's consistency gate for the rest: a relay forwards no fix
//!   that disagrees with its own receptions, so every fix here may refuse a disagreeing superset.
//!   Anything else is incomparable and never averaged: the one that ranks first is kept and the
//!   other recorded as an alternative.
//! - **The rule ranks by the tie rule** (the rule's `rank` with no standing, which is a relay's):
//!   by weight (the tags the fix used), then by the lowest input set hash (`input_set`).
//! - **A fault proof convicts its signers**, and is the one verdict that reaches a client. A
//!   checked tagged `FaultProof` (two fixes of one used tag set under one model that disagree)
//!   marks each engine it names as faulted: what it signed is dropped from every track (a fix any
//!   other engine also signed stands on that engine's word; a transmission whose fix is dropped
//!   keeps its best alternative, and a superset the dropped fix refused is judged again without
//!   it), its models are forgotten, and nothing it signs later counts. A verdict that comes late
//!   moves the answer once and never back: what is held is a function of the records taken,
//!   whatever order they came in, and a conviction holds while the merge holds the key
//!   (`Settings::max_faulted`).
//! - **Memory is bounded**, every table least-recently-active first (the relay's `Bounded`):
//!   tracks, models, fixes waiting for their model and faulted keys by count.

// It reaches keys (`tally_wire::Identity`): no `unsafe` code at all, forbidden, so no module
// can allow it.
#![forbid(unsafe_code)]

pub mod contest;
pub mod link;

pub use contest::{Contest, SupersetVerdict, superset_verdict};

use std::collections::{BTreeMap, BTreeSet};

use tally_mlat_solver::modes;
use tally_mlat_solver::standing::{Candidate, Claimed, decide};
use tally_relay::bounded::Bounded;
use tally_wire::batch::Hash;
use tally_wire::{
    ClientClockModel, ClientFaultProof, ClientRecord, Positions, PublicKey, TaggedFix, TaggedSet,
    Tolerance, TransmitTime,
};

/// Transmissions kept per aircraft, the latest. Two engines' transmit times are on their models'
/// own time origins, which agree only as well as the gauges' wall clocks when neither is GNSS
/// disciplined, so one aircraft's transmissions are held a few at a time and a fix joins the one
/// it is of, rather than being judged older or newer than another engine's.
pub const TRANSMISSIONS: usize = 8;
/// Alternatives kept per transmission, the best ranked first.
pub const ALTERNATIVES: usize = 4;
/// Fixes held per missing model while it has not arrived.
pub const PENDING_PER_MODEL: usize = 4_096;

/// How much the client holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub max_aircraft: usize,
    pub max_models: usize,
    /// Models fixes are waiting for.
    pub max_pending: usize,
    pub max_faulted: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_aircraft: 65_536,
            max_models: 16_384,
            max_pending: 1_024,
            max_faulted: 4_096,
        }
    }
}

/// One fix as the merge holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Fix {
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
    /// The message and the tags of every reception of it the engine had when it solved: what a
    /// superset is judged by.
    pub considered: TaggedSet,
    /// The tags it was solved from, a subset of `considered`.
    pub used: TaggedSet,
    /// The cited models' ids, one per area of its used hearers, ascending (`tally_wire::Fix::models`,
    /// each a pair model's id as its `ClientClockModel` names it).
    pub models: Vec<Hash>,
    /// The specification its record names, which every cited summary is of.
    pub spec: u16,
    /// The cited models' inputs together (`tally_mlat_solver::publish::cited_inputs`, each
    /// summary's inputs hash in the order of `models`).
    pub model_inputs: Hash,
    /// BLAKE2s-256 over `"tally merge input set" 0x00`, the considered set's hash and the model
    /// inputs hash: the full input set's identity.
    pub input_set: Hash,
    /// The tags used: the tie rule's weight.
    pub weight: u64,
    /// The engines that signed it.
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
        &self.considered
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
    /// which a client is not sent: it trusts the relay's consistency gate, which drops one that
    /// does not before it forwards it.
    fn consistent(&self) -> bool {
        true
    }

    /// Unjudged: verifying a fix needs its raw, which a client never holds, so a disagreeing
    /// superset stays contested here (crate docs).
    fn verified(&self) -> Option<bool> {
        None
    }
}

/// Whether the two share a tag: a reception in common.
fn in_common(a: &TaggedSet, b: &TaggedSet) -> bool {
    let theirs = b.tags();
    a.tags().iter().any(|tag| theirs.binary_search(tag).is_ok())
}

/// The fixes of one transmission the merge holds, as the rule decides them
/// (`tally_mlat_solver::standing::decide`, RFC-0174 §2.12): none dominated by another (the same
/// model's inputs and a subset of an agreeing superset's considered tags), none refused (an
/// unjudged superset that disagrees with a smaller fix: contested, a fault, never the answer),
/// best first by `order`, at most `ALTERNATIVES` after the first. A function of the set of fixes
/// taken, whatever order they came in.
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
    /// arrival order. A refused fix is judged again with the rest every time, so one whose
    /// refuser is dropped (its engine convicted) stands.
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

/// An aircraft's most recent transmissions, oldest first by their current fix's transmit time,
/// at most `TRANSMISSIONS`. Never empty.
#[derive(Clone, Debug, PartialEq)]
pub struct Track {
    pub address: u32,
    pub transmissions: Vec<Transmission>,
}

impl Track {
    fn new(address: u32) -> Self {
        Self {
            address,
            transmissions: Vec::new(),
        }
    }

    /// The aircraft's latest position: the latest transmission's fix. What is served.
    pub fn current(&self) -> Option<&Fix> {
        self.latest().map(Transmission::current)
    }

    pub fn latest(&self) -> Option<&Transmission> {
        self.transmissions.last()
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
    /// Fixes taken: how many changed a track, were duplicates, were dropped (failed a check, an
    /// earlier transmission, a subset, a contested superset), or wait for their model.
    Fixes {
        accepted: usize,
        duplicate: usize,
        dropped: usize,
        pending: usize,
    },
    /// A model summary held.
    Model,
    /// A checked fault proof.
    Fault,
    Ignored,
}

/// What a held model summary says, as the merge needs it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Model {
    spec: u16,
    inputs: Hash,
}

/// A model's summaries, by the engine that signed each. A fix may cite a model another engine
/// signed (a neighbouring area's, its own relays'), so a model is held by its id alone, and its
/// id is a content address (`tally_mlat_solver::publish::pair_model_id`): honest summaries of one
/// id say the same (the inputs hash is a function of the model, `publish::inputs_id`). Summaries
/// that disagree make the id disputed, and no fix citing it counts until a conviction settles it.
type Summaries = BTreeMap<PublicKey, Model>;

/// What a cited id resolves to.
enum Resolved {
    /// Every summary held says this.
    Agreed(Model),
    /// No summary held.
    Missing,
    /// Summaries that disagree.
    Disputed,
}

/// Fixes waiting for a model they cite: the signing engine, the specification and the fix.
type Waiting = Vec<(PublicKey, u16, TaggedFix)>;

pub struct Merge {
    settings: Settings,
    tracks: Bounded<u32, Track>,
    models: Bounded<Hash, Summaries>,
    pending: Bounded<Hash, Waiting>,
    faulted: Bounded<PublicKey, ()>,
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
            contested: 0,
        }
    }

    /// Supersets refused for disagreeing with a smaller fix of their transmission, since the merge
    /// began: each a fault, kept as evidence (`Transmission::contests`).
    pub fn contested(&self) -> u64 {
        self.contested
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

    /// Whether the merge holds `fix` as a fix of its aircraft: it passed every check and the rule
    /// keeps it (ranked, not refused, dominated or dropped). A client that credits anyone for a
    /// published position asks this, never the record alone.
    pub fn holds(&self, fix: &TaggedFix) -> bool {
        self.tracks.get(&fix.address).is_some_and(|track| {
            track.transmissions.iter().any(|transmission| {
                transmission
                    .fixes
                    .iter()
                    .any(|held| held.models == fix.models && held.considered == *fix.considered())
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

    /// Takes one record a relay delivered. An error is a record that claimed to be signed and is
    /// not.
    pub fn ingest(&mut self, record: &ClientRecord) -> Result<Ingested, String> {
        match record {
            ClientRecord::ClockModel(model) => self.model(model),
            ClientRecord::Positions(positions) => self.positions(positions.get()),
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
        let id = content.model;
        let summary = Model {
            spec: content.spec_version,
            inputs: content.inputs,
        };
        let was = self.resolve(&id);
        match self.models.get_mut(&id) {
            Some(summaries) => {
                summaries.insert(engine, summary);
            }
            None => {
                self.models
                    .insert_active(id, [(engine, summary)].into_iter().collect());
            }
        }
        self.models.touch(&id);
        if matches!(self.resolve(&id), Resolved::Disputed) && !matches!(was, Resolved::Disputed) {
            self.recheck();
        }
        if let Some(waiting) = self.pending.remove(&id) {
            for (signer, spec, fix) in waiting {
                self.fix(signer, spec, fix, &mut Tally::default());
            }
        }
        Ok(Ingested::Model)
    }

    fn positions(&mut self, positions: &Positions) -> Result<Ingested, String> {
        let engine = positions.engine().map_err(|error| error.to_string())?;
        positions
            .verify()
            .map_err(|error| format!("positions of {engine}: {error}"))?;
        if self.is_faulted(&engine) {
            return Ok(Ingested::Ignored);
        }
        let Ok(content) = positions.tagged_fixes() else {
            return Ok(Ingested::Ignored);
        };
        let mut tally = Tally::default();
        for fix in content.fixes {
            self.fix(engine, content.spec_version, fix, &mut tally);
        }
        Ok(Ingested::Fixes {
            accepted: tally.accepted,
            duplicate: tally.duplicate,
            dropped: tally.dropped,
            pending: tally.pending,
        })
    }

    fn fix(&mut self, engine: PublicKey, spec: u16, wire: TaggedFix, tally: &mut Tally) {
        let missing = wire
            .models
            .iter()
            .find(|id| matches!(self.resolve(id), Resolved::Missing))
            .copied();
        if let Some(id) = missing {
            // A model it cites is on its way by another path, or never coming: held a while,
            // bounded, under the first one missing.
            match self.pending.get_mut(&id) {
                Some(waiting) if waiting.len() < PENDING_PER_MODEL => {
                    waiting.push((engine, spec, wire));
                }
                Some(_) => {
                    tally.dropped += 1;
                    return;
                }
                None => {
                    self.pending.insert_active(id, vec![(engine, spec, wire)]);
                }
            }
            tally.pending += 1;
            return;
        }
        match self.check(engine, spec, &wire) {
            Some(fix) => match self.merge(fix) {
                Merged::Changed => tally.accepted += 1,
                Merged::Duplicate => tally.duplicate += 1,
                Merged::Dropped | Merged::Contested => tally.dropped += 1,
            },
            None => tally.dropped += 1,
        }
    }

    /// What every summary held of `id` says, if they agree.
    fn resolve(&self, id: &Hash) -> Resolved {
        let Some(summaries) = self.models.get(id) else {
            return Resolved::Missing;
        };
        let mut said = summaries.values();
        let Some(first) = said.next() else {
            return Resolved::Missing;
        };
        if said.all(|other| other == first) {
            Resolved::Agreed(*first)
        } else {
            Resolved::Disputed
        }
    }

    /// The cited models' inputs together, if every id is held, agreed and of `spec`.
    fn cited(&self, models: &[Hash], spec: u16) -> Option<Hash> {
        let mut inputs = Vec::with_capacity(models.len());
        for id in models {
            match self.resolve(id) {
                Resolved::Agreed(model) if model.spec == spec => inputs.push(model.inputs),
                _ => return None,
            }
        }
        Some(tally_mlat_solver::publish::cited_inputs(inputs))
    }

    /// The fix as the merge holds it, if it passes every check a client can make (crate docs):
    /// every model it cites held, its summaries agreeing and of the record's specification, and
    /// its message naming its aircraft.
    fn check(&mut self, engine: PublicKey, spec: u16, wire: &TaggedFix) -> Option<Fix> {
        for id in &wire.models {
            self.models.touch(id);
        }
        let inputs = self.cited(&wire.models, spec)?;
        let message = wire.considered().message();
        if modes::address(message) != Some(wire.address) {
            return None;
        }
        Some(Fix {
            address: wire.address,
            transmitted: wire.transmitted,
            lat_e7: wire.lat_e7,
            lon_e7: wire.lon_e7,
            alt_hae_mm: wire.alt_hae_mm,
            altitude_ft: barometric_ft(message),
            horizontal_sigma_m: horizontal_sigma_m(&wire.covariance),
            covariance: wire.covariance,
            input_set: input_set(wire.considered(), &inputs),
            considered: wire.considered().clone(),
            used: wire.used().clone(),
            models: wire.models.clone(),
            spec,
            model_inputs: inputs,
            weight: wire.used().tags().len() as u64,
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
                    .chain(&transmission.refused)
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
            .chain(transmission.refused.iter_mut())
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

    /// Whether two fixes are of one transmission (crate docs, § Fixes merge per transmission):
    /// one aircraft, the same bytes, and a considered tag in common.
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

    /// Marks `engine` faulted and drops everything that stands on its word alone. Every
    /// transmission it touched is decided again without it, so a superset its fix had refused
    /// stands now.
    fn convict(&mut self, engine: PublicKey) {
        self.faulted.insert_active(engine, ());
        let signed: Vec<Hash> = self
            .models
            .iter()
            .filter(|(_, summaries)| summaries.contains_key(&engine))
            .map(|(id, _)| *id)
            .collect();
        let mut settled = Vec::new();
        for id in signed {
            let was = self.resolve(&id);
            let Some(summaries) = self.models.get_mut(&id) else {
                continue;
            };
            summaries.remove(&engine);
            if summaries.is_empty() {
                self.models.remove(&id);
            } else if matches!(was, Resolved::Disputed)
                && matches!(self.resolve(&id), Resolved::Agreed(_))
            {
                settled.push(id);
            }
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
            track.arrange();
            if track.transmissions.is_empty() {
                self.tracks.remove(&address);
            }
        }
        self.recheck();
        for id in settled {
            if let Some(waiting) = self.pending.remove(&id) {
                for (signer, spec, fix) in waiting {
                    self.fix(signer, spec, fix, &mut Tally::default());
                }
            }
        }
    }

    /// Drops every fix whose cited models no longer resolve to what it was checked under: one
    /// citing a model now disputed, forgotten with its convicted signer's summary, or whose
    /// summaries now say other inputs. Every transmission it touches is decided again.
    fn recheck(&mut self) {
        let addresses: Vec<u32> = self.tracks.iter().map(|(address, _)| *address).collect();
        for address in addresses {
            let Some(track) = self.tracks.get(&address) else {
                continue;
            };
            let stale = track.transmissions.iter().any(|transmission| {
                transmission
                    .fixes
                    .iter()
                    .chain(&transmission.refused)
                    .any(|fix| self.cited(&fix.models, fix.spec) != Some(fix.model_inputs))
            });
            if !stale {
                continue;
            }
            let standing: BTreeMap<(Vec<Hash>, u16), Option<Hash>> = track
                .transmissions
                .iter()
                .flat_map(|transmission| transmission.fixes.iter().chain(&transmission.refused))
                .map(|fix| {
                    let key = (fix.models.clone(), fix.spec);
                    let inputs = self.cited(&fix.models, fix.spec);
                    (key, inputs)
                })
                .collect();
            let Some(track) = self.tracks.get_mut(&address) else {
                continue;
            };
            for transmission in &mut track.transmissions {
                let stands = |fix: &Fix| {
                    standing
                        .get(&(fix.models.clone(), fix.spec))
                        .copied()
                        .flatten()
                        == Some(fix.model_inputs)
                };
                transmission.fixes.retain(stands);
                transmission.refused.retain(stands);
                transmission.normalize();
            }
            track.arrange();
            if track.transmissions.is_empty() {
                self.tracks.remove(&address);
            }
        }
    }
}

/// Whether two fixes are of one transmission: one aircraft, the same bytes, a considered tag in
/// common.
fn same_transmission(a: &Fix, b: &Fix) -> bool {
    a.address == b.address
        && a.considered.message() == b.considered.message()
        && in_common(&a.considered, &b.considered)
}

/// Which of two fixes of one transmission ranks first, by the rule
/// (`tally_mlat_solver::standing::rank`).
#[cfg(test)]
fn order(a: &Fix, b: &Fix) -> std::cmp::Ordering {
    a.rank().cmp(&b.rank())
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
