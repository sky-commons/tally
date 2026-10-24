//! What an MLAT engine publishes (RFC-0171 §3.8): positions it solved, signed by the engine's own
//! key. Like a batch it is immutable once signed, keeps a fixed prefix in every format version
//! (format, engine key, boot id, sequence), and is forwarded by relays byte for byte, whatever its
//! format.
//!
//! Format 1 (a position, a sigma and a receiver count, verifiable by no one) is retired with the
//! engine that wrote it, and the byte 1 is never reused. Format 2 cited a clock model per aircraft
//! and is retired with specification version 2. Format 3 (§3.8.1) is the native engine's: each
//! solution is a cached view, a deterministic function of the exact observation set it used, the
//! tile clock model it used, the aircraft's own receptions in the window (which chose that tile),
//! and the solver specification's version, and names all four, so consumers can deduplicate it,
//! merge it by set relation, verify it against raw (the tile choice included), and prove a fault.
//!
//! ```text
//! format u8 = 3 | engine key [32] | boot_id u64 | sequence u64
//! | issued_ms u64 | spec_version u16
//! | receiver count u16 | count x receiver key [32]        strictly ascending, every one used
//! | clock count u16 | count x clock model id [32]         strictly ascending, every one used
//! | solution count u16 | count x solution
//! | signature [64]
//!
//! solution = address u32
//!          | message length u8 | message bytes
//!          | transmit unix ms u64 | transmit sub-ms ps u32 (< 1 000 000 000)
//!          | lat_e7 i32 | lon_e7 i32 | alt_hae_mm i32 (i32::MIN for none)
//!          | covariance 6 x f32: xx xy xz yy yz zz, ENU metres squared
//!          | clock model index u16
//!          | addressed citation hash [32] | addressed count u32
//!          | observation count u8 (>= 1)
//!          | count x (receiver index u16, counter epoch u32, raw counter u48)
//! ```
//!
//! Format 4 is a provisional record (§3.8.1), carried by its own record kind
//! (`Record::Provisional`): format 3's layout exactly, each solution solved a second or so after
//! its transmission under the latest model of its tile carried past that model's knots, a
//! deterministic function of the model, its observation set and the spec as a final one is. Its
//! addressed citation is all zero: a provisional names no assignment (the engine solved it under
//! the newest model holding its receivers), and a reader refuses one that names any.
//!
//! Formats 5 and 6 (wire version 3) are what a client receives: formats 3 and 4 with every
//! reception named by its `ReceptionTag` (`crate::site`) instead of (receiver, epoch, counter), so
//! no client learns a receiver's counters, from which with the aircraft's own positions its site
//! follows by reverse MLAT. There is no receiver table:
//!
//! ```text
//! format u8 = 5 (final) or 6 (provisional) | engine key [32] | boot_id u64 | sequence u64
//! | issued_ms u64 | spec_version u16
//! | clock count u16 | count x clock model id [32]         strictly ascending, every one used
//! | solution count u16 | count x solution
//! | signature [64]
//!
//! solution = format 3's, to the addressed count, then
//!          | tag count u8 (>= 1) | count x tag [16]      strictly ascending
//! ```
//!
//! Format 6 is to 5 as 4 is to 3: provisional, under its own record kind, with no addressed
//! citation. A relay rematches a tagged solution against its own raw by computing the tags of
//! what it holds.
//!
//! Formats 7 and 8 (wire version 4, "MLAT in seconds") are the one fix: each solved a second or so
//! after its transmission's first reception arrived, under the newest trailing-window model of its
//! tile, from the receptions that had arrived. A fix names the receptions it considered (what had
//! arrived) and which of them it used (the solver specification's outlier rule over the considered
//! set), so a verifier judges an omission only inside the considered set and never convicts an
//! honest engine that solved before a reception came. Format 7 is relay-only, format 8 what a
//! client receives (each reception a tag, no receiver table). Both travel under the positions kind:
//!
//! ```text
//! format u8 = 7 | engine key [32] | boot_id u64 | sequence u64
//! | issued_ms u64 | spec_version u16
//! | receiver count u16 | count x receiver key [32]        strictly ascending, every one considered
//! | clock count u16 | count x clock model id [32]         strictly ascending, every one used
//! | fix count u16 | count x fix
//! | signature [64]
//!
//! fix = clock model index u16
//!     | considered count u16 (>= 1)
//!     | count x (receiver index u16, counter epoch u32, raw counter u48)
//!     | used mask [ceil(count / 8)]
//!     | address u32
//!     | message length u8 | message bytes
//!     | transmit unix ms u64 | transmit sub-ms ps u32 (< 1 000 000 000)
//!     | lat_e7 i32 | lon_e7 i32 | alt_hae_mm i32 (i32::MIN for none)
//!     | covariance 6 x f32: xx xy xz yy yz zz, ENU metres squared
//!
//! format u8 = 8: format 7 without the receiver table, and each considered reception a tag [16],
//! strictly ascending
//! ```
//!
//! The used mask has a bit per considered reception in its canonical order: reception `i` is bit
//! `7 - i % 8` of byte `i / 8`. At least one is set, and the bits past the count are zero, so the
//! used set is a subset of the considered set by construction and a mask naming more is refused.
//! The considered count is two bytes, but a set holds at most `MAX_OBSERVATIONS`, as its own hash
//! counts it in one.
//!
//! Every integer is big-endian and every f32 is IEEE 754 big-endian. A solution's observations
//! are in the canonical order of `ObservationSet`, by (receiver key, epoch, counter); since the
//! receiver table is ascending by key, that is ascending by (receiver index, epoch, counter) on the
//! wire. Fields a later version appends after the solutions are signed and ignored by this reader.
//! The signature is Ed25519 over `"tally positions" 0x00` and every byte before it, in every format.

use std::collections::BTreeSet;

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, domain, split_signature, u64_at};
use crate::fault_proof::FAULT_PROOF_OVERHEAD;
use crate::key::{KEY_LEN, PublicKey, SIGNATURE_LEN, Signs};
use crate::observation_set::{ObservationSet, Reception, Relation, TaggedSet};
use crate::record::{Body, MAX_BODY};
use crate::site::{ReceptionTag, TAG_LEN};

/// The native engine's format: solutions naming their observation set, tile clock model, the
/// aircraft's addressed receptions and the spec.
pub const POSITIONS_FORMAT_3: u8 = 3;
/// The native engine's provisional format: format 3's layout, solved under a carried model, with
/// no addressed citation.
pub const POSITIONS_FORMAT_PROVISIONAL: u8 = 4;
/// Format 3 with each reception a tag: what a client receives (module docs).
pub const POSITIONS_FORMAT_TAGGED: u8 = 5;
/// Format 4 with each reception a tag.
pub const POSITIONS_FORMAT_TAGGED_PROVISIONAL: u8 = 6;
/// The fix, relay-only: each solution names its model, the receptions it considered and which of
/// them it used (module docs).
pub const POSITIONS_FORMAT_FIX: u8 = 7;
/// Format 7 with each reception a tag: what a client receives.
pub const POSITIONS_FORMAT_TAGGED_FIX: u8 = 8;
const POSITIONS_DOMAIN: &[u8] = b"tally positions";
/// What a fix's identity is computed under.
const FIX_IDENTITY_DOMAIN: &[u8] = b"tally fix identity";
/// Format, engine key, boot id, sequence: fixed across every format version.
const PREFIX_LEN: usize = 1 + KEY_LEN + 8 + 8;
/// The altitude field when the engine solved no altitude of its own.
const NO_ALTITUDE: i32 = i32::MIN;
/// The largest format 3 record an engine signs: half of what a `FaultProof` can carry, so any two
/// of them fit one proof (and either fits one Noise message). A record that would be larger is
/// refused at signing, so a fault can never be unprovable for want of room.
pub const MAX_POSITIONS_LEN: usize = (MAX_BODY - FAULT_PROOF_OVERHEAD) / 2;
/// Picoseconds in a millisecond: the bound on a transmit time's sub-millisecond part.
const PS_PER_MS: u32 = 1_000_000_000;

/// When a transmission was sent: Unix milliseconds and the picoseconds past them, so a time needs
/// no float and no 128-bit field on the wire. Picoseconds, not nanoseconds, because the solver
/// computes the transmit time in whole picoseconds of its clock model and a verifier checks the
/// claim's optimality against its own covariance: half a nanosecond is 15 cm of light travel,
/// which moves a well-determined transmit time off its optimum by more than the verifier allows
/// (`tally-mlat-solver`, § Verifying), so a claim rounded to the nanosecond fails its own check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransmitTime {
    pub unix_ms: u64,
    /// Below 1 000 000 000.
    pub sub_ms_ps: u32,
}

impl TransmitTime {
    pub fn new(unix_ms: u64, sub_ms_ps: u32) -> Result<Self, WireError> {
        let time = Self { unix_ms, sub_ms_ps };
        time.check()?;
        Ok(time)
    }

    /// Unix picoseconds.
    pub fn unix_ps(self) -> u128 {
        u128::from(self.unix_ms) * u128::from(PS_PER_MS) + u128::from(self.sub_ms_ps)
    }

    fn check(self) -> Result<(), WireError> {
        if self.sub_ms_ps >= PS_PER_MS {
            return Err(WireError::Invalid {
                field: "transmit sub-millisecond ps",
                value: u64::from(self.sub_ms_ps),
            });
        }
        Ok(())
    }
}

/// A position's covariance, in metres squared, in the local east-north-up frame at the solved
/// position: the upper triangle of the symmetric 3x3 matrix. It includes the clock component,
/// from the cited clock model's joint covariance (§3.8.1).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EnuCovariance {
    pub xx: f32,
    pub xy: f32,
    pub xz: f32,
    pub yy: f32,
    pub yz: f32,
    pub zz: f32,
}

impl EnuCovariance {
    /// In wire order.
    pub fn terms(&self) -> [f32; 6] {
        [self.xx, self.xy, self.xz, self.yy, self.yz, self.zz]
    }

    fn from_terms([xx, xy, xz, yy, yz, zz]: [f32; 6]) -> Self {
        Self {
            xx,
            xy,
            xz,
            yy,
            yz,
            zz,
        }
    }

    /// Every term finite, and every variance (the diagonal) not negative.
    pub(crate) fn check(&self) -> Result<(), WireError> {
        let finite = self.terms().iter().all(|term| term.is_finite());
        let variances = [self.xx, self.yy, self.zz].iter().all(|v| *v >= 0.0);
        if !(finite && variances) {
            return Err(WireError::Invalid {
                field: "position covariance",
                value: 0,
            });
        }
        Ok(())
    }
}

/// What a solution names as the observations it used: the raw set (formats 3 and 4, relay-only)
/// or the tagged set a client sees (formats 5 and 6).
pub trait Observed: Clone + std::fmt::Debug + PartialEq {
    /// The transmission's bytes.
    fn message(&self) -> &[u8];
    /// The set's own hash (`ObservationSet::hash`, `TaggedSet::hash`).
    fn set_hash(&self) -> Hash;
}

impl Observed for ObservationSet {
    fn message(&self) -> &[u8] {
        ObservationSet::message(self)
    }

    fn set_hash(&self) -> Hash {
        self.hash()
    }
}

impl Observed for TaggedSet {
    fn message(&self) -> &[u8] {
        TaggedSet::message(self)
    }

    fn set_hash(&self) -> Hash {
        self.hash()
    }
}

/// One solution: where one transmission was sent from, and exactly what it was solved from. Of
/// format 3 or 4 with its raw `ObservationSet`; of format 5 or 6 (`TaggedSolution`) with its
/// `TaggedSet`.
#[derive(Clone, Debug, PartialEq)]
pub struct Solution<O = ObservationSet> {
    /// The aircraft's 24-bit ICAO address.
    pub address: u32,
    pub transmitted: TransmitTime,
    pub lat_e7: i32,
    pub lon_e7: i32,
    /// Millimetres above the WGS84 ellipsoid; `None` when the engine solved no altitude.
    pub alt_hae_mm: Option<i32>,
    pub covariance: EnuCovariance,
    /// The id (`ClockModel::id`) of the clock model the solution used.
    pub clock_model: Hash,
    /// The aircraft's receptions in the window that chose the tile, as the solver specification
    /// cites them: a verifier holding the same raw recomputes the tile from them.
    pub addressed: AddressedCitation,
    /// The transmission's message and the receptions of it the solution used.
    pub observations: O,
}

/// A solution as a client receives it (formats 5 and 6).
pub type TaggedSolution = Solution<TaggedSet>;
/// A tagged record's content.
pub type TaggedSolutionsContent = SolutionsContent<TaggedSet>;

impl Solution {
    /// The solution as a client sees it: its raw set tagged (`ObservationSet::tagged`).
    pub fn tagged(
        &self,
        key_of: impl Fn(&PublicKey) -> Option<crate::site::ReceptionKey>,
    ) -> Result<TaggedSolution, WireError> {
        Ok(Solution {
            address: self.address,
            transmitted: self.transmitted,
            lat_e7: self.lat_e7,
            lon_e7: self.lon_e7,
            alt_hae_mm: self.alt_hae_mm,
            covariance: self.covariance,
            clock_model: self.clock_model,
            addressed: self.addressed,
            observations: self.observations.tagged(key_of)?,
        })
    }
}

impl<O> Solution<O> {
    /// What signing and reading a solution both hold it to: a valid transmit time, a position on
    /// the globe, a finite covariance with no negative variance, and no altitude spelled as the
    /// "none" marker.
    fn check(&self) -> Result<(), WireError> {
        self.transmitted.check()?;
        crate::batch::check_coordinates(self.lat_e7, self.lon_e7)?;
        self.covariance.check()?;
        if self.alt_hae_mm == Some(NO_ALTITUDE) {
            return Err(WireError::Invalid {
                field: "altitude",
                value: u64::from(NO_ALTITUDE.unsigned_abs()),
            });
        }
        Ok(())
    }
}

/// A set of receptions cited by hash and count (the solver specification defines the hash).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressedCitation {
    pub hash: Hash,
    pub count: u32,
}

/// What a format 3 (or, with `TaggedSet`, a format 5) record says.
#[derive(Clone, Debug, PartialEq)]
pub struct SolutionsContent<O = ObservationSet> {
    /// Random per engine process start. With `sequence`, names this record uniquely for its
    /// engine, so a restarted engine starts a new stream instead of being refused as a replay.
    pub boot_id: u64,
    /// 0, 1, 2, ... within one boot; a gap is results some hop did not deliver.
    pub sequence: u64,
    pub issued_ms: u64,
    /// The version of the solver specification every solution here was computed under.
    pub spec_version: u16,
    pub solutions: Vec<Solution<O>>,
}

/// An observed set whose members a fix's used mask selects: a raw set's receptions (format 7) or
/// a tagged set's tags (format 8), each in its set's one canonical order.
pub trait Members: Observed + Sized {
    type Member: Copy + Ord;
    /// In canonical order.
    fn members(&self) -> &[Self::Member];
    /// The set of `message` and `members`, canonical as the set's own constructor makes it.
    fn of_members(message: Vec<u8>, members: Vec<Self::Member>) -> Result<Self, WireError>;
    /// The set's own relation (`ObservationSet::relation`, `TaggedSet::relation`).
    fn relation_to(&self, other: &Self) -> Relation;
}

impl Members for ObservationSet {
    type Member = Reception;

    fn members(&self) -> &[Reception] {
        self.receptions()
    }

    fn of_members(message: Vec<u8>, members: Vec<Reception>) -> Result<Self, WireError> {
        ObservationSet::new(message, members)
    }

    fn relation_to(&self, other: &Self) -> Relation {
        self.relation(other)
    }
}

impl Members for TaggedSet {
    type Member = ReceptionTag;

    fn members(&self) -> &[ReceptionTag] {
        self.tags()
    }

    fn of_members(message: Vec<u8>, members: Vec<ReceptionTag>) -> Result<Self, WireError> {
        TaggedSet::new(message, members)
    }

    fn relation_to(&self, other: &Self) -> Relation {
        self.relation(other)
    }
}

/// What a fix considered and what it used of that: two sets of one message, the used one a
/// non-empty subset of the considered one. Built only by [`FixSets::new`] (and by reading a record),
/// so the subset holds of every value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FixSets<O = ObservationSet> {
    considered: O,
    used: O,
}

impl<O: Members> FixSets<O> {
    /// Refused: a used set of another message, or one holding a reception the considered set does
    /// not (either set is non-empty by its own constructor).
    pub fn new(considered: O, used: O) -> Result<Self, WireError> {
        if !matches!(
            used.relation_to(&considered),
            Relation::Equal | Relation::Subset
        ) {
            return Err(WireError::Invalid {
                field: "used reception outside the considered set",
                value: 0,
            });
        }
        Ok(Self { considered, used })
    }

    /// Every reception that had arrived when the fix was solved, of its transmission.
    pub fn considered(&self) -> &O {
        &self.considered
    }

    /// The receptions the fix was solved from: the outlier rule's choice of the considered.
    pub fn used(&self) -> &O {
        &self.used
    }

    /// The used mask (module docs): a bit per considered reception, in its canonical order.
    pub fn mask(&self) -> Vec<u8> {
        let considered = self.considered.members();
        let used = self.used.members();
        let mut mask = vec![0u8; considered.len().div_ceil(8)];
        let mut next = 0;
        for (at, member) in considered.iter().enumerate() {
            if used.get(next) == Some(member) {
                mask[at / 8] |= 0x80 >> (at % 8);
                next += 1;
            }
        }
        mask
    }

    /// The sets a mask read off the wire names over `considered`. Refused: a mask of the wrong
    /// length, one naming no reception, and one with a bit past the considered count, which would
    /// be a used reception outside the considered set.
    fn from_mask(considered: O, mask: &[u8]) -> Result<Self, WireError> {
        let members = considered.members();
        if mask.len() != members.len().div_ceil(8) {
            return Err(WireError::Invalid {
                field: "used mask length",
                value: mask.len() as u64,
            });
        }
        let past = (members.len()..mask.len() * 8).any(|at| mask[at / 8] & (0x80 >> (at % 8)) != 0);
        if past {
            return Err(WireError::Invalid {
                field: "used reception outside the considered set",
                value: members.len() as u64,
            });
        }
        let used: Vec<O::Member> = members
            .iter()
            .enumerate()
            .filter(|(at, _)| mask[at / 8] & (0x80 >> (at % 8)) != 0)
            .map(|(_, member)| *member)
            .collect();
        if used.is_empty() {
            return Err(WireError::Invalid {
                field: "used set size",
                value: 0,
            });
        }
        let used = O::of_members(considered.message().to_vec(), used)?;
        Ok(Self { considered, used })
    }
}

/// One fix (formats 7 and 8): where one transmission was sent from, the model it was solved
/// under, what it considered and what it used. Of format 7 with raw `ObservationSet`s; of format
/// 8 (`TaggedFix`) with `TaggedSet`s.
#[derive(Clone, Debug, PartialEq)]
pub struct Fix<O = ObservationSet> {
    /// The aircraft's 24-bit ICAO address.
    pub address: u32,
    pub transmitted: TransmitTime,
    pub lat_e7: i32,
    pub lon_e7: i32,
    /// Millimetres above the WGS84 ellipsoid; `None` when the engine solved no altitude.
    pub alt_hae_mm: Option<i32>,
    pub covariance: EnuCovariance,
    /// The id (`ClockModel::id`) of the trailing-window model the fix was solved under.
    pub model: Hash,
    /// What it considered and what it used.
    pub sets: FixSets<O>,
}

/// A fix as a client receives it (format 8).
pub type TaggedFix = Fix<TaggedSet>;
/// A format 8 record's content.
pub type TaggedFixesContent = FixesContent<TaggedSet>;

impl<O: Members> Fix<O> {
    /// What it considered: every reception of its transmission that had arrived when it was
    /// solved.
    pub fn considered(&self) -> &O {
        self.sets.considered()
    }

    /// What it used, a subset of what it considered.
    pub fn used(&self) -> &O {
        self.sets.used()
    }

    /// How this fix stands to `other` by what each considered (`Relation`): fixes under
    /// different models are `Incomparable`, never averaged, whatever their sets, since two
    /// relays' models of one tile may differ when each fitted what had arrived.
    pub fn relation(&self, other: &Self) -> Relation {
        if self.model != other.model {
            return Relation::Incomparable;
        }
        self.considered().relation_to(other.considered())
    }

    /// Its identity: BLAKE2s-256 over `"tally fix identity" 0x00`, the model's id and the
    /// considered set's hash. Two fixes are `Relation::Equal` exactly when their identities are
    /// equal: the same considered set under the same model, which an honest engine solves to the
    /// same fix.
    pub fn identity(&self) -> Hash {
        let mut hasher = Blake2s256::new();
        hasher.update(FIX_IDENTITY_DOMAIN);
        hasher.update([0]);
        hasher.update(self.model);
        hasher.update(self.considered().set_hash());
        hasher.finalize().into()
    }

    /// What signing and reading a fix both hold it to, as a solution's (`Solution::check`).
    fn check(&self) -> Result<(), WireError> {
        self.transmitted.check()?;
        crate::batch::check_coordinates(self.lat_e7, self.lon_e7)?;
        self.covariance.check()?;
        if self.alt_hae_mm == Some(NO_ALTITUDE) {
            return Err(WireError::Invalid {
                field: "altitude",
                value: u64::from(NO_ALTITUDE.unsigned_abs()),
            });
        }
        Ok(())
    }
}

impl Fix {
    /// The fix as a client sees it: both sets tagged (`ObservationSet::tagged`), its mask over the
    /// tags' own order.
    pub fn tagged(
        &self,
        key_of: impl Fn(&PublicKey) -> Option<crate::site::ReceptionKey>,
    ) -> Result<TaggedFix, WireError> {
        Ok(Fix {
            address: self.address,
            transmitted: self.transmitted,
            lat_e7: self.lat_e7,
            lon_e7: self.lon_e7,
            alt_hae_mm: self.alt_hae_mm,
            covariance: self.covariance,
            model: self.model,
            sets: FixSets::new(
                self.considered().tagged(&key_of)?,
                self.used().tagged(&key_of)?,
            )?,
        })
    }
}

/// What a format 7 (or, with `TaggedSet`, a format 8) record says.
#[derive(Clone, Debug, PartialEq)]
pub struct FixesContent<O = ObservationSet> {
    /// As `SolutionsContent::boot_id`.
    pub boot_id: u64,
    pub sequence: u64,
    pub issued_ms: u64,
    /// The version of the solver specification every fix here was computed under.
    pub spec_version: u16,
    pub fixes: Vec<Fix<O>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Positions {
    bytes: Vec<u8>,
}

impl Positions {
    /// Signs a format 3 record. Refused when a solution is malformed or the record would be
    /// larger than `MAX_POSITIONS_LEN`.
    pub fn sign_solutions(
        identity: &impl Signs,
        content: &SolutionsContent,
    ) -> Result<Self, WireError> {
        Self::sign_format(identity, content, POSITIONS_FORMAT_3)
    }

    /// Signs a provisional (format 4) record: as `sign_solutions`, and refused when a solution
    /// names an addressed citation.
    pub fn sign_provisional(
        identity: &impl Signs,
        content: &SolutionsContent,
    ) -> Result<Self, WireError> {
        Self::sign_format(identity, content, POSITIONS_FORMAT_PROVISIONAL)
    }

    fn sign_format(
        identity: &impl Signs,
        content: &SolutionsContent,
        format: u8,
    ) -> Result<Self, WireError> {
        for solution in &content.solutions {
            solution.check()?;
            provisional_citation(format == POSITIONS_FORMAT_PROVISIONAL, &solution.addressed)?;
        }
        let receivers: Vec<PublicKey> = content
            .solutions
            .iter()
            .flat_map(|solution| solution.observations.receptions())
            .map(|reception| reception.receiver)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let clocks: Vec<Hash> = content
            .solutions
            .iter()
            .map(|solution| solution.clock_model)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let mut bytes = prefix(format, identity, content.boot_id, content.sequence);
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&content.spec_version.to_be_bytes());
        bytes.extend_from_slice(&count_u16(receivers.len())?.to_be_bytes());
        for receiver in &receivers {
            bytes.extend_from_slice(receiver.as_bytes());
        }
        bytes.extend_from_slice(&count_u16(clocks.len())?.to_be_bytes());
        for clock in &clocks {
            bytes.extend_from_slice(clock);
        }
        bytes.extend_from_slice(&count_u16(content.solutions.len())?.to_be_bytes());
        for solution in &content.solutions {
            put_solution(
                &mut bytes,
                solution,
                index_of(&clocks, &solution.clock_model)?,
                |receiver| index_of(&receivers, receiver),
            )?;
        }
        if bytes.len() + SIGNATURE_LEN > MAX_POSITIONS_LEN {
            return Err(WireError::Oversize(bytes.len() + SIGNATURE_LEN));
        }
        Ok(Self::signed(identity, bytes))
    }

    /// How many of `solutions`, from the first, one record holds: the longest prefix whose record
    /// is within `MAX_POSITIONS_LEN`, in any format, by any engine and under any numbering (none
    /// changes a record's length). Measured as `sign_format` lays a record out, one solution at a
    /// time, so a caller cutting a step's solutions into records signs each record once: cutting by
    /// signing ever shorter prefixes of all that is left (a binary search from the whole) cost a
    /// window step of 80,000 solutions two minutes of one thread. A solution `sign_format`
    /// would refuse for its content is counted by its length all the same; signing says so.
    pub fn fitting(solutions: &[Solution]) -> usize {
        // Format to sequence, issued, specification version, and the three tables' counts.
        let mut len = PREFIX_LEN + 8 + 2 + 2 + 2 + 2 + SIGNATURE_LEN;
        let mut receivers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut clocks: BTreeSet<Hash> = BTreeSet::new();
        let mut scratch = Vec::new();
        for (at, solution) in solutions.iter().enumerate() {
            scratch.clear();
            if put_solution(&mut scratch, solution, 0, |_| Ok(0)).is_err() {
                return at;
            }
            len += scratch.len();
            if clocks.insert(solution.clock_model) {
                len += solution.clock_model.len();
            }
            for reception in solution.observations.receptions() {
                if receivers.insert(reception.receiver) {
                    len += KEY_LEN;
                }
            }
            if len > MAX_POSITIONS_LEN
                || receivers.len() > usize::from(u16::MAX)
                || clocks.len() > usize::from(u16::MAX)
                || at >= usize::from(u16::MAX)
            {
                return at;
            }
        }
        solutions.len()
    }

    pub(crate) fn signed(identity: &impl Signs, mut bytes: Vec<u8>) -> Self {
        let signature = identity.sign(&domain(POSITIONS_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        Self { bytes }
    }

    /// Accepts any format whose fixed prefix is well formed. Does not check the signature.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() < PREFIX_LEN + SIGNATURE_LEN {
            return Err(WireError::Truncated {
                needed: PREFIX_LEN + SIGNATURE_LEN,
                had: bytes.len(),
            });
        }
        PublicKey::from_slice(&bytes[1..1 + KEY_LEN])?;
        Ok(Self { bytes })
    }

    /// What it allocates of its own: its bytes' capacity.
    pub fn allocated(&self) -> usize {
        crate::footprint::vec::<u8>(self.bytes.capacity())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    /// Whether the record is provisional: superseded by the final positions that follow it, and
    /// carried under a record kind of its own.
    pub fn is_provisional(&self) -> bool {
        matches!(
            self.format(),
            POSITIONS_FORMAT_PROVISIONAL | POSITIONS_FORMAT_TAGGED_PROVISIONAL
        )
    }

    /// Whether its receptions are tags (formats 5, 6 and 8): the only positions a client is sent.
    pub fn is_tagged(&self) -> bool {
        matches!(
            self.format(),
            POSITIONS_FORMAT_TAGGED
                | POSITIONS_FORMAT_TAGGED_PROVISIONAL
                | POSITIONS_FORMAT_TAGGED_FIX
        )
    }

    /// Whether it is a record of fixes (formats 7 and 8).
    pub fn is_fix(&self) -> bool {
        matches!(
            self.format(),
            POSITIONS_FORMAT_FIX | POSITIONS_FORMAT_TAGGED_FIX
        )
    }

    pub fn engine(&self) -> Result<PublicKey, WireError> {
        PublicKey::from_slice(&self.bytes[1..1 + KEY_LEN])
    }

    pub fn boot_id(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN)
    }

    pub fn sequence(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN + 8)
    }

    /// Its signed `issued_ms` (`SolutionsContent::issued_ms`), read without decoding a solution: what a
    /// relay's time window judges it by.
    pub fn issued_ms(&self) -> Result<u64, WireError> {
        crate::batch::u64_from(&self.bytes, 1 + KEY_LEN + 16)
    }

    /// BLAKE2s over the whole signed record: its identity for deduplication.
    pub fn hash(&self) -> Hash {
        Blake2s256::digest(&self.bytes).into()
    }

    pub fn verify(&self) -> Result<(), WireError> {
        let (signed, signature) = split_signature(&self.bytes)?;
        self.engine()?
            .verify(&domain(POSITIONS_DOMAIN, signed), &signature)
    }

    /// The content of a format 3 or a provisional (format 4) record. Refuses a record that is
    /// not in its one canonical form (tables ascending, without repeats and all used;
    /// observations in canonical order; no addressed citation in a provisional), so a solution
    /// read back re-signs to the same bytes.
    pub fn solutions(&self) -> Result<SolutionsContent, WireError> {
        if self.format() != POSITIONS_FORMAT_PROVISIONAL {
            self.expect_format(POSITIONS_FORMAT_3)?;
        }
        let provisional = self.is_provisional();
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let spec_version = reader.u16()?;
        let receivers = (0..reader.u16()?)
            .map(|_| PublicKey::from_slice(reader.bytes(KEY_LEN)?))
            .collect::<Result<Vec<_>, _>>()?;
        ascending(&receivers, "receiver table order")?;
        let clocks = (0..reader.u16()?)
            .map(|_| reader.array::<32>())
            .collect::<Result<Vec<Hash>, _>>()?;
        ascending(&clocks, "clock model table order")?;
        let mut receivers_used = vec![false; receivers.len()];
        let mut clocks_used = vec![false; clocks.len()];
        let count = reader.u16()?;
        let mut solutions = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let address = reader.u32()?;
            let length = usize::from(reader.u8()?);
            let message = reader.bytes(length)?.to_vec();
            let transmitted = TransmitTime::new(reader.u64()?, reader.u32()?)?;
            let lat_e7 = reader.i32()?;
            let lon_e7 = reader.i32()?;
            let alt_hae_mm = Some(reader.i32()?).filter(|alt| *alt != NO_ALTITUDE);
            let mut terms = [0.0; 6];
            for term in &mut terms {
                *term = reader.f32()?;
            }
            let clock_model = *lookup(&clocks, &mut clocks_used, reader.u16()?, "clock index")?;
            let addressed = AddressedCitation {
                hash: reader.array::<32>()?,
                count: reader.u32()?,
            };
            provisional_citation(provisional, &addressed)?;
            let observed = usize::from(reader.u8()?);
            let mut wire_order = Vec::with_capacity(observed);
            let mut receptions = Vec::with_capacity(observed);
            for _ in 0..observed {
                let index = reader.u16()?;
                let receiver = *lookup(&receivers, &mut receivers_used, index, "receiver index")?;
                let epoch = reader.u32()?;
                let counter = reader.counter()?;
                wire_order.push((index, epoch, counter));
                receptions.push(Reception {
                    receiver,
                    epoch,
                    counter,
                });
            }
            ascending(&wire_order, "observation order")?;
            let solution = Solution {
                address,
                transmitted,
                lat_e7,
                lon_e7,
                alt_hae_mm,
                covariance: EnuCovariance::from_terms(terms),
                clock_model,
                addressed,
                observations: ObservationSet::new(message, receptions)?,
            };
            solution.check()?;
            solutions.push(solution);
        }
        if receivers_used.contains(&false) || clocks_used.contains(&false) {
            return Err(WireError::Invalid {
                field: "unused table entry",
                value: 0,
            });
        }
        Ok(SolutionsContent {
            boot_id,
            sequence,
            issued_ms,
            spec_version,
            solutions,
        })
    }

    /// Signs a format 5 record: what a client is sent in place of format 3. Refused as
    /// `sign_solutions` refuses.
    pub fn sign_tagged(
        identity: &impl Signs,
        content: &TaggedSolutionsContent,
    ) -> Result<Self, WireError> {
        Self::sign_tagged_format(identity, content, POSITIONS_FORMAT_TAGGED)
    }

    /// Signs a format 6 record: provisional, tagged; refused when a solution names an addressed
    /// citation.
    pub fn sign_tagged_provisional(
        identity: &impl Signs,
        content: &TaggedSolutionsContent,
    ) -> Result<Self, WireError> {
        Self::sign_tagged_format(identity, content, POSITIONS_FORMAT_TAGGED_PROVISIONAL)
    }

    fn sign_tagged_format(
        identity: &impl Signs,
        content: &TaggedSolutionsContent,
        format: u8,
    ) -> Result<Self, WireError> {
        for solution in &content.solutions {
            solution.check()?;
            provisional_citation(
                format == POSITIONS_FORMAT_TAGGED_PROVISIONAL,
                &solution.addressed,
            )?;
        }
        let clocks: Vec<Hash> = content
            .solutions
            .iter()
            .map(|solution| solution.clock_model)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut bytes = prefix(format, identity, content.boot_id, content.sequence);
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&content.spec_version.to_be_bytes());
        bytes.extend_from_slice(&count_u16(clocks.len())?.to_be_bytes());
        for clock in &clocks {
            bytes.extend_from_slice(clock);
        }
        bytes.extend_from_slice(&count_u16(content.solutions.len())?.to_be_bytes());
        for solution in &content.solutions {
            put_tagged(
                &mut bytes,
                solution,
                index_of(&clocks, &solution.clock_model)?,
            );
        }
        if bytes.len() + SIGNATURE_LEN > MAX_POSITIONS_LEN {
            return Err(WireError::Oversize(bytes.len() + SIGNATURE_LEN));
        }
        Ok(Self::signed(identity, bytes))
    }

    /// As `fitting`, for a tagged record: the longest prefix of `solutions` one format 5 or 6
    /// record holds.
    pub fn fitting_tagged(solutions: &[TaggedSolution]) -> usize {
        // Format to sequence, issued, specification version, and the two tables' counts.
        let mut len = PREFIX_LEN + 8 + 2 + 2 + 2 + SIGNATURE_LEN;
        let mut clocks: BTreeSet<Hash> = BTreeSet::new();
        let mut scratch = Vec::new();
        for (at, solution) in solutions.iter().enumerate() {
            scratch.clear();
            put_tagged(&mut scratch, solution, 0);
            len += scratch.len();
            if clocks.insert(solution.clock_model) {
                len += solution.clock_model.len();
            }
            if len > MAX_POSITIONS_LEN
                || clocks.len() > usize::from(u16::MAX)
                || at >= usize::from(u16::MAX)
            {
                return at;
            }
        }
        solutions.len()
    }

    /// The content of a format 5 or 6 record, refusing one not in its canonical form (the clock
    /// table ascending, without repeats and all used; tags ascending; no addressed citation in a
    /// provisional), so a solution read back re-signs to the same bytes.
    pub fn tagged_solutions(&self) -> Result<TaggedSolutionsContent, WireError> {
        if !self.is_tagged() || self.is_fix() {
            return Err(WireError::Invalid {
                field: "positions format",
                value: u64::from(self.format()),
            });
        }
        let provisional = self.is_provisional();
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let spec_version = reader.u16()?;
        let clocks = (0..reader.u16()?)
            .map(|_| reader.array::<32>())
            .collect::<Result<Vec<Hash>, _>>()?;
        ascending(&clocks, "clock model table order")?;
        let mut clocks_used = vec![false; clocks.len()];
        let count = reader.u16()?;
        let mut solutions = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let address = reader.u32()?;
            let length = usize::from(reader.u8()?);
            let message = reader.bytes(length)?.to_vec();
            let transmitted = TransmitTime::new(reader.u64()?, reader.u32()?)?;
            let lat_e7 = reader.i32()?;
            let lon_e7 = reader.i32()?;
            let alt_hae_mm = Some(reader.i32()?).filter(|alt| *alt != NO_ALTITUDE);
            let mut terms = [0.0; 6];
            for term in &mut terms {
                *term = reader.f32()?;
            }
            let clock_model = *lookup(&clocks, &mut clocks_used, reader.u16()?, "clock index")?;
            let addressed = AddressedCitation {
                hash: reader.array::<32>()?,
                count: reader.u32()?,
            };
            provisional_citation(provisional, &addressed)?;
            let tags = (0..reader.u8()?)
                .map(|_| reader.array::<TAG_LEN>().map(ReceptionTag))
                .collect::<Result<Vec<_>, _>>()?;
            ascending(&tags, "tag order")?;
            let solution = Solution {
                address,
                transmitted,
                lat_e7,
                lon_e7,
                alt_hae_mm,
                covariance: EnuCovariance::from_terms(terms),
                clock_model,
                addressed,
                observations: TaggedSet::new(message, tags)?,
            };
            solution.check()?;
            solutions.push(solution);
        }
        if clocks_used.contains(&false) {
            return Err(WireError::Invalid {
                field: "unused table entry",
                value: 0,
            });
        }
        Ok(SolutionsContent {
            boot_id,
            sequence,
            issued_ms,
            spec_version,
            solutions,
        })
    }

    fn expect_format(&self, format: u8) -> Result<(), WireError> {
        if self.format() != format {
            return Err(WireError::Invalid {
                field: "positions format",
                value: u64::from(self.format()),
            });
        }
        Ok(())
    }
}

impl Positions {
    /// Signs a format 7 record of fixes. Refused when a fix is malformed or the record would be
    /// larger than `MAX_POSITIONS_LEN`.
    pub fn sign_fix(identity: &impl Signs, content: &FixesContent) -> Result<Self, WireError> {
        for fix in &content.fixes {
            fix.check()?;
        }
        let receivers: Vec<PublicKey> = content
            .fixes
            .iter()
            .flat_map(|fix| fix.considered().receptions())
            .map(|reception| reception.receiver)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let clocks = models_of(&content.fixes);
        let mut bytes = prefix(
            POSITIONS_FORMAT_FIX,
            identity,
            content.boot_id,
            content.sequence,
        );
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&content.spec_version.to_be_bytes());
        bytes.extend_from_slice(&count_u16(receivers.len())?.to_be_bytes());
        for receiver in &receivers {
            bytes.extend_from_slice(receiver.as_bytes());
        }
        bytes.extend_from_slice(&count_u16(clocks.len())?.to_be_bytes());
        for clock in &clocks {
            bytes.extend_from_slice(clock);
        }
        bytes.extend_from_slice(&count_u16(content.fixes.len())?.to_be_bytes());
        for fix in &content.fixes {
            put_fix(
                &mut bytes,
                fix,
                index_of(&clocks, &fix.model)?,
                |receiver| index_of(&receivers, receiver),
            )?;
        }
        if bytes.len() + SIGNATURE_LEN > MAX_POSITIONS_LEN {
            return Err(WireError::Oversize(bytes.len() + SIGNATURE_LEN));
        }
        Ok(Self::signed(identity, bytes))
    }

    /// Signs a format 8 record: what a client is sent in place of format 7. Refused as
    /// `sign_fix` refuses.
    pub fn sign_tagged_fix(
        identity: &impl Signs,
        content: &TaggedFixesContent,
    ) -> Result<Self, WireError> {
        for fix in &content.fixes {
            fix.check()?;
        }
        let clocks = models_of(&content.fixes);
        let mut bytes = prefix(
            POSITIONS_FORMAT_TAGGED_FIX,
            identity,
            content.boot_id,
            content.sequence,
        );
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&content.spec_version.to_be_bytes());
        bytes.extend_from_slice(&count_u16(clocks.len())?.to_be_bytes());
        for clock in &clocks {
            bytes.extend_from_slice(clock);
        }
        bytes.extend_from_slice(&count_u16(content.fixes.len())?.to_be_bytes());
        for fix in &content.fixes {
            put_tagged_fix(&mut bytes, fix, index_of(&clocks, &fix.model)?);
        }
        if bytes.len() + SIGNATURE_LEN > MAX_POSITIONS_LEN {
            return Err(WireError::Oversize(bytes.len() + SIGNATURE_LEN));
        }
        Ok(Self::signed(identity, bytes))
    }

    /// As `fitting`, for fixes: the longest prefix of `fixes` one format 7 record holds, measured
    /// as `sign_fix` lays it out.
    pub fn fitting_fixes(fixes: &[Fix]) -> usize {
        // Format to sequence, issued, specification version, and the three tables' counts.
        let mut len = PREFIX_LEN + 8 + 2 + 2 + 2 + 2 + SIGNATURE_LEN;
        let mut receivers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut clocks: BTreeSet<Hash> = BTreeSet::new();
        let mut scratch = Vec::new();
        for (at, fix) in fixes.iter().enumerate() {
            scratch.clear();
            if put_fix(&mut scratch, fix, 0, |_| Ok(0)).is_err() {
                return at;
            }
            len += scratch.len();
            if clocks.insert(fix.model) {
                len += fix.model.len();
            }
            for reception in fix.considered().receptions() {
                if receivers.insert(reception.receiver) {
                    len += KEY_LEN;
                }
            }
            if len > MAX_POSITIONS_LEN
                || receivers.len() > usize::from(u16::MAX)
                || clocks.len() > usize::from(u16::MAX)
                || at >= usize::from(u16::MAX)
            {
                return at;
            }
        }
        fixes.len()
    }

    /// As `fitting_fixes`, for a format 8 record.
    pub fn fitting_tagged_fixes(fixes: &[TaggedFix]) -> usize {
        // Format to sequence, issued, specification version, and the two tables' counts.
        let mut len = PREFIX_LEN + 8 + 2 + 2 + 2 + SIGNATURE_LEN;
        let mut clocks: BTreeSet<Hash> = BTreeSet::new();
        let mut scratch = Vec::new();
        for (at, fix) in fixes.iter().enumerate() {
            scratch.clear();
            put_tagged_fix(&mut scratch, fix, 0);
            len += scratch.len();
            if clocks.insert(fix.model) {
                len += fix.model.len();
            }
            if len > MAX_POSITIONS_LEN
                || clocks.len() > usize::from(u16::MAX)
                || at >= usize::from(u16::MAX)
            {
                return at;
            }
        }
        fixes.len()
    }

    /// The content of a format 7 record. Refuses a record not in its one canonical form (tables
    /// ascending, without repeats and all used; considered receptions in canonical order; a used
    /// mask naming at least one considered reception and nothing past them), so a fix read back
    /// re-signs to the same bytes.
    pub fn fixes(&self) -> Result<FixesContent, WireError> {
        self.expect_format(POSITIONS_FORMAT_FIX)?;
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let spec_version = reader.u16()?;
        let receivers = (0..reader.u16()?)
            .map(|_| PublicKey::from_slice(reader.bytes(KEY_LEN)?))
            .collect::<Result<Vec<_>, _>>()?;
        ascending(&receivers, "receiver table order")?;
        let clocks = (0..reader.u16()?)
            .map(|_| reader.array::<32>())
            .collect::<Result<Vec<Hash>, _>>()?;
        ascending(&clocks, "clock model table order")?;
        let mut receivers_used = vec![false; receivers.len()];
        let mut clocks_used = vec![false; clocks.len()];
        let count = reader.u16()?;
        let mut fixes = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let model = *lookup(&clocks, &mut clocks_used, reader.u16()?, "clock index")?;
            let considered = usize::from(reader.u16()?);
            let mut wire_order = Vec::with_capacity(considered);
            let mut receptions = Vec::with_capacity(considered);
            for _ in 0..considered {
                let index = reader.u16()?;
                let receiver = *lookup(&receivers, &mut receivers_used, index, "receiver index")?;
                let epoch = reader.u32()?;
                let counter = reader.counter()?;
                wire_order.push((index, epoch, counter));
                receptions.push(Reception {
                    receiver,
                    epoch,
                    counter,
                });
            }
            ascending(&wire_order, "observation order")?;
            let mask = reader.bytes(considered.div_ceil(8))?;
            let fix = read_fix_rest(&mut reader, model, mask, |message| {
                ObservationSet::new(message, receptions)
            })?;
            fixes.push(fix);
        }
        if receivers_used.contains(&false) || clocks_used.contains(&false) {
            return Err(WireError::Invalid {
                field: "unused table entry",
                value: 0,
            });
        }
        Ok(FixesContent {
            boot_id,
            sequence,
            issued_ms,
            spec_version,
            fixes,
        })
    }

    /// The content of a format 8 record, refusing one not in its canonical form as `fixes` does
    /// (tags ascending in place of receptions).
    pub fn tagged_fixes(&self) -> Result<TaggedFixesContent, WireError> {
        self.expect_format(POSITIONS_FORMAT_TAGGED_FIX)?;
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let spec_version = reader.u16()?;
        let clocks = (0..reader.u16()?)
            .map(|_| reader.array::<32>())
            .collect::<Result<Vec<Hash>, _>>()?;
        ascending(&clocks, "clock model table order")?;
        let mut clocks_used = vec![false; clocks.len()];
        let count = reader.u16()?;
        let mut fixes = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let model = *lookup(&clocks, &mut clocks_used, reader.u16()?, "clock index")?;
            let considered = usize::from(reader.u16()?);
            let tags = (0..considered)
                .map(|_| reader.array::<TAG_LEN>().map(ReceptionTag))
                .collect::<Result<Vec<_>, _>>()?;
            ascending(&tags, "tag order")?;
            let mask = reader.bytes(considered.div_ceil(8))?;
            let fix = read_fix_rest(&mut reader, model, mask, |message| {
                TaggedSet::new(message, tags)
            })?;
            fixes.push(fix);
        }
        if clocks_used.contains(&false) {
            return Err(WireError::Invalid {
                field: "unused table entry",
                value: 0,
            });
        }
        Ok(FixesContent {
            boot_id,
            sequence,
            issued_ms,
            spec_version,
            fixes,
        })
    }
}

/// The ids of the models `fixes` were solved under, ascending and without repeats: a record's
/// clock table.
fn models_of<O>(fixes: &[Fix<O>]) -> Vec<Hash> {
    fixes
        .iter()
        .map(|fix| fix.model)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// One fix as a format 7 record lays it out: what `Positions::sign_fix` writes and
/// `Positions::fitting_fixes` measures.
fn put_fix(
    bytes: &mut Vec<u8>,
    fix: &Fix,
    clock: u16,
    receiver: impl Fn(&PublicKey) -> Result<u16, WireError>,
) -> Result<(), WireError> {
    bytes.extend_from_slice(&clock.to_be_bytes());
    let receptions = fix.considered().receptions();
    // An `ObservationSet` bounds its receptions to a byte.
    bytes.extend_from_slice(&(receptions.len() as u16).to_be_bytes());
    for reception in receptions {
        bytes.extend_from_slice(&receiver(&reception.receiver)?.to_be_bytes());
        bytes.extend_from_slice(&reception.epoch.to_be_bytes());
        bytes.extend_from_slice(&reception.counter.to_be_bytes()[2..]);
    }
    put_fix_rest(bytes, fix);
    Ok(())
}

/// One tagged fix as a format 8 record lays it out.
fn put_tagged_fix(bytes: &mut Vec<u8>, fix: &TaggedFix, clock: u16) {
    bytes.extend_from_slice(&clock.to_be_bytes());
    let tags = fix.considered().tags();
    // A `TaggedSet` bounds its tags to a byte.
    bytes.extend_from_slice(&(tags.len() as u16).to_be_bytes());
    for tag in tags {
        bytes.extend_from_slice(&tag.0);
    }
    put_fix_rest(bytes, fix);
}

/// Every field of a fix after its considered receptions, in both formats: the used mask, then
/// the solution's own fields.
fn put_fix_rest<O: Members>(bytes: &mut Vec<u8>, fix: &Fix<O>) {
    bytes.extend_from_slice(&fix.sets.mask());
    bytes.extend_from_slice(&fix.address.to_be_bytes());
    let message = fix.considered().message();
    // A set bounds its message to a byte.
    bytes.push(message.len() as u8);
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(&fix.transmitted.unix_ms.to_be_bytes());
    bytes.extend_from_slice(&fix.transmitted.sub_ms_ps.to_be_bytes());
    bytes.extend_from_slice(&fix.lat_e7.to_be_bytes());
    bytes.extend_from_slice(&fix.lon_e7.to_be_bytes());
    bytes.extend_from_slice(&fix.alt_hae_mm.unwrap_or(NO_ALTITUDE).to_be_bytes());
    for term in fix.covariance.terms() {
        bytes.extend_from_slice(&term.to_bits().to_be_bytes());
    }
}

/// Reads a fix's fields after its considered receptions and mask, the considered set built by
/// `considered` from the message: what `put_fix_rest` writes, checked as signing checks it.
fn read_fix_rest<O: Members>(
    reader: &mut Body<'_>,
    model: Hash,
    mask: &[u8],
    considered: impl FnOnce(Vec<u8>) -> Result<O, WireError>,
) -> Result<Fix<O>, WireError> {
    let address = reader.u32()?;
    let length = usize::from(reader.u8()?);
    let message = reader.bytes(length)?.to_vec();
    let transmitted = TransmitTime::new(reader.u64()?, reader.u32()?)?;
    let lat_e7 = reader.i32()?;
    let lon_e7 = reader.i32()?;
    let alt_hae_mm = Some(reader.i32()?).filter(|alt| *alt != NO_ALTITUDE);
    let mut terms = [0.0; 6];
    for term in &mut terms {
        *term = reader.f32()?;
    }
    let fix = Fix {
        address,
        transmitted,
        lat_e7,
        lon_e7,
        alt_hae_mm,
        covariance: EnuCovariance::from_terms(terms),
        model,
        sets: FixSets::from_mask(considered(message)?, mask)?,
    };
    fix.check()?;
    Ok(fix)
}

/// A provisional solution names no addressed citation.
fn provisional_citation(provisional: bool, addressed: &AddressedCitation) -> Result<(), WireError> {
    if provisional && *addressed != AddressedCitation::default() {
        return Err(WireError::Invalid {
            field: "provisional addressed citation",
            value: u64::from(addressed.count),
        });
    }
    Ok(())
}

/// One solution as a record lays it out, its clock model's index `clock` and each reception's
/// receiver's from `receiver`: what `Positions::sign_format` writes and `Positions::fitting`
/// measures, one layout for both.
fn put_solution(
    bytes: &mut Vec<u8>,
    solution: &Solution,
    clock: u16,
    receiver: impl Fn(&PublicKey) -> Result<u16, WireError>,
) -> Result<(), WireError> {
    put_common(bytes, solution, clock);
    let receptions = solution.observations.receptions();
    bytes.push(receptions.len() as u8);
    for reception in receptions {
        bytes.extend_from_slice(&receiver(&reception.receiver)?.to_be_bytes());
        bytes.extend_from_slice(&reception.epoch.to_be_bytes());
        bytes.extend_from_slice(&reception.counter.to_be_bytes()[2..]);
    }
    Ok(())
}

/// A tagged solution as a format 5 or 6 record lays it out.
fn put_tagged(bytes: &mut Vec<u8>, solution: &TaggedSolution, clock: u16) {
    put_common(bytes, solution, clock);
    let tags = solution.observations.tags();
    // A `TaggedSet` bounds its tags to a byte.
    bytes.push(tags.len() as u8);
    for tag in tags {
        bytes.extend_from_slice(&tag.0);
    }
}

/// Every field of a solution before its observations, in every format.
fn put_common<O: Observed>(bytes: &mut Vec<u8>, solution: &Solution<O>, clock: u16) {
    bytes.extend_from_slice(&solution.address.to_be_bytes());
    let message = solution.observations.message();
    // An `ObservationSet` bounds its message and its receptions to a byte each.
    bytes.push(message.len() as u8);
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(&solution.transmitted.unix_ms.to_be_bytes());
    bytes.extend_from_slice(&solution.transmitted.sub_ms_ps.to_be_bytes());
    bytes.extend_from_slice(&solution.lat_e7.to_be_bytes());
    bytes.extend_from_slice(&solution.lon_e7.to_be_bytes());
    bytes.extend_from_slice(&solution.alt_hae_mm.unwrap_or(NO_ALTITUDE).to_be_bytes());
    for term in solution.covariance.terms() {
        bytes.extend_from_slice(&term.to_bits().to_be_bytes());
    }
    bytes.extend_from_slice(&clock.to_be_bytes());
    bytes.extend_from_slice(&solution.addressed.hash);
    bytes.extend_from_slice(&solution.addressed.count.to_be_bytes());
}

fn prefix(format: u8, identity: &impl Signs, boot_id: u64, sequence: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(format);
    bytes.extend_from_slice(identity.public().as_bytes());
    bytes.extend_from_slice(&boot_id.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes
}

fn count_u16(count: usize) -> Result<u16, WireError> {
    u16::try_from(count).map_err(|_| WireError::Oversize(count))
}

fn index_of<T: Ord>(table: &[T], item: &T) -> Result<u16, WireError> {
    let at = table.binary_search(item).map_err(|_| WireError::Invalid {
        field: "table entry",
        value: 0,
    })?;
    count_u16(at)
}

fn lookup<'a, T>(
    table: &'a [T],
    used: &mut [bool],
    index: u16,
    field: &'static str,
) -> Result<&'a T, WireError> {
    let at = usize::from(index);
    let invalid = WireError::Invalid {
        field,
        value: u64::from(index),
    };
    let entry = table.get(at).ok_or(invalid)?;
    if let Some(flag) = used.get_mut(at) {
        *flag = true;
    }
    Ok(entry)
}

/// Strictly ascending: in order and without repeats.
pub(crate) fn ascending<T: Ord>(items: &[T], field: &'static str) -> Result<(), WireError> {
    match items.windows(2).position(|pair| pair[0] >= pair[1]) {
        Some(at) => Err(WireError::Invalid {
            field,
            value: at as u64 + 1,
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::key::Identity;
    use crate::observation_set::Reception;

    pub(crate) fn receiver(seed: u8) -> PublicKey {
        Identity::from_seed([seed; 32]).public()
    }

    pub(crate) fn solution(
        clock_model: Hash,
        receivers: &[u8],
        lat_e7: i32,
    ) -> Result<Solution, WireError> {
        let receptions = receivers
            .iter()
            .map(|seed| Reception {
                receiver: receiver(*seed),
                epoch: u32::from(*seed) % 2,
                counter: 0xffff_0000_0000 + u64::from(*seed),
            })
            .collect();
        Ok(Solution {
            address: 0xa1b2c3,
            transmitted: TransmitTime::new(1_791_219_999_000, 123_456_789)?,
            lat_e7,
            lon_e7: -1_221_000_000,
            alt_hae_mm: Some(1_371_600),
            covariance: EnuCovariance {
                xx: 400.0,
                xy: -12.5,
                xz: 3.0,
                yy: 900.0,
                yz: 0.25,
                zz: 2_500.0,
            },
            clock_model,
            addressed: AddressedCitation {
                hash: [5; 32],
                count: 17,
            },
            observations: ObservationSet::new(
                vec![0x8d, 0xa1, 0xb2, 0xc3, 0x58, 0, 1, 2, 3, 4, 5, 6, 7, 8],
                receptions,
            )?,
        })
    }

    pub(crate) fn solutions(sequence: u64, solutions: Vec<Solution>) -> SolutionsContent {
        SolutionsContent {
            boot_id: 0xb007,
            sequence,
            issued_ms: 1_791_220_000_000,
            spec_version: 1,
            solutions,
        }
    }

    fn content() -> Result<SolutionsContent, WireError> {
        let mut second = solution([2; 32], &[9, 3, 4, 7], 374_200_000)?;
        second.alt_hae_mm = None;
        Ok(solutions(
            4,
            vec![solution([1; 32], &[4, 1, 2, 3], 374_100_000)?, second],
        ))
    }

    #[test]
    fn format_3_round_trips_and_verifies() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = content()?;
        let signed = Positions::sign_solutions(&engine, &content)?;
        let back = Positions::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.format(), POSITIONS_FORMAT_3);
        assert_eq!(back.solutions()?, content);
        assert_eq!(
            (back.engine()?, back.boot_id(), back.sequence()),
            (engine.public(), 0xb007, 4)
        );
        // Read back, it signs to the same bytes: one canonical form.
        assert_eq!(
            Positions::sign_solutions(&engine, &back.solutions()?)?,
            signed
        );
        Ok(())
    }

    #[test]
    fn a_provisional_record_round_trips_under_its_own_kind_and_names_no_citation()
    -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let mut content = content()?;
        for solution in &mut content.solutions {
            solution.addressed = AddressedCitation::default();
        }
        let signed = Positions::sign_provisional(&engine, &content)?;
        assert!(signed.is_provisional());
        assert_eq!(signed.format(), POSITIONS_FORMAT_PROVISIONAL);
        assert_eq!(signed.solutions()?, content);
        let mut bytes = Vec::new();
        crate::Record::Provisional(signed.clone()).encode(&mut bytes)?;
        let (back, _) = crate::Record::decode(&bytes)?;
        assert_eq!(back, Some(crate::Record::Provisional(signed.clone())));
        // Each kind refuses the other's format, so a provisional never reaches a reader of final
        // positions as one, nor a final one a reader of provisionals.
        let mut wrong = Vec::new();
        crate::Record::Positions(signed).encode(&mut wrong)?;
        assert!(crate::Record::decode(&wrong).is_err());
        let final_one = Positions::sign_solutions(&engine, &content)?;
        let mut wrong = Vec::new();
        crate::Record::Provisional(final_one).encode(&mut wrong)?;
        assert!(crate::Record::decode(&wrong).is_err());
        // A provisional names no assignment.
        assert!(Positions::sign_provisional(&engine, &self::content()?).is_err());
        Ok(())
    }

    fn raw_content() -> Result<SolutionsContent, WireError> {
        content()
    }

    fn key_of(receiver: &PublicKey) -> Option<crate::site::ReceptionKey> {
        Some(crate::site::ReceptionKey::of_signed(receiver.as_bytes()))
    }

    fn tagged_content() -> Result<TaggedSolutionsContent, WireError> {
        let raw = content()?;
        Ok(SolutionsContent {
            boot_id: raw.boot_id,
            sequence: raw.sequence,
            issued_ms: raw.issued_ms,
            spec_version: raw.spec_version,
            solutions: raw
                .solutions
                .iter()
                .map(|solution| solution.tagged(key_of))
                .collect::<Result<_, _>>()?,
        })
    }

    #[test]
    fn a_tagged_record_round_trips_and_names_no_receiver() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = tagged_content()?;
        let signed = Positions::sign_tagged(&engine, &content)?;
        let back = Positions::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert!(back.is_tagged() && !back.is_provisional());
        assert_eq!(back.format(), POSITIONS_FORMAT_TAGGED);
        assert_eq!(back.tagged_solutions()?, content);
        assert!(back.solutions().is_err());
        assert_eq!(
            Positions::sign_tagged(&engine, &back.tagged_solutions()?)?,
            signed
        );
        // No receiver key appears anywhere in its bytes.
        for solution in &raw_content()?.solutions {
            for reception in solution.observations.receptions() {
                let key = reception.receiver.as_bytes();
                assert!(!signed.as_bytes().windows(key.len()).any(|at| at == key));
            }
        }
        // Raw records are not tagged.
        assert!(!Positions::sign_solutions(&engine, &raw_content()?)?.is_tagged());
        // Provisional: its own kind, no addressed citation.
        let mut provisional = content.clone();
        for solution in &mut provisional.solutions {
            solution.addressed = AddressedCitation::default();
        }
        let signed = Positions::sign_tagged_provisional(&engine, &provisional)?;
        assert!(signed.is_tagged() && signed.is_provisional());
        assert_eq!(signed.tagged_solutions()?, provisional);
        let mut bytes = Vec::new();
        crate::Record::Provisional(signed.clone()).encode(&mut bytes)?;
        assert_eq!(
            crate::Record::decode(&bytes)?.0,
            Some(crate::Record::Provisional(signed))
        );
        assert!(Positions::sign_tagged_provisional(&engine, &content).is_err());
        Ok(())
    }

    #[test]
    fn fitting_tagged_is_the_longest_prefix_a_tagged_record_holds() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let one = solution([1; 32], &[1, 2, 3, 4, 5, 6], 0)?.tagged(key_of)?;
        let all = vec![one; 2_000];
        let fits = Positions::fitting_tagged(&all);
        assert!(fits > 0 && fits < all.len());
        let signed = Positions::sign_tagged(&engine, &solutions_of(all[..fits].to_vec()))?;
        assert!(signed.as_bytes().len() <= MAX_POSITIONS_LEN);
        assert!(matches!(
            Positions::sign_tagged(&engine, &solutions_of(all[..=fits].to_vec())),
            Err(WireError::Oversize(_))
        ));
        Ok(())
    }

    fn solutions_of(solutions: Vec<TaggedSolution>) -> TaggedSolutionsContent {
        SolutionsContent {
            boot_id: 1,
            sequence: 0,
            issued_ms: 0,
            spec_version: 1,
            solutions,
        }
    }

    #[test]
    fn any_changed_byte_of_format_2_fails_verification() -> Result<(), WireError> {
        let signed = Positions::sign_solutions(&Identity::generate()?, &content()?)?;
        for at in 0..signed.as_bytes().len() {
            let mut bytes = signed.as_bytes().to_vec();
            bytes[at] ^= 1;
            let tampered = Positions::from_bytes(bytes);
            assert!(
                tampered.is_err() || tampered.is_ok_and(|record| record.verify().is_err()),
                "byte {at}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_order_solutions_list_receptions_in_does_not_change_the_bytes() -> Result<(), WireError> {
        let engine = Identity::from_seed([3; 32]);
        let a = Positions::sign_solutions(
            &engine,
            &solutions(0, vec![solution([1; 32], &[1, 2, 3, 4], 0)?]),
        )?;
        let b = Positions::sign_solutions(
            &engine,
            &solutions(0, vec![solution([1; 32], &[4, 3, 2, 1], 0)?]),
        )?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn a_non_canonical_format_3_body_is_refused_though_signed() -> Result<(), WireError> {
        let engine = Identity::from_seed([3; 32]);
        let one = solution([1; 32], &[1, 2], 0)?;
        // Hand-built: two receptions on the wire out of canonical order.
        let low = one.observations.receptions()[0];
        let high = one.observations.receptions()[1];
        let mut bytes = prefix(POSITIONS_FORMAT_3, &engine, 0, 0);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(low.receiver.as_bytes());
        bytes.extend_from_slice(high.receiver.as_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&one.address.to_be_bytes());
        bytes.push(1);
        bytes.push(0x8d);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(&[0; 24]);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        // The addressed citation.
        bytes.extend_from_slice(&[0; 36]);
        bytes.push(2);
        for (index, reception) in [(1u16, high), (0u16, low)] {
            bytes.extend_from_slice(&index.to_be_bytes());
            bytes.extend_from_slice(&reception.epoch.to_be_bytes());
            bytes.extend_from_slice(&reception.counter.to_be_bytes()[2..]);
        }
        let record = Positions::signed(&engine, bytes);
        record.verify()?;
        assert!(matches!(
            record.solutions(),
            Err(WireError::Invalid {
                field: "observation order",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn a_malformed_solution_is_refused_at_signing() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let mut bad_time = solution([1; 32], &[1, 2, 3], 0)?;
        bad_time.transmitted.sub_ms_ps = 1_000_000_000;
        let mut bad_covariance = solution([1; 32], &[1, 2, 3], 0)?;
        bad_covariance.covariance.yy = -1.0;
        let mut nan = solution([1; 32], &[1, 2, 3], 0)?;
        nan.covariance.xy = f32::NAN;
        for bad in [bad_time, bad_covariance, nan] {
            assert!(Positions::sign_solutions(&engine, &solutions(0, vec![bad])).is_err());
        }
        Ok(())
    }

    /// `fitting` is exactly the longest prefix a record holds: that prefix signs, one more is
    /// refused for its size, whatever mix of shared and new receivers and models the solutions
    /// cite, in either format.
    #[test]
    fn fitting_is_the_longest_prefix_a_record_holds() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let mut all = Vec::new();
        for at in 0..3_000u32 {
            let model = [(at % 7) as u8; 32];
            let seeds: Vec<u8> = (0..(3 + at % 9))
                .map(|k| ((at * 13 + k * 31) % 251) as u8)
                .collect::<BTreeSet<u8>>()
                .into_iter()
                .collect();
            let mut one = solution(model, &seeds, at as i32)?;
            one.addressed = Default::default();
            all.push(one);
        }
        for start in [0, 1, 500, 1_700] {
            let rest = &all[start..];
            let fits = Positions::fitting(rest);
            assert!(fits > 0 && fits < rest.len(), "{fits}");
            for sign in [Positions::sign_solutions, Positions::sign_provisional] {
                let record = sign(&engine, &solutions(9, rest[..fits].to_vec()))?;
                assert!(record.as_bytes().len() <= MAX_POSITIONS_LEN);
                assert!(matches!(
                    sign(&engine, &solutions(9, rest[..=fits].to_vec())),
                    Err(WireError::Oversize(_))
                ));
            }
        }
        assert_eq!(Positions::fitting(&all[..5]), 5);
        assert_eq!(Positions::fitting(&[]), 0);
        Ok(())
    }

    fn set_of(receivers: &[u8]) -> Result<ObservationSet, WireError> {
        let receptions = receivers
            .iter()
            .map(|seed| Reception {
                receiver: receiver(*seed),
                epoch: u32::from(*seed) % 2,
                counter: 0xffff_0000_0000 + u64::from(*seed),
            })
            .collect();
        ObservationSet::new(
            vec![0x8d, 0xa1, 0xb2, 0xc3, 0x58, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            receptions,
        )
    }

    /// A fix under `model` that considered the receptions of `considered` and used those of
    /// `used`.
    pub(crate) fn fix(model: Hash, considered: &[u8], used: &[u8]) -> Result<Fix, WireError> {
        let base = solution(model, considered, 374_100_000)?;
        Ok(Fix {
            address: base.address,
            transmitted: base.transmitted,
            lat_e7: base.lat_e7,
            lon_e7: base.lon_e7,
            alt_hae_mm: base.alt_hae_mm,
            covariance: base.covariance,
            model,
            sets: FixSets::new(set_of(considered)?, set_of(used)?)?,
        })
    }

    fn fixes_of<O>(fixes: Vec<Fix<O>>) -> FixesContent<O> {
        FixesContent {
            boot_id: 0xb007,
            sequence: 4,
            issued_ms: 1_791_220_000_000,
            spec_version: 7,
            fixes,
        }
    }

    fn fix_content() -> Result<FixesContent, WireError> {
        let mut second = fix([2; 32], &[9, 3, 4, 7, 11], &[3, 9, 11])?;
        second.alt_hae_mm = None;
        Ok(fixes_of(vec![
            fix([1; 32], &[4, 1, 2, 3], &[1, 2, 3, 4])?,
            second,
        ]))
    }

    #[test]
    fn a_fix_record_round_trips_and_names_what_it_considered_and_used() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = fix_content()?;
        let signed = Positions::sign_fix(&engine, &content)?;
        let back = Positions::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.format(), POSITIONS_FORMAT_FIX);
        assert!(back.is_fix() && !back.is_tagged() && !back.is_provisional());
        assert_eq!(back.fixes()?, content);
        assert_eq!(Positions::sign_fix(&engine, &back.fixes()?)?, signed);
        let second = &back.fixes()?.fixes[1];
        assert_eq!(second.considered(), &set_of(&[3, 4, 7, 9, 11])?);
        assert_eq!(second.used(), &set_of(&[3, 9, 11])?);
        // Neither an older reader's content nor the tagged one reads it.
        assert!(back.solutions().is_err() && back.tagged_fixes().is_err());
        assert!(back.tagged_solutions().is_err());
        // It travels under the positions kind, the decode path every positions record takes.
        let mut bytes = Vec::new();
        crate::Record::Positions(signed.clone()).encode(&mut bytes)?;
        assert_eq!(
            crate::Record::decode(&bytes)?.0,
            Some(crate::Record::Positions(signed.clone()))
        );
        let mut wrong = Vec::new();
        crate::Record::Provisional(signed).encode(&mut wrong)?;
        assert!(crate::Record::decode(&wrong).is_err());
        Ok(())
    }

    #[test]
    fn a_tagged_fix_record_round_trips_and_names_no_receiver() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let raw = fix_content()?;
        let content = fixes_of(
            raw.fixes
                .iter()
                .map(|fix| fix.tagged(key_of))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let signed = Positions::sign_tagged_fix(&engine, &content)?;
        let back = Positions::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.format(), POSITIONS_FORMAT_TAGGED_FIX);
        assert!(back.is_fix() && back.is_tagged());
        assert_eq!(back.tagged_fixes()?, content);
        assert_eq!(
            Positions::sign_tagged_fix(&engine, &back.tagged_fixes()?)?,
            signed
        );
        assert!(back.fixes().is_err() && back.tagged_solutions().is_err());
        // The tagged form uses what the raw form used, tag for tag.
        for (tagged, raw) in content.fixes.iter().zip(&raw.fixes) {
            assert_eq!(tagged.used(), &raw.used().tagged(key_of)?);
            assert_eq!(tagged.considered(), &raw.considered().tagged(key_of)?);
        }
        for fix in &raw.fixes {
            for reception in fix.considered().receptions() {
                let key = reception.receiver.as_bytes();
                assert!(!signed.as_bytes().windows(key.len()).any(|at| at == key));
            }
        }
        Ok(())
    }

    /// The mask's length is `ceil(n / 8)`: none for no reception (refused, a set is never empty),
    /// one byte for eight, two for nine, its last seven bits padding.
    #[test]
    fn the_used_mask_is_a_bit_per_considered_reception() -> Result<(), WireError> {
        let eight: Vec<u8> = (1..=8).collect();
        let nine: Vec<u8> = (1..=9).collect();
        let all_eight = FixSets::new(set_of(&eight)?, set_of(&eight)?)?;
        assert_eq!(all_eight.mask(), vec![0xff]);
        // The first and the last in canonical order (by key, not by seed).
        let order = set_of(&eight)?;
        let ends = vec![order.receptions()[0], order.receptions()[7]];
        let ends = ObservationSet::new(order.message().to_vec(), ends)?;
        let first_and_last = FixSets::new(order, ends)?;
        assert_eq!(first_and_last.mask(), vec![0x81]);
        let nine_sets = FixSets::new(set_of(&nine)?, set_of(&nine)?)?;
        assert_eq!(nine_sets.mask(), vec![0xff, 0x80]);
        // Each round trips through its own mask.
        for sets in [all_eight, first_and_last, nine_sets] {
            let back = FixSets::from_mask(sets.considered().clone(), &sets.mask())?;
            assert_eq!(back, sets);
        }
        // No reception considered: no set, and no fix.
        assert!(set_of(&[]).is_err());
        // A mask naming none is refused, as is one of the wrong length.
        assert!(FixSets::from_mask(set_of(&nine)?, &[0, 0]).is_err());
        assert!(FixSets::from_mask(set_of(&nine)?, &[0xff]).is_err());
        assert!(FixSets::from_mask(set_of(&eight)?, &[0xff, 0]).is_err());
        // A bit past the ninth would be a used reception outside the considered set.
        for padding in 1..8u8 {
            assert!(matches!(
                FixSets::from_mask(set_of(&nine)?, &[0xff, 0x80 | (1 << (padding - 1))]),
                Err(WireError::Invalid {
                    field: "used reception outside the considered set",
                    ..
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn a_used_reception_outside_the_considered_set_is_refused() -> Result<(), WireError> {
        // At building: one the considered set does not hold, or of another message.
        assert!(FixSets::new(set_of(&[1, 2, 3])?, set_of(&[1, 4])?).is_err());
        let other_message = ObservationSet::new(vec![0x5d], set_of(&[1])?.receptions().to_vec())?;
        assert!(FixSets::new(set_of(&[1, 2, 3])?, other_message).is_err());
        // On the wire: a signed record whose mask sets a bit past the considered count.
        let engine = Identity::generate()?;
        let one = fixes_of(vec![fix([1; 32], &(1..=9).collect::<Vec<_>>(), &[1])?]);
        let signed = Positions::sign_fix(&engine, &one)?;
        let (body, _) = split_signature(signed.as_bytes())?;
        let mut bytes = body.to_vec();
        // The fix's mask follows its clock index, count and nine receptions, after the tables.
        let tables = PREFIX_LEN + 8 + 2 + 2 + 9 * KEY_LEN + 2 + 32 + 2;
        let mask = tables + 2 + 2 + 9 * (2 + 4 + 6);
        assert_eq!(bytes[mask..mask + 2], one.fixes[0].sets.mask()[..]);
        bytes[mask + 1] |= 0x01;
        let forged = Positions::signed(&engine, bytes);
        forged.verify()?;
        assert!(matches!(
            forged.fixes(),
            Err(WireError::Invalid {
                field: "used reception outside the considered set",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn fixes_relate_by_what_they_considered_under_one_model() -> Result<(), WireError> {
        let small = fix([1; 32], &[1, 2, 3, 4], &[1, 2, 3, 4])?;
        // A superset considered, whatever it used.
        let large = fix([1; 32], &[1, 2, 3, 4, 5], &[1, 2, 3])?;
        let other = fix([1; 32], &[1, 2, 3, 5], &[1, 2, 3, 5])?;
        assert_eq!(small.relation(&large), Relation::Subset);
        assert_eq!(large.relation(&small), Relation::Superset);
        assert_eq!(small.relation(&other), Relation::Incomparable);
        // The same considered set, used differently: the same fix by its identity.
        let same = fix([1; 32], &[1, 2, 3, 4], &[1, 2, 4])?;
        assert_eq!(small.relation(&same), Relation::Equal);
        assert_eq!(small.identity(), same.identity());
        assert_ne!(small.identity(), large.identity());
        // Under another model, never comparable, and another identity.
        let elsewhere = fix([2; 32], &[1, 2, 3, 4, 5], &[1, 2, 3, 4, 5])?;
        assert_eq!(small.relation(&elsewhere), Relation::Incomparable);
        let twin = fix([2; 32], &[1, 2, 3, 4], &[1, 2, 3, 4])?;
        assert_eq!(small.relation(&twin), Relation::Incomparable);
        assert_ne!(small.identity(), twin.identity());
        // Tagged, the same relations hold.
        let tagged = |fix: &Fix| fix.tagged(key_of);
        assert_eq!(tagged(&small)?.relation(&tagged(&large)?), Relation::Subset);
        assert_eq!(
            tagged(&small)?.relation(&tagged(&other)?),
            Relation::Incomparable
        );
        Ok(())
    }

    #[test]
    fn fitting_fixes_is_the_longest_prefix_a_record_holds() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let mut all = Vec::new();
        for at in 0..3_000u32 {
            let seeds: Vec<u8> = (0..(3 + at % 9))
                .map(|k| ((at * 13 + k * 31) % 251) as u8)
                .collect::<BTreeSet<u8>>()
                .into_iter()
                .collect();
            all.push(fix([(at % 7) as u8; 32], &seeds, &seeds[..2])?);
        }
        let fits = Positions::fitting_fixes(&all);
        assert!(fits > 0 && fits < all.len(), "{fits}");
        let record = Positions::sign_fix(&engine, &fixes_of(all[..fits].to_vec()))?;
        assert!(record.as_bytes().len() <= MAX_POSITIONS_LEN);
        assert!(matches!(
            Positions::sign_fix(&engine, &fixes_of(all[..=fits].to_vec())),
            Err(WireError::Oversize(_))
        ));
        let tagged = all
            .iter()
            .map(|fix| fix.tagged(key_of))
            .collect::<Result<Vec<_>, _>>()?;
        let fits = Positions::fitting_tagged_fixes(&tagged);
        assert!(fits > 0 && fits < tagged.len(), "{fits}");
        let record = Positions::sign_tagged_fix(&engine, &fixes_of(tagged[..fits].to_vec()))?;
        assert!(record.as_bytes().len() <= MAX_POSITIONS_LEN);
        assert!(matches!(
            Positions::sign_tagged_fix(&engine, &fixes_of(tagged[..=fits].to_vec())),
            Err(WireError::Oversize(_))
        ));
        assert_eq!(Positions::fitting_fixes(&[]), 0);
        Ok(())
    }

    #[test]
    fn a_record_too_large_for_a_fault_proof_is_refused() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let one = solution([1; 32], &[1, 2, 3, 4, 5, 6], 0)?;
        let mut many = Vec::new();
        loop {
            many.push(one.clone());
            match Positions::sign_solutions(&engine, &solutions(0, many.clone())) {
                Ok(record) => assert!(record.as_bytes().len() <= MAX_POSITIONS_LEN),
                Err(WireError::Oversize(_)) => break,
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }
}
