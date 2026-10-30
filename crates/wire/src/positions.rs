//! What an MLAT engine publishes (RFC-0171 §3.8): positions it solved, signed by the engine's own
//! key. Like a batch it is immutable once signed, keeps a fixed prefix in every format version
//! (format, engine key, boot id, sequence), and is forwarded by relays byte for byte, whatever its
//! format.
//!
//! Formats 1 to 6 are retired, and their bytes are never reused: 1 (a position, a sigma and a
//! receiver count, verifiable by no one) with the engine that wrote it, 2 with specification
//! version 2, and 3 to 6 (a windowed final solution and a provisional one, each raw and tagged)
//! with wire version 4 (`crate::record::FIXES_VERSION`, RFC-0171 §3.8.1 as amended 2026-10-24),
//! which made the fix the one kind of MLAT position. A record of a retired format is refused where
//! a record is read (`Positions::is_retired`, `crate::Record::decode`): dropped from a peer of an
//! older version, and a breach from one of version 4 or later.
//!
//! Formats 7 and 8 (wire version 4, "MLAT in seconds") are the fix: each solved a second or so
//! after its transmission's first reception arrived, under the newest trailing-window pair model
//! of each area its used hearers are in (`tally-mlat-solver`, § Areas), from the receptions that
//! had arrived. A fix names the receptions it considered (what had
//! arrived) and which of them it used (the solver specification's outlier rule over the considered
//! set), so a verifier judges an omission only inside the considered set and never convicts an
//! honest engine that solved before a reception came. Format 7 is relay-only, format 8 what a
//! client receives (each reception a tag, no receiver table). Both travel under the positions kind:
//!
//! ```text
//! format u8 = 7 | engine key [32] | boot_id u64 | sequence u64
//! | issued_ms u64 | spec_version u16
//! | receiver count u16 | count x receiver key [32]        strictly ascending, every one considered
//! | model count u16 | count x model id [32]               strictly ascending, every one used
//! | fix count u16 | count x fix
//! | signature [64]
//!
//! fix = cited count u8 (>= 1) | count x model index u16  strictly ascending
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
//! A fix cites every model it was solved under, one per area of its used hearers, as indices into
//! the record's model table; a verifier looks each one up by its id and refuses a fix whose list
//! is not the one the solver specification names for its used hearers (a missing or an extra id).
//!
//! The used mask has a bit per considered reception in its canonical order: reception `i` is bit
//! `7 - i % 8` of byte `i / 8`. At least one is set, and the bits past the count are zero, so the
//! used set is a subset of the considered set by construction and a mask naming more is refused.
//! The considered count is two bytes, but a set holds at most `MAX_OBSERVATIONS`, as its own hash
//! counts it in one.
//!
//! Every fix is a deterministic function of the models it cites, its used set and the solver
//! specification's version, so consumers can deduplicate it (`Fix::identity`), merge it by set
//! relation (`Fix::relation`), verify it against raw, and prove a fault (`crate::FaultProof`).
//!
//! Every integer is big-endian and every f32 is IEEE 754 big-endian. A fix's raw receptions are in
//! the canonical order of `ObservationSet`, by (receiver key, epoch, counter); since the receiver
//! table is ascending by key, that is ascending by (receiver index, epoch, counter) on the wire.
//! Fields a later version appends after the fixes are signed and ignored by this reader.
//! The signature is Ed25519 over `"tally positions" 0x00` and every byte before it, in every format.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, domain, split_signature, u64_at};
use crate::fault_proof::FAULT_PROOF_OVERHEAD;
use crate::key::{KEY_LEN, PublicKey, SIGNATURE_LEN, Signs};
use crate::observation_set::{ObservationSet, Reception, Relation, TaggedSet};
use crate::record::{Body, MAX_BODY};
use crate::site::{ReceptionTag, TAG_LEN};

/// The fix, relay-only: each names its model, the receptions it considered and which of them it
/// used (module docs). Every format below it is retired.
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
/// The largest positions record an engine signs: half of what a `FaultProof` can carry, so any two
/// of them fit one proof (and either fits one Noise message). A record that would be larger is
/// refused at signing, so a fault can never be unprovable for want of room.
pub const MAX_POSITIONS_LEN: usize = (MAX_BODY - FAULT_PROOF_OVERHEAD) / 2;
/// The most models one fix cites: one per area of its used hearers, and a transmission's hearers
/// are at most `crate::observation_set::MAX_OBSERVATIONS`, so the list's count is one byte.
pub const MAX_FIX_MODELS: usize = u8::MAX as usize;
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
/// from the cited pair models' timing covariance (§3.8.1).
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

/// What a fix names as the receptions it considered and used: the raw set (format 7, relay-only)
/// or the tagged set a client sees (format 8).
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

/// One fix (formats 7 and 8): where one transmission was sent from, the models it was solved
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
    /// The ids (`PairModel::id`) of the trailing-window models the fix was solved under, one per
    /// area of its used hearers: strictly ascending, at least one and at most `MAX_FIX_MODELS`.
    pub models: Vec<Hash>,
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
    /// different model lists are `Incomparable`, never averaged, whatever their sets, since two
    /// relays' models of one area may differ when each fitted what had arrived.
    pub fn relation(&self, other: &Self) -> Relation {
        if self.models != other.models {
            return Relation::Incomparable;
        }
        self.considered().relation_to(other.considered())
    }

    /// Its identity: BLAKE2s-256 over `"tally fix identity" 0x00`, the count of models it cites
    /// as one byte, each model's id in order, and the considered set's hash. Two fixes are
    /// `Relation::Equal` exactly when their identities are equal: the same considered set under
    /// the same models, which an honest engine solves to the same fix.
    pub fn identity(&self) -> Hash {
        let mut hasher = Blake2s256::new();
        hasher.update(FIX_IDENTITY_DOMAIN);
        hasher.update([0]);
        // `check` bounds the list to a byte; a longer one is never signed or read.
        hasher.update([self.models.len() as u8]);
        for model in &self.models {
            hasher.update(model);
        }
        hasher.update(self.considered().set_hash());
        hasher.finalize().into()
    }

    /// What signing and reading a fix both hold it to: a model list strictly ascending of one to
    /// `MAX_FIX_MODELS` ids, a valid transmit time, a position on the globe, a finite covariance
    /// with no negative variance, and no altitude spelled as the "none" marker.
    fn check(&self) -> Result<(), WireError> {
        if self.models.is_empty() || self.models.len() > MAX_FIX_MODELS {
            return Err(WireError::Invalid {
                field: "cited model count",
                value: self.models.len() as u64,
            });
        }
        ascending(&self.models, "cited model order")?;
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
            models: self.models.clone(),
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
    /// Random per engine process start. With `sequence`, names this record uniquely for its
    /// engine, so a restarted engine starts a new stream instead of being refused as a replay.
    pub boot_id: u64,
    /// 0, 1, 2, ... within one boot; a gap is results some hop did not deliver.
    pub sequence: u64,
    pub issued_ms: u64,
    /// The version of the solver specification every fix here was computed under.
    pub spec_version: u16,
    pub fixes: Vec<Fix<O>>,
}

#[derive(Clone, Debug)]
pub struct Positions {
    bytes: Vec<u8>,
    /// Set once `fixes` has read the record whole, its receiver table's keys checked as points
    /// (`PublicKey::from_slice`): a later read of the same bytes takes them as checked. Before
    /// (2026-10-27), every read decompressed every key again, and a relay reads one record in five
    /// places (its twin's check, standing, the figures, the products, its own solved fixes): a
    /// quarter of its duties thread at 2,000 feeders.
    keys_checked: OnceLock<()>,
}

/// Two records are the same record when their bytes are: whether either was read yet is not part
/// of it.
impl PartialEq for Positions {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Positions {}

impl Positions {
    pub(crate) fn signed(identity: &impl Signs, mut bytes: Vec<u8>) -> Self {
        let signature = identity.sign(&domain(POSITIONS_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        Self::of(bytes)
    }

    fn of(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            keys_checked: OnceLock::new(),
        }
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
        Ok(Self::of(bytes))
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

    /// Whether its receptions are tags (format 8): the only positions a client is sent.
    pub fn is_tagged(&self) -> bool {
        self.format() == POSITIONS_FORMAT_TAGGED_FIX
    }

    /// Whether its format is retired (module docs): any below the fix's.
    pub fn is_retired(&self) -> bool {
        self.format() < POSITIONS_FORMAT_FIX
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

    /// Its signed `issued_ms` (`FixesContent::issued_ms`), read without decoding a fix: what a
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
        let models = models_of(&content.fixes);
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
        bytes.extend_from_slice(&count_u16(models.len())?.to_be_bytes());
        for model in &models {
            bytes.extend_from_slice(model);
        }
        bytes.extend_from_slice(&count_u16(content.fixes.len())?.to_be_bytes());
        for fix in &content.fixes {
            put_fix(
                &mut bytes,
                fix,
                |model| index_of(&models, model),
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
        let models = models_of(&content.fixes);
        let mut bytes = prefix(
            POSITIONS_FORMAT_TAGGED_FIX,
            identity,
            content.boot_id,
            content.sequence,
        );
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&content.spec_version.to_be_bytes());
        bytes.extend_from_slice(&count_u16(models.len())?.to_be_bytes());
        for model in &models {
            bytes.extend_from_slice(model);
        }
        bytes.extend_from_slice(&count_u16(content.fixes.len())?.to_be_bytes());
        for fix in &content.fixes {
            put_tagged_fix(&mut bytes, fix, |model| index_of(&models, model))?;
        }
        if bytes.len() + SIGNATURE_LEN > MAX_POSITIONS_LEN {
            return Err(WireError::Oversize(bytes.len() + SIGNATURE_LEN));
        }
        Ok(Self::signed(identity, bytes))
    }

    /// How many of `fixes`, from the first, one format 7 record holds: the longest prefix whose
    /// record is within `MAX_POSITIONS_LEN`, by any engine and under any numbering (none changes a
    /// record's length). Measured as `sign_fix` lays a record out, one fix at a time, so a caller
    /// cutting a step's fixes into records signs each record once. A fix `sign_fix` would refuse
    /// for its content is counted by its length all the same; signing says so.
    pub fn fitting_fixes<'a>(fixes: impl IntoIterator<Item = &'a Fix>) -> usize {
        // Format to sequence, issued, specification version, and the three tables' counts.
        let mut len = PREFIX_LEN + 8 + 2 + 2 + 2 + 2 + SIGNATURE_LEN;
        let mut receivers: BTreeSet<PublicKey> = BTreeSet::new();
        let mut clocks: BTreeSet<Hash> = BTreeSet::new();
        let mut scratch = Vec::new();
        let mut count = 0;
        for (at, fix) in fixes.into_iter().enumerate() {
            count = at + 1;
            scratch.clear();
            if put_fix(&mut scratch, fix, |_| Ok(0), |_| Ok(0)).is_err() {
                return at;
            }
            len += scratch.len();
            for model in &fix.models {
                if clocks.insert(*model) {
                    len += model.len();
                }
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
        count
    }

    /// As `fitting_fixes`, for a format 8 record.
    pub fn fitting_tagged_fixes<'a>(fixes: impl IntoIterator<Item = &'a TaggedFix>) -> usize {
        // Format to sequence, issued, specification version, and the two tables' counts.
        let mut len = PREFIX_LEN + 8 + 2 + 2 + 2 + SIGNATURE_LEN;
        let mut clocks: BTreeSet<Hash> = BTreeSet::new();
        let mut scratch = Vec::new();
        let mut count = 0;
        for (at, fix) in fixes.into_iter().enumerate() {
            count = at + 1;
            scratch.clear();
            if put_tagged_fix(&mut scratch, fix, |_| Ok(0)).is_err() {
                return at;
            }
            len += scratch.len();
            for model in &fix.models {
                if clocks.insert(*model) {
                    len += model.len();
                }
            }
            if len > MAX_POSITIONS_LEN
                || clocks.len() > usize::from(u16::MAX)
                || at >= usize::from(u16::MAX)
            {
                return at;
            }
        }
        count
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
        let checked = self.keys_checked.get().is_some();
        let receivers = (0..reader.u16()?)
            .map(|_| {
                let key = reader.bytes(KEY_LEN)?;
                if checked {
                    PublicKey::checked_before(key)
                } else {
                    PublicKey::from_slice(key)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        ascending(&receivers, "receiver table order")?;
        let clocks = (0..reader.u16()?)
            .map(|_| reader.array::<32>())
            .collect::<Result<Vec<Hash>, _>>()?;
        ascending(&clocks, "model table order")?;
        let mut receivers_used = vec![false; receivers.len()];
        let mut clocks_used = vec![false; clocks.len()];
        let count = reader.u16()?;
        let mut fixes = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let models = read_models(&mut reader, &clocks, &mut clocks_used)?;
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
            let fix = read_fix_rest(&mut reader, models, mask, |message| {
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
        let _ = self.keys_checked.set(());
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
        ascending(&clocks, "model table order")?;
        let mut clocks_used = vec![false; clocks.len()];
        let count = reader.u16()?;
        let mut fixes = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let models = read_models(&mut reader, &clocks, &mut clocks_used)?;
            let considered = usize::from(reader.u16()?);
            let tags = (0..considered)
                .map(|_| reader.array::<TAG_LEN>().map(ReceptionTag))
                .collect::<Result<Vec<_>, _>>()?;
            ascending(&tags, "tag order")?;
            let mask = reader.bytes(considered.div_ceil(8))?;
            let fix = read_fix_rest(&mut reader, models, mask, |message| {
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
/// model table.
fn models_of<O>(fixes: &[Fix<O>]) -> Vec<Hash> {
    fixes
        .iter()
        .flat_map(|fix| fix.models.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// A fix's cited models as both formats lay them out: the count as a byte, then each model's index
/// into the record's model table (`model`), ascending as the list is.
fn put_models(
    bytes: &mut Vec<u8>,
    models: &[Hash],
    model: impl Fn(&Hash) -> Result<u16, WireError>,
) -> Result<(), WireError> {
    let count = u8::try_from(models.len()).map_err(|_| WireError::Oversize(models.len()))?;
    bytes.push(count);
    for id in models {
        bytes.extend_from_slice(&model(id)?.to_be_bytes());
    }
    Ok(())
}

/// Reads a fix's cited models (`put_models`), each an index into `table`, marking it used. The list
/// is checked as signing checks it (`Fix::check`); its indices ascend exactly when the ids do,
/// since the table is ascending.
fn read_models(
    reader: &mut Body<'_>,
    table: &[Hash],
    used: &mut [bool],
) -> Result<Vec<Hash>, WireError> {
    (0..reader.u8()?)
        .map(|_| Ok(*lookup(table, used, reader.u16()?, "model index")?))
        .collect()
}

/// One fix as a format 7 record lays it out: what `Positions::sign_fix` writes and
/// `Positions::fitting_fixes` measures.
fn put_fix(
    bytes: &mut Vec<u8>,
    fix: &Fix,
    model: impl Fn(&Hash) -> Result<u16, WireError>,
    receiver: impl Fn(&PublicKey) -> Result<u16, WireError>,
) -> Result<(), WireError> {
    put_models(bytes, &fix.models, model)?;
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
fn put_tagged_fix(
    bytes: &mut Vec<u8>,
    fix: &TaggedFix,
    model: impl Fn(&Hash) -> Result<u16, WireError>,
) -> Result<(), WireError> {
    put_models(bytes, &fix.models, model)?;
    let tags = fix.considered().tags();
    // A `TaggedSet` bounds its tags to a byte.
    bytes.extend_from_slice(&(tags.len() as u16).to_be_bytes());
    for tag in tags {
        bytes.extend_from_slice(&tag.0);
    }
    put_fix_rest(bytes, fix);
    Ok(())
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
    models: Vec<Hash>,
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
        models,
        sets: FixSets::from_mask(considered(message)?, mask)?,
    };
    fix.check()?;
    Ok(fix)
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

    fn key_of(receiver: &PublicKey) -> Option<crate::site::ReceptionKey> {
        Some(crate::site::ReceptionKey::of_signed(receiver.as_bytes()))
    }

    /// The receptions of the one test transmission by the receivers seeded `receivers`.
    pub(crate) fn set_of(receivers: &[u8]) -> Result<ObservationSet, WireError> {
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

    /// A fix under `model` at `lat_e7` that considered the receptions of `considered` and used
    /// those of `used`.
    pub(crate) fn fix_at(
        model: Hash,
        considered: &[u8],
        used: &[u8],
        lat_e7: i32,
    ) -> Result<Fix, WireError> {
        Ok(Fix {
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
            models: vec![model],
            sets: FixSets::new(set_of(considered)?, set_of(used)?)?,
        })
    }

    /// As `fix_at`, at one latitude.
    pub(crate) fn fix(model: Hash, considered: &[u8], used: &[u8]) -> Result<Fix, WireError> {
        fix_at(model, considered, used, 374_100_000)
    }

    /// `fixes` as the content of record `sequence` of one boot.
    pub(crate) fn fixes_of<O>(sequence: u64, fixes: Vec<Fix<O>>) -> FixesContent<O> {
        FixesContent {
            boot_id: 0xb007,
            sequence,
            issued_ms: 1_791_220_000_000,
            spec_version: 7,
            fixes,
        }
    }

    fn fix_content() -> Result<FixesContent, WireError> {
        let mut second = fix([2; 32], &[9, 3, 4, 7, 11], &[3, 9, 11])?;
        second.alt_hae_mm = None;
        Ok(fixes_of(
            4,
            vec![fix([1; 32], &[4, 1, 2, 3], &[1, 2, 3, 4])?, second],
        ))
    }

    #[test]
    fn a_fix_record_round_trips_and_names_what_it_considered_and_used() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = fix_content()?;
        let signed = Positions::sign_fix(&engine, &content)?;
        let back = Positions::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.format(), POSITIONS_FORMAT_FIX);
        assert!(back.is_fix() && !back.is_tagged() && !back.is_retired());
        assert_eq!(back.fixes()?, content);
        assert_eq!(
            (back.engine()?, back.boot_id(), back.sequence()),
            (engine.public(), 0xb007, 4)
        );
        assert_eq!(back.issued_ms()?, content.issued_ms);
        // Read back, it signs to the same bytes: one canonical form.
        assert_eq!(Positions::sign_fix(&engine, &back.fixes()?)?, signed);
        let second = &back.fixes()?.fixes[1];
        assert_eq!(second.considered(), &set_of(&[3, 4, 7, 9, 11])?);
        assert_eq!(second.used(), &set_of(&[3, 9, 11])?);
        // The tagged reader does not read it.
        assert!(back.tagged_fixes().is_err());
        // It travels under the positions kind.
        let mut bytes = Vec::new();
        crate::Record::Positions(signed.clone()).encode(&mut bytes)?;
        assert_eq!(
            crate::Record::decode(&bytes, crate::record::MAX_VERSION)?.0,
            Some(crate::Record::Positions(signed))
        );
        Ok(())
    }

    #[test]
    fn a_tagged_fix_record_round_trips_and_names_no_receiver() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let raw = fix_content()?;
        let content = fixes_of(
            4,
            raw.fixes
                .iter()
                .map(|fix| fix.tagged(key_of))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let signed = Positions::sign_tagged_fix(&engine, &content)?;
        let back = Positions::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.format(), POSITIONS_FORMAT_TAGGED_FIX);
        assert!(back.is_fix() && back.is_tagged() && !back.is_retired());
        assert_eq!(back.tagged_fixes()?, content);
        assert_eq!(
            Positions::sign_tagged_fix(&engine, &back.tagged_fixes()?)?,
            signed
        );
        assert!(back.fixes().is_err());
        // Raw records are not tagged.
        assert!(!Positions::sign_fix(&engine, &raw)?.is_tagged());
        // The tagged form uses what the raw form used, tag for tag.
        for (tagged, raw) in content.fixes.iter().zip(&raw.fixes) {
            assert_eq!(tagged.used(), &raw.used().tagged(key_of)?);
            assert_eq!(tagged.considered(), &raw.considered().tagged(key_of)?);
        }
        // No receiver key appears anywhere in its bytes.
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
        let one = fixes_of(4, vec![fix([1; 32], &(1..=9).collect::<Vec<_>>(), &[1])?]);
        let signed = Positions::sign_fix(&engine, &one)?;
        let (body, _) = split_signature(signed.as_bytes())?;
        let mut bytes = body.to_vec();
        // The fix's mask follows its one cited model, count and nine receptions, after the tables.
        let tables = PREFIX_LEN + 8 + 2 + 2 + 9 * KEY_LEN + 2 + 32 + 2;
        let mask = tables + 1 + 2 + 2 + 9 * (2 + 4 + 6);
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

    /// A fix lists every model it cites, ascending, in both formats: several round-trip through a
    /// record whose table holds each once; an empty list, one out of order or with a repeat is
    /// refused at signing and on the wire; and two fixes of one considered set under lists that
    /// differ by one model are incomparable and of different identities.
    #[test]
    fn a_fix_lists_every_model_it_cites() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let mut one = fix([1; 32], &[1, 2, 3, 4], &[1, 2, 3, 4])?;
        one.models = vec![[1; 32], [2; 32], [5; 32]];
        let mut two = fix([2; 32], &[1, 2, 3, 5], &[1, 2, 3, 5])?;
        two.models = vec![[2; 32], [9; 32]];
        let content = fixes_of(0, vec![one.clone(), two.clone()]);
        let signed = Positions::sign_fix(&engine, &content)?;
        assert_eq!(signed.fixes()?, content);
        assert_eq!(Positions::fitting_fixes(&content.fixes), 2);
        let tagged = |fix: &Fix| fix.tagged(key_of);
        let tagged_content = fixes_of(0, vec![tagged(&one)?, tagged(&two)?]);
        let signed_tagged = Positions::sign_tagged_fix(&engine, &tagged_content)?;
        assert_eq!(signed_tagged.tagged_fixes()?, tagged_content);
        // Four distinct models in the table, each once: [1], [2], [5], [9].
        let (body, _) = split_signature(signed_tagged.as_bytes())?;
        let table = PREFIX_LEN + 8 + 2;
        assert_eq!(u16::from_be_bytes([body[table], body[table + 1]]), 4);
        for bad in [vec![], vec![[2; 32], [1; 32]], vec![[1; 32], [1; 32]]] {
            let mut wrong = one.clone();
            wrong.models = bad;
            assert!(Positions::sign_fix(&engine, &fixes_of(0, vec![wrong])).is_err());
        }
        // On the wire: the first fix's list hand-swapped out of order, re-signed.
        let (body, _) = split_signature(signed.as_bytes())?;
        let mut bytes = body.to_vec();
        let receivers = 5;
        let first = PREFIX_LEN + 8 + 2 + 2 + receivers * KEY_LEN + 2 + 4 * 32 + 2;
        assert_eq!(bytes[first], 3);
        bytes.swap(first + 2, first + 4);
        let forged = Positions::signed(&engine, bytes);
        assert!(matches!(
            forged.fixes(),
            Err(WireError::Invalid {
                field: "cited model order",
                ..
            })
        ));
        let mut fewer = one.clone();
        fewer.models.pop();
        assert_eq!(one.relation(&fewer), Relation::Incomparable);
        assert_ne!(one.identity(), fewer.identity());
        Ok(())
    }

    /// `fitting_fixes` is exactly the longest prefix a record holds: that prefix signs, one more
    /// is refused for its size, whatever mix of shared and new receivers and models the fixes cite,
    /// in either format.
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
            all.push(fix_at(
                [(at % 7) as u8; 32],
                &seeds,
                &seeds[..2],
                at as i32,
            )?);
        }
        for start in [0, 1, 500, 1_700] {
            let rest = &all[start..];
            let fits = Positions::fitting_fixes(rest);
            assert!(fits > 0 && fits < rest.len(), "{fits}");
            let record = Positions::sign_fix(&engine, &fixes_of(9, rest[..fits].to_vec()))?;
            assert!(record.as_bytes().len() <= MAX_POSITIONS_LEN);
            assert!(matches!(
                Positions::sign_fix(&engine, &fixes_of(9, rest[..=fits].to_vec())),
                Err(WireError::Oversize(_))
            ));
        }
        let tagged = all
            .iter()
            .map(|fix| fix.tagged(key_of))
            .collect::<Result<Vec<_>, _>>()?;
        let fits = Positions::fitting_tagged_fixes(&tagged);
        assert!(fits > 0 && fits < tagged.len(), "{fits}");
        let record = Positions::sign_tagged_fix(&engine, &fixes_of(9, tagged[..fits].to_vec()))?;
        assert!(record.as_bytes().len() <= MAX_POSITIONS_LEN);
        assert!(matches!(
            Positions::sign_tagged_fix(&engine, &fixes_of(9, tagged[..=fits].to_vec())),
            Err(WireError::Oversize(_))
        ));
        assert_eq!(Positions::fitting_fixes(&all[..5]), 5);
        assert_eq!(Positions::fitting_fixes(&[]), 0);
        Ok(())
    }

    #[test]
    fn any_changed_byte_of_a_fix_record_fails_verification() -> Result<(), WireError> {
        let signed = Positions::sign_fix(&Identity::generate()?, &fix_content()?)?;
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
    fn the_order_fixes_list_receptions_in_does_not_change_the_bytes() -> Result<(), WireError> {
        let engine = Identity::from_seed([3; 32]);
        let a = Positions::sign_fix(
            &engine,
            &fixes_of(0, vec![fix([1; 32], &[1, 2, 3, 4], &[1, 2])?]),
        )?;
        let b = Positions::sign_fix(
            &engine,
            &fixes_of(0, vec![fix([1; 32], &[4, 3, 2, 1], &[2, 1])?]),
        )?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn a_non_canonical_fix_body_is_refused_though_signed() -> Result<(), WireError> {
        let engine = Identity::from_seed([3; 32]);
        let one = fix([1; 32], &[1, 2], &[1, 2])?;
        // Hand-built: two receptions on the wire out of canonical order.
        let low = one.considered().receptions()[0];
        let high = one.considered().receptions()[1];
        let mut bytes = prefix(POSITIONS_FORMAT_FIX, &engine, 0, 0);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&7u16.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(low.receiver.as_bytes());
        bytes.extend_from_slice(high.receiver.as_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        // The fix: its one cited model, two receptions high first, both used.
        bytes.push(1);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        for (index, reception) in [(1u16, high), (0u16, low)] {
            bytes.extend_from_slice(&index.to_be_bytes());
            bytes.extend_from_slice(&reception.epoch.to_be_bytes());
            bytes.extend_from_slice(&reception.counter.to_be_bytes()[2..]);
        }
        bytes.push(0xc0);
        bytes.extend_from_slice(&one.address.to_be_bytes());
        bytes.push(1);
        bytes.push(0x8d);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(&[0; 24]);
        let record = Positions::signed(&engine, bytes);
        record.verify()?;
        assert!(matches!(
            record.fixes(),
            Err(WireError::Invalid {
                field: "observation order",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn a_malformed_fix_is_refused_at_signing() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let mut bad_time = fix([1; 32], &[1, 2, 3], &[1, 2, 3])?;
        bad_time.transmitted.sub_ms_ps = 1_000_000_000;
        let mut bad_covariance = fix([1; 32], &[1, 2, 3], &[1, 2, 3])?;
        bad_covariance.covariance.yy = -1.0;
        let mut nan = fix([1; 32], &[1, 2, 3], &[1, 2, 3])?;
        nan.covariance.xy = f32::NAN;
        let mut no_altitude = fix([1; 32], &[1, 2, 3], &[1, 2, 3])?;
        no_altitude.alt_hae_mm = Some(NO_ALTITUDE);
        for bad in [bad_time, bad_covariance, nan, no_altitude] {
            assert!(Positions::sign_fix(&engine, &fixes_of(0, vec![bad])).is_err());
        }
        Ok(())
    }

    #[test]
    fn a_record_too_large_for_a_fault_proof_is_refused() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let one = fix([1; 32], &[1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6])?;
        let mut many = Vec::new();
        loop {
            many.push(one.clone());
            match Positions::sign_fix(&engine, &fixes_of(0, many.clone())) {
                Ok(record) => assert!(record.as_bytes().len() <= MAX_POSITIONS_LEN),
                Err(WireError::Oversize(_)) => break,
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    /// Every format below the fix's is retired, whatever its bytes say: no reader of this build
    /// reads one, and `Record::decode` refuses it.
    #[test]
    fn every_format_below_the_fix_is_retired() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        for format in 1..=8u8 {
            let mut bytes = prefix(format, &engine, 0, 0);
            bytes.extend_from_slice(&[0; 24]);
            let record = Positions::signed(&engine, bytes);
            assert_eq!(
                record.is_retired(),
                format < POSITIONS_FORMAT_FIX,
                "{format}"
            );
            assert_eq!(
                record.is_fix(),
                matches!(format, POSITIONS_FORMAT_FIX | POSITIONS_FORMAT_TAGGED_FIX)
            );
            if record.is_retired() {
                assert!(record.fixes().is_err() && record.tagged_fixes().is_err());
            }
        }
        Ok(())
    }
}
