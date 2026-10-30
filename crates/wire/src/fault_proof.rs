//! A fault proof (RFC-0171 §3.8.1), of either of two shapes.
//!
//! Format 1: two signed fixes (`Positions` formats 7 and 8, both raw or both tagged) of the same
//! used set, under the same clock model and the same solver specification, that disagree beyond
//! the specification's tolerance. A fix is solved from its used set alone, under its model (what
//! else it considered only decided what it used), so it is a deterministic function of those
//! three, and two that disagree prove that at least one engine did not compute what it signed.
//! Two fixes that considered different sets but used the same are held to it as one. Anyone may
//! build one from what relays already carry, and anyone can check it with nothing but the proof: a
//! relay checks it before forwarding it, and a consumer that checks it drops the engines on its
//! own authority. A proof of records of a retired format (`Positions::is_retired`) proves nothing,
//! and `crate::Record::decode` refuses one (`FaultProof::retired_format`).
//!
//! The proof is not signed: it is evidence, and the evidence carries the engines' own signatures.
//!
//! ```text
//! format u8 = 1
//! | first length u16 | first Positions record (signed bytes)
//! | second length u16 | second Positions record
//! | first fix index u16 | second fix index u16
//! ```
//!
//! The two (record, index) pairs are in canonical order, by (record hash, index), strictly
//! ascending, so one fault has one proof and relays deduplicate it by `FaultProof::hash`. Every
//! positions record is at most `MAX_POSITIONS_LEN`, so any two fit one proof.
//!
//! Format 2: two signed `ClockModel` manifests with the same specification version and the same
//! inputs (`Manifest::inputs`) whose content (`ClockModel::content_id`) differs. Under
//! specification versions 1 and 2 a model is a deterministic function of its inputs, so two that
//! differ prove that at least one engine did not compute what it signed, with nothing but the two
//! manifests. From version 3 the rule is optimality within the verifier's tolerance, not bytes
//! (RFC-0171 §3.8.1): two honest engines may publish different optima of one inputs, so such a
//! pair proves nothing and `check` refuses it. A dishonest model is shown by the model and its
//! cited raw, which anyone holding the raw checks.
//!
//! ```text
//! format u8 = 2 | first length u16 | first manifest | second length u16 | second manifest
//! ```
//!
//! The two in canonical order, by record hash, strictly ascending. Every manifest is at most
//! `MAX_MANIFEST_LEN`, so any two fit one proof.

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::Hash;
use crate::clock_model::{CLOCK_MODEL_FORMAT, ClockModel};
use crate::key::PublicKey;
use crate::positions::{Fix, FixesContent, Members, Positions};
use crate::record::{Body, MAX_BODY};

pub const FAULT_PROOF_FORMAT: u8 = 1;
/// Two clock model manifests of one inputs that differ.
pub const MODEL_FAULT_PROOF_FORMAT: u8 = 2;
/// The first specification version under which two different models of one inputs are no fault
/// (`check_models`).
pub const MODELS_DIFFER_NOT_A_FAULT_FROM: u16 = 3;
/// The bytes of a proof that are not the two records: format, two lengths, two indices.
pub(crate) const FAULT_PROOF_OVERHEAD: usize = 1 + 2 + 2 + 2 + 2;

/// How far two fixes of one (used set, clock model, spec version) may differ and still agree: floating point differs between implementations, the answer does not. Integer
/// fields are compared in integers, so every checker reaches the same verdict on a proof.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tolerance {
    /// Latitude and longitude, in 10^-7 degrees (longitude across the antimeridian the short way).
    pub position_e7: u32,
    /// Altitude, millimetres.
    pub alt_mm: u32,
    /// Transmit time, nanoseconds.
    pub transmit_ns: u32,
    /// Each covariance term, relative to the larger of the two magnitudes and 1 m^2.
    pub covariance_relative: f32,
}

impl Tolerance {
    /// The tolerance a solver specification version sets, `None` for a version this build does
    /// not know (whose proofs it therefore cannot judge). Here, not in the solver, because relays
    /// judge proofs and depend on the wire alone; the solver refuses to compile with a
    /// `SPEC_VERSION` this does not know (`tally_mlat_solver::clock`), so a version is never
    /// bumped without its tolerance.
    pub const fn for_spec(spec_version: u16) -> Option<Self> {
        match spec_version {
            // About 1 m of latitude, 1 m of altitude, 3 m of light travel, 0.1% of a variance.
            // Version 5 changed what is derived (a gauge's origin, the sync messages kept), not
            // how far two implementations' floating point may differ; version 6 only how a model
            // names its scope's sites (by site id), not any number solved; version 7 the
            // trailing window a model is fitted over and the frontier it cites, not how precisely.
            // Version 8 the pairwise path (a pair model per area), solved to the same precision.
            1..=8 => Some(Self {
                position_e7: 10,
                alt_mm: 1_000,
                transmit_ns: 10,
                covariance_relative: 1e-3,
            }),
            _ => None,
        }
    }

    /// True when the two fixes differ by more than this tolerance anywhere.
    pub fn disagree<O>(&self, a: &Fix<O>, b: &Fix<O>) -> bool {
        let beyond = |difference: u64, limit: u32| difference > u64::from(limit);
        let lat = a.lat_e7.abs_diff(b.lat_e7);
        let lon = {
            const TURN_E7: u32 = 3_600_000_000;
            let raw = a.lon_e7.abs_diff(b.lon_e7) % TURN_E7;
            raw.min(TURN_E7 - raw)
        };
        let alt = match (a.alt_hae_mm, b.alt_hae_mm) {
            (Some(x), Some(y)) => beyond(u64::from(x.abs_diff(y)), self.alt_mm),
            (None, None) => false,
            _ => true,
        };
        let transmit = a.transmitted.unix_ps().abs_diff(b.transmitted.unix_ps());
        let covariance = a
            .covariance
            .terms()
            .iter()
            .zip(b.covariance.terms())
            .any(|(x, y)| (x - y).abs() > self.covariance_relative * x.abs().max(y.abs()).max(1.0));
        a.address != b.address
            || beyond(u64::from(lat), self.position_e7)
            || beyond(u64::from(lon), self.position_e7)
            || alt
            || transmit > u128::from(self.transmit_ns) * 1_000
            || covariance
    }
}

/// What a valid proof proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    Fixes(FixFault),
    Models(ModelFault),
}

impl Fault {
    /// The engines that signed the two records; the same key twice when one engine contradicted
    /// itself.
    pub fn engines(&self) -> [PublicKey; 2] {
        match self {
            Self::Fixes(fault) => fault.engines,
            Self::Models(fault) => fault.engines,
        }
    }
}

/// Two models of the same inputs that differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelFault {
    pub engines: [PublicKey; 2],
    /// The `Manifest::inputs` both name.
    pub inputs: Hash,
    pub spec_version: u16,
}

/// Two fixes of the same inputs that disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixFault {
    /// The engines that signed the two fixes; the same key twice when one engine contradicted
    /// itself.
    pub engines: [PublicKey; 2],
    /// The hash of the used set both fixes name (`ObservationSet::hash`, or `TaggedSet::hash` of
    /// tagged ones).
    pub used: Hash,
    /// The models both fixes cite (`Fix::models`), in their order.
    pub models: Vec<Hash>,
    pub spec_version: u16,
}

/// A fault proof, as bytes. Immutable: forwarding never re-encodes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultProof {
    bytes: Vec<u8>,
}

impl FaultProof {
    /// A proof that fix `a_index` of `a` and `b_index` of `b` disagree. Puts the two in
    /// canonical order; does not check them (`check` does).
    pub fn new(
        a: &Positions,
        a_index: u16,
        b: &Positions,
        b_index: u16,
    ) -> Result<Self, WireError> {
        let (first, second) = if (a.hash(), a_index) <= (b.hash(), b_index) {
            ((a, a_index), (b, b_index))
        } else {
            ((b, b_index), (a, a_index))
        };
        let mut bytes = vec![FAULT_PROOF_FORMAT];
        for (record, _) in [first, second] {
            let record = record.as_bytes();
            let length =
                u16::try_from(record.len()).map_err(|_| WireError::Oversize(record.len()))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(record);
        }
        bytes.extend_from_slice(&first.1.to_be_bytes());
        bytes.extend_from_slice(&second.1.to_be_bytes());
        if bytes.len() > MAX_BODY {
            return Err(WireError::Oversize(bytes.len()));
        }
        Ok(Self { bytes })
    }

    /// A proof that two clock model manifests of the same inputs differ. Puts the two in
    /// canonical order; does not check them (`check` does).
    pub fn models(a: &ClockModel, b: &ClockModel) -> Result<Self, WireError> {
        let hash = |model: &ClockModel| -> Hash { Blake2s256::digest(model.as_bytes()).into() };
        let (first, second) = if hash(a) <= hash(b) { (a, b) } else { (b, a) };
        let mut bytes = vec![MODEL_FAULT_PROOF_FORMAT];
        for record in [first, second] {
            let record = record.as_bytes();
            let length =
                u16::try_from(record.len()).map_err(|_| WireError::Oversize(record.len()))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(record);
        }
        if bytes.len() > MAX_BODY {
            return Err(WireError::Oversize(bytes.len()));
        }
        Ok(Self { bytes })
    }

    /// The two manifests of a format 2 proof, in its order.
    pub fn models_of(&self) -> Result<[ClockModel; 2], WireError> {
        if self.format() != MODEL_FAULT_PROOF_FORMAT {
            return Err(WireError::Invalid {
                field: "fault proof format",
                value: u64::from(self.format()),
            });
        }
        let mut reader = Body::new(&self.bytes[1..]);
        let mut record = || -> Result<ClockModel, WireError> {
            let length = usize::from(reader.u16()?);
            ClockModel::from_bytes(reader.bytes(length)?.to_vec())
        };
        Ok([record()?, record()?])
    }

    /// Accepts any non-empty body, so a proof of a format this build cannot read still decodes
    /// (and is not forwarded, since it cannot be checked).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.is_empty() {
            return Err(WireError::Truncated { needed: 1, had: 0 });
        }
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

    /// BLAKE2s over the whole proof: its identity for deduplication.
    pub fn hash(&self) -> Hash {
        Blake2s256::digest(&self.bytes).into()
    }

    /// The two records and their fix indices, in the proof's order.
    pub fn parts(&self) -> Result<[(Positions, u16); 2], WireError> {
        if self.format() != FAULT_PROOF_FORMAT {
            return Err(WireError::Invalid {
                field: "fault proof format",
                value: u64::from(self.format()),
            });
        }
        let mut reader = Body::new(&self.bytes[1..]);
        let mut record = || -> Result<Positions, WireError> {
            let length = usize::from(reader.u16()?);
            Positions::from_bytes(reader.bytes(length)?.to_vec())
        };
        let first = record()?;
        let second = record()?;
        Ok([(first, reader.u16()?), (second, reader.u16()?)])
    }

    /// The solver specification version of the first record, for choosing the `Tolerance` to
    /// check the proof under.
    pub fn spec_version(&self) -> Result<u16, WireError> {
        if self.format() == MODEL_FAULT_PROOF_FORMAT {
            let [first, _] = self.models_of()?;
            return Ok(first.manifest()?.spec_version);
        }
        let [(first, _), _] = self.parts()?;
        if first.is_tagged() {
            return Ok(first.tagged_fixes()?.spec_version);
        }
        Ok(first.fixes()?.spec_version)
    }

    /// The retired format of a record a format 1 proof carries (`Positions::is_retired`), if it
    /// carries one: a proof of the formats wire version 4 retired, which proves nothing now, and
    /// which `crate::Record::decode` reads as that version says.
    pub fn retired_format(&self) -> Option<u8> {
        if self.format() != FAULT_PROOF_FORMAT {
            return None;
        }
        let parts = self.parts().ok()?;
        parts
            .iter()
            .find(|(record, _)| record.is_retired())
            .map(|(record, _)| record.format())
    }

    /// Checks the proof: both records are fixes (formats 7 and 8) and verify, both tagged or both
    /// raw, the pairs are in canonical order, both name one spec version, both fixes exist and
    /// name the same used set and the same clock model, and they disagree beyond `tolerance`.
    /// What it proves, or why it does not.
    pub fn check(&self, tolerance: &Tolerance) -> Result<Fault, WireError> {
        if self.format() == MODEL_FAULT_PROOF_FORMAT {
            return self.check_models().map(Fault::Models);
        }
        let [(first, i), (second, j)] = self.parts()?;
        if (first.hash(), i) >= (second.hash(), j) {
            return Err(WireError::NotAFault("not in canonical order"));
        }
        for record in [&first, &second] {
            if !record.is_fix() {
                return Err(WireError::NotAFault("not a record of fixes"));
            }
            record.verify()?;
        }
        let engines = [first.engine()?, second.engine()?];
        // Tagged against tagged, raw against raw: a raw and a tagged set are never one set.
        match (first.is_tagged(), second.is_tagged()) {
            (true, true) => fix_fault(
                (&first.tagged_fixes()?, i),
                (&second.tagged_fixes()?, j),
                tolerance,
                engines,
            ),
            (false, false) => fix_fault(
                (&first.fixes()?, i),
                (&second.fixes()?, j),
                tolerance,
                engines,
            ),
            _ => Err(WireError::NotAFault("different used sets")),
        }
    }

    /// Checks a format 2 proof: both manifests verify and are in canonical order, both name one
    /// specification version and the same inputs, and their content differs. Exact: a model is
    /// one set of bytes, so no tolerance applies.
    fn check_models(&self) -> Result<ModelFault, WireError> {
        let [first, second] = self.models_of()?;
        let hash = |model: &ClockModel| -> Hash { Blake2s256::digest(model.as_bytes()).into() };
        if hash(&first) >= hash(&second) {
            return Err(WireError::NotAFault("not in canonical order"));
        }
        for model in [&first, &second] {
            if model.format() != CLOCK_MODEL_FORMAT {
                return Err(WireError::NotAFault("not a format 1 clock model"));
            }
            model.verify()?;
        }
        let (a, b) = (first.manifest()?, second.manifest()?);
        if a.spec_version != b.spec_version {
            return Err(WireError::NotAFault("different spec versions"));
        }
        // From specification version 3 the rule is optimality within tolerance, not bytes: two
        // honest engines may publish different optima of one inputs, so two models that differ
        // prove nothing. What proves a model dishonest is the model and its cited raw, which
        // anyone holding the raw checks.
        if a.spec_version >= MODELS_DIFFER_NOT_A_FAULT_FROM {
            return Err(WireError::NotAFault(
                "models of one inputs may differ from specification version 3",
            ));
        }
        if a.inputs != b.inputs {
            return Err(WireError::NotAFault("different inputs"));
        }
        if first.content_id()? == second.content_id()? {
            return Err(WireError::NotAFault("the models are the same"));
        }
        Ok(ModelFault {
            engines: [first.engine()?, second.engine()?],
            inputs: a.inputs,
            spec_version: a.spec_version,
        })
    }
}

/// Whether fix `i` of `a` and `j` of `b`, of one kind of set, prove a fault.
fn fix_fault<O: Members>(
    (a, i): (&FixesContent<O>, u16),
    (b, j): (&FixesContent<O>, u16),
    tolerance: &Tolerance,
    engines: [PublicKey; 2],
) -> Result<Fault, WireError> {
    if a.spec_version != b.spec_version {
        return Err(WireError::NotAFault("different spec versions"));
    }
    let (Some(x), Some(y)) = (a.fixes.get(usize::from(i)), b.fixes.get(usize::from(j))) else {
        return Err(WireError::NotAFault("no such fix"));
    };
    if x.used() != y.used() {
        return Err(WireError::NotAFault("different used sets"));
    }
    if x.models != y.models {
        return Err(WireError::NotAFault("different clock models"));
    }
    if !tolerance.disagree(x, y) {
        return Err(WireError::NotAFault("the fixes agree within tolerance"));
    }
    Ok(Fault::Fixes(FixFault {
        engines,
        used: x.used().set_hash(),
        models: x.models.clone(),
        spec_version: a.spec_version,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;
    use crate::positions::tests::{fix, fix_at, fixes_of, set_of};

    fn tolerance() -> Result<Tolerance, WireError> {
        Tolerance::for_spec(1).ok_or(WireError::NotAFault("no spec 1"))
    }

    fn fixes_fault(fault: Fault) -> Result<FixFault, WireError> {
        match fault {
            Fault::Fixes(fault) => Ok(fault),
            Fault::Models(_) => Err(WireError::NotAFault("a model fault")),
        }
    }

    fn model(engine: &Identity, inputs: u8, bytes: &[u8]) -> Result<ClockModel, WireError> {
        Ok(ClockModel::sign(
            engine,
            &crate::ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 0,
                spec_version: 1,
                inputs: [inputs; 32],
                model: bytes.to_vec(),
            },
        )?
        .manifest)
    }

    /// From specification version 3 two models of one inputs may differ honestly (optimality
    /// within tolerance is the rule, not bytes): such a pair is no fault.
    #[test]
    fn from_spec_3_two_different_models_of_one_inputs_prove_nothing() -> Result<(), WireError> {
        let model3 = |engine: &Identity, bytes: &[u8]| -> Result<ClockModel, WireError> {
            Ok(ClockModel::sign(
                engine,
                &crate::ClockModelContent {
                    boot_id: 1,
                    sequence: 0,
                    issued_ms: 0,
                    spec_version: 3,
                    inputs: [1; 32],
                    model: bytes.to_vec(),
                },
            )?
            .manifest)
        };
        let (one, two) = (Identity::generate()?, Identity::generate()?);
        let proof = FaultProof::models(&model3(&one, b"one optimum")?, &model3(&two, b"another")?)?;
        let tolerance = Tolerance::for_spec(3).ok_or(WireError::NotAFault("no spec 3"))?;
        assert!(matches!(
            proof.check(&tolerance),
            Err(WireError::NotAFault(_))
        ));
        Ok(())
    }

    #[test]
    fn two_models_of_the_same_inputs_that_differ_are_a_fault() -> Result<(), WireError> {
        let (honest, liar) = (Identity::generate()?, Identity::generate()?);
        let a = model(&honest, 1, b"the model")?;
        let b = model(&liar, 1, b"another model")?;
        let proof = FaultProof::models(&a, &b)?;
        assert_eq!(FaultProof::models(&b, &a)?, proof);
        let Fault::Models(fault) = proof.check(&tolerance()?)? else {
            return Err(WireError::NotAFault("not a model fault"));
        };
        assert_eq!(fault.inputs, [1; 32]);
        assert!(fault.engines.contains(&honest.public()) && fault.engines.contains(&liar.public()));
        assert_eq!(proof.spec_version()?, 1);
        // The same model from two engines, and two models of different inputs, prove nothing.
        let same = model(&liar, 1, b"the model")?;
        assert!(FaultProof::models(&a, &same)?.check(&tolerance()?).is_err());
        let other = model(&liar, 2, b"another model")?;
        assert!(
            FaultProof::models(&a, &other)?
                .check(&tolerance()?)
                .is_err()
        );
        // A forged signature proves nothing.
        let mut bytes = b.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let forged = ClockModel::from_bytes(bytes)?;
        assert!(
            FaultProof::models(&a, &forged)?
                .check(&tolerance()?)
                .is_err()
        );
        Ok(())
    }

    /// Record `sequence` of `engine`: an unrelated fix, then a fix under model `[clock; 32]` at
    /// `lat_e7` that used the receptions of `receivers`, having considered them and one more.
    fn signed(
        engine: &Identity,
        sequence: u64,
        lat_e7: i32,
        clock: u8,
        receivers: &[u8],
    ) -> Result<Positions, WireError> {
        let considered: Vec<u8> = receivers.iter().copied().chain([200]).collect();
        let mut content = fixes_of(
            sequence,
            vec![
                fix_at([9; 32], &[7, 8, 9], &[7, 8, 9], 0)?,
                fix_at([clock; 32], &considered, receivers, lat_e7)?,
            ],
        );
        content.spec_version = 1;
        Positions::sign_fix(engine, &content)
    }

    #[test]
    fn two_engines_disagreeing_on_the_same_inputs_is_a_fault() -> Result<(), WireError> {
        let (honest, liar) = (Identity::generate()?, Identity::generate()?);
        let a = signed(&honest, 0, 374_100_000, 1, &[1, 2, 3, 4])?;
        let b = signed(&liar, 0, 374_200_000, 1, &[4, 3, 2, 1])?;
        let proof = FaultProof::new(&a, 1, &b, 1)?;
        let fault = fixes_fault(proof.check(&tolerance()?)?)?;
        assert!(fault.engines.contains(&honest.public()) && fault.engines.contains(&liar.public()));
        assert_eq!(fault.models, vec![[1; 32]]);
        assert_eq!(fault.spec_version, 1);
        assert_eq!(fault.used, set_of(&[1, 2, 3, 4])?.hash());
        // The same proof whichever way round it was built.
        assert_eq!(FaultProof::new(&b, 1, &a, 1)?, proof);
        let back = FaultProof::from_bytes(proof.as_bytes().to_vec())?;
        assert_eq!(fixes_fault(back.check(&tolerance()?)?)?, fault);
        assert_eq!(back.spec_version()?, 1);
        assert_eq!(back.retired_format(), None);
        Ok(())
    }

    /// A fix is solved from its used set: two that used the same set under one model must agree
    /// however much else each considered, so an engine that solved before a reception arrived is
    /// held to the same answer as one that held it and left it out.
    #[test]
    fn fixes_of_one_used_set_are_held_to_it_whatever_else_they_considered() -> Result<(), WireError>
    {
        let (early, late) = (Identity::generate()?, Identity::generate()?);
        let content = |considered: &[u8], lat_e7: i32| -> Result<FixesContent, WireError> {
            let mut content = fixes_of(0, vec![fix_at([1; 32], considered, &[1, 2, 3], lat_e7)?]);
            content.spec_version = 1;
            Ok(content)
        };
        let a = Positions::sign_fix(&early, &content(&[1, 2, 3], 374_100_000)?)?;
        let b = Positions::sign_fix(&late, &content(&[1, 2, 3, 4, 5], 374_200_000)?)?;
        let fault = fixes_fault(FaultProof::new(&a, 0, &b, 0)?.check(&tolerance()?)?)?;
        assert!(fault.engines.contains(&late.public()));
        // Agreeing, they prove nothing.
        let close = Positions::sign_fix(&late, &content(&[1, 2, 3, 4], 374_100_003)?)?;
        assert!(
            FaultProof::new(&a, 0, &close, 0)?
                .check(&tolerance()?)
                .is_err()
        );
        Ok(())
    }

    /// Two tagged records of one tagged set, as clients receive them, prove a fault as raw ones
    /// do; a tagged and a raw record of the same receptions are never one set.
    #[test]
    fn tagged_fixes_prove_a_fault_as_raw_ones_do() -> Result<(), WireError> {
        let (honest, liar) = (Identity::generate()?, Identity::generate()?);
        let key_of =
            |receiver: &PublicKey| Some(crate::site::ReceptionKey::of_signed(receiver.as_bytes()));
        let tagged = |engine: &Identity, lat_e7: i32| -> Result<Positions, WireError> {
            let one = fix_at([1; 32], &[1, 2, 3, 4], &[1, 2, 3, 4], lat_e7)?.tagged(key_of)?;
            let mut content = fixes_of(0, vec![one]);
            content.spec_version = 1;
            Positions::sign_tagged_fix(engine, &content)
        };
        let a = tagged(&honest, 374_100_000)?;
        let b = tagged(&liar, 374_200_000)?;
        let proof = FaultProof::new(&a, 0, &b, 0)?;
        let fault = fixes_fault(proof.check(&tolerance()?)?)?;
        assert!(fault.engines.contains(&liar.public()));
        assert_eq!(proof.spec_version()?, 1);
        let close = tagged(&liar, 374_100_003)?;
        assert!(
            FaultProof::new(&a, 0, &close, 0)?
                .check(&tolerance()?)
                .is_err()
        );
        let raw = signed(&liar, 0, 374_200_000, 1, &[1, 2, 3, 4])?;
        assert!(
            FaultProof::new(&a, 0, &raw, 1)?
                .check(&tolerance()?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn an_engine_contradicting_itself_is_a_fault() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let a = signed(&engine, 0, 374_100_000, 1, &[1, 2, 3])?;
        let b = signed(&engine, 1, 374_100_100, 1, &[1, 2, 3])?;
        let fault = FaultProof::new(&a, 1, &b, 1)?.check(&tolerance()?)?;
        assert_eq!(fault.engines(), [engine.public(); 2]);
        Ok(())
    }

    #[test]
    fn what_is_not_a_fault_is_refused() -> Result<(), WireError> {
        let (one, two) = (Identity::generate()?, Identity::generate()?);
        let base = signed(&one, 0, 374_100_000, 1, &[1, 2, 3])?;
        let cases = [
            // Agrees within tolerance (a few e7 units).
            (signed(&two, 0, 374_100_005, 1, &[1, 2, 3])?, 1),
            // Different used sets: a superset, not a contradiction.
            (signed(&two, 0, 374_200_000, 1, &[1, 2, 3, 4])?, 1),
            // Different clock models.
            (signed(&two, 0, 374_200_000, 2, &[1, 2, 3])?, 1),
            // No such fix.
            (signed(&two, 0, 374_200_000, 1, &[1, 2, 3])?, 5),
            // Different transmissions entirely.
            (signed(&two, 0, 374_200_000, 1, &[1, 2, 3])?, 0),
        ];
        for (other, index) in cases {
            let proof = FaultProof::new(&base, 1, &other, index)?;
            assert!(
                matches!(proof.check(&tolerance()?), Err(WireError::NotAFault(_))),
                "{index}"
            );
        }
        let mut spec_2 = fixes_of(
            0,
            vec![fix_at([1; 32], &[1, 2, 3], &[1, 2, 3], 374_200_000)?],
        );
        spec_2.spec_version = 2;
        let other = Positions::sign_fix(&two, &spec_2)?;
        assert!(
            FaultProof::new(&base, 1, &other, 0)?
                .check(&tolerance()?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_tampered_or_reordered_proof_is_refused() -> Result<(), WireError> {
        let (one, two) = (Identity::generate()?, Identity::generate()?);
        let a = signed(&one, 0, 374_100_000, 1, &[1, 2, 3])?;
        let b = signed(&two, 0, 374_200_000, 1, &[1, 2, 3])?;
        let proof = FaultProof::new(&a, 1, &b, 1)?;
        proof.check(&tolerance()?)?;
        // A byte inside either record breaks its signature or its form.
        for at in [40, proof.as_bytes().len() - 100] {
            let mut bytes = proof.as_bytes().to_vec();
            bytes[at] ^= 1;
            assert!(FaultProof::from_bytes(bytes)?.check(&tolerance()?).is_err());
        }
        // The same pairs in the other order are not the canonical proof.
        let [(first, i), (second, j)] = proof.parts()?;
        let mut swapped = vec![FAULT_PROOF_FORMAT];
        for record in [&second, &first] {
            swapped.extend_from_slice(
                &u16::try_from(record.as_bytes().len())
                    .map_err(|_| WireError::Oversize(record.as_bytes().len()))?
                    .to_be_bytes(),
            );
            swapped.extend_from_slice(record.as_bytes());
        }
        swapped.extend_from_slice(&j.to_be_bytes());
        swapped.extend_from_slice(&i.to_be_bytes());
        assert!(matches!(
            FaultProof::from_bytes(swapped)?.check(&tolerance()?),
            Err(WireError::NotAFault("not in canonical order"))
        ));
        Ok(())
    }

    /// A record of a retired format proves nothing, and the proof names it as retired, which is
    /// what `Record::decode` refuses it by.
    #[test]
    fn a_record_of_a_retired_format_proves_nothing() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let new = signed(&engine, 0, 0, 1, &[1, 2, 3])?;
        for format in [1u8, 3, 4, 5, 6] {
            let mut bytes = vec![format];
            bytes.extend_from_slice(engine.public().as_bytes());
            bytes.extend_from_slice(&[0; 24]);
            let old = Positions::signed(&engine, bytes);
            old.verify()?;
            let proof = FaultProof::new(&old, 0, &new, 1)?;
            assert!(proof.check(&tolerance()?).is_err());
            assert_eq!(proof.retired_format(), Some(format));
        }
        Ok(())
    }

    #[test]
    fn two_largest_records_fit_one_proof_and_one_message() -> Result<(), WireError> {
        let one = fix([1; 32], &[1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6])?;
        let largest = |engine: &Identity| -> Result<Positions, WireError> {
            let mut many = vec![one.clone()];
            let mut last = Positions::sign_fix(engine, &fixes_of(0, many.clone()))?;
            loop {
                many.push(one.clone());
                match Positions::sign_fix(engine, &fixes_of(0, many.clone())) {
                    Ok(record) => last = record,
                    Err(_) => return Ok(last),
                }
            }
        };
        let (a, b) = (
            largest(&Identity::generate()?)?,
            largest(&Identity::generate()?)?,
        );
        let proof = FaultProof::new(&a, 0, &b, 0)?;
        let mut message = Vec::new();
        crate::Record::FaultProof(proof).encode(&mut message)?;
        assert!(message.len() <= crate::noise::MAX_PLAINTEXT);
        Ok(())
    }

    #[test]
    fn longitude_is_compared_across_the_antimeridian() -> Result<(), WireError> {
        let mut east = fix([1; 32], &[1, 2], &[1, 2])?;
        let mut west = east.clone();
        east.lon_e7 = 1_799_999_998;
        west.lon_e7 = -1_799_999_998;
        assert!(!tolerance()?.disagree(&east, &west));
        west.lon_e7 = -1_799_999_000;
        assert!(tolerance()?.disagree(&east, &west));
        Ok(())
    }
}
