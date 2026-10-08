//! A fault proof (RFC-0171 §3.8.1), of either of two shapes.
//!
//! Format 1: two signed format 3 or provisional (format 4) `Positions` solutions over the same
//! observation set, the same clock model and the same solver specification that disagree beyond
//! the specification's tolerance. A solution is a deterministic function of those three, whether
//! final or provisional (a provisional maps its receptions through the model carried past its
//! knots, and where the model reaches them both map alike), so two that disagree prove that at
//! least one engine did not compute what it signed. Anyone may build
//! one from what relays already carry, and anyone can check it with nothing but the proof: a relay
//! checks it before forwarding it, and a consumer that checks it drops the engines on its own
//! authority.
//!
//! The proof is not signed: it is evidence, and the evidence carries the engines' own signatures.
//!
//! ```text
//! format u8 = 1
//! | first length u16 | first Positions record (signed bytes)
//! | second length u16 | second Positions record
//! | first solution index u16 | second solution index u16
//! ```
//!
//! The two (record, index) pairs are in canonical order, by (record hash, index), strictly
//! ascending, so one fault has one proof and relays deduplicate it by `FaultProof::hash`. Every
//! format 3 record is at most `MAX_POSITIONS_LEN`, so any two fit one proof.
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
use crate::positions::{POSITIONS_FORMAT_3, Positions, Solution};
use crate::record::{Body, MAX_BODY};

pub const FAULT_PROOF_FORMAT: u8 = 1;
/// Two clock model manifests of one inputs that differ.
pub const MODEL_FAULT_PROOF_FORMAT: u8 = 2;
/// The first specification version under which two different models of one inputs are no fault
/// (`check_models`).
pub const MODELS_DIFFER_NOT_A_FAULT_FROM: u16 = 3;
/// The bytes of a proof that are not the two records: format, two lengths, two indices.
pub(crate) const FAULT_PROOF_OVERHEAD: usize = 1 + 2 + 2 + 2 + 2;

/// How far two solutions of one (observation set, clock model, spec version) may differ and
/// still agree: floating point differs between implementations, the answer does not. Integer
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
            1..=4 => Some(Self {
                position_e7: 10,
                alt_mm: 1_000,
                transmit_ns: 10,
                covariance_relative: 1e-3,
            }),
            _ => None,
        }
    }

    /// True when the two solutions differ by more than this tolerance anywhere.
    pub fn disagree(&self, a: &Solution, b: &Solution) -> bool {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Solutions(SolutionFault),
    Models(ModelFault),
}

impl Fault {
    /// The engines that signed the two records; the same key twice when one engine contradicted
    /// itself.
    pub fn engines(&self) -> [PublicKey; 2] {
        match self {
            Self::Solutions(fault) => fault.engines,
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

/// Two solutions of the same inputs that disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolutionFault {
    /// The engines that signed the two solutions; the same key twice when one engine contradicted
    /// itself.
    pub engines: [PublicKey; 2],
    /// The `ObservationSet::hash` both solutions name.
    pub observations: Hash,
    /// The `ClockModel::id` both solutions name.
    pub clock_model: Hash,
    pub spec_version: u16,
}

/// A fault proof, as bytes. Immutable: forwarding never re-encodes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultProof {
    bytes: Vec<u8>,
}

impl FaultProof {
    /// A proof that solution `a_index` of `a` and `b_index` of `b` disagree. Puts the two in
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

    /// The two records and their solution indices, in the proof's order.
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
        Ok(first.solutions()?.spec_version)
    }

    /// Checks the proof: both records are format 3 or provisional (format 4) and verify, the pairs are in canonical order,
    /// both name one spec version, both solutions exist and name the same observation set and the
    /// same clock model, and they disagree beyond `tolerance`. What it proves, or why it does not.
    pub fn check(&self, tolerance: &Tolerance) -> Result<Fault, WireError> {
        if self.format() == MODEL_FAULT_PROOF_FORMAT {
            return self.check_models().map(Fault::Models);
        }
        let [(first, i), (second, j)] = self.parts()?;
        if (first.hash(), i) >= (second.hash(), j) {
            return Err(WireError::NotAFault("not in canonical order"));
        }
        for record in [&first, &second] {
            if record.format() != POSITIONS_FORMAT_3 && !record.is_provisional() {
                return Err(WireError::NotAFault("not a format 3 or provisional record"));
            }
            record.verify()?;
        }
        let (a, b) = (first.solutions()?, second.solutions()?);
        if a.spec_version != b.spec_version {
            return Err(WireError::NotAFault("different spec versions"));
        }
        let (Some(x), Some(y)) = (
            a.solutions.get(usize::from(i)),
            b.solutions.get(usize::from(j)),
        ) else {
            return Err(WireError::NotAFault("no such solution"));
        };
        if x.observations != y.observations {
            return Err(WireError::NotAFault("different observation sets"));
        }
        if x.clock_model != y.clock_model {
            return Err(WireError::NotAFault("different clock models"));
        }
        if !tolerance.disagree(x, y) {
            return Err(WireError::NotAFault("the solutions agree within tolerance"));
        }
        Ok(Fault::Solutions(SolutionFault {
            engines: [first.engine()?, second.engine()?],
            observations: x.observations.hash(),
            clock_model: x.clock_model,
            spec_version: a.spec_version,
        }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;
    use crate::positions::tests::{solution, solutions};

    fn tolerance() -> Result<Tolerance, WireError> {
        Tolerance::for_spec(1).ok_or(WireError::NotAFault("no spec 1"))
    }

    fn solutions_fault(fault: Fault) -> Result<SolutionFault, WireError> {
        match fault {
            Fault::Solutions(fault) => Ok(fault),
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

    fn signed(
        engine: &Identity,
        sequence: u64,
        lat_e7: i32,
        clock: u8,
        receivers: &[u8],
    ) -> Result<Positions, WireError> {
        Positions::sign_solutions(
            engine,
            &solutions(
                sequence,
                vec![
                    solution([9; 32], &[7, 8, 9], 0)?,
                    solution([clock; 32], receivers, lat_e7)?,
                ],
            ),
        )
    }

    #[test]
    fn two_engines_disagreeing_on_the_same_inputs_is_a_fault() -> Result<(), WireError> {
        let (honest, liar) = (Identity::generate()?, Identity::generate()?);
        let a = signed(&honest, 0, 374_100_000, 1, &[1, 2, 3, 4])?;
        let b = signed(&liar, 0, 374_200_000, 1, &[4, 3, 2, 1])?;
        let proof = FaultProof::new(&a, 1, &b, 1)?;
        let fault = solutions_fault(proof.check(&tolerance()?)?)?;
        assert!(fault.engines.contains(&honest.public()) && fault.engines.contains(&liar.public()));
        assert_eq!(fault.clock_model, [1; 32]);
        assert_eq!(fault.spec_version, 1);
        // The same proof whichever way round it was built.
        assert_eq!(FaultProof::new(&b, 1, &a, 1)?, proof);
        let back = FaultProof::from_bytes(proof.as_bytes().to_vec())?;
        assert_eq!(solutions_fault(back.check(&tolerance()?)?)?, fault);
        assert_eq!(back.spec_version()?, 1);
        Ok(())
    }

    /// As `signed`, provisional: no addressed citation.
    fn provisional(
        engine: &Identity,
        sequence: u64,
        lat_e7: i32,
        receivers: &[u8],
    ) -> Result<Positions, WireError> {
        let mut one = solution([1; 32], receivers, lat_e7)?;
        one.addressed = Default::default();
        Positions::sign_provisional(engine, &solutions(sequence, vec![one]))
    }

    #[test]
    fn provisional_positions_are_held_to_the_same_rule() -> Result<(), WireError> {
        let (honest, liar) = (Identity::generate()?, Identity::generate()?);
        // Two provisionals of one observation set under one model that disagree.
        let a = provisional(&honest, 0, 374_100_000, &[1, 2, 3, 4])?;
        let b = provisional(&liar, 0, 374_200_000, &[1, 2, 3, 4])?;
        let fault = solutions_fault(FaultProof::new(&a, 0, &b, 0)?.check(&tolerance()?)?)?;
        assert!(fault.engines.contains(&liar.public()));
        // A provisional and a final of one observation set under one model: where the model
        // reaches every reception both map alike, so they must agree too.
        let final_one = signed(&honest, 1, 374_200_000, 1, &[1, 2, 3, 4])?;
        assert!(
            FaultProof::new(&a, 0, &final_one, 1)?
                .check(&tolerance()?)
                .is_ok()
        );
        // Agreeing, they prove nothing.
        let close = provisional(&liar, 1, 374_100_003, &[1, 2, 3, 4])?;
        assert!(
            FaultProof::new(&a, 0, &close, 0)?
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
            // Different observation sets: a superset, not a contradiction.
            (signed(&two, 0, 374_200_000, 1, &[1, 2, 3, 4])?, 1),
            // Different clock models.
            (signed(&two, 0, 374_200_000, 2, &[1, 2, 3])?, 1),
            // No such solution.
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
        let mut spec_2 = solutions(0, vec![solution([1; 32], &[1, 2, 3], 374_200_000)?]);
        spec_2.spec_version = 2;
        let other = Positions::sign_solutions(&two, &spec_2)?;
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

    #[test]
    fn a_record_of_another_format_proves_nothing() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        // A signed record whose format byte is not 2 (1 is the retired format).
        let mut bytes = vec![1];
        bytes.extend_from_slice(engine.public().as_bytes());
        bytes.extend_from_slice(&[0; 24]);
        let old = Positions::signed(&engine, bytes);
        old.verify()?;
        let new = signed(&engine, 0, 0, 1, &[1, 2, 3])?;
        assert!(
            FaultProof::new(&old, 0, &new, 1)?
                .check(&tolerance()?)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn two_largest_records_fit_one_proof_and_one_message() -> Result<(), WireError> {
        let one = solution([1; 32], &[1, 2, 3, 4, 5, 6], 0)?;
        let largest = |engine: &Identity| -> Result<Positions, WireError> {
            let mut many = vec![one.clone()];
            let mut last = Positions::sign_solutions(engine, &solutions(0, many.clone()))?;
            loop {
                many.push(one.clone());
                match Positions::sign_solutions(engine, &solutions(0, many.clone())) {
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
        let mut east = solution([1; 32], &[1, 2], 0)?;
        let mut west = east.clone();
        east.lon_e7 = 1_799_999_998;
        west.lon_e7 = -1_799_999_998;
        assert!(!tolerance()?.disagree(&east, &west));
        west.lon_e7 = -1_799_999_000;
        assert!(tolerance()?.disagree(&east, &west));
        Ok(())
    }
}
