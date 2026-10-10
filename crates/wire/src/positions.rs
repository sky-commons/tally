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
use crate::key::{Identity, KEY_LEN, PublicKey, SIGNATURE_LEN};
use crate::observation_set::{ObservationSet, Reception};
use crate::record::{Body, MAX_BODY};

/// The native engine's format: solutions naming their observation set, tile clock model, the
/// aircraft's addressed receptions and the spec.
pub const POSITIONS_FORMAT_3: u8 = 3;
/// The native engine's provisional format: format 3's layout, solved under a carried model, with
/// no addressed citation.
pub const POSITIONS_FORMAT_PROVISIONAL: u8 = 4;
const POSITIONS_DOMAIN: &[u8] = b"tally positions";
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

/// One solution, format 3: where one transmission was sent from, and exactly what it was solved
/// from.
#[derive(Clone, Debug, PartialEq)]
pub struct Solution {
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
    pub observations: ObservationSet,
}

impl Solution {
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

/// What a format 3 record says.
#[derive(Clone, Debug, PartialEq)]
pub struct SolutionsContent {
    /// Random per engine process start. With `sequence`, names this record uniquely for its
    /// engine, so a restarted engine starts a new stream instead of being refused as a replay.
    pub boot_id: u64,
    /// 0, 1, 2, ... within one boot; a gap is results some hop did not deliver.
    pub sequence: u64,
    pub issued_ms: u64,
    /// The version of the solver specification every solution here was computed under.
    pub spec_version: u16,
    pub solutions: Vec<Solution>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Positions {
    bytes: Vec<u8>,
}

impl Positions {
    /// Signs a format 3 record. Refused when a solution is malformed or the record would be
    /// larger than `MAX_POSITIONS_LEN`.
    pub fn sign_solutions(
        identity: &Identity,
        content: &SolutionsContent,
    ) -> Result<Self, WireError> {
        Self::sign_format(identity, content, POSITIONS_FORMAT_3)
    }

    /// Signs a provisional (format 4) record: as `sign_solutions`, and refused when a solution
    /// names an addressed citation.
    pub fn sign_provisional(
        identity: &Identity,
        content: &SolutionsContent,
    ) -> Result<Self, WireError> {
        Self::sign_format(identity, content, POSITIONS_FORMAT_PROVISIONAL)
    }

    fn sign_format(
        identity: &Identity,
        content: &SolutionsContent,
        format: u8,
    ) -> Result<Self, WireError> {
        for solution in &content.solutions {
            solution.check()?;
            provisional_citation(format, &solution.addressed)?;
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

    pub(crate) fn signed(identity: &Identity, mut bytes: Vec<u8>) -> Self {
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

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    /// Whether the record is provisional: superseded by the final positions that follow it, and
    /// carried under a record kind of its own.
    pub fn is_provisional(&self) -> bool {
        self.format() == POSITIONS_FORMAT_PROVISIONAL
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
            provisional_citation(self.format(), &addressed)?;
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

/// A provisional solution names no addressed citation.
fn provisional_citation(format: u8, addressed: &AddressedCitation) -> Result<(), WireError> {
    if format == POSITIONS_FORMAT_PROVISIONAL && *addressed != AddressedCitation::default() {
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
    let receptions = solution.observations.receptions();
    bytes.push(receptions.len() as u8);
    for reception in receptions {
        bytes.extend_from_slice(&receiver(&reception.receiver)?.to_be_bytes());
        bytes.extend_from_slice(&reception.epoch.to_be_bytes());
        bytes.extend_from_slice(&reception.counter.to_be_bytes()[2..]);
    }
    Ok(())
}

fn prefix(format: u8, identity: &Identity, boot_id: u64, sequence: u64) -> Vec<u8> {
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
