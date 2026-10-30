//! What an engine publishes and a checker reads back (crate docs, § The pairwise path,
//! publishing): a pair model's one encoding, its id, the hash of what it is a function of, its
//! client summary, and a fix's wire form (format 7, and through `tally_wire::Fix::tagged` its
//! tagged twin, format 8) and the claim a verifier rebuilds from it. One implementation for both
//! sides, so the model a fix cites is the model it was computed from.

use blake2::{Blake2s256, Digest};
use tally_wire::{
    ClientClockModel, ClientClockModelContent, Clock, EnuCovariance, FixSets, Location,
    ObservationSet, PublicKey, ReceptionKey, ReceptionTag, Region, SiteId, TransmitTime,
};

use crate::clock::ClockKey;
use crate::geo::{self, Geodetic};
use crate::modes;
use crate::obs::{ObservationId, Reception, Site, message_hash};
use crate::pair::{Models, PairModel};
use crate::scope::{Citation, Frontier, Trailing};
use crate::solve::Solution;

/// Picoseconds in a nanosecond.
const PS_PER_NS: i128 = 1_000;
/// Picoseconds in a millisecond.
const PS_PER_MS: i128 = 1_000_000_000;
/// An absent `from`.
const NONE_I64: i64 = i64::MIN;
/// What the inputs hash is computed under.
const INPUTS_DOMAIN: &[u8] = b"tally pair model inputs id";
/// What a fix's models' inputs, together, are hashed under.
const CITED_INPUTS_DOMAIN: &[u8] = b"tally pair model cited inputs";

/// Why a published model or solution cannot be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    #[error("the model ends early")]
    Truncated,
    #[error("malformed model: {0}")]
    Malformed(&'static str),
    #[error("the message names no aircraft address")]
    NoAddress,
    #[error("out of range: {0}")]
    Range(&'static str),
    #[error("wire: {0}")]
    Wire(String),
}

/// A scope entry as the encoding writes it: the site in full (relay-only, crate docs § Publishing).
fn site(out: &mut Vec<u8>, site: &Site) {
    out.extend_from_slice(site.receiver.as_bytes());
    out.push(site.clock.byte());
    out.extend_from_slice(&site.id.0);
    out.extend_from_slice(&site.location.lat_e7.to_be_bytes());
    out.extend_from_slice(&site.location.lon_e7.to_be_bytes());
    out.extend_from_slice(&site.location.alt_m.to_be_bytes());
    out.extend_from_slice(&site.location.precision_m.to_be_bytes());
}

/// A scope entry as the inputs id hashes it: receiver, clock, site id and stated precision. The
/// site id covers the site-bearing record's signature, which no client is sent, so the inputs id a
/// client is given cannot be tested against guessed sites (as a hash over the site itself could,
/// one guess at a time over the public cell).
fn scope_entry(out: &mut Vec<u8>, site: &Site) {
    out.extend_from_slice(site.receiver.as_bytes());
    out.push(site.clock.byte());
    out.extend_from_slice(&site.id.0);
    out.extend_from_slice(&site.location.precision_m.to_be_bytes());
}

/// The `through_sequence` a member with no frontier is written with (its `boot_id` 0): a member
/// none of whose raw had arrived when the model was fitted cites nothing. No batch has this
/// sequence, so a frontier is never confused with it (`encode_pairs` refuses one that has it).
const NO_FRONTIER: u64 = u64::MAX;

/// Area, trailing window, scope (each entry written by `entry`, then its member's frontier, or
/// none) and input citation: what a pair model is a function of, as its encoding and its inputs id
/// begin. Refused when the scope's count exceeds its two bytes.
fn leading(model: &PairModel, entry: fn(&mut Vec<u8>, &Site)) -> Result<Vec<u8>, PublishError> {
    let count = u16::try_from(model.scope.len()).map_err(|_| PublishError::Range("count"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&model.area.as_u64().to_be_bytes());
    out.extend_from_slice(&model.trailing.edge_ms.to_be_bytes());
    out.extend_from_slice(&model.trailing.span_ms.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    for site in &model.scope {
        entry(&mut out, site);
        let (boot_id, through_sequence) = model
            .frontier
            .binary_search_by_key(&site.receiver, |frontier| frontier.receiver)
            .map_or((0, NO_FRONTIER), |at| {
                let frontier = &model.frontier[at];
                (frontier.boot_id, frontier.through_sequence)
            });
        out.extend_from_slice(&boot_id.to_be_bytes());
        out.extend_from_slice(&through_sequence.to_be_bytes());
    }
    out.extend_from_slice(&model.input.hash);
    out.extend_from_slice(&model.input.count.to_be_bytes());
    Ok(out)
}

/// What a pair model is a function of, as one hash the manifest carries: BLAKE2s-256 over
/// `"tally pair model inputs id" 0x00`, the specification version (two bytes), and area, trailing
/// edge and span, scope with each member's frontier, and input citation, each scope entry as
/// receiver key, clock, site id and stated precision (never the site: the id is published to
/// clients, `tally_wire::ClientClockModel`, and must name nothing a client could test a guess
/// against). Two models of one area that fitted different arrivals have different ids. `None` for a
/// scope too large to encode.
pub fn inputs_id(model: &PairModel) -> Option<[u8; 32]> {
    let leading = leading(model, scope_entry).ok()?;
    let mut hasher = Blake2s256::new();
    hasher.update(INPUTS_DOMAIN);
    hasher.update([0]);
    hasher.update(model.spec.to_be_bytes());
    hasher.update(leading);
    Some(hasher.finalize().into())
}

/// What the models one fix cites are a function of, together: BLAKE2s-256 over `"tally pair model
/// cited inputs" 0x00` and each model's inputs id (`inputs_id`), in the order of the models' ids
/// (`tally_wire::Fix::models`). What the standing rule's tie rule and dominance compare two fixes'
/// citations by (`standing::Candidate::model_inputs`).
pub fn cited_inputs(inputs: impl IntoIterator<Item = [u8; 32]>) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(CITED_INPUTS_DOMAIN);
    hasher.update([0]);
    for one in inputs {
        hasher.update(one);
    }
    hasher.finalize().into()
}

/// What a client is sent of `model`, signed by `identity` (`tally_wire::ClientClockModel` of
/// format 2, `ClientClockModelContent`, crate docs § The pairwise path, publishing): the id fixes
/// cite, the manifest's inputs and the trailing window. Nothing of its scope: no site, no clock, no
/// pair (with the aircraft's published positions a pair's offsets narrow its ends' sites), no
/// member at all, and no frontier, which names the members. `boot_id` and `sequence` are the full
/// model's, so the summary is numbered with the model it summarises.
pub fn client_model(
    identity: &impl tally_wire::Signs,
    model: &PairModel,
    id: [u8; 32],
    inputs: [u8; 32],
    (boot_id, sequence, issued_ms): (u64, u64, u64),
) -> Result<ClientClockModel, tally_wire::WireError> {
    ClientClockModel::sign(
        identity,
        &ClientClockModelContent {
            boot_id,
            sequence,
            issued_ms,
            spec_version: model.spec,
            model: id,
            inputs,
            edge_ms: model.trailing.edge_ms,
            span_ms: model.trailing.span_ms,
        },
    )
}

/// The area a pair model's encoding names, read from its first bytes alone (its specification
/// version, then its area): what a relay routes a model by before it decodes the rest.
pub fn area_of(prefix: &[u8]) -> Result<Region, PublishError> {
    let mut reader = Reader {
        bytes: prefix,
        at: 0,
    };
    let _spec = reader.u16()?;
    Region::from_u64(reader.u64()?).map_err(|_| PublishError::Malformed("area"))
}

/// A solution as the wire carries it (a format 7 fix) on a timeline whose zero is Unix
/// nanoseconds `origin_unix_ns` (`pair::Normalised::origin_unix_ns`): the transmit time in Unix
/// terms, to the picosecond; latitude and longitude rounded to 10^-7 degree and height to the
/// millimetre; the covariance in east, north, up at the solution, as f32; the models it was solved
/// under, `models` (their ids ascending, `pair::Models::ids`); every reception it considered and
/// the subset it used.
pub fn to_wire_at(
    origin_unix_ns: u64,
    solution: &Solution,
    models: Vec<[u8; 32]>,
    message: &[u8],
) -> Result<tally_wire::Fix, PublishError> {
    let address = modes::address(message).ok_or(PublishError::NoAddress)?;
    let unix_ps = i128::from(origin_unix_ns) * PS_PER_NS + i128::from(solution.transmit_ps);
    if unix_ps < 0 {
        return Err(PublishError::Range("transmit time"));
    }
    let unix_ms =
        u64::try_from(unix_ps / PS_PER_MS).map_err(|_| PublishError::Range("transmit time"))?;
    let sub_ms_ps = (unix_ps % PS_PER_MS) as u32;
    let e7 = |degrees: f64| {
        let value = (degrees * 1e7).round();
        (value.abs() <= f64::from(i32::MAX))
            .then_some(value as i32)
            .ok_or(PublishError::Range("degrees"))
    };
    let height = (solution.position.height_m * 1000.0).round();
    if height.abs() >= f64::from(i32::MAX) {
        return Err(PublishError::Range("height"));
    }
    let enu = solution.enu_covariance();
    let set = |ids: &[ObservationId]| {
        ObservationSet::new(
            message.to_vec(),
            ids.iter()
                .map(|id| tally_wire::Reception {
                    receiver: id.receiver,
                    epoch: id.epoch,
                    counter: id.timestamp,
                })
                .collect(),
        )
        .map_err(|error| PublishError::Wire(error.to_string()))
    };
    let sets = FixSets::new(set(&solution.considered)?, set(&solution.used)?)
        .map_err(|error| PublishError::Wire(error.to_string()))?;
    Ok(tally_wire::Fix {
        address,
        transmitted: TransmitTime::new(unix_ms, sub_ms_ps)
            .map_err(|error| PublishError::Wire(error.to_string()))?,
        lat_e7: e7(solution.position.lat_deg)?,
        lon_e7: e7(solution.position.lon_deg)?,
        alt_hae_mm: Some(height as i32),
        covariance: EnuCovariance {
            xx: enu[0][0] as f32,
            xy: enu[0][1] as f32,
            xz: enu[0][2] as f32,
            yy: enu[1][1] as f32,
            yz: enu[1][2] as f32,
            zz: enu[2][2] as f32,
        },
        models,
        sets,
    })
}

/// The raw fix a tagged one stands for (`tally_wire::TaggedFix`, what a client is sent),
/// rematched by a relay against the raw it holds: each of `held` (receptions of the fix's message
/// that the relay holds) tagged under its receiver's reception key as `key_of` gives it (the key of
/// the receiver's site-bearing record current when it was heard), and the fix rebuilt from the
/// receptions whose tags its considered set names, the used set the same tags' receptions. `None`
/// unless every tag it names is matched by exactly one reception held, so a tag the relay cannot
/// account for is never taken on trust.
pub fn rematch(
    tagged: &tally_wire::TaggedFix,
    held: impl IntoIterator<Item = tally_wire::Reception>,
    key_of: impl Fn(&PublicKey) -> Option<ReceptionKey>,
) -> Option<tally_wire::Fix> {
    let considered = tagged.considered();
    let message = considered.message();
    let wanted = considered.tags();
    let mut found: Vec<Option<tally_wire::Reception>> = vec![None; wanted.len()];
    for reception in held {
        let Some(key) = key_of(&reception.receiver) else {
            continue;
        };
        let Ok(tag) = ReceptionTag::of(&key, reception.epoch, reception.counter, message) else {
            continue;
        };
        if let Ok(at) = wanted.binary_search(&tag) {
            match found[at] {
                Some(held) if held != reception => return None,
                _ => found[at] = Some(reception),
            }
        }
    }
    let receptions = found.into_iter().collect::<Option<Vec<_>>>()?;
    let used_tags = tagged.used().tags();
    let used: Vec<tally_wire::Reception> = wanted
        .iter()
        .zip(&receptions)
        .filter(|(tag, _)| used_tags.binary_search(tag).is_ok())
        .map(|(_, reception)| *reception)
        .collect();
    let sets = FixSets::new(
        ObservationSet::new(message.to_vec(), receptions).ok()?,
        ObservationSet::new(message.to_vec(), used).ok()?,
    )
    .ok()?;
    Some(tally_wire::Fix {
        address: tagged.address,
        transmitted: tagged.transmitted,
        lat_e7: tagged.lat_e7,
        lon_e7: tagged.lon_e7,
        alt_hae_mm: tagged.alt_hae_mm,
        covariance: tagged.covariance,
        models: tagged.models.clone(),
        sets,
    })
}

/// Why a transmission is not published.
#[derive(Debug, Clone, PartialEq)]
pub enum Unpublished {
    /// No transmission of the considered set maps under the model (every reception unmapped or
    /// ambiguous).
    Ungrouped,
    /// The solver found no solution.
    Unsolved(crate::solve::SolveError),
    /// The solution cannot be written to the wire.
    Unwritable(PublishError),
    /// The verifier refuses the claim read back from what would be published.
    Refuted(crate::verify::Verdict),
    /// The transmission's considered set is one its engine already published a fix of
    /// (`solve_transmission`'s `published`): taken again only because another transmission of its bytes
    /// grew the set, it is not solved again, since a fix of the same set under a newer model is
    /// `Relation::Incomparable` to the first and supersedes nothing.
    Published,
    /// A hearer of the transmission is of an area whose model is not among those it was solved by
    /// (the areas named): it cannot cite every model its hearers' areas need (crate docs, § Areas,
    /// the models a fix cites), so it is not published until that model is held.
    Unheld(Vec<Region>),
    /// The pair model cannot put the transmission on one timeline (`pair::Prepared::normalise`).
    Unnormalised(&'static str),
}

/// What a fix states, however it reached its verifier: a wire fix whole (`Stated::of`), or what a
/// keeper holds of one (`standing::Asked::stated`). The one form [`claim`] and the verifier read,
/// so a fix judged from either is judged alike.
#[derive(Clone, Copy, Debug)]
pub struct Stated<'a> {
    pub claimed: crate::standing::Claimed,
    /// The ids of the models it cites, ascending (`tally_wire::Fix::models`).
    pub models: &'a [[u8; 32]],
    pub message: &'a [u8],
    /// In canonical order, as the wire's observation set holds them.
    pub considered: &'a [tally_wire::Reception],
    /// In canonical order: a subset of `considered`.
    pub used: &'a [tally_wire::Reception],
}

impl<'a> Stated<'a> {
    /// What a wire fix states.
    pub fn of(wire: &'a tally_wire::Fix) -> Self {
        Self {
            claimed: crate::standing::Claimed::of(wire),
            models: &wire.models,
            message: wire.considered().message(),
            considered: wire.considered().receptions(),
            used: wire.used().receptions(),
        }
    }
}

/// [`claim_of`] on a timeline whose zero is Unix nanoseconds `origin_unix_ns`.
pub fn claim_at(
    origin_unix_ns: u64,
    stated: &Stated<'_>,
    spec: u16,
) -> Result<Solution, PublishError> {
    let wire = &stated.claimed;
    let height_mm = wire.alt_hae_mm.ok_or(PublishError::Range("no altitude"))?;
    let position = Geodetic {
        lat_deg: f64::from(wire.lat_e7) * 1e-7,
        lon_deg: f64::from(wire.lon_e7) * 1e-7,
        height_m: f64::from(height_mm) / 1000.0,
    };
    let ecef = geo::to_ecef(position);
    let unix_ps = i128::try_from(wire.transmitted.unix_ps())
        .map_err(|_| PublishError::Range("transmit time"))?;
    let transmit_ps = i64::try_from(unix_ps - i128::from(origin_unix_ns) * PS_PER_NS)
        .map_err(|_| PublishError::Range("transmit time"))?;
    let terms = wire.covariance.terms().map(f64::from);
    let enu = [
        [terms[0], terms[1], terms[2]],
        [terms[1], terms[3], terms[4]],
        [terms[2], terms[4], terms[5]],
    ];
    let basis = geo::enu_basis(position.lat_deg, position.lon_deg);
    let mut covariance = [[0.0; 3]; 3];
    for (a, row) in covariance.iter_mut().enumerate() {
        for (b, value) in row.iter_mut().enumerate() {
            let mut sum = 0.0;
            for i in 0..3 {
                for j in 0..3 {
                    sum += basis[i][a] * enu[i][j] * basis[j][b];
                }
            }
            *value = sum;
        }
    }
    let message = stated.message;
    let hash = message_hash(message);
    let ids = |set: &[tally_wire::Reception]| -> Vec<ObservationId> {
        set.iter()
            .map(|reception| ObservationId {
                receiver: reception.receiver,
                epoch: reception.epoch,
                timestamp: reception.counter,
                message: hash,
            })
            .collect()
    };
    let used = ids(stated.used);
    let altitude = modes::altitude(message);
    let dof = (used.len() + usize::from(altitude.is_some())).saturating_sub(4);
    Ok(Solution {
        spec,
        ecef,
        position,
        transmit_ps,
        covariance,
        considered: ids(stated.considered),
        used,
        altitude,
        chi2: 0.0,
        dof: u32::try_from(dof).unwrap_or(u32::MAX),
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

/// The least each listed entry takes on the wire: a site (its key, clock and location, its id
/// and its frontier besides), a clock (its key, timebase, `from`, site, noise, base, first knot and
/// at least two knots), a jump, a dropped clock and a jump published with a drop. What [`Reader::list`] reserves for a count by.
const SITE_WIRE_BYTES: usize = 32 + 1 + 16 + 16;

impl Reader<'_> {
    /// A list for `count` entries of at least `each` bytes on the wire: exactly `count` when the
    /// bytes left can hold them, so a model decoded holds every list at its length
    /// (`standing::model_bytes_most`), and never more than the bytes left could fill, so a count
    /// that lies reserves nothing it cannot read.
    fn list<T>(&self, count: u16, each: usize) -> Vec<T> {
        let left = self.bytes.len().saturating_sub(self.at) / each;
        Vec::with_capacity(usize::from(count).min(left))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PublishError> {
        let end = self.at.checked_add(N).ok_or(PublishError::Truncated)?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(PublishError::Truncated)?;
        self.at = end;
        let mut out = [0; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, PublishError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, PublishError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, PublishError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, PublishError> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, PublishError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, PublishError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn public_key(&mut self) -> Result<PublicKey, PublishError> {
        PublicKey::from_slice(&self.array::<32>()?)
            .map_err(|_| PublishError::Malformed("receiver key"))
    }

    /// A clock's key as a model writes it: its receiver as its index in `scope`, then its epoch.
    fn clock_key(&mut self, scope: &[Site]) -> Result<ClockKey, PublishError> {
        let at = usize::from(self.u16()?);
        let site = scope
            .get(at)
            .ok_or(PublishError::Malformed("clock outside the scope"))?;
        Ok(ClockKey {
            receiver: site.receiver,
            epoch: self.u32()?,
        })
    }
}

/// What a pair model id is computed under.
const PAIR_ID_DOMAIN: &[u8] = b"tally pair model id";
/// The least each listed entry of a pair model takes on the wire: a clock and a pair of two knots.
const PAIR_CLOCK_WIRE_BYTES: usize = 2 + 4 + 8 + 8 + 8 + 3 * 8 + 2 * 4;
const PAIR_WIRE_BYTES: usize = 2 + 2 + 8 + 8 + 1 + 2 * 8 + 3 * 4 + 8 + 3 * 4;

/// A pair model's one encoding (crate docs, § The pairwise path, the model): relay-only, its
/// specification version then its area first (what `area_of` reads), every float as its IEEE 754
/// bits big-endian, each at the precision its field has (`pair::ClockPair`). Refused when a count
/// exceeds its field, the frontier is not the scope's, a clock's receiver is not in the scope, or a
/// pair holds fewer than two or more than `pair::PAIR_KNOTS_MOST` knots.
pub fn encode_pairs(model: &crate::pair::PairModel) -> Result<Vec<u8>, PublishError> {
    let count32 = |len: usize| u32::try_from(len).map_err(|_| PublishError::Range("count"));
    let frontier_is_the_scopes = model
        .frontier
        .windows(2)
        .all(|pair| pair[0].receiver < pair[1].receiver)
        && model.frontier.iter().all(|frontier| {
            frontier.through_sequence != NO_FRONTIER
                && model
                    .scope
                    .binary_search_by_key(&frontier.receiver, |site| site.receiver)
                    .is_ok()
        });
    if !frontier_is_the_scopes {
        return Err(PublishError::Malformed("frontier"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&model.spec.to_be_bytes());
    out.extend(leading(model, site)?);
    out.extend_from_slice(&model.kappa.to_bits().to_be_bytes());
    let count16 = |len: usize| u16::try_from(len).map_err(|_| PublishError::Range("count"));
    out.extend_from_slice(&count16(model.clocks.len())?.to_be_bytes());
    for clock in &model.clocks {
        let at = model
            .scope
            .binary_search_by_key(&clock.key.receiver, |site| site.receiver)
            .map_err(|_| PublishError::Malformed("clock outside the scope"))?;
        out.extend_from_slice(&count16(at)?.to_be_bytes());
        out.extend_from_slice(&clock.key.epoch.to_be_bytes());
        out.extend_from_slice(&clock.lowest.to_be_bytes());
        out.extend_from_slice(&clock.heard_ns.to_be_bytes());
        out.extend_from_slice(&clock.from.unwrap_or(NONE_I64).to_be_bytes());
        for value in [clock.noise_ns, clock.white_ns, clock.rate] {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        for value in [clock.rate_var, clock.common_var] {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
    }
    out.extend_from_slice(&count32(model.pairs.len())?.to_be_bytes());
    for pair in &model.pairs {
        let size = pair.knots.len();
        if !(2..=crate::pair::PAIR_KNOTS_MOST).contains(&size)
            || pair.cov.len() != size * (size + 1) / 2
        {
            return Err(PublishError::Malformed("knots"));
        }
        out.extend_from_slice(&count16(pair.a as usize)?.to_be_bytes());
        out.extend_from_slice(&count16(pair.b as usize)?.to_be_bytes());
        out.extend_from_slice(&pair.anchor_a.to_be_bytes());
        out.extend_from_slice(&pair.anchor_b.to_be_bytes());
        out.push(size as u8);
        for value in &pair.knots {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        for value in &pair.cov {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        out.extend_from_slice(&pair.slope.to_bits().to_be_bytes());
        for value in [pair.slope_var, pair.kappa, pair.share] {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
    }
    Ok(out)
}

/// The id fixes cite a pair model by: BLAKE2s-256 over `"tally pair model id" 0x00` and its
/// encoding.
pub fn pair_model_id(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(PAIR_ID_DOMAIN);
    hasher.update([0]);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Reads a pair model's one encoding, refusing anything not in canonical form: the scope, its
/// frontier, the clocks (by key) and the pairs (by their clocks)
/// strictly ascending, every clock's receiver in the scope, every pair's clocks the model's with
/// `a < b` and two to `pair::PAIR_KNOTS_MOST` knots, every float finite, nothing after. So a model
/// read back encodes to the same bytes.
pub fn decode_pairs(bytes: &[u8]) -> Result<crate::pair::PairModel, PublishError> {
    let mut reader = Reader { bytes, at: 0 };
    let float = |reader: &mut Reader<'_>| -> Result<f64, PublishError> {
        let value = f64::from_bits(reader.u64()?);
        value
            .is_finite()
            .then_some(value)
            .ok_or(PublishError::Malformed("float"))
    };
    let single = |reader: &mut Reader<'_>| -> Result<f32, PublishError> {
        let value = f32::from_bits(reader.u32()?);
        value
            .is_finite()
            .then_some(value)
            .ok_or(PublishError::Malformed("float"))
    };
    let spec = reader.u16()?;
    let area = Region::from_u64(reader.u64()?).map_err(|_| PublishError::Malformed("area"))?;
    let trailing = Trailing {
        edge_ms: reader.u64()?,
        span_ms: reader.u32()?,
    };
    let scope_count = reader.u16()?;
    let mut scope: Vec<Site> = reader.list(scope_count, SITE_WIRE_BYTES);
    let mut frontier: Vec<Frontier> = Vec::new();
    for _ in 0..scope_count {
        let receiver = reader.public_key()?;
        let clock = Clock::from_byte(reader.u8()?);
        let id = SiteId(reader.array()?);
        let location = Location {
            lat_e7: reader.i32()?,
            lon_e7: reader.i32()?,
            alt_m: reader.i32()?,
            precision_m: reader.u32()?,
        };
        if scope.last().is_some_and(|last| last.receiver >= receiver) {
            return Err(PublishError::Malformed("scope order"));
        }
        let (boot_id, through_sequence) = (reader.u64()?, reader.u64()?);
        if through_sequence != NO_FRONTIER {
            frontier.push(Frontier {
                receiver,
                boot_id,
                through_sequence,
            });
        } else if boot_id != 0 {
            return Err(PublishError::Malformed("frontier"));
        }
        scope.push(Site {
            receiver,
            clock,
            location,
            id,
        });
    }
    let input = Citation {
        hash: reader.array()?,
        count: reader.u32()?,
    };
    let count = |reader: &mut Reader<'_>, each: usize| -> Result<usize, PublishError> {
        let count = reader.u32()? as usize;
        if count > reader.bytes.len().saturating_sub(reader.at) / each {
            return Err(PublishError::Truncated);
        }
        Ok(count)
    };
    let kappa = single(&mut reader)?;
    let clocks_count = usize::from(reader.u16()?);
    if clocks_count > reader.bytes.len().saturating_sub(reader.at) / PAIR_CLOCK_WIRE_BYTES {
        return Err(PublishError::Truncated);
    }
    let mut clocks: Vec<crate::pair::PairClock> = Vec::with_capacity(clocks_count);
    for _ in 0..clocks_count {
        let key = reader.clock_key(&scope)?;
        if clocks.last().is_some_and(|last| last.key >= key) {
            return Err(PublishError::Malformed("clock order"));
        }
        let lowest = reader.i64()?;
        let heard_ns = reader.u64()?;
        let from = reader.i64()?;
        clocks.push(crate::pair::PairClock {
            key,
            lowest,
            heard_ns,
            from: (from != NONE_I64).then_some(from),
            noise_ns: float(&mut reader)?,
            white_ns: float(&mut reader)?,
            rate: float(&mut reader)?,
            rate_var: single(&mut reader)?,
            common_var: single(&mut reader)?,
        });
    }
    let pairs_count = count(&mut reader, PAIR_WIRE_BYTES)?;
    let mut pairs: Vec<crate::pair::ClockPair> = Vec::with_capacity(pairs_count);
    for _ in 0..pairs_count {
        let (a, b) = (u32::from(reader.u16()?), u32::from(reader.u16()?));
        if a >= b
            || b as usize >= clocks.len()
            || pairs.last().is_some_and(|last| (last.a, last.b) >= (a, b))
        {
            return Err(PublishError::Malformed("pair order"));
        }
        let anchor_a = reader.i64()?;
        let anchor_b = reader.i64()?;
        let size = usize::from(reader.u8()?);
        if !(2..=crate::pair::PAIR_KNOTS_MOST).contains(&size) {
            return Err(PublishError::Malformed("knots"));
        }
        let knots = (0..size)
            .map(|_| float(&mut reader))
            .collect::<Result<Vec<f64>, _>>()?;
        let cov = (0..size * (size + 1) / 2)
            .map(|_| single(&mut reader))
            .collect::<Result<Vec<f32>, _>>()?;
        pairs.push(crate::pair::ClockPair {
            a,
            b,
            anchor_a,
            anchor_b,
            knots,
            cov,
            slope: float(&mut reader)?,
            slope_var: single(&mut reader)?,
            kappa: single(&mut reader)?,
            share: single(&mut reader)?,
        });
    }
    if reader.at != bytes.len() {
        return Err(PublishError::Malformed("trailing bytes"));
    }
    Ok(crate::pair::PairModel {
        spec,
        area,
        trailing,
        scope,
        frontier,
        input,
        kappa,
        clocks,
        pairs,
    })
}

/// A transmission of a due set (`pair::Models::transmissions` of its considered set), as the
/// backoff weighs it (`backoff`): its receptions, its heard time (`pair::Models::heard_unix_ns`)
/// and its rank among its slot's.
#[derive(Clone, Debug)]
pub struct Transmission {
    pub group: Vec<Reception>,
    pub heard_unix_ns: u64,
    pub rank: crate::backoff::Rank,
}

impl Transmission {
    /// Its slot, its aircraft's `address`.
    pub fn slot(&self, address: u32) -> crate::backoff::Slot {
        crate::backoff::Slot::of(address, self.heard_unix_ns)
    }

    /// What it allocates beyond itself: its receptions (each holds its message).
    pub fn bytes(&self) -> usize {
        self.group.capacity() * size_of::<Reception>()
    }
}

/// The transmissions `models` group `considered` into (crate docs, § The pairwise path,
/// grouping), each dated and ranked for its slot (`backoff`). `Err(Unpublished::Ungrouped)` when
/// they group none, or date none.
pub fn transmissions(
    models: &Models<'_>,
    considered: &[Reception],
) -> Result<Vec<Transmission>, Unpublished> {
    transmissions_unless(models, considered, |_| false)
}

/// [`transmissions`] but for the parts `skip` takes (`pair::Models::transmissions_unless`): `Ok`
/// and empty when every part was skipped.
pub fn transmissions_unless(
    models: &Models<'_>,
    considered: &[Reception],
    skip: impl Fn(&[&Reception]) -> bool,
) -> Result<Vec<Transmission>, Unpublished> {
    let (groups, skipped) = models.transmissions_unless(considered, skip);
    if groups.is_empty() && skipped > 0 {
        return Ok(Vec::new());
    }
    let transmissions: Vec<Transmission> = groups
        .into_iter()
        .filter_map(|group| {
            let heard_unix_ns = models.heard_unix_ns(&group)?;
            let receivers: std::collections::BTreeSet<PublicKey> =
                group.iter().map(|reception| reception.receiver).collect();
            // Every reception of a group is of one message, so the least identity is the least
            // reception by its receiver, epoch and counter, its message hashed once.
            let first = group
                .iter()
                .min_by_key(|reception| (reception.receiver, reception.epoch, reception.timestamp))
                .map(Reception::id)?;
            Some(Transmission {
                rank: crate::backoff::Rank::new(receivers.len(), first),
                heard_unix_ns,
                group,
            })
        })
        .collect();
    if transmissions.is_empty() {
        return Err(Unpublished::Ungrouped);
    }
    Ok(transmissions)
}

/// A transmission's receptions' ids, ascending and without repeats: the considered set it is
/// published with.
fn ids_of(group: &[Reception]) -> Vec<ObservationId> {
    let mut ids: Vec<ObservationId> = crate::obs::ids(group);
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Solves one transmission (`group`, one of `transmissions` of a due set under `all`, the newest
/// verified pair model held of each area its hearers are in, all of one trailing window) and
/// writes it to the wire as a format 7 fix citing the models of the areas its used hearers are in
/// (crate docs, § Areas, the models a fix cites). It is solved under only its hearers' areas'
/// models, and again under only its used hearers' areas' models while those are fewer, until the
/// areas it used are the areas it was solved by, each time grouped again and solved from its
/// capped receivers (`pair::Models::capped`); one that used a hearer of an area `all` holds no
/// model of is `Unpublished::Unheld`. A transmission whose considered set the engine already
/// published (`published`) is not solved again, and the fix is published only when the verifier
/// passes the claim read back from its very bytes (`verify::verify_pair_fix`, judged on the
/// normalisation it was solved on, which the verifier's own regrouping of its considered set
/// rebuilds exactly: § Verifying a fix).
pub fn solve_transmission(
    all: &Models<'_>,
    mut group: Vec<Reception>,
    published: impl Fn(&[ObservationId]) -> bool,
) -> Result<(Solution, tally_wire::Fix), Unpublished> {
    let within = |areas: &[Region]| -> Result<Option<Models<'_>>, Unpublished> {
        if *areas == *all.areas() {
            return Ok(None);
        }
        let held = all.areas();
        let unheld: Vec<Region> = areas
            .iter()
            .filter(|area| !held.contains(area))
            .copied()
            .collect();
        if !unheld.is_empty() {
            return Err(Unpublished::Unheld(unheld));
        }
        all.within(areas).map(Some).ok_or(Unpublished::Ungrouped)
    };
    // Every reception of a transmission was located, so each is of an area one of `all` holds a
    // clock in.
    let hearers = all
        .areas_of(group.iter().map(|reception| reception.receiver))
        .ok_or(Unpublished::Ungrouped)?;
    let mut narrowed = within(&hearers)?;
    // The area sets solved by so far: a used hearer's area may lie outside the models it was
    // solved by (a boundary member), so the narrowing need not shrink; a set met again ends it.
    let mut tried: Vec<Vec<Region>> = Vec::new();
    loop {
        let under = narrowed.as_ref().unwrap_or(all);
        if narrowed.is_some() {
            // Grouped again under the fewer models: of the parts, the largest, ties to the first.
            group = under
                .transmissions(&group)
                .into_iter()
                .fold(None, |best: Option<Vec<Reception>>, part| match best {
                    Some(best) if best.len() >= part.len() => Some(best),
                    _ => Some(part),
                })
                .ok_or(Unpublished::Ungrouped)?;
        }
        let ids = ids_of(&group);
        if published(&ids) {
            return Err(Unpublished::Published);
        }
        let capped = under.capped(&group);
        let normalised = under
            .normalise(&capped)
            .map_err(Unpublished::Unnormalised)?;
        let mut solution = normalised.solve().map_err(Unpublished::Unsolved)?;
        let used = under
            .areas_of(solution.used.iter().map(|id| id.receiver))
            .ok_or(Unpublished::Ungrouped)?;
        if used != under.areas() {
            // Other areas than it was solved by: solved again under those alone, until they agree
            // or a set comes round again.
            tried.push(under.areas());
            if tried.contains(&used) {
                return Err(Unpublished::Ungrouped);
            }
            narrowed = within(&used)?;
            continue;
        }
        solution.considered = ids;
        let message = &group[0].message;
        let wire = to_wire_at(normalised.origin_unix_ns, &solution, under.ids(), message)
            .map_err(Unpublished::Unwritable)?;
        let verdict = crate::verify::verify_solved(
            under,
            &Stated::of(&wire),
            crate::clock::SPEC_VERSION,
            &normalised,
        );
        if !verdict.passed() {
            return Err(Unpublished::Refuted(verdict));
        }
        return Ok((solution, wire));
    }
}
