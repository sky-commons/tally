//! What an engine publishes and a checker reads back (crate docs, § Publishing): a clock model's
//! one encoding, the hash of what it is a function of, and a solution's wire form and the claim a
//! verifier rebuilds from it. One implementation for both sides, so the model a solution cites is
//! the model it was computed from.

use blake2::{Blake2s256, Digest};
use tally_wire::{
    Clock, EnuCovariance, Location, ObservationSet, PublicKey, ReceptionKey, ReceptionTag, SiteId,
    TransmitTime,
};

use crate::clock::{Bias, BiasKind, ClockKey, ClockModel, ClockPiece, Jump, Timebase};
use crate::geo::{self, Geodetic};
use crate::modes;
use crate::obs::{ObservationId, Site, message_hash};
use crate::scope::{Citation, Window};
use crate::solve::Solution;

/// Picoseconds in a nanosecond.
const PS_PER_NS: i128 = 1_000;
/// Picoseconds in a millisecond.
const PS_PER_MS: i128 = 1_000_000_000;
/// An absent `begins` or `ends`.
const NONE_I64: i64 = i64::MIN;
/// What the inputs hash is computed under.
const INPUTS_DOMAIN: &[u8] = b"tally clock model inputs id";

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

fn key(out: &mut Vec<u8>, key: &ClockKey) {
    out.extend_from_slice(key.receiver.as_bytes());
    out.extend_from_slice(&key.epoch.to_be_bytes());
    out.extend_from_slice(&key.piece.to_be_bytes());
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

/// Tile, window, scope (each entry written by `entry`) and input citation: what the model is a
/// function of.
fn leading(model: &ClockModel, entry: fn(&mut Vec<u8>, &Site)) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&model.tile.bytes());
    out.extend_from_slice(&model.window.first.to_be_bytes());
    out.extend_from_slice(&model.window.last.to_be_bytes());
    out.extend_from_slice(&(model.scope.len() as u16).to_be_bytes());
    for site in &model.scope {
        entry(&mut out, site);
    }
    out.extend_from_slice(&model.input.hash);
    out.extend_from_slice(&model.input.count.to_be_bytes());
    out
}

/// What the model is a function of, as one hash the manifest carries: BLAKE2s-256 over
/// `"tally clock model inputs id" 0x00`, the specification version (two bytes), and tile, window,
/// scope and input citation, each scope entry as receiver key, clock, site id and stated
/// precision (never the site: the id is published to clients, `tally_wire::ClientClockModel`,
/// and must name nothing a client could test a guess against).
/// Two honest engines that agree on it publish the same model bytes.
pub fn inputs_id(model: &ClockModel) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(INPUTS_DOMAIN);
    hasher.update([0]);
    hasher.update(model.spec.to_be_bytes());
    hasher.update(leading(model, scope_entry));
    hasher.finalize().into()
}

/// What a client is sent of `model` (`tally_wire::ClientClockModel`, crate docs § Publishing):
/// the id solutions cite, the manifest's inputs and the window. Nothing of its scope: no site, no
/// `site_mm`, no offset (with the aircraft's published positions they give every receiver's
/// site), and no member at all, since a tile's members are chosen by their exact sites and the
/// tiles a receiver is in, over time, narrow its site. `boot_id` and `sequence` are the full
/// model's, so the summary is numbered with the model it summarises.
pub fn client_model(
    model: &ClockModel,
    id: [u8; 32],
    inputs: [u8; 32],
    (boot_id, sequence, issued_ms): (u64, u64, u64),
) -> tally_wire::ClientClockModelContent {
    tally_wire::ClientClockModelContent {
        boot_id,
        sequence,
        issued_ms,
        spec_version: model.spec,
        model: id,
        inputs,
        window_first: model.window.first,
        window_last: model.window.last,
    }
}

/// The one encoding (crate docs, § Publishing). Refused when a count exceeds its two bytes.
pub fn encode(model: &ClockModel) -> Result<Vec<u8>, PublishError> {
    let count = |len: usize| u16::try_from(len).map_err(|_| PublishError::Range("count"));
    count(model.scope.len())?;
    let mut out = leading(model, site);
    key(&mut out, &model.gauge);
    out.extend_from_slice(&model.origin_unix_ns.to_be_bytes());
    out.extend_from_slice(&model.gauge_rate.to_be_bytes());
    out.extend_from_slice(&count(model.pieces.len())?.to_be_bytes());
    for piece in &model.pieces {
        key(&mut out, &piece.key);
        out.push(match piece.timebase {
            Timebase::Mhz12 => 0,
            Timebase::GpsNanos => 1,
        });
        out.extend_from_slice(&piece.begins.unwrap_or(NONE_I64).to_be_bytes());
        out.extend_from_slice(&piece.ends.unwrap_or(NONE_I64).to_be_bytes());
        for axis in piece.site_mm {
            out.extend_from_slice(&axis.to_be_bytes());
        }
        out.extend_from_slice(&piece.site_sigma_mm.to_be_bytes());
        out.extend_from_slice(&piece.noise_ps.to_be_bytes());
        out.extend_from_slice(&piece.base.to_be_bytes());
        out.extend_from_slice(&piece.first.to_be_bytes());
        out.extend_from_slice(&count(piece.offsets_ps.len())?.to_be_bytes());
        for offset in &piece.offsets_ps {
            out.extend_from_slice(&offset.to_be_bytes());
        }
    }
    out.extend_from_slice(&count(model.biases.len())?.to_be_bytes());
    for bias in &model.biases {
        out.extend_from_slice(&bias.address.to_be_bytes());
        out.push(bias.kind.byte());
        out.extend_from_slice(&bias.mm.to_be_bytes());
    }
    out.extend_from_slice(&count(model.jumps.len())?.to_be_bytes());
    for jump in &model.jumps {
        out.extend_from_slice(jump.receiver.as_bytes());
        out.extend_from_slice(&jump.epoch.to_be_bytes());
        out.extend_from_slice(&jump.at.to_be_bytes());
        out.extend_from_slice(&jump.step_ps.to_be_bytes());
    }
    out.extend_from_slice(&count(model.dropped.len())?.to_be_bytes());
    for (receiver, epoch) in &model.dropped {
        out.extend_from_slice(receiver.as_bytes());
        out.extend_from_slice(&epoch.to_be_bytes());
    }
    Ok(out)
}

/// The tile a model is of, from the first bytes of its encoding (the tile leads it): what a relay
/// groups a model by when it holds only the model's first part.
pub fn tile_of(prefix: &[u8]) -> Result<crate::tile::Tile, PublishError> {
    let mut reader = Reader {
        bytes: prefix,
        at: 0,
    };
    let tile = crate::tile::Tile {
        level: reader.u8()?,
        cube: [reader.i64()?, reader.i64()?, reader.i64()?],
    };
    if tile.level >= crate::tile::LEVELS {
        return Err(PublishError::Malformed("tile level"));
    }
    Ok(tile)
}

/// Reads the one encoding, refusing anything not in canonical form: the scope, pieces, biases
/// and jumps strictly ascending, every piece's receiver in the scope with its site, at least two
/// knots a piece, the gauge a piece whose offsets are all zero, nothing after the jumps. So a
/// model read back encodes to the same bytes.
pub fn decode(bytes: &[u8], spec: u16) -> Result<ClockModel, PublishError> {
    let mut reader = Reader { bytes, at: 0 };
    let tile = crate::tile::Tile {
        level: reader.u8()?,
        cube: [reader.i64()?, reader.i64()?, reader.i64()?],
    };
    if tile.level >= crate::tile::LEVELS {
        return Err(PublishError::Malformed("tile level"));
    }
    let window = Window {
        first: reader.i64()?,
        last: reader.i64()?,
    };
    if window.first > window.last {
        return Err(PublishError::Malformed("window"));
    }
    let count = reader.u16()?;
    let mut scope: Vec<Site> = reader.list(count, SITE_WIRE_BYTES);
    for _ in 0..count {
        let entry = Site {
            receiver: reader.public_key()?,
            clock: Clock::from_byte(reader.u8()?),
            id: SiteId(reader.array()?),
            location: Location {
                lat_e7: reader.i32()?,
                lon_e7: reader.i32()?,
                alt_m: reader.i32()?,
                precision_m: reader.u32()?,
            },
        };
        if scope
            .last()
            .is_some_and(|last| last.receiver >= entry.receiver)
        {
            return Err(PublishError::Malformed("scope order"));
        }
        scope.push(entry);
    }
    let input = Citation {
        hash: reader.array()?,
        count: reader.u32()?,
    };
    let gauge = reader.clock_key()?;
    let origin_unix_ns = reader.u64()?;
    let gauge_rate = reader.i64()?;
    let count = reader.u16()?;
    let mut pieces: Vec<ClockPiece> = reader.list(count, PIECE_WIRE_BYTES);
    for _ in 0..count {
        let key = reader.clock_key()?;
        if pieces.last().is_some_and(|last| last.key >= key) {
            return Err(PublishError::Malformed("piece order"));
        }
        let timebase = match reader.u8()? {
            0 => Timebase::Mhz12,
            1 => Timebase::GpsNanos,
            _ => return Err(PublishError::Malformed("timebase")),
        };
        let begins = Some(reader.i64()?).filter(|value| *value != NONE_I64);
        let ends = Some(reader.i64()?).filter(|value| *value != NONE_I64);
        let site_mm = [reader.i64()?, reader.i64()?, reader.i64()?];
        let site_sigma_mm = reader.i64()?;
        let noise_ps = reader.i64()?;
        let base = reader.i64()?;
        let first = reader.i32()?;
        let knots = reader.u16()?;
        if knots < 2 {
            return Err(PublishError::Malformed("fewer than two knots"));
        }
        let mut offsets_ps: Vec<i64> = reader.list(knots, 8);
        for _ in 0..knots {
            offsets_ps.push(reader.i64()?);
        }
        let Some(entry) = scope.iter().find(|entry| entry.receiver == key.receiver) else {
            return Err(PublishError::Malformed("a clock outside the scope"));
        };
        if Timebase::of(entry.clock) != Some(timebase) {
            return Err(PublishError::Malformed("timebase against the scope"));
        }
        pieces.push(ClockPiece {
            key,
            timebase,
            begins,
            ends,
            site_mm,
            site_sigma_mm,
            noise_ps,
            base,
            first,
            offsets_ps,
        });
    }
    let gauge_zero = pieces
        .iter()
        .find(|piece| piece.key == gauge)
        .is_some_and(|piece| piece.offsets_ps.iter().all(|offset| *offset == 0));
    if !gauge_zero {
        return Err(PublishError::Malformed("gauge"));
    }
    let count = reader.u16()?;
    let mut biases: Vec<Bias> = reader.list(count, BIAS_WIRE_BYTES);
    for _ in 0..count {
        let address = reader.u32()?;
        let kind = BiasKind::from_byte(reader.u8()?).ok_or(PublishError::Malformed("bias kind"))?;
        let bias = Bias {
            address,
            kind,
            mm: reader.i64()?,
        };
        if biases
            .last()
            .is_some_and(|last| (last.address, last.kind) >= (bias.address, bias.kind))
        {
            return Err(PublishError::Malformed("bias order"));
        }
        biases.push(bias);
    }
    let count = reader.u16()?;
    let mut jumps: Vec<Jump> = reader.list(count, JUMP_WIRE_BYTES);
    for _ in 0..count {
        let jump = Jump {
            receiver: reader.public_key()?,
            epoch: reader.u32()?,
            at: reader.i64()?,
            step_ps: reader.i64()?,
        };
        if jumps.last().is_some_and(|last| *last >= jump) {
            return Err(PublishError::Malformed("jump order"));
        }
        jumps.push(jump);
    }
    let count = reader.u16()?;
    let mut dropped: Vec<(PublicKey, u32)> = reader.list(count, DROPPED_WIRE_BYTES);
    for _ in 0..count {
        let clock = (reader.public_key()?, reader.u32()?);
        if dropped.last().is_some_and(|last| *last >= clock) {
            return Err(PublishError::Malformed("dropped order"));
        }
        dropped.push(clock);
    }
    if reader.at != bytes.len() {
        return Err(PublishError::Malformed("trailing bytes"));
    }
    Ok(ClockModel {
        spec,
        tile,
        window,
        scope,
        input,
        gauge,
        origin_unix_ns,
        gauge_rate,
        pieces,
        biases,
        jumps,
        dropped,
    })
}

/// A solution under `model`, as the wire carries it: the transmit time in Unix terms through
/// the model's origin, to the picosecond (exactly the solver's); latitude and longitude rounded
/// to 10^-7 degree and height to the millimetre; the covariance in east, north, up at the
/// solution, as f32.
pub fn to_wire(
    model: &ClockModel,
    solution: &Solution,
    clock_model: [u8; 32],
    addressed: Citation,
    message: &[u8],
) -> Result<tally_wire::Solution, PublishError> {
    let address = modes::address(message).ok_or(PublishError::NoAddress)?;
    let unix_ps = i128::from(model.origin_unix_ns) * PS_PER_NS + i128::from(solution.transmit_ps);
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
    let receptions = solution
        .observations
        .iter()
        .map(|id| tally_wire::Reception {
            receiver: id.receiver,
            epoch: id.epoch,
            counter: id.timestamp,
        })
        .collect();
    Ok(tally_wire::Solution {
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
        clock_model,
        addressed: addressed.to_wire(),
        observations: ObservationSet::new(message.to_vec(), receptions)
            .map_err(|error| PublishError::Wire(error.to_string()))?,
    })
}

/// The raw solution a tagged one stands for (`tally_wire::TaggedSolution`, what a client is sent),
/// rematched by a relay against the raw it holds: each of `held` (receptions of the solution's
/// message that the relay holds) tagged under its receiver's reception key as `key_of` gives it
/// (the key of the receiver's site-bearing record current when it was heard), and the solution
/// rebuilt from the receptions whose tags it names. `None` unless every tag it names is matched
/// by exactly one reception held, so a tag the relay cannot account for is never taken on trust.
pub fn rematch(
    tagged: &tally_wire::TaggedSolution,
    held: impl IntoIterator<Item = tally_wire::Reception>,
    key_of: impl Fn(&PublicKey) -> Option<ReceptionKey>,
) -> Option<tally_wire::Solution> {
    let message = tagged.observations.message();
    let wanted = tagged.observations.tags();
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
    Some(tally_wire::Solution {
        address: tagged.address,
        transmitted: tagged.transmitted,
        lat_e7: tagged.lat_e7,
        lon_e7: tagged.lon_e7,
        alt_hae_mm: tagged.alt_hae_mm,
        covariance: tagged.covariance,
        clock_model: tagged.clock_model,
        addressed: tagged.addressed,
        observations: ObservationSet::new(message.to_vec(), receptions).ok()?,
    })
}

/// Why a transmission is not published.
#[derive(Debug, Clone, PartialEq)]
pub enum Unpublished {
    /// The solver found no solution.
    Unsolved(crate::solve::SolveError),
    /// The solution cannot be written to the wire.
    Unwritable(PublishError),
    /// The verifier refuses the claim read back from what would be published.
    Refuted(crate::verify::Verdict),
}

/// Solves `transmission` under `calibrated` and writes it to the wire, citing `clock_model` and
/// `addressed`: published only when the verifier passes the claim read back from those very
/// bytes (`verify_grouped`, the verifier's own checks and limits). The one acceptance rule, every
/// solution checked: nothing is published that a verifier holding the same raw would refuse.
/// `transmission` is one group of `group_reach` over every reception of the message the publisher
/// holds, as the verifier would regroup them.
pub fn solve_published(
    calibrated: &crate::sync::Calibrated,
    transmission: &crate::group::Transmission,
    clock_model: [u8; 32],
    addressed: Citation,
) -> Result<(Solution, tally_wire::Solution), Unpublished> {
    let model = &calibrated.model;
    let solution = crate::solve::solve(calibrated, transmission).map_err(Unpublished::Unsolved)?;
    let wire = to_wire(model, &solution, clock_model, addressed, &transmission.data)
        .map_err(Unpublished::Unwritable)?;
    let claim = claim(model, &wire, crate::clock::SPEC_VERSION).map_err(Unpublished::Unwritable)?;
    let verdict = crate::verify::verify_grouped(calibrated, transmission, &claim);
    if !verdict.passed() {
        return Err(Unpublished::Refuted(verdict));
    }
    Ok((solution, wire))
}

/// The claim a verifier checks for a wire solution under `model`: its position and transmit
/// time read back, its covariance rotated back to ECEF, its observations' identities. The wire
/// carries no chi-square (the verifier computes it; it is 0 here) and no degrees of freedom,
/// which follow from the count and the message's altitude.
pub fn claim(
    model: &ClockModel,
    wire: &tally_wire::Solution,
    spec: u16,
) -> Result<Solution, PublishError> {
    let height_mm = wire.alt_hae_mm.ok_or(PublishError::Range("no altitude"))?;
    let position = Geodetic {
        lat_deg: f64::from(wire.lat_e7) * 1e-7,
        lon_deg: f64::from(wire.lon_e7) * 1e-7,
        height_m: f64::from(height_mm) / 1000.0,
    };
    let ecef = geo::to_ecef(position);
    let unix_ps = i128::try_from(wire.transmitted.unix_ps())
        .map_err(|_| PublishError::Range("transmit time"))?;
    let transmit_ps = i64::try_from(unix_ps - i128::from(model.origin_unix_ns) * PS_PER_NS)
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
    let message = wire.observations.message();
    let hash = message_hash(message);
    let observations: Vec<ObservationId> = wire
        .observations
        .receptions()
        .iter()
        .map(|reception| ObservationId {
            receiver: reception.receiver,
            epoch: reception.epoch,
            timestamp: reception.counter,
            message: hash,
        })
        .collect();
    let altitude = modes::altitude(message);
    let dof = (observations.len() + usize::from(altitude.is_some())).saturating_sub(4);
    Ok(Solution {
        spec,
        ecef,
        position,
        transmit_ps,
        covariance,
        observations,
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
/// besides), a clock's piece (its key, timebase, times, site, noise, base, first knot and at least
/// two knots), a bias, a jump and a dropped clock. What [`Reader::list`] reserves for a count by.
const SITE_WIRE_BYTES: usize = 32 + 1 + 16;
const PIECE_WIRE_BYTES: usize = 38 + 1 + 8 * 8 + 4 + 2 + 2 * 8;
const BIAS_WIRE_BYTES: usize = 4 + 1 + 8;
const JUMP_WIRE_BYTES: usize = 32 + 4 + 8 + 8;
const DROPPED_WIRE_BYTES: usize = 32 + 4;

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

    fn clock_key(&mut self) -> Result<ClockKey, PublishError> {
        Ok(ClockKey {
            receiver: self.public_key()?,
            epoch: self.u32()?,
            piece: self.u16()?,
        })
    }
}
