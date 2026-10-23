//! The two products (RFC-0174 §2.11).
//!
//! - **World:** one fix per aircraft per second, everywhere: the merged final and provisional
//!   fixes of every area, thinned to one an aircraft a second by a rule anyone can rerun
//!   ([`world_choice`]), each citing its input set hash and the origin `Positions` record it came
//!   from, so a reader checks a world record exactly as it would its areas'. Signed by the relay
//!   that gathered it (`WorldPositions`).
//! - **Regional:** everything for one area. Its deduplicated receptions travel as `RegionalBatch`
//!   records, one cell's one copy of each message, signed by the origin relay that deduplicated it
//!   under a domain of its own; raw, positions and clock models travel as themselves.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, Observation, check_coordinates};
use crate::decoded::ObsView;
use crate::key::{KEY_LEN, PublicKey, Signs};
#[cfg(test)]
use crate::observation_set::ObservationSet;
use crate::positions::{EnuCovariance, TransmitTime};
use crate::record::{Body, MAX_BODY};
use crate::region::Region;
use crate::signed::{Check, Checked, Fields, Unchecked, count_u16, read_count, signed_record};

/// The most fixes one world record carries; a second of the world is several records.
pub const MAX_WORLD_FIXES: usize = 400;
/// The most observations one regional batch carries.
pub const MAX_REGIONAL_OBSERVATIONS: usize = 2_000;
/// The altitude field when a fix states none.
const NO_ALTITUDE: i32 = i32::MIN;

/// How long after a transmission its final MLAT fix has surely arrived, wherever it is read: the
/// one bound every party waits on before treating a final fix as never coming (the merge rule's
/// retraction of an unconfirmed provisional fix, the precise world product's seal, a receiver's
/// standing settling a transmission).
///
/// Derived in the clocks' error budget (`crate::budget::FINAL_FIX_ARRIVED`, 108.5 s): the
/// engine's settling and solving, the skew between its relay's clock and a reader's (`K`), and a
/// relay hop or two. Before, the skew was a literal 8 s of this module's own, less than two
/// judging clocks may be apart.
pub const FINAL_FIX_ARRIVED_MS: u64 = crate::budget::FINAL_FIX_ARRIVED_MS;

/// One aircraft's fix for one second of the world product.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WorldFix {
    pub address: u32,
    pub transmitted: TransmitTime,
    pub lat_e7: i32,
    pub lon_e7: i32,
    pub alt_hae_mm: Option<i32>,
    /// The pressure altitude the transmission itself carries, feet: what a display draws an
    /// aircraft's level by (a fix's height above the ellipsoid is not a flight level).
    pub pressure_altitude_ft: Option<i32>,
    pub covariance: EnuCovariance,
    /// A provisional fix (superseded later by a final one).
    pub provisional: bool,
    /// Solved by multilateration (its origin is a `Positions` or `Provisional` record), not
    /// decoded from the aircraft's own broadcast.
    pub mlat: bool,
    /// The merge rule's full input set hash of the fix (RFC-0171 §3.8.1).
    pub input_set: Hash,
    /// Who signed the origin record: the engine of a `Positions` or `Provisional` record, the
    /// origin relay of a `RegionalBatch`. [`world_rank`] breaks a tie by it.
    pub source: PublicKey,
    /// The origin record's hash (`Positions`, `Provisional` or `RegionalBatch`), and the fix's
    /// index in it (a solution's, or an observation's).
    pub origin: Hash,
    pub origin_index: u16,
}

/// One part of one second of the world.
#[derive(Clone, Debug, PartialEq)]
pub struct WorldPositionsContent {
    /// Unix seconds of the fixes' transmit times.
    pub second: u64,
    /// This record's index among the second's parts, from 0.
    pub part: u16,
    /// Ascending by address, one an aircraft.
    pub fixes: Vec<WorldFix>,
}

/// Unix milliseconds at the start of `second`: `None` past `u64::MAX`.
fn second_ms(second: u64) -> Option<u64> {
    second.checked_mul(1_000)
}

impl Check for WorldPositionsContent {
    /// At most `MAX_WORLD_FIXES` fixes, strictly ascending by address (one an aircraft); each
    /// inside the record's second (whose start fits a `u64` of milliseconds), its transmit time
    /// valid, its position on the globe, its covariance finite with no negative variance, and one
    /// source for each origin record.
    fn check(&self) -> Result<(), WireError> {
        if self.fixes.len() > MAX_WORLD_FIXES
            || self
                .fixes
                .windows(2)
                .any(|pair| pair[0].address >= pair[1].address)
        {
            return Err(WireError::Invalid {
                field: "world fix order",
                value: self.fixes.len() as u64,
            });
        }
        let start = second_ms(self.second).ok_or(WireError::Invalid {
            field: "world second",
            value: self.second,
        })?;
        let mut sources: BTreeMap<Hash, PublicKey> = BTreeMap::new();
        for fix in &self.fixes {
            TransmitTime::new(fix.transmitted.unix_ms, fix.transmitted.sub_ms_ps)?;
            if fix
                .transmitted
                .unix_ms
                .checked_sub(start)
                .is_none_or(|into| into >= 1_000)
            {
                return Err(WireError::Invalid {
                    field: "world fix second",
                    value: fix.transmitted.unix_ms,
                });
            }
            check_coordinates(fix.lat_e7, fix.lon_e7)?;
            fix.covariance.check()?;
            if fix.alt_hae_mm == Some(NO_ALTITUDE) || fix.pressure_altitude_ft == Some(NO_ALTITUDE)
            {
                return Err(WireError::Invalid {
                    field: "world fix altitude",
                    value: u64::from(NO_ALTITUDE.unsigned_abs()),
                });
            }
            if *sources.entry(fix.origin).or_insert(fix.source) != fix.source {
                return Err(WireError::Invalid {
                    field: "world fix origin source",
                    value: 0,
                });
            }
        }
        Ok(())
    }
}

/// Each fix's transmit time as milliseconds into the record's second (0 to 999) and the
/// picoseconds past them; each fix's origin as an index into the record's table of origins (each
/// a record hash and the key that signed it, ascending by hash, each once), which most fixes of a
/// second share: about 85 bytes a fix, against 151 with each time and origin whole.
impl Fields for WorldPositionsContent {
    fn write(world: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        let origins: BTreeMap<Hash, PublicKey> = world
            .fixes
            .iter()
            .map(|fix| (fix.origin, fix.source))
            .collect();
        let table: Vec<Hash> = origins.keys().copied().collect();
        // The check placed every fix inside the second, whose start fits.
        let start = second_ms(world.second).unwrap_or(0);
        out.extend_from_slice(&world.second.to_be_bytes());
        out.extend_from_slice(&world.part.to_be_bytes());
        count_u16(out, origins.len(), MAX_WORLD_FIXES)?;
        for (origin, source) in &origins {
            out.extend_from_slice(origin);
            out.extend_from_slice(source.as_bytes());
        }
        count_u16(out, world.fixes.len(), MAX_WORLD_FIXES)?;
        for fix in &world.fixes {
            let into_ms = fix.transmitted.unix_ms - start;
            let slot = table
                .binary_search(&fix.origin)
                .map_err(|_| WireError::Invalid {
                    field: "world fix origin",
                    value: 0,
                })?;
            out.extend_from_slice(&fix.address.to_be_bytes());
            out.extend_from_slice(&(into_ms as u16).to_be_bytes());
            out.extend_from_slice(&fix.transmitted.sub_ms_ps.to_be_bytes());
            out.extend_from_slice(&fix.lat_e7.to_be_bytes());
            out.extend_from_slice(&fix.lon_e7.to_be_bytes());
            out.extend_from_slice(&fix.alt_hae_mm.unwrap_or(NO_ALTITUDE).to_be_bytes());
            out.extend_from_slice(
                &fix.pressure_altitude_ft
                    .unwrap_or(NO_ALTITUDE)
                    .to_be_bytes(),
            );
            for term in fix.covariance.terms() {
                out.extend_from_slice(&term.to_bits().to_be_bytes());
            }
            // One byte of flags: bit 0 provisional, bit 1 MLAT.
            out.push(u8::from(fix.provisional) | u8::from(fix.mlat) << 1);
            out.extend_from_slice(&fix.input_set);
            out.extend_from_slice(&(slot as u16).to_be_bytes());
            out.extend_from_slice(&fix.origin_index.to_be_bytes());
        }
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let second = reader.u64()?;
        let part = reader.u16()?;
        let start = second_ms(second).ok_or(WireError::Invalid {
            field: "world second",
            value: second,
        })?;
        let tabled = read_count(reader, MAX_WORLD_FIXES)?;
        let origins = (0..tabled)
            .map(|_| {
                Ok((
                    reader.array()?,
                    PublicKey::from_slice(reader.bytes(KEY_LEN)?)?,
                ))
            })
            .collect::<Result<Vec<(Hash, PublicKey)>, WireError>>()?;
        if origins.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(WireError::Invalid {
                field: "world origin order",
                value: 0,
            });
        }
        let count = read_count(reader, MAX_WORLD_FIXES)?;
        let fixes = (0..count)
            .map(|_| {
                let address = reader.u32()?;
                let into_ms = u64::from(reader.u16()?);
                if into_ms >= 1_000 {
                    return Err(WireError::Invalid {
                        field: "world fix second",
                        value: into_ms,
                    });
                }
                let transmitted = TransmitTime::new(start + into_ms, reader.u32()?)?;
                let lat_e7 = reader.i32()?;
                let lon_e7 = reader.i32()?;
                let alt_hae_mm = Some(reader.i32()?).filter(|alt| *alt != NO_ALTITUDE);
                let pressure_altitude_ft = Some(reader.i32()?).filter(|alt| *alt != NO_ALTITUDE);
                let mut terms = [0.0; 6];
                for term in &mut terms {
                    *term = reader.f32()?;
                }
                let flags = reader.u8()?;
                let [xx, xy, xz, yy, yz, zz] = terms;
                let input_set = reader.array()?;
                let (origin, source) =
                    *origins
                        .get(usize::from(reader.u16()?))
                        .ok_or(WireError::Invalid {
                            field: "world fix origin",
                            value: 0,
                        })?;
                Ok(WorldFix {
                    address,
                    transmitted,
                    lat_e7,
                    lon_e7,
                    alt_hae_mm,
                    pressure_altitude_ft,
                    covariance: EnuCovariance {
                        xx,
                        xy,
                        xz,
                        yy,
                        yz,
                        zz,
                    },
                    provisional: flags & 1 != 0,
                    mlat: flags & 2 != 0,
                    input_set,
                    source,
                    origin,
                    origin_index: reader.u16()?,
                })
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        Ok(Unchecked::new(Self {
            second,
            part,
            fixes,
        }))
    }
}

signed_record!(
    /// The gathering relay's signed `WorldPositionsContent`: the live world product, each second
    /// sealed a few seconds after it ends, an MLAT aircraft by its provisional fix.
    WorldPositions,
    WorldPositionsContent,
    b"tally world positions",
    1,
    MAX_BODY
);

signed_record!(
    /// The precise world product: the same content and the same choice rule over final MLAT fixes
    /// only (ADS-B as in the live product), each second sealed once its finals have surely come. Its
    /// own domain, so a precise record never verifies as a live one or back.
    WorldPrecise,
    WorldPositionsContent,
    b"tally world precise positions",
    1,
    MAX_BODY
);

/// One candidate for an aircraft's world fix of one second: what [`world_choice`] decides by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldCandidate {
    pub transmitted: TransmitTime,
    pub provisional: bool,
    pub input_set: Hash,
    /// Who signed the origin record.
    pub source: PublicKey,
    /// The origin record's hash, and the fix's index in it.
    pub origin: Hash,
    pub origin_index: u16,
}

/// The rule that picks an aircraft's world fix of one second among its candidates, the same for
/// every relay and reader and independent of the order the candidates are given in (RFC-0174
/// §2.11: the newest fix of each aircraft each second). The index chosen, or `None` for no
/// candidates.
///
/// The rule is the merge rule's serving order (RFC-0171 §3.8.1, *Provisional fixes*: the latest
/// final fix is served unless a provisional one is later by transmit time) applied inside one
/// second, and its tie rule:
///
/// 1. the latest transmit time;
/// 2. at the same transmit time, a final fix (an MLAT final or a decoded ADS-B position) over a
///    provisional one;
/// 3. then the lowest input set hash;
/// 4. then the lowest source key, by its bytes (two relays that solved the same set each sign
///    their own record);
/// 5. then the lowest origin record hash, and the lowest index in it.
///
/// [`world_rank`] is that order, a total order, so a gatherer that keeps only the best candidate
/// so far chooses what this function would over every candidate at once, in any order.
/// Candidates equal in all of it are one fix named twice; the first of them is returned. Refused:
/// a transmit time out of range.
pub fn world_choice(candidates: &[WorldCandidate]) -> Result<Option<usize>, WireError> {
    let mut best: Option<usize> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        TransmitTime::new(
            candidate.transmitted.unix_ms,
            candidate.transmitted.sub_ms_ps,
        )?;
        best = match best {
            Some(held) if world_rank(candidate, &candidates[held]) != Ordering::Greater => {
                Some(held)
            }
            _ => Some(index),
        };
    }
    Ok(best)
}

/// How `a` stands to `b` under [`world_choice`]'s rule: `Greater` when `a` is chosen over `b`.
/// A total order on (transmit time, final before provisional, input set hash, source key, origin
/// hash, origin index): `Equal` only for one fix named twice.
pub fn world_rank(a: &WorldCandidate, b: &WorldCandidate) -> Ordering {
    a.transmitted
        .cmp(&b.transmitted)
        .then_with(|| (!a.provisional).cmp(&!b.provisional))
        .then_with(|| b.input_set.cmp(&a.input_set))
        .then_with(|| b.source.as_bytes().cmp(a.source.as_bytes()))
        .then_with(|| b.origin.cmp(&a.origin))
        .then_with(|| b.origin_index.cmp(&a.origin_index))
}

impl WorldFix {
    /// What [`world_choice`] decides this fix by.
    pub fn candidate(&self) -> WorldCandidate {
        WorldCandidate {
            transmitted: self.transmitted,
            provisional: self.provisional,
            input_set: self.input_set,
            source: self.source,
            origin: self.origin,
            origin_index: self.origin_index,
        }
    }

    /// Whether this fix is chosen over `other` by [`world_rank`].
    pub fn ranks_above(&self, other: &Self) -> bool {
        world_rank(&self.candidate(), &other.candidate()) == Ordering::Greater
    }
}

/// What the merge rule's full input set hash is computed under.
const INPUT_SET_DOMAIN: &[u8] = b"tally merge input set";
/// What an ADS-B world fix's input set hash is computed under.
const ADSB_INPUT_SET_DOMAIN: &[u8] = b"tally world adsb input set";

/// The full input set's identity of an MLAT solution (RFC-0171 §3.8.1): BLAKE2s-256 over
/// `"tally merge input set" 0x00`, the observation set's hash and the cited model's inputs hash.
/// The one definition, for the merge rule and the world product alike. Of a tagged solution, over
/// its `TaggedSet`'s hash, and so what the world product states. A client cannot recompute it from
/// anything it can check: a tag hides which receiver and reception it stands for, and the model's
/// inputs hash is over site ids a client is never sent. To a client the stated input set is the
/// signer's word; the relay that serves it checks it (`consistency`, RFC-0171 §3.8.2).
pub fn input_set<O: crate::positions::Observed>(observations: &O, model_inputs: &Hash) -> Hash {
    let mut hasher = Blake2s256::new();
    hasher.update(INPUT_SET_DOMAIN);
    hasher.update([0]);
    hasher.update(observations.set_hash());
    hasher.update(model_inputs);
    hasher.finalize().into()
}

/// The input set's identity of an ADS-B world fix, decoded globally from the airborne position
/// `position` and the opposite-parity one it was paired with, `pair` (RFC-0174 §2.11):
/// BLAKE2s-256 over `"tally world adsb input set" 0x00` and each message, length first. Two
/// relays that decode the same pair state the same set, whichever regional batch carried it.
pub fn adsb_input_set(position: &[u8], pair: &[u8]) -> Hash {
    let mut hasher = Blake2s256::new();
    hasher.update(ADSB_INPUT_SET_DOMAIN);
    hasher.update([0]);
    for message in [position, pair] {
        // A Mode S message is 7 or 14 bytes; the length keeps the two apart.
        hasher.update([message.len().min(usize::from(u8::MAX)) as u8]);
        hasher.update(message);
    }
    hasher.finalize().into()
}

/// One cell's deduplicated receptions, as its origin relay signs them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionalBatchContent {
    /// The area.
    pub cell: Region,
    /// The origin's own stream: random per process start, numbered from 0.
    pub boot_id: u64,
    pub sequence: u64,
    pub wall_ms: u64,
    pub observations: Vec<Observation>,
}

impl Check for RegionalBatchContent {
    /// At most `MAX_REGIONAL_OBSERVATIONS` observations.
    fn check(&self) -> Result<(), WireError> {
        if self.observations.len() > MAX_REGIONAL_OBSERVATIONS {
            return Err(WireError::Invalid {
                field: "regional observations",
                value: self.observations.len() as u64,
            });
        }
        Ok(())
    }
}

/// One cell's deduplicated receptions as its origin relay is about to sign them, borrowed where
/// they are held (a decoded batch's, `ObsView`): signed into the same bytes as the
/// `RegionalBatchContent` of their owned copies (`RegionalBatch::sign_draft`), with no copy made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionalDraft<'a> {
    pub cell: Region,
    pub boot_id: u64,
    pub sequence: u64,
    pub wall_ms: u64,
    pub observations: Vec<ObsView<'a>>,
}

/// The one layout of a regional batch's body, whether its receptions are owned or borrowed: at
/// most `MAX_REGIONAL_OBSERVATIONS` of them, as `RegionalBatchContent::check` says.
fn write_regional<'a>(
    out: &mut Vec<u8>,
    (cell, boot_id, sequence, wall_ms): (Region, u64, u64, u64),
    observations: impl ExactSizeIterator<Item = ObsView<'a>>,
) -> Result<(), WireError> {
    out.extend_from_slice(&cell.as_u64().to_be_bytes());
    out.extend_from_slice(&boot_id.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&wall_ms.to_be_bytes());
    count_u16(out, observations.len(), MAX_REGIONAL_OBSERVATIONS)?;
    for observation in observations {
        observation.encode(out)?;
    }
    Ok(())
}

impl RegionalDraft<'_> {
    fn body(&self) -> Result<Vec<u8>, WireError> {
        let mut body = Vec::new();
        write_regional(
            &mut body,
            (self.cell, self.boot_id, self.sequence, self.wall_ms),
            self.observations.iter().copied(),
        )?;
        Ok(body)
    }
}

impl RegionalBatch {
    /// Its signed `wall_ms` (`RegionalBatchContent::wall_ms`), read without its receptions: what a
    /// relay's time window judges it by. After the cell, the boot id and the sequence.
    pub fn wall_ms(&self) -> Result<u64, WireError> {
        crate::batch::u64_from(self.as_bytes(), 1 + crate::key::KEY_LEN + 24)
    }

    /// As `sign`, from receptions borrowed: the bytes `sign` makes of their owned copies.
    pub fn sign_draft(identity: &impl Signs, draft: &RegionalDraft<'_>) -> Result<Self, WireError> {
        let body = draft.body()?;
        crate::signed::Signed::sign(Self::DOMAIN, Self::FORMAT, identity, &body, Self::MAX_LEN)
            .map(Self)
    }

    /// As `fits`, for a draft: whether `sign_draft` would make it.
    pub fn fits_draft(draft: &RegionalDraft<'_>) -> bool {
        draft
            .body()
            .is_ok_and(|body| crate::signed::Signed::fits(body.len(), Self::MAX_LEN))
    }
}

impl Fields for RegionalBatchContent {
    fn write(regional: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        write_regional(
            out,
            (
                regional.cell,
                regional.boot_id,
                regional.sequence,
                regional.wall_ms,
            ),
            regional.observations.iter().map(ObsView::from),
        )
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let cell = Region::from_u64(reader.u64()?)?;
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let wall_ms = reader.u64()?;
        let count = read_count(reader, MAX_REGIONAL_OBSERVATIONS)?;
        let observations = (0..count)
            .map(|_| Observation::decode(reader))
            .collect::<Result<_, _>>()?;
        Ok(Unchecked::new(Self {
            cell,
            boot_id,
            sequence,
            wall_ms,
            observations,
        }))
    }
}

signed_record!(
    /// The origin relay's signed `RegionalBatchContent`.
    RegionalBatch,
    RegionalBatchContent,
    b"tally regional batch",
    1,
    MAX_BODY
);

/// One deduplicated reception as a client receives it: the message alone, with no receiver
/// counter and no signal level. A counter, grouped by the clock line it lies on and set against
/// the aircraft's MLAT positions, ranges the receiver that heard it; a signal level, set against
/// the aircraft's public positions, estimates the distance to it, which in an area of one receiver
/// places that receiver. So both are relay-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientObservation {
    /// As `Observation::format`.
    pub format: u8,
    pub data: Vec<u8>,
}

/// One area's deduplicated receptions as a client receives them (wire version 3): a
/// `RegionalBatchContent` with every counter stripped and the batch's wall clock kept.
///
/// ```text
/// format u8 = 1 | origin key [32] | cell u64 | boot_id u64 | sequence u64 | wall_ms u64
/// | count u16 | count x (format u8 | length u16 | data)
/// | signature [64]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRegionalBatchContent {
    /// The area: no finer than a receiver's public cell, so the area tells no more of a receiver.
    pub cell: Region,
    pub boot_id: u64,
    pub sequence: u64,
    pub wall_ms: u64,
    pub observations: Vec<ClientObservation>,
}

impl RegionalBatchContent {
    /// What a client is sent of it: the same receptions, counters stripped, and none that is not
    /// a product's (`format::in_products`), whatever relay signed it.
    pub fn for_clients(&self) -> ClientRegionalBatchContent {
        ClientRegionalBatchContent {
            cell: self.cell,
            boot_id: self.boot_id,
            sequence: self.sequence,
            wall_ms: self.wall_ms,
            observations: self
                .observations
                .iter()
                .filter(|observation| crate::batch::format::in_products(observation.format))
                .map(|observation| ClientObservation {
                    format: observation.format,
                    data: observation.data.clone(),
                })
                .collect(),
        }
    }
}

impl Check for ClientRegionalBatchContent {
    /// At most `MAX_REGIONAL_OBSERVATIONS` observations, each of at most `u16::MAX` bytes, of an
    /// area no finer than the public cell.
    fn check(&self) -> Result<(), WireError> {
        if self.observations.len() > MAX_REGIONAL_OBSERVATIONS {
            return Err(WireError::Invalid {
                field: "regional observations",
                value: self.observations.len() as u64,
            });
        }
        if self.cell.resolution() > crate::site::PUBLIC_CELL_RESOLUTION {
            return Err(WireError::Invalid {
                field: "client regional cell resolution",
                value: u64::from(self.cell.resolution()),
            });
        }
        if let Some(long) = self
            .observations
            .iter()
            .find(|observation| u16::try_from(observation.data.len()).is_err())
        {
            return Err(WireError::Oversize(long.data.len()));
        }
        Ok(())
    }
}

/// The one layout of a client regional batch's body, owned or borrowed.
fn write_client_regional<'a>(
    out: &mut Vec<u8>,
    (cell, boot_id, sequence, wall_ms): (Region, u64, u64, u64),
    observations: impl ExactSizeIterator<Item = (u8, &'a [u8])>,
) -> Result<(), WireError> {
    out.extend_from_slice(&cell.as_u64().to_be_bytes());
    out.extend_from_slice(&boot_id.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&wall_ms.to_be_bytes());
    count_u16(out, observations.len(), MAX_REGIONAL_OBSERVATIONS)?;
    for (format, data) in observations {
        out.push(format);
        let length = u16::try_from(data.len()).map_err(|_| WireError::Oversize(data.len()))?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(data);
    }
    Ok(())
}

impl Fields for ClientRegionalBatchContent {
    fn write(regional: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        write_client_regional(
            out,
            (
                regional.cell,
                regional.boot_id,
                regional.sequence,
                regional.wall_ms,
            ),
            regional
                .observations
                .iter()
                .map(|observation| (observation.format, &observation.data[..])),
        )
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let cell = Region::from_u64(reader.u64()?)?;
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let wall_ms = reader.u64()?;
        let count = read_count(reader, MAX_REGIONAL_OBSERVATIONS)?;
        let observations = (0..count)
            .map(|_| {
                let format = reader.u8()?;
                let length = usize::from(reader.u16()?);
                Ok(ClientObservation {
                    format,
                    data: reader.bytes(length)?.to_vec(),
                })
            })
            .collect::<Result<_, WireError>>()?;
        Ok(Unchecked::new(Self {
            cell,
            boot_id,
            sequence,
            wall_ms,
            observations,
        }))
    }
}

signed_record!(
    /// The origin relay's signed `ClientRegionalBatchContent`: the regional product a client is
    /// sent. Its own domain, so it never verifies as a `RegionalBatch` or back.
    ClientRegionalBatch,
    ClientRegionalBatchContent,
    b"tally client regional batch",
    1,
    MAX_BODY
);

impl ClientRegionalBatch {
    /// Its signed `wall_ms`, as `RegionalBatch::wall_ms`.
    pub fn wall_ms(&self) -> Result<u64, WireError> {
        crate::batch::u64_from(self.as_bytes(), 1 + crate::key::KEY_LEN + 24)
    }

    /// As `sign`, from a draft's borrowed receptions, their counters dropped: the bytes `sign`
    /// makes of `RegionalBatchContent::for_clients` of their owned copies, with no copy made.
    pub fn sign_draft(identity: &impl Signs, draft: &RegionalDraft<'_>) -> Result<Self, WireError> {
        if draft.cell.resolution() > crate::site::PUBLIC_CELL_RESOLUTION {
            return Err(WireError::Invalid {
                field: "client regional cell resolution",
                value: u64::from(draft.cell.resolution()),
            });
        }
        let observations: Vec<(u8, &[u8])> = draft
            .observations
            .iter()
            .filter(|observation| crate::batch::format::in_products(observation.format))
            .map(|observation| (observation.format, observation.data))
            .collect();
        let mut body = Vec::new();
        write_client_regional(
            &mut body,
            (draft.cell, draft.boot_id, draft.sequence, draft.wall_ms),
            observations.into_iter(),
        )?;
        crate::signed::Signed::sign(Self::DOMAIN, Self::FORMAT, identity, &body, Self::MAX_LEN)
            .map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::tests::cell;
    use crate::key::Identity;

    /// A regional batch signed from borrowed receptions is the one signed from their owned
    /// copies, byte for byte, and fits exactly when it does.
    #[test]
    fn a_draft_signs_the_bytes_its_owned_copies_sign() -> Result<(), WireError> {
        let relay = Identity::from_seed([9; 32]);
        let observations: Vec<Observation> = (0..40u8)
            .map(|n| Observation {
                format: b'3',
                timestamp: 1_000 + u64::from(n),
                signal: n,
                data: vec![n; 14],
            })
            .collect();
        let content = RegionalBatchContent {
            cell: cell()?,
            boot_id: 3,
            sequence: 7,
            wall_ms: 1_791_244_800_000,
            observations: observations.clone(),
        };
        let draft = RegionalDraft {
            cell: content.cell,
            boot_id: 3,
            sequence: 7,
            wall_ms: content.wall_ms,
            observations: observations.iter().map(ObsView::from).collect(),
        };
        assert_eq!(
            RegionalBatch::sign_draft(&relay, &draft)?,
            RegionalBatch::sign(&relay, &content)?
        );
        assert!(RegionalBatch::fits_draft(&draft) && RegionalBatch::fits(&content));
        let huge = vec![0u8; MAX_BODY];
        let draft = RegionalDraft {
            observations: vec![ObsView {
                format: b'3',
                timestamp: 0,
                signal: 0,
                data: &huge,
            }],
            ..draft
        };
        assert!(!RegionalBatch::fits_draft(&draft));
        Ok(())
    }

    /// An ACARS-family message is never in a client's regional batch, whoever signed the regional
    /// batch it was in, signed from owned copies or from a draft alike.
    #[test]
    fn a_client_regional_batch_carries_no_acars() -> Result<(), WireError> {
        let relay = Identity::from_seed([9; 32]);
        let acars = br#"{"kind":"acars","label":"H1","t":1}"#;
        let observations = vec![
            Observation {
                format: b'3',
                timestamp: 1,
                signal: 0,
                data: vec![7; 14],
            },
            Observation {
                format: crate::batch::format::ACARS_JSON,
                timestamp: 2,
                signal: 0,
                data: acars.to_vec(),
            },
        ];
        let content = RegionalBatchContent {
            cell: cell()?,
            boot_id: 3,
            sequence: 7,
            wall_ms: 1_791_244_800_000,
            observations: observations.clone(),
        };
        let client = content.for_clients();
        assert_eq!(client.observations.len(), 1);
        assert_eq!(client.observations[0].format, b'3');
        let draft = RegionalDraft {
            cell: content.cell,
            boot_id: 3,
            sequence: 7,
            wall_ms: content.wall_ms,
            observations: observations.iter().map(ObsView::from).collect(),
        };
        let signed = ClientRegionalBatch::sign_draft(&relay, &draft)?;
        assert_eq!(signed, ClientRegionalBatch::sign(&relay, &client)?);
        assert!(!signed.as_bytes().windows(acars.len()).any(|at| at == acars));
        Ok(())
    }

    #[test]
    fn a_client_regional_batch_carries_no_counter() -> Result<(), WireError> {
        let relay = Identity::from_seed([9; 32]);
        let observations: Vec<Observation> = (0..20u8)
            .map(|n| Observation {
                format: b'3',
                timestamp: 0x0a0b_0c0d_0e00 + u64::from(n),
                signal: n,
                data: vec![n; 14],
            })
            .collect();
        let content = RegionalBatchContent {
            cell: cell()?,
            boot_id: 3,
            sequence: 7,
            wall_ms: 1_791_244_800_000,
            observations: observations.clone(),
        };
        let client = content.for_clients();
        let signed = ClientRegionalBatch::sign(&relay, &client)?;
        signed.verify()?;
        assert_eq!(signed.content()?, client);
        assert_eq!(client.observations.len(), 20);
        // The draft signs the same bytes, and no counter's bytes are in them.
        let draft = RegionalDraft {
            cell: content.cell,
            boot_id: 3,
            sequence: 7,
            wall_ms: content.wall_ms,
            observations: observations.iter().map(ObsView::from).collect(),
        };
        assert_eq!(ClientRegionalBatch::sign_draft(&relay, &draft)?, signed);
        let counter = &0x0a0b_0c0d_0e00u64.to_be_bytes()[2..6];
        assert!(!signed.as_bytes().windows(4).any(|at| at == counter));
        // Nor any signal level: the same receptions heard louder or softer are the same bytes.
        let louder = RegionalBatchContent {
            observations: observations
                .iter()
                .map(|observation| Observation {
                    signal: observation.signal.wrapping_add(100),
                    ..observation.clone()
                })
                .collect(),
            ..content.clone()
        };
        assert_eq!(
            ClientRegionalBatch::sign(&relay, &louder.for_clients())?,
            signed
        );
        // Never a regional batch's signature, and never an area finer than a public cell.
        assert!(
            RegionalBatch::from_bytes(signed.as_bytes().to_vec())?
                .verify()
                .is_err()
        );
        let fine = ClientRegionalBatchContent {
            cell: Region::containing(
                &crate::batch::Location {
                    lat_e7: 0,
                    lon_e7: 0,
                    alt_m: 0,
                    precision_m: 0,
                },
                7,
            )?,
            ..client
        };
        assert!(ClientRegionalBatch::sign(&relay, &fine).is_err());
        Ok(())
    }

    #[test]
    fn products_round_trip_under_their_own_domains() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let fix = WorldFix {
            address: 0xa1b2c3,
            transmitted: TransmitTime::new(1_791_244_800_123, 5)?,
            lat_e7: 337_000_000,
            lon_e7: -843_000_000,
            alt_hae_mm: None,
            pressure_altitude_ft: Some(35_000),
            covariance: EnuCovariance {
                xx: 400.0,
                xy: 1.0,
                xz: 0.0,
                yy: 400.0,
                yz: 0.0,
                zz: 900.0,
            },
            provisional: true,
            mlat: true,
            input_set: [3; 32],
            source: relay.public(),
            origin: [4; 32],
            origin_index: 2,
        };
        let world = WorldPositionsContent {
            second: 1_791_244_800,
            part: 0,
            fixes: vec![
                fix,
                WorldFix {
                    address: 0xa1b2c4,
                    alt_hae_mm: Some(10_000_000),
                    pressure_altitude_ft: None,
                    origin: [9; 32],
                    ..fix
                },
            ],
        };
        let signed = WorldPositions::sign(&relay, &world)?;
        signed.verify()?;
        assert_eq!(signed.content()?, world);
        // A fix outside the record's second is refused.
        let stray = WorldPositionsContent {
            second: world.second + 1,
            ..world.clone()
        };
        assert!(WorldPositions::sign(&relay, &stray).is_err());
        let regional = RegionalBatchContent {
            cell: cell()?,
            boot_id: 1,
            sequence: 2,
            wall_ms: 3,
            observations: vec![Observation {
                format: crate::batch::format::MODE_S_SHORT,
                timestamp: 12,
                signal: 9,
                data: vec![0x5d, 1, 2, 3, 4, 5, 6],
            }],
        };
        let signed = RegionalBatch::sign(&relay, &regional)?;
        signed.verify()?;
        assert_eq!(signed.content()?, regional);
        // A regional batch's signature is no world record's.
        let forged = WorldPositions::from_bytes(signed.as_bytes().to_vec())?;
        assert!(forged.verify().is_err());
        Ok(())
    }

    fn candidate(ms: u64, ps: u32, provisional: bool, hash: u8) -> WorldCandidate {
        WorldCandidate {
            transmitted: TransmitTime {
                unix_ms: ms,
                sub_ms_ps: ps,
            },
            provisional,
            input_set: [hash; 32],
            source: Identity::from_seed([7; 32]).public(),
            origin: [hash; 32],
            origin_index: 0,
        }
    }

    /// Every permutation of `items`, by Heap's algorithm.
    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        fn heap<T: Clone>(k: usize, items: &mut Vec<T>, out: &mut Vec<Vec<T>>) {
            if k <= 1 {
                out.push(items.clone());
                return;
            }
            for i in 0..k {
                heap(k - 1, items, out);
                let swap = if k.is_multiple_of(2) { i } else { 0 };
                items.swap(swap, k - 1);
            }
        }
        let mut out = Vec::new();
        heap(items.len(), &mut items.to_vec(), &mut out);
        out
    }

    #[test]
    fn world_choice_is_the_newest_then_final_then_lowest_hash_in_any_order() -> Result<(), WireError>
    {
        let candidates = [
            candidate(1_000, 0, false, 9),
            // Newest, but two of them: the final one at the same time wins.
            candidate(1_900, 7, true, 1),
            candidate(1_900, 7, false, 8),
            // As new and final too, with a lower input set: the tie is broken by the hash.
            candidate(1_900, 7, false, 5),
            candidate(1_899, 999_999_999, false, 0),
        ];
        let expected = candidates[3];
        for order in permutations(&candidates) {
            let chosen = world_choice(&order)?.map(|index| order[index]);
            assert_eq!(chosen, Some(expected));
            // Keeping only the best so far chooses the same.
            let folded = order.iter().copied().reduce(|best, next| {
                if world_rank(&next, &best) == Ordering::Greater {
                    next
                } else {
                    best
                }
            });
            assert_eq!(folded, Some(expected));
        }
        assert_eq!(world_choice(&[])?, None);
        // A provisional fix later by transmit time is served over an older final one.
        let later = [candidate(1_000, 0, false, 0), candidate(1_000, 1, true, 9)];
        assert_eq!(world_choice(&later)?, Some(1));
        Ok(())
    }

    #[test]
    fn one_fix_from_two_origins_is_chosen_by_source_key_then_record_in_any_order()
    -> Result<(), WireError> {
        // The same solution signed by two engines, and one of them twice: equal in time, kind
        // and input set, apart only by who signed it, which record and where in it.
        let low = Identity::from_seed([1; 32]).public();
        let high = Identity::from_seed([2; 32]).public();
        let (low, high) = if low.as_bytes() < high.as_bytes() {
            (low, high)
        } else {
            (high, low)
        };
        let same = |source, origin: u8, origin_index| WorldCandidate {
            source,
            origin: [origin; 32],
            origin_index,
            ..candidate(5_000, 9, false, 4)
        };
        let candidates = [
            same(high, 1, 0),
            same(low, 9, 3),
            same(low, 9, 1),
            same(low, 8, 7),
            same(high, 0, 0),
        ];
        // The lowest source key, then its lowest record hash, then the lowest index in it.
        let expected = candidates[3];
        for order in permutations(&candidates) {
            let chosen = world_choice(&order)?.map(|index| order[index]);
            assert_eq!(chosen, Some(expected));
            let folded = order.iter().copied().reduce(|best, next| {
                if world_rank(&next, &best) == Ordering::Greater {
                    next
                } else {
                    best
                }
            });
            assert_eq!(folded, Some(expected));
        }
        // A total order: only one fix named twice is equal to itself.
        for a in &candidates {
            for b in &candidates {
                assert_eq!(world_rank(a, b) == Ordering::Equal, a == b);
            }
        }
        Ok(())
    }

    #[test]
    fn a_hostile_world_record_is_refused_on_both_sides() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let source = relay.public();
        let fix = |address, unix_ms| WorldFix {
            address,
            transmitted: TransmitTime {
                unix_ms,
                sub_ms_ps: 0,
            },
            lat_e7: 0,
            lon_e7: 0,
            alt_hae_mm: None,
            pressure_altitude_ft: None,
            covariance: EnuCovariance {
                xx: 1.0,
                xy: 0.0,
                xz: 0.0,
                yy: 1.0,
                yz: 0.0,
                zz: 1.0,
            },
            provisional: false,
            mlat: false,
            input_set: [0; 32],
            source,
            origin: [1; 32],
            origin_index: 0,
        };
        let refused = |content: WorldPositionsContent| WorldPositions::sign(&relay, &content);
        // A second whose start does not fit a u64 of milliseconds.
        assert!(
            refused(WorldPositionsContent {
                second: u64::MAX,
                part: 0,
                fixes: vec![fix(1, u64::MAX)],
            })
            .is_err()
        );
        // Out of order, off the globe, two sources for one origin.
        let base = WorldPositionsContent {
            second: 10,
            part: 0,
            fixes: vec![fix(1, 10_000), fix(2, 10_999)],
        };
        assert!(refused(base.clone()).is_ok());
        let mut backwards = base.clone();
        backwards.fixes.reverse();
        assert!(refused(backwards).is_err());
        let mut off = base.clone();
        off.fixes[0].lat_e7 = 900_000_001;
        assert!(refused(off).is_err());
        let mut forked = base.clone();
        forked.fixes[1].source = Identity::generate()?.public();
        assert!(refused(forked).is_err());
        // Read: a signed record whose second is u64::MAX is refused, never wrapped.
        let mut body = Vec::new();
        body.extend_from_slice(&u64::MAX.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        let signed = crate::signed::Signed::sign(
            WorldPositions::DOMAIN,
            WorldPositions::FORMAT,
            &relay,
            &body,
            MAX_BODY,
        )?;
        let record = WorldPositions::from_bytes(signed.as_bytes().to_vec())?;
        record.verify()?;
        assert!(record.content().is_err());
        Ok(())
    }

    #[test]
    fn world_choice_refuses_a_transmit_time_out_of_range() {
        let bad = [candidate(1, PS_PER_MS_FOR_TEST, false, 0)];
        assert!(world_choice(&bad).is_err());
    }

    const PS_PER_MS_FOR_TEST: u32 = 1_000_000_000;

    #[test]
    fn input_sets_depend_on_what_was_used_and_on_nothing_else() -> Result<(), WireError> {
        let even = [0x8d, 1, 2, 3, 0x58, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let odd = [0x8d, 1, 2, 3, 0x58, 0, 4, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(adsb_input_set(&even, &odd), adsb_input_set(&even, &odd));
        assert_ne!(adsb_input_set(&even, &odd), adsb_input_set(&odd, &even));
        let receiver = Identity::generate()?.public();
        let reception = |counter| crate::observation_set::Reception {
            receiver,
            epoch: 0,
            counter,
        };
        let one = ObservationSet::new(even.to_vec(), vec![reception(1), reception(2)])?;
        let same = ObservationSet::new(even.to_vec(), vec![reception(2), reception(1)])?;
        assert_eq!(input_set(&one, &[1; 32]), input_set(&same, &[1; 32]));
        assert_ne!(input_set(&one, &[1; 32]), input_set(&one, &[2; 32]));
        Ok(())
    }
}
