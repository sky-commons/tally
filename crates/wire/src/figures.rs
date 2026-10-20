//! Feeder figures (RFC-0174 §2.12, founder decision 2026-10-19): what a relay computes of the
//! receivers it hosts or carries, signed as its own claim, for any client to read and serve.
//!
//! Only a relay holds what the figures are computed from (receivers' raw batches and the raw
//! positions citing their receptions are relay-only, wire version 3), so a relay computes them and
//! a client reads them. They carry nothing a site can be read or derived from: each receiver's
//! public cell (as its own format 2 description names it), counts, areas in square kilometres
//! of coverage cells no finer than the public cell, and a range measured from the centre of the
//! public cell, never from the site. No counter, no reception, no coordinate.
//!
//! ```text
//! format u8 = 1 | relay key [32] | issued_ms u64 | window_for_ms u64 | area u64 | count u16
//! | count x (receiver key [32] | public cell u64, 0 for none | uptime ‰ u16 | messages u64
//!            | aircraft u32 | range_m u32, u32::MAX for none | coverage 0.1 km² u32
//!            | unique coverage 0.1 km² u32 | mlat positions u64 | standing u8)
//! | signature [64]
//! ```
//!
//! One record is one area's (`rendezvous::area_of_public`: the public cell's parent at
//! `rendezvous::AREA_RESOLUTION`, the one rule a relay groups, routes and publishes by), its
//! receivers strictly ascending by key, so a relay routes it as it routes the area's other
//! products.
//!
//! Figures are of whole hours ([`FIGURES_BUCKET_MS`]): issued at an hour's start, over the whole
//! hours before it (at most [`FIGURES_WINDOW_MS`]), so the finest series a client can difference
//! out of two records is an hour's, never a minute's. A record that is not is refused.

use crate::WireError;

/// The one bucket feeder figures are counted and published in: an hour.
pub const FIGURES_BUCKET_MS: u64 = 3_600_000;
/// The most a record covers: the 24 whole hours before it was issued.
pub const FIGURES_WINDOW_MS: u64 = 24 * FIGURES_BUCKET_MS;
use crate::key::{KEY_LEN, PublicKey};
use crate::record::{Body, MAX_BODY};
use crate::region::Region;
use crate::signed::{Check, Checked, Fields, Unchecked, count_u16, read_count, signed_record};

/// One receiver's figures over the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeederFigure {
    pub receiver: PublicKey,
    /// Its public cell (`site::PUBLIC_CELL_RESOLUTION`), as its own description names it; `None`
    /// for one that names none.
    pub cell: Option<Region>,
    /// The share of the window's minutes in which a batch of it was published, in thousandths.
    pub uptime_permille: u16,
    /// Receptions in its batches over the window.
    pub messages: u64,
    /// Distinct aircraft whose address it heard in a checked format.
    pub aircraft: u32,
    /// The farthest positioned aircraft it heard, metres from its public cell's centre.
    pub range_m: Option<u32>,
    /// The coverage cells it heard positioned aircraft in, tenths of a square kilometre.
    pub coverage_dkm2: u32,
    /// The part of `coverage_dkm2` no other receiver the relay holds heard.
    pub unique_coverage_dkm2: u32,
    /// Distinct final MLAT positions citing one of its receptions.
    pub mlat_positions: u64,
    /// Whether its receptions have standing by the relay's own ledger.
    pub standing: bool,
}

/// What a relay signs of one area's receivers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeederFiguresContent {
    pub issued_ms: u64,
    /// The span the figures cover, ending at `issued_ms`.
    pub window_for_ms: u64,
    /// The area (`rendezvous::AREA_RESOLUTION`) its receivers' public cells lie in; `None` for
    /// the receivers that name no public cell, which no area holds.
    pub area: Option<Region>,
    pub feeders: Vec<FeederFigure>,
}

/// One figure's bytes.
const FIGURE_LEN: usize = KEY_LEN + 8 + 2 + 8 + 4 + 4 + 4 + 4 + 8 + 1;
/// Every byte of a record but its figures, signature included.
const FIXED_LEN: usize = 1 + KEY_LEN + 8 + 8 + 8 + 2 + 64;
/// The most receivers one record holds: what fits one record.
pub const MAX_FEEDER_FIGURES: usize = (MAX_BODY - FIXED_LEN) / FIGURE_LEN;
/// A range written as this is none.
const NO_RANGE: u32 = u32::MAX;

impl Check for FeederFiguresContent {
    /// An area of the area resolution; each cell of exactly the public resolution, every
    /// receiver with a cell in a record with an area and every one without in a record without;
    /// an uptime no more than whole; unique coverage within coverage; receivers strictly
    /// ascending, at most `MAX_FEEDER_FIGURES` of them.
    fn check(&self) -> Result<(), WireError> {
        if !self.issued_ms.is_multiple_of(FIGURES_BUCKET_MS)
            || !self.window_for_ms.is_multiple_of(FIGURES_BUCKET_MS)
            || self.window_for_ms > FIGURES_WINDOW_MS
        {
            return Err(WireError::Invalid {
                field: "figures window (whole hours, at most a day)",
                value: self.window_for_ms,
            });
        }
        if let Some(area) = self.area
            && area.resolution() != crate::rendezvous::AREA_RESOLUTION
        {
            return Err(WireError::Invalid {
                field: "figures area resolution",
                value: u64::from(area.resolution()),
            });
        }
        if self.feeders.len() > MAX_FEEDER_FIGURES {
            return Err(WireError::Oversize(self.feeders.len()));
        }
        for figure in &self.feeders {
            if figure.cell.is_some() != self.area.is_some() {
                return Err(WireError::Invalid {
                    field: "figures cell without an area",
                    value: u64::from(figure.cell.is_some()),
                });
            }
            if let Some(cell) = figure.cell
                && cell.resolution() != crate::site::PUBLIC_CELL_RESOLUTION
            {
                return Err(WireError::Invalid {
                    field: "figures public cell resolution",
                    value: u64::from(cell.resolution()),
                });
            }
            // Each receiver in its public cell's parent's record, the one area rule.
            if let Some(cell) = figure.cell
                && crate::rendezvous::area_of_public(cell) != self.area
            {
                return Err(WireError::Invalid {
                    field: "figures cell outside its area",
                    value: cell.as_u64(),
                });
            }
            if figure.uptime_permille > 1000 {
                return Err(WireError::Invalid {
                    field: "figures uptime",
                    value: u64::from(figure.uptime_permille),
                });
            }
            if figure.unique_coverage_dkm2 > figure.coverage_dkm2 {
                return Err(WireError::Invalid {
                    field: "figures unique coverage",
                    value: u64::from(figure.unique_coverage_dkm2),
                });
            }
            if figure.range_m == Some(NO_RANGE) {
                return Err(WireError::Invalid {
                    field: "figures range",
                    value: u64::from(NO_RANGE),
                });
            }
        }
        let keys: Vec<[u8; 32]> = self
            .feeders
            .iter()
            .map(|figure| *figure.receiver.as_bytes())
            .collect();
        crate::positions::ascending(&keys, "figures receiver order")
    }
}

impl Fields for FeederFiguresContent {
    fn write(figures: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&figures.issued_ms.to_be_bytes());
        out.extend_from_slice(&figures.window_for_ms.to_be_bytes());
        out.extend_from_slice(&figures.area.map_or(0, Region::as_u64).to_be_bytes());
        count_u16(out, figures.feeders.len(), MAX_FEEDER_FIGURES)?;
        for figure in &figures.feeders {
            out.extend_from_slice(figure.receiver.as_bytes());
            out.extend_from_slice(&figure.cell.map_or(0, Region::as_u64).to_be_bytes());
            out.extend_from_slice(&figure.uptime_permille.to_be_bytes());
            out.extend_from_slice(&figure.messages.to_be_bytes());
            out.extend_from_slice(&figure.aircraft.to_be_bytes());
            out.extend_from_slice(&figure.range_m.unwrap_or(NO_RANGE).to_be_bytes());
            out.extend_from_slice(&figure.coverage_dkm2.to_be_bytes());
            out.extend_from_slice(&figure.unique_coverage_dkm2.to_be_bytes());
            out.extend_from_slice(&figure.mlat_positions.to_be_bytes());
            out.push(u8::from(figure.standing));
        }
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let issued_ms = reader.u64()?;
        let window_for_ms = reader.u64()?;
        let area = match reader.u64()? {
            0 => None,
            area => Some(Region::from_u64(area)?),
        };
        let count = read_count(reader, MAX_FEEDER_FIGURES)?;
        let feeders = (0..count)
            .map(|_| {
                let receiver = PublicKey::from_slice(reader.bytes(KEY_LEN)?)?;
                let cell = match reader.u64()? {
                    0 => None,
                    cell => Some(Region::from_u64(cell)?),
                };
                let uptime_permille = reader.u16()?;
                let messages = reader.u64()?;
                let aircraft = reader.u32()?;
                let range_m = Some(reader.u32()?).filter(|range| *range != NO_RANGE);
                let coverage_dkm2 = reader.u32()?;
                let unique_coverage_dkm2 = reader.u32()?;
                let mlat_positions = reader.u64()?;
                let standing = match reader.u8()? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(WireError::Invalid {
                            field: "figures standing",
                            value: u64::from(other),
                        });
                    }
                };
                Ok(FeederFigure {
                    receiver,
                    cell,
                    uptime_permille,
                    messages,
                    aircraft,
                    range_m,
                    coverage_dkm2,
                    unique_coverage_dkm2,
                    mlat_positions,
                    standing,
                })
            })
            .collect::<Result<_, WireError>>()?;
        Ok(Unchecked::new(Self {
            issued_ms,
            window_for_ms,
            area,
            feeders,
        }))
    }
}

signed_record!(
    /// A relay's signed `FeederFiguresContent`: its own claim of what its receivers gave.
    FeederFigures,
    FeederFiguresContent,
    b"tally feeder figures",
    1,
    MAX_BODY
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identity, Location, Record};

    fn location() -> Location {
        Location {
            lat_e7: 337_490_123,
            lon_e7: -843_880_456,
            alt_m: 321,
            precision_m: 0,
        }
    }

    fn figure(seed: u8, cell: Option<Region>) -> FeederFigure {
        FeederFigure {
            receiver: Identity::from_seed([seed; 32]).public(),
            cell,
            uptime_permille: 875,
            messages: 1_234_567,
            aircraft: 42,
            range_m: Some(250_000),
            coverage_dkm2: 12_500,
            unique_coverage_dkm2: 2_500,
            mlat_positions: 99,
            standing: true,
        }
    }

    fn content(feeders: Vec<FeederFigure>) -> Result<FeederFiguresContent, WireError> {
        let mut feeders = feeders;
        feeders.sort_by_key(|figure| *figure.receiver.as_bytes());
        let area = feeders
            .first()
            .and_then(|figure| figure.cell)
            .and_then(crate::rendezvous::area_of_public);
        Ok(FeederFiguresContent {
            issued_ms: 472_222 * FIGURES_BUCKET_MS,
            window_for_ms: 86_400_000,
            area,
            feeders,
        })
    }

    /// A record round-trips through its kind, as a client reads it too, and holds no byte of the
    /// site it was computed beside: no coordinate, no altitude.
    #[test]
    fn figures_round_trip_and_carry_no_site() -> Result<(), WireError> {
        let relay = Identity::from_seed([7; 32]);
        let cell = Region::public_cell(&location())?;
        let signed = FeederFigures::sign(
            &relay,
            &content(vec![figure(1, Some(cell)), figure(3, Some(cell))])?,
        )?;
        signed.verify()?;
        assert_eq!(signed.signer()?, relay.public());
        assert_eq!(
            signed.content()?,
            content(vec![figure(1, Some(cell)), figure(3, Some(cell))])?
        );
        // The receivers that name no cell: a record of no area.
        let mut none = figure(2, None);
        none.range_m = None;
        let unplaced = FeederFigures::sign(&relay, &content(vec![none])?)?;
        assert_eq!(unplaced.content()?.area, None);
        let record = Record::FeederFigures(signed.clone());
        assert!(!record.carries_site());
        let mut bytes = Vec::new();
        record.encode(&mut bytes)?;
        assert_eq!(Record::decode(&bytes)?, (Some(record.clone()), bytes.len()));
        let client = crate::ClientRecord::try_from(record).map_err(|_| WireError::Invalid {
            field: "a client form",
            value: 0,
        })?;
        let mut sent = Vec::new();
        client.encode(&mut sent)?;
        assert_eq!(sent, bytes);
        let site = location();
        for canary in [
            site.lat_e7.to_be_bytes(),
            site.lon_e7.to_be_bytes(),
            site.alt_m.to_be_bytes(),
        ] {
            assert!(!bytes.windows(4).any(|window| window == canary));
        }
        Ok(())
    }

    /// What would say more than the record may is refused: a cell finer than public, an area of
    /// another resolution, receivers out of order, more unique coverage than coverage.
    #[test]
    fn figures_that_say_too_much_or_disagree_are_refused() -> Result<(), WireError> {
        let relay = Identity::from_seed([7; 32]);
        let fine = Region::point(&location())?;
        assert!(FeederFigures::sign(&relay, &content(vec![figure(1, Some(fine))])?).is_err());
        let cell = Region::public_cell(&location())?;
        let mut wide = content(vec![figure(1, Some(cell))])?;
        wide.area = Some(cell);
        assert!(FeederFigures::sign(&relay, &wide).is_err());
        // A cell in a record of no area, or none in a record of one.
        let mut unplaced = content(vec![figure(1, Some(cell))])?;
        unplaced.area = None;
        assert!(FeederFigures::sign(&relay, &unplaced).is_err());
        let mut placed = content(vec![figure(1, None)])?;
        placed.area = crate::rendezvous::area_of_public(cell);
        assert!(FeederFigures::sign(&relay, &placed).is_err());
        let mut unordered = content(vec![figure(1, None), figure(2, None)])?;
        unordered.feeders.reverse();
        assert!(FeederFigures::sign(&relay, &unordered).is_err());
        // A receiver in an area other than its public cell's parent, as a record would put it
        // that placed it by the area its cell's centre (or its site) lies in.
        let mut elsewhere = content(vec![figure(1, Some(cell))])?;
        elsewhere.area = Some(crate::rendezvous::area_of(&Location {
            lat_e7: location().lat_e7 + 20_000_000,
            ..location()
        })?);
        assert!(FeederFigures::sign(&relay, &elsewhere).is_err());
        // Anything but whole hours, ending at an hour, at most a day: a client could difference a
        // finer series out of two.
        for (issued_ms, window_for_ms) in [
            (472_222 * FIGURES_BUCKET_MS + 60_000, 23 * FIGURES_BUCKET_MS),
            (472_222 * FIGURES_BUCKET_MS, 23 * FIGURES_BUCKET_MS + 60_000),
            (
                472_222 * FIGURES_BUCKET_MS,
                FIGURES_WINDOW_MS + FIGURES_BUCKET_MS,
            ),
        ] {
            let unaligned = FeederFiguresContent {
                issued_ms,
                window_for_ms,
                ..content(vec![figure(1, Some(cell))])?
            };
            assert!(FeederFigures::sign(&relay, &unaligned).is_err());
        }
        let mut more = figure(1, None);
        more.unique_coverage_dkm2 = more.coverage_dkm2 + 1;
        assert!(FeederFigures::sign(&relay, &content(vec![more])?).is_err());
        let full: Vec<FeederFigure> = (0..=MAX_FEEDER_FIGURES)
            .map(|n| {
                let mut one = figure(1, None);
                let mut seed = [9; 32];
                seed[0] = (n % 251) as u8;
                seed[1] = (n / 251) as u8;
                one.receiver = Identity::from_seed(seed).public();
                one
            })
            .collect();
        assert!(FeederFigures::sign(&relay, &content(full.clone())?).is_err());
        assert!(
            FeederFigures::sign(&relay, &content(full[..MAX_FEEDER_FIGURES].to_vec())?).is_ok()
        );
        Ok(())
    }
}
