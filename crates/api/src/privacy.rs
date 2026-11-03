//! THE ONE READ OF A RECEIVER'S PLACE FOR ANYTHING THE API PUBLISHES: `public_place`.
//!
//! A receiver's exact site is relay-only (RFC-0171 §3.5, wire version 3): it travels in its
//! `ReceiverSite`, only between relays, and never reaches the API, which is a client. What a relay
//! tells the API of a station is its public cell (`StationReport::cell`: the H3 cell of resolution
//! 6, about 36 km² and about 6 km across, that the antenna is in, which its owner signed into its
//! description), never a coordinate and never an altitude. The protocol's cells are the one grid:
//! the API places a station by the same cell, so no second grid can be crossed with it to narrow a
//! site.
//!
//! The API takes a station's place in at one door (`snapshot::Stations::from_report`), through
//! this function, and holds nothing finer: the station answer and the feeder figures (area, range)
//! read the place it returns, so anyone who reads the same public records computes the same figures
//! from the same place.
//!
//! The place is the cell and its centre, the centre rounded to [`DIGITS`] (0.01°, about 1 km): a
//! figure that reads as coarse as it is. Every receiver of one cell is answered the same place,
//! and nothing about where in the cell the antenna is can be read from it.

use h3o::{CellIndex, LatLng};
use tally_api_types::Position;
use tally_relay::stations::StationReport;

/// The digits of a public place: 1e-2 degrees, about 1.1 km, coarser than any coordinate could
/// pass for an antenna's and finer than the cell (about 6 km across), so the rounded centre is
/// still inside it.
pub const DIGITS: f64 = 1e2;

/// A station's public place: its public cell (H3 resolution 6, as hex) and that cell's centre,
/// rounded to [`DIGITS`].
#[derive(Clone, Debug, PartialEq)]
pub struct PublicPlace {
    pub cell: String,
    pub centre: Position,
}

/// Where the API may say a receiver is: its public cell and the cell's rounded centre, or `None`
/// when its report states no cell, or one the API cannot read. Every receiver place the API
/// publishes, or computes a published figure from, is this; the network's rule for every relay
/// that publishes places is `docs/relay-operators.md`.
pub fn public_place(report: &StationReport) -> Option<PublicPlace> {
    let cell = u64::from_str_radix(report.cell.as_deref()?, 16).ok()?;
    let cell = CellIndex::try_from(cell).ok()?;
    if cell.resolution() != h3o::Resolution::Six {
        // A relay names only resolution 6; anything else is not a public cell, so no place.
        return None;
    }
    Some(PublicPlace {
        cell: format!("{:x}", u64::from(cell)),
        centre: centre(cell),
    })
}

/// `cell`'s centre, rounded to [`DIGITS`].
pub fn centre(cell: CellIndex) -> Position {
    let centre = LatLng::from(cell);
    Position {
        lat: rounded(centre.lat()),
        lon: rounded(centre.lng()),
    }
}

fn rounded(degrees: f64) -> f64 {
    (degrees * DIGITS).round() / DIGITS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_relay::stations::cell_name;
    use tally_wire::{Identity, Location, Region};

    fn location(lat: f64, lon: f64) -> Location {
        Location {
            lat_e7: (lat * 1e7) as i32,
            lon_e7: (lon * 1e7) as i32,
            alt_m: 1_234,
            precision_m: 0,
        }
    }

    /// A relay's report of a station at `lat`, `lon`: its public cell, as the relay names it.
    fn located(lat: f64, lon: f64) -> Result<StationReport, String> {
        let key = Identity::from_seed([3; 32]).public();
        let cell = Region::public_cell(&location(lat, lon)).map_err(|e| e.to_string())?;
        Ok(StationReport {
            key: key.to_base64(),
            online: true,
            connected: true,
            connected_since_ms: Some(0),
            sessions: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
            batches: 1,
            gaps: 0,
            late_batches: 0,
            observations: 1,
            cell: Some(cell_name(cell)),
            software: None,
            address: None,
        })
    }

    fn cell_of(lat: f64, lon: f64) -> Result<String, String> {
        Region::public_cell(&location(lat, lon))
            .map(cell_name)
            .map_err(|e| e.to_string())
    }

    /// No more digits than [`DIGITS`]: the place reads as coarse as it is.
    fn coarse(degrees: f64) -> bool {
        ((degrees * DIGITS).round() / DIGITS - degrees).abs() < 1e-9
    }

    /// The place is the public cell and its rounded centre, which is inside the cell, on every
    /// read, the same for every antenna in the cell.
    #[test]
    fn the_place_is_the_cell_and_its_rounded_centre() -> Result<(), String> {
        for (lat, lon) in [
            (37.512_345_6, -122.251_234_5),
            (51.477_928_1, -0.001_545_3),
            (-33.868_820_1, 151.209_295_5),
            (64.135_482_3, -21.895_411_1),
            (0.000_000_1, 179.999_999_9),
            (78.223_3, 15.646_7),
            (-77.846_3, 166.668_2),
        ] {
            let place = public_place(&located(lat, lon)?).ok_or("no place")?;
            assert_eq!(place.cell, cell_of(lat, lon)?);
            assert!(
                coarse(place.centre.lat) && coarse(place.centre.lon),
                "{place:?}"
            );
            assert_eq!(
                cell_of(place.centre.lat, place.centre.lon)?,
                place.cell,
                "{place:?} left its cell"
            );
            // Another antenna of the same cell, its very centre: the same place.
            let cell = CellIndex::try_from(
                u64::from_str_radix(&place.cell, 16).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let middle = LatLng::from(cell);
            assert_eq!(
                public_place(&located(middle.lat(), middle.lng())?),
                Some(place)
            );
        }
        Ok(())
    }

    /// Every resolution 6 cell of a broad sweep of the globe: its rounded centre stays inside it.
    #[test]
    fn a_rounded_centre_never_leaves_its_cell() -> Result<(), String> {
        let mut checked = 0;
        for lat in (-890..=890).step_by(7) {
            for lon in (-1795..=1795).step_by(11) {
                let (lat, lon) = (f64::from(lat) / 10.0, f64::from(lon) / 10.0);
                let cell = Region::public_cell(&location(lat, lon)).map_err(|e| e.to_string())?;
                let cell = CellIndex::try_from(cell.as_u64()).map_err(|e| e.to_string())?;
                let at = centre(cell);
                assert_eq!(
                    cell_of(at.lat, at.lon)?,
                    format!("{:x}", u64::from(cell)),
                    "{at:?}"
                );
                checked += 1;
            }
        }
        assert!(checked > 50_000);
        Ok(())
    }

    #[test]
    fn no_cell_stated_is_no_place() -> Result<(), String> {
        let mut report = located(1.0, 2.0)?;
        report.cell = None;
        assert_eq!(public_place(&report), None);
        report.cell = Some("not a cell".to_owned());
        assert_eq!(public_place(&report), None);
        // A finer cell than the public one is no public cell: no place.
        let fine = h3o::LatLng::new(1.0, 2.0)
            .map_err(|e| e.to_string())?
            .to_cell(h3o::Resolution::Nine);
        report.cell = Some(format!("{fine:x}"));
        assert_eq!(public_place(&report), None);
        Ok(())
    }
}
