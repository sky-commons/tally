//! THE ONE READ OF A RECEIVER'S PLACE FOR ANYTHING THE API PUBLISHES: `public_location`.
//!
//! A receiver's exact site is relay-only (RFC-0171 §3.5, wire version 3): it travels in its
//! `ReceiverSite`, only between relays, and never reaches the API, which is a client. What a relay
//! tells the API of a station is its public cell (`StationReport::cell`: the H3 cell of resolution
//! 6, about 36 km², that the antenna is in, which its owner signed into its description), never a
//! coordinate and never an altitude. The protocol's cells are the one grid: the API pins on the
//! same cell, so no second grid can be crossed with it to narrow a site.
//!
//! The API takes a station's place in at one door (`snapshot::Stations::from_report`), through
//! this function, and holds nothing finer: the station answer and the feeder figures (area, range)
//! read the pin it returns, so anyone who reads the same public records computes the same figures
//! from the same pin.
//!
//! The pin is deterministic, never fresh noise per read. It sits inside its cell, between the
//! cell's centre and one of its corners, at a share of the way its key fixes, so receivers of one
//! cell do not stack on one pin. The key is public, so the offset can be undone, and what remains
//! is the cell: the pin says the public cell and nothing finer.

use h3o::{CellIndex, LatLng};
use tally_api_types::Position;
use tally_relay::stations::StationReport;
use tally_wire::PublicKey;

/// How far from the cell's centre toward its chosen corner a pin may sit, as a share of that
/// distance: inside the cell always (a hexagon is convex).
const OFFSET_SHARE: f64 = 0.6;

/// The pin's digits: 1e-4 degrees, about 11 m, far finer than the cell.
const DIGITS: f64 = 1e4;

/// Where the API may say `key`'s receiver is: a pin inside its public cell (`pinned`), or `None`
/// when it states no cell, or one the API cannot read. Every receiver place the API publishes, or
/// computes a published figure from, is this; the network's rule for every relay that publishes
/// places is `docs/relay-operators.md`.
pub fn public_location(key: &PublicKey, report: &StationReport) -> Option<Position> {
    let cell = u64::from_str_radix(report.cell.as_deref()?, 16).ok()?;
    let cell = CellIndex::try_from(cell).ok()?;
    Some(pinned(key, cell))
}

/// The pin of `key` in `cell`: from its centre toward the corner the key picks, the share of the
/// way the key fixes.
fn pinned(key: &PublicKey, cell: CellIndex) -> Position {
    let centre = LatLng::from(cell);
    let corners: Vec<LatLng> = cell.boundary().iter().copied().collect();
    let bytes = key.as_bytes();
    let (lat, lon) = (centre.lat(), centre.lng());
    let Some(corner) = corners
        .get(usize::from(bytes[0]) % corners.len().max(1))
        .copied()
    else {
        return Position {
            lat: rounded(lat),
            lon: rounded(lon),
        };
    };
    let share = f64::from(u16::from_be_bytes([bytes[1], bytes[2]])) / 65_535.0 * OFFSET_SHARE;
    // A cell never spans the antimeridian by more than its own width: the shorter way round.
    let mut east = corner.lng() - lon;
    if east > 180.0 {
        east -= 360.0;
    } else if east < -180.0 {
        east += 360.0;
    }
    let pin_lon = lon + share * east;
    Position {
        lat: rounded(lat + share * (corner.lat() - lat)),
        lon: rounded(if pin_lon > 180.0 {
            pin_lon - 360.0
        } else if pin_lon < -180.0 {
            pin_lon + 360.0
        } else {
            pin_lon
        }),
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
    fn located(key: &PublicKey, lat: f64, lon: f64) -> Result<StationReport, String> {
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

    /// The pin is inside the station's public cell (the protocol's grid, the only one), the same
    /// on every read, and differs between two receivers of one cell.
    #[test]
    fn the_pin_is_inside_the_public_cell_and_the_same_every_read() -> Result<(), String> {
        let mut pins = Vec::new();
        for (seed, (lat, lon)) in [
            (1, (37.512_345_6, -122.251_234_5)),
            (2, (37.512_345_6, -122.251_234_5)),
            (3, (51.477_928_1, -0.001_545_3)),
            (4, (-33.868_820_1, 151.209_295_5)),
            (5, (64.135_482_3, -21.895_411_1)),
            (6, (0.000_000_1, 179.999_999_9)),
        ] {
            let key = Identity::from_seed([seed; 32]).public();
            let report = located(&key, lat, lon)?;
            let pin = public_location(&key, &report).ok_or("no pin")?;
            assert_eq!(public_location(&key, &report), Some(pin), "deterministic");
            let cell = Region::public_cell(&location(lat, lon)).map_err(|e| e.to_string())?;
            let pinned =
                Region::public_cell(&location(pin.lat, pin.lon)).map_err(|e| e.to_string())?;
            assert_eq!(pinned, cell, "{pin:?} left its cell");
            pins.push(pin);
        }
        assert_ne!(pins[0], pins[1], "two receivers of one cell share a pin");
        Ok(())
    }

    /// Two places of one public cell pin alike: the pin says the cell, never where in it.
    #[test]
    fn the_pin_says_the_cell_and_nothing_finer() -> Result<(), String> {
        let key = Identity::from_seed([8; 32]).public();
        let a = location(37.511, -122.251);
        let cell = Region::public_cell(&a).map_err(|e| e.to_string())?;
        // Another point of the same cell: its centre.
        let centre = LatLng::from(CellIndex::try_from(cell.as_u64()).map_err(|e| e.to_string())?);
        let b = located(&key, centre.lat(), centre.lng())?;
        let a = located(&key, 37.511, -122.251)?;
        assert_eq!(a.cell, b.cell);
        assert_eq!(public_location(&key, &a), public_location(&key, &b));
        Ok(())
    }

    #[test]
    fn no_cell_stated_is_no_pin() -> Result<(), String> {
        let key = Identity::from_seed([9; 32]).public();
        let mut report = located(&key, 1.0, 2.0)?;
        report.cell = None;
        assert_eq!(public_location(&key, &report), None);
        report.cell = Some("not a cell".to_owned());
        assert_eq!(public_location(&key, &report), None);
        Ok(())
    }
}
