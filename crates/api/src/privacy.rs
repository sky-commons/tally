//! THE ONE READ OF A RECEIVER'S PLACE FOR ANYTHING THE API PUBLISHES: `public_location`.
//!
//! A receiver signs its exact place into its description, because MLAT needs it, and the relays
//! carry it exactly in that signed record (RFC-0171 §3.5, §8.3). What the API serves to anyone who
//! asks is a different thing: a pin about 5 km from the receiver, never the place itself. Every
//! peer does the same (wiedehopf's mlat-server snaps its public pin to a 0.05 degree grid and
//! moves it within the cell, `coordinator.py`; FlightAware shows a random place; FR24 keeps it
//! server side).
//!
//! The API takes a station's place in at one door (`snapshot::Stations::from_report`), through
//! this function, and holds nothing finer: the station answer and the feeder figures (area, range)
//! read the pin it returns, so no public answer can carry the exact coordinates, and anyone who
//! reads the same public records computes the same figures from the same pin.
//!
//! The blur is deterministic, never fresh noise per read: averaging many noisy reads of one place
//! would recover it. The world is cut into cells 0.05 degrees of latitude tall (about 5.6 km) and
//! as wide in kilometres where they lie (their longitude step grows toward the poles); a receiver
//! is pinned inside its own cell at an offset its key fixes, so receivers of one cell do not stack
//! on one pin. The key is public, so the offset can be undone, and what remains is the cell: the
//! blur is the cell's size, about 5 km, and no finer.

use tally_api_types::Position;
use tally_relay::stations::StationReport;
use tally_wire::PublicKey;

/// The cell's height, degrees of latitude: about 5.6 km, mlat-server's public grid (precision 20).
pub const CELL_DEG: f64 = 0.05;

/// How far into its cell from the centre a pin may sit, as a share of the cell: inside it always.
const OFFSET_SHARE: f64 = 0.35;

/// The pin's digits: 1e-4 degrees, about 11 m, far finer than the cell and coarser than a
/// receiver's own place.
const DIGITS: f64 = 1e4;

/// Where the API may say `key`'s receiver is: its declared place blurred to about 5 km
/// (`blurred`), or `None` when it declares none. Every receiver place the API publishes, or
/// computes a published figure from, is this; the network's rule for every relay that publishes
/// places is `docs/relay-operators.md`.
pub fn public_location(key: &PublicKey, report: &StationReport) -> Option<Position> {
    let place = report.location?;
    Some(blurred(key, place.lat, place.lon))
}

/// `lat`, `lon` pinned inside their cell at the offset `key` fixes.
fn blurred(key: &PublicKey, lat: f64, lon: f64) -> Position {
    let lat = lat.clamp(-90.0, 90.0);
    let rows = (180.0 / CELL_DEG).round();
    let row = ((lat + 90.0) / CELL_DEG).floor().min(rows - 1.0);
    let centre_lat = -90.0 + (row + 0.5) * CELL_DEG;
    // As wide in kilometres as it is tall, up to one cell round the whole parallel at a pole.
    let columns = (360.0 * centre_lat.to_radians().cos() / CELL_DEG)
        .floor()
        .max(1.0);
    let width = 360.0 / columns;
    let column = ((lon + 180.0).rem_euclid(360.0) / width)
        .floor()
        .min(columns - 1.0);
    let centre_lon = -180.0 + (column + 0.5) * width;
    let (north, east) = offsets(key);
    Position {
        lat: rounded(centre_lat + north * OFFSET_SHARE * CELL_DEG),
        lon: rounded(centre_lon + east * OFFSET_SHARE * width),
    }
}

/// Two shares in [-1, 1] that `key` fixes: an Ed25519 key's bytes are as good as random.
fn offsets(key: &PublicKey) -> (f64, f64) {
    let bytes = key.as_bytes();
    let share = |high: u8, low: u8| f64::from(u16::from_be_bytes([high, low])) / 32_767.5 - 1.0;
    (share(bytes[0], bytes[1]), share(bytes[2], bytes[3]))
}

fn rounded(degrees: f64) -> f64 {
    (degrees * DIGITS).round() / DIGITS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_relay::stations::StationLocation;
    use tally_wire::Identity;

    fn located(key: &PublicKey, lat: f64, lon: f64) -> StationReport {
        StationReport {
            key: key.to_base64(),
            online: true,
            connected: true,
            connected_since_ms: Some(0),
            sessions: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
            batches: 1,
            gaps: 0,
            observations: 1,
            location: Some(StationLocation {
                lat,
                lon,
                alt_m: 12,
                precision_m: 0,
            }),
            software: None,
            address: None,
        }
    }

    /// Distance in kilometres, flat over a few kilometres.
    fn km(a: (f64, f64), b: (f64, f64)) -> f64 {
        let north = (a.0 - b.0) * 111.2;
        let east = (a.1 - b.1) * 111.2 * a.0.to_radians().cos();
        north.hypot(east)
    }

    /// The pin is never the place, is within about 5 km of it (inside its cell), is the same on
    /// every read, and differs between two receivers of one cell.
    #[test]
    fn the_pin_is_near_the_place_never_on_it_and_the_same_every_read() -> Result<(), String> {
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
            let report = located(&key, lat, lon);
            let pin = public_location(&key, &report).ok_or("no pin")?;
            assert_eq!(public_location(&key, &report), Some(pin), "deterministic");
            assert!(pin.lat != lat && pin.lon != lon, "{pin:?} is the place");
            let off = km((lat, lon), (pin.lat, pin.lon));
            // Inside a cell of 5.6 km a side: at most its diagonal from any point in it.
            assert!(off < 8.0, "{off} km");
            pins.push(pin);
        }
        assert_ne!(pins[0], pins[1], "two receivers of one cell share a pin");
        Ok(())
    }

    /// Moving a receiver a few metres inside its cell moves its pin not at all: the pin says the
    /// cell, never where in it.
    #[test]
    fn the_pin_says_the_cell_and_nothing_finer() -> Result<(), String> {
        let key = Identity::from_seed([8; 32]).public();
        let pin = |lat, lon| public_location(&key, &located(&key, lat, lon));
        assert_eq!(pin(37.511, -122.251), pin(37.519, -122.259));
        Ok(())
    }

    #[test]
    fn no_place_declared_is_no_pin() -> Result<(), String> {
        let key = Identity::from_seed([9; 32]).public();
        let mut report = located(&key, 1.0, 2.0);
        report.location = None;
        assert_eq!(public_location(&key, &report), None);
        Ok(())
    }
}
