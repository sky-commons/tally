//! The owner's `--precision` (RFC-0171 §8.3): the antenna's position snapped to a grid of the
//! stated size before the feeder signs or sends anything, so the exact position never leaves the
//! host. The relay directory snaps the location it is given (`relays::Directory::new`): the signed
//! site relays are sent (`ReceiverSite`) is the snapped one, and the public cell every description
//! names and every area choice reads are the snapped one's.
//!
//! The grid, for a precision of P metres (0 publishes the position exactly):
//!
//! - **Latitude** is rounded to the nearest multiple of P metres of latitude, measured on a sphere
//!   of the Earth's mean radius (IUGG R1, 6 371 008.8 m, so one degree is 111 195.08 m), counted
//!   from the equator. The step is held in the wire's units (degrees times 10^7) as a whole
//!   number, so this half is integer arithmetic and the same on every host.
//! - **Longitude** is rounded to the nearest multiple of P metres of longitude, counted from the
//!   prime meridian, at the snapped band's equatorward edge, where a degree of longitude is
//!   longest: no point in the band is moved more than P/2 east or west. The step depends only on
//!   the snapped latitude, so every antenna in a cell lands on the same point. Where one step
//!   would span the globe (within P of a pole) the longitude is 0.
//! - Halves round away from zero, and the result is clamped to the globe.
//! - **Altitude** is kept as given: an MLAT engine needs the height, and a height says nothing of
//!   where on the map the antenna is.
//!
//! So the published point is within P/2 of the antenna along each axis, within P·√2/2 (0.71 P)
//! in all, and the precision it carries (`Location::precision_m`, the owner's P) is a true bound.
//! Snapping a snapped location changes nothing.

use tally_wire::Location;

/// Metres in one degree of latitude on the sphere of the Earth's mean radius.
pub const METRES_PER_DEGREE: f64 = 6_371_008.8 * std::f64::consts::PI / 180.0;

const LAT_LIMIT_E7: i64 = 900_000_000;
const LON_LIMIT_E7: i64 = 1_800_000_000;

/// `location` as it is published: snapped to its own precision's grid.
pub fn snap(location: Location) -> Location {
    if location.precision_m == 0 {
        return location;
    }
    let metres = f64::from(location.precision_m);
    // One step of P metres, in degrees times 10^7; at least one unit.
    let lat_step = (metres * 1e7 / METRES_PER_DEGREE).round().max(1.0) as i64;
    let lat = nearest(i64::from(location.lat_e7), lat_step).clamp(-LAT_LIMIT_E7, LAT_LIMIT_E7);
    let edge_e7 = (lat.abs() - lat_step / 2).max(0);
    let metres_per_lon_degree = METRES_PER_DEGREE * (edge_e7 as f64 / 1e7).to_radians().cos();
    let lon_step = (metres * 1e7 / metres_per_lon_degree).round();
    let lon = if lon_step.is_finite() && lon_step < (2 * LON_LIMIT_E7) as f64 {
        nearest(i64::from(location.lon_e7), (lon_step as i64).max(1))
            .clamp(-LON_LIMIT_E7, LON_LIMIT_E7)
    } else {
        0
    };
    Location {
        // Both are within the globe's limits, which fit an i32.
        lat_e7: i32::try_from(lat).unwrap_or(location.lat_e7),
        lon_e7: i32::try_from(lon).unwrap_or(location.lon_e7),
        alt_m: location.alt_m,
        precision_m: location.precision_m,
    }
}

/// The multiple of `step` nearest `value`, halves away from zero.
fn nearest(value: i64, step: i64) -> i64 {
    let magnitude = (value.abs() + step / 2) / step * step;
    if value < 0 { -magnitude } else { magnitude }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(lat: f64, lon: f64, precision_m: u32) -> Location {
        Location {
            lat_e7: (lat * 1e7).round() as i32,
            lon_e7: (lon * 1e7).round() as i32,
            alt_m: 34,
            precision_m,
        }
    }

    /// Great-circle metres between two locations, on the same sphere.
    fn distance(one: &Location, other: &Location) -> f64 {
        let (lat1, lon1) = (
            (f64::from(one.lat_e7) / 1e7).to_radians(),
            (f64::from(one.lon_e7) / 1e7).to_radians(),
        );
        let (lat2, lon2) = (
            (f64::from(other.lat_e7) / 1e7).to_radians(),
            (f64::from(other.lon_e7) / 1e7).to_radians(),
        );
        let a = ((lat2 - lat1) / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * ((lon2 - lon1) / 2.0).sin().powi(2);
        2.0 * 6_371_008.8 * a.sqrt().asin()
    }

    #[test]
    fn precision_zero_publishes_the_position_exactly() {
        let exact = at(33.942_536_1, -118.408_074_9, 0);
        assert_eq!(snap(exact), exact);
    }

    #[test]
    fn a_rounded_position_is_within_its_precision_and_keeps_altitude_and_precision() {
        for precision in [1, 10, 100, 500, 1_000, 5_000, 20_000] {
            for lat in [
                -89.9,
                -60.123_456,
                -33.9,
                -0.000_1,
                0.0,
                12.345_678,
                51.5,
                78.2,
                89.99,
            ] {
                for lon in [
                    -179.999,
                    -118.408_074_9,
                    -0.000_1,
                    0.0,
                    2.35,
                    151.2,
                    179.999,
                ] {
                    let exact = at(lat, lon, precision);
                    let published = snap(exact);
                    let off = distance(&exact, &published);
                    assert!(
                        off <= f64::from(precision) * 0.71 + 0.01,
                        "{lat},{lon} at {precision} m moved {off} m"
                    );
                    assert_eq!(published.alt_m, exact.alt_m);
                    assert_eq!(published.precision_m, precision);
                    assert!(published.check().is_ok());
                }
            }
        }
    }

    #[test]
    fn the_exact_position_is_not_published() {
        let exact = at(33.942_536_1, -118.408_074_9, 1_000);
        let published = snap(exact);
        assert_ne!(
            (published.lat_e7, published.lon_e7),
            (exact.lat_e7, exact.lon_e7)
        );
    }

    #[test]
    fn antennas_in_one_cell_publish_one_point_and_snapping_is_idempotent() {
        // A kilometre's step of latitude is 0.008 993 2 degrees: both of these round to its
        // 3774th multiple, and to the same multiple of the band's longitude step (108 396 units).
        let one = snap(at(33.940_1, -118.408_1, 1_000));
        let other = snap(at(33.942_9, -118.408_3, 1_000));
        assert_eq!(one, other);
        assert_eq!(snap(one), one);
    }

    #[test]
    fn the_grid_is_the_documented_one() {
        // 1000 m of latitude is 89 932 units of 10^-7 degree; 33.942 536 1 / 0.008 993 2 is
        // 3774.24, so the latitude is 3774 steps: 33.940 336 8.
        let published = snap(at(33.942_536_1, -118.408_074_9, 1_000));
        assert_eq!(published.lat_e7, 3774 * 89_932);
        // The band's equatorward edge is 44 966 units south; there a kilometre of longitude is
        // 1e10 / (111 195.08 * cos(33.935 840 2 degrees)) = 108 396 units, and -118.408 074 9
        // is -10 923.66 of them: -10 924 steps.
        let edge = f64::from(3774 * 89_932 - 44_966) / 1e7;
        let step = (1e10 / (METRES_PER_DEGREE * edge.to_radians().cos())).round() as i64;
        assert_eq!(step, 108_396);
        assert_eq!(i64::from(published.lon_e7), -10_924 * step);
    }

    #[test]
    fn near_a_pole_the_grid_holds_and_a_globe_sized_cell_drops_the_longitude() {
        let exact = at(89.999, 45.0, 50_000);
        let published = snap(exact);
        assert!(published.check().is_ok());
        assert!(distance(&exact, &published) <= 50_000.0 * 0.71);
        let huge = snap(at(-12.0, 170.0, u32::MAX));
        assert_eq!(huge.lon_e7, 0);
        assert!(huge.check().is_ok());
    }
}
