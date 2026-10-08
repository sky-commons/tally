//! WGS84 (NIMA TR8350.2): geodetic latitude, longitude and ellipsoidal height to and from
//! Earth-centred Earth-fixed metres, and the local east, north, up basis. The transcendental
//! functions are `libm`'s, pure Rust: the platform's own differ in the last bit between x86 and
//! ARM, and a published model is bytes, so every engine must compute them alike.

use crate::linalg::Vec3;

/// The semi-major axis, metres.
pub const A: f64 = 6_378_137.0;
/// The flattening.
pub const F: f64 = 1.0 / 298.257_223_563;
/// The first eccentricity squared.
pub const E2: f64 = F * (2.0 - F);
/// The speed of light, metres per second (exact by definition of the metre).
pub const C: f64 = 299_792_458.0;

/// A geodetic position: degrees, degrees, metres above the WGS84 ellipsoid.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Geodetic {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub height_m: f64,
}

pub fn to_ecef(position: Geodetic) -> Vec3 {
    let lat = position.lat_deg.to_radians();
    let lon = position.lon_deg.to_radians();
    let (sin_lat, cos_lat) = libm::sincos(lat);
    let (sin_lon, cos_lon) = libm::sincos(lon);
    let n = A / (1.0 - E2 * sin_lat * sin_lat).sqrt();
    [
        (n + position.height_m) * cos_lat * cos_lon,
        (n + position.height_m) * cos_lat * sin_lon,
        (n * (1.0 - E2) + position.height_m) * sin_lat,
    ]
}

/// ECEF to geodetic by Bowring's iteration, a fixed six rounds (converged to well under a
/// millimetre anywhere an aircraft can be).
pub fn from_ecef(ecef: Vec3) -> Geodetic {
    let [x, y, z] = ecef;
    let lon = libm::atan2(y, x);
    let p = libm::hypot(x, y);
    let mut lat = libm::atan2(z, p * (1.0 - E2));
    let mut height = 0.0;
    for _ in 0..6 {
        let (sin_lat, cos_lat) = libm::sincos(lat);
        let n = A / (1.0 - E2 * sin_lat * sin_lat).sqrt();
        height = if cos_lat.abs() > 1e-9 {
            p / cos_lat - n
        } else {
            z.abs() / sin_lat.abs() - n * (1.0 - E2)
        };
        lat = libm::atan2(z, p * (1.0 - E2 * n / (n + height)));
    }
    Geodetic {
        lat_deg: lat.to_degrees(),
        lon_deg: lon.to_degrees(),
        height_m: height,
    }
}

/// The unit vectors east, north and up at a geodetic latitude and longitude, in ECEF.
pub fn enu_basis(lat_deg: f64, lon_deg: f64) -> [Vec3; 3] {
    let (sin_lat, cos_lat) = libm::sincos(lat_deg.to_radians());
    let (sin_lon, cos_lon) = libm::sincos(lon_deg.to_radians());
    [
        [-sin_lon, cos_lon, 0.0],
        [-sin_lat * cos_lon, -sin_lat * sin_lon, cos_lat],
        [cos_lat * cos_lon, cos_lat * sin_lon, sin_lat],
    ]
}

/// ECEF metres rounded to whole millimetres, the form a clock model stores a site in.
pub fn to_mm(ecef: Vec3) -> [i64; 3] {
    ecef.map(|metres| (metres * 1000.0).round() as i64)
}

pub fn from_mm(mm: [i64; 3]) -> Vec3 {
    mm.map(|value| value as f64 / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geodetic_round_trips() {
        for (lat, lon, height) in [
            (52.3, 4.9, 12.0),
            (-33.9, 151.2, 11_000.0),
            (0.0, 0.0, 0.0),
            (89.5, -170.0, 3_000.0),
        ] {
            let back = from_ecef(to_ecef(Geodetic {
                lat_deg: lat,
                lon_deg: lon,
                height_m: height,
            }));
            assert!((back.lat_deg - lat).abs() < 1e-9);
            assert!((back.lon_deg - lon).abs() < 1e-9);
            assert!((back.height_m - height).abs() < 1e-4);
        }
    }

    #[test]
    fn the_equator_at_the_prime_meridian_is_the_semi_major_axis() {
        let ecef = to_ecef(Geodetic {
            lat_deg: 0.0,
            lon_deg: 0.0,
            height_m: 0.0,
        });
        assert_eq!(ecef, [A, 0.0, 0.0]);
    }
}
