//! The geometry MLAT makes of the Mode S fields: the airborne position's CPR (global and local
//! decoding, and encoding for the simulator), the accuracy a NACp declares and the containment
//! radius a type code implies. The fields themselves (the CRC and the address, the altitude,
//! the airborne position's raw fields, NACp) and which receptions are wanted are the network's one
//! decoding, `tally_wire::modes`, re-exported here, so MLAT, the relay and the feeder read the
//! same bytes the same way.
//!
//! Sources: RTCA DO-260B (CPR, NACp, NIC) and Junzi Sun, "The 1090 Megahertz Riddle"
//! (mode-s.org), whose published examples are the test vectors below. The encoder is written from
//! the standard independently of the decoders, so a round trip is a real check.

pub use tally_wire::modes::*;

/// The 95% horizontal accuracy bound (EPU) a NACp declares, metres (DO-260B Table 2-69).
pub fn epu_m(nacp: u8) -> Option<f64> {
    match nacp {
        11 => Some(3.0),
        10 => Some(10.0),
        9 => Some(30.0),
        8 => Some(92.6),
        7 => Some(185.2),
        6 => Some(555.6),
        5 => Some(926.0),
        4 => Some(1852.0),
        3 => Some(3704.0),
        2 => Some(7408.0),
        1 => Some(18_520.0),
        _ => None,
    }
}

/// The largest horizontal containment radius Rc an airborne position type code allows, metres,
/// with every NIC supplement taken at its worst (DO-260B Table 2-14). An integrity bound, so as
/// an accuracy it is conservative.
pub fn containment_m(type_code: u8) -> Option<f64> {
    match type_code {
        9 | 20 => Some(7.5),
        10 | 21 => Some(25.0),
        11 => Some(185.2),
        12 => Some(370.4),
        13 => Some(1111.2),
        14 => Some(1852.0),
        15 => Some(3704.0),
        16 => Some(14_816.0),
        17 => Some(37_040.0),
        _ => None,
    }
}

/// The number of latitude zones (NZ) of airborne CPR.
const NZ: f64 = 15.0;
/// 2^17, the airborne CPR resolution.
const CPR_MAX: f64 = 131_072.0;

/// The latitude at which the number of longitude zones drops below `zones`.
fn nl_transition(zones: u32) -> f64 {
    let a = 1.0 - libm::cos(std::f64::consts::PI / (2.0 * NZ));
    let b = 1.0 - libm::cos(2.0 * std::f64::consts::PI / f64::from(zones));
    libm::acos((a / b).sqrt()).to_degrees()
}

/// NL(lat), the number of longitude zones (DO-260B A.1.7.2.d): the largest `n` with
/// `|lat| <= T(n)`, `T(n) = acos(sqrt((1 - cos(pi/2NZ)) / (1 - cos(2pi/n))))`; 59 at the
/// equator, 1 beyond 87 degrees.
pub fn nl(lat_deg: f64) -> u32 {
    let lat = lat_deg.abs();
    if lat >= 87.0 {
        return if lat > 87.0 { 1 } else { 2 };
    }
    let transitions = &*NL_TRANSITIONS;
    (2..=59)
        .rev()
        .find(|zones| lat <= transitions[*zones as usize])
        .unwrap_or(1)
}

/// `nl_transition(n)` at index `n`, for 2 to 59, computed once by that formula, so `nl` reads
/// the same latitudes bit for bit. Before (2026-10-27), each `nl` computed up to 58 cosines and
/// arccosines: a quarter of the relay's figures and of the pairs' read of a window, profiled at
/// 2,000 feeders.
static NL_TRANSITIONS: std::sync::LazyLock<[f64; 60]> = std::sync::LazyLock::new(|| {
    let mut transitions = [0.0; 60];
    for zones in 2..=59u32 {
        transitions[zones as usize] = nl_transition(zones);
    }
    transitions
});

fn modulo(x: f64, y: f64) -> f64 {
    x - y * (x / y).floor()
}

/// A position decoded from CPR, degrees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LatLon {
    pub lat_deg: f64,
    pub lon_deg: f64,
}

/// Global decoding of an even and an odd airborne position (DO-260B A.1.7.7), taking the
/// position of whichever was received later (`odd_latest`). `None` when the two lie in
/// different longitude zone counts (the pair straddles a zone boundary and must not be used).
pub fn cpr_global(even: (u32, u32), odd: (u32, u32), odd_latest: bool) -> Option<LatLon> {
    let lat_even_cpr = f64::from(even.0) / CPR_MAX;
    let lon_even_cpr = f64::from(even.1) / CPR_MAX;
    let lat_odd_cpr = f64::from(odd.0) / CPR_MAX;
    let lon_odd_cpr = f64::from(odd.1) / CPR_MAX;
    let d_lat_even = 360.0 / 60.0;
    let d_lat_odd = 360.0 / 59.0;
    let j = (59.0 * lat_even_cpr - 60.0 * lat_odd_cpr + 0.5).floor();
    let mut lat_even = d_lat_even * (modulo(j, 60.0) + lat_even_cpr);
    let mut lat_odd = d_lat_odd * (modulo(j, 59.0) + lat_odd_cpr);
    if lat_even >= 270.0 {
        lat_even -= 360.0;
    }
    if lat_odd >= 270.0 {
        lat_odd -= 360.0;
    }
    if !(-90.0..=90.0).contains(&lat_even) || !(-90.0..=90.0).contains(&lat_odd) {
        return None;
    }
    let zones = nl(lat_even);
    if zones != nl(lat_odd) {
        return None;
    }
    let (lat, ni, lon_cpr) = if odd_latest {
        (lat_odd, zones.saturating_sub(1).max(1), lon_odd_cpr)
    } else {
        (lat_even, zones.max(1), lon_even_cpr)
    };
    let nl_f = f64::from(zones);
    let m = (lon_even_cpr * (nl_f - 1.0) - lon_odd_cpr * nl_f + 0.5).floor();
    let ni_f = f64::from(ni);
    let mut lon = (360.0 / ni_f) * (modulo(m, ni_f) + lon_cpr);
    if lon >= 180.0 {
        lon -= 360.0;
    }
    Some(LatLon {
        lat_deg: lat,
        lon_deg: lon,
    })
}

/// Local decoding of one airborne position against a reference within 180 NM of it (DO-260B
/// A.1.7.5).
pub fn cpr_local(cpr: (u32, u32), odd: bool, reference: LatLon) -> LatLon {
    let i = f64::from(u8::from(odd));
    let lat_cpr = f64::from(cpr.0) / CPR_MAX;
    let lon_cpr = f64::from(cpr.1) / CPR_MAX;
    let d_lat = 360.0 / (60.0 - i);
    let j = (reference.lat_deg / d_lat).floor()
        + (modulo(reference.lat_deg, d_lat) / d_lat - lat_cpr + 0.5).floor();
    let lat = d_lat * (j + lat_cpr);
    let zones = f64::from(nl(lat)) - i;
    let d_lon = 360.0 / zones.max(1.0);
    let m = (reference.lon_deg / d_lon).floor()
        + (modulo(reference.lon_deg, d_lon) / d_lon - lon_cpr + 0.5).floor();
    let mut lon = d_lon * (m + lon_cpr);
    if lon >= 180.0 {
        lon -= 360.0;
    }
    if lon < -180.0 {
        lon += 360.0;
    }
    LatLon {
        lat_deg: lat,
        lon_deg: lon,
    }
}

/// Airborne CPR encoding (DO-260B A.1.7.3), for the simulator.
pub fn cpr_encode(position: LatLon, odd: bool) -> (u32, u32) {
    let i = f64::from(u8::from(odd));
    let d_lat = 360.0 / (60.0 - i);
    let yz = (CPR_MAX * modulo(position.lat_deg, d_lat) / d_lat + 0.5).floor();
    let r_lat = d_lat * (yz / CPR_MAX + (position.lat_deg / d_lat).floor());
    let zones = f64::from(nl(r_lat)) - i;
    let d_lon = 360.0 / zones.max(1.0);
    let xz = (CPR_MAX * modulo(position.lon_deg, d_lon) / d_lon + 0.5).floor();
    ((yz as u32) & 0x1ffff, (xz as u32) & 0x1ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
            .collect()
    }

    #[test]
    fn the_riddle_airborne_position_decodes_globally_and_locally() -> Result<(), String> {
        let even = hex("8D40621D58C382D690C8AC2863A7");
        let odd = hex("8D40621D58C386435CC412692AD6");
        let even = airborne_position(&even).ok_or("even")?;
        let odd = airborne_position(&odd).ok_or("odd")?;
        assert!(!even.odd && odd.odd);
        assert_eq!(even.type_code, 11);
        assert_eq!(
            even.altitude,
            Some(Altitude {
                kind: AltitudeKind::Barometric,
                feet: 38_000
            })
        );
        assert_eq!((even.lat_cpr, even.lon_cpr), (93_000, 51_372));
        assert_eq!((odd.lat_cpr, odd.lon_cpr), (74_158, 50_194));
        // The even message is the newer one (t = 1457996402 against 1457996400).
        let global = cpr_global(
            (even.lat_cpr, even.lon_cpr),
            (odd.lat_cpr, odd.lon_cpr),
            false,
        )
        .ok_or("global")?;
        assert!((global.lat_deg - 52.25720).abs() < 1e-5, "{global:?}");
        assert!((global.lon_deg - 3.91937).abs() < 1e-5, "{global:?}");
        let local = cpr_local(
            (even.lat_cpr, even.lon_cpr),
            false,
            LatLon {
                lat_deg: 52.258,
                lon_deg: 3.918,
            },
        );
        assert!((local.lat_deg - 52.25720).abs() < 1e-5, "{local:?}");
        assert!((local.lon_deg - 3.91937).abs() < 1e-5, "{local:?}");
        Ok(())
    }

    #[test]
    fn the_number_of_longitude_zones_matches_the_published_transitions() {
        assert_eq!(nl(0.0), 59);
        assert_eq!(nl(10.47), 59);
        assert_eq!(nl(10.48), 58);
        assert_eq!(nl(14.82), 58);
        assert_eq!(nl(14.83), 57);
        assert_eq!(nl(52.2572), 36);
        assert_eq!(nl(86.53), 3);
        assert_eq!(nl(86.54), 2);
        assert_eq!(nl(87.0), 2);
        assert_eq!(nl(-87.5), 1);
        assert!((nl_transition(59) - 10.470_471_30).abs() < 1e-7);
        assert!((nl_transition(58) - 14.828_174_37).abs() < 1e-7);
        for zones in 2..=59u32 {
            assert_eq!(
                NL_TRANSITIONS[zones as usize].to_bits(),
                nl_transition(zones).to_bits()
            );
        }
    }

    #[test]
    fn cpr_encoding_round_trips_through_both_decoders() -> Result<(), String> {
        for (lat, lon) in [
            (52.2572, 3.91937),
            (51.9, 4.47),
            (-33.86, 151.21),
            (0.1, -179.9),
            (60.5, 24.9),
        ] {
            let position = LatLon {
                lat_deg: lat,
                lon_deg: lon,
            };
            let even = cpr_encode(position, false);
            let odd = cpr_encode(position, true);
            for odd_latest in [false, true] {
                let back = cpr_global(even, odd, odd_latest).ok_or("global")?;
                assert!((back.lat_deg - lat).abs() < 1e-4, "{lat} {back:?}");
                assert!((back.lon_deg - lon).abs() < 1e-4, "{lon} {back:?}");
            }
            let reference = LatLon {
                lat_deg: lat + 0.7,
                lon_deg: lon - 0.6,
            };
            let back = cpr_local(odd, true, reference);
            assert!((back.lat_deg - lat).abs() < 1e-4);
            assert!((back.lon_deg - lon).abs() < 1e-4);
        }
        Ok(())
    }
}
