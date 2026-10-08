//! The Mode S and ADS-B decoding MLAT needs, and nothing else: the CRC and the address, the
//! altitude (Q bit and Gillham), the airborne position (CPR, global and local), NACp and the
//! containment radius a type code implies.
//!
//! Sources: ICAO Annex 10 Vol IV and Doc 9871 (Mode S formats, AC field, Gillham code), RTCA
//! DO-260B (ADS-B ME layouts, CPR, NACp, NIC), and Junzi Sun, "The 1090 Megahertz Riddle"
//! (mode-s.org), whose published examples are the test vectors below. Encoders sit beside the
//! decoders for the simulator; they are written from the standard independently of the decoders
//! (Gray code arithmetic against the decoder's XOR chain), so a round trip is a real check.

/// The Mode S CRC generator polynomial, x^24 + x^23 + ... (Annex 10 Vol IV 3.1.2.3.3).
const GENERATOR: u32 = 0x00ff_f409;

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 16;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 0x0080_0000 != 0 {
                (c << 1) ^ GENERATOR
            } else {
                c << 1
            };
            bit += 1;
        }
        table[i] = c & 0x00ff_ffff;
        i += 1;
    }
    table
};

/// The 24-bit CRC of `bytes`.
pub fn crc(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |rem, byte| {
        let index = usize::from(*byte ^ ((rem >> 16) & 0xff) as u8);
        ((rem & 0x00_ffff) << 8) ^ CRC_TABLE[index]
    })
}

/// The CRC of everything but the last three bytes, XORed with those three bytes. Zero for an
/// undamaged DF17/18; the interrogator code for DF11; the address for an address/parity format.
pub fn crc_residual(message: &[u8]) -> u32 {
    let Some(split) = message.len().checked_sub(3) else {
        return u32::MAX;
    };
    let parity = &message[split..];
    crc(&message[..split])
        ^ (u32::from(parity[0]) << 16)
        ^ (u32::from(parity[1]) << 8)
        ^ u32::from(parity[2])
}

/// The message with its parity field computed: `body` is everything but the last three bytes,
/// and the parity is the CRC XOR `overlay` (zero for DF17, the address for DF4/5/20/21).
pub fn with_parity(body: &[u8], overlay: u32) -> Vec<u8> {
    let parity = crc(body) ^ overlay;
    let mut message = body.to_vec();
    message.extend_from_slice(&[(parity >> 16) as u8, (parity >> 8) as u8, parity as u8]);
    message
}

/// The downlink format: the first five bits, with every format from 24 up reported as 24.
pub fn downlink_format(message: &[u8]) -> Option<u8> {
    let df = message.first()? >> 3;
    Some(if df >= 24 { 24 } else { df })
}

/// The length in bytes the downlink format implies: 7 below DF16, 14 from it.
pub fn expected_len(df: u8) -> usize {
    if df < 16 { 7 } else { 14 }
}

fn announced_address(message: &[u8]) -> u32 {
    (u32::from(message[1]) << 16) | (u32::from(message[2]) << 8) | u32::from(message[3])
}

/// The 24-bit address the message belongs to, when it can be known:
///
/// - DF11: the AA field, if the CRC residual is an interrogator code (below 0x80).
/// - DF17: the AA field, if the residual is zero.
/// - DF18: the AA field, if the residual is zero and CF is 0 or 1 (ADS-B from a non-transponder
///   device). CF 2 and up are TIS-B and ADS-R, transmitted by a ground station, never by the
///   aircraft, so their arrival times say nothing about where the aircraft is.
/// - DF0, 4, 5, 16, 20, 21: the residual itself (address/parity). Unverifiable: a damaged
///   message yields a wrong address, so a caller that cares requires the address be seen in a
///   checked format too.
pub fn address(message: &[u8]) -> Option<u32> {
    let df = downlink_format(message)?;
    if message.len() != expected_len(df) {
        return None;
    }
    let residual = crc_residual(message);
    match df {
        11 => (residual & !0x7f == 0).then(|| announced_address(message)),
        17 => (residual == 0).then(|| announced_address(message)),
        18 => {
            let cf = message[0] & 0x07;
            (residual == 0 && cf <= 1).then(|| announced_address(message))
        }
        0 | 4 | 5 | 16 | 20 | 21 => Some(residual),
        _ => None,
    }
}

/// What an altitude is measured against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AltitudeKind {
    /// Pressure altitude, feet, referenced to 1013.25 hPa.
    Barometric,
    /// GNSS height above the WGS84 ellipsoid.
    Gnss,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Altitude {
    pub kind: AltitudeKind,
    pub feet: i32,
}

impl Altitude {
    pub fn metres(self) -> f64 {
        f64::from(self.feet) * 0.3048
    }
}

/// Gillham (Mode C) code to altitude, feet. `code` is in the squawk layout: A4 A2 A1 at bits
/// 14..12, B4 B2 B1 at 10..8, C4 C2 C1 at 6..4, D4 D2 D1 at 2..0. The decoding is the XOR chain
/// of the Gray code (100 ft digits from C, 500 ft digits from D, A, B), as Annex 10 Vol IV
/// 3.1.1.7.12.2.3 tabulates it.
pub fn gillham_feet(code: u16) -> Option<i32> {
    if code & 0x8889 != 0 || code & 0x00f0 == 0 {
        return None;
    }
    let mut hundreds = 0i32;
    if code & 0x0010 != 0 {
        hundreds ^= 0x7;
    }
    if code & 0x0020 != 0 {
        hundreds ^= 0x3;
    }
    if code & 0x0040 != 0 {
        hundreds ^= 0x1;
    }
    if hundreds & 5 == 5 {
        hundreds ^= 2;
    }
    if hundreds > 5 {
        return None;
    }
    let mut five_hundreds = 0i32;
    for (bit, mask) in [
        (0x0002, 0xff), // D2
        (0x0004, 0x7f), // D4
        (0x1000, 0x3f), // A1
        (0x2000, 0x1f), // A2
        (0x4000, 0x0f), // A4
        (0x0100, 0x07), // B1
        (0x0200, 0x03), // B2
        (0x0400, 0x01), // B4
    ] {
        if code & bit != 0 {
            five_hundreds ^= mask;
        }
    }
    if five_hundreds & 1 != 0 {
        hundreds = 6 - hundreds;
    }
    Some((five_hundreds * 5 + hundreds - 13) * 100)
}

/// Altitude, feet, to its Gillham code in the squawk layout, by Gray-encoding the 500 ft and
/// 100 ft digits. Defined from -1200 ft to 126 700 ft in 100 ft steps.
pub fn gillham_encode(feet: i32) -> Option<u16> {
    if feet % 100 != 0 || !(-1200..=126_700).contains(&feet) {
        return None;
    }
    let units = feet / 100 + 12;
    let five_hundreds = units / 5;
    let mut hundreds = units % 5 + 1;
    if five_hundreds & 1 != 0 {
        hundreds = 6 - hundreds;
    }
    if hundreds == 5 {
        hundreds = 7;
    }
    let gray_hundreds = hundreds ^ (hundreds >> 1);
    let gray_five = five_hundreds ^ (five_hundreds >> 1);
    let mut code = 0u16;
    for (index, bit) in [0x0010u16, 0x0020, 0x0040].into_iter().enumerate() {
        if gray_hundreds & (4 >> index) != 0 {
            code |= bit;
        }
    }
    for (index, bit) in [
        0x0002u16, 0x0004, 0x1000, 0x2000, 0x4000, 0x0100, 0x0200, 0x0400,
    ]
    .into_iter()
    .enumerate()
    {
        if gray_five & (0x80 >> index) != 0 {
            code |= bit;
        }
    }
    Some(code)
}

/// The 13-bit AC field (C1 A1 C2 A2 C4 A4 M B1 Q B2 D2 B4 D4) in the squawk layout.
fn ac13_to_squawk_layout(field: u16) -> u16 {
    let mut code = 0u16;
    for (from, to) in [
        (0x1000, 0x0010), // C1
        (0x0800, 0x1000), // A1
        (0x0400, 0x0020), // C2
        (0x0200, 0x2000), // A2
        (0x0100, 0x0040), // C4
        (0x0080, 0x4000), // A4
        (0x0020, 0x0100), // B1
        (0x0010, 0x0001), // D1 (Q)
        (0x0008, 0x0200), // B2
        (0x0004, 0x0002), // D2
        (0x0002, 0x0400), // B4
        (0x0001, 0x0004), // D4
    ] {
        if field & from != 0 {
            code |= to;
        }
    }
    code
}

fn squawk_layout_to_ac13(code: u16) -> u16 {
    let mut field = 0u16;
    for (to, from) in [
        (0x1000, 0x0010),
        (0x0800, 0x1000),
        (0x0400, 0x0020),
        (0x0200, 0x2000),
        (0x0100, 0x0040),
        (0x0080, 0x4000),
        (0x0020, 0x0100),
        (0x0010, 0x0001),
        (0x0008, 0x0200),
        (0x0004, 0x0002),
        (0x0002, 0x0400),
        (0x0001, 0x0004),
    ] {
        if code & from != 0 {
            field |= to;
        }
    }
    field
}

/// The 13-bit altitude code of DF0/4/16/20: all zeros is "unknown"; M set is metric (not
/// decoded: no fielded transponder sends it, and its layout is not settled across sources);
/// Q set is 25 ft steps, `N * 25 - 1000`; otherwise Gillham.
pub fn decode_ac13(field: u16) -> Option<i32> {
    if field == 0 || field & 0x40 != 0 {
        return None;
    }
    if field & 0x10 != 0 {
        let n = ((field & 0x1f80) >> 2) | ((field & 0x20) >> 1) | (field & 0x0f);
        return Some(i32::from(n) * 25 - 1000);
    }
    gillham_feet(ac13_to_squawk_layout(field))
}

/// The 12-bit altitude of an ADS-B airborne position (the AC field without its M bit).
pub fn decode_ac12(field: u16) -> Option<i32> {
    if field == 0 {
        return None;
    }
    if field & 0x10 != 0 {
        let n = ((field & 0xfe0) >> 1) | (field & 0x0f);
        return Some(i32::from(n) * 25 - 1000);
    }
    decode_ac13(((field & 0xfc0) << 1) | (field & 0x3f))
}

/// The 13-bit AC field for an altitude in 25 ft steps (Q set), from -1000 ft to 50 175 ft.
pub fn encode_ac13_q(feet: i32) -> Option<u16> {
    if (feet + 1000) % 25 != 0 {
        return None;
    }
    let n = u16::try_from((feet + 1000) / 25)
        .ok()
        .filter(|n| *n < 2048)?;
    Some(((n & 0x7e0) << 2) | ((n & 0x10) << 1) | (n & 0x0f) | 0x10)
}

/// The 13-bit AC field for an altitude in 100 ft Gillham code.
pub fn encode_ac13_gillham(feet: i32) -> Option<u16> {
    gillham_encode(feet).map(squawk_layout_to_ac13)
}

/// The 12-bit ADS-B altitude field: the AC field with its M bit removed.
pub fn ac13_to_ac12(field: u16) -> u16 {
    ((field & 0x1f80) >> 1) | (field & 0x3f)
}

/// The altitude a message reports about its sender, if any: AC13 for DF0/4/16/20, the 12-bit
/// field of a DF17/18 airborne position (TC 9-18 barometric, TC 20-22 GNSS height, metres on the
/// wire as DO-260B and The 1090 Megahertz Riddle give it).
pub fn altitude(message: &[u8]) -> Option<Altitude> {
    let df = downlink_format(message)?;
    if message.len() != expected_len(df) {
        return None;
    }
    match df {
        0 | 4 | 16 | 20 => {
            let field = ((u16::from(message[2]) & 0x1f) << 8) | u16::from(message[3]);
            decode_ac13(field).map(|feet| Altitude {
                kind: AltitudeKind::Barometric,
                feet,
            })
        }
        17 | 18 => airborne_position(message).and_then(|position| position.altitude),
        _ => None,
    }
}

/// The ADS-B type code of a DF17/18 message (the first five bits of ME).
pub fn type_code(message: &[u8]) -> Option<u8> {
    let df = downlink_format(message)?;
    ((df == 17 || df == 18) && message.len() == 14).then(|| message[4] >> 3)
}

/// One airborne position message's fields (DO-260B 2.2.3.2.3).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AirbornePosition {
    pub type_code: u8,
    pub odd: bool,
    pub lat_cpr: u32,
    pub lon_cpr: u32,
    pub altitude: Option<Altitude>,
}

/// The airborne position fields of a DF17/18 with a zero CRC residual and type code 9-18 or
/// 20-22.
pub fn airborne_position(message: &[u8]) -> Option<AirbornePosition> {
    let tc = type_code(message)?;
    if crc_residual(message) != 0 || !matches!(tc, 9..=18 | 20..=22) {
        return None;
    }
    let me = &message[4..11];
    let alt_field = (u16::from(me[1]) << 4) | (u16::from(me[2]) >> 4);
    let odd = me[2] & 0x04 != 0;
    let lat_cpr =
        ((u32::from(me[2]) & 0x03) << 15) | (u32::from(me[3]) << 7) | (u32::from(me[4]) >> 1);
    let lon_cpr = ((u32::from(me[4]) & 0x01) << 16) | (u32::from(me[5]) << 8) | u32::from(me[6]);
    let altitude = if tc <= 18 {
        decode_ac12(alt_field).map(|feet| Altitude {
            kind: AltitudeKind::Barometric,
            feet,
        })
    } else if alt_field == 0 {
        None
    } else {
        // Metres on the wire; reported in feet like every other altitude, rounded.
        Some(Altitude {
            kind: AltitudeKind::Gnss,
            feet: (f64::from(alt_field) / 0.3048).round() as i32,
        })
    };
    Some(AirbornePosition {
        type_code: tc,
        odd,
        lat_cpr,
        lon_cpr,
        altitude,
    })
}

/// The ME field of an airborne position, for the simulator.
pub fn encode_airborne_position(
    type_code: u8,
    alt_field: u16,
    odd: bool,
    lat_cpr: u32,
    lon_cpr: u32,
) -> [u8; 7] {
    let mut bits: u64 = u64::from(type_code & 0x1f) << 51;
    bits |= u64::from(alt_field & 0xfff) << 36;
    bits |= u64::from(odd) << 34;
    bits |= u64::from(lat_cpr & 0x1ffff) << 17;
    bits |= u64::from(lon_cpr & 0x1ffff);
    let bytes = bits.to_be_bytes();
    [
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]
}

/// NACp from an airborne operational status message (TC 31, subtype 0, ME bits 45-48), when
/// the CRC checks.
pub fn nacp(message: &[u8]) -> Option<u8> {
    let tc = type_code(message)?;
    if tc != 31 || crc_residual(message) != 0 {
        return None;
    }
    let me = &message[4..11];
    let subtype = me[0] & 0x07;
    (subtype == 0).then_some(me[5] & 0x0f)
}

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
    (2..=59)
        .rev()
        .find(|zones| lat <= nl_transition(*zones))
        .unwrap_or(1)
}

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
    fn the_riddle_extended_squitters_check_and_name_their_aircraft() {
        // The 1090 Megahertz Riddle: identification, airborne position (even and odd) and
        // velocity examples.
        for (message, icao) in [
            ("8D4840D6202CC371C32CE0576098", 0x4840d6),
            ("8D40621D58C382D690C8AC2863A7", 0x40621d),
            ("8D40621D58C386435CC412692AD6", 0x40621d),
            ("8D485020994409940838175B284F", 0x485020),
        ] {
            let bytes = hex(message);
            assert_eq!(crc_residual(&bytes), 0, "{message}");
            assert_eq!(address(&bytes), Some(icao), "{message}");
        }
        // One flipped bit is caught.
        let mut damaged = hex("8D4840D6202CC371C32CE0576098");
        damaged[6] ^= 0x10;
        assert_ne!(crc_residual(&damaged), 0);
        assert_eq!(address(&damaged), None);
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

    #[test]
    fn the_q_bit_altitude_of_a_comm_b_reply_decodes() {
        // pyModeS's DF20 vector: AC = 0x14B4, Q set, 32 300 ft.
        let message = hex("A02014B400000000000000F9D514");
        assert_eq!(
            altitude(&message),
            Some(Altitude {
                kind: AltitudeKind::Barometric,
                feet: 32_300
            })
        );
        assert_eq!(encode_ac13_q(32_300), Some(0x14b4));
    }

    #[test]
    fn gillham_round_trips_over_its_whole_range() -> Result<(), String> {
        for feet in (-1200..=126_700).step_by(100) {
            let code = gillham_encode(feet).ok_or("encode")?;
            assert_eq!(gillham_feet(code), Some(feet), "{feet} {code:#06x}");
            let field = encode_ac13_gillham(feet).ok_or("ac13")?;
            assert_eq!(field & 0x50, 0);
            assert_eq!(decode_ac13(field), Some(feet));
            assert_eq!(decode_ac12(ac13_to_ac12(field)), Some(feet));
        }
        // A D1 bit, or no C bit, is not an altitude.
        assert_eq!(gillham_feet(0x0001 | 0x0010), None);
        assert_eq!(gillham_feet(0x0100), None);
        Ok(())
    }

    #[test]
    fn q_bit_altitudes_round_trip_in_both_fields() -> Result<(), String> {
        for feet in (-1000..=50_175).step_by(25) {
            let field = encode_ac13_q(feet).ok_or("encode")?;
            assert_eq!(decode_ac13(field), Some(feet));
            assert_eq!(decode_ac12(ac13_to_ac12(field)), Some(feet));
        }
        Ok(())
    }

    #[test]
    fn an_address_parity_reply_yields_its_address() {
        let address_in = 0x4840d6;
        // DF4, FS 0, DR 0, UM 0, AC for 36 000 ft.
        let ac = encode_ac13_q(36_000).unwrap_or(0);
        let body = [4 << 3, 0, (ac >> 8) as u8, ac as u8];
        let message = with_parity(&body, address_in);
        assert_eq!(address(&message), Some(address_in));
        assert_eq!(
            altitude(&message).map(|altitude| altitude.feet),
            Some(36_000)
        );
    }

    #[test]
    fn ground_transmitted_extended_squitters_have_no_aircraft_address() {
        // DF18 CF 2 (fine TIS-B): sent by a ground station, so useless for MLAT.
        let body = [(18 << 3) | 2, 0x48, 0x40, 0xd6, 0x58, 0, 0, 0, 0, 0, 0];
        assert_eq!(address(&with_parity(&body, 0)), None);
        let body = [18 << 3, 0x48, 0x40, 0xd6, 0x58, 0, 0, 0, 0, 0, 0];
        assert_eq!(address(&with_parity(&body, 0)), Some(0x4840d6));
    }

    #[test]
    fn nacp_reads_from_operational_status() {
        // TC 31, subtype 0, version 2, NACp 10 in ME bits 45-48.
        let mut me = [0u8; 7];
        me[0] = 31 << 3;
        me[5] = 10;
        let mut body = vec![17 << 3, 0x48, 0x40, 0xd6];
        body.extend_from_slice(&me);
        let message = with_parity(&body, 0);
        assert_eq!(nacp(&message), Some(10));
        assert_eq!(epu_m(10), Some(10.0));
    }
}
