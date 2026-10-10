//! The Mode S and ADS-B fields the network reads, and nothing else: the CRC and the address, the
//! altitude (Q bit and Gillham), an airborne position's fields and NACp (the geometry MLAT makes
//! of them, CPR and containment, is MLAT's own, `tally_mlat_solver::modes`); and which receptions are wanted ([`wanted_reception`]),
//! the one unit a receiver's reception ceiling is stated in, on the wire (`Record::RateLimit`'s
//! `wanted_per_sec`), at the feeder that sheds to it, at the relay that holds a feeder to it and at
//! MLAT's raw holder that sizes a receiver's bins by it. One definition in the crate every one of
//! them reads, so the feeder never sheds by one rule while the relay counts by another.
//!
//! Sources: ICAO Annex 10 Vol IV and Doc 9871 (Mode S formats, AC field, Gillham code), RTCA
//! DO-260B (ADS-B ME layouts, CPR, NACp, NIC), and Junzi Sun, "The 1090 Megahertz Riddle"
//! (mode-s.org), whose published examples are the test vectors below. Encoders sit beside the
//! decoders for the simulator; they are written from the standard independently of the decoders
//! (Gray code arithmetic against the decoder's XOR chain), so a round trip is a real check.

use crate::batch::format;

/// The longest Mode S message.
pub const LONG: usize = 14;

/// Whether MLAT ever uses `data`, a Mode S message: a reply whose address can be known (DF0, 4,
/// 5, 11, 16, 20, 21), or an extended squitter (DF17, 18) carrying an airborne position with an
/// altitude or a NACp. Everything else (identification, velocity, surface positions, Mode A/C,
/// damaged messages) is never solved for, so it is not counted against a receiver's ceiling.
pub fn wanted(data: &[u8]) -> bool {
    let Some(df) = downlink_format(data) else {
        return false;
    };
    match df {
        0 | 4 | 5 | 11 | 16 | 20 | 21 => address(data).is_some(),
        17 | 18 => {
            airborne_position(data).is_some_and(|position| position.altitude.is_some())
                || nacp(data).is_some()
        }
        _ => false,
    }
}

/// Whether a reception of `format` carrying `data` is a wanted one ([`wanted`]): a Mode S
/// reception (short or long) no longer than [`LONG`] whose message MLAT uses. What a receiver's
/// reception ceiling counts.
pub fn wanted_reception(format: u8, data: &[u8]) -> bool {
    matches!(format, format::MODE_S_SHORT | format::MODE_S_LONG)
        && data.len() <= LONG
        && wanted(data)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
            .collect()
    }

    /// A wanted reception is a Mode S message MLAT solves with: an airborne position with its
    /// altitude is, an identification or a velocity is not, nor anything not Mode S or longer than
    /// a long message.
    #[test]
    fn only_what_mlat_solves_with_is_wanted() {
        let position = hex("8D40621D58C382D690C8AC2863A7");
        let identification = hex("8D4840D6202CC371C32CE0576098");
        let velocity = hex("8D485020994409940838175B284F");
        assert!(wanted_reception(format::MODE_S_LONG, &position));
        assert!(!wanted_reception(format::MODE_S_LONG, &identification));
        assert!(!wanted_reception(format::MODE_S_LONG, &velocity));
        assert!(!wanted_reception(format::MODE_AC, &position));
        let mut longer = position.clone();
        longer.push(0);
        assert!(!wanted_reception(format::MODE_S_LONG, &longer));
        // A short reply with its address in its parity is wanted: DF4, altitude reply.
        let reply = with_parity(&[0x20, 0x00, 0x12, 0x34], 0x00ab_cdef);
        assert!(wanted_reception(format::MODE_S_SHORT, &reply));
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
    }
}
