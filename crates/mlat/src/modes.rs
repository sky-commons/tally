//! The little Mode S decoding mlat-client does before it chooses what to send: the downlink
//! format, the CRC residual, the address, and for DF17 the CPR format, NUCp and altitude. A port of
//! mlat-client's `modes_message.c` (`decode`, `decode_ac13`, `decode_ac12`, `crc_residual`) and
//! `modes_crc.c`, field for field, so the engine selects exactly what mlat-client would.
//! <https://github.com/wiedehopf/mlat-client/blob/master/modes_message.c>

/// The Mode S CRC generator polynomial (`MODES_GENERATOR_POLY`, modes_crc.c).
const GENERATOR: u32 = 0x00ff_f409;

/// The CRC of every single byte, as `modescrc_module_init` builds it.
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

/// `modescrc_buffer_crc`: the CRC of `bytes`.
pub fn crc(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |rem, byte| {
        let index = usize::from(*byte ^ ((rem & 0x00ff_0000) >> 16) as u8);
        ((rem & 0x00_ffff) << 8) ^ CRC_TABLE[index]
    })
}

/// `crc_residual`: the CRC of everything but the parity field, XORed with the parity field. Zero
/// for an undamaged DF11 (IID 0) or DF17; the address for an address/parity format.
pub fn crc_residual(message: &[u8]) -> u32 {
    let Some(split) = message.len().checked_sub(3) else {
        return 0;
    };
    let parity = &message[split..];
    crc(&message[..split])
        ^ (u32::from(parity[0]) << 16)
        ^ (u32::from(parity[1]) << 8)
        ^ u32::from(parity[2])
}

/// One Mode S message as mlat-client's decoder sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The receiver's timestamp after mlat-client's per-format adjustment (`client.rs`).
    pub timestamp: u64,
    pub data: Vec<u8>,
    pub df: u8,
    pub address: Option<u32>,
    /// "Does the message look OK?": a CRC that checks, where the format allows checking.
    pub valid: bool,
    pub even_cpr: bool,
    pub odd_cpr: bool,
    pub nuc: u8,
    pub altitude: Option<i32>,
}

impl Message {
    /// `decode` in modes_message.c, for a 7- or 14-byte Mode S message.
    pub fn decode(timestamp: u64, data: &[u8]) -> Self {
        let mut message = Self {
            timestamp,
            data: data.to_vec(),
            df: data.first().map_or(0, |byte| (byte >> 3) & 31),
            address: None,
            valid: false,
            even_cpr: false,
            odd_cpr: false,
            nuc: 0,
            altitude: None,
        };
        let df = message.df;
        if (df < 16 && data.len() != 7) || (df >= 16 && data.len() != 14) {
            return message;
        }
        if !matches!(df, 0 | 4 | 5 | 11 | 16 | 17 | 20 | 21) {
            return message;
        }
        let residual = crc_residual(data);
        match df {
            0 | 4 | 16 | 20 => {
                message.address = Some(residual);
                message.altitude =
                    decode_ac13((u32::from(data[2] & 0x1f) << 8) | u32::from(data[3]));
                message.valid = true;
            }
            5 | 21 => {
                message.address = Some(residual);
                message.valid = true;
            }
            11 => {
                // An interrogator id in the low seven bits still leaves the message valid.
                message.valid = residual & !0x7f == 0;
                if message.valid {
                    message.address = Some(address(data));
                }
            }
            17 => {
                message.valid = residual == 0;
                if message.valid {
                    message.address = Some(address(data));
                    let metype = data[4] >> 3;
                    // `(metype >= 9 && metype <= 18) || (metype >= 20 && metype < 22)`.
                    if (9..=18).contains(&metype) || (20..22).contains(&metype) {
                        message.nuc = if metype <= 18 {
                            18 - metype
                        } else {
                            29 - metype
                        };
                        if data[6] & 0x04 != 0 {
                            message.odd_cpr = true;
                        } else {
                            message.even_cpr = true;
                        }
                        message.altitude = decode_ac12(
                            (u32::from(data[5]) << 4) | (u32::from(data[6] & 0xf0) >> 4),
                        );
                        // "crude check if there is any CPR data": mostly-zero CPR is invalid.
                        if (data[7] == 0 && data[8] & 0x7f == 0) || (data[9] == 0 && data[10] == 0)
                        {
                            message.valid = false;
                        }
                    }
                }
            }
            _ => {}
        }
        message
    }

    /// `str(message)`: the bytes as lowercase hex, as the JSON protocol carries them.
    pub fn hex(&self) -> String {
        hex(&self.data)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

fn address(data: &[u8]) -> u32 {
    (u32::from(data[1]) << 16) | (u32::from(data[2]) << 8) | u32::from(data[3])
}

/// `decode_ac13`: a 13-bit altitude code to feet, `None` when absent, metric or illegal.
pub fn decode_ac13(ac13: u32) -> Option<i32> {
    if ac13 == 0 || ac13 & 0x0040 != 0 {
        return None;
    }
    if ac13 & 0x0010 != 0 {
        let n = ((ac13 & 0x1f80) >> 2) | ((ac13 & 0x0020) >> 1) | (ac13 & 0x000f);
        return i32::try_from(n).ok().map(|n| n * 25 - 1000);
    }
    // Gillham code.
    if ac13 & 0x1500 == 0 {
        return None;
    }
    let mut h: i32 = 0;
    if ac13 & 0x1000 != 0 {
        h ^= 7;
    }
    if ac13 & 0x0400 != 0 {
        h ^= 3;
    }
    if ac13 & 0x0100 != 0 {
        h ^= 1;
    }
    if h & 5 != 0 {
        h ^= 5;
    }
    if h > 5 {
        return None;
    }
    let mut f: i32 = 0;
    for (bit, mask) in [
        (0x0010, 0x1ff),
        (0x0004, 0x0ff),
        (0x0001, 0x07f),
        (0x0800, 0x03f),
        (0x0200, 0x01f),
        (0x0080, 0x00f),
        (0x0020, 0x007),
        (0x0008, 0x003),
        (0x0002, 0x001),
    ] {
        if ac13 & bit != 0 {
            f ^= mask;
        }
    }
    if f & 1 != 0 {
        h = 6 - h;
    }
    let altitude = 500 * f + 100 * h - 1300;
    (altitude >= -1200).then_some(altitude)
}

/// `decode_ac12`: the 12-bit altitude of an airborne position message.
pub fn decode_ac12(ac12: u32) -> Option<i32> {
    decode_ac13(((ac12 & 0x0fc0) << 1) | (ac12 & 0x003f))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .filter_map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
            .collect()
    }

    /// The airborne position pair of "The 1090 MHz Riddle" (Junzi Sun), §5: ICAO 40621D,
    /// type code 11, 38 000 ft.
    pub const EVEN: &str = "8d40621d58c382d690c8ac2863a7";
    pub const ODD: &str = "8d40621d58c386435cc412692ad6";

    #[test]
    fn a_published_position_pair_decodes_as_mlat_client_decodes_it() {
        let even = Message::decode(1, &bytes(EVEN));
        assert_eq!(
            (
                even.df,
                even.address,
                even.valid,
                even.even_cpr,
                even.odd_cpr
            ),
            (17, Some(0x40621d), true, true, false)
        );
        assert_eq!((even.nuc, even.altitude), (7, Some(38_000)));
        let odd = Message::decode(1, &bytes(ODD));
        assert_eq!((odd.odd_cpr, odd.even_cpr, odd.valid), (true, false, true));
        assert_eq!(odd.hex(), ODD);
    }

    #[test]
    fn a_damaged_extended_squitter_is_invalid() {
        let mut data = bytes(EVEN);
        data[9] ^= 1;
        let message = Message::decode(1, &data);
        assert!(!message.valid);
        assert_eq!(message.address, None);
    }

    #[test]
    fn an_identification_message_is_valid_but_carries_no_position() {
        // The Riddle's identification example, "KLM1023".
        let message = Message::decode(1, &bytes("8d4840d6202cc371c32ce0576098"));
        assert_eq!((message.valid, message.address), (true, Some(0x4840d6)));
        assert!(!message.even_cpr && !message.odd_cpr);
    }

    #[test]
    fn address_parity_formats_recover_the_address_from_the_residual() {
        let mut data = vec![0x20, 0x00, 0x1b, 0x30];
        let parity = crc(&data) ^ 0xabcdef;
        data.extend_from_slice(&[(parity >> 16) as u8, (parity >> 8) as u8, parity as u8]);
        let message = Message::decode(1, &data);
        assert_eq!(
            (message.df, message.address, message.valid),
            (4, Some(0xabcdef), true)
        );
    }

    #[test]
    fn an_all_call_reply_checks_its_crc_but_allows_an_interrogator_id() {
        let mut data = vec![0x5d, 0xab, 0xcd, 0xef];
        let parity = crc(&data) ^ 0x05;
        data.extend_from_slice(&[(parity >> 16) as u8, (parity >> 8) as u8, parity as u8]);
        let message = Message::decode(1, &data);
        assert_eq!(
            (message.df, message.address, message.valid),
            (11, Some(0xabcdef), true)
        );
        data[6] ^= 0x80;
        assert!(!Message::decode(1, &data).valid);
    }

    #[test]
    fn q_bit_and_gillham_altitudes_decode() {
        assert_eq!(decode_ac12(0xc38), Some(38_000));
        assert_eq!(decode_ac13(0), None);
        assert_eq!(decode_ac13(0x0040), None);
    }
}
