//! Reading dump978-fa's raw output, the 978 MHz UAT receptions (RFC-0171 §3.4, §3.5).
//!
//! dump978-fa (github.com/flightaware/dump978, `uat_message.cc`, `operator<<` on `RawMessage`)
//! writes one reception per line on its raw port (30978 in its Debian defaults):
//!
//! ```text
//! -<hex payload>;rs=<corrected errors>;rssi=<dBFS, one decimal>;t=<unix seconds>.<millis>;rt=<n>;
//! +<hex payload>;...
//! !key=value;...
//! ```
//!
//! `-` is a downlink from an aircraft (18 bytes basic, 34 long), `+` a ground uplink (432 bytes),
//! `!` metadata about the decoder, which is not a reception. Every field after the payload is
//! optional (dump978 omits one that is zero) and their order is not relied on, so a later dump978
//! adding a field changes nothing here.

use tally_wire::Observation;
use tally_wire::batch::format;

use crate::lines::{Line, TIMESTAMP_MODULUS};

/// The longest line dump978 writes is an uplink: 865 characters of payload and its fields. A line
/// past this is not dump978's and is skipped whole.
pub const MAX_LINE: usize = 2048;

const DOWNLINK_SHORT: usize = 18;
const DOWNLINK_LONG: usize = 34;
const UPLINK: usize = 432;

/// One line, without its newline. `now_us` is the feeder's wall clock, used when the line has no
/// usable `t=`.
pub fn parse_line(line: &str, now_us: u64) -> Line {
    let line = line.trim_end_matches('\r');
    let (format, rest) = match line.as_bytes().first() {
        None => return Line::Ignored,
        Some(b'!') => return Line::Ignored,
        Some(b'-') => (format::UAT_DOWNLINK, &line[1..]),
        Some(b'+') => (format::UAT_UPLINK, &line[1..]),
        Some(_) => return Line::Bad,
    };
    let mut fields = rest.split(';');
    let Some(data) = fields.next().and_then(hex) else {
        return Line::Bad;
    };
    let length_ok = match format {
        format::UAT_DOWNLINK => data.len() == DOWNLINK_SHORT || data.len() == DOWNLINK_LONG,
        _ => data.len() == UPLINK,
    };
    if !length_ok {
        return Line::Bad;
    }
    let (mut timestamp, mut signal) = (None, 0);
    for field in fields {
        match field.split_once('=') {
            Some(("t", value)) => timestamp = wall_us(value),
            Some(("rssi", value)) => signal = value.parse().map_or(0, signal_from_dbfs),
            _ => {}
        }
    }
    Line::Reception(Observation {
        format,
        timestamp: timestamp.unwrap_or(now_us) % TIMESTAMP_MODULUS,
        signal,
        data,
    })
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// `t=` is Unix seconds with a fraction (dump978 writes milliseconds). A value this cannot read
/// falls back to the feeder's clock rather than losing the reception: the timestamp of a UAT
/// reception is a wall clock either way, only a less precise one.
fn wall_us(text: &str) -> Option<u64> {
    let (seconds, fraction) = text.split_once('.').unwrap_or((text, ""));
    if seconds.is_empty() || !seconds.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seconds: u64 = seconds.parse().ok()?;
    // Microseconds: the first six digits of the fraction, padded on the right.
    let mut micros = 0u64;
    for at in 0..6 {
        let digit = fraction.as_bytes().get(at).map_or(0, |byte| byte - b'0');
        micros = micros * 10 + u64::from(digit);
    }
    seconds.checked_mul(1_000_000)?.checked_add(micros)
}

/// dump978's rssi is the mean power of the message's samples in dBFS (`10 * log10(power)`, 0 at
/// full scale, more negative when weaker). BEAST's signal byte is the amplitude scaled to 255
/// (`255 * sqrt(power)`, as readsb writes it), so the same mapping, `255 * 10^(dBFS / 20)`, puts
/// both bands on one scale: 0 dBFS is 255, -6 dBFS about 128, -48 dBFS about 1. Anything weaker,
/// or a missing rssi, is 0; anything above full scale is 255.
fn signal_from_dbfs(dbfs: f64) -> u8 {
    let amplitude = 255.0 * 10f64.powf(dbfs / 20.0);
    if amplitude.is_nan() {
        return 0;
    }
    amplitude.round().clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(length: usize) -> String {
        (0..length).map(|at| format!("{:02x}", at % 256)).collect()
    }

    fn bytes(length: usize) -> Vec<u8> {
        (0..length).map(|at| (at % 256) as u8).collect()
    }

    #[test]
    fn a_downlink_keeps_its_bytes_wall_clock_and_signal() -> Result<(), String> {
        let line = format!("-{};rs=2;rssi=-6.0;t=1696500000.123;rt=42;", payload(18));
        let expected = Observation {
            format: format::UAT_DOWNLINK,
            timestamp: 1_696_500_000_123_000 % TIMESTAMP_MODULUS,
            signal: 128,
            data: bytes(18),
        };
        assert_eq!(parse_line(&line, 7), Line::Reception(expected));
        let long = format!("-{};t=1.5;", payload(34));
        let Line::Reception(long) = parse_line(&long, 7) else {
            return Err("a long downlink was refused".to_owned());
        };
        assert_eq!(
            (long.timestamp, long.signal, long.data.len()),
            (1_500_000, 0, 34)
        );
        Ok(())
    }

    #[test]
    fn an_uplink_is_its_own_format() -> Result<(), String> {
        let line = format!("+{};rssi=-20.4;t=1696500000.000;\r", payload(432));
        let Line::Reception(uplink) = parse_line(&line, 7) else {
            return Err("an uplink was refused".to_owned());
        };
        assert_eq!(uplink.format, format::UAT_UPLINK);
        assert_eq!(uplink.data, bytes(432));
        assert_eq!(uplink.signal, 24);
        Ok(())
    }

    #[test]
    fn bad_hex_is_skipped() {
        let mut line = format!("-{};t=1.0;", payload(18));
        line.replace_range(3..4, "g");
        assert_eq!(parse_line(&line, 7), Line::Bad);
        assert_eq!(parse_line(&format!("-{}0;", payload(18)), 7), Line::Bad);
        assert_eq!(parse_line("-;t=1.0;", 7), Line::Bad);
        assert_eq!(parse_line("*8d4840d6202cc371c32ce0576098;", 7), Line::Bad);
    }

    #[test]
    fn a_wrong_length_is_skipped() {
        for length in [17, 19, 33, 35, 432] {
            assert_eq!(parse_line(&format!("-{};", payload(length)), 7), Line::Bad);
        }
        for length in [18, 34, 431, 433] {
            assert_eq!(parse_line(&format!("+{};", payload(length)), 7), Line::Bad);
        }
    }

    #[test]
    fn without_a_time_the_feeders_clock_is_used() -> Result<(), String> {
        let now = TIMESTAMP_MODULUS + 99;
        let Line::Reception(reception) = parse_line(&format!("-{};rssi=0.0;", payload(18)), now)
        else {
            return Err("a downlink without t= was refused".to_owned());
        };
        assert_eq!((reception.timestamp, reception.signal), (99, 255));
        let Line::Reception(garbled) = parse_line(&format!("-{};t=soon;", payload(18)), 5) else {
            return Err("a downlink with an unreadable t= was refused".to_owned());
        };
        assert_eq!(garbled.timestamp, 5);
        Ok(())
    }

    #[test]
    fn metadata_and_blank_lines_are_not_receptions() {
        assert_eq!(parse_line("!version=9.0;", 7), Line::Ignored);
        assert_eq!(parse_line("", 7), Line::Ignored);
    }
}
