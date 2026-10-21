//! What the decoders that write text lines share (dump978-fa's raw output, `uat`; the
//! ACARS-family decoders' JSON, `acars`): splitting a stream into bounded lines, and the wall
//! clock their receptions are timestamped by.

use std::time::{SystemTime, UNIX_EPOCH};

use tally_wire::Observation;

/// A wall-clock timestamp is microseconds modulo 2^48, the width of a reception's counter field.
pub const TIMESTAMP_MODULUS: u64 = 1 << 48;

/// The feeder's wall clock in microseconds, for a line that carries none.
pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_micros()).unwrap_or(u64::MAX)
        })
}

/// What one line of a decoder's output was.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Reception(Observation),
    /// Decoder metadata or an empty line: not a reception, and not an error.
    Ignored,
    /// Not a reception this feeder can publish faithfully.
    Bad,
    /// A well-formed frame this feeder does not publish (an ACARS-family decoder's frame that
    /// carries no ACARS message, or one its decoder says is damaged or partial): counted apart
    /// from what is bad.
    NotPublished,
}

/// Splits a byte stream into lines, never holding more than its `max` bytes of one: a stream
/// that is not line shaped is skipped and counted rather than buffered.
pub struct Lines {
    max: usize,
    pending: Vec<u8>,
    overlong: bool,
}

impl Lines {
    /// Lines of at most `max` bytes (without the newline); a longer one is skipped whole.
    pub fn new(max: usize) -> Self {
        Self {
            max,
            pending: Vec::new(),
            overlong: false,
        }
    }

    /// Calls `line` with each complete line in `bytes` (without its newline), and returns how many
    /// were skipped for being too long or not text.
    pub fn push(&mut self, bytes: &[u8], mut line: impl FnMut(&str)) -> u64 {
        let mut skipped = 0;
        for &byte in bytes {
            if byte != b'\n' {
                if self.pending.len() < self.max {
                    self.pending.push(byte);
                } else {
                    self.overlong = true;
                }
                continue;
            }
            if self.overlong {
                skipped += 1;
            } else {
                match std::str::from_utf8(&self.pending) {
                    Ok(text) => line(text),
                    Err(_) => skipped += 1,
                }
            }
            self.pending.clear();
            self.overlong = false;
        }
        skipped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_split_across_reads_and_overlong_lines_are_skipped() {
        let max = 64;
        let mut lines = Lines::new(max);
        let mut seen = Vec::new();
        let skipped = lines.push(b"-ab;t=1", |line| seen.push(line.to_owned()));
        assert_eq!((skipped, seen.len()), (0, 0));
        let skipped = lines.push(b".0;\n!x=1;\n", |line| seen.push(line.to_owned()));
        assert_eq!(skipped, 0);
        assert_eq!(seen, ["-ab;t=1.0;", "!x=1;"]);
        let long = vec![b'a'; max + 10];
        assert_eq!(lines.push(&long, |_| {}), 0);
        assert_eq!(
            lines.push(b"\n\xff\n+ok\n", |line| seen.push(line.to_owned())),
            2
        );
        assert_eq!(seen.last().map(String::as_str), Some("+ok"));
        let exact = vec![b'b'; max];
        lines.push(&exact, |_| {});
        assert_eq!(lines.push(b"\n", |line| seen.push(line.to_owned())), 0);
        assert_eq!(seen.last().map(String::len), Some(max));
    }
}
