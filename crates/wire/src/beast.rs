//! BEAST, the binary output readsb and every feeder stack serve on port 30005.
//!
//! A frame is `0x1a`, a type byte, a 48-bit big-endian 12 MHz counter, one signal byte, then the
//! message (2 bytes Mode A/C, 7 Mode-S short, 14 Mode-S long). Any `0x1a` after the type byte is
//! sent twice. Types other than the three message types (readsb's receiver-status frames, for
//! one) are skipped, never forwarded: the network carries receptions, not a decoder's chatter.
//!
//! Two things on a feeder's port are not this receiver's receptions, and the decoder keeps them out
//! (RFC-0171 §3.5): positions an MLAT server sent back, which readsb re-emits with a magic counter,
//! and a stream merging several receivers, which readsb marks with `0xe3` receiver-id frames.

use crate::WireError;

/// The byte that starts a frame, and that is doubled wherever it appears inside one.
pub const ESCAPE: u8 = 0x1a;

/// The longest message a frame carries (Mode-S long).
pub const MAX_MESSAGE: usize = 14;

/// The counter is 48 bits on the wire.
pub const TIMESTAMP_MASK: u64 = (1 << 48) - 1;

/// The counter readsb gives a position an MLAT server computed and sent back ("MLAT" in ASCII).
/// It is someone else's result, never this receiver's reception.
pub const MLAT_RESULT_TIMESTAMP: u64 = 0xFF00_4D4C_4154;

/// The type byte of readsb's receiver-id frame, which precedes frames from a named receiver
/// when one port merges several.
pub const RECEIVER_ID_TYPE: u8 = 0xe3;

const RECEIVER_ID_LEN: usize = 8;

/// The most distinct receiver ids remembered: two already mean the stream is not one receiver.
const RECEIVER_IDS_KEPT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameKind {
    ModeAc,
    ModeSShort,
    ModeSLong,
}

impl FrameKind {
    pub fn from_type_byte(byte: u8) -> Option<Self> {
        match byte {
            b'1' => Some(Self::ModeAc),
            b'2' => Some(Self::ModeSShort),
            b'3' => Some(Self::ModeSLong),
            _ => None,
        }
    }

    pub fn type_byte(self) -> u8 {
        match self {
            Self::ModeAc => b'1',
            Self::ModeSShort => b'2',
            Self::ModeSLong => b'3',
        }
    }

    pub fn message_len(self) -> usize {
        match self {
            Self::ModeAc => 2,
            Self::ModeSShort => 7,
            Self::ModeSLong => 14,
        }
    }

    /// Counter, signal and message: everything after the type byte, unescaped.
    fn body_len(self) -> usize {
        6 + 1 + self.message_len()
    }
}

/// One reception as the receiver's decoder emitted it. The network never decodes the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Frame {
    kind: FrameKind,
    timestamp: u64,
    signal: u8,
    message: [u8; MAX_MESSAGE],
}

impl Frame {
    pub fn new(
        kind: FrameKind,
        timestamp: u64,
        signal: u8,
        message: &[u8],
    ) -> Result<Self, WireError> {
        if message.len() != kind.message_len() {
            return Err(WireError::Invalid {
                field: "message length",
                value: message.len() as u64,
            });
        }
        if timestamp > TIMESTAMP_MASK {
            return Err(WireError::Invalid {
                field: "timestamp",
                value: timestamp,
            });
        }
        let mut bytes = [0; MAX_MESSAGE];
        bytes[..message.len()].copy_from_slice(message);
        Ok(Self {
            kind,
            timestamp,
            signal,
            message: bytes,
        })
    }

    pub fn kind(&self) -> FrameKind {
        self.kind
    }

    /// The receiver's 48-bit counter. Its clock class is the `Receiver` record's to say.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn signal(&self) -> u8 {
        self.signal
    }

    pub fn message(&self) -> &[u8] {
        &self.message[..self.kind.message_len()]
    }

    /// Counter, signal and message, unescaped: the form a record carries.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.timestamp.to_be_bytes()[2..]);
        out.push(self.signal);
        out.extend_from_slice(self.message());
    }

    /// Rebuilds a frame from `write_body`'s bytes.
    pub fn from_body(kind: FrameKind, body: &[u8]) -> Result<Self, WireError> {
        if body.len() != kind.body_len() {
            return Err(WireError::Truncated {
                needed: kind.body_len(),
                had: body.len(),
            });
        }
        let mut counter = [0; 8];
        counter[2..].copy_from_slice(&body[..6]);
        Self::new(kind, u64::from_be_bytes(counter), body[6], &body[7..])
    }

    /// The frame as BEAST, escaped, for a decoder reading it on loopback.
    pub fn encode_beast(&self, out: &mut Vec<u8>) {
        out.push(ESCAPE);
        out.push(self.kind.type_byte());
        let mut body = Vec::with_capacity(self.kind.body_len());
        self.write_body(&mut body);
        for byte in body {
            out.push(byte);
            if byte == ESCAPE {
                out.push(ESCAPE);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Collect {
    Message(FrameKind),
    ReceiverId,
}

impl Collect {
    fn body_len(self) -> usize {
        match self {
            Self::Message(kind) => kind.body_len(),
            Self::ReceiverId => RECEIVER_ID_LEN,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum State {
    /// Between frames, looking for `0x1a`.
    Hunting,
    /// Saw `0x1a` outside a frame; the next byte is a type, or a second `0x1a`.
    Start,
    /// Inside a frame's body.
    Body(Collect),
    /// Inside a body, just after a `0x1a`: a second one is data, anything else begins a frame.
    BodyEscape(Collect),
}

/// Turns a byte stream into frames, across reads that split frames anywhere. A frame cut short
/// by the start of the next one is dropped and counted; the stream resynchronises on its own.
#[derive(Debug)]
pub struct Decoder {
    state: State,
    body: Vec<u8>,
    torn: u64,
    skipped: u64,
    mlat_results: u64,
    receiver_ids: Vec<[u8; RECEIVER_ID_LEN]>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            state: State::Hunting,
            body: Vec::with_capacity(6 + 1 + MAX_MESSAGE),
            torn: 0,
            skipped: 0,
            mlat_results: 0,
            receiver_ids: Vec::new(),
        }
    }

    /// Frames cut short by the start of another.
    pub fn torn(&self) -> u64 {
        self.torn
    }

    /// Frames of a type the network does not carry.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    /// MLAT positions sent back by a server and dropped.
    pub fn mlat_results(&self) -> u64 {
        self.mlat_results
    }

    /// True once the stream has named more than one receiver: it is an aggregate, and a feeder
    /// must not publish it under one receiver's key.
    pub fn is_merged(&self) -> bool {
        self.receiver_ids.len() > 1
    }

    pub fn push(&mut self, bytes: &[u8], mut emit: impl FnMut(Frame)) {
        for &byte in bytes {
            self.state = match self.state {
                State::Hunting if byte == ESCAPE => State::Start,
                State::Hunting => State::Hunting,
                State::Start => self.begin(byte),
                State::Body(collect) if byte == ESCAPE => State::BodyEscape(collect),
                State::Body(collect) => self.take(collect, byte, &mut emit),
                State::BodyEscape(collect) if byte == ESCAPE => self.take(collect, byte, &mut emit),
                State::BodyEscape(_) => {
                    self.torn += 1;
                    self.begin(byte)
                }
            };
        }
    }

    fn begin(&mut self, type_byte: u8) -> State {
        if type_byte == ESCAPE {
            // An escaped 0x1a seen while hunting: data of a frame we never started.
            return State::Hunting;
        }
        let collect = match FrameKind::from_type_byte(type_byte) {
            Some(kind) => Collect::Message(kind),
            None if type_byte == RECEIVER_ID_TYPE => Collect::ReceiverId,
            None => {
                self.skipped += 1;
                return State::Hunting;
            }
        };
        self.body.clear();
        State::Body(collect)
    }

    fn take(&mut self, collect: Collect, byte: u8, emit: &mut impl FnMut(Frame)) -> State {
        self.body.push(byte);
        if self.body.len() < collect.body_len() {
            return State::Body(collect);
        }
        match collect {
            Collect::Message(kind) => match Frame::from_body(kind, &self.body) {
                Ok(frame) if frame.timestamp() == MLAT_RESULT_TIMESTAMP => self.mlat_results += 1,
                Ok(frame) => emit(frame),
                Err(_) => self.torn += 1,
            },
            Collect::ReceiverId => {
                let mut id = [0; RECEIVER_ID_LEN];
                id.copy_from_slice(&self.body);
                if !self.receiver_ids.contains(&id) && self.receiver_ids.len() < RECEIVER_IDS_KEPT {
                    self.receiver_ids.push(id);
                }
            }
        }
        State::Hunting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_frame(timestamp: u64, fill: u8) -> Result<Frame, WireError> {
        Frame::new(FrameKind::ModeSLong, timestamp, 0x80, &[fill; 14])
    }

    fn decode(bytes: &[u8]) -> (Vec<Frame>, Decoder) {
        let mut decoder = Decoder::new();
        let mut frames = Vec::new();
        decoder.push(bytes, |frame| frames.push(frame));
        (frames, decoder)
    }

    #[test]
    fn every_kind_round_trips_through_beast() -> Result<(), WireError> {
        let frames = [
            Frame::new(FrameKind::ModeAc, 1, 2, &[0x12, 0x34])?,
            Frame::new(FrameKind::ModeSShort, TIMESTAMP_MASK, 255, &[7; 7])?,
            long_frame(0x0102_0304_0506, 0x8d)?,
        ];
        let mut bytes = Vec::new();
        for frame in &frames {
            frame.encode_beast(&mut bytes);
        }
        assert_eq!(decode(&bytes).0, frames);
        Ok(())
    }

    #[test]
    fn an_escape_byte_inside_a_frame_is_doubled_and_undoubled() -> Result<(), WireError> {
        let frame = Frame::new(
            FrameKind::ModeSShort,
            0x1a1a_1a1a_1a1a,
            ESCAPE,
            &[ESCAPE; 7],
        )?;
        let mut bytes = Vec::new();
        frame.encode_beast(&mut bytes);
        assert_eq!(bytes.len(), 2 + 2 * (6 + 1 + 7));
        assert_eq!(decode(&bytes).0, vec![frame]);
        Ok(())
    }

    #[test]
    fn a_frame_split_across_reads_at_every_byte_decodes_once() -> Result<(), WireError> {
        let frame = Frame::new(
            FrameKind::ModeSLong,
            0x1a00_0000_001a,
            ESCAPE,
            &[ESCAPE; 14],
        )?;
        let mut bytes = Vec::new();
        frame.encode_beast(&mut bytes);
        for split in 0..=bytes.len() {
            let mut decoder = Decoder::new();
            let mut frames = Vec::new();
            decoder.push(&bytes[..split], |f| frames.push(f));
            decoder.push(&bytes[split..], |f| frames.push(f));
            assert_eq!(frames, vec![frame], "split at {split}");
        }
        Ok(())
    }

    #[test]
    fn a_frame_cut_short_is_counted_and_the_next_one_still_decodes() -> Result<(), WireError> {
        let whole = long_frame(9, 1)?;
        let mut bytes = Vec::new();
        long_frame(8, 2)?.encode_beast(&mut bytes);
        bytes.truncate(10);
        whole.encode_beast(&mut bytes);
        let (frames, decoder) = decode(&bytes);
        assert_eq!(frames, vec![whole]);
        assert_eq!(decoder.torn(), 1);
        Ok(())
    }

    #[test]
    fn other_frame_types_are_skipped_not_forwarded() -> Result<(), WireError> {
        let frame = long_frame(3, 4)?;
        let mut bytes = vec![ESCAPE, b'4', 0, 0, 0, 0, 0, 0, 0];
        frame.encode_beast(&mut bytes);
        let (frames, decoder) = decode(&bytes);
        assert_eq!(frames, vec![frame]);
        assert_eq!(decoder.skipped(), 1);
        Ok(())
    }

    #[test]
    fn mlat_results_sent_back_are_dropped_not_published() -> Result<(), WireError> {
        let heard = long_frame(5, 6)?;
        let mut bytes = Vec::new();
        long_frame(MLAT_RESULT_TIMESTAMP, 7)?.encode_beast(&mut bytes);
        heard.encode_beast(&mut bytes);
        let (frames, decoder) = decode(&bytes);
        assert_eq!(frames, vec![heard]);
        assert_eq!(decoder.mlat_results(), 1);
        Ok(())
    }

    #[test]
    fn two_receiver_ids_mark_the_stream_merged() -> Result<(), WireError> {
        let mut bytes = Vec::new();
        for id in [[1u8; 8], [1; 8], [ESCAPE; 8]] {
            bytes.extend_from_slice(&[ESCAPE, RECEIVER_ID_TYPE]);
            for byte in id {
                bytes.push(byte);
                if byte == ESCAPE {
                    bytes.push(ESCAPE);
                }
            }
            long_frame(1, 2)?.encode_beast(&mut bytes);
        }
        let mut decoder = Decoder::new();
        let mut frames = 0;
        decoder.push(&bytes[..bytes.len() / 2], |_| frames += 1);
        assert!(!decoder.is_merged());
        decoder.push(&bytes[bytes.len() / 2..], |_| frames += 1);
        assert!(decoder.is_merged());
        assert_eq!(frames, 3);
        Ok(())
    }

    #[test]
    fn a_message_of_the_wrong_length_is_refused() {
        assert!(Frame::new(FrameKind::ModeSShort, 0, 0, &[0; 14]).is_err());
        assert!(Frame::new(FrameKind::ModeAc, TIMESTAMP_MASK + 1, 0, &[0; 2]).is_err());
    }
}
