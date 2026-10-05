//! What a receiver signs (RFC-0166 §3.2, §4): batches of its receptions, and a description of
//! itself. Both are immutable once signed. Relays forward them byte for byte and never repack
//! them, so anyone downstream can check that a receiver really published what arrives.
//!
//! Every signed form starts with the same prefix in every format version (format byte, signer
//! key, and for a batch its boot id and sequence number) and ends with a 64-byte signature over
//! everything before it. A relay can therefore check, route and deduplicate a batch of a format it
//! does not otherwise understand.

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::beast::{Frame, FrameKind};
use crate::key::{Identity, KEY_LEN, PublicKey, SIGNATURE_LEN};
use crate::record::Body;

/// The batch layout this build writes.
pub const BATCH_FORMAT: u8 = 1;
/// The receiver-info layout this build writes.
pub const RECEIVER_INFO_FORMAT: u8 = 1;

const BATCH_DOMAIN: &[u8] = b"tally batch";
/// What a relay signs its own deduplicated stream under. A separate domain, so a relay's batch can
/// never verify as a receiver's: the signature, not the record kind, says who claims what.
const RELAY_BATCH_DOMAIN: &[u8] = b"tally relay batch";
const RECEIVER_INFO_DOMAIN: &[u8] = b"tally receiver";

/// Format, key, boot id, sequence: the part of a batch fixed across every format version.
const BATCH_PREFIX_LEN: usize = 1 + KEY_LEN + 8 + 8;
const INFO_PREFIX_LEN: usize = 1 + KEY_LEN;

pub type Hash = [u8; 32];

/// What an `Observation`'s bytes are. The 1090 MHz forms are BEAST's own type bytes, so a BEAST
/// frame converts without a table; a reader forwards a format it does not know untouched.
pub mod format {
    /// Mode A/C, 2 bytes.
    pub const MODE_AC: u8 = b'1';
    /// Mode-S short, 7 bytes.
    pub const MODE_S_SHORT: u8 = b'2';
    /// Mode-S long (ADS-B extended squitter among them), 14 bytes.
    pub const MODE_S_LONG: u8 = b'3';
    /// A 978 MHz UAT downlink from an aircraft, 18 (basic) or 34 (long) bytes. Its timestamp is
    /// the receiver's wall clock in microseconds, modulo 2^48, as dump978 reports it.
    pub const UAT_DOWNLINK: u8 = b'D';
    /// A 978 MHz UAT ground uplink (FIS-B weather, TIS-B), 432 bytes, timestamped as a downlink.
    pub const UAT_UPLINK: u8 = b'U';
}

/// What a receiver's decoder emitted for one reception, unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Observation {
    /// What `data` is. BEAST's own type bytes name the 1090 MHz forms (`'1'` Mode A/C, `'2'`
    /// Mode-S short, `'3'` Mode-S long); a later format (978 MHz UAT) takes a new value, and a
    /// relay forwards a format it does not know untouched.
    pub format: u8,
    /// The receiver's 48-bit counter, raw. Never calibrated by anyone before an MLAT engine.
    pub timestamp: u64,
    pub signal: u8,
    pub data: Vec<u8>,
}

impl Observation {
    pub fn from_beast(frame: &Frame) -> Self {
        Self {
            format: frame.kind().type_byte(),
            timestamp: frame.timestamp(),
            signal: frame.signal(),
            data: frame.message().to_vec(),
        }
    }

    /// The BEAST frame, for a format BEAST carries.
    pub fn to_beast(&self) -> Option<Frame> {
        let kind = FrameKind::from_type_byte(self.format)?;
        Frame::new(kind, self.timestamp, self.signal, &self.data).ok()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.push(self.format);
        out.extend_from_slice(&self.timestamp.to_be_bytes()[2..]);
        out.push(self.signal);
        let length =
            u16::try_from(self.data.len()).map_err(|_| WireError::Oversize(self.data.len()))?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(())
    }

    fn decode(reader: &mut Body<'_>) -> Result<Self, WireError> {
        let format = reader.u8()?;
        let mut counter = [0; 8];
        counter[2..].copy_from_slice(reader.bytes(6)?);
        let signal = reader.u8()?;
        let length = usize::from(reader.u16()?);
        Ok(Self {
            format,
            timestamp: u64::from_be_bytes(counter),
            signal,
            data: reader.bytes(length)?.to_vec(),
        })
    }
}

/// The content of a batch before it is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchContent {
    /// Random per process start. With `sequence`, names this batch uniquely for its receiver.
    pub boot_id: u64,
    /// 0, 1, 2, ... within one boot. A gap downstream is data some hop did not deliver.
    pub sequence: u64,
    /// Bumped whenever the receiver's counter may have restarted (readsb restarted, the source
    /// reconnected, the counter went backwards), so counters from before and after never meet.
    pub counter_epoch: u32,
    /// The feeder's wall clock, Unix milliseconds. Informational: it can be wrong.
    pub wall_ms: u64,
    /// Receptions the feeder's own rate ceiling dropped since the previous batch, so a gap the
    /// feeder chose is never mistaken for one a relay caused.
    pub dropped: u32,
    /// The hash of this boot's previous batch (zeros for the first), chaining a boot's batches so
    /// a receiver cannot sign two different histories.
    pub previous: Hash,
    pub observations: Vec<Observation>,
}

/// A signed batch, as bytes. Immutable: forwarding never re-encodes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    bytes: Vec<u8>,
}

impl Batch {
    /// A receiver's batch of its own receptions.
    pub fn sign(identity: &Identity, content: &BatchContent) -> Result<Self, WireError> {
        Self::sign_in(BATCH_DOMAIN, identity, content)
    }

    /// A relay's batch of its deduplicated stream (`Record::RelayBatch`).
    pub fn sign_as_relay(identity: &Identity, content: &BatchContent) -> Result<Self, WireError> {
        Self::sign_in(RELAY_BATCH_DOMAIN, identity, content)
    }

    fn sign_in(
        label: &[u8],
        identity: &Identity,
        content: &BatchContent,
    ) -> Result<Self, WireError> {
        let mut bytes = Vec::new();
        bytes.push(BATCH_FORMAT);
        bytes.extend_from_slice(identity.public().as_bytes());
        bytes.extend_from_slice(&content.boot_id.to_be_bytes());
        bytes.extend_from_slice(&content.sequence.to_be_bytes());
        bytes.extend_from_slice(&content.counter_epoch.to_be_bytes());
        bytes.extend_from_slice(&content.wall_ms.to_be_bytes());
        bytes.extend_from_slice(&content.dropped.to_be_bytes());
        bytes.extend_from_slice(&content.previous);
        let count = u32::try_from(content.observations.len())
            .map_err(|_| WireError::Oversize(content.observations.len()))?;
        bytes.extend_from_slice(&count.to_be_bytes());
        for observation in &content.observations {
            observation.encode(&mut bytes)?;
        }
        let signature = identity.sign(&domain(label, &bytes));
        bytes.extend_from_slice(&signature);
        Ok(Self { bytes })
    }

    /// Accepts any format whose fixed prefix is well formed. Does not check the signature.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() < BATCH_PREFIX_LEN + SIGNATURE_LEN {
            return Err(WireError::Truncated {
                needed: BATCH_PREFIX_LEN + SIGNATURE_LEN,
                had: bytes.len(),
            });
        }
        PublicKey::from_slice(&bytes[1..1 + KEY_LEN])?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    pub fn receiver(&self) -> Result<PublicKey, WireError> {
        PublicKey::from_slice(&self.bytes[1..1 + KEY_LEN])
    }

    pub fn boot_id(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN)
    }

    pub fn sequence(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN + 8)
    }

    /// BLAKE2s over the whole signed batch: its identity for deduplication and the chain.
    pub fn hash(&self) -> Hash {
        Blake2s256::digest(&self.bytes).into()
    }

    /// True when the receiver it names signed it as its own receptions.
    pub fn verify(&self) -> Result<(), WireError> {
        self.verify_in(BATCH_DOMAIN)
    }

    /// True when the relay it names signed it as its deduplicated stream.
    pub fn verify_as_relay(&self) -> Result<(), WireError> {
        self.verify_in(RELAY_BATCH_DOMAIN)
    }

    fn verify_in(&self, label: &[u8]) -> Result<(), WireError> {
        let (signed, signature) = split_signature(&self.bytes)?;
        self.receiver()?.verify(&domain(label, signed), &signature)
    }

    /// The content, for a format this build reads.
    pub fn content(&self) -> Result<BatchContent, WireError> {
        if self.format() != BATCH_FORMAT {
            return Err(WireError::Invalid {
                field: "batch format",
                value: u64::from(self.format()),
            });
        }
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let counter_epoch = reader.u32()?;
        let wall_ms = reader.u64()?;
        let dropped = reader.u32()?;
        let previous = reader.array()?;
        let count = reader.u32()?;
        let observations = (0..count)
            .map(|_| Observation::decode(&mut reader))
            .collect::<Result<_, _>>()?;
        Ok(BatchContent {
            boot_id,
            sequence,
            counter_epoch,
            wall_ms,
            dropped,
            previous,
            observations,
        })
    }
}

/// The receiver's timestamp class, as mlat-client's `--input-type` names it, so an MLAT engine
/// knows how far to trust the counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clock {
    Unknown,
    /// readsb or dump1090 on an RTL-SDR: a 12 MHz counter of the sample clock.
    Dump1090,
    Beast,
    Radarcape12Mhz,
    RadarcapeGps,
    Other(u8),
}

impl Clock {
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::Unknown => Some("unknown"),
            Self::Dump1090 => Some("dump1090"),
            Self::Beast => Some("beast"),
            Self::Radarcape12Mhz => Some("radarcape_12mhz"),
            Self::RadarcapeGps => Some("radarcape_gps"),
            Self::Other(_) => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Unknown,
            Self::Dump1090,
            Self::Beast,
            Self::Radarcape12Mhz,
            Self::RadarcapeGps,
        ]
        .into_iter()
        .find(|clock| clock.name() == Some(name))
    }

    fn byte(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Dump1090 => 1,
            Self::Beast => 2,
            Self::Radarcape12Mhz => 3,
            Self::RadarcapeGps => 4,
            Self::Other(byte) => byte,
        }
    }

    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Unknown,
            1 => Self::Dump1090,
            2 => Self::Beast,
            3 => Self::Radarcape12Mhz,
            4 => Self::RadarcapeGps,
            other => Self::Other(other),
        }
    }
}

/// Where the antenna is: degrees times 10^7, metres above the WGS84 ellipsoid, and how precise
/// the owner chose to be. Published exactly unless the owner rounds it (RFC-0166 §8.3); a rounded
/// location says so here, and an MLAT engine gives it less weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    pub lat_e7: i32,
    pub lon_e7: i32,
    pub alt_m: i32,
    pub precision_m: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverInfoContent {
    /// Unix milliseconds. The newest a relay has seen for a key wins.
    pub issued_ms: u64,
    pub location: Option<Location>,
    pub clock: Clock,
    /// The feeder's name and version, for operators.
    pub software: String,
    /// The relays this receiver chose to publish to. Signed, so a relay's standing (how many
    /// real antennas chose it) can be counted later by anyone, under any rule, from what
    /// receivers said themselves.
    pub relays: Vec<PublicKey>,
}

/// A receiver's signed description of itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverInfo {
    bytes: Vec<u8>,
}

impl ReceiverInfo {
    pub fn sign(identity: &Identity, content: &ReceiverInfoContent) -> Result<Self, WireError> {
        let mut bytes = Vec::new();
        bytes.push(RECEIVER_INFO_FORMAT);
        bytes.extend_from_slice(identity.public().as_bytes());
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        match content.location {
            None => bytes.push(0),
            Some(location) => {
                bytes.push(1);
                bytes.extend_from_slice(&location.lat_e7.to_be_bytes());
                bytes.extend_from_slice(&location.lon_e7.to_be_bytes());
                bytes.extend_from_slice(&location.alt_m.to_be_bytes());
                bytes.extend_from_slice(&location.precision_m.to_be_bytes());
            }
        }
        bytes.push(content.clock.byte());
        let software = content.software.as_bytes();
        let length =
            u8::try_from(software.len()).map_err(|_| WireError::Oversize(software.len()))?;
        bytes.push(length);
        bytes.extend_from_slice(software);
        let count = u8::try_from(content.relays.len())
            .map_err(|_| WireError::Oversize(content.relays.len()))?;
        bytes.push(count);
        for relay in &content.relays {
            bytes.extend_from_slice(relay.as_bytes());
        }
        let signature = identity.sign(&domain(RECEIVER_INFO_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() < INFO_PREFIX_LEN + SIGNATURE_LEN {
            return Err(WireError::Truncated {
                needed: INFO_PREFIX_LEN + SIGNATURE_LEN,
                had: bytes.len(),
            });
        }
        PublicKey::from_slice(&bytes[1..1 + KEY_LEN])?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn receiver(&self) -> Result<PublicKey, WireError> {
        PublicKey::from_slice(&self.bytes[1..1 + KEY_LEN])
    }

    pub fn verify(&self) -> Result<(), WireError> {
        let (signed, signature) = split_signature(&self.bytes)?;
        self.receiver()?
            .verify(&domain(RECEIVER_INFO_DOMAIN, signed), &signature)
    }

    pub fn content(&self) -> Result<ReceiverInfoContent, WireError> {
        if self.bytes[0] != RECEIVER_INFO_FORMAT {
            return Err(WireError::Invalid {
                field: "receiver info format",
                value: u64::from(self.bytes[0]),
            });
        }
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[INFO_PREFIX_LEN..]);
        let issued_ms = reader.u64()?;
        let location = match reader.u8()? {
            0 => None,
            _ => Some(Location {
                lat_e7: reader.i32()?,
                lon_e7: reader.i32()?,
                alt_m: reader.i32()?,
                precision_m: reader.u32()?,
            }),
        };
        let clock = Clock::from_byte(reader.u8()?);
        let length = usize::from(reader.u8()?);
        let software = String::from_utf8_lossy(reader.bytes(length)?).into_owned();
        let count = reader.u8()?;
        let relays = (0..count)
            .map(|_| PublicKey::from_slice(reader.bytes(KEY_LEN)?))
            .collect::<Result<_, _>>()?;
        Ok(ReceiverInfoContent {
            issued_ms,
            location,
            clock,
            software,
            relays,
        })
    }
}

pub(crate) fn domain(label: &[u8], signed: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(label.len() + 1 + signed.len());
    message.extend_from_slice(label);
    message.push(0);
    message.extend_from_slice(signed);
    message
}

pub(crate) fn split_signature(bytes: &[u8]) -> Result<(&[u8], [u8; SIGNATURE_LEN]), WireError> {
    let at = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(WireError::Truncated {
            needed: SIGNATURE_LEN,
            had: bytes.len(),
        })?;
    let mut signature = [0; SIGNATURE_LEN];
    signature.copy_from_slice(&bytes[at..]);
    Ok((&bytes[..at], signature))
}

pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut array = [0; 8];
    array.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content() -> Result<BatchContent, WireError> {
        Ok(BatchContent {
            boot_id: 0xfeed,
            sequence: 7,
            counter_epoch: 2,
            wall_ms: 1_791_220_000_000,
            dropped: 3,
            previous: [9; 32],
            observations: vec![
                Observation::from_beast(&Frame::new(
                    FrameKind::ModeSLong,
                    0xffff_ffff_ffff,
                    200,
                    &[0x8d; 14],
                )?),
                Observation {
                    format: b'U',
                    timestamp: 1,
                    signal: 2,
                    data: vec![0; 432],
                },
            ],
        })
    }

    #[test]
    fn a_batch_round_trips_and_verifies() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let batch = Batch::sign(&identity, &content()?)?;
        let back = Batch::from_bytes(batch.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content()?);
        assert_eq!(back.receiver()?, identity.public());
        assert_eq!((back.boot_id(), back.sequence()), (0xfeed, 7));
        assert_eq!(back.hash(), batch.hash());
        Ok(())
    }

    #[test]
    fn any_changed_byte_fails_verification() -> Result<(), WireError> {
        let batch = Batch::sign(&Identity::generate()?, &content()?)?;
        for at in 0..batch.as_bytes().len() {
            let mut bytes = batch.as_bytes().to_vec();
            bytes[at] ^= 1;
            let tampered = Batch::from_bytes(bytes);
            assert!(
                tampered.is_err() || tampered.is_ok_and(|batch| batch.verify().is_err()),
                "byte {at}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_relay_batch_never_verifies_as_a_receivers_and_back() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let derived = Batch::sign_as_relay(&relay, &content()?)?;
        derived.verify_as_relay()?;
        assert!(derived.verify().is_err());
        let own = Batch::sign(&relay, &content()?)?;
        assert!(own.verify_as_relay().is_err());
        Ok(())
    }

    #[test]
    fn a_batch_signature_cannot_pass_as_receiver_info() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let batch = Batch::sign(&identity, &content()?)?;
        let info = ReceiverInfo::from_bytes(batch.as_bytes().to_vec())?;
        assert!(info.verify().is_err());
        Ok(())
    }

    #[test]
    fn receiver_info_round_trips_with_and_without_location() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        for location in [
            None,
            Some(Location {
                lat_e7: 374_100_000,
                lon_e7: -1_221_000_000,
                alt_m: -12,
                precision_m: 0,
            }),
        ] {
            let content = ReceiverInfoContent {
                issued_ms: 5,
                location,
                clock: Clock::Dump1090,
                software: "tally-feed 0.1.0".to_owned(),
                relays: vec![
                    Identity::generate()?.public(),
                    Identity::generate()?.public(),
                ],
            };
            let info = ReceiverInfo::sign(&identity, &content)?;
            let back = ReceiverInfo::from_bytes(info.as_bytes().to_vec())?;
            back.verify()?;
            assert_eq!(back.content()?, content);
        }
        Ok(())
    }

    #[test]
    fn a_beast_observation_converts_back() -> Result<(), WireError> {
        let frame = Frame::new(FrameKind::ModeSShort, 9, 8, &[7; 7])?;
        assert_eq!(Observation::from_beast(&frame).to_beast(), Some(frame));
        Ok(())
    }

    #[test]
    fn clock_names_are_mlat_clients() {
        assert_eq!(Clock::from_name("dump1090"), Some(Clock::Dump1090));
        assert_eq!(Clock::from_name("radarcape_gps"), Some(Clock::RadarcapeGps));
        assert_eq!(Clock::from_name("sdr"), None);
        assert_eq!(Clock::from_byte(77), Clock::Other(77));
    }
}
