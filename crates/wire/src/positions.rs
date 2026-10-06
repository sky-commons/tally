//! What an MLAT engine publishes (RFC-0171 §3.8): positions it solved, signed by the engine's own
//! key, with the uncertainty of each and how many receivers it used. Like a batch it is immutable
//! once signed, keeps a fixed prefix in every format version (format, engine key, sequence), and
//! is forwarded by relays byte for byte.

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, domain, split_signature, u64_at};
use crate::key::{Identity, KEY_LEN, PublicKey, SIGNATURE_LEN};
use crate::record::Body;

pub const POSITIONS_FORMAT: u8 = 1;
const POSITIONS_DOMAIN: &[u8] = b"tally positions";
/// Format, engine key, boot id, sequence: fixed across every format version.
const PREFIX_LEN: usize = 1 + KEY_LEN + 8 + 8;
/// `alt_ft` when the engine solved no altitude of its own.
const NO_ALTITUDE: i32 = i32::MIN;

/// One solved position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    /// The aircraft's 24-bit ICAO address.
    pub address: u32,
    /// When the transmission was sent, Unix milliseconds.
    pub time_ms: u64,
    pub lat_e7: i32,
    pub lon_e7: i32,
    /// Feet, pressure or geometric as the engine solved it; `None` when it solved none.
    pub alt_ft: Option<i32>,
    /// One standard deviation of the horizontal position, metres.
    pub sigma_m: u32,
    /// Receivers whose observations the solution used.
    pub receivers: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionsContent {
    /// Random per engine process start. With `sequence`, names this record uniquely for its
    /// engine, so a restarted engine starts a new stream instead of being refused as a replay.
    pub boot_id: u64,
    /// 0, 1, 2, ... within one boot; a gap is results some hop did not deliver.
    pub sequence: u64,
    pub issued_ms: u64,
    pub positions: Vec<Position>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Positions {
    bytes: Vec<u8>,
}

impl Positions {
    pub fn sign(identity: &Identity, content: &PositionsContent) -> Result<Self, WireError> {
        let mut bytes = Vec::new();
        bytes.push(POSITIONS_FORMAT);
        bytes.extend_from_slice(identity.public().as_bytes());
        bytes.extend_from_slice(&content.boot_id.to_be_bytes());
        bytes.extend_from_slice(&content.sequence.to_be_bytes());
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        let count = u32::try_from(content.positions.len())
            .map_err(|_| WireError::Oversize(content.positions.len()))?;
        bytes.extend_from_slice(&count.to_be_bytes());
        for position in &content.positions {
            bytes.extend_from_slice(&position.address.to_be_bytes());
            bytes.extend_from_slice(&position.time_ms.to_be_bytes());
            bytes.extend_from_slice(&position.lat_e7.to_be_bytes());
            bytes.extend_from_slice(&position.lon_e7.to_be_bytes());
            bytes.extend_from_slice(&position.alt_ft.unwrap_or(NO_ALTITUDE).to_be_bytes());
            bytes.extend_from_slice(&position.sigma_m.to_be_bytes());
            bytes.extend_from_slice(&position.receivers.to_be_bytes());
        }
        let signature = identity.sign(&domain(POSITIONS_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WireError> {
        if bytes.len() < PREFIX_LEN + SIGNATURE_LEN {
            return Err(WireError::Truncated {
                needed: PREFIX_LEN + SIGNATURE_LEN,
                had: bytes.len(),
            });
        }
        PublicKey::from_slice(&bytes[1..1 + KEY_LEN])?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn engine(&self) -> Result<PublicKey, WireError> {
        PublicKey::from_slice(&self.bytes[1..1 + KEY_LEN])
    }

    pub fn boot_id(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN)
    }

    pub fn sequence(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN + 8)
    }

    pub fn hash(&self) -> Hash {
        Blake2s256::digest(&self.bytes).into()
    }

    pub fn verify(&self) -> Result<(), WireError> {
        let (signed, signature) = split_signature(&self.bytes)?;
        self.engine()?
            .verify(&domain(POSITIONS_DOMAIN, signed), &signature)
    }

    pub fn content(&self) -> Result<PositionsContent, WireError> {
        if self.bytes[0] != POSITIONS_FORMAT {
            return Err(WireError::Invalid {
                field: "positions format",
                value: u64::from(self.bytes[0]),
            });
        }
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let boot_id = reader.u64()?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let count = reader.u32()?;
        let positions = (0..count)
            .map(|_| {
                Ok(Position {
                    address: reader.u32()?,
                    time_ms: reader.u64()?,
                    lat_e7: reader.i32()?,
                    lon_e7: reader.i32()?,
                    alt_ft: Some(reader.i32()?).filter(|alt| *alt != NO_ALTITUDE),
                    sigma_m: reader.u32()?,
                    receivers: reader.u16()?,
                })
            })
            .collect::<Result<_, WireError>>()?;
        Ok(PositionsContent {
            boot_id,
            sequence,
            issued_ms,
            positions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_round_trip_and_verify_and_refuse_tampering() -> Result<(), WireError> {
        let engine = Identity::generate()?;
        let content = PositionsContent {
            boot_id: 0xb007,
            sequence: 3,
            issued_ms: 1_791_220_000_000,
            positions: vec![
                Position {
                    address: 0xa1b2c3,
                    time_ms: 1_791_219_999_000,
                    lat_e7: 374_100_000,
                    lon_e7: -1_221_000_000,
                    alt_ft: Some(4_500),
                    sigma_m: 60,
                    receivers: 5,
                },
                Position {
                    address: 0x400001,
                    time_ms: 1,
                    lat_e7: 0,
                    lon_e7: 0,
                    alt_ft: None,
                    sigma_m: 1_000,
                    receivers: 4,
                },
            ],
        };
        let signed = Positions::sign(&engine, &content)?;
        let back = Positions::from_bytes(signed.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content);
        assert_eq!(
            (back.engine()?, back.boot_id(), back.sequence()),
            (engine.public(), 0xb007, 3)
        );
        let mut bytes = signed.as_bytes().to_vec();
        bytes[60] ^= 1;
        assert!(Positions::from_bytes(bytes)?.verify().is_err());
        Ok(())
    }
}
