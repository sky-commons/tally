//! Round-trip probes (RFC-0174 §2.2): a feeder measures how near a relay is by the time an `Echo`
//! takes to come back, never by where the relay says it is. The reply is signed and carries the
//! relay's headroom (how many more feeders it takes, how much of its upload cap is spare, the MLAT
//! cores it offers) and the network it is on, so the feeder ranks a band of relays by measured time
//! and signed capacity alone.

use crate::WireError;
use crate::record::Body;
use crate::signed::{Check, Checked, Fields, Unchecked, signed_record};

/// A probe: a nonce and nothing else (unsigned; the reply names the nonce).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub nonce: u64,
}

impl Check for Echo {
    /// Any nonce.
    fn check(&self) -> Result<(), WireError> {
        Ok(())
    }
}

impl Fields for Echo {
    fn write(echo: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&echo.nonce.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            nonce: reader.u64()?,
        }))
    }
}

/// What a relay has spare, as it declares it now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Headroom {
    /// More feeders it would admit now (RFC-0171 §3.6's admission).
    pub feeder_slots: u32,
    /// Its upload cap less what it is committed to send, bytes a second.
    pub pace_headroom_bytes_per_sec: u64,
    /// Cores it offers for MLAT (RFC-0174 §2.3); zero when it runs none.
    pub mlat_cores: u16,
}

/// A signed answer to an `Echo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoReplyContent {
    /// The probe's nonce.
    pub nonce: u64,
    /// The relay's wall clock, Unix milliseconds.
    pub issued_ms: u64,
    /// The autonomous system the relay says it is on (0 when it does not say): two destinations on
    /// different networks (§2.2).
    pub network: u32,
    pub headroom: Headroom,
}

impl Check for EchoReplyContent {
    /// Every field is a count or a stamp a reader weighs for itself; none is out of range.
    fn check(&self) -> Result<(), WireError> {
        Ok(())
    }
}

impl Fields for EchoReplyContent {
    fn write(reply: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&reply.nonce.to_be_bytes());
        out.extend_from_slice(&reply.issued_ms.to_be_bytes());
        out.extend_from_slice(&reply.network.to_be_bytes());
        out.extend_from_slice(&reply.headroom.feeder_slots.to_be_bytes());
        out.extend_from_slice(&reply.headroom.pace_headroom_bytes_per_sec.to_be_bytes());
        out.extend_from_slice(&reply.headroom.mlat_cores.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            nonce: reader.u64()?,
            issued_ms: reader.u64()?,
            network: reader.u32()?,
            headroom: Headroom {
                feeder_slots: reader.u32()?,
                pace_headroom_bytes_per_sec: reader.u64()?,
                mlat_cores: reader.u16()?,
            },
        }))
    }
}

signed_record!(
    /// A relay's signed `EchoReplyContent`.
    EchoReply,
    EchoReplyContent,
    b"tally echo reply",
    1,
    256
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;

    #[test]
    fn an_echo_reply_round_trips_and_is_bound_to_its_signer() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let content = EchoReplyContent {
            nonce: 7,
            issued_ms: 1_791_244_800_000,
            network: 64_512,
            headroom: Headroom {
                feeder_slots: 120,
                pace_headroom_bytes_per_sec: 1 << 20,
                mlat_cores: 16,
            },
        };
        let reply = EchoReply::sign(&relay, &content)?;
        let back = EchoReply::from_bytes(reply.as_bytes().to_vec())?;
        back.verify()?;
        assert_eq!(back.content()?, content);
        assert_eq!(back.signer()?, relay.public());
        let mut bytes = reply.as_bytes().to_vec();
        bytes[40] ^= 1;
        assert!(EchoReply::from_bytes(bytes).is_ok_and(|bad| bad.verify().is_err()));
        assert_eq!(
            Echo::from_body(&Echo { nonce: 9 }.to_bytes()?)?,
            Echo { nonce: 9 }
        );
        Ok(())
    }
}
