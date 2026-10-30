//! A relay's signed freshness anchor (RFC-0171 §3.6): its judging clock's reading, signed. A feeder
//! puts the newest one from each relay it holds a session with into the signed bytes of every batch
//! it makes ([`crate::batch::Batch::sign_anchored`]), so the batch proves it was made after that
//! relay's clock read `j_ms`, whatever the feeder's own clock says. Every hop bounds a batch's age
//! by its oldest anchor, judged by the hop's own clock, never the feeder's: the pattern of TLS 1.3's
//! 0-RTT tickets (RFC 8446 §8.3, a ticket's age bounded by the server's own issue time) and of
//! Roughtime's nonces. A relay issues one about every [`crate::budget::ANCHOR_PERIOD`], only
//! while its clock is judging, and sends it to every feeder session as a [`crate::Record::Anchor`].

use crate::WireError;
use crate::key::{KEY_LEN, PublicKey, SIGNATURE_LEN, Signs};
use crate::record::Body;

/// What an anchor's signature is made under: no other signed form verifies as one.
pub const ANCHOR_DOMAIN: &[u8] = b"tally/anchor/v1";
/// An anchor's bytes: the relay's key, its clock's reading and the signature.
pub const ANCHOR_LEN: usize = KEY_LEN + 8 + SIGNATURE_LEN;

/// A relay's signed reading of its judging clock (`J`), Unix milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Anchor {
    /// The relay that signed it.
    pub relay: PublicKey,
    /// Its judging clock when it signed it.
    pub j_ms: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

/// The bytes an anchor's signature covers: its domain, the relay's key and the reading.
fn signed(relay: &PublicKey, j_ms: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ANCHOR_DOMAIN.len() + 1 + KEY_LEN + 8);
    bytes.extend_from_slice(ANCHOR_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(relay.as_bytes());
    bytes.extend_from_slice(&j_ms.to_be_bytes());
    bytes
}

impl Anchor {
    /// The anchor `identity` signs for its clock's reading `j_ms`.
    pub fn sign(identity: &impl Signs, j_ms: u64) -> Self {
        let relay = identity.public();
        Self {
            relay,
            j_ms,
            signature: identity.sign(&signed(&relay, j_ms)),
        }
    }

    /// Whether the relay it names signed it (strict Ed25519). Says nothing of whether that relay
    /// is one the reader knows: a reader holds the key to the relays it knows.
    pub fn verify(&self) -> Result<(), WireError> {
        self.relay
            .verify(&signed(&self.relay, self.j_ms), &self.signature)
    }

    /// Its bytes, as a batch and a record carry them.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.relay.as_bytes());
        out.extend_from_slice(&self.j_ms.to_be_bytes());
        out.extend_from_slice(&self.signature);
    }

    pub(crate) fn read(reader: &mut Body<'_>) -> Result<Self, WireError> {
        let relay = PublicKey::from_bytes(reader.array()?)?;
        let j_ms = reader.u64()?;
        let signature = reader.array()?;
        Ok(Self {
            relay,
            j_ms,
            signature,
        })
    }

    /// An anchor read from its bytes (`write`'s), all of them.
    pub fn from_body(body: &[u8]) -> Result<Self, WireError> {
        let mut reader = Body::new(body);
        let anchor = Self::read(&mut reader)?;
        if reader.remaining() != 0 {
            return Err(WireError::Invalid {
                field: "anchor length",
                value: body.len() as u64,
            });
        }
        Ok(anchor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn an_anchor_verifies_under_its_relay_and_nothing_else_does() -> Result<(), WireError> {
        let relay = Identity::from_seed([3; 32]);
        let anchor = Anchor::sign(&relay, 1_800_000_000_000);
        anchor.verify()?;
        let mut bytes = Vec::new();
        anchor.write(&mut bytes);
        assert_eq!(bytes.len(), ANCHOR_LEN);
        assert_eq!(Anchor::from_body(&bytes)?, anchor);
        // Another reading under the same signature, or another relay's key: refused.
        let moved = Anchor {
            j_ms: anchor.j_ms + 1,
            ..anchor
        };
        assert!(moved.verify().is_err());
        let other = Anchor {
            relay: Identity::from_seed([4; 32]).public(),
            ..anchor
        };
        assert!(other.verify().is_err());
        Ok(())
    }
}
