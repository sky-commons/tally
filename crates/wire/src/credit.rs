//! Firehose credit (RFC-0174 §2.1): a client never shares, so its access beyond the free tier is
//! the credit of a relay it is linked to. The relay signs a short-lived `FirehoseCredential` bound
//! to the client's key (the key its Noise handshake proves), and hands it an `EvidenceBundle`: the
//! signed records anyone can check without a history of their own (feeders' descriptions naming
//! the relay, children's stripe receipts for slices it delivered, the answers it gave to delivery
//! checks). Any relay a client reaches checks the bundle and serves it in proportion to what it
//! shows; how much, and the free tier's caps, are the relay's (`tally-relay`'s `credit`).

use crate::WireError;
use crate::batch::ReceiverInfo;
use crate::delivery::DeliveryAnswer;
use crate::key::{KEY_LEN, PublicKey};
use crate::record::{Body, MAX_BODY, Streams};
use crate::sharing::StripeReceipt;
use crate::signed::{
    Check, Checked, Fields, Unchecked, count_u16, put_blob, read_blob, read_count, signed_record,
};

/// The longest a credential lives: a client re-asks its relay.
pub const MAX_CREDENTIAL_LIFETIME_MS: u64 = 60 * 60 * 1000;
/// The most records of each kind one bundle carries: a sample of the evidence, not all of it.
pub const MAX_EVIDENCE: usize = 64;

/// "This client belongs to me", signed by the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirehoseCredentialContent {
    /// The client's key: only a session whose handshake proves it may present the credential.
    pub client: PublicKey,
    /// What it may read on the relay's credit.
    pub products: Streams,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

impl Check for FirehoseCredentialContent {
    /// A lifetime of at most `MAX_CREDENTIAL_LIFETIME_MS`, ending after it begins.
    fn check(&self) -> Result<(), WireError> {
        let lifetime = self.expires_ms.saturating_sub(self.issued_ms);
        if self.expires_ms <= self.issued_ms || lifetime > MAX_CREDENTIAL_LIFETIME_MS {
            return Err(WireError::Invalid {
                field: "credential lifetime",
                value: lifetime,
            });
        }
        Ok(())
    }
}

impl Fields for FirehoseCredentialContent {
    fn write(credential: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(credential.client.as_bytes());
        credential.products.write(out);
        out.extend_from_slice(&credential.issued_ms.to_be_bytes());
        out.extend_from_slice(&credential.expires_ms.to_be_bytes());
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        Ok(Unchecked::new(Self {
            client: PublicKey::from_slice(reader.bytes(KEY_LEN)?)?,
            products: Streams::read(reader)?,
            issued_ms: reader.u64()?,
            expires_ms: reader.u64()?,
        }))
    }
}

signed_record!(
    /// A relay's signed `FirehoseCredentialContent`.
    FirehoseCredential,
    FirehoseCredentialContent,
    b"tally firehose credential",
    1,
    1 + 32 + 32 + 2 + 8 + 8 + 64
);

/// A relay's evidence, each record carried whole with its own signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceBundleContent {
    pub issued_ms: u64,
    /// Feeders' signed descriptions naming the relay among their relays.
    pub feeders: Vec<ReceiverInfo>,
    /// Children's signed receipts for stripe slices the relay delivered.
    pub receipts: Vec<StripeReceipt>,
    /// The relay's own signed answers to delivery checks.
    pub answers: Vec<DeliveryAnswer>,
}

impl Check for EvidenceBundleContent {
    /// At most `MAX_EVIDENCE` records of each kind. Each record is carried whole and checked by
    /// whoever weighs it, by its own signature and content.
    fn check(&self) -> Result<(), WireError> {
        for count in [self.feeders.len(), self.receipts.len(), self.answers.len()] {
            if count > MAX_EVIDENCE {
                return Err(WireError::Invalid {
                    field: "evidence count",
                    value: count as u64,
                });
            }
        }
        Ok(())
    }
}

impl Fields for EvidenceBundleContent {
    fn write(bundle: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&bundle.issued_ms.to_be_bytes());
        count_u16(out, bundle.feeders.len(), MAX_EVIDENCE)?;
        for info in &bundle.feeders {
            put_blob(out, info.as_bytes())?;
        }
        count_u16(out, bundle.receipts.len(), MAX_EVIDENCE)?;
        for receipt in &bundle.receipts {
            put_blob(out, receipt.as_bytes())?;
        }
        count_u16(out, bundle.answers.len(), MAX_EVIDENCE)?;
        for answer in &bundle.answers {
            put_blob(out, answer.as_bytes())?;
        }
        Ok(())
    }

    fn read(reader: &mut Body<'_>) -> Result<Unchecked<Self>, WireError> {
        let issued_ms = reader.u64()?;
        let count = read_count(reader, MAX_EVIDENCE)?;
        let feeders = (0..count)
            .map(|_| ReceiverInfo::from_bytes(read_blob(reader)?))
            .collect::<Result<_, _>>()?;
        let count = read_count(reader, MAX_EVIDENCE)?;
        let receipts = (0..count)
            .map(|_| StripeReceipt::from_bytes(read_blob(reader)?))
            .collect::<Result<_, _>>()?;
        let count = read_count(reader, MAX_EVIDENCE)?;
        let answers = (0..count)
            .map(|_| DeliveryAnswer::from_bytes(read_blob(reader)?))
            .collect::<Result<_, _>>()?;
        Ok(Unchecked::new(Self {
            issued_ms,
            feeders,
            receipts,
            answers,
        }))
    }
}

signed_record!(
    /// A relay's signed `EvidenceBundleContent`: portable, checked record by record.
    EvidenceBundle,
    EvidenceBundleContent,
    b"tally evidence bundle",
    1,
    MAX_BODY
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;

    #[test]
    fn a_credential_is_short_lived_and_a_bundle_carries_its_records_whole() -> Result<(), WireError>
    {
        let relay = Identity::generate()?;
        let client = Identity::generate()?;
        let content = FirehoseCredentialContent {
            client: client.public(),
            products: Streams::RAW.with(Streams::POSITIONS),
            issued_ms: 1_000,
            expires_ms: 1_000 + 15 * 60 * 1000,
        };
        let credential = FirehoseCredential::sign(&relay, &content)?;
        credential.verify()?;
        assert_eq!(credential.content()?, content);
        let forever = FirehoseCredentialContent {
            expires_ms: u64::MAX,
            ..content
        };
        assert!(FirehoseCredential::sign(&relay, &forever).is_err());
        let feeder = Identity::generate()?;
        let info = ReceiverInfo::sign(
            &feeder,
            &crate::batch::ReceiverInfoContent {
                issued_ms: 1,
                location: None,
                clock: crate::batch::Clock::Beast,
                software: "tally-feed".to_owned(),
                relays: vec![relay.public()],
            },
        )?;
        let bundle = EvidenceBundleContent {
            issued_ms: 2_000,
            feeders: vec![info],
            receipts: Vec::new(),
            answers: Vec::new(),
        };
        let signed = EvidenceBundle::sign(&relay, &bundle)?;
        signed.verify()?;
        let back = signed.content()?;
        assert_eq!(back, bundle);
        back.feeders[0].verify()?;
        Ok(())
    }
}
