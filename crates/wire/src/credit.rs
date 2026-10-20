//! Firehose credit (RFC-0174 §2.1): a client never shares, so its access beyond the free tier is
//! the credit of a relay it is linked to. The relay signs a short-lived `FirehoseCredential` bound
//! to the client's key (the key its Noise handshake proves), and hands it an `EvidenceBundle`: the
//! signed records anyone can check without a history of their own (feeders' descriptions naming
//! the relay, children's stripe receipts for slices it delivered, the answers it gave to delivery
//! checks). Any relay a client reaches checks the bundle and serves it in proportion to what it
//! shows; how much, and the free tier's caps, are the relay's (`tally-relay`'s `credit`).

use blake2::{Blake2s256, Digest};

use crate::WireError;
use crate::batch::{Hash, ReceiverInfo};
use crate::delivery::DeliveryAnswer;
use crate::key::{KEY_LEN, PublicKey};
use crate::record::{Body, MAX_BODY, Streams};
use crate::sharing::StripeReceipt;
use crate::signed::{
    Check, Checked, Fields, Signed, Unchecked, count_u16, put_blob, read_blob, read_count,
    signed_record,
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

/// The format of an [`EvidenceBundle`] that names its feeders' descriptions by reference
/// ([`ReferencedEvidenceContent`]) instead of carrying them whole: what this build signs, since a
/// bundle travels to clients and to every relay, and a description of an old feeder (format 1)
/// carries its site (RFC-0171 §3.5, wire version 3). Same domain as format 1.
pub const EVIDENCE_FORMAT_REFERENCED: u8 = 2;

/// One feeder's description named by reference: whose, when it was issued, and the BLAKE2s of its
/// signed bytes (signature included, so it reveals nothing of what it hashes). The relay judging
/// a bundle resolves it against its own copy of that feeder's description ([`Self::of`] over its
/// copy), never against anything the bundle carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FeederReference {
    pub feeder: PublicKey,
    pub issued_ms: u64,
    pub description: Hash,
}

impl FeederReference {
    const LEN: usize = KEY_LEN + 8 + 32;

    /// The reference to `info`: its signer, its issued time (either format), and its hash.
    pub fn of(info: &ReceiverInfo) -> Result<Self, WireError> {
        Ok(Self {
            feeder: info.receiver()?,
            issued_ms: info.issued_ms()?,
            description: description_hash(info),
        })
    }
}

/// The hash a [`FeederReference`] names a description by: BLAKE2s over every byte of it.
pub fn description_hash(info: &ReceiverInfo) -> Hash {
    Blake2s256::digest(info.as_bytes()).into()
}

/// A relay's evidence with its feeders named by reference (format
/// [`EVIDENCE_FORMAT_REFERENCED`]): receipts and answers are carried whole, as in format 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferencedEvidenceContent {
    pub issued_ms: u64,
    /// Feeders whose descriptions name the relay among their relays, by reference.
    pub feeders: Vec<FeederReference>,
    /// Children's signed receipts for stripe slices the relay delivered.
    pub receipts: Vec<StripeReceipt>,
    /// The relay's own signed answers to delivery checks.
    pub answers: Vec<DeliveryAnswer>,
}

impl Check for ReferencedEvidenceContent {
    /// At most `MAX_EVIDENCE` items of each kind.
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

impl Fields for ReferencedEvidenceContent {
    fn write(bundle: Checked<'_, Self>, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&bundle.issued_ms.to_be_bytes());
        count_u16(out, bundle.feeders.len(), MAX_EVIDENCE)?;
        for reference in &bundle.feeders {
            out.extend_from_slice(reference.feeder.as_bytes());
            out.extend_from_slice(&reference.issued_ms.to_be_bytes());
            out.extend_from_slice(&reference.description);
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
            .map(|_| {
                let fields = reader.bytes(FeederReference::LEN)?;
                let mut issued = [0; 8];
                issued.copy_from_slice(&fields[KEY_LEN..KEY_LEN + 8]);
                let mut description = [0; 32];
                description.copy_from_slice(&fields[KEY_LEN + 8..]);
                Ok(FeederReference {
                    feeder: PublicKey::from_slice(&fields[..KEY_LEN])?,
                    issued_ms: u64::from_be_bytes(issued),
                    description,
                })
            })
            .collect::<Result<_, WireError>>()?;
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

/// What a bundle says, in whichever format this build reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Format 1: feeders' descriptions carried whole.
    Carried(EvidenceBundleContent),
    /// Format 2: feeders' descriptions by reference.
    Referenced(ReferencedEvidenceContent),
}

impl EvidenceBundle {
    /// Signs a format 2 bundle: its feeders by reference, so it carries no description, and no
    /// site, whatever format its feeders signed in.
    pub fn sign_referenced(
        identity: &crate::key::Identity,
        content: &ReferencedEvidenceContent,
    ) -> Result<Self, WireError> {
        let mut body = Vec::new();
        Fields::encode(content, &mut body)?;
        Signed::sign(
            Self::DOMAIN,
            EVIDENCE_FORMAT_REFERENCED,
            identity,
            &body,
            Self::MAX_LEN,
        )
        .map(Self)
    }

    /// The content of a format 2 bundle.
    pub fn referenced(&self) -> Result<ReferencedEvidenceContent, WireError> {
        let mut body = self.0.body(EVIDENCE_FORMAT_REFERENCED)?;
        <ReferencedEvidenceContent as Fields>::decode(&mut body)
    }

    /// What it says, in either format this build reads.
    pub fn evidence(&self) -> Result<Evidence, WireError> {
        match self.format() {
            EVIDENCE_FORMAT_REFERENCED => self.referenced().map(Evidence::Referenced),
            _ => self.content().map(Evidence::Carried),
        }
    }

    /// When it was signed, in either format.
    pub fn issued_ms(&self) -> Result<u64, WireError> {
        Ok(match self.evidence()? {
            Evidence::Carried(content) => content.issued_ms,
            Evidence::Referenced(content) => content.issued_ms,
        })
    }

    /// Whether any description it carries carries a site: a format 1 bundle holding a format 1
    /// description, or one this build cannot read (which it cannot show carries none). A format 2
    /// bundle carries no description at all.
    pub fn carries_site(&self) -> bool {
        match self.evidence() {
            Ok(Evidence::Referenced(_)) => false,
            Ok(Evidence::Carried(content)) => {
                content.feeders.iter().any(ReceiverInfo::carries_site)
            }
            Err(_) => true,
        }
    }
}

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

    fn old_and_new_infos(
        feeder: &Identity,
        relay: &Identity,
    ) -> Result<(ReceiverInfo, ReceiverInfo), WireError> {
        let site = crate::batch::Location {
            lat_e7: 337_490_123,
            lon_e7: -843_880_456,
            alt_m: 312,
            precision_m: 5,
        };
        let old = ReceiverInfo::sign(
            feeder,
            &crate::batch::ReceiverInfoContent {
                issued_ms: 5,
                location: Some(site),
                clock: crate::batch::Clock::Beast,
                software: "tally-feed 0.3".to_owned(),
                relays: vec![relay.public()],
            },
        )?;
        let new = ReceiverInfo::sign_public(
            feeder,
            &crate::batch::PublicInfoContent {
                issued_ms: 6,
                cell: Some(crate::region::Region::public_cell(&site)?),
                clock: crate::batch::Clock::Beast,
                software: "tally-feed".to_owned(),
                relays: vec![relay.public()],
            },
        )?;
        Ok((old, new))
    }

    #[test]
    fn a_referenced_bundle_round_trips_and_names_each_description_by_its_hash()
    -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (old, new) = old_and_new_infos(&feeder, &relay)?;
        let content = ReferencedEvidenceContent {
            issued_ms: 9,
            feeders: vec![FeederReference::of(&old)?, FeederReference::of(&new)?],
            receipts: Vec::new(),
            answers: Vec::new(),
        };
        let bundle = EvidenceBundle::sign_referenced(&relay, &content)?;
        bundle.verify()?;
        assert_eq!(bundle.format(), EVIDENCE_FORMAT_REFERENCED);
        assert_eq!(bundle.referenced()?, content);
        assert_eq!(bundle.evidence()?, Evidence::Referenced(content.clone()));
        assert_eq!(bundle.issued_ms()?, 9);
        assert!(bundle.content().is_err(), "format 1's reader refuses it");
        assert!(!bundle.carries_site());
        // A reference is the feeder, its time and the hash of every byte, whichever format.
        assert_eq!(content.feeders[0].feeder, feeder.public());
        assert_eq!(content.feeders[0].issued_ms, 5);
        assert_eq!(content.feeders[1].issued_ms, 6);
        assert_eq!(
            content.feeders[0].description,
            <[u8; 32]>::from(Blake2s256::digest(old.as_bytes()))
        );
        assert_ne!(
            content.feeders[0].description,
            content.feeders[1].description
        );
        // Nothing of the site is in the bundle's bytes.
        let lat = 337_490_123_i32.to_be_bytes();
        assert!(!bundle.as_bytes().windows(4).any(|window| window == lat));
        // Too many references are refused on sign and on read.
        let mut many = content.clone();
        many.feeders = vec![content.feeders[0]; MAX_EVIDENCE + 1];
        assert!(EvidenceBundle::sign_referenced(&relay, &many).is_err());
        Ok(())
    }

    #[test]
    fn a_carried_bundle_carries_a_site_only_with_an_old_feeders_description()
    -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let feeder = Identity::generate()?;
        let (old, new) = old_and_new_infos(&feeder, &relay)?;
        for (info, carries) in [(old, true), (new, false)] {
            let bundle = EvidenceBundle::sign(
                &relay,
                &EvidenceBundleContent {
                    issued_ms: 9,
                    feeders: vec![info],
                    receipts: Vec::new(),
                    answers: Vec::new(),
                },
            )?;
            assert_eq!(bundle.carries_site(), carries);
            assert!(matches!(bundle.evidence()?, Evidence::Carried(_)));
            assert_eq!(bundle.issued_ms()?, 9);
        }
        Ok(())
    }
}
