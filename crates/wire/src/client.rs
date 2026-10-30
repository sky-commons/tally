//! What a client may be sent (wire version 3, `crate::site`): the one record type a relay's client
//! egress is typed against, so no product, present or future, can put a receiver's site, or what
//! derives it, on a client link by accident.
//!
//! A client is every peer that is not a relay-role peer on a version 3 link
//! ([`crate::record::carries_sites`]): free-tier, credited, vouched and linked subscribers, feeders
//! and probes, and every product built on them (the HTTP API, stats). [`ClientRecord`] has no
//! variant for what is relay-only, and the variants whose wire type also has a relay-only form
//! hold a wrapper that can be built only from the client form:
//!
//! | Relay-only (`Record`)                       | Why                                       | A client gets                  |
//! | ------------------------------------------- | ----------------------------------------- | ------------------------------ |
//! | `ReceiverSite`, `ReceiverInfo` format 1     | the exact site                            | `ReceiverInfo` format 2        |
//! | `Batch`, `RelayBatch`, `RegionalBatch`      | counters: reverse MLAT, clock-line ranging | `ClientRegionalBatch`          |
//! | `Positions` format 7                        | (receiver, epoch, counter) per reception  | format 8 (tags)                |
//! | `ClockModel`, `ClockModelPart`              | scope sites, `site_mm`, offsets           | `ClientClockModel`             |
//! | `FaultProof` of raw records, or of models   | carries the records above                 | `FaultProof` of tagged records |
//! | `EvidenceBundle` holding a format 1 info    | carries the site                          | a bundle by reference, or of format 2 infos |
//!
//! `TryFrom<Record>` is the one conversion: it gives back the record it refuses, so egress can
//! count or drop it. `From<ClientRecord> for Record` and [`ClientRecord::encode`] go the other way.

use crate::WireError;
use crate::batch::ReceiverInfo;
use crate::clock_model::ClientClockModel;
use crate::credit::{EvidenceBundle, FirehoseCredential};
use crate::delivery::DeliveryAnswer;
use crate::directory::ProviderOffer;
use crate::fault_proof::FaultProof;
use crate::positions::Positions;
use crate::probe::EchoReply;
use crate::products::{ClientRegionalBatch, WorldPositions};
use crate::record::{Reason, Record, RelayAddress};

/// A format 2 `ReceiverInfo`: a description that carries no site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicReceiverInfo(ReceiverInfo);

impl PublicReceiverInfo {
    /// The description, when it carries no site; it back otherwise.
    pub fn new(info: ReceiverInfo) -> Result<Self, ReceiverInfo> {
        if info.carries_site() {
            return Err(info);
        }
        Ok(Self(info))
    }

    pub fn get(&self) -> &ReceiverInfo {
        &self.0
    }
}

/// A tagged `Positions` record (format 8): no receiver, no counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaggedPositions(Positions);

impl TaggedPositions {
    /// The record, when it is tagged; it back otherwise.
    pub fn new(positions: Positions) -> Result<Self, Positions> {
        if !positions.is_tagged() {
            return Err(positions);
        }
        Ok(Self(positions))
    }

    pub fn get(&self) -> &Positions {
        &self.0
    }
}

/// A fault proof a client may hold: format 1, of two tagged records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientFaultProof(FaultProof);

impl ClientFaultProof {
    /// The proof, when both its records are tagged; it back otherwise (a format 2 proof carries
    /// two full clock models, and a format 1 proof of raw records carries their counters).
    pub fn new(proof: FaultProof) -> Result<Self, FaultProof> {
        let tagged = proof
            .parts()
            .is_ok_and(|parts| parts.iter().all(|(positions, _)| positions.is_tagged()));
        if !tagged {
            return Err(proof);
        }
        Ok(Self(proof))
    }

    pub fn get(&self) -> &FaultProof {
        &self.0
    }
}

/// An evidence bundle a client may hold: one whose every feeder description carries no site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientEvidence(EvidenceBundle);

impl ClientEvidence {
    /// The bundle, when it reads and none of its descriptions carries a site (a format 2 bundle
    /// names its feeders by reference and carries none); it back otherwise.
    pub fn new(bundle: EvidenceBundle) -> Result<Self, EvidenceBundle> {
        if bundle.carries_site() {
            return Err(bundle);
        }
        Ok(Self(bundle))
    }

    pub fn get(&self) -> &EvidenceBundle {
        &self.0
    }
}

/// A record a client may be sent (module docs). Nothing site-bearing fits in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientRecord {
    Welcome {
        version: u16,
    },
    Heartbeat,
    TimedHeartbeat(crate::record::HeartbeatTimes),
    Redirect {
        retry_after_secs: u32,
        hints: Vec<RelayAddress>,
    },
    RelayList(Vec<RelayAddress>),
    RateLimit {
        bytes_per_sec: u32,
        burst: u32,
        wanted_per_sec: Option<u32>,
        clock_ms: Option<u64>,
        error_ms: Option<u64>,
    },
    Goodbye {
        reason: Reason,
        retry_after_secs: u32,
    },
    ReceiverInfo(PublicReceiverInfo),
    Positions(TaggedPositions),
    ClockModel(ClientClockModel),
    FaultProof(ClientFaultProof),
    RegionalBatch(ClientRegionalBatch),
    WorldPositions(WorldPositions),
    EchoReply(EchoReply),
    DeliveryAnswer(DeliveryAnswer),
    ProviderOffer(ProviderOffer),
    FirehoseCredential(FirehoseCredential),
    EvidenceBundle(ClientEvidence),
    FeederFigures(crate::figures::FeederFigures),
    /// A relay's freshness anchor, to its feeder (RFC-0171 §3.6): what the feeder puts in each
    /// batch it signs.
    Anchor(crate::anchor::Anchor),
}

impl TryFrom<Record> for ClientRecord {
    type Error = Record;

    /// The client form of `record`, or `record` back when it is relay-only (module docs).
    fn try_from(record: Record) -> Result<Self, Record> {
        Ok(match record {
            Record::Welcome { version } => Self::Welcome { version },
            Record::Heartbeat => Self::Heartbeat,
            Record::TimedHeartbeat(times) => Self::TimedHeartbeat(times),
            Record::Redirect {
                retry_after_secs,
                hints,
            } => Self::Redirect {
                retry_after_secs,
                hints,
            },
            Record::RelayList(relays) => Self::RelayList(relays),
            Record::RateLimit {
                bytes_per_sec,
                burst,
                wanted_per_sec,
                clock_ms,
                error_ms,
            } => Self::RateLimit {
                bytes_per_sec,
                burst,
                wanted_per_sec,
                clock_ms,
                error_ms,
            },
            Record::Goodbye {
                reason,
                retry_after_secs,
            } => Self::Goodbye {
                reason,
                retry_after_secs,
            },
            Record::ReceiverInfo(info) => PublicReceiverInfo::new(info)
                .map(Self::ReceiverInfo)
                .map_err(Record::ReceiverInfo)?,
            Record::Positions(positions) => TaggedPositions::new(positions)
                .map(Self::Positions)
                .map_err(Record::Positions)?,
            Record::FaultProof(proof) => ClientFaultProof::new(proof)
                .map(Self::FaultProof)
                .map_err(Record::FaultProof)?,
            Record::EvidenceBundle(bundle) => ClientEvidence::new(bundle)
                .map(Self::EvidenceBundle)
                .map_err(Record::EvidenceBundle)?,
            Record::ClientClockModel(model) => Self::ClockModel(model),
            Record::ClientRegionalBatch(batch) => Self::RegionalBatch(batch),
            Record::FeederFigures(figures) => Self::FeederFigures(figures),
            Record::WorldPositions(world) => Self::WorldPositions(world),
            Record::EchoReply(reply) => Self::EchoReply(reply),
            Record::DeliveryAnswer(answer) => Self::DeliveryAnswer(answer),
            Record::ProviderOffer(offer) => Self::ProviderOffer(offer),
            Record::FirehoseCredential(credential) => Self::FirehoseCredential(credential),
            Record::Anchor(anchor) => Self::Anchor(anchor),
            // Relay-only, or never sent to a client at all. Listed, not a wildcard, so a new
            // record kind is a compile error here until someone decides which it is.
            other @ (Record::Hello { .. }
            | Record::Batch(_)
            | Record::Subscribe { .. }
            | Record::RelayBatch(_)
            | Record::ClockModel(_)
            | Record::ClockModelPart(_)
            | Record::Echo(_)
            | Record::DeliveryQuery(_)
            | Record::Retired(_)
            | Record::ProviderQuery(_)
            | Record::StripeAssignment(_)
            | Record::PieceManifest(_)
            | Record::HaveSummary(_)
            | Record::StripeReceipt(_)
            | Record::RegionalBatch(_)
            | Record::Parity(_)
            | Record::BundleIndex(_)
            | Record::MlatCut(_)
            | Record::ReceiverSite(_)) => return Err(other),
        })
    }
}

impl From<ClientRecord> for Record {
    fn from(record: ClientRecord) -> Self {
        match record {
            ClientRecord::Welcome { version } => Self::Welcome { version },
            ClientRecord::Heartbeat => Self::Heartbeat,
            ClientRecord::TimedHeartbeat(times) => Self::TimedHeartbeat(times),
            ClientRecord::Redirect {
                retry_after_secs,
                hints,
            } => Self::Redirect {
                retry_after_secs,
                hints,
            },
            ClientRecord::RelayList(relays) => Self::RelayList(relays),
            ClientRecord::RateLimit {
                bytes_per_sec,
                burst,
                wanted_per_sec,
                clock_ms,
                error_ms,
            } => Self::RateLimit {
                bytes_per_sec,
                burst,
                wanted_per_sec,
                clock_ms,
                error_ms,
            },
            ClientRecord::Goodbye {
                reason,
                retry_after_secs,
            } => Self::Goodbye {
                reason,
                retry_after_secs,
            },
            ClientRecord::ReceiverInfo(info) => Self::ReceiverInfo(info.0),
            ClientRecord::Positions(positions) => Self::Positions(positions.0),
            ClientRecord::ClockModel(model) => Self::ClientClockModel(model),
            ClientRecord::FaultProof(proof) => Self::FaultProof(proof.0),
            ClientRecord::RegionalBatch(batch) => Self::ClientRegionalBatch(batch),
            ClientRecord::FeederFigures(figures) => Self::FeederFigures(figures),
            ClientRecord::WorldPositions(world) => Self::WorldPositions(world),
            ClientRecord::EchoReply(reply) => Self::EchoReply(reply),
            ClientRecord::DeliveryAnswer(answer) => Self::DeliveryAnswer(answer),
            ClientRecord::ProviderOffer(offer) => Self::ProviderOffer(offer),
            ClientRecord::FirehoseCredential(credential) => Self::FirehoseCredential(credential),
            ClientRecord::EvidenceBundle(bundle) => Self::EvidenceBundle(bundle.0),
            ClientRecord::Anchor(anchor) => Self::Anchor(anchor),
        }
    }
}

impl ClientRecord {
    /// The signed bytes it carries and their kind, for every record that is one signed record.
    fn signed(&self) -> Option<(u8, &[u8])> {
        use crate::record::*;
        Some(match self {
            Self::ReceiverInfo(info) => (KIND_RECEIVER_INFO, info.0.as_bytes()),
            Self::Positions(positions) => (KIND_POSITIONS, positions.0.as_bytes()),
            Self::ClockModel(model) => (KIND_CLIENT_CLOCK_MODEL, model.as_bytes()),
            Self::FaultProof(proof) => (KIND_FAULT_PROOF, proof.0.as_bytes()),
            Self::RegionalBatch(batch) => (KIND_CLIENT_REGIONAL_BATCH, batch.as_bytes()),
            Self::WorldPositions(world) => (KIND_WORLD_POSITIONS, world.as_bytes()),
            Self::EchoReply(reply) => (KIND_ECHO_REPLY, reply.as_bytes()),
            Self::DeliveryAnswer(answer) => (KIND_DELIVERY_ANSWER, answer.as_bytes()),
            Self::ProviderOffer(offer) => (KIND_PROVIDER_OFFER, offer.as_bytes()),
            Self::FirehoseCredential(credential) => {
                (KIND_FIREHOSE_CREDENTIAL, credential.as_bytes())
            }
            Self::EvidenceBundle(bundle) => (KIND_EVIDENCE_BUNDLE, bundle.0.as_bytes()),
            Self::FeederFigures(figures) => (KIND_FEEDER_FIGURES, figures.as_bytes()),
            Self::Welcome { .. }
            | Self::Heartbeat
            | Self::TimedHeartbeat(_)
            | Self::Redirect { .. }
            | Self::RelayList(_)
            | Self::RateLimit { .. }
            | Self::Goodbye { .. }
            | Self::Anchor(_) => return None,
        })
    }

    /// Appends the record to `out`, as `Record::encode` writes its `Record`. A signed record's
    /// bytes are written where they are, never copied first.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match self.signed() {
            Some((kind, bytes)) => {
                let length =
                    u16::try_from(bytes.len()).map_err(|_| WireError::Oversize(bytes.len()))?;
                out.push(kind);
                out.extend_from_slice(&length.to_be_bytes());
                out.extend_from_slice(bytes);
                Ok(())
            }
            // A few bytes each: built as a `Record` to be written.
            None => Record::from(self.clone()).encode(out),
        }
    }

    /// What it allocates of its own beside its place, as `Record::allocated` says of a record: a
    /// signed record its bytes' capacity, any other its lists' and strings'.
    pub fn allocated(&self) -> usize {
        use crate::footprint::vec;
        match self {
            Self::Welcome { .. }
            | Self::Heartbeat
            | Self::TimedHeartbeat(_)
            | Self::RateLimit { .. }
            | Self::Goodbye { .. }
            | Self::Anchor(_) => 0,
            Self::Redirect { hints, .. } | Self::RelayList(hints) => {
                vec::<RelayAddress>(hints.capacity())
                    + hints
                        .iter()
                        .map(|hint| hint.address.capacity())
                        .sum::<usize>()
            }
            Self::ReceiverInfo(info) => info.0.allocated(),
            Self::Positions(positions) => positions.0.allocated(),
            Self::ClockModel(model) => model.allocated(),
            Self::FaultProof(proof) => proof.0.allocated(),
            Self::RegionalBatch(batch) => batch.allocated(),
            Self::WorldPositions(world) => world.allocated(),
            Self::EchoReply(reply) => reply.allocated(),
            Self::DeliveryAnswer(answer) => answer.allocated(),
            Self::ProviderOffer(offer) => offer.allocated(),
            Self::FirehoseCredential(credential) => credential.allocated(),
            Self::EvidenceBundle(bundle) => bundle.0.allocated(),
            Self::FeederFigures(figures) => figures.allocated(),
        }
    }

    /// The bytes `encode` writes, as `Record::encoded_len` measures a record.
    pub fn encoded_len(&self) -> usize {
        match self.signed() {
            Some((_, bytes)) => 3 + bytes.len(),
            None => Record::from(self.clone()).encoded_len(),
        }
    }

    /// Its kind byte, as it is written.
    pub fn kind(&self) -> u8 {
        match self.signed() {
            Some((kind, _)) => kind,
            None => Record::from(self.clone()).kind(),
        }
    }

    /// Decodes one record from the front of `bytes` as a client on a session that negotiated
    /// `version` reads it: as `Record::decode`, and a relay-only record is an error (a relay that
    /// sends one to a client broke version 3).
    pub fn decode(bytes: &[u8], version: u16) -> Result<(Option<Self>, usize), WireError> {
        let (record, used) = Record::decode(bytes, version)?;
        match record {
            None => Ok((None, used)),
            Some(record) => {
                let kind = record.kind();
                Self::try_from(record)
                    .map(|client| (Some(client), used))
                    .map_err(|_| WireError::Invalid {
                        field: "relay-only record on a client link",
                        value: u64::from(kind),
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;
    use crate::record::MAX_VERSION;

    #[test]
    fn nothing_site_bearing_converts_and_everything_client_safe_round_trips()
    -> Result<(), WireError> {
        let records = crate::record::tests::site_records()?;
        let refused: Vec<bool> = records
            .iter()
            .map(|record| ClientRecord::try_from(record.clone()).is_err())
            .collect();
        // Site, public info, old info, client model, client regional.
        assert_eq!(refused, vec![true, false, true, false, false]);
        for record in &records {
            assert!(!record.carries_site() || ClientRecord::try_from(record.clone()).is_err());
            let Ok(client) = ClientRecord::try_from(record.clone()) else {
                let mut bytes = Vec::new();
                record.encode(&mut bytes)?;
                assert!(ClientRecord::decode(&bytes, MAX_VERSION).is_err());
                continue;
            };
            let (mut ours, mut theirs) = (Vec::new(), Vec::new());
            client.encode(&mut ours)?;
            record.encode(&mut theirs)?;
            assert_eq!(ours, theirs);
            assert_eq!(client.encoded_len(), ours.len());
            assert_eq!(client.kind(), record.kind());
            assert_eq!(
                ClientRecord::decode(&ours, MAX_VERSION)?,
                (Some(client.clone()), ours.len())
            );
            assert_eq!(Record::from(client), *record);
        }
        Ok(())
    }

    #[test]
    fn raw_counters_and_full_models_never_convert() -> Result<(), WireError> {
        use crate::positions::tests::{fix_at, fixes_of};
        let engine = Identity::generate()?;
        let raw = Positions::sign_fix(
            &engine,
            &fixes_of(0, vec![fix_at([1; 32], &[1, 2, 3], &[1, 2, 3], 10)?]),
        )?;
        let other = Positions::sign_fix(
            &engine,
            &fixes_of(1, vec![fix_at([1; 32], &[1, 2, 3], &[1, 2, 3], 9_000)?]),
        )?;
        let model = crate::ClockModel::sign(
            &engine,
            &crate::ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 0,
                spec_version: 1,
                inputs: [0; 32],
                model: vec![1, 2, 3],
            },
        )?
        .manifest;
        let batch = crate::Batch::sign(
            &engine,
            &crate::BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )?;
        for relay_only in [
            Record::Positions(raw.clone()),
            Record::FaultProof(FaultProof::new(&raw, 0, &other, 0)?),
            Record::FaultProof(FaultProof::models(&model, &model)?),
            Record::ClockModel(model),
            Record::Batch(batch.clone()),
            Record::RelayBatch(batch),
            Record::hello(crate::Role::Relay),
        ] {
            assert!(
                ClientRecord::try_from(relay_only.clone()).is_err(),
                "{relay_only:?}"
            );
        }
        // Control converts, a relay's anchor to its feeder among it.
        for control in [
            Record::Anchor(crate::anchor::Anchor::sign(
                &Identity::from_seed([5; 32]),
                1_800_000_000_000,
            )),
            Record::Heartbeat,
            Record::Welcome { version: 3 },
            Record::Goodbye {
                reason: Reason::Full,
                retry_after_secs: 1,
            },
        ] {
            let client =
                ClientRecord::try_from(control.clone()).map_err(|_| WireError::Invalid {
                    field: "control",
                    value: 0,
                })?;
            let mut bytes = Vec::new();
            client.encode(&mut bytes)?;
            assert_eq!(client.encoded_len(), bytes.len());
            assert_eq!(Record::decode(&bytes, MAX_VERSION)?.0, Some(control));
        }
        Ok(())
    }

    #[test]
    fn an_evidence_bundle_converts_only_without_a_site() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let records = crate::record::tests::site_records()?;
        let infos: Vec<ReceiverInfo> = records
            .into_iter()
            .filter_map(|record| match record {
                Record::ReceiverInfo(info) => Some(info),
                _ => None,
            })
            .collect();
        for info in infos {
            let carries = info.carries_site();
            let bundle = EvidenceBundle::sign(
                &relay,
                &crate::credit::EvidenceBundleContent {
                    issued_ms: 1,
                    feeders: vec![info],
                    receipts: Vec::new(),
                    answers: Vec::new(),
                },
            )?;
            assert_eq!(
                ClientRecord::try_from(Record::EvidenceBundle(bundle)).is_err(),
                carries
            );
        }
        Ok(())
    }
}
