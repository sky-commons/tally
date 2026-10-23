//! The only code that speaks Tally's wire (RFC-0171 §3): the BEAST frames a receiver's decoder
//! emits, the signed batches that carry them, the records that move between feeders, relays and
//! subscribers, and the Noise transport every hop runs over. Every binary goes through this crate.
// The crate that holds every key: no `unsafe` code outside the one read of the host's clock
// (`kernel_clock`). Denied, not forbidden, since `kernel_clock` needs its allow, and a forbid
// refuses that too: the build refuses `unsafe` in every other module, and that `kernel_clock`
// touches no key, so nothing can forge what the types refuse (`key`'s seal), is review's to hold. A test's
// counting allocator is the test-support crate's (`tally_counting`), never this one's.
#![deny(unsafe_code)]

pub mod acars;
pub mod anchor;
pub mod backoff;
pub mod batch;
pub mod beast;
pub mod budget;
pub mod client;
pub mod clock_model;
pub mod clocks;
pub mod credit;
pub mod cut;
pub mod decoded;
pub mod delivery;
pub mod directory;
pub mod fault_proof;
pub mod figures;
pub mod footprint;
/// The one module that calls libc, and so the one allowed `unsafe`: it reaches no key.
#[allow(unsafe_code)]
pub mod kernel_clock;
pub mod key;
pub mod modes;
pub mod noise;
pub mod observation_set;
pub mod positions;
pub mod probe;
pub mod products;
pub mod record;
pub mod region;
pub mod rendezvous;
pub mod sharing;
mod signed;
pub mod site;

pub use anchor::Anchor;
pub use batch::{
    Batch, BatchContent, BatchDraft, Clock, Codec, Description, Location, Observation,
    PublicInfoContent, ReceiverInfo,
};
pub use beast::{Frame, FrameKind};
/// The shared byte buffer batches are held in, so a crate reading them needs no dependency of its own.
pub use bytes::Bytes;
pub use client::{
    ClientEvidence, ClientFaultProof, ClientRecord, PublicReceiverInfo, TaggedPositions,
};
pub use clock_model::{
    Assembler, CLIENT_MODEL_LEN, ClientClockModel, ClientClockModelContent, ClockModel,
    ClockModelContent, ClockModelPart, Manifest, SignedClockModel,
};
pub use credit::{
    EVIDENCE_FORMAT_REFERENCED, Evidence, EvidenceBundle, EvidenceBundleContent, FeederReference,
    FirehoseCredential, FirehoseCredentialContent, ReferencedEvidenceContent,
};
pub use cut::{
    CUT_REFRESH_STEPS, CUT_TTL_STEPS, MAX_CUT_AREAS, MAX_CUT_FROM_MS, MlatCut, MlatCutContent,
};
pub use decoded::{ClientObsView, Decoded, FingerprintKey, ObsRef, ObsView, Undecodable};
pub use delivery::{
    DeliveryAnswer, DeliveryAnswerContent, DeliveryQuery, Possession, SequenceRange, Tag, TagKey,
    TagKeys, TagKeysContent, delivery_tag,
};
pub use directory::{ProviderOffer, ProviderOfferContent, ProviderQuery};
pub use fault_proof::{Fault, FaultProof, ModelFault, SolutionFault, Tolerance};
pub use figures::{
    FIGURES_BUCKET_MS, FIGURES_WINDOW_MS, FeederFigure, FeederFigures, FeederFiguresContent,
    MAX_FEEDER_FIGURES,
};
pub use key::{Handshakes, Identity, NoiseKey, PublicKey, Signer, Signing, Signs};
pub use noise::{Accepted, Outgoing, Reader, Session, Writer};
pub use observation_set::{
    Citations, ObservationIdentity, ObservationSet, Reception, Relation, TaggedSet,
};
pub use positions::{
    AddressedCitation, EnuCovariance, Observed, Positions, Solution, SolutionsContent,
    TaggedSolution, TaggedSolutionsContent, TransmitTime,
};
pub use probe::{Echo, EchoReply, EchoReplyContent, Headroom};
pub use products::{
    ClientObservation, ClientRegionalBatch, ClientRegionalBatchContent, RegionalBatch,
    RegionalBatchContent, RegionalDraft, WorldCandidate, WorldFix, WorldPositions,
    WorldPositionsContent, WorldPrecise,
};
pub use record::{
    HeartbeatTimes, Reason, Record, RelayAddress, Role, SITES_VERSION, Streams, carries_sites,
    least_version,
};
pub use region::{Region, Regions};
pub use sharing::{
    BundleIndex, BundleIndexContent, HaveSummary, ParityChunk, PieceManifest, PieceManifestContent,
    StripeAssignment, StripeReceipt, StripeReceiptContent,
};
pub use signed::Check;
pub use site::{
    PUBLIC_CELL_RESOLUTION, ReceiverSite, ReceiverSiteContent, ReceptionKey, ReceptionTag,
    SHARING_AREA_RESOLUTION, SiteId,
};

/// Everything that can go wrong on the wire. Any of these ends the connection.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("timed out")]
    Timeout,
    #[error("preamble: {0}")]
    Preamble(&'static str),
    #[error("refused by the peer ({reason:?}), retry after {retry_after_secs} s")]
    Refused {
        reason: Reason,
        retry_after_secs: u32,
    },
    #[error("unknown critical record kind {0:#04x}")]
    UnknownCritical(u8),
    #[error("record truncated: needed {needed} bytes, had {had}")]
    Truncated { needed: usize, had: usize },
    #[error("too large for its field: {0}")]
    Oversize(usize),
    #[error("invalid {field}: {value}")]
    Invalid { field: &'static str, value: u64 },
    #[error("bad key: {0}")]
    Key(String),
    #[error("signature does not verify")]
    BadSignature,
    #[error("not a fault proof: {0}")]
    NotAFault(&'static str),
    /// A record not signed because its signer's clock is not judging (`key::Signer::sign_with`).
    #[error("not signed: the signer's clock is not synced")]
    Unsynced,
}
