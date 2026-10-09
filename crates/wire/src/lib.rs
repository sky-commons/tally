//! The only code that speaks Tally's wire (RFC-0171 §3): the BEAST frames a receiver's decoder
//! emits, the signed batches that carry them, the records that move between feeders, relays and
//! subscribers, and the Noise transport every hop runs over. Every binary goes through this crate.

pub mod backoff;
pub mod batch;
pub mod beast;
pub mod clock_model;
pub mod credit;
pub mod cut;
pub mod decoded;
pub mod delivery;
pub mod directory;
pub mod fault_proof;
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

pub use batch::{
    Batch, BatchContent, BatchDraft, Clock, Codec, Location, Observation, ReceiverInfo,
};
pub use beast::{Frame, FrameKind};
/// The shared byte buffer batches are held in, so a crate reading them needs no dependency of its own.
pub use bytes::Bytes;
pub use clock_model::{
    Assembler, ClockModel, ClockModelContent, ClockModelPart, Manifest, SignedClockModel,
};
pub use credit::{
    EvidenceBundle, EvidenceBundleContent, FirehoseCredential, FirehoseCredentialContent,
};
pub use cut::{MlatCut, MlatCutContent};
pub use decoded::{Decoded, FingerprintKey, ObsRef, ObsView, Undecodable};
pub use delivery::{
    DeliveryAnswer, DeliveryAnswerContent, DeliveryQuery, Possession, SequenceRange, Tag, TagKey,
    TagKeys, TagKeysContent, delivery_tag,
};
pub use directory::{ProviderOffer, ProviderOfferContent, ProviderQuery};
pub use fault_proof::{Fault, FaultProof, ModelFault, SolutionFault, Tolerance};
pub use key::{Identity, PublicKey};
pub use noise::{Accepted, Reader, Session, Writer};
pub use observation_set::{Citations, ObservationIdentity, ObservationSet, Reception, Relation};
pub use positions::{
    AddressedCitation, EnuCovariance, Positions, Solution, SolutionsContent, TransmitTime,
};
pub use probe::{Echo, EchoReply, EchoReplyContent, Headroom};
pub use products::{
    RegionalBatch, RegionalBatchContent, RegionalDraft, WorldCandidate, WorldFix, WorldPositions,
    WorldPositionsContent, WorldPrecise,
};
pub use record::{Reason, Record, RelayAddress, Role, Streams};
pub use region::{Region, Regions};
pub use sharing::{
    BundleIndex, BundleIndexContent, HaveSummary, ParityChunk, PieceManifest, PieceManifestContent,
    StripeAssignment, StripeReceipt, StripeReceiptContent,
};
pub use signed::Check;

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
}
