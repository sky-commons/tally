//! Records (RFC-0171 §3.4): a kind byte, a two-byte big-endian body length, the body. A Noise
//! message carries whole records only.
//!
//! Feeders never update, so the format is built to be extended without them (§3.4's rules):
//! - an unknown kind is skipped, unless its high bit marks it critical, which ends the session;
//! - a body may carry bytes after the fields a reader knows, and they are ignored, so a field is
//!   added by appending it;
//! - an enum value a reader does not know is kept as `Other`, never an error.

use crate::WireError;
use crate::batch::{Batch, ReceiverInfo};
use crate::clock_model::{ClockModel, ClockModelPart};
use crate::credit::{EvidenceBundle, FirehoseCredential};
use crate::delivery::{DeliveryAnswer, DeliveryQuery};
use crate::directory::{ProviderOffer, ProviderQuery};
use crate::fault_proof::FaultProof;
use crate::key::{KEY_LEN, PublicKey};
use crate::positions::Positions;
use crate::probe::{Echo, EchoReply};
use crate::products::{RegionalBatch, WorldPositions, WorldPrecise};
use crate::region::Region;
use crate::sharing::{
    BundleIndex, HaveSummary, ParityChunk, PieceManifest, StripeAssignment, StripeReceipt,
};
use crate::signed::Fields;

/// The oldest wire version this build speaks: 2 (RFC-0171 §3.3, RFC-0174 §2.10). Version 1 is
/// retired before any feeder beyond Flightlines' own ran it (adsb.im ships version 2, RFC-0174
/// §5), so a responder refuses an initiator whose highest version is 1 with
/// `Goodbye { reason: Version }`, and the forever rule (a relay answers every version a feeder
/// ever shipped) starts at 2.
pub const MIN_VERSION: u16 = 2;
/// Version 2 (RFC-0174 §2.2, §2.10): the network records (echo, delivery checks, the provider
/// directory, sharing, credit, the products), compressed batches, the `Probe` role and 16-bit
/// `Streams`.
pub const MAX_VERSION: u16 = 2;

/// The bit of a kind byte that says "a reader that does not know this kind must stop".
pub const CRITICAL: u8 = 0x80;

pub const KIND_HELLO: u8 = 0x01;
pub const KIND_WELCOME: u8 = 0x02;
pub const KIND_BATCH: u8 = 0x03;
pub const KIND_RECEIVER_INFO: u8 = 0x04;
pub const KIND_HEARTBEAT: u8 = 0x05;
pub const KIND_REDIRECT: u8 = 0x06;
pub const KIND_RELAY_LIST: u8 = 0x07;
pub const KIND_RATE_LIMIT: u8 = 0x08;
pub const KIND_GOODBYE: u8 = 0x09;
pub const KIND_SUBSCRIBE: u8 = 0x0a;
pub const KIND_RELAY_BATCH: u8 = 0x0b;
pub const KIND_POSITIONS: u8 = 0x0c;
pub const KIND_CLOCK_MODEL: u8 = 0x0d;
pub const KIND_FAULT_PROOF: u8 = 0x0e;
pub const KIND_CLOCK_MODEL_PART: u8 = 0x0f;
pub const KIND_PROVISIONAL: u8 = 0x10;
// RFC-0174 §2.10, version 2. Non-critical, as every new kind is unless ignoring it would be wrong.
pub const KIND_ECHO: u8 = 0x11;
pub const KIND_ECHO_REPLY: u8 = 0x12;
/// Retired (RFC-0181 §7): the delivery check's first form, a proof of possession over the feeder's
/// nonce, which needs the member to hold every batch's bytes until it is asked. A build that knows
/// the tagged form reads these two kinds as `Record::Retired` and nothing of their bodies, and
/// answers the query with `Record::refusal`; it never writes either. The kind bytes are never
/// reused, so no build reads one form as the other.
pub const KIND_POSSESSION_QUERY: u8 = 0x13;
pub const KIND_POSSESSION_ANSWER: u8 = 0x14;
pub const KIND_PROVIDER_OFFER: u8 = 0x15;
pub const KIND_PROVIDER_QUERY: u8 = 0x16;
pub const KIND_STRIPE_ASSIGNMENT: u8 = 0x17;
pub const KIND_PIECE_MANIFEST: u8 = 0x18;
pub const KIND_HAVE_SUMMARY: u8 = 0x19;
pub const KIND_STRIPE_RECEIPT: u8 = 0x1a;
pub const KIND_FIREHOSE_CREDENTIAL: u8 = 0x1b;
pub const KIND_EVIDENCE_BUNDLE: u8 = 0x1c;
pub const KIND_WORLD_POSITIONS: u8 = 0x1d;
pub const KIND_REGIONAL_BATCH: u8 = 0x1e;
pub const KIND_PARITY: u8 = 0x1f;
pub const KIND_BUNDLE_INDEX: u8 = 0x20;
pub const KIND_WORLD_PRECISE: u8 = 0x21;
// RFC-0181 §7: the delivery check by tags made on arrival. Kinds of their own, not the retired
// ones' bytes, so a build that predates them skips them as unknown (non-critical) rather than
// misreading one form as the other, and an answer's signed record is a format of its own too.
pub const KIND_DELIVERY_QUERY: u8 = 0x22;
pub const KIND_DELIVERY_ANSWER: u8 = 0x23;

/// Kinds this build knows were retired: read as `Record::Retired`, never written.
pub const RETIRED_KINDS: [u8; 2] = [KIND_POSSESSION_QUERY, KIND_POSSESSION_ANSWER];

/// Every kind this build reads and writes, in kind order: what a table over kinds is checked
/// against, so a kind added here and nowhere else is a failing test.
pub const KINDS: [u8; 33] = [
    KIND_HELLO,
    KIND_WELCOME,
    KIND_BATCH,
    KIND_RECEIVER_INFO,
    KIND_HEARTBEAT,
    KIND_REDIRECT,
    KIND_RELAY_LIST,
    KIND_RATE_LIMIT,
    KIND_GOODBYE,
    KIND_SUBSCRIBE,
    KIND_RELAY_BATCH,
    KIND_POSITIONS,
    KIND_CLOCK_MODEL,
    KIND_FAULT_PROOF,
    KIND_CLOCK_MODEL_PART,
    KIND_PROVISIONAL,
    KIND_ECHO,
    KIND_ECHO_REPLY,
    KIND_PROVIDER_OFFER,
    KIND_PROVIDER_QUERY,
    KIND_STRIPE_ASSIGNMENT,
    KIND_PIECE_MANIFEST,
    KIND_HAVE_SUMMARY,
    KIND_STRIPE_RECEIPT,
    KIND_FIREHOSE_CREDENTIAL,
    KIND_EVIDENCE_BUNDLE,
    KIND_WORLD_POSITIONS,
    KIND_REGIONAL_BATCH,
    KIND_PARITY,
    KIND_BUNDLE_INDEX,
    KIND_WORLD_PRECISE,
    KIND_DELIVERY_QUERY,
    KIND_DELIVERY_ANSWER,
];

const HEADER_LEN: usize = 3;
/// The largest body a record may have and still travel in one Noise message.
pub const MAX_BODY: usize = crate::noise::MAX_PLAINTEXT - HEADER_LEN;

/// What the initiator of a connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A receiver publishing its own batches.
    Feeder,
    /// A consumer reading a relay's streams.
    Subscriber,
    /// Another relay.
    Relay,
    /// An MLAT engine: subscribes like a subscriber and publishes its own signed `Positions`.
    Engine,
    /// A measurement session (RFC-0171 §3.3, RFC-0174 §2.2): it may send only `Echo` and
    /// `DeliveryQuery`, is answered, and is never admitted as a feeder or a subscriber, so probing
    /// a relay takes none of its feeder slots and is sent none of its streams. A responder ends a
    /// probe that sends anything else ([`Role::may_send`]).
    Probe,
    Other(u8),
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Self::Feeder => 1,
            Self::Subscriber => 2,
            Self::Relay => 3,
            Self::Engine => 4,
            Self::Probe => 5,
            Self::Other(byte) => byte,
        }
    }

    fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Feeder,
            2 => Self::Subscriber,
            3 => Self::Relay,
            4 => Self::Engine,
            5 => Self::Probe,
            other => Self::Other(other),
        }
    }

    /// Whether a session of this role may send `record` after its `Hello`. Only a `Probe` is held
    /// to a list here (`Echo` and `DeliveryQuery`); what every other role may publish is the
    /// responder's to decide, by the keys that signed it.
    pub fn may_send(self, record: &Record) -> bool {
        match self {
            // A retired delivery query too: an old feeder's probe is answered with a refusal
            // (`Record::refusal`), not ended as a breach of the protocol.
            Self::Probe => matches!(
                record,
                Record::Echo(_) | Record::DeliveryQuery(_) | Record::Retired(KIND_POSSESSION_QUERY)
            ),
            _ => true,
        }
    }
}

/// The most regions one `Subscribe` may name. A relay ends a session that names more; a subscriber
/// refuses to send more. Part of the protocol, so both sides read it from here.
pub const MAX_REGIONS: usize = 64;

/// Which of a relay's streams a subscriber wants (RFC-0171 §3.6), as bits: two bytes on the wire
/// (version 2), so products after the eighth have bits of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Streams(pub u16);

impl Streams {
    /// Receivers' own signed batches: every copy, for MLAT and research.
    pub const RAW: Self = Self(1);
    /// One copy of each message, in batches the relay signs.
    pub const DEDUPLICATED: Self = Self(2);
    /// Positions MLAT engines solved, and the fault proofs against them: a reader of positions
    /// is who must act on a proof.
    pub const POSITIONS: Self = Self(4);
    /// MLAT engines' clock models (RFC-0171 §3.8.1), for verifying solutions against raw and for
    /// engines adopting another's model as a prior. Its own bit, since most readers of positions
    /// never need them.
    pub const CLOCK_MODELS: Self = Self(8);
    /// Provisional positions (RFC-0171 §3.8.1): solved a second or so after a transmission under
    /// the latest model of its tile, carried forward, and superseded by the final positions that
    /// follow. Opt-in, and its own bit: a reader of final positions is never sent them unasked.
    pub const PROVISIONAL: Self = Self(16);
    /// The regional product (RFC-0174 §2.11): each area's deduplicated receptions as its origin
    /// relay signs them (`RegionalBatch`), by the subscription's regions.
    pub const REGIONAL: Self = Self(32);
    /// The world product (RFC-0174 §2.11): one fix per aircraft per second (`WorldPositions`).
    pub const WORLD: Self = Self(64);
    /// The precise world product (RFC-0174 §2.11): one fix per aircraft per second from final MLAT
    /// fixes, sealed once they can have come (`WorldPrecise`).
    pub const WORLD_PRECISE: Self = Self(128);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Its two bytes, big-endian, as every record that names streams writes them.
    pub(crate) fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_be_bytes());
    }

    pub(crate) fn read(reader: &mut Body<'_>) -> Result<Self, WireError> {
        reader.u16().map(Self)
    }
}

/// Why a relay closes a session. A feeder backs off by `retry_after_secs` whatever the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// No version in the initiator's range.
    Version,
    /// The relay is at capacity: to a feeder or a subscriber, it holds every one it admits; to a
    /// relay whose link brings it data (a sharing member's, RFC-0174 §2.5), it holds every member
    /// session its plan admits. A relay told so takes the sender as a full provider: it routes
    /// what it would have sent it to the next members of that area's trees, and does not dial it
    /// again until the wait it was given has passed, doubled on each refusal that follows.
    Full,
    /// The relay is shutting down or retiring.
    Leaving,
    /// The relay refuses this key.
    Refused,
    /// The peer broke the protocol.
    Protocol,
    /// The subscriber fell behind what it asked for (RFC-0181 §8): its queue held more than its
    /// bound of bytes or of time, so the relay let it go rather than slow anyone else. Not that
    /// the relay is full: the subscriber may come back at once. A reader that predates it reads
    /// `Other(6)`.
    FellBehind,
    /// The peer sent a record of a form this build has retired (`RETIRED_KINDS`) and will never
    /// answer: an old feeder's delivery query (RFC-0181 §7). A reader that predates it reads
    /// `Other(7)`, and a feeder that predates the tagged check takes any `Goodbye` to its query as
    /// no answer, never as evidence.
    Retired,
    /// The peer sent more than this relay's ceiling for its role allows (its bytes a second, or
    /// its signed records a second): the sender's abuse, not this relay's capacity. A relay told so
    /// is not a full provider, and the relay saying it files its shortfalls against the sender as
    /// for any link that brought nothing (RFC-0174 §2.5): a parent that overruns its child's
    /// ceiling to be turned away delivers nothing and is held to it. Before, it was `Full`, which
    /// exempted such a parent from every shortfall. A reader that predates it reads `Other(8)`,
    /// which no reader takes as full.
    OverCeiling,
    Other(u8),
}

impl Reason {
    fn byte(self) -> u8 {
        match self {
            Self::Version => 1,
            Self::Full => 2,
            Self::Leaving => 3,
            Self::Refused => 4,
            Self::Protocol => 5,
            Self::FellBehind => 6,
            Self::Retired => 7,
            Self::OverCeiling => 8,
            Self::Other(byte) => byte,
        }
    }

    fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Version,
            2 => Self::Full,
            3 => Self::Leaving,
            4 => Self::Refused,
            5 => Self::Protocol,
            6 => Self::FellBehind,
            7 => Self::Retired,
            8 => Self::OverCeiling,
            other => Self::Other(other),
        }
    }
}

/// A relay a feeder may dial: where, and the key it must answer with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAddress {
    pub key: PublicKey,
    /// `host:port`.
    pub address: String,
}

impl RelayAddress {
    /// `HOST:PORT=KEY`, as every command line names a relay. A base64 key may end in `=`, and an
    /// address never holds one: split at the first.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (address, key) = text
            .split_once('=')
            .ok_or_else(|| format!("{text}: expected HOST:PORT=KEY"))?;
        let key = PublicKey::from_base64(key).map_err(|error| format!("{text}: {error}"))?;
        Ok(Self {
            key,
            address: address.to_owned(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// The initiator's first record: the versions it speaks and what it is.
    Hello {
        min_version: u16,
        max_version: u16,
        role: Role,
    },
    /// The responder's answer: the version both will speak from here on.
    Welcome {
        version: u16,
    },
    /// A receiver's signed receptions (`batch.rs`). Relays forward it byte for byte.
    Batch(Batch),
    /// A receiver's signed description of itself. Sent at start and whenever it changes.
    ReceiverInfo(ReceiverInfo),
    Heartbeat,
    /// "Leave me", from a relay. The relays named are hints; the feeder still chooses by its
    /// own rules, so a redirect can never steer a feeder somewhere it would not go.
    Redirect {
        retry_after_secs: u32,
        hints: Vec<RelayAddress>,
    },
    /// Relays this relay knows of, offered as hints for a feeder's list.
    RelayList(Vec<RelayAddress>),
    /// The most the relay wants from this feeder. A feeder may go lower, never higher than its
    /// owner's own ceiling.
    RateLimit {
        bytes_per_sec: u32,
        burst: u32,
    },
    /// The relay is closing the session.
    Goodbye {
        reason: Reason,
        retry_after_secs: u32,
    },
    /// What a subscriber wants from here on: streams, and regions by the receivers' declared
    /// locations (none means the whole world). A subscriber that never sends one gets every
    /// receiver's raw batches.
    Subscribe {
        streams: Streams,
        regions: Vec<Region>,
    },
    /// A batch the relay itself signed: its deduplicated stream.
    RelayBatch(Batch),
    /// Positions an MLAT engine solved and signed.
    Positions(Positions),
    /// An MLAT engine's signed clock model manifest, which its format 3 positions cite by id.
    ClockModel(ClockModel),
    /// One part of a clock model too large for its manifest, checked against the manifest's
    /// hash of it.
    ClockModelPart(ClockModelPart),
    /// Two signed solutions of the same inputs that disagree: anyone's, checked before it is
    /// forwarded.
    FaultProof(FaultProof),
    /// Provisional positions an MLAT engine solved and signed: a `Positions` of a provisional
    /// format (`Positions::is_provisional`), under a kind of its own so a relay routes it by kind
    /// alone and a reader that does not know it skips it. Each kind refuses the other's formats.
    Provisional(Positions),
    /// A round-trip probe (RFC-0174 §2.2).
    Echo(Echo),
    /// A relay's signed answer to an `Echo`, with its headroom.
    EchoReply(EchoReply),
    /// A feeder giving a sharing group member its tag keys, and in an audit asking it for the
    /// tags it made of some of its batches (RFC-0181 §7).
    DeliveryQuery(DeliveryQuery),
    /// A member's signed answer: the tag it made per batch, or that it does not take the area.
    DeliveryAnswer(DeliveryAnswer),
    /// A record of a kind this build knows was retired (`RETIRED_KINDS`): nothing of its body is
    /// read, it is never written, and a responder answers it with `refusal`.
    Retired(u8),
    /// A relay's signed offer of a cell (RFC-0174 §2.6).
    ProviderOffer(ProviderOffer),
    /// "Who offers this cell?"
    ProviderQuery(ProviderQuery),
    /// A sharing group member asking its parent for stripes (RFC-0174 §2.5).
    StripeAssignment(StripeAssignment),
    /// An origin's signed list of one cell's records of one second.
    PieceManifest(PieceManifest),
    /// Which seconds a member holds whole.
    HaveSummary(HaveSummary),
    /// A child's signed receipt for a stripe slice.
    StripeReceipt(StripeReceipt),
    /// A relay's signed credential for a client it vouches for (RFC-0174 §2.1).
    FirehoseCredential(FirehoseCredential),
    /// A relay's portable evidence.
    EvidenceBundle(EvidenceBundle),
    /// One second of the world product (RFC-0174 §2.11).
    WorldPositions(WorldPositions),
    /// One area's deduplicated receptions, signed by its origin relay.
    RegionalBatch(RegionalBatch),
    /// A chunk of a sharing group's parity stripe (RFC-0174 §2.5).
    Parity(ParityChunk),
    /// A bundler's signed index of one second of a parent cell (RFC-0174 §2.6).
    BundleIndex(BundleIndex),
    /// One second of the precise world product (RFC-0174 §2.11).
    WorldPrecise(WorldPrecise),
}

impl Record {
    pub fn hello(role: Role) -> Self {
        Self::Hello {
            min_version: MIN_VERSION,
            max_version: MAX_VERSION,
            role,
        }
    }

    /// The record's kind byte, as it is written.
    pub fn kind(&self) -> u8 {
        match self {
            Self::Hello { .. } => KIND_HELLO,
            Self::Welcome { .. } => KIND_WELCOME,
            Self::Batch(_) => KIND_BATCH,
            Self::ReceiverInfo(_) => KIND_RECEIVER_INFO,
            Self::Heartbeat => KIND_HEARTBEAT,
            Self::Redirect { .. } => KIND_REDIRECT,
            Self::RelayList(_) => KIND_RELAY_LIST,
            Self::RateLimit { .. } => KIND_RATE_LIMIT,
            Self::Goodbye { .. } => KIND_GOODBYE,
            Self::Subscribe { .. } => KIND_SUBSCRIBE,
            Self::RelayBatch(_) => KIND_RELAY_BATCH,
            Self::Positions(_) => KIND_POSITIONS,
            Self::ClockModel(_) => KIND_CLOCK_MODEL,
            Self::ClockModelPart(_) => KIND_CLOCK_MODEL_PART,
            Self::FaultProof(_) => KIND_FAULT_PROOF,
            Self::Provisional(_) => KIND_PROVISIONAL,
            Self::Echo(_) => KIND_ECHO,
            Self::EchoReply(_) => KIND_ECHO_REPLY,
            Self::DeliveryQuery(_) => KIND_DELIVERY_QUERY,
            Self::DeliveryAnswer(_) => KIND_DELIVERY_ANSWER,
            Self::ProviderOffer(_) => KIND_PROVIDER_OFFER,
            Self::ProviderQuery(_) => KIND_PROVIDER_QUERY,
            Self::StripeAssignment(_) => KIND_STRIPE_ASSIGNMENT,
            Self::PieceManifest(_) => KIND_PIECE_MANIFEST,
            Self::HaveSummary(_) => KIND_HAVE_SUMMARY,
            Self::StripeReceipt(_) => KIND_STRIPE_RECEIPT,
            Self::FirehoseCredential(_) => KIND_FIREHOSE_CREDENTIAL,
            Self::EvidenceBundle(_) => KIND_EVIDENCE_BUNDLE,
            Self::WorldPositions(_) => KIND_WORLD_POSITIONS,
            Self::RegionalBatch(_) => KIND_REGIONAL_BATCH,
            Self::Parity(_) => KIND_PARITY,
            Self::BundleIndex(_) => KIND_BUNDLE_INDEX,
            Self::WorldPrecise(_) => KIND_WORLD_PRECISE,
            Self::Retired(kind) => *kind,
        }
    }

    /// What a responder sends back for a record of a retired form: for an old feeder's delivery
    /// query, a `Goodbye` saying the form is retired (the session ends; the feeder reads it as no
    /// answer from this member, never as evidence either way). Nothing for any other record.
    pub fn refusal(&self) -> Option<Record> {
        match self {
            Self::Retired(KIND_POSSESSION_QUERY) => Some(Self::Goodbye {
                reason: Reason::Retired,
                // This relay will never answer that form.
                retry_after_secs: 86_400,
            }),
            _ => None,
        }
    }

    /// The bytes `encode` writes for this record, header included: a signed record's own bytes
    /// are read, never copied; any other is encoded to be measured (each a few bytes, or a
    /// parity chunk's). The one measure of a record's size, for what it costs a queue or a store.
    pub fn encoded_len(&self) -> usize {
        let signed = match self {
            Self::Batch(batch) | Self::RelayBatch(batch) => batch.as_bytes().len(),
            Self::ReceiverInfo(info) => info.as_bytes().len(),
            Self::Positions(positions) | Self::Provisional(positions) => positions.as_bytes().len(),
            Self::ClockModel(model) => model.as_bytes().len(),
            Self::ClockModelPart(part) => part.as_bytes().len(),
            Self::FaultProof(proof) => proof.as_bytes().len(),
            Self::EchoReply(signed) => signed.as_bytes().len(),
            Self::DeliveryAnswer(signed) => signed.as_bytes().len(),
            Self::ProviderOffer(signed) => signed.as_bytes().len(),
            Self::PieceManifest(signed) => signed.as_bytes().len(),
            Self::StripeReceipt(signed) => signed.as_bytes().len(),
            Self::FirehoseCredential(signed) => signed.as_bytes().len(),
            Self::EvidenceBundle(signed) => signed.as_bytes().len(),
            Self::WorldPositions(signed) => signed.as_bytes().len(),
            Self::RegionalBatch(signed) => signed.as_bytes().len(),
            Self::BundleIndex(signed) => signed.as_bytes().len(),
            Self::WorldPrecise(signed) => signed.as_bytes().len(),
            _ => {
                let mut out = Vec::new();
                return match self.encode(&mut out) {
                    Ok(()) => out.len(),
                    // Too large to send: measured by what it would have taken.
                    Err(_) => out.len().max(HEADER_LEN),
                };
            }
        };
        HEADER_LEN + signed
    }

    /// Appends the record to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let start = out.len();
        out.push(self.kind());
        out.extend_from_slice(&[0, 0]);
        match self {
            Self::Hello {
                min_version,
                max_version,
                role,
            } => {
                out.extend_from_slice(&min_version.to_be_bytes());
                out.extend_from_slice(&max_version.to_be_bytes());
                out.push(role.byte());
            }
            Self::Welcome { version } => out.extend_from_slice(&version.to_be_bytes()),
            Self::Batch(batch) => out.extend_from_slice(batch.as_bytes()),
            Self::ReceiverInfo(info) => out.extend_from_slice(info.as_bytes()),
            Self::Heartbeat => {}
            Self::Redirect {
                retry_after_secs,
                hints,
            } => {
                out.extend_from_slice(&retry_after_secs.to_be_bytes());
                encode_relays(hints, out)?;
            }
            Self::RelayList(relays) => encode_relays(relays, out)?,
            Self::RateLimit {
                bytes_per_sec,
                burst,
            } => {
                out.extend_from_slice(&bytes_per_sec.to_be_bytes());
                out.extend_from_slice(&burst.to_be_bytes());
            }
            Self::Goodbye {
                reason,
                retry_after_secs,
            } => {
                out.push(reason.byte());
                out.extend_from_slice(&retry_after_secs.to_be_bytes());
            }
            Self::Subscribe { streams, regions } => {
                streams.write(out);
                let count =
                    u16::try_from(regions.len()).map_err(|_| WireError::Oversize(regions.len()))?;
                out.extend_from_slice(&count.to_be_bytes());
                for region in regions {
                    out.extend_from_slice(&region.as_u64().to_be_bytes());
                }
            }
            Self::RelayBatch(batch) => out.extend_from_slice(batch.as_bytes()),
            Self::Positions(positions) | Self::Provisional(positions) => {
                out.extend_from_slice(positions.as_bytes())
            }
            Self::ClockModel(model) => out.extend_from_slice(model.as_bytes()),
            Self::ClockModelPart(part) => out.extend_from_slice(part.as_bytes()),
            Self::FaultProof(proof) => out.extend_from_slice(proof.as_bytes()),
            Self::Echo(echo) => echo.encode(out)?,
            Self::DeliveryQuery(query) => query.encode(out)?,
            Self::ProviderQuery(query) => query.encode(out)?,
            Self::StripeAssignment(assignment) => assignment.encode(out)?,
            Self::HaveSummary(have) => have.encode(out)?,
            Self::EchoReply(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::DeliveryAnswer(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::ProviderOffer(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::PieceManifest(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::StripeReceipt(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::FirehoseCredential(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::EvidenceBundle(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::WorldPositions(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::RegionalBatch(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::Parity(chunk) => chunk.encode(out)?,
            Self::BundleIndex(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::WorldPrecise(signed) => out.extend_from_slice(signed.as_bytes()),
            Self::Retired(kind) => {
                out.truncate(start);
                return Err(WireError::Invalid {
                    field: "retired record kind",
                    value: u64::from(*kind),
                });
            }
        }
        let body = out.len() - start - HEADER_LEN;
        let length = u16::try_from(body).map_err(|_| WireError::Oversize(body))?;
        out[start + 1..start + HEADER_LEN].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    /// Decodes every record in one message's plaintext. Unknown non-critical kinds are skipped
    /// and counted in the return value.
    pub fn decode_message(mut bytes: &[u8], out: &mut Vec<Record>) -> Result<usize, WireError> {
        let mut skipped = 0;
        while !bytes.is_empty() {
            let (record, used) = Self::decode(bytes)?;
            match record {
                Some(record) => out.push(record),
                None => skipped += 1,
            }
            bytes = &bytes[used..];
        }
        Ok(skipped)
    }

    /// Decodes one record from the front of `bytes`: `None` for a kind this build does not know
    /// and may skip.
    pub fn decode(bytes: &[u8]) -> Result<(Option<Record>, usize), WireError> {
        Self::decode_knowing(bytes, Self::knows)
    }

    /// Whether this build reads `kind`: every kind it writes (`KINDS`), and the ones it knows
    /// were retired (`RETIRED_KINDS`).
    pub fn knows(kind: u8) -> bool {
        KINDS.contains(&kind) || RETIRED_KINDS.contains(&kind)
    }

    /// As `decode`, as a reader that knows only the kinds `knows` admits (an older build, whose
    /// kinds were a prefix of these): a kind it does not know is put to the one rule for unknown
    /// kinds (§3.4), skipped unless critical. `decode` is this with `Record::knows`.
    pub(crate) fn decode_knowing(
        bytes: &[u8],
        knows: impl Fn(u8) -> bool,
    ) -> Result<(Option<Record>, usize), WireError> {
        let header = take(bytes, 0, HEADER_LEN)?;
        let kind = header[0];
        let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
        let body = take(bytes, HEADER_LEN, length)?;
        if !knows(kind) {
            return Self::unknown(kind, length);
        }
        let mut reader = Body::new(body);
        let record = match kind {
            KIND_HELLO => Self::Hello {
                min_version: reader.u16()?,
                max_version: reader.u16()?,
                role: Role::from_byte(reader.u8()?),
            },
            KIND_WELCOME => Self::Welcome {
                version: reader.u16()?,
            },
            KIND_BATCH => Self::Batch(Batch::from_bytes(body.to_vec())?),
            KIND_RECEIVER_INFO => Self::ReceiverInfo(ReceiverInfo::from_bytes(body.to_vec())?),
            KIND_HEARTBEAT => Self::Heartbeat,
            KIND_REDIRECT => Self::Redirect {
                retry_after_secs: reader.u32()?,
                hints: decode_relays(&mut reader)?,
            },
            KIND_RELAY_LIST => Self::RelayList(decode_relays(&mut reader)?),
            KIND_RATE_LIMIT => Self::RateLimit {
                bytes_per_sec: reader.u32()?,
                burst: reader.u32()?,
            },
            KIND_GOODBYE => Self::Goodbye {
                reason: Reason::from_byte(reader.u8()?),
                retry_after_secs: reader.u32()?,
            },
            KIND_SUBSCRIBE => {
                let streams = Streams::read(&mut reader)?;
                let count = reader.u16()?;
                let regions = (0..count)
                    .map(|_| Region::from_u64(reader.u64()?))
                    .collect::<Result<_, _>>()?;
                Self::Subscribe { streams, regions }
            }
            KIND_RELAY_BATCH => Self::RelayBatch(Batch::from_bytes(body.to_vec())?),
            KIND_POSITIONS => Self::Positions(positions_of(body, false)?),
            KIND_PROVISIONAL => Self::Provisional(positions_of(body, true)?),
            KIND_CLOCK_MODEL => Self::ClockModel(ClockModel::from_bytes(body.to_vec())?),
            KIND_CLOCK_MODEL_PART => {
                Self::ClockModelPart(ClockModelPart::from_bytes(body.to_vec())?)
            }
            KIND_FAULT_PROOF => Self::FaultProof(FaultProof::from_bytes(body.to_vec())?),
            KIND_ECHO => Self::Echo(Echo::from_body(body)?),
            KIND_ECHO_REPLY => Self::EchoReply(EchoReply::from_bytes(body.to_vec())?),
            KIND_DELIVERY_QUERY => Self::DeliveryQuery(DeliveryQuery::from_body(body)?),
            KIND_DELIVERY_ANSWER => {
                Self::DeliveryAnswer(DeliveryAnswer::from_bytes(body.to_vec())?)
            }
            KIND_PROVIDER_OFFER => Self::ProviderOffer(ProviderOffer::from_bytes(body.to_vec())?),
            KIND_PROVIDER_QUERY => Self::ProviderQuery(ProviderQuery::from_body(body)?),
            KIND_STRIPE_ASSIGNMENT => Self::StripeAssignment(StripeAssignment::from_body(body)?),
            KIND_PIECE_MANIFEST => Self::PieceManifest(PieceManifest::from_bytes(body.to_vec())?),
            KIND_HAVE_SUMMARY => Self::HaveSummary(HaveSummary::from_body(body)?),
            KIND_STRIPE_RECEIPT => Self::StripeReceipt(StripeReceipt::from_bytes(body.to_vec())?),
            KIND_FIREHOSE_CREDENTIAL => {
                Self::FirehoseCredential(FirehoseCredential::from_bytes(body.to_vec())?)
            }
            KIND_EVIDENCE_BUNDLE => {
                Self::EvidenceBundle(EvidenceBundle::from_bytes(body.to_vec())?)
            }
            KIND_WORLD_POSITIONS => {
                Self::WorldPositions(WorldPositions::from_bytes(body.to_vec())?)
            }
            KIND_REGIONAL_BATCH => Self::RegionalBatch(RegionalBatch::from_bytes(body.to_vec())?),
            KIND_PARITY => Self::Parity(ParityChunk::from_body(body)?),
            KIND_BUNDLE_INDEX => Self::BundleIndex(BundleIndex::from_bytes(body.to_vec())?),
            KIND_WORLD_PRECISE => Self::WorldPrecise(WorldPrecise::from_bytes(body.to_vec())?),
            KIND_POSSESSION_QUERY | KIND_POSSESSION_ANSWER => Self::Retired(kind),
            _ => return Self::unknown(kind, length),
        };
        Ok((Some(record), HEADER_LEN + length))
    }

    /// The one rule for a kind a reader does not know (§3.4): skipped, its `length` bytes of body
    /// unread, unless its critical bit says a reader that does not know it must stop.
    fn unknown(kind: u8, length: usize) -> Result<(Option<Record>, usize), WireError> {
        if kind & CRITICAL != 0 {
            return Err(WireError::UnknownCritical(kind));
        }
        Ok((None, HEADER_LEN + length))
    }
}

/// A `Positions` body under its kind: provisional formats under the provisional kind only, and
/// every other format under the positions kind only.
fn positions_of(body: &[u8], provisional: bool) -> Result<Positions, WireError> {
    let positions = Positions::from_bytes(body.to_vec())?;
    if positions.is_provisional() != provisional {
        return Err(WireError::Invalid {
            field: "positions format for its kind",
            value: u64::from(positions.format()),
        });
    }
    Ok(positions)
}

fn encode_relays(relays: &[RelayAddress], out: &mut Vec<u8>) -> Result<(), WireError> {
    let count = u8::try_from(relays.len()).map_err(|_| WireError::Oversize(relays.len()))?;
    out.push(count);
    for relay in relays {
        out.extend_from_slice(relay.key.as_bytes());
        let address = relay.address.as_bytes();
        let length = u8::try_from(address.len()).map_err(|_| WireError::Oversize(address.len()))?;
        out.push(length);
        out.extend_from_slice(address);
    }
    Ok(())
}

fn decode_relays(reader: &mut Body<'_>) -> Result<Vec<RelayAddress>, WireError> {
    let count = reader.u8()?;
    (0..count)
        .map(|_| {
            let key = PublicKey::from_slice(reader.bytes(KEY_LEN)?)?;
            let length = usize::from(reader.u8()?);
            let address = std::str::from_utf8(reader.bytes(length)?)
                .map_err(|_| WireError::Invalid {
                    field: "relay address",
                    value: length as u64,
                })?
                .to_owned();
            Ok(RelayAddress { key, address })
        })
        .collect()
}

fn take(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], WireError> {
    bytes.get(at..at + len).ok_or(WireError::Truncated {
        needed: at + len,
        had: bytes.len(),
    })
}

/// Reads fields from the front of a body. What is left after the known fields is ignored.
pub(crate) struct Body<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Body<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes have been read.
    pub(crate) fn position(&self) -> usize {
        self.at
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let slice = take(self.bytes, self.at, len)?;
        self.at += len;
        Ok(slice)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut array = [0; N];
        array.copy_from_slice(self.bytes(N)?);
        Ok(array)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, WireError> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// An IEEE 754 single, big-endian.
    pub(crate) fn f32(&mut self) -> Result<f32, WireError> {
        Ok(f32::from_bits(self.u32()?))
    }

    /// A receiver's 48-bit counter, six bytes big-endian.
    pub(crate) fn counter(&mut self) -> Result<u64, WireError> {
        let mut counter = [0; 8];
        counter[2..].copy_from_slice(self.bytes(6)?);
        Ok(u64::from_be_bytes(counter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;

    fn relay(port: u16) -> Result<RelayAddress, WireError> {
        Ok(RelayAddress {
            key: Identity::generate()?.public(),
            address: format!("relay.example:{port}"),
        })
    }

    fn every_record() -> Result<Vec<Record>, WireError> {
        Ok(vec![
            Record::hello(Role::Feeder),
            Record::Hello {
                min_version: 1,
                max_version: 9,
                role: Role::Other(42),
            },
            Record::Welcome { version: 1 },
            Record::Heartbeat,
            Record::Redirect {
                retry_after_secs: 30,
                hints: vec![relay(1)?, relay(2)?],
            },
            Record::RelayList(vec![relay(3)?]),
            Record::RelayList(Vec::new()),
            Record::RateLimit {
                bytes_per_sec: 64_000,
                burst: 128_000,
            },
            Record::Goodbye {
                reason: Reason::Full,
                retry_after_secs: 600,
            },
            Record::Goodbye {
                reason: Reason::Other(200),
                retry_after_secs: 0,
            },
            Record::Goodbye {
                reason: Reason::FellBehind,
                retry_after_secs: 0,
            },
            Record::Goodbye {
                reason: Reason::OverCeiling,
                retry_after_secs: 60,
            },
            Record::hello(Role::Engine),
            Record::hello(Role::Probe),
            // A bit past the eighth: `Streams` is two bytes.
            Record::Subscribe {
                streams: Streams(0x8000).with(Streams::RAW),
                regions: Vec::new(),
            },
            Record::Subscribe {
                streams: Streams::RAW.with(Streams::POSITIONS),
                regions: vec![Region::containing(
                    &crate::batch::Location {
                        lat_e7: 374_400_000,
                        lon_e7: -1_221_400_000,
                        alt_m: 0,
                        precision_m: 0,
                    },
                    3,
                )?],
            },
            Record::Subscribe {
                streams: Streams::DEDUPLICATED,
                regions: Vec::new(),
            },
            Record::Subscribe {
                streams: Streams::POSITIONS.with(Streams::CLOCK_MODELS),
                regions: Vec::new(),
            },
        ])
    }

    /// A record's measured size is what encoding it writes, for every kind: the one size every
    /// queue and store charges a record by.
    #[test]
    fn a_records_encoded_len_is_what_it_encodes_to() -> Result<(), WireError> {
        for record in every_record()? {
            let mut out = Vec::new();
            record.encode(&mut out)?;
            assert_eq!(record.encoded_len(), out.len(), "{:?}", record.kind());
        }
        Ok(())
    }

    #[test]
    fn the_mlat_records_round_trip_in_one_message() -> Result<(), WireError> {
        use crate::positions::tests::{solution, solutions};
        let engine = Identity::generate()?;
        let first = Positions::sign_solutions(
            &engine,
            &solutions(0, vec![solution([1; 32], &[1, 2, 3], 10)?]),
        )?;
        let second = Positions::sign_solutions(
            &engine,
            &solutions(1, vec![solution([1; 32], &[1, 2, 3], 9_000)?]),
        )?;
        let model = ClockModel::sign(
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
        let part = crate::ClockModelPart::new(model.id(), 0, &[4, 5, 6]);
        let records = vec![
            Record::Positions(first.clone()),
            Record::ClockModel(model),
            Record::ClockModelPart(part),
            Record::FaultProof(FaultProof::new(&first, 0, &second, 0)?),
        ];
        let mut message = Vec::new();
        for record in &records {
            record.encode(&mut message)?;
        }
        let mut back = Vec::new();
        assert_eq!(Record::decode_message(&message, &mut back)?, 0);
        assert_eq!(back, records);
        Ok(())
    }

    /// Every RFC-0174 record, once each: what a version 2 peer may send.
    fn network_records() -> Result<Vec<Record>, WireError> {
        use crate::delivery::{DeliveryAnswerContent, Possession, SequenceRange};
        use crate::directory::ProviderOfferContent;
        use crate::probe::{EchoReplyContent, Headroom};
        use crate::sharing::{PieceManifestContent, StripeReceiptContent};
        let relay = Identity::generate()?;
        let cell = crate::directory::tests::cell()?;
        let receipt = StripeReceipt::sign(
            &relay,
            &StripeReceiptContent {
                parent: relay.public(),
                cell,
                product: Streams::RAW,
                stripe: 0,
                stripes_of: 2,
                first_second: 1,
                last_second: 2,
                records: 3,
                bytes: 4,
                digest: [5; 32],
                issued_ms: 6,
            },
        )?;
        let answer = DeliveryAnswer::sign(
            &relay,
            &DeliveryAnswerContent {
                nonce: [1; 32],
                receiver: relay.public(),
                boot_id: 2,
                issued_ms: 3,
                takes_area: true,
                entries: vec![(9, Possession::NotSeen)],
            },
        )?;
        Ok(vec![
            Record::Echo(Echo { nonce: 1 }),
            Record::EchoReply(EchoReply::sign(
                &relay,
                &EchoReplyContent {
                    nonce: 1,
                    issued_ms: 2,
                    network: 3,
                    headroom: Headroom::default(),
                },
            )?),
            Record::DeliveryQuery(DeliveryQuery {
                nonce: [1; 32],
                receiver: relay.public(),
                boot_id: 2,
                ranges: vec![SequenceRange { first: 9, last: 9 }],
                keys: None,
            }),
            Record::DeliveryAnswer(answer.clone()),
            Record::ProviderOffer(ProviderOffer::sign(
                &relay,
                &ProviderOfferContent {
                    address: "relay.example:7450".to_owned(),
                    cell,
                    products: Streams::WORLD,
                    stripes_of: 1,
                    stripes: 1,
                    mlat_cores: 0,
                    feeder_slots: 0,
                    network: 0,
                    issued_ms: 1,
                    expires_ms: 2,
                },
            )?),
            Record::ProviderQuery(ProviderQuery {
                cell,
                products: Streams::REGIONAL,
            }),
            Record::StripeAssignment(StripeAssignment {
                cell,
                product: Streams::RAW,
                stripes_of: 2,
                stripes: 0b10,
            }),
            Record::PieceManifest(PieceManifest::sign(
                &relay,
                &PieceManifestContent {
                    cell,
                    product: Streams::RAW,
                    second: 1,
                    hashes: vec![[1; 32]],
                },
            )?),
            Record::HaveSummary(HaveSummary {
                cell,
                product: Streams::RAW,
                first_second: 1,
                seconds: vec![1],
            }),
            Record::StripeReceipt(receipt.clone()),
            Record::FirehoseCredential(FirehoseCredential::sign(
                &relay,
                &crate::credit::FirehoseCredentialContent {
                    client: relay.public(),
                    products: Streams::RAW,
                    issued_ms: 1,
                    expires_ms: 2,
                },
            )?),
            Record::EvidenceBundle(EvidenceBundle::sign(
                &relay,
                &crate::credit::EvidenceBundleContent {
                    issued_ms: 1,
                    feeders: Vec::new(),
                    receipts: vec![receipt],
                    answers: vec![answer],
                },
            )?),
            Record::WorldPositions(WorldPositions::sign(
                &relay,
                &crate::products::WorldPositionsContent {
                    second: 1,
                    part: 0,
                    fixes: Vec::new(),
                },
            )?),
            Record::RegionalBatch(RegionalBatch::sign(
                &relay,
                &crate::products::RegionalBatchContent {
                    cell,
                    boot_id: 1,
                    sequence: 0,
                    wall_ms: 1,
                    observations: Vec::new(),
                },
            )?),
            Record::WorldPrecise(WorldPrecise::sign(
                &relay,
                &crate::products::WorldPositionsContent {
                    second: 1,
                    part: 0,
                    fixes: Vec::new(),
                },
            )?),
            Record::Parity(ParityChunk {
                manifest: [1; 32],
                cell,
                product: Streams::RAW,
                second: 1,
                lens: vec![1, 2, 3],
                total: 3,
                offset: 0,
                bytes: vec![7, 8, 9],
            }),
            Record::BundleIndex(BundleIndex::sign(
                &relay,
                &crate::sharing::BundleIndexContent {
                    parent: cell,
                    product: Streams::POSITIONS,
                    second: 1,
                    children: Vec::new(),
                },
            )?),
        ])
    }

    #[test]
    fn every_network_record_round_trips_and_is_non_critical() -> Result<(), WireError> {
        let records = network_records()?;
        let mut message = Vec::new();
        for record in &records {
            record.encode(&mut message)?;
        }
        let mut back = Vec::new();
        assert_eq!(Record::decode_message(&message, &mut back)?, 0);
        assert_eq!(back, records);
        // Each kind is non-critical, so a reader that knows none of them skips it.
        let mut offset = 0;
        for record in &records {
            let mut one = Vec::new();
            record.encode(&mut one)?;
            assert_eq!(one[0] & CRITICAL, 0, "{record:?}");
            offset += one.len();
        }
        assert_eq!(offset, message.len());
        Ok(())
    }

    #[test]
    fn every_record_kind_round_trips_in_one_message() -> Result<(), WireError> {
        let records = every_record()?;
        let mut message = Vec::new();
        for record in &records {
            record.encode(&mut message)?;
        }
        let mut back = Vec::new();
        assert_eq!(Record::decode_message(&message, &mut back)?, 0);
        assert_eq!(back, records);
        Ok(())
    }

    #[test]
    fn a_probe_may_send_only_echoes_and_delivery_queries() -> Result<(), WireError> {
        let relay = Identity::generate()?;
        let query = Record::DeliveryQuery(DeliveryQuery {
            nonce: [1; 32],
            receiver: relay.public(),
            boot_id: 0,
            ranges: Vec::new(),
            keys: None,
        });
        assert!(Role::Probe.may_send(&Record::Echo(Echo { nonce: 1 })));
        assert!(Role::Probe.may_send(&query));
        for other in every_record()? {
            assert!(!Role::Probe.may_send(&other), "{other:?}");
            assert!(Role::Feeder.may_send(&other));
        }
        Ok(())
    }

    /// The kinds every version 2 build before the tagged delivery check knew (RFC-0181 §7): the
    /// first through `KIND_WORLD_PRECISE`, the possession check's 0x13 and 0x14 among them.
    const KINDS_BEFORE_TAGS: std::ops::RangeInclusive<u8> = KIND_HELLO..=KIND_WORLD_PRECISE;

    /// What a build before the tagged check does with one record: this build's decoder, knowing
    /// only that build's kinds.
    fn read_before_tags(record: &[u8]) -> Result<(Option<Record>, usize), WireError> {
        Record::decode_knowing(record, |kind| KINDS_BEFORE_TAGS.contains(&kind))
    }

    #[test]
    fn a_build_before_the_tagged_delivery_check_skips_it_as_unknown() -> Result<(), WireError> {
        use crate::delivery::{DeliveryAnswerContent, Possession, SequenceRange, TagKey};
        use crate::delivery::{TagKeys, TagKeysContent};
        let feeder = Identity::generate()?;
        let member = Identity::generate()?;
        let keys = TagKeys::sign(
            &feeder,
            &TagKeysContent {
                member: member.public(),
                current: TagKey {
                    id: 1,
                    key: [1; 32],
                },
                next: TagKey {
                    id: 2,
                    key: [2; 32],
                },
                switch_in_ms: 1,
            },
        )?;
        let query = Record::DeliveryQuery(DeliveryQuery {
            nonce: [1; 32],
            receiver: feeder.public(),
            boot_id: 1,
            ranges: vec![SequenceRange { first: 4, last: 4 }],
            keys: Some(keys),
        });
        let answer = Record::DeliveryAnswer(DeliveryAnswer::sign(
            &member,
            &DeliveryAnswerContent {
                nonce: [1; 32],
                receiver: feeder.public(),
                boot_id: 1,
                issued_ms: 2,
                takes_area: true,
                entries: vec![(
                    4,
                    Possession::Proved {
                        key: 1,
                        tag: [3; 16],
                    },
                )],
            },
        )?);
        for record in [query, answer] {
            let mut bytes = Vec::new();
            record.encode(&mut bytes)?;
            // Unknown to it, and not critical: skipped whole, never read as the possession check.
            assert_eq!(read_before_tags(&bytes)?, (None, bytes.len()), "{record:?}");
            assert!(!RETIRED_KINDS.contains(&bytes[0]));
            assert_eq!(Record::decode(&bytes)?.0, Some(record));
        }
        // What it knew, it still reads, and an unknown critical kind still ends it.
        let mut echo = Vec::new();
        Record::Echo(Echo { nonce: 1 }).encode(&mut echo)?;
        assert_eq!(
            read_before_tags(&echo)?,
            (Some(Record::Echo(Echo { nonce: 1 })), echo.len())
        );
        assert!(matches!(
            read_before_tags(&[CRITICAL | KIND_DELIVERY_QUERY, 0, 0]),
            Err(WireError::UnknownCritical(_))
        ));
        Ok(())
    }

    #[test]
    fn a_query_of_the_retired_form_is_refused_clearly_and_never_read() -> Result<(), WireError> {
        // An old feeder's possession query: nonce, receiver, boot, one range, and no keys flag
        // (it had none). Read by this build as a retired kind, its body untouched.
        let mut body = Vec::new();
        body.extend_from_slice(&[9; 32]);
        body.extend_from_slice(Identity::generate()?.public().as_bytes());
        body.extend_from_slice(&3u64.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&40u64.to_be_bytes());
        body.extend_from_slice(&41u64.to_be_bytes());
        let mut message = vec![KIND_POSSESSION_QUERY];
        message.extend_from_slice(&(body.len() as u16).to_be_bytes());
        message.extend_from_slice(&body);
        // An old member's answer under its old kind, even one whose body is nothing this build
        // reads: retired, never parsed.
        message.extend_from_slice(&[KIND_POSSESSION_ANSWER, 0, 2, 0xff, 0xff]);
        Record::Heartbeat.encode(&mut message)?;
        let mut back = Vec::new();
        assert_eq!(Record::decode_message(&message, &mut back)?, 0);
        assert_eq!(
            back,
            vec![
                Record::Retired(KIND_POSSESSION_QUERY),
                Record::Retired(KIND_POSSESSION_ANSWER),
                Record::Heartbeat,
            ]
        );
        // A probe may send the old query, and is answered with a refusal that names it, which an
        // old reader reads as `Other(7)` and an old feeder as no answer.
        let old_query = &back[0];
        assert!(Role::Probe.may_send(old_query));
        let refusal = old_query.refusal().ok_or(WireError::Invalid {
            field: "no refusal of an old query",
            value: 0,
        })?;
        assert!(matches!(
            refusal,
            Record::Goodbye {
                reason: Reason::Retired,
                ..
            }
        ));
        let mut bytes = Vec::new();
        refusal.encode(&mut bytes)?;
        assert_eq!(bytes[3], 7);
        assert_eq!(Record::decode(&bytes)?.0, Some(refusal));
        // Nothing answers an old answer, nor any current record.
        assert_eq!(back[1].refusal(), None);
        assert!(!Role::Probe.may_send(&back[1]));
        for record in every_record()? {
            assert_eq!(record.refusal(), None);
        }
        // A retired kind is never written.
        for kind in RETIRED_KINDS {
            let mut out = vec![1];
            assert!(Record::Retired(kind).encode(&mut out).is_err());
            assert_eq!(out, vec![1]);
            assert!(!KINDS.contains(&kind));
        }
        Ok(())
    }

    #[test]
    fn an_unknown_kind_is_skipped_and_the_rest_still_decode() -> Result<(), WireError> {
        let mut message = vec![0x7f, 0, 2, 9, 9];
        Record::Heartbeat.encode(&mut message)?;
        let mut back = Vec::new();
        assert_eq!(Record::decode_message(&message, &mut back)?, 1);
        assert_eq!(back, vec![Record::Heartbeat]);
        Ok(())
    }

    #[test]
    fn an_unknown_critical_kind_ends_the_session() {
        assert!(matches!(
            Record::decode_message(&[CRITICAL | 0x7f, 0, 0], &mut Vec::new()),
            Err(WireError::UnknownCritical(_))
        ));
    }

    #[test]
    fn a_field_appended_by_a_later_version_is_ignored() -> Result<(), WireError> {
        let mut message = Vec::new();
        Record::Welcome { version: 1 }.encode(&mut message)?;
        message[2] += 3;
        message.extend_from_slice(&[1, 2, 3]);
        let mut back = Vec::new();
        Record::decode_message(&message, &mut back)?;
        assert_eq!(back, vec![Record::Welcome { version: 1 }]);
        Ok(())
    }

    #[test]
    fn a_message_ending_mid_record_is_an_error() -> Result<(), WireError> {
        let mut message = Vec::new();
        Record::hello(Role::Subscriber).encode(&mut message)?;
        message.pop();
        assert!(matches!(
            Record::decode_message(&message, &mut Vec::new()),
            Err(WireError::Truncated { .. })
        ));
        Ok(())
    }
}
