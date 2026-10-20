//! What a receiver signs (RFC-0171 §3.2, §4): batches of its receptions, and a description of
//! itself. Both are immutable once signed. Relays forward them byte for byte and never repack
//! them, so anyone downstream can check that a receiver really published what arrives.
//!
//! Every signed form starts with the same prefix in every format version (format byte, signer
//! key, and for a batch its boot id and sequence number) and ends with a 64-byte signature over
//! everything before it. A relay can therefore check, route and deduplicate a batch of a format it
//! does not otherwise understand.

use blake2::{Blake2s256, Digest};
use bytes::Bytes;

use crate::WireError;
use crate::beast::Frame;
use crate::decoded::ObsView;
use crate::key::{Identity, KEY_LEN, PublicKey, SIGNATURE_LEN};
use crate::record::Body;

/// The batch layout this build writes uncompressed.
pub const BATCH_FORMAT: u8 = 1;
/// The compressed layout (wire version 2, RFC-0174 §2.2): format 1's fields to `previous`, then
/// `plain length u32` and the raw DEFLATE (RFC 1951) of what format 1 has after `previous`
/// (`count u32 | observations`). Signed over the compressed bytes, so a relay forwards and
/// deduplicates it without inflating it, and a reader inflates at most `MAX_PLAIN_LEN` and at most
/// `MAX_INFLATION` times its compressed stream ([`inflation_allowed`]).
pub const BATCH_FORMAT_DEFLATE: u8 = 2;
/// The most a compressed batch's observations may inflate to: far beyond any record's body, so
/// no honest batch is refused, and bounded, so no batch is a decompression bomb.
pub const MAX_PLAIN_LEN: usize = 1 << 20;
/// The most a compressed batch's observations may inflate to, as a multiple of its compressed
/// stream (the DEFLATE bytes after the stated length): a wire rule every reader applies before it
/// inflates anything, and every writer keeps by writing a denser batch plain (format 1).
///
/// Why 8: the densest batch of honest 1090 MHz receptions the encoder makes is about 5 times
/// (one aircraft's identical Mode-S short replies at a steady counter and a steady signal level,
/// level 6 levelling off at 5.03 from a thousand receptions up; identical Mode A/C replies, 4.0;
/// real extended squitters, 1.5). A receiver never hears two receptions at one counter value, so
/// each reception carries at least its counter's changing bytes, and no honest 1090 MHz batch is
/// denser. 8 clears that with room; a batch of mostly zero-filled UAT uplinks can be denser and is
/// written plain, losing only its compression. What a relay does per byte it is sent is then at
/// most 8 times what it is charged for the wire bytes, and it charges the inflated bytes and the
/// receptions anyway (`Batch::inflated_len`, `Batch::receptions_at_most`).
pub const MAX_INFLATION: usize = 8;

/// The wire's one rule for a compressed batch (`MAX_INFLATION`, `MAX_PLAIN_LEN`): whether
/// observations of `plain` bytes may be carried in a DEFLATE stream of `compressed` bytes. The
/// encoder asks it before writing format 2 and every reader before inflating one.
pub fn inflation_allowed(plain: usize, compressed: usize) -> bool {
    plain <= MAX_PLAIN_LEN && plain <= MAX_INFLATION.saturating_mul(compressed)
}
/// DEFLATE's level 6: zlib's default, where its ratio levels off.
const DEFLATE_LEVEL: u8 = 6;

/// How a batch's observations are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// Format 1: as they are.
    Plain,
    /// Format 2: raw DEFLATE. Every peer reads it (wire version 2 is the minimum). Written as
    /// format 1 instead whenever compressing would not make the batch smaller, so a batch signed
    /// with it is never larger than the plain one, and a size bound on the plain layout holds; and
    /// whenever it would inflate past `MAX_INFLATION` times its stream, so no reader refuses it.
    Deflate,
    /// As `Deflate`, at compression level `n` (1 to 9) instead of the wire's own: the same layout
    /// every reader takes, only the ratio and the time spent differ. For a load harness whose
    /// thousands of feeders share the cores one reader has.
    DeflateAt(u8),
}
/// The receiver-info layout an old feeder writes: its exact `Location` in the clear, signed.
/// Site-bearing ([`ReceiverInfo::carries_site`]): still read, forwarded byte for byte only to
/// version 3 relay-role peers ([`crate::record::carries_sites`]), never sent to a client.
pub const RECEIVER_INFO_FORMAT: u8 = 1;
/// The receiver-info layout this build's feeder writes (wire version 3): the receiver's public
/// cell (`crate::site::PUBLIC_CELL_RESOLUTION`), computed by the feeder, in place of its site,
/// which travels relay-only in a `ReceiverSite`. Travels everywhere format 1 did.
///
/// ```text
/// format u8 = 2 | receiver key [32] | issued_ms u64
/// | cell flag u8 (0 none, 1 present) | [public cell u64, H3 resolution 6]
/// | clock u8 | software length u8 | software | relay count u8 | count x relay key [32]
/// | signature [64]
/// ```
pub const RECEIVER_INFO_FORMAT_PUBLIC: u8 = 2;

const BATCH_DOMAIN: &[u8] = b"tally batch";
/// What a relay signs its own deduplicated stream under. A separate domain, so a relay's batch can
/// never verify as a receiver's: the signature, not the record kind, says who claims what.
const RELAY_BATCH_DOMAIN: &[u8] = b"tally relay batch";
const RECEIVER_INFO_DOMAIN: &[u8] = b"tally receiver";

/// Format, key, boot id, sequence: the part of a batch fixed across every format version.
const BATCH_PREFIX_LEN: usize = 1 + KEY_LEN + 8 + 8;
/// The prefix and the rest of format 1's fixed fields: counter epoch, wall clock, dropped,
/// previous.
const BATCH_HEADER_LEN: usize = BATCH_PREFIX_LEN + 4 + 8 + 4 + 32;
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
        ObsView::from(self).to_beast()
    }

    pub(crate) fn decode(reader: &mut Body<'_>) -> Result<Self, WireError> {
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

impl BatchContent {
    fn header(&self) -> Header {
        Header {
            boot_id: self.boot_id,
            sequence: self.sequence,
            counter_epoch: self.counter_epoch,
            wall_ms: self.wall_ms,
            dropped: self.dropped,
            previous: self.previous,
        }
    }
}

/// A batch's content with its receptions borrowed where they are held (a decoded batch's,
/// `ObsView`): signed into the same bytes as the `BatchContent` of their owned copies, with no copy
/// made. What a relay signs its deduplicated stream from (`Batch::sign_relay_draft`), as the
/// regional product is signed from a `RegionalDraft`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchDraft<'a> {
    pub boot_id: u64,
    pub sequence: u64,
    pub counter_epoch: u32,
    pub wall_ms: u64,
    pub dropped: u32,
    pub previous: Hash,
    pub observations: Vec<ObsView<'a>>,
}

impl BatchDraft<'_> {
    fn header(&self) -> Header {
        Header {
            boot_id: self.boot_id,
            sequence: self.sequence,
            counter_epoch: self.counter_epoch,
            wall_ms: self.wall_ms,
            dropped: self.dropped,
            previous: self.previous,
        }
    }
}

/// A signed batch, as bytes. Immutable: forwarding never re-encodes it, and every holder shares
/// the one allocation (`Bytes`), so a clone is a reference count, not a copy. The signer's key is
/// decompressed once, when the batch is read (`from_bytes`) or signed, and kept: naming the
/// receiver and checking the signature never decompress it again (RFC-0181 §2). Its hash is
/// computed once, the first time anyone asks (admission does), and kept the same way.
#[derive(Clone, Debug)]
pub struct Batch {
    bytes: Bytes,
    /// Shared with every clone, so a batch (and every record holding one) stays small.
    kept: std::sync::Arc<Kept>,
    /// Its bytes carry their own charge ([`Batch::owned_by`]): every holder shares them, and none
    /// charges them again.
    owned: bool,
}

/// A batch's signed bytes with their owner's charge beside them, in the one allocation `Bytes`
/// shares (`Bytes::from_owner`): the charge goes when the last holder of the bytes lets them go.
struct OwnedBytes {
    bytes: Vec<u8>,
    _owner: crate::decoded::Owner,
}

impl AsRef<[u8]> for OwnedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// What `Bytes::from_owner` allocates beside the owner: its reference count.
pub const OWNED_HEADER: usize =
    std::mem::size_of::<std::sync::atomic::AtomicUsize>() + std::mem::size_of::<OwnedBytes>();

/// What a batch keeps of its bytes once worked out: its signer's key, and its hash.
#[derive(Debug)]
struct Kept {
    signer: ed25519_dalek::VerifyingKey,
    hash: std::sync::OnceLock<Hash>,
}

impl Kept {
    fn new(signer: ed25519_dalek::VerifyingKey) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            signer,
            hash: std::sync::OnceLock::new(),
        })
    }
}

/// Two batches are the same batch when their signed bytes are: the kept key is read from them.
impl PartialEq for Batch {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Batch {}

impl Batch {
    /// A receiver's batch of its own receptions.
    pub fn sign(identity: &Identity, content: &BatchContent) -> Result<Self, WireError> {
        Self::sign_content(BATCH_DOMAIN, identity, content, Codec::Plain)
    }

    /// A receiver's batch, its observations written by `codec`.
    pub fn sign_with(
        identity: &Identity,
        content: &BatchContent,
        codec: Codec,
    ) -> Result<Self, WireError> {
        Self::sign_content(BATCH_DOMAIN, identity, content, codec)
    }

    /// A relay's batch of its deduplicated stream (`Record::RelayBatch`).
    pub fn sign_as_relay(identity: &Identity, content: &BatchContent) -> Result<Self, WireError> {
        Self::sign_content(RELAY_BATCH_DOMAIN, identity, content, Codec::Plain)
    }

    fn sign_content(
        label: &[u8],
        identity: &Identity,
        content: &BatchContent,
        codec: Codec,
    ) -> Result<Self, WireError> {
        let observations = content.observations.iter().map(ObsView::from);
        Self::sign_in(label, identity, &content.header(), observations, codec)
    }

    /// As `sign_as_relay`, from receptions borrowed where they are held: the bytes
    /// `sign_as_relay` makes of their owned copies, with no copy made.
    pub fn sign_relay_draft(
        identity: &Identity,
        draft: &BatchDraft<'_>,
    ) -> Result<Self, WireError> {
        Self::sign_in(
            RELAY_BATCH_DOMAIN,
            identity,
            &draft.header(),
            draft.observations.iter().copied(),
            Codec::Plain,
        )
    }

    /// Whether `sign_relay_draft` would make a batch that fits one record (`record::MAX_BODY`),
    /// decided without signing: the signature's length is fixed.
    pub fn relay_draft_fits(draft: &BatchDraft<'_>) -> bool {
        let observations: usize = draft
            .observations
            .iter()
            .map(|observation| crate::decoded::OBSERVATION_FIXED + observation.data.len())
            .sum();
        BATCH_HEADER_LEN + 4 + observations + SIGNATURE_LEN <= crate::record::MAX_BODY
            && draft
                .observations
                .iter()
                .all(|observation| u16::try_from(observation.data.len()).is_ok())
            && u32::try_from(draft.observations.len()).is_ok()
    }

    fn sign_in<'a>(
        label: &[u8],
        identity: &Identity,
        header: &Header,
        observations: impl ExactSizeIterator<Item = ObsView<'a>>,
        codec: Codec,
    ) -> Result<Self, WireError> {
        let mut plain = Vec::new();
        let count = u32::try_from(observations.len())
            .map_err(|_| WireError::Oversize(observations.len()))?;
        plain.extend_from_slice(&count.to_be_bytes());
        for observation in observations {
            observation.encode(&mut plain)?;
        }
        let deflated = match codec {
            Codec::Plain => None,
            Codec::Deflate | Codec::DeflateAt(_) => {
                if plain.len() > MAX_PLAIN_LEN {
                    return Err(WireError::Oversize(plain.len()));
                }
                let level = match codec {
                    Codec::DeflateAt(level) => level.clamp(1, 9),
                    _ => DEFLATE_LEVEL,
                };
                let deflated = miniz_oxide::deflate::compress_to_vec(&plain, level);
                // The length field and the stream must come out smaller, and within the wire's
                // inflation rule, or the batch is plain.
                (4 + deflated.len() < plain.len() && inflation_allowed(plain.len(), deflated.len()))
                    .then_some(deflated)
            }
        };
        let mut bytes = Vec::new();
        bytes.push(if deflated.is_some() {
            BATCH_FORMAT_DEFLATE
        } else {
            BATCH_FORMAT
        });
        bytes.extend_from_slice(identity.public().as_bytes());
        bytes.extend_from_slice(&header.boot_id.to_be_bytes());
        bytes.extend_from_slice(&header.sequence.to_be_bytes());
        bytes.extend_from_slice(&header.counter_epoch.to_be_bytes());
        bytes.extend_from_slice(&header.wall_ms.to_be_bytes());
        bytes.extend_from_slice(&header.dropped.to_be_bytes());
        bytes.extend_from_slice(&header.previous);
        match deflated {
            None => bytes.extend_from_slice(&plain),
            Some(deflated) => {
                // Bounded by `MAX_PLAIN_LEN` above.
                bytes.extend_from_slice(&(plain.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&deflated);
            }
        }
        let signature = identity.sign(&domain(label, &bytes));
        bytes.extend_from_slice(&signature);
        Ok(Self {
            bytes: Bytes::from(bytes),
            kept: Kept::new(identity.point()),
            owned: false,
        })
    }

    /// Accepts any format whose fixed prefix is well formed. Does not check the signature.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Result<Self, WireError> {
        let bytes = bytes.into();
        if bytes.len() < BATCH_PREFIX_LEN + SIGNATURE_LEN {
            return Err(WireError::Truncated {
                needed: BATCH_PREFIX_LEN + SIGNATURE_LEN,
                had: bytes.len(),
            });
        }
        // The one decompression of the signer's key, on the link task that read the batch.
        let signer = PublicKey::point_of(&bytes[1..1 + KEY_LEN])?;
        Ok(Self {
            bytes,
            kept: Kept::new(signer),
            owned: false,
        })
    }

    /// What its signed bytes take as an allocation of their own: their bytes and the header of
    /// the one allocation every holder shares ([`Batch::owned_by`]). What a holder that keeps the
    /// batch past its decode is charged for them, once (`Decoded::footprint` leaves them out).
    pub fn footprint(&self) -> usize {
        self.bytes.len() + OWNED_HEADER
    }

    /// Whether its bytes carry their own charge ([`Batch::owned_by`]): a holder of it charges
    /// only what it allocates itself.
    pub fn is_owned(&self) -> bool {
        self.owned
    }

    /// The same batch, its signed bytes charged once for their life by `owner`, told their
    /// [`Batch::footprint`]: the bytes moved (not copied, when nothing else holds them) into one
    /// allocation with the charge beside them, which every clone shares and the last lets go.
    /// `None` from `owner` refuses them, and the batch comes back as it was.
    pub fn owned_by(
        self,
        owner: impl FnOnce(usize) -> Option<crate::decoded::Owner>,
    ) -> Result<Self, Self> {
        if self.owned {
            return Ok(self);
        }
        let Some(charge) = owner(self.footprint()) else {
            return Err(self);
        };
        let Self { bytes, kept, .. } = self;
        // Unique and made from a `Vec` (a batch read off a link is): moved, not copied.
        let mut bytes = Vec::from(bytes);
        bytes.shrink_to_fit();
        Ok(Self {
            bytes: Bytes::from_owner(OwnedBytes {
                bytes,
                _owner: charge,
            }),
            kept,
            owned: true,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The signed bytes, shared: a reference count, not a copy.
    pub fn shared_bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    /// The key that signed it, as kept: never decompressed again. A `Result` for its callers'
    /// sake; it cannot fail, the key was checked when the batch was read.
    pub fn receiver(&self) -> Result<PublicKey, WireError> {
        Ok(PublicKey::of_point(&self.kept.signer))
    }

    pub fn boot_id(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN)
    }

    pub fn sequence(&self) -> u64 {
        u64_at(&self.bytes, 1 + KEY_LEN + 8)
    }

    /// BLAKE2s over the whole signed batch: its identity for deduplication, the chain and the
    /// last tiebreak of a relay's canonical order. Computed once and kept (`Kept`).
    pub fn hash(&self) -> Hash {
        *self
            .kept
            .hash
            .get_or_init(|| Blake2s256::digest(&self.bytes).into())
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
        PublicKey::verify_by(&self.kept.signer, &domain(label, signed), &signature)
    }

    /// The content, for a format this build reads.
    pub fn content(&self) -> Result<BatchContent, WireError> {
        let (header, plain) = self.header_and_plain()?;
        let mut plain = Body::new(&plain);
        let count = plain.u32()?;
        let observations = (0..count)
            .map(|_| Observation::decode(&mut plain))
            .collect::<Result<_, _>>()?;
        Ok(BatchContent {
            boot_id: header.boot_id,
            sequence: header.sequence,
            counter_epoch: header.counter_epoch,
            wall_ms: header.wall_ms,
            dropped: header.dropped,
            previous: header.previous,
            observations,
        })
    }

    /// The bytes this batch's observations take plain (`count u32 | observations`): what a reader
    /// inflates a compressed batch to, read from its stated length and held to the wire's rule
    /// (`inflation_allowed`) without inflating anything; a plain batch's own. What a relay charges
    /// for a batch's work alongside its wire bytes, before it decodes it.
    pub fn inflated_len(&self) -> Result<usize, WireError> {
        let (_, layout) = self.layout()?;
        Ok(match layout {
            Layout::Plain(range) => range.len(),
            Layout::Deflate { stated, .. } => stated,
        })
    }

    /// The most receptions this batch can hold, from `inflated_len` alone: every reception takes
    /// at least its fixed part, and a decode refuses a count past this. What a relay charges for
    /// the receptions before it decodes the batch (a decode's exact count is
    /// `Decoded::receptions`).
    pub fn receptions_at_most(&self) -> Result<usize, WireError> {
        Ok(self.inflated_len()?.saturating_sub(4) / crate::decoded::OBSERVATION_FIXED)
    }

    /// The receptions this batch states it holds (`count u32`, the first four bytes of its
    /// observations): exactly what a decode of it reads, if it decodes at all, since a decode
    /// reads that many and refuses a batch whose bytes cannot hold them. Read without decoding
    /// anything: a plain batch's from its bytes, a compressed one's by inflating its first four
    /// bytes alone. What a relay paces a feeder's receptions by before the batch reaches a worker
    /// (`tally_relay::link`); `receptions_at_most` overstates an honest batch by its messages'
    /// bytes, some twice.
    pub fn receptions(&self) -> Result<usize, WireError> {
        let (_, layout) = self.layout()?;
        let mut count = [0u8; 4];
        match layout {
            Layout::Plain(range) => {
                let bytes =
                    self.bytes
                        .get(range.start..range.start + 4)
                        .ok_or(WireError::Truncated {
                            needed: 4,
                            had: range.len(),
                        })?;
                count.copy_from_slice(bytes);
            }
            Layout::Deflate { stream, .. } => {
                use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
                let mut inflater = Box::<DecompressorOxide>::default();
                let (_, _, written) = decompress(
                    &mut inflater,
                    &self.bytes[stream],
                    &mut count,
                    0,
                    inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
                );
                if written < 4 {
                    return Err(WireError::Invalid {
                        field: "compressed batch",
                        value: written as u64,
                    });
                }
            }
        }
        Ok(u32::from_be_bytes(count) as usize)
    }

    /// The fixed fields, and where the observations are, for a format this build reads: a
    /// compressed batch's stated length already held to the wire's rule (`inflation_allowed`).
    fn layout(&self) -> Result<(Header, Layout), WireError> {
        let format = self.format();
        if format != BATCH_FORMAT && format != BATCH_FORMAT_DEFLATE {
            return Err(WireError::Invalid {
                field: "batch format",
                value: u64::from(format),
            });
        }
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[1 + KEY_LEN..]);
        let header = Header {
            boot_id: reader.u64()?,
            sequence: reader.u64()?,
            counter_epoch: reader.u32()?,
            wall_ms: reader.u64()?,
            dropped: reader.u32()?,
            previous: reader.array()?,
        };
        let fixed = 1 + KEY_LEN + reader.position();
        if format == BATCH_FORMAT {
            return Ok((header, Layout::Plain(fixed..signed.len())));
        }
        let stated = reader.u32()? as usize;
        let stream = fixed + 4..signed.len();
        if stated > MAX_PLAIN_LEN {
            return Err(WireError::Oversize(stated));
        }
        if !inflation_allowed(stated, stream.len()) {
            return Err(WireError::Invalid {
                field: "compressed batch inflation",
                value: stated as u64,
            });
        }
        Ok((header, Layout::Deflate { stated, stream }))
    }

    /// The fixed fields, and the observations' plain bytes (`count u32 | observations`), for a
    /// format this build reads: a slice of the signed bytes for format 1 (shared, not copied), and
    /// for format 2 inflated once, to its stated length and never past it, so at most
    /// `MAX_INFLATION` times its stream and `MAX_PLAIN_LEN`.
    pub(crate) fn header_and_plain(&self) -> Result<(Header, Bytes), WireError> {
        let (header, layout) = self.layout()?;
        let (stated, stream) = match layout {
            Layout::Plain(range) => return Ok((header, self.bytes.slice(range))),
            Layout::Deflate { stated, stream } => (stated, stream),
        };
        // Allocated once at its stated length, never grown (a growing buffer doubles, and holds
        // up to twice what it inflated to); a stream that would inflate further is refused there.
        let mut inflated = vec![0; stated];
        let written = miniz_oxide::inflate::decompress_slice_iter_to_slice(
            &mut inflated,
            std::iter::once(&self.bytes[stream]),
            false,
            true,
        )
        .map_err(|_| WireError::Invalid {
            field: "compressed batch",
            value: stated as u64,
        })?;
        if written != stated {
            return Err(WireError::Invalid {
                field: "compressed batch length",
                value: written as u64,
            });
        }
        Ok((header, Bytes::from(inflated)))
    }
}

/// Where a batch's observations are in its signed bytes.
enum Layout {
    /// Format 1: these bytes, as they are.
    Plain(std::ops::Range<usize>),
    /// Format 2: a DEFLATE stream in these bytes, stated to inflate to `stated`.
    Deflate {
        stated: usize,
        stream: std::ops::Range<usize>,
    },
}

/// A batch's fixed fields after its prefix, read without its observations.
pub(crate) struct Header {
    pub(crate) boot_id: u64,
    pub(crate) sequence: u64,
    pub(crate) counter_epoch: u32,
    pub(crate) wall_ms: u64,
    pub(crate) dropped: u32,
    pub(crate) previous: Hash,
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

    /// The clock's byte, as a receiver's description carries it.
    pub fn byte(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Dump1090 => 1,
            Self::Beast => 2,
            Self::Radarcape12Mhz => 3,
            Self::RadarcapeGps => 4,
            Self::Other(byte) => byte,
        }
    }

    /// The clock a byte names; a byte this build does not know is `Other`.
    pub fn from_byte(byte: u8) -> Self {
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
/// the owner chose to be. Published exactly unless the owner rounds it (RFC-0171 §8.3); a rounded
/// location says so here, and an MLAT engine gives it less weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    pub lat_e7: i32,
    pub lon_e7: i32,
    pub alt_m: i32,
    pub precision_m: u32,
}

impl Location {
    /// On the globe: latitude within 90 degrees, longitude within 180.
    pub fn check(&self) -> Result<(), WireError> {
        check_coordinates(self.lat_e7, self.lon_e7)
    }
}

/// Degrees times 10^7 that name a point on the globe: latitude in -90..=90 and longitude in
/// -180..=180. Every record that carries a position holds it to this.
pub fn check_coordinates(lat_e7: i32, lon_e7: i32) -> Result<(), WireError> {
    if lat_e7.unsigned_abs() > 900_000_000 {
        return Err(WireError::Invalid {
            field: "latitude",
            value: u64::from(lat_e7.unsigned_abs()),
        });
    }
    if lon_e7.unsigned_abs() > 1_800_000_000 {
        return Err(WireError::Invalid {
            field: "longitude",
            value: u64::from(lon_e7.unsigned_abs()),
        });
    }
    Ok(())
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

/// What a format 2 description says: everything format 1 did, the site replaced by the public
/// cell it lies in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInfoContent {
    /// Unix milliseconds. The newest a relay has seen for a key wins, whatever its format.
    pub issued_ms: u64,
    /// The H3 cell of resolution `PUBLIC_CELL_RESOLUTION` the antenna is in (`Region::public_cell`),
    /// `None` for a receiver that declared no location.
    pub cell: Option<crate::region::Region>,
    pub clock: Clock,
    /// The feeder's name and version, for operators.
    pub software: String,
    /// The relays this receiver chose to publish to (as format 1's).
    pub relays: Vec<PublicKey>,
}

impl crate::signed::Check for PublicInfoContent {
    /// A cell, if any, of exactly the public resolution: no finer, so it tells no more.
    fn check(&self) -> Result<(), WireError> {
        match self.cell {
            Some(cell) if cell.resolution() != crate::site::PUBLIC_CELL_RESOLUTION => {
                Err(WireError::Invalid {
                    field: "public cell resolution",
                    value: u64::from(cell.resolution()),
                })
            }
            _ => Ok(()),
        }
    }
}

impl PublicInfoContent {
    /// Whether this description's public cell is the one `location` is in
    /// ([`Region::public_cell`](crate::region::Region::public_cell)): a relay holding a format 2
    /// description and a `ReceiverSite` of one key refuses the pair when it is not. Equality, not
    /// [`Region::covers`](crate::region::Region::covers): H3 cells are not nested, so the cell
    /// containing a point and the ancestor of its finest cell differ for about one point in
    /// sixteen, and the feeder names the containing one.
    pub fn holds(&self, location: &Location) -> bool {
        self.cell.is_some_and(|cell| {
            crate::region::Region::public_cell(location).is_ok_and(|named| named == cell)
        })
    }
}

/// What a receiver's description says, of whichever format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Description {
    /// Format 1: carries the site. Relay-only.
    Site(ReceiverInfoContent),
    /// Format 2: carries the public cell.
    Public(PublicInfoContent),
}

/// A receiver's signed description of itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverInfo {
    bytes: Vec<u8>,
}

impl crate::signed::Check for ReceiverInfoContent {
    /// A location on the globe, if any. The software name and the relay list are bounded by
    /// their length bytes, which writing refuses to exceed.
    fn check(&self) -> Result<(), WireError> {
        self.location.as_ref().map_or(Ok(()), Location::check)
    }
}

impl ReceiverInfo {
    /// A format 1 description, carrying the site: what an old feeder signs. This build's feeder
    /// signs `sign_public` and a `ReceiverSite`; this stays for tests and for simulating old
    /// feeders.
    pub fn sign(identity: &Identity, content: &ReceiverInfoContent) -> Result<Self, WireError> {
        crate::signed::Check::check(content)?;
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
        write_tail(
            &mut bytes,
            content.clock,
            &content.software,
            &content.relays,
        )?;
        let signature = identity.sign(&domain(RECEIVER_INFO_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        Ok(Self { bytes })
    }

    /// A format 2 description: the public cell, no site.
    pub fn sign_public(
        identity: &Identity,
        content: &PublicInfoContent,
    ) -> Result<Self, WireError> {
        crate::signed::Check::check(content)?;
        let mut bytes = Vec::new();
        bytes.push(RECEIVER_INFO_FORMAT_PUBLIC);
        bytes.extend_from_slice(identity.public().as_bytes());
        bytes.extend_from_slice(&content.issued_ms.to_be_bytes());
        match content.cell {
            None => bytes.push(0),
            Some(cell) => {
                bytes.push(1);
                bytes.extend_from_slice(&cell.as_u64().to_be_bytes());
            }
        }
        write_tail(
            &mut bytes,
            content.clock,
            &content.software,
            &content.relays,
        )?;
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

    pub fn format(&self) -> u8 {
        self.bytes[0]
    }

    /// Whether it carries the receiver's site: format 1, and any format this build does not know
    /// (which it cannot show carries none). Such a description is relay-only.
    pub fn carries_site(&self) -> bool {
        self.format() != RECEIVER_INFO_FORMAT_PUBLIC
    }

    /// The reference clients see in place of a site-bearing description; `None` for one that
    /// carries no site.
    pub fn site_id(&self) -> Option<crate::site::SiteId> {
        self.carries_site()
            .then(|| crate::site::SiteId::of_signed(&self.bytes))
    }

    /// What an old feeder's reception tags are keyed by while this format 1 description is
    /// current; `None` for one that carries no site.
    pub fn reception_key(&self) -> Option<crate::site::ReceptionKey> {
        self.carries_site()
            .then(|| crate::site::ReceptionKey::of_signed(&self.bytes))
    }

    /// When it was issued, in either format: the newest a relay has seen for a key wins.
    pub fn issued_ms(&self) -> Result<u64, WireError> {
        let (signed, _) = split_signature(&self.bytes)?;
        Body::new(&signed[INFO_PREFIX_LEN..]).u64()
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
        let (clock, software, relays) = read_tail(&mut reader)?;
        let content = ReceiverInfoContent {
            issued_ms,
            location,
            clock,
            software,
            relays,
        };
        crate::signed::Check::check(&content)?;
        Ok(content)
    }

    /// The content of a format 2 description.
    pub fn public(&self) -> Result<PublicInfoContent, WireError> {
        if self.bytes[0] != RECEIVER_INFO_FORMAT_PUBLIC {
            return Err(WireError::Invalid {
                field: "receiver info format",
                value: u64::from(self.bytes[0]),
            });
        }
        let (signed, _) = split_signature(&self.bytes)?;
        let mut reader = Body::new(&signed[INFO_PREFIX_LEN..]);
        let issued_ms = reader.u64()?;
        let cell = match reader.u8()? {
            0 => None,
            _ => Some(crate::region::Region::from_u64(reader.u64()?)?),
        };
        let (clock, software, relays) = read_tail(&mut reader)?;
        let content = PublicInfoContent {
            issued_ms,
            cell,
            clock,
            software,
            relays,
        };
        crate::signed::Check::check(&content)?;
        Ok(content)
    }

    /// What it says, in whichever format this build reads.
    pub fn description(&self) -> Result<Description, WireError> {
        match self.format() {
            RECEIVER_INFO_FORMAT => self.content().map(Description::Site),
            _ => self.public().map(Description::Public),
        }
    }

    /// The receiver's public cell, in either format: format 2's own, format 1's the cell its
    /// site lies in. `None` for a receiver that declared no location.
    pub fn public_cell(&self) -> Result<Option<crate::region::Region>, WireError> {
        match self.description()? {
            Description::Public(content) => Ok(content.cell),
            Description::Site(content) => content
                .location
                .map(|location| crate::region::Region::public_cell(&location))
                .transpose(),
        }
    }
}

/// Clock, software and relays: the fields both description formats end with.
fn write_tail(
    bytes: &mut Vec<u8>,
    clock: Clock,
    software: &str,
    relays: &[PublicKey],
) -> Result<(), WireError> {
    bytes.push(clock.byte());
    let software = software.as_bytes();
    let length = u8::try_from(software.len()).map_err(|_| WireError::Oversize(software.len()))?;
    bytes.push(length);
    bytes.extend_from_slice(software);
    let count = u8::try_from(relays.len()).map_err(|_| WireError::Oversize(relays.len()))?;
    bytes.push(count);
    for relay in relays {
        bytes.extend_from_slice(relay.as_bytes());
    }
    Ok(())
}

fn read_tail(reader: &mut Body<'_>) -> Result<(Clock, String, Vec<PublicKey>), WireError> {
    let clock = Clock::from_byte(reader.u8()?);
    let length = usize::from(reader.u8()?);
    let software = String::from_utf8_lossy(reader.bytes(length)?).into_owned();
    let count = reader.u8()?;
    let relays = (0..count)
        .map(|_| PublicKey::from_slice(reader.bytes(KEY_LEN)?))
        .collect::<Result<_, _>>()?;
    Ok((clock, software, relays))
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
    use crate::beast::FrameKind;

    #[test]
    fn a_compressed_batch_reads_back_as_its_plain_twin_and_a_bomb_is_refused()
    -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        let observations: Vec<Observation> = (0..300u64)
            .map(|at| Observation {
                format: format::MODE_S_LONG,
                timestamp: 1_000_000 + at * 12_000,
                signal: 80,
                data: vec![
                    0x8d,
                    0x4c,
                    0xa1,
                    0xb2,
                    0x58,
                    0xc3,
                    0x82,
                    0xd6,
                    0x90,
                    0xc8,
                    0xac,
                    0x28,
                    0x63,
                    (at % 251) as u8,
                ],
            })
            .collect();
        let content = BatchContent {
            boot_id: 1,
            sequence: 2,
            counter_epoch: 3,
            wall_ms: 4,
            dropped: 5,
            previous: [6; 32],
            observations,
        };
        let plain = Batch::sign(&feeder, &content)?;
        let packed = Batch::sign_with(&feeder, &content, Codec::Deflate)?;
        packed.verify()?;
        assert_eq!(packed.format(), BATCH_FORMAT_DEFLATE);
        assert_eq!(packed.content()?, content);
        assert!(packed.as_bytes().len() * 2 < plain.as_bytes().len());
        // A stated length past the bound is refused before anything is inflated.
        let mut bytes = packed.as_bytes()[..packed.as_bytes().len() - SIGNATURE_LEN].to_vec();
        let at = 1 + KEY_LEN + 8 + 8 + 4 + 8 + 4 + 32;
        bytes[at..at + 4].copy_from_slice(&((MAX_PLAIN_LEN as u32) + 1).to_be_bytes());
        let signature = feeder.sign(&domain(BATCH_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        assert!(Batch::from_bytes(bytes)?.content().is_err());
        Ok(())
    }

    /// A format 2 batch of whatever stream and stated length a hostile signer chooses.
    fn signed_deflate(feeder: &Identity, stated: u32, stream: &[u8]) -> Result<Batch, WireError> {
        let mut bytes = vec![BATCH_FORMAT_DEFLATE];
        bytes.extend_from_slice(feeder.public().as_bytes());
        bytes.extend_from_slice(&[0; BATCH_HEADER_LEN - 1 - KEY_LEN]);
        bytes.extend_from_slice(&stated.to_be_bytes());
        bytes.extend_from_slice(stream);
        let signature = feeder.sign(&domain(BATCH_DOMAIN, &bytes));
        bytes.extend_from_slice(&signature);
        Batch::from_bytes(bytes)
    }

    /// `count` receptions of one shape, as the encoder lays them out plain.
    fn plain_of(observations: &[Observation]) -> Result<Vec<u8>, WireError> {
        let mut plain = (observations.len() as u32).to_be_bytes().to_vec();
        for observation in observations {
            ObsView::from(observation).encode(&mut plain)?;
        }
        Ok(plain)
    }

    fn receptions(count: u64, format: u8, step: u64, data: &[u8]) -> Vec<Observation> {
        (0..count)
            .map(|at| Observation {
                format,
                timestamp: 1_000_000 + at * step,
                signal: 80,
                data: data.to_vec(),
            })
            .collect()
    }

    /// The densest honest batches compress within the rule, so no honest compression is lost;
    /// anything denser (zero-filled UAT uplinks, receptions an honest receiver cannot hear) is
    /// written plain; and nothing the encoder writes is past the rule a reader applies.
    #[test]
    fn the_encoder_never_writes_a_batch_past_the_inflation_rule() -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        let short = [0x5d, 0x4c, 0xa1, 0xb2, 0x11, 0x22, 0x33];
        let honest = [
            // One aircraft's identical all-call replies at a steady counter and signal: the
            // densest honest 1090 MHz batch (`MAX_INFLATION`'s docs).
            receptions(5_000, format::MODE_S_SHORT, 12_000, &short),
            receptions(100, format::MODE_S_SHORT, 12_000, &short),
            receptions(5_000, format::MODE_AC, 1_000, &[0x12, 0x34]),
        ];
        let denser = [
            receptions(40, format::UAT_UPLINK, 31_000, &[0; 432]),
            receptions(5_000, format::MODE_AC, 0, &[0x12, 0x34]),
            receptions(3_000, format::MODE_S_LONG, 0, &[0; 14]),
        ];
        for (observations, compressed) in honest
            .iter()
            .map(|o| (o, true))
            .chain(denser.iter().map(|o| (o, false)))
        {
            let content = BatchContent {
                observations: observations.clone(),
                ..content()?
            };
            let batch = Batch::sign_with(&feeder, &content, Codec::Deflate)?;
            let shape = (observations.len(), observations[0].format, compressed);
            let expected = if compressed {
                BATCH_FORMAT_DEFLATE
            } else {
                BATCH_FORMAT
            };
            assert_eq!(batch.format(), expected, "{shape:?}");
            assert_eq!(
                batch.inflated_len()?,
                plain_of(observations)?.len(),
                "{shape:?}"
            );
            if batch.format() == BATCH_FORMAT_DEFLATE {
                let stream = batch.as_bytes().len() - BATCH_HEADER_LEN - 4 - SIGNATURE_LEN;
                assert!(
                    inflation_allowed(batch.inflated_len()?, stream),
                    "{shape:?}"
                );
            }
            assert_eq!(batch.content()?, content, "{shape:?}");
            assert!(
                batch.receptions_at_most()? >= observations.len(),
                "{shape:?}"
            );
        }
        Ok(())
    }

    /// A batch that states, honestly, that it inflates past `MAX_INFLATION` times its stream (well
    /// within `MAX_PLAIN_LEN`) is refused by its stated length, before anything is inflated: the
    /// refusal is the rule's, not the inflater's. One that states a length within the rule and
    /// inflates further is cut off at its stated length, never inflated whole.
    #[test]
    fn a_bomb_past_the_inflation_rule_is_refused_before_inflating() -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        // 30,000 zeroed Mode-S long receptions: 720 KB, deflating to under a kilobyte.
        let plain = plain_of(&receptions(30_000, format::MODE_S_LONG, 0, &[0; 14]))?;
        let stream = miniz_oxide::deflate::compress_to_vec(&plain, DEFLATE_LEVEL);
        assert!(plain.len() <= MAX_PLAIN_LEN && plain.len() > MAX_INFLATION * stream.len());
        let refused = |result: Result<usize, WireError>| {
            matches!(
                result,
                Err(WireError::Invalid {
                    field: "compressed batch inflation",
                    ..
                })
            )
        };
        let bomb = signed_deflate(&feeder, plain.len() as u32, &stream)?;
        bomb.verify()?;
        assert!(refused(bomb.inflated_len()));
        assert!(refused(bomb.receptions_at_most()));
        assert!(refused(
            bomb.content().map(|content| content.observations.len())
        ));
        let decoded = crate::Decoded::from_verified(bomb, 0, 0).map(|decoded| decoded.receptions());
        assert!(refused(decoded.map_err(|undecodable| undecodable.error)));
        // Stated within the rule, inflating to far more: stopped at the stated length.
        let stated = MAX_INFLATION * stream.len();
        let liar = signed_deflate(&feeder, stated as u32, &stream)?;
        assert_eq!(liar.inflated_len()?, stated);
        assert!(matches!(
            liar.content(),
            Err(WireError::Invalid {
                field: "compressed batch",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn a_batch_compression_would_not_shrink_is_written_plain() -> Result<(), WireError> {
        let feeder = Identity::generate()?;
        // An empty batch: its count alone, which DEFLATE only grows.
        let empty = BatchContent {
            observations: Vec::new(),
            ..content()?
        };
        let packed = Batch::sign_with(&feeder, &empty, Codec::Deflate)?;
        assert_eq!(packed.format(), BATCH_FORMAT);
        assert_eq!(packed, Batch::sign(&feeder, &empty)?);
        assert_eq!(packed.content()?, empty);
        Ok(())
    }

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

    /// A relay batch signed from borrowed receptions is the one signed from their owned copies,
    /// byte for byte, and fits a record exactly when that batch's record encodes within a
    /// message's plaintext.
    #[test]
    fn a_relay_draft_signs_the_bytes_its_owned_copies_sign() -> Result<(), WireError> {
        let relay = Identity::from_seed([5; 32]);
        let fits_record = |batch: &Batch| {
            let mut encoded = Vec::new();
            crate::Record::RelayBatch(batch.clone())
                .encode(&mut encoded)
                .is_ok()
                && encoded.len() <= crate::noise::MAX_PLAINTEXT
        };
        for (count, length) in [
            (0usize, 14usize),
            (40, 14),
            (2_700, 14),
            (2_800, 14),
            (3, 30_000),
        ] {
            let observations: Vec<Observation> = (0..count)
                .map(|n| Observation {
                    format: format::MODE_S_LONG,
                    timestamp: 1_000 + n as u64,
                    signal: (n % 251) as u8,
                    data: vec![(n % 256) as u8; length],
                })
                .collect();
            let content = BatchContent {
                boot_id: 11,
                sequence: 4,
                counter_epoch: 0,
                wall_ms: 1_791_244_800_000,
                dropped: 0,
                previous: [7; 32],
                observations: observations.clone(),
            };
            let draft = BatchDraft {
                boot_id: 11,
                sequence: 4,
                counter_epoch: 0,
                wall_ms: content.wall_ms,
                dropped: 0,
                previous: [7; 32],
                observations: observations.iter().map(ObsView::from).collect(),
            };
            let owned = Batch::sign_as_relay(&relay, &content)?;
            let borrowed = Batch::sign_relay_draft(&relay, &draft)?;
            assert_eq!(borrowed, owned, "{count} of {length} bytes");
            borrowed.verify_as_relay()?;
            assert_eq!(
                Batch::relay_draft_fits(&draft),
                fits_record(&owned),
                "{count} of {length} bytes"
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
    fn a_public_description_round_trips_and_carries_no_site() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let location = Location {
            lat_e7: 374_100_000,
            lon_e7: -1_221_000_000,
            alt_m: 12,
            precision_m: 0,
        };
        for cell in [None, Some(crate::region::Region::public_cell(&location)?)] {
            let content = PublicInfoContent {
                issued_ms: 9,
                cell,
                clock: Clock::Beast,
                software: "tally-feed 0.4.0".to_owned(),
                relays: vec![Identity::generate()?.public()],
            };
            let info = ReceiverInfo::sign_public(&identity, &content)?;
            let back = ReceiverInfo::from_bytes(info.as_bytes().to_vec())?;
            back.verify()?;
            assert_eq!(back.format(), RECEIVER_INFO_FORMAT_PUBLIC);
            assert_eq!(back.public()?, content);
            assert_eq!(back.description()?, Description::Public(content.clone()));
            assert_eq!(back.public_cell()?, cell);
            assert_eq!(back.issued_ms()?, 9);
            assert!(!back.carries_site());
            assert_eq!(back.site_id(), None);
            assert!(back.content().is_err());
            assert_eq!(content.holds(&location), cell.is_some());
        }
        // A cell finer than the public resolution is refused on both sides.
        let fine = PublicInfoContent {
            issued_ms: 9,
            cell: Some(crate::region::Region::point(&location)?),
            clock: Clock::Beast,
            software: String::new(),
            relays: Vec::new(),
        };
        assert!(ReceiverInfo::sign_public(&identity, &fine).is_err());
        // A format 1 description carries the site and is named by an id that is not its hash.
        let old = ReceiverInfo::sign(
            &identity,
            &ReceiverInfoContent {
                issued_ms: 3,
                location: Some(location),
                clock: Clock::Beast,
                software: String::new(),
                relays: Vec::new(),
            },
        )?;
        assert!(old.carries_site());
        assert_eq!(old.issued_ms()?, 3);
        assert_eq!(
            old.public_cell()?,
            Some(crate::region::Region::public_cell(&location)?)
        );
        assert_eq!(
            old.site_id(),
            Some(crate::site::SiteId::of_signed(old.as_bytes()))
        );
        assert!(matches!(old.description()?, Description::Site(_)));
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
