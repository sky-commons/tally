//! A verified batch decoded once (RFC-0181 §1): its fixed fields, its observations inflated once
//! into one shared buffer, and each reception's place in that buffer with its one fingerprint.
//! Every stage of a relay that reads a batch's receptions (the hub's deduplicated stream, the
//! regional product, standing, the hosted MLAT engine, the BEAST output) takes this, shared
//! (`Arc<Decoded>`), and none inflates, verifies or allocates per reception again.
//!
//! # The fingerprint
//!
//! A reception's message is remembered by a 128-bit fingerprint of its format and bytes, never by a
//! copy of them. It is two SipHash-2-4 outputs under two independent 128-bit keys drawn from the
//! operating system once per process ([`FingerprintKey::process`]), concatenated. SipHash-2-4 is a
//! pseudorandom function designed for exactly this: hash tables whose keys an adversary chooses. A
//! feeder chooses the messages it signs, so an unkeyed or guessable hash would let it make two
//! different messages share a fingerprint (one suppressing the other in every deduplication) or
//! make every message fall in one shard. Under a secret key it can do neither better than chance,
//! and two real messages share a fingerprint with probability about 2^-128 a pair. The key never
//! leaves the process, so fingerprints are only ever compared within one relay; nothing on the
//! wire carries one. BLAKE2s keyed would serve too but costs several times as much per message at
//! twelve million receptions a second, for no property this use needs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;

use crate::WireError;
use crate::batch::{Batch, Hash, Observation};
use crate::beast::{Frame, FrameKind};
use crate::clocks::{Judged, Moment, Mono};
use crate::key::PublicKey;

/// The fixed part of one encoded observation: format, 48-bit counter, signal, length.
pub const OBSERVATION_FIXED: usize = 1 + 6 + 1 + 2;

/// The secret keys of the fingerprint (module docs): two SipHash-2-4 keys of 128 bits each.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FingerprintKey {
    halves: [(u64, u64); 2],
}

impl std::fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A secret: never printed.
        f.write_str("FingerprintKey(..)")
    }
}

impl FingerprintKey {
    /// Fresh keys from the operating system's randomness.
    pub fn random() -> Self {
        Self::from_bytes(Self::fresh_seed())
    }

    /// Fresh key bytes from the operating system's randomness (the `getrandom` crate, no `unsafe`
    /// of ours), what [`FingerprintKey::random`] keys from and what a relay keeps as its
    /// directory's key. With no OS randomness, the standard library's per-process random hasher
    /// keys, which are seeded from it too when it works at all: still unknown outside the process.
    pub fn fresh_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        if getrandom::getrandom(&mut seed).is_err() {
            use std::hash::{BuildHasher, Hasher};
            let state = std::collections::hash_map::RandomState::new();
            for (index, chunk) in seed.chunks_mut(8).enumerate() {
                let mut hasher = state.build_hasher();
                hasher.write_usize(index);
                chunk.copy_from_slice(&hasher.finish().to_le_bytes());
            }
        }
        seed
    }

    /// Keys from 32 bytes: for tests that need the same fingerprints twice.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        let word = |at: usize| {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&seed[at..at + 8]);
            u64::from_le_bytes(bytes)
        };
        Self {
            halves: [(word(0), word(8)), (word(16), word(24))],
        }
    }

    /// This process's keys: drawn once, the same for every batch decoded here, so every stage
    /// compares the same fingerprints.
    pub fn process() -> &'static Self {
        static KEY: OnceLock<FingerprintKey> = OnceLock::new();
        KEY.get_or_init(Self::random)
    }

    /// The fingerprint of one message: its format byte, then its bytes.
    pub fn fingerprint(&self, format: u8, data: &[u8]) -> u128 {
        let [(a0, a1), (b0, b1)] = self.halves;
        (u128::from(siphash24(a0, a1, format, data)) << 64)
            | u128::from(siphash24(b0, b1, format, data))
    }
}

/// The domains of the process's keyed hashes other than a message's fingerprint, each taken under
/// [`FingerprintKey::process`] in place of a format byte: listed once, so no two share one.
pub mod keyed {
    /// A receiver's draw for an MLAT seat (`tally_mlat::intake::draw`).
    pub const SEAT_DRAW: u8 = 0xf0;
    /// An ICAO address's shard (`tally_mlat::provisional::shard_of`, the relay's address shards).
    pub const ADDRESS_SHARD: u8 = 0xf1;
    /// A receiver's raw shard (`tally_relay::exchange::raw_shard`).
    pub const RAW_SHARD: u8 = 0xf2;
    /// A record's fingerprint in a relay's strike register (`tally_relay::strikes`), over its
    /// hash.
    pub const STRIKE: u8 = 0xf3;
    /// A relay's state file's code (`tally_relay::durable`), over the file before it, under the
    /// state directory's key.
    pub const STATE: u8 = 0xf4;
    /// A relay's state directory's key named, a keyed hash of a constant (`tally_relay::durable`):
    /// a file written under another key is known at once.
    pub const STATE_KEY_ID: u8 = 0xf5;
    /// One record of a relay's table log (`tally_relay::durable::Log`).
    pub const STATE_LOG: u8 = 0xf6;
    /// A freshness anchor's slot in a relay's cache of verified anchors
    /// (`tally_relay::anchors`), over its bytes.
    pub const ANCHOR_SLOT: u8 = 0xf7;
}

/// One reception of a decoded batch: its fixed fields, where its message is in the batch's plain
/// bytes, and its fingerprint. Its message is [`Decoded::data`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObsRef {
    /// The fingerprint of (format, message) under the process key (module docs).
    pub fp: u128,
    /// The receiver's 48-bit counter, raw.
    pub timestamp: u64,
    /// Where the message starts in [`Decoded::plain`].
    off: u32,
    /// The message's length. A `u16`, not a `u8`: a UAT uplink is 432 bytes.
    len: u16,
    pub format: u8,
    pub signal: u8,
}

impl ObsRef {
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One reception as a client may be given it (wire version 3, `crate::client`): its message and
/// nothing of the receiver that heard it. A reception's counter is the receiver's clock, which
/// reverse multilateration against the aircraft positions anyone reads turns into the site, and its
/// signal level ranges the receiver against those positions; both are relay-only, so this form has
/// no room for either. It is what the relay's BEAST output (`--beast-out`) writes, the feed every
/// public map and API over a relay decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientObsView<'a> {
    pub format: u8,
    pub data: &'a [u8],
}

impl<'a> From<ObsView<'a>> for ClientObsView<'a> {
    fn from(view: ObsView<'a>) -> Self {
        Self {
            format: view.format,
            data: view.data,
        }
    }
}

impl ClientObsView<'_> {
    /// The BEAST frame, for a format BEAST carries: its counter and signal level zero, as a
    /// decoder reads a frame from a source that stamps neither.
    pub fn to_beast(&self) -> Option<Frame> {
        let kind = FrameKind::from_type_byte(self.format)?;
        Frame::new(kind, 0, 0, self.data).ok()
    }
}

impl<'a> ClientObsView<'a> {
    /// The line, for an ACARS-family reception that is one (`acars::line`, parsed, never taken on
    /// the feeder's word): what a relay's `--acars-out` writes, a newline after each.
    pub fn to_acars_line(&self) -> Option<&'a str> {
        if self.format != crate::batch::format::ACARS_JSON {
            return None;
        }
        crate::acars::line(self.data)
    }
}

/// One reception borrowed: from a decoded batch or from an owned `Observation`, so a reader of
/// receptions takes either without a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObsView<'a> {
    pub format: u8,
    pub timestamp: u64,
    pub signal: u8,
    pub data: &'a [u8],
}

impl ObsView<'_> {
    /// The BEAST frame, for a format BEAST carries.
    pub fn to_beast(&self) -> Option<Frame> {
        let kind = FrameKind::from_type_byte(self.format)?;
        Frame::new(kind, self.timestamp, self.signal, self.data).ok()
    }

    /// Its bytes in a signed list of receptions: the one encoding of a reception, whether it is
    /// borrowed or owned (an owned one is written as its view, `ObsView::from`).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.push(self.format);
        out.extend_from_slice(&self.timestamp.to_be_bytes()[2..]);
        out.push(self.signal);
        let length =
            u16::try_from(self.data.len()).map_err(|_| WireError::Oversize(self.data.len()))?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(self.data);
        Ok(())
    }

    /// An owned copy (what a stage that keeps the message past the batch holds).
    pub fn to_observation(&self) -> Observation {
        Observation {
            format: self.format,
            timestamp: self.timestamp,
            signal: self.signal,
            data: self.data.to_vec(),
        }
    }
}

impl<'a> From<&'a Observation> for ObsView<'a> {
    fn from(observation: &'a Observation) -> Self {
        Self {
            format: observation.format,
            timestamp: observation.timestamp,
            signal: observation.signal,
            data: &observation.data,
        }
    }
}

/// A batch whose decoding failed: the batch, and why (a format this build cannot read, or one it
/// reads that is malformed).
#[derive(Debug)]
pub struct Undecodable {
    pub batch: Batch,
    pub error: WireError,
}

/// What a decode holds for its life beside its own bytes: its holder's charge for them (a relay's,
/// `tally_relay::budget::Charge`), let go with the decode's last reference and never before it, so
/// however many stages share the decode its bytes are charged once, by whoever made it.
pub type Owner = Box<dyn std::any::Any + Send + Sync>;

/// Why a verified batch was not made a decode: it does not decode (a format this build cannot
/// read, or a malformed one), or its owner had no room for it (`Decoded::from_verified_owned`).
#[derive(Debug)]
pub enum NotDecoded {
    Undecodable(Box<Undecodable>),
    /// The owner refused the decode's bytes: the batch, untouched.
    NoRoom(Batch),
}

/// A verified batch decoded once (module docs). Immutable; shared as `Arc<Decoded>`.
#[derive(Debug)]
pub struct Decoded {
    batch: Batch,
    receiver: PublicKey,
    boot_id: u64,
    sequence: u64,
    counter_epoch: u32,
    wall_ms: u64,
    dropped: u32,
    previous: Hash,
    at: Moment,
    judging: bool,
    ingest_seq: u64,
    plain: Bytes,
    obs: Box<[ObsRef]>,
    /// Its charge, released when the last holder lets it go (after `live` stops counting it).
    owner: Option<Held>,
    /// Counted in `live`: set once it is shared, so one refused before that is never uncounted.
    counted: bool,
}

/// An [`Owner`], printed by its presence only.
struct Held(#[allow(dead_code)] Owner);

impl std::fmt::Debug for Held {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Owner")
    }
}

/// What an `Arc` adds to what it holds: its two reference counts.
pub const ARC_HEADER: usize = 2 * std::mem::size_of::<usize>();
/// What `Bytes` of a `Vec` adds once it is shared (cloned or sliced): its shared header (the
/// buffer, its capacity and a reference count), allocated on the first clone.
pub const BYTES_HEADER: usize = 3 * std::mem::size_of::<usize>();

/// Every `Decoded` alive in this process: how many, and the bytes they hold
/// ([`Decoded::footprint`]). A relay's stages share each one, so this is what every queue and
/// store downstream of ingest holds of batches together, whichever charged it: a relay serves it
/// beside its stores' gauges (`GET /memory`), so a holder that escapes them shows.
static LIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

/// (Decoded batches alive, the bytes they hold.)
pub fn live() -> (usize, usize) {
    (
        LIVE_COUNT.load(Ordering::Relaxed),
        LIVE_BYTES.load(Ordering::Relaxed),
    )
}

/// Told each decode's address as it is let go, once [`live`] has stopped counting it
/// ([`on_drop`]).
static ON_DROP: std::sync::OnceLock<fn(usize)> = std::sync::OnceLock::new();

/// Sets what is told each decode's address (`Arc::as_ptr`) as it is let go, after [`live`] has
/// stopped counting it: for a holder that tracks decodes by address (a relay's charges,
/// `tally_relay::budget::Covered`) to mark it gone at the moment it leaves `live`, so the two agree
/// at every instant, never only once whoever last held it has let its charge go too. One a
/// process: false if one was already set.
pub fn on_drop(hook: fn(usize)) -> bool {
    ON_DROP.set(hook).is_ok()
}

impl Drop for Decoded {
    fn drop(&mut self) {
        // Never shared: never counted, and nothing tracks it.
        if !self.counted {
            return;
        }
        LIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
        LIVE_BYTES.fetch_sub(self.footprint(), Ordering::Relaxed);
        if let Some(hook) = ON_DROP.get() {
            hook(std::ptr::from_ref(self) as usize);
        }
    }
}

impl Decoded {
    /// What this decode allocated itself: the struct in its `Arc` (and the counts beside it), its
    /// inflated bytes when they are its own allocation (at their capacity, with the header `Bytes`
    /// adds once they are shared) and the receptions' references. Not the signed batch: those bytes
    /// are their own allocation, shared with every holder of the batch, and charged on their own
    /// (`Batch::footprint`), so the two are each counted once however many stages hold them.
    pub fn footprint(&self) -> usize {
        let batch = self.batch.as_bytes();
        let shares_batch = self.plain.as_ptr() >= batch.as_ptr()
            && self.plain.as_ptr() < batch.as_ptr().wrapping_add(batch.len());
        ARC_HEADER
            + std::mem::size_of::<Self>()
            + if shares_batch {
                0
            } else {
                self.plain.len() + BYTES_HEADER
            }
            + std::mem::size_of_val(&*self.obs)
    }

    /// Whether it carries its own charge ([`Decoded::from_verified_owned`]).
    pub fn is_owned(&self) -> bool {
        self.owner.is_some()
    }

    /// Decodes `batch`, whose signature the caller has already verified (this does not verify it),
    /// under the process's fingerprint key. `at` is the instant its stamp read the ingest's clocks
    /// (`M` and `J` together) and `ingest_seq` its place in the ingest order: what every later
    /// decision reads, never a clock of its own. Inflates once and makes two allocations whatever
    /// the batch holds (the observations' references, and for a compressed batch its inflated
    /// bytes); a message is a slice of those bytes. Taken while its clock judged: for a holder
    /// whose clock always does (a reference engine, a replay, a test).
    pub fn from_verified(
        batch: Batch,
        at: Moment,
        ingest_seq: u64,
    ) -> Result<Arc<Self>, Box<Undecodable>> {
        Self::from_verified_keyed(batch, FingerprintKey::process(), at, ingest_seq)
    }

    /// As `from_verified`, taken at `at` while its clock judged or not (`judging`, read in the
    /// same instant, [`Decoded::judging`]): a relay's, whose clock may not judge.
    pub fn from_verified_stamped(
        batch: Batch,
        (at, judging): (Moment, bool),
        ingest_seq: u64,
    ) -> Result<Arc<Self>, Box<Undecodable>> {
        Self::decode_unshared(batch, FingerprintKey::process(), at, judging, ingest_seq)
            .map(|decoded| Self::shared(decoded, |_| {}))
    }

    /// As `from_verified`, the fingerprints under `key`.
    pub fn from_verified_keyed(
        batch: Batch,
        key: &FingerprintKey,
        at: Moment,
        ingest_seq: u64,
    ) -> Result<Arc<Self>, Box<Undecodable>> {
        Self::decode_unshared(batch, key, at, true, ingest_seq)
            .map(|decoded| Self::shared(decoded, |_| {}))
    }

    /// As `from_verified`, the decode charged for its life by `owner`, which is told the decode's
    /// own bytes ([`Decoded::footprint`]) before it is shared and keeps what it returns inside the
    /// decode, let go with its last reference (after `live` has stopped counting it); `None` from
    /// `owner` refuses the decode, and the batch comes back ([`NotDecoded::NoRoom`]). `held` is
    /// given the decode once it is shared and before it is counted alive ([`live`]): a holder that
    /// tracks its charge there (a relay's, `tally_relay::budget::Covered`) is never seen with a
    /// decode alive that nothing has charged, not even for an instant. So a decode is charged
    /// exactly once, by whoever made it, however many stages share it, and none is alive that its
    /// own charge does not hold.
    /// `judging` is whether the clock judged when the stamp was read ([`Decoded::judging`]), read
    /// in the same instant as `at`.
    pub fn from_verified_owned(
        batch: Batch,
        (at, judging): (Moment, bool),
        ingest_seq: u64,
        owner: impl FnOnce(&Self) -> Option<Owner>,
        held: impl FnOnce(&Arc<Self>),
    ) -> Result<Arc<Self>, NotDecoded> {
        let mut decoded = match Self::decode_unshared(
            batch,
            FingerprintKey::process(),
            at,
            judging,
            ingest_seq,
        ) {
            Ok(decoded) => decoded,
            Err(undecodable) => return Err(NotDecoded::Undecodable(undecodable)),
        };
        match owner(&decoded) {
            Some(charge) => decoded.owner = Some(Held(charge)),
            None => return Err(NotDecoded::NoRoom(decoded.batch.clone())),
        }
        Ok(Self::shared(decoded, held))
    }

    /// The batch decoded, not yet shared nor counted alive.
    fn decode_unshared(
        batch: Batch,
        key: &FingerprintKey,
        at: Moment,
        judging: bool,
        ingest_seq: u64,
    ) -> Result<Self, Box<Undecodable>> {
        match Self::decode(&batch, key) {
            Ok((receiver, header, plain, obs)) => Ok(Self {
                batch,
                receiver,
                boot_id: header.boot_id,
                sequence: header.sequence,
                counter_epoch: header.counter_epoch,
                wall_ms: header.wall_ms,
                dropped: header.dropped,
                previous: header.previous,
                at,
                judging,
                ingest_seq,
                plain,
                obs,
                owner: None,
                counted: false,
            }),
            Err(error) => Err(Box::new(Undecodable { batch, error })),
        }
    }

    /// `decoded` shared, `held` told, then counted alive.
    fn shared(mut decoded: Self, held: impl FnOnce(&Arc<Self>)) -> Arc<Self> {
        let footprint = decoded.footprint();
        decoded.counted = true;
        let decoded = Arc::new(decoded);
        held(&decoded);
        LIVE_COUNT.fetch_add(1, Ordering::Relaxed);
        LIVE_BYTES.fetch_add(footprint, Ordering::Relaxed);
        decoded
    }

    #[allow(clippy::type_complexity)]
    fn decode(
        batch: &Batch,
        key: &FingerprintKey,
    ) -> Result<(PublicKey, crate::batch::Header, Bytes, Box<[ObsRef]>), WireError> {
        let receiver = batch.receiver()?;
        let (header, plain) = batch.header_and_plain()?;
        let count = read(&plain, 0, 4)?;
        let count = u32::from_be_bytes([count[0], count[1], count[2], count[3]]) as usize;
        // Every observation takes at least its fixed part, so a count the bytes cannot hold is
        // refused before anything is reserved for it.
        if count > (plain.len() - 4) / OBSERVATION_FIXED {
            return Err(WireError::Truncated {
                needed: 4 + count.saturating_mul(OBSERVATION_FIXED),
                had: plain.len(),
            });
        }
        let mut obs = Vec::with_capacity(count);
        let mut at = 4;
        for _ in 0..count {
            let fixed = read(&plain, at, OBSERVATION_FIXED)?;
            let format = fixed[0];
            crate::batch::composed(batch.format(), format)?;
            let mut counter = [0; 8];
            counter[2..].copy_from_slice(&fixed[1..7]);
            let signal = fixed[7];
            let len = u16::from_be_bytes([fixed[8], fixed[9]]);
            let off = at + OBSERVATION_FIXED;
            let data = read(&plain, off, usize::from(len))?;
            obs.push(ObsRef {
                fp: key.fingerprint(format, data),
                timestamp: u64::from_be_bytes(counter),
                // Bounded by `MAX_PLAIN_LEN` (inflated) or a record's size (plain).
                off: u32::try_from(off).map_err(|_| WireError::Oversize(off))?,
                len,
                format,
                signal,
            });
            at = off + usize::from(len);
        }
        Ok((receiver, header, plain, obs.into_boxed_slice()))
    }

    /// The signed batch, shared with every other holder.
    pub fn batch(&self) -> &Batch {
        &self.batch
    }

    pub fn receiver(&self) -> PublicKey {
        self.receiver
    }

    pub fn boot_id(&self) -> u64 {
        self.boot_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn counter_epoch(&self) -> u32 {
        self.counter_epoch
    }

    /// The feeder's signed wall clock, Unix milliseconds.
    pub fn wall_ms(&self) -> u64 {
        self.wall_ms
    }

    /// Receptions the feeder's own ceiling dropped since its previous batch.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    pub fn previous(&self) -> &Hash {
        &self.previous
    }

    /// The ingest's monotonic clock when the batch was taken, in milliseconds: the only time a
    /// later stage orders and ages by.
    pub fn stamp_ms(&self) -> u64 {
        self.at.mono().ms()
    }

    /// The ingest's monotonic clock when the batch was taken.
    pub fn mono(&self) -> Mono {
        self.at.mono()
    }

    /// The judging clock when the batch was taken: what its signed time is compared against
    /// (`crate::budget`), as the stamp is the monotonic clock every later stage orders by. The two
    /// part when the host's clock is stepped; a holder whose one clock is both has them equal.
    pub fn judged(&self) -> Judged {
        self.at.judged()
    }

    /// The instant its stamp read both clocks.
    pub fn at(&self) -> Moment {
        self.at
    }

    /// Whether the clock judged when the batch was stamped: one taken while it did not is never
    /// blamed, and nothing is signed from it (RFC-0171 §3.6).
    pub fn judging(&self) -> bool {
        self.judging
    }

    /// The batch's place in the ingest order.
    pub fn ingest_seq(&self) -> u64 {
        self.ingest_seq
    }

    /// The observations' plain bytes (`count u32 | observations`), inflated once.
    pub fn plain(&self) -> &Bytes {
        &self.plain
    }

    /// Every reception, in the batch's order.
    pub fn observations(&self) -> &[ObsRef] {
        &self.obs
    }

    /// How many bytes its observations took inflated (`Batch::inflated_len`, now exact): with
    /// `receptions`, what a relay charges for the batch's work, never its wire bytes alone.
    pub fn inflated_len(&self) -> usize {
        self.plain.len()
    }

    /// How many receptions it holds (at most `Batch::receptions_at_most`).
    pub fn receptions(&self) -> usize {
        self.obs.len()
    }

    /// A reception's message bytes.
    pub fn data(&self, obs: &ObsRef) -> &[u8] {
        let start = obs.off as usize;
        self.plain.get(start..start + obs.len()).unwrap_or_default()
    }

    /// A reception borrowed whole.
    pub fn view(&self, obs: &ObsRef) -> ObsView<'_> {
        ObsView {
            format: obs.format,
            timestamp: obs.timestamp,
            signal: obs.signal,
            data: self.data(obs),
        }
    }

    /// Every reception borrowed, in order.
    pub fn views(&self) -> impl ExactSizeIterator<Item = ObsView<'_>> + '_ {
        self.obs.iter().map(|obs| self.view(obs))
    }
}

fn read(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], WireError> {
    bytes.get(at..at + len).ok_or(WireError::Truncated {
        needed: at + len,
        had: bytes.len(),
    })
}

/// SipHash-2-4 (Aumasson and Bernstein, 2012) of `format` then `data` under key (k0, k1), as the
/// reference implementation computes it over that byte string.
fn siphash24(k0: u64, k1: u64, format: u8, data: &[u8]) -> u64 {
    let mut state = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let total = data.len() + 1;
    let mut word = [0u8; 8];
    let mut filled = 0;
    let bytes = std::iter::once(format).chain(data.iter().copied());
    for byte in bytes {
        word[filled] = byte;
        filled += 1;
        if filled == 8 {
            compress(&mut state, u64::from_le_bytes(word));
            filled = 0;
        }
    }
    let mut last = [0u8; 8];
    last[..filled].copy_from_slice(&word[..filled]);
    let last = u64::from_le_bytes(last) | ((total as u64 & 0xff) << 56);
    compress(&mut state, last);
    state[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut state);
    }
    state[0] ^ state[1] ^ state[2] ^ state[3]
}

fn compress(state: &mut [u64; 4], word: u64) {
    state[3] ^= word;
    round(state);
    round(state);
    state[0] ^= word;
}

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use crate::batch::{BatchContent, Codec, format};
    use crate::key::Identity;

    #[test]
    fn siphash_matches_the_papers_test_vector() {
        // Appendix A of the SipHash paper: key 00..0f, message 00..0e, output a129ca6149be45e5.
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        let message: Vec<u8> = (1..15).collect();
        assert_eq!(siphash24(k0, k1, 0, &message), 0xa129_ca61_49be_45e5);
    }

    fn content(observations: Vec<Observation>) -> BatchContent {
        BatchContent {
            boot_id: 7,
            sequence: 3,
            counter_epoch: 2,
            wall_ms: 1_700_000_000_000,
            dropped: 5,
            previous: [9; 32],
            observations,
        }
    }

    fn observations() -> Vec<Observation> {
        (0..40u8)
            .map(|n| Observation {
                format: if n % 3 == 0 {
                    format::UAT_UPLINK
                } else {
                    format::MODE_S_LONG
                },
                timestamp: u64::from(n) * 1_000 + 0xfff0_0000_0000,
                signal: n,
                // Varied, as real messages are: a batch denser than `MAX_INFLATION` is written
                // plain whatever codec is asked for.
                data: (0..if n % 3 == 0 { 432 } else { 14 })
                    .map(|at: usize| (at as u8).wrapping_mul(31) ^ n)
                    .collect(),
            })
            .collect()
    }

    /// A client's frame of a reception is its message alone: the same message heard at another
    /// counter, or louder, is the same frame, with counter and signal zero; a format BEAST does
    /// not carry has none.
    #[test]
    fn a_clients_frame_has_no_counter_and_no_signal() -> Result<(), WireError> {
        for observation in observations() {
            let view = ObsView::from(&observation);
            let client = ClientObsView::from(view).to_beast();
            if observation.format == format::UAT_UPLINK {
                assert_eq!(client, None);
                continue;
            }
            let frame = client.ok_or(WireError::Invalid {
                field: "frame",
                value: 0,
            })?;
            assert_eq!((frame.timestamp(), frame.signal()), (0, 0));
            assert_eq!(frame.message(), observation.data.as_slice());
            let elsewhere = ObsView {
                timestamp: observation.timestamp + 12_345,
                signal: observation.signal.wrapping_add(80),
                ..view
            };
            assert_eq!(ClientObsView::from(elsewhere).to_beast(), Some(frame));
        }
        Ok(())
    }

    #[test]
    fn a_decoded_batch_reads_as_its_content_in_either_codec() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let key = FingerprintKey::from_bytes([1; 32]);
        for codec in [Codec::Plain, Codec::Deflate] {
            let content = content(observations());
            let batch = Batch::sign_with(&identity, &content, codec)?;
            let decoded = Decoded::from_verified_keyed(
                batch.clone(),
                &key,
                crate::clocks::recorded::aligned(11),
                12,
            )
            .map_err(|undecodable| undecodable.error)?;
            assert_eq!(decoded.batch(), &batch);
            let format = match codec {
                Codec::Plain => crate::batch::BATCH_FORMAT,
                Codec::Deflate | Codec::DeflateAt(_) => crate::batch::BATCH_FORMAT_DEFLATE,
            };
            assert_eq!(batch.format(), format);
            assert_eq!(decoded.inflated_len(), batch.inflated_len()?);
            assert_eq!(decoded.receptions(), content.observations.len());
            assert!(decoded.receptions() <= batch.receptions_at_most()?);
            // Stated before any decode, in either codec: what a relay paces receptions by.
            assert_eq!(batch.receptions()?, decoded.receptions());
            assert_eq!(decoded.receiver(), identity.public());
            assert_eq!(
                (
                    decoded.boot_id(),
                    decoded.sequence(),
                    decoded.counter_epoch()
                ),
                (7, 3, 2)
            );
            assert_eq!((decoded.wall_ms(), decoded.dropped()), (content.wall_ms, 5));
            assert_eq!(decoded.previous(), &[9; 32]);
            assert_eq!((decoded.stamp_ms(), decoded.ingest_seq()), (11, 12));
            let back: Vec<Observation> =
                decoded.views().map(|view| view.to_observation()).collect();
            assert_eq!(back, content.observations);
            for (obs, observation) in decoded.observations().iter().zip(&content.observations) {
                assert_eq!(
                    obs.fp,
                    key.fingerprint(observation.format, &observation.data)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn the_fingerprint_reads_format_and_message_and_depends_on_the_key() {
        let key = FingerprintKey::from_bytes([1; 32]);
        let other = FingerprintKey::from_bytes([2; 32]);
        let a = key.fingerprint(format::MODE_S_SHORT, &[1, 2, 3]);
        assert_eq!(a, key.fingerprint(format::MODE_S_SHORT, &[1, 2, 3]));
        assert_ne!(a, key.fingerprint(format::MODE_S_LONG, &[1, 2, 3]));
        assert_ne!(a, key.fingerprint(format::MODE_S_SHORT, &[1, 2, 4]));
        assert_ne!(a, other.fingerprint(format::MODE_S_SHORT, &[1, 2, 3]));
    }

    #[test]
    fn a_batch_that_does_not_decode_comes_back_whole() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let batch = Batch::sign(&identity, &content(observations()))?;
        let mut bytes = batch.as_bytes().to_vec();
        // A count far beyond what the bytes hold.
        let count_at = 1 + 32 + 8 + 8 + 4 + 8 + 4 + 32;
        bytes[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let forged = Batch::from_bytes(bytes)?;
        let undecodable =
            Decoded::from_verified(forged.clone(), crate::clocks::recorded::aligned(0), 0)
                .err()
                .ok_or(WireError::Timeout)?;
        assert_eq!(undecodable.batch, forged);
        assert!(forged.content().is_err());
        Ok(())
    }
}
