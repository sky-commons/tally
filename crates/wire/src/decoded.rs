//! A verified batch decoded once (RFC-0177 §1): its fixed fields, its observations inflated once
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

use std::sync::{Arc, OnceLock};

use bytes::Bytes;

use crate::WireError;
use crate::batch::{Batch, Hash, Observation};
use crate::beast::{Frame, FrameKind};
use crate::key::PublicKey;

/// The fixed part of one encoded observation: format, 48-bit counter, signal, length.
const OBSERVATION_FIXED: usize = 1 + 6 + 1 + 2;

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
        let mut seed = [0u8; 32];
        if getrandom::getrandom(&mut seed).is_err() {
            // No OS randomness: the standard library's per-process random hasher keys, which
            // are seeded from it too when it works at all. Still unknown outside the process.
            use std::hash::{BuildHasher, Hasher};
            let state = std::collections::hash_map::RandomState::new();
            for (index, chunk) in seed.chunks_mut(8).enumerate() {
                let mut hasher = state.build_hasher();
                hasher.write_usize(index);
                chunk.copy_from_slice(&hasher.finish().to_le_bytes());
            }
        }
        Self::from_bytes(seed)
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

/// A batch whose decoding failed: the batch, so it is still forwarded raw (a format this build
/// cannot read), and why.
#[derive(Debug)]
pub struct Undecodable {
    pub batch: Batch,
    pub error: WireError,
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
    stamp_ms: u64,
    ingest_seq: u64,
    plain: Bytes,
    obs: Box<[ObsRef]>,
}

impl Decoded {
    /// Decodes `batch`, whose signature the caller has already verified (this does not verify it),
    /// under the process's fingerprint key. `stamp_ms` is the ingest clock's reading when it was
    /// taken and `ingest_seq` its place in the ingest order: what every later decision reads, never
    /// a clock of its own. Inflates once and makes two allocations whatever the batch holds (the
    /// observations' references, and for a compressed batch its inflated bytes); a message is a
    /// slice of those bytes.
    pub fn from_verified(
        batch: Batch,
        stamp_ms: u64,
        ingest_seq: u64,
    ) -> Result<Arc<Self>, Box<Undecodable>> {
        Self::from_verified_keyed(batch, FingerprintKey::process(), stamp_ms, ingest_seq)
    }

    /// As `from_verified`, the fingerprints under `key`.
    pub fn from_verified_keyed(
        batch: Batch,
        key: &FingerprintKey,
        stamp_ms: u64,
        ingest_seq: u64,
    ) -> Result<Arc<Self>, Box<Undecodable>> {
        match Self::decode(&batch, key) {
            Ok((receiver, header, plain, obs)) => Ok(Arc::new(Self {
                batch,
                receiver,
                boot_id: header.boot_id,
                sequence: header.sequence,
                counter_epoch: header.counter_epoch,
                wall_ms: header.wall_ms,
                dropped: header.dropped,
                previous: header.previous,
                stamp_ms,
                ingest_seq,
                plain,
                obs,
            })),
            Err(error) => Err(Box::new(Undecodable { batch, error })),
        }
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

    /// The ingest clock when the batch was taken: the only time a later stage decides by.
    pub fn stamp_ms(&self) -> u64 {
        self.stamp_ms
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
                data: vec![n; if n % 3 == 0 { 432 } else { 14 }],
            })
            .collect()
    }

    #[test]
    fn a_decoded_batch_reads_as_its_content_in_either_codec() -> Result<(), WireError> {
        let identity = Identity::generate()?;
        let key = FingerprintKey::from_bytes([1; 32]);
        for codec in [Codec::Plain, Codec::Deflate] {
            let content = content(observations());
            let batch = Batch::sign_with(&identity, &content, codec)?;
            let decoded = Decoded::from_verified_keyed(batch.clone(), &key, 11, 12)
                .map_err(|undecodable| undecodable.error)?;
            assert_eq!(decoded.batch(), &batch);
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
        let undecodable = Decoded::from_verified(forged.clone(), 0, 0)
            .err()
            .ok_or(WireError::Timeout)?;
        assert_eq!(undecodable.batch, forged);
        assert!(forged.content().is_err());
        Ok(())
    }
}
