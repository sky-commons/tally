//! Canonical selection by hash threshold: an item is kept when the first eight bytes of its hash,
//! read big-endian as a `u64`, are below a fixed threshold. Never top-k: whether one item is kept
//! depends on that item alone, so what a holder of a subset of the raw keeps is exactly what a
//! holder of a superset keeps, restricted to the subset, and a model over less is a strict subset
//! of one over more. A hard cap on what is kept stays, as a refusal by the relay-wide budget,
//! never as trimming by rank.
//!
//! What a holder keeps of one receiver's batch (`arrived::Arrived::admit`) is decided by that
//! batch alone, so holders of the same batches keep the same receptions whatever order they came
//! in:
//!
//! - **Sync**: every sync event (an airborne position with an altitude) and every operational
//!   status of a reference aircraft ([`reference`], by its address alone), and nothing of any
//!   other aircraft. A batch carrying `c` reference events keeps each at the rate
//!   `min(1, REFERENCE_EVENTS_PER_BATCH / c)` ([`batch_sync_keep`]), by the message alone
//!   ([`sync_key`]): every receiver of an event keeps it at its own batch's rate, and since the
//!   key is the message's, a receiver at a lower rate keeps a subset of what one at a higher rate
//!   keeps. No batch is cut at a cliff: one event more thins a batch by one in `c`.
//!
//! - **Replies**: every reply, but those of an aircraft the same batch carries an ADS-B position
//!   of (it is no MLAT target) unless it is in the calibration sample. Only a batch carrying more
//!   than [`REPLIES_PER_BATCH`] is thinned, to those [`KEPT_KEEP`] keeps by the message alone
//!   ([`reply_key`]).
//!
//! Each threshold is stated as an absolute fraction of every candidate, not of what an earlier
//! threshold kept.

use blake2::{Blake2s256, Digest};

use crate::obs::Reception;

/// Keep iff the first eight bytes of a hash, big-endian, are below `self.0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Threshold(pub u64);

impl Threshold {
    /// The threshold that keeps `keep_per_million` in a million uniform hashes:
    /// `floor(keep_per_million * 2^64 / 1_000_000)`. A rate of a million or more keeps every hash
    /// but those whose first eight bytes are all ones (one in 2^64).
    pub const fn of_rate(keep_per_million: u32) -> Self {
        if keep_per_million >= 1_000_000 {
            return Self(u64::MAX);
        }
        Self((((keep_per_million as u128) << 64) / 1_000_000) as u64)
    }

    /// Whether `hash` is kept.
    pub fn keeps(self, hash: &[u8; 32]) -> bool {
        let mut head = [0u8; 8];
        head.copy_from_slice(&hash[..8]);
        u64::from_be_bytes(head) < self.0
    }
}

/// Reference aircraft: an aircraft's sync events are all kept when its [`reference_key`] is below
/// this, and none otherwise. It keeps every aircraft heard with ADS-B (ruled 2026-10-24): at about
/// a quarter of them (the old `SYNC_AIRCRAFT_MAX = 16` of 60) the sweep's tiles had one reference
/// aircraft at the median and the calibration mix's median error was 46.5 m; with all of them,
/// 33.8 m. It stays a threshold, so a holder of fewer batches keeps a subset, and a rate below a
/// million would thin aircraft everywhere. A pair's points are one an event its two clocks
/// heard, whatever the aircraft (crate docs, § The pairwise path, a pair's points), so no count
/// of them caps an area's inputs.
pub const REFERENCE_KEEP: Threshold = Threshold::of_rate(1_000_000);
/// The reference aircraft's sync events one batch of one receiver keeps whole: a batch carrying
/// more keeps about this many of them (`batch_sync_keep`). A feeder seals a batch every second, so
/// a second of 16 reference aircraft at their two airborne positions a second.
pub const REFERENCE_EVENTS_PER_BATCH: usize = 32;
/// The threshold a batch carrying `events` reference events keeps each of them at (by
/// [`sync_key`]): every one up to [`REFERENCE_EVENTS_PER_BATCH`], and
/// `REFERENCE_EVENTS_PER_BATCH / events` of them beyond, so a busy batch keeps about as many as a
/// full one and one event more never halves it.
pub fn batch_sync_keep(events: usize) -> Threshold {
    if events <= REFERENCE_EVENTS_PER_BATCH {
        return Threshold::of_rate(1_000_000);
    }
    let rate = REFERENCE_EVENTS_PER_BATCH as u64 * 1_000_000 / events as u64;
    Threshold::of_rate(u32::try_from(rate).unwrap_or(u32::MAX))
}

/// The replies one batch of one receiver keeps whole: a batch carrying more keeps of them only
/// those [`KEPT_KEEP`] keeps. A second at `arrived::KEPT_CEILING_PER_S`, as a feeder seals a batch
/// every second.
pub const REPLIES_PER_BATCH: usize = 300;
/// Replies a batch over [`REPLIES_PER_BATCH`] keeps. Replaces `KEPT_PER_RECEIVER_BIN`
/// (`KEPT_CEILING_PER_S = 300` a second), over the measured 360 wanted receptions a receiver a
/// second (`Rates::MEASURED`): 300 / 360 = 833,333 a million.
pub const KEPT_KEEP: Threshold = Threshold::of_rate(833_333);

/// What a sync event's selection key is hashed under.
const SYNC_DOMAIN: &[u8] = b"tally sync selection";
/// What a reference aircraft's key is hashed under.
const REFERENCE_DOMAIN: &[u8] = b"tally reference aircraft";
/// What a reply's selection key is hashed under.
const REPLY_DOMAIN: &[u8] = b"tally reply selection";

/// A sync event's selection key: BLAKE2s-256 over `"tally sync selection" 0x00` and the hash of
/// the message bytes. A function of the message alone, so every receiver of one event, and every
/// holder of any of its receptions, keeps or drops it together.
pub fn sync_key(r: &Reception) -> [u8; 32] {
    message_key(SYNC_DOMAIN, &crate::obs::message_hash(&r.message))
}

/// An aircraft's reference key: BLAKE2s-256 over `"tally reference aircraft" 0x00` and its
/// address, big-endian. A function of the address alone, so whether an aircraft syncs clocks
/// never depends on where or when it was heard, nor on what else was.
pub fn reference_key(address: u32) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(REFERENCE_DOMAIN);
    hasher.update([0]);
    hasher.update(address.to_be_bytes());
    hasher.finalize().into()
}

/// Whether `address` is a reference aircraft, whose sync events and status are kept.
pub fn reference(address: u32) -> bool {
    REFERENCE_KEEP.keeps(&reference_key(address))
}

/// A reply's selection key: BLAKE2s-256 over `"tally reply selection" 0x00` and the hash of the
/// message bytes (`message_hash`). A function of the message alone, so every receiver of one
/// transmission keeps or drops it together, and a thinned transmission is still solvable.
pub fn reply_key(message_hash: &[u8; 32]) -> [u8; 32] {
    message_key(REPLY_DOMAIN, message_hash)
}

/// `sync_key` of a message by its hash.
pub(crate) fn sync_key_of(message_hash: &[u8; 32]) -> [u8; 32] {
    message_key(SYNC_DOMAIN, message_hash)
}

fn message_key(domain: &[u8], message_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(message_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(head: u64) -> [u8; 32] {
        let mut hash = [0xff; 32];
        hash[..8].copy_from_slice(&head.to_be_bytes());
        hash
    }

    #[test]
    fn a_rate_is_its_fraction_of_the_hash_space() {
        assert_eq!(Threshold::of_rate(0), Threshold(0));
        assert_eq!(Threshold::of_rate(500_000), Threshold(1 << 63));
        assert_eq!(Threshold::of_rate(250_000), Threshold(1 << 62));
        assert_eq!(Threshold::of_rate(1_000_000), Threshold(u64::MAX));
        assert_eq!(Threshold::of_rate(u32::MAX), Threshold(u64::MAX));
        // floor(2^64 / 1e6).
        assert_eq!(Threshold::of_rate(1), Threshold(18_446_744_073_709));
    }

    #[test]
    fn keeps_strictly_below_on_the_first_eight_bytes_alone() {
        let half = Threshold::of_rate(500_000);
        assert!(half.keeps(&hash_of((1 << 63) - 1)));
        assert!(!half.keeps(&hash_of(1 << 63)));
        let mut low = [0u8; 32];
        low[8..].fill(0xff);
        assert!(half.keeps(&low));
        assert!(!Threshold(0).keeps(&[0; 32]));
        assert!(Threshold(u64::MAX).keeps(&hash_of(u64::MAX - 1)));
        assert!(!Threshold(u64::MAX).keeps(&hash_of(u64::MAX)));
    }

    #[test]
    fn a_smaller_threshold_keeps_a_subset() {
        let keys: Vec<[u8; 32]> = (0u64..4096)
            .map(|i| {
                let mut hasher = Blake2s256::new();
                hasher.update(i.to_be_bytes());
                hasher.finalize().into()
            })
            .collect();
        let kept = |threshold: Threshold| keys.iter().filter(|k| threshold.keeps(k)).count();
        // A busier batch: each keeps a subset of the one before.
        let ladder = [0, 32, 33, 64, 500, 5_000].map(batch_sync_keep);
        for pair in ladder.windows(2) {
            assert!(pair[1] <= pair[0]);
            for key in &keys {
                assert!(!pair[1].keeps(key) || pair[0].keeps(key));
            }
        }
        assert_eq!(batch_sync_keep(32), REFERENCE_KEEP);
        // Near its rate over uniform hashes: 32 of 500 is 64,000 a million, of 4096 about 262.
        let sync = kept(batch_sync_keep(500));
        assert!((200..330).contains(&sync), "{sync}");
    }

    #[test]
    fn the_sync_key_is_the_messages_alone() {
        let reception =
            |receiver: u8, epoch: u32, timestamp: u64, wall_ms: u64, data: &[u8]| Reception {
                receiver: tally_wire::Identity::from_seed([receiver; 32]).public(),
                epoch,
                timestamp,
                message: crate::obs::ModeS::new(data)
                    .unwrap_or_else(|| panic!("{data:?} is no Mode S")),
                wall_ms,
            };
        let one = reception(1, 0, 10, 1_000, &[0x8d, 1, 2, 3]);
        let other = reception(2, 7, 99, 9_000, &[0x8d, 1, 2, 3]);
        let different = reception(1, 0, 10, 1_000, &[0x8d, 1, 2, 4]);
        assert_eq!(sync_key(&one), sync_key(&other));
        assert_ne!(sync_key(&one), sync_key(&different));
    }
}
