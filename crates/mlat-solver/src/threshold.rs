//! Canonical selection by hash threshold: an item is kept when the first eight bytes of its hash,
//! read big-endian as a `u64`, are below a fixed threshold. Never top-k: whether one item is kept
//! depends on that item alone, so what a holder of a subset of the raw keeps is exactly what a
//! holder of a superset keeps, restricted to the subset, and a model over less is a strict subset
//! of one over more. A hard cap on what is kept stays, as a refusal by the relay-wide budget,
//! never as trimming by rank.
//!
//! Every threshold below that selects sync events keys on [`sync_key`], so they nest: an event a
//! smaller threshold keeps is kept by every larger one. Each is stated as an absolute fraction of
//! every candidate, not of what an earlier threshold kept.

use blake2::{Blake2s256, Digest};

use crate::obs::Reception;

/// What a sync event's selection key is hashed under.
const SYNC_DOMAIN: &[u8] = b"tally sync selection";

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

// The placeholder rates below are today's top-k caps over the rates they bind at; the trailing
// window sweep (trailing_tests.rs) measures and replaces each.

/// Sync events a receiver keeps at ingest. Replaces `SYNC_PER_RECEIVER = 32` lowest-hash
/// candidates a receiver a 5 s bin (6.4 a second). Over a receiver hearing 50 ADS-B aircraft
/// at their nominal two airborne positions a second (100 candidates a second; assumed, not
/// measured: no per-receiver sync rate is recorded), 6.4 / 100 = 64,000 a million.
pub const SYNC_KEEP: Threshold = Threshold::of_rate(64_000);
/// Sync aircraft a tile takes its events from. Replaces `SYNC_AIRCRAFT_MAX = 16` a tile's window,
/// over the 60 ADS-B aircraft of the scenario that cap was measured in (100 receivers, 60 ADS-B
/// and 40 Mode S aircraft): 16 / 60 = 266,667 a million.
pub const REFERENCE_KEEP: Threshold = Threshold::of_rate(266_667);
/// Sync events a tile keeps of the candidates. Replaces the greedy `K = 10` a member and `P = 1`
/// a pair a bin, chosen today among the 32 a receiver keeps at ingest: 10 / 32 of `SYNC_KEEP`'s
/// rate, 20,000 a million. The pair rule's guarantee (every two members hearing one aircraft
/// tied in every bin) has no threshold form; the sweep measures whether it is missed.
pub const PAIR_KEEP: Threshold = Threshold::of_rate(20_000);
/// Replies a receiver keeps. Replaces `KEPT_PER_RECEIVER_BIN` (`KEPT_CEILING_PER_S = 300` a
/// second), over the measured 360 wanted receptions a receiver a second (`Rates::MEASURED`):
/// 300 / 360 = 833,333 a million. Today's ceiling binds only above it; a threshold thins every
/// receiver, so this is the upper bound of what a receiver at the mean keeps.
pub const KEPT_KEEP: Threshold = Threshold::of_rate(833_333);

const _: () = assert!(PAIR_KEEP.0 <= SYNC_KEEP.0);

/// A sync event's selection key: BLAKE2s-256 over `"tally sync selection" 0x00` and the hash of
/// the message bytes. A function of the message alone, so every receiver of one event, and every
/// holder of any of its receptions, keeps or drops it together.
pub fn sync_key(r: &Reception) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(SYNC_DOMAIN);
    hasher.update([0]);
    hasher.update(crate::obs::message_hash(&r.observation.data));
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
        for key in &keys {
            assert!(!PAIR_KEEP.keeps(key) || SYNC_KEEP.keeps(key));
        }
        // Near its rate over uniform hashes: 64,000 a million of 4096 is about 262.
        let sync = kept(SYNC_KEEP);
        assert!((200..330).contains(&sync), "{sync}");
        assert!(kept(PAIR_KEEP) <= sync);
    }

    #[test]
    fn the_sync_key_is_the_messages_alone() {
        let reception =
            |receiver: u8, epoch: u32, timestamp: u64, wall_ms: u64, data: &[u8]| Reception {
                receiver: tally_wire::Identity::from_seed([receiver; 32]).public(),
                epoch,
                observation: tally_wire::Observation {
                    format: tally_wire::batch::format::MODE_S_LONG,
                    timestamp,
                    signal: 0,
                    data: data.to_vec(),
                },
                wall_ms,
            };
        let one = reception(1, 0, 10, 1_000, &[0x8d, 1, 2, 3]);
        let other = reception(2, 7, 99, 9_000, &[0x8d, 1, 2, 3]);
        let different = reception(1, 0, 10, 1_000, &[0x8d, 1, 2, 4]);
        assert_eq!(sync_key(&one), sync_key(&other));
        assert_ne!(sync_key(&one), sync_key(&different));
    }
}
