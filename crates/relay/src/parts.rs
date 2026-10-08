//! Clock model parts on their way through a relay (RFC-0171 §3.4, §3.8.1). A part is unsigned:
//! what vouches for it is its manifest's signature over its hash. An engine sends a model's parts
//! before its manifest, so a relay holds the parts it cannot yet check, by model id, until the
//! manifest arrives; then it forwards each part whose hash the manifest lists at its index, in
//! index order, ahead of the manifest, and drops the rest. A part that arrives after its manifest
//! is checked against the manifest's list, kept for a while for that, and forwarded once.
//!
//! Bounded both ways: parts held wait at most `HOLD`, and at most `HELD_BYTES` of them are held,
//! the model least recently active (a part of it arriving) forgotten first, so a stranger's
//! parts for manifests that never come forget each other oldest first; a manifest's list is kept
//! for `HOLD`, at most `EXPECTED_HASHES` hashes over all of them, the oldest forgotten first.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tally_wire::ClockModelPart;
use tally_wire::batch::Hash;

use crate::bounded::Bounded;

/// How long a part waits for its manifest, and a manifest's list waits for its late parts. An
/// engine sends a model's parts and its manifest back to back, so anything this late is lost.
pub const HOLD: Duration = Duration::from_secs(30);
/// The most bytes of parts held waiting for their manifests: a few dense models in flight.
pub const HELD_BYTES: usize = 64 * 1024 * 1024;
/// The most part hashes kept from manifests already forwarded (32 bytes each, 32 MiB).
pub const EXPECTED_HASHES: usize = 1_000_000;
/// Models with parts held, and manifests whose lists are kept: a bound on the tables' keys
/// beside their bytes.
const MODELS_REMEMBERED: usize = 65_536;

/// One model's parts waiting for its manifest, each with the connection it came from.
struct Held {
    active: Instant,
    parts: Vec<(u64, ClockModelPart)>,
    bytes: usize,
}

/// A forwarded manifest's list, and which of its parts have gone out.
struct Expected {
    at: Instant,
    hashes: Vec<Hash>,
    forwarded: Vec<bool>,
}

pub struct Parts {
    held: Bounded<Hash, Held>,
    held_bytes: usize,
    max_bytes: usize,
    expected: Bounded<Hash, Expected>,
    expected_hashes: usize,
    max_hashes: usize,
    hold: Duration,
}

impl Default for Parts {
    fn default() -> Self {
        Self::new(HELD_BYTES, EXPECTED_HASHES, HOLD)
    }
}

impl Parts {
    pub fn new(max_bytes: usize, max_hashes: usize, hold: Duration) -> Self {
        Self {
            held: Bounded::new(MODELS_REMEMBERED),
            held_bytes: 0,
            max_bytes,
            expected: Bounded::new(MODELS_REMEMBERED),
            expected_hashes: 0,
            max_hashes,
            hold,
        }
    }

    /// Bytes of parts held now.
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    /// Takes a part from connection `source`. The part to forward now (its manifest went out and
    /// lists it, and it has not gone out yet), or `None`: held for its manifest, or dropped.
    pub fn part(
        &mut self,
        source: u64,
        part: ClockModelPart,
        now: Instant,
    ) -> Option<ClockModelPart> {
        self.expire(now);
        let (Ok(id), Ok(index)) = (part.model(), part.index()) else {
            return None;
        };
        let index = usize::from(index);
        if let Some(expected) = self.expected.get_mut(&id) {
            let listed = expected.hashes.get(index) == Some(&part.hash());
            let first = expected.forwarded.get(index) == Some(&false);
            if listed && first {
                expected.forwarded[index] = true;
                return Some(part);
            }
            return None;
        }
        let size = part.as_bytes().len();
        if size > self.max_bytes {
            return None;
        }
        match self.held.get_mut(&id) {
            Some(held) => {
                if held.parts.iter().any(|(_, other)| *other == part) {
                    return None;
                }
                held.active = now;
                held.parts.push((source, part));
                held.bytes += size;
                self.held.touch(&id);
            }
            None => {
                if self.held.len() >= MODELS_REMEMBERED {
                    self.forget_held();
                }
                self.held.insert(
                    id,
                    Held {
                        active: now,
                        parts: vec![(source, part)],
                        bytes: size,
                    },
                );
            }
        }
        self.held_bytes += size;
        while self.held_bytes > self.max_bytes {
            if !self.forget_held() {
                break;
            }
        }
        None
    }

    /// A manifest `id` listing `hashes` has gone out (new, and verified). The parts held for it
    /// that it lists, in index order with their sources, to forward ahead of it; any other part
    /// held for it is dropped. Its list is kept for parts still to come.
    pub fn manifest(
        &mut self,
        id: Hash,
        hashes: Vec<Hash>,
        now: Instant,
    ) -> Vec<(u64, ClockModelPart)> {
        self.expire(now);
        let mut ready: BTreeMap<usize, (u64, ClockModelPart)> = BTreeMap::new();
        if let Some(held) = self.held.remove(&id) {
            self.held_bytes -= held.bytes;
            for (source, part) in held.parts {
                let Ok(index) = part.index().map(usize::from) else {
                    continue;
                };
                if hashes.get(index) == Some(&part.hash()) && !ready.contains_key(&index) {
                    ready.insert(index, (source, part));
                }
            }
        }
        if !hashes.is_empty() && hashes.len() <= self.max_hashes {
            let mut forwarded = vec![false; hashes.len()];
            for index in ready.keys() {
                forwarded[*index] = true;
            }
            if self.expected.len() >= MODELS_REMEMBERED {
                self.forget_expected();
            }
            self.expected_hashes += hashes.len();
            if let Some(old) = self.expected.remove(&id) {
                self.expected_hashes -= old.hashes.len();
            }
            self.expected.insert(
                id,
                Expected {
                    at: now,
                    hashes,
                    forwarded,
                },
            );
            while self.expected_hashes > self.max_hashes {
                if !self.forget_expected() {
                    break;
                }
            }
        }
        ready.into_values().collect()
    }

    /// Forgets what has waited longer than `hold`.
    fn expire(&mut self, now: Instant) {
        while let Some((_, held)) = self.held.first() {
            if now.saturating_duration_since(held.active) < self.hold {
                break;
            }
            self.forget_held();
        }
        while let Some((_, expected)) = self.expected.first() {
            if now.saturating_duration_since(expected.at) < self.hold {
                break;
            }
            self.forget_expected();
        }
    }

    fn forget_held(&mut self) -> bool {
        match self.held.pop_first() {
            Some((_, held)) => {
                self.held_bytes -= held.bytes;
                true
            }
            None => false,
        }
    }

    fn forget_expected(&mut self) -> bool {
        match self.expected.pop_first() {
            Some((_, expected)) => {
                self.expected_hashes -= expected.hashes.len();
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::clock_model::part_hash;

    fn parts(id: u8, count: u16, len: usize) -> Vec<ClockModelPart> {
        (0..count)
            .map(|index| {
                let data: Vec<u8> = (0..len).map(|at| (at as u8) ^ (index as u8) ^ id).collect();
                ClockModelPart::new([id; 32], index, &data)
            })
            .collect()
    }

    fn hashes(parts: &[ClockModelPart]) -> Vec<Hash> {
        parts.iter().map(|part| part_hash(part.data())).collect()
    }

    #[test]
    fn parts_wait_for_their_manifest_and_go_out_ahead_of_it_in_index_order() {
        let now = Instant::now();
        let mut table = Parts::default();
        let model = parts(1, 3, 100);
        // Reordered and repeated, from two connections.
        for (source, part) in [
            (1, &model[2]),
            (2, &model[0]),
            (1, &model[2]),
            (2, &model[1]),
        ] {
            assert!(table.part(source, part.clone(), now).is_none());
        }
        let out = table.manifest([1; 32], hashes(&model), now);
        assert_eq!(
            out.iter().map(|(_, part)| part.clone()).collect::<Vec<_>>(),
            model
        );
        assert_eq!(out[0].0, 2);
        assert_eq!(table.held_bytes(), 0);
        // A copy arriving later by another path is not forwarded again.
        assert!(table.part(3, model[1].clone(), now).is_none());
    }

    #[test]
    fn a_part_the_manifest_does_not_list_is_dropped_and_a_late_listed_one_goes_out_once() {
        let now = Instant::now();
        let mut table = Parts::default();
        let model = parts(1, 3, 100);
        let forged = ClockModelPart::new([1; 32], 1, b"not the part");
        table.part(1, model[0].clone(), now);
        table.part(1, forged.clone(), now);
        let out = table.manifest([1; 32], hashes(&model), now);
        assert_eq!(out.len(), 1);
        assert_eq!(table.held_bytes(), 0);
        // After the manifest: a forged part, a part out of range, the real ones once each.
        assert!(table.part(1, forged, now).is_none());
        assert!(table.part(1, parts(1, 4, 100)[3].clone(), now).is_none());
        assert_eq!(table.part(1, model[2].clone(), now), Some(model[2].clone()));
        assert_eq!(table.part(1, model[1].clone(), now), Some(model[1].clone()));
        assert!(table.part(1, model[1].clone(), now).is_none());
        // A part of a model whose manifest never came is held, then given up.
        let orphan = parts(9, 1, 100);
        assert!(table.part(1, orphan[0].clone(), now).is_none());
        assert!(table.held_bytes() > 0);
        table.part(1, parts(8, 1, 10)[0].clone(), now + HOLD);
        assert_eq!(table.held_bytes(), parts(8, 1, 10)[0].as_bytes().len());
        // And a manifest's list is given up too: a late part is then just held.
        assert!(table.part(1, model[2].clone(), now + HOLD).is_none());
    }

    #[test]
    fn held_parts_are_bounded_by_bytes_forgetting_the_model_least_recently_active() {
        let now = Instant::now();
        let budget = 10_000;
        let mut table = Parts::new(budget, 100, HOLD);
        // A flood of parts for manifests that never come.
        for flood in 2..60u8 {
            table.part(2, parts(flood, 1, 1_000)[0].clone(), now);
            assert!(table.held_bytes() <= budget);
        }
        // The oldest went first, the newest are held.
        let oldest = parts(2, 1, 1_000);
        assert!(table.manifest([2; 32], hashes(&oldest), now).is_empty());
        let newest = parts(59, 1, 1_000);
        assert_eq!(table.manifest([59; 32], hashes(&newest), now).len(), 1);
        // One far too large is never held.
        assert!(
            table
                .part(3, parts(70, 1, budget)[0].clone(), now)
                .is_none()
        );
        assert!(table.held_bytes() <= budget);
        // Lists from manifests are bounded by hashes.
        let mut lists = Parts::new(budget, 100, HOLD);
        for id in 0..20u8 {
            lists.manifest([id; 32], vec![[id; 32]; 30], now);
            assert!(lists.expected_hashes <= 100);
        }
    }
}
