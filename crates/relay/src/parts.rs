//! Clock model parts on their way through a relay (RFC-0171 §3.4, §3.8.1). A part is unsigned:
//! what vouches for it is its manifest's signature over its hash. An engine sends a model's parts
//! before its manifest, so a relay holds the parts it cannot yet check, by model id, until the
//! manifest arrives; then it forwards each part whose hash the manifest lists at its index, in
//! index order, ahead of the manifest, and drops the rest. A part that arrives after its manifest
//! is checked against the manifest's list, kept for a while for that, and forwarded once.
//!
//! Bounded both ways, by one room (`budget::Plan::parts_room`: what the members' shared rate and
//! the relay's own MLAT may bring while a part waits): parts held wait at most `HOLD`, and at most
//! the room's bytes of them are held, each model's entry in its table with them, the model least
//! recently active (a part of it arriving) forgotten first, so a stranger's parts for manifests
//! that never come forget each other oldest first; a manifest's list is kept for `HOLD`, at most
//! the room's bytes of lists, each with its entry (a manifest lists 32 bytes for each part, and
//! came within the same rate), the oldest forgotten first. What the tables allocate at the room
//! is charged whole (`budget::Store::Parts`, [`planned_bytes`]).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tally_wire::ClockModelPart;
use tally_wire::batch::Hash;

use crate::bounded::Bounded;

/// How long a part waits for its manifest, and a manifest's list waits for its late parts. An
/// engine sends a model's parts and its manifest back to back, so anything this late is lost.
pub const HOLD: Duration = Duration::from_secs(30);
/// What one part holds while it waits, at most: its bytes at the most a part carries
/// (`clock_model::PART_LEN` and its header), and its slot in its model's list, twice as the list
/// grows beside the one it replaces.
pub const ONE_PART_BYTES: usize =
    tally_wire::clock_model::PART_LEN + 64 + 2 * std::mem::size_of::<(u64, ClockModelPart)>();
/// What a model with parts held takes of the room beside its parts: its entry in the table of
/// models (`Bounded::bytes_per_key`), so a flood of the smallest parts, each of a model of its
/// own, fills the room with what the table holds for them and is held to it.
const HELD_KEY_BYTES: usize = Bounded::<Hash, Held>::bytes_per_key();
/// What a kept list takes of the room beside its hashes: its entry in the table of lists.
const EXPECTED_KEY_BYTES: usize = Bounded::<Hash, Expected>::bytes_per_key();
/// The least room: one model of one part, so a relay with no members and no MLAT still passes
/// one on.
pub const ONE_MODEL_BYTES: usize = HELD_KEY_BYTES + ONE_PART_BYTES;
/// The fewest bytes a part takes held (its header, `clock_model`'s 35 bytes, and its slot).
const PART_LEAST: usize = 35 + 2 * std::mem::size_of::<(u64, ClockModelPart)>();
/// What a kept list takes for each hash: the hash and whether its part went out.
const PER_HASH: usize = std::mem::size_of::<Hash>() + std::mem::size_of::<bool>();

/// The most models a room of `room` bytes holds parts for: the room over what the smallest model
/// takes of it (its entry and one part of the fewest bytes), one at least.
const fn held_models(room: usize) -> usize {
    let models = room / (HELD_KEY_BYTES + PART_LEAST);
    if models == 0 { 1 } else { models }
}

/// The most lists a room of `room` bytes keeps: the room over what the smallest list takes of it
/// (its entry and one hash), one at least.
const fn expected_models(room: usize) -> usize {
    let models = room / (EXPECTED_KEY_BYTES + PER_HASH);
    if models == 0 { 1 } else { models }
}

/// What a kept list of `hashes` takes of the room: its entry, its hashes as allocated, and
/// whether each went out.
fn list_bytes(hashes: &[Hash], capacity: usize) -> usize {
    EXPECTED_KEY_BYTES
        + capacity * std::mem::size_of::<Hash>()
        + hashes.len() * std::mem::size_of::<bool>()
}

/// What the tables allocate at most in a room of `room` bytes: each table of models at the most
/// models the room holds (`Bounded::planned_bytes`, its pages kept once made), and beside it the
/// room's bytes of parts, and of lists, each held to the room together with its models' entries.
pub const fn planned_bytes(room: usize) -> usize {
    Bounded::<Hash, Held>::planned_bytes(held_models(room))
        + room
        + Bounded::<Hash, Expected>::planned_bytes(expected_models(room))
        + room
}

/// One model's parts waiting for its manifest, each with the connection it came from.
struct Held {
    active: Instant,
    parts: Vec<(u64, ClockModelPart)>,
    /// What it takes of the room: its entry and its parts, each one's bytes and its slot, twice
    /// ([`part_bytes`]).
    bytes: usize,
}

/// What `part` holds while it waits, counted against the room: its bytes, and its slot in its
/// model's list twice, as a list grows beside the one it replaces.
fn part_bytes(part: &ClockModelPart) -> usize {
    part.allocated() + 2 * std::mem::size_of::<(u64, ClockModelPart)>()
}

/// A forwarded manifest's list, and which of its parts have gone out.
struct Expected {
    at: Instant,
    hashes: Vec<Hash>,
    forwarded: Vec<bool>,
    /// What it takes of the room ([`list_bytes`]).
    bytes: usize,
}

pub struct Parts {
    held: Bounded<Hash, Held>,
    held_bytes: usize,
    max_bytes: usize,
    expected: Bounded<Hash, Expected>,
    expected_bytes: usize,
    hold: Duration,
}

impl Parts {
    /// Tables in a room of `room` bytes ([`planned_bytes`]).
    pub fn sized(room: usize) -> Self {
        Self::new(room, HOLD)
    }

    /// Tables in a room of `room` bytes, each waiting `hold` at most.
    pub fn new(room: usize, hold: Duration) -> Self {
        Self {
            held: Bounded::new(held_models(room)),
            held_bytes: 0,
            max_bytes: room,
            expected: Bounded::new(expected_models(room)),
            expected_bytes: 0,
            hold,
        }
    }

    /// The tables in a room of `room` bytes from now, the least recently active forgotten past
    /// it: what a budget resized tells them.
    pub fn resize(&mut self, room: usize) {
        self.max_bytes = room;
        for (_, held) in self.held.set_capacity(held_models(room)) {
            self.held_bytes -= held.bytes;
        }
        for (_, expected) in self.expected.set_capacity(expected_models(room)) {
            self.expected_bytes -= expected.bytes;
        }
        while self.held_bytes > self.max_bytes && self.forget_held() {}
        while self.expected_bytes > self.max_bytes && self.forget_expected() {}
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
        let size = part_bytes(&part);
        let new_model = self.held.get(&id).is_none();
        // A model's first part brings its entry too.
        let cost = size + if new_model { HELD_KEY_BYTES } else { 0 };
        if cost > self.max_bytes {
            return None;
        }
        match self.held.get_mut(&id) {
            Some(held) => {
                if held.parts.iter().any(|(_, other)| *other == part) {
                    return None;
                }
                held.active = now;
                held.parts.push((source, part));
                held.bytes += cost;
                self.held.touch(&id);
            }
            None => {
                if self.held.len() >= self.held.capacity() {
                    self.forget_held();
                }
                self.held.insert(
                    id,
                    Held {
                        active: now,
                        parts: vec![(source, part)],
                        bytes: cost,
                    },
                );
            }
        }
        self.held_bytes += cost;
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
        let bytes = list_bytes(&hashes, hashes.capacity());
        if !hashes.is_empty() && bytes <= self.max_bytes {
            let mut forwarded = vec![false; hashes.len()];
            for index in ready.keys() {
                forwarded[*index] = true;
            }
            if let Some(old) = self.expected.remove(&id) {
                self.expected_bytes -= old.bytes;
            }
            if self.expected.len() >= self.expected.capacity() {
                self.forget_expected();
            }
            self.expected_bytes += bytes;
            self.expected.insert(
                id,
                Expected {
                    at: now,
                    hashes,
                    forwarded,
                    bytes,
                },
            );
            while self.expected_bytes > self.max_bytes {
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
                self.expected_bytes -= expected.bytes;
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
        let mut table = Parts::sized(1 << 20);
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
        let mut table = Parts::sized(1 << 20);
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
        assert_eq!(
            table.held_bytes(),
            HELD_KEY_BYTES + part_bytes(&parts(8, 1, 10)[0])
        );
        // And a manifest's list is given up too: a late part is then just held.
        assert!(table.part(1, model[2].clone(), now + HOLD).is_none());
    }

    #[test]
    fn held_parts_are_bounded_by_bytes_forgetting_the_model_least_recently_active() {
        let now = Instant::now();
        let budget = 10_000;
        let mut table = Parts::new(budget, HOLD);
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
        // Lists from manifests are bounded by their bytes in the same room.
        let mut lists = Parts::new(budget, HOLD);
        for id in 0..20u8 {
            lists.manifest([id; 32], vec![[id; 32]; 30], now);
            assert!(lists.expected_bytes <= budget);
        }
        assert!(lists.expected.len() < 20);
    }

    /// The tables at a room, flooded by parts of many models that never get their manifest and by
    /// manifests whose lists are kept, allocate no more than [`planned_bytes`] of the room plans,
    /// and a smaller room forgets past it. Measured by the allocator, on this thread.
    #[test]
    fn the_tables_stay_within_their_plan_at_a_room() {
        use tally_counting::Counting;
        let now = Instant::now();
        let room = 6 * ONE_MODEL_BYTES;
        let floods: Vec<Vec<ClockModelPart>> = (0..120u8)
            .map(|id| parts(id, 1 + u16::from(id % 5), 1 + usize::from(id) * 251))
            .collect();
        let lists: Vec<(Hash, Vec<Hash>)> = (0..200u8)
            .map(|id| {
                (
                    [id; 32].map(|byte| byte ^ 0x5a),
                    vec![[id; 32]; 1 + usize::from(id)],
                )
            })
            .collect();
        let base = Counting::peak_base();
        let mut table = Parts::sized(room);
        // Each taken as a copy, so what the tables keep is counted.
        for (flood, (id, list)) in floods.iter().zip(&lists) {
            for part in flood {
                let _ = table.part(2, part.clone(), now);
            }
            let _ = table.manifest(*id, list.clone(), now);
            assert!(table.held_bytes() <= room);
        }
        let peak = usize::try_from(Counting::peak_since(base)).unwrap_or(0);
        assert!(
            peak <= planned_bytes(room),
            "{peak} at the peak, {} planned",
            planned_bytes(room)
        );
        // And each table's figures are tight: the room's bytes of what it holds are most of it.
        assert!(peak * 3 >= planned_bytes(room), "{peak}");
        table.resize(ONE_MODEL_BYTES);
        assert!(table.held_bytes() <= ONE_MODEL_BYTES);
        assert!(table.expected_bytes <= ONE_MODEL_BYTES);
    }
}
