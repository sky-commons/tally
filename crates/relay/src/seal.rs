//! Sealing by watermark, off the hot path (RFC-0181 §4). A message thread owns its open epochs.
//! When its watermark (`exchange::Watermark`) passes the end of one, it decides that epoch's
//! receptions, swaps its generations ([`Closer`]) and hands the frozen result to the sealer
//! (`products::Sealer`, its own thread) through a bounded queue it never waits on; no lock is held
//! across a seal, so a slow seal (Ed25519, CPR, a canonical sort) never stalls ingest. A sealer
//! that is behind refuses the epoch whole, counted ([`Coordinator`]), never part of it.
//!
//! An epoch is decided by stamps alone (`ingest::Stamp`), never by a clock read at seal time, and in
//! one order ([`canonical`]) that no thread, worker or queue chooses, so the same stamped batches
//! close the same epochs with the same contents on any number of threads, whatever the delays.
//! The [`Coordinator`] gathers an epoch's frozen parts from every message thread and merges them:
//! the hub's deduplicated stream and each area's copies, each in canonical order. Regional products
//! are then signed area by area in cell order; the world seals at watermark plus
//! `products::WORLD_SETTLE_MS`. Geography appears only here.

use std::collections::BTreeMap;
use std::sync::Arc;

use tally_wire::batch::Hash;
use tally_wire::{Decoded, ObsRef, PublicKey, Region};

use crate::budget::Charge;
use crate::exchange::{Frozen, Parts};
use crate::ingest::Stamp;

/// An epoch: one `EPOCH_MS` of the ingest clock.
pub type Epoch = u64;

/// How long an epoch is: the regional product's once a second.
pub const EPOCH_MS: u64 = crate::products::REGIONAL_EVERY_MS;

/// Epochs whose decoded batches the relay holds between ingest and the products, at most: the one
/// open, the one closing (open until the slowest producer's tick passes it), and the one the sealer
/// is working on. Past what they are budgeted (`budget::Store::Epochs`) an epoch is refused whole.
pub const EPOCHS_HELD: u64 = 3;

/// The epoch a stamp falls in.
pub fn epoch_of(stamp: Stamp) -> Epoch {
    epoch_of_ms(stamp.mono_ms())
}

/// The epoch a stamp's milliseconds fall in.
pub fn epoch_of_ms(stamp_ms: u64) -> Epoch {
    stamp_ms / EPOCH_MS
}

/// The canonical order of batches: by stamp, then by the batch itself (its receiver, boot and
/// sequence), and last by its hash. Never by the ingest order (`Stamp::ingest_seq`), which is the
/// order the workers happened to take batches in: two batches stamped in one millisecond on two
/// workers are ordered the same however the workers raced, so which copy of a message is kept (and
/// so the stream's and the regional product's bytes) follows the stamps and the batches alone.
///
/// The hash is what makes the order total. Admission keeps batches unique by their hash alone
/// (`strikes`), never by receiver, boot and sequence: two different batches under the same three can
/// be admitted in the same millisecond, and only the hash (which admission already holds,
/// `Batch::hash` computed once) orders the two without the insertion order.
/// It is the key's last field, so it orders only batches whose other fields are equal: any two
/// batches it did not tie before keep the order they had.
pub fn canonical(decoded: &Decoded) -> (u64, PublicKey, u64, u64, Hash) {
    (
        decoded.stamp_ms(),
        decoded.receiver(),
        decoded.boot_id(),
        decoded.sequence(),
        decoded.batch().hash(),
    )
}

/// The first stamp after epoch `epoch`: the watermark at which it is closed.
pub fn end_of(epoch: Epoch) -> u64 {
    (epoch + 1) * EPOCH_MS
}

/// The instant `mono_ms` on the monotonic clock's own grid (an epoch's end, [`end_of`]; a hosted
/// MLAT step), its judging clock by `moment`'s offset: a time the pipeline states on `M` from its
/// own grid, never a reading of another clock. The relay's one statement of one
/// (`tally_wire::clocks::Moment::at_ms`, which Clippy refuses elsewhere).
#[allow(
    clippy::disallowed_methods,
    reason = "the pipeline's one statement of a time on its own monotonic grid"
)]
pub fn on_grid(moment: tally_wire::clocks::Moment, mono_ms: u64) -> tally_wire::clocks::Moment {
    moment.at_ms(mono_ms)
}

/// Which epochs a shard has closed: each closes once, in order, when the watermark has passed it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Closer {
    /// Epochs before this are closed.
    open_from: Epoch,
    started: bool,
}

impl Closer {
    /// The watermark advanced to `watermark`: the epochs it closes now, oldest first. The first
    /// call starts at the older of the watermark's epoch and `oldest_open`, the oldest epoch the
    /// shard holds anything of: a shard starts with nothing before either.
    pub fn advance(
        &mut self,
        watermark: tally_wire::clocks::Mono,
        oldest_open: Option<Epoch>,
    ) -> std::ops::Range<Epoch> {
        let current = epoch_of_ms(watermark.ms());
        if !self.started {
            self.started = true;
            self.open_from = oldest_open.map_or(current, |oldest| oldest.min(current));
        }
        let closing = self.open_from..current.max(self.open_from);
        self.open_from = closing.end;
        closing
    }

    /// Whether `epoch` has closed: a slice for it now is late.
    pub fn closed(&self, epoch: Epoch) -> bool {
        self.started && epoch < self.open_from
    }
}

/// One reception kept: its batch, shared, and its index there.
#[derive(Clone, Debug)]
pub struct Kept {
    pub decoded: Arc<Decoded>,
    pub index: u32,
}

impl Kept {
    pub fn obs(&self) -> &ObsRef {
        &self.decoded.observations()[self.index as usize]
    }

    /// The canonical order: by batch ([`canonical`]), then index in the batch.
    fn key(&self) -> ((u64, PublicKey, u64, u64, Hash), u32) {
        (canonical(&self.decoded), self.index)
    }
}

/// One epoch merged across every message thread.
#[derive(Debug, Default)]
pub struct Merged {
    pub epoch: Epoch,
    /// No copy of it is kept: a part was lost (a sealer behind), so all of it is refused.
    pub refused: bool,
    /// First copies of each message the relay heard, in canonical order.
    pub stream: Vec<Kept>,
    /// First copies in each area, by the area's cell number, each in canonical order.
    pub regional: BTreeMap<u64, (Region, Vec<Kept>)>,
    /// What its batches are charged, released when the epoch is let go.
    pub charges: Vec<Charge>,
    /// The newest tick of its parts (`exchange::Frozen::judged`): what it is signed by.
    pub judged: Option<Stamp>,
}

impl Merged {
    /// The judging clock at this epoch's end (`end_of`), by its newest tick's two readings: the
    /// time its products are signed at. None when that tick was stamped while the relay's clock
    /// did not judge: nothing is signed from a stamp taken then (RFC-0171 §3.6).
    pub fn signed_ms(&self) -> Option<u64> {
        self.signed_at().map(|at| at.judged().ms())
    }

    /// As [`Merged::signed_ms`], the stamp at the epoch's end: its products' fixes are offered to
    /// the world by it.
    pub fn signed_at(&self) -> Option<Stamp> {
        self.judged
            .filter(|judged| judged.judging())
            .map(|judged| judged.at_mono_ms(end_of(self.epoch)))
    }
}

impl Merged {
    pub fn receptions(&self) -> usize {
        self.stream.len()
            + self
                .regional
                .values()
                .map(|(_, copies)| copies.len())
                .sum::<usize>()
    }
}

/// Gathers each epoch's frozen parts from every message thread and hands each epoch on whole and
/// in order, once every thread has closed it: merged when every part came, refused when one was
/// refused or lost. A thread sends a part only for an epoch it held receptions of, and numbers its
/// parts (a marker of how far it has closed carries the count so far), so a gap in a thread's
/// numbers is a part of its lost (the sealer's queue was full), never a marker: every epoch from the
/// thread's last word to the next that lacks a part of that thread is refused, and nothing else.
/// Each lost part is counted ([`Ready::parts_lost`]), whether or not any other thread held anything
/// of its epoch.
pub struct Coordinator {
    pending: BTreeMap<Epoch, Gathering>,
    /// Per thread: every epoch before this is closed there.
    closed: Vec<Option<Epoch>>,
    /// Per thread: the number of its next epoch part.
    expected: Vec<u64>,
    /// Per thread, the epochs a part of it that was lost may have been for.
    lost: Vec<(usize, std::ops::Range<Epoch>)>,
    /// Every epoch before this has been handed on.
    next: Epoch,
}

/// One epoch's parts as they come: let go whole (`exchange::Parts`), every part's batches before
/// any part's charge.
#[derive(Default)]
struct Gathering {
    parts: Parts,
    refused: bool,
}

/// What a thread's word completes.
#[derive(Debug, Default)]
pub struct Ready {
    /// Epochs handed on, oldest first: merged, or refused whole.
    pub merged: Vec<Merged>,
    /// Epoch parts lost on the way since the last word (each one thread's part of one epoch).
    pub parts_lost: u64,
    /// Receptions a thread let go since its last word, their epoch closed before they came
    /// (`exchange::Frozen::late`).
    pub late: u64,
    /// Receptions a thread let go since its last word, their epoch past the window
    /// (`exchange::Frozen::past`).
    pub past: u64,
    /// Every epoch before this is closed on every thread.
    pub watermark: Option<Epoch>,
    /// The thread's newest tick (`exchange::Frozen::judged`): what the watermark is signed by.
    pub judged: Option<Stamp>,
}

impl Coordinator {
    pub fn new(threads: usize) -> Self {
        Self {
            pending: BTreeMap::new(),
            closed: vec![None; threads.max(1)],
            expected: vec![0; threads.max(1)],
            lost: Vec::new(),
            next: 0,
        }
    }

    /// One thread's word: the epochs it completes, merged or refused, oldest first, and the
    /// watermark every thread has closed to (every epoch before it is done).
    pub fn take(&mut self, frozen: Frozen) -> Ready {
        let (frozen_late, frozen_past, judged) = (frozen.late, frozen.past, frozen.judged);
        let thread = frozen.thread.min(self.closed.len() - 1);
        let mut parts_lost = 0;
        if frozen.seq > self.expected[thread] {
            parts_lost = frozen.seq - self.expected[thread];
            // Lost on the way: each was for an epoch from the thread's last word to this one
            // (from its first, the oldest epoch anyone has a part of).
            let until = frozen.epoch.unwrap_or(frozen.closed_before);
            let since = self.closed[thread]
                .or_else(|| self.pending.keys().next().copied())
                .unwrap_or(until)
                .max(self.next);
            if since < until {
                self.lost.push((thread, since..until));
            }
        }
        self.expected[thread] = self.expected[thread].max(frozen.seq);
        if frozen.epoch.is_some() {
            self.expected[thread] = frozen.seq + 1;
        }
        self.closed[thread] = Some(frozen.closed_before.max(self.closed[thread].unwrap_or(0)));
        if let Some(epoch) = frozen.epoch
            && epoch >= self.next
        {
            let gathering = self.pending.entry(epoch).or_default();
            gathering.refused |= frozen.refused;
            gathering.parts.push(frozen);
        }
        let (merged, watermark) = self.ready();
        Ready {
            merged,
            parts_lost,
            late: frozen_late,
            past: frozen_past,
            watermark,
            judged,
        }
    }

    /// Every epoch before the least thread's close, in order.
    fn ready(&mut self) -> (Vec<Merged>, Option<Epoch>) {
        let Some(watermark) = self
            .closed
            .iter()
            .copied()
            .collect::<Option<Vec<Epoch>>>()
            .and_then(|closed| closed.into_iter().min())
        else {
            return (Vec::new(), None);
        };
        let mut out = Vec::new();
        while let Some(entry) = self.pending.first_entry() {
            let epoch = *entry.key();
            if epoch >= watermark {
                break;
            }
            let gathering = entry.remove();
            let lost = self.lost.iter().any(|(thread, lost)| {
                lost.contains(&epoch) && !gathering.parts.iter().any(|part| part.thread == *thread)
            });
            if gathering.refused || lost {
                // Its parts, and what they are charged, are let go here.
                out.push(Merged {
                    epoch,
                    refused: true,
                    ..Merged::default()
                });
            } else {
                out.push(merge(epoch, gathering.parts.into_vec()));
            }
        }
        self.next = self.next.max(watermark);
        let next = self.next;
        self.lost.retain(|(_, lost)| lost.end > next);
        (out, Some(watermark))
    }
}

/// Every thread's part of one epoch as one: each list in canonical order.
pub fn merge(epoch: Epoch, parts: Vec<Frozen>) -> Merged {
    let mut merged = Merged {
        epoch,
        ..Merged::default()
    };
    for mut part in parts {
        merged.judged = merged.judged.max(part.judged);
        merged.charges.push(std::mem::take(&mut part.charge));
        let copy = |at: u32, index: u32| Kept {
            decoded: Arc::clone(&part.batches[at as usize]),
            index,
        };
        merged
            .stream
            .extend(part.stream.iter().map(|(at, index)| copy(*at, *index)));
        for (area, at, index) in &part.regional {
            merged
                .regional
                .entry(area.as_u64())
                .or_insert_with(|| (*area, Vec::new()))
                .1
                .push(copy(*at, *index));
        }
    }
    merged.stream.sort_by_key(Kept::key);
    for (_, copies) in merged.regional.values_mut() {
        copies.sort_by_key(Kept::key);
    }
    merged
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;

    fn at(stamp_ms: u64) -> tally_wire::clocks::Mono {
        tally_wire::clocks::recorded::mono(stamp_ms)
    }

    #[test]
    fn each_epoch_closes_once_in_order_when_the_watermark_passes_it() {
        let mut closer = Closer::default();
        assert_eq!(closer.advance(at(5_500), None), 5..5);
        assert_eq!(closer.advance(at(5_999), None), 5..5);
        assert_eq!(closer.advance(at(6_000), None), 5..6);
        assert_eq!(closer.advance(at(9_100), None), 6..9);
        assert_eq!(closer.advance(at(8_000), None), 9..9);
        // A shard that holds an older epoch than its first watermark starts there.
        let mut closer = Closer::default();
        assert_eq!(closer.advance(at(7_200), Some(4)), 4..7);
    }

    fn part(epoch: Epoch, thread: usize, seq: u64) -> Frozen {
        Frozen {
            thread,
            seq,
            epoch: Some(epoch),
            closed_before: epoch + 1,
            ..Frozen::default()
        }
    }

    fn epochs(done: Ready) -> Vec<(Epoch, bool)> {
        done.merged.iter().map(|m| (m.epoch, m.refused)).collect()
    }

    fn marker(thread: usize, seq: u64, closed_before: Epoch) -> Frozen {
        Frozen {
            thread,
            seq,
            epoch: None,
            closed_before,
            ..Frozen::default()
        }
    }

    #[test]
    fn an_epoch_is_handed_on_once_every_thread_closed_it_and_refused_whole_if_a_part_was_lost() {
        let mut coordinator = Coordinator::new(2);
        assert!(epochs(coordinator.take(part(5, 0, 0))).is_empty());
        assert_eq!(epochs(coordinator.take(part(5, 1, 0))), vec![(5, false)]);
        // Thread 1's part of epoch 6 was lost (its next part is its third): 6 is refused.
        assert!(epochs(coordinator.take(part(6, 0, 1))).is_empty());
        let ready = coordinator.take(part(7, 1, 2));
        assert_eq!(ready.parts_lost, 1);
        assert_eq!(epochs(ready), vec![(6, true)]);
        assert_eq!(epochs(coordinator.take(part(7, 0, 2))), vec![(7, false)]);
        // An epoch a thread held nothing of needs nothing from it: its close is enough.
        assert!(epochs(coordinator.take(part(9, 0, 3))).is_empty());
        let ready = coordinator.take(marker(1, 3, 1_000_000_000));
        assert_eq!(ready.parts_lost, 0);
        assert_eq!(ready.watermark, Some(10));
        assert_eq!(epochs(ready), vec![(9, false)]);
    }

    /// A marker carries no data, so losing one loses nothing: the epochs it spans that every thread
    /// completed are merged, not refused.
    #[test]
    fn a_lost_marker_refuses_nothing() {
        let mut coordinator = Coordinator::new(2);
        assert!(epochs(coordinator.take(part(5, 0, 0))).is_empty());
        // Thread 1's marker closing 5 was lost; its next word is its part of 6, still its first.
        assert!(epochs(coordinator.take(part(6, 0, 1))).is_empty());
        let ready = coordinator.take(part(6, 1, 0));
        assert_eq!(ready.parts_lost, 0);
        assert_eq!(epochs(ready), vec![(5, false), (6, false)]);
    }

    fn decoded(
        receiver: &tally_wire::Identity,
        stamp_ms: u64,
        sequence: u64,
        signal: u8,
    ) -> Result<Arc<Decoded>, String> {
        let content = tally_wire::BatchContent {
            boot_id: 1,
            sequence,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: vec![tally_wire::Observation {
                format: tally_wire::batch::format::MODE_S_SHORT,
                timestamp: 7,
                signal,
                data: vec![0x5d, 1, 2, 3, 4, 5, 6],
            }],
        };
        let batch = crate::anchors::anchored(receiver, &content).map_err(|e| e.to_string())?;
        Decoded::from_verified(batch, tally_wire::clocks::recorded::aligned(stamp_ms), 0)
            .map_err(|e| e.error.to_string())
    }

    /// One thread's part of epoch 0 holding `batches`, each one reception kept.
    fn holding(thread: usize, batches: Vec<Arc<Decoded>>) -> Frozen {
        Frozen {
            thread,
            epoch: Some(0),
            closed_before: 1,
            stream: (0..batches.len() as u32).map(|at| (at, 0)).collect(),
            batches,
            ..Frozen::default()
        }
    }

    fn order(merged: &Merged) -> Vec<Hash> {
        merged
            .stream
            .iter()
            .map(|kept| kept.decoded.batch().hash())
            .collect()
    }

    /// Two different batches under one stamp, receiver, boot and sequence (admission forgot the
    /// boot between them) merge in one order whichever thread's part came first: the hash decides,
    /// never the insertion order. Batches whose other fields differ keep the order those fields
    /// give, whichever way their hashes fall.
    #[test]
    fn the_canonical_order_is_total_and_the_hash_breaks_only_ties() -> Result<(), String> {
        let receiver = tally_wire::Identity::from_seed([3; 32]);
        let a = decoded(&receiver, 500, 4, 1)?;
        let b = decoded(&receiver, 500, 4, 2)?;
        assert_ne!(a.batch().hash(), b.batch().hash());
        let one = merge(
            0,
            vec![
                holding(0, vec![Arc::clone(&a)]),
                holding(1, vec![Arc::clone(&b)]),
            ],
        );
        let other = merge(
            0,
            vec![
                holding(1, vec![Arc::clone(&b)]),
                holding(0, vec![Arc::clone(&a)]),
            ],
        );
        assert_eq!(order(&one), order(&other));
        let mut tied = [a.batch().hash(), b.batch().hash()];
        tied.sort();
        assert_eq!(order(&one), tied);
        // Earlier stamp, or lower sequence, first: whatever the hashes say.
        for (first, second) in [
            (
                decoded(&receiver, 499, 9, 1)?,
                decoded(&receiver, 500, 1, 1)?,
            ),
            (
                decoded(&receiver, 500, 5, 1)?,
                decoded(&receiver, 500, 6, 1)?,
            ),
            (
                decoded(&receiver, 500, 6, 2)?,
                decoded(&receiver, 500, 7, 2)?,
            ),
        ] {
            let expected = vec![first.batch().hash(), second.batch().hash()];
            for parts in [
                vec![holding(0, vec![Arc::clone(&first), Arc::clone(&second)])],
                vec![holding(0, vec![Arc::clone(&second), Arc::clone(&first)])],
            ] {
                assert_eq!(order(&merge(0, parts)), expected);
            }
        }
        Ok(())
    }

    /// A part a thread refused (its epoch past the budget) refuses its epoch whole, whatever the
    /// other threads sent of it; a lost part is counted even when no other thread held its epoch.
    #[test]
    fn a_refused_part_refuses_its_epoch_and_every_lost_part_is_counted() {
        let mut coordinator = Coordinator::new(2);
        let mut refused = part(5, 1, 0);
        refused.refused = true;
        assert!(epochs(coordinator.take(part(5, 0, 0))).is_empty());
        assert_eq!(epochs(coordinator.take(refused)), vec![(5, true)]);
        // Thread 0 lost three parts, for epochs no other thread held: counted, nothing to refuse.
        let ready = coordinator.take(marker(0, 4, 20));
        assert_eq!(ready.parts_lost, 3);
        assert_eq!(epochs(coordinator.take(marker(1, 1, 20))), Vec::new());
    }
}
