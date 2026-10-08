//! Sealing by watermark, off the hot path (RFC-0177 §4). A message thread owns its open epochs.
//! When its watermark (`exchange::Watermark`) passes the end of one, it decides that epoch's
//! receptions, swaps its generations ([`Closer`]) and hands the frozen result to the sealer
//! (`products::Sealer`, its own thread) through a bounded queue it never waits on; no lock is held
//! across a seal, so a slow seal (Ed25519, CPR, a canonical sort) never stalls ingest. A sealer
//! that is behind refuses the epoch whole, counted ([`Coordinator`]), never part of it.
//!
//! An epoch is decided by stamps alone (`ingest::Stamp`), never by a clock read at seal time, so
//! the same stamped trace closes the same epochs with the same contents on any number of threads.
//! The [`Coordinator`] gathers an epoch's frozen parts from every message thread and merges them:
//! the hub's deduplicated stream and each area's copies, each in canonical order. Regional products
//! are then signed area by area in cell order; the world seals at watermark plus
//! `products::WORLD_SETTLE_MS`. Geography appears only here.

use std::collections::BTreeMap;
use std::sync::Arc;

use tally_wire::{Decoded, ObsRef, Region};

use crate::budget::Charge;
use crate::exchange::Frozen;
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
    stamp.stamp_ms / EPOCH_MS
}

/// The first stamp after epoch `epoch`: the watermark at which it is closed.
pub fn end_of(epoch: Epoch) -> u64 {
    (epoch + 1) * EPOCH_MS
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
        watermark: Stamp,
        oldest_open: Option<Epoch>,
    ) -> std::ops::Range<Epoch> {
        let current = epoch_of(watermark);
        if !self.started {
            self.started = true;
            self.open_from = oldest_open.map_or(current, |oldest| oldest.min(current));
        }
        let closing = self.open_from..current.max(self.open_from);
        self.open_from = closing.end;
        closing
    }
}

/// One reception kept: its batch, shared, and its index there.
#[derive(Clone, Debug)]
pub struct Copy {
    pub decoded: Arc<Decoded>,
    pub index: u32,
}

impl Copy {
    pub fn obs(&self) -> &ObsRef {
        &self.decoded.observations()[self.index as usize]
    }

    /// The canonical order: by stamp, then place in the ingest order, then index in the batch.
    fn key(&self) -> (u64, u64, u32) {
        (
            self.decoded.stamp_ms(),
            self.decoded.ingest_seq(),
            self.index,
        )
    }
}

/// One epoch merged across every message thread.
#[derive(Debug, Default)]
pub struct Merged {
    pub epoch: Epoch,
    /// No copy of it is kept: a part was lost (a sealer behind), so all of it is refused.
    pub refused: bool,
    /// First copies of each message the relay heard, in canonical order.
    pub stream: Vec<Copy>,
    /// First copies in each area, by the area's cell number, each in canonical order.
    pub regional: BTreeMap<u64, (Region, Vec<Copy>)>,
    /// What its batches are charged, released when the epoch is let go.
    pub charges: Vec<Charge>,
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

#[derive(Default)]
struct Gathering {
    parts: Vec<Frozen>,
    refused: bool,
}

/// What a thread's word completes.
#[derive(Debug, Default)]
pub struct Ready {
    /// Epochs handed on, oldest first: merged, or refused whole.
    pub merged: Vec<Merged>,
    /// Epoch parts lost on the way since the last word (each one thread's part of one epoch).
    pub parts_lost: u64,
    /// Every epoch before this is closed on every thread.
    pub watermark: Option<Epoch>,
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
            watermark,
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
                out.push(merge(epoch, gathering.parts));
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
        merged.charges.push(std::mem::take(&mut part.charge));
        let copy = |at: u32, index: u32| Copy {
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
    merged.stream.sort_by_key(Copy::key);
    for (_, copies) in merged.regional.values_mut() {
        copies.sort_by_key(Copy::key);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(stamp_ms: u64) -> Stamp {
        Stamp {
            stamp_ms,
            ingest_seq: 0,
        }
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
