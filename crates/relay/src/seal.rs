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

use crate::exchange::Frozen;
use crate::ingest::Stamp;

/// An epoch: one `EPOCH_MS` of the ingest clock.
pub type Epoch = u64;

/// How long an epoch is: the regional product's once a second.
pub const EPOCH_MS: u64 = crate::products::REGIONAL_EVERY_MS;

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
/// lost. A thread sends a part only for an epoch it held receptions of, and numbers what it sends,
/// so a gap in its numbers is a part lost (the sealer's queue was full): every epoch it could have
/// been for, from the thread's last word to the next, is refused.
pub struct Coordinator {
    pending: BTreeMap<Epoch, Gathering>,
    /// Per thread: every epoch before this is closed there.
    closed: Vec<Option<Epoch>>,
    /// Per thread: the number of its next message.
    expected: Vec<u64>,
    /// Epochs a lost part may have been for: refused when they complete.
    lost: Vec<std::ops::Range<Epoch>>,
    /// Every epoch before this has been handed on.
    next: Epoch,
}

#[derive(Default)]
struct Gathering {
    parts: Vec<Frozen>,
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
    pub fn take(&mut self, frozen: Frozen) -> (Vec<Merged>, Option<Epoch>) {
        let thread = frozen.thread.min(self.closed.len() - 1);
        if frozen.seq != self.expected[thread] {
            // Lost on the way: whatever it was, it was for an epoch from the thread's last word
            // to this one (from its first, the oldest epoch anyone has a part of).
            let until = frozen.epoch.unwrap_or(frozen.closed_before);
            let since = self.closed[thread]
                .or_else(|| self.pending.keys().next().copied())
                .unwrap_or(until)
                .max(self.next);
            if since < until {
                self.lost.push(since..until);
            }
        }
        self.expected[thread] = frozen.seq + 1;
        self.closed[thread] = Some(frozen.closed_before.max(self.closed[thread].unwrap_or(0)));
        if let Some(epoch) = frozen.epoch
            && epoch >= self.next
        {
            self.pending.entry(epoch).or_default().parts.push(frozen);
        }
        self.ready()
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
            if self.lost.iter().any(|lost| lost.contains(&epoch)) {
                out.push(Merged {
                    epoch,
                    refused: true,
                    ..Merged::default()
                });
            } else {
                out.push(merge(epoch, gathering.parts));
            }
        }
        // An epoch lost whole (every part of it lost) is refused all the same.
        for lost in &self.lost {
            for epoch in lost.start.max(self.next)..lost.end.min(watermark) {
                if !out.iter().any(|merged| merged.epoch == epoch) {
                    out.push(Merged {
                        epoch,
                        refused: true,
                        ..Merged::default()
                    });
                }
                // A lost range is never wider than the epochs one thread closed at once.
                if out.len() > 4_096 {
                    break;
                }
            }
        }
        out.sort_by_key(|merged| merged.epoch);
        self.next = self.next.max(watermark);
        let next = self.next;
        self.lost.retain(|lost| lost.end > next);
        (out, Some(watermark))
    }
}

/// Every thread's part of one epoch as one: each list in canonical order.
pub fn merge(epoch: Epoch, parts: Vec<Frozen>) -> Merged {
    let mut merged = Merged {
        epoch,
        ..Merged::default()
    };
    for part in parts {
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

    fn epochs(done: (Vec<Merged>, Option<Epoch>)) -> Vec<(Epoch, bool)> {
        done.0.iter().map(|m| (m.epoch, m.refused)).collect()
    }

    #[test]
    fn an_epoch_is_handed_on_once_every_thread_closed_it_and_refused_whole_if_a_part_was_lost() {
        let mut coordinator = Coordinator::new(2);
        assert!(epochs(coordinator.take(part(5, 0, 0))).is_empty());
        assert_eq!(epochs(coordinator.take(part(5, 1, 0))), vec![(5, false)]);
        // Thread 1's part of epoch 6 was lost (its next message is its third): 6 is refused.
        assert!(epochs(coordinator.take(part(6, 0, 1))).is_empty());
        assert_eq!(epochs(coordinator.take(part(7, 1, 2))), vec![(6, true)]);
        assert_eq!(epochs(coordinator.take(part(7, 0, 2))), vec![(7, false)]);
        // An epoch a thread held nothing of needs nothing from it: its close is enough.
        assert!(epochs(coordinator.take(part(9, 0, 3))).is_empty());
        let closed = Frozen {
            thread: 1,
            seq: 3,
            epoch: None,
            closed_before: 1_000_000_000,
            ..Frozen::default()
        };
        let (done, watermark) = coordinator.take(closed);
        assert_eq!(
            done.iter()
                .map(|m| (m.epoch, m.refused))
                .collect::<Vec<_>>(),
            vec![(9, false)]
        );
        assert_eq!(watermark, Some(10));
    }
}
