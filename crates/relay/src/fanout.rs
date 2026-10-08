//! Fan-out to subscribers (RFC-0177 §8). A router keyed by subscription cell feeds one queue per
//! subscriber, bounded in bytes and in time ([`Bounds`]): a subscriber whose queue would hold more
//! than about [`BEHIND_MS`] of inbound, or more bytes than its bound, has fallen behind and is
//! disconnected with a Goodbye that says so, never cut for a full shared ring. Fed per receiver
//! shard, so each (receiver, boot)'s admitted order holds and a receiver's description goes out
//! before its first batch.
//!
//! Step 1 of the RFC: [`Queue`] is defined; the hub still fans out through its broadcast ring
//! (`hub::FAN_OUT_CAPACITY`), and each item carries its batch's one decode (`hub::Item::decoded`)
//! so a BEAST output never decodes again.

use std::collections::VecDeque;

/// How far behind its inbound a subscriber may fall before it is let go.
pub const BEHIND_MS: u64 = 2_000;

/// A subscriber queue's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub max_bytes: usize,
    pub max_age_ms: u64,
}

/// Why a subscriber is let go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FellBehind {
    /// It holds more than `max_bytes`.
    Bytes,
    /// Its oldest item is more than `max_age_ms` older than the newest offered.
    Age,
}

/// One subscriber's queue of `T`, each with its size in bytes and its ingest stamp.
#[derive(Debug)]
pub struct Queue<T> {
    bounds: Bounds,
    items: VecDeque<(T, usize, u64)>,
    bytes: usize,
}

impl<T> Queue<T> {
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            items: VecDeque::new(),
            bytes: 0,
        }
    }

    /// Queues `item` of `bytes` stamped `stamp_ms`, or says the subscriber fell behind (the item
    /// is not queued, and the subscriber is to be disconnected).
    pub fn push(&mut self, item: T, bytes: usize, stamp_ms: u64) -> Result<(), FellBehind> {
        if self.bytes + bytes > self.bounds.max_bytes {
            return Err(FellBehind::Bytes);
        }
        if let Some((_, _, oldest)) = self.items.front()
            && stamp_ms.saturating_sub(*oldest) > self.bounds.max_age_ms
        {
            return Err(FellBehind::Age);
        }
        self.bytes += bytes;
        self.items.push_back((item, bytes, stamp_ms));
        Ok(())
    }

    /// The oldest item, to write.
    pub fn pop(&mut self) -> Option<T> {
        let (item, bytes, _) = self.items.pop_front()?;
        self.bytes -= bytes;
        Some(item)
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_queue_is_bounded_in_bytes_and_in_time() {
        let mut queue = Queue::new(Bounds {
            max_bytes: 100,
            max_age_ms: BEHIND_MS,
        });
        assert_eq!(queue.push(1, 60, 0), Ok(()));
        assert_eq!(queue.push(2, 60, 10), Err(FellBehind::Bytes));
        assert_eq!(queue.push(3, 10, BEHIND_MS + 1), Err(FellBehind::Age));
        assert_eq!(queue.push(4, 10, BEHIND_MS), Ok(()));
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.bytes(), 10);
        assert_eq!(queue.pop(), Some(4));
        assert!(queue.is_empty());
    }
}
