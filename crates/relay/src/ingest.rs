//! The ingest stage (RFC-0177 §2): where a batch becomes one immutable [`Decoded`], once, before
//! any other stage reads it. A connection task does I/O only and holds at most [`CREDIT`] batches
//! in flight; out of credit it stops reading its socket, so TCP pushes back on the feeder (whose
//! signed `dropped` records its own loss) and nothing queues unbounded. The work (verify, hash,
//! admit, inflate, decode) runs on a CPU pool ([`CpuPool`]), never on the async runtime's workers.
//!
//! Every batch is stamped here ([`Stamp`]): the ingest clock's reading and the batch's place in the
//! ingest order. Every later decision (which epoch a reception is in, when a shard may seal) reads
//! the stamp and never a clock of its own, so the same stamped trace gives the same output on any
//! number of threads (RFC-0177, invariants 1 and 2).
//!
//! Step 1 of the RFC: the stamp and the one decode are real and used by the hub
//! (`Hub::publish_batch`); the credit and the pool are defined, and the connection task still runs
//! the work inline ([`Inline`]), one batch at a time, which is within a credit of two.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tally_wire::{Batch, Decoded, Undecodable};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Batches one connection may have in the ingest stage at once. Two: one being worked on, one read
/// and waiting, so a connection's socket is read while its previous batch is decoded.
pub const CREDIT: usize = 2;

/// When a batch was taken, by the ingest clock, and its place in the ingest order. Ordered by
/// `(stamp_ms, ingest_seq)`: a watermark (`exchange::Tick`) is a stamp.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stamp {
    pub stamp_ms: u64,
    pub ingest_seq: u64,
}

/// What reads the ingest clock: the system's wall clock in a relay, a script in a test.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The ingest clock and order. One per relay.
pub struct Ingest {
    clock: Clock,
    next: AtomicU64,
}

impl Default for Ingest {
    fn default() -> Self {
        Self::new(Arc::new(crate::network::wall_ms))
    }
}

impl Ingest {
    pub fn new(clock: Clock) -> Self {
        Self {
            clock,
            next: AtomicU64::new(0),
        }
    }

    /// The next stamp: now by the ingest clock, and the next place in the ingest order.
    pub fn stamp(&self) -> Stamp {
        Stamp {
            stamp_ms: (self.clock)(),
            ingest_seq: self.next.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Stamps and decodes a batch whose signature the caller verified: the one decode every later
    /// stage shares. A batch of a format this build cannot read comes back whole, to be forwarded
    /// raw and read by nothing else.
    pub fn decode(&self, batch: Batch) -> Result<Arc<Decoded>, Box<Undecodable>> {
        let stamp = self.stamp();
        Decoded::from_verified(batch, stamp.stamp_ms, stamp.ingest_seq)
    }
}

/// One connection's credit (`CREDIT` batches in the ingest stage). The connection task takes a
/// permit before it hands a batch over and the stage drops it when the batch is decoded and
/// routed; with none left the task does not read its socket.
#[derive(Clone)]
pub struct Credit {
    permits: Arc<Semaphore>,
}

impl Default for Credit {
    fn default() -> Self {
        Self::new(CREDIT)
    }
}

impl Credit {
    pub fn new(batches: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(batches)),
        }
    }

    /// A permit for one batch, waiting while the connection has `CREDIT` in flight.
    pub async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).acquire_owned().await.ok()
    }

    /// Permits free now.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// The threads the ingest work runs on: dedicated CPU threads, never the async runtime's workers,
/// so a burst of verification never stalls a heartbeat or an egress write.
pub trait CpuPool: Send + Sync {
    /// Runs `work` on one of the pool's threads.
    fn run(&self, work: Box<dyn FnOnce() + Send>);
}

/// Runs the work where it is handed over: today's path, the connection task itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inline;

impl CpuPool for Inline {
    fn run(&self, work: Box<dyn FnOnce() + Send>) {
        work();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_read_the_ingest_clock_and_count_up() {
        let ingest = Ingest::new(Arc::new(|| 42));
        let first = ingest.stamp();
        let second = ingest.stamp();
        assert_eq!((first.stamp_ms, first.ingest_seq), (42, 0));
        assert_eq!((second.stamp_ms, second.ingest_seq), (42, 1));
        assert!(first < second);
    }

    #[tokio::test]
    async fn a_connection_holds_at_most_its_credit() {
        let credit = Credit::default();
        let first = credit.acquire().await;
        let second = credit.acquire().await;
        assert!(first.is_some() && second.is_some());
        assert_eq!(credit.available(), 0);
        drop(first);
        assert_eq!(credit.available(), 1);
    }
}
