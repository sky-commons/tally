//! Sealing by watermark, off the hot path (RFC-0177 §4). A shard owns an open buffer per epoch.
//! When its watermark (`exchange::Watermark`) passes the end of an epoch, the shard swaps that
//! buffer out ([`Closer`]) and hands the frozen buffer to a sealer pool ([`SealerPool`]); no lock is
//! held across a seal, so a slow seal (Ed25519, CPR, a canonical sort) never stalls ingest.
//!
//! An epoch is decided by stamps alone (`ingest::Stamp`), never by a clock read at seal time, so
//! the same stamped trace closes the same epochs with the same contents on any number of threads.
//! Regional products merge the frozen copies of an area across message shards, sort canonically,
//! sequence in cell order and sign; MLAT bins are sealed from per-receiver fragments
//! (`Bin::seal_from`), byte-equal to one whole `Held`'s; the world seals at watermark plus
//! `products::WORLD_SETTLE_MS`. Geography appears only here.
//!
//! Step 1 of the RFC: [`Closer`] and the pool are defined; `products::tick` still seals inline
//! under its lock ([`Inline`]).

use crate::ingest::Stamp;

/// An epoch: one `EPOCH_MS` of the ingest clock.
pub type Epoch = u64;

/// How long an epoch is: the regional product's once a second.
pub const EPOCH_MS: u64 = crate::products::REGIONAL_EVERY_MS;

/// The epoch a stamp falls in.
pub fn epoch_of(stamp: Stamp) -> Epoch {
    stamp.stamp_ms / EPOCH_MS
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
    /// call closes nothing before the watermark's own epoch (a shard starts with nothing older).
    pub fn advance(&mut self, watermark: Stamp) -> std::ops::Range<Epoch> {
        let current = epoch_of(watermark);
        if !self.started {
            self.started = true;
            self.open_from = current;
            return current..current;
        }
        let closing = self.open_from..current.max(self.open_from);
        self.open_from = closing.end;
        closing
    }
}

/// A frozen buffer, sealed into what it publishes. Runs on a sealer thread, owning its input.
pub trait Sealable: Send + 'static {
    type Sealed: Send + 'static;
    fn seal(self) -> Self::Sealed;
}

/// The threads seals run on.
pub trait SealerPool: Send + Sync {
    fn submit(&self, work: Box<dyn FnOnce() + Send>);
}

/// Seals where it is asked: today's path, under the caller's lock.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inline;

impl SealerPool for Inline {
    fn submit(&self, work: Box<dyn FnOnce() + Send>) {
        work();
    }
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
        assert_eq!(closer.advance(at(5_500)), 5..5);
        assert_eq!(closer.advance(at(5_999)), 5..5);
        assert_eq!(closer.advance(at(6_000)), 5..6);
        assert_eq!(closer.advance(at(9_100)), 6..9);
        assert_eq!(closer.advance(at(8_000)), 9..9);
    }
}
