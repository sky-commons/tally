//! Keyed exchanges between the ingest stage and the shards that own state (RFC-0177 §3). There
//! are [`SHARDS`] logical shards per exchange, mapped onto threads, each owning its state outright,
//! so nothing on the per-reception path takes a lock. A producer (an ingest worker) sends a shard
//! one [`Slice`] per batch, never one message per reception: the batch, shared, and the index
//! ranges of its receptions whose key falls in that shard. Queues are bounded per (producer,
//! shard).
//!
//! Keys are uniform hashes only, never geography, so a dense area cannot make a hot shard:
//!
//! - [`Exchange::Message`]: by a reception's fingerprint. The one deduplication (the hub's stream
//!   and each area's first-heard).
//! - [`Exchange::Raw`]: by receiver. Open MLAT fragments, station counters.
//! - [`Exchange::Address`]: by ICAO address. The world and provisional products.
//!
//! Every producer sends [`Envelope::Tick`] down every queue as its stamps advance; a shard's
//! watermark ([`Watermark`]) is the least of its producers' ticks, and a shard closes an epoch
//! (`seal`) once its watermark passes it.
//!
//! Step 1 of the RFC: the keys, the split of a batch into slices and the watermark are real; the
//! hub still calls each consumer inline with the whole batch ([`Inline`]).

use std::ops::Range;
use std::sync::Arc;

use tally_wire::{Decoded, ObsRef, PublicKey};

use crate::ingest::Stamp;

/// Logical shards per exchange: fixed, so a key's shard never depends on how many threads run.
pub const SHARDS: usize = 256;

/// Slices a (producer, shard) queue holds before the producer waits: about a second of one
/// feeder's batches per producer at the RFC's rate, bounded whatever the shard's speed.
pub const QUEUE_SLICES: usize = 1_024;

/// A shard of one exchange, `0..SHARDS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(pub u16);

/// The exchanges, by what their shards are keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exchange {
    Message,
    Raw,
    Address,
}

/// The shard of a reception's fingerprint: its low bits, uniform whatever the messages (the
/// fingerprint is keyed, `tally_wire::decoded`).
pub fn message_shard(fp: u128) -> ShardId {
    ShardId((fp % SHARDS as u128) as u16)
}

/// The shard of a receiver: its key's low bytes. A public key is uniform; a feeder can choose its
/// key, and choosing one that lands on a busy shard only puts its own batches in that shard's queue.
pub fn raw_shard(receiver: &PublicKey) -> ShardId {
    let bytes = receiver.as_bytes();
    ShardId((u16::from_le_bytes([bytes[0], bytes[1]]) as usize % SHARDS) as u16)
}

/// The shard of an ICAO address, mixed (Fibonacci hashing) so the registries' consecutive blocks
/// spread across shards.
pub fn address_shard(address: u32) -> ShardId {
    let mixed = address.wrapping_mul(0x9E37_79B9);
    ShardId(((mixed >> 16) as usize % SHARDS) as u16)
}

/// One batch's receptions for one shard: the batch, shared, and the runs of its observation
/// indices whose key falls in the shard, ascending.
#[derive(Clone, Debug)]
pub struct Slice {
    pub decoded: Arc<Decoded>,
    pub ranges: Box<[Range<u32>]>,
}

impl Slice {
    /// The receptions of the slice, in the batch's order.
    pub fn observations(&self) -> impl Iterator<Item = &ObsRef> + '_ {
        let all = self.decoded.observations();
        self.ranges
            .iter()
            .flat_map(move |range| &all[range.start as usize..range.end as usize])
    }
}

/// What travels down a (producer, shard) queue.
#[derive(Clone, Debug)]
pub enum Envelope {
    Slice(Slice),
    /// Everything this producer sends from now on is stamped at or after this.
    Tick(Stamp),
}

/// Splits a batch into one slice per shard its receptions key into, by `shard_of` each reception,
/// shards ascending. A batch keyed as a whole (by receiver) is one slice: `whole`.
pub fn split(
    decoded: &Arc<Decoded>,
    shard_of: impl Fn(&ObsRef) -> ShardId,
) -> Vec<(ShardId, Slice)> {
    let mut runs: Vec<(ShardId, Range<u32>)> = Vec::new();
    for (index, obs) in decoded.observations().iter().enumerate() {
        let index = index as u32;
        let shard = shard_of(obs);
        match runs.last_mut() {
            Some((last, range)) if *last == shard && range.end == index => range.end += 1,
            _ => runs.push((shard, index..index + 1)),
        }
    }
    // Stable: each shard's runs stay ascending.
    runs.sort_by_key(|(shard, _)| *shard);
    let mut slices: Vec<(ShardId, Slice)> = Vec::new();
    let mut at = 0;
    while at < runs.len() {
        let shard = runs[at].0;
        let end = runs[at..]
            .iter()
            .position(|(other, _)| *other != shard)
            .map_or(runs.len(), |offset| at + offset);
        let ranges = runs[at..end]
            .iter()
            .map(|(_, range)| range.clone())
            .collect();
        slices.push((
            shard,
            Slice {
                decoded: Arc::clone(decoded),
                ranges,
            },
        ));
        at = end;
    }
    slices
}

/// The whole batch as one slice, for an exchange keyed per batch (`Exchange::Raw`).
pub fn whole(decoded: &Arc<Decoded>) -> (ShardId, Slice) {
    let count = decoded.observations().len() as u32;
    (
        raw_shard(&decoded.receiver()),
        Slice {
            decoded: Arc::clone(decoded),
            ranges: std::iter::once(0..count).collect(),
        },
    )
}

/// A shard's view of its producers' progress: the newest tick from each, and the least of them,
/// before which nothing more will arrive.
#[derive(Clone, Debug)]
pub struct Watermark {
    ticks: Box<[Stamp]>,
}

impl Watermark {
    pub fn new(producers: usize) -> Self {
        Self {
            ticks: vec![Stamp::default(); producers].into_boxed_slice(),
        }
    }

    /// Producer `producer` ticked at `stamp`; the watermark after it. A tick never goes back.
    pub fn tick(&mut self, producer: usize, stamp: Stamp) -> Stamp {
        if let Some(tick) = self.ticks.get_mut(producer) {
            *tick = (*tick).max(stamp);
        }
        self.at()
    }

    /// The least producer tick: every slice stamped before it has arrived.
    pub fn at(&self) -> Stamp {
        self.ticks.iter().copied().min().unwrap_or_default()
    }
}

/// What owns one shard's state: takes its slices and its watermark, on its own thread.
pub trait Shard: Send {
    fn take(&mut self, slice: &Slice);
    /// The watermark advanced to `watermark`: what closes by it closes now (`seal`).
    fn advance(&mut self, watermark: Stamp);
}

/// Routes a batch to the shards of one exchange.
pub trait Router: Send + Sync {
    fn route(&self, exchange: Exchange, decoded: &Arc<Decoded>);
    fn tick(&self, stamp: Stamp);
}

/// Today's path: the hub hands each consumer the whole batch itself, so this routes nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inline;

impl Router for Inline {
    fn route(&self, _exchange: Exchange, _decoded: &Arc<Decoded>) {}
    fn tick(&self, _stamp: Stamp) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::{Batch, BatchContent, Identity, Observation};

    fn decoded(count: u8) -> Result<Arc<Decoded>, String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let content = BatchContent {
            boot_id: 1,
            sequence: 0,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: (0..count)
                .map(|n| Observation {
                    format: b'3',
                    timestamp: u64::from(n),
                    signal: 0,
                    data: vec![n; 14],
                })
                .collect(),
        };
        let batch = Batch::sign(&identity, &content).map_err(|error| error.to_string())?;
        Decoded::from_verified(batch, 0, 0).map_err(|undecodable| undecodable.error.to_string())
    }

    #[test]
    fn a_batch_splits_into_each_shards_receptions_once_in_order() -> Result<(), String> {
        let decoded = decoded(200)?;
        let slices = split(&decoded, |obs| message_shard(obs.fp));
        let mut seen: Vec<u64> = Vec::new();
        for (shard, slice) in &slices {
            let mut previous = None;
            for obs in slice.observations() {
                assert_eq!(message_shard(obs.fp), *shard);
                assert!(previous.is_none_or(|previous| previous < obs.timestamp));
                previous = Some(obs.timestamp);
                seen.push(obs.timestamp);
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..200).collect::<Vec<u64>>());
        assert!(slices.windows(2).all(|pair| pair[0].0 < pair[1].0));
        Ok(())
    }

    #[test]
    fn the_watermark_is_the_slowest_producers_tick() {
        let at = |stamp_ms| Stamp {
            stamp_ms,
            ingest_seq: 0,
        };
        let mut watermark = Watermark::new(2);
        assert_eq!(watermark.tick(0, at(10)), at(0));
        assert_eq!(watermark.tick(1, at(5)), at(5));
        assert_eq!(watermark.tick(1, at(3)), at(5));
        assert_eq!(watermark.tick(1, at(20)), at(10));
    }
}
