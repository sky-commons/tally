//! The deduplicated stream (RFC-0171 §3.6): every second, the first copies of each message the
//! hub gathered across all receivers, signed by this relay as its own claim. It is a batch like a
//! receiver's (its own random boot id, sequence from 0, hash chain), sent as `RelayBatch` so no
//! one mistakes it for a receiver's reception, and never passed to another relay: each relay
//! derives its own.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tally_wire::batch::Hash;
use tally_wire::noise::MAX_PLAINTEXT;
use tally_wire::{Batch, BatchContent, Identity, Observation, Record};

use crate::hub::Hub;

const EVERY: Duration = Duration::from_secs(1);
/// How often messages left out for want of room are reported, at most.
const REPORT_EVERY: Duration = Duration::from_secs(60);
/// The most observations tried in one batch before it is measured; halved until it fits a
/// message.
const FIRST_TRY: usize = 2_048;

/// One boot of the relay's own signed stream.
struct Signer {
    identity: Identity,
    boot_id: u64,
    sequence: u64,
    previous: Hash,
}

impl Signer {
    fn new(identity: Identity) -> Self {
        Self {
            identity,
            // The standard library's per-process random keys: random per start, which is all a
            // boot id must be.
            boot_id: RandomState::new().build_hasher().finish(),
            sequence: 0,
            previous: [0; 32],
        }
    }

    /// Signs the observations as one or more batches, each small enough for one message.
    fn sign(&mut self, observations: Vec<Observation>) -> Vec<Batch> {
        let mut signed = Vec::new();
        let mut todo: Vec<Vec<Observation>> = observations
            .chunks(FIRST_TRY)
            .rev()
            .map(<[Observation]>::to_vec)
            .collect();
        while let Some(chunk) = todo.pop() {
            match self.try_sign(&chunk) {
                Some(batch) => {
                    self.previous = batch.hash();
                    self.sequence += 1;
                    signed.push(batch);
                }
                // One observation too large for any message is not deliverable; drop it.
                None if chunk.len() <= 1 => {}
                None => {
                    let (first, second) = chunk.split_at(chunk.len() / 2);
                    todo.push(second.to_vec());
                    todo.push(first.to_vec());
                }
            }
        }
        signed
    }

    /// The signed batch, or `None` when it would not fit one message.
    fn try_sign(&self, observations: &[Observation]) -> Option<Batch> {
        let batch = Batch::sign_as_relay(
            &self.identity,
            &BatchContent {
                boot_id: self.boot_id,
                sequence: self.sequence,
                counter_epoch: 0,
                wall_ms: wall_ms(),
                dropped: 0,
                previous: self.previous,
                observations: observations.to_vec(),
            },
        )
        .ok()?;
        let record = Record::RelayBatch(batch);
        let mut encoded = Vec::new();
        record.encode(&mut encoded).ok()?;
        match record {
            Record::RelayBatch(batch) if encoded.len() <= MAX_PLAINTEXT => Some(batch),
            _ => None,
        }
    }
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Signs and broadcasts the deduplicated stream for as long as the relay runs.
pub async fn run(hub: Arc<Hub>, identity: Identity) {
    let mut signer = Signer::new(identity);
    let mut every = tokio::time::interval(EVERY);
    let mut skipped = 0u64;
    let mut reported = Instant::now();
    loop {
        every.tick().await;
        let (gathered, left_out) = hub.take_deduplicated();
        skipped += left_out;
        if skipped > 0 && reported.elapsed() >= REPORT_EVERY {
            eprintln!(
                "tally-relay: {skipped} new messages in the last minute were forwarded raw but \
                 left out of the deduplicated stream: it was holding as much as it may"
            );
            skipped = 0;
            reported = Instant::now();
        }
        if gathered.is_empty() {
            continue;
        }
        for batch in signer.sign(gathered) {
            hub.publish_relay_batch(batch);
        }
    }
}
