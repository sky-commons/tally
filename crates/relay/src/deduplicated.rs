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
/// How often seconds of the stream refused whole are reported, at most.
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
    /// Observations too large for any message since the last report: never sent, counted
    /// (`ProductsReport::stream_oversized`) and said.
    oversized: u64,
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
            oversized: 0,
        }
    }

    /// Signs the observations as one or more batches, each small enough for one message. Each
    /// observation is moved, never copied: into its chunk, its batch's content, and back when a
    /// chunk is halved. Returns the batches and how many observations were too large for any.
    fn sign(&mut self, mut observations: Vec<Observation>) -> (Vec<Batch>, u64) {
        let mut signed = Vec::new();
        let mut oversized = 0;
        if observations.is_empty() {
            return (signed, oversized);
        }
        let mut todo: Vec<Vec<Observation>> = Vec::new();
        while observations.len() > FIRST_TRY {
            let rest = observations.split_off(FIRST_TRY);
            todo.push(std::mem::replace(&mut observations, rest));
        }
        todo.push(observations);
        todo.reverse();
        while let Some(chunk) = todo.pop() {
            match self.try_sign(chunk) {
                Ok(batch) => {
                    self.previous = batch.hash();
                    self.sequence += 1;
                    signed.push(batch);
                }
                // One observation too large for any message is not deliverable: counted.
                Err(chunk) if chunk.len() <= 1 => oversized += chunk.len() as u64,
                Err(mut first) => {
                    let second = first.split_off(first.len() / 2);
                    todo.push(second);
                    todo.push(first);
                }
            }
        }
        self.oversized += oversized;
        (signed, oversized)
    }

    /// The signed batch, or the observations back when it would not fit one message.
    fn try_sign(&self, observations: Vec<Observation>) -> Result<Batch, Vec<Observation>> {
        let content = BatchContent {
            boot_id: self.boot_id,
            sequence: self.sequence,
            counter_epoch: 0,
            wall_ms: wall_ms(),
            dropped: 0,
            previous: self.previous,
            observations,
        };
        let Ok(batch) = Batch::sign_as_relay(&self.identity, &content) else {
            return Err(content.observations);
        };
        let record = Record::RelayBatch(batch);
        let mut encoded = Vec::new();
        let fits = record.encode(&mut encoded).is_ok() && encoded.len() <= MAX_PLAINTEXT;
        match record {
            Record::RelayBatch(batch) if fits => Ok(batch),
            _ => Err(content.observations),
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
    let mut refused = 0u64;
    let mut reported = Instant::now();
    loop {
        every.tick().await;
        let (gathered, epochs_refused) = hub.take_deduplicated();
        refused += epochs_refused;
        if (refused > 0 || signer.oversized > 0) && reported.elapsed() >= REPORT_EVERY {
            eprintln!(
                "tally-relay: {refused} seconds of the deduplicated stream were refused whole \
                 since the last report, each with every message first heard in it (their batches \
                 were forwarded raw): the products were behind or past their budget \
                 (`stream_refused` in GET /products); {} observations were too large for any \
                 message (`stream_oversized`)",
                signer.oversized
            );
            refused = 0;
            signer.oversized = 0;
            reported = Instant::now();
        }
        if gathered.is_empty() {
            continue;
        }
        let (signed, oversized) = signer.sign(gathered);
        hub.network().products.stream_oversized(oversized);
        for batch in signed {
            hub.publish_relay_batch(batch);
        }
    }
}
