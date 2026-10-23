//! The deduplicated stream (RFC-0171 §3.6): each epoch, the first copies of each message the
//! relay gathered across all receivers, signed by this relay as its own claim. It is a batch like a
//! receiver's (its own random boot id, sequence from 0, hash chain), sent as `RelayBatch` so no
//! one mistakes it for a receiver's reception, and never passed to another relay: each relay
//! derives its own.
//!
//! The sealer signs it (RFC-0181 §4), in its pool beside the epoch's areas, while the epoch's
//! batches are still held: each reception is read where its batch holds it
//! (`Batch::sign_relay_draft`), never copied, and the signed batches go out with the epoch's other
//! records (`products::Sealer`). An epoch's batches carry its end as their time, as its regional
//! records do, so the same stamped batches sign the same stream on any number of threads.

use tally_wire::batch::Hash;
use tally_wire::{Batch, BatchDraft, Signs};

use crate::seal::Kept;

/// The most observations tried in one batch before it is measured; halved until it fits a
/// record.
const FIRST_TRY: usize = 2_048;

/// One boot of the relay's own signed stream: where its chain stands.
#[derive(Clone, Debug, Default)]
pub struct Stream {
    boot_id: u64,
    sequence: u64,
    previous: Hash,
}

/// One epoch's stream, signed: its batches in order, the copies too large for any, and the copies
/// left unsigned because the signer's clock stopped judging while the epoch sealed.
#[derive(Debug, Default)]
pub struct Signed {
    pub batches: Vec<Batch>,
    pub oversized: u64,
    pub unsigned: u64,
}

impl Signed {
    /// `copies` copies left unsigned: the signer's clock was not judging.
    pub fn unsigned(copies: usize) -> Self {
        Self {
            unsigned: copies as u64,
            ..Self::default()
        }
    }
}

impl Stream {
    /// A stream from its first batch, under `boot_id`.
    pub fn new(boot_id: u64) -> Self {
        Self {
            boot_id,
            sequence: 0,
            previous: [0; 32],
        }
    }

    /// Signs one epoch's first copies (`copies`, in canonical order) as one or more batches, each
    /// small enough for one record, timed `wall_ms`. Each copy is moved, never its reception
    /// copied: into its chunk, and into a half when a chunk is halved. A copy too large for any
    /// record is not deliverable, and is counted.
    pub fn sign(&mut self, identity: &impl Signs, mut copies: Vec<Kept>, wall_ms: u64) -> Signed {
        let mut signed = Signed::default();
        let mut todo: Vec<Vec<Kept>> = Vec::new();
        while copies.len() > FIRST_TRY {
            let rest = copies.split_off(FIRST_TRY);
            todo.push(std::mem::replace(&mut copies, rest));
        }
        todo.push(copies);
        todo.reverse();
        while let Some(mut chunk) = todo.pop() {
            if chunk.is_empty() {
                continue;
            }
            let draft = self.draft(&chunk, wall_ms);
            if Batch::relay_draft_fits(&draft) {
                match Batch::sign_relay_draft(identity, &draft) {
                    Ok(batch) => {
                        self.previous = batch.hash();
                        self.sequence += 1;
                        signed.batches.push(batch);
                    }
                    // A draft that fits always signs; were it not to, its copies are counted.
                    Err(_) => signed.oversized += chunk.len() as u64,
                }
            } else if chunk.len() <= 1 {
                signed.oversized += chunk.len() as u64;
            } else {
                let second = chunk.split_off(chunk.len() / 2);
                todo.push(second);
                todo.push(chunk);
            }
        }
        signed
    }

    /// The next batch of the chain over `copies`, each read where its batch holds it.
    fn draft<'a>(&self, copies: &'a [Kept], wall_ms: u64) -> BatchDraft<'a> {
        BatchDraft {
            boot_id: self.boot_id,
            sequence: self.sequence,
            counter_epoch: 0,
            wall_ms,
            dropped: 0,
            previous: self.previous,
            observations: copies
                .iter()
                .map(|copy| copy.decoded.view(copy.obs()))
                .collect(),
        }
    }
}
