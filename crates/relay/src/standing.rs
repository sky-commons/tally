//! Receiver standing at this relay (RFC-0174 §2.12): a [`Book`] of it, kept by the rule
//! `tally_mlat_solver::standing` states (the same for every relay and client), from the public
//! signed records the relay forwards: receivers' batches ([`Standing::batch`]), clock models
//! ([`Standing::model`]) and final and provisional positions ([`Standing::positions`]). A relay
//! that reads the same records as a client holds the same standing as it.
//!
//! It weighs which of a transmission's solutions stands (`Book::settle`, by `decide`) and which
//! receivers have standing (`credit` corroborates them). Gating a receiver out of the solver
//! (`ReceiverStanding::gated`) is not wired: the verifier refuses a solution that omits a
//! reception that fits (`Failure::Omitted`), so a relay that gated alone would publish solutions
//! every client refutes. It needs the gate in the specification, on both sides.

use std::sync::{Arc, Mutex, MutexGuard};

use tally_mlat_solver::ClockModel as Model;
use tally_mlat_solver::held::Held;
use tally_mlat_solver::publish;
use tally_mlat_solver::scope::{AFTER, BEFORE, STRIDE, bin_of};
use tally_mlat_solver::standing::{Book, ReceiverStanding, Solved, heard_in};
use tally_wire::batch::Hash;
use tally_wire::clock_model::Assembler;
use tally_wire::{Batch, ClockModel, Positions, PublicKey, Record, Solution};

use crate::bounded::Bounded;

/// Models held, the most recently cited kept.
pub const MAX_MODELS: usize = 16_384;
/// Bytes of clock model parts waiting for their manifest.
pub const MAX_MODEL_BYTES: usize = 64 << 20;
/// Models solutions wait for, and solutions each.
pub const MAX_WAITING: usize = 1_024;
pub const WAITING_PER_MODEL: usize = 4_096;
/// Bytes of raw held for telling when a reception was heard.
pub const MAX_HELD: usize = 1 << 30;
/// Transmissions waiting to be settled.
pub const MAX_TRANSMISSIONS: usize = 262_144;
/// Receivers whose standing is kept.
pub const MAX_RECEIVERS: usize = 65_536;
/// Bins of raw kept behind the relay's clock beyond a canonical window: the merge rule's.
const RAW_SPARE_BINS: i64 = 4;

struct HeldModel {
    spec: u16,
    inputs: Hash,
    model: Arc<Model>,
}

type Waiting = Vec<(u16, u64, bool, Solution)>;

struct Inner {
    assembler: Assembler,
    models: Bounded<Hash, HeldModel>,
    waiting: Bounded<Hash, Waiting>,
    held: Held,
    book: Book,
}

/// Every receiver's standing as this relay reads the records it forwards.
pub struct Standing {
    inner: Mutex<Inner>,
}

impl Default for Standing {
    fn default() -> Self {
        Self::new()
    }
}

impl Standing {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                assembler: Assembler::new(MAX_MODEL_BYTES, MAX_WAITING),
                models: Bounded::new(MAX_MODELS),
                waiting: Bounded::new(MAX_WAITING),
                held: Held::new(MAX_HELD),
                book: Book::new(MAX_TRANSMISSIONS, MAX_RECEIVERS),
            }),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A receiver's batch the relay forwarded (verified): when its receptions were heard.
    pub fn batch(&self, batch: &Batch, now_ms: u64) {
        let (Ok(receiver), Ok(content)) = (batch.receiver(), batch.content()) else {
            return;
        };
        let mut inner = self.inner();
        inner.held.add(receiver, &content);
        inner
            .held
            .forget_before(bin_of(now_ms) - BEFORE - AFTER - STRIDE - RAW_SPARE_BINS);
    }

    /// A clock model manifest or part the relay forwarded: held once whole, read under the
    /// specification it names, and only when it is a function of what it says.
    pub fn model(&self, record: &Record, now_ms: u64) {
        let mut inner = self.inner();
        let done = match record {
            Record::ClockModel(manifest) => {
                inner.assembler.manifest(manifest.clone()).ok().flatten()
            }
            Record::ClockModelPart(part) => inner.assembler.part(part.clone()),
            _ => None,
        };
        let Some((manifest, content)) = done else {
            return;
        };
        inner.hold(&manifest, content);
        inner.settle(now_ms);
    }

    /// Final or provisional positions the relay forwarded (verified): each solution under a held
    /// model, consistent with its own receptions, joins its transmission until it is settled.
    pub fn positions(&self, positions: &Positions, now_ms: u64) {
        let Ok(content) = positions.solutions() else {
            return;
        };
        let provisional = positions.is_provisional();
        let mut inner = self.inner();
        for solution in content.solutions {
            inner.solution(
                content.spec_version,
                content.issued_ms,
                provisional,
                solution,
            );
        }
        inner.settle(now_ms);
    }

    /// Settles what is due by `now_ms`.
    pub fn tick(&self, now_ms: u64) {
        self.inner().settle(now_ms);
    }

    /// A receiver's standing now: a new key's, none.
    pub fn of(&self, receiver: &PublicKey) -> ReceiverStanding {
        self.inner().book.of(receiver)
    }

    /// The receivers with standing now (their receptions kept agreeing with verified fixes):
    /// corroborated first-hand, which is what `credit` counts a feeder's description by.
    pub fn agreeing(&self, now_ms: u64) -> Vec<PublicKey> {
        let period = tally_mlat_solver::standing::period_of(now_ms);
        self.inner()
            .book
            .receivers()
            .iter()
            .filter(|(_, standing)| standing.has_standing(period))
            .map(|(key, _)| *key)
            .collect()
    }
}

impl Inner {
    fn hold(&mut self, manifest: &ClockModel, content: tally_wire::ClockModelContent) {
        let Ok(decoded) = publish::decode(&content.model, content.spec_version) else {
            return;
        };
        if publish::inputs_id(&decoded) != content.inputs {
            return;
        }
        // An engine solved the window, so its raw is in: sealed, as the merge rule seals it.
        self.held.seal_through(decoded.window.last);
        let id = manifest.id();
        self.models.insert_active(
            id,
            HeldModel {
                spec: content.spec_version,
                inputs: content.inputs,
                model: Arc::new(decoded),
            },
        );
        if let Some(waiting) = self.waiting.remove(&id) {
            for (spec, issued_ms, provisional, solution) in waiting {
                self.solution(spec, issued_ms, provisional, solution);
            }
        }
    }

    fn solution(&mut self, spec: u16, issued_ms: u64, provisional: bool, solution: Solution) {
        let id = solution.clock_model;
        self.models.touch(&id);
        let Some(model) = self.models.get(&id) else {
            match self.waiting.get_mut(&id) {
                Some(waiting) if waiting.len() < WAITING_PER_MODEL => {
                    waiting.push((spec, issued_ms, provisional, solution));
                }
                Some(_) => {}
                None => {
                    self.waiting
                        .insert_active(id, vec![(spec, issued_ms, provisional, solution)]);
                }
            }
            return;
        };
        if model.spec != spec {
            return;
        }
        if let Some(solved) = Solved::new(
            &solution,
            spec,
            issued_ms,
            provisional,
            Arc::clone(&model.model),
            model.inputs,
        ) {
            self.book.add(solved);
        }
    }

    fn settle(&mut self, now_ms: u64) {
        let held = &self.held;
        self.book.settle(now_ms, |id, transmitted_ms| {
            heard_in(held, id, transmitted_ms)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    #[test]
    fn a_new_key_has_no_standing_and_records_it_cannot_read_change_nothing() {
        let standing = Standing::new();
        let key = Identity::from_seed([3; 32]).public();
        assert_eq!(standing.of(&key), ReceiverStanding::NEW);
        standing.model(&Record::Heartbeat, 0);
        standing.tick(u64::MAX / 2);
        assert_eq!(standing.of(&key), ReceiverStanding::NEW);
    }
}
