//! The raw a holder has received, as it arrived: held in one-second slices of signed wall clock,
//! indexed by transmission, with each receiver's contiguous frontier of batches. A model's inputs
//! are what had arrived when it was fitted (cited by each member's frontier), and a transmission
//! is solved from the receptions that had arrived `SETTLE_MS` after its first one (its
//! considered set). Replaces `held` (phase 1 deletes it).
//!
//! Phase 0: the seam alone. Every body is `todo!("phase 1")`.

#![allow(dead_code)]

use tally_wire::PublicKey;

use crate::clock::ClockModel;
use crate::held::Limits;
use crate::obs::{ObservationId, Reception};
use crate::scope::{Frontier, Sites, TrailingInputs};
use crate::tile::Tile;
use crate::verify::ModelFailure;

// phase 0: from tally_wire::budget::TRAILING_WINDOW_MS.
const TRAILING_WINDOW_MS: u64 = crate::scope::TRAILING_WINDOW_MS;
// phase 0: from tally_wire::budget::SIGNED_LAG_MS (MLAT_BATCHING 2 + E 7.5 + 2 U_M, 11.5 s).
const SIGNED_LAG_MS: u64 = 11_500;
// phase 0: from tally_wire::budget::REFIT_EVERY_MS, which the engine's `STEP_MS` equals.
const STEP_MS: u64 = 1_000;

/// How long arrived raw is held: a trailing window, how late a reception's signed wall clock may
/// be behind its arrival, and one step.
pub const HELD_MS: u64 = TRAILING_WINDOW_MS + SIGNED_LAG_MS + STEP_MS;

/// One signed batch: its receiver, the receiver's boot and the batch's sequence in that boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BatchId {
    pub receiver: PublicKey,
    pub boot_id: u64,
    pub sequence: u64,
}

/// Which transmission a considered set is of: its message's hash and its lowest-identity
/// reception's identity.
// phase 0: the plan names `TransmissionKey` without defining it; phase 1 settles its fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransmissionKey {
    pub message: [u8; 32],
    pub lowest: ObservationId,
}

/// Why a batch, or part of it, was not admitted: a hard cap of the relay-wide budget, refused
/// whole, never trimmed by rank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    OverCap {
        what: &'static str,
        count: usize,
        cap: usize,
    },
}

/// What admitting one batch did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    /// Receptions held.
    pub kept: u32,
    /// Receptions a threshold dropped.
    pub thinned: u32,
    pub refused: Option<Refused>,
}

/// A transmission due to be solved: the receptions of it that had arrived `SETTLE_MS` after its
/// first did, which is all a solution of it may be judged on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Considered {
    pub key: TransmissionKey,
    pub first_arrival_ms: u64,
    /// Sorted by identity.
    pub receptions: Vec<Reception>,
}

/// The raw a holder has received (module docs).
pub struct Arrived {
    limits: Limits,
}

impl Arrived {
    pub fn new(limits: Limits) -> Self {
        let _ = limits;
        todo!("phase 1")
    }

    /// Admits one batch's receptions, arrived at `now_ms`, by threshold, within the limits.
    pub fn admit(&mut self, batch: BatchId, now_ms: u64, receptions: &[Reception]) -> Admitted {
        let _ = (batch, now_ms, receptions);
        todo!("phase 1")
    }

    /// Drops what is older than `HELD_MS` before `now_ms`.
    pub fn seal(&mut self, now_ms: u64) {
        let _ = now_ms;
        todo!("phase 1")
    }

    /// The receiver's contiguous frontier: its newest boot's batches with no gap below.
    pub fn frontier(&self, receiver: PublicKey) -> Option<Frontier> {
        let _ = receiver;
        todo!("phase 1")
    }

    /// The tile's inputs at the trailing edge `edge_ms`, from what has arrived.
    pub fn inputs(&self, tile: Tile, sites: &Sites, edge_ms: u64) -> Option<TrailingInputs> {
        let _ = (tile, sites, edge_ms);
        todo!("phase 1")
    }

    /// The inputs `model` cites, rebuilt from what has arrived: `ModelFailure::Unjudged` when a
    /// batch at or below a cited frontier has not.
    pub fn rebuild(&self, model: &ClockModel) -> Result<TrailingInputs, ModelFailure> {
        let _ = model;
        todo!("phase 1")
    }

    /// The transmissions whose first arrival plus `SETTLE_MS` is at or before `now_ms`.
    pub fn due(&self, now_ms: u64) -> impl Iterator<Item = Considered> + '_ {
        let _ = now_ms;
        // An opaque iterator needs a concrete type even where the body panics.
        if true {
            todo!("phase 1")
        }
        std::iter::empty()
    }

    /// Bytes held, every byte counted as allocated.
    pub fn bytes(&self) -> usize {
        todo!("phase 1")
    }
}
