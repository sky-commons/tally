//! Standing-weighted merging (RFC-0174 §2.12), the client's half. The rule is
//! `tally_mlat_solver::standing`'s, once for relays and clients; this is how the merge holds it.
//!
//! - **A bigger answer wins only if it agrees.** The merge rule's superset preference holds only
//!   when the solution over the larger observation set agrees with the smaller within the
//!   smaller's uncertainty (a chi-square test of the difference, [`superset_verdict`]). A superset
//!   that disagrees is `Contested`: a fault, never the answer. The smaller fix stands, both are
//!   kept as evidence (`Transmission::refused` and `Transmission::contests`), and the added
//!   receptions' receivers pay for it when the transmission is settled.
//! - **Sets are weighed by standing, not count** (`Fix::standing`, the rule's `decide`).
//! - **A position whose receivers lack standing is unconfirmed** ([`Confidence`]).
//! - **Receiver standing** is kept per receiver in a [`StandingLedger`] from every solution this
//!   client checked and the raw it holds, settled as the rule says. A client that does not hold
//!   raw cannot tell who heard what when, so it earns nobody standing.

use std::collections::BTreeSet;

use tally_mlat_solver::held::Held;
use tally_mlat_solver::standing::{self, Book, Claimed, ReceiverStanding, Solved, heard_in};
use tally_wire::batch::Hash;
use tally_wire::{PublicKey, Reception, TransmitTime};

use crate::Fix;

/// The chi-square point a superset's difference from the smaller fix must stay under to agree:
/// three degrees of freedom at 0.999 (the rule's).
pub const AGREE_CHI2: f64 = standing::AGREE_CHI2;

/// What comparing a superset with the smaller fix it would replace found.
#[derive(Clone, Debug, PartialEq)]
pub enum SupersetVerdict {
    /// Within the smaller's uncertainty: the superset may win, as RFC-0171 §3.8.1 says.
    Agrees,
    /// Not: the smaller stands.
    Contested(Contest),
}

/// A superset that disagreed: the evidence kept.
#[derive(Clone, Debug, PartialEq)]
pub struct Contest {
    /// The fix that stands, and the one refused, by full input set.
    pub kept: Hash,
    pub refused: Hash,
    /// The squared Mahalanobis distance of their difference under the smaller's covariance.
    pub chi2: f64,
    /// The receptions the superset added: their receivers pay for it.
    pub added: Vec<Reception>,
}

/// Whether a position's receivers carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// At least the solver's minimum of its receivers have standing.
    Standing,
    /// Fewer: drawn, and labelled unconfirmed.
    Unconfirmed,
}

pub(crate) fn claimed(fix: &Fix) -> Claimed {
    Claimed {
        lat_e7: fix.lat_e7,
        lon_e7: fix.lon_e7,
        alt_hae_mm: fix.alt_hae_mm,
        covariance: fix.covariance,
        transmitted: fix.transmitted,
    }
}

/// Whether `larger` (a strict superset of `smaller`'s observations) agrees with `smaller`.
pub fn superset_verdict(smaller: &Fix, larger: &Fix) -> SupersetVerdict {
    let agreement = standing::agreement(&claimed(smaller), &claimed(larger));
    if agreement.agrees() {
        return SupersetVerdict::Agrees;
    }
    SupersetVerdict::Contested(Contest {
        kept: smaller.input_set,
        refused: larger.input_set,
        chi2: agreement.chi2,
        added: larger
            .observations
            .receptions()
            .iter()
            .filter(|reception| !smaller.observations.receptions().contains(reception))
            .copied()
            .collect(),
    })
}

/// Receivers' standing, from the solutions this client checked and the raw it holds.
pub struct StandingLedger {
    book: Book,
}

impl StandingLedger {
    pub fn new(max_transmissions: usize, max_receivers: usize) -> Self {
        Self {
            book: Book::new(max_transmissions, max_receivers),
        }
    }

    /// A checked solution: held until its transmission is settled.
    pub(crate) fn solved(&mut self, solved: Solved) {
        self.book.add(solved);
    }

    /// Settles what is due by `now_ms` against the raw held: the receivers whose standing changed.
    pub(crate) fn settle(&mut self, now_ms: u64, held: &Held) -> BTreeSet<PublicKey> {
        self.book.settle(now_ms, |id, transmitted_ms| {
            heard_in(held, id, transmitted_ms)
        })
    }

    /// A fix's standing and confidence, as this ledger holds them now.
    pub(crate) fn weigh(&self, fix: &mut Fix) {
        fix.standing = self.standing_of(&fix.observations, fix.transmitted);
        fix.confidence = if fix.consistent {
            self.confidence(&fix.observations, fix.transmitted)
        } else {
            Confidence::Unconfirmed
        };
    }

    pub fn of(&self, receiver: &PublicKey) -> ReceiverStanding {
        self.book.of(receiver)
    }

    /// The rule's book: every receiver's standing, and what settling did.
    pub fn book(&self) -> &Book {
        &self.book
    }

    /// The sum of a fix's receivers' weights at its transmit time, thousandths.
    pub fn standing_of(&self, observations: &tally_wire::ObservationSet, at: TransmitTime) -> u64 {
        self.book.standing_of(observations, at)
    }

    pub fn confidence(
        &self,
        observations: &tally_wire::ObservationSet,
        at: TransmitTime,
    ) -> Confidence {
        if self.book.confirmed(observations, at) {
            Confidence::Standing
        } else {
            Confidence::Unconfirmed
        }
    }
}

#[cfg(test)]
mod tests;
