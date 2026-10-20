//! A bigger answer wins only if it agrees (RFC-0174 §2.12), the client's half. The rule is
//! `tally_mlat_solver::standing`'s, once for relays and clients; this is how the merge holds it
//! over tag sets.
//!
//! The merge rule's superset preference holds only when the solution over the larger tag set
//! agrees with the smaller within the smaller's uncertainty (a chi-square test of the difference,
//! [`superset_verdict`]). A superset that disagrees is contested: a fault, never the answer. The
//! smaller fix stands, both are kept as evidence (`Transmission::refused` and
//! `Transmission::contests`), and the tags the superset added are named ([`Contest::added`]): a
//! relay, which can rematch them to receivers (`tally_mlat_solver::publish::rematch`), makes those
//! receivers pay for it in standing. A client keeps no standing: it cannot tell who heard what
//! when, nor whose a tag is.

use tally_mlat_solver::standing::{self, Claimed};
use tally_wire::ReceptionTag;
use tally_wire::batch::Hash;

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
    /// The tags the superset added: a relay rematches them to the receivers that pay for it.
    pub added: Vec<ReceptionTag>,
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

/// Whether `larger` (a strict superset of `smaller`'s tags) agrees with `smaller`.
pub fn superset_verdict(smaller: &Fix, larger: &Fix) -> SupersetVerdict {
    let agreement = standing::agreement(&claimed(smaller), &claimed(larger));
    if agreement.agrees() {
        return SupersetVerdict::Agrees;
    }
    let theirs = smaller.observations.tags();
    SupersetVerdict::Contested(Contest {
        kept: smaller.input_set,
        refused: larger.input_set,
        chi2: agreement.chi2,
        added: larger
            .observations
            .tags()
            .iter()
            .filter(|tag| theirs.binary_search(tag).is_err())
            .copied()
            .collect(),
    })
}

#[cfg(test)]
mod tests;
