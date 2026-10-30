//! Checking a pair model against the raw it cites, rebuilt from what has arrived (crate docs,
//! § The pairwise path, verifying a model), and a fix against the verified model it cites and the
//! receptions it considered (§ The pairwise path, verifying a fix): its cited models, regroup,
//! normalisation, rescreen, residuals and chi-square, optimality, covariance, and the outlier
//! rule's fixed point over what it considered. No search, no iteration: one evaluation of the
//! residuals and one Gauss-Newton step's worth of algebra.

use std::collections::BTreeSet;

use crate::arrived::{Arrived, BatchId};
use crate::clock::{PS, SPEC_VERSION};
use crate::geo::{self, C};
use crate::obs::{ObservationId, Reception};
use crate::scope::{Inputs, Sites};
use crate::solve::{OUTLIER_Z, Problem, Solution, published_chi2_limit, rounding_norm};

/// How far a claim may sit from the optimum: the squared Mahalanobis length of the Gauss-Newton
/// step from it (a tenth of a standard deviation in every direction would be 0.01).
pub const OPTIMALITY_TOLERANCE: f64 = 1e-4;
/// The relative Frobenius difference a claimed covariance may have from the recomputed one.
pub const COVARIANCE_TOLERANCE: f64 = 1e-3;
/// The band either side of `OUTLIER_Z` within which the verifier accepts either decision, so
/// two correct implementations whose floating point differs in the last bits never disagree.
pub const OUTLIER_BAND: f64 = 0.05;

/// One reason a claim fails.
#[derive(Clone, Debug, PartialEq)]
pub enum Failure {
    /// The claim names another specification version.
    Spec(u16),
    /// Its position or transmit time cannot be read back (no altitude, out of range).
    Unreadable,
    /// The considered or used observations are not sorted and distinct.
    Unsorted,
    /// A considered observation is not among the receptions the verifier holds.
    Unknown(ObservationId),
    /// The considered observations the model maps are not exactly one transmission of their
    /// regrouping.
    NotOneTransmission,
    /// Fewer than the minimum observations are cited.
    TooFew(usize),
    /// A cited observation fails the integer feasibility screen.
    Infeasible(ObservationId),
    /// The claimed geodetic position is not the claimed ECEF position.
    Position,
    /// The residuals fail the chi-square test.
    Chi2 { chi2: f64, limit: f64 },
    /// The claimed degrees of freedom are not the cited count's.
    Dof { claimed: u32, actual: u32 },
    /// The claim is not the least-squares optimum of its own observations.
    NotOptimal { distance: f64 },
    /// The claimed covariance is not the one the observations and clock model imply.
    Covariance { relative: f64 },
    /// A used observation is an outlier by the rule.
    Outlier { id: ObservationId, z: f64 },
    /// A considered observation it did not use is not an outlier by the rule. Judged only inside
    /// the considered set: a reception that had not arrived when the fix was solved is never one.
    Omitted { id: ObservationId, z: f64 },
    /// The timing covariance or the information matrix is not positive definite.
    Singular,
    /// The models it cites are not one of each area its used hearers are in, and no other (crate
    /// docs, § Areas, the models a fix cites): one is missing, or one is extra.
    Area,
    /// The models it was verified under are not the ones it lists (`tally_wire::Fix::models`).
    Models,
    /// A used observation is not among the fix's considered set.
    NotConsidered { id: ObservationId },
    /// A used observation is not of a receiver the cap chooses of its considered set
    /// (`pair::Models::capped`).
    Uncapped { id: ObservationId },
    /// The pair models it cites cannot put its transmission on one timeline (`pair::Models::
    /// normalise`), or leave out a reception it used.
    Unnormalised(&'static str),
}

/// The verifier's answer: pass when there is no failure.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Verdict {
    pub failures: Vec<Failure>,
}

impl Verdict {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// False when the claim names a specification version this verifier does not implement
    /// (`judges`): neither passed nor failed, and nothing else was checked.
    pub fn judged(&self) -> bool {
        !matches!(self.failures.as_slice(), [Failure::Spec(_)])
    }
}

/// Whether this verifier can judge a model or claim of specification version `spec`. Each version
/// is a derivation (version 5 dates a free-running gauge's origin by every cited reception of its
/// clock and rejects a sync message any receiver heard twice; version 4 did neither), so the same
/// raw gives each version a different model, and this build implements its own alone: a model or
/// claim of another version is unjudged, never failed, so a fleet part-way through an upgrade
/// convicts nobody for the version it runs. The wire's tolerance
/// (`tally_wire::Tolerance::for_spec`) knows every version, so fault proofs of any are still
/// judged.
pub fn judges(spec: u16) -> bool {
    spec == SPEC_VERSION
}

/// The checks of a claim against the problem its transmission is (its timing covariance the
/// pairwise adjustment's, `pair::Models::normalise`): `cited` its used receptions.
fn check_problem(
    problem: &Problem,
    cited: &BTreeSet<ObservationId>,
    claim: &Solution,
    mut failures: Vec<Failure>,
) -> Verdict {
    if problem.clock_m2.is_none() {
        failures.push(Failure::Singular);
        return Verdict { failures };
    }
    if cited.len() < problem.minimum() {
        failures.push(Failure::TooFew(cited.len()));
        return Verdict { failures };
    }
    let screened = problem.screen();
    let subset: Vec<usize> = (0..problem.items.len())
        .filter(|index| cited.contains(&problem.items[*index].id))
        .collect();
    for index in &subset {
        if !screened.contains(index) {
            failures.push(Failure::Infeasible(problem.items[*index].id));
        }
    }
    let position_ecef = geo::to_ecef(claim.position);
    if crate::linalg::norm(crate::linalg::sub(position_ecef, claim.ecef)) > 0.01 {
        failures.push(Failure::Position);
    }
    let transmit = (i128::from(claim.transmit_ps) - problem.reference_ps) as f64 / PS as f64 * C;
    let params = [claim.ecef[0], claim.ecef[1], claim.ecef[2], transmit];
    let Some(whitener) = problem.whitener(&subset) else {
        failures.push(Failure::Singular);
        return Verdict { failures };
    };
    let (residuals, jacobian) = problem.whitened(&subset, &whitener, &params);
    let mut chi2 = 0.0;
    let mut information = crate::linalg::Matrix::zeros(4);
    let mut gradient = [0.0; 4];
    for (r, row) in residuals.iter().zip(&jacobian) {
        chi2 += r * r;
        for i in 0..4 {
            gradient[i] += row[i] * r;
            for j in 0..4 {
                information.add(i, j, row[i] * row[j]);
            }
        }
    }
    let dof = (subset.len() + usize::from(problem.altitude.is_some())).saturating_sub(4);
    let dof = u32::try_from(dof).unwrap_or(u32::MAX);
    if dof != claim.dof {
        failures.push(Failure::Dof {
            claimed: claim.dof,
            actual: dof,
        });
    }
    // The solver's own acceptance limit, at the claim as published (`published_chi2_limit`).
    let limit = published_chi2_limit(dof, rounding_norm(&jacobian));
    if chi2 > limit {
        failures.push(Failure::Chi2 { chi2, limit });
    }
    let Some(factor) = information.cholesky() else {
        failures.push(Failure::Singular);
        return Verdict { failures };
    };
    let step = factor.solve(&gradient.map(|value| -value));
    let moved = information.mul_vec(&step);
    let distance: f64 = step.iter().zip(&moved).map(|(a, b)| a * b).sum();
    if distance > OPTIMALITY_TOLERANCE {
        failures.push(Failure::NotOptimal { distance });
    }
    let inverse = crate::solve::published(&factor.inverse());
    let mut difference = 0.0;
    let mut size = 0.0;
    for (i, row) in claim.covariance.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            let want = inverse[i][j];
            difference += (value - want) * (value - want);
            size += want * want;
        }
    }
    let relative = (difference / size.max(f64::MIN_POSITIVE)).sqrt();
    if relative.is_nan() || relative > COVARIANCE_TOLERANCE {
        failures.push(Failure::Covariance { relative });
    }
    for index in &screened {
        let z = problem.residual(*index, &params).abs() / problem.sigma(*index);
        let id = problem.items[*index].id;
        if cited.contains(&id) {
            if z > OUTLIER_Z + OUTLIER_BAND {
                failures.push(Failure::Outlier { id, z });
            }
        } else if z < OUTLIER_Z - OUTLIER_BAND {
            failures.push(Failure::Omitted { id, z });
        }
    }
    Verdict { failures }
}

/// How far, relative, a published noise may sit below the rule's estimate at the published
/// estimate (the rule was last applied a few steps before the end); above it is conservative and
/// never refused.
pub const NOISE_BAND: f64 = 0.25;

/// One reason a pair model fails (crate docs, § The pairwise path, verifying a model).
#[derive(Clone, Debug, PartialEq)]
pub enum PairModelFailure {
    /// It names another specification version.
    Spec(u16),
    /// Its scope is not its area's members by the verifier's own site records.
    Scope,
    /// Its frontiers are not one contiguous run a member's boot, or name no member.
    Frontier,
    /// The verifier lacks batches at or below a cited frontier: neither passed nor failed.
    Unjudged { missing: Vec<BatchId> },
    /// Its area, trailing window, scope, frontier or input citation is not the window's.
    Inputs,
    /// Its clocks or pairs are not strictly ascending, or a pair names no clock of it.
    Unordered,
    /// A clock it publishes is not the window's, or its lowest count is not.
    Clock(crate::clock::ClockKey),
    /// A published pair is not its points' fit under the published noise and rates.
    Pair {
        a: crate::clock::ClockKey,
        b: crate::clock::ClockKey,
        why: &'static str,
    },
    /// The pooled inflation is not its pairs'.
    Kappa,
    /// A clock's noise is more than `NOISE_BAND` below the rule's estimate from the published
    /// pairs.
    Noise(crate::clock::ClockKey),
    /// The rates are not an optimum of their system within `pair::RATE_OPTIMALITY_TOLERANCE`.
    Rates { distance: f64 },
    /// A clock's rate variances are not its system's.
    RateVariance(crate::clock::ClockKey),
    /// A pair the rule finds valid is not published, or one it refuses is.
    Dropped {
        a: crate::clock::ClockKey,
        b: crate::clock::ClockKey,
    },
    /// A clock's kept segment does not start where the jump rule puts it.
    Jump(crate::clock::ClockKey),
}

/// The pair model verifier's answer: pass when there is no failure.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PairModelVerdict {
    pub failures: Vec<PairModelFailure>,
}

impl PairModelVerdict {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// False when the model names a specification version this verifier does not implement, or
    /// cites batches it lacks.
    pub fn judged(&self) -> bool {
        !matches!(
            self.failures.as_slice(),
            [PairModelFailure::Spec(_) | PairModelFailure::Unjudged { .. }]
        )
    }
}

/// Verifies a published pair model against the raw it cites, rebuilt from what has arrived at the
/// verifier (`Arrived::rebuild`): its scope must be its area's members by the verifier's own
/// `sites` (`Sites::members`), and its inputs what the batches at or below its frontiers hold.
/// `PairModelFailure::Unjudged` when a cited batch has not arrived, never a failure. `cache` is
/// the area's (`pair::PairCache`, one per area the verifier checks models of).
pub fn verify_pair_model_held(
    sites: &Sites,
    model: &crate::pair::PairModel,
    arrived: &Arrived,
    cache: &mut crate::pair::PairCache,
) -> PairModelVerdict {
    let refused = |failure| PairModelVerdict {
        failures: vec![failure],
    };
    if !judges(model.spec) {
        return refused(PairModelFailure::Spec(model.spec));
    }
    if *sites.members(model.area) != *model.scope {
        return refused(PairModelFailure::Scope);
    }
    match arrived.rebuild(model) {
        Ok(inputs) => verify_pair_model(&inputs, model, cache),
        Err(failure) => refused(failure),
    }
}

/// Verifies a pair model against the window it cites (`inputs`, rebuilt from what has arrived;
/// crate docs, § The pairwise path, verifying a model): once a refit by any holder of the window,
/// whatever fixes cite the model.
pub fn verify_pair_model(
    inputs: &Inputs,
    model: &crate::pair::PairModel,
    cache: &mut crate::pair::PairCache,
) -> PairModelVerdict {
    if !judges(model.spec) {
        return PairModelVerdict {
            failures: vec![PairModelFailure::Spec(model.spec)],
        };
    }
    PairModelVerdict {
        failures: crate::pair::check_model(inputs, model, cache),
    }
}

/// Verifies a fix (what it states, of specification version `spec`) under `models`, the verified
/// pair models it lists, each looked up by its id, against `held`, the receptions of its message
/// the verifier holds (crate docs, § The pairwise path, verifying a fix): the models are the ones
/// it lists (`Failure::Models`) and exactly one of each area its used hearers are in
/// (`Failure::Area`), its considered set regrouped by them is one transmission, capped to the
/// receivers it is solved from (`pair::Models::capped`) and normalised by their pairs, and the
/// claim is the solution of that problem as `check_problem` checks one: what it used among the
/// capped receivers' receptions, and judged for omission over those alone. Nothing but the models
/// and the fix's own receptions is read.
pub fn verify_pair_fix(
    models: &crate::pair::Models<'_>,
    stated: &crate::publish::Stated<'_>,
    spec: u16,
    held: &[Reception],
) -> Verdict {
    let (ids, mut failures) = match read(models, stated, spec) {
        Ok(read) => read,
        Err(verdict) => return verdict,
    };
    let mut receptions: Vec<Reception> = held
        .iter()
        .filter(|reception| ids.considered.binary_search(&reception.id()).is_ok())
        .cloned()
        .collect();
    receptions.sort_by_cached_key(|reception| (reception.id(), reception.wall_ms));
    receptions.dedup_by_key(|reception| reception.id());
    for id in &ids.considered {
        if receptions.binary_search_by_key(id, Reception::id).is_err() {
            failures.push(Failure::Unknown(*id));
        }
    }
    if !failures.is_empty() {
        return Verdict { failures };
    }
    let groups = models.transmissions(&receptions);
    if !matches!(groups.as_slice(), [one] if one.len() == receptions.len()) {
        failures.push(Failure::NotOneTransmission);
        return Verdict { failures };
    }
    let capped = models.capped(&groups[0]);
    for id in &ids.used {
        if !capped.iter().any(|reception| reception.id() == *id) {
            failures.push(Failure::Uncapped { id: *id });
        }
    }
    if !failures.is_empty() {
        return Verdict { failures };
    }
    match models.normalise(&capped) {
        Ok(normalised) => judge(stated, spec, &ids, &normalised, failures),
        Err(why) => {
            failures.push(Failure::Unnormalised(why));
            Verdict { failures }
        }
    }
}

/// The verifier over the normalisation a fix was just solved on (`publish::solve_transmission`):
/// `verify_pair_fix` but for the regrouping, capping and normalising of its considered set, which
/// rebuild `normalised` exactly (the grouping returns a transmission whole, and the cap and the
/// normalisation are functions of their receptions as a set, in any order: § Verifying a fix).
pub(crate) fn verify_solved(
    models: &crate::pair::Models<'_>,
    stated: &crate::publish::Stated<'_>,
    spec: u16,
    normalised: &crate::pair::Normalised,
) -> Verdict {
    match read(models, stated, spec) {
        Ok((ids, failures)) => judge(stated, spec, &ids, normalised, failures),
        Err(verdict) => verdict,
    }
}

/// What a fix considered and used, read on a timeline at its own transmit time (the claim proper
/// once the normalisation gives the timeline's zero), with what its lists and its models' areas
/// fail; `Err` with the verdict when nothing more can be judged.
fn read(
    models: &crate::pair::Models<'_>,
    stated: &crate::publish::Stated<'_>,
    spec: u16,
) -> Result<(Solution, Vec<Failure>), Verdict> {
    if !judges(spec) {
        return Err(Verdict {
            failures: vec![Failure::Spec(spec)],
        });
    }
    let at_ns = u64::try_from(stated.claimed.transmitted.unix_ps() / 1000).unwrap_or(0);
    let Ok(ids) = crate::publish::claim_at(at_ns, stated, spec) else {
        return Err(Verdict {
            failures: vec![Failure::Unreadable],
        });
    };
    let mut failures = Vec::new();
    let ascending = |ids: &[ObservationId]| ids.windows(2).all(|pair| pair[0] < pair[1]);
    if !ascending(&ids.considered) || !ascending(&ids.used) {
        failures.push(Failure::Unsorted);
        return Err(Verdict { failures });
    }
    for id in &ids.used {
        if ids.considered.binary_search(id).is_err() {
            failures.push(Failure::NotConsidered { id: *id });
        }
    }
    if *stated.models != *models.ids() {
        failures.push(Failure::Models);
    }
    if models.areas_of(ids.used.iter().map(|id| id.receiver)) != Some(models.areas()) {
        failures.push(Failure::Area);
    }
    Ok((ids, failures))
}

/// The claim against the problem its transmission normalised to: every used reception one of
/// its items, then `check_problem`.
fn judge(
    stated: &crate::publish::Stated<'_>,
    spec: u16,
    ids: &Solution,
    normalised: &crate::pair::Normalised,
    mut failures: Vec<Failure>,
) -> Verdict {
    let cited: BTreeSet<ObservationId> = ids.used.iter().copied().collect();
    let items: BTreeSet<ObservationId> = normalised
        .problem
        .items
        .iter()
        .map(|item| item.id)
        .collect();
    if !cited.is_subset(&items) {
        failures.push(Failure::Unnormalised(
            "a used reception the pairs leave out",
        ));
        return Verdict { failures };
    }
    let Ok(claim) = crate::publish::claim_at(normalised.origin_unix_ns, stated, spec) else {
        failures.push(Failure::Unreadable);
        return Verdict { failures };
    };
    check_problem(&normalised.problem, &cited, &claim, failures)
}
