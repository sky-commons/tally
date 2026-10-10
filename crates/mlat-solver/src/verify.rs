//! Checking a claimed solution against the raw observations and the clock model it cites (crate
//! docs, § Verifying): regroup, rescreen, residuals and chi-square, optimality, covariance, and
//! the outlier rule's fixed point. No search, no iteration: one evaluation of the residuals and
//! one Gauss-Newton step's worth of algebra. And checking the clock model itself against the raw
//! it cites (§ Verifying a model).

use std::collections::BTreeSet;

use crate::clock::{PS, Reach, SPEC_VERSION};
use crate::geo::{self, C};
use crate::group;
use crate::obs::{ObservationId, Reception};
use crate::solve::{OUTLIER_Z, Problem, Solution, published_chi2_limit, rounding_norm};
use crate::sync::Calibrated;

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
    /// The cited observations are not sorted and distinct.
    Unsorted,
    /// A cited observation is not among the candidates.
    Unknown(ObservationId),
    /// The cited observations are not exactly within one transmission of the regrouped
    /// candidates.
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
    /// A cited observation is an outlier by the rule.
    Outlier { id: ObservationId, z: f64 },
    /// An omitted observation is not an outlier by the rule.
    Omitted { id: ObservationId, z: f64 },
    /// The timing covariance or the information matrix is not positive definite.
    Singular,
    /// The solution's addressed citation is not the verifier's raw's, so it cannot recompute the
    /// tile.
    Addressed,
    /// The model it cites is not of the tile the assignment rule gives the aircraft.
    Tile,
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
/// convicts nobody for the version it runs. The wire's tolerance (`tally_wire::Tolerance::for_spec`)
/// knows every version, so fault proofs of any are still judged.
pub fn judges(spec: u16) -> bool {
    spec == SPEC_VERSION
}

/// Verifies `claim` against `candidates` (every reception the verifier holds of the claimed
/// message, cited or not) under `model`.
pub fn verify(calibrated: &Calibrated, candidates: &[Reception], claim: &Solution) -> Verdict {
    verify_reach(calibrated, candidates, claim, Reach::Window)
}

/// As `verify`, the receptions mapped at `reach`: a provisional solution is verified with the
/// model carried (`Reach::Carried`), against the receptions it was solved from, which are all the
/// engine held when it solved (crate docs, § Provisional solutions).
pub fn verify_reach(
    calibrated: &Calibrated,
    candidates: &[Reception],
    claim: &Solution,
    reach: Reach,
) -> Verdict {
    let model = &calibrated.model;
    let mut failures = Vec::new();
    if !judges(claim.spec) {
        failures.push(Failure::Spec(claim.spec));
        return Verdict { failures };
    }
    if claim.observations.windows(2).any(|pair| pair[0] >= pair[1]) {
        failures.push(Failure::Unsorted);
        return Verdict { failures };
    }
    let known: BTreeSet<ObservationId> = candidates.iter().map(Reception::id).collect();
    for id in &claim.observations {
        if !known.contains(id) {
            failures.push(Failure::Unknown(*id));
        }
    }
    if !failures.is_empty() {
        return Verdict { failures };
    }
    let grouping = group::group_reach(model, candidates, reach);
    let cited: BTreeSet<ObservationId> = claim.observations.iter().copied().collect();
    let Some(transmission) = grouping.transmissions.iter().find(|transmission| {
        transmission
            .receptions
            .iter()
            .any(|timed| cited.contains(&timed.id))
    }) else {
        failures.push(Failure::NotOneTransmission);
        return Verdict { failures };
    };
    verify_in(calibrated, transmission, &cited, claim, failures)
}

/// As `verify_reach`, for the publisher that grouped the candidates itself (with `group_reach`,
/// the same function over the same receptions) and solved `transmission`, the group its claim
/// cites: the regrouping, which would find this very transmission, is not done twice. Every other
/// check is the verifier's own.
pub fn verify_grouped(
    calibrated: &Calibrated,
    transmission: &group::Transmission,
    claim: &Solution,
) -> Verdict {
    let mut failures = Vec::new();
    if !judges(claim.spec) {
        failures.push(Failure::Spec(claim.spec));
        return Verdict { failures };
    }
    if claim.observations.windows(2).any(|pair| pair[0] >= pair[1]) {
        failures.push(Failure::Unsorted);
        return Verdict { failures };
    }
    let cited: BTreeSet<ObservationId> = claim.observations.iter().copied().collect();
    for id in &cited {
        if !transmission.receptions.iter().any(|timed| timed.id == *id) {
            failures.push(Failure::Unknown(*id));
        }
    }
    if !failures.is_empty() {
        return Verdict { failures };
    }
    verify_in(calibrated, transmission, &cited, claim, failures)
}

/// The checks of a claim within the one transmission it cites.
fn verify_in(
    calibrated: &Calibrated,
    transmission: &group::Transmission,
    cited: &BTreeSet<ObservationId>,
    claim: &Solution,
    mut failures: Vec<Failure>,
) -> Verdict {
    let in_group = transmission
        .receptions
        .iter()
        .filter(|timed| cited.contains(&timed.id))
        .count();
    if in_group != cited.len() {
        failures.push(Failure::NotOneTransmission);
        return Verdict { failures };
    }
    let problem = Problem::new(calibrated, transmission);
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

/// How far a model's estimate may sit from its optimum: the squared Mahalanobis length of the
/// Gauss-Newton step from it.
pub const MODEL_OPTIMALITY_TOLERANCE: f64 = 1e-4;
/// The band either side of `JUMP_THRESHOLD` within which the verifier accepts either decision.
pub const JUMP_BAND: f64 = 0.05;
/// How far, relative, a published noise may sit below the rule's estimate at the published
/// estimate (the rule was last applied a few steps before the end); above it is conservative and
/// never refused.
pub const NOISE_BAND: f64 = 0.25;

/// One reason a model fails.
#[derive(Clone, Debug, PartialEq)]
pub enum ModelFailure {
    /// The model names another specification version.
    Spec(u16),
    /// Its tile, window or members are not what the raw gives.
    Scope,
    /// Its input citation is not the raw's.
    Citation,
    /// Its clocks, gauge, knots, sites or origin are not what the rules derive.
    Shape(&'static str),
    /// Its normal equations cannot be formed or factored at its estimate.
    Singular,
    /// Its estimate is not the optimum of its own inputs under its own weights.
    NotOptimal { distance: f64 },
    /// A clock's noise is further below the rule's at the estimate than the band allows.
    Noise {
        piece: usize,
        published: i64,
        estimated: i64,
    },
    /// A clock's residuals step by more than the jump threshold where no jump is declared.
    Jump { score: f64 },
}

/// The model verifier's answer: pass when there is no failure.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ModelVerdict {
    pub failures: Vec<ModelFailure>,
}

impl ModelVerdict {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// False when the model names a specification version this verifier does not implement
    /// (`judges`): neither passed nor failed, and nothing else was checked.
    pub fn judged(&self) -> bool {
        !matches!(self.failures.as_slice(), [ModelFailure::Spec(_)])
    }
}

/// Verifies a published model against `inputs`, rebuilt by the verifier from its own raw for the
/// model's tile and window (crate docs, § Verifying a model). Returns the calibration too, which
/// solving and verifying solutions under the model need, when the model passes.
pub fn verify_model(
    model: &crate::ClockModel,
    inputs: &crate::scope::Inputs,
) -> (ModelVerdict, Option<Calibrated>) {
    let mut failures = Vec::new();
    if !judges(model.spec) {
        failures.push(ModelFailure::Spec(model.spec));
        return (ModelVerdict { failures }, None);
    }
    if model.tile != inputs.tile || model.window != inputs.window || model.scope != inputs.scope {
        failures.push(ModelFailure::Scope);
    }
    if model.input != inputs.citation {
        failures.push(ModelFailure::Citation);
    }
    if !failures.is_empty() {
        return (ModelVerdict { failures }, None);
    }
    if let Some(what) = crate::sync::check_shape(model, inputs) {
        failures.push(ModelFailure::Shape(what));
        return (ModelVerdict { failures }, None);
    }
    let Ok((calibrated, assessment)) = crate::sync::calibrate(model, inputs) else {
        failures.push(ModelFailure::Singular);
        return (ModelVerdict { failures }, None);
    };
    // Not within the tolerance, NaN included.
    if assessment.distance.is_nan() || assessment.distance > MODEL_OPTIMALITY_TOLERANCE {
        failures.push(ModelFailure::NotOptimal {
            distance: assessment.distance,
        });
    }
    for (index, piece) in model.pieces.iter().enumerate() {
        let estimated = assessment
            .noise_ps
            .get(&piece.key)
            .copied()
            .unwrap_or_else(|| (piece.timebase.default_noise_s() * 1e12).round() as i64);
        // Understated noise makes every solution under the model overconfident; overstated noise
        // only makes them conservative. So only the first is refused.
        if (piece.noise_ps as f64) < (1.0 - NOISE_BAND) * estimated as f64 {
            failures.push(ModelFailure::Noise {
                piece: index,
                published: piece.noise_ps,
                estimated,
            });
        }
    }
    if let Some(score) = assessment
        .jump
        .filter(|score| *score > crate::sync::JUMP_THRESHOLD + JUMP_BAND)
    {
        failures.push(ModelFailure::Jump { score });
    }
    let passed = failures.is_empty();
    (ModelVerdict { failures }, passed.then_some(calibrated))
}

/// Checks that a solution of `address` under `model` cites the tile the assignment rule gives
/// (crate docs, § Assignment), recomputed from the verifier's own raw (`window`): an engine
/// cannot solve an aircraft under a tile of its choosing. The solution's addressed citation must
/// be the raw's, or the verifier does not hold what chose the tile.
pub fn verify_assignment(
    window: &crate::scope::WindowIndex<'_>,
    address: u32,
    model: &crate::ClockModel,
    addressed: &tally_wire::AddressedCitation,
) -> Result<(), Failure> {
    let citation = window.addressed_citation(address);
    if citation.hash != addressed.hash || citation.count != addressed.count {
        return Err(Failure::Addressed);
    }
    let mut members = std::collections::BTreeMap::new();
    match window.assign(address, &mut members) {
        Some(assignment) if assignment.tile == model.tile && model.window == window.window => {
            Ok(())
        }
        _ => Err(Failure::Tile),
    }
}
