//! Receiver standing (RFC-0174 §2.12), the rule: from public signed data alone (receivers' signed
//! batches, engines' signed clock models and solutions), how far each receiver's receptions are to
//! be believed, and when a bigger answer may replace a smaller one. Every party that reads the same
//! records computes the same standing, so it is never on the wire. Relays (`tally-relay`'s
//! `standing`) and clients (`tally-merge`) each keep a [`Book`] of it; both decide which of one
//! transmission's solutions stands by [`decide`].
//!
//! # The attack it answers
//!
//! A receiver key is free. Anyone can make ten, and from ADS-B positions, or from the network's own
//! provisional fixes, fabricate receptions that look right, then publish them beside an honest
//! fix's so that the solution over the larger set wins the merge by being a superset, and moves a
//! cockpit target. Three rules close it:
//!
//! 1. **A bigger answer wins only if it agrees** ([`agreement`]): a solution over a strict
//!    superset of another's observations replaces it only when its position is inside the
//!    smaller's uncertainty (the squared Mahalanobis length of the difference under the smaller's
//!    covariance at most [`AGREE_CHI2`], three degrees of freedom at 0.999, or [`AGREE_CHI2_2D`]
//!    when either states no height). One that does not is contested ([`decide`]): a fault, never
//!    the answer, kept as evidence. The smaller stands whatever order the two came in.
//! 2. **Sets are weighed by their receivers' standing, not their count** ([`Candidate::standing`]):
//!    of solutions neither of which refuses the other, the one whose receptions' receivers carry
//!    the most standing ranks first, then the tie rule (observations plus the model's inputs),
//!    then the lowest input set hash. Ten new keys add nothing to a set's standing.
//! 3. **A position whose receivers lack standing is unconfirmed** ([`Book::confirmed`]): fewer
//!    than the solver's minimum (three with an altitude, four without) of its receivers have
//!    [`HAS_STANDING`].
//!
//! # How a receiver earns standing
//!
//! A transmission's solutions are gathered as they arrive ([`Book::add`]): every solution of one
//! aircraft and message that shares a reception with another is of the same transmission. A solution
//! is consistent when every reception it cites, mapped through the model it cites, puts its
//! transmit time within [`AGREE_Z`] of where the solution says ([`reception_z`]); one that is not
//! is evidence against what it cites and nothing more. [`SETTLE_MS`] after the transmission (its
//! transmit time, signed in every solution of it, by the keeper's clock), once every final fix of
//! it has surely arrived, it is settled ([`Book::settle`]) against its final fix, the first
//! consistent one of its final solutions by [`decide`], each ranked by its receivers' standing as
//! the book holds it then. When a solution arrived decides nothing: the deadline is the record's,
//! and standing is read when the transmission is decided, never frozen when a solution came. Every reception any of its
//! solutions cites, when it is in its receiver's own signed raw (an attacker can cite receptions a
//! receiver never made, and that receiver must not pay for them):
//!
//! - **agrees** when its whitened residual under the final fix is at most `AGREE_Z`. It earns the
//!   receiver one count only when the reception *arrived before any solution of its transmission
//!   existed*: its batch's signed wall clock is before the earliest signed issue time of any
//!   consistent solution of the transmission, final or provisional, and that solution cites it. A
//!   receiver that fabricates receptions from a published fix (provisional or final) is in no
//!   earliest solution, so it earns nothing however well it agrees. And only of a transmission
//!   whose position the network learns only by solving ([`eligible`]): not an ADS-B message (DF17,
//!   18 or 19), and not of the calibration sample (`held::sampled` in the transmission's bin or the
//!   next, which is how the network solves ADS-B aircraft), so nothing an ADS-B position could
//!   have told a fabricator earns.
//! - **disagrees** when its residual is above `AGREE_Z`, or, not mapped by the final fix's model,
//!   when only refused (contested) solutions cite it. It costs the receiver [`DISAGREE_COST`]
//!   counts. Padding a fix with bad receptions loses the padders' receivers their standing.
//!
//! A reception is settled once ([`SETTLED_PERIODS`] of memory). Counts are kept per receiver by
//! [`PERIOD_MS`] of transmit time ([`ReceiverStanding`]); a period earns at most
//! [`EARN_PER_PERIOD`]; standing at a time is the sum over its periods, each halved for every
//! [`HALF_LIFE_PERIODS`] it is older, capped at [`FULL`] and floored at `-FULL`. Its weight is its
//! share of `FULL`, in thousandths, never below 0. Every quantity is an integer, every iteration in
//! key order, so two keepers holding the same records hold the same standing.
//!
//! # What it does not stop
//!
//! Without a trusted clock, a party that both runs a fast solver over public raw and controls
//! receivers can sign their batches early with receptions computed from honest ones and publish
//! the earliest solution itself, and so farm standing. It is bounded: one key's weight is at most
//! one honest receiver's, earning is capped per period and decays, and standing never lets a
//! disagreeing superset win. A keeper that does not hold raw (a client without `raw`) can check
//! agreement but cannot see who heard what when, so it earns nobody standing and labels every
//! position unconfirmed.
//!
//! The solver's gating by standing ([`ReceiverStanding::gated`]): a receiver whose standing is
//! below `-GATED_BELOW` is one the specification's outlier rule should leave out.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tally_wire::batch::Hash;
use tally_wire::{EnuCovariance, ObservationSet, PublicKey, Relation, TransmitTime};

use crate::clock::{ClockModel, Reach};
use crate::geo::{self, C, Geodetic};
use crate::held::{HoldsBins, sampled};
use crate::linalg::{self, Matrix, Vec3};
use crate::obs::{ObservationId, message_hash};
use crate::scope::bin_of;
use crate::solve::{MIN_RECEIVERS, MIN_RECEIVERS_WITH_ALTITUDE, OUTLIER_Z};
use crate::{modes, publish};

/// The chi-square point a superset's difference from the smaller fix must stay under to agree:
/// three degrees of freedom at 0.999.
pub const AGREE_CHI2: f64 = 16.266;
/// The same with two degrees of freedom, when either fix states no height.
pub const AGREE_CHI2_2D: f64 = 13.815_51;
/// How far a reception's whitened residual under a fix may be and agree: the solver's outlier
/// threshold.
pub const AGREE_Z: f64 = OUTLIER_Z;
/// What a reception's residual is whitened by beyond its receiver's noise and the fix's own
/// uncertainty: the clock model's own error for one member, which the model does not publish.
/// The simulator's honest fixes put every reception well inside `AGREE_Z` with it.
pub const CLOCK_SIGMA_M: f64 = 30.0;
/// How fast a provisional fix's clock error grows past the model's last knot, metres a second of
/// carry: the curvature prior's walk (crate docs, § Provisional solutions), generously.
pub const CARRY_SIGMA_M_PER_S: f64 = 15.0;
/// Standing is counted in periods of transmit time this long.
pub const PERIOD_MS: u64 = 600_000;
/// The most agreeing receptions one period earns a receiver: about one a target a five seconds.
pub const EARN_PER_PERIOD: u32 = 120;
/// What one disagreeing reception costs, in agreeing ones.
pub const DISAGREE_COST: i64 = 10;
/// Full standing: twelve periods (two hours) of agreement at the most a period earns.
pub const FULL: i64 = 1_440;
/// A receiver has standing at a quarter of full: half an hour of agreement at the most.
pub const HAS_STANDING: i64 = FULL / 4;
/// A receiver below minus this is one the solver gates: ten disagreements not earned back.
pub const GATED_BELOW: i64 = 10 * DISAGREE_COST;
/// Every this many periods (one day) a period's counts are worth half.
pub const HALF_LIFE_PERIODS: u64 = 144;
/// Periods older than this (eight half-lives) are worth under a 256th and forgotten.
pub const HORIZON_PERIODS: u64 = 8 * HALF_LIFE_PERIODS;
/// How long after a transmission (its signed transmit time, by the keeper's clock) it is settled:
/// once every final fix of it has surely arrived, `tally_wire::products::FINAL_FIX_ARRIVED_MS`
/// (90 s: the latest a final fix leaves its engine, about 82 s, plus relay hops and clock skew;
/// derived there). That is inside the 120 s a keeper holds raw behind its clock (24 bins of 5 s:
/// a window's 11 before and 1 after, a stride of 8 and 4 spare), so the raw a settlement asks
/// [`heard_in`] for is still held.
pub const SETTLE_MS: u64 = tally_wire::products::FINAL_FIX_ARRIVED_MS;
/// Periods of settled receptions remembered, so a reception is settled once.
pub const SETTLED_PERIODS: u64 = 3;
/// Weights are thousandths.
pub const PERMILLE: u64 = 1_000;
/// A transmission's sample bins: its transmit time's and the one its receptions' batches may fall
/// in, a batch being sealed up to a second after.
const SAMPLE_SLACK_MS: u64 = 2_000;

/// One period's counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub agreed: u32,
    pub disagreed: u32,
}

/// One receiver's standing: its counts by period of transmit time. A new key's is none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiverStanding {
    pub periods: BTreeMap<u64, Tally>,
}

impl ReceiverStanding {
    /// A new key's: none.
    pub const NEW: Self = Self {
        periods: BTreeMap::new(),
    };

    /// One settled reception of `period`: it agreed (and earned) or it disagreed.
    pub fn observe(&mut self, period: u64, agreed: bool) {
        let tally = self.periods.entry(period).or_default();
        if agreed {
            tally.agreed = tally.agreed.saturating_add(1);
        } else {
            tally.disagreed = tally.disagreed.saturating_add(1);
        }
        let newest = self.periods.keys().next_back().copied().unwrap_or(period);
        let horizon = newest.saturating_sub(HORIZON_PERIODS);
        self.periods = self.periods.split_off(&horizon);
    }

    /// Standing at `period`: every period up to it, earning capped, each halved for every
    /// half-life it is older; capped at `FULL`, floored at `-FULL`.
    pub fn score(&self, period: u64) -> i64 {
        let mut score: i64 = 0;
        for (at, tally) in self.periods.range(..=period) {
            let age = period - at;
            if age >= HORIZON_PERIODS {
                continue;
            }
            let shift = age / HALF_LIFE_PERIODS;
            let earned = i64::from(tally.agreed.min(EARN_PER_PERIOD));
            let cost = i64::from(tally.disagreed) * DISAGREE_COST;
            let net = earned - cost;
            // Halving towards zero, the same for gains and costs.
            let decayed = if net >= 0 {
                net >> shift
            } else {
                -((-net) >> shift)
            };
            score = score.saturating_add(decayed);
        }
        score.clamp(-FULL, FULL)
    }

    /// The weight a receiver's receptions carry at `period`, thousandths: its share of full
    /// standing, never below 0.
    pub fn weight(&self, period: u64) -> u64 {
        (self.score(period).max(0) as u64) * PERMILLE / FULL as u64
    }

    /// Whether it has standing at `period`.
    pub fn has_standing(&self, period: u64) -> bool {
        self.score(period) >= HAS_STANDING
    }

    /// Whether the solver should leave its receptions out at `period`.
    pub fn gated(&self, period: u64) -> bool {
        self.score(period) < -GATED_BELOW
    }
}

/// The period a transmit time is in.
pub fn period_of(unix_ms: u64) -> u64 {
    unix_ms / PERIOD_MS
}

/// Whether a transmission can earn standing: one the network learns the position of only by
/// solving (module docs): not ADS-B, and not of the calibration sample.
pub fn eligible(message: &[u8], transmitted: TransmitTime) -> bool {
    let Some(df) = modes::downlink_format(message) else {
        return false;
    };
    if matches!(df, 17..=19) {
        return false;
    }
    let Some(address) = modes::address(message) else {
        return false;
    };
    let ms = transmitted.unix_ms;
    !(sampled(address, bin_of(ms)) || sampled(address, bin_of(ms + SAMPLE_SLACK_MS)))
}

/// A full input set's identity: one definition, `tally_wire::products::input_set` (the merge
/// rule's, which the world product cites too).
pub use tally_wire::products::input_set;

/// What a solution claims: where, when, how sure.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Claimed {
    pub lat_e7: i32,
    pub lon_e7: i32,
    /// Millimetres above the WGS84 ellipsoid.
    pub alt_hae_mm: Option<i32>,
    pub covariance: EnuCovariance,
    pub transmitted: TransmitTime,
}

impl Claimed {
    pub fn of(wire: &tally_wire::Solution) -> Self {
        Self {
            lat_e7: wire.lat_e7,
            lon_e7: wire.lon_e7,
            alt_hae_mm: wire.alt_hae_mm,
            covariance: wire.covariance,
            transmitted: wire.transmitted,
        }
    }

    fn geodetic(&self) -> Geodetic {
        Geodetic {
            lat_deg: f64::from(self.lat_e7) * 1e-7,
            lon_deg: f64::from(self.lon_e7) * 1e-7,
            height_m: f64::from(self.alt_hae_mm.unwrap_or(0)) / 1000.0,
        }
    }

    /// ECEF metres, when it states a height.
    pub fn ecef(&self) -> Option<Vec3> {
        self.alt_hae_mm.map(|_| geo::to_ecef(self.geodetic()))
    }

    fn trace_m2(&self) -> f64 {
        let c = &self.covariance;
        (f64::from(c.xx) + f64::from(c.yy) + f64::from(c.zz)).max(0.0)
    }
}

/// How a superset's position stands to the smaller's.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Agreement {
    /// The squared Mahalanobis length of the difference under the smaller's covariance; infinite
    /// when that covariance is not positive definite (nothing can be inside it).
    pub chi2: f64,
    pub limit: f64,
}

impl Agreement {
    pub fn agrees(&self) -> bool {
        self.chi2 <= self.limit
    }
}

/// Whether `larger` is inside `smaller`'s uncertainty: the difference in east, north and up at the
/// smaller's position, under the smaller's covariance (east and north only when either states no
/// height).
pub fn agreement(smaller: &Claimed, larger: &Claimed) -> Agreement {
    let from = smaller.geodetic();
    let basis = geo::enu_basis(from.lat_deg, from.lon_deg);
    let difference = linalg::sub(geo::to_ecef(larger.geodetic()), geo::to_ecef(from));
    let enu = [
        linalg::dot(basis[0], difference),
        linalg::dot(basis[1], difference),
        linalg::dot(basis[2], difference),
    ];
    let c = &smaller.covariance;
    let terms = [
        [f64::from(c.xx), f64::from(c.xy), f64::from(c.xz)],
        [f64::from(c.xy), f64::from(c.yy), f64::from(c.yz)],
        [f64::from(c.xz), f64::from(c.yz), f64::from(c.zz)],
    ];
    let three = smaller.alt_hae_mm.is_some() && larger.alt_hae_mm.is_some();
    let n = if three { 3 } else { 2 };
    let mut matrix = Matrix::zeros(n);
    for row in 0..n {
        for column in 0..n {
            matrix.set(row, column, terms[row][column]);
        }
    }
    let limit = if three { AGREE_CHI2 } else { AGREE_CHI2_2D };
    let chi2 = match matrix.cholesky() {
        Some(factor) => {
            let solved = factor.solve(&enu[..n]);
            (0..n).map(|at| enu[at] * solved[at]).sum::<f64>()
        }
        None => f64::INFINITY,
    };
    Agreement {
        chi2: if chi2.is_finite() {
            chi2
        } else {
            f64::INFINITY
        },
        limit,
    }
}

/// A reception's whitened residual under a fix solved with `model` (mapped at `reach`): how far,
/// in standard deviations, the transmit time it implies is from the fix's. Its standard
/// deviation is its receiver's noise and site, the model's own clock error (`CLOCK_SIGMA_M`, and
/// `CARRY_SIGMA_M_PER_S` for every second carried past the model's knots) and the fix's
/// uncertainty (its covariance's trace, twice: position and transmit time). `None` when the model
/// does not map the reception or the fix states no height.
pub fn reception_z(
    model: &ClockModel,
    reach: Reach,
    reception: &tally_wire::Reception,
    fix: &Claimed,
) -> Option<f64> {
    let position = fix.ecef()?;
    let time = model.time_reach(
        &reception.receiver,
        reception.epoch,
        reception.counter,
        reach,
    )?;
    let site = geo::from_mm(model.pieces[time.piece].site_mm);
    let range = linalg::norm(linalg::sub(position, site));
    let transmitted = i128::try_from(fix.transmitted.unix_ps()).ok()?;
    let heard_ps = i128::from(model.origin_unix_ns) * 1_000 + time.ps;
    let residual = (heard_ps - transmitted) as f64 * 1e-12 * C - range;
    let carried = time.carried_ps as f64 * 1e-12 * CARRY_SIGMA_M_PER_S;
    let variance = model.noise_m2(time.piece)
        + CLOCK_SIGMA_M * CLOCK_SIGMA_M
        + carried * carried
        + 2.0 * fix.trace_m2();
    Some(residual.abs() / variance.sqrt())
}

/// Whether a solution agrees with its own receptions under its own model: every one mapped, and
/// within `AGREE_Z`. One that does not is no solution: it is never held, and never the answer.
pub fn consistent(
    model: &ClockModel,
    reach: Reach,
    observations: &ObservationSet,
    fix: &Claimed,
) -> bool {
    observations
        .receptions()
        .iter()
        .all(|reception| reception_z(model, reach, reception, fix).is_some_and(|z| z <= AGREE_Z))
}

/// Whether a wire solution is one under `model` at all, as a keeper without raw can tell: the
/// model's specification, its message naming its aircraft, every reception of a member of the
/// model's tile, and a claim under the model that reads back.
pub fn under(model: &ClockModel, wire: &tally_wire::Solution, spec: u16) -> bool {
    model.spec == spec
        && modes::address(wire.observations.message()) == Some(wire.address)
        && wire.observations.receptions().iter().all(|reception| {
            model
                .scope
                .iter()
                .any(|site| site.receiver == reception.receiver)
        })
        && publish::claim(model, wire, spec).is_ok()
}

/// One solution as the rule weighs it.
pub trait Candidate {
    fn observations(&self) -> &ObservationSet;
    fn model_inputs(&self) -> &Hash;
    fn claimed(&self) -> Claimed;
    /// The sum of its receptions' receivers' weights, thousandths.
    fn standing(&self) -> u64;
    /// The tie rule's weight: observations plus the model citation's input count.
    fn weight(&self) -> u64;
    /// Its full input set's identity.
    fn identity(&self) -> Hash;
    /// Whether it agrees with its own receptions under its own model ([`consistent`]). Only a
    /// consistent solution refuses a superset: a smaller one that lies about where its own
    /// receptions put the aircraft refuses nothing.
    fn consistent(&self) -> bool;
    /// Ranks before every other whatever its standing (a keeper's own solution of a union).
    fn preferred(&self) -> bool {
        false
    }
}

/// A superset refused: it disagreed with a smaller solution of the same transmission.
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    /// Indices into what [`decide`] was given.
    pub refused: usize,
    pub kept: usize,
    pub chi2: f64,
}

/// What [`decide`] found: who stands, best first, and who was refused.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Decision {
    /// Not refused and not dominated, best first: the first is the answer.
    pub ranked: Vec<usize>,
    /// Dominated: the same model's inputs and a strict subset of an agreeing superset's.
    pub dominated: Vec<usize>,
    pub refusals: Vec<Refusal>,
}

impl Decision {
    pub fn refused(&self, index: usize) -> bool {
        self.refusals.iter().any(|refusal| refusal.refused == index)
    }
}

/// The order [`decide`] ranks by: `preferred`, then standing, then the tie rule's weight, then the
/// lowest identity. The less ranks first.
pub fn rank<T: Candidate>(item: &T) -> (bool, Reverse<u64>, Reverse<u64>, Hash) {
    (
        !item.preferred(),
        Reverse(item.standing()),
        Reverse(item.weight()),
        item.identity(),
    )
}

/// Of one transmission's solutions, distinct by identity, which stands (module docs, rules 1 and
/// 2). A function of the set, whatever order it is given in:
///
/// - a solution over a strict superset of a consistent one's observations that does not agree
///   with it ([`agreement`]) is refused, against the lowest such by identity (a fixed answer);
/// - of the rest, one whose model inputs are another's and whose observations are a strict subset
///   of it is dominated;
/// - the rest rank by `preferred`, then standing, then the tie rule's weight, then the lowest
///   identity.
pub fn decide<T: Candidate>(items: &[T]) -> Decision {
    let mut refusals = Vec::new();
    for (at, larger) in items.iter().enumerate() {
        let mut against: Option<(Hash, usize, f64)> = None;
        for (other, smaller) in items.iter().enumerate() {
            if other == at
                || !smaller.consistent()
                || smaller.observations().relation(larger.observations()) != Relation::Subset
            {
                continue;
            }
            let agreement = agreement(&smaller.claimed(), &larger.claimed());
            if agreement.agrees() {
                continue;
            }
            let identity = smaller.identity();
            if against.is_none_or(|(held, _, _)| identity < held) {
                against = Some((identity, other, agreement.chi2));
            }
        }
        if let Some((_, kept, chi2)) = against {
            refusals.push(Refusal {
                refused: at,
                kept,
                chi2,
            });
        }
    }
    let refused = |index: usize| refusals.iter().any(|refusal| refusal.refused == index);
    let standing: Vec<usize> = (0..items.len()).filter(|at| !refused(*at)).collect();
    let mut dominated = Vec::new();
    let mut ranked = Vec::new();
    for &at in &standing {
        let item = &items[at];
        let is_dominated = standing.iter().any(|&other| {
            other != at
                && items[other].model_inputs() == item.model_inputs()
                && item.observations().relation(items[other].observations()) == Relation::Subset
        });
        if is_dominated {
            dominated.push(at);
        } else {
            ranked.push(at);
        }
    }
    ranked.sort_by_key(|&at| rank(&items[at]));
    Decision {
        ranked,
        dominated,
        refusals,
    }
}

/// A solution a keeper took: final or provisional, and where its model is.
#[derive(Clone, Debug)]
pub struct Solved {
    pub provisional: bool,
    /// Its record's signed issue time.
    pub issued_ms: u64,
    pub claimed: Claimed,
    pub observations: ObservationSet,
    pub model: Arc<ClockModel>,
    pub model_inputs: Hash,
    /// The tie rule's weight.
    pub weight: u64,
    pub identity: Hash,
    /// Whether it agrees with its own receptions ([`consistent`]). One that does not is held only
    /// as evidence against the receptions it cites: it is never the final fix and never the
    /// earliest.
    pub consistent: bool,
}

/// A solution weighed for [`decide`]: its receivers' standing as the book holds it when the
/// transmission is decided, never as it was when the solution arrived, so the same solutions
/// under the same book rank the same in any arrival order.
struct Weighed<'a> {
    solved: &'a Solved,
    standing: u64,
}

impl Solved {
    /// `wire`, signed at `issued_ms`, under `model` (whose inputs hash is `model_inputs`), as the
    /// rule takes it: `None` unless it is a solution under the model ([`under`]).
    pub fn new(
        wire: &tally_wire::Solution,
        spec: u16,
        issued_ms: u64,
        provisional: bool,
        model: Arc<ClockModel>,
        model_inputs: Hash,
    ) -> Option<Self> {
        if !under(&model, wire, spec) {
            return None;
        }
        let claimed = Claimed::of(wire);
        let reach = if provisional {
            Reach::Carried
        } else {
            Reach::Window
        };
        let consistent = consistent(&model, reach, &wire.observations, &claimed);
        Some(Self {
            consistent,
            provisional,
            issued_ms,
            claimed,
            weight: wire.observations.receptions().len() as u64 + u64::from(model.input.count),
            identity: input_set(&wire.observations, &model_inputs),
            observations: wire.observations.clone(),
            model,
            model_inputs,
        })
    }

    fn ids(&self) -> Vec<ObservationId> {
        let message = message_hash(self.observations.message());
        self.observations
            .receptions()
            .iter()
            .map(|reception| ObservationId {
                receiver: reception.receiver,
                epoch: reception.epoch,
                timestamp: reception.counter,
                message,
            })
            .collect()
    }
}

impl Candidate for Weighed<'_> {
    fn observations(&self) -> &ObservationSet {
        &self.solved.observations
    }

    fn model_inputs(&self) -> &Hash {
        &self.solved.model_inputs
    }

    fn claimed(&self) -> Claimed {
        self.solved.claimed
    }

    fn standing(&self) -> u64 {
        self.standing
    }

    fn weight(&self) -> u64 {
        self.solved.weight
    }

    fn identity(&self) -> Hash {
        self.solved.identity
    }

    fn consistent(&self) -> bool {
        self.solved.consistent
    }
}

/// A transmission's solutions, waiting to be settled at `due_ms` (its earliest transmit time plus
/// `SETTLE_MS`).
struct Pending {
    due_ms: u64,
    solutions: Vec<Solved>,
}

/// What settling did, since the book began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settled {
    pub transmissions: u64,
    /// Receptions that agreed and earned, agreed without earning, and disagreed.
    pub earned: u64,
    pub agreed: u64,
    pub disagreed: u64,
}

/// One keeper's standing of every receiver, and the transmissions waiting to be settled.
pub struct Book {
    receivers: BTreeMap<PublicKey, ReceiverStanding>,
    pending: BTreeMap<u64, Pending>,
    /// Every reception a pending transmission holds, and which.
    index: BTreeMap<ObservationId, u64>,
    /// Pending transmissions by (due, number): what `settle` walks.
    deadlines: BTreeSet<(u64, u64)>,
    next: u64,
    /// Receptions settled, by period, the last `SETTLED_PERIODS`.
    settled: BTreeMap<u64, BTreeSet<ObservationId>>,
    max_pending: usize,
    max_receivers: usize,
    counts: Settled,
}

impl Book {
    /// At most `max_pending` transmissions waiting (the oldest forgotten beyond) and
    /// `max_receivers` receivers (the one least recently counted forgotten beyond).
    pub fn new(max_pending: usize, max_receivers: usize) -> Self {
        Self {
            receivers: BTreeMap::new(),
            pending: BTreeMap::new(),
            index: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            next: 0,
            settled: BTreeMap::new(),
            max_pending,
            max_receivers,
            counts: Settled::default(),
        }
    }

    /// A receiver's standing now: a new key's, none.
    pub fn of(&self, receiver: &PublicKey) -> ReceiverStanding {
        self.receivers.get(receiver).cloned().unwrap_or_default()
    }

    /// Every receiver with any standing, in key order.
    pub fn receivers(&self) -> &BTreeMap<PublicKey, ReceiverStanding> {
        &self.receivers
    }

    pub fn counts(&self) -> Settled {
        self.counts
    }

    /// Transmissions waiting to be settled.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// A receiver's weight at a transmit time, thousandths.
    pub fn weight(&self, receiver: &PublicKey, transmitted: TransmitTime) -> u64 {
        self.receivers.get(receiver).map_or(0, |standing| {
            standing.weight(period_of(transmitted.unix_ms))
        })
    }

    /// The sum of a set's receivers' weights at a transmit time, thousandths.
    pub fn standing_of(&self, observations: &ObservationSet, transmitted: TransmitTime) -> u64 {
        observations
            .receptions()
            .iter()
            .map(|reception| self.weight(&reception.receiver, transmitted))
            .sum()
    }

    /// Whether a position's receivers carry it (module docs, rule 3): at least the solver's
    /// minimum of them have standing at its transmit time.
    pub fn confirmed(&self, observations: &ObservationSet, transmitted: TransmitTime) -> bool {
        let period = period_of(transmitted.unix_ms);
        let minimum = if modes::altitude(observations.message()).is_some() {
            MIN_RECEIVERS_WITH_ALTITUDE
        } else {
            MIN_RECEIVERS
        };
        let receivers: BTreeSet<PublicKey> = observations
            .receptions()
            .iter()
            .map(|reception| reception.receiver)
            .filter(|receiver| {
                self.receivers
                    .get(receiver)
                    .is_some_and(|standing| standing.has_standing(period))
            })
            .collect();
        receivers.len() >= minimum
    }

    /// A solution the keeper took ([`Solved::new`]): held with every other solution of its
    /// transmission until it is settled, `SETTLE_MS` after the transmission. When it arrived
    /// decides nothing.
    pub fn add(&mut self, solved: Solved) {
        let due_ms = solved.claimed.transmitted.unix_ms.saturating_add(SETTLE_MS);
        let ids = solved.ids();
        let address = modes::address(solved.observations.message());
        let joined: BTreeSet<u64> = ids
            .iter()
            .filter_map(|id| self.index.get(id).copied())
            .filter(|number| {
                self.pending.get(number).is_some_and(|pending| {
                    pending.solutions.first().is_some_and(|first| {
                        modes::address(first.observations.message()) == address
                            && first.observations.message() == solved.observations.message()
                    })
                })
            })
            .collect();
        let number = match joined.first().copied() {
            Some(first) => {
                // Joining two held transmissions makes them one.
                for other in joined.iter().skip(1) {
                    if let Some(gone) = self.pending.remove(other) {
                        self.deadlines.remove(&(gone.due_ms, *other));
                        for moved in &gone.solutions {
                            for id in moved.ids() {
                                self.index.insert(id, first);
                            }
                        }
                        if let Some(kept) = self.pending.get_mut(&first) {
                            let before = kept.due_ms;
                            kept.due_ms = kept.due_ms.min(gone.due_ms);
                            kept.solutions.extend(gone.solutions);
                            let after = kept.due_ms;
                            self.deadlines.remove(&(before, first));
                            self.deadlines.insert((after, first));
                        }
                    }
                }
                first
            }
            None => {
                let number = self.next;
                self.next += 1;
                self.pending.insert(
                    number,
                    Pending {
                        due_ms,
                        solutions: Vec::new(),
                    },
                );
                self.deadlines.insert((due_ms, number));
                number
            }
        };
        for id in ids {
            self.index.insert(id, number);
        }
        if let Some(pending) = self.pending.get_mut(&number) {
            if due_ms < pending.due_ms {
                self.deadlines.remove(&(pending.due_ms, number));
                pending.due_ms = due_ms;
                self.deadlines.insert((due_ms, number));
            }
            match pending.solutions.iter_mut().find(|held| {
                held.identity == solved.identity && held.provisional == solved.provisional
            }) {
                Some(held) => held.issued_ms = held.issued_ms.min(solved.issued_ms),
                None => pending.solutions.push(solved),
            }
        }
        while self.pending.len() > self.max_pending {
            let Some((_, oldest)) = self.deadlines.pop_first() else {
                break;
            };
            if let Some(gone) = self.pending.remove(&oldest) {
                self.unindex(&gone);
            }
        }
    }

    fn unindex(&mut self, gone: &Pending) {
        for solution in &gone.solutions {
            for id in solution.ids() {
                self.index.remove(&id);
            }
        }
    }

    /// Settles every transmission `SETTLE_MS` or more before `now_ms` (its transmit time).
    /// `heard` is the signed wall clock of the batch that carried a reception (given with its
    /// transmission's transmit time, Unix milliseconds), when the keeper holds it in its
    /// receiver's own signed raw (the earliest of copies). The receivers whose standing changed,
    /// so a keeper that ranks by it ranks again.
    pub fn settle(
        &mut self,
        now_ms: u64,
        heard: impl Fn(&ObservationId, u64) -> Option<u64>,
    ) -> BTreeSet<PublicKey> {
        self.settle_up_to(now_ms, heard, usize::MAX).0
    }

    /// As `settle`, `most` transmissions at most, earliest due first, and whether any due by
    /// `now_ms` is left: a keeper that settles in pieces holds what it shares for one piece at a
    /// time, and settles the same transmissions in the same order as at once.
    pub fn settle_up_to(
        &mut self,
        now_ms: u64,
        heard: impl Fn(&ObservationId, u64) -> Option<u64>,
        most: usize,
    ) -> (BTreeSet<PublicKey>, bool) {
        let mut changed = BTreeSet::new();
        let mut settled = 0;
        while let Some(&(due_ms, number)) = self.deadlines.first() {
            if due_ms > now_ms {
                break;
            }
            if settled == most {
                return (changed, true);
            }
            settled += 1;
            self.deadlines.remove(&(due_ms, number));
            let Some(pending) = self.pending.remove(&number) else {
                continue;
            };
            self.unindex(&pending);
            self.settle_one(&pending, &heard, &mut changed);
        }
        (changed, false)
    }

    fn settle_one(
        &mut self,
        pending: &Pending,
        heard: &impl Fn(&ObservationId, u64) -> Option<u64>,
        changed: &mut BTreeSet<PublicKey>,
    ) {
        // Weighed by standing as the book holds it now, whatever it was when each arrived.
        let weighed: Vec<Weighed<'_>> = pending
            .solutions
            .iter()
            .filter(|solution| !solution.provisional)
            .map(|solved| Weighed {
                solved,
                standing: self.standing_of(&solved.observations, solved.claimed.transmitted),
            })
            .collect();
        let decision = decide(&weighed);
        let finals: Vec<&Solved> = weighed.iter().map(|weighed| weighed.solved).collect();
        let Some(&answer) = decision.ranked.iter().find(|&&at| finals[at].consistent) else {
            return;
        };
        let fix = finals[answer];
        self.counts.transmissions += 1;
        let period = period_of(fix.claimed.transmitted.unix_ms);
        let can_earn = eligible(fix.observations.message(), fix.claimed.transmitted);
        // The earliest solutions, by signed issue time, of those consistent with their own
        // receptions: one signed before its own transmission says nothing true about time and is
        // not counted.
        let possible = || {
            pending.solutions.iter().filter(|solution| {
                solution.consistent && solution.issued_ms >= solution.claimed.transmitted.unix_ms
            })
        };
        let earliest_ms = possible().map(|solution| solution.issued_ms).min();
        let earliest: BTreeSet<ObservationId> = possible()
            .filter(|solution| Some(solution.issued_ms) == earliest_ms)
            .flat_map(Solved::ids)
            .collect();
        let mut cited: BTreeMap<ObservationId, (tally_wire::Reception, bool)> = BTreeMap::new();
        for (at, solution) in finals.iter().enumerate() {
            let refused = decision.refused(at);
            for (id, reception) in solution
                .ids()
                .into_iter()
                .zip(solution.observations.receptions())
            {
                let entry = cited.entry(id).or_insert((*reception, true));
                entry.1 &= refused;
            }
        }
        for solution in pending
            .solutions
            .iter()
            .filter(|solution| solution.provisional)
        {
            for (id, reception) in solution
                .ids()
                .into_iter()
                .zip(solution.observations.receptions())
            {
                let entry = cited.entry(id).or_insert((*reception, false));
                entry.1 = false;
            }
        }
        for (id, (reception, only_refused)) in cited {
            let Some(heard_ms) = heard(&id, fix.claimed.transmitted.unix_ms) else {
                continue;
            };
            if self
                .settled
                .get(&period)
                .is_some_and(|settled| settled.contains(&id))
            {
                continue;
            }
            let verdict = match reception_z(&fix.model, Reach::Window, &reception, &fix.claimed) {
                Some(z) if z <= AGREE_Z => {
                    self.counts.agreed += 1;
                    let arrived_first =
                        earliest.contains(&id) && earliest_ms.is_some_and(|ms| heard_ms < ms);
                    (can_earn && arrived_first).then_some(true)
                }
                Some(_) => Some(false),
                None => only_refused.then_some(false),
            };
            let Some(agreed) = verdict else {
                continue;
            };
            if agreed {
                self.counts.earned += 1;
            } else {
                self.counts.disagreed += 1;
            }
            self.settled.entry(period).or_default().insert(id);
            changed.insert(id.receiver);
            self.receivers
                .entry(id.receiver)
                .or_default()
                .observe(period, agreed);
        }
        if let Some(&newest) = self.settled.keys().next_back() {
            self.settled = self
                .settled
                .split_off(&newest.saturating_sub(SETTLED_PERIODS));
        }
        while self.receivers.len() > self.max_receivers {
            // The one counted longest ago, then the lowest key.
            let Some(oldest) = self
                .receivers
                .iter()
                .min_by_key(|(key, standing)| {
                    (
                        standing.periods.keys().next_back().copied().unwrap_or(0),
                        **key,
                    )
                })
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.receivers.remove(&oldest);
        }
    }
}

/// The signed wall clock of the batch that carried `id`, when `held` holds it in a sealed bin of
/// its transmission (`transmitted_ms`) or the next few: what a keeper with raw passes
/// [`Book::settle`]. `held` is a holder of raw or the shared handle of its sealed bins
/// (`held::SealedBins`), so a relay's standing reads the bins its MLAT engine holds.
pub fn heard_in(held: &impl HoldsBins, id: &ObservationId, transmitted_ms: u64) -> Option<u64> {
    let bin = bin_of(transmitted_ms);
    held.bins(bin - 1, bin + 2).iter().find_map(|sealed| {
        let at = sealed.find(id)?;
        Some(sealed.wall_ms(&sealed.records[at as usize]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    const AT: TransmitTime = TransmitTime {
        unix_ms: 1_791_288_000_000,
        sub_ms_ps: 0,
    };

    fn key(seed: u8) -> PublicKey {
        Identity::from_seed([seed; 32]).public()
    }

    #[test]
    fn standing_is_earned_capped_a_period_and_in_all_and_decays() {
        let mut standing = ReceiverStanding::NEW;
        assert_eq!(standing.score(10), 0);
        assert_eq!(standing.weight(10), 0);
        assert!(!standing.has_standing(10));
        for _ in 0..200 {
            standing.observe(10, true);
        }
        assert_eq!(
            standing.score(10),
            i64::from(EARN_PER_PERIOD),
            "a period is capped"
        );
        assert_eq!(standing.score(9), 0, "nothing counts before it happened");
        for period in 11..12 {
            for _ in 0..EARN_PER_PERIOD {
                standing.observe(period, true);
            }
        }
        assert!(!standing.has_standing(11), "two periods are not enough");
        for _ in 0..EARN_PER_PERIOD {
            standing.observe(12, true);
        }
        assert!(standing.has_standing(12), "half an hour of agreement is");
        for period in 13..40 {
            for _ in 0..EARN_PER_PERIOD {
                standing.observe(period, true);
            }
        }
        assert_eq!(standing.score(39), FULL, "capped in all");
        assert_eq!(standing.weight(39), PERMILLE);
        // A day later, every period is worth half: still capped. Two days of silence later, the
        // thirty periods' 3,600 are worth 900, a quarter.
        assert_eq!(standing.score(39 + HALF_LIFE_PERIODS), FULL);
        assert_eq!(standing.score(39 + 2 * HALF_LIFE_PERIODS), 900);
        assert!(standing.has_standing(39 + 2 * HALF_LIFE_PERIODS));
        assert_eq!(
            standing.score(39 + HORIZON_PERIODS + 40),
            0,
            "forgotten past the horizon"
        );
        // Disagreement costs ten agreements, and enough of it gates the receiver.
        let mut padder = ReceiverStanding::NEW;
        for _ in 0..11 {
            padder.observe(10, false);
        }
        assert_eq!(padder.score(10), -11 * DISAGREE_COST);
        assert_eq!(padder.weight(10), 0);
        assert!(padder.gated(10));
    }

    #[test]
    fn standing_is_the_same_whatever_order_it_is_counted_in() {
        let events: Vec<(u64, bool)> = (0..300).map(|at| (100 + at % 7, at % 11 != 0)).collect();
        let mut forward = ReceiverStanding::NEW;
        for (period, agreed) in &events {
            forward.observe(*period, *agreed);
        }
        let mut backward = ReceiverStanding::NEW;
        for (period, agreed) in events.iter().rev() {
            backward.observe(*period, *agreed);
        }
        assert_eq!(forward, backward);
        assert_eq!(forward.score(110), backward.score(110));
    }

    #[derive(Clone)]
    struct Item {
        observations: ObservationSet,
        inputs: Hash,
        claimed: Claimed,
        standing: u64,
        identity: Hash,
        consistent: bool,
    }

    impl Candidate for Item {
        fn observations(&self) -> &ObservationSet {
            &self.observations
        }
        fn model_inputs(&self) -> &Hash {
            &self.inputs
        }
        fn claimed(&self) -> Claimed {
            self.claimed
        }
        fn standing(&self) -> u64 {
            self.standing
        }
        fn weight(&self) -> u64 {
            self.observations.receptions().len() as u64
        }
        fn identity(&self) -> Hash {
            self.identity
        }
        fn consistent(&self) -> bool {
            self.consistent
        }
    }

    /// A DF11 reply heard by `receivers`, claimed `east_m` east of a point with a 50 m standard
    /// deviation each way.
    fn item(receivers: &[u8], east_m: f64, inputs: u8, standing: u64) -> Item {
        let receptions = receivers
            .iter()
            .map(|seed| tally_wire::Reception {
                receiver: key(*seed),
                epoch: 1,
                counter: 1_000 + u64::from(*seed),
            })
            .collect();
        let observations = ObservationSet::new(vec![0x58, 0xab, 0xcd, 0xef, 0, 0, 0], receptions)
            .unwrap_or_else(|error| panic!("{error}"));
        let lon_e7 = (5.0 * 1e7 + east_m / (111_320.0 * 52f64.to_radians().cos()) * 1e7) as i32;
        let variance = 2_500.0;
        let identity = input_set(&observations, &[inputs; 32]);
        Item {
            observations,
            inputs: [inputs; 32],
            claimed: Claimed {
                lat_e7: 520_000_000,
                lon_e7,
                alt_hae_mm: Some(10_000_000),
                covariance: EnuCovariance {
                    xx: variance,
                    xy: 0.0,
                    xz: 0.0,
                    yy: variance,
                    yz: 0.0,
                    zz: variance,
                },
                transmitted: AT,
            },
            standing,
            identity,
            consistent: true,
        }
    }

    fn first(items: &[Item]) -> Hash {
        items[decide(items).ranked[0]].identity
    }

    #[test]
    fn an_agreeing_superset_wins_and_dominates_the_smaller() {
        let smaller = item(&[1, 2, 3, 4], 0.0, 7, 0);
        let larger = item(&[1, 2, 3, 4, 5], 40.0, 7, 0);
        for items in [
            vec![smaller.clone(), larger.clone()],
            vec![larger.clone(), smaller.clone()],
        ] {
            let decision = decide(&items);
            assert!(decision.refusals.is_empty());
            assert_eq!(decision.ranked.len(), 1);
            assert_eq!(first(&items), larger.identity);
        }
    }

    #[test]
    fn a_disagreeing_superset_is_refused_and_the_smaller_stands_in_either_order() {
        let smaller = item(&[1, 2, 3, 4], 0.0, 7, 0);
        // Ten new receivers' receptions, the position moved 2 km.
        let larger = item(
            &[1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
            2_000.0,
            7,
            0,
        );
        for items in [
            vec![smaller.clone(), larger.clone()],
            vec![larger.clone(), smaller.clone()],
        ] {
            let decision = decide(&items);
            assert_eq!(first(&items), smaller.identity);
            assert_eq!(decision.refusals.len(), 1);
            let refusal = &decision.refusals[0];
            assert_eq!(items[refusal.refused].identity, larger.identity);
            assert_eq!(items[refusal.kept].identity, smaller.identity);
            assert!(refusal.chi2 > AGREE_CHI2);
        }
        // A smaller fix that disagrees with its own receptions refuses nothing.
        let mut liar = smaller;
        liar.consistent = false;
        let items = vec![liar, larger.clone()];
        assert!(decide(&items).refusals.is_empty());
        assert_eq!(first(&items), larger.identity);
    }

    #[test]
    fn sets_are_weighed_by_standing_not_count() {
        // Incomparable: four receivers with standing against eight without.
        let few = item(&[1, 2, 3, 4], 0.0, 7, 3_000);
        let many = item(&[5, 6, 7, 8, 9, 10, 11, 12], 10.0, 8, 0);
        assert_eq!(first(&[few.clone(), many.clone()]), few.identity);
        assert_eq!(first(&[many.clone(), few.clone()]), few.identity);
        // Standing equal, the count decides.
        let mut level = many.clone();
        level.standing = 3_000;
        assert_eq!(first(&[few.clone(), level.clone()]), level.identity);
    }

    #[test]
    fn a_position_is_confirmed_only_when_enough_of_its_receivers_have_standing() {
        let at = AT;
        let period = period_of(at.unix_ms);
        let mut book = Book::new(16, 16);
        let earn = |book: &mut Book, seed: u8| {
            let standing = book.receivers.entry(key(seed)).or_default();
            for earlier in period - 11..=period {
                for _ in 0..EARN_PER_PERIOD {
                    standing.observe(earlier, true);
                }
            }
        };
        // A DF11 reply states no altitude: four receivers with standing confirm it.
        let set = item(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], 0.0, 7, 0).observations;
        for seed in [1, 2, 3] {
            earn(&mut book, seed);
        }
        assert!(!book.confirmed(&set, at), "ten new keys confirm nothing");
        assert_eq!(book.standing_of(&set, at), 3 * PERMILLE);
        earn(&mut book, 4);
        assert!(book.confirmed(&set, at));
        assert_eq!(book.standing_of(&set, at), 4 * PERMILLE);
    }

    #[test]
    fn only_a_transmission_no_ads_b_position_could_have_told_earns() {
        let at = AT;
        let adsb = [
            0x8d, 0x48, 0x40, 0xd6, 0x20, 0x2c, 0xc3, 0x71, 0xc3, 0x2c, 0xe0, 0x57, 0x60, 0x98,
        ];
        assert!(!eligible(&adsb, at));
        // DF11 all-call replies of many aircraft: most are eligible, the calibration sample not.
        let mut eligible_count = 0;
        for address in 0..256u32 {
            let body = [
                0x58,
                (address >> 16) as u8,
                (address >> 8) as u8,
                address as u8,
            ];
            let message = modes::with_parity(&body, 0);
            let sampled_now = sampled(address, bin_of(at.unix_ms))
                || sampled(address, bin_of(at.unix_ms + SAMPLE_SLACK_MS));
            assert_eq!(eligible(&message, at), !sampled_now);
            eligible_count += usize::from(eligible(&message, at));
        }
        assert!(eligible_count > 200);
    }
}
