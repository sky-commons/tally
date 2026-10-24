//! Receiver standing (RFC-0174 §2.12), the rule: from public signed data alone (receivers' signed
//! batches, engines' signed clock models and solutions), how far each receiver's receptions are to
//! be believed, and when a bigger answer may replace a smaller one. Every party that reads the same
//! records computes the same standing, so it is never on the wire. Relays (`tally-relay`'s
//! `standing`), which hold those records, keep a [`Book`] of it; relays and clients (`tally-merge`)
//! both decide which of one transmission's solutions stands by [`decide`].
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
//! is evidence against what it cites and nothing more. [`SETTLE`] after the transmission (its
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
//! A reception is settled once: a solution whose transmission is already due by the keeper's clock
//! (`SETTLE` after it) is late and refused ([`Book::add`]), so a reception settled is remembered only
//! while a solution that may still be added could find it in raw ([`SETTLED_SLACK_MS`] past its
//! transmission's due time). Counts are kept per receiver by
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
//! disagreeing superset win.
//!
//! Standing is a relay's (`tally-relay`'s `standing`): it holds the raw, the full models and the
//! raw solutions. A client holds none of them (wire version 3: a receiver's counters and a model's
//! sites and offsets give its site), only tagged solutions and models' summaries, so it cannot
//! see who heard what when, nor map a reception through a model: it decides between one
//! transmission's tagged solutions by [`decide`] (agreement and the tie rule, over tag sets,
//! [`Set`]) with no standing (`tally-merge`).
//!
//! The solver's gating by standing ([`ReceiverStanding::gated`]): a receiver whose standing is
//! below `-GATED_BELOW` is one the specification's outlier rule should leave out.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tally_wire::batch::Hash;
use tally_wire::clocks::Judged;
use tally_wire::{EnuCovariance, ObservationSet, PublicKey, Relation, TaggedSet, TransmitTime};

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
/// How long after a transmission (its signed transmit time, by the keeper's judging clock) it is
/// settled: once every final fix of it has surely arrived, the error budget's
/// `tally_wire::budget::FINAL_FIX_ARRIVED` (108.5 s: the latest a final fix leaves its engine,
/// `FINAL_FIX_LEAVES`, 91.5 s, then `K`, how far the keeper's clock may be from that engine's
/// relay's, and a repair's transit; derived there). That is inside what a keeper holds raw behind
/// its clock (`held::SEALED_BINS_HELD` bins, less the one being sealed: a window's 11 before, its
/// own and 1 after, a stride of 8 and 4 spare, 24 bins, 120 s), so the raw a settlement asks
/// [`heard_in`] for is still held: the assert below holds it, so a settling or a holding changed
/// without the other stops compiling.
pub const SETTLE: tally_wire::budget::Tolerance = tally_wire::budget::FINAL_FIX_ARRIVED;

const _: () = assert!(
    SETTLE.span::<Judged>().ms()
        <= (crate::held::SEALED_BINS_HELD - 1) as u64 * crate::scope::GRID_MS
);
/// How long past its transmission's due time (`SETTLE` after it, by the keeper's clock) a settled
/// reception is remembered, so it is settled once: a solution added later is of a transmission no
/// earlier than the due time ([`Book::add`] refuses any earlier, late), and the raw it is settled
/// against ([`heard_in`]) is its transmit time's grid bin, the one before and the two after, so a
/// reception of a transmission more than four bins before it is never found for it. Six bins.
/// Before, every reception settled was remembered three ten-minute periods, some thirty minutes of
/// every solved reception the keeper held raw for: a table nothing bounded but the clock.
pub const SETTLED_SLACK_MS: u64 = 6 * crate::scope::GRID_MS;
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

/// The periods a receiver's standing keeps: the newest it counted and the [`HORIZON_PERIODS`]
/// before it.
const KEPT_PERIODS: usize = HORIZON_PERIODS as usize + 1;

/// One receiver's standing: its counts by period of transmit time, the newest counted and the
/// [`HORIZON_PERIODS`] before it, each period in its slot of a ring ([`KEPT_PERIODS`] of them,
/// made whole at its first count). A new key's is none. Before, the periods were a tree of one
/// node entry each, some 75 KB a receiver planned at its horizon; the ring is 9 KB, exactly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiverStanding {
    /// The newest period counted; none before the first.
    newest: Option<u64>,
    /// Period `p`'s counts at `p % KEPT_PERIODS`, for `p` within the horizon of `newest`.
    ring: Vec<Tally>,
}

impl ReceiverStanding {
    /// A new key's: none.
    pub const NEW: Self = Self {
        newest: None,
        ring: Vec::new(),
    };

    /// The newest period it counted.
    pub fn newest(&self) -> Option<u64> {
        self.newest
    }

    /// One settled reception of `period`: it agreed (and earned) or it disagreed. A period past
    /// the horizon of the newest is not counted.
    pub fn observe(&mut self, period: u64, agreed: bool) {
        if self.ring.is_empty() {
            self.ring = vec![Tally::default(); KEPT_PERIODS];
        }
        match self.newest {
            Some(newest) if period.saturating_add(HORIZON_PERIODS) < newest => return,
            Some(newest) if period > newest => {
                // The periods between are counted nothing: their slots held the oldest.
                let cleared = (period - newest).min(KEPT_PERIODS as u64);
                for gone in period + 1 - cleared..=period {
                    self.ring[(gone % KEPT_PERIODS as u64) as usize] = Tally::default();
                }
                self.newest = Some(period);
            }
            Some(_) => {}
            None => self.newest = Some(period),
        }
        let tally = &mut self.ring[(period % KEPT_PERIODS as u64) as usize];
        if agreed {
            tally.agreed = tally.agreed.saturating_add(1);
        } else {
            tally.disagreed = tally.disagreed.saturating_add(1);
        }
    }

    /// The periods it keeps, oldest first, with their counts.
    fn periods(&self) -> impl Iterator<Item = (u64, &Tally)> {
        let newest = self.newest.unwrap_or(0);
        let oldest = newest.saturating_sub(HORIZON_PERIODS);
        let live = self.newest.is_some() && !self.ring.is_empty();
        (oldest..=newest)
            .filter(move |_| live)
            .map(move |at| (at, &self.ring[(at % KEPT_PERIODS as u64) as usize]))
    }

    /// Standing at `period`: every period up to it, earning capped, each halved for every
    /// half-life it is older; capped at `FULL`, floored at `-FULL`.
    pub fn score(&self, period: u64) -> i64 {
        let mut score: i64 = 0;
        for (at, tally) in self.periods().filter(|(at, _)| *at <= period) {
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

/// A held clock model as a keeper's book cites it: the model, the inputs it is the function of
/// (`publish::inputs_id`) and the engine that signed it. A relay's handle on its one store of
/// decoded models (`tally-relay`'s `models::Model`), which charges the model while any handle is
/// alive, so a book holds handles and never counts a model's bytes again.
pub trait ModelRef: Clone {
    fn model(&self) -> &ClockModel;
    fn inputs(&self) -> &Hash;
    fn engine(&self) -> &PublicKey;
}

/// An observation set as the rule compares two: a relay's raw `ObservationSet`, or the
/// `TaggedSet` a client is sent (each reception its tag), which relate alike.
pub trait Set {
    fn relation(&self, other: &Self) -> Relation;
}

impl Set for ObservationSet {
    fn relation(&self, other: &Self) -> Relation {
        ObservationSet::relation(self, other)
    }
}

impl Set for TaggedSet {
    fn relation(&self, other: &Self) -> Relation {
        TaggedSet::relation(self, other)
    }
}

/// One solution as the rule weighs it.
pub trait Candidate {
    /// What its observations are: raw (a relay's) or tagged (a client's).
    type Set: Set;
    fn observations(&self) -> &Self::Set;
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

/// A solution a keeper took ([`Solved::new`]): what its book takes in, once, by value. Nothing of
/// it is weighed as it is taken: a final's consistency with its own receptions is read when its
/// transmission is settled, once ([`Book::settle`]), so taking a solution in is its decode and a
/// compact insert.
#[derive(Clone, Debug)]
pub struct Solved<M> {
    pub provisional: bool,
    /// Its record's signed issue time.
    pub issued_ms: u64,
    pub claimed: Claimed,
    pub observations: ObservationSet,
    /// The model it cites, held (a relay's handle on its store of models).
    pub model: M,
    /// The tie rule's weight.
    pub weight: u64,
    pub identity: Hash,
    /// A provisional's consistency with its own receptions under the model it carried, read as
    /// it is taken: the book keeps neither a provisional's claim nor its model, only whether it
    /// may be the earliest. `None` for a final, whose consistency the book reads at settling.
    pub consistent: Option<bool>,
}

impl<M: ModelRef> Solved<M> {
    /// `wire`, signed at `issued_ms`, under `model`, as the rule takes it: `None` unless it is a
    /// solution under the model ([`under`]).
    pub fn new(
        wire: &tally_wire::Solution,
        spec: u16,
        issued_ms: u64,
        provisional: bool,
        model: M,
    ) -> Option<Self> {
        if !under(model.model(), wire, spec) {
            return None;
        }
        let claimed = Claimed::of(wire);
        let consistent = provisional
            .then(|| consistent(model.model(), Reach::Carried, &wire.observations, &claimed));
        Some(Self {
            provisional,
            issued_ms,
            claimed,
            weight: wire.observations.receptions().len() as u64
                + u64::from(model.model().input.count),
            identity: input_set(&wire.observations, model.inputs()),
            observations: wire.observations.clone(),
            model,
            consistent,
        })
    }

    /// What it allocates in hand: itself, its message and its receptions.
    pub fn allocated(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.observations.message().len()
            + std::mem::size_of_val(self.observations.receptions())
    }
}

/// The receptions a held transmission keeps at most: a solution's receptions are a set of the
/// transmission's, one bit each ([`Bits`]). A solution that would take its transmission past them
/// is refused and counted (`Settled::refused`). Every model has at most `tile::MEMBERS_MAX` members,
/// and an honest transmission's solutions cite much the same receivers.
pub const RECEPTIONS_MOST: usize = 64;
/// The solutions a held transmission keeps at most: one final and one provisional of each of its
/// area's engines (`rendezvous::MLAT_RELAYS_PER_AREA`); one more, or a second of one engine's kind
/// over different receptions, is refused and counted. Before, every distinct input set was a
/// solution of its own, so an engine that varied its receptions' subsets held without bound, and
/// deciding was quadratic in them.
pub const SOLUTIONS_MOST: usize = 2 * tally_wire::rendezvous::MLAT_RELAYS_PER_AREA;
/// The longest message a transmission holds: a long Mode S reply.
pub const MESSAGE_MOST: usize = tally_wire::modes::LONG;

/// A held solution's receptions: bit `i` is its transmission's reception `i`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bits(u64);

impl Bits {
    fn has(self, at: usize) -> bool {
        self.0 & (1 << at) != 0
    }

    fn ones(self) -> impl Iterator<Item = usize> {
        (0..RECEPTIONS_MOST).filter(move |at| self.has(*at))
    }
}

impl Set for Bits {
    /// As two observation sets of one message relate (`ObservationSet::relation`).
    fn relation(&self, other: &Self) -> Relation {
        if self.0 == other.0 {
            Relation::Equal
        } else if self.0 & !other.0 == 0 {
            Relation::Subset
        } else if other.0 & !self.0 == 0 {
            Relation::Superset
        } else {
            Relation::Incomparable
        }
    }
}

/// A transmission's message, held once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Message {
    len: u8,
    bytes: [u8; MESSAGE_MOST],
}

impl Message {
    fn of(message: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; MESSAGE_MOST];
        bytes.get_mut(..message.len())?.copy_from_slice(message);
        Some(Self {
            len: message.len() as u8,
            bytes,
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// One distinct reception of a held transmission: its receiver interned ([`Interned`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rec {
    receiver: u32,
    epoch: u32,
    counter: u64,
}

/// A final solution held: what settling weighs it by.
struct Final<M> {
    engine: u64,
    issued_ms: u64,
    claimed: Claimed,
    identity: Hash,
    weight: u64,
    model: M,
    bits: Bits,
    /// Its consistency with its own receptions, read at settling, once.
    consistent: std::cell::Cell<Option<bool>>,
}

/// A provisional solution held: only whether it may be the earliest of its transmission.
#[derive(Clone, Copy, Debug)]
struct Provisional {
    engine: u64,
    issued_ms: u64,
    transmitted_ms: u64,
    consistent: bool,
    bits: Bits,
}

/// A transmission's solutions waiting to be settled [`SETTLE`] after `earliest_ms`, its earliest
/// transmit time: its message once, its distinct receptions once, and each solution a set of
/// them.
struct Transmission<M> {
    earliest_ms: u64,
    message: Message,
    receptions: Vec<Rec>,
    finals: Vec<Final<M>>,
    provisionals: Vec<Provisional>,
    /// What it takes of the book's room ([`Transmission::bytes_of`]).
    bytes: usize,
}

/// The parts a transmission's bytes are shared in among the engines whose solutions it holds:
/// divisible by every count of them up to [`SOLUTIONS_MOST`], so each engine's share is exact.
const SHARE_PARTS: u64 = 60;
const _: () =
    assert!(SOLUTIONS_MOST <= 6 && SHARE_PARTS.is_multiple_of(4) && SHARE_PARTS.is_multiple_of(5));

impl<M> Transmission<M> {
    /// What it takes of the book's room: its entries, its lists at their capacity, and an entry of
    /// the index for each of its receptions.
    fn bytes_of(&self) -> usize {
        use tally_wire::footprint::vec;
        transmission_entry_bytes::<M>()
            + vec::<Rec>(self.receptions.capacity())
            + self.receptions.len() * INDEX_ENTRY_BYTES
            + vec::<Final<M>>(self.finals.capacity())
            + vec::<Provisional>(self.provisionals.capacity())
    }

    /// The engines whose solutions it holds, each once.
    fn sources(&self) -> Vec<u64> {
        let mut sources: Vec<u64> = self
            .finals
            .iter()
            .map(|one| one.engine)
            .chain(self.provisionals.iter().map(|one| one.engine))
            .collect();
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    /// Each of its engines' share of its bytes, in [`SHARE_PARTS`] of a byte.
    fn split(&self) -> u64 {
        let sources = self.sources().len().max(1) as u64;
        self.bytes as u64 * SHARE_PARTS / sources
    }

    /// The work settling it costs: each reception weighed under each final, and once more.
    fn work(&self) -> usize {
        self.receptions.len() * (1 + self.finals.len()) + 1
    }
}

/// What a transmission held takes beside its lists: its entry among the transmissions and among
/// the deadlines.
pub const fn transmission_entry_bytes<M>() -> usize {
    tally_wire::footprint::btree_planned::<u64, Transmission<M>>(1)
        - tally_wire::footprint::btree_planned::<u64, Transmission<M>>(0)
        + tally_wire::footprint::btree_planned::<(u64, u64), ()>(1)
        - tally_wire::footprint::btree_planned::<(u64, u64), ()>(0)
}

/// What one entry of the book's index of receptions takes at most (`footprint::btree_planned`): a
/// reception's fingerprint and its transmission's number.
pub const INDEX_ENTRY_BYTES: usize = tally_wire::footprint::btree_planned::<u64, u64>(1)
    - tally_wire::footprint::btree_planned::<u64, u64>(0);

/// What the book's room counts for a transmission held with `finals` finals and `provisionals`
/// provisionals over `receptions` distinct receptions, as `Book::add` grows its lists (each to
/// exactly its length): its entries, its lists, and an entry of the index for each reception.
pub const fn transmission_bytes_most<M>(
    finals: usize,
    provisionals: usize,
    receptions: usize,
) -> usize {
    use tally_wire::footprint::vec;
    transmission_entry_bytes::<M>()
        + vec::<Rec>(receptions)
        + receptions * INDEX_ENTRY_BYTES
        + vec::<Final<M>>(finals)
        + vec::<Provisional>(provisionals)
}

/// What a settled reception remembered takes at most: its digest in its bin's list, which a push
/// at a time leaves at most twice its length.
pub const SETTLED_ENTRY_BYTES: usize = 2 * std::mem::size_of::<u128>();
/// What a receiver's standing takes at most: its entry among the receivers and its ring of
/// periods ([`KEPT_PERIODS`]), and its entry among the receivers interned while a held
/// transmission cites it ([`Interned`]: its id, its key and count, and the free list's slot, each
/// list at most twice its length).
pub const RECEIVER_BYTES: usize =
    tally_wire::footprint::btree_planned::<PublicKey, ReceiverStanding>(1)
        - tally_wire::footprint::btree_planned::<PublicKey, ReceiverStanding>(0)
        + tally_wire::footprint::vec::<Tally>(KEPT_PERIODS)
        + tally_wire::footprint::btree_planned::<PublicKey, u32>(1)
        - tally_wire::footprint::btree_planned::<PublicKey, u32>(0)
        + 2 * (std::mem::size_of::<(PublicKey, u32)>() + std::mem::size_of::<u32>());
/// The bins of settled receptions remembered at once, at most: the slack, the bin a due time
/// falls in, and the bins a settling in pieces may still reach back for.
pub const SETTLED_BINS: usize = (SETTLED_SLACK_MS / crate::scope::GRID_MS) as usize + 4;
/// What the book's trees and rings take whatever they hold: each one's root, and the ring of bins.
pub const fn book_fixed_bytes<M>() -> usize {
    tally_wire::footprint::btree_planned::<u64, Transmission<M>>(0)
        + tally_wire::footprint::btree_planned::<(u64, u64), ()>(0)
        + tally_wire::footprint::btree_planned::<u64, u64>(0)
        + tally_wire::footprint::btree_planned::<PublicKey, ReceiverStanding>(0)
        + tally_wire::footprint::btree_planned::<PublicKey, u32>(0)
        + tally_wire::footprint::btree_planned::<u64, u64>(0)
        + 2 * SETTLED_BINS.next_power_of_two() * std::mem::size_of::<(u64, Vec<u128>)>()
        + SETTLED_BINS * tally_wire::footprint::vec::<u128>(SMALLEST_LIST)
        + tally_wire::footprint::vec::<(PublicKey, u32)>(SMALLEST_LIST)
        + tally_wire::footprint::vec::<u32>(SMALLEST_LIST)
}

/// The least capacity a list grown a push at a time takes (the standard library's least for an
/// element of up to 1 KiB): what each of the book's lists may hold beyond twice its length.
const SMALLEST_LIST: usize = 4;

/// The most knots a clock's piece of a model has: one every `clock::KNOT_PS` over the model's
/// window (`scope::BEFORE`, its own bin and `scope::AFTER`, each `scope::GRID_MS`), and one at
/// either end. Held by the models the reference engine fits (`tables_bytes`).
pub const KNOTS_MOST: usize = ((crate::scope::BEFORE + 1 + crate::scope::AFTER) as u128
    * crate::scope::GRID_MS as u128
    * 1_000_000_000
    / crate::clock::KNOT_PS as u128) as usize
    + 2;
/// The sync aircraft's biases a model holds at most: each of `scope::SYNC_AIRCRAFT_MAX` aircraft
/// in each of the four kinds (`clock::BiasKind`).
pub const BIASES_MOST: usize = crate::scope::SYNC_AIRCRAFT_MAX * 4;

/// What a decoded model of `members` members allocates at most ([`model_bytes`]): `publish::decode`
/// makes every list exactly as long as its encoding says, so each member's site, a piece for each
/// member's clock and one more for each jump a fit declares (`sync::MAX_JUMPS`), each piece's knots
/// ([`KNOTS_MOST`]), the biases ([`BIASES_MOST`]), the jumps, and a dropped clock for each piece.
/// Before, every list was planned at the capacity a push at a time leaves, up to twice its length.
pub const fn model_bytes_most(members: usize) -> usize {
    MODEL_FIXED_BYTES + members * MODEL_BYTES_PER_MEMBER
}

/// What each member adds to a model at most ([`model_bytes_most`]): its site, its clock's piece
/// with its knots, and its dropped clock.
pub const MODEL_BYTES_PER_MEMBER: usize = std::mem::size_of::<crate::obs::Site>()
    + std::mem::size_of::<crate::clock::ClockPiece>()
    + std::mem::size_of::<(PublicKey, u32)>()
    + tally_wire::footprint::vec::<i64>(KNOTS_MOST);
/// What a model takes beside its members ([`MODEL_BYTES_PER_MEMBER`]): its `Arc`, a piece with its
/// knots and a dropped clock for each jump, and the biases and jumps at their most.
pub const MODEL_FIXED_BYTES: usize = {
    use tally_wire::footprint::{arc, vec};
    arc::<ClockModel>()
        + crate::sync::MAX_JUMPS
            * (std::mem::size_of::<crate::clock::ClockPiece>()
                + std::mem::size_of::<(PublicKey, u32)>()
                + vec::<i64>(KNOTS_MOST))
        + vec::<crate::clock::Bias>(BIASES_MOST)
        + vec::<crate::clock::Jump>(crate::sync::MAX_JUMPS)
};

/// What a decoded clock model allocates: its `Arc` and every list it holds, at their capacity.
/// Counted once, where a model is held (a relay's store of models).
pub fn model_bytes(model: &ClockModel) -> usize {
    use tally_wire::footprint::{arc, vec};
    arc::<ClockModel>()
        + vec::<crate::obs::Site>(model.scope.capacity())
        + vec::<crate::clock::ClockPiece>(model.pieces.capacity())
        + model
            .pieces
            .iter()
            .map(|piece| vec::<i64>(piece.offsets_ps.capacity()))
            .sum::<usize>()
        + vec::<crate::clock::Bias>(model.biases.capacity())
        + vec::<crate::clock::Jump>(model.jumps.capacity())
        + vec::<(PublicKey, u32)>(model.dropped.capacity())
}

/// What a keeper's book holds at most (`Book::new`): the bytes its transmissions waiting take
/// (their lists and index entries; the models they cite are the keeper's store's), past which a
/// solution that would add to them is refused and counted, never a transmission held forgotten;
/// each engine's share of them (`source_share`), past which its solutions are refused likewise;
/// the receivers whose standing it keeps and that the transmissions held cite, the one counted
/// longest ago forgotten past them; and the settled receptions it remembers, the oldest forgotten
/// past them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookCaps {
    pub pending_bytes: usize,
    pub source_share: usize,
    pub receivers: usize,
    pub settled: usize,
}

impl BookCaps {
    /// What a book at these caps allocates at most: its room of transmissions, each receiver at
    /// its most ([`RECEIVER_BYTES`]), each settled reception ([`SETTLED_ENTRY_BYTES`]), and its
    /// trees' roots ([`book_fixed_bytes`]).
    pub const fn planned_bytes<M>(&self) -> usize {
        book_fixed_bytes::<M>()
            + self.pending_bytes
            + self.receivers * RECEIVER_BYTES
            + self.settled * SETTLED_ENTRY_BYTES
    }
}

/// What settling did and what was refused, since the book began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settled {
    pub transmissions: u64,
    /// Receptions that agreed and earned, agreed without earning, and disagreed.
    pub earned: u64,
    pub agreed: u64,
    pub disagreed: u64,
    /// Solutions refused as late: their transmission was due when they came (`Book::add`).
    pub late: u64,
    /// Solutions refused: a second of one engine's kind over other receptions, or past
    /// [`SOLUTIONS_MOST`] or [`RECEPTIONS_MOST`] of a transmission (`slots`); past the book's
    /// room (`room`); past its engine's share of it (`share`); citing a receiver past the book's
    /// cap of them (`receivers`); of a message no transmission holds (`malformed`). None of them
    /// lets go of anything held.
    pub slots: u64,
    pub room: u64,
    pub share: u64,
    pub receivers: u64,
    pub malformed: u64,
    /// Solutions let go as two held transmissions became one and both held one engine's kind.
    pub merged_out: u64,
}

impl Settled {
    /// Every solution refused, whatever the reason.
    pub fn refused(&self) -> u64 {
        self.slots + self.room + self.share + self.receivers + self.malformed
    }
}

/// Why [`Book::add`] did not hold a solution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Late,
    Slots,
    Room,
    Share,
    Receivers,
    Malformed,
}

/// The receivers the transmissions held cite, each as a number: its key held once, with how many
/// held receptions are its.
#[derive(Default)]
struct Interned {
    ids: BTreeMap<PublicKey, u32>,
    keys: Vec<(PublicKey, u32)>,
    free: Vec<u32>,
}

impl Interned {
    fn get(&self, key: &PublicKey) -> Option<u32> {
        self.ids.get(key).copied()
    }

    fn key(&self, id: u32) -> PublicKey {
        self.keys[id as usize].0
    }

    fn live(&self) -> usize {
        self.ids.len()
    }

    /// One more held reception of `key`: its number.
    fn take(&mut self, key: PublicKey) -> u32 {
        if let Some(id) = self.ids.get(&key).copied() {
            self.keys[id as usize].1 += 1;
            return id;
        }
        let id = match self.free.pop() {
            Some(id) => {
                self.keys[id as usize] = (key, 1);
                id
            }
            None => {
                self.keys.push((key, 1));
                (self.keys.len() - 1) as u32
            }
        };
        self.ids.insert(key, id);
        id
    }

    /// One held reception of `id` fewer.
    fn give(&mut self, id: u32) {
        let entry = &mut self.keys[id as usize];
        entry.1 -= 1;
        if entry.1 == 0 {
            self.ids.remove(&entry.0);
            self.free.push(id);
        }
    }
}

/// A reception's digest: of its receiver, counter epoch, counter and message. Its first eight
/// bytes index it ([`Book`]'s index, confirmed against the transmission it names), and all
/// sixteen remember it settled.
fn digest(receiver: &PublicKey, epoch: u32, counter: u64, message: &[u8]) -> u128 {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"tally standing reception");
    hasher.update(receiver.as_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.update(counter.to_be_bytes());
    hasher.update(message);
    let out = hasher.finalize();
    let mut first = [0u8; 16];
    first.copy_from_slice(&out[..16]);
    u128::from_be_bytes(first)
}

/// An engine's key as the book tells engines apart: its first eight bytes.
fn engine_of(key: &PublicKey) -> u64 {
    let mut first = [0u8; 8];
    first.copy_from_slice(&key.as_bytes()[..8]);
    u64::from_be_bytes(first)
}

/// One keeper's standing of every receiver, and the transmissions waiting to be settled.
pub struct Book<M> {
    receivers: BTreeMap<PublicKey, ReceiverStanding>,
    interned: Interned,
    pending: BTreeMap<u64, Transmission<M>>,
    /// Every reception a pending transmission holds, by the first eight bytes of its digest, and
    /// which: a hit is confirmed against the transmission's message and receptions.
    index: BTreeMap<u64, u64>,
    /// Pending transmissions by (earliest transmit time, number): what `settle` walks, earliest
    /// due first.
    deadlines: BTreeSet<(u64, u64)>,
    next: u64,
    /// Receptions settled, by the grid bin of their transmission's time, oldest first, each bin's
    /// digests in order: remembered [`SETTLED_SLACK_MS`] past their due time, at most
    /// `caps.settled`.
    settled: VecDeque<(u64, Vec<u128>)>,
    settled_len: usize,
    /// The latest time asked to settle by: a solution of a transmission due by it is late.
    through: Option<Judged>,
    /// Each engine's share of the transmissions held, in [`SHARE_PARTS`] of a byte: every
    /// transmission's bytes split evenly among the engines whose solutions it holds.
    sources: BTreeMap<u64, u64>,
    /// What the transmissions held take ([`Transmission::bytes_of`]).
    pending_bytes: usize,
    caps: BookCaps,
    counts: Settled,
}

/// A final weighed for [`decide`]: its receivers' standing as the book holds it when the
/// transmission is decided, never as it was when the solution arrived, so the same solutions under
/// the same book rank the same in any arrival order.
struct Weighed<'a, M> {
    held: &'a Final<M>,
    receptions: &'a [Rec],
    interned: &'a Interned,
    standing: u64,
}

impl<M: ModelRef> Weighed<'_, M> {
    /// Its receptions as the wire states them.
    fn wire(&self, at: usize) -> tally_wire::Reception {
        let rec = self.receptions[at];
        tally_wire::Reception {
            receiver: self.interned.key(rec.receiver),
            epoch: rec.epoch,
            counter: rec.counter,
        }
    }
}

impl<M: ModelRef> Candidate for Weighed<'_, M> {
    type Set = Bits;

    fn observations(&self) -> &Bits {
        &self.held.bits
    }

    fn model_inputs(&self) -> &Hash {
        self.held.model.inputs()
    }

    fn claimed(&self) -> Claimed {
        self.held.claimed
    }

    fn standing(&self) -> u64 {
        self.standing
    }

    fn weight(&self) -> u64 {
        self.held.weight
    }

    fn identity(&self) -> Hash {
        self.held.identity
    }

    /// Read once, at settling, and remembered ([`consistent`]).
    fn consistent(&self) -> bool {
        if let Some(known) = self.held.consistent.get() {
            return known;
        }
        let known = self.held.bits.ones().all(|at| {
            reception_z(
                self.held.model.model(),
                Reach::Window,
                &self.wire(at),
                &self.held.claimed,
            )
            .is_some_and(|z| z <= AGREE_Z)
        });
        self.held.consistent.set(Some(known));
        known
    }
}

impl<M: ModelRef> Book<M> {
    /// A book held to `caps` ([`BookCaps`]).
    pub fn new(caps: BookCaps) -> Self {
        Self {
            receivers: BTreeMap::new(),
            interned: Interned::default(),
            pending: BTreeMap::new(),
            index: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            next: 0,
            settled: VecDeque::new(),
            settled_len: 0,
            through: None,
            sources: BTreeMap::new(),
            pending_bytes: 0,
            caps,
            counts: Settled::default(),
        }
    }

    /// The caps from now (a keeper resized): what is held stays held (a smaller room refuses what
    /// would add to it), the settled receptions and receivers past their caps forgotten at once.
    pub fn set_caps(&mut self, caps: BookCaps) {
        self.caps = caps;
        self.forget_settled_past(None);
        self.forget_receivers_past_cap();
    }

    /// What the transmissions held take now, of `caps.pending_bytes`.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// The settled receptions remembered now.
    pub fn settled_remembered(&self) -> usize {
        self.settled_len
    }

    /// The receivers the transmissions held cite now.
    pub fn interned(&self) -> usize {
        self.interned.live()
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

    fn refuse(&mut self, why: Refused) -> Result<(), Refused> {
        let counter = match why {
            Refused::Late => &mut self.counts.late,
            Refused::Slots => &mut self.counts.slots,
            Refused::Room => &mut self.counts.room,
            Refused::Share => &mut self.counts.share,
            Refused::Receivers => &mut self.counts.receivers,
            Refused::Malformed => &mut self.counts.malformed,
        };
        *counter += 1;
        Err(why)
    }

    /// A transmission's engines' shares given back (before it changes or goes).
    fn uncharge(&mut self, number: u64) {
        let Some(held) = self.pending.get(&number) else {
            return;
        };
        let split = held.split();
        for source in held.sources() {
            if let Some(share) = self.sources.get_mut(&source) {
                *share -= split;
                if *share == 0 {
                    self.sources.remove(&source);
                }
            }
        }
    }

    /// A transmission's engines' shares taken (after it changed).
    fn charge(&mut self, number: u64) {
        let Some(held) = self.pending.get(&number) else {
            return;
        };
        let split = held.split();
        for source in held.sources() {
            *self.sources.entry(source).or_default() += split;
        }
    }

    /// The transmission held that holds `rec` (of `message`), confirmed: the index's entry for
    /// its digest's fingerprint names it, and it holds the same message and reception.
    fn holding(&self, fingerprint: u64, message: &Message, rec: Option<Rec>) -> Option<u64> {
        let number = *self.index.get(&fingerprint)?;
        let held = self.pending.get(&number)?;
        (held.message == *message && rec.is_some_and(|rec| held.receptions.contains(&rec)))
            .then_some(number)
    }

    /// A solution the keeper took ([`Solved::new`]): held with every other solution of its
    /// transmission until it is settled, [`SETTLE`] after the transmission, or refused and
    /// counted ([`Refused`]); nothing held is ever let go for it. When it arrived decides nothing.
    /// It reads nothing of the solution's consistency: that is settling's.
    pub fn add(&mut self, solved: Solved<M>) -> Result<(), Refused> {
        let earliest_ms = solved.claimed.transmitted.unix_ms;
        // Its transmission is due already: every final fix of it has surely come, and it is late.
        if self
            .through
            .is_some_and(|through| SETTLE.settled(earliest_ms, through))
        {
            return self.refuse(Refused::Late);
        }
        let Some(message) = Message::of(solved.observations.message()) else {
            return self.refuse(Refused::Malformed);
        };
        let engine = engine_of(solved.model.engine());
        let wire = solved.observations.receptions();
        if wire.len() > RECEPTIONS_MOST {
            return self.refuse(Refused::Slots);
        }
        let digests: Vec<u128> = wire
            .iter()
            .map(|one| digest(&one.receiver, one.epoch, one.counter, message.as_slice()))
            .collect();
        let rec_of = |interned: &Interned, one: &tally_wire::Reception| {
            interned.get(&one.receiver).map(|receiver| Rec {
                receiver,
                epoch: one.epoch,
                counter: one.counter,
            })
        };
        let joined: BTreeSet<u64> = wire
            .iter()
            .zip(&digests)
            .filter_map(|(one, digest)| {
                self.holding(*digest as u64, &message, rec_of(&self.interned, one))
            })
            .collect();
        let number = match joined.first().copied() {
            Some(first) => {
                // Joining two held transmissions makes them one.
                for other in joined.iter().skip(1) {
                    self.merge(first, *other);
                }
                first
            }
            None => {
                let number = self.next;
                self.next += 1;
                let mut held = Transmission {
                    earliest_ms,
                    message,
                    receptions: Vec::new(),
                    finals: Vec::new(),
                    provisionals: Vec::new(),
                    bytes: 0,
                };
                held.bytes = held.bytes_of();
                if self.pending_bytes + held.bytes > self.caps.pending_bytes {
                    return self.refuse(Refused::Room);
                }
                self.pending_bytes += held.bytes;
                self.pending.insert(number, held);
                self.deadlines.insert((earliest_ms, number));
                number
            }
        };
        let result = self.add_to(number, engine, &solved, &digests);
        // A transmission made for a solution refused holds nothing: let go.
        if self
            .pending
            .get(&number)
            .is_some_and(|held| held.finals.is_empty() && held.provisionals.is_empty())
            && let Some(gone) = self.pending.remove(&number)
        {
            self.deadlines.remove(&(gone.earliest_ms, number));
            self.let_go(number, &gone);
        }
        result
    }

    /// `solved` into held transmission `number` (whose receptions' digests are `digests`), or
    /// refused: a slot its engine's kind holds over other receptions, past [`SOLUTIONS_MOST`] or
    /// [`RECEPTIONS_MOST`], the receivers' cap, the room or its engine's share.
    fn add_to(
        &mut self,
        number: u64,
        engine: u64,
        solved: &Solved<M>,
        digests: &[u128],
    ) -> Result<(), Refused> {
        let Some(held) = self.pending.get_mut(&number) else {
            return Err(Refused::Malformed);
        };
        // One of each engine's kind: the same again (or another engine's of the same inputs)
        // only keeps the earlier issue time.
        let wire = solved.observations.receptions();
        let known = Self::known_bits(held, &self.interned, wire);
        if solved.provisional {
            if let Some(same) = held
                .provisionals
                .iter_mut()
                .find(|one| one.engine == engine)
            {
                return if known == Some(same.bits)
                    && same.transmitted_ms == solved.claimed.transmitted.unix_ms
                    && Some(same.consistent) == solved.consistent
                {
                    same.issued_ms = same.issued_ms.min(solved.issued_ms);
                    Ok(())
                } else {
                    self.refuse(Refused::Slots)
                };
            }
        } else {
            if let Some(same) = held
                .finals
                .iter_mut()
                .find(|one| one.identity == solved.identity)
            {
                same.issued_ms = same.issued_ms.min(solved.issued_ms);
                return Ok(());
            }
            if held.finals.iter().any(|one| one.engine == engine) {
                return self.refuse(Refused::Slots);
            }
        }
        if held.finals.len() + held.provisionals.len() >= SOLUTIONS_MOST {
            return self.refuse(Refused::Slots);
        }
        // Its receptions new to the transmission, and the receivers new to the book.
        let mut new: Vec<usize> = Vec::new();
        let mut new_receivers: BTreeSet<PublicKey> = BTreeSet::new();
        for (at, one) in wire.iter().enumerate() {
            let known = self.interned.get(&one.receiver).is_some_and(|receiver| {
                held.receptions.contains(&Rec {
                    receiver,
                    epoch: one.epoch,
                    counter: one.counter,
                })
            });
            if !known {
                new.push(at);
                if self.interned.get(&one.receiver).is_none() {
                    new_receivers.insert(one.receiver);
                }
            }
        }
        if held.receptions.len() + new.len() > RECEPTIONS_MOST {
            return self.refuse(Refused::Slots);
        }
        if self.interned.live() + new_receivers.len() > self.caps.receivers {
            return self.refuse(Refused::Receivers);
        }
        // What it would take, each list grown to exactly its length.
        let (finals, provisionals) = if solved.provisional {
            (held.finals.len(), held.provisionals.len() + 1)
        } else {
            (held.finals.len() + 1, held.provisionals.len())
        };
        let receptions = held.receptions.len() + new.len();
        let after = transmission_entry_bytes::<M>()
            + tally_wire::footprint::vec::<Rec>(held.receptions.capacity().max(receptions))
            + receptions * INDEX_ENTRY_BYTES
            + tally_wire::footprint::vec::<Final<M>>(held.finals.capacity().max(finals))
            + tally_wire::footprint::vec::<Provisional>(
                held.provisionals.capacity().max(provisionals),
            );
        let grows = after.saturating_sub(held.bytes);
        if self.pending_bytes + grows > self.caps.pending_bytes {
            return self.refuse(Refused::Room);
        }
        // Its engine's share once it holds it: the transmission's bytes split again among its
        // engines, this one among them.
        let mut sources = held.sources();
        let had = sources.contains(&engine);
        let before = if had { held.split() } else { 0 };
        if !had {
            sources.push(engine);
        }
        let share_after = after as u64 * SHARE_PARTS / sources.len() as u64;
        let mine = self.sources.get(&engine).copied().unwrap_or(0) - before + share_after;
        if mine > self.caps.source_share as u64 * SHARE_PARTS {
            return self.refuse(Refused::Share);
        }
        // Held: nothing below refuses.
        self.uncharge(number);
        let Some(held) = self.pending.get_mut(&number) else {
            return Err(Refused::Malformed);
        };
        held.receptions.reserve_exact(new.len());
        for at in &new {
            let one = wire[*at];
            let receiver = self.interned.take(one.receiver);
            held.receptions.push(Rec {
                receiver,
                epoch: one.epoch,
                counter: one.counter,
            });
            let fingerprint = digests[*at] as u64;
            self.index.entry(fingerprint).or_insert(number);
        }
        let bits = Self::known_bits(held, &self.interned, wire).unwrap_or_default();
        if solved.provisional {
            held.provisionals.reserve_exact(1);
            held.provisionals.push(Provisional {
                engine,
                issued_ms: solved.issued_ms,
                transmitted_ms: solved.claimed.transmitted.unix_ms,
                consistent: solved.consistent.unwrap_or(false),
                bits,
            });
        } else {
            held.finals.reserve_exact(1);
            held.finals.push(Final {
                engine,
                issued_ms: solved.issued_ms,
                claimed: solved.claimed,
                identity: solved.identity,
                weight: solved.weight,
                model: solved.model.clone(),
                bits,
                consistent: std::cell::Cell::new(None),
            });
        }
        let earliest_ms = solved.claimed.transmitted.unix_ms;
        if earliest_ms < held.earliest_ms {
            self.deadlines.remove(&(held.earliest_ms, number));
            held.earliest_ms = earliest_ms;
            self.deadlines.insert((earliest_ms, number));
        }
        let bytes = held.bytes_of();
        self.pending_bytes = self.pending_bytes - held.bytes + bytes;
        held.bytes = bytes;
        self.charge(number);
        Ok(())
    }

    /// A solution's receptions as a set of a held transmission's, when it holds every one.
    fn known_bits(
        held: &Transmission<M>,
        interned: &Interned,
        wire: &[tally_wire::Reception],
    ) -> Option<Bits> {
        let mut bits = Bits::default();
        for one in wire {
            let receiver = interned.get(&one.receiver)?;
            let at = held.receptions.iter().position(|rec| {
                *rec == Rec {
                    receiver,
                    epoch: one.epoch,
                    counter: one.counter,
                }
            })?;
            bits.0 |= 1 << at;
        }
        Some(bits)
    }

    /// Held transmission `other` into `into`: they share a reception, so they are one. Its
    /// receptions join `into`'s (each solution's set mapped to them); a solution of a kind an
    /// engine holds in `into` already, or one past the slots, is let go, counted.
    fn merge(&mut self, into: u64, other: u64) {
        self.uncharge(into);
        self.uncharge(other);
        let Some(gone) = self.pending.remove(&other) else {
            self.charge(into);
            return;
        };
        self.deadlines.remove(&(gone.earliest_ms, other));
        self.pending_bytes -= gone.bytes;
        let Some(kept) = self.pending.get_mut(&into) else {
            return;
        };
        // Its receptions' places in the kept transmission, each added where it is new and room
        // is left.
        let mut place: Vec<Option<usize>> = Vec::with_capacity(gone.receptions.len());
        let mut moved_out = 0;
        // Each list grown to exactly what it takes, so the one held takes no more than the two.
        kept.receptions.reserve_exact(gone.receptions.len());
        kept.finals.reserve_exact(gone.finals.len());
        kept.provisionals.reserve_exact(gone.provisionals.len());
        for rec in &gone.receptions {
            match kept.receptions.iter().position(|kept| kept == rec) {
                Some(at) => {
                    // The same reception twice: its receiver's count once.
                    self.interned.give(rec.receiver);
                    place.push(Some(at));
                }
                None if kept.receptions.len() < RECEPTIONS_MOST => {
                    kept.receptions.push(*rec);
                    place.push(Some(kept.receptions.len() - 1));
                }
                None => place.push(None),
            }
        }
        let remap = |bits: Bits| -> Option<Bits> {
            let mut out = Bits::default();
            for at in bits.ones() {
                out.0 |= 1 << place[at]?;
            }
            Some(out)
        };
        let slots = |kept: &Transmission<M>| kept.finals.len() + kept.provisionals.len();
        for one in gone.finals {
            let fits = !kept.finals.iter().any(|held| held.engine == one.engine)
                && slots(kept) < SOLUTIONS_MOST;
            match remap(one.bits).filter(|_| fits) {
                Some(bits) => kept.finals.push(Final { bits, ..one }),
                None => moved_out += 1,
            }
        }
        for one in gone.provisionals {
            let fits = !kept
                .provisionals
                .iter()
                .any(|held| held.engine == one.engine)
                && slots(kept) < SOLUTIONS_MOST;
            match remap(one.bits).filter(|_| fits) {
                Some(bits) => kept.provisionals.push(Provisional { bits, ..one }),
                None => moved_out += 1,
            }
        }
        // Receptions past the room no solution kept cites: their receivers given back, their
        // index entries let go.
        for (rec, at) in gone.receptions.iter().zip(&place) {
            if at.is_none() {
                self.interned.give(rec.receiver);
            }
        }
        let before = kept.earliest_ms;
        kept.earliest_ms = kept.earliest_ms.min(gone.earliest_ms);
        let after = kept.earliest_ms;
        let message = kept.message;
        let keys: Vec<(u128, bool)> = kept
            .receptions
            .iter()
            .map(|rec| {
                (
                    digest(
                        &self.interned.key(rec.receiver),
                        rec.epoch,
                        rec.counter,
                        message.as_slice(),
                    ),
                    true,
                )
            })
            .collect();
        self.pending_bytes -= kept.bytes;
        kept.bytes = kept.bytes_of();
        self.pending_bytes += kept.bytes;
        self.deadlines.remove(&(before, into));
        self.deadlines.insert((after, into));
        for (digest, _) in keys {
            let fingerprint = digest as u64;
            match self.index.get(&fingerprint) {
                Some(number) if *number == other => {
                    self.index.insert(fingerprint, into);
                }
                None => {
                    self.index.insert(fingerprint, into);
                }
                _ => {}
            }
        }
        // Entries still naming the gone transmission (its receptions past the room) go.
        self.index.retain(|_, number| *number != other);
        self.counts.merged_out += moved_out;
        self.charge(into);
    }

    /// A transmission no longer held: its index entries, its receivers, its bytes and its
    /// engines' shares (`gone` already out of `pending`).
    fn let_go(&mut self, number: u64, gone: &Transmission<M>) {
        let split = gone.split();
        for source in gone.sources() {
            if let Some(share) = self.sources.get_mut(&source) {
                *share -= split;
                if *share == 0 {
                    self.sources.remove(&source);
                }
            }
        }
        for rec in &gone.receptions {
            let fingerprint = digest(
                &self.interned.key(rec.receiver),
                rec.epoch,
                rec.counter,
                gone.message.as_slice(),
            ) as u64;
            if self.index.get(&fingerprint) == Some(&number) {
                self.index.remove(&fingerprint);
            }
            self.interned.give(rec.receiver);
        }
        self.pending_bytes -= gone.bytes;
    }

    /// Whether a reception (by its digest) was settled already.
    fn was_settled(&self, digest: u128) -> bool {
        self.settled
            .iter()
            .any(|(_, digests)| digests.binary_search(&digest).is_ok())
    }

    /// A reception (by its digest) settled for a transmission at `at_ms`.
    fn remember(&mut self, digest: u128, at_ms: u64) {
        let bin = at_ms / crate::scope::GRID_MS;
        let at = match self.settled.binary_search_by_key(&bin, |(bin, _)| *bin) {
            Ok(at) => at,
            Err(at) => {
                self.settled.insert(at, (bin, Vec::new()));
                at
            }
        };
        let digests = &mut self.settled[at].1;
        if let Err(place) = digests.binary_search(&digest) {
            digests.insert(place, digest);
            self.settled_len += 1;
        }
    }

    /// Forgets the settled receptions no solution may still find (`SETTLED_SLACK_MS` past their
    /// due time by `through`), a bin at a time, and the oldest past `caps.settled`.
    fn forget_settled_past(&mut self, through: Option<Judged>) {
        if let Some(through) = through {
            // No earlier than the slack before the earliest transmission still held, so a held
            // one settled late (in pieces) still finds what was settled beside it.
            let held = self.deadlines.first().map_or(u64::MAX, |(earliest_ms, _)| {
                earliest_ms.saturating_sub(SETTLED_SLACK_MS)
            });
            let horizon = through
                .ms()
                .saturating_sub(SETTLE.span::<Judged>().ms() + SETTLED_SLACK_MS)
                .min(held);
            while let Some((bin, digests)) = self.settled.front() {
                // A bin goes once every time in it is before the horizon.
                if (bin + 1) * crate::scope::GRID_MS > horizon {
                    break;
                }
                self.settled_len -= digests.len();
                self.settled.pop_front();
            }
        }
        // Past the cap the oldest bin goes whole, so no list is left holding room it no longer
        // fills.
        while self.settled_len > self.caps.settled {
            let Some((_, digests)) = self.settled.pop_front() else {
                break;
            };
            self.settled_len -= digests.len();
        }
    }

    /// Forgets the receiver counted longest ago, then the lowest key, past `caps.receivers`.
    fn forget_receivers_past_cap(&mut self) {
        while self.receivers.len() > self.caps.receivers {
            let Some(oldest) = self
                .receivers
                .iter()
                .min_by_key(|(key, standing)| (standing.newest().unwrap_or(0), **key))
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.receivers.remove(&oldest);
        }
    }

    /// Settles every transmission [`SETTLE`] or more before the keeper's judging clock `now` (by
    /// its transmit time).
    /// `heard` is the signed wall clock of the batch that carried a reception (given with its
    /// transmission's transmit time, Unix milliseconds), when the keeper holds it in its
    /// receiver's own signed raw (the earliest of copies). The receivers whose standing changed,
    /// so a keeper that ranks by it ranks again.
    pub fn settle(
        &mut self,
        now: Judged,
        heard: impl Fn(&ObservationId, u64) -> Option<u64>,
    ) -> BTreeSet<PublicKey> {
        self.settle_up_to(now, heard, usize::MAX).0
    }

    /// As `settle`, `work` of work at most (each transmission's receptions weighed under each of
    /// its finals, and once more, `Transmission::work`), and at least one transmission, earliest
    /// due first, and whether any due by `now` is left: a keeper that settles in pieces holds
    /// what it shares for one piece at a time, however many transmissions fall due at once, and
    /// settles the same transmissions in the same order as at once.
    pub fn settle_up_to(
        &mut self,
        now: Judged,
        heard: impl Fn(&ObservationId, u64) -> Option<u64>,
        work: usize,
    ) -> (BTreeSet<PublicKey>, bool) {
        let mut changed = BTreeSet::new();
        let mut done = 0usize;
        // From now a solution of a transmission due by `now` is late (`Book::add`), whether or not
        // it is settled in this piece.
        self.through = self.through.max(Some(now));
        while let Some(&(earliest_ms, number)) = self.deadlines.first() {
            if !SETTLE.settled(earliest_ms, now) {
                break;
            }
            let cost = self.pending.get(&number).map_or(1, Transmission::work);
            if done > 0 && done.saturating_add(cost) > work {
                self.forget_settled_past(self.through);
                return (changed, true);
            }
            done = done.saturating_add(cost);
            self.deadlines.remove(&(earliest_ms, number));
            let Some(pending) = self.pending.remove(&number) else {
                continue;
            };
            self.settle_one(&pending, &heard, &mut changed);
            self.let_go(number, &pending);
        }
        self.forget_settled_past(self.through);
        (changed, false)
    }

    fn settle_one(
        &mut self,
        pending: &Transmission<M>,
        heard: &impl Fn(&ObservationId, u64) -> Option<u64>,
        changed: &mut BTreeSet<PublicKey>,
    ) {
        // Weighed by standing as the book holds it now, whatever it was when each arrived.
        let weighed: Vec<Weighed<'_, M>> = pending
            .finals
            .iter()
            .map(|held| Weighed {
                held,
                receptions: &pending.receptions,
                interned: &self.interned,
                standing: held
                    .bits
                    .ones()
                    .map(|at| {
                        self.weight(
                            &self.interned.key(pending.receptions[at].receiver),
                            held.claimed.transmitted,
                        )
                    })
                    .sum(),
            })
            .collect();
        let decision = decide(&weighed);
        let Some(&answer) = decision.ranked.iter().find(|&&at| weighed[at].consistent()) else {
            return;
        };
        let fix = &weighed[answer];
        let claimed = fix.held.claimed;
        let period = period_of(claimed.transmitted.unix_ms);
        let message = pending.message.as_slice();
        let can_earn = eligible(message, claimed.transmitted);
        // The earliest solutions, by signed issue time, of those consistent with their own
        // receptions: one signed before its own transmission says nothing true about time and is
        // not counted.
        let possible: Vec<(u64, Bits)> = weighed
            .iter()
            .filter(|one| {
                one.consistent() && one.held.issued_ms >= one.held.claimed.transmitted.unix_ms
            })
            .map(|one| (one.held.issued_ms, one.held.bits))
            .chain(
                pending
                    .provisionals
                    .iter()
                    .filter(|one| one.consistent && one.issued_ms >= one.transmitted_ms)
                    .map(|one| (one.issued_ms, one.bits)),
            )
            .collect();
        let earliest_ms = possible.iter().map(|(issued, _)| *issued).min();
        let earliest = possible
            .iter()
            .filter(|(issued, _)| Some(*issued) == earliest_ms)
            .fold(0u64, |bits, (_, one)| bits | one.0);
        // Each reception cited, and whether only refused finals cite it.
        let mut cited: Vec<Option<bool>> = vec![None; pending.receptions.len()];
        for (at, one) in weighed.iter().enumerate() {
            let refused = decision.refused(at);
            for reception in one.held.bits.ones() {
                let entry = cited[reception].get_or_insert(true);
                *entry &= refused;
            }
        }
        for one in &pending.provisionals {
            for reception in one.bits.ones() {
                cited[reception] = Some(false);
            }
        }
        let hash = message_hash(message);
        let model = fix.held.model.clone();
        drop(weighed);
        self.counts.transmissions += 1;
        let at = claimed.transmitted.unix_ms;
        for (place, only_refused) in cited.into_iter().enumerate() {
            let Some(only_refused) = only_refused else {
                continue;
            };
            let rec = pending.receptions[place];
            let receiver = self.interned.key(rec.receiver);
            let id = ObservationId {
                receiver,
                epoch: rec.epoch,
                timestamp: rec.counter,
                message: hash,
            };
            let Some(heard_ms) = heard(&id, at) else {
                continue;
            };
            let settled = digest(&receiver, rec.epoch, rec.counter, message);
            if self.was_settled(settled) {
                continue;
            }
            let reception = tally_wire::Reception {
                receiver,
                epoch: rec.epoch,
                counter: rec.counter,
            };
            let verdict = match reception_z(model.model(), Reach::Window, &reception, &claimed) {
                Some(z) if z <= AGREE_Z => {
                    self.counts.agreed += 1;
                    let arrived_first =
                        earliest & (1 << place) != 0 && earliest_ms.is_some_and(|ms| heard_ms < ms);
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
            self.remember(settled, at);
            changed.insert(receiver);
            self.receivers
                .entry(receiver)
                .or_default()
                .observe(period, agreed);
        }
        self.forget_settled_past(None);
        self.forget_receivers_past_cap();
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
        type Set = ObservationSet;

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

    /// A model held as a book cites one: the model, its inputs and its engine.
    #[derive(Clone)]
    struct Cited(std::sync::Arc<ClockModel>, Hash, PublicKey);

    impl ModelRef for Cited {
        fn model(&self) -> &ClockModel {
            &self.0
        }
        fn inputs(&self) -> &Hash {
            &self.1
        }
        fn engine(&self) -> &PublicKey {
            &self.2
        }
    }

    /// A model of nothing, signed by engine `engine`, for a book's solutions to cite: its lists
    /// empty.
    fn empty_model(engine: u8) -> Cited {
        Cited(
            std::sync::Arc::new(ClockModel {
                spec: crate::SPEC_VERSION,
                tile: crate::tile::Tile {
                    level: 0,
                    cube: [0; 3],
                },
                window: crate::scope::Window { first: 0, last: 0 },
                scope: Vec::new(),
                input: crate::scope::Citation {
                    hash: [7; 32],
                    count: 3,
                },
                gauge: crate::clock::ClockKey {
                    receiver: key(1),
                    epoch: 1,
                    piece: 0,
                },
                origin_unix_ns: 0,
                gauge_rate: 0,
                pieces: Vec::new(),
                biases: Vec::new(),
                jumps: Vec::new(),
                dropped: Vec::new(),
            }),
            [engine; 32],
            key(200 + engine),
        )
    }

    /// A final solution of the receivers `seeds` heard, of a transmission at `at_ms`.
    fn solved(seeds: &[u8], at_ms: u64, model: &Cited) -> Solved<Cited> {
        let item = item(seeds, 0.0, model.1[0], 0);
        let mut claimed = item.claimed;
        claimed.transmitted = TransmitTime {
            unix_ms: at_ms,
            sub_ms_ps: 0,
        };
        Solved {
            provisional: false,
            issued_ms: at_ms + 1_000,
            claimed,
            weight: seeds.len() as u64,
            identity: item.identity,
            observations: item.observations,
            model: model.clone(),
            consistent: None,
        }
    }

    /// A provisional of the same.
    fn provisional(seeds: &[u8], at_ms: u64, model: &Cited) -> Solved<Cited> {
        Solved {
            provisional: true,
            consistent: Some(true),
            ..solved(seeds, at_ms, model)
        }
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "a test's scripted readings: the book is judged at the times it is told"
    )]
    fn judged_at(ms: u64) -> Judged {
        tally_wire::clocks::recorded::judged(ms)
    }

    fn caps(pending_bytes: usize, settled: usize) -> BookCaps {
        BookCaps {
            pending_bytes,
            source_share: pending_bytes,
            receivers: 64,
            settled,
        }
    }

    /// A solution of a transmission already due when it comes is refused as late, counted, and
    /// holds nothing: every final fix of it has surely come (`SETTLE`). Before, it was held and
    /// settled again, and the receptions settled once were remembered half an hour to refuse it.
    #[test]
    fn a_solution_of_a_transmission_already_due_is_refused_as_late() {
        let model = empty_model(1);
        let mut book = Book::new(caps(1 << 20, 1_024));
        let at = AT.unix_ms;
        let due = at + SETTLE.span::<Judged>().ms();
        let _ = book.settle(judged_at(due), |_, _| None);
        assert_eq!(book.add(solved(&[1, 2, 3], at, &model)), Err(Refused::Late));
        assert_eq!(book.counts().late, 1);
        assert_eq!((book.pending(), book.pending_bytes()), (0, 0));
        // One not yet due is held.
        assert_eq!(book.add(solved(&[1, 2, 3], at + 1, &model)), Ok(()));
        assert_eq!(book.pending(), 1);
        assert_eq!(book.counts().late, 1);
    }

    /// The receptions settled are remembered only while a solution may still find them: let go
    /// once `SETTLED_SLACK_MS` past their due time, never before the slack ahead of a
    /// transmission still held, and the oldest past the cap at once. Before, every reception
    /// settled was remembered three ten-minute periods.
    #[test]
    fn settled_receptions_are_let_go_past_the_slack_and_past_the_cap() {
        // At the start of a grid bin, so the bin is let go as its time is.
        let at = AT.unix_ms - AT.unix_ms % crate::scope::GRID_MS;
        let remember = |book: &mut Book<Cited>, seeds: &[u8], at_ms: u64| {
            for seed in seeds {
                book.remember(u128::from(*seed), at_ms);
            }
        };
        let mut book = Book::new(caps(1 << 20, 1_024));
        remember(&mut book, &[1, 2, 3], at);
        let due = at + SETTLE.span::<Judged>().ms();
        let horizon = due + SETTLED_SLACK_MS + crate::scope::GRID_MS;
        let _ = book.settle(judged_at(horizon - 1), |_, _| None);
        assert_eq!(book.settled_remembered(), 3, "within the slack");
        let _ = book.settle(judged_at(horizon), |_, _| None);
        assert_eq!(book.settled_remembered(), 0, "past the slack");
        // A transmission still held keeps what was settled within the slack before it.
        let mut held = Book::new(caps(1 << 20, 1_024));
        remember(&mut held, &[1, 2, 3], at);
        let model = empty_model(1);
        assert_eq!(held.add(solved(&[4, 5, 6], at + 10, &model)), Ok(()));
        // A piece settles one at least: the earlier goes, the later stays held.
        assert_eq!(held.add(solved(&[7, 8, 9], at + 5, &model)), Ok(()));
        let _ = held.settle_up_to(judged_at(horizon), |_, _| None, 0);
        assert_eq!(held.settled_remembered(), 3);
        // Past the cap, the oldest bin goes at once.
        let mut capped = Book::new(caps(1 << 20, 4));
        remember(&mut capped, &[1, 2, 3], at);
        remember(&mut capped, &[4, 5], at + crate::scope::GRID_MS);
        capped.set_caps(caps(1 << 20, 4));
        assert_eq!(capped.settled_remembered(), 2);
    }

    /// The transmissions held take no more than the book's room: past it a solution is refused,
    /// counted, and nothing held is let go for it. Settled, everything is given back.
    #[test]
    fn the_transmissions_held_stay_within_the_books_room() {
        let model = empty_model(1);
        let mut roomy = Book::new(caps(1 << 20, 1_024));
        assert_eq!(roomy.add(solved(&[1, 2, 3], AT.unix_ms, &model)), Ok(()));
        let one = roomy.pending_bytes();
        assert_eq!(
            one,
            transmission_bytes_most::<Cited>(1, 0, 3),
            "a transmission takes what the plan says"
        );
        let mut book = Book::new(caps(2 * one, 1_024));
        for n in 0..10u8 {
            let added = book.add(solved(
                &[3 * n + 1, 3 * n + 2, 3 * n + 3],
                AT.unix_ms + u64::from(n),
                &model,
            ));
            assert_eq!(added.is_ok(), n < 2, "{n}");
            assert!(book.pending_bytes() <= 2 * one, "{}", book.pending_bytes());
        }
        assert_eq!(book.pending(), 2);
        assert_eq!(book.counts().room, 8);
        // Settled, everything is given back.
        let _ = book.settle(judged_at(AT.unix_ms + 60_000_000), |_, _| None);
        assert_eq!(
            (book.pending(), book.pending_bytes(), book.interned()),
            (0, 0, 0)
        );
    }

    /// A transmission holds one final and one provisional of each engine, and at most
    /// `SOLUTIONS_MOST`: a second of one engine's kind over other receptions is refused, counted,
    /// and the same again only keeps the earlier issue time. Each solution's receptions are a set
    /// of the transmission's, held once.
    #[test]
    fn a_transmission_holds_one_solution_of_each_engines_kind() {
        let mut book = Book::new(caps(1 << 20, 1_024));
        let at = AT.unix_ms;
        let engines: Vec<Cited> = (1..=4).map(empty_model).collect();
        assert_eq!(book.add(solved(&[1, 2, 3], at, &engines[0])), Ok(()));
        assert_eq!(book.add(solved(&[1, 2, 3], at, &engines[0])), Ok(()));
        assert_eq!(
            book.add(solved(&[1, 2, 3, 4], at, &engines[0])),
            Err(Refused::Slots)
        );
        assert_eq!(
            book.add(provisional(&[1, 2, 3, 4], at, &engines[0])),
            Ok(())
        );
        assert_eq!(book.add(solved(&[2, 3, 4, 5], at, &engines[1])), Ok(()));
        assert_eq!(book.add(provisional(&[2, 3, 5], at, &engines[1])), Ok(()));
        assert_eq!(book.add(solved(&[1, 3, 5], at, &engines[2])), Ok(()));
        assert_eq!(book.add(provisional(&[1, 3, 5], at, &engines[2])), Ok(()));
        // Six held: a fourth engine's is past the slots.
        assert_eq!(
            book.add(solved(&[1, 2, 5], at, &engines[3])),
            Err(Refused::Slots)
        );
        assert_eq!((book.pending(), book.counts().slots), (1, 2));
        let held = book
            .pending
            .values()
            .next()
            .map(|held| held.receptions.len());
        assert_eq!(held, Some(5), "every distinct reception once");
        assert_eq!(
            book.pending_bytes(),
            transmission_bytes_most::<Cited>(3, 3, 5)
        );
    }

    /// No engine takes more than its share of the room: past it its solutions are refused,
    /// counted, and another engine's transmissions are never let go for it.
    #[test]
    fn an_engine_past_its_share_is_refused_and_takes_nothing_of_another() {
        let one = transmission_bytes_most::<Cited>(1, 0, 3);
        let mut book = Book::new(BookCaps {
            pending_bytes: 10 * one,
            source_share: 3 * one,
            receivers: 64,
            settled: 1_024,
        });
        let (flood, honest) = (empty_model(1), empty_model(2));
        for n in 0..6u8 {
            let added = book.add(solved(
                &[3 * n + 1, 3 * n + 2, 3 * n + 3],
                AT.unix_ms + u64::from(n),
                &flood,
            ));
            assert_eq!(added.is_ok(), n < 3, "{n}");
        }
        assert_eq!(book.counts().share, 3);
        for n in 0..3u8 {
            let seeds = [100 + 3 * n, 101 + 3 * n, 102 + 3 * n];
            assert_eq!(
                book.add(solved(&seeds, AT.unix_ms + 100 + u64::from(n), &honest)),
                Ok(())
            );
        }
        assert_eq!(book.pending(), 6);
    }

    /// Taking a final in reads nothing of its consistency: it is read once, when its transmission
    /// is settled.
    #[test]
    fn a_finals_consistency_is_read_at_settling_not_as_it_is_taken() {
        let model = empty_model(1);
        let mut book = Book::new(caps(1 << 20, 1_024));
        assert_eq!(book.add(solved(&[1, 2, 3], AT.unix_ms, &model)), Ok(()));
        let read = |book: &Book<Cited>| {
            book.pending
                .values()
                .flat_map(|held| held.finals.iter().map(|one| one.consistent.get()))
                .collect::<Vec<_>>()
        };
        assert_eq!(read(&book), vec![None]);
        let _ = book.settle(judged_at(AT.unix_ms + 60_000_000), |_, _| None);
        // A model of nothing maps no reception: inconsistent, settled as no answer.
        assert_eq!(book.counts().transmissions, 0);
    }

    /// Settling in pieces is held to its work, not its transmissions: a piece weighs each
    /// transmission's receptions under each of its finals, and stops once the next would pass
    /// the piece, at least one a piece. The same transmissions settle in the same order as at once.
    #[test]
    fn settling_in_pieces_is_held_to_its_work() {
        let engines: Vec<Cited> = (1..=3).map(empty_model).collect();
        let mut book = Book::new(caps(1 << 20, 1_024));
        for n in 0..4u8 {
            let seeds = [4 * n + 1, 4 * n + 2, 4 * n + 3, 4 * n + 4];
            for engine in &engines {
                assert_eq!(
                    book.add(solved(&seeds, AT.unix_ms + u64::from(n), engine)),
                    Ok(())
                );
            }
        }
        let work = 4 * (1 + 3) + 1;
        let late = judged_at(AT.unix_ms + 60_000_000);
        let (_, left) = book.settle_up_to(late, |_, _| None, 2 * work);
        assert!(left);
        assert_eq!(book.pending(), 2);
        let (_, left) = book.settle_up_to(late, |_, _| None, 1);
        assert!(left, "one at least a piece");
        assert_eq!(book.pending(), 1);
        let (_, left) = book.settle_up_to(late, |_, _| None, usize::MAX);
        assert!(!left);
        assert_eq!((book.pending(), book.pending_bytes()), (0, 0));
    }

    /// Two transmissions a solution joins are one: their receptions held once, each solution's set
    /// mapped to them, every index entry naming the one kept.
    #[test]
    fn a_solution_joining_two_transmissions_makes_them_one() {
        let (a, b, c) = (empty_model(1), empty_model(2), empty_model(3));
        let mut book = Book::new(caps(1 << 20, 1_024));
        assert_eq!(book.add(solved(&[1, 2, 3], AT.unix_ms, &a)), Ok(()));
        assert_eq!(book.add(solved(&[4, 5, 6], AT.unix_ms, &b)), Ok(()));
        assert_eq!(book.pending(), 2);
        assert_eq!(book.add(solved(&[3, 4, 7], AT.unix_ms, &c)), Ok(()));
        assert_eq!(book.pending(), 1);
        assert_eq!(
            book.pending_bytes(),
            transmission_bytes_most::<Cited>(3, 0, 7)
        );
        let kept = *book.pending.keys().next().unwrap_or(&u64::MAX);
        assert_eq!(book.index.len(), 7);
        assert!(book.index.values().all(|number| *number == kept));
        let _ = book.settle(judged_at(AT.unix_ms + 60_000_000), |_, _| None);
        assert_eq!(
            (book.pending_bytes(), book.interned(), book.index.len()),
            (0, 0, 0)
        );
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

    /// A receiver's ring of periods scores what a tree of every period counted within the horizon
    /// of the newest scored (the shape it replaced, kept here as the reference): periods advancing
    /// by steps and by jumps past the horizon, some counted late, some past the horizon.
    #[test]
    fn the_ring_of_periods_scores_what_every_period_counted_scored() {
        let reference_score = |periods: &BTreeMap<u64, Tally>, period: u64| -> i64 {
            let mut score: i64 = 0;
            for (at, tally) in periods.range(..=period) {
                let age = period - at;
                if age >= HORIZON_PERIODS {
                    continue;
                }
                let shift = age / HALF_LIFE_PERIODS;
                let net = i64::from(tally.agreed.min(EARN_PER_PERIOD))
                    - i64::from(tally.disagreed) * DISAGREE_COST;
                score += if net >= 0 {
                    net >> shift
                } else {
                    -((-net) >> shift)
                };
            }
            score.clamp(-FULL, FULL)
        };
        let mut ring = ReceiverStanding::NEW;
        let mut tree: BTreeMap<u64, Tally> = BTreeMap::new();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut period = 5_000u64;
        for _ in 0..20_000 {
            let draw = next();
            period += match draw % 100 {
                0 => HORIZON_PERIODS + draw % 300,
                1..=9 => draw % 40,
                _ => u64::from(draw % 3 == 0),
            };
            // Now and then a late count, sometimes past the horizon.
            let at = if draw % 17 == 0 {
                period.saturating_sub(draw % (HORIZON_PERIODS + 200))
            } else {
                period
            };
            let agreed = draw % 5 != 0;
            ring.observe(at, agreed);
            let tally = tree.entry(at).or_default();
            if agreed {
                tally.agreed += 1;
            } else {
                tally.disagreed += 1;
            }
            let newest = tree.keys().next_back().copied().unwrap_or(at);
            tree = tree.split_off(&newest.saturating_sub(HORIZON_PERIODS));
            for asked in [period, period + 1, period + HALF_LIFE_PERIODS, at] {
                assert_eq!(
                    ring.score(asked),
                    reference_score(&tree, asked),
                    "at {asked}"
                );
            }
        }
        assert_eq!(ring.newest(), tree.keys().next_back().copied());
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
        let mut book: Book<Cited> = Book::new(BookCaps {
            pending_bytes: 1 << 20,
            source_share: 1 << 20,
            receivers: 16,
            settled: 16,
        });
        let earn = |book: &mut Book<Cited>, seed: u8| {
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
