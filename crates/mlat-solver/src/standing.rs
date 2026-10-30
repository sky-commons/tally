//! Receiver standing (RFC-0174 §2.12), the rule: from public signed data alone (receivers' signed
//! batches, engines' signed clock models and fixes), how far each receiver's receptions are to be
//! believed, and when a bigger answer may replace a smaller one. Every party that reads the same
//! records computes the same standing, so it is never on the wire. Relays (`tally-relay`'s
//! `standing`), which hold those records, keep a [`Book`] of it; relays and clients (`tally-merge`)
//! both decide which of one transmission's fixes stands by [`decide`].
//!
//! # The attack it answers
//!
//! A receiver key is free. Anyone can make ten, and from ADS-B positions, or from the network's own
//! published fixes, fabricate receptions that look right, then publish a fix over them beside an
//! honest one, so that the fix over the larger set wins the merge by being a superset, and moves a
//! cockpit target. Three rules close it:
//!
//! 1. **A bigger answer wins only if it agrees, or is verified and carries more standing**
//!    ([`agreement`], [`decide`]): a fix that considered a strict superset of what a consistent fix
//!    considered agrees with it when its position is inside the smaller's uncertainty (the squared
//!    Mahalanobis length of the difference under the smaller's covariance at most [`AGREE_CHI2`],
//!    three degrees of freedom at 0.999, or [`AGREE_CHI2_2D`] when either states no height), and
//!    then it dominates the smaller. One that disagrees **supersedes** the smaller only when a
//!    holder of its raw verified it ([`Candidate::verified`]) and its receivers carry strictly more
//!    standing than every disagreeing smaller one's: the smaller is then refused, and its
//!    receptions are judged under the superset's fix like any other. Otherwise the superset is
//!    **contested**: a fault, never the answer, kept as evidence, and the smaller stands. Either
//!    way the answer is the same whatever order the fixes came in. An engine solves a transmission
//!    from what had arrived when it was due (its considered set, crate docs § The trailing window),
//!    so an honest engine that heard more publishes a superset of an honest engine that heard less:
//!    the rule must let it win, or the first fast, favourable subset would freeze the honest bigger
//!    fix out; it lets it win only on evidence a fabricator cannot make (verification over raw, and
//!    standing earned before the transmission).
//! 2. **Sets are weighed by their receivers' standing, not their count** ([`Candidate::standing`]):
//!    of fixes neither of which refuses the other, the one whose used receptions' receivers carry
//!    the most standing ranks first, then the tie rule (used receptions plus the model's inputs),
//!    then the lowest identity. Ten new keys add nothing to a set's standing.
//! 3. **A position whose receivers lack standing is unconfirmed** ([`Book::confirmed`]): fewer
//!    than the solver's minimum (three with an altitude, four without) of its receivers have
//!    [`HAS_STANDING`].
//!
//! The relation between two fixes is model-agnostic here (two sets of one transmission's
//! receptions, [`Set`]): a fabricator cannot escape rule 1 by citing a model of its own.
//!
//! # How a receiver earns standing
//!
//! A transmission's fixes are gathered as they arrive ([`Book::add`]): every fix of one aircraft
//! and message that shares a considered reception with another is of the same transmission, and a
//! transmission holds one fix of each engine of its area. A fix is consistent when every reception
//! it used, mapped through the model it cites, puts its transmit time within [`AGREE_Z`] of where
//! the fix says ([`reception_zs`]); one that is not is evidence against what it cites and nothing
//! more. [`SETTLE`] after the transmission (its transmit time, signed in every fix of it, by the
//! keeper's clock), once every fix of it has surely arrived, it is settled ([`Book::settle`])
//! against its answer, the first consistent one of its fixes by [`decide`], each ranked by its
//! receivers' standing as the book holds it then. When a fix arrived decides nothing: the deadline
//! is the record's, and standing is read when the transmission is decided, never frozen when a fix
//! came. Every reception any of its fixes considered, when it is in its receiver's own signed raw
//! (an attacker can cite receptions a receiver never made, and that receiver must not pay for
//! them):
//!
//! - **agrees** when its whitened residual under the answer is at most `AGREE_Z`. It earns the
//!   receiver one count only when the reception *arrived before any fix of its transmission
//!   existed*: its batch's signed wall clock is before the earliest signed issue time of any
//!   consistent fix of the transmission, and that fix used it. A receiver that fabricates
//!   receptions from a published fix is in no earliest fix, so it earns nothing however well it
//!   agrees. And only of a transmission whose position the network learns only by solving
//!   ([`eligible`]): not an ADS-B message (DF17, 18 or 19), and not of the calibration sample
//!   (`arrived::sampled` at the transmission's time or `SAMPLE_SLACK_MS` after, which is how the
//!   network solves ADS-B aircraft), so nothing an ADS-B position could have told a fabricator
//!   earns.
//! - **disagrees** when its residual is above `AGREE_Z`, or, not mapped by the answer's model,
//!   when only refused (contested or superseded) fixes cite it. It costs the receiver
//!   [`DISAGREE_COST`] counts. Padding a fix with bad receptions loses the padders' receivers their
//!   standing.
//!
//! A reception is settled once: a fix whose transmission is already due by the keeper's clock
//! (`SETTLE` after it) is late and refused ([`Book::add`]), so a reception settled is remembered
//! only while a fix that may still be added could find it in raw ([`SETTLED_SLACK_MS`] past its
//! transmission's due time). Counts are kept per receiver by [`PERIOD_MS`] of transmit time
//! ([`ReceiverStanding`]); a period earns at most [`EARN_PER_PERIOD`]; standing at a time is the
//! sum over its periods, each halved for every [`HALF_LIFE_PERIODS`] it is older, capped at
//! [`FULL`] and floored at `-FULL`. Its weight is its share of `FULL`, in thousandths, never below
//! 0. Every quantity is an integer, every iteration in key order, so two keepers holding the same
//! records hold the same standing.
//!
//! # What it does not stop
//!
//! Without a trusted clock, a party that both runs a fast solver over public raw and controls
//! receivers can sign their batches early with receptions computed from honest ones and publish
//! the earliest fix itself, and so farm standing. It is bounded: one key's weight is at most one
//! honest receiver's, earning is capped per period and decays, and a disagreeing superset wins only
//! verified and with more standing than what it would replace.
//!
//! Standing is a relay's (`tally-relay`'s `standing`): it holds the raw, the full models and the
//! raw fixes. A client holds none of them (wire version 3: a receiver's counters and a model's
//! sites and offsets give its site), only tagged fixes and models' summaries, so it cannot see who
//! heard what when, nor map a reception through a model: it decides between one transmission's
//! tagged fixes by [`decide`] (agreement and the tie rule, over tag sets, [`Set`]) with no standing
//! and nothing verified (`tally-merge`), so to a client a disagreeing superset stays contested.
//!
//! The solver's gating by standing ([`ReceiverStanding::gated`]): a receiver whose standing is
//! below `-GATED_BELOW` is one the specification's outlier rule should leave out.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tally_wire::batch::Hash;
use tally_wire::clocks::Judged;
use tally_wire::{EnuCovariance, ObservationSet, PublicKey, Relation, TaggedSet, TransmitTime};

use crate::arrived::sampled;
use crate::geo::{self, Geodetic};
use crate::linalg::{self, Matrix, Vec3};
use crate::obs::{ObservationId, Reception, message_hash};
use crate::pair::{Models, Prepared};
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
/// settled: once every fix of it has surely arrived, the error budget's
/// `tally_wire::budget::FIX_ARRIVED` (32.5 s: the latest a fix leaves its engine, `FIX_LEAVES`,
/// then `K`, how far the keeper's clock may be from that engine's relay's, and a repair's transit;
/// derived there). That is inside what a keeper holds raw behind its clock (`arrived::HELD_MS`), so
/// the raw a settlement asks `heard` for is still held: the assert below holds it, so a settling or
/// a holding changed without the other stops compiling.
pub const SETTLE: tally_wire::budget::Tolerance = tally_wire::budget::FIX_ARRIVED;

const _: () = assert!(SETTLE.span::<Judged>().ms() <= crate::arrived::HELD_MS);
/// The settled receptions are remembered in bins of their transmission's time this long: let go a
/// bin at a time.
pub const SETTLED_BIN_MS: u64 = 5_000;
/// How long past its transmission's due time (`SETTLE` after it, by the keeper's clock) a settled
/// reception is remembered, so it is settled once: a fix added later is of a transmission no
/// earlier than the due time ([`Book::add`] refuses any earlier, late), and the raw it is settled
/// against is let go by every holder `arrived::HELD_MS` after its signed wall clock, which is no
/// later than `arrived::AHEAD_MS` past the keeper's clock at the due time; so past both no holder
/// finds it. Before, every reception settled was remembered three ten-minute periods.
pub const SETTLED_SLACK_MS: u64 = crate::arrived::HELD_MS + crate::arrived::AHEAD_MS;
/// Weights are thousandths.
pub const PERMILLE: u64 = 1_000;
/// How far after a transmission its receptions' batches may be signed and still be read for the
/// calibration sample: a batch is sealed up to a second after, so the sample period it falls in may
/// be the next.
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
    !(sampled(address, ms) || sampled(address, ms + SAMPLE_SLACK_MS))
}

/// A full input set's identity: one definition, `tally_wire::products::input_set` (the merge
/// rule's, which the world product cites too).
pub use tally_wire::products::input_set;

/// What a fix claims: where, when, how sure.
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
    pub fn of<O>(wire: &tally_wire::Fix<O>) -> Self {
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

/// The receptions of `message` the wire names, as the pairwise path reads them, each dated by
/// `wall_ms`: a keeper holds no batch's wall clock for a wire reception, and the fix's claimed
/// transmit time is within milliseconds of each, which is all a GNSS-disciplined reading needs of
/// a wall clock (the UTC day it is in, `sync::origin_unix_ns`). Before, they were dated at zero,
/// which put a GNSS reference's reading past the middle of its day on the day before 1970, and
/// every fix whose reference it was failed to normalise at every keeper.
fn receptions_of(
    message: &[u8],
    receptions: &[tally_wire::Reception],
    wall_ms: u64,
) -> Vec<Reception> {
    let Some(message) = crate::obs::ModeS::new(message) else {
        return Vec::new();
    };
    receptions
        .iter()
        .map(|reception| Reception {
            receiver: reception.receiver,
            epoch: reception.epoch,
            timestamp: reception.counter,
            message,
            wall_ms,
        })
        .collect()
}

/// Each of `receptions`' whitened residual under a fix of `message` solved with `models`: how
/// far, in standard deviations, the transmit time it implies is from the fix's, its arrivals
/// normalised together by the models' pairs (`pair::Models::normalise`, `pair::Normalised::
/// residual_z`) and its variance widened by the fix's uncertainty (its covariance's trace, twice:
/// position and transmit time). A reception the normalisation leaves out has `None`, and all have
/// `None` when the fix states no height or they cannot be normalised.
pub fn reception_zs(
    models: &Models<'_>,
    message: &[u8],
    receptions: &[tally_wire::Reception],
    fix: &Claimed,
) -> Vec<Option<f64>> {
    let none = || vec![None; receptions.len()];
    let (Some(position), Ok(transmitted)) = (fix.ecef(), i128::try_from(fix.transmitted.unix_ps()))
    else {
        return none();
    };
    let wall_ms = fix.transmitted.unix_ms;
    let Ok(normalised) = models.normalise(&receptions_of(message, receptions, wall_ms)) else {
        return none();
    };
    let zs = normalised.residual_z(position, transmitted, 2.0 * fix.trace_m2());
    let hash = message_hash(message);
    receptions
        .iter()
        .map(|reception| {
            let id = ObservationId {
                receiver: reception.receiver,
                epoch: reception.epoch,
                timestamp: reception.counter,
                message: hash,
            };
            zs.binary_search_by_key(&id, |(id, _)| *id)
                .ok()
                .map(|at| zs[at].1)
        })
        .collect()
}

/// Whether a fix agrees with the receptions it used under the models it cites: every one
/// normalised, and within `AGREE_Z`. One that does not is never the answer.
pub fn consistent(models: &Models<'_>, used: &ObservationSet, fix: &Claimed) -> bool {
    reception_zs(models, used.message(), used.receptions(), fix)
        .iter()
        .all(|z| z.is_some_and(|z| z <= AGREE_Z))
}

/// Whether a wire fix is one under `models` at all, as a keeper without raw can tell: every
/// model of its specification, its message naming its aircraft, every reception it used of a
/// clock of the models, the models exactly the ones the fix lists, one for each area of its used
/// hearers (crate docs, § Areas, the models a fix cites), and a claim that reads back.
pub fn under(models: &Models<'_>, wire: &tally_wire::Fix, spec: u16) -> bool {
    let used = wire.used().receptions();
    let at_ns = u64::try_from(wire.transmitted.unix_ps() / 1000).unwrap_or(0);
    models.parts().iter().all(|part| part.model.spec == spec)
        && modes::address(wire.used().message()) == Some(wire.address)
        && used
            .iter()
            .all(|reception| models.clock_of(&reception.receiver).is_some())
        && models.areas_of(used.iter().map(|reception| reception.receiver)) == Some(models.areas())
        && wire.models == models.ids()
        && publish::claim_at(at_ns, &publish::Stated::of(wire), spec).is_ok()
}

/// The pair models one fix cites, held, as a keeper's book cites them: the models (one per area
/// of its used hearers, `pair::Models`), what they are a function of together
/// (`publish::cited_inputs`) and the engine that signed the fix. A relay's handles on its one
/// store of decoded models (`tally-relay`'s `models::Model`), which charges a model while any
/// handle is alive, so a book holds handles and never counts a model's bytes again.
pub trait ModelRef: Clone {
    fn models(&self) -> Models<'_>;
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

/// One fix as the rule weighs it.
pub trait Candidate {
    /// What its sets are: raw (a relay's) or tagged (a client's).
    type Set: Set;
    /// What it considered: the set two fixes of one transmission are related by.
    fn observations(&self) -> &Self::Set;
    fn model_inputs(&self) -> &Hash;
    fn claimed(&self) -> Claimed;
    /// The sum of its used receptions' receivers' weights, thousandths.
    fn standing(&self) -> u64;
    /// The tie rule's weight: used receptions plus the model citation's input count.
    fn weight(&self) -> u64;
    /// Its identity (`tally_wire::Fix::identity`).
    fn identity(&self) -> Hash;
    /// Whether it agrees with the receptions it used under its own model ([`consistent`]). Only a
    /// consistent fix refuses a superset: a smaller one that lies about where its own receptions
    /// put the aircraft refuses nothing.
    fn consistent(&self) -> bool;
    /// Ranks before every other whatever its standing (a keeper's own fix of a union).
    fn preferred(&self) -> bool {
        false
    }
    /// Whether a holder of its raw verified it (`verify::verify`): `Some(true)` passed,
    /// `Some(false)` failed, `None` not judged (no raw held, or not yet). A disagreeing superset
    /// supersedes a consistent subset only when `Some(true)` and of more standing (module docs,
    /// rule 1).
    fn verified(&self) -> Option<bool> {
        None
    }
}

/// A fix refused, against the one kept, where the two disagree: a contested superset (`refused`
/// the larger, `kept` the smaller it disagreed with), or a superseded subset (`superseded`:
/// `refused` the smaller, `kept` the verified superset of more standing that replaced it).
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    /// Indices into what [`decide`] was given.
    pub refused: usize,
    pub kept: usize,
    pub chi2: f64,
    pub superseded: bool,
}

/// What [`decide`] found: who stands, best first, and who was refused (contested or superseded).
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

/// Of one transmission's fixes, distinct by identity, which stands (module docs, rules 1 and 2). A
/// function of the set, whatever order it is given in:
///
/// - a consistent fix whose considered set is a strict subset of another's and which disagrees
///   with it ([`agreement`]) is that larger fix's disagreeing subset;
/// - a larger fix with disagreeing subsets supersedes them all when it is verified
///   (`Candidate::verified` is `Some(true)`) and its standing is strictly more than each of
///   theirs: each is refused as superseded, against it;
/// - otherwise it is contested: refused against the lowest by identity of its disagreeing subsets
///   that no other fix superseded (a fixed answer), and not refused at all when every one was;
/// - of the rest, one whose model inputs are another's and whose considered set is a strict
///   subset of it is dominated;
/// - the rest rank by `preferred`, then standing, then the tie rule's weight, then the lowest
///   identity.
pub fn decide<T: Candidate>(items: &[T]) -> Decision {
    // Each fix's disagreeing subsets: (index, chi2).
    let disagreeing: Vec<Vec<(usize, f64)>> = items
        .iter()
        .enumerate()
        .map(|(at, larger)| {
            items
                .iter()
                .enumerate()
                .filter(|(other, smaller)| {
                    *other != at
                        && smaller.consistent()
                        && smaller.observations().relation(larger.observations())
                            == Relation::Subset
                })
                .filter_map(|(other, smaller)| {
                    let agreement = agreement(&smaller.claimed(), &larger.claimed());
                    (!agreement.agrees()).then_some((other, agreement.chi2))
                })
                .collect()
        })
        .collect();
    let supersedes = |at: usize| {
        let larger = &items[at];
        // Standing first: verifying is the costly question, asked only where it decides.
        !disagreeing[at].is_empty()
            && disagreeing[at]
                .iter()
                .all(|(smaller, _)| larger.standing() > items[*smaller].standing())
            && larger.verified() == Some(true)
    };
    let mut refusals = Vec::new();
    let mut superseded = vec![false; items.len()];
    for at in (0..items.len()).filter(|at| supersedes(*at)) {
        for &(smaller, chi2) in &disagreeing[at] {
            // Against the lowest identity of what supersedes it, once.
            let held = refusals
                .iter_mut()
                .find(|refusal: &&mut Refusal| refusal.superseded && refusal.refused == smaller);
            match held {
                Some(refusal) if items[at].identity() < items[refusal.kept].identity() => {
                    refusal.kept = at;
                    refusal.chi2 = chi2;
                }
                Some(_) => {}
                None => refusals.push(Refusal {
                    refused: smaller,
                    kept: at,
                    chi2,
                    superseded: true,
                }),
            }
            superseded[smaller] = true;
        }
    }
    for at in (0..items.len()).filter(|at| !supersedes(*at) && !superseded[*at]) {
        let against = disagreeing[at]
            .iter()
            .filter(|(smaller, _)| !superseded[*smaller])
            .min_by_key(|(smaller, _)| items[*smaller].identity());
        if let Some(&(kept, chi2)) = against {
            refusals.push(Refusal {
                refused: at,
                kept,
                chi2,
                superseded: false,
            });
        }
    }
    refusals.sort_by_key(|refusal| (refusal.refused, refusal.kept));
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

/// A fix a keeper took ([`Solved::new`]): what its book takes in, once, by value. Nothing of it is
/// weighed as it is taken: its consistency with the receptions it used is read when its
/// transmission is settled, once ([`Book::settle`]), so taking a fix in is its decode and a compact
/// insert.
#[derive(Clone, Debug)]
pub struct Solved<M> {
    /// Its record's signed issue time.
    pub issued_ms: u64,
    pub claimed: Claimed,
    /// What it considered, and the subset it used.
    pub considered: ObservationSet,
    pub used: ObservationSet,
    /// The models it cites, held (a relay's handles on its store of models).
    pub model: M,
    /// The tie rule's weight.
    pub weight: u64,
    /// `tally_wire::Fix::identity`.
    pub identity: Hash,
}

impl<M: ModelRef> Solved<M> {
    /// `wire`, signed at `issued_ms`, under `model`, as the rule takes it: `None` unless it is a
    /// fix under the models ([`under`]).
    pub fn new(wire: &tally_wire::Fix, spec: u16, issued_ms: u64, model: M) -> Option<Self> {
        let models = model.models();
        if !under(&models, wire, spec) {
            return None;
        }
        let inputs: u64 = models
            .parts()
            .iter()
            .map(|part| u64::from(part.model.input.count))
            .sum();
        drop(models);
        Some(Self {
            issued_ms,
            claimed: Claimed::of(wire),
            weight: wire.used().receptions().len() as u64 + inputs,
            identity: wire.identity(),
            considered: wire.considered().clone(),
            used: wire.used().clone(),
            model,
        })
    }

    /// What it allocates in hand: itself, its messages and its receptions.
    pub fn allocated(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.considered.message().len()
            + std::mem::size_of_val(self.considered.receptions())
            + self.used.message().len()
            + std::mem::size_of_val(self.used.receptions())
    }
}

/// The receptions a held transmission keeps at most: a fix's considered receptions are a set of
/// the transmission's, one bit each ([`Bits`]). A fix that would take its transmission past them
/// is refused and counted (`Settled::refused`). An honest transmission's fixes consider much the
/// same receivers, of which the solver's minimum to a few dozen hear one aircraft.
pub const RECEPTIONS_MOST: usize = 64;
/// The fixes a held transmission keeps at most: one of each of its area's engines
/// (`rendezvous::MLAT_RELAYS_PER_AREA`); one more, or a second of one engine over a different
/// considered set, is refused and counted. An engine solves a transmission once, when it is due
/// (crate docs § The trailing window), so an honest engine never sends a second.
pub const SOLUTIONS_MOST: usize = tally_wire::rendezvous::MLAT_RELAYS_PER_AREA;
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

/// A fix held: what settling weighs it by.
struct Held<M> {
    engine: u64,
    issued_ms: u64,
    claimed: Claimed,
    identity: Hash,
    weight: u64,
    model: M,
    /// What it considered, and the subset it used, of its transmission's receptions.
    considered: Bits,
    used: Bits,
    /// Its consistency with the receptions it used, read at settling, once.
    consistent: std::cell::Cell<Option<bool>>,
    /// What the keeper's verifier said of it (`Book::settle_up_to`'s `verify`), asked at
    /// settling, once.
    verified: std::cell::Cell<Option<Option<bool>>>,
}

/// A transmission's fixes waiting to be settled [`SETTLE`] after `earliest_ms`, its earliest
/// transmit time: its message once, its distinct receptions once, and each fix's sets of them.
struct Transmission<M> {
    earliest_ms: u64,
    message: Message,
    receptions: Vec<Rec>,
    fixes: Vec<Held<M>>,
    /// What it takes of the book's room ([`Transmission::bytes_of`]).
    bytes: usize,
}

/// The parts a transmission's bytes are shared in among the engines whose solutions it holds:
/// divisible by every count of them up to [`SOLUTIONS_MOST`], so each engine's share is exact.
const SHARE_PARTS: u64 = 60;
const _: () = assert!(
    SOLUTIONS_MOST <= 6
        && SHARE_PARTS.is_multiple_of(4)
        && SHARE_PARTS.is_multiple_of(5)
        && SHARE_PARTS.is_multiple_of(6)
);

impl<M> Transmission<M> {
    /// What it takes of the book's room: its entries, its lists at their capacity, and an entry of
    /// the index for each of its receptions.
    fn bytes_of(&self) -> usize {
        use tally_wire::footprint::vec;
        transmission_entry_bytes::<M>()
            + vec::<Rec>(self.receptions.capacity())
            + self.receptions.len() * INDEX_ENTRY_BYTES
            + vec::<Held<M>>(self.fixes.capacity())
    }

    /// The engines whose fixes it holds, each once.
    fn sources(&self) -> Vec<u64> {
        let mut sources: Vec<u64> = self.fixes.iter().map(|one| one.engine).collect();
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    /// Each of its engines' share of its bytes, in [`SHARE_PARTS`] of a byte.
    fn split(&self) -> u64 {
        let sources = self.sources().len().max(1) as u64;
        self.bytes as u64 * SHARE_PARTS / sources
    }

    /// The work settling it costs: each reception weighed under each fix, and once more.
    fn work(&self) -> usize {
        self.receptions.len() * (1 + self.fixes.len()) + 1
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

/// What the book's room counts for a transmission held with `fixes` fixes over `receptions`
/// distinct receptions, as `Book::add` grows its lists (each to exactly its length): its entries,
/// its lists, and an entry of the index for each reception.
pub const fn transmission_bytes_most<M>(fixes: usize, receptions: usize) -> usize {
    use tally_wire::footprint::vec;
    transmission_entry_bytes::<M>()
        + vec::<Rec>(receptions)
        + receptions * INDEX_ENTRY_BYTES
        + vec::<Held<M>>(fixes)
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
pub const SETTLED_BINS: usize = SETTLED_SLACK_MS.div_ceil(SETTLED_BIN_MS) as usize + 4;
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

/// What a decoded and prepared pair model allocates at most ([`model_bytes`]) with `clocks`
/// clocks and `pairs` pairs: `publish::decode_pairs` makes every
/// list exactly as long as its encoding says, and `pair::Prepared::of` builds an index entry, an
/// adjacency entry each end and a curve of each pair (`pair::Prepared::bytes`). A member of an area
/// keeps at most `pair::PAIR_NEIGHBOURS` pairs, so an area of `r` receivers has at most
/// `r * PAIR_NEIGHBOURS` pairs and `r * (PAIR_NEIGHBOURS + 1)` members.
pub const fn model_bytes_most(clocks: usize, pairs: usize) -> usize {
    crate::pair::Prepared::bytes_most(clocks, pairs)
}

/// What a decoded and prepared pair model allocates: its `Arc` and every list it holds, at their
/// capacity (`pair::Prepared::bytes`). Counted once, where a model is held (a relay's store of
/// models).
pub fn model_bytes(prepared: &Prepared) -> usize {
    tally_wire::footprint::arc::<Prepared>() + prepared.bytes()
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
    /// Fixes refused as late: their transmission was due when they came (`Book::add`).
    pub late: u64,
    /// Fixes refused: a second of one engine over another considered set, or past
    /// [`SOLUTIONS_MOST`] or [`RECEPTIONS_MOST`] of a transmission (`slots`); past the book's
    /// room (`room`); past its engine's share of it (`share`); citing a receiver past the book's
    /// cap of them (`receivers`); of a message no transmission holds (`malformed`). None of them
    /// lets go of anything held.
    pub slots: u64,
    pub room: u64,
    pub share: u64,
    pub receivers: u64,
    pub malformed: u64,
    /// Fixes let go as two held transmissions became one and both held one engine's.
    pub merged_out: u64,
}

impl Settled {
    /// Every fix refused, whatever the reason.
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

/// A fix weighed for [`decide`]: its receivers' standing as the book holds it when the
/// transmission is decided, never as it was when the fix arrived, so the same fixes under the same
/// book rank the same in any arrival order.
struct Weighed<'a, M> {
    held: &'a Held<M>,
    receptions: &'a [Rec],
    message: &'a [u8],
    interned: &'a Interned,
    standing: u64,
    verify: &'a dyn Fn(&Asked<'_, M>) -> Option<bool>,
}

/// A fix a keeper's verifier is asked to judge (`Book::settle_up_to`): a disagreeing superset of
/// more standing than every consistent subset it disagrees with, which supersedes them only when a
/// holder of its raw verified it (module docs, rule 1). The keeper finds the raw of `considered`
/// (a relay in its `arrived::Arrived`), rebuilds the claim and runs `verify::verify`, answering
/// `Some(true)` passed, `Some(false)` failed, `None` not judged (raw not held, or past its
/// verifying budget: decision D6 caps it per engine per second, which `engine` names). Asked at
/// most once a fix.
pub struct Asked<'a, M> {
    pub engine: &'a PublicKey,
    pub model: &'a M,
    pub identity: Hash,
    pub claimed: Claimed,
    /// The ids of the models it cites, ascending.
    pub models: Vec<Hash>,
    pub message: &'a [u8],
    pub considered: Vec<tally_wire::Reception>,
    pub used: Vec<tally_wire::Reception>,
}

impl<M> Asked<'_, M> {
    /// What the fix states, as the verifier reads it (`verify::verify_stated`).
    pub fn stated(&self) -> crate::publish::Stated<'_> {
        crate::publish::Stated {
            claimed: self.claimed,
            models: &self.models,
            message: self.message,
            considered: &self.considered,
            used: &self.used,
        }
    }
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
        &self.held.considered
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
        let used: Vec<tally_wire::Reception> =
            self.held.used.ones().map(|at| self.wire(at)).collect();
        let known = reception_zs(
            &self.held.model.models(),
            self.message,
            &used,
            &self.held.claimed,
        )
        .iter()
        .all(|z| z.is_some_and(|z| z <= AGREE_Z));
        self.held.consistent.set(Some(known));
        known
    }

    /// Asked of the keeper's verifier once, at settling, and remembered.
    fn verified(&self) -> Option<bool> {
        if let Some(known) = self.held.verified.get() {
            return known;
        }
        let asked = Asked {
            engine: self.held.model.engine(),
            model: &self.held.model,
            identity: self.held.identity,
            claimed: self.held.claimed,
            models: self.held.model.models().ids(),
            message: self.message,
            considered: self
                .held
                .considered
                .ones()
                .map(|at| self.wire(at))
                .collect(),
            used: self.held.used.ones().map(|at| self.wire(at)).collect(),
        };
        let known = (self.verify)(&asked);
        self.held.verified.set(Some(known));
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

    /// A fix the keeper took ([`Solved::new`]): held with every other fix of its transmission until
    /// it is settled, [`SETTLE`] after the transmission, or refused and counted ([`Refused`]);
    /// nothing held is ever let go for it. When it arrived decides nothing. It reads nothing of
    /// the fix's consistency: that is settling's.
    pub fn add(&mut self, solved: Solved<M>) -> Result<(), Refused> {
        let earliest_ms = solved.claimed.transmitted.unix_ms;
        // Its transmission is due already: every fix of it has surely come, and it is late.
        if self
            .through
            .is_some_and(|through| SETTLE.settled(earliest_ms, through))
        {
            return self.refuse(Refused::Late);
        }
        let Some(message) = Message::of(solved.considered.message()) else {
            return self.refuse(Refused::Malformed);
        };
        let engine = engine_of(solved.model.engine());
        let wire = solved.considered.receptions();
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
                    fixes: Vec::new(),
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
        // A transmission made for a fix refused holds nothing: let go.
        if self
            .pending
            .get(&number)
            .is_some_and(|held| held.fixes.is_empty())
            && let Some(gone) = self.pending.remove(&number)
        {
            self.deadlines.remove(&(gone.earliest_ms, number));
            self.let_go(number, &gone);
        }
        result
    }

    /// `solved` into held transmission `number` (whose considered receptions' digests are
    /// `digests`), or refused: a second of its engine over another considered set, past
    /// [`SOLUTIONS_MOST`] or [`RECEPTIONS_MOST`], the receivers' cap, the room or its engine's
    /// share.
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
        // One of each engine: the same again (or another engine's of the same identity) only
        // keeps the earlier issue time.
        let wire = solved.considered.receptions();
        if let Some(same) = held
            .fixes
            .iter_mut()
            .find(|one| one.identity == solved.identity)
        {
            same.issued_ms = same.issued_ms.min(solved.issued_ms);
            return Ok(());
        }
        if held.fixes.iter().any(|one| one.engine == engine) {
            return self.refuse(Refused::Slots);
        }
        if held.fixes.len() >= SOLUTIONS_MOST {
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
        let fixes = held.fixes.len() + 1;
        let receptions = held.receptions.len() + new.len();
        let after = transmission_entry_bytes::<M>()
            + tally_wire::footprint::vec::<Rec>(held.receptions.capacity().max(receptions))
            + receptions * INDEX_ENTRY_BYTES
            + tally_wire::footprint::vec::<Held<M>>(held.fixes.capacity().max(fixes));
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
        let considered = Self::known_bits(held, &self.interned, wire).unwrap_or_default();
        let used =
            Self::known_bits(held, &self.interned, solved.used.receptions()).unwrap_or_default();
        held.fixes.reserve_exact(1);
        held.fixes.push(Held {
            engine,
            issued_ms: solved.issued_ms,
            claimed: solved.claimed,
            identity: solved.identity,
            weight: solved.weight,
            model: solved.model.clone(),
            considered,
            used,
            consistent: std::cell::Cell::new(None),
            verified: std::cell::Cell::new(None),
        });
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

    /// A fix's receptions as a set of a held transmission's, when it holds every one.
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
    /// receptions join `into`'s (each fix's sets mapped to them); a fix of an engine `into` holds
    /// one of already, or one past the slots, is let go, counted.
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
        kept.fixes.reserve_exact(gone.fixes.len());
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
        for one in gone.fixes {
            let fits = !kept.fixes.iter().any(|held| held.engine == one.engine)
                && kept.fixes.len() < SOLUTIONS_MOST;
            match (remap(one.considered), remap(one.used)) {
                (Some(considered), Some(used)) if fits => kept.fixes.push(Held {
                    considered,
                    used,
                    ..one
                }),
                _ => moved_out += 1,
            }
        }
        // Receptions past the room no fix kept cites: their receivers given back, their
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
        let bin = at_ms / SETTLED_BIN_MS;
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

    /// Forgets the settled receptions no fix may still find (`SETTLED_SLACK_MS` past their
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
                if (bin + 1) * SETTLED_BIN_MS > horizon {
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
    /// receiver's own signed raw (the earliest of copies; a relay reads its `arrived::Arrived`).
    /// The receivers whose standing changed, so a keeper that ranks by it ranks again.
    pub fn settle(
        &mut self,
        now: Judged,
        heard: impl Fn(&ObservationId, u64) -> Option<u64>,
    ) -> BTreeSet<PublicKey> {
        self.settle_up_to(now, heard, |_| None, usize::MAX).0
    }

    /// As `settle`, `work` of work at most (each transmission's receptions weighed under each of
    /// its fixes, and once more, `Transmission::work`), and at least one transmission, earliest
    /// due first, and whether any due by `now` is left: a keeper that settles in pieces holds
    /// what it shares for one piece at a time, however many transmissions fall due at once, and
    /// settles the same transmissions in the same order as at once. `verify` judges a fix the rule
    /// asks about ([`Asked`]): a keeper holding raw verifies it, one holding none (a client, or a
    /// keeper past its budget) answers `None`, and the fix then stays contested.
    pub fn settle_up_to(
        &mut self,
        now: Judged,
        heard: impl Fn(&ObservationId, u64) -> Option<u64>,
        verify: impl Fn(&Asked<'_, M>) -> Option<bool>,
        work: usize,
    ) -> (BTreeSet<PublicKey>, bool) {
        let mut changed = BTreeSet::new();
        let mut done = 0usize;
        // From now a fix of a transmission due by `now` is late (`Book::add`), whether or not
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
            self.settle_one(&pending, &heard, &verify, &mut changed);
            self.let_go(number, &pending);
        }
        self.forget_settled_past(self.through);
        (changed, false)
    }

    fn settle_one(
        &mut self,
        pending: &Transmission<M>,
        heard: &impl Fn(&ObservationId, u64) -> Option<u64>,
        verify: &dyn Fn(&Asked<'_, M>) -> Option<bool>,
        changed: &mut BTreeSet<PublicKey>,
    ) {
        // Weighed by standing as the book holds it now, whatever it was when each arrived.
        let weighed: Vec<Weighed<'_, M>> = pending
            .fixes
            .iter()
            .map(|held| Weighed {
                held,
                receptions: &pending.receptions,
                message: pending.message.as_slice(),
                verify,
                interned: &self.interned,
                standing: held
                    .used
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
        // The earliest fixes, by signed issue time, of those consistent with their own receptions:
        // one signed before its own transmission says nothing true about time and is not counted.
        let possible: Vec<(u64, Bits)> = weighed
            .iter()
            .filter(|one| {
                one.consistent() && one.held.issued_ms >= one.held.claimed.transmitted.unix_ms
            })
            .map(|one| (one.held.issued_ms, one.held.used))
            .collect();
        let earliest_ms = possible.iter().map(|(issued, _)| *issued).min();
        let earliest = possible
            .iter()
            .filter(|(issued, _)| Some(*issued) == earliest_ms)
            .fold(0u64, |bits, (_, one)| bits | one.0);
        // Each reception considered, and whether only refused fixes consider it.
        let mut cited: Vec<Option<bool>> = vec![None; pending.receptions.len()];
        for (at, one) in weighed.iter().enumerate() {
            let refused = decision.refused(at);
            for reception in one.held.considered.ones() {
                let entry = cited[reception].get_or_insert(true);
                *entry &= refused;
            }
        }
        let hash = message_hash(message);
        // Every reception any fix considered, normalised together under the answer's models.
        let places: Vec<usize> = (0..cited.len()).filter(|at| cited[*at].is_some()).collect();
        let wire: Vec<tally_wire::Reception> = places
            .iter()
            .map(|place| {
                let rec = pending.receptions[*place];
                tally_wire::Reception {
                    receiver: self.interned.key(rec.receiver),
                    epoch: rec.epoch,
                    counter: rec.counter,
                }
            })
            .collect();
        let zs: BTreeMap<usize, Option<f64>> = places
            .iter()
            .copied()
            .zip(reception_zs(
                &fix.held.model.models(),
                message,
                &wire,
                &claimed,
            ))
            .collect();
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
            let verdict = match zs.get(&place).copied().flatten() {
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
        verified: Option<bool>,
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
        fn verified(&self) -> Option<bool> {
            self.verified
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
            verified: None,
        }
    }

    fn first(items: &[Item]) -> Hash {
        items[decide(items).ranked[0]].identity
    }

    /// A model held as a book cites one: the model, its inputs and its engine.
    #[derive(Clone)]
    struct Cited(std::sync::Arc<Prepared>, Hash, PublicKey);

    impl ModelRef for Cited {
        fn models(&self) -> Models<'_> {
            Models::one(&self.0)
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
            std::sync::Arc::new(
                Prepared::of(
                    crate::pair::PairModel {
                        spec: crate::SPEC_VERSION,
                        area: tally_wire::rendezvous::area_at(52.0, 5.0)
                            .unwrap_or_else(|error| panic!("{error}")),
                        trailing: crate::scope::Trailing::at(AT.unix_ms),
                        scope: Vec::new(),
                        frontier: Vec::new(),
                        input: crate::scope::Citation {
                            hash: [7; 32],
                            count: 3,
                        },
                        kappa: 1.0,
                        clocks: Vec::new(),
                        pairs: Vec::new(),
                    },
                    [engine; 32],
                )
                .unwrap_or_else(|| unreachable!("a model of nothing prepares")),
            ),
            [engine; 32],
            key(200 + engine),
        )
    }

    /// A fix of the receivers `seeds` heard, of a transmission at `at_ms`, that used all it
    /// considered.
    fn solved(seeds: &[u8], at_ms: u64, model: &Cited) -> Solved<Cited> {
        let item = item(seeds, 0.0, model.1[0], 0);
        let mut claimed = item.claimed;
        claimed.transmitted = TransmitTime {
            unix_ms: at_ms,
            sub_ms_ps: 0,
        };
        Solved {
            issued_ms: at_ms + 1_000,
            claimed,
            weight: seeds.len() as u64,
            identity: item.identity,
            considered: item.observations.clone(),
            used: item.observations,
            model: model.clone(),
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

    /// A fix of a transmission already due when it comes is refused as late, counted, and holds
    /// nothing: every fix of it has surely come (`SETTLE`). Before, it was held and settled again,
    /// and the receptions settled once were remembered half an hour to refuse it.
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
        // At the start of a bin, so the bin is let go as its time is.
        let at = AT.unix_ms - AT.unix_ms % SETTLED_BIN_MS;
        let remember = |book: &mut Book<Cited>, seeds: &[u8], at_ms: u64| {
            for seed in seeds {
                book.remember(u128::from(*seed), at_ms);
            }
        };
        let mut book = Book::new(caps(1 << 20, 1_024));
        remember(&mut book, &[1, 2, 3], at);
        let due = at + SETTLE.span::<Judged>().ms();
        // The bin goes once its end is the slack past the due time of everything in it.
        let horizon = due + SETTLED_SLACK_MS + SETTLED_BIN_MS;
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
        let _ = held.settle_up_to(judged_at(horizon), |_, _| None, |_| None, 0);
        assert_eq!(held.settled_remembered(), 3);
        // Past the cap, the oldest bin goes at once.
        let mut capped = Book::new(caps(1 << 20, 4));
        remember(&mut capped, &[1, 2, 3], at);
        remember(&mut capped, &[4, 5], at + SETTLED_BIN_MS);
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
            transmission_bytes_most::<Cited>(1, 3),
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

    /// A transmission holds one fix of each engine, and at most `SOLUTIONS_MOST`: a second of one
    /// engine over another considered set is refused, counted, and the same again only keeps the
    /// earlier issue time. Each fix's receptions are a set of the transmission's, held once.
    #[test]
    fn a_transmission_holds_one_fix_of_each_engine() {
        let mut book = Book::new(caps(1 << 20, 1_024));
        let at = AT.unix_ms;
        let engines: Vec<Cited> = (1..=4).map(empty_model).collect();
        assert_eq!(book.add(solved(&[1, 2, 3], at, &engines[0])), Ok(()));
        assert_eq!(book.add(solved(&[1, 2, 3], at, &engines[0])), Ok(()));
        assert_eq!(
            book.add(solved(&[1, 2, 3, 4], at, &engines[0])),
            Err(Refused::Slots)
        );
        assert_eq!(book.add(solved(&[2, 3, 4, 5], at, &engines[1])), Ok(()));
        assert_eq!(book.add(solved(&[1, 3, 5], at, &engines[2])), Ok(()));
        // Three held: a fourth engine's is past the slots.
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
        assert_eq!(book.pending_bytes(), transmission_bytes_most::<Cited>(3, 5));
    }

    /// No engine takes more than its share of the room: past it its solutions are refused,
    /// counted, and another engine's transmissions are never let go for it.
    #[test]
    fn an_engine_past_its_share_is_refused_and_takes_nothing_of_another() {
        let one = transmission_bytes_most::<Cited>(1, 3);
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

    /// Taking a fix in reads nothing of its consistency: it is read once, when its transmission is
    /// settled.
    #[test]
    fn a_fixs_consistency_is_read_at_settling_not_as_it_is_taken() {
        let model = empty_model(1);
        let mut book = Book::new(caps(1 << 20, 1_024));
        assert_eq!(book.add(solved(&[1, 2, 3], AT.unix_ms, &model)), Ok(()));
        let read = |book: &Book<Cited>| {
            book.pending
                .values()
                .flat_map(|held| held.fixes.iter().map(|one| one.consistent.get()))
                .collect::<Vec<_>>()
        };
        assert_eq!(read(&book), vec![None]);
        let _ = book.settle(judged_at(AT.unix_ms + 60_000_000), |_, _| None);
        // A model of nothing maps no reception: inconsistent, settled as no answer.
        assert_eq!(book.counts().transmissions, 0);
    }

    /// Settling in pieces is held to its work, not its transmissions: a piece weighs each
    /// transmission's receptions under each of its fixes, and stops once the next would pass
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
        let (_, left) = book.settle_up_to(late, |_, _| None, |_| None, 2 * work);
        assert!(left);
        assert_eq!(book.pending(), 2);
        let (_, left) = book.settle_up_to(late, |_, _| None, |_| None, 1);
        assert!(left, "one at least a piece");
        assert_eq!(book.pending(), 1);
        let (_, left) = book.settle_up_to(late, |_, _| None, |_| None, usize::MAX);
        assert!(!left);
        assert_eq!((book.pending(), book.pending_bytes()), (0, 0));
    }

    /// Two transmissions a fix joins are one: their receptions held once, each fix's sets mapped to
    /// them, every index entry naming the one kept.
    #[test]
    fn a_solution_joining_two_transmissions_makes_them_one() {
        let (a, b, c) = (empty_model(1), empty_model(2), empty_model(3));
        let mut book = Book::new(caps(1 << 20, 1_024));
        assert_eq!(book.add(solved(&[1, 2, 3], AT.unix_ms, &a)), Ok(()));
        assert_eq!(book.add(solved(&[4, 5, 6], AT.unix_ms, &b)), Ok(()));
        assert_eq!(book.pending(), 2);
        assert_eq!(book.add(solved(&[3, 4, 7], AT.unix_ms, &c)), Ok(()));
        assert_eq!(book.pending(), 1);
        assert_eq!(book.pending_bytes(), transmission_bytes_most::<Cited>(3, 7));
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

    /// Decides `items` in both orders and checks the answer and refusals are the same each way,
    /// by identity: `(answer, [(refused, kept, superseded)])`.
    fn decided(items: &[Item]) -> (Hash, Vec<(Hash, Hash, bool)>) {
        let mut seen = Vec::new();
        for order in [items.to_vec(), items.iter().rev().cloned().collect()] {
            let decision = decide(&order);
            let mut refusals: Vec<(Hash, Hash, bool)> = decision
                .refusals
                .iter()
                .map(|one| {
                    (
                        order[one.refused].identity,
                        order[one.kept].identity,
                        one.superseded,
                    )
                })
                .collect();
            refusals.sort();
            seen.push((order[decision.ranked[0]].identity, refusals));
        }
        assert_eq!(seen[0], seen[1], "the same whatever the order");
        seen.swap_remove(0)
    }

    /// A smaller fix and a disagreeing superset of ten more receivers, 2 km away.
    fn disagreeing_pair(smaller_standing: u64, larger_standing: u64) -> (Item, Item) {
        let smaller = item(&[1, 2, 3, 4], 0.0, 7, smaller_standing);
        let larger = item(
            &[1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
            2_000.0,
            7,
            larger_standing,
        );
        (smaller, larger)
    }

    /// A disagreeing superset that a holder of its raw verified, of more standing than the subset,
    /// supersedes it: the subset is refused as superseded and the superset is the answer, either
    /// order. An engine that heard more is not frozen out by one that solved first.
    #[test]
    fn a_verified_disagreeing_superset_of_more_standing_supersedes_the_subset() {
        let (smaller, mut larger) = disagreeing_pair(2_000, 3_000);
        larger.verified = Some(true);
        let (answer, refusals) = decided(&[smaller.clone(), larger.clone()]);
        assert_eq!(answer, larger.identity);
        assert_eq!(refusals, vec![(smaller.identity, larger.identity, true)]);
    }

    /// Verified, but of no more standing than the subset (equal): contested, the subset stands.
    #[test]
    fn a_verified_disagreeing_superset_of_no_more_standing_is_contested() {
        let (smaller, mut larger) = disagreeing_pair(3_000, 3_000);
        larger.verified = Some(true);
        let (answer, refusals) = decided(&[smaller.clone(), larger.clone()]);
        assert_eq!(answer, smaller.identity);
        assert_eq!(refusals, vec![(larger.identity, smaller.identity, false)]);
    }

    /// Of more standing, but not judged (no raw held: a client, or a relay that has not verified
    /// it) or failed: contested, the subset stands. Ten new keys of no standing never win by count.
    #[test]
    fn an_unverified_or_failed_disagreeing_superset_is_contested_whatever_its_standing() {
        for verified in [None, Some(false)] {
            let (smaller, mut larger) = disagreeing_pair(0, 3_000);
            larger.verified = verified;
            let (answer, refusals) = decided(&[smaller.clone(), larger.clone()]);
            assert_eq!(answer, smaller.identity, "{verified:?}");
            assert_eq!(
                refusals,
                vec![(larger.identity, smaller.identity, false)],
                "{verified:?}"
            );
        }
    }

    /// A verified superset of more standing than one disagreeing subset but not another supersedes
    /// neither: it is contested against the one that stands, and both subsets stand.
    #[test]
    fn a_superset_outweighed_by_any_disagreeing_subset_supersedes_none() {
        let weak = item(&[1, 2, 3, 4], 0.0, 7, 500);
        let strong = item(&[1, 2, 3, 5], 10.0, 7, 4_000);
        let mut larger = item(&[1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15], 2_000.0, 7, 3_000);
        larger.verified = Some(true);
        let (answer, refusals) = decided(&[weak.clone(), strong.clone(), larger.clone()]);
        assert_eq!(answer, strong.identity);
        let kept = if weak.identity < strong.identity {
            weak.identity
        } else {
            strong.identity
        };
        assert_eq!(refusals, vec![(larger.identity, kept, false)]);
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
            let sampled_now =
                sampled(address, at.unix_ms) || sampled(address, at.unix_ms + SAMPLE_SLACK_MS);
            assert_eq!(eligible(&message, at), !sampled_now);
            eligible_count += usize::from(eligible(&message, at));
        }
        assert!(eligible_count > 200);
    }
}
