//! The per-transmission solver (crate docs, § Solving): the integer feasibility screen,
//! Levenberg-Marquardt over position and transmit time against the joint covariance of the
//! receptions' timing (noise plus the pair models' timing covariance, `pair::Models::normalise`),
//! the altitude pseudo-measurement, and the outlier rule's fixed point.

use std::collections::BTreeSet;

use crate::clock::{ModelTime, PS, SPEC_VERSION};
use crate::geo::{self, C, Geodetic};
use crate::linalg::{self, Cholesky, Matrix, Vec3};
use crate::modes::{self, Altitude, AltitudeKind};
use crate::obs::ObservationId;

/// Receivers a solve needs without an altitude, and with one.
pub const MIN_RECEIVERS: usize = 4;
pub const MIN_RECEIVERS_WITH_ALTITUDE: usize = 3;
/// The feasibility screen's allowance beyond the baseline, millimetres (about 3.3 µs).
pub const SCREEN_MARGIN_MM: i128 = 1_000_000;
/// The outlier rule's threshold on a reception's normalised residual.
pub const OUTLIER_Z: f64 = 5.0;
/// One standard deviation of a barometric altitude as a height above the ellipsoid, metres.
pub const BARO_SIGMA_M: f64 = 100.0;
/// One standard deviation of a GNSS height, metres.
pub const GNSS_SIGMA_M: f64 = 15.0;
/// Levenberg-Marquardt: iteration cap, initial damping, and the step below which it has
/// converged (metres, on every parameter).
pub const LM_ITERATIONS: usize = 50;
pub const LM_LAMBDA: f64 = 1e-3;
pub const LM_TOLERANCE_M: f64 = 1e-4;
/// Heights a solution may have, metres above the ellipsoid.
pub const MIN_HEIGHT_M: f64 = -1_500.0;
pub const MAX_HEIGHT_M: f64 = 25_000.0;
/// The farthest a solution may be from a receiver that heard it, metres.
pub const MAX_RANGE_M: f64 = 600_000.0;
/// The chi-square test's tail probability is 10^-6; this is its standard normal quantile.
pub const CHI2_TAIL_Z: f64 = 4.753_424;

/// Why a transmission has no solution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SolveError {
    #[error("too few receptions survive ({0})")]
    TooFew(usize),
    #[error("the solve did not converge")]
    NoConvergence,
    #[error("no solution lies where an aircraft can be")]
    OutOfRange,
    #[error("the outlier rule reached no fixed point")]
    NoFixedPoint,
    #[error("the residuals fail the chi-square test")]
    Inconsistent,
    #[error("the timing covariance is not positive definite")]
    Singular,
    #[error("no timing covariance was formed for the receptions")]
    Uncovered,
    #[error("two places fit the receptions alike")]
    Ambiguous,
    #[error("the position is too poorly determined to publish")]
    Uncertain,
}

/// The most a published fix's standard deviation may be along any axis, metres. Beyond it the
/// Gaussian the covariance describes is no longer the solution's error: a transmission with no
/// altitude heard across a flat network leaves the height nearly free, the least-squares surface
/// is curved over kilometres, and the minimum found can sit kilometres from the truth with a
/// covariance that calls that impossible (measured: a DF11 6 km below its aircraft at 58 squared
/// standard deviations). Such fixes are not published.
pub const MAX_SIGMA_M: f64 = 1_500.0;

/// The published position covariance is the solve's, its standard deviations times this, plus
/// `ERROR_FLOOR_M` squared on each axis. The simulator calibrates without them; real receivers
/// carry what it does not model (tropospheric delay differences of a metre or two between sites,
/// antenna phase centres off their declared sites, multipath), so a fix claims a little less than
/// the mathematics alone would. The calibration over real receivers (RFC-0171 §3.8.1) shows no
/// uniform overconfidence for these to correct, so they stand (the crate docs, § Solving).
pub const ERROR_INFLATION: f64 = 1.1;
/// The least one-axis standard deviation a fix claims, metres (see `ERROR_INFLATION`).
pub const ERROR_FLOOR_M: f64 = 5.0;

/// The published 3 x 3 position block of a solve's (X, T) covariance (`ERROR_INFLATION`).
pub fn published(inverse: &Matrix) -> [[f64; 3]; 3] {
    let mut covariance = [[0.0; 3]; 3];
    for (i, row) in covariance.iter_mut().enumerate() {
        for (j, value) in row.iter_mut().enumerate() {
            *value = inverse.get(i, j) * ERROR_INFLATION * ERROR_INFLATION;
            if i == j {
                *value += ERROR_FLOOR_M * ERROR_FLOOR_M;
            }
        }
    }
    covariance
}

/// The ring of starts an exactly determined transmission is also solved from: these radii about
/// the receivers' centroid, metres, at this many bearings from north.
pub const RING_RADII_M: [f64; 2] = [100_000.0, 300_000.0];
pub const RING_BEARINGS: usize = 8;

/// How much more a second fit may cost than the best and still fit as well: three standard
/// deviations' worth.
pub const AMBIGUOUS_COST: f64 = 9.0;

/// A solved position.
#[derive(Clone, Debug, PartialEq)]
pub struct Solution {
    pub spec: u16,
    /// ECEF metres.
    pub ecef: Vec3,
    pub position: Geodetic,
    /// Time of transmission on the timeline the models give, picoseconds from its zero.
    pub transmit_ps: i64,
    /// The position's covariance, ECEF metres squared, with the timing covariance propagated
    /// jointly.
    pub covariance: [[f64; 3]; 3],
    /// Every reception of the transmission it was solved from, sorted: what it considered.
    pub considered: Vec<ObservationId>,
    /// The receptions the outlier rule kept of them, sorted: what it used (a subset of
    /// `considered`).
    pub used: Vec<ObservationId>,
    /// The altitude pseudo-measurement, if the message carried one.
    pub altitude: Option<Altitude>,
    pub chi2: f64,
    pub dof: u32,
}

impl Solution {
    /// The covariance in the local east, north, up frame at the solution, metres squared.
    pub fn enu_covariance(&self) -> [[f64; 3]; 3] {
        let basis = geo::enu_basis(self.position.lat_deg, self.position.lon_deg);
        let mut out = [[0.0; 3]; 3];
        for (i, row) in out.iter_mut().enumerate() {
            for (j, value) in row.iter_mut().enumerate() {
                let mut sum = 0.0;
                for a in 0..3 {
                    for b in 0..3 {
                        sum += basis[i][a] * self.covariance[a][b] * basis[j][b];
                    }
                }
                *value = sum;
            }
        }
        out
    }

    /// One standard deviation of the horizontal position, metres: the root of half the trace of
    /// the east-north covariance.
    pub fn horizontal_sigma_m(&self) -> f64 {
        let enu = self.enu_covariance();
        (0.5 * (enu[0][0] + enu[1][1])).max(0.0).sqrt()
    }
}

/// The chi-square value the residuals of the exact optimum may reach (Wilson-Hilferty at
/// `CHI2_TAIL_Z`). With no redundancy (`dof` 0) the optimum explains every reception exactly, so
/// the limit is 0: what a published claim adds to it is its rounding, which
/// [`published_chi2_limit`] bounds.
pub fn chi2_limit(dof: u32) -> f64 {
    if dof == 0 {
        return 0.0;
    }
    let k = f64::from(dof);
    let a = 2.0 / (9.0 * k);
    let base = 1.0 - a + CHI2_TAIL_Z * a.sqrt();
    // Multiplied out, never `powi`, whose lowering is the compiler's to choose.
    k * (base * base * base)
}

/// Half the wire's quantum of each solved parameter, metres, plus floating point's share: what
/// writing a solution moves it by at most (`publish::to_wire`). Latitude and longitude are written
/// to 10^-7 degree (at most 5.6 mm on the ground each way) and height to the millimetre, so an ECEF
/// axis moves at most the length of that box's half-diagonal; the transmit time is written to the
/// picosecond (0.15 mm of light). Floating point adds a few ulps of an ECEF coordinate
/// (about 10^-9 m), held at 10^-6 m.
pub const ROUNDING_M: [f64; 4] = [7.9e-3 + 1e-6, 7.9e-3 + 1e-6, 7.9e-3 + 1e-6, 1.5e-4 + 1e-6];

/// How far rounding a solution to the wire can move its whitened residuals, at most: per
/// residual, the sum over the parameters of its whitened derivative times the parameter's
/// rounding ([`ROUNDING_M`]); the root of their sum of squares.
pub fn rounding_norm(jacobian: &[[f64; 4]]) -> f64 {
    jacobian
        .iter()
        .map(|row| {
            let moved: f64 = row
                .iter()
                .zip(ROUNDING_M)
                .map(|(derivative, rounding)| derivative.abs() * rounding)
                .sum();
            moved * moved
        })
        .sum::<f64>()
        .sqrt()
}

/// The chi-square a published solution may reach: the exact optimum's limit ([`chi2_limit`])
/// widened by what rounding can add (`rounding`, from [`rounding_norm`]), as the triangle
/// inequality bounds the residual vector's length. The one acceptance limit: the solver accepts
/// a fit only under it, and the verifier checks a claim against it.
pub fn published_chi2_limit(dof: u32, rounding: f64) -> f64 {
    let reach = chi2_limit(dof).sqrt() + rounding;
    reach * reach
}

pub(crate) struct Item {
    pub id: ObservationId,
    pub time: ModelTime,
    pub site: Vec3,
    pub site_mm: [i64; 3],
    /// Model time minus the earliest reception's, metres of light time.
    pub z: f64,
    /// Its own timing noise plus its site's variance, metres squared: the diagonal its clock's
    /// covariance is added to.
    pub noise_m2: f64,
}

pub(crate) struct Problem {
    /// Sorted by identity.
    pub items: Vec<Item>,
    /// The clock part of every pair's timing covariance, metres squared (the adjustment's, crate
    /// docs § The pairwise path); `None` when none was formed, which no solve accepts.
    pub clock_m2: Option<Vec<Vec<f64>>>,
    pub reference_ps: i128,
    pub altitude: Option<(Altitude, f64, f64)>,
}

/// Parameters: ECEF position and transmit time (metres of light time after the reference).
pub(crate) type Params = [f64; 4];

pub(crate) struct Fit {
    pub params: Params,
    pub cost: f64,
    /// `(Jᵀ J)` of the whitened problem at `params`.
    pub information: Matrix,
}

fn isqrt(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    // The float guess through 64 bits whenever they hold it: the same nearest float, without
    // 128-bit conversion's calls.
    let mut x = match u64::try_from(value) {
        Ok(small) => u128::from((small as f64).sqrt() as u64),
        Err(_) => (value as f64).sqrt() as u128,
    };
    while x * x > value {
        x -= 1;
    }
    while (x + 1) * (x + 1) <= value {
        x += 1;
    }
    x
}

/// A message's altitude as the pseudo-measurement it gives: the altitude, metres above the
/// ellipsoid, and its standard deviation (crate docs, § Solving, step 2).
pub(crate) fn altitude_prior(data: &[u8]) -> Option<(Altitude, f64, f64)> {
    modes::altitude(data).map(|altitude| {
        let sigma = match altitude.kind {
            AltitudeKind::Barometric => BARO_SIGMA_M,
            AltitudeKind::Gnss => GNSS_SIGMA_M,
        };
        (altitude, altitude.metres(), sigma)
    })
}

impl Problem {
    pub fn minimum(&self) -> usize {
        if self.altitude.is_some() {
            MIN_RECEIVERS_WITH_ALTITUDE
        } else {
            MIN_RECEIVERS
        }
    }

    /// The feasibility screen (crate docs, § Solving, step 1): exact integer arithmetic. A pair
    /// is feasible when `|t_i - t_j| * c <= baseline + SCREEN_MARGIN_MM` (`t` in picoseconds,
    /// `c` in m/s, the baseline the floored integer square root of the squared millimetre
    /// difference). While any pair is infeasible, the reception in the most infeasible pairs
    /// (ties: the lowest identity) is removed. Returns the survivors' indices, ascending.
    pub fn screen(&self) -> Vec<usize> {
        let n = self.items.len();
        let mut feasible = vec![vec![true; n]; n];
        for i in 0..n {
            for j in i + 1..n {
                let (a, b) = (&self.items[i], &self.items[j]);
                let squared: i128 = (0..3)
                    .map(|axis| {
                        let d = i128::from(a.site_mm[axis]) - i128::from(b.site_mm[axis]);
                        d * d
                    })
                    .sum();
                let baseline = isqrt(squared as u128) as i128;
                let gap = (a.time.ps - b.time.ps).abs();
                let ok = gap * 299_792_458 <= (baseline + SCREEN_MARGIN_MM) * 1_000_000_000;
                feasible[i][j] = ok;
                feasible[j][i] = ok;
            }
        }
        let mut alive: Vec<usize> = (0..n).collect();
        loop {
            let counts: Vec<usize> = alive
                .iter()
                .map(|i| alive.iter().filter(|j| !feasible[*i][**j]).count())
                .collect();
            let Some(worst) = counts.iter().copied().max().filter(|count| *count > 0) else {
                return alive;
            };
            // `alive` is in identity order, so the first maximum is the lowest identity.
            if let Some(position) = counts.iter().position(|count| *count == worst) {
                alive.remove(position);
            }
        }
    }

    /// The timing covariance of a subset, metres squared: each reception's noise on the diagonal
    /// plus `c² G C Gᵀ` from the clock model.
    pub fn covariance(&self, subset: &[usize]) -> Matrix {
        let n = subset.len();
        let mut sigma = Matrix::zeros(n);
        for (a, i) in subset.iter().enumerate() {
            for (b, j) in subset.iter().enumerate().skip(a) {
                let mut value = self.clock_m2.as_ref().map_or(0.0, |clock| clock[*i][*j]);
                if a == b {
                    value += self.items[*i].noise_m2;
                }
                sigma.set(a, b, value);
                sigma.set(b, a, value);
            }
        }
        sigma
    }

    /// One reception's standard deviation, metres: the root of its diagonal entry.
    pub fn sigma(&self, index: usize) -> f64 {
        let clock = self
            .clock_m2
            .as_ref()
            .map_or(0.0, |clock| clock[index][index]);
        (clock + self.items[index].noise_m2).sqrt()
    }

    /// The raw residual of one reception at `params`, metres.
    pub fn residual(&self, index: usize, params: &Params) -> f64 {
        let item = &self.items[index];
        let x = [params[0], params[1], params[2]];
        item.z - params[3] - linalg::norm(linalg::sub(x, item.site))
    }

    /// Whitened residuals and Jacobian of a subset at `params`, the altitude row last.
    pub fn whitened(
        &self,
        subset: &[usize],
        whitener: &Cholesky,
        params: &Params,
    ) -> (Vec<f64>, Vec<[f64; 4]>) {
        let x = [params[0], params[1], params[2]];
        let mut residuals = Vec::with_capacity(subset.len() + 1);
        let mut columns = [
            Vec::with_capacity(subset.len()),
            Vec::with_capacity(subset.len()),
            Vec::with_capacity(subset.len()),
            Vec::with_capacity(subset.len()),
        ];
        for index in subset {
            let item = &self.items[*index];
            let delta = linalg::sub(x, item.site);
            let range = linalg::norm(delta);
            residuals.push(item.z - params[3] - range);
            for axis in 0..3 {
                columns[axis].push(-delta[axis] / range);
            }
            columns[3].push(-1.0);
        }
        let mut whitened = whitener.forward(&residuals);
        let columns = columns.map(|column| whitener.forward(&column));
        let mut jacobian: Vec<[f64; 4]> = (0..subset.len())
            .map(|row| {
                [
                    columns[0][row],
                    columns[1][row],
                    columns[2][row],
                    columns[3][row],
                ]
            })
            .collect();
        if let Some((_, metres, sigma)) = self.altitude {
            let position = geo::from_ecef(x);
            let up = geo::enu_basis(position.lat_deg, position.lon_deg)[2];
            whitened.push((position.height_m - metres) / sigma);
            jacobian.push([up[0] / sigma, up[1] / sigma, up[2] / sigma, 0.0]);
        }
        (whitened, jacobian)
    }

    pub fn whitener(&self, subset: &[usize]) -> Option<Cholesky> {
        self.covariance(subset).cholesky()
    }

    fn normal(residuals: &[f64], jacobian: &[[f64; 4]]) -> (Matrix, [f64; 4], f64) {
        let mut information = Matrix::zeros(4);
        let mut gradient = [0.0; 4];
        let mut cost = 0.0;
        for (r, row) in residuals.iter().zip(jacobian) {
            cost += r * r;
            for i in 0..4 {
                gradient[i] += row[i] * r;
                for j in 0..4 {
                    information.add(i, j, row[i] * row[j]);
                }
            }
        }
        (information, gradient, cost)
    }

    /// Levenberg-Marquardt from `start` (crate docs, § Solving, step 3).
    pub fn levenberg_marquardt(
        &self,
        subset: &[usize],
        whitener: &Cholesky,
        start: Params,
    ) -> Option<Fit> {
        let mut params = start;
        let (r, j) = self.whitened(subset, whitener, &params);
        let (mut information, mut gradient, mut cost) = Self::normal(&r, &j);
        let mut lambda = LM_LAMBDA;
        for _ in 0..LM_ITERATIONS {
            let mut damped = information.clone();
            for i in 0..4 {
                damped.add(i, i, lambda * information.get(i, i).max(1e-12));
            }
            let step = damped.cholesky()?.solve(&gradient.map(|value| -value));
            let candidate = [
                params[0] + step[0],
                params[1] + step[1],
                params[2] + step[2],
                params[3] + step[3],
            ];
            let (r, j) = self.whitened(subset, whitener, &candidate);
            let (next_information, next_gradient, next_cost) = Self::normal(&r, &j);
            if next_cost.is_finite() && next_cost <= cost {
                params = candidate;
                information = next_information;
                gradient = next_gradient;
                cost = next_cost;
                lambda = (lambda / 10.0).max(1e-12);
                if step.iter().all(|value| value.abs() < LM_TOLERANCE_M) {
                    return Some(Fit {
                        params,
                        cost,
                        information,
                    });
                }
            } else {
                lambda *= 10.0;
                if lambda > 1e12 {
                    break;
                }
            }
        }
        // Converged only if a plain Gauss-Newton step from here is below tolerance.
        let step = information.cholesky()?.solve(&gradient.map(|value| -value));
        step.iter()
            .all(|value| value.abs() < LM_TOLERANCE_M)
            .then_some(Fit {
                params,
                cost,
                information,
            })
    }

    /// Where a solution may be: between the height limits and within range of every receiver
    /// used.
    pub fn plausible(&self, subset: &[usize], params: &Params) -> bool {
        let x = [params[0], params[1], params[2]];
        let height = geo::from_ecef(x).height_m;
        (MIN_HEIGHT_M..=MAX_HEIGHT_M).contains(&height)
            && subset
                .iter()
                .all(|index| linalg::norm(linalg::sub(x, self.items[*index].site)) <= MAX_RANGE_M)
    }

    /// Starting points (crate docs, § Solving, step 2): Bancroft's roots when there are four or
    /// more receptions, then the receivers' centroid lifted to the reported altitude (9 km
    /// without one).
    pub fn starts(&self, subset: &[usize]) -> Vec<Params> {
        let mut starts = Vec::new();
        if subset.len() >= 4 {
            starts.extend(self.bancroft(subset));
        }
        let n = subset.len().max(1) as f64;
        let centroid = subset.iter().fold([0.0; 3], |sum, index| {
            linalg::add(sum, linalg::scale(self.items[*index].site, 1.0 / n))
        });
        let ground = geo::from_ecef(centroid);
        let height = self.altitude.map_or(9_000.0, |(_, metres, _)| metres);
        let x = geo::to_ecef(Geodetic {
            height_m: height,
            ..ground
        });
        let t = subset
            .iter()
            .map(|index| {
                let item = &self.items[*index];
                item.z - linalg::norm(linalg::sub(x, item.site))
            })
            .sum::<f64>()
            / n;
        starts.push([x[0], x[1], x[2], t]);
        // Without Bancroft (three receptions and the altitude: exactly determined) a transmission
        // generally has two roots, and one start finds one: a ring about the centroid at the
        // altitude finds both, so the ambiguity rule can see them (`best_fit`).
        if subset.len() < 4 {
            let basis = geo::enu_basis(ground.lat_deg, ground.lon_deg);
            for radius in RING_RADII_M {
                for step in 0..RING_BEARINGS {
                    let bearing = std::f64::consts::TAU * step as f64 / RING_BEARINGS as f64;
                    let offset = linalg::add(
                        linalg::scale(basis[0], radius * libm::sin(bearing)),
                        linalg::scale(basis[1], radius * libm::cos(bearing)),
                    );
                    let place = geo::from_ecef(linalg::add(centroid, offset));
                    let x = geo::to_ecef(Geodetic {
                        height_m: height,
                        ..place
                    });
                    let t = subset
                        .iter()
                        .map(|index| {
                            let item = &self.items[*index];
                            item.z - linalg::norm(linalg::sub(x, item.site))
                        })
                        .sum::<f64>()
                        / n;
                    starts.push([x[0], x[1], x[2], t]);
                }
            }
        }
        starts
    }

    /// Bancroft's closed form for `z_i = T + |X - s_i|`, in coordinates centred on the sites'
    /// centroid and the earliest time.
    fn bancroft(&self, subset: &[usize]) -> Vec<Params> {
        let n = subset.len() as f64;
        let centroid = subset.iter().fold([0.0; 3], |sum, index| {
            linalg::add(sum, linalg::scale(self.items[*index].site, 1.0 / n))
        });
        let rows: Vec<[f64; 4]> = subset
            .iter()
            .map(|index| {
                let item = &self.items[*index];
                let s = linalg::sub(item.site, centroid);
                [s[0], s[1], s[2], item.z]
            })
            .collect();
        let lorentz =
            |a: &[f64; 4], b: &[f64; 4]| a[0] * b[0] + a[1] * b[1] + a[2] * b[2] - a[3] * b[3];
        let mut btb = Matrix::zeros(4);
        for row in &rows {
            for i in 0..4 {
                for j in 0..4 {
                    btb.add(i, j, row[i] * row[j]);
                }
            }
        }
        let Some(factor) = btb.cholesky() else {
            return Vec::new();
        };
        let pseudo = |rhs: &[f64]| -> [f64; 4] {
            let mut bt = [0.0; 4];
            for (row, value) in rows.iter().zip(rhs) {
                for i in 0..4 {
                    bt[i] += row[i] * value;
                }
            }
            let x = factor.solve(&bt);
            [x[0], x[1], x[2], -x[3]]
        };
        let ones = vec![1.0; rows.len()];
        let alpha: Vec<f64> = rows.iter().map(|row| 0.5 * lorentz(row, row)).collect();
        let u = pseudo(&ones);
        let v = pseudo(&alpha);
        let a = lorentz(&u, &u);
        let b = 2.0 * (lorentz(&u, &v) - 1.0);
        let c = lorentz(&v, &v);
        let mut lambdas = Vec::new();
        if a.abs() < 1e-30 {
            if b.abs() > 1e-30 {
                lambdas.push(-c / b);
            }
        } else {
            let discriminant = b * b - 4.0 * a * c;
            if discriminant >= 0.0 {
                let root = discriminant.sqrt();
                lambdas.push((-b - root) / (2.0 * a));
                lambdas.push((-b + root) / (2.0 * a));
            }
        }
        lambdas
            .into_iter()
            .map(|lambda| {
                [
                    lambda * u[0] + v[0] + centroid[0],
                    lambda * u[1] + v[1] + centroid[1],
                    lambda * u[2] + v[2] + centroid[2],
                    lambda * u[3] + v[3],
                ]
            })
            .filter(|params| params.iter().all(|value| value.is_finite()))
            .collect()
    }

    /// The best plausible fit of a subset from the given starts: the lowest cost, ties to the
    /// earlier start. Refused as ambiguous when another plausible fit costs at most
    /// `AMBIGUOUS_COST` more and lies outside the best's own 10^-6 ellipsoid (squared
    /// Mahalanobis distance of the four parameters under the best's information above
    /// `chi2_limit(4)`): two places explain the receptions alike, as an exactly determined
    /// transmission's two roots do, and the covariance of either would describe neither.
    pub fn best_fit(&self, subset: &[usize], starts: &[Params]) -> Result<Fit, SolveError> {
        let whitener = self.whitener(subset).ok_or(SolveError::Singular)?;
        let mut fits: Vec<Fit> = Vec::new();
        let mut converged = false;
        for start in starts {
            let Some(fit) = self.levenberg_marquardt(subset, &whitener, *start) else {
                continue;
            };
            converged = true;
            if self.plausible(subset, &fit.params) {
                fits.push(fit);
            }
        }
        let Some(at) = (0..fits.len()).fold(None, |best: Option<usize>, index| match best {
            Some(top) if fits[index].cost >= fits[top].cost => best,
            _ => Some(index),
        }) else {
            return Err(if converged {
                SolveError::OutOfRange
            } else {
                SolveError::NoConvergence
            });
        };
        let best = &fits[at];
        let limit = chi2_limit(4);
        for other in &fits {
            if other.cost > best.cost + AMBIGUOUS_COST {
                continue;
            }
            let delta: Vec<f64> = (0..4).map(|i| other.params[i] - best.params[i]).collect();
            let moved = best.information.mul_vec(&delta);
            let distance: f64 = delta.iter().zip(&moved).map(|(a, b)| a * b).sum();
            if distance > limit {
                return Err(SolveError::Ambiguous);
            }
        }
        Ok(fits.swap_remove(at))
    }
}

/// Solves one transmission's problem (crate docs, § Solving), its timing covariance the pairwise
/// path's network adjustment (`pair::Prepared::normalise`).
pub(crate) fn solve_problem(problem: &Problem) -> Result<Solution, SolveError> {
    if problem.clock_m2.is_none() {
        return Err(SolveError::Uncovered);
    }
    let screened = problem.screen();
    let minimum = problem.minimum();
    let mut included: BTreeSet<usize> = screened.iter().copied().collect();
    let mut previous: Option<Params> = None;
    for _ in 0..2 * screened.len() + 2 {
        if included.len() < minimum {
            return Err(SolveError::TooFew(included.len()));
        }
        let subset: Vec<usize> = included.iter().copied().collect();
        let starts = match previous {
            Some(params) => {
                let mut starts = vec![params];
                starts.extend(problem.starts(&subset));
                starts
            }
            None => problem.starts(&subset),
        };
        let fit = problem.best_fit(&subset, &starts)?;
        previous = Some(fit.params);
        let z: Vec<(usize, f64)> = screened
            .iter()
            .map(|index| {
                (
                    *index,
                    problem.residual(*index, &fit.params).abs() / problem.sigma(*index),
                )
            })
            .collect();
        // Worst included above the threshold: remove it. Ties go to the lowest identity, which
        // is the lowest index.
        let worst = z
            .iter()
            .filter(|(index, value)| included.contains(index) && *value > OUTLIER_Z)
            .fold(
                None,
                |best: Option<(usize, f64)>, (index, value)| match best {
                    Some((_, top)) if *value <= top => best,
                    _ => Some((*index, *value)),
                },
            );
        if let Some((index, _)) = worst {
            included.remove(&index);
            continue;
        }
        let readmit = z
            .iter()
            .filter(|(index, value)| !included.contains(index) && *value <= OUTLIER_Z)
            .fold(
                None,
                |best: Option<(usize, f64)>, (index, value)| match best {
                    Some((_, top)) if *value >= top => best,
                    _ => Some((*index, *value)),
                },
            );
        if let Some((index, _)) = readmit {
            included.insert(index);
            continue;
        }
        let dof = (subset.len() + usize::from(problem.altitude.is_some())).saturating_sub(4);
        let dof = u32::try_from(dof).unwrap_or(u32::MAX);
        let whitener = problem.whitener(&subset).ok_or(SolveError::Singular)?;
        let (_, jacobian) = problem.whitened(&subset, &whitener, &fit.params);
        if fit.cost > published_chi2_limit(dof, rounding_norm(&jacobian)) {
            return Err(SolveError::Inconsistent);
        }
        return finish(problem, &subset, &fit, dof);
    }
    Err(SolveError::NoFixedPoint)
}

fn finish(
    problem: &Problem,
    subset: &[usize],
    fit: &Fit,
    dof: u32,
) -> Result<Solution, SolveError> {
    let inverse = fit
        .information
        .cholesky()
        .ok_or(SolveError::Singular)?
        .inverse();
    let covariance = published(&inverse);
    let mut check = Matrix::zeros(3);
    for (i, row) in covariance.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            check.set(i, j, *value);
        }
    }
    if (0..3).any(|axis| covariance[axis][axis] > MAX_SIGMA_M * MAX_SIGMA_M)
        || check.cholesky().is_none()
    {
        return Err(SolveError::Uncertain);
    }
    let ecef = [fit.params[0], fit.params[1], fit.params[2]];
    let transmit = problem.reference_ps + (fit.params[3] / C * PS as f64).round() as i128;
    Ok(Solution {
        spec: SPEC_VERSION,
        ecef,
        position: geo::from_ecef(ecef),
        transmit_ps: i64::try_from(transmit).map_err(|_| SolveError::OutOfRange)?,
        covariance,
        considered: problem.items.iter().map(|item| item.id).collect(),
        used: subset
            .iter()
            .map(|index| problem.items[*index].id)
            .collect(),
        altitude: problem.altitude.map(|(altitude, _, _)| altitude),
        chi2: fit.cost,
        dof,
    })
}
