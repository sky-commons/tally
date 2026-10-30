//! Scoring a published fix against the withheld aircraft's own report (crate docs, § What
//! is measured).

use tally_mlat_solver::geo::{self, Geodetic};
use tally_mlat_solver::linalg::{self, Vec3};
use tally_mlat_solver::solve::{ERROR_FLOOR_M, ERROR_INFLATION};
use tally_wire::Fix;

/// The 95% points of chi-square with one, two and three degrees of freedom.
pub const CHI2_1_95: f64 = 3.841_459;
pub const CHI2_2_95: f64 = 5.991_465;
pub const CHI2_3_95: f64 = 7.814_728;

/// Where a withheld transmission truly was: the aircraft's own ADS-B report of it.
#[derive(Clone, Copy, Debug)]
pub struct Truth {
    pub aircraft: u32,
    pub heard_ms: u64,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// The GNSS height, when the report had one.
    pub geo_m: Option<f64>,
    pub baro_m: f64,
    /// LocaRDS's verification of the aircraft's positions.
    pub trusted: Option<bool>,
    /// East and north speed, metres per second, from its neighbouring reports (zero when it has
    /// none within 10 s).
    pub velocity: [f64; 2],
}

/// A count of truths inside an ellipse.
#[derive(Clone, Copy, Debug, Default)]
pub struct Count {
    pub inside: u64,
    pub total: u64,
}

impl Count {
    pub fn add(&mut self, inside: bool) {
        self.total += 1;
        self.inside += u64::from(inside);
    }

    pub fn rate(&self) -> f64 {
        self.inside as f64 / self.total.max(1) as f64
    }
}

impl std::fmt::Display for Count {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.3} of {}", self.rate(), self.total)
    }
}

/// One slice's coverage: horizontal (the east-north block, two degrees of freedom) and 3D (when
/// the report had a GNSS height), each under the mathematics' own covariance (floor and inflation
/// stripped, as the simulator's calibration measures) and under what is published.
#[derive(Clone, Debug, Default)]
pub struct Slice {
    pub horizontal: Count,
    pub horizontal_published: Count,
    pub spatial: Count,
    pub spatial_published: Count,
    /// Across the track only (one degree of freedom), under the stripped covariance: what the
    /// truth's own lag along the track (an ADS-B position some tenths of a second old) cannot
    /// touch.
    pub cross: Count,
    /// Each solution's squared Mahalanobis distance, horizontal and across the track, stripped.
    pub horizontal_d2: Vec<f64>,
    pub cross_d2: Vec<f64>,
    pub errors_m: Vec<f64>,
    /// Signed along-track error, metres (positive: the fix ahead of the report).
    pub along_m: Vec<f64>,
    /// Horizontal sigma claimed (root half trace of the stripped east-north block).
    pub sigmas_m: Vec<f64>,
    /// Each solution as a truth with errors of its own judges it (`TruthModel`).
    pub planar: Vec<Planar>,
}

/// A horizontal fix as a truth with errors of its own judges it: the truth less the fix, east and
/// north; its covariance stripped of the floor and inflation and as published; and the unit
/// vector along the track, when the aircraft was moving.
#[derive(Clone, Copy, Debug)]
pub struct Planar {
    pub error: [f64; 2],
    pub stripped: [[f64; 2]; 2],
    pub published: [[f64; 2]; 2],
    pub along: Option<[f64; 2]>,
}

/// What the dataset's truth is itself off by, measured by `reference`: an ADS-B position lags its
/// aircraft along the track by `lag_m` (the median), and scatters by `along_sd_m` along it and
/// `cross_sd_m` across it, each the least for which a reference fix's 95% interval, widened by it,
/// holds the truth 95% of the time. Judged against the truth widened so, a fix whose own
/// covariance is honest covers 95% as the reference does.
#[derive(Clone, Copy, Debug, Default)]
pub struct TruthModel {
    pub lag_m: f64,
    pub along_sd_m: f64,
    pub cross_sd_m: f64,
    pub samples: usize,
}

impl TruthModel {
    /// Fits the model to reference fixes (`reference::Reference`), each with a velocity.
    pub fn fit(reference: &[Planar]) -> Self {
        let mut along = Vec::new();
        let mut across = Vec::new();
        for planar in reference {
            let Some(u) = planar.along else { continue };
            let w = [-u[1], u[0]];
            let project = |v: [f64; 2]| {
                let c = planar.stripped;
                v[0] * v[0] * c[0][0] + 2.0 * v[0] * v[1] * c[0][1] + v[1] * v[1] * c[1][1]
            };
            // The fix ahead of the truth along the track is positive.
            let a = -(planar.error[0] * u[0] + planar.error[1] * u[1]);
            let x = planar.error[0] * w[0] + planar.error[1] * w[1];
            along.push((a, project(u)));
            across.push((x, project(w)));
        }
        let lag = Slice::percentile(&along.iter().map(|(a, _)| *a).collect::<Vec<_>>(), 0.5);
        let centred: Vec<(f64, f64)> = along.iter().map(|(a, v)| (a - lag, *v)).collect();
        Self {
            lag_m: if lag.is_finite() { lag } else { 0.0 },
            along_sd_m: widening(&centred),
            cross_sd_m: widening(&across),
            samples: along.len(),
        }
    }

    /// Whether the truth, widened by the model, is inside `planar`'s 95% ellipse (stripped or
    /// published).
    pub fn inside(&self, planar: &Planar, published: bool) -> bool {
        let Some(u) = planar.along else {
            return false;
        };
        let w = [-u[1], u[0]];
        let mut c = if published {
            planar.published
        } else {
            planar.stripped
        };
        let (a2, c2) = (self.along_sd_m.powi(2), self.cross_sd_m.powi(2));
        for i in 0..2 {
            for j in 0..2 {
                c[i][j] += a2 * u[i] * u[j] + c2 * w[i] * w[j];
            }
        }
        let error = [
            planar.error[0] + self.lag_m * u[0],
            planar.error[1] + self.lag_m * u[1],
        ];
        distance(error, c).is_some_and(|d2| d2 < CHI2_2_95)
    }
}

/// The least standard deviation which, added to each (error, variance), puts 95% of the errors
/// inside their 95% intervals (bisection to a centimetre).
fn widening(samples: &[(f64, f64)]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let covered = |extra: f64| {
        let inside = samples
            .iter()
            .filter(|(e, v)| e * e < CHI2_1_95 * (v + extra * extra))
            .count();
        inside as f64 >= 0.95 * samples.len() as f64
    };
    let (mut low, mut high) = (0.0, 10_000.0);
    if covered(low) {
        return 0.0;
    }
    while high - low > 0.01 {
        let middle = (low + high) / 2.0;
        if covered(middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    high
}

/// What one solution scored.
#[derive(Clone, Copy, Debug)]
pub struct Scored {
    pub horizontal_d2: Option<f64>,
    pub horizontal_published_d2: Option<f64>,
    pub spatial_d2: Option<f64>,
    pub spatial_published_d2: Option<f64>,
    pub cross_d2: Option<f64>,
    pub error_m: f64,
    pub along_m: f64,
    pub sigma_m: f64,
    /// The truth less the fix, east and north (at the fix's height), and up (from the report's
    /// GNSS height, when it had one), metres.
    pub east_m: f64,
    pub north_m: f64,
    pub up_m: Option<f64>,
    /// The east-north-up covariance with the floor and inflation stripped.
    pub stripped: [[f64; 3]; 3],
    pub planar: Planar,
}

impl Slice {
    pub fn add(&mut self, scored: &Scored) {
        let inside = |d2: Option<f64>, limit: f64| d2.is_some_and(|d2| d2 < limit);
        self.horizontal.add(inside(scored.horizontal_d2, CHI2_2_95));
        self.horizontal_published
            .add(inside(scored.horizontal_published_d2, CHI2_2_95));
        if scored.spatial_published_d2.is_some() {
            self.spatial.add(inside(scored.spatial_d2, CHI2_3_95));
            self.spatial_published
                .add(inside(scored.spatial_published_d2, CHI2_3_95));
        }
        if let Some(d2) = scored.cross_d2 {
            self.cross.add(d2 < CHI2_1_95);
            self.cross_d2.push(d2);
        }
        self.horizontal_d2
            .push(scored.horizontal_d2.unwrap_or(f64::INFINITY));
        self.planar.push(scored.planar);
        self.errors_m.push(scored.error_m);
        self.along_m.push(scored.along_m);
        self.sigmas_m.push(scored.sigma_m);
    }

    pub fn percentile(values: &[f64], at: f64) -> f64 {
        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);
        sorted
            .get(((sorted.len() as f64 - 1.0) * at).round().max(0.0) as usize)
            .copied()
            .unwrap_or(f64::NAN)
    }

    /// The coverage against the truth widened by `model` (stripped, published).
    pub fn against(&self, model: &TruthModel) -> (Count, Count) {
        let (mut stripped, mut published) = (Count::default(), Count::default());
        for planar in self.planar.iter().filter(|p| p.along.is_some()) {
            stripped.add(model.inside(planar, false));
            published.add(model.inside(planar, true));
        }
        (stripped, published)
    }

    pub fn summary(&self, model: &TruthModel) -> String {
        if self.horizontal.total == 0 {
            return "none".to_owned();
        }
        let (against, against_published) = self.against(model);
        // The factor every standard deviation would need for the 95% ellipse to hold 95%.
        let scale = |d2: &[f64], limit: f64| (Self::percentile(d2, 0.95) / limit).sqrt();
        format!(
            "against the truth model {against} (published {:.3}); against the raw truth: \
             horizontal {} (published {}); 3D {} (published {}); cross-track {} (scale needed \
             {:.2} horizontal, {:.2} cross-track); horizontal error median {:.1} m, p95 {:.1} m; \
             claimed sigma median {:.1} m; along-track median {:+.1} m",
            against_published.rate(),
            self.horizontal,
            self.horizontal_published.rate(),
            self.spatial,
            self.spatial_published.rate(),
            self.cross,
            scale(&self.horizontal_d2, CHI2_2_95),
            scale(&self.cross_d2, CHI2_1_95),
            Self::percentile(&self.errors_m, 0.5),
            Self::percentile(&self.errors_m, 0.95),
            Self::percentile(&self.sigmas_m, 0.5),
            Self::percentile(&self.along_m, 0.5),
        )
    }
}

/// The squared Mahalanobis distance of `error` under `covariance` (Cholesky; none when not
/// positive definite, which counts as missing the truth).
pub fn distance<const N: usize>(error: [f64; N], covariance: [[f64; N]; N]) -> Option<f64> {
    let mut l = [[0.0; N]; N];
    for i in 0..N {
        for j in 0..=i {
            let mut sum = covariance[i][j];
            for k in 0..j {
                sum -= l[i][k] * l[j][k];
            }
            if i == j {
                if sum <= 0.0 || !sum.is_finite() {
                    return None;
                }
                l[i][i] = sum.sqrt();
            } else {
                l[i][j] = sum / l[j][j];
            }
        }
    }
    let mut y = [0.0; N];
    for i in 0..N {
        let mut sum = error[i];
        for k in 0..i {
            sum -= l[i][k] * y[k];
        }
        y[i] = sum / l[i][i];
    }
    Some(y.iter().map(|v| v * v).sum())
}

/// A published east-north-up covariance, and the same with the floor and inflation taken off
/// (`solve::ERROR_INFLATION`, `ERROR_FLOOR_M`): the floor is the same on every axis of any frame,
/// so it comes off the ENU diagonal as it went on the ECEF one.
fn covariances(solution: &Fix) -> ([[f64; 3]; 3], [[f64; 3]; 3]) {
    let c = solution.covariance;
    let published = [
        [f64::from(c.xx), f64::from(c.xy), f64::from(c.xz)],
        [f64::from(c.xy), f64::from(c.yy), f64::from(c.yz)],
        [f64::from(c.xz), f64::from(c.yz), f64::from(c.zz)],
    ];
    let k = ERROR_INFLATION * ERROR_INFLATION;
    let floor = ERROR_FLOOR_M * ERROR_FLOOR_M;
    let mut stripped = published;
    for (i, row) in stripped.iter_mut().enumerate() {
        for (j, value) in row.iter_mut().enumerate() {
            if i == j {
                *value -= floor;
            }
            *value /= k;
        }
    }
    (published, stripped)
}

fn ecef(lat_deg: f64, lon_deg: f64, height_m: f64) -> Vec3 {
    geo::to_ecef(Geodetic {
        lat_deg,
        lon_deg,
        height_m,
    })
}

/// Scores `solution` against `truth`. The error is taken in the solution's own east-north-up
/// frame, the frame its covariance is published in.
pub fn score(solution: &Fix, truth: &Truth) -> Scored {
    let lat = f64::from(solution.lat_e7) * 1e-7;
    let lon = f64::from(solution.lon_e7) * 1e-7;
    let solved_height = solution.alt_hae_mm.map(|mm| f64::from(mm) / 1000.0);
    // Horizontally, the truth is put at the solution's own height, so a height error does not
    // leak into east and north through the frame.
    let height = solved_height.unwrap_or(truth.baro_m);
    let at = ecef(lat, lon, height);
    let basis = geo::enu_basis(lat, lon);
    let level = linalg::sub(ecef(truth.lat_deg, truth.lon_deg, height), at);
    let east = linalg::dot(level, basis[0]);
    let north = linalg::dot(level, basis[1]);
    let (published, stripped) = covariances(solution);
    let block = |c: [[f64; 3]; 3]| [[c[0][0], c[0][1]], [c[1][0], c[1][1]]];
    let spatial = truth.geo_m.zip(solved_height).map(|(geo_m, _)| {
        let error = linalg::sub(ecef(truth.lat_deg, truth.lon_deg, geo_m), at);
        [
            linalg::dot(error, basis[0]),
            linalg::dot(error, basis[1]),
            linalg::dot(error, basis[2]),
        ]
    });
    let speed = truth.velocity[0].hypot(truth.velocity[1]);
    // Across the track: the unit vector left of the velocity, and the stripped variance along it.
    let cross_d2 = (speed > 1.0).then(|| {
        let unit = [-truth.velocity[1] / speed, truth.velocity[0] / speed];
        let c = block(stripped);
        let variance = unit[0] * unit[0] * c[0][0]
            + 2.0 * unit[0] * unit[1] * c[0][1]
            + unit[1] * unit[1] * c[1][1];
        let across = east * unit[0] + north * unit[1];
        across * across / variance
    });
    // The truth minus the fix along the track, negated: positive when the fix is ahead.
    let along = if speed > 1.0 {
        -(east * truth.velocity[0] + north * truth.velocity[1]) / speed
    } else {
        0.0
    };
    Scored {
        horizontal_d2: distance([east, north], block(stripped)),
        horizontal_published_d2: distance([east, north], block(published)),
        spatial_d2: spatial.and_then(|e| distance(e, stripped)),
        spatial_published_d2: spatial.and_then(|e| distance(e, published)),
        cross_d2: cross_d2.filter(|d2| d2.is_finite()),
        east_m: east,
        north_m: north,
        up_m: spatial.map(|e| e[2]),
        stripped,
        error_m: east.hypot(north),
        along_m: along,
        sigma_m: ((stripped[0][0] + stripped[1][1]) / 2.0).max(0.0).sqrt(),
        planar: Planar {
            error: [east, north],
            stripped: block(stripped),
            published: block(published),
            along: (speed > 50.0).then(|| [truth.velocity[0] / speed, truth.velocity[1] / speed]),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_is_the_squared_mahalanobis_length() {
        let d = distance([3.0, 4.0], [[9.0, 0.0], [0.0, 16.0]]);
        assert!(d.is_some_and(|d| (d - 2.0).abs() < 1e-12));
        assert_eq!(distance([1.0, 1.0], [[1.0, 2.0], [2.0, 1.0]]), None);
    }
}
