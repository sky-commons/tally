//! What the truth itself is off by (crate docs, § The truth's own error): a textbook solver that
//! needs no clock model, run on the receptions of LocaRDS-verified GNSS Radarcapes alone, whose
//! stamps are one UTC scale to some 70 ns (measured here: verified Radarcape pairs agree to 0 to
//! 200 ns with a spread of 40 to 150 ns over the hour). Its fixes' residuals fit that noise (the
//! median chi-square per degree of freedom is reported), so what separates them from the reported
//! position beyond their own covariance is the report's error, which `score::TruthModel` is fitted
//! to.

use std::collections::BTreeMap;

use tally_mlat_solver::geo::{self, C, Geodetic};
use tally_mlat_solver::linalg::{self, Vec3};

use crate::locards::{Row, Sensor};
use crate::score::Planar;

/// One standard deviation of a verified Radarcape's stamp, seconds.
pub const TIMING_SIGMA_S: f64 = 70e-9;
/// One standard deviation of the height pseudo-measurement, the report's own GNSS height, metres.
pub const HEIGHT_SIGMA_M: f64 = 15.0;
/// Where each solve starts, metres east, north and up of the truth (ECEF axes; the solve's
/// minimum is the data's, not the start's).
const START_OFFSET_M: Vec3 = [1500.0, -1200.0, 300.0];
const ITERATIONS: usize = 60;

/// The reference: the verified Radarcapes' sites.
pub struct Reference {
    sites: BTreeMap<u32, Vec3>,
}

/// One reference fix: as a truth with errors judges it, and its chi-square per degree of freedom.
pub struct Fix {
    pub planar: Planar,
    pub chi2_per_dof: f64,
}

impl Reference {
    /// The sensors LocaRDS verified that are Radarcapes on the GNSS scale (`gnss`).
    pub fn new(sensors: &[Sensor], gnss: &dyn Fn(u32) -> bool) -> Self {
        let sites = sensors
            .iter()
            .filter(|s| s.good && s.kind == "Radarcape" && gnss(s.serial))
            .map(|s| {
                (
                    s.serial,
                    geo::to_ecef(Geodetic {
                        lat_deg: s.lat_deg,
                        lon_deg: s.lon_deg,
                        height_m: s.height_m,
                    }),
                )
            })
            .collect();
        Self { sites }
    }

    /// The reference fix of `row`, when four or more distinct verified Radarcapes heard it, it has
    /// a GNSS height, the solve converges, and its chi-square passes at 0.999.
    pub fn solve(&self, row: &Row, velocity: [f64; 2]) -> Option<Fix> {
        let geo_m = row.geo_m?;
        let mut heard: BTreeMap<u32, f64> = BTreeMap::new();
        for (sensor, ns) in &row.measurements {
            if self.sites.contains_key(sensor) && heard.insert(*sensor, *ns).is_some() {
                return None;
            }
        }
        if heard.len() < 4 {
            return None;
        }
        let truth = geo::to_ecef(Geodetic {
            lat_deg: row.lat_deg,
            lon_deg: row.lon_deg,
            height_m: geo_m,
        });
        let truth_radius = linalg::norm(truth);
        let rows: Vec<(Vec3, f64)> = heard
            .iter()
            .map(|(sensor, ns)| (self.sites[sensor], ns * 1e-9 * C))
            .collect();
        let sigma = TIMING_SIGMA_S * C;
        // The cost and the normal equations at p = (x, y, z, transmit time in metres).
        let system = |p: [f64; 4]| {
            let mut h = [[0.0; 4]; 4];
            let mut g = [0.0; 4];
            let mut cost = 0.0;
            let mut add = |j: [f64; 4], r: f64, w: f64| {
                cost += w * r * r;
                for a in 0..4 {
                    g[a] += w * j[a] * r;
                    for b in 0..4 {
                        h[a][b] += w * j[a] * j[b];
                    }
                }
            };
            let x = [p[0], p[1], p[2]];
            for (site, t) in &rows {
                let range = linalg::norm(linalg::sub(x, *site));
                let d = linalg::sub(x, *site);
                add(
                    [d[0] / range, d[1] / range, d[2] / range, 1.0],
                    t - p[3] - range,
                    1.0 / (sigma * sigma),
                );
            }
            let radius = linalg::norm(x);
            add(
                [x[0] / radius, x[1] / radius, x[2] / radius, 0.0],
                truth_radius - radius,
                1.0 / (HEIGHT_SIGMA_M * HEIGHT_SIGMA_M),
            );
            (h, g, cost)
        };
        let start = linalg::add(truth, START_OFFSET_M);
        let mut times: Vec<f64> = rows
            .iter()
            .map(|(site, t)| t - linalg::norm(linalg::sub(start, *site)))
            .collect();
        times.sort_by(f64::total_cmp);
        let mut p = [start[0], start[1], start[2], times[times.len() / 2]];
        let mut lambda = 1e-3;
        let mut converged = false;
        for _ in 0..ITERATIONS {
            let (h, g, cost) = system(p);
            let mut damped = h;
            for (a, row) in damped.iter_mut().enumerate() {
                row[a] *= 1.0 + lambda;
            }
            let step = solve4(damped, g)?;
            let next = [
                p[0] + step[0],
                p[1] + step[1],
                p[2] + step[2],
                p[3] + step[3],
            ];
            if system(next).2 <= cost {
                p = next;
                lambda /= 10.0;
                if step[..3].iter().all(|s| s.abs() < 1e-3) {
                    converged = true;
                    break;
                }
            } else {
                lambda *= 10.0;
            }
        }
        let (h, _, cost) = system(p);
        let x = [p[0], p[1], p[2]];
        let dof = heard.len() - 3;
        if !converged || linalg::norm(linalg::sub(x, truth)) > 20_000.0 || cost > chi2_999(dof) {
            return None;
        }
        let covariance = invert4(h)?;
        let at = geo::from_ecef(truth);
        let basis = geo::enu_basis(at.lat_deg, at.lon_deg);
        let error = linalg::sub(truth, x);
        let mut planar = [[0.0; 2]; 2];
        for (i, row) in planar.iter_mut().enumerate() {
            for (j, value) in row.iter_mut().enumerate() {
                let mut sum = 0.0;
                for a in 0..3 {
                    for b in 0..3 {
                        sum += basis[i][a] * covariance[a][b] * basis[j][b];
                    }
                }
                *value = sum;
            }
        }
        let speed = velocity[0].hypot(velocity[1]);
        Some(Fix {
            planar: Planar {
                error: [linalg::dot(error, basis[0]), linalg::dot(error, basis[1])],
                stripped: planar,
                published: planar,
                along: (speed > 50.0).then(|| [velocity[0] / speed, velocity[1] / speed]),
            },
            chi2_per_dof: cost / dof as f64,
        })
    }
}

/// The 0.999 point of chi-square with `dof` degrees of freedom (Wilson-Hilferty).
fn chi2_999(dof: usize) -> f64 {
    let k = dof as f64;
    let z = 3.090_232;
    let a = 2.0 / (9.0 * k);
    k * (1.0 - a + z * a.sqrt()).powi(3)
}

/// Solves a 4 x 4 system by Gaussian elimination with partial pivoting.
fn solve4(mut a: [[f64; 4]; 4], mut b: [f64; 4]) -> Option<[f64; 4]> {
    for col in 0..4 {
        let pivot = (col..4).max_by(|&i, &j| a[i][col].abs().total_cmp(&a[j][col].abs()))?;
        if a[pivot][col].abs() < 1e-300 || !a[pivot][col].is_finite() {
            return None;
        }
        a.swap(col, pivot);
        b.swap(col, pivot);
        for row in col + 1..4 {
            let f = a[row][col] / a[col][col];
            for k in col..4 {
                a[row][k] -= f * a[col][k];
            }
            b[row] -= f * b[col];
        }
    }
    let mut x = [0.0; 4];
    for row in (0..4).rev() {
        let mut sum = b[row];
        for k in row + 1..4 {
            sum -= a[row][k] * x[k];
        }
        x[row] = sum / a[row][row];
    }
    x.iter().all(|v| v.is_finite()).then_some(x)
}

fn invert4(a: [[f64; 4]; 4]) -> Option<[[f64; 4]; 4]> {
    let mut out = [[0.0; 4]; 4];
    for col in 0..4 {
        let mut e = [0.0; 4];
        e[col] = 1.0;
        let x = solve4(a, e)?;
        for row in 0..4 {
            out[row][col] = x[row];
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_solves_exact_stamps_to_the_truth() {
        let sensors: Vec<Sensor> = [(50.0, 8.0), (50.8, 9.1), (49.3, 9.4), (50.2, 7.0)]
            .iter()
            .enumerate()
            .map(|(i, (lat, lon))| Sensor {
                serial: i as u32 + 1,
                lat_deg: *lat,
                lon_deg: *lon,
                height_m: 200.0,
                kind: "Radarcape".to_owned(),
                good: true,
            })
            .collect();
        let reference = Reference::new(&sensors, &|_| true);
        let truth = geo::to_ecef(Geodetic {
            lat_deg: 50.1,
            lon_deg: 8.4,
            height_m: 10_000.0,
        });
        let measurements = sensors
            .iter()
            .map(|s| {
                let site = geo::to_ecef(Geodetic {
                    lat_deg: s.lat_deg,
                    lon_deg: s.lon_deg,
                    height_m: s.height_m,
                });
                (
                    s.serial,
                    1e6 + linalg::norm(linalg::sub(truth, site)) / C * 1e9,
                )
            })
            .collect();
        let row = Row {
            id: 1,
            server_s: 0.0,
            aircraft: 1,
            lat_deg: 50.1,
            lon_deg: 8.4,
            baro_m: Some(10_100.0),
            geo_m: Some(10_000.0),
            measurements,
        };
        let fix = reference.solve(&row, [200.0, 0.0]);
        let Some(fix) = fix else {
            panic!("no fix");
        };
        assert!(fix.planar.error[0].hypot(fix.planar.error[1]) < 0.01);
        assert!(fix.chi2_per_dof < 1e-6);
    }
}
