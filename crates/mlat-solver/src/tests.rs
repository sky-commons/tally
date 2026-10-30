//! End-to-end tests over the simulator: the pairwise path as an engine runs it (`pair_compare`),
//! and what every test of it shares: the truth, the scenarios, and how a fix's error is measured.
//! Every test runs the engine as the crate docs specify it (§ The trailing window, § Areas): the
//! simulator's batches arrive at a holder as feeders deliver them, every second the holder seals,
//! every `REFIT_EVERY` it refits every area over its trailing window, and solves what is due.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use tally_wire::budget::{REFIT_EVERY_MS, TRAILING_WINDOW_MS};

use crate::arrived::{Arrived, Considered, HELD_MS, Limits, SETTLE_MS};
use crate::geo;
use crate::linalg::{self, Matrix};
use crate::obs::{ObservationId, Reception};
use crate::scope::{Inputs, Sites, Trailing};
use crate::sim::{self, Arrival, Rng, Scenario, Simulation};
use crate::solve::Solution;
use crate::{SPEC_VERSION, publish};

#[path = "pair_tests.rs"]
mod pair_compare;

type Result<T = ()> = std::result::Result<T, String>;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The 95% point of chi-square with three degrees of freedom.
const CHI2_3_95: f64 = 7.814_728;

fn truth_of(simulation: &Simulation) -> BTreeMap<ObservationId, usize> {
    simulation
        .receptions
        .iter()
        .zip(&simulation.sources)
        .map(|(reception, source)| (reception.id(), *source))
        .collect()
}

/// The squared Mahalanobis distance of an error under a covariance.
fn distance(error: &[f64], covariance: &Matrix) -> Option<f64> {
    let solved = covariance.cholesky()?.solve(error);
    Some(error.iter().zip(&solved).map(|(a, b)| a * b).sum())
}

/// A published covariance without its floor and inflation (`solve::ERROR_INFLATION`): the
/// mathematics' own, which the simulator calibrates. What is published only adds to it.
fn raw(published: &[[f64; 3]; 3]) -> [[f64; 3]; 3] {
    let k = crate::solve::ERROR_INFLATION * crate::solve::ERROR_INFLATION;
    let floor = crate::solve::ERROR_FLOOR_M * crate::solve::ERROR_FLOOR_M;
    let mut out = *published;
    for (i, row) in out.iter_mut().enumerate() {
        for (j, value) in row.iter_mut().enumerate() {
            if i == j {
                *value -= floor;
            }
            *value /= k;
        }
    }
    out
}

/// The squared Mahalanobis distance of a solution from the truth, under its own covariance.
fn mahalanobis(solution: &Solution, truth: [f64; 3]) -> Option<f64> {
    mahalanobis_under(&raw(&solution.covariance), solution, truth)
}

fn mahalanobis_under(of: &[[f64; 3]; 3], solution: &Solution, truth: [f64; 3]) -> Option<f64> {
    let error = linalg::sub(solution.ecef, truth);
    let mut covariance = Matrix::zeros(3);
    for (i, row) in of.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            covariance.set(i, j, *value);
        }
    }
    distance(&error, &covariance)
}

/// The horizontal distance of a solution from the truth, metres.
fn horizontal_m(solution: &Solution, truth: [f64; 3]) -> f64 {
    let error = linalg::sub(solution.ecef, truth);
    let basis = geo::enu_basis(solution.position.lat_deg, solution.position.lon_deg);
    linalg::dot(error, basis[0]).hypot(linalg::dot(error, basis[1]))
}

/// A step of the engine, milliseconds: a slice of signed wall clock.
const STEP_MS: u64 = crate::arrived::SLICE_MS;

/// The default scenario, `duration_s` long.
fn of(seed: u64, duration_s: f64) -> Scenario {
    Scenario {
        duration_s,
        ..Scenario::new(seed)
    }
}

/// The receiver whose counter steps once, when, and by how much; and the one that steps every
/// two seconds.
const JUMPER: usize = 3;
const BAD: usize = 4;

/// When the jumper's counter steps: a third of the way in, past a whole first window.
fn jump_at_s(duration_s: f64) -> f64 {
    (duration_s / 3.0).max(25.0).floor() + 0.3
}

/// The sweep's scenarios, by name: each a list of seeds' scenarios.
fn scenarios(duration_s: f64) -> Vec<(&'static str, Vec<Scenario>)> {
    let seeds = 9000..9006;
    vec![
        (
            "default",
            seeds.clone().map(|seed| of(seed, duration_s)).collect(),
        ),
        (
            "jump",
            seeds
                .clone()
                .take(3)
                .map(|seed| Scenario {
                    jumps: vec![(JUMPER, jump_at_s(duration_s), 3e-6)],
                    bad: vec![BAD],
                    ..of(seed, duration_s)
                })
                .collect(),
        ),
        (
            "gauge 30 ppm",
            seeds
                .clone()
                .take(3)
                .map(|seed| Scenario {
                    gps: Vec::new(),
                    rate_ppm: Some(30.0),
                    ..of(seed, duration_s)
                })
                .collect(),
        ),
        (
            "world density",
            seeds
                .take(1)
                .map(|seed| world_density(seed, duration_s.min(60.0)))
                .collect(),
        ),
    ]
}

/// Airspace as dense as the world's busiest: 120 receivers and 180 aircraft over 150 km, so every
/// receiver keeps its full `pair::PAIR_NEIGHBOURS`, its receivers span several areas, and every
/// receiver hears enough reference aircraft to fill its batches
/// (`threshold::REFERENCE_EVENTS_PER_BATCH`). Small enough in area that the sweep holds it in a few
/// gigabytes.
fn world_density(seed: u64, duration_s: f64) -> Scenario {
    Scenario {
        duration_s,
        receivers: 120,
        adsb_aircraft: 120,
        modes_aircraft: 60,
        spread_m: 150_000.0,
        reception_probability: 0.5,
        ..Scenario::new(seed)
    }
}

/// The arrivals of a second holder of the same batches: each receiver's path to it `extra` longer
/// (a draw of 0 to 200 ms each, and a jitter), so the same batches arrive in another order.
fn relayed(arrivals: &[Arrival], seed: u64) -> Vec<Arrival> {
    let mut rng = Rng::new(seed);
    let mut paths: BTreeMap<tally_wire::PublicKey, u64> = BTreeMap::new();
    let mut out: Vec<Arrival> = arrivals
        .iter()
        .map(|arrival| {
            let path = *paths
                .entry(arrival.batch.receiver)
                .or_insert_with(|| (rng.uniform() * 200.0) as u64);
            Arrival {
                at_ms: arrival.at_ms + path + (rng.uniform() * 30.0) as u64,
                ..arrival.clone()
            }
        })
        .collect();
    out.sort_by_key(|arrival| arrival.at_ms);
    out
}

/// The same batches, each one's receptions reversed, those arriving at one time in reverse
/// order, and a third of them again a second later (a copy adds nothing).
fn reordered(arrivals: &[Arrival], rng: &mut Rng) -> Vec<Arrival> {
    let mut out: Vec<Arrival> = Vec::new();
    for arrival in arrivals {
        let mut receptions = arrival.receptions.clone();
        receptions.reverse();
        out.push(Arrival {
            receptions,
            ..arrival.clone()
        });
        if rng.uniform() < 0.33 {
            out.push(Arrival {
                at_ms: arrival.at_ms + 1_000,
                ..arrival.clone()
            });
        }
    }
    out.sort_by(|a, b| a.at_ms.cmp(&b.at_ms).then(b.batch.cmp(&a.batch)));
    out
}

/// The process's peak resident memory, bytes (`VmHWM`).
fn peak_rss() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmHWM:"))
                .and_then(|kb| {
                    kb.trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
        })
        .map_or(0, |kb| kb * 1024)
}
