//! End-to-end tests over the simulator: tiles and assignment, the time-banded fit, calibration
//! (single and joint), solving and verifying, determinism, and the verifiers' refusals.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::clock::{ClockModel, KNOT_PS, ModelTime};
use crate::geo;
use crate::group::Transmission;
use crate::held::{self, Bin};
use crate::linalg::{self, Matrix};
use crate::obs::{ObservationId, Reception, Site};
use crate::scope::{Citation, Inputs, Sites, Window, WindowIndex};
use crate::sim::{self, Rng, Scenario, Simulation};
use crate::solve::solve;
use crate::solve::{Problem, Solution};
use crate::sync::Calibrated;
use crate::tile::Tile;
use crate::verify::{Failure, ModelFailure};
use crate::{SPEC_VERSION, group, publish, verify, verify_model};

type Result<T = ()> = std::result::Result<T, String>;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The 95% point of chi-square with three degrees of freedom.
const CHI2_3_95: f64 = 7.814_728;
/// And with six.
const CHI2_6_95: f64 = 12.591_587;

fn truth_of(simulation: &Simulation) -> BTreeMap<ObservationId, usize> {
    simulation
        .receptions
        .iter()
        .zip(&simulation.sources)
        .map(|(reception, source)| (reception.id(), *source))
        .collect()
}

/// Where the transmission a reception is of was truly sent from.
fn truth_of_one(simulation: &Simulation, id: &ObservationId) -> Option<[f64; 3]> {
    simulation
        .receptions
        .iter()
        .position(|reception| reception.id() == *id)
        .map(|at| simulation.transmissions[simulation.sources[at]].ecef)
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

/// The same under what is published.
fn mahalanobis_published(solution: &Solution, truth: [f64; 3]) -> Option<f64> {
    mahalanobis_under(&solution.covariance, solution, truth)
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

/// One aircraft solved under a tile in one bin.
struct Solved {
    address: u32,
    solution: Solution,
    transmission: Transmission,
    /// It has hearers outside its tile's members.
    outside: bool,
}

/// One tile's model in one window, and every aircraft solved under it.
struct Run {
    inputs: Inputs,
    model: ClockModel,
    bytes: Vec<u8>,
    calibrated: Calibrated,
    /// Per aircraft assigned the tile: its scope's receptions, its addressed citation.
    aircraft: BTreeMap<u32, (Vec<Reception>, Citation)>,
    solutions: Vec<Solved>,
}

fn all_bins(receptions: &[Reception]) -> Vec<Arc<Bin>> {
    held::bins_of(receptions).into_values().collect()
}

/// Every bin, as an engine would: plan, fit each distinct tile once, publish and read back,
/// verify the model, then group and solve each assigned aircraft's transmissions of the bin.
fn run_with(sites: &[Site], receptions: &[Reception], a_max: Option<usize>) -> Result<Vec<Run>> {
    run_strided(sites, receptions, a_max, crate::scope::STRIDE)
}

/// The windows of `bins` at `stride`, each once.
fn windows(bins: &[Arc<Bin>], stride: i64) -> Vec<Window> {
    let set: BTreeSet<Window> = bins
        .iter()
        .map(|bin| Window::strided(bin.bin, stride))
        .collect();
    set.into_iter().collect()
}

fn run_strided(
    sites: &[Site],
    receptions: &[Reception],
    a_max: Option<usize>,
    stride: i64,
) -> Result<Vec<Run>> {
    let bins = all_bins(receptions);
    let sites = Sites::new(sites);
    let mut runs = Vec::new();
    for window in windows(&bins, stride) {
        let index = WindowIndex::with_sync_aircraft(window, &bins, &sites, a_max);
        let plan = index.plan();
        for tile in plan.tiles() {
            let Some(inputs) = index.inputs(tile, &plan.members[&tile]) else {
                continue;
            };
            let Ok((model, calibrated)) = crate::fit_calibrated(&inputs) else {
                continue;
            };
            let bytes = publish::encode(&model).map_err(text)?;
            let decoded = publish::decode(&bytes, SPEC_VERSION).map_err(text)?;
            assert_eq!(decoded, model, "a model reads back as itself");
            let (verdict, _) = verify_model(&model, &inputs);
            assert!(verdict.passed(), "{:?}", verdict.failures);
            let mut run = Run {
                inputs,
                model,
                bytes,
                calibrated,
                aircraft: BTreeMap::new(),
                solutions: Vec::new(),
            };
            for (address, assignment) in &plan.assignments {
                if assignment.tile != tile {
                    continue;
                }
                let receptions = index.receptions(*address, &assignment.scope);
                let outside = index.hearers(*address).len() > assignment.scope.len();
                let grouping = group(&run.model, &receptions);
                for transmission in crate::scope::chosen(&window, grouping.transmissions) {
                    if let Ok(solution) = solve(&run.calibrated, &transmission) {
                        run.solutions.push(Solved {
                            address: *address,
                            solution,
                            transmission,
                            outside,
                        });
                    }
                }
                run.aircraft
                    .insert(*address, (receptions, index.addressed_citation(*address)));
            }
            runs.push(run);
        }
    }
    Ok(runs)
}

fn run(sites: &[Site], receptions: &[Reception]) -> Result<Vec<Run>> {
    run_with(sites, receptions, Some(crate::scope::SYNC_AIRCRAFT_MAX))
}

/// Receivers close together (30 in 60 km), where the smallest tiles hold every hearer.
fn tight(seed: u64) -> Scenario {
    Scenario {
        duration_s: 20.0,
        receivers: 30,
        adsb_aircraft: 14,
        modes_aircraft: 20,
        spread_m: 30_000.0,
        reception_probability: 0.7,
        named: false,
        ..Scenario::new(seed)
    }
}

/// Receivers spread far apart (40 over 600 km), where only the largest tiles hold an
/// aircraft's hearers.
fn wide(seed: u64) -> Scenario {
    Scenario {
        duration_s: 20.0,
        receivers: 40,
        adsb_aircraft: 14,
        modes_aircraft: 20,
        spread_m: 600_000.0,
        reception_probability: 0.7,
        ..Scenario::new(seed)
    }
}

/// A region dense enough that every tile level is chosen by some aircraft.
fn dense(seed: u64) -> Scenario {
    Scenario {
        duration_s: 20.0,
        receivers: 60,
        adsb_aircraft: 14,
        modes_aircraft: 20,
        spread_m: 300_000.0,
        reception_probability: 0.6,
        ..Scenario::new(seed)
    }
}

#[test]
fn grouping_puts_each_transmission_together_and_nothing_else() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 12.0,
        ..Scenario::new(11)
    });
    let truth = truth_of(&simulation);
    let runs = run(&simulation.sites(), &simulation.receptions)?;
    assert!(!runs.is_empty());
    for run in &runs {
        for (receptions, _) in run.aircraft.values() {
            let grouping = group(&run.model, receptions);
            let mut seen: BTreeMap<usize, usize> = BTreeMap::new();
            for transmission in &grouping.transmissions {
                let sources: BTreeSet<usize> = transmission
                    .receptions
                    .iter()
                    .filter_map(|timed| truth.get(&timed.id).copied())
                    .collect();
                assert_eq!(sources.len(), 1, "a transmission mixes two");
                for source in sources {
                    *seen.entry(source).or_default() += 1;
                }
            }
            assert!(
                seen.values().all(|count| *count == 1),
                "a transmission split"
            );
        }
    }
    Ok(())
}

/// What a calibration count is over: the truth inside the 95% ellipsoid, of how many.
#[derive(Default, Clone, Copy)]
struct Count {
    inside: usize,
    total: usize,
}

impl Count {
    fn add(&mut self, inside: bool) {
        self.total += 1;
        self.inside += usize::from(inside);
    }

    fn rate(&self) -> f64 {
        self.inside as f64 / self.total.max(1) as f64
    }
}

/// Every solution's coverage of the truth, overall and by kind, level, altitude band and whether
/// the aircraft had hearers outside its tile; and the median horizontal error.
struct Coverage {
    overall: Count,
    mode_s: Count,
    levels: [Count; 4],
    /// Below 6 km, 6 to 9 km, above 9 km.
    bands: [Count; 3],
    outside: Count,
    /// Under the published covariance, floor and inflation included.
    published: Count,
    median_m: f64,
}

fn coverage_of(scenarios: &[Scenario], a_max: Option<usize>) -> Result<Coverage> {
    let mut out = Coverage {
        overall: Count::default(),
        mode_s: Count::default(),
        levels: [Count::default(); 4],
        bands: [Count::default(); 3],
        outside: Count::default(),
        published: Count::default(),
        median_m: 0.0,
    };
    let mut horizontal: Vec<f64> = Vec::new();
    for scenario in scenarios {
        let simulation = sim::run(scenario);
        let truth = truth_of(&simulation);
        for run in run_with(&simulation.sites(), &simulation.receptions, a_max)? {
            for solved in &run.solutions {
                let solution = &solved.solution;
                let source = truth
                    .get(&solution.observations[0])
                    .ok_or("unknown observation")?;
                let transmission = &simulation.transmissions[*source];
                // A covariance too ill-conditioned to factor counts as missing the truth.
                let inside =
                    mahalanobis(solution, transmission.ecef).is_some_and(|d| d < CHI2_3_95);
                let error = linalg::sub(solution.ecef, transmission.ecef);
                let basis = geo::enu_basis(solution.position.lat_deg, solution.position.lon_deg);
                horizontal.push(linalg::dot(error, basis[0]).hypot(linalg::dot(error, basis[1])));
                out.overall.add(inside);
                out.published.add(
                    mahalanobis_published(solution, transmission.ecef).ok_or("singular")?
                        < CHI2_3_95,
                );
                if !transmission.adsb {
                    out.mode_s.add(inside);
                }
                out.levels[usize::from(run.model.tile.level)].add(inside);
                let height = geo::from_ecef(transmission.ecef).height_m;
                let band = if height < 6_000.0 {
                    0
                } else if height < 9_000.0 {
                    1
                } else {
                    2
                };
                out.bands[band].add(inside);
                if solved.outside {
                    out.outside.add(inside);
                }
            }
        }
    }
    horizontal.sort_by(f64::total_cmp);
    out.median_m = horizontal.get(horizontal.len() / 2).copied().unwrap_or(0.0);
    Ok(out)
}

fn report(name: &str, coverage: &Coverage) {
    let levels: Vec<String> = coverage
        .levels
        .iter()
        .enumerate()
        .map(|(level, count)| format!("level {level} {:.4} of {}", count.rate(), count.total))
        .collect();
    let bands: Vec<String> = coverage
        .bands
        .iter()
        .map(|count| format!("{:.4} of {}", count.rate(), count.total))
        .collect();
    eprintln!(
        "{name}: overall {:.4} of {}, Mode S only {:.4} of {}, {}; altitude bands {}; hearers \
         outside the tile {:.4} of {}; published (floor and inflation) {:.4}; median horizontal \
         error {:.1} m",
        coverage.overall.rate(),
        coverage.overall.total,
        coverage.mode_s.rate(),
        coverage.mode_s.total,
        levels.join(", "),
        bands.join(", "),
        coverage.outside.rate(),
        coverage.outside.total,
        coverage.published.rate(),
        coverage.median_m
    );
}

/// Held to the band where a count is large enough to say anything (a few hundred solutions).
fn calibrated(name: &str, count: &Count) {
    if count.total >= 300 {
        assert!(
            (0.93..=0.97).contains(&count.rate()),
            "{name}: {} of {}",
            count.rate(),
            count.total
        );
    }
}

/// (c) The published covariance is honest: the truth falls inside the 95% ellipsoid of 93% to
/// 97% of solutions, overall, for aircraft that send no ADS-B, at every tile level, in every
/// altitude band, and for aircraft some of whose hearers are outside their tile. Over sixteen
/// small scenarios, twelve dense ones, six tight and six wide (consecutive windows share a model, so a few thousand
/// solutions are far fewer independent samples): one scenario's coverage alone ranges widely (its aircraft
/// and geometry), so fewer would test the seeds, not the covariance.
#[test]
fn position_covariance_is_calibrated_by_kind_level_band_and_tile_edge() -> Result {
    let mut scenarios: Vec<Scenario> = (11..27)
        .map(|seed| Scenario {
            duration_s: 20.0,
            ..Scenario::new(seed)
        })
        .collect();
    scenarios.extend((201..213).map(dense));
    scenarios.extend((231..237).map(tight));
    scenarios.extend((241..247).map(wide));
    let coverage = coverage_of(&scenarios, Some(crate::scope::SYNC_AIRCRAFT_MAX))?;
    report("coverage", &coverage);
    calibrated("overall", &coverage.overall);
    calibrated("Mode S only", &coverage.mode_s);
    for (level, count) in coverage.levels.iter().enumerate() {
        calibrated(&format!("level {level}"), count);
    }
    for (band, count) in coverage.bands.iter().enumerate() {
        calibrated(&format!("band {band}"), count);
    }
    calibrated("hearers outside the tile", &coverage.outside);
    assert!(coverage.overall.total >= 1000 && coverage.mode_s.total >= 300);
    Ok(())
}

/// `A_max`, measured: coverage and the median error at each cap. Run in release with
/// `--ignored`.
#[test]
#[ignore = "a measurement: run with --release -- --ignored --nocapture"]
fn sync_aircraft_cap_sweep() -> Result {
    // Busy: sixty ADS-B aircraft heard across a hundred receivers, where the cap bites.
    let scenarios: Vec<Scenario> = (301..309)
        .map(|seed| Scenario {
            duration_s: 20.0,
            receivers: 100,
            adsb_aircraft: 60,
            modes_aircraft: 40,
            spread_m: 250_000.0,
            reception_probability: 0.5,
            ..Scenario::new(seed)
        })
        .collect();
    let caps: Vec<Option<usize>> = match std::env::var("SWEEP_CAPS") {
        Ok(text) => text.split(',').map(|v| v.parse().ok()).collect(),
        Err(_) => vec![Some(8), Some(16), Some(32), None],
    };
    for cap in caps {
        let started = std::time::Instant::now();
        let coverage = coverage_of(&scenarios, cap)?;
        report(
            &format!("A_max {cap:?} ({:?})", started.elapsed()),
            &coverage,
        );
    }
    Ok(())
}

/// The stride `s`, measured: fits per solved bin, the time they take, coverage, and the latency of
/// a final position (a transmission in bin `b` of a stride is final once the window's last bin
/// and the settling time have passed: on average `(2.5 + (s - 1) / 2)` bins and 2 s). Run in
/// release with `--ignored`.
#[test]
#[ignore = "a measurement: run with --release -- --ignored --nocapture"]
fn stride_sweep() -> Result {
    let scenarios: Vec<Scenario> = (311..315)
        .map(|seed| Scenario {
            duration_s: 40.0,
            receivers: 100,
            adsb_aircraft: 60,
            modes_aircraft: 40,
            spread_m: 250_000.0,
            reception_probability: 0.5,
            ..Scenario::new(seed)
        })
        .collect();
    for stride in [1, 2, 4, 8] {
        let (mut fits, mut solved_bins, mut inside) = (0usize, 0usize, Count::default());
        let mut elapsed = std::time::Duration::ZERO;
        for scenario in &scenarios {
            let simulation = sim::run(scenario);
            let truth = truth_of(&simulation);
            let started = std::time::Instant::now();
            let runs = run_strided(
                &simulation.sites(),
                &simulation.receptions,
                Some(crate::scope::SYNC_AIRCRAFT_MAX),
                stride,
            )?;
            elapsed += started.elapsed();
            fits += runs.len();
            let bins = all_bins(&simulation.receptions);
            solved_bins += windows(&bins, stride)
                .iter()
                .map(|window| window.solved().count())
                .sum::<usize>();
            for run in &runs {
                for solved in &run.solutions {
                    let source = truth
                        .get(&solved.solution.observations[0])
                        .ok_or("unknown observation")?;
                    inside.add(
                        mahalanobis(&solved.solution, simulation.transmissions[*source].ecef)
                            .is_some_and(|d| d < CHI2_3_95),
                    );
                }
            }
        }
        let latency = (2.5 + (stride as f64 - 1.0) / 2.0) * 5.0 + 2.0;
        eprintln!(
            "stride {stride}: {:.2} fits per solved bin, {:?} per solved bin (fits, calibration and \
             solves), coverage {:.4} of {}, mean final latency {latency:.1} s",
            fits as f64 / solved_bins.max(1) as f64,
            elapsed / solved_bins.max(1) as u32,
            inside.rate(),
            inside.total
        );
    }
    Ok(())
}

/// Warm starts, bounded: the time a fit takes from scratch against the time it would take begun
/// at its own converged model (the best any warm start could do). Run in release with
/// `--ignored`.
#[test]
#[ignore = "a measurement: run with --release -- --ignored --nocapture"]
fn warm_start_bound() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 40.0,
        receivers: 100,
        adsb_aircraft: 60,
        modes_aircraft: 40,
        spread_m: 250_000.0,
        reception_probability: 0.5,
        ..Scenario::new(321)
    });
    let bins = all_bins(&simulation.receptions);
    let sites = Sites::new(&simulation.sites());
    let window = Window::canonical(bins[bins.len() - 3].bin);
    let index = WindowIndex::new(window, &bins, &sites);
    let plan = index.plan();
    let (mut cold, mut warm, mut n) = (std::time::Duration::ZERO, std::time::Duration::ZERO, 0);
    for tile in plan.tiles() {
        let Some(inputs) = index.inputs(tile, &plan.members[&tile]) else {
            continue;
        };
        let started = std::time::Instant::now();
        let Ok(model) = crate::fit(&inputs) else {
            continue;
        };
        cold += started.elapsed();
        let started = std::time::Instant::now();
        let _ = crate::sync::fit_from_converged(&inputs, &model);
        warm += started.elapsed();
        n += 1;
    }
    eprintln!(
        "warm start bound: {n} tiles, from scratch {:?} a fit, from its own converged model {:?}",
        cold / n.max(1),
        warm / n.max(1)
    );
    // The real warm start: each tile of this window begun at its model of the previous stride's.
    let previous = Window::canonical(window.bin() - crate::scope::STRIDE);
    let earlier = WindowIndex::new(previous, &bins, &sites);
    let (mut cold, mut warm, mut n, mut agree) =
        (std::time::Duration::ZERO, std::time::Duration::ZERO, 0, 0);
    for tile in plan.tiles() {
        let Some(inputs) = index.inputs(tile, &plan.members[&tile]) else {
            continue;
        };
        let Some(before) = earlier.inputs(tile, &earlier.members(tile)) else {
            continue;
        };
        let Ok(prior) = crate::fit(&before) else {
            continue;
        };
        let started = std::time::Instant::now();
        let Ok((model, _)) = crate::fit_calibrated(&inputs) else {
            continue;
        };
        cold += started.elapsed();
        let started = std::time::Instant::now();
        let Ok((warmed, _)) = crate::sync::fit_calibrated_from(&inputs, Some(&prior)) else {
            continue;
        };
        warm += started.elapsed();
        n += 1;
        let verdict = verify_model(&warmed, &inputs).0;
        agree += usize::from(verdict.passed() && warmed.pieces.len() == model.pieces.len());
    }
    eprintln!(
        "warm start from the previous stride: {n} tiles, cold {:?} a fit and calibration, warm \
         {:?}; {agree} of {n} warm models pass the model verifier with the cold fit's clocks",
        cold / n.max(1),
        warm / n.max(1)
    );
    Ok(())
}

/// How a solution's position moves with its receptions' times: the 3 x n block of
/// `(Jᵀ W J)⁻¹ Jᵀ W` over the time rows, and the receptions it is over.
type Sensitivity<'a> = (Vec<[f64; 3]>, Vec<usize>, Problem<'a>);

fn sensitivity<'a>(calibrated: &'a Calibrated, solved: &Solved) -> Option<Sensitivity<'a>> {
    let problem = Problem::new(calibrated, &solved.transmission);
    let cited: BTreeSet<ObservationId> = solved.solution.observations.iter().copied().collect();
    let subset: Vec<usize> = (0..problem.items.len())
        .filter(|index| cited.contains(&problem.items[*index].id))
        .collect();
    let whitener = problem.whitener(&subset)?;
    let transmit =
        (i128::from(solved.solution.transmit_ps) - problem.reference_ps) as f64 * 1e-12 * geo::C;
    let params = [
        solved.solution.ecef[0],
        solved.solution.ecef[1],
        solved.solution.ecef[2],
        transmit,
    ];
    let (_, jacobian) = problem.whitened(&subset, &whitener, &params);
    let mut information = Matrix::zeros(4);
    for row in &jacobian {
        for i in 0..4 {
            for j in 0..4 {
                information.add(i, j, row[i] * row[j]);
            }
        }
    }
    let inverse = information.cholesky()?.inverse();
    let n = subset.len();
    let mut out = Vec::with_capacity(n);
    for k in 0..n {
        // The whitened response to one unit of time on reception k.
        let mut unit = vec![0.0; n];
        unit[k] = 1.0;
        let white = whitener.forward(&unit);
        let mut gradient = [0.0; 4];
        for (row, value) in jacobian.iter().zip(&white) {
            for i in 0..4 {
                gradient[i] += row[i] * value;
            }
        }
        let moved = inverse.mul_vec(&gradient);
        out.push([moved[0], moved[1], moved[2]]);
    }
    Some((out, subset, problem))
}

/// The joint statistic of two solutions under one model: the squared Mahalanobis distance of
/// their stacked errors with the cross block the shared clock errors imply, and without it.
fn joint(
    calibrated: &Calibrated,
    truth: &BTreeMap<ObservationId, usize>,
    simulation: &Simulation,
    a: &Solved,
    b: &Solved,
) -> Result<Option<(f64, f64, f64)>> {
    let (Some((sa, ia, pa)), Some((sb, ib, pb))) =
        (sensitivity(calibrated, a), sensitivity(calibrated, b))
    else {
        return Ok(None);
    };
    // The cross covariance of the two positions: A_a C_ab A_bᵀ.
    let mut cross = [[0.0f64; 3]; 3];
    for (ka, index_a) in ia.iter().enumerate() {
        for (kb, index_b) in ib.iter().enumerate() {
            let Some(c) = calibrated.clock_cross_covariance(
                (&pa.items[*index_a].time, pa.reference_ps),
                (&pb.items[*index_b].time, pb.reference_ps),
            ) else {
                return Ok(None);
            };
            let c = c * geo::C * geo::C;
            for x in 0..3 {
                for y in 0..3 {
                    cross[x][y] += sa[ka][x] * c * sb[kb][y];
                }
            }
        }
    }
    let error = |solved: &Solved| -> Result<[f64; 3]> {
        let source = truth
            .get(&solved.solution.observations[0])
            .ok_or("unknown observation")?;
        Ok(linalg::sub(
            solved.solution.ecef,
            simulation.transmissions[*source].ecef,
        ))
    };
    let (ea, eb) = (error(a)?, error(b)?);
    let stacked = [ea[0], ea[1], ea[2], eb[0], eb[1], eb[2]];
    let mut full = Matrix::zeros(6);
    let mut alone = Matrix::zeros(6);
    let (ca, cb) = (raw(&a.solution.covariance), raw(&b.solution.covariance));
    for x in 0..3 {
        for y in 0..3 {
            full.set(x, y, ca[x][y]);
            full.set(x + 3, y + 3, cb[x][y]);
            full.set(x, y + 3, cross[x][y]);
            full.set(y + 3, x, cross[x][y]);
            alone.set(x, y, ca[x][y]);
            alone.set(x + 3, y + 3, cb[x][y]);
        }
    }
    let (Some(d_full), Some(d_alone)) = (distance(&stacked, &full), distance(&stacked, &alone))
    else {
        return Ok(None);
    };
    let scale = (ca[0][0] * cb[0][0]).sqrt();
    Ok(Some((
        d_full,
        d_alone,
        cross[0][0] / scale.max(f64::MIN_POSITIVE),
    )))
}

/// (h) JOINT calibration: two solutions under one tile in one bin share its clock errors, so
/// their errors are correlated. The stacked six-vector of both errors, under the covariance with
/// the cross block the shared model implies, covers the truth as a 95% ellipsoid should: for two
/// aircraft sharing the tile, and for one aircraft's consecutive transmissions (what a tracker
/// fuses). The same pairs without the cross block are reported beside: in this geometry the
/// shared clock error is a small part of each covariance (the median correlation is about 0.01),
/// so they cover alike. The negative control, where errors truly share (one transmission solved
/// under two tiles, glued together as if independent), is in
/// `a_transmission_solved_under_two_tiles_steps_by_no_more_than_its_sigma_and_glued_is_overconfident`.
#[test]
fn solutions_sharing_a_tile_are_jointly_calibrated_and_glued_tiles_are_not() -> Result {
    let (mut aircraft, mut aircraft_glued) = (Count::default(), Count::default());
    let (mut fixes, mut fixes_glued) = (Count::default(), Count::default());
    let (mut across, mut along): (Vec<f64>, Vec<f64>) = (Vec::new(), Vec::new());
    for scenario in (211..219).map(dense) {
        let simulation = sim::run(&scenario);
        let truth = truth_of(&simulation);
        for run in run(&simulation.sites(), &simulation.receptions)? {
            let mut by_aircraft: BTreeMap<u32, Vec<&Solved>> = BTreeMap::new();
            for solved in &run.solutions {
                by_aircraft.entry(solved.address).or_default().push(solved);
            }
            // One aircraft's consecutive fixes.
            for list in by_aircraft.values() {
                for pair in list.windows(2) {
                    if let Some((full, alone, correlation)) =
                        joint(&run.calibrated, &truth, &simulation, pair[0], pair[1])?
                    {
                        fixes.add(full < CHI2_6_95);
                        fixes_glued.add(alone < CHI2_6_95);
                        along.push(correlation);
                    }
                }
            }
            // Two aircraft: in each bin solved, each one's first fix there.
            let mut firsts: BTreeMap<(i64, u32), &Solved> = BTreeMap::new();
            for solved in &run.solutions {
                let bin = solved.transmission.bin().unwrap_or(0);
                firsts.entry((bin, solved.address)).or_insert(solved);
            }
            let mut by_bin: BTreeMap<i64, Vec<&Solved>> = BTreeMap::new();
            for ((bin, _), solved) in firsts {
                by_bin.entry(bin).or_default().push(solved);
            }
            for list in by_bin.values() {
                for (i, a) in list.iter().enumerate() {
                    for b in &list[i + 1..] {
                        if let Some((full, alone, correlation)) =
                            joint(&run.calibrated, &truth, &simulation, a, b)?
                        {
                            aircraft.add(full < CHI2_6_95);
                            aircraft_glued.add(alone < CHI2_6_95);
                            across.push(correlation);
                        }
                    }
                }
            }
        }
    }
    let median = |values: &mut Vec<f64>| {
        values.sort_by(f64::total_cmp);
        values.get(values.len() / 2).copied().unwrap_or(0.0)
    };
    eprintln!(
        "joint: two aircraft {:.4} of {} (glued {:.4}, median east-east correlation {:.3}); \
         one aircraft's consecutive fixes {:.4} of {} (glued {:.4}, median correlation {:.3})",
        aircraft.rate(),
        aircraft.total,
        aircraft_glued.rate(),
        median(&mut across),
        fixes.rate(),
        fixes.total,
        fixes_glued.rate(),
        median(&mut along)
    );
    assert!(aircraft.total >= 300 && fixes.total >= 300);
    assert!(
        (0.93..=0.97).contains(&aircraft.rate()),
        "{}",
        aircraft.rate()
    );
    assert!((0.93..=0.97).contains(&fixes.rate()), "{}", fixes.rate());
    Ok(())
}

/// Every reception twice, a third of them a third time, shuffled.
fn shuffled(receptions: &[Reception], rng: &mut Rng) -> Vec<Reception> {
    let mut out: Vec<Reception> = receptions.to_vec();
    for reception in receptions {
        if rng.uniform() < 0.33 {
            out.push(reception.clone());
        }
        out.push(reception.clone());
    }
    for at in (1..out.len()).rev() {
        let other = (rng.next_u64() % (at as u64 + 1)) as usize;
        out.swap(at, other);
    }
    out
}

/// What a run published, by tile and window: the model's bytes and the solutions under it.
type Published = BTreeMap<(Tile, i64), (Vec<u8>, Vec<(u32, Solution)>)>;

fn published(runs: &[Run]) -> Published {
    runs.iter()
        .map(|run| {
            (
                (run.model.tile, run.model.window.first),
                (
                    run.bytes.clone(),
                    run.solutions
                        .iter()
                        .map(|solved| (solved.address, solved.solution.clone()))
                        .collect(),
                ),
            )
        })
        .collect()
}

/// (b) The same raw in any order and with copies publishes byte-identical tile models and
/// identical solutions; and a second, independent region far away changes nothing about the
/// first's tiles.
#[test]
fn the_same_raw_in_any_order_and_any_number_of_copies_publishes_the_same_tiles() -> Result {
    let near = sim::run(&Scenario {
        duration_s: 24.0,
        ..Scenario::new(21)
    });
    let far = sim::run(&Scenario {
        duration_s: 24.0,
        centre: (40.4, -3.7),
        ..Scenario::new(22)
    });
    let mut rng = Rng::new(5);
    let mut both: Vec<Reception> = near.receptions.clone();
    both.extend(far.receptions.iter().cloned());
    let mut sites = near.sites();
    sites.extend(far.sites());
    let mut reversed = sites.clone();
    reversed.reverse();
    let a = published(&run(&sites, &both)?);
    let b = published(&run(&reversed, &shuffled(&both, &mut rng))?);
    let alone = published(&run(&near.sites(), &near.receptions)?);
    assert!(a.len() >= 10, "{} tiles", a.len());
    assert_eq!(a, b);
    for (key, value) in &alone {
        assert_eq!(
            a.get(key),
            Some(value),
            "tile {key:?} changed with a far region"
        );
    }
    Ok(())
}

/// (d) Model time is any clock's: fitted with another gauge, the same transmission's position
/// covariance agrees.
#[test]
fn another_gauge_leaves_a_positions_covariance_unchanged() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 30.0,
        gps: Vec::new(),
        modes_aircraft: 20,
        ..Scenario::new(31)
    });
    let bins = all_bins(&simulation.receptions);
    let sites = Sites::new(&simulation.sites());
    let bin = bins[bins.len() / 2].bin;
    let index = WindowIndex::new(Window::canonical(bin), &bins, &sites);
    let plan = index.plan();
    let mut relatives: Vec<f64> = Vec::new();
    for tile in plan.tiles() {
        let inputs = index
            .inputs(tile, &plan.members[&tile])
            .ok_or("no inputs")?;
        let model = crate::fit(&inputs).map_err(text)?;
        let other = model
            .pieces
            .iter()
            .map(|piece| piece.key.receiver)
            .find(|receiver| *receiver != model.gauge.receiver)
            .ok_or("one clock")?;
        let swapped = crate::sync::fit_with_gauge(&inputs, Some(other)).map_err(text)?;
        assert_eq!(swapped.gauge.receiver, other);
        let (calibrated, _) = crate::calibrate(&model, &inputs).map_err(text)?;
        let (moved_calibrated, _) = crate::calibrate(&swapped, &inputs).map_err(text)?;
        for (address, assignment) in &plan.assignments {
            if assignment.tile != tile {
                continue;
            }
            let receptions = index.receptions(*address, &assignment.scope);
            let grouping = group(&model, &receptions);
            let moved_grouping = group(&swapped, &receptions);
            for transmission in &crate::scope::chosen(&index.window, grouping.transmissions.clone())
            {
                let ids = transmission.receptions.iter().map(|r| r.id);
                let Some(again) = moved_grouping
                    .transmissions
                    .iter()
                    .find(|t| t.receptions.iter().map(|r| r.id).eq(ids.clone()))
                else {
                    continue;
                };
                let (Ok(solution), Ok(moved)) = (
                    solve(&calibrated, transmission),
                    solve(&moved_calibrated, again),
                ) else {
                    continue;
                };
                if moved.observations != solution.observations {
                    continue;
                }
                let mut difference = 0.0;
                let mut size = 0.0;
                for i in 0..3 {
                    for j in 0..3 {
                        let (a, b) = (solution.covariance[i][j], moved.covariance[i][j]);
                        difference += (a - b) * (a - b);
                        size += a * a;
                    }
                }
                relatives.push((difference / size).sqrt());
            }
        }
    }
    relatives.sort_by(f64::total_cmp);
    let n = relatives.len();
    assert!(n > 30, "{n} compared");
    let typical = relatives[n * 95 / 100];
    let rare = relatives[n * 99 / 100];
    let worst = relatives[n - 1];
    eprintln!("gauge swap: 95th percentile {typical:.4}, 99th {rare:.4}, worst {worst:.4} of {n}");
    // Where a time falls between knots moves a little with the gauge's anchor; a transmission at
    // the very edge of a clock's knots can move by more, which is why the worst is reported, not
    // held.
    assert!(typical < 0.05 && rare < 0.10, "{typical} {rare}");
    Ok(())
}

/// (e) A clock's uncertainty is continuous in time: no step where one interval ends and the
/// next begins.
#[test]
fn a_clocks_variance_has_no_step_at_a_knot() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 12.0,
        ..Scenario::new(41)
    });
    let runs = run(&simulation.sites(), &simulation.receptions)?;
    let run = runs.first().ok_or("no model")?;
    let mut checked = 0;
    for (index, piece) in run.model.pieces.iter().enumerate() {
        if piece.key == run.model.gauge {
            continue;
        }
        for knot in piece.first + 1..piece.end() - 1 {
            let at = |knot: i32, into: i128| ModelTime {
                piece: index,
                knot,
                linear: 0,
                ps: 0,
                into_ps: into,
                carried_ps: 0,
            };
            let before = at(knot - 1, KNOT_PS - 1);
            let after = at(knot, 0);
            let variance = |time: &ModelTime| run.calibrated.clock_covariance(time, time, 0);
            let (a, b) = (
                variance(&before).ok_or("no covariance")?,
                variance(&after).ok_or("no covariance")?,
            );
            assert!(
                (a - b).abs() <= 1e-9 * a.max(b),
                "{a} then {b} at knot {knot}"
            );
            checked += 1;
        }
    }
    assert!(checked > 10);
    Ok(())
}

/// (f) The model verifier refuses a tampered knot, members or a tile that are not the raw's, a
/// citation that is not the raw's, and a jump the model does not declare.
#[test]
fn the_model_verifier_refuses_tampering_and_an_undeclared_jump() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 12.0,
        ..Scenario::new(51)
    });
    let runs = run(&simulation.sites(), &simulation.receptions)?;
    let run = runs.first().ok_or("no model")?;
    let failures = |model: &ClockModel| verify_model(model, &run.inputs).0.failures;

    let mut knot = run.model.clone();
    let piece = knot
        .pieces
        .iter_mut()
        .find(|piece| piece.key != run.model.gauge)
        .ok_or("one clock")?;
    piece.offsets_ps[1] += 2_000;
    assert!(
        failures(&knot)
            .iter()
            .any(|f| matches!(f, ModelFailure::NotOptimal { .. })),
        "{:?}",
        failures(&knot)
    );

    let mut scope = run.model.clone();
    scope.scope.pop();
    assert_eq!(failures(&scope), vec![ModelFailure::Scope]);

    let mut tile = run.model.clone();
    tile.tile.cube[0] += 1;
    assert_eq!(failures(&tile), vec![ModelFailure::Scope]);

    let mut citation = run.model.clone();
    citation.input.hash[0] ^= 1;
    assert_eq!(failures(&citation), vec![ModelFailure::Citation]);

    // A receiver whose counter steps by 3 microseconds mid-window.
    let mut scenario = Scenario {
        duration_s: 12.0,
        ..Scenario::new(52)
    };
    scenario.jumps = vec![(3, 6.3, 3e-6)];
    let simulation = sim::run(&scenario);
    let bins = all_bins(&simulation.receptions);
    let sites = Sites::new(&simulation.sites());
    let bin = bins.last().ok_or("no bins")?.bin;
    let index = WindowIndex::new(Window::canonical(bin), &bins, &sites);
    let plan = index.plan();
    let jumper = simulation.receivers[3].key;
    let tile = plan
        .tiles()
        .into_iter()
        .find(|tile| plan.members[tile].contains(&jumper))
        .ok_or("no tile holds the jumper")?;
    let inputs = index
        .inputs(tile, &plan.members[&tile])
        .ok_or("no inputs")?;
    let declared = crate::fit(&inputs).map_err(text)?;
    assert_eq!(declared.jumps.len(), 1, "{:?}", declared.jumps);
    assert!(verify_model(&declared, &inputs).0.passed());
    let hidden = crate::sync::fit_ignoring_jumps(&inputs).map_err(text)?;
    let verdict = verify_model(&hidden, &inputs).0;
    assert!(
        verdict
            .failures
            .iter()
            .any(|f| matches!(f, ModelFailure::Jump { .. })),
        "{:?}",
        verdict.failures
    );
    Ok(())
}

/// A counter jump on a receiver that is a member of several tiles is declared in every one of
/// them, at the same place.
#[test]
fn a_jump_on_a_receiver_in_several_tiles_is_declared_in_each() -> Result {
    let mut scenario = dense(61);
    scenario.jumps = vec![(3, 9.3, 3e-6)];
    let simulation = sim::run(&scenario);
    let runs = run(&simulation.sites(), &simulation.receptions)?;
    let jumper = simulation.receivers[3].key;
    let with: Vec<&Run> = runs
        .iter()
        .filter(|run| {
            run.model
                .pieces
                .iter()
                .any(|p| p.key.receiver == jumper && p.key.piece == 1)
        })
        .collect();
    let tiles: BTreeSet<Tile> = with.iter().map(|run| run.model.tile).collect();
    assert!(tiles.len() >= 2, "the jumper is in {} tiles", tiles.len());
    let places: BTreeSet<i64> = with
        .iter()
        .flat_map(|run| run.model.jumps.iter())
        .filter(|jump| jump.receiver == jumper)
        .map(|jump| jump.at)
        .collect();
    for run in &with {
        assert!(
            run.model.jumps.iter().any(|jump| {
                jump.receiver == jumper && (1_500_000..=4_500_000).contains(&jump.step_ps)
            }),
            "tile {:?} has the second piece without the jump",
            run.model.tile
        );
    }
    // Where it is declared is the first reception after the step in that tile's own sync
    // material, so tiles may name different receptions; all of them within a second (12 million
    // counts) of each other.
    let spread = places.last().copied().unwrap_or(0) - places.first().copied().unwrap_or(0);
    assert!(spread <= 12_000_000, "{places:?}");
    assert!(
        runs.iter()
            .flat_map(|run| &run.model.jumps)
            .all(|jump| jump.receiver == jumper)
    );
    Ok(())
}

/// Every receiver at dump1090-class jitter (500 ns) and one whose counter steps every two
/// seconds: the jump rule, scored against each clock's own robust noise, declares no false jumps
/// on the honest clocks, the bad clock is dropped from every tile it was in rather than failing
/// the fit, and what is solved stays calibrated.
#[test]
fn noisy_clocks_raise_no_false_jumps_and_a_bad_clock_is_dropped_not_fatal() -> Result {
    let bad = 4;
    let mut inside = Count::default();
    let mut tiles = 0;
    let mut dropped = 0;
    for seed in 251..255 {
        let simulation = sim::run(&Scenario {
            jitter_s: Some(500e-9),
            bad: vec![bad],
            ..dense(seed)
        });
        let truth = truth_of(&simulation);
        let culprit = simulation.receivers[bad].key;
        for run in run(&simulation.sites(), &simulation.receptions)? {
            tiles += 1;
            // No honest clock is given a jump; the bad one, if a member, is dropped or split.
            assert!(
                run.model.jumps.iter().all(|jump| jump.receiver == culprit),
                "a false jump on an honest clock: {:?}",
                run.model.jumps
            );
            if run
                .model
                .dropped
                .iter()
                .any(|(receiver, _)| *receiver == culprit)
            {
                dropped += 1;
                assert!(
                    run.model
                        .pieces
                        .iter()
                        .all(|piece| piece.key.receiver != culprit),
                    "a dropped clock still has pieces"
                );
            }
            for solved in &run.solutions {
                let source = truth
                    .get(&solved.solution.observations[0])
                    .ok_or("unknown observation")?;
                inside.add(
                    mahalanobis(&solved.solution, simulation.transmissions[*source].ecef)
                        .ok_or("singular")?
                        < CHI2_3_95,
                );
            }
        }
    }
    eprintln!(
        "noisy clocks: {tiles} tiles fitted, the bad clock dropped from {dropped}; coverage \
         {:.4} of {}",
        inside.rate(),
        inside.total
    );
    assert!(tiles >= 20 && dropped >= 5, "{tiles} {dropped}");
    assert!((0.93..=0.97).contains(&inside.rate()), "{}", inside.rate());
    Ok(())
}

/// Every tile's fit over `receptions`: how many were tried, and why any failed.
fn fit_failures(sites: &[Site], receptions: &[Reception]) -> (usize, Vec<crate::FitError>) {
    let bins = all_bins(receptions);
    let sites = Sites::new(sites);
    let (mut tried, mut failures) = (0, Vec::new());
    for window in windows(&bins, crate::scope::STRIDE) {
        let index = WindowIndex::new(window, &bins, &sites);
        let plan = index.plan();
        for tile in plan.tiles() {
            let Some(inputs) = index.inputs(tile, &plan.members[&tile]) else {
                continue;
            };
            tried += 1;
            if let Err(error) = crate::fit_calibrated(&inputs) {
                failures.push(error);
            }
        }
    }
    (tried, failures)
}

/// A receiver that declares GNSS discipline is fitted as it behaves, not as it declares (RFC-0171
/// §3.8.1, the calibration over real receivers): one whose stamps are 120.6 µs late throughout
/// (a GRX1090 in OpenSky's data, stamping a long message's end) and one whose stamps carry 300 µs
/// of jitter (a Radarcape without its lock, also there), beside an honest one, so the gauge of a
/// tile is often a liar. No tile fails its fit for them, and what is solved stays calibrated.
/// With the fit holding every GNSS clock to the gauge's stamps (100 ns), as it did, most of these
/// tiles' normal equations were singular, and on LocaRDS half of all fits failed.
#[test]
fn a_declared_gnss_clock_is_fitted_as_it_behaves() -> Result {
    let mut inside = Count::default();
    let (mut tried, mut failed) = (0, Vec::new());
    for seed in 261..265 {
        let simulation = sim::run(&Scenario {
            gps: vec![0, 2, 5],
            offsets: vec![(0, 120.6e-6)],
            jitters: vec![(2, 300e-6)],
            ..dense(seed)
        });
        let (tiles, failures) = fit_failures(&simulation.sites(), &simulation.receptions);
        tried += tiles;
        failed.extend(
            failures
                .into_iter()
                .filter(|error| *error != crate::FitError::NoSyncEvents),
        );
        let truth = truth_of(&simulation);
        for run in run(&simulation.sites(), &simulation.receptions)? {
            for solved in &run.solutions {
                let source = truth
                    .get(&solved.solution.observations[0])
                    .ok_or("unknown observation")?;
                inside.add(
                    mahalanobis(&solved.solution, simulation.transmissions[*source].ecef)
                        .ok_or("singular")?
                        < CHI2_3_95,
                );
            }
        }
    }
    eprintln!(
        "declared GNSS, offset and unlocked: {tried} fits, {} failed ({failed:?}); coverage {:.4} \
         of {}",
        failed.len(),
        inside.rate(),
        inside.total
    );
    assert!(tried >= 20 && failed.is_empty(), "{tried} {failed:?}");
    assert!((0.93..=0.97).contains(&inside.rate()), "{}", inside.rate());
    Ok(())
}

/// A receiver that declares GNSS and whose counter is noise at a millisecond (so it is often a
/// tile's gauge) costs no fit and no honest clock, and what is solved stays calibrated. While a
/// clock's noise was taken from its declaration until estimated (30 ns for GNSS), such a gauge
/// made the robust start lose every event it heard: 18 of these 89 fits failed singular, and once
/// clocks nothing places were dropped (`sync::uninformed`), 62 models dropped 469 honest clocks.
/// Every clock now starts at the worst common class (500 ns) until its receptions say otherwise.
#[test]
fn a_declared_gnss_clock_of_noise_costs_no_honest_clock() -> Result {
    let garbage = 3;
    let mut inside = Count::default();
    let (mut tried, mut failed, mut dropped, mut honest) = (0, Vec::new(), 0, 0);
    for seed in 271..275 {
        let simulation = sim::run(&Scenario {
            gps: vec![garbage, 7],
            jitters: vec![(garbage, 1e-3)],
            ..dense(seed)
        });
        let (tiles, failures) = fit_failures(&simulation.sites(), &simulation.receptions);
        tried += tiles;
        failed.extend(
            failures
                .into_iter()
                .filter(|error| *error != crate::FitError::NoSyncEvents),
        );
        let truth = truth_of(&simulation);
        let culprit = simulation.receivers[garbage].key;
        for run in run(&simulation.sites(), &simulation.receptions)? {
            dropped += usize::from(!run.model.dropped.is_empty());
            honest += run
                .model
                .dropped
                .iter()
                .filter(|(receiver, _)| *receiver != culprit)
                .count();
            for solved in &run.solutions {
                let source = truth
                    .get(&solved.solution.observations[0])
                    .ok_or("unknown observation")?;
                inside.add(
                    mahalanobis(&solved.solution, simulation.transmissions[*source].ecef)
                        .ok_or("singular")?
                        < CHI2_3_95,
                );
            }
        }
    }
    eprintln!(
        "a clock of noise: {tried} fits, {} failed, {dropped} models drop a clock ({honest} honest \
         clocks dropped); coverage {:.4} of {}",
        failed.len(),
        inside.rate(),
        inside.total
    );
    assert!(tried >= 20 && failed.is_empty(), "{tried} {failed:?}");
    assert_eq!(honest, 0, "honest clocks dropped");
    assert!((0.93..=0.97).contains(&inside.rate()), "{}", inside.rate());
    Ok(())
}

#[test]
fn a_receiver_with_an_unknown_clock_or_coarse_location_takes_no_part() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 12.0,
        ..Scenario::new(71)
    });
    let mut sites = simulation.sites();
    sites[1].clock = tally_wire::Clock::Unknown;
    sites[3].location.precision_m = 500;
    let excluded = [sites[1].receiver, sites[3].receiver];
    let runs = run(&sites, &simulation.receptions)?;
    assert!(!runs.is_empty());
    for run in &runs {
        assert!(
            run.model
                .scope
                .iter()
                .all(|s| !excluded.contains(&s.receiver))
        );
        assert!(
            run.model
                .pieces
                .iter()
                .all(|p| !excluded.contains(&p.key.receiver))
        );
    }
    Ok(())
}

/// Solutions carried to the wire and read back pass the solution verifier and the assignment
/// check; a moved one, a partial one, an unsorted or unknown citation, and one under a tile the
/// assignment rule does not give do not.
#[test]
fn the_verifier_accepts_honest_wire_solutions_and_rejects_tampered_ones() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 12.0,
        modes_aircraft: 20,
        ..Scenario::new(81)
    });
    let runs = run(&simulation.sites(), &simulation.receptions)?;
    let bins = all_bins(&simulation.receptions);
    let sites = Sites::new(&simulation.sites());
    let (mut honest, mut moved, mut omitted, mut partials) = (0, 0, 0, 0);
    for run in &runs {
        let mut per_address: BTreeMap<u32, usize> = BTreeMap::new();
        let index = WindowIndex::new(run.model.window, &bins, &sites);
        for solved in &run.solutions {
            let (pool, addressed) = &run.aircraft[&solved.address];
            let solution = &solved.solution;
            let wire = publish::to_wire(
                &run.model,
                solution,
                [7; 32],
                *addressed,
                &solved.transmission.data,
            )
            .map_err(text)?;
            let claim = publish::claim(&run.model, &wire, SPEC_VERSION).map_err(text)?;
            let verdict = verify(&run.calibrated, pool, &claim);
            assert!(verdict.passed(), "{:?}", verdict.failures);
            crate::verify_assignment(&index, solved.address, &run.model, &wire.addressed)
                .map_err(|failure| format!("{failure:?}"))?;
            honest += 1;

            let mut tampered = solution.clone();
            let east = geo::enu_basis(solution.position.lat_deg, solution.position.lon_deg)[0];
            tampered.ecef = linalg::add(solution.ecef, linalg::scale(east, 100.0));
            tampered.position = geo::from_ecef(tampered.ecef);
            let verdict = verify(&run.calibrated, pool, &tampered);
            assert!(
                verdict
                    .failures
                    .iter()
                    .any(|f| matches!(f, Failure::NotOptimal { .. })),
                "{:?}",
                verdict.failures
            );
            moved += 1;

            let of_aircraft = per_address.entry(solved.address).or_default();
            if solution.observations.len() > 5 && partials < 60 && *of_aircraft < 4 {
                let dropped = solution.observations[2];
                let reduced = Transmission {
                    receptions: solved
                        .transmission
                        .receptions
                        .iter()
                        .filter(|timed| timed.id != dropped)
                        .copied()
                        .collect(),
                    ..solved.transmission.clone()
                };
                if let Ok(partial) = solve(&run.calibrated, &reduced) {
                    let verdict = verify(&run.calibrated, pool, &partial);
                    partials += 1;
                    *of_aircraft += 1;
                    let refused = verdict
                        .failures
                        .iter()
                        .any(|f| matches!(f, Failure::Omitted { id, .. } if *id == dropped));
                    omitted += usize::from(refused);
                    if !refused {
                        // Accepted: then it is a fixed point of the rule, the dropped reception an
                        // outlier where the rest put the aircraft.
                        let problem = Problem::new(&run.calibrated, &solved.transmission);
                        let index = problem
                            .items
                            .iter()
                            .position(|item| item.id == dropped)
                            .ok_or("the dropped reception")?;
                        let transmit = (i128::from(partial.transmit_ps) - problem.reference_ps)
                            as f64
                            * 1e-12
                            * geo::C;
                        let params = [partial.ecef[0], partial.ecef[1], partial.ecef[2], transmit];
                        let z = problem.residual(index, &params).abs() / problem.sigma(index);
                        assert!(
                            z >= crate::solve::OUTLIER_Z - crate::verify::OUTLIER_BAND,
                            "an omission accepted at z {z}"
                        );
                    }
                }
            }
        }
    }
    assert!(honest > 200 && moved == honest, "{honest} {moved}");
    assert!(
        partials >= 40 && omitted * 4 >= partials * 3,
        "{omitted} of {partials}"
    );
    let run = runs
        .iter()
        .find(|run| !run.solutions.is_empty())
        .ok_or("none")?;
    let solved = &run.solutions[0];
    let (pool, addressed) = &run.aircraft[&solved.address];
    let mut unsorted = solved.solution.clone();
    unsorted.observations.reverse();
    assert_eq!(
        verify(&run.calibrated, pool, &unsorted).failures,
        vec![Failure::Unsorted]
    );
    assert!(matches!(
        verify(&run.calibrated, &[], &solved.solution).failures[0],
        Failure::Unknown(_)
    ));
    // The same solution citing a tile the rule does not give it, or receptions not the raw's.
    let index = WindowIndex::new(run.model.window, &bins, &sites);
    let mut elsewhere = run.model.clone();
    elsewhere.tile.level = (elsewhere.tile.level + 1) % crate::tile::LEVELS;
    assert_eq!(
        crate::verify_assignment(&index, solved.address, &elsewhere, &addressed.to_wire()),
        Err(Failure::Tile)
    );
    let mut forged = addressed.to_wire();
    forged.count += 1;
    assert_eq!(
        crate::verify_assignment(&index, solved.address, &run.model, &forged),
        Err(Failure::Addressed)
    );
    Ok(())
}

#[test]
fn identical_bytes_one_receiver_hears_twice_within_the_gate_are_ambiguous() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 12.0,
        ..Scenario::new(91)
    });
    let runs = run(&simulation.sites(), &simulation.receptions)?;
    let run = runs
        .iter()
        .find(|run| run.solutions.len() > 2)
        .ok_or("no model")?;
    let solved = &run.solutions[0];
    let mut receptions = run.aircraft[&solved.address].0.clone();
    let first = solved.transmission.receptions[0].id;
    let copy = receptions
        .iter()
        .find(|reception| reception.id() == first)
        .cloned()
        .ok_or("no reception")?;
    let mut echo = copy.clone();
    echo.observation.timestamp += 1_200;
    receptions.push(echo);
    let grouping = group(&run.model, &receptions);
    assert!(grouping.ambiguous.contains(&first));
    Ok(())
}

/// Where an aircraft crosses from one tile to another, its position does not step: at the
/// crossing it is solved under either tile. Every transmission whose scope is also wholly among
/// the members of the tile one level up or down (the tile it would move to) is solved under that
/// tile too, from the same receptions; the two positions differ by no more than both solutions'
/// uncertainty allows (the 10^-6 bound of their summed covariance: an upper bound, the two
/// sharing raw). And the joint test's negative control: the two solutions of one transmission
/// share their receptions' noise, so taken as two independent fixes (two tiles glued together)
/// their stacked errors must measure overconfident: the joint test can tell, and a consumer must
/// never fuse two tiles' solutions of one transmission (it keeps one, as the merge rule does).
#[test]
fn a_transmission_solved_under_two_tiles_steps_by_no_more_than_its_sigma_and_glued_is_overconfident()
-> Result {
    let mut compared = 0;
    let mut steps: Vec<f64> = Vec::new();
    let mut glued = Count::default();
    for seed in 221..229 {
        let simulation = sim::run(&dense(seed));
        let bins = all_bins(&simulation.receptions);
        let sites = Sites::new(&simulation.sites());
        for bin in bins.iter().map(|bin| bin.bin) {
            let index = WindowIndex::new(Window::canonical(bin), &bins, &sites);
            let mut plan = index.plan();
            let mut models: BTreeMap<Tile, Option<(ClockModel, Calibrated)>> = BTreeMap::new();
            let mut fitted = |tile: Tile, members: &[tally_wire::PublicKey]| {
                models
                    .entry(tile)
                    .or_insert_with(|| {
                        index
                            .inputs(tile, members)
                            .and_then(|inputs| crate::fit_calibrated(&inputs).ok())
                    })
                    .clone()
            };
            let assignments: Vec<(u32, crate::Assignment)> = plan
                .assignments
                .iter()
                .map(|(address, assignment)| (*address, assignment.clone()))
                .collect();
            for (address, assignment) in assignments {
                let tile = assignment.tile;
                for level in [tile.level.wrapping_sub(1), tile.level + 1] {
                    if level >= crate::tile::LEVELS {
                        continue;
                    }
                    let hearers: Vec<[i64; 3]> =
                        index.hearers(address).iter().map(|(_, mm)| *mm).collect();
                    let Some(median) = crate::tile::lower_median(&hearers) else {
                        continue;
                    };
                    let other = Tile::containing(level, median);
                    let members = plan
                        .members
                        .entry(other)
                        .or_insert_with(|| index.members(other))
                        .clone();
                    if !assignment.scope.iter().all(|key| members.contains(key)) {
                        continue;
                    }
                    let (Some((model, calibrated)), Some((model_b, calibrated_b))) =
                        (fitted(tile, &plan.members[&tile]), fitted(other, &members))
                    else {
                        continue;
                    };
                    let receptions = index.receptions(address, &assignment.scope);
                    let there = group(&model_b, &receptions);
                    for transmission in crate::scope::chosen(
                        &index.window,
                        group(&model, &receptions).transmissions,
                    ) {
                        let ids = transmission.receptions.iter().map(|r| r.id);
                        let Some(again) = there
                            .transmissions
                            .iter()
                            .find(|t| t.receptions.iter().map(|r| r.id).eq(ids.clone()))
                        else {
                            continue;
                        };
                        let (Ok(a), Ok(b)) = (
                            solve(&calibrated, &transmission),
                            solve(&calibrated_b, again),
                        ) else {
                            continue;
                        };
                        let step: Vec<f64> =
                            (0..3).map(|axis| b.ecef[axis] - a.ecef[axis]).collect();
                        let mut sum = Matrix::zeros(3);
                        for x in 0..3 {
                            for y in 0..3 {
                                sum.set(x, y, a.covariance[x][y] + b.covariance[x][y]);
                            }
                        }
                        let d = distance(&step, &sum).ok_or("singular")?;
                        assert!(
                            d < crate::solve::chi2_limit(3),
                            "{address:06x} from {tile:?} to {other:?}: a step of {d} squared sigma"
                        );
                        steps.push(d);
                        compared += 1;
                        let source = truth_of_one(&simulation, &transmission.receptions[0].id)
                            .ok_or("no truth")?;
                        let (ea, eb) = (linalg::sub(a.ecef, source), linalg::sub(b.ecef, source));
                        let stacked = [ea[0], ea[1], ea[2], eb[0], eb[1], eb[2]];
                        let mut alone = Matrix::zeros(6);
                        let (ca, cb) = (raw(&a.covariance), raw(&b.covariance));
                        for x in 0..3 {
                            for y in 0..3 {
                                alone.set(x, y, ca[x][y]);
                                alone.set(x + 3, y + 3, cb[x][y]);
                            }
                        }
                        glued.add(distance(&stacked, &alone).ok_or("singular")? < CHI2_6_95);
                    }
                }
            }
        }
    }
    steps.sort_by(f64::total_cmp);
    eprintln!(
        "tile crossings: {compared} transmissions solved under both tiles, median step {:.3}, \
         95th percentile {:.3} squared sigma of the summed covariance; glued as independent, \
         joint coverage {:.4}",
        steps.get(steps.len() / 2).copied().unwrap_or(0.0),
        steps.get(steps.len() * 95 / 100).copied().unwrap_or(0.0),
        glued.rate()
    );
    assert!(compared >= 100, "{compared} compared");
    assert!(glued.rate() < 0.93, "glued tiles measured {}", glued.rate());
    Ok(())
}

/// An exactly determined transmission (three receptions and the altitude) has two roots in
/// general, both fitting perfectly; every solution published is within its own 10^-6 ellipsoid
/// of the truth: an ambiguous one is refused.
#[test]
fn an_exactly_determined_transmission_with_two_roots_is_refused_not_guessed() -> Result {
    let simulation = sim::run(&Scenario {
        duration_s: 20.0,
        midnight_unix_ms: 1_791_158_400_000,
        modes_aircraft: 30,
        ..Scenario::new(31)
    });
    let truth = truth_of(&simulation);
    let mut exact = 0;
    for run in run(&simulation.sites(), &simulation.receptions)? {
        for solved in &run.solutions {
            let solution = &solved.solution;
            let source = truth
                .get(&solution.observations[0])
                .ok_or("unknown observation")?;
            let transmission = &simulation.transmissions[*source];
            let distance = mahalanobis(solution, transmission.ecef).ok_or("singular")?;
            assert!(
                distance < crate::solve::chi2_limit(3),
                "{:06x}: {} receptions, {distance} squared standard deviations from the truth",
                solved.address,
                solution.observations.len()
            );
            exact += usize::from(solution.observations.len() == 3);
        }
    }
    assert!(
        exact > 0,
        "no exactly determined solution was published at all"
    );
    Ok(())
}

/// A free-running gauge's frequency error scales every time difference under it: every clock
/// here runs 30 ppm fast, so nothing but the sync ranges shows it. The fit measures the gauge's
/// rate, and the solutions cover the truth as under a GNSS gauge.
#[test]
fn a_free_running_gauge_30_ppm_fast_is_measured_and_covers_as_a_gnss_gauge() -> Result {
    let fast = |seed| Scenario {
        duration_s: 20.0,
        gps: Vec::new(),
        rate_ppm: Some(30.0),
        ..Scenario::new(seed)
    };
    // Model time is the gauge's count times (1 + rate): a clock 30 ppm fast needs about -30 (its
    // rate wanders a little as it runs). How well a small network sees it varies by tile, so
    // each fit's rate is held to its own stated uncertainty.
    let mut scores: Vec<f64> = Vec::new();
    for seed in 11..15 {
        let simulation = sim::run(&fast(seed));
        for run in run(&simulation.sites(), &simulation.receptions)? {
            let rate = run.model.gauge_rate as f64 * 1e6 / crate::clock::RATE_SCALE as f64;
            let sigma = run
                .calibrated
                .gauge_rate_sigma_ppm()
                .ok_or("no rate variance")?;
            scores.push((rate + 30.0) / sigma);
        }
    }
    scores.sort_by(f64::total_cmp);
    let n = scores.len();
    let within = scores.iter().filter(|z| z.abs() <= 3.0).count();
    eprintln!(
        "gauge rate against -30 ppm, in its own sigmas: median {:.2}, {within} of {n} within 3",
        scores[n / 2]
    );
    assert!(scores[n / 2].abs() < 1.0 && within * 10 >= n * 9);
    let seeds: Vec<Scenario> = (11..19).map(fast).collect();
    let gnss: Vec<Scenario> = (11..19)
        .map(|seed| Scenario {
            duration_s: 20.0,
            ..Scenario::new(seed)
        })
        .collect();
    let free = coverage_of(&seeds, Some(crate::scope::SYNC_AIRCRAFT_MAX))?.overall;
    let disciplined = coverage_of(&gnss, Some(crate::scope::SYNC_AIRCRAFT_MAX))?.overall;
    eprintln!(
        "coverage: 30 ppm gauge {:.4} of {}, GNSS gauge {:.4} of {}",
        free.rate(),
        free.total,
        disciplined.rate(),
        disciplined.total
    );
    assert!((free.rate() - disciplined.rate()).abs() < 0.02);
    assert!((0.93..=0.97).contains(&free.rate()), "{}", free.rate());
    Ok(())
}

/// (i) A model's bytes are the same on every platform: computed here, compared with the
/// committed golden made on the x86 development host (the ARM comparison is the build Mac's).
/// The linear algebra runs in one fixed order with no fused multiply-add and no runtime SIMD
/// choice, and the transcendental functions are `libm`'s.
#[test]
fn a_tile_models_bytes_are_the_committed_golden() -> Result {
    use blake2::{Blake2s256, Digest};
    let simulation = sim::run(&Scenario {
        duration_s: 12.0,
        ..Scenario::new(301)
    });
    let runs = run(&simulation.sites(), &simulation.receptions)?;
    let run = runs.first().ok_or("no model")?;
    let digest: [u8; 32] = Blake2s256::digest(&run.bytes).into();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        GOLDEN,
        "{} bytes of tile {:?}",
        run.bytes.len(),
        run.model.tile
    );
    Ok(())
}

/// BLAKE2s-256 of the first tile model of scenario 301 (12 s), made on the x86 host (version 4:
/// every clock starts at 500 ns, so the GNSS gauge's fit starts elsewhere than version 3's).
const GOLDEN: &str = "0758416042f68480004ce93fee8ca8699248818e1e35eb51b2a6db8f41dabc3e";

/// Per-stage timers at a region's scale: index, plan, inputs, fit (folded calibration), solve,
/// and an external verification. Run in release with `--ignored`.
#[test]
#[ignore = "a benchmark: run with --release -- --ignored --nocapture"]
fn per_stage_timers_and_fit_time_flat_in_the_regions_receivers() -> Result {
    let sizes: Vec<usize> = std::env::var("BENCH_R")
        .ok()
        .map(|v| v.split(',').filter_map(|x| x.parse().ok()).collect())
        .unwrap_or(vec![100, 300, 1000]);
    let mut per_tile = Vec::new();
    for receivers in sizes {
        let simulation = sim::run(&Scenario {
            duration_s: 70.0,
            receivers,
            adsb_aircraft: 60,
            modes_aircraft: 40,
            spread_m: 250_000.0,
            reception_probability: 0.5,
            ..Scenario::new(101)
        });
        let started = std::time::Instant::now();
        let bins = all_bins(&simulation.receptions);
        let sealing = started.elapsed();
        let sites = Sites::new(&simulation.sites());
        let bin = bins[bins.len() - 3].bin;
        let started = std::time::Instant::now();
        let index = WindowIndex::new(Window::canonical(bin), &bins, &sites);
        let assembling = started.elapsed();
        let started = std::time::Instant::now();
        let plan = index.plan();
        let planning = started.elapsed();
        let tiles = plan.tiles();
        let zero = std::time::Duration::ZERO;
        let (mut inputs_time, mut fit_time, mut solve_time, mut verify_time) =
            (zero, zero, zero, zero);
        let (mut events, mut members, mut solved) = (0, 0, 0);
        for tile in &tiles {
            let started = std::time::Instant::now();
            let Some(inputs) = index.inputs(*tile, &plan.members[tile]) else {
                continue;
            };
            inputs_time += started.elapsed();
            events += inputs.sync.len();
            members += inputs.scope.len();
            let started = std::time::Instant::now();
            let Ok((model, calibrated)) = crate::fit_calibrated(&inputs) else {
                continue;
            };
            fit_time += started.elapsed();
            let started = std::time::Instant::now();
            for (address, assignment) in &plan.assignments {
                if assignment.tile != *tile {
                    continue;
                }
                let receptions = index.receptions(*address, &assignment.scope);
                for transmission in
                    crate::scope::chosen(&index.window, group(&model, &receptions).transmissions)
                {
                    if solve(&calibrated, &transmission).is_ok() {
                        solved += 1;
                    }
                }
            }
            solve_time += started.elapsed();
            let started = std::time::Instant::now();
            assert!(verify_model(&model, &inputs).0.passed());
            verify_time += started.elapsed();
        }
        let n = tiles.len().max(1) as u32;
        eprintln!(
            "benchmark: {receivers} receivers, {} receptions; seal {sealing:?}, window \
             {assembling:?}, plan {planning:?}; {} aircraft on {} tiles (mean {} members, {} \
             sync receptions); per tile: inputs {:?}, fit and calibration {:?}, solves {:?} \
             ({solved} solved), external model verification {:?}",
            simulation.receptions.len(),
            plan.assignments.len(),
            tiles.len(),
            members / tiles.len().max(1),
            events / tiles.len().max(1),
            inputs_time / n,
            fit_time / n,
            solve_time / n,
            verify_time / n
        );
        per_tile.push((fit_time / n).as_secs_f64());
    }
    if per_tile.len() >= 3 {
        assert!(
            per_tile[2] < 3.0 * per_tile[0],
            "fit time grew: {per_tile:?}"
        );
    }
    Ok(())
}

/// One cluster of the world benchmark, measured.
#[derive(Default)]
struct Measured {
    receivers: usize,
    made: usize,
    filtered: usize,
    wanted: usize,
    late: usize,
    seconds: f64,
    generated: std::time::Duration,
    /// Each bin sealed as the stream passed it: the receptions it took and how long it took.
    seals: Vec<(usize, std::time::Duration)>,
    /// The most held at once, open and sealed, and of it open.
    peak_bytes: usize,
    peak_open_bytes: usize,
    window_bins: usize,
    window_records: usize,
    window_bytes: usize,
    indexing: std::time::Duration,
    plan_wall: std::time::Duration,
    planning: std::time::Duration,
    targets: usize,
    tiles: usize,
    fit_wall: std::time::Duration,
    fit_cpu: std::time::Duration,
    solutions: usize,
    solve_cpu: std::time::Duration,
    alone_cpu: std::time::Duration,
}

/// Streams `scenario`'s receptions in time order into a holder as an engine takes them, sealing
/// each bin on `threads` threads once the stream has passed it and forgetting what the window does
/// not need, then solves the window as the engine would, every stage timed.
fn world_cluster(scenario: &Scenario, window: Window, threads: usize) -> Result<Measured> {
    use crate::held::{Held, Limits, SealedBins};
    use crate::scope::bin_of;
    let mut measured = Measured {
        receivers: scenario.receivers,
        seconds: scenario.duration_s,
        ..Measured::default()
    };
    let started = std::time::Instant::now();
    let mut held = Held::with(Limits::UNBOUNDED, threads, SealedBins::new());
    let mut newest = i64::MIN;
    let mut through = i64::MIN;
    let simulation = sim::run_into_in_time_order(scenario, &mut |reception, _| {
        measured.made += 1;
        let bin = bin_of(reception.wall_ms);
        let added = held.add_one(&reception);
        measured.wanted += added.new + added.late;
        measured.filtered += added.filtered;
        measured.late += added.late;
        if bin > newest {
            newest = bin;
            // A bin is complete once the stream is a whole bin past it.
            if newest - 2 > through && newest - 2 >= window.first - 1 {
                through = newest - 2;
                measured.peak_bytes = measured.peak_bytes.max(held.bytes());
                measured.peak_open_bytes = measured.peak_open_bytes.max(held.open_bytes());
                let open = held.len() - held.sealed_bins().len();
                let sealing = std::time::Instant::now();
                held.seal_through(through);
                measured.seals.push((open, sealing.elapsed()));
                held.forget_before(window.first);
            }
        }
    });
    held.seal_through(window.last);
    measured.peak_bytes = measured.peak_bytes.max(held.bytes());
    held.forget_before(window.first);
    measured.generated = started.elapsed();
    let bins = held.bins(window.first, window.last);
    measured.window_bins = bins.len();
    measured.window_records = bins.iter().map(|bin| bin.records.len()).sum();
    measured.window_bytes = bins.iter().map(|bin| bin.bytes()).sum();
    let sites = Sites::new(&simulation.sites());
    let started = std::time::Instant::now();
    let index = WindowIndex::new(window, &bins, &sites);
    measured.indexing = started.elapsed();
    let started = std::time::Instant::now();
    let plan = index.plan_on(threads);
    measured.plan_wall = started.elapsed();
    measured.planning = measured.indexing + measured.plan_wall * threads as u32;
    let tiles = plan.tiles();
    measured.targets = plan.assignments.len();
    measured.tiles = tiles.len();
    let size = tiles.len().div_ceil(threads).max(1);
    let started = std::time::Instant::now();
    type Fitted = Vec<(Vec<(Tile, (ClockModel, Calibrated))>, std::time::Duration)>;
    let fitted: Fitted = std::thread::scope(|scope| {
        let handles: Vec<_> = tiles
            .chunks(size)
            .map(|chunk| {
                let (index, plan) = (&index, &plan);
                scope.spawn(move || {
                    let started = std::time::Instant::now();
                    let out = chunk
                        .iter()
                        .filter_map(|tile| {
                            let inputs = index.inputs(*tile, &plan.members[tile])?;
                            crate::fit_calibrated(&inputs).ok().map(|fit| (*tile, fit))
                        })
                        .collect::<Vec<_>>();
                    (out, started.elapsed())
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .collect()
    });
    measured.fit_wall = started.elapsed();
    measured.fit_cpu = fitted.iter().map(|(_, time)| *time).sum();
    let models: BTreeMap<Tile, (ClockModel, Calibrated)> =
        fitted.into_iter().flat_map(|(list, _)| list).collect();
    let work: Vec<(&u32, &crate::Assignment)> = plan
        .assignments
        .iter()
        .filter(|(_, assignment)| models.contains_key(&assignment.tile))
        .collect();
    let size = work.len().div_ceil(threads).max(1);
    // Each solve as the engine publishes it (`publish::solve_published`: solved, written, read
    // back and verified), and the solve alone beside it, to measure what checking every one costs.
    type Solved = (usize, std::time::Duration, std::time::Duration);
    let solved: Vec<Solved> = std::thread::scope(|scope| {
        let handles: Vec<_> = work
            .chunks(size)
            .map(|chunk| {
                let (index, models) = (&index, &models);
                scope.spawn(move || {
                    let (mut published, mut alone) =
                        (std::time::Duration::ZERO, std::time::Duration::ZERO);
                    let mut solved = 0;
                    for (address, assignment) in chunk {
                        let (model, calibrated) = &models[&assignment.tile];
                        let receptions = index.receptions(**address, &assignment.scope);
                        let grouping = group(model, &receptions);
                        let addressed = index.addressed_citation(**address);
                        for transmission in
                            crate::scope::chosen(&index.window, grouping.transmissions)
                        {
                            let started = std::time::Instant::now();
                            solved += usize::from(
                                crate::publish::solve_published(
                                    calibrated,
                                    &transmission,
                                    [0; 32],
                                    addressed,
                                )
                                .is_ok(),
                            );
                            published += started.elapsed();
                            let started = std::time::Instant::now();
                            let _ = solve(calibrated, &transmission);
                            alone += started.elapsed();
                        }
                    }
                    (solved, published, alone)
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .collect()
    });
    measured.solve_cpu = solved.iter().map(|(_, time, _)| *time).sum();
    measured.alone_cpu = solved.iter().map(|(_, _, time)| *time).sum();
    measured.solutions = solved.iter().map(|(count, _, _)| count).sum();
    Ok(measured)
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

/// The founder's baseline at world scale: one node, 20,000 receivers clustered as the US and
/// Europe's are, about 3,000 Mode S-only aircraft among 9,000. Each cluster's raw is made in time
/// order straight into a holder (no batches, no copies) and each bin sealed once the stream is past
/// it, as an engine seals, so only the window and the open bins are ever held; then the window is
/// solved as the engine would, every stage timed: tile fits on every core, then the solves. The
/// clusters are an ocean apart (no tile spans both), so the world's figures are their sums.
/// Reports the reception rate per receiver (`WORLD_RECEPTION`, the chance a receiver in reach hears
/// a transmission: 0.12 is the rate RFC-0174 first measured at, about 40 wanted receptions a
/// second a receiver; 1.0, the default, every receiver in reach hearing everything, is the nearest
/// the simulator's few message kinds come to a real receiver's 360 a second, RFC-0181), the raw a
/// window holds and its bytes per observation, each bin's sealing time, and the cores the work of
/// one stride needs to keep up. Run in release with `--ignored --nocapture` (`WORLD_RECEIVERS` a
/// cluster, default 10,000; `WORLD_THREADS`, default every core).
#[test]
#[ignore = "a benchmark: run with --release -- --ignored --nocapture"]
fn world_scale_one_node() -> Result {
    let env = |name: &str| std::env::var(name).ok();
    let receivers: usize = env("WORLD_RECEIVERS")
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);
    let reception: f64 = env("WORLD_RECEPTION")
        .and_then(|value| value.parse().ok())
        .unwrap_or(1.0);
    let threads = env("WORLD_THREADS")
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(8, usize::from));
    let cluster = |seed: u64, centre: (f64, f64), spread_m: f64| Scenario {
        receivers,
        adsb_aircraft: 3_000,
        modes_aircraft: 1_500,
        centre,
        spread_m,
        reception_probability: reception,
        named: false,
        gps: (0..receivers).step_by(50).collect(),
        ..Scenario::new(seed)
    };
    // The first canonical window wholly after the run's first bin, and the run just long enough
    // to fill it.
    let base = cluster(0, (0.0, 0.0), 0.0);
    let first = crate::scope::bin_of(base.wall_ms(0.0)) + 1;
    let window = (first..)
        .map(Window::canonical)
        .find(|window| window.first >= first)
        .ok_or("no window")?;
    let duration_s = ((window.last + 1 - crate::scope::bin_of(base.wall_ms(0.0))) as u64
        * crate::scope::GRID_MS) as f64
        / 1_000.0;
    let clusters = [
        Scenario {
            duration_s,
            ..cluster(901, (50.0, 10.0), 1_500_000.0)
        },
        Scenario {
            duration_s,
            ..cluster(902, (39.0, -95.0), 2_000_000.0)
        },
    ];
    let mut all: Vec<Measured> = Vec::new();
    for scenario in &clusters {
        let measured = world_cluster(scenario, window, threads)?;
        eprintln!(
            "world cluster {}: {} receptions made in {:?}, {:.0} wanted a receiver a second; \
             window {} bins, {} held, {:.2} GB, {:.1} bytes each; peak held {:.2} GB ({:.2} GB \
             open); {} tiles, {} targets",
            scenario.seed,
            measured.made,
            measured.generated,
            measured.wanted as f64 / (measured.receivers as f64 * measured.seconds),
            measured.window_bins,
            measured.window_records,
            measured.window_bytes as f64 / 1e9,
            measured.window_bytes as f64 / measured.window_records.max(1) as f64,
            measured.peak_bytes as f64 / 1e9,
            measured.peak_open_bytes as f64 / 1e9,
            measured.tiles,
            measured.targets,
        );
        all.push(measured);
    }
    let sum = |field: fn(&Measured) -> usize| all.iter().map(field).sum::<usize>();
    let time = |field: fn(&Measured) -> std::time::Duration| {
        all.iter().map(field).sum::<std::time::Duration>()
    };
    let receivers_all = sum(|m| m.receivers);
    let wanted = sum(|m| m.wanted);
    let made = sum(|m| m.made);
    let records = sum(|m| m.window_records);
    let window_bytes = sum(|m| m.window_bytes);
    let window_s = (window.last - window.first + 1) as f64 * 5.0;
    // A world bin is both clusters' bins of one number, sealed one after the other.
    let seals: Vec<(usize, std::time::Duration)> = (0..all[0].seals.len().min(all[1].seals.len()))
        .skip(1)
        .map(|at| {
            (
                all[0].seals[at].0 + all[1].seals[at].0,
                all[0].seals[at].1 + all[1].seals[at].1,
            )
        })
        .collect();
    let seal_mean = seals
        .iter()
        .map(|(_, time)| *time)
        .sum::<std::time::Duration>()
        / seals.len().max(1) as u32;
    let seal_max = seals
        .iter()
        .map(|(_, time)| *time)
        .max()
        .unwrap_or_default();
    let seal_receptions = seals.iter().map(|(count, _)| count).sum::<usize>() / seals.len().max(1);
    let stride_s = crate::scope::STRIDE as f64 * 5.0;
    let planning = time(|m| m.planning);
    let fit_cpu = time(|m| m.fit_cpu);
    let solve_cpu = time(|m| m.solve_cpu);
    let alone_cpu = time(|m| m.alone_cpu);
    let seal_cpu = seal_mean.as_secs_f64() * threads as f64 * crate::scope::STRIDE as f64;
    let cpu = planning.as_secs_f64() + fit_cpu.as_secs_f64() + solve_cpu.as_secs_f64();
    eprintln!(
        "world: {receivers_all} receivers at reception {reception}, {made} receptions made, \
         {:.0} wanted a receiver a second, {:.0} kept after thinning; one window ({} bins, {} s) \
         holds {records} observations, {:.2} GB, {:.1} bytes each; peak held {:.2} GB a cluster; \
         process peak RSS {:.2} GB",
        wanted as f64 / (receivers_all as f64 * all[0].seconds),
        records as f64 / (receivers_all as f64 * window_s),
        all[0].window_bins,
        window_s,
        window_bytes as f64 / 1e9,
        window_bytes as f64 / records.max(1) as f64,
        all.iter().map(|m| m.peak_bytes).max().unwrap_or(0) as f64 / 1e9,
        peak_rss() as f64 / 1e9,
    );
    eprintln!(
        "world: a bin of {seal_receptions} receptions sealed in {seal_mean:?} on {threads} threads \
         (at most {seal_max:?}, {} bins)",
        seals.len()
    );
    eprintln!(
        "world: window index {:?}, plan {:?} wall on {threads} threads; {} targets on {} tiles; \
         fits {:?} wall on {threads} threads ({fit_cpu:?} of cores); {} published in \
         {solve_cpu:?} of cores, every one verified ({alone_cpu:?} solving alone, so checking \
         costs {:.0}% more); {:.1} core-seconds a stride of {stride_s} s: {:.1} cores to keep up, \
         and sealing at most {:.1} cores more",
        time(|m| m.indexing),
        time(|m| m.plan_wall),
        sum(|m| m.targets),
        sum(|m| m.tiles),
        time(|m| m.fit_wall),
        sum(|m| m.solutions),
        100.0 * (solve_cpu.as_secs_f64() / alone_cpu.as_secs_f64().max(1e-9) - 1.0),
        cpu,
        cpu / stride_s,
        seal_cpu / stride_s,
    );
    Ok(())
}

#[path = "provisional_tests.rs"]
mod provisional;
