//! Provisional solutions over the simulator (crate docs, § Provisional solutions): a tile's model
//! carried past its knots to the transmissions after its window, as an engine solves them a second
//! after they are heard; calibrated by how far the model was carried, deterministic, and verified
//! as any checker would.

use super::*;
use crate::clock::{MAX_CARRY_PS, PS, Reach};
use crate::group::group_reach;
use crate::modes;
use crate::scope::{GRID_MS, STRIDE};
use crate::solve::solve;

/// One provisional solution and its truth.
struct Carried {
    /// How far the model was carried for its earliest reception, seconds.
    carried_s: f64,
    inside: bool,
    published_inside: bool,
    horizontal_m: f64,
}

/// The replies (not ADS-B: those sync clocks, and MLAT is for aircraft without them) of
/// `address` by the receivers of `scope`, heard after `from_ms` and up to `until_ms`.
fn later_replies(
    simulation: &Simulation,
    address: u32,
    scope: &[tally_wire::PublicKey],
    from_ms: u64,
    until_ms: u64,
) -> Vec<Reception> {
    let wanted: BTreeSet<&tally_wire::PublicKey> = scope.iter().collect();
    simulation
        .receptions
        .iter()
        .filter(|reception| {
            reception.wall_ms > from_ms
                && reception.wall_ms <= until_ms
                && wanted.contains(&reception.receiver)
                && modes::address(&reception.observation.data) == Some(address)
                && !matches!(
                    modes::downlink_format(&reception.observation.data),
                    Some(17 | 18)
                )
        })
        .cloned()
        .collect()
}

/// A tile's model of one window, and each of its aircraft's replies after the window, up to the
/// longest carry.
struct Model {
    model: ClockModel,
    calibrated: Calibrated,
    later: Vec<Vec<Reception>>,
}

/// Every tile model of the first `windows_used` windows with a carry's span of raw after them.
fn carried_models(simulation: &Simulation, windows_used: usize) -> Result<Vec<Model>> {
    let bins = all_bins(&simulation.receptions);
    let sites = Sites::new(&simulation.sites());
    let last_ms = simulation
        .receptions
        .iter()
        .map(|reception| reception.wall_ms)
        .max()
        .ok_or("no receptions")?;
    let carry_ms = (MAX_CARRY_PS / (PS / 1000)) as u64;
    let mut out = Vec::new();
    let usable = windows(&bins, STRIDE)
        .into_iter()
        .filter(|window| (window.last as u64 + 1) * GRID_MS + carry_ms <= last_ms)
        .take(windows_used);
    for window in usable {
        let end_ms = (window.last as u64 + 1) * GRID_MS;
        let index = WindowIndex::new(window, &bins, &sites);
        let plan = index.plan();
        for tile in plan.tiles() {
            let Some(inputs) = index.inputs(tile, &plan.members[&tile]) else {
                continue;
            };
            let Ok((model, calibrated)) = crate::fit_calibrated(&inputs) else {
                continue;
            };
            let later = plan
                .assignments
                .iter()
                .filter(|(_, assignment)| assignment.tile == tile)
                .map(|(address, assignment)| {
                    later_replies(
                        simulation,
                        *address,
                        &assignment.scope,
                        end_ms,
                        end_ms + carry_ms,
                    )
                })
                .collect();
            out.push(Model {
                model,
                calibrated,
                later,
            });
        }
    }
    Ok(out)
}

/// A carried model's transmissions as an engine solves them: carried past the model's knots, at
/// most one an aircraft a second.
fn carried_transmissions(model: &ClockModel, later: &[Reception]) -> Vec<Transmission> {
    let mut seconds = BTreeSet::new();
    group_reach(model, later, Reach::Carried)
        .transmissions
        .into_iter()
        .filter(|transmission| {
            let carried = transmission
                .receptions
                .iter()
                .map(|timed| timed.time.carried_ps)
                .min()
                .unwrap_or(0);
            let second = transmission
                .receptions
                .iter()
                .map(|timed| timed.wall_ms / 1000)
                .min();
            carried > 0 && seconds.insert(second)
        })
        .collect()
}

/// Every model carried over the replies after its window, each transmission solved and checked
/// against the truth.
fn carried_solutions(scenario: &Scenario, windows_used: usize) -> Result<Vec<Carried>> {
    let simulation = sim::run(scenario);
    let truth = truth_of(&simulation);
    let mut out = Vec::new();
    for carried in carried_models(&simulation, windows_used)? {
        for later in &carried.later {
            for transmission in carried_transmissions(&carried.model, later) {
                let earliest = transmission
                    .receptions
                    .iter()
                    .map(|timed| timed.time.carried_ps)
                    .min()
                    .unwrap_or(0);
                let Ok(solution) = solve(&carried.calibrated, &transmission) else {
                    continue;
                };
                let source = truth
                    .get(&solution.observations[0])
                    .ok_or("unknown observation")?;
                let actual = simulation.transmissions[*source].ecef;
                let error = linalg::sub(solution.ecef, actual);
                let basis = geo::enu_basis(solution.position.lat_deg, solution.position.lon_deg);
                out.push(Carried {
                    carried_s: earliest as f64 / PS as f64,
                    inside: mahalanobis(&solution, actual).is_some_and(|d| d < CHI2_3_95),
                    published_inside: mahalanobis_published(&solution, actual)
                        .is_some_and(|d| d < CHI2_3_95),
                    horizontal_m: linalg::dot(error, basis[0]).hypot(linalg::dot(error, basis[1])),
                });
            }
        }
    }
    Ok(out)
}

/// A scenario long enough to carry a window's model its whole span.
fn long(seed: u64) -> Scenario {
    Scenario {
        duration_s: 170.0,
        ..Scenario::new(seed)
    }
}

/// The median of a list, or zero.
fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values.get(values.len() / 2).copied().unwrap_or(0.0)
}

#[test]
fn a_carried_models_provisional_positions_are_calibrated_however_far_it_was_carried() -> Result {
    let mut all = Vec::new();
    for seed in 0..6 {
        all.extend(carried_solutions(&long(9_000 + seed), 2)?);
    }
    // The bands: a model a step old (up to 20 s), one a stride old (to 45 s), and the longest a
    // world-scale engine carries one (to 90 s).
    let bands = [(0.0, 20.0), (20.0, 45.0), (45.0, 90.0)];
    let mut overall = Count::default();
    let mut published = Count::default();
    for (low, high) in bands {
        let mut band = Count::default();
        let mut errors = Vec::new();
        for one in all
            .iter()
            .filter(|one| one.carried_s > low && one.carried_s <= high)
        {
            band.add(one.inside);
            errors.push(one.horizontal_m);
        }
        eprintln!(
            "carried {low} to {high} s: {}/{} inside the 95% ellipsoid ({:.3}), median \
             horizontal error {:.1} m",
            band.inside,
            band.total,
            band.rate(),
            median(errors)
        );
        assert!(band.total >= 100, "too few carried {low} to {high} s");
        assert!(
            (0.90..=0.985).contains(&band.rate()),
            "carried {low} to {high} s: {}",
            band.rate()
        );
    }
    for one in &all {
        overall.add(one.inside);
        published.add(one.published_inside);
    }
    eprintln!(
        "provisional overall {:.3} of {}, published {:.3}, median horizontal error {:.1} m",
        overall.rate(),
        overall.total,
        published.rate(),
        median(all.iter().map(|one| one.horizontal_m).collect())
    );
    assert!(
        (0.93..=0.97).contains(&overall.rate()),
        "provisional coverage {}",
        overall.rate()
    );
    assert!(published.rate() >= overall.rate());
    Ok(())
}

#[test]
fn a_provisional_is_a_function_of_its_model_and_receptions_and_verifies_carried() -> Result {
    let simulation = sim::run(&long(9_100));
    let mut rng = Rng::new(5);
    let (mut solved, mut checked) = (0, 0);
    for carried in carried_models(&simulation, 1)? {
        for later in &carried.later {
            let transmissions = carried_transmissions(&carried.model, later);
            // The same receptions in any order and with copies: the same transmissions, and
            // each the same solution to the bit.
            let again = carried_transmissions(&carried.model, &shuffled(later, &mut rng));
            assert_eq!(transmissions, again);
            for transmission in &transmissions {
                let Ok(solution) = solve(&carried.calibrated, transmission) else {
                    continue;
                };
                assert_eq!(
                    solve(&carried.calibrated, transmission).ok().as_ref(),
                    Some(&solution)
                );
                solved += 1;
                if solved % 7 != 0 {
                    continue;
                }
                // As any checker would: read back from the wire, verified with the model carried
                // against the receptions it was solved from.
                let wire = publish::to_wire(
                    &carried.model,
                    &solution,
                    [0; 32],
                    Citation::default(),
                    &transmission.data,
                )
                .map_err(text)?;
                let claim = publish::claim(&carried.model, &wire, SPEC_VERSION).map_err(text)?;
                let verdict =
                    crate::verify_reach(&carried.calibrated, later, &claim, Reach::Carried);
                assert!(verdict.passed(), "{:?}", verdict.failures);
                // Within its window only, the model says nothing of it.
                assert!(!crate::verify(&carried.calibrated, later, &claim).passed());
                let mut moved = wire.clone();
                moved.lat_e7 += 300;
                let claim = publish::claim(&carried.model, &moved, SPEC_VERSION).map_err(text)?;
                assert!(
                    !crate::verify_reach(&carried.calibrated, later, &claim, Reach::Carried)
                        .passed()
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 20, "{checked} of {solved}");
    Ok(())
}
