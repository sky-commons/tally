//! Provisional positions over the simulator, on a virtual clock: how soon after its transmission
//! each is published, that each is what its model and receptions solve to, and that only targets
//! are solved, at most one an aircraft a second.

use std::collections::BTreeMap;

use tally_mlat_solver::ObservationId;
use tally_mlat_solver::sim;
use tally_wire::{Identity, Record};

use crate::engine::{Engine, Settings};
use crate::replay::{arrivals, replay, scenario, transmitted_ms};

fn engine(threads: usize) -> Engine {
    Engine::new(
        Identity::from_seed([4; 32]),
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            settle_ms: 1_000,
            threads,
            capacity: crate::engine::Capacity::default(),
        },
    )
}

/// Each provisional solution published, with when, and the true transmit time of what it solved.
fn provisionals(
    published: &[(u64, Record)],
    truth: &BTreeMap<ObservationId, usize>,
    simulation: &sim::Simulation,
) -> Result<Vec<(u64, u64, tally_wire::Solution)>, String> {
    let mut out = Vec::new();
    for (at, record) in published {
        // The raw form (a relay's); the tagged one is the same solutions for clients.
        let Record::Provisional(positions) = record else {
            continue;
        };
        if positions.is_tagged() {
            continue;
        }
        for solution in positions.solutions().map_err(|e| e.to_string())?.solutions {
            let first = solution.observations.receptions()[0];
            let id = ObservationId {
                receiver: first.receiver,
                epoch: first.epoch,
                timestamp: first.counter,
                message: tally_mlat_solver::obs::message_hash(solution.observations.message()),
            };
            let source = truth.get(&id).ok_or("an unknown observation")?;
            out.push((*at, transmitted_ms(simulation, *source), solution));
        }
    }
    Ok(out)
}

fn percentile(values: &mut [u64], at: f64) -> u64 {
    values.sort_unstable();
    values
        .get(((values.len() as f64 - 1.0) * at).round() as usize)
        .copied()
        .unwrap_or(0)
}

#[test]
fn a_provisional_position_is_published_within_two_seconds_of_its_transmission() -> Result<(), String>
{
    let mut simulation = sim::run(&scenario(31, 110.0));
    let delivered = arrivals(&mut simulation, 7)?;
    let truth: BTreeMap<ObservationId, usize> = simulation
        .receptions
        .iter()
        .zip(&simulation.sources)
        .map(|(reception, source)| (reception.id(), *source))
        .collect();
    let until = delivered.last().map_or(0, |(at, _)| *at) + 3_000;
    let mut engine = engine(2);
    let published = replay(&mut engine, &delivered, 100, until)?;
    let solved = provisionals(&published, &truth, &simulation)?;
    // Every provisional is published tagged too (format 6), for clients: no counter, no receiver.
    let mut tagged = 0;
    for (_, record) in &published {
        if let Record::Provisional(positions) = record
            && positions.is_tagged()
        {
            assert!(positions.is_provisional());
            tagged += positions
                .tagged_solutions()
                .map_err(|e| e.to_string())?
                .solutions
                .len();
        }
    }
    assert_eq!(tagged, solved.len());
    let bytes = |provisional: bool| -> usize {
        published
            .iter()
            .filter(|(_, record)| matches!(record, Record::Provisional(_)) == provisional)
            .filter(|(_, record)| matches!(record, Record::Provisional(_) | Record::Positions(_)))
            .map(|(_, record)| {
                let mut out = Vec::new();
                record.encode(&mut out).map_or(0, |()| out.len())
            })
            .sum()
    };
    eprintln!(
        "provisional records {} bytes, final positions records {} bytes",
        bytes(true),
        bytes(false)
    );
    let mut latency: Vec<u64> = solved
        .iter()
        .map(|(at, sent, _)| at.saturating_sub(*sent))
        .collect();
    let report = engine.provisional_report();
    assert!(
        latency.len() >= 200,
        "{} provisionals, {report:?}",
        latency.len()
    );
    let (median, p95, most) = (
        percentile(&mut latency, 0.5),
        percentile(&mut latency, 0.95),
        percentile(&mut latency, 1.0),
    );
    eprintln!(
        "{} provisional positions: latency median {median} ms, 95th {p95} ms, most {most} ms; \
         {report:?}",
        latency.len()
    );
    assert!(median <= 1_600, "median {median} ms");
    assert!(p95 <= 2_000, "95th percentile {p95} ms");
    assert_eq!(report.rejected, 0, "{report:?}");
    // At most one an aircraft a second (by transmit time, which a model states on its gauge's
    // origin, so a second's boundary may fall between two), and only targets: no aircraft whose
    // ADS-B positions were being heard, the calibration sample aside.
    let per_second: BTreeMap<(u32, u64), usize> =
        solved
            .iter()
            .fold(BTreeMap::new(), |mut counts, (_, _, s)| {
                *counts
                    .entry((s.address, s.transmitted.unix_ms / 1000))
                    .or_default() += 1;
                counts
            });
    assert!(
        per_second.values().all(|count| *count <= 2),
        "more than one an aircraft a second"
    );
    let adsb: std::collections::BTreeSet<u32> = simulation
        .aircraft
        .iter()
        .filter(|aircraft| aircraft.adsb)
        .map(|aircraft| aircraft.address)
        .collect();
    let sampled = solved
        .iter()
        .filter(|(_, _, s)| adsb.contains(&s.address))
        .count();
    assert!(
        sampled * 4 <= solved.len(),
        "{sampled} of {} provisionals are of ADS-B aircraft",
        solved.len()
    );
    Ok(())
}
