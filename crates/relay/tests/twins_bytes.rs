//! The positions checks' twins cost no more than the store they are charged to (RFC-0181, "The
//! positions checks"; `consistency::Caps::twins_bytes`, `budget::Store::Twins`): filled past both
//! rooms by the worst a sender can make of them (raw records of the smallest solutions the wire
//! carries, so the most entries for their bytes), from the relay's own engine and from two members,
//! each refused past its room or its share and nothing let go. Measured by an allocator that counts
//! every byte asked of it, in one test so nothing else in the binary allocates while it measures.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use std::sync::Arc;

use tally_mlat::engine::{Capacity, Engine, Settings};
use tally_mlat::replay::{arrivals, replay, scenario};
use tally_relay::consistency::{
    Caps, Class, Consistency, ConsistencyReport, SOLUTION_WIRE_LEAST, Sizing,
};
use tally_relay::models::Models;
use tally_wire::clocks::recorded::{judged, mono};
use tally_wire::{Identity, Positions, Record};

#[global_allocator]
static GLOBAL: tally_counting::CountingAll = tally_counting::CountingAll;

/// The most the twins' plan may be above what they hold at rest, filled: the table's slots and its
/// two tables made at an eighth more than its keys, beside the records' bytes themselves.
const SLACK_PERCENT: usize = 250;

/// A model a reference engine published, held in a store of decoded models as the hub holds one.
fn a_model() -> Result<(Arc<Models>, [u8; 32]), String> {
    let mut simulation = tally_mlat_solver::sim::run(&scenario(23, 40.0));
    let delivered = arrivals(&mut simulation, 5)?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = Engine::new(
        tally_wire::Signer::new(Identity::from_seed([4; 32]), Arc::new(|| true)),
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, 1_000>(),
            threads: 2,
            capacity: Capacity::default(),
        },
    );
    let published = replay(&mut engine, &delivered, 100, until)?;
    let records: Vec<Record> = published.iter().map(|(_, record)| record.clone()).collect();
    let models = Arc::new(Models::new());
    for (at, record) in &published {
        if let Record::ClockModel(manifest) = record {
            let parts: Vec<tally_wire::ClockModelPart> = records
                .iter()
                .filter_map(|record| match record {
                    Record::ClockModelPart(part) if part.model().ok() == Some(manifest.id()) => {
                        Some(part.clone())
                    }
                    _ => None,
                })
                .collect();
            let content = manifest.content(&parts).map_err(|e| e.to_string())?;
            if models
                .admit(manifest, &content, |_, _| true, judged(*at))
                .is_ok()
            {
                return Ok((models, manifest.id()));
            }
        }
    }
    Err("the engine published no model".to_owned())
}

/// A raw record of `count` solutions, each under `model`, of aircraft `first..`, each cited by
/// `receptions` receptions of receivers that are the record's every one, so their keys are in its
/// table once. At one reception a solution is the smallest the wire carries.
fn solutions(model: [u8; 32], first: u32, count: u32, receptions: u8) -> Result<Positions, String> {
    let receivers: Vec<_> = (0..receptions)
        .map(|at| Identity::from_seed([at.wrapping_add(100); 32]).public())
        .collect();
    let solutions = (first..first + count)
        .map(|address| {
            Ok(tally_wire::Solution {
                address,
                transmitted: tally_wire::TransmitTime::new(1_000, 0).map_err(|e| e.to_string())?,
                lat_e7: 374_000_000,
                lon_e7: -1_221_000_000,
                alt_hae_mm: None,
                covariance: tally_wire::EnuCovariance {
                    xx: 1.0,
                    xy: 0.0,
                    xz: 0.0,
                    yy: 1.0,
                    yz: 0.0,
                    zz: 1.0,
                },
                clock_model: model,
                addressed: tally_wire::AddressedCitation::default(),
                observations: tally_wire::ObservationSet::new(
                    Vec::new(),
                    receivers
                        .iter()
                        .map(|receiver| tally_wire::Reception {
                            receiver: *receiver,
                            epoch: 0,
                            counter: u64::from(address),
                        })
                        .collect(),
                )
                .map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Positions::sign_solutions(
        &Identity::from_seed([9; 32]),
        &tally_wire::SolutionsContent {
            boot_id: 1,
            sequence: u64::from(first),
            issued_ms: 1,
            spec_version: 1,
            solutions,
        },
    )
    .map_err(|e| e.to_string())
}

/// What filling checks of `caps` with `made`, each source in turn (the relay's own engine, and two
/// members sharing their room), allocates: at its peak, and held at rest once filled.
fn filled(
    models: &Arc<Models>,
    caps: Caps,
    made: &[Positions],
) -> (usize, usize, ConsistencyReport) {
    let mark = tally_counting::CountingAll::peak_base();
    let base = tally_counting::CountingAll::live();
    let rest;
    let report;
    {
        let checks = Consistency::with_caps(Arc::clone(models), caps);
        for (at, positions) in made.iter().enumerate() {
            let from = match at % 3 {
                0 => (0, Class::Own),
                1 => (1, Class::Members),
                _ => (2, Class::Members),
            };
            checks.raw(positions, from, mono(0), |_| true);
        }
        rest = usize::try_from(tally_counting::CountingAll::since(base)).unwrap_or(usize::MAX);
        report = checks.report();
    }
    let peak = usize::try_from(tally_counting::CountingAll::peak_since(mark)).unwrap_or(0);
    (peak, rest, report)
}

/// Holds one fill to the plan of `caps`: every room reached (the members' by their shares too),
/// the peak within the plan, at rest within its tables, and the tables no looser than the slack.
fn within(caps: Caps, (peak, rest, report): (usize, usize, ConsistencyReport), what: &str) {
    let planned = caps.twins_bytes() + caps.sites_bytes();
    let tables = planned - tally_relay::consistency::WORKING_BYTES;
    println!("{what}: {peak} at the peak, {rest} at rest, {planned} planned: {report:?} {caps:?}");
    assert!(
        report.full > 0 && report.over_share > 0,
        "{what}: {report:?}"
    );
    assert!(
        report.held > 0 && report.unwanted == 0,
        "{what}: {report:?}"
    );
    assert!(
        peak <= planned,
        "{what}: {peak} at the peak, {planned} planned"
    );
    assert!(
        rest <= tables,
        "{what}: {rest} at rest, the tables {tables}"
    );
    assert!(
        tables * 100 <= rest * SLACK_PERCENT,
        "{what}: the plan is loose: {rest} at rest, the tables {tables}"
    );
}

/// `per_record` solutions of `receptions` each a record, each source a third more than the larger
/// room, so the relay's own fills its room and each member passes its share.
fn made(
    model: [u8; 32],
    caps: Caps,
    per_record: u32,
    receptions: u8,
) -> Result<Vec<Positions>, String> {
    let record = solutions(model, 0, per_record, receptions)?
        .as_bytes()
        .len();
    let records = 3 * caps.own.bytes.max(caps.members.bytes) * 4 / 3 / record;
    (0..records as u32)
        .map(|at| solutions(model, at * per_record, per_record, receptions))
        .collect()
}

#[test]
fn the_twins_allocate_no_more_than_they_are_charged() -> Result<(), String> {
    let (models, model) = a_model()?;
    // The wire's least is the least a solution takes: one of these is no larger.
    let one = solutions(model, 0, 1, 1)?.as_bytes().len();
    let two = solutions(model, 0, 2, 1)?.as_bytes().len();
    assert_eq!(
        two - one,
        SOLUTION_WIRE_LEAST,
        "a solution's least on the wire"
    );
    let caps = Caps::of(Sizing {
        receivers: 0,
        members: 1,
        members_bytes_per_sec: 20_000,
        own_bytes_per_sec: 20_000,
    });
    // The smallest solutions: the most entries for their bytes, the table at its worst.
    let smallest = made(model, caps, 200, 1)?;
    within(caps, filled(&models, caps, &smallest), "the smallest");
    drop(smallest);
    // Solutions cited by many receptions, in rooms of as many entries as their bytes bring: the
    // records' bytes at their worst, the table small, so a plan short of the bytes is seen.
    let heavy = made(model, caps, 20, 40)?;
    let per_twin = heavy[0].as_bytes().len() / 20;
    let rooms = |room: tally_relay::consistency::RoomCaps| tally_relay::consistency::RoomCaps {
        bytes: room.bytes,
        twins: room.bytes / per_twin,
    };
    let bytes_bound = Caps {
        own: rooms(caps.own),
        members: rooms(caps.members),
        ..caps
    };
    within(
        bytes_bound,
        filled(&models, bytes_bound, &heavy),
        "the heaviest",
    );
    Ok(())
}
