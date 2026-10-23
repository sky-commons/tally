//! The step over the simulator: determinism under order, copies and threads; two engines that
//! cover a footprint publish the same tile; one that does not publishes none; one fit per tile.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use super::*;
use crate::engine::{Engine, Settings};
use std::collections::{BTreeMap, BTreeSet};
use tally_mlat_solver::scope::{AFTER, GRID_MS, STRIDE, bin_of};
use tally_mlat_solver::sim::{self, Rng, Scenario, Simulation};
use tally_wire::clocks::recorded::aligned;
use tally_wire::{
    EnuCovariance, Identity, ObservationSet, Reception as WireReception, Region, TransmitTime,
};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

const SETTLE_MS: u64 = 1_000;

fn engine(seed: u8, regions: Vec<Region>, threads: usize) -> Engine {
    Engine::new(
        tally_wire::Signer::new(
            Identity::from_seed([seed; 32]),
            std::sync::Arc::new(|| true),
        ),
        0xb007,
        Settings {
            regions: regions.into_iter().collect(),
            settle: tally_wire::budget::policy::<_, SETTLE_MS>(),
            threads,
            capacity: crate::engine::Capacity::default(),
        },
    )
}

/// What `simulation`'s receivers publish: descriptions and sites, then batches.
fn records(simulation: &Simulation) -> Result<(Vec<Record>, Vec<Record>), String> {
    let feeds = simulation.feeds().map_err(text)?;
    let infos = feeds
        .iter()
        .flat_map(|feed| {
            [
                Record::ReceiverInfo(feed.info.clone()),
                Record::ReceiverSite(feed.site.clone()),
            ]
        })
        .collect();
    let batches = feeds
        .iter()
        .flat_map(|feed| feed.batches.iter().cloned().map(Record::Batch))
        .collect();
    Ok((infos, batches))
}

/// The engine's clock: past every window of `simulation`'s raw.
fn after(simulation: &Simulation) -> u64 {
    let last = simulation
        .receptions
        .iter()
        .map(|r| bin_of(r.wall_ms))
        .max()
        .unwrap_or(0);
    (last + STRIDE + AFTER + 1) as u64 * GRID_MS + SETTLE_MS
}

fn encoded(records: &[Record]) -> Result<Vec<Vec<u8>>, String> {
    records
        .iter()
        .map(|record| {
            let mut bytes = Vec::new();
            record.encode(&mut bytes).map_err(text)?;
            Ok(bytes)
        })
        .collect()
}

/// Shuffled, with every batch delivered two or three times, as overlapping relays would.
fn delivered<'a>(batches: &'a [Record], rng: &mut Rng) -> Vec<&'a Record> {
    let mut out: Vec<&Record> = batches.iter().collect();
    out.extend(batches.iter());
    out.extend(batches.iter().filter(|_| rng.uniform() < 0.5));
    for at in (1..out.len()).rev() {
        let other = (rng.next_u64() % (at as u64 + 1)) as usize;
        out.swap(at, other);
    }
    out
}

/// A busier scenario than the default: more Mode S-only aircraft, the engine's targets.
fn scenario(seed: u64) -> Scenario {
    Scenario {
        duration_s: 30.0,
        modes_aircraft: 16,
        ..Scenario::new(seed)
    }
}

/// What a step publishes for clients beside each relay-only form: a `ClientClockModel` per full
/// model (numbered with it, naming it by id, nothing of its members) and every solution tagged, in
/// records numbered after the raw ones. No client form names a receiver: its key, its site (each
/// site's latitude and longitude as the wire writes them), its site id and its counters, the
/// canaries, are in none (its reception key is never written at all); a relay
/// holding the receivers' sites and the raw rematches every tagged solution to the raw one.
#[test]
fn a_step_publishes_client_forms_that_carry_no_site_and_rematch_on_a_relay() -> Result<(), String> {
    let simulation = sim::run(&scenario(5));
    let (infos, batches) = records(&simulation)?;
    let now = after(&simulation);
    let mut engine = engine(9, Vec::new(), 2);
    for record in infos.iter().chain(&batches) {
        engine.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let (published, report) = engine.step(tally_wire::clocks::recorded::aligned(now));
    assert!(report.solved >= 100, "{report:?}");
    assert_eq!(report.untagged, 0, "{report:?}");
    assert!(report.tagged_positions >= 1, "{report:?}");
    let client: Vec<tally_wire::ClientRecord> = published
        .iter()
        .filter_map(|record| tally_wire::ClientRecord::try_from(record.clone()).ok())
        .collect();
    let relay_only = published.len() - client.len();
    assert!(relay_only >= report.clock_models + report.positions);
    // The canaries: every receiver's site and key, and every raw counter published.
    let contains = |bytes: &[u8], canary: &[u8]| bytes.windows(canary.len()).any(|at| at == canary);
    let mut raw: Vec<tally_wire::Solution> = Vec::new();
    let mut models = Vec::new();
    for record in &published {
        match record {
            Record::Positions(positions) if !positions.is_tagged() => {
                raw.extend(positions.solutions().map_err(text)?.solutions);
            }
            Record::ClockModel(manifest) => models.push(manifest.id()),
            _ => {}
        }
    }
    let mut tagged: Vec<tally_wire::TaggedSolution> = Vec::new();
    let mut summaries = Vec::new();
    for record in &client {
        let mut bytes = Vec::new();
        record.encode(&mut bytes).map_err(text)?;
        // No client form names a receiver: not its key, its site or its site id.
        for receiver in &simulation.receivers {
            let canaries: [&[u8]; 4] = [
                receiver.key.as_bytes(),
                &receiver.site.location.lat_e7.to_be_bytes(),
                &receiver.site.location.lon_e7.to_be_bytes(),
                &receiver.record.site_id().0,
            ];
            for canary in canaries {
                assert!(!contains(&bytes, canary), "{record:?}");
            }
        }
        match record {
            tally_wire::ClientRecord::Positions(positions) => {
                let content = positions.get().tagged_solutions().map_err(text)?;
                for solution in &raw {
                    for reception in solution.observations.receptions() {
                        assert!(!contains(&bytes, &reception.counter.to_be_bytes()[2..]));
                    }
                }
                tagged.extend(content.solutions);
            }
            tally_wire::ClientRecord::ClockModel(summary) => {
                summaries.push(summary.content().map_err(text)?)
            }
            _ => {}
        }
    }
    // One summary a model, naming it, of one size: nothing of its members.
    let ids: Vec<_> = summaries.iter().map(|summary| summary.model).collect();
    assert_eq!(ids, models);
    for summary in &summaries {
        assert_eq!(summary.spec_version, SPEC_VERSION);
    }
    // Every raw solution, and only those, tagged; a relay rematches each.
    assert_eq!(tagged.len(), raw.len());
    let keys: BTreeMap<_, _> = simulation
        .receivers
        .iter()
        .map(|receiver| (receiver.key, receiver.record.reception_key()))
        .collect();
    for (one, wire) in tagged.iter().zip(&raw) {
        let held = wire.observations.receptions().iter().copied();
        let back = tally_mlat_solver::publish::rematch(one, held, |key| keys.get(key).copied());
        assert_eq!(back.as_ref(), Some(wire));
    }
    // The positions sequence runs on through the tagged records.
    let sequences: Vec<u64> = published
        .iter()
        .filter_map(|record| match record {
            Record::Positions(positions) => Some(positions.sequence()),
            _ => None,
        })
        .collect();
    assert_eq!(sequences, (0..sequences.len() as u64).collect::<Vec<_>>());
    Ok(())
}

/// (b) The same observations, delivered in any order and any number of times, and solved on one
/// thread or several, sign to the same bytes.
#[test]
fn the_same_raw_signs_the_same_bytes_whatever_the_order_copies_and_threads() -> Result<(), String> {
    let simulation = sim::run(&scenario(5));
    let (infos, batches) = records(&simulation)?;
    let now = after(&simulation);
    let mut first = engine(9, Vec::new(), 1);
    for record in infos.iter().chain(&batches) {
        first.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let (one, report) = first.step(tally_wire::clocks::recorded::aligned(now));
    assert!(report.solved >= 100, "{report:?}");
    assert_eq!(report.rejected, 0, "{report:?}");
    assert!(one.iter().any(|r| matches!(r, Record::ClockModel(_))));
    assert!(one.iter().any(|r| matches!(r, Record::Positions(_))));
    // Sealing and solving spread over 2, 8 and 32 threads (RFC-0181 invariant 1).
    for threads in [2, 8, 32] {
        let mut rng = Rng::new(77 + threads as u64);
        let mut second = engine(9, Vec::new(), threads);
        for record in infos.iter().rev() {
            second.ingest(record, aligned(crate::replay::sent_ms(record)))?;
        }
        for record in delivered(&batches, &mut rng) {
            second.ingest(record, aligned(crate::replay::sent_ms(record)))?;
        }
        let (two, _) = second.step(tally_wire::clocks::recorded::aligned(now));
        assert_eq!(encoded(&one)?, encoded(&two)?, "{threads} threads");
    }
    // Each window is solved once: the same clock again publishes nothing.
    let (none, _) = first.step(tally_wire::clocks::recorded::aligned(now + 1));
    assert!(none.is_empty());
    Ok(())
}

/// The engine signs through its signer only (`tally_wire::Signer`): a step whose relay's clock is
/// not judging when it signs publishes no model, no client model and no positions, though it
/// solved them. Before, the engine held the relay's key itself and signed whatever the clock.
#[test]
fn a_step_signs_nothing_while_its_signers_clock_is_not_judging() -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let simulation = sim::run(&scenario(5));
    let (infos, batches) = records(&simulation)?;
    let now = after(&simulation);
    let judging = std::sync::Arc::new(AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&judging);
    let mut engine = Engine::new(
        tally_wire::Signer::new(
            Identity::from_seed([9; 32]),
            std::sync::Arc::new(move || flag.load(Ordering::Relaxed)),
        ),
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, SETTLE_MS>(),
            threads: 1,
            capacity: crate::engine::Capacity::default(),
        },
    );
    for record in infos.iter().chain(&batches) {
        engine.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let (records, report) = engine.step(tally_wire::clocks::recorded::aligned(now));
    assert!(report.solved >= 100, "{report:?}");
    assert!(
        !records.iter().any(|record| matches!(
            record,
            Record::ClockModel(_)
                | Record::ClientClockModel(_)
                | Record::Positions(_)
                | Record::ClockModelPart(_)
        )),
        "signed while the clock was not judging"
    );
    Ok(())
}

/// The models and solutions an engine published, by tile and window: each model's bytes and the
/// solutions citing it (their citation aside, which names the engine's own record).
type Published = BTreeMap<(Tile, i64), (Vec<u8>, Vec<tally_wire::Solution>)>;

fn published(records: &[Record]) -> Result<Published, String> {
    let mut models: BTreeMap<[u8; 32], (Tile, i64)> = BTreeMap::new();
    let mut out = Published::new();
    for record in records {
        match record {
            Record::ClockModel(manifest) => {
                let content = manifest.content(&[]).map_err(text)?;
                let model = publish::decode(&content.model, content.spec_version).map_err(text)?;
                models.insert(manifest.id(), (model.tile, model.window.first));
                out.insert(
                    (model.tile, model.window.first),
                    (content.model, Vec::new()),
                );
            }
            Record::Positions(positions) if !positions.is_tagged() => {
                for mut solution in positions.solutions().map_err(text)?.solutions {
                    let key = *models
                        .get(&solution.clock_model)
                        .ok_or("an uncited model")?;
                    solution.clock_model = [0; 32];
                    if let Some((_, list)) = out.get_mut(&key) {
                        list.push(solution);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The H3 cells (resolution 3, about 60 km across) of every point within `radius_m` of each
/// receiver of `receivers`: a region generous enough to cover the tiles those receivers' aircraft
/// are assigned.
fn region_around(
    simulation: &Simulation,
    receivers: std::ops::Range<usize>,
    radius_m: f64,
) -> Result<Vec<Region>, String> {
    let mut cells: BTreeSet<u64> = BTreeSet::new();
    for receiver in &simulation.receivers[receivers] {
        let centre = receiver.site.location;
        let lat = f64::from(centre.lat_e7) * 1e-7;
        let lon = f64::from(centre.lon_e7) * 1e-7;
        let steps = (radius_m / 10_000.0) as i32;
        for north in -steps..=steps {
            for east in -steps..=steps {
                let location = tally_wire::Location {
                    lat_e7: ((lat + f64::from(north) * 10_000.0 / 111_132.0) * 1e7) as i32,
                    lon_e7: ((lon
                        + f64::from(east) * 10_000.0 / (111_320.0 * lat.to_radians().cos()))
                        * 1e7) as i32,
                    alt_m: 0,
                    precision_m: 0,
                };
                cells.insert(Region::containing(&location, 3).map_err(text)?.as_u64());
            }
        }
    }
    cells
        .into_iter()
        .map(|cell| Region::from_u64(cell).map_err(text))
        .collect()
}

/// (b) THE POINT: two engines whose regions both cover a tile's footprint, holding different raw
/// beyond it and receiving it in different orders, publish the byte-identical tile model and the
/// identical solutions under it. And an engine whose region does not cover a footprint publishes
/// no model of that tile (it does not hold every receiver the members are chosen from).
#[test]
fn engines_covering_a_footprint_publish_the_same_tile_and_one_not_covering_it_none()
-> Result<(), String> {
    let near = sim::run(&scenario(21));
    let far = sim::run(&Scenario {
        centre: (40.4, -3.7),
        ..scenario(22)
    });
    let mut both = engine(1, Vec::new(), 2);
    // The second: the near receivers and 600 km around them (every footprint of theirs), and none
    // of the far ones.
    let around = region_around(&near, 0..near.receivers.len(), 600_000.0)?;
    let mut near_only = engine(2, around, 3);
    // The third: a small cell (about 8 km) round each near receiver: it holds every one of them,
    // so it plans their tiles, but covers no footprint (the least is 70 km about its centre).
    let mut small: Vec<Region> = Vec::new();
    for receiver in &near.receivers {
        let cell = Region::containing(&receiver.site.location, 5).map_err(text)?;
        if !small.contains(&cell) {
            small.push(cell);
        }
    }
    let mut tiny = engine(3, small, 1);
    let (near_infos, near_batches) = records(&near)?;
    let (far_infos, far_batches) = records(&far)?;
    let all: Vec<&Record> = near_infos
        .iter()
        .chain(&far_infos)
        .chain(&near_batches)
        .chain(&far_batches)
        .collect();
    for record in &all {
        both.ingest(record, aligned(crate::replay::sent_ms(record)))?;
        tiny.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let mut rng = Rng::new(9);
    for record in far_infos.iter().chain(near_infos.iter().rev()) {
        near_only.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let mut mixed: Vec<Record> = near_batches.clone();
    mixed.extend(far_batches.iter().cloned());
    for record in delivered(&mixed, &mut rng) {
        near_only.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let now = after(&near).max(after(&far));
    let (a, report) = both.step(tally_wire::clocks::recorded::aligned(now));
    let (b, near_report) = near_only.step(tally_wire::clocks::recorded::moment(now, now + 7));
    let (c, tiny_report) = tiny.step(tally_wire::clocks::recorded::aligned(now));
    let (a, b) = (published(&a)?, published(&b)?);
    let near_tiles: BTreeSet<(Tile, i64)> = b.keys().copied().collect();
    assert!(
        near_tiles.len() >= 5,
        "{} tiles; {near_report:?}",
        near_tiles.len()
    );
    for key in &near_tiles {
        assert!(
            a.get(key) == b.get(key),
            "tile {key:?} differs between the engines"
        );
    }
    // The far region's tiles are the first engine's alone.
    assert!(a.len() > b.len(), "{} {}; {report:?}", a.len(), b.len());
    // The engine covering no footprint fits nothing and publishes nothing.
    assert_eq!(tiny_report.fits, 0, "{tiny_report:?}");
    assert!(tiny_report.uncovered > 0, "{tiny_report:?}");
    assert!(c.is_empty());
    Ok(())
}

/// One fit per distinct tile the window's targets chose, never more: the step's counters say so,
/// and the models published are of distinct tiles.
#[test]
fn a_window_fits_each_distinct_tile_its_targets_chose_once() -> Result<(), String> {
    let simulation = sim::run(&scenario(31));
    let (infos, batches) = records(&simulation)?;
    let mut engine = engine(4, Vec::new(), 4);
    for record in infos.iter().chain(&batches) {
        engine.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let now = after(&simulation);
    let (records, report) = engine.step(tally_wire::clocks::recorded::aligned(now));
    assert!(report.windows >= 2 && report.tiles > 0, "{report:?}");
    assert_eq!(report.fits + report.uncovered, report.tiles, "{report:?}");
    assert_eq!(report.uncovered, 0, "{report:?}");
    let models: Vec<(Tile, i64)> = published(&records)?.keys().copied().collect();
    let distinct: BTreeSet<(Tile, i64)> = models.iter().copied().collect();
    assert_eq!(models.len(), distinct.len());
    assert!(report.clock_models <= report.fits, "{report:?}");
    Ok(())
}

#[test]
fn a_window_waits_until_it_has_ended_and_settled() -> Result<(), String> {
    let simulation = sim::run(&Scenario {
        duration_s: 8.0,
        ..scenario(6)
    });
    let (infos, batches) = records(&simulation)?;
    let mut engine = engine(3, Vec::new(), 1);
    for record in infos.iter().chain(&batches) {
        engine.ingest(record, aligned(crate::replay::sent_ms(record)))?;
    }
    let first = simulation
        .receptions
        .iter()
        .map(|r| bin_of(r.wall_ms))
        .min()
        .ok_or("no raw")?;
    let window = Window::canonical(first);
    let due = (window.last + 1) as u64 * GRID_MS + SETTLE_MS;
    let (early, report) = engine.step(tally_wire::clocks::recorded::aligned(due - 1));
    assert!(early.is_empty() && report.windows == 0, "{report:?}");
    let (_, report) = engine.step(tally_wire::clocks::recorded::aligned(due));
    assert_eq!(report.windows, 1, "{report:?}");
    Ok(())
}

fn solution(seed: u8) -> Result<tally_wire::Solution, String> {
    let receptions = (1..=8u8)
        .map(|n| WireReception {
            receiver: Identity::from_seed([n; 32]).public(),
            epoch: 1,
            counter: u64::from(seed) * 100 + u64::from(n),
        })
        .collect();
    Ok(tally_wire::Solution {
        address: 0x480000 + u32::from(seed),
        transmitted: TransmitTime::new(1_791_244_800_000, u32::from(seed)).map_err(text)?,
        lat_e7: 521_000_000,
        lon_e7: 51_000_000,
        alt_hae_mm: Some(10_000_000),
        covariance: EnuCovariance {
            xx: 100.0,
            xy: 1.0,
            xz: 2.0,
            yy: 100.0,
            yz: 3.0,
            zz: 900.0,
        },
        clock_model: [seed % 3; 32],
        addressed: tally_wire::AddressedCitation::default(),
        observations: ObservationSet::new(vec![0x5d, 0x48, 0, seed, 1, 2, 3], receptions)
            .map_err(text)?,
    })
}

#[test]
fn solutions_are_packed_into_as_few_records_as_hold_them_in_order() -> Result<(), String> {
    let identity = Identity::from_seed([4; 32]);
    let all = (0..=255u8)
        .cycle()
        .take(700)
        .map(solution)
        .collect::<Result<Vec<_>, _>>()?;
    let records = pack_with(
        10,
        all.clone(),
        Positions::fitting,
        |sequence, run: &[tally_wire::Solution]| {
            Positions::sign_solutions(&identity, &solutions_content((1, sequence, 2), run))
        },
    );
    assert!(records.len() >= 2, "{} records", records.len());
    let mut back = Vec::new();
    for (at, record) in records.iter().enumerate() {
        record.verify().map_err(text)?;
        assert!(record.as_bytes().len() <= tally_wire::positions::MAX_POSITIONS_LEN);
        assert_eq!(record.sequence(), 10 + at as u64);
        back.extend(record.solutions().map_err(text)?.solutions);
    }
    assert_eq!(back, all);
    let first = records[0].solutions().map_err(text)?.solutions.len();
    assert!(
        Positions::sign_solutions(
            &identity,
            &SolutionsContent {
                boot_id: 1,
                sequence: 10,
                issued_ms: 2,
                spec_version: SPEC_VERSION,
                solutions: all[..=first].to_vec(),
            },
        )
        .is_err()
    );
    Ok(())
}

/// Packing signs record after record, and on a gate of one permit a provisional step
/// waits for one signing at most: a checkpoint comes before every one. Before, the packing of a
/// window's solutions (tens of signings, each over up to the wire's largest record) was one item.
/// And each record is signed once, over the prefix the wire measures it holds
/// (`Positions::fitting`): before, each was found by signing ever shorter prefixes of all that was
/// left, about twice what was left signed a record, and a window step of 80,000 solutions packed
/// for two minutes on one thread.
#[test]
fn packing_signs_each_record_once_and_checkpoints_before_every_signing() -> Result<(), String> {
    let identity = Identity::from_seed([4; 32]);
    let all = (0..=255u8)
        .cycle()
        .take(700)
        .map(solution)
        .collect::<Result<Vec<_>, _>>()?;
    let signed = std::cell::Cell::new(0u64);
    let before = tally_mlat_solver::gate::checkpoints_here();
    let records = pack_with(
        10,
        all,
        Positions::fitting,
        |sequence, run: &[tally_wire::Solution]| {
            signed.set(signed.get() + 1);
            Positions::sign_solutions(&identity, &solutions_content((1, sequence, 2), run))
        },
    );
    let passed = tally_mlat_solver::gate::checkpoints_here() - before;
    assert!(records.len() >= 2);
    assert_eq!(signed.get(), records.len() as u64);
    assert!(
        passed >= signed.get(),
        "{passed} checkpoints for {} signings",
        signed.get()
    );
    Ok(())
}
