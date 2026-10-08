//! The step over the simulator: determinism under order, copies and threads; two engines that
//! cover a footprint publish the same tile; one that does not publishes none; one fit per tile.

use super::*;
use crate::engine::{Engine, Settings};
use std::collections::{BTreeMap, BTreeSet};
use tally_mlat_solver::scope::{AFTER, GRID_MS, STRIDE, bin_of};
use tally_mlat_solver::sim::{self, Rng, Scenario, Simulation};
use tally_wire::{EnuCovariance, ObservationSet, Reception as WireReception, TransmitTime};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

const SETTLE_MS: u64 = 1_000;

fn engine(seed: u8, regions: Vec<Region>, threads: usize) -> Engine {
    Engine::new(
        Identity::from_seed([seed; 32]),
        0xb007,
        Settings {
            regions,
            settle_ms: SETTLE_MS,
            threads,
        },
    )
}

/// What `simulation`'s receivers publish: descriptions, then batches.
fn records(simulation: &Simulation) -> Result<(Vec<Record>, Vec<Record>), String> {
    let feeds = simulation.feeds().map_err(text)?;
    let infos = feeds
        .iter()
        .map(|feed| Record::ReceiverInfo(feed.info.clone()))
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

/// (b) The same observations, delivered in any order and any number of times, and solved on one
/// thread or several, sign to the same bytes.
#[test]
fn the_same_raw_signs_the_same_bytes_whatever_the_order_copies_and_threads() -> Result<(), String> {
    let simulation = sim::run(&scenario(5));
    let (infos, batches) = records(&simulation)?;
    let now = after(&simulation);
    let mut first = engine(9, Vec::new(), 1);
    for record in infos.iter().chain(&batches) {
        first.ingest(record, 0)?;
    }
    let mut rng = Rng::new(77);
    let mut second = engine(9, Vec::new(), 4);
    for record in infos.iter().rev() {
        second.ingest(record, 0)?;
    }
    for record in delivered(&batches, &mut rng) {
        second.ingest(record, 0)?;
    }
    let (one, report) = first.step(now, now);
    let (two, _) = second.step(now, now);
    assert!(report.solved >= 100, "{report:?}");
    assert_eq!(report.rejected, 0, "{report:?}");
    assert!(one.iter().any(|r| matches!(r, Record::ClockModel(_))));
    assert!(one.iter().any(|r| matches!(r, Record::Positions(_))));
    assert_eq!(encoded(&one)?, encoded(&two)?);
    // Each window is solved once: the same clock again publishes nothing.
    let (none, _) = first.step(now + 1, now + 1);
    assert!(none.is_empty());
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
            Record::Positions(positions) => {
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
        both.ingest(record, 0)?;
        tiny.ingest(record, 0)?;
    }
    let mut rng = Rng::new(9);
    for record in far_infos.iter().chain(near_infos.iter().rev()) {
        near_only.ingest(record, 0)?;
    }
    let mut mixed: Vec<Record> = near_batches.clone();
    mixed.extend(far_batches.iter().cloned());
    for record in delivered(&mixed, &mut rng) {
        near_only.ingest(record, 0)?;
    }
    let now = after(&near).max(after(&far));
    let (a, report) = both.step(now, now);
    let (b, near_report) = near_only.step(now, now + 7);
    let (c, tiny_report) = tiny.step(now, now);
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
        engine.ingest(record, 0)?;
    }
    let now = after(&simulation);
    let (records, report) = engine.step(now, now);
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
        engine.ingest(record, 0)?;
    }
    let first = simulation
        .receptions
        .iter()
        .map(|r| bin_of(r.wall_ms))
        .min()
        .ok_or("no raw")?;
    let window = Window::canonical(first);
    let due = (window.last + 1) as u64 * GRID_MS + SETTLE_MS;
    let (early, report) = engine.step(due - 1, 0);
    assert!(early.is_empty() && report.windows == 0, "{report:?}");
    let (_, report) = engine.step(due, 0);
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
    let records = pack(&identity, 1, 2, 10, all.clone());
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
