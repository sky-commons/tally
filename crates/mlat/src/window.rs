//! One step (RFC-0171 §3.8.1): every window due, in two pure phases, so the same raw signs to the
//! same bytes whatever order it was delivered in, whichever engine holds it, and however many
//! threads run it.
//!
//! 1. Per window, its sealed bins are assembled (`WindowIndex`, no copy) and its targets
//!    assigned their tiles (`WindowIndex::plan`). A tile is fitted only when the engine's regions
//!    cover its whole footprint (`covers`): only then does the engine hold every receiver the
//!    tile's members are chosen from, so two engines that both cover it fit the same model.
//! 2. Phase one: the distinct tiles the window's targets chose are fitted, in parallel, each once:
//!    one fit and its calibration at the published estimate (`fit_calibrated`). The engine does
//!    not run the model verifier on its own model: anyone else does (`verify_model`).
//! 3. Phase two: every target assigned a fitted tile is solved, in parallel: its scope's
//!    receptions grouped under the tile's model, at most `TRANSMISSIONS_PER_BIN` transmissions a
//!    bin by rank (`scope::chosen`), each solved, carried to the wire's form, read back as a claim
//!    and verified as any checker would (`publish::solve_published`, every one); one that fails is
//!    dropped and counted.
//! 4. In order: each tile model with a solution is signed, its parts (none when it fits its
//!    manifest, the normal case) then its manifest published; then the solutions, in as few
//!    `Positions` records as fit, so every record a solution cites arrives before it.

use std::time::{Duration, Instant};

use tally_mlat_solver::scope::{Sites, Window, WindowIndex};
use tally_mlat_solver::tile::{self, Tile};
use tally_mlat_solver::{
    Calibrated, ClockModel as Model, SPEC_VERSION, Site, Unpublished, geo, publish,
};
use tally_wire::batch::Hash;
use tally_wire::{
    ClockModel, ClockModelContent, Identity, Location, Positions, Record, Regions,
    SolutionsContent, WireError,
};

/// A step's work, owned.
pub struct Job {
    pub identity: Identity,
    pub boot_id: u64,
    pub issued_ms: u64,
    pub threads: usize,
    /// The H3 cells the engine covers; empty is the whole world.
    pub regions: Regions,
    /// The areas whose tiles it fits (`owns`); empty is every tile `regions` cover.
    pub owned: Regions,
    /// The windows to solve, ascending.
    pub windows: Vec<Window>,
    /// Every receiver taking part.
    pub sites: Vec<Site>,
    /// Every sealed bin any of the windows spans.
    pub bins: Vec<std::sync::Arc<tally_mlat_solver::held::Bin>>,
    pub positions_sequence: u64,
    pub models_sequence: u64,
}

/// What a step did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub windows: usize,
    /// Bins solved.
    pub bins: usize,
    /// Targets assigned a tile.
    pub targets: usize,
    /// Distinct tiles the targets chose.
    pub tiles: usize,
    /// Of those, the ones whose footprint the engine's regions do not wholly cover: not fitted.
    pub uncovered: usize,
    /// Fits run: one per covered tile chosen, never more.
    pub fits: usize,
    /// Tiles with no model: why, the first time it happened.
    pub unfitted: usize,
    pub unfitted_reason: Option<String>,
    /// Clocks the fits dropped as cut off from their gauge by robust weights
    /// (`FitError::Disconnected`): fitted around, not failed, so apart from `unfitted`.
    pub disconnected: usize,
    /// Transmissions chosen for solving.
    pub transmissions: usize,
    pub solved: usize,
    pub unsolved: usize,
    /// Solutions the verifier refused as published (and were dropped).
    pub rejected: usize,
    pub clock_models: usize,
    /// Parts of the clock models too large for their manifests.
    pub clock_model_parts: usize,
    pub clock_model_bytes: usize,
    pub positions: usize,
    pub positions_bytes: usize,
    /// Time spent fitting, over every thread.
    pub fit_time: Duration,
    /// Time spent solving, over every thread.
    pub solve_time: Duration,
    /// Time the step took.
    pub elapsed: Duration,
}

/// What one thread's share of a step reports, and how two shares add up.
pub trait Part: Default + Send {
    fn add(&mut self, other: &Self);
}

impl Part for Report {
    fn add(&mut self, other: &Report) {
        self.unfitted += other.unfitted;
        if self.unfitted_reason.is_none() {
            self.unfitted_reason = other.unfitted_reason.clone();
        }
        self.disconnected += other.disconnected;
        self.transmissions += other.transmissions;
        self.solved += other.solved;
        self.unsolved += other.unsolved;
        self.rejected += other.rejected;
        self.fit_time += other.fit_time;
        self.solve_time += other.solve_time;
    }
}

/// A finished step.
pub struct Outcome {
    pub windows: Vec<Window>,
    pub records: Vec<Record>,
    /// Every model published, for provisional solutions to carry (`crate::provisional`).
    pub carried: Vec<crate::provisional::Carried>,
    pub positions_sequence: u64,
    pub models_sequence: u64,
    pub report: Report,
}

/// Whether the engine's regions cover a tile's whole footprint: every point of the ground disc of
/// the footprint's radius about the centre, on rings 20 km apart every 10 degrees (a region is
/// an H3 cell, tens of kilometres across at the resolutions engines are given), is in a region.
/// Empty regions are the whole world.
pub fn covers(regions: &Regions, tile: Tile) -> bool {
    if regions.is_empty() {
        return true;
    }
    let centre = geo::from_ecef(geo::from_mm(tile.centre_mm()));
    let radius_m = tile::footprint_mm(tile.level) as f64 / 1000.0;
    let basis = geo::enu_basis(centre.lat_deg, centre.lon_deg);
    let ground = geo::to_ecef(geo::Geodetic {
        height_m: 0.0,
        ..centre
    });
    let inside = |point: [f64; 3]| {
        let at = geo::from_ecef(point);
        let location = Location {
            lat_e7: (at.lat_deg * 1e7).round() as i32,
            lon_e7: (at.lon_deg * 1e7).round() as i32,
            alt_m: 0,
            precision_m: 0,
        };
        regions.covers(&location)
    };
    if !inside(ground) {
        return false;
    }
    let mut ring = 20_000.0;
    while ring <= radius_m + 20_000.0 {
        let ring_m = ring.min(radius_m);
        for step in 0..36 {
            let bearing = f64::from(step) * std::f64::consts::TAU / 36.0;
            let offset = [0, 1, 2].map(|axis| {
                basis[0][axis] * ring_m * libm::sin(bearing)
                    + basis[1][axis] * ring_m * libm::cos(bearing)
            });
            if !inside([
                ground[0] + offset[0],
                ground[1] + offset[1],
                ground[2] + offset[2],
            ]) {
                return false;
            }
        }
        ring += 20_000.0;
    }
    true
}

/// Whether a tile is one of `owned`'s: its centre, on the ground, is in one of them (RFC-0174
/// §2.3: each tile is fitted by the MLAT relays of the area its centre is in, so an area's k relays
/// fit its tiles and no others, however wide the band of raw they hold). Empty owns every tile.
pub fn owns(owned: &Regions, tile: Tile) -> bool {
    if owned.is_empty() {
        return true;
    }
    let location = crate::area::centre(tile);
    owned.covers(&location)
}

/// A tile fitted: its model's encoding and inputs hash, and the model and calibration solving
/// under it needs.
struct Fitted {
    tile: Tile,
    bytes: Vec<u8>,
    inputs: Hash,
    model: Model,
    calibrated: Calibrated,
}

/// One window's solutions, citing no model yet: by the tile that solved them.
type Solved = Vec<(Tile, tally_wire::Solution)>;

/// Phase one for one tile.
fn fit_one(
    index: &WindowIndex<'_>,
    tile: Tile,
    members: &[tally_wire::PublicKey],
    report: &mut Report,
) -> Option<Fitted> {
    let inputs = index.inputs(tile, members)?;
    let started = Instant::now();
    let fitted = tally_mlat_solver::fit_calibrated(&inputs);
    report.fit_time += started.elapsed();
    let (model, calibrated) = match fitted {
        Ok(fitted) => fitted,
        Err(error) => {
            report.unfitted += 1;
            report
                .unfitted_reason
                .get_or_insert_with(|| error.to_string());
            return None;
        }
    };
    report.disconnected += calibrated.disconnected;
    let bytes = publish::encode(&model).ok()?;
    Some(Fitted {
        tile,
        inputs: publish::inputs_id(&model),
        bytes,
        model,
        calibrated,
    })
}

/// Phase two for one target.
fn solve_one(
    index: &WindowIndex<'_>,
    address: u32,
    assignment: &tally_mlat_solver::Assignment,
    fitted: &Fitted,
    report: &mut Report,
) -> Vec<tally_wire::Solution> {
    let started = Instant::now();
    let receptions = index.receptions(address, &assignment.scope);
    let addressed = index.addressed_citation(address);
    let grouping = tally_mlat_solver::group(&fitted.model, &receptions);
    let mut out = Vec::new();
    for transmission in tally_mlat_solver::scope::chosen(&index.window, grouping.transmissions) {
        report.transmissions += 1;
        match publish::solve_published(&fitted.calibrated, &transmission, [0; 32], addressed) {
            Ok((_, wire)) => {
                report.solved += 1;
                out.push(wire);
            }
            Err(Unpublished::Refuted(_)) => report.rejected += 1,
            Err(_) => report.unsolved += 1,
        }
    }
    report.solve_time += started.elapsed();
    out
}

/// Runs `work` over `threads` contiguous runs, each with its own report, and puts the results
/// back in order: the same whatever the cut. The runs go on threads under the gate of the thread
/// asking, if any (`tally_mlat_solver::gate`): a host's every kind of MLAT work spread over no more
/// threads than its plan gave MLAT, background work letting provisional work in between two items.
/// One run is done here, on no thread of its own.
pub fn parallel<T: Sync, R: Send, P: Part>(
    threads: usize,
    work: &[T],
    run: impl Fn(&T, &mut P) -> R + Sync,
) -> (Vec<R>, P) {
    let threads = threads.clamp(1, work.len().max(1));
    let size = work.len().div_ceil(threads).max(1);
    let chunks: Vec<&[T]> = work.chunks(size).collect();
    let runs: Vec<(Vec<R>, P)> = tally_mlat_solver::gate::on_threads(chunks, |chunk| {
        let mut report = P::default();
        let out = chunk
            .iter()
            .map(|item| {
                tally_mlat_solver::gate::checkpoint();
                run(item, &mut report)
            })
            .collect();
        (out, report)
    });
    let mut report = P::default();
    let mut out = Vec::with_capacity(work.len());
    for (results, part) in runs {
        report.add(&part);
        out.extend(results);
    }
    (out, report)
}

impl Job {
    pub fn run(self) -> Outcome {
        let started = Instant::now();
        let sites = Sites::new(&self.sites);
        let mut report = Report {
            windows: self.windows.len(),
            ..Report::default()
        };
        let mut outcome = Outcome {
            windows: self.windows.clone(),
            records: Vec::new(),
            carried: Vec::new(),
            positions_sequence: self.positions_sequence,
            models_sequence: self.models_sequence,
            report: Report::default(),
        };
        let mut solutions: Vec<tally_wire::Solution> = Vec::new();
        for window in &self.windows {
            report.bins += window.solved().count();
            let index = WindowIndex::new(*window, &self.bins, &sites);
            let plan = index.plan_on(self.threads);
            report.targets += plan.assignments.len();
            let chosen = plan.tiles();
            let count = chosen.len();
            let tiles: Vec<Tile> = chosen
                .into_iter()
                .filter(|tile| covers(&self.regions, *tile) && owns(&self.owned, *tile))
                .collect();
            report.tiles += count;
            report.uncovered += count - tiles.len();
            report.fits += tiles.len();
            // Phase one: every distinct tile once.
            let (fitted, part) = parallel(self.threads, &tiles, |tile, report| {
                fit_one(&index, *tile, &plan.members[tile], report)
            });
            report.add(&part);
            let mut fitted: std::collections::BTreeMap<Tile, Fitted> = fitted
                .into_iter()
                .flatten()
                .map(|fitted| (fitted.tile, fitted))
                .collect();
            // Phase two: every target under its fitted tile.
            let work: Vec<(u32, &tally_mlat_solver::Assignment)> = plan
                .assignments
                .iter()
                .filter(|(_, assignment)| fitted.contains_key(&assignment.tile))
                .map(|(address, assignment)| (*address, assignment))
                .collect();
            let (solved, part) = parallel(self.threads, &work, |(address, assignment), report| {
                let tile = assignment.tile;
                let found = &fitted[&tile];
                solve_one(&index, *address, assignment, found, report)
                    .into_iter()
                    .map(|solution| (tile, solution))
                    .collect::<Solved>()
            });
            report.add(&part);
            let mut by_tile: std::collections::BTreeMap<Tile, Vec<tally_wire::Solution>> =
                std::collections::BTreeMap::new();
            for (tile, solution) in solved.into_iter().flatten() {
                by_tile.entry(tile).or_default().push(solution);
            }
            // In tile order: each model with a solution, then its solutions citing it.
            for (tile, list) in by_tile {
                let Some(found) = fitted.remove(&tile) else {
                    continue;
                };
                let Ok(signed) = ClockModel::sign(
                    &self.identity,
                    &ClockModelContent {
                        boot_id: self.boot_id,
                        sequence: outcome.models_sequence,
                        issued_ms: self.issued_ms,
                        spec_version: SPEC_VERSION,
                        inputs: found.inputs,
                        model: found.bytes.clone(),
                    },
                ) else {
                    report.unsolved += list.len();
                    continue;
                };
                let id = signed.manifest.id();
                let records = signed.records();
                report.clock_models += 1;
                report.clock_model_parts += signed.parts.len();
                report.clock_model_bytes += records.iter().map(encoded_len).sum::<usize>();
                outcome.records.extend(records);
                outcome.models_sequence += 1;
                outcome.carried.push(crate::provisional::Carried {
                    tile,
                    window: *window,
                    id,
                    model: found.model,
                    calibrated: found.calibrated,
                });
                solutions.extend(list.into_iter().map(|mut solution| {
                    solution.clock_model = id;
                    solution
                }));
            }
        }
        let positions = pack(
            &self.identity,
            self.boot_id,
            self.issued_ms,
            outcome.positions_sequence,
            solutions,
        );
        report.positions = positions.len();
        report.positions_bytes = positions
            .iter()
            .map(|record| encoded_len(&Record::Positions(record.clone())))
            .sum();
        outcome.positions_sequence += positions.len() as u64;
        outcome
            .records
            .extend(positions.into_iter().map(Record::Positions));
        report.elapsed = started.elapsed();
        outcome.report = report;
        outcome
    }
}

/// A record's bytes on the wire, header included.
fn encoded_len(record: &Record) -> usize {
    let mut bytes = Vec::new();
    record.encode(&mut bytes).map_or(0, |()| bytes.len())
}

/// Signs `solutions` into as few `Positions` records as hold them, in order: each record takes the
/// longest run that signs within the wire's size limit.
fn pack(
    identity: &Identity,
    boot_id: u64,
    issued_ms: u64,
    sequence: u64,
    solutions: Vec<tally_wire::Solution>,
) -> Vec<Positions> {
    pack_with(
        sequence,
        solutions,
        |sequence, run: &[tally_wire::Solution]| {
            Positions::sign_solutions(
                identity,
                &SolutionsContent {
                    boot_id,
                    sequence,
                    issued_ms,
                    spec_version: SPEC_VERSION,
                    solutions: run.to_vec(),
                },
            )
        },
    )
}

/// As `pack`, each record signed by `sign` (final or provisional), numbered from `sequence`.
pub fn pack_with(
    mut sequence: u64,
    solutions: Vec<tally_wire::Solution>,
    sign: impl Fn(u64, &[tally_wire::Solution]) -> Result<Positions, WireError>,
) -> Vec<Positions> {
    let mut records = Vec::new();
    let mut rest = solutions.as_slice();
    while !rest.is_empty() {
        // The longest prefix that fits: all of it, else a binary search between one (which
        // always fits: a solution is at most a few kilobytes) and the first length that did not.
        let (mut fits, mut fails) = (0, rest.len() + 1);
        let mut signed = None;
        let mut take = rest.len();
        while fits + 1 < fails {
            match sign(sequence, &rest[..take]) {
                Ok(record) => {
                    fits = take;
                    signed = Some(record);
                }
                Err(WireError::Oversize(_)) => fails = take,
                // A solution the wire refuses outright: leave it out.
                Err(_) if take == 1 => break,
                Err(_) => fails = take,
            }
            take = (fits + fails) / 2;
        }
        let Some(record) = signed.filter(|_| fits > 0) else {
            rest = &rest[1..];
            continue;
        };
        records.push(record);
        sequence += 1;
        rest = &rest[fits..];
    }
    records
}

#[cfg(test)]
#[path = "window_tests.rs"]
mod tests;
