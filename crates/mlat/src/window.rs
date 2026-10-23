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
//!    manifest, the normal case) then its manifest published, then its summary for clients
//!    (`ClientClockModel`: no site, no offset); then the solutions, in as few `Positions` records as
//!    fit, so every record a solution cites arrives before it: raw (format 3) for relays, then the
//!    same solutions tagged (format 5) for clients, each reception its `ReceptionTag` under its
//!    receiver's reception key (`intake::Sited`). The raw forms and the full models are relay-only
//!    (`tally_wire::ClientRecord` refuses them); a client gets the summaries and the tagged forms.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tally_mlat_solver::scope::{Sites, Window, WindowIndex};
use tally_mlat_solver::tile::{self, Tile};
use tally_mlat_solver::{
    Calibrated, ClockModel as Model, SPEC_VERSION, Site, Unpublished, geo, publish,
};
use tally_wire::batch::Hash;
use tally_wire::{
    ClientClockModel, ClockModel, ClockModelContent, Location, Positions, PublicKey, ReceptionKey,
    Record, Regions, Signer, SiteId, SolutionsContent, TaggedSolution, WireError,
};

use crate::intake::Sited;

/// The reception keys of a model's scope, by receiver: what its solutions are tagged under.
pub type Keys = BTreeMap<PublicKey, ReceptionKey>;

/// A step's work, owned.
pub struct Job {
    pub signer: Signer,
    pub boot_id: u64,
    pub issued_ms: u64,
    pub threads: usize,
    /// The H3 cells the engine covers; empty is the whole world.
    pub regions: Regions,
    /// The areas whose tiles it fits (`owns`); empty is every tile `regions` cover.
    pub owned: Regions,
    /// The windows to solve, ascending.
    pub windows: Vec<Window>,
    /// Every receiver taking part, each with its reception key.
    pub sites: Vec<Sited>,
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
    /// Raw positions records (relay-only) and their bytes.
    pub positions: usize,
    pub positions_bytes: usize,
    /// Tagged positions records (what a client is sent) and their bytes; the models' summaries
    /// for clients are one a model (`clock_models`).
    pub tagged_positions: usize,
    pub tagged_positions_bytes: usize,
    /// Solutions published raw that could not be tagged (a scope receiver with no reception key).
    pub untagged: usize,
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

/// The reception keys of `model`'s scope, each the key of the record its site id names: every
/// scope receiver's, or `None` when one is missing (its solutions cannot be tagged).
fn keys_of(model: &Model, keys: &BTreeMap<SiteId, ReceptionKey>) -> Option<Keys> {
    model
        .scope
        .iter()
        .map(|site| keys.get(&site.id).map(|key| (site.receiver, *key)))
        .collect()
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

/// Runs `run` on every item of `work` on up to `threads` threads, each item with a report of its
/// own, and puts the results and reports back in the items' order: the same whatever the threads.
/// The threads pull the items one at a time (`tally_mlat_solver::gate::on_threads`), under the
/// gate of the thread asking, if any: a host's every kind of MLAT work spread over no more threads
/// than its plan gave MLAT, background work letting provisional work in between two items, and a
/// pass ending in about its work over the permits it holds, however few (cut into
/// one fixed share a thread, a pass that held one permit fewer than its threads took twice as
/// long). With one thread the items run here.
pub fn parallel<T: Sync, R: Send, P: Part>(
    threads: usize,
    work: &[T],
    run: impl Fn(&T, &mut P) -> R + Sync,
) -> (Vec<R>, P) {
    let runs: Vec<(R, P)> =
        tally_mlat_solver::gate::on_threads(threads, work.iter().collect(), |item| {
            let mut report = P::default();
            let out = run(item, &mut report);
            (out, report)
        });
    let mut report = P::default();
    let mut out = Vec::with_capacity(work.len());
    for (result, part) in runs {
        report.add(&part);
        out.push(result);
    }
    (out, report)
}

impl Job {
    /// The step's work, signed by the engine's signer: a job exists only for a step the host
    /// took by a watermark read while the relay's clock judged (`tally_relay::mlat_host`'s
    /// `take_published`), and the signer lends its key only while the clock judges still.
    #[allow(
        clippy::disallowed_methods,
        reason = "stepped only by a judging watermark (`MlatHost::take_published`)"
    )]
    pub fn run(self) -> Outcome {
        let started = Instant::now();
        let plain: Vec<Site> = self.sites.iter().map(|sited| sited.site).collect();
        let sites = Sites::new(&plain);
        let keys: BTreeMap<SiteId, ReceptionKey> = self
            .sites
            .iter()
            .map(|sited| (sited.site.id, sited.key))
            .collect();
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
        let mut tagged: Vec<TaggedSolution> = Vec::new();
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
                // A model's signing and encoding is one item of the step.
                tally_mlat_solver::gate::checkpoint();
                let Some(found) = fitted.remove(&tile) else {
                    continue;
                };
                let Ok(signed) = self.signer.sign_with(|identity| {
                    ClockModel::sign(
                        identity,
                        &ClockModelContent {
                            boot_id: self.boot_id,
                            sequence: outcome.models_sequence,
                            issued_ms: self.issued_ms,
                            spec_version: SPEC_VERSION,
                            inputs: found.inputs,
                            model: found.bytes.clone(),
                        },
                    )
                }) else {
                    report.unsolved += list.len();
                    continue;
                };
                let id = signed.manifest.id();
                // What a client is sent of it, numbered with it: a model whose summary cannot be
                // signed is not published, so no client is sent a solution citing a model it
                // cannot hold.
                let Ok(summary) = self.signer.sign_with(|identity| {
                    ClientClockModel::sign(
                        identity,
                        &publish::client_model(
                            &found.model,
                            id,
                            found.inputs,
                            (self.boot_id, outcome.models_sequence, self.issued_ms),
                        ),
                    )
                }) else {
                    report.unsolved += list.len();
                    continue;
                };
                let mut records = signed.records();
                records.push(Record::ClientClockModel(summary));
                report.clock_models += 1;
                report.clock_model_parts += signed.parts.len();
                report.clock_model_bytes += records.iter().map(encoded_len).sum::<usize>();
                outcome.records.extend(records);
                outcome.models_sequence += 1;
                let scope_keys = keys_of(&found.model, &keys);
                for mut solution in list {
                    solution.clock_model = id;
                    let tag = scope_keys.as_ref().and_then(|scope_keys| {
                        solution
                            .tagged(|receiver| scope_keys.get(receiver).copied())
                            .ok()
                    });
                    match tag {
                        Some(one) => tagged.push(one),
                        None => report.untagged += 1,
                    }
                    solutions.push(solution);
                }
                outcome.carried.push(crate::provisional::Carried {
                    tile,
                    window: *window,
                    id,
                    keys: scope_keys.unwrap_or_default(),
                    model: found.model,
                    calibrated: found.calibrated,
                });
            }
        }
        let content = |sequence: u64| (self.boot_id, sequence, self.issued_ms);
        let positions = pack_with(
            outcome.positions_sequence,
            solutions,
            Positions::fitting,
            |sequence, run: &[tally_wire::Solution]| {
                self.signer.sign_with(|identity| {
                    Positions::sign_solutions(identity, &solutions_content(content(sequence), run))
                })
            },
        );
        report.positions = positions.len();
        report.positions_bytes = bytes_of(&positions);
        outcome.positions_sequence += positions.len() as u64;
        // The same solutions tagged, numbered after the raw records in the one positions sequence.
        let tagged = pack_with(
            outcome.positions_sequence,
            tagged,
            Positions::fitting_tagged,
            |sequence, run: &[TaggedSolution]| {
                self.signer.sign_with(|identity| {
                    Positions::sign_tagged(identity, &solutions_content(content(sequence), run))
                })
            },
        );
        report.tagged_positions = tagged.len();
        report.tagged_positions_bytes = bytes_of(&tagged);
        outcome.positions_sequence += tagged.len() as u64;
        outcome
            .records
            .extend(positions.into_iter().chain(tagged).map(Record::Positions));
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

/// The content of one positions record of `run`, numbered `(boot_id, sequence, issued_ms)`, under
/// this specification.
pub fn solutions_content<O: Clone>(
    (boot_id, sequence, issued_ms): (u64, u64, u64),
    run: &[tally_wire::Solution<O>],
) -> SolutionsContent<O> {
    SolutionsContent {
        boot_id,
        sequence,
        issued_ms,
        spec_version: SPEC_VERSION,
        solutions: run.to_vec(),
    }
}

/// The records' bytes on the wire, headers included.
fn bytes_of(records: &[Positions]) -> usize {
    records
        .iter()
        .map(|record| {
            tally_mlat_solver::gate::checkpoint();
            encoded_len(&Record::Positions(record.clone()))
        })
        .sum()
}

/// Signs `solutions` (raw or tagged) into as few `Positions` records as hold them, in order,
/// numbered from `sequence`, each signed by `sign` (final or provisional): each record takes the
/// longest run that signs within the wire's size limit, measured by `fitting`
/// (`Positions::fitting` or `Positions::fitting_tagged`).
pub fn pack_with<S>(
    mut sequence: u64,
    solutions: Vec<S>,
    fitting: impl Fn(&[S]) -> usize,
    sign: impl Fn(u64, &[S]) -> Result<Positions, WireError>,
) -> Vec<Positions> {
    let mut records = Vec::new();
    let mut rest = solutions.as_slice();
    while !rest.is_empty() {
        // The longest prefix one record holds, measured (`fitting`), signed once. Only
        // when that prefix is refused for a solution's content is it searched below, between none
        // and the length refused. Before, every record was found by signing ever shorter prefixes
        // of all that was left, from the whole: a window step of 80,000 solutions spent two
        // minutes of one thread here, and its provisional steps were shed for want of its models
        //.
        let mut take = fitting(rest);
        let (mut fits, mut fails) = (0, take + 1);
        let mut signed = None;
        while fits + 1 < fails {
            // Each signing is one item: on a gate of one permit a provisional step waits for one
            // at most, never the whole packing.
            tally_mlat_solver::gate::checkpoint();
            match sign(sequence, &rest[..take]) {
                Ok(record) => {
                    fits = take;
                    signed = Some(record);
                }
                Err(WireError::Oversize(_)) => fails = take,
                // Its signer's clock is not judging: nothing more is signed.
                Err(WireError::Unsynced) => return records,
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
