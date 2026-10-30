//! The pairwise path (`pair`, crate docs § The pairwise path, § Areas) as an engine runs it: every
//! `REFIT_EVERY_MS` each area's pair model is fitted over its members' window
//! (`Arrived::area_inputs_over`), warm from the area's last, encoded and verified by a holder of
//! the window (`verify::verify_pair_model_held`); every step each due set is grouped under the
//! models of the areas its hearers are in (`publish::transmissions`), one transmission an aircraft
//! a slot chosen (`backoff`, as an engine chooses, its complete fix again as its set closes
//! bigger), and each chosen solved and published citing the models of its used hearers' areas
//! (`publish::solve_transmission`); and every `PAIR_VERIFY_EVERY`th fix is verified cold, from the
//! verified models it lists and its own receptions alone, and under models that are not one of each
//! of its used hearers' areas, which must refuse it. Coverage, horizontal error, and each part's
//! cost a feeder-second, for every fix and apart for fixes whose used hearers span areas.

use super::*;
use crate::pair::{self, Models, Network, PairCache, PairModel, Prepared};
use tally_wire::Region;

fn env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// One fix as the engine measured it: horizontal error, covered, squared Mahalanobis distance,
/// whether its used hearers span areas, and how many it used.
type Measured = (f64, bool, f64, bool, usize);

/// The fixes of the two classes the boundary is measured by: inside one area, and straddling.
const CLASSES: [&str; 2] = ["inside one area", "straddling areas"];

/// The engine's fixes and costs over a scenario list.
#[derive(Default)]
struct Path {
    /// By transmission.
    fixes: BTreeMap<(u64, usize), Measured>,
    /// By hearers used: the timing check's (`timing_check`) distances under the fix's own
    /// covariance, under its clock part with the true jitter, degrees of freedom, fixes, and read
    /// without jitter.
    timing: BTreeMap<usize, (f64, f64, usize, usize, f64)>,
    sync_ns: u128,
    /// Every fix whole (`publish::transmissions` and `publish::solve_transmission`: grouping,
    /// capping, normalising, solving and the engine's own check of what it publishes), and of it,
    /// normalising a published fix once.
    solve_ns: u128,
    normalise_ns: u128,
    /// The cold verifier of a fix: from the verified model and the fix's receptions.
    verify_ns: u128,
    /// A holder of the window verifying each model once a refit, and each model's cost by its id;
    /// and the models a published fix cites, which are all a verifier that judges a model only
    /// when a fix it publishes or judges cites it verifies (`Engine::step`).
    model_verify_ns: u128,
    model_ns: BTreeMap<[u8; 32], u128>,
    cited_models: BTreeSet<[u8; 32]>,
    /// Each model's area, and the neighbours' models the fixes each area owns cite (the owner: the
    /// area most of the fix's hearers are in, ties to the lowest, `tally_mlat::area::owner`).
    model_area: BTreeMap<[u8; 32], Region>,
    owned_cites: BTreeSet<(Region, [u8; 32])>,
    /// What an area's relay verifies of its band's models (the models of every other area its
    /// members are in): all of them, or only those its own fixes cite; over every area.
    band_ns: [u128; 2],
    band_models: [usize; 2],
    /// Decoding a model and preparing it for fixes, once a refit.
    prepare_ns: u128,
    model_bytes: usize,
    model_clocks: usize,
    models: usize,
    models_refused: usize,
    model_failures: BTreeMap<String, usize>,
    /// Areas with receivers, summed over scenarios.
    areas: usize,
    /// Members of each model, summed: against the receivers, the overlap.
    members: usize,
    receivers: usize,
    /// The transmissions grouped, by the class of their hearers' areas; and why one of each class
    /// was not published (`publish::Unpublished`).
    groups: [usize; 2],
    unpublished: [BTreeMap<String, usize>; 2],
    /// Fixes published citing fewer models than they were first solved by: their used hearers
    /// are of fewer areas than their hearers.
    narrowed: usize,
    /// Considered sets of whose hearers' areas a model was not held.
    unmodelled: usize,
    /// By class, the network's pairs among published fixes' used hearers, and of them those the
    /// fix's models hold.
    hearer_pairs: [usize; 2],
    held_pairs: [usize; 2],
    /// By class, the areas the used hearers span, summed; and the fixes.
    spanned: [usize; 2],
    published: [usize; 2],
    verified: usize,
    /// Of the verified, how many passed, and why the others did not.
    passed: usize,
    fix_failures: BTreeMap<String, usize>,
    /// Sampled fixes verified under models not one of each of their used hearers' areas, and of
    /// them refused.
    wrong_area: usize,
    wrong_area_refused: usize,
    feeder_s: f64,
    /// Transmissions of the due sets, and of them those never solved: another of their slot was
    /// chosen (`backoff`).
    transmissions: usize,
    backed_off: usize,
    refits: usize,
    passes: usize,
    failures: BTreeMap<String, usize>,
    bridges: usize,
    rejected: usize,
    inflated: usize,
    dropped: usize,
    stats: Vec<pair::Stats>,
    /// Refits whose model gives the scenario's jumping receiver a jump, and that give any other
    /// clock one.
    jumped: usize,
    false_jumps: usize,
    /// From the first fix published on, the receptions the pool kept, the fixes published and the
    /// receptions they considered: what the relay's tables sized by the fixes are planned per kept
    /// reception from (`backoff::Published::MEASURED`).
    kept: usize,
    /// The sets due (each again as it closes bigger), and of them the transmissions solved
    /// (published or not) and the fixes published.
    due: usize,
    attempted: usize,
    considered: usize,
    counted: usize,
    /// Feeder-seconds from the first fix published to the last arrival.
    counted_s: f64,
}

impl Path {
    /// What it solved and published a thousand feeder-seconds from the first fix published on,
    /// each rounded up: what `backoff::Published::MEASURED` is.
    fn rates(&self) -> crate::backoff::Published {
        let per_ks = |n: usize| (n as f64 * 1_000.0 / self.counted_s.max(1.0)).ceil() as usize;
        crate::backoff::Published {
            due_per_ks: per_ks(self.due),
            solved_per_ks: per_ks(self.attempted),
            published_per_ks: per_ks(self.counted),
            considered_per_ks: per_ks(self.considered),
        }
    }
}

fn quantile(values: &[f64], at: f64) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    values[((values.len() - 1) as f64 * at).round() as usize]
}

/// A failure's kind: its name without its fields.
fn kind(failure: &impl std::fmt::Debug) -> String {
    let name = format!("{failure:?}");
    name.split(['(', ' ', '{']).next().unwrap_or("").to_owned()
}

impl Path {
    fn line(&self, name: &str, class: Option<bool>) -> String {
        let mut errors: Vec<f64> = Vec::new();
        let mut distances: Vec<f64> = Vec::new();
        let mut covered = 0usize;
        for (error, inside, distance, straddles, _) in self.fixes.values() {
            if class.is_some_and(|class| class != *straddles) {
                continue;
            }
            errors.push(*error);
            distances.push(*distance);
            covered += usize::from(*inside);
        }
        errors.sort_by(f64::total_cmp);
        distances.sort_by(f64::total_cmp);
        let per = |ns: u128| ns as f64 / 1e6 / self.feeder_s.max(1.0);
        format!(
            "PAIR {name}{}: {} fixes, coverage {:.4} (d² p50 {:.2}, p95 {:.1}), horizontal p50 {:.1} m p95 {:.1} m; \
             ms a feeder-second: sync {:.3}, fixes {:.3} (normalising once {:.3}), all-in {:.3}; \
             a holder of the window verifying each model {:.3} ms a feeder-second, only the {} of {} \
             a published fix cites {:.3}; each area's relay verifying its band's models {:.3} ({} \
             models), only those its fixes cite {:.3} ({}); \
             a cold fix verifier {:.3} ms a fix over {} ({} passed); decode and prepare {:.3} ms a model; \
             model {:.0} bytes a clock",
            class.map_or(String::new(), |class| format!(
                " ({})",
                CLASSES[usize::from(class)]
            )),
            errors.len(),
            covered as f64 / errors.len().max(1) as f64,
            quantile(&distances, 0.5),
            quantile(&distances, 0.95),
            quantile(&errors, 0.5),
            quantile(&errors, 0.95),
            per(self.sync_ns),
            per(self.solve_ns),
            per(self.normalise_ns),
            per(self.sync_ns + self.solve_ns),
            per(self.model_verify_ns),
            self.cited_models.len(),
            self.model_ns.len(),
            per(self
                .cited_models
                .iter()
                .filter_map(|id| self.model_ns.get(id))
                .sum()),
            per(self.band_ns[0]),
            self.band_models[0],
            per(self.band_ns[1]),
            self.band_models[1],
            self.verify_ns as f64 / 1e6 / self.verified.max(1) as f64,
            self.verified,
            self.passed,
            self.prepare_ns as f64 / 1e6 / self.models.max(1) as f64,
            self.model_bytes as f64 / self.model_clocks.max(1) as f64,
        )
    }
}

/// A normalised fix's timing against the truth: each reception's arrival after the first item's,
/// as normalised less as it truly was, its squared Mahalanobis distance under the fix's own
/// timing covariance (clock and noise), and under the clock part plus each receiver's true jitter;
/// and read without jitter under the clock part; and the degrees of freedom.
fn timing_check(
    models: &Models<'_>,
    group: &[Reception],
    normalised: &crate::pair::Normalised,
    simulation: &Simulation,
    truth: &BTreeMap<ObservationId, usize>,
) -> Option<(f64, f64, f64, usize)> {
    let problem = &normalised.problem;
    let n = problem.items.len();
    if n < 3 {
        return None;
    }
    let source = *truth.get(&problem.items[0].id)?;
    let sent = &simulation.transmissions[source];
    let arrival = |item: &crate::solve::Item| -> Option<f64> {
        let receiver = simulation.receiver(&item.id.receiver)?;
        Some(sent.time + linalg::norm(linalg::sub(sent.ecef, receiver.ecef)) / geo::C)
    };
    let quantum_of = |item: &crate::solve::Item| -> Option<f64> {
        let receiver = simulation.receiver(&item.id.receiver)?;
        Some(match receiver.truth.timebase {
            crate::Timebase::Mhz12 => 1.0 / 12e6,
            crate::Timebase::GpsNanos => 1e-9,
        })
    };
    let distance_of =
        |problem: &crate::solve::Problem, diagonal: &dyn Fn(usize) -> Option<f64>| -> Option<f64> {
            let first = arrival(&problem.items[0])?;
            let mut error = Vec::with_capacity(n - 1);
            for item in &problem.items[1..] {
                let estimated = (item.time.ps - problem.items[0].time.ps) as f64 * 1e-12;
                error.push((estimated - (arrival(item)? - first)) * geo::C);
            }
            let clock = problem.clock_m2.as_ref()?;
            let d0 = diagonal(0)?;
            let mut covariance = Matrix::zeros(n - 1);
            for i in 1..n {
                for j in 1..n {
                    let mut value = clock[i][j] - clock[i][0] - clock[0][j] + clock[0][0] + d0;
                    if i == j {
                        value += diagonal(i)?;
                    }
                    covariance.set(i - 1, j - 1, value);
                }
            }
            distance(&error, &covariance)
        };
    let own = distance_of(problem, &|i| Some(problem.items[i].noise_m2))?;
    let jitter = distance_of(problem, &|i| {
        let item = &problem.items[i];
        let s = simulation.receiver(&item.id.receiver)?.truth.jitter_s;
        let q = quantum_of(item)?;
        Some((s * s + q * q / 12.0) * geo::C * geo::C)
    })?;
    // The same receptions read without jitter: what is left is the clock part and the counter's
    // quantum.
    let clean: Vec<Reception> = group
        .iter()
        .filter_map(|reception| {
            let receiver = simulation.receiver(&reception.receiver)?;
            let at = truth.get(&reception.id())?;
            let sent = &simulation.transmissions[*at];
            let arrival = sent.time + linalg::norm(linalg::sub(sent.ecef, receiver.ecef)) / geo::C;
            let mut clean = reception.clone();
            clean.timestamp = receiver
                .truth
                .counter(arrival, simulation.scenario.start_tod_s, 0.0);
            Some(clean)
        })
        .collect();
    let again = models.normalise(&clean).ok()?;
    if again.problem.items.len() != n {
        return None;
    }
    let clean = distance_of(&again.problem, &|i| {
        let q = quantum_of(&again.problem.items[i])?;
        Some(q * q / 12.0 * geo::C * geo::C)
    })?;
    Some((own, jitter, clean, n - 1))
}

/// One fix the engine published.
struct Fixed {
    /// The areas whose models it was solved under and cites: its used hearers'.
    areas: Vec<Region>,
    wire: tally_wire::Fix,
    /// What it considered: the transmission's receptions as the model regrouped them.
    group: Vec<Reception>,
    solution: Solution,
}

/// What a run of the engine published, when asked to keep it: each verified model's bytes by
/// (area, edge), and each fix.
#[derive(Default)]
struct Ran {
    models: BTreeMap<(Region, u64), Vec<u8>>,
    fixes: Vec<Fixed>,
}

/// How a run is measured: every `verify_every`th fix verified cold, and whether what it published
/// is kept.
#[derive(Clone, Copy)]
struct Options {
    verify_every: usize,
    keep: bool,
    /// Every pair of every refit fitted from the closed-form start, not its previous knots (the
    /// previous model's noise and rates still where the fixed point is sought from).
    cold: bool,
}

/// The engine over one scenario with `sites` (the simulation's, or edited), into `path`.
fn areas(
    scenario: &Scenario,
    simulation: &Simulation,
    site_list: &[crate::Site],
    arrivals: &[Arrival],
    options: Options,
    path: &mut Path,
) -> Result<Ran> {
    let truth = truth_of(simulation);
    let sites = Sites::new(site_list);
    let network = sites.network().clone();
    let jumper = scenario
        .jumps
        .first()
        .map(|(index, _, _)| simulation.receivers[*index].key);
    let bad: BTreeSet<tally_wire::PublicKey> = scenario
        .bad
        .iter()
        .map(|index| simulation.receivers[*index].key)
        .collect();
    let mut arrived = Arrived::new(Limits {
        held_ms: HELD_MS,
        ..Limits::UNBOUNDED
    });
    let mut caches: BTreeMap<Region, PairCache> = BTreeMap::new();
    let mut verifiers: BTreeMap<Region, PairCache> = BTreeMap::new();
    let mut current: BTreeMap<Region, Arc<Prepared>> = BTreeMap::new();
    // Which transmissions are solved, as an engine chooses them (`backoff`): one an aircraft a
    // slot, its complete fix once its raw has come (`Considered::come_ms`) or as its set closes,
    // bigger, once (`tally_mlat`'s `fix::again`); and the receptions of each solved, by the number
    // of receptions it was solved from, so a later set of it is known, and whether it was solved
    // again.
    let mut slots: crate::backoff::Slots<Work> = crate::backoff::Slots::default();
    let mut chosen: BTreeMap<ObservationId, usize> = BTreeMap::new();
    let mut solved_from: Vec<usize> = Vec::new();
    let mut again: Vec<bool> = Vec::new();
    let mut ran = Ran::default();
    let mut first_of: BTreeMap<crate::arrived::BatchId, u64> = BTreeMap::new();
    for arrival in arrivals {
        let at = first_of.entry(arrival.batch).or_insert(arrival.at_ms);
        *at = (*at).min(arrival.at_ms);
    }
    let (Some(first), Some(last)) = (arrivals.first(), first_of.values().max()) else {
        return Err("no arrivals".into());
    };
    path.feeder_s += scenario.duration_s * scenario.receivers as f64;
    path.areas += sites.areas().count();
    path.receivers += sites.len();
    let mut latest: BTreeMap<usize, Measured> = BTreeMap::new();
    let mut next = 0;
    let mut solved = 0usize;
    // When the first fix was published: the rates are counted from it.
    let mut counting_from: Option<u64> = None;
    let mut now = first.at_ms.next_multiple_of(STEP_MS);
    while now <= last + SETTLE_MS + 2 * STEP_MS {
        while let Some(arrival) = arrivals.get(next).filter(|arrival| arrival.at_ms <= now) {
            let kept = arrived
                .admit(arrival.batch, arrival.at_ms, &arrival.receptions)
                .kept as usize;
            // Counted from the first fix published: the rates of the steady state, not of the
            // trailing window filling before any model is fitted.
            if counting_from.is_some() {
                path.kept += kept;
            }
            next += 1;
        }
        arrived.seal(now);
        if now.is_multiple_of(REFIT_EVERY_MS) {
            let trailing = Trailing {
                span_ms: TRAILING_WINDOW_MS as u32,
                ..Trailing::fitted_at(now)
            };
            let owned: Vec<Region> = sites.areas().map(|(area, _)| *area).collect();
            for area in owned {
                let started = Instant::now();
                let Some(inputs) = arrived.area_inputs_over(area, &sites, trailing) else {
                    continue;
                };
                // Cold: the previous noise and rates, and no pair's knots to start from.
                let knotless =
                    current
                        .get(&area)
                        .filter(|_| options.cold)
                        .map(|prepared| PairModel {
                            pairs: Vec::new(),
                            ..prepared.model.clone()
                        });
                let fitted = pair::fit(
                    &inputs,
                    knotless
                        .as_ref()
                        .or(current.get(&area).map(|prepared| &prepared.model)),
                    caches.entry(area).or_default(),
                );
                path.sync_ns += started.elapsed().as_nanos();
                path.refits += 1;
                let fitted = match fitted {
                    Ok(fitted) => fitted,
                    Err(why) => {
                        *path.failures.entry(format!("refit {why}")).or_default() += 1;
                        continue;
                    }
                };
                path.stats.push(fitted.stats);
                path.passes += fitted.stats.passes;
                let model = fitted.model;
                let bytes = publish::encode_pairs(&model).map_err(text)?;
                let id = publish::pair_model_id(&bytes);
                // A holder of the window verifies the model once, from its own sites and raw.
                let started = Instant::now();
                let verdict = crate::verify::verify_pair_model_held(
                    &sites,
                    &model,
                    &arrived,
                    verifiers.entry(area).or_default(),
                );
                path.model_verify_ns += started.elapsed().as_nanos();
                path.model_ns.insert(id, started.elapsed().as_nanos());
                path.model_area.insert(id, area);
                path.models += 1;
                path.model_bytes += bytes.len();
                path.model_clocks += model.clocks.len();
                path.members += model.scope.len();
                if !verdict.passed() {
                    path.models_refused += 1;
                    for failure in &verdict.failures {
                        *path.model_failures.entry(kind(failure)).or_default() += 1;
                    }
                    if std::env::var("PAIR_DEBUG").is_ok() {
                        eprintln!(
                            "DEBUG refused at {now}: {:?}",
                            &verdict.failures[..verdict.failures.len().min(6)]
                        );
                    }
                    continue;
                }
                for clock in &model.clocks {
                    if clock.from.is_some() {
                        if Some(clock.key.receiver) == jumper {
                            path.jumped += 1;
                        } else if !bad.contains(&clock.key.receiver) {
                            path.false_jumps += 1;
                        }
                    }
                }
                // A fix verifier holding the bytes decodes and prepares the model once.
                let started = Instant::now();
                let decoded = publish::decode_pairs(&bytes).map_err(text)?;
                if publish::area_of(&bytes).map_err(text)? != area {
                    return Err("a model's bytes name another area".into());
                }
                let prepared = Prepared::of(decoded, id).ok_or("unpreparable model")?;
                path.prepare_ns += started.elapsed().as_nanos();
                if prepared.model != model {
                    return Err("a model read back differs".into());
                }
                if options.keep {
                    ran.models.insert((area, trailing.edge_ms), bytes);
                }
                current.insert(area, Arc::new(prepared));
            }
        }
        // The models held, one index for each trailing window they are of: what each set's
        // models are read from without a rebuild (`pair::Models::of`), as the engine reads them.
        let started = Instant::now();
        let mut windows: BTreeMap<(u64, u32), Vec<&Prepared>> = BTreeMap::new();
        for part in current.values() {
            windows
                .entry((part.model.trailing.edge_ms, part.model.trailing.span_ms))
                .or_default()
                .push(part);
        }
        let indexes: BTreeMap<(u64, u32), pair::Models<'_>> = windows
            .into_iter()
            .filter_map(|(window, parts)| Some((window, pair::Models::index(parts)?)))
            .collect();
        path.solve_ns += started.elapsed().as_nanos();
        let due: Vec<Considered> = arrived.due(now).collect();
        if counting_from.is_some() {
            path.due += due.len();
        }
        let mut ready: Vec<Work> = Vec::new();
        for considered in due {
            let hearers = sites.areas_of(considered.receptions.iter().map(|r| r.receiver));
            let class = usize::from(hearers.len() > 1);
            // The newest model of each of its hearers' areas, of the newest edge any is at.
            let held: Vec<Arc<Prepared>> = hearers
                .iter()
                .filter_map(|a| current.get(a).cloned())
                .collect();
            let Some(edge) = held
                .iter()
                .map(|part| part.model.trailing)
                .max_by_key(|t| t.edge_ms)
            else {
                path.unmodelled += 1;
                continue;
            };
            let held: Vec<Arc<Prepared>> = held
                .into_iter()
                .filter(|part| part.model.trailing == edge)
                .collect();
            path.unmodelled += usize::from(held.len() < hearers.len());
            let started = Instant::now();
            let parts: Vec<&Prepared> = held.iter().map(|part| &**part).collect();
            let all = indexes
                .get(&(edge.edge_ms, edge.span_ms))
                .and_then(|index| index.of(&parts));
            path.solve_ns += started.elapsed().as_nanos();
            let Some(all) = all else {
                continue;
            };
            let started = Instant::now();
            let address = considered
                .receptions
                .first()
                .and_then(|reception| crate::modes::address(&reception.message))
                .unwrap_or(0);
            // Whether a part is a transmission solved before that is solved again now: once, once
            // its raw has come or as its set closes (`fix::again`).
            fn solved_again_in<R: std::borrow::Borrow<crate::Reception>>(
                part: &[R],
                chosen: &BTreeMap<ObservationId, usize>,
                again: &[bool],
                considered: &crate::arrived::Considered,
                now: u64,
            ) -> bool {
                part.iter()
                    .find_map(|r| chosen.get(&r.borrow().id()).copied())
                    .is_some_and(|number| {
                        !again[number] && (considered.closing || considered.come_ms(part) <= now)
                    })
            }
            let solved_again = |part: &[crate::Reception]| -> bool {
                solved_again_in(part, &chosen, &again, &considered, now)
            };
            // A part whose slot is decided would be backed off whatever it split into, unless it
            // is solved again: it is not split (`fix::weigh`).
            let skip = |part: &[&crate::Reception]| -> bool {
                all.heard_unix_ns(part).is_some_and(|heard| {
                    slots.is_decided(crate::backoff::Slot::of(address, heard))
                        && !solved_again_in(part, &chosen, &again, &considered, now)
                })
            };
            let transmissions = publish::transmissions_unless(&all, &considered.receptions, skip);
            path.solve_ns += started.elapsed().as_nanos();
            let transmissions = match transmissions {
                Ok(transmissions) => transmissions,
                Err(why) => {
                    path.groups[class] += 1;
                    *path.unpublished[class].entry(kind(&why)).or_default() += 1;
                    continue;
                }
            };
            for transmission in transmissions {
                path.transmissions += 1;
                let before = transmission
                    .group
                    .iter()
                    .find_map(|reception| chosen.get(&reception.id()).copied());
                let work = Work {
                    models: held.clone(),
                    group: transmission.group.clone(),
                    class,
                    number: before,
                };
                match before {
                    // Solved before: again once, once its raw has come or as its set closes, bigger.
                    Some(number) => {
                        if solved_again(&transmission.group)
                            && transmission.group.len() > solved_from[number]
                        {
                            ready.push(work);
                        }
                    }
                    None => {
                        let offered = slots.offer(
                            transmission.slot(address),
                            transmission.rank,
                            considered.first_arrival_ms + SETTLE_MS,
                            work,
                        );
                        path.backed_off += usize::from(offered.is_some());
                    }
                }
            }
        }
        ready.extend(slots.decide(now));
        slots.forget(now, HELD_MS);
        for work in ready {
            let class = work.class;
            let number = work.number.unwrap_or(solved_from.len());
            if number == solved_from.len() {
                solved_from.push(0);
                again.push(false);
            } else {
                again[number] = true;
            }
            solved_from[number] = work.group.len();
            for reception in &work.group {
                chosen.insert(reception.id(), number);
            }
            let started = Instant::now();
            let parts: Vec<&Prepared> = work.models.iter().map(|part| &**part).collect();
            let all = match parts.first().and_then(|part| {
                indexes.get(&(part.model.trailing.edge_ms, part.model.trailing.span_ms))
            }) {
                Some(index) => index.of(&parts),
                None => pair::Models::new(parts.clone()),
            };
            path.solve_ns += started.elapsed().as_nanos();
            let Some(all) = all else {
                continue;
            };
            let started = Instant::now();
            let results = [publish::solve_transmission(
                &all,
                work.group.clone(),
                |_| false,
            )];
            path.solve_ns += started.elapsed().as_nanos();
            for result in results {
                path.groups[class] += 1;
                path.attempted += usize::from(counting_from.is_some());
                let (solution, wire) = match result {
                    Ok(published) => published,
                    Err(why) => {
                        let why = match why {
                            publish::Unpublished::Unnormalised(why) => why.to_owned(),
                            publish::Unpublished::Unsolved(why) => kind(&why),
                            other => kind(&other),
                        };
                        *path.unpublished[class].entry(why).or_default() += 1;
                        continue;
                    }
                };
                // The models it cites, looked up by the ids it lists.
                let cited: Vec<&Prepared> = wire
                    .models
                    .iter()
                    .map(|id| {
                        work.models
                            .iter()
                            .find(|part| part.id == *id)
                            .map(|part| &**part)
                    })
                    .collect::<Option<_>>()
                    .ok_or("a fix cites a model not held")?;
                path.cited_models.extend(wire.models.iter().copied());
                let mut counts: BTreeMap<Region, usize> = BTreeMap::new();
                for reception in &work.group {
                    if let Some(area) = sites.area(&reception.receiver) {
                        *counts.entry(area).or_default() += 1;
                    }
                }
                let most = counts.values().copied().max().unwrap_or(0);
                if let Some(owner) = counts.iter().find(|(_, n)| **n == most).map(|(a, _)| *a) {
                    path.owned_cites
                        .extend(wire.models.iter().map(|id| (owner, *id)));
                }
                let under = pair::Models::new(cited).ok_or("a fix cites models of one area")?;
                path.narrowed += usize::from(under.parts().len() < all.parts().len());
                let considered_ids = &solution.considered;
                let group: Vec<Reception> = work
                    .group
                    .iter()
                    .filter(|r| considered_ids.binary_search(&r.id()).is_ok())
                    .cloned()
                    .collect();
                let started = Instant::now();
                let normalised = under.normalise(&group).map_err(text)?;
                path.normalise_ns += started.elapsed().as_nanos();
                path.bridges += normalised.bridges;
                path.rejected += normalised.rejected;
                path.inflated += usize::from(normalised.kappa > 1.0);
                path.dropped += normalised.dropped;
                let source = *truth.get(&solution.used[0]).ok_or("unknown observation")?;
                let truth_at = simulation.transmissions[source].ecef;
                let used_areas: BTreeSet<Region> = solution
                    .used
                    .iter()
                    .filter_map(|id| sites.area(&id.receiver))
                    .collect();
                if used_areas.iter().copied().collect::<Vec<_>>() != under.areas() {
                    return Err("a fix cites other areas than its used hearers'".into());
                }
                let straddles = used_areas.len() > 1;
                // How many of the network's pairs among its used hearers its models hold.
                let used: Vec<crate::ClockKey> = solution
                    .used
                    .iter()
                    .map(|id| crate::ClockKey {
                        receiver: id.receiver,
                        epoch: id.epoch,
                    })
                    .collect();
                let class = usize::from(straddles);
                path.spanned[class] += used_areas.len();
                path.published[class] += 1;
                path.considered += solution.considered.len();
                path.counted += 1;
                for (i, a) in used.iter().enumerate() {
                    for b in &used[i + 1..] {
                        if network.has(&a.receiver, &b.receiver) {
                            path.hearer_pairs[class] += 1;
                            path.held_pairs[class] += usize::from(under.holds(a, b));
                        }
                    }
                }
                if let Some((own, jitter, clean, dof)) =
                    timing_check(&under, &group, &normalised, simulation, &truth)
                {
                    let entry = path.timing.entry(solution.used.len().min(8)).or_default();
                    entry.0 += own;
                    entry.1 += jitter;
                    entry.4 += clean;
                    entry.2 += dof;
                    entry.3 += 1;
                }
                let d2 = mahalanobis(&solution, truth_at);
                latest.insert(
                    source,
                    (
                        horizontal_m(&solution, truth_at),
                        d2.is_some_and(|d| d < CHI2_3_95),
                        d2.unwrap_or(f64::INFINITY),
                        straddles,
                        solution.used.len(),
                    ),
                );
                solved += 1;
                counting_from.get_or_insert(now);
                if solved.is_multiple_of(options.verify_every) {
                    // Verified cold: the verified models it lists and its own receptions alone.
                    let started = Instant::now();
                    let verdict = crate::verify::verify_pair_fix(
                        &under,
                        &publish::Stated::of(&wire),
                        SPEC_VERSION,
                        &group,
                    );
                    path.verify_ns += started.elapsed().as_nanos();
                    path.verified += 1;
                    path.passed += usize::from(verdict.passed());
                    for failure in &verdict.failures {
                        *path.fix_failures.entry(kind(failure)).or_default() += 1;
                    }
                    // Under models that are not one of each of its used hearers' areas, the same
                    // bytes are refused: one missing when it cites more than one, else another
                    // area's in place of its own.
                    let mut wrong: Vec<&Prepared> = under.parts().to_vec();
                    if wrong.len() > 1 {
                        wrong.pop();
                    } else if let Some(other) = current
                        .values()
                        .find(|part| part.model.area != wrong[0].model.area)
                    {
                        wrong = vec![&**other];
                    }
                    if let Some(wrong) =
                        pair::Models::new(wrong).filter(|wrong| wrong.areas() != under.areas())
                    {
                        let verdict = crate::verify::verify_pair_fix(
                            &wrong,
                            &publish::Stated::of(&wire),
                            SPEC_VERSION,
                            &group,
                        );
                        path.wrong_area += 1;
                        path.wrong_area_refused += usize::from(!verdict.passed());
                    }
                }
                if options.keep {
                    ran.fixes.push(Fixed {
                        areas: under.areas(),
                        wire,
                        group,
                        solution,
                    });
                }
            }
        }
        now += STEP_MS;
    }
    for (source, fix) in latest {
        path.fixes.insert((scenario.seed, source), fix);
    }
    // What each area's relay verifies of its band's models: every one, or only those the fixes
    // it owns cite.
    for (area, _) in sites.areas() {
        let band: BTreeSet<Region> = sites
            .areas_of(sites.members(*area).iter().map(|site| site.receiver))
            .into_iter()
            .filter(|other| other != area)
            .collect();
        for (id, of) in &path.model_area {
            if band.contains(of) {
                let ns = path.model_ns.get(id).copied().unwrap_or(0);
                let cited = path.owned_cites.contains(&(*area, *id));
                for (at, counted) in [true, cited].into_iter().enumerate() {
                    path.band_ns[at] += if counted { ns } else { 0 };
                    path.band_models[at] += usize::from(counted);
                }
            }
        }
    }
    if let Some(from) = counting_from {
        path.counted_s += last.saturating_sub(from) as f64 / 1_000.0 * scenario.receivers as f64;
    }
    path.model_area.clear();
    path.owned_cites.clear();
    Ok(ran)
}

/// A transmission to solve: the models it is solved under, its receptions, its class, and which
/// solved transmission it is, if it is one solved before.
struct Work {
    models: Vec<Arc<Prepared>>,
    group: Vec<Reception>,
    class: usize,
    number: Option<usize>,
}

/// The engine over a scenario as the simulator made it.
fn run_areas(scenario: &Scenario, options: Options) -> Result<(Simulation, Ran, Path)> {
    let mut simulation = sim::run(scenario);
    let arrivals = sim::arrivals(&mut simulation, scenario.seed);
    let mut path = Path::default();
    let ran = areas(
        scenario,
        &simulation,
        &simulation.sites(),
        &arrivals,
        options,
        &mut path,
    )?;
    Ok((simulation, ran, path))
}

fn report(name: &str, b: &Path) {
    let stats = |field: fn(&pair::Stats) -> usize| -> usize {
        let mut values: Vec<usize> = b.stats.iter().map(field).collect();
        values.sort_unstable();
        values.get(values.len() / 2).copied().unwrap_or(0)
    };
    eprintln!(
        "PAIR {name}: {} areas over {} receivers, {:.2} members a model a receiver; {} refits, {} \
         models ({} refused by their verifier: {:?}); refit median {} clocks, {} events, {} \
         candidates, {} valid, {} jumped, {} unattributed, {} inflated, {:.2} passes a refit ({} \
         again for the noise, {} for the rates; {:.0} pairs refitted after the first pass); blocks \
         a refit {:.1} built, {:.1} held; ms a refit: read {:.1}, fit {:.1}; jumper's jump in {} models, \
         false jumps {}; bridges {}, loop rejects {}, fixes inflated {}, receptions dropped {}; \
         unsolved {:?}; fixes the cold verifier refuses {:?}; under models not one of each of its \
         used hearers' areas {} of {} refused",
        b.areas,
        b.receivers,
        b.members as f64 / b.models.max(1) as f64 * b.areas as f64 / b.receivers.max(1) as f64,
        b.refits,
        b.models,
        b.models_refused,
        b.model_failures,
        stats(|s| s.clocks),
        stats(|s| s.events),
        stats(|s| s.candidates),
        stats(|s| s.valid),
        stats(|s| s.jumped),
        stats(|s| s.unattributed),
        stats(|s| s.inflated),
        b.passes as f64 / b.models.max(1) as f64,
        b.stats.iter().map(|s| s.again_noise).sum::<usize>(),
        b.stats.iter().map(|s| s.again_rates).sum::<usize>(),
        b.stats.iter().map(|s| s.refitted).sum::<usize>() as f64 / b.models.max(1) as f64,
        b.stats.iter().map(|s| s.blocks_built).sum::<usize>() as f64 / b.models.max(1) as f64,
        b.stats.iter().map(|s| s.blocks_reused).sum::<usize>() as f64 / b.models.max(1) as f64,
        stats(|s| s.read_ns as usize) as f64 / 1e6,
        stats(|s| s.fit_ns as usize) as f64 / 1e6,
        b.jumped,
        b.false_jumps,
        b.bridges,
        b.rejected,
        b.inflated,
        b.dropped,
        b.failures,
        b.fix_failures,
        b.wrong_area_refused,
        b.wrong_area,
    );
    for (class, name_of) in CLASSES.iter().enumerate() {
        eprintln!(
            "PAIR {name} boundary, {name_of}: {} transmissions grouped (by their hearers' areas), \
             {} not published {:?}; {} published (by their used hearers' areas), its models hold \
             {:.3} of the network's pairs among its used hearers; {:.2} areas a fix",
            b.groups[class],
            b.unpublished[class].values().sum::<usize>(),
            b.unpublished[class],
            b.published[class],
            b.held_pairs[class] as f64 / b.hearer_pairs[class].max(1) as f64,
            b.spanned[class] as f64 / b.published[class].max(1) as f64,
        );
    }
    eprintln!(
        "PAIR {name} boundary: {} published citing fewer models than they were solved by, {} \
         considered sets of an area with no model held; {} transmissions due, {} backed off \
         (never solved: another of their slot was chosen)",
        b.narrowed, b.unmodelled, b.transmissions, b.backed_off
    );
    let rates = b.rates();
    eprintln!(
        "PAIR {name} rates, from the first fix published: {} kept over {:.0} feeder-seconds \
         ({:.1} a feeder-second); {} sets due, {} transmissions solved, {} fixes published, {} receptions they \
         considered ({:.2} a fix); a thousand feeder-seconds: {rates:?}",
        b.kept,
        b.counted_s,
        b.kept as f64 / b.counted_s.max(1.0),
        b.due,
        b.attempted,
        b.counted,
        b.considered,
        b.considered as f64 / b.counted.max(1) as f64,
    );
    eprintln!("{}", b.line(name, None));
    eprintln!("{}", b.line(name, Some(false)));
    eprintln!("{}", b.line(name, Some(true)));
    // Coverage by receivers used: 4 to 7 one by one, 8 and more together.
    let mut bands: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    for (_, inside, _, _, used) in b.fixes.values() {
        let band = bands.entry((*used).min(8)).or_default();
        band.0 += 1;
        band.1 += usize::from(*inside);
    }
    for (used, (own, jitter, dof, fixes, clean)) in &b.timing {
        let (all, covered) = bands.get(used).copied().unwrap_or_default();
        eprintln!(
            "PAIR {name} timing, {used} used: {fixes} fixes, d² a degree of freedom \
             {:.2} under its own covariance, {:.2} under its clock part and the true jitter, \
             {:.2} read without jitter under its clock part; coverage {:.3} of {all}",
            own / *dof as f64,
            jitter / *dof as f64,
            clean / *dof as f64,
            covered as f64 / all.max(1) as f64,
        );
    }
}

/// The pairwise path over the default mix, world density, a receiver that jumps once beside one
/// that steps every two seconds, and no GNSS clock with every clock 30 ppm fast (`scenarios`).
/// `PAIR_ONLY` narrows by name, `PAIR_SEEDS` the seeds a scenario, `PAIR_S` the length,
/// `PAIR_SPREAD_KM` the world density's spread (so its receivers span more areas). Run with
/// `--ignored --nocapture`.
#[test]
#[ignore = "an experiment: run with --ignored --nocapture"]
fn pairwise_path_sweep() -> Result {
    let duration_s: f64 = env("PAIR_S", 120.0);
    let seeds: usize = env("PAIR_SEEDS", 3);
    let spread_km: f64 = env("PAIR_SPREAD_KM", 0.0);
    let options = Options {
        verify_every: env("PAIR_VERIFY_EVERY", 25),
        keep: false,
        cold: false,
    };
    let mut scenarios = scenarios(duration_s);
    if let Ok(only) = std::env::var("PAIR_ONLY") {
        scenarios.retain(|(name, _)| only.split(',').any(|one| one == *name));
    }
    for (name, list) in &mut scenarios {
        list.truncate(seeds);
        let mut path = Path::default();
        for scenario in list.iter_mut() {
            if *name == "world density" && spread_km > 0.0 {
                scenario.spread_m = spread_km * 1000.0;
            }
            let mut simulation = sim::run(scenario);
            let arrivals = sim::arrivals(&mut simulation, scenario.seed);
            let network = Network::of(&simulation.sites());
            eprintln!(
                "PAIR {name} seed {}: {} receivers, {} pairs in the network",
                scenario.seed,
                scenario.receivers,
                network.len()
            );
            areas(
                scenario,
                &simulation,
                &simulation.sites(),
                &arrivals,
                options,
                &mut path,
            )?;
        }
        report(name, &path);
        eprintln!("PAIR {name} peak RSS {} MB", peak_rss() >> 20);
        // The relay's tables sized by the fixes are planned at world density's rates
        // (`backoff::Published::MEASURED`): a run of it over a minute or more never exceeds them.
        if *name == "world density" && spread_km == 0.0 && duration_s >= 60.0 {
            let rates = path.rates();
            let planned = crate::backoff::Published::MEASURED;
            if rates.due_per_ks > planned.due_per_ks
                || rates.solved_per_ks > planned.solved_per_ks
                || rates.published_per_ks > planned.published_per_ks
                || rates.considered_per_ks > planned.considered_per_ks
            {
                return Err(format!("{rates:?} past the planned {planned:?}"));
            }
        }
    }
    Ok(())
}

/// The pairwise path over one seed of the default mix for a minute: its fixes cover the truth as a
/// 95% ellipsoid should (held to [0.92, 0.98], about five hundred fixes, one an aircraft a slot
/// (`backoff`), over several areas' refits); every model passes its verifier, holding the window
/// and its own sites, and reads back from its bytes to itself; every sampled fix, written to the
/// wire, passes the cold verifier holding the verified models it lists and the fix's receptions
/// alone, and is refused under models that are not one of each of its used hearers' areas.
#[test]
fn pairwise_path_is_calibrated_and_verifies() -> Result {
    let (_, _, path) = run_areas(
        &of(9000, 60.0),
        Options {
            verify_every: 25,
            keep: false,
            cold: false,
        },
    )?;
    report("default", &path);
    let covered = path.fixes.values().filter(|fix| fix.1).count();
    let rate = covered as f64 / path.fixes.len().max(1) as f64;
    assert!(path.areas >= 2, "{} areas", path.areas);
    assert!(path.fixes.len() >= 450, "{} fixes", path.fixes.len());
    assert!(path.backed_off > 0, "no transmission backed off");
    assert!((0.92..=0.98).contains(&rate), "coverage {rate}");
    assert!(path.models >= 25, "{} models", path.models);
    assert_eq!(path.models_refused, 0, "{:?}", path.model_failures);
    assert!(path.verified >= 20, "{} verified", path.verified);
    assert_eq!(
        path.passed, path.verified,
        "a fix the cold verifier refuses"
    );
    assert!(path.wrong_area > 0);
    assert_eq!(
        path.wrong_area_refused, path.wrong_area,
        "a fix passes under models not its used hearers' areas'"
    );
    Ok(())
}

/// The fixture of the tampering checks: half a minute of the default mix held at its last edge,
/// the area holding the most receivers, and its model fitted cold over its window.
fn fitted_window() -> std::result::Result<(Sites, Arrived, Inputs, PairModel), String> {
    let scenario = of(9000, 30.0);
    let mut simulation = sim::run(&scenario);
    let arrivals = sim::arrivals(&mut simulation, scenario.seed);
    let sites = Sites::new(&simulation.sites());
    let mut arrived = Arrived::new(Limits {
        held_ms: HELD_MS,
        ..Limits::UNBOUNDED
    });
    for arrival in &arrivals {
        arrived.admit(arrival.batch, arrival.at_ms, &arrival.receptions);
    }
    let last = arrivals.last().map_or(0, |arrival| arrival.at_ms);
    arrived.seal(last);
    let trailing = Trailing {
        span_ms: TRAILING_WINDOW_MS as u32,
        ..Trailing::fitted_at(last.next_multiple_of(REFIT_EVERY_MS) - 2 * REFIT_EVERY_MS)
    };
    let area = sites
        .areas()
        .max_by_key(|(area, keys)| (keys.len(), std::cmp::Reverse(**area)))
        .map(|(area, _)| *area)
        .ok_or("no area")?;
    let inputs = arrived
        .area_inputs_over(area, &sites, trailing)
        .ok_or("two members")?;
    let model = pair::fit(&inputs, None, &mut PairCache::default())
        .map_err(text)?
        .model;
    Ok((sites, arrived, inputs, model))
}

/// A pair model's verifier, holding the window and its own sites, passes the honest model and
/// refuses each tampering: an understated noise, a rate moved, a knot moved, a pair left out, a
/// jump declared where there is none, a CPR reference left out, another area named, and a scope
/// that is not the area's members; the encoding reads back to the model, names its area first,
/// and refuses a byte more.
#[test]
fn the_pair_model_verifier_refuses_tampering() -> Result {
    let (sites, arrived, inputs, model) = fitted_window()?;
    let check = |model: &PairModel| {
        crate::verify::verify_pair_model_held(&sites, model, &arrived, &mut PairCache::default())
            .failures
    };
    assert_eq!(check(&model), Vec::new());
    assert_eq!(
        crate::verify::verify_pair_model(&inputs, &model, &mut PairCache::default()).failures,
        Vec::new()
    );
    let bytes = publish::encode_pairs(&model).map_err(text)?;
    assert_eq!(publish::decode_pairs(&bytes).map_err(text)?, model);
    assert_eq!(publish::area_of(&bytes[..10]).map_err(text)?, model.area);
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(publish::decode_pairs(&longer).is_err());
    let refused = |tamper: &dyn Fn(&mut PairModel), what: &str| {
        let mut tampered = model.clone();
        tamper(&mut tampered);
        let failures = check(&tampered);
        assert!(!failures.is_empty(), "{what} passes");
    };
    refused(&|m| m.clocks[0].noise_ns *= 0.5, "an understated noise");
    refused(
        &|m| m.clocks[1].white_ns *= 0.5,
        "an understated white noise",
    );
    refused(&|m| m.clocks[0].rate += 1e-7, "a rate moved");
    refused(&|m| m.pairs[0].knots[1] += 30.0, "a knot moved");
    refused(&|m| m.pairs[0].kappa *= 1.5, "an inflation changed");
    refused(&|m| m.pairs[0].share *= 1.5, "a share changed");
    refused(
        &|m| {
            m.pairs.remove(0);
        },
        "a pair left out",
    );
    refused(
        &|m| m.clocks[0].from = Some(m.clocks[0].lowest + 1),
        "a jump that is not",
    );
    refused(&|m| m.pairs[0].anchor_a += 1, "an anchor moved");
    let other = sites
        .areas()
        .map(|(area, _)| *area)
        .find(|area| *area != model.area)
        .ok_or("one area only")?;
    refused(&|m| m.area = other, "another area named");
    refused(
        &|m| {
            let gone = m.scope.remove(m.scope.len() - 1);
            m.frontier
                .retain(|frontier| frontier.receiver != gone.receiver);
        },
        "a member left out",
    );
    Ok(())
}

/// A pair model's bytes are the same on every platform: its id, computed here, is the committed
/// golden made on the x86 development host. The pair fit, the noise and the rates run in one fixed
/// order with no fused multiply-add and no transcendental function.
#[test]
fn a_pair_models_bytes_are_the_committed_golden() -> Result {
    let (_, _, _, model) = fitted_window()?;
    let bytes = publish::encode_pairs(&model).map_err(text)?;
    let hex: String = publish::pair_model_id(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(hex, PAIR_GOLDEN, "{} bytes", bytes.len());
    Ok(())
}

/// BLAKE2s-256 of the area model of `fitted_window`, made on the x86 host (version 8; remade when
/// each clock came to carry `heard_ns`, its transmit-time dating bound, when the inputs came to be
/// cited by their batches' parts, `scope::Citation`, when the variances came to be published
/// single, the clocks by their scope index, and the white noise read at its degrees of freedom,
/// and last on 2026-10-30 after the pair blocks of 2026-10-27, the same bytes on two runs).
const PAIR_GOLDEN: &str = "30b808d670df0332bc4c856d753b13cba60e6ff0af84a53be1652688501c8223";

/// Every area's members are its receivers and those they keep (crate docs, § Areas): a pure
/// function of the sites, the same over the members alone as over every site, and every pair of
/// the network is in the model of an area an end of it keeping it is in.
#[test]
fn an_areas_members_and_pairs_are_its_receivers_kept_pairs() -> Result {
    let simulation = sim::run(&world_density(9000, 10.0));
    let site_list = simulation.sites();
    let sites = Sites::new(&site_list);
    let network = Network::of(&site_list);
    let mut covered: BTreeSet<(tally_wire::PublicKey, tally_wire::PublicKey)> = BTreeSet::new();
    assert!(
        sites.areas().count() >= 2,
        "{} areas",
        sites.areas().count()
    );
    for (area, keys) in sites.areas() {
        let members = sites.members(*area);
        let over_members = Network::of_area(&members, *area);
        let over_all = Network::of_area(&site_list, *area);
        assert_eq!(
            over_members, over_all,
            "the area's network over its members alone"
        );
        for key in keys {
            assert!(members.iter().any(|site| site.receiver == *key));
            for kept in network.kept(key) {
                assert!(members.iter().any(|site| site.receiver == *kept));
                assert!(over_all.has(key, kept));
                covered.insert((*key.min(kept), *key.max(kept)));
            }
        }
    }
    let mut every = 0;
    for (key, _) in sites.iter() {
        for other in network.neighbours(key) {
            if key < other {
                every += 1;
                assert!(
                    covered.contains(&(*key, *other)),
                    "a pair in no area's model"
                );
            }
        }
    }
    assert_eq!(every, network.len());
    Ok(())
}

/// Two holders of the same batches, one given them in another order with copies, publish the same
/// model bytes for every area at every edge both fitted.
#[test]
fn the_same_batches_in_any_order_and_copies_publish_the_same_models() -> Result {
    let scenario = of(301, 30.0);
    let mut simulation = sim::run(&scenario);
    let arrivals = sim::arrivals(&mut simulation, scenario.seed);
    let options = Options {
        verify_every: usize::MAX,
        keep: true,
        cold: false,
    };
    let sites = simulation.sites();
    let one = areas(
        &scenario,
        &simulation,
        &sites,
        &arrivals,
        options,
        &mut Path::default(),
    )?;
    let shuffled = reordered(&relayed(&arrivals, 7), &mut Rng::new(11));
    let other = areas(
        &scenario,
        &simulation,
        &sites,
        &shuffled,
        options,
        &mut Path::default(),
    )?;
    let mut compared = 0;
    for (at, bytes) in &one.models {
        if let Some(theirs) = other.models.get(at) {
            assert_eq!(bytes, theirs, "{at:?}");
            compared += 1;
        }
    }
    assert!(compared >= 10, "{compared} models compared");
    Ok(())
}

/// A refit whose pairs are fitted from their knots in the area's previous model (the cutoff passes
/// alone) publishes the same model bytes as one whose pairs are fitted from the closed-form start
/// (the medians' line and the Huber passes first), at every area and edge: the warm start changes
/// where each pair's optimum is sought from, never which one is found.
#[test]
fn a_warm_refit_publishes_what_a_cold_refit_publishes() -> Result {
    let scenario = world_density(9000, 20.0);
    let mut simulation = sim::run(&scenario);
    let arrivals = sim::arrivals(&mut simulation, scenario.seed);
    let sites = simulation.sites();
    let run = |cold: bool| {
        let options = Options {
            verify_every: usize::MAX,
            keep: true,
            cold,
        };
        areas(
            &scenario,
            &simulation,
            &sites,
            &arrivals,
            options,
            &mut Path::default(),
        )
    };
    let (warm, cold) = (run(false)?, run(true)?);
    assert_eq!(warm.models.len(), cold.models.len());
    for (at, bytes) in &warm.models {
        assert_eq!(Some(bytes), cold.models.get(at), "{at:?}");
    }
    assert!(warm.models.len() >= 60, "{} models", warm.models.len());
    Ok(())
}

/// A receiver whose clock is unknown or whose location is too coarse is in no model.
#[test]
fn a_receiver_with_an_unknown_clock_or_coarse_location_takes_no_part() -> Result {
    let scenario = of(71, 20.0);
    let mut simulation = sim::run(&scenario);
    let arrivals = sim::arrivals(&mut simulation, scenario.seed);
    let mut sites = simulation.sites();
    sites[1].clock = tally_wire::Clock::Unknown;
    sites[3].location.precision_m = 500;
    let excluded = [sites[1].receiver, sites[3].receiver];
    let ran = areas(
        &scenario,
        &simulation,
        &sites,
        &arrivals,
        Options {
            verify_every: usize::MAX,
            keep: true,
            cold: false,
        },
        &mut Path::default(),
    )?;
    assert!(!ran.models.is_empty());
    for bytes in ran.models.values() {
        let model = publish::decode_pairs(bytes).map_err(text)?;
        assert!(model.scope.iter().all(|s| !excluded.contains(&s.receiver)));
        assert!(
            model
                .clocks
                .iter()
                .all(|c| !excluded.contains(&c.key.receiver))
        );
    }
    Ok(())
}

/// An exactly determined transmission (three receptions and the altitude) has two roots in
/// general, both fitting perfectly; every fix published is within its own 10^-6 ellipsoid of the
/// truth: an ambiguous one is refused.
#[test]
fn an_exactly_determined_transmission_with_two_roots_is_refused_not_guessed() -> Result {
    let (simulation, ran, _) = run_areas(
        &Scenario {
            midnight_unix_ms: 1_791_158_400_000,
            modes_aircraft: 30,
            ..of(31, 20.0)
        },
        Options {
            verify_every: usize::MAX,
            keep: true,
            cold: false,
        },
    )?;
    let truth = truth_of(&simulation);
    let mut exact = 0;
    for fixed in &ran.fixes {
        let solution = &fixed.solution;
        let source = truth.get(&solution.used[0]).ok_or("unknown observation")?;
        let transmission = &simulation.transmissions[*source];
        let distance = mahalanobis(solution, transmission.ecef).ok_or("singular")?;
        assert!(
            distance < crate::solve::chi2_limit(3),
            "{} receptions, {distance} squared standard deviations from the truth",
            solution.used.len()
        );
        exact += usize::from(solution.used.len() == 3);
    }
    assert!(exact > 0, "no exactly determined fix was published at all");
    Ok(())
}

/// What a client is sent of a model (`publish::client_model`, a signed `ClientClockModel`) and of
/// its fixes (tagged, positions format 8) names no receiver and holds no site, no site id, no
/// clock, no pair and no frontier; the inputs id moves with a site's id, a frontier and the area,
/// never with a site; and a relay holding the raw rematches every tagged fix to the raw one
/// exactly (`publish::rematch`), and one whose tags it cannot all account for to nothing.
#[test]
fn a_clients_forms_carry_no_site_and_a_relay_rematches_their_tags() -> Result {
    let (simulation, ran, _) = run_areas(
        &of(301, 20.0),
        Options {
            verify_every: usize::MAX,
            keep: true,
            cold: false,
        },
    )?;
    let model =
        publish::decode_pairs(ran.models.values().next().ok_or("no model")?).map_err(text)?;
    let contains = |bytes: &[u8], canary: &[u8]| bytes.windows(canary.len()).any(|at| at == canary);
    let engine = tally_wire::Identity::from_seed([9; 32]);
    let inputs = publish::inputs_id(&model).ok_or("inputs id")?;
    let signed =
        publish::client_model(&engine, &model, [1; 32], inputs, (1, 2, 3)).map_err(text)?;
    let bytes = signed.as_bytes();
    // It is of one size, and names no member: no receiver key, no site id, no site, no frontier.
    assert_eq!(bytes.len(), tally_wire::CLIENT_MODEL_LEN);
    for site in &model.scope {
        assert!(!contains(bytes, site.receiver.as_bytes()));
        assert!(!contains(bytes, &site.id.0));
        assert!(!contains(bytes, &site.location.lat_e7.to_be_bytes()));
        assert!(!contains(bytes, &site.location.lon_e7.to_be_bytes()));
    }
    for frontier in &model.frontier {
        assert!(
            !contains(bytes, &frontier.through_sequence.to_be_bytes())
                || frontier.through_sequence < 4
        );
    }
    for pair in &model.pairs {
        for knot in &pair.knots {
            assert!(!contains(bytes, &knot.to_bits().to_be_bytes()));
        }
    }
    // The inputs id is the site ids' and precisions', never the sites': moving a site with the
    // same id leaves it, a new site-bearing record (a new id) changes it, and so does a frontier
    // and another area.
    let mut moved = model.clone();
    moved.scope[0].location.lat_e7 += 1;
    assert_eq!(publish::inputs_id(&moved), Some(inputs));
    moved.scope[0].id = tally_wire::SiteId([0; 32]);
    assert_ne!(publish::inputs_id(&moved), Some(inputs));
    let mut further = model.clone();
    further.frontier[0].through_sequence += 1;
    assert_ne!(publish::inputs_id(&further), Some(inputs));
    let other = ran
        .models
        .keys()
        .map(|(area, _)| *area)
        .find(|area| *area != model.area)
        .ok_or("one area only")?;
    let mut elsewhere = model.clone();
    elsewhere.area = other;
    assert_ne!(publish::inputs_id(&elsewhere), Some(inputs));

    let keys: BTreeMap<tally_wire::PublicKey, tally_wire::ReceptionKey> = simulation
        .receivers
        .iter()
        .map(|receiver| (receiver.key, receiver.record.reception_key()))
        .collect();
    let key_of = |receiver: &tally_wire::PublicKey| keys.get(receiver).copied();
    let mut rematched = 0;
    for fixed in ran.fixes.iter().take(40) {
        let wire = &fixed.wire;
        let tagged = wire.tagged(key_of).map_err(text)?;
        let record = tally_wire::Positions::sign_tagged_fix(
            &engine,
            &tally_wire::TaggedFixesContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 0,
                spec_version: SPEC_VERSION,
                fixes: vec![tagged.clone()],
            },
        )
        .map_err(text)?;
        for reception in wire.considered().receptions() {
            assert!(!contains(record.as_bytes(), reception.receiver.as_bytes()));
            assert!(!contains(
                record.as_bytes(),
                &reception.counter.to_be_bytes()[2..]
            ));
        }
        let held: Vec<tally_wire::Reception> = fixed
            .group
            .iter()
            .map(|reception| tally_wire::Reception {
                receiver: reception.receiver,
                epoch: reception.epoch,
                counter: reception.timestamp,
            })
            .collect();
        assert_eq!(
            publish::rematch(&tagged, held.iter().copied(), key_of),
            Some(wire.clone())
        );
        // A relay missing one reception, or holding none of the keys, accounts for nothing.
        let cited = wire.considered().receptions()[0];
        let missing = held
            .iter()
            .filter(|reception| **reception != cited)
            .copied();
        assert_eq!(publish::rematch(&tagged, missing, key_of), None);
        assert_eq!(
            publish::rematch(&tagged, held.iter().copied(), |_| None),
            None
        );
        for area in &fixed.areas {
            assert!(ran.models.keys().any(|(held, _)| held == area));
        }
        rematched += 1;
    }
    assert!(rematched > 5, "{rematched} rematched");
    Ok(())
}

/// An inputs pass on a gate a prompt thread keeps asking of: every area's inputs are built by
/// workers holding the gate's permits, and they finish. A pass whose workers waited on one
/// another while holding permits (as a lazily built table once made them) would stop a relay's
/// steps for good. The pass is given a minute; it takes well under one.
#[test]
fn an_inputs_pass_on_a_contended_gate_finishes() -> Result {
    use crate::gate::{self, Gate, Urgency};
    use std::sync::atomic::{AtomicBool, Ordering};
    let simulation = sim::run(&of(61, 20.0));
    let arrived = Arc::new(Arrived::holding(&simulation.receptions));
    let sites = Arc::new(Sites::new(&simulation.sites()));
    let owned: Vec<Region> = sites.areas().map(|(area, _)| *area).collect();
    let edge = simulation
        .receptions
        .iter()
        .map(|reception| reception.wall_ms)
        .max()
        .unwrap_or(0);
    let gate = Gate::new(3);
    let done = Arc::new(AtomicBool::new(false));
    let (sent, finished) = std::sync::mpsc::channel();
    let prompt = {
        let (gate, done) = (Arc::clone(&gate), Arc::clone(&done));
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                gate::enter(&gate, Urgency::Prompt, std::thread::yield_now);
            }
        })
    };
    {
        let gate = Arc::clone(&gate);
        let (arrived, sites) = (Arc::clone(&arrived), Arc::clone(&sites));
        std::thread::spawn(move || {
            let built = gate::enter(&gate, Urgency::Background, || {
                (0..8)
                    .map(|_| {
                        gate::on_threads(4, owned.clone(), |area| {
                            arrived.area_inputs(area, &sites, edge).is_some()
                        })
                        .into_iter()
                        .filter(|built| *built)
                        .count()
                    })
                    .sum::<usize>()
            });
            let _ = sent.send(built);
        });
    }
    let built = finished.recv_timeout(std::time::Duration::from_secs(60));
    done.store(true, Ordering::Relaxed);
    let _ = prompt.join();
    let built = built.map_err(|_| "the pass did not finish: its workers wait on each other")?;
    assert!(built > 0);
    Ok(())
}

/// `values` in an order drawn from `rng` (Fisher and Yates).
fn shuffled<T: Clone>(values: &[T], rng: &mut Rng) -> Vec<T> {
    let mut out = values.to_vec();
    for at in (1..out.len()).rev() {
        out.swap(at, (rng.next_u64() % (at as u64 + 1)) as usize);
    }
    out
}

/// Every id of each part, ascending, the parts ascending: a grouping as a set of sets.
fn as_sets(groups: &[Vec<Reception>]) -> Vec<Vec<ObservationId>> {
    let mut sets: Vec<Vec<ObservationId>> = groups
        .iter()
        .map(|group| {
            let mut ids: Vec<ObservationId> = group.iter().map(Reception::id).collect();
            ids.sort_unstable();
            ids
        })
        .collect();
    sets.sort_unstable();
    sets
}

/// A normalisation's problem and timeline zero, to the bit.
fn bits_of(normalised: &pair::Normalised) -> Vec<u128> {
    let problem = &normalised.problem;
    let mut bits = vec![
        u128::from(normalised.origin_unix_ns),
        problem.reference_ps as u128,
        u128::from(normalised.kappa.to_bits()),
    ];
    for item in &problem.items {
        bits.extend([
            item.time.linear as u128,
            item.time.ps as u128,
            item.time.carried_ps as u128,
            u128::from(item.z.to_bits()),
            u128::from(item.noise_m2.to_bits()),
        ]);
    }
    for row in problem.clock_m2.iter().flatten() {
        bits.extend(row.iter().map(|value| u128::from(value.to_bits())));
    }
    bits
}

/// Grouping, dating, capping and normalising are functions of a transmission's receptions as a
/// set (crate docs, § Verifying a fix): over world density's due sets, each shuffled, the
/// transmissions are the same sets, and each one's heard time, capped receivers and normalisation
/// the same to the bit, so the solver may judge its own fix on the normalisation it solved
/// (`verify::verify_solved`), which the verifier's regrouping of the sorted considered set
/// rebuilds. A transmission heard by more than `HEARERS_MOST` is solved from that many, its fix
/// passes the cold verifier, and the same transmission solved from every hearer is refused
/// (`Failure::Uncapped`).
#[test]
fn grouping_and_normalising_are_invariant_to_reception_order() -> Result {
    let scenario = world_density(9000, 16.0);
    let mut simulation = sim::run(&scenario);
    let arrivals = sim::arrivals(&mut simulation, scenario.seed);
    let sites = Sites::new(&simulation.sites());
    let mut arrived = Arrived::new(Limits {
        held_ms: HELD_MS,
        ..Limits::UNBOUNDED
    });
    let mut rng = Rng::new(5);
    // Every area's model at the first edge each fits at.
    let mut prepared: BTreeMap<Region, Prepared> = BTreeMap::new();
    let (mut checked, mut over, mut refused) = (0usize, 0usize, 0usize);
    let mut next = 0;
    let mut now = arrivals
        .first()
        .ok_or("no arrivals")?
        .at_ms
        .next_multiple_of(STEP_MS);
    let last = arrivals.last().map_or(0, |arrival| arrival.at_ms);
    while now <= last && checked < 400 {
        while let Some(arrival) = arrivals.get(next).filter(|arrival| arrival.at_ms <= now) {
            arrived.admit(arrival.batch, arrival.at_ms, &arrival.receptions);
            next += 1;
        }
        arrived.seal(now);
        if prepared.is_empty() && now.is_multiple_of(REFIT_EVERY_MS) {
            let trailing = Trailing {
                span_ms: TRAILING_WINDOW_MS as u32,
                ..Trailing::fitted_at(now)
            };
            let areas: Vec<Region> = sites.areas().map(|(area, _)| *area).collect();
            for area in areas {
                if let Some(inputs) = arrived.area_inputs_over(area, &sites, trailing)
                    && let Ok(fitted) = pair::fit(&inputs, None, &mut PairCache::default())
                {
                    let bytes = publish::encode_pairs(&fitted.model).map_err(text)?;
                    let id = publish::pair_model_id(&bytes);
                    prepared.extend(Prepared::of(fitted.model, id).map(|part| (area, part)));
                }
            }
        }
        for considered in arrived.due(now).collect::<Vec<_>>() {
            let hearers = sites.areas_of(considered.receptions.iter().map(|r| r.receiver));
            let parts: Option<Vec<&Prepared>> = hearers.iter().map(|a| prepared.get(a)).collect();
            let Some(models) = parts.and_then(Models::new) else {
                continue;
            };
            let groups = models.transmissions(&considered.receptions);
            let again = models.transmissions(&shuffled(&considered.receptions, &mut rng));
            assert_eq!(as_sets(&groups), as_sets(&again), "the transmissions");
            for group in &groups {
                let other = shuffled(group, &mut rng);
                assert_eq!(models.heard_unix_ns(group), models.heard_unix_ns(&other));
                let capped = models.capped(group);
                assert_eq!(
                    as_sets(std::slice::from_ref(&capped)),
                    as_sets(&[models.capped(&other)]),
                    "the capped receivers"
                );
                let receivers: BTreeSet<_> = group.iter().map(|r| r.receiver).collect();
                let kept: BTreeSet<_> = capped.iter().map(|r| r.receiver).collect();
                assert_eq!(kept.len(), receivers.len().min(pair::HEARERS_MOST));
                let (Ok(one), Ok(two)) = (
                    models.normalise(&capped),
                    models.normalise(&shuffled(&capped, &mut rng)),
                ) else {
                    continue;
                };
                assert_eq!(bits_of(&one), bits_of(&two), "the normalisation");
                checked += 1;
                if receivers.len() <= pair::HEARERS_MOST || over >= 10 {
                    continue;
                }
                // Solved from its capped receivers it verifies cold; solved from every hearer,
                // what it used beyond the cap is refused.
                let Ok((solution, wire)) =
                    publish::solve_transmission(&models, group.clone(), |_| false)
                else {
                    continue;
                };
                // Under the models it cites.
                let cited: Vec<&Prepared> = prepared
                    .values()
                    .filter(|part| wire.models.contains(&part.id))
                    .collect();
                let under = Models::new(cited).ok_or("no models cited")?;
                let verdict = crate::verify::verify_pair_fix(
                    &under,
                    &publish::Stated::of(&wire),
                    SPEC_VERSION,
                    &other,
                );
                assert!(verdict.passed(), "{:?}", verdict.failures);
                let considered: Vec<Reception> = group
                    .iter()
                    .filter(|r| solution.considered.binary_search(&r.id()).is_ok())
                    .cloned()
                    .collect();
                let Ok(whole) = under.normalise(&considered) else {
                    continue;
                };
                let Ok(mut uncapped) = whole.solve() else {
                    continue;
                };
                if under.areas_of(uncapped.used.iter().map(|id| id.receiver)) != Some(under.areas())
                {
                    continue;
                }
                over += 1;
                uncapped.considered = solution.considered.clone();
                let wire = publish::to_wire_at(
                    whole.origin_unix_ns,
                    &uncapped,
                    under.ids(),
                    &group[0].message,
                )
                .map_err(text)?;
                let verdict = crate::verify::verify_pair_fix(
                    &under,
                    &publish::Stated::of(&wire),
                    SPEC_VERSION,
                    group,
                );
                refused += usize::from(
                    verdict
                        .failures
                        .iter()
                        .any(|failure| matches!(failure, crate::verify::Failure::Uncapped { .. })),
                );
            }
        }
        now += STEP_MS;
    }
    assert!(checked >= 300, "{checked} transmissions checked");
    assert!(
        over >= 5 && refused == over,
        "{over} over the cap, {refused} refused"
    );
    Ok(())
}

/// What a refit costs, split as an engine pays it (`tally_mlat::fix::refit`): gathering an area's
/// window from what has arrived (`Arrived::area_inputs_over`), reading it (`pair::Stats::read_ns`)
/// and fitting it (`pair::Stats::fit_ns`); each area's whole refit against its points, by least
/// squares, so a cost that does not follow the points shows as the intercept; and the most an
/// area's memos (`PairCache::bytes`) hold a receiver of it. Over the world density,
/// `PAIR_DURATION_S` long, every refit after the first window is whole.
#[test]
#[ignore = "a measurement: run with --ignored --nocapture"]
fn a_refits_cost_follows_its_points() -> Result {
    let scenario = world_density(env("PAIR_SEED", 9000), env("PAIR_DURATION_S", 120.0));
    let mut simulation = sim::run(&scenario);
    let arrivals = sim::arrivals(&mut simulation, scenario.seed);
    let sites = Sites::new(&simulation.sites());
    let mut arrived = Arrived::new(Limits {
        held_ms: HELD_MS,
        ..Limits::UNBOUNDED
    });
    let mut caches: BTreeMap<Region, (PairCache, Option<PairModel>)> = BTreeMap::new();
    let (Some(first), Some(last)) = (arrivals.first(), arrivals.last()) else {
        return Err("no arrivals".into());
    };
    let measured_from = first.at_ms + TRAILING_WINDOW_MS + REFIT_EVERY_MS;
    let (mut gather_ns, mut read_ns, mut fit_ns) = (0u128, 0u128, 0u128);
    let (mut refits, mut points) = (0usize, 0usize);
    // Each measured refit's points and whole cost, nanoseconds.
    let mut samples: Vec<(f64, f64)> = Vec::new();
    let mut next = 0;
    let mut now = first.at_ms.next_multiple_of(STEP_MS);
    while now <= last.at_ms {
        while let Some(arrival) = arrivals.get(next).filter(|arrival| arrival.at_ms <= now) {
            arrived.admit(arrival.batch, arrival.at_ms, &arrival.receptions);
            next += 1;
        }
        arrived.seal(now);
        if now.is_multiple_of(REFIT_EVERY_MS) {
            let trailing = Trailing {
                span_ms: TRAILING_WINDOW_MS as u32,
                ..Trailing::fitted_at(now)
            };
            for area in sites.areas().map(|(area, _)| *area).collect::<Vec<_>>() {
                let (cache, warm) = caches.entry(area).or_default();
                let started = Instant::now();
                let Some(inputs) = arrived.area_inputs_over(area, &sites, trailing) else {
                    continue;
                };
                let gathered = started.elapsed().as_nanos();
                let Ok(fitted) = pair::fit(&inputs, warm.as_ref(), cache) else {
                    continue;
                };
                if now >= measured_from {
                    gather_ns += gathered;
                    read_ns += u128::from(fitted.stats.read_ns);
                    fit_ns += u128::from(fitted.stats.fit_ns);
                    refits += 1;
                    points += inputs.sync.len();
                    samples.push((
                        inputs.sync.len() as f64,
                        (gathered + u128::from(fitted.stats.read_ns + fitted.stats.fit_ns)) as f64,
                    ));
                }
                *warm = Some(fitted.model);
            }
        }
        now += STEP_MS;
    }
    let memos = caches
        .iter()
        .filter_map(|(area, (cache, _))| {
            let (_, members) = sites.areas().find(|(of, _)| *of == area)?;
            Some(cache.bytes() / members.len().max(1))
        })
        .max()
        .unwrap_or(0);
    let n = samples.len() as f64;
    let (mean_x, mean_y) = (
        samples.iter().map(|s| s.0).sum::<f64>() / n,
        samples.iter().map(|s| s.1).sum::<f64>() / n,
    );
    let slope = samples
        .iter()
        .map(|s| (s.0 - mean_x) * (s.1 - mean_y))
        .sum::<f64>()
        / samples.iter().map(|s| (s.0 - mean_x).powi(2)).sum::<f64>();
    let intercept = mean_y - slope * mean_x;
    let per = |ns: u128| ns as f64 / refits.max(1) as f64 / 1e6;
    eprintln!(
        "REFIT {refits} refits, {:.0} points a refit: gather {:.3} ms, read {:.3} ms, fit {:.3} \
         ms a refit; a refit {:.1} ns a point plus {:.3} ms; memos {memos} bytes a receiver",
        points as f64 / refits.max(1) as f64,
        per(gather_ns),
        per(read_ns),
        per(fit_ns),
        slope,
        intercept / 1e6,
    );
    assert!(refits > 0, "no refit measured");
    Ok(())
}
