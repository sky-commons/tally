#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use std::sync::{Arc, OnceLock};

use tally_mlat_solver::sim;
use tally_wire::observation_set::Relation;
use tally_wire::{Identity, Record, Signer};

use super::*;
use crate::engine::{Capacity, Engine, STEP_MS, Settings, Step};
use crate::replay::{replay, scenario};

/// The simulated scenario every engine test replays: long enough for trailing windows to fill.
const SECONDS: f64 = 45.0;

/// How long after its first batch arrives a cold engine publishes its first fix, at most: its
/// first model is fitted once sync raw spans a knot interval (`MODEL_KNOT`, the least a clock's
/// rate is fitted over, `sync::FitError`), at an edge `FIT_LAG` below the step's clock; then its
/// transmissions fall due a settle later, at the next step. From then on a transmission's first
/// fix comes in seconds (`fixes_come_within_seconds_of_their_transmissions`).
const WARM_UP_MS: u64 = tally_wire::budget::FIT_LAG_MS
    + tally_wire::budget::MODEL_KNOT
        .span::<tally_wire::clocks::Judged>()
        .ms()
    + crate::engine::SETTLE_MS
    + STEP_MS;

/// The latencies of first fixes of transmissions sent once a cold engine had warmed up
/// ([`WARM_UP_MS`] after the first transmission any fix is of), within `span_ms` of then.
fn warmed(firsts: &[(u64, u64)], span_ms: u64) -> Vec<u64> {
    let start = firsts.iter().map(|(sent, _)| *sent).min().unwrap_or(0);
    let from = start + WARM_UP_MS;
    firsts
        .iter()
        .filter(|(sent, _)| *sent >= from && *sent - from < span_ms)
        .map(|(_, ms)| *ms)
        .collect()
}
const SEED: u64 = 11;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn signer() -> Signer {
    Signer::new(Identity::from_seed([4; 32]), Arc::new(|| true))
}

fn settings(threads: usize) -> Settings {
    Settings {
        regions: Regions::default(),
        threads,
        capacity: Capacity::default(),
    }
}

/// The simulation and its records as they reach the engine.
fn delivered() -> Result<(sim::Simulation, Vec<(u64, Record)>), String> {
    let mut simulation = sim::run(&scenario(SEED, SECONDS));
    let records = sim::arrived_records(&mut simulation, SEED).map_err(text)?;
    Ok((simulation, records))
}

fn until(records: &[(u64, Record)]) -> u64 {
    records.last().map_or(0, |(at, _)| *at) + 2 * STEP_MS
}

fn run(
    threads: usize,
    records: &[(u64, Record)],
    signer: &Signer,
) -> Result<Vec<(u64, Step)>, String> {
    let mut engine = Engine::new(9, settings(threads));
    replay(&mut engine, records, signer, until(records))
}

/// A replay: its simulation and every step that published, with its time.
type Replayed = (sim::Simulation, Vec<(u64, Step)>);

/// One replay on one thread, shared by the tests that only read it.
fn baseline() -> Result<&'static Replayed, String> {
    static RUN: OnceLock<Result<Replayed, String>> = OnceLock::new();
    RUN.get_or_init(|| {
        let (simulation, records) = delivered()?;
        let steps = run(1, &records, &signer())?;
        Ok((simulation, steps))
    })
    .as_ref()
    .map_err(Clone::clone)
}

fn bytes_of(steps: &[(u64, Step)]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    steps
        .iter()
        .map(|(at, step)| {
            let mut bytes = Vec::new();
            for record in step.records() {
                record.encode(&mut bytes).map_err(text)?;
            }
            Ok((*at, bytes))
        })
        .collect()
}

/// Every raw fix of a step's records, with its step's time.
fn fixes_of(steps: &[(u64, Step)]) -> Result<Vec<(u64, tally_wire::Fix)>, String> {
    let mut out = Vec::new();
    for (at, step) in steps {
        for fix in &step.fixes {
            for one in fix.raw.fixes().map_err(text)?.fixes {
                out.push((*at, one));
            }
        }
    }
    Ok(out)
}

/// The engine's output is a function of what arrived and when, never of how its work was split:
/// one thread, three and eight sign the same records, byte for byte.
#[test]
fn any_split_of_threads_signs_the_same_bytes() -> Result<(), String> {
    let (_, records) = delivered()?;
    let signer = signer();
    let one = bytes_of(&run(1, &records, &signer)?)?;
    assert!(
        one.iter().any(|(_, bytes)| !bytes.is_empty()),
        "the replay published nothing"
    );
    for threads in [3, 8] {
        assert_eq!(
            bytes_of(&run(threads, &records, &signer)?)?,
            one,
            "{threads} threads"
        );
    }
    Ok(())
}

/// A step's records carry every model before any fix, so a fix never arrives before the model it
/// cites; each fix record is followed by its tagged twin, numbered next, holding as many fixes;
/// every fix cites a model this step or an earlier one carried; and no model is sent twice (one
/// refit every second step is solved under at two steps, published at the first,
/// `Held::published`).
#[test]
fn a_step_sends_its_models_first_then_each_fix_beside_its_twin() -> Result<(), String> {
    let (_, steps) = baseline()?;
    let mut fixes = 0;
    let mut models: std::collections::BTreeSet<Hash> = std::collections::BTreeSet::new();
    for (_, step) in steps {
        let records = step.records();
        let first_fix = records
            .iter()
            .position(|record| matches!(record, Record::Positions(_)))
            .unwrap_or(records.len());
        assert!(
            records[first_fix..]
                .iter()
                .all(|record| matches!(record, Record::Positions(_))),
            "a model after a fix"
        );
        for model in &step.models {
            assert!(models.insert(model.id), "a model sent twice");
            let edges = step
                .models
                .iter()
                .filter(|other| other.area == model.area && other.edge_ms == model.edge_ms)
                .count();
            assert_eq!(edges, 1, "two models of one area and edge");
        }
        for pair in records[first_fix..].chunks(2) {
            let [Record::Positions(raw), Record::Positions(tagged)] = pair else {
                return Err("a fix record without its twin".to_owned());
            };
            assert!(raw.is_fix() && !raw.is_tagged());
            assert!(tagged.is_tagged());
            assert_eq!(tagged.sequence(), raw.sequence() + 1);
            let raw = raw.fixes().map_err(text)?;
            let tagged = tagged.tagged_fixes().map_err(text)?;
            assert_eq!(raw.fixes.len(), tagged.fixes.len());
            for (raw, tagged) in raw.fixes.iter().zip(&tagged.fixes) {
                assert!(
                    raw.models.iter().all(|id| models.contains(id)),
                    "a fix citing a model not sent"
                );
                assert_eq!(raw.models, tagged.models);
            }
            fixes += raw.fixes.len();
        }
    }
    assert!(fixes > 0, "no fixes to check");
    Ok(())
}

/// A transmission is solved from what had arrived about a second after its first reception, and
/// solved again, under a later step, once a reception that came late joins it: the later fix
/// considered a superset of the earlier one.
#[test]
fn a_late_reception_is_solved_again_into_a_superset() -> Result<(), String> {
    let (simulation, mut records) = delivered()?;
    let feeds = simulation.feeds().map_err(text)?;
    let late = feeds.first().ok_or("no receivers")?.identity.public();
    for (at, record) in &mut records {
        if let Record::Batch(batch) = record
            && batch.receiver().ok() == Some(late)
        {
            *at += 2_000;
        }
    }
    records.sort_by_key(|(at, _)| *at);
    let fixes = fixes_of(&run(1, &records, &signer())?)?;
    let grew = fixes.iter().any(|(earlier_at, earlier)| {
        fixes.iter().any(|(later_at, later)| {
            later_at > earlier_at
                && later.address == earlier.address
                && later.considered().relation(earlier.considered()) == Relation::Superset
                && later
                    .considered()
                    .receptions()
                    .iter()
                    .any(|reception| reception.receiver == late)
        })
    });
    assert!(
        grew,
        "no transmission was solved again with its late reception"
    );
    Ok(())
}

/// No fix is carried past its model's edge by more than `MAX_CARRY` (RFC-0174, the carry bound),
/// and the report's carry histogram counts every fix solved.
#[test]
fn no_fix_is_carried_past_max_carry() -> Result<(), String> {
    let (_, steps) = baseline()?;
    let mut fixes = 0;
    // Every model sent so far: a fix cites one this step or an earlier one sent.
    let mut edges: BTreeMap<Hash, u64> = BTreeMap::new();
    for (_, step) in steps {
        edges.extend(step.models.iter().map(|model| (model.id, model.edge_ms)));
        for fix in &step.fixes {
            for one in fix.raw.fixes().map_err(text)?.fixes {
                let edge = one
                    .models
                    .iter()
                    .map(|id| edges.get(id).ok_or("a fix citing a model not sent"))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .min()
                    .ok_or("a fix citing no model")?;
                assert!(
                    one.transmitted.unix_ms <= edge + MAX_CARRY_MS,
                    "carried {} ms",
                    one.transmitted.unix_ms.saturating_sub(*edge)
                );
                fixes += 1;
            }
        }
        assert_eq!(step.report.carry.iter().sum::<usize>(), step.report.solved);
    }
    assert!(fixes > 0, "no fixes to check");
    Ok(())
}

/// Each transmission's fixes: fixes of one aircraft and message sent within milliseconds of each
/// other (fixes of one transmission by different engines agree to milliseconds; repeats
/// of a message are a second apart). The transmit time and the steps that published a fix of it,
/// ascending.
fn transmissions(steps: &[(u64, Step)]) -> Result<Vec<(u64, Vec<u64>)>, String> {
    let mut fixes: Vec<(u32, Vec<u8>, u64, u64)> = fixes_of(steps)?
        .into_iter()
        .map(|(at, fix)| {
            let message = fix.considered().message().to_vec();
            (fix.address, message, fix.transmitted.unix_ms, at)
        })
        .collect();
    fixes.sort_unstable();
    let mut out: Vec<(u32, Vec<u8>, u64, Vec<u64>)> = Vec::new();
    for (address, message, sent, at) in fixes {
        match out.last_mut() {
            Some((last, bytes, first, steps))
                if *last == address && *bytes == message && sent <= *first + 20 =>
            {
                steps.push(at);
            }
            _ => out.push((address, message, sent, vec![at])),
        }
    }
    Ok(out
        .into_iter()
        .map(|(_, _, sent, mut steps)| {
            steps.sort_unstable();
            (sent, steps)
        })
        .collect())
}

/// The most published fixes any one reception was considered by: how many times the engine
/// solved what it heard (module docs, How many).
fn most_considering(steps: &[(u64, Step)]) -> Result<usize, String> {
    let mut receptions: Vec<tally_wire::observation_set::Reception> = fixes_of(steps)?
        .into_iter()
        .flat_map(|(_, fix)| fix.considered().receptions().to_vec())
        .collect();
    receptions.sort_unstable();
    Ok(receptions
        .chunk_by(|a, b| a == b)
        .map(<[_]>::len)
        .max()
        .unwrap_or(0))
}

/// When each transmission was first published, after its transmission: in milliseconds from the
/// transmission to the step that first published it. An upper bound on first arrival to fix, since
/// no reception arrives before it was sent.
fn first_fixes(steps: &[(u64, Step)]) -> Result<Vec<(u64, u64)>, String> {
    Ok(transmissions(steps)?
        .into_iter()
        .map(|(sent, steps)| (sent, steps[0].saturating_sub(sent)))
        .collect())
}

/// The median and the 95th percentile of `latencies`.
fn spread(mut latencies: Vec<u64>) -> Result<(u64, u64), String> {
    if latencies.is_empty() {
        return Err("no fixes".to_owned());
    }
    latencies.sort_unstable();
    Ok((
        latencies[latencies.len() / 2],
        latencies[latencies.len() * 95 / 100],
    ))
}

/// Fixes come in seconds: once the engine has warmed up ([`WARM_UP_MS`]), each transmission is
/// first published within about two seconds of when it was sent (a feeder's seal, its path,
/// `SETTLE_MS` and the step), and every solve the engine attempts verifies. Measured 2026-10-26 on
/// this replay, 5 s spans past the warm-up: medians of 1.2 to 1.4 s, 95th percentiles of 1.7 to
/// 2.7 s (2026-10-24, before the fit lag and the knot interval's least span, and over the whole
/// replay: 1.04 s and 1.83 s).
#[test]
fn fixes_come_within_seconds_of_their_transmissions() -> Result<(), String> {
    let (_, steps) = baseline()?;
    let (median, p95) = spread(warmed(&first_fixes(steps)?, u64::MAX))?;
    assert!(median <= 1_500, "median {median} ms");
    assert!(p95 <= 2_500, "p95 {p95} ms");
    for (_, step) in steps {
        assert_eq!(step.report.unpublished, 0, "{:?}", step.report);
    }
    Ok(())
}

/// Receivers described when the feed starts take part from their first batch, though their first
/// batches came before their descriptions took effect: the first fixes come by the warm-up
/// ([`WARM_UP_MS`], 9.1 s; measured 8 s), never a trailing window later, and the transmissions
/// sent in the ten seconds after it are fixed as soon as later ones (a relay hosting MLAT, fed
/// from the start, as `tally_relay`'s feeders test feeds it). Before batches before a description
/// were held, no member's raw was whole over a window for its first 20 s, and the first fix of
/// this replay came 22 s in.
#[test]
fn receivers_take_part_from_their_first_batch() -> Result<(), String> {
    let seed = 31;
    let mut simulation = sim::run(&sim::Scenario {
        duration_s: 60.0,
        modes_aircraft: 16,
        ..sim::Scenario::new(seed)
    });
    let records = sim::arrived_records(&mut simulation, seed).map_err(text)?;
    let start = records.first().map_or(0, |(at, _)| *at);
    let steps = run(4, &records, &signer())?;
    let first = steps.first().map_or(u64::MAX, |(at, _)| *at);
    assert!(
        first <= start + WARM_UP_MS,
        "first fix {} ms in",
        first - start
    );
    let (median, p95) = spread(warmed(&first_fixes(&steps)?, 10_000))?;
    assert!(median <= 1_500 && p95 <= 2_500, "{median} {p95}");
    Ok(())
}

/// What a relay asks of a peer's fix (`Engine::heard`, `Engine::verify`): an engine verifies its
/// own fixes against what arrived at it, and holds every reception they considered; an engine
/// that knows the receivers and holds none of their raw cannot judge them, and says so rather
/// than refusing them.
#[test]
fn an_engine_judges_a_fix_by_what_arrived_at_it() -> Result<(), String> {
    let (_, records) = delivered()?;
    let mut engine = Engine::new(9, settings(1));
    let steps = replay(&mut engine, &records, &signer(), until(&records))?;
    // The same receivers described, none of their batches held.
    let mut described = Engine::new(9, settings(1));
    for (at, record) in &records {
        if crate::intake::SiteRecord::of(record).is_some() {
            described.ingest_record(record, tally_wire::clocks::recorded::aligned(*at))?;
        }
    }
    let mut judged = 0;
    let sent: BTreeMap<Hash, &crate::engine::SignedModel> = steps
        .iter()
        .flat_map(|(_, step)| step.models.iter())
        .map(|model| (model.id, model))
        .collect();
    for (_, step) in steps.iter().rev().take(3) {
        for fix in &step.fixes {
            for one in fix.raw.fixes().map_err(text)?.fixes.iter().take(2) {
                let models: Vec<Arc<crate::fix::Held>> = one
                    .models
                    .iter()
                    .map(|id| {
                        sent.get(id)
                            .map(|model| Arc::clone(&model.model))
                            .ok_or("a fix citing a model not sent")
                    })
                    .collect::<Result<_, _>>()?;
                assert_eq!(
                    engine.verify(&models, &tally_mlat_solver::Stated::of(one)),
                    Some(true)
                );
                assert_eq!(
                    described.verify(&models, &tally_mlat_solver::Stated::of(one)),
                    None
                );
                let hash = tally_mlat_solver::obs::message_hash(one.considered().message());
                for reception in one.considered().receptions() {
                    let id = tally_mlat_solver::ObservationId {
                        receiver: reception.receiver,
                        epoch: reception.epoch,
                        timestamp: reception.counter,
                        message: hash,
                    };
                    assert!(engine.heard(&id, one.transmitted.unix_ms).is_some());
                }
                judged += 1;
            }
        }
    }
    assert!(judged > 0, "no fixes to judge");
    Ok(())
}

/// A neighbour's model is judged over the raw here only once a fix to publish cites it
/// (`Engine::trust`, module docs of `engine`, Models): an engine that owns one area and holds
/// every other area's models another engine fitted from the same raw, each a step after it was
/// published, verifies those its fixes cite, refutes none, and never judges the rest. The area is
/// the first, by key, whose engine publishes a fix: one most of whose transmissions' hearers are
/// in it (`area::owner`). So that a model no fix can cite is always among them, the first
/// neighbour's model is held only once its edge is past carrying (`usable`), beside the newer.
#[test]
fn a_neighbours_model_is_judged_only_once_a_fix_cites_it() -> Result<(), String> {
    let (_, records) = delivered()?;
    let mut fitter = Engine::new(9, settings(1));
    let fitted = replay(&mut fitter, &records, &signer(), until(&records))?;
    let published: Vec<(u64, tally_wire::Region, Vec<u8>)> = fitted
        .iter()
        .flat_map(|(at, step)| {
            step.models
                .iter()
                .map(|model| (*at, model.area, model.model.bytes.clone()))
        })
        .collect();
    let areas: BTreeSet<tally_wire::Region> = published.iter().map(|(_, area, _)| *area).collect();
    assert!(areas.len() >= 2, "{} areas", areas.len());
    for own in &areas {
        let mut engine = Engine::new(9, settings(1));
        let regions = engine.settings().regions.clone();
        engine.set_scope(regions, tally_wire::Regions::new([*own]));
        let mut held: Vec<Arc<Held>> = Vec::new();
        let mut next = 0;
        let mut stale: Option<Arc<Held>> = None;
        let mut late: Option<Arc<Held>> = None;
        let steps = crate::replay::replay_with(
            &mut engine,
            &records,
            &signer(),
            until(&records),
            |engine, now| {
                while let Some((_, area, bytes)) = published.get(next).filter(|(at, ..)| *at < now)
                {
                    if area != own
                        && let Some(model) = Held::decoded(bytes.clone())
                    {
                        let model = Arc::new(model);
                        if stale.is_none() {
                            stale = Some(Arc::clone(&model));
                            late = Some(Arc::clone(&model));
                        } else {
                            engine.hold(Arc::clone(&model));
                        }
                        held.push(model);
                    }
                    next += 1;
                }
                // Past its edge by more than any fix is carried, and a step's lag besides.
                if let Some(model) =
                    late.take_if(|model| model.edge_ms() + MAX_CARRY_MS + 2 * STEP_MS < now)
                {
                    engine.hold(model);
                }
            },
        )?;
        let mut cited: BTreeSet<Hash> = BTreeSet::new();
        for (_, step) in &steps {
            for fix in &step.fixes {
                for one in fix.raw.fixes().map_err(text)?.fixes {
                    cited.extend(one.models);
                }
            }
        }
        if cited.is_empty() {
            continue;
        }
        let (mut verified, mut unjudged) = (0, 0);
        for model in &held {
            match model.verdict.get() {
                Some(verdict) => {
                    assert!(
                        *verdict,
                        "a neighbour's model fitted from the same raw refuted"
                    );
                    assert!(
                        model.cited.get().is_some(),
                        "a model judged that no fix cited"
                    );
                    verified += 1;
                }
                None => {
                    assert!(
                        !cited.contains(&model.id()),
                        "a published fix cites a model never judged"
                    );
                    unjudged += 1;
                }
            }
        }
        assert!(
            verified > 0,
            "no neighbour's model verified of {}",
            held.len()
        );
        assert!(late.is_none(), "the stale model was never held");
        assert!(
            stale.is_some_and(|model| model.verdict.get().is_none()),
            "a model past carrying judged"
        );
        assert!(
            unjudged > 0,
            "every neighbour's model of {} judged",
            held.len()
        );
        return Ok(());
    }
    Err("no area's engine published a fix".to_owned())
}

/// A signer whose clock does not judge lends no key: the engine steps and signs nothing.
#[test]
fn nothing_is_signed_while_the_clock_does_not_judge() -> Result<(), String> {
    let (_, records) = delivered()?;
    let unsynced = Signer::new(Identity::from_seed([4; 32]), Arc::new(|| false));
    let steps = run(1, &records, &unsynced)?;
    assert!(steps.iter().all(|(_, step)| step.fixes.is_empty()));
    Ok(())
}

/// Packing takes the longest run that signs, numbers records `per_record` apart, and leaves out
/// an item the wire refuses outright.
#[test]
fn packing_takes_the_longest_run_that_signs() {
    let items: Vec<u32> = vec![1, 1, 1, 1, 99, 1, 1, 1];
    let sign = |sequence: u64, run: &[u32]| {
        if run.contains(&99) && run.len() == 1 {
            Err(WireError::Invalid {
                field: "item",
                value: 99,
            })
        } else if run.contains(&99) || run.len() > 3 {
            Err(WireError::Oversize(run.len()))
        } else {
            Ok((sequence, run.to_vec()))
        }
    };
    let packed = pack_with(10, items, 2, |rest: &[u32]| rest.len(), sign);
    let ranges: Vec<_> = packed.iter().map(|(_, range)| range.clone()).collect();
    assert_eq!(ranges, vec![0..3, 3..4, 5..8]);
    let sequences: Vec<u64> = packed.iter().map(|((sequence, _), _)| *sequence).collect();
    assert_eq!(sequences, vec![10, 12, 14]);
}

/// Once the signer's clock stops judging, nothing more is packed.
#[test]
fn packing_stops_when_the_clock_stops_judging() {
    let packed = pack_with(
        0,
        vec![1u32, 2, 3],
        1,
        |_: &[u32]| 1,
        |sequence, run: &[u32]| {
            if sequence == 0 {
                Ok(run.to_vec())
            } else {
                Err(WireError::Unsynced)
            }
        },
    );
    assert_eq!(packed.len(), 1);
}

/// Whole batches are refused against one shared count, in order, and a later small batch that
/// fits is kept after a big one was refused.
#[test]
fn admit_refuses_whole_batches_in_order() -> Result<(), String> {
    let key = Identity::from_seed([5; 32]).public();
    let order = |sequence| Order {
        stamp: tally_wire::clocks::recorded::mono(sequence),
        receiver: key,
        boot: 1,
        sequence,
    };
    let refused = admit(2, [(order(0), 3), (order(1), 6), (order(2), 4)], 10);
    assert_eq!(refused, BTreeSet::from([order(1)]));
    Ok(())
}

/// What a replay cost and gave, per transmission (the measures RFC-0181's plan is sized on).
#[derive(Debug)]
#[allow(dead_code, reason = "read by its `Debug`, printed by the test")]
struct Measured {
    transmissions: usize,
    fixes: usize,
    most_fixes: usize,
    most_considering: usize,
    solves: usize,
    solve_calls: usize,
    solves_per_transmission: f64,
    ns_per_reception: u64,
    unheld: usize,
    unjudged: usize,
    ungrouped: usize,
    unsolved: usize,
    overcarried: usize,
    first_p50: u64,
    first_p95: u64,
    complete_p50: u64,
    complete_p95: u64,
}

fn measured(steps: &[(u64, Step)]) -> Result<Measured, String> {
    let solved = transmissions(steps)?;
    let fixes: usize = solved.iter().map(|(_, steps)| steps.len()).sum();
    let most_fixes = solved
        .iter()
        .map(|(_, steps)| steps.len())
        .max()
        .unwrap_or(0);
    let firsts: Vec<(u64, u64)> = solved
        .iter()
        .map(|(sent, steps)| (*sent, steps[0].saturating_sub(*sent)))
        .collect();
    let (first_p50, first_p95) = spread(warmed(&firsts, u64::MAX))?;
    let (complete_p50, complete_p95) = spread(
        solved
            .iter()
            .filter(|(_, steps)| steps.len() > 1)
            .map(|(sent, steps)| steps[steps.len() - 1].saturating_sub(*sent))
            .collect(),
    )
    .unwrap_or((0, 0));
    let total = |of: fn(&Report) -> usize| steps.iter().map(|(_, step)| of(&step.report)).sum();
    let solves: usize = total(|report| report.solves);
    let receptions: usize = total(|report| report.solve_receptions);
    let solve_ns: u64 = steps.iter().map(|(_, step)| step.report.solve_ns).sum();
    Ok(Measured {
        transmissions: solved.len(),
        fixes,
        most_fixes,
        most_considering: most_considering(steps)?,
        solves,
        solve_calls: total(|report| report.solve_calls),
        solves_per_transmission: solves as f64 / solved.len().max(1) as f64,
        ns_per_reception: solve_ns / receptions.max(1) as u64,
        unheld: total(|report| report.unheld),
        unjudged: total(|report| report.unjudged),
        ungrouped: total(|report| report.ungrouped),
        unsolved: total(|report| report.unsolved),
        overcarried: total(|report| report.overcarried),
        first_p50,
        first_p95,
        complete_p50,
        complete_p95,
    })
}

/// Each transmission is solved twice at most (its fast fix when first seen, its complete one as
/// its set closes, if it grew), however many seals its set is due at: no reception is considered
/// by more than two fixes. Its first fix still comes within seconds, once warmed up. On the
/// feeders test's scene (seed 31, 60 s) and one of 80 receivers, whose transmissions' hearers span
/// several areas.
#[test]
fn a_transmission_is_solved_twice_at_most() -> Result<(), String> {
    for (receivers, seconds) in [(0, 60.0), (80, 40.0)] {
        let seed = 31;
        let base = sim::Scenario::new(seed);
        let mut simulation = sim::run(&sim::Scenario {
            duration_s: seconds,
            modes_aircraft: 16,
            receivers: if receivers == 0 {
                base.receivers
            } else {
                receivers
            },
            ..base
        });
        let records = sim::arrived_records(&mut simulation, seed).map_err(text)?;
        let steps = run(4, &records, &signer())?;
        let measured = measured(&steps)?;
        eprintln!(
            "{} receivers, {seconds} s: {measured:?}",
            simulation.receivers.len()
        );
        assert!(measured.most_considering <= 2, "{measured:?}");
        assert!(measured.first_p95 <= 2_500, "{measured:?}");
    }
    Ok(())
}

/// A step solves about what its neighbours do, however the due sets fell: a Mode S reply repeats
/// its bytes, so one set holds an aircraft's replies for its `JOIN_MS`, and the sets an engine
/// opens together at its start close together for as long as it runs. A transmission is solved
/// again once its own raw has come (`back_off`), not as its set closes, so on seed 31's scene of
/// 40 Mode S-only aircraft over 40 receivers, once warmed up, no step publishes more than three
/// times the median step's fixes (148 at most of a median 102, 2026-10-26). Before, every
/// transmission of a closing set was solved again at its close, and every 11.5 s one step
/// published ten times its neighbours' fixes (558 of a median 54).
#[test]
fn closing_sets_solve_no_burst() -> Result<(), String> {
    let mut simulation = sim::run(&sim::Scenario {
        duration_s: 60.0,
        modes_aircraft: 40,
        receivers: 40,
        ..sim::Scenario::new(31)
    });
    let records = sim::arrived_records(&mut simulation, 31).map_err(text)?;
    let steps = run(4, &records, &signer())?;
    let start = steps.first().map_or(0, |(at, _)| *at);
    let mut fixes: Vec<usize> = steps
        .iter()
        .filter(|(at, _)| *at >= start + WARM_UP_MS)
        .map(|(_, step)| step.report.solved)
        .collect();
    let most = fixes.iter().copied().max().unwrap_or(0);
    fixes.sort_unstable();
    let median = fixes.get(fixes.len() / 2).copied().unwrap_or(0);
    eprintln!(
        "fixes a step: median {median}, most {most}, over {} steps",
        fixes.len()
    );
    assert!(median > 0, "no fixes");
    assert!(
        most <= 3 * median,
        "a step published {most} fixes where the median step published {median}"
    );
    Ok(())
}

/// What solving costs a kept reception (`tally_relay::cores::MLAT_SOLVE_NANOS_PER_KEPT`): the
/// engine on one thread, stepped a second at a time over seed 31's scene with 40 Mode S-only
/// aircraft for 90 s, at 10, 40 and 80 receivers, its solve time over the steps after the first
/// 30 s against the receptions that arrived over them (every one kept: some 100 a receiver a
/// second, below the keeping ceiling). A measurement, not a test: run it in a release build,
/// `bazel run -c opt //crates/mlat:mlat_test -- --ignored --nocapture solve_cost`.
#[test]
#[ignore = "a measurement for the relay's plan, not a check"]
fn solve_cost_per_kept_reception() -> Result<(), String> {
    const FROM_MS: u64 = 30_000;
    for receivers in [10, 40, 80] {
        let mut simulation = sim::run(&sim::Scenario {
            duration_s: 90.0,
            modes_aircraft: 40,
            receivers,
            ..sim::Scenario::new(31)
        });
        let records = sim::arrived_records(&mut simulation, 31).map_err(text)?;
        let start = records.first().map_or(0, |(at, _)| *at);
        let from = start + FROM_MS;
        let received: usize = records
            .iter()
            .filter(|(at, _)| *at >= from)
            .filter_map(|(_, record)| match record {
                Record::Batch(batch) => batch.content().ok().map(|c| c.observations.len()),
                _ => None,
            })
            .sum();
        let steps = run(1, &records, &signer())?;
        let solve_ns: u64 = steps
            .iter()
            .filter(|(at, _)| *at >= from)
            .map(|(_, step)| step.report.solve_ns)
            .sum();
        eprintln!(
            "{receivers} receivers: {} ns a kept reception ({received} received, {:.3} s solving)",
            solve_ns / received.max(1) as u64,
            solve_ns as f64 / 1e9
        );
    }
    Ok(())
}
