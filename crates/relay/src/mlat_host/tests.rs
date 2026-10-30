//! The hosted MLAT makes the reference drive's bytes, steps once a second by the stamps, and holds
//! what it holds within its stores.
#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use super::*;
use crate::budget::PerFeeder;
use tally_mlat::replay::{described_midway, replay, scenario};
use tally_mlat_solver::publish;
use tally_mlat_solver::sim;
use tally_wire::Identity;
use tally_wire::Location;
use tally_wire::clocks::recorded::aligned;
use tally_wire::rendezvous::AREA_RESOLUTION;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

const BOOT: u64 = 0xb007;

fn settings() -> Settings {
    Settings {
        regions: Regions::default(),
        threads: 2,
        capacity: Capacity::default(),
    }
}

fn identity() -> Identity {
    Identity::from_seed([5; 32])
}

/// The engine's signer, on a clock that is always synced.
fn signer() -> Signer {
    crate::signer::synced(identity())
}

/// The areas within about 150 km of the simulator's centre, where its receivers and aircraft are.
fn areas() -> Result<Regions, String> {
    let (lat, lon) = sim::CENTRE;
    let mut areas = Vec::new();
    for north in -2..=2 {
        for east in -2..=2 {
            let location = Location {
                lat_e7: ((lat + f64::from(north) * 0.6) * 1e7) as i32,
                lon_e7: ((lon + f64::from(east) * 1.0) * 1e7) as i32,
                alt_m: 0,
                precision_m: 0,
            };
            areas.push(Region::containing(&location, AREA_RESOLUTION).map_err(text)?);
        }
    }
    Ok(Regions::new(areas))
}

/// What a simulation delivers, in arrival order, and when it ends.
fn delivered(seed: u64, seconds: f64) -> Result<(Vec<(u64, Record)>, u64), String> {
    let mut simulation = sim::run(&scenario(seed, seconds));
    let delivered = sim::arrived_records(&mut simulation, 3).map_err(text)?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 5_000;
    Ok((delivered, until))
}

/// Waits until everything handed to the host is done with: the test runner's deadline fails a host
/// that never settles.
fn quiet(host: &HostedMlat) {
    while host.in_flight() > 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// The steps from `from_ms` to `until_ms`: every multiple of `STEP_MS` after the first.
fn steps(from_ms: u64, until_ms: u64) -> impl Iterator<Item = u64> {
    (from_ms / STEP_MS + 1..=until_ms / STEP_MS).map(|step| step * STEP_MS)
}

/// A record arriving at `at_ms`, as the relay hands it on: a batch as its one decode stamped `at_ms`
/// (one this build cannot read holds nothing), a site-bearing record as it is, and a format 2
/// description not at all (it places nobody).
fn offer(host: &HostedMlat, record: &Record, at_ms: u64) {
    match record {
        Record::Batch(batch) => {
            if let Ok(decoded) = Decoded::from_verified(batch.clone(), aligned(at_ms), 0) {
                host.offer_batch(&decoded, at_ms);
            }
        }
        record => {
            if let Some(site) = SiteRecord::of(record) {
                host.offer_description(&site, at_ms);
            }
        }
    }
}

/// The host asked with the watermark at `step_ms`.
fn ask(host: &HostedMlat, step_ms: u64) -> Vec<Record> {
    host.take_published(crate::products::Watermark::recorded(aligned(step_ms), true))
}

/// Drives the host in line: for each step, what arrived before it is offered stamped when it
/// arrived, then the host is asked with the step as the watermark, then waited on. Every record it
/// published, in order. (The concurrent path, unwaited, is `tests/staged_mlat.rs`'s.)
fn drive(host: &HostedMlat, arrivals: &[(u64, Record)], until_ms: u64) -> Vec<Record> {
    let Some(first) = arrivals.first().map(|(at, _)| *at) else {
        return Vec::new();
    };
    let mut published = Vec::new();
    let mut next = 0;
    for step in steps(first, until_ms) {
        while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at < step) {
            offer(host, record, *at);
            next += 1;
        }
        published.extend(ask(host, step));
        quiet(host);
        published.extend(host.take_signed());
    }
    published
}

/// The reference drive of the same arrivals (`tally_mlat::replay`), scoped to `areas`: every
/// record it published, in order.
fn reference(
    arrivals: &[(u64, Record)],
    areas: &Regions,
    until_ms: u64,
) -> Result<Vec<Record>, String> {
    let mut engine = Engine::new(BOOT, settings());
    engine.set_scope(area::border_band(areas), areas.clone());
    Ok(replay(&mut engine, arrivals, &signer(), until_ms)?
        .iter()
        .flat_map(|(_, step)| step.records())
        .collect())
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

/// THE POINT of one program: the relay's hosted MLAT, fed a feeder's raw as the hub offers it,
/// publishes byte for byte what the reference engine publishes from the same raw on the same steps
/// (`tally_mlat::replay`, the engine driven in line): the same clock models and positions, raw and
/// tagged, signed by the relay's key, in the order a reader needs them (a model before any fix
/// citing it, each fix raw then tagged). Every model it fits is of one of
/// its areas, and every model it publishes is handed to the relay's store of models before the
/// records that carry it are taken.
#[test]
fn a_hosted_engine_publishes_what_the_reference_engine_publishes_from_the_same_raw()
-> Result<(), String> {
    let (delivered, until) = delivered(17, 60.0)?;
    let areas = areas()?;
    let host = HostedMlat::new(signer(), BOOT, settings(), StepClock::KEEPING_UP)?;
    host.set_areas(areas.clone(), Vec::new());
    let hosted = drive(&host, &delivered, until);
    let reference = reference(&delivered, &areas, until)?;
    assert!(
        hosted
            .iter()
            .any(|record| matches!(record, Record::Positions(positions) if positions.is_fix())),
        "no positions"
    );
    assert_eq!(encoded(&hosted)?, encoded(&reference)?);
    let own = host.take_own_models();
    let mut manifests = 0;
    let mut models_seen = std::collections::BTreeSet::new();
    let mut raw_waiting: Option<&tally_wire::Positions> = None;
    for record in &hosted {
        match record {
            Record::ClockModel(manifest) => {
                manifests += 1;
                assert_eq!(manifest.engine().map_err(text)?, identity().public());
                let content = manifest.content(&[]).map_err(text)?;
                let model = publish::decode_pairs(&content.model).map_err(text)?;
                assert!(areas.contains(model.area), "{:?}", model.area);
                models_seen.insert(publish::pair_model_id(&content.model));
            }
            Record::Positions(positions) if !positions.is_tagged() => {
                assert!(raw_waiting.is_none(), "two raw records in a row");
                for fix in positions.fixes().map_err(text)?.fixes {
                    assert!(
                        fix.models.iter().all(|id| models_seen.contains(id)),
                        "a fix before its models"
                    );
                }
                raw_waiting = Some(positions);
            }
            Record::Positions(positions) => {
                let raw = raw_waiting
                    .take()
                    .ok_or("a tagged record with no raw before it")?;
                assert_eq!(
                    positions.tagged_fixes().map_err(text)?.fixes.len(),
                    raw.fixes().map_err(text)?.fixes.len()
                );
            }
            _ => {}
        }
    }
    assert!(raw_waiting.is_none(), "a raw record with no tagged twin");
    assert_eq!(own.len(), manifests);
    assert!(own.iter().all(|own| models_seen.contains(&own.model.id())));
    let report = host.report();
    assert!(report.steps > 0 && report.last_step.is_some(), "{report:?}");
    assert!(report.steps_total.solved > 0, "{report:?}");
    assert!(report.ingested > 0, "{report:?}");
    assert_eq!(
        (
            report.refused,
            report.overflowed,
            report.steps_discarded,
            report.ingest_errors,
            report.descriptions_dropped,
            report.arrived_over,
        ),
        (0, 0, 0, 0, 0, 0),
        "{report:?}"
    );
    // A host that keeps up collapses nothing.
    assert_eq!(
        (
            report.steps_collapsed,
            report.steps_unsynced,
            report.steps_unreserved
        ),
        (0, 0, 0),
        "{report:?}"
    );
    Ok(())
}

/// RFC-0181 §4: a site that moves midway, and one first sent halfway, take effect at the step
/// after their stamps, as in the reference engine, so the same trace makes the same bytes; a batch
/// of a receiver whose site has not taken effect is not used, and counted.
#[test]
fn descriptions_midway_take_effect_at_their_step_as_in_the_reference_engine() -> Result<(), String>
{
    let mut simulation = sim::run(&scenario(17, 60.0));
    let delivered = sim::arrived_records(&mut simulation, 3).map_err(text)?;
    let delivered = described_midway(&simulation, &delivered)?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 5_000;
    let areas = areas()?;
    let host = HostedMlat::new(signer(), BOOT, settings(), StepClock::KEEPING_UP)?;
    host.set_areas(areas.clone(), Vec::new());
    let hosted = drive(&host, &delivered, until);
    assert_eq!(
        encoded(&hosted)?,
        encoded(&reference(&delivered, &areas, until)?)?
    );
    let report = host.report();
    assert!(report.unused > 0, "{report:?}");
    Ok(())
}

/// A relay that solves no area holds nothing and publishes nothing, and its runner is woken by no
/// ask.
#[test]
fn a_relay_that_solves_no_area_publishes_nothing_and_wakes_for_no_ask() -> Result<(), String> {
    let (delivered, until) = delivered(17, 20.0)?;
    let host = HostedMlat::new(signer(), BOOT, settings(), StepClock::KEEPING_UP)?;
    assert!(drive(&host, &delivered, until).is_empty());
    let report = host.report();
    assert_eq!((report.offered, report.steps), (0, 0), "{report:?}");
    assert_eq!(host.shared.ticked_ms.load(Ordering::SeqCst), 0);
    Ok(())
}

/// No area at all drops the engine and its raw; the first area after none starts a new engine
/// under the next boot id, whose records never reuse the first's (key, boot, sequence).
#[test]
fn a_relay_that_stops_solving_an_area_publishes_nothing_more_and_starts_afresh()
-> Result<(), String> {
    let (delivered, until) = delivered(17, 60.0)?;
    let areas = areas()?;
    let host = HostedMlat::new(signer(), BOOT, settings(), StepClock::KEEPING_UP)?;
    let sites: Vec<SiteRecord> = delivered
        .iter()
        .filter_map(|(_, record)| SiteRecord::of(record))
        .collect();
    host.set_areas(areas.clone(), sites.clone());
    let half = delivered.len() / 2;
    let split = delivered[half].0;
    let first = drive(&host, &delivered[..half], split);
    assert!(!first.is_empty());
    host.set_areas(Regions::default(), Vec::new());
    quiet(&host);
    assert!(lock(&host.shared.engine).is_none(), "the engine stayed");
    assert!(ask(&host, split + STEP_MS).is_empty());
    host.set_areas(areas, sites);
    let second = drive(&host, &delivered[half..], until);
    let boots: std::collections::BTreeSet<u64> = second
        .iter()
        .filter_map(|record| match record {
            Record::Positions(positions) => Some(positions.boot_id()),
            _ => None,
        })
        .collect();
    assert_eq!(boots, [BOOT + 1].into_iter().collect());
    Ok(())
}

fn config(line: &str) -> Result<Config, String> {
    Config::from_args(line.split_whitespace().map(str::to_owned))?
        .ok_or_else(|| "no config".to_owned())
}

/// The relay hosts MLAT when its duties are on, unless told `--no-mlat`, on the threads its
/// cores' plan gives MLAT, and never with `--no-relay-duties`.
#[test]
fn mlat_is_hosted_with_relay_duties_on_the_planned_threads_and_never_without_duties()
-> Result<(), String> {
    let base = "--key k --max-upload 8Mbit/s";
    let budget = Budget::of_memory(
        64 << 30,
        crate::budget::Plan::planned(true).with_cores(Some(32)),
    );
    let host = |line: &str| -> Result<Option<HostedMlat>, String> {
        host_for(&config(line)?, signer(), 1, &budget)
    };
    let hosted = host(base)?.ok_or("not hosted")?;
    assert_eq!(usize::from(hosted.cores()), budget.mlat_threads());
    assert!(budget.mlat_threads() > 1, "{}", budget.mlat_threads());
    assert!(host(&format!("{base} --no-mlat"))?.is_none());
    assert!(host(&format!("{base} --no-relay-duties"))?.is_none());
    // The thread count is the plan's, not an operator's.
    assert!(config(&format!("{base} --mlat-threads 3")).is_err());
    Ok(())
}

/// RFC-0181 §9, §10: the engine seats exactly the pool the relay's budget plans for MLAT
/// (`Budget::mlat_seats`, at most the feeders it admits), and the stores reserved cover what that
/// pool holds: the arrived pool at what a holder keeps of each seat at most in one pool for the
/// relay, its tables, and the receptions on their way in, in `Arrived`; a step's working set
/// and its positions in `Engine`.
#[test]
fn the_seats_are_the_planned_pool_and_what_they_hold_is_the_stores() {
    let per_feeder = PerFeeder::planned(true);
    for feeders in [1, 7, 30_000] {
        let budget = Budget::new(per_feeder.total() * feeders, per_feeder);
        assert_eq!(budget.ceiling(), feeders);
        let capacity = capacity(&budget);
        assert_eq!(capacity.receivers, budget.mlat_seats());
        assert!(capacity.receivers <= feeders);
        let seats = capacity.receivers.max(1);
        let pool = tally_mlat_solver::arrived::Limits::for_receivers(seats, capacity.rates).bytes;
        let arrived = budget.store_bytes(Store::Arrived);
        assert!(
            arrived >= pool + seats * PENDING_BYTES_PER_SEAT,
            "{arrived} {pool}"
        );
        assert!(arrived >= seats * arrived_bytes_per_seat());
        // The inboxes hold every admitted feeder's raw on its way in, seated or not.
        assert!(budget.store_bytes(Store::Inbox) >= feeders * INBOX_BYTES_PER_FEEDER);
        assert!(
            budget.store_bytes(Store::Engine)
                >= seats * (STEP_BYTES_PER_SEAT + PUBLISHED_BYTES_PER_SEAT)
        );
    }
    // The pool is planned at what a holder keeps of a receiver at most (every seat at its
    // ceiling in the load test, `arrived::Rates::MEASURED`), a fraction of what it may send.
    let measured = Rates::MEASURED;
    assert_eq!(
        measured.kept_per_s,
        tally_mlat_solver::arrived::KEPT_CEILING_PER_S
    );
    assert!(measured.kept_per_s * 2 < measured.ceiling_per_s);
}

/// A step's records are queued whole or refused whole, counted: a model's records never go
/// without its fixes' store having room, and into an empty queue a step's records are taken
/// whatever their size, so no step is refused forever.
#[test]
fn a_steps_records_are_published_whole_or_refused_whole() -> Result<(), String> {
    let (delivered, until) = delivered(17, 40.0)?;
    let areas = areas()?;
    let records = reference(&delivered, &areas, until)?;
    let (models, fixes): (Vec<Record>, Vec<Record>) = records.into_iter().partition(is_model);
    assert!(!models.is_empty() && !fixes.is_empty());
    let one_step: Vec<Record> = models
        .iter()
        .take(1)
        .chain(fixes.iter().take(2))
        .cloned()
        .collect();
    let bytes: usize = one_step.iter().map(Record::encoded_len).sum();
    let gauges = Gauges {
        arrived: Gauge::unlimited(Store::Arrived),
        inbox: Gauge::unlimited(Store::Inbox),
        engine: Gauge::new(Store::Engine, bytes),
        models: Gauge::new(Store::Models, bytes),
    };
    let host = HostedMlat::charging(signer(), BOOT, settings(), gauges, StepClock::KEEPING_UP)?;
    let shared = &host.shared;
    assert!(shared.publish(one_step.clone(), Vec::new()));
    // The stores hold no second step beside the first: refused whole, counted.
    assert!(!shared.publish(one_step.clone(), Vec::new()));
    assert_eq!(host.report().overflowed, one_step.len() as u64);
    assert_eq!(host.take_signed().len(), one_step.len());
    // Taken, the charges go: the next step fits again.
    assert!(shared.publish(one_step.clone(), Vec::new()));
    host.take_signed();
    // Larger than its stores, into an empty queue: taken all the same.
    let all: Vec<Record> = models.iter().chain(&fixes).cloned().collect();
    assert!(shared.publish(all.clone(), Vec::new()));
    assert_eq!(host.take_signed().len(), all.len());
    Ok(())
}

/// RFC-0181 §9, §10: steps the watermark passes while the one before ran are taken and described
/// in their turn and stepped as one with the newest, counted, so a host behind solves what is due
/// a second late and never runs a queue of steps; a watermark taken unsynced steps nothing, and
/// the steps it passed are collapsed into the one it resyncs at, counted apart.
#[test]
fn steps_passed_while_one_ran_are_collapsed_into_the_newest_and_counted() -> Result<(), String> {
    let (delivered, until) = delivered(17, 40.0)?;
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let host = HostedMlat::new(signer(), BOOT, settings(), StepClock::KEEPING_UP)?;
    host.set_areas(areas()?, Vec::new());
    let mut next = 0;
    let mut asked = 0;
    for (index, step) in steps(first, until).enumerate() {
        while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
            offer(&host, record, *at);
            next += 1;
        }
        // The host is asked every third step only: two of every three are collapsed.
        if index % 3 == 2 {
            ask(&host, step);
            quiet(&host);
            asked += 1;
        }
    }
    let report = host.report();
    assert_eq!(report.steps, asked, "{report:?}");
    assert!(report.steps_collapsed >= 2 * (asked - 1), "{report:?}");
    assert!(report.steps_total.solved > 0, "{report:?}");
    assert_eq!(report.steps_unsynced, 0);
    // Unsynced for a minute: nothing steps, and the steps passed are collapsed into one, counted
    // apart.
    let resync = until + 60_000;
    assert!(
        host.take_published(crate::products::Watermark::recorded(
            aligned(until + 1_000),
            false
        ))
        .is_empty()
    );
    ask(&host, resync);
    quiet(&host);
    let after = host.report();
    assert_eq!(after.steps, report.steps + 1, "{after:?}");
    assert!(after.steps_unsynced >= 59, "{after:?}");
    Ok(())
}

/// A receiver that re-signs its site in a loop holds one description a step, the newest it
/// signed, whatever order its records came in; an older one never takes a newer's place.
#[test]
fn a_receiver_re_signing_in_a_loop_holds_one_description_a_step_and_the_newest_applies()
-> Result<(), String> {
    let receiver = Identity::from_seed([9; 32]);
    let site = |issued_ms: u64| -> Result<SiteRecord, String> {
        let content = tally_wire::ReceiverSiteContent {
            issued_ms,
            location: Location {
                lat_e7: 521_000_000,
                lon_e7: 51_000_000,
                alt_m: 10,
                precision_m: 0,
            },
            clock: tally_wire::Clock::Unknown,
        };
        Ok(SiteRecord::Site(
            tally_wire::ReceiverSite::sign(&receiver, &content).map_err(text)?,
        ))
    };
    let mut descriptions = Descriptions {
        pending: Tree::new(),
        records: 0,
        most: 4,
        asked_ms: 0,
        charge: Gauge::unlimited(Store::Arrived).empty(),
    };
    let key = receiver.public();
    for issued_ms in [5, 3, 9, 7, 9] {
        assert!(descriptions.hold(2_000, key, 1_500, &site(issued_ms)?));
    }
    assert_eq!(descriptions.pending.len(), 1);
    assert!(descriptions.hold(3_000, key, 2_500, &site(11)?));
    assert_eq!(
        descriptions.charge.bytes(),
        descriptions.pending.bytes() + descriptions.records
    );
    let taken = descriptions.take_through(2_000);
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].1.content().map_err(text)?.issued_ms, 9);
    assert_eq!(descriptions.pending.len(), 1);
    // Past what the seats may hold waiting, a new one is refused, counted by the host.
    for (step, issued_ms) in [(4_000, 12), (5_000, 13), (6_000, 14)] {
        assert!(descriptions.hold(step, key, step - 500, &site(issued_ms)?));
    }
    assert!(!descriptions.hold(7_000, key, 6_500, &site(15)?));
    Ok(())
}

/// The inboxes are charged what they allocate before they allocate it (each reception's message
/// too), measured by the counting allocator on this thread, and refuse a batch whole past their
/// store, counted.
#[test]
fn an_inbox_is_charged_what_it_allocates_and_refuses_past_its_store() -> Result<(), String> {
    let (delivered, _) = delivered(17, 20.0)?;
    let batches: Vec<Arc<Decoded>> = delivered
        .iter()
        .filter_map(|(at, record)| match record {
            Record::Batch(batch) => Decoded::from_verified(batch.clone(), aligned(*at), 0).ok(),
            _ => None,
        })
        .collect();
    let gauge = Gauge::unlimited(Store::Inbox);
    let mut inbox = Inbox {
        heard: Deque::new(),
        receptions: 0,
        charge: gauge.empty(),
    };
    let heard_of = |batch: &Arc<Decoded>| {
        let (mut receptions, _) = receptions_of(batch);
        receptions.shrink_to_fit();
        Heard {
            generation: 1,
            order: Order::of(batch),
            batch: batch_id(batch),
            wall_ms: batch.wall_ms(),
            at: batch.at(),
            receptions,
        }
    };
    let made: Vec<Heard> = batches.iter().map(heard_of).collect();
    let base = tally_counting::Counting::live();
    let held: usize = made.iter().map(Heard::bytes).sum();
    for heard in made {
        assert!(inbox.push(heard));
    }
    // The receptions moved in were allocated before the base; the deque's own is measured.
    let allocated = usize::try_from(tally_counting::Counting::since(base)).unwrap_or(0) + held;
    assert!(
        inbox.charge.bytes() >= allocated,
        "{} < {allocated}",
        inbox.charge.bytes()
    );
    assert_eq!(inbox.charge.bytes(), inbox.heard.bytes() + inbox.receptions);
    let stamp = batches
        .get(batches.len() / 2)
        .map_or(0, |batch| batch.stamp_ms());
    let taken = inbox.take_before(1, stamp);
    assert!(!taken.is_empty() && taken.iter().all(|heard| heard.order.stamp.ms() < stamp));
    assert_eq!(inbox.charge.bytes(), inbox.heard.bytes() + inbox.receptions);
    // Of another generation, an entry is let go, never handed on.
    inbox.forget_before(2);
    assert!(inbox.heard.is_empty());
    assert_eq!(inbox.charge.bytes(), inbox.heard.bytes());
    // A host whose `Inbox` store has no room refuses every batch whole, counted, but the first:
    // an empty store takes what it is offered (`Gauge::try_charge`), so nothing is refused forever.
    let gauges = Gauges {
        inbox: Gauge::new(Store::Inbox, 0),
        ..Gauges::unlimited()
    };
    let host = HostedMlat::charging(signer(), BOOT, settings(), gauges, StepClock::KEEPING_UP)?;
    host.set_areas(areas()?, Vec::new());
    for batch in batches.iter().take(10) {
        host.offer_batch(batch, batch.stamp_ms());
    }
    assert_eq!(host.report().refused, 9);
    Ok(())
}

/// RFC-0181 §10: a host whose steps run past their budget cuts the receivers of its areas by rank,
/// from `CUT_LEAD_STEPS` past the watermark, published for its peers; the cut seats fewer from its
/// step on, the best ranked few never cut.
#[test]
fn an_overloaded_host_cuts_by_rank_from_a_step_ahead() -> Result<(), String> {
    let (delivered, until) = delivered(17, 30.0)?;
    let overloaded = StepClock::Declared {
        ran_ms: 4 * STEP_BUDGET_MS,
        budget_ms: STEP_BUDGET_MS,
    };
    let host = HostedMlat::new(signer(), BOOT, settings(), overloaded)?;
    host.set_areas(areas()?, Vec::new());
    drive(&host, &delivered, until);
    let cuts = host.take_cuts();
    assert!(!cuts.is_empty(), "no cut");
    assert!(cuts.iter().all(|cut| cut.origin == identity().public()
        && cut.from_ms.is_multiple_of(STEP_MS)
        && cut.below != u128::MAX));
    let report = host.report();
    assert!(report.cuts_decided > 0, "{report:?}");
    assert!(report.seat_cap < report.seat_limit, "{report:?}");
    assert!(report.seats_taken >= MIN_CUT_SEATS.min(report.seats_taken as usize) as u64);
    Ok(())
}

/// RFC-0181 §10, Overload: the governor cuts a host whose steps run past their budget to seats
/// whose steps fit and holds them there, never cutting by half and climbing back on steps its new
/// seats have not reached (the sawtooth of 2026-10-26: 500, 250, 313, 392, 491, 500) nor on one
/// dear step; once its steps run cheap it lifts, a quarter at a time, each lift judged only once
/// the last one's cost is a step's, back to every seat. The host is a step's cost of a fixed part
/// (the aircraft's) and a part each seat's, every thirteenth step dearer than two budgets, a cut
/// costed from a refit after it takes effect and a lift once its seats are fitted
/// (`SEATS_SETTLE_MS`), one change in flight at a time as `Host::judge` holds it. A step that ran
/// past its budget lets the steps it overran pass, and the next takes them in, collapsed
/// (`Host::steps`): judged as each of them, so a host far behind at its start (2,000 seats at 3.3 s
/// a step) is cut within two steps, where judging only the steps run left 2,000 feeders on 16 cores
/// collapsing 106 steps (2026-10-26).
#[test]
fn the_governor_settles_where_its_steps_fit() {
    let total: usize = 2_000;
    // Tenths of a millisecond a seat: 1.6 ms first (562 seats fit a second), then 0.2.
    let cost = |(fixed, per_seat): (u64, u64), seats: usize| fixed + per_seat * seats as u64 / 10;
    let (dear, cheap) = ((100, 16), (50, 2));
    let mut governor = Governor::default();
    let (mut taken, mut costed) = (total, total);
    let mut changes: Vec<(u64, u64, usize)> = Vec::new();
    let mut last_from_ms = 0;
    let mut run: Vec<(usize, u64)> = Vec::new();
    let (mut through, mut taken_in, mut stepped) = (0u64, 1u64, 0u64);
    let mut collapsed = 0u64;
    while through < 600 * STEP_MS {
        through += taken_in * STEP_MS;
        stepped += 1;
        for (seated_at, costed_at, seats) in &changes {
            if *seated_at <= through {
                taken = *seats;
            }
            if *costed_at <= through {
                costed = *seats;
            }
        }
        let mut ran = cost(
            if through <= 300 * STEP_MS {
                dear
            } else {
                cheap
            },
            costed,
        );
        if stepped % 13 == 0 {
            ran = ran.max(2 * STEP_BUDGET_MS + STEP_BUDGET_MS / 2);
        }
        // The steps collapsed into this one ran as it did.
        run.extend((0..taken_in).map(|_| (taken, ran)));
        let took = taken_in;
        collapsed += took - 1;
        taken_in = ran.div_ceil(STEP_BUDGET_MS).max(1);
        if last_from_ms > through {
            continue;
        }
        let seated = Seated {
            taken,
            total,
            floor: MIN_CUT_SEATS,
            cut: taken < total,
        };
        let Some(wanted) = governor.judge(through, ran, took, STEP_BUDGET_MS, seated) else {
            continue;
        };
        let wanted = wanted.min(total);
        if wanted == taken {
            continue;
        }
        let from_ms = (through / STEP_MS + CUT_LEAD_STEPS) * STEP_MS;
        let costed_at = if wanted > taken {
            from_ms + SEATS_SETTLE_MS - tally_wire::budget::REFIT_EVERY_MS
        } else {
            from_ms + tally_wire::budget::REFIT_EVERY_MS
        };
        changes.push((from_ms, costed_at, wanted));
        last_from_ms = from_ms;
        governor.changed(from_ms);
    }
    run.truncate(600);
    // Cut at once at the start: the steps collapsed are the first steps' and the dear ones'.
    assert!(
        collapsed <= 6 + 2 * 600 / 13,
        "{collapsed} collapsed: {run:?}"
    );
    let (dearer, cheaper) = run.split_at(300);
    // Cut, only ever down, and settled with a third of the dear half to spare.
    assert!(
        dearer.windows(2).all(|pair| pair[1].0 <= pair[0].0),
        "{dearer:?}"
    );
    let settled = &dearer[200..];
    assert!(
        settled.iter().all(|(seats, _)| *seats == settled[0].0),
        "{settled:?}"
    );
    let dear_steps = |steps: &[(usize, u64)]| {
        steps
            .iter()
            .filter(|(_, ran)| *ran > STEP_BUDGET_MS)
            .count()
    };
    assert!(
        settled
            .iter()
            .all(|(_, ran)| *ran >= STEP_TARGET_MS / 8 * 7),
        "{settled:?}"
    );
    assert!(
        dear_steps(settled) <= settled.len().div_ceil(13),
        "{settled:?}"
    );
    assert!(settled[0].0 > MIN_CUT_SEATS, "{settled:?}");
    // Lifted, only ever up, every step but the dear ones within its budget, back to every seat.
    assert!(
        cheaper.windows(2).all(|pair| pair[1].0 >= pair[0].0),
        "{cheaper:?}"
    );
    assert!(
        dear_steps(cheaper) <= cheaper.len().div_ceil(13),
        "{cheaper:?}"
    );
    assert_eq!(cheaper.last().map(|(seats, _)| *seats), Some(total));
}

/// The lowest priority Linux has: a thread already there stays (`os::LOWEST_NICE`).
const LOWEST_NICE: libc::c_int = crate::os::LOWEST_NICE;

fn own_nice() -> libc::c_int {
    crate::os::own_nice().unwrap_or(0)
}

/// RFC-0181 §10, "The cores": every MLAT step runs below the stages' priority, so a host short of
/// cores delays MLAT, which collapses, and never raw. Below the relay's own priority, whatever it
/// was started at, at the lowest where that is below it, a runner held there counted.
#[test]
fn every_step_runs_below_the_stages() -> Result<(), String> {
    let (delivered, until) = delivered(17, 20.0)?;
    // The relay started below the default: the runner, started here, inherits it.
    let _ = crate::os::lower_own_nice(3);
    let host = HostedMlat::new(signer(), BOOT, settings(), StepClock::KEEPING_UP)?;
    host.set_areas(areas()?, Vec::new());
    let seen: Arc<Mutex<Vec<libc::c_int>>> = Arc::new(Mutex::new(Vec::new()));
    let seeing = Arc::clone(&seen);
    host.delaying(Arc::new(move |stage: Stage| {
        if stage == Stage::Step {
            lock(&seeing).push(own_nice());
        }
    }));
    drive(&host, &delivered, until);
    let base = own_nice();
    let seen = lock(&seen).clone();
    assert!(!seen.is_empty(), "no step ran");
    assert!(
        seen.iter()
            .all(|nice| *nice == (base + STEPS_NICE).min(LOWEST_NICE)),
        "steps at {seen:?}, the stages at {base}"
    );
    let clipped = u64::from(base + STEPS_NICE > LOWEST_NICE);
    assert_eq!(host.report().priority_unset, clipped);
    Ok(())
}

/// What the child of a panic test is told to panic at.
const PANIC_CHILD: &str = "TALLY_MLAT_HOST_PANIC_CHILD";

/// A host whose step panics.
fn panicking_host() -> Result<(), String> {
    let (delivered, until) = delivered(17, 20.0)?;
    let host = HostedMlat::new(signer(), BOOT, settings(), StepClock::KEEPING_UP)?;
    host.set_areas(areas()?, Vec::new());
    host.delaying(Arc::new(|stage: Stage| {
        assert!(stage != Stage::Step, "a step panics");
    }));
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let mut next = 0;
    for step in steps(first, until) {
        while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < step) {
            offer(&host, record, *at);
            next += 1;
        }
        ask(&host, step);
    }
    let since = std::time::Instant::now();
    while host.in_flight() > 0 && since.elapsed() < std::time::Duration::from_secs(20) {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}

/// MLAT work that panics ends the process, as a panic anywhere in the relay does
/// (`crate::abort_on_any_panic`), whether or not the relay's hook is set: a host whose step
/// panicked never runs on with nothing stepping. Run again as a child of this test, which must end
/// by `SIGABRT`.
#[test]
fn a_panic_in_mlat_work_ends_the_process() -> Result<(), String> {
    if std::env::var_os(PANIC_CHILD).is_some() {
        return panicking_host();
    }
    let status = std::process::Command::new(std::env::current_exe().map_err(text)?)
        .args([
            "--exact",
            "mlat_host::tests::a_panic_in_mlat_work_ends_the_process",
            "--test-threads=1",
        ])
        .env(PANIC_CHILD, "step")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(text)?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGABRT), "{status:?}");
    Ok(())
}

fn area_at(lat_e7: i32, lon_e7: i32) -> Result<Region, String> {
    Region::containing(
        &Location {
            lat_e7,
            lon_e7,
            alt_m: 0,
            precision_m: 0,
        },
        AREA_RESOLUTION,
    )
    .map_err(text)
}

fn cut_of(origin: PublicKey, from_ms: u64, below: u128, area: Region) -> Cut {
    Cut {
        from_ms,
        origin,
        below,
        areas: vec![area],
    }
}

fn origin(seed: u8) -> PublicKey {
    Identity::from_seed([seed; 32]).public()
}

/// RFC-0181 §10: a cut is applied at its stamped step and stands for `CUT_TTL_MS` from it;
/// announced again (refreshed) it stands on, and unannounced it expires, by the stamps alone.
#[test]
fn a_cut_stands_from_its_step_and_expires_unless_announced_again() -> Result<(), String> {
    let area = area_at(515_000_000, -1_000_000)?;
    let who = origin(1);
    let mut cuts = Cuts::default();
    assert_eq!(cuts.offer(&cut_of(who, 10_000, 5, area), 0), Offered::Kept);
    assert!(cuts.cutoffs_at(9_000).is_empty(), "before its step");
    assert_eq!(cuts.cutoffs_at(10_000), vec![(area, 5)]);
    assert_eq!(
        cuts.cutoffs_at(10_000 + CUT_TTL_MS - STEP_MS),
        vec![(area, 5)]
    );
    assert!(cuts.cutoffs_at(10_000 + CUT_TTL_MS).is_empty(), "expired");
    assert_eq!(
        cuts.offer(&cut_of(who, 10_000 + CUT_REFRESH_MS, 5, area), 0),
        Offered::Kept
    );
    let past = 10_000 + CUT_TTL_MS;
    assert_eq!(cuts.cutoffs_at(past), vec![(area, 5)]);
    // Its signer's lifting announcement supersedes its older cut; another signer's does not lift
    // it.
    let other = origin(2);
    cuts.offer(&cut_of(other, 10_000, u128::MAX, area), 0);
    assert_eq!(cuts.cutoffs_at(past), vec![(area, 5)]);
    cuts.offer(&cut_of(who, past, u128::MAX, area), 0);
    assert!(cuts.cutoffs_at(past).is_empty());
    Ok(())
}

/// A cut for a step already applied is kept with the stamp it was signed with: it takes effect at
/// the next step and ends when its stamp says.
#[test]
fn a_late_cut_keeps_its_stamp() -> Result<(), String> {
    let area = area_at(515_000_000, -1_000_000)?;
    let mut cuts = Cuts::default();
    cuts.applied(30_000);
    assert_eq!(
        cuts.offer(&cut_of(origin(1), 25_000, 7, area), 0),
        Offered::Late
    );
    assert_eq!(cuts.cutoffs_at(31_000), vec![(area, 7)]);
    assert!(cuts.cutoffs_at(25_000 + CUT_TTL_MS).is_empty());
    Ok(())
}

/// A stamp a peer signs cannot overflow the table or leave a cut waiting for a step far ahead: off
/// the grid, past `MAX_CUT_FROM_MS`, expired already, or further ahead than `CUT_AHEAD_MS` is
/// refused, with checked arithmetic.
#[test]
fn a_cut_stamped_off_the_grid_expired_or_far_ahead_is_refused() -> Result<(), String> {
    let area = area_at(515_000_000, -1_000_000)?;
    let who = origin(1);
    let mut cuts = Cuts::default();
    for from_ms in [
        u64::MAX,
        u64::MAX - STEP_MS + 1,
        tally_wire::MAX_CUT_FROM_MS + STEP_MS,
        12_345,
    ] {
        assert_eq!(
            cuts.offer(&cut_of(who, from_ms, 1, area), 0),
            Offered::Refused,
            "{from_ms}"
        );
    }
    assert_eq!(
        cuts.offer(&cut_of(who, 10_000, 1, area), 100_000),
        Offered::Refused
    );
    assert_eq!(
        cuts.offer(
            &cut_of(who, 100_000 + CUT_AHEAD_MS + STEP_MS, 1, area),
            100_000
        ),
        Offered::Refused
    );
    assert!(cuts.by_origin.is_empty(), "something was kept");
    assert_eq!(
        cuts.offer(&cut_of(who, 100_000 + CUT_AHEAD_MS, 1, area), 100_000),
        Offered::Kept
    );
    // What was offered before the host knew the stamps, past the horizon, goes when the first
    // step is applied.
    let mut early = Cuts::default();
    early.offer(&cut_of(who, 5_000_000_000_000, 1, area), 0);
    assert_eq!(early.by_origin.len(), 1);
    early.applied(100_000);
    assert!(early.by_origin.is_empty());
    Ok(())
}

/// The table keeps the origins of the best rank, never the first to come: 70 origins offered in
/// any order leave the same 64.
#[test]
fn the_origins_kept_are_the_best_ranked_whatever_order_they_came_in() -> Result<(), String> {
    let area = area_at(515_000_000, -1_000_000)?;
    let origins: Vec<PublicKey> = (0..70u8).map(origin).collect();
    let kept = |order: Vec<&PublicKey>| {
        let mut cuts = Cuts::default();
        for key in order {
            cuts.offer(&cut_of(*key, 10_000, 3, area), 0);
        }
        cuts.by_origin.keys().copied().collect::<Vec<_>>()
    };
    let forward = kept(origins.iter().collect());
    let backward = kept(origins.iter().rev().collect());
    assert_eq!(forward.len(), CUT_ORIGINS);
    assert_eq!(forward, backward);
    let mut ranked = origins.clone();
    ranked.sort_by_key(|key| (tally_mlat::intake::draw(key), *key));
    let mut best: Vec<PublicKey> = ranked[..CUT_ORIGINS].to_vec();
    best.sort_unstable();
    assert_eq!(forward, best);
    Ok(())
}
