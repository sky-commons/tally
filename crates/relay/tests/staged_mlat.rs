//! The hosted MLAT's invariants on the staged relay's own threads (RFC-0181, "Invariants the tests
//! hold", 1 to 3 and 7): the relay holds MLAT's raw once, in its raw shards, taken there by the
//! ingest workers and sealed from them, and its provisional state in address shards; the host steps
//! by the stamp watermark the products seal by, asked as the network task asks it, on a thread of
//! its own, never waited on step by step, only kept within its limits of the watermark
//! (`PROVISIONAL_BEHIND` and `STEPS_BEHIND`), past which a host sheds whole steps (`mlat_host`, Behind: what a host that cannot keep up does,
//! counted, and asserted here never to happen). The same stamped trace makes the same clock models,
//! positions and provisional positions, byte for byte, on 1, 2 and 8 ingest workers and as many MLAT
//! threads, with delays injected inside every stage of the host and between the batches, and they
//! are what the reference engine, holding all the raw itself and driven in line on the same steps,
//! makes of it (`tally_mlat::replay`). At capacity the same receivers are refused, whole, whatever
//! the order the descriptions came in and however they raced.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tally_relay::hub::{Description, Hub, Inbound, Origin};
use tally_relay::ingest::{Stamp, Threads};
use tally_relay::mlat_host::{
    HostedMlat, MlatHost, MlatReport, PROVISIONAL_BEHIND, STEP_MS, Stage,
};
use tally_wire::{Identity, Location, PublicKey, ReceiverInfo, Record, Region, Regions};

type Result<T = ()> = std::result::Result<T, String>;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The areas within about 150 km of the simulator's centre, where its receivers and aircraft are.
fn mlat_areas() -> Result<Regions> {
    let (lat, lon) = tally_mlat_solver::sim::CENTRE;
    let mut areas = Vec::new();
    for north in -2..=2 {
        for east in -2..=2 {
            let location = Location {
                lat_e7: ((lat + f64::from(north) * 0.6) * 1e7) as i32,
                lon_e7: ((lon + f64::from(east) * 1.0) * 1e7) as i32,
                alt_m: 0,
                precision_m: 0,
            };
            let area = Region::containing(&location, tally_wire::rendezvous::AREA_RESOLUTION)
                .map_err(text)?;
            areas.push(area);
        }
    }
    Ok(Regions::new(areas))
}

const MLAT_BOOT: u64 = 0xb007;

fn mlat_settings(threads: usize) -> tally_mlat::engine::Settings {
    tally_mlat::engine::Settings {
        regions: Regions::default(),
        settle_ms: tally_relay::mlat_host::SETTLE_MS,
        threads,
        capacity: tally_mlat::engine::Capacity::default(),
    }
}

/// How the receivers' descriptions before the first batch reach a relay in `mlat_run_with` (those
/// after it reach the host at their stamps, as the relay stamps them).
#[derive(Clone, Copy, Debug)]
enum Describing {
    /// In the trace's order, or reversed.
    Before { reversed: bool },
    /// From several threads at once, each pausing pseudorandomly between them: an interleaving
    /// nobody chose.
    Racing { seed: u64 },
}

/// Hands every description of `arrivals` that comes before the first batch to `hub` as
/// `describing` says (the rest come at their stamps, `mlat_run_with`).
fn describe_all(hub: &Arc<Hub>, arrivals: &[(u64, Record)], describing: Describing) -> Result {
    let mut infos: Vec<ReceiverInfo> = arrivals
        .iter()
        .take_while(|(_, record)| !matches!(record, Record::Batch(_)))
        .filter_map(|(_, record)| match record {
            Record::ReceiverInfo(info) => Some(info.clone()),
            _ => None,
        })
        .collect();
    let publish = |hub: &Hub, info: &ReceiverInfo| -> Result {
        let content = info.content().map_err(text)?;
        hub.publish_info(
            1,
            info.clone(),
            info.receiver().map_err(text)?,
            content.issued_ms,
            content.location,
            true,
        );
        Ok(())
    };
    match describing {
        Describing::Before { reversed } => {
            if reversed {
                infos.reverse();
            }
            for info in &infos {
                publish(hub, info)?;
            }
        }
        Describing::Racing { seed } => {
            const RACERS: usize = 4;
            std::thread::scope(|scope| -> Result {
                let handles: Vec<_> = (0..RACERS)
                    .map(|racer| {
                        let infos = &infos;
                        let publish = &publish;
                        scope.spawn(move || -> Result {
                            for (n, info) in infos.iter().enumerate().skip(racer).step_by(RACERS) {
                                let pause = (n as u64 ^ seed).wrapping_mul(2_654_435_761) % 700;
                                std::thread::sleep(Duration::from_micros(pause));
                                publish(hub, info)?;
                            }
                            Ok(())
                        })
                    })
                    .collect();
                for handle in handles {
                    handle.join().map_err(|_| "a racer panicked".to_owned())??;
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

/// A pseudorandom pause of up to `most` microseconds, the `n`th of `seed`'s.
fn pause(seed: u64, n: u64, most: u64) -> Duration {
    let mixed = (n ^ seed.rotate_left(17))
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .rotate_left(29);
    Duration::from_micros(mixed % most.max(1))
}

/// Delays injected inside the host (`HostedMlat::delaying`) and between the batches handed in:
/// none, or pseudorandom ones from a seed.
#[derive(Clone, Copy, Debug)]
enum Delays {
    None,
    Seeded(u64),
}

/// What a staged relay on `threads` hosting MLAT for `areas` (on `settings`) signs from `arrivals`,
/// on the real concurrent path: the descriptions handed in as `describing` says, then each step's
/// batches (each stamped when it arrived) handed to the ingest workers and every worker ticked to
/// the step, never waiting for them, only for the host to be within its limits of the next
/// (`PROVISIONAL_BEHIND`, `STEPS_BEHIND`; a host further behind sheds, which a relay's real-time watermark gives it the seconds
/// not to); meanwhile another thread asks the host with the products' watermark as the network
/// task does, never waiting for it either. Only at the end is the host waited on, once. Its records, provisional ones apart from the rest, each encoded in order; its
/// report; and the receivers whose raw it held.
fn mlat_run_with(
    arrivals: &[(u64, Record)],
    areas: &Regions,
    threads: Threads,
    settings: tally_mlat::engine::Settings,
    describing: Describing,
    delays: Delays,
) -> Result<(Signed, MlatReport, Vec<PublicKey>)> {
    let hub = Arc::new(Hub::clocked(8, Arc::new(|| 0)).staged(threads)?);
    let host = Arc::new(HostedMlat::new(
        Identity::from_seed([5; 32]),
        MLAT_BOOT,
        settings,
    )?);
    if let Delays::Seeded(seed) = delays {
        let count = Arc::new(AtomicU64::new(0));
        host.delaying(Arc::new(move |stage: Stage| {
            let n = count.fetch_add(1, Ordering::Relaxed);
            let most = match stage {
                // An ingest worker held up on its way to the host (the message exchange pushing
                // back on `route`).
                Stage::Offer => 400,
                Stage::Provisional | Stage::Seal | Stage::Window => 30_000,
            };
            std::thread::sleep(pause(seed, n, most));
        }));
    }
    hub.network()
        .host_mlat(Arc::clone(&host) as Arc<dyn MlatHost>);
    host.set_areas(areas.clone(), Vec::new());
    describe_all(&hub, arrivals, describing)?;
    let first = arrivals.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = arrivals.last().map_or(0, |(at, _)| *at) + 60_000;
    let last_step = until / STEP_MS * STEP_MS;
    let published: Mutex<Vec<Record>> = Mutex::new(Vec::new());
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| -> Result {
        // The network task's ask: the products' watermark, as it stands, every few milliseconds.
        let asker = scope.spawn(|| {
            let mut n = 0;
            while !done.load(Ordering::SeqCst) {
                let watermark = hub.network().products.watermark_ms();
                let records = host.take_published(watermark);
                if let Ok(mut published) = published.lock() {
                    published.extend(records);
                }
                n += 1;
                let most = match delays {
                    Delays::None => 2_000,
                    Delays::Seeded(seed) => 2_000 + pause(seed, n, 8_000).as_micros() as u64,
                };
                std::thread::sleep(Duration::from_micros(most));
            }
        });
        let mut next = 0;
        let mut step = (first / STEP_MS + 1) * STEP_MS;
        // The host's tighter limit: its provisional steps' (`PROVISIONAL_BEHIND`, below
        // `STEPS_BEHIND`). A step handed in once every part of the one this many steps before it
        // has reported finds at most that many not started behind the one running, so nothing is
        // shed.
        let ahead = (PROVISIONAL_BEHIND as u64 + 1) * STEP_MS;
        let since = Instant::now();
        while step <= until {
            // Within the host's limits (`PROVISIONAL_BEHIND` steps, the tighter, and
            // `STEPS_BEHIND`), as a real-time watermark keeps it.
            while step > host.stepped_ms().max(first / STEP_MS * STEP_MS) + ahead {
                if since.elapsed() > Duration::from_secs(300) {
                    return Err(format!(
                        "the hosted MLAT stepped to {}, {step} handed in",
                        host.stepped_ms()
                    ));
                }
                std::thread::sleep(Duration::from_micros(200));
            }
            while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at < step) {
                // A description after the first batch, stamped when it came, handed in as a link
                // hands one in: through the ingest stage, on its receiver's worker among its
                // batches, stamped there (`Hub::describe`); it takes effect at its step.
                if let Record::ReceiverInfo(info) = record
                    && next > 0
                    && arrivals[..next]
                        .iter()
                        .any(|(_, record)| matches!(record, Record::Batch(_)))
                {
                    if let Delays::Seeded(seed) = delays {
                        std::thread::sleep(pause(seed, next as u64, 200));
                    }
                    let content = info.content().map_err(text)?;
                    hub.describe(Description {
                        source: 2,
                        info: info.clone(),
                        receiver: info.receiver().map_err(text)?,
                        issued_ms: content.issued_ms,
                        place: content.location,
                        publishing: false,
                        stamp: Some(Stamp {
                            stamp_ms: *at,
                            ingest_seq: next as u64,
                        }),
                        in_flight: hub.in_flight_of(info.as_bytes().len()),
                    });
                }
                if let Record::Batch(batch) = record {
                    if let Delays::Seeded(seed) = delays {
                        std::thread::sleep(pause(seed, next as u64, 200));
                    }
                    let in_flight = hub.in_flight_for(batch);
                    hub.ingest(Inbound {
                        source: 2,
                        batch: batch.clone(),
                        origin: Origin::Elsewhere,
                        verify: true,
                        stamp: Some(Stamp {
                            stamp_ms: *at,
                            ingest_seq: next as u64,
                        }),
                        in_flight,
                        refusal: None,
                    });
                }
                next += 1;
            }
            // Everything stamped before the step is handed in: every worker ticks to it.
            hub.advance(step);
            step += STEP_MS;
        }
        let started = Instant::now();
        let mut failed = None;
        while host.stepped_ms() < last_step || host.in_flight() > 0 {
            if started.elapsed() > Duration::from_secs(300) {
                failed = Some(format!(
                    "the hosted MLAT stepped to {} of {last_step}; the products' watermark is {}",
                    host.stepped_ms(),
                    hub.network().products.watermark_ms()
                ));
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        done.store(true, Ordering::SeqCst);
        asker.join().map_err(|_| "the asker panicked".to_owned())?;
        failed.map_or(Ok(()), Err)
    })?;
    let mut published = published.into_inner().map_err(text)?;
    published.extend(host.take_signed());
    // The receivers whose raw the engine held, by the sealed bins it kept.
    let sealed = host.sealed_bins().ok_or("no sealed bins")?;
    let mut held: Vec<PublicKey> = sealed
        .bins(i64::MIN, i64::MAX)
        .iter()
        .flat_map(|bin| bin.receivers.clone())
        .collect();
    held.sort_unstable();
    held.dedup();
    Ok((encoded(&published), host.report(), held))
}

/// Records as bytes, in order: provisional positions, and the rest.
type Signed = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Each record's bytes, provisional positions apart from the rest, each in order.
fn encoded(records: &[Record]) -> Signed {
    let mut provisional = Vec::new();
    let mut rest = Vec::new();
    for record in records {
        let mut bytes = Vec::new();
        if record.encode(&mut bytes).is_err() {
            continue;
        }
        if matches!(record, Record::Provisional(_)) {
            provisional.push(bytes);
        } else {
            rest.push(bytes);
        }
    }
    (provisional, rest)
}

/// RFC-0181 §3, §4, §5 and invariants 1 to 3: the same stamped trace makes the same clock models,
/// positions and provisional positions, byte for byte, on 1, 2 and 8 ingest workers and as many
/// MLAT threads, with and without delays injected inside every stage of the host (an offer held up
/// on its way, a provisional step, a seal and a window step each slowed by up to 30 ms) and between
/// the batches, the host asked by the watermark on a thread of its own and never waited on step by
/// step (only kept within its limits of it); and they are what the reference engine makes of
/// the same raw on the same steps (`tally_mlat::replay`). Nothing is refused, shed or let go on the
/// way.
#[test]
fn hosted_mlat_makes_the_same_bytes_on_any_threads_with_any_delays_and_the_reference_engines()
-> Result {
    use tally_mlat::replay::{arrivals, replay, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let delivered = arrivals(&mut simulation, 3)?;
    let areas = mlat_areas()?;
    let run = |ingest: usize, message: usize, delays: Delays| -> Result<Signed> {
        let (signed, report, _) = mlat_run_with(
            &delivered,
            &areas,
            Threads { ingest, message },
            mlat_settings(ingest),
            Describing::Before { reversed: false },
            delays,
        )?;
        assert_eq!(
            (
                report.refused,
                report.overflowed,
                report.steps_discarded,
                report.ingest_errors,
                report.steps_shed,
                report.provisional_steps_shed,
                report.shed,
                report.provisional_models_late,
                report.waiting_dropped
            ),
            (0, 0, 0, 0, 0, 0, 0, 0, 0),
            "{ingest} threads, {delays:?}: {report:?}"
        );
        Ok(signed)
    };
    let one = run(1, 1, Delays::None)?;
    assert!(!one.0.is_empty(), "no provisional positions");
    let positions = one
        .1
        .iter()
        .filter_map(|bytes| Record::decode(bytes).ok().and_then(|(record, _)| record))
        .filter(|record| matches!(record, Record::Positions(_)))
        .count();
    assert!(positions > 0, "no positions");
    for (ingest, message, delays) in [
        (2, 2, Delays::None),
        (8, 8, Delays::None),
        (8, 3, Delays::None),
        (1, 1, Delays::Seeded(1)),
        (2, 2, Delays::Seeded(2)),
        (8, 8, Delays::Seeded(3)),
    ] {
        let many = run(ingest, message, delays)?;
        assert_eq!(
            one.1, many.1,
            "{ingest} ingest threads, {delays:?}: models and positions differ"
        );
        assert_eq!(
            one.0, many.0,
            "{ingest} ingest threads, {delays:?}: provisionals differ"
        );
    }
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine =
        tally_mlat::engine::Engine::new(Identity::from_seed([5; 32]), MLAT_BOOT, mlat_settings(2));
    engine.set_scope(tally_mlat::area::border_band(&areas), areas.clone());
    let reference: Vec<Record> = replay(&mut engine, &delivered, STEP_MS, until)?
        .into_iter()
        .filter(|(at, _)| *at >= first)
        .map(|(_, record)| record)
        .collect();
    let reference = encoded(&reference);
    assert_eq!(
        one.1, reference.1,
        "models and positions differ from the reference"
    );
    assert_eq!(one.0, reference.0, "provisionals differ from the reference");
    Ok(())
}

/// RFC-0181 §9 and invariant 1 at capacity: a relay whose MLAT seats fewer receivers than are
/// described refuses the same ones, whole, whatever order the descriptions came in, however they
/// raced, and on any number of threads, with delays or none: the best ranked are seated
/// (`tally_mlat::intake::Seats`: taking part first, then the draw under the relay's secret,
/// `tally_mlat::intake::draw`, never the key itself, which a feeder could grind), every other one
/// refused and counted, and the same records signed byte for byte.
#[test]
fn at_capacity_the_same_receivers_are_refused_whatever_the_order_and_the_threads() -> Result {
    use tally_mlat::replay::{arrivals, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let delivered = arrivals(&mut simulation, 3)?;
    let areas = mlat_areas()?;
    let mut keys: Vec<PublicKey> = delivered
        .iter()
        .filter_map(|(_, record)| match record {
            Record::ReceiverInfo(info) => info.receiver().ok(),
            _ => None,
        })
        .collect();
    // Every receiver of the trace takes part (they are all inside the areas), so the seats go by
    // the draw alone.
    keys.sort_unstable_by_key(|key| (tally_mlat::intake::draw(key), *key));
    // Two seats short: the two with the worst draws are refused.
    const SHORT: usize = 2;
    assert!(keys.len() > SHORT + 3, "{} receivers", keys.len());
    let seats = keys.len() - SHORT;
    let mut seated = keys[..seats].to_vec();
    seated.sort_unstable();
    let settings = |threads: usize| tally_mlat::engine::Settings {
        capacity: tally_mlat::engine::Capacity {
            receivers: seats,
            rates: tally_mlat_solver::held::Rates::MEASURED,
        },
        ..mlat_settings(threads)
    };
    let mut runs = Vec::new();
    for (ingest, describing, delays) in [
        (1, Describing::Before { reversed: false }, Delays::None),
        (2, Describing::Before { reversed: true }, Delays::None),
        (8, Describing::Before { reversed: false }, Delays::Seeded(4)),
        (1, Describing::Racing { seed: 1 }, Delays::None),
        (2, Describing::Racing { seed: 2 }, Delays::Seeded(5)),
        (8, Describing::Racing { seed: 3 }, Delays::None),
    ] {
        let threads = Threads {
            ingest,
            message: ingest,
        };
        let (signed, report, held) = mlat_run_with(
            &delivered,
            &areas,
            threads,
            settings(ingest),
            describing,
            delays,
        )?;
        assert_eq!(
            report.receivers_refused, SHORT as u64,
            "{ingest} threads, {describing:?}, {delays:?}: {report:?}"
        );
        assert_eq!(
            (
                report.steps_shed,
                report.provisional_steps_shed,
                report.shed,
                report.provisional_models_late,
                report.waiting_dropped
            ),
            (0, 0, 0, 0, 0),
            "{ingest} threads, {describing:?}, {delays:?}: {report:?}"
        );
        assert_eq!(
            held, seated,
            "{ingest} threads, {describing:?}, {delays:?}: other receivers held"
        );
        runs.push((ingest, describing, delays, signed));
    }
    let (_, _, _, first) = &runs[0];
    assert!(!first.0.is_empty(), "no provisional positions");
    for (ingest, describing, delays, signed) in &runs[1..] {
        assert_eq!(
            first, signed,
            "{ingest} threads, {describing:?}, {delays:?}: the records differ"
        );
    }
    Ok(())
}

/// RFC-0181 §4 and invariant 2 for descriptions (item 13 of the sweep): a receiver described again
/// midway (out of the areas, so it stops taking part, and back ten seconds later) and one whose
/// first description comes halfway in (its batches before it waiting, those that waited too long
/// let go), each description stamped when it came and taking effect at the step after, make the
/// same clock models, positions and provisional positions on 1, 2 and 8 ingest workers, with
/// delays inside every stage of the host and between the batches, as the reference engine driven
/// in line makes of them (`tally_mlat::replay`); and other bytes than the same trace with no
/// change.
#[test]
fn descriptions_midway_make_the_same_bytes_with_any_delays_and_the_reference_engines() -> Result {
    use tally_mlat::replay::{arrivals, described_midway, replay, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let plain = arrivals(&mut simulation, 3)?;
    let delivered = described_midway(&simulation, &plain)?;
    let areas = mlat_areas()?;
    let run = |delivered: &[(u64, Record)], ingest: usize, delays: Delays| -> Result<Signed> {
        let (signed, report, _) = mlat_run_with(
            delivered,
            &areas,
            Threads {
                ingest,
                message: ingest,
            },
            mlat_settings(ingest),
            Describing::Before { reversed: false },
            delays,
        )?;
        assert_eq!(
            (
                report.steps_shed,
                report.provisional_steps_shed,
                report.shed,
                report.steps_discarded,
                report.provisional_models_late,
                report.waiting_dropped
            ),
            (0, 0, 0, 0, 0, 0),
            "{ingest} threads, {delays:?}: {report:?}"
        );
        assert!(report.orphans_expired > 0, "{report:?}");
        Ok(signed)
    };
    let one = run(&delivered, 1, Delays::None)?;
    for (ingest, delays) in [
        (2, Delays::Seeded(6)),
        (8, Delays::Seeded(7)),
        (8, Delays::None),
    ] {
        let many = run(&delivered, ingest, delays)?;
        assert_eq!(one.1, many.1, "{ingest} threads, {delays:?}: models differ");
        assert_eq!(
            one.0, many.0,
            "{ingest} threads, {delays:?}: provisionals differ"
        );
    }
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine =
        tally_mlat::engine::Engine::new(Identity::from_seed([5; 32]), MLAT_BOOT, mlat_settings(2));
    engine.set_scope(tally_mlat::area::border_band(&areas), areas.clone());
    let reference: Vec<Record> = replay(&mut engine, &delivered, STEP_MS, until)?
        .into_iter()
        .filter(|(at, _)| *at >= first)
        .map(|(_, record)| record)
        .collect();
    let reference = encoded(&reference);
    assert_eq!(one.1, reference.1, "models differ from the reference");
    assert_eq!(one.0, reference.0, "provisionals differ from the reference");
    let unchanged = mlat_run_with(
        &plain,
        &areas,
        Threads {
            ingest: 1,
            message: 1,
        },
        mlat_settings(1),
        Describing::Before { reversed: false },
        Delays::None,
    )?;
    assert_ne!(
        one.1, unchanged.0.1,
        "the descriptions midway changed nothing"
    );
    Ok(())
}
