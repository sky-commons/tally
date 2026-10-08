//! The staged relay's invariants (RFC-0177, "Invariants the tests hold"), on the relay's own
//! threads: the same stamped trace gives byte-identical products and stream on 1, 2 and 8
//! threads, and byte-identical MLAT (clock models, positions, provisional positions: the raw held
//! once, in the raw shards, sealed from them) which is also what the reference engine makes of
//! the same raw; no consumer reads a clock (delays injected anywhere change nothing); a message heard
//! by many receivers on many workers is kept once a window; each receiver's batches reach a
//! subscriber in admitted order, described first; and what is let go is let go whole, counted.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tally_mlat_solver::modes::{self, LatLon};
use tally_relay::fanout::{Fell, Filter};
use tally_relay::hub::{Hub, Inbound, Item, Origin};
use tally_relay::ingest::{Stamp, Threads};
use tally_wire::batch::{ReceiverInfoContent, format};
use tally_wire::{
    Batch, BatchContent, Clock, Identity, Location, Observation, ReceiverInfo, Record, Streams,
};

type Result<T = ()> = std::result::Result<T, String>;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// 2026-10-04T00:00:00Z.
const BASE_MS: u64 = 1_791_244_800_000;
const FEEDERS: usize = 24;
const SECONDS: u64 = 4;
const AIRCRAFT: u32 = 30;

/// A DF17 airborne position of `address` at `position`.
fn airborne(address: u32, position: LatLon, odd: bool) -> Vec<u8> {
    let (lat_cpr, lon_cpr) = modes::cpr_encode(position, odd);
    let ac13 = modes::encode_ac13_q(35_000).unwrap_or(0);
    let me = modes::encode_airborne_position(11, modes::ac13_to_ac12(ac13), odd, lat_cpr, lon_cpr);
    let mut body = vec![
        (17 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    body.extend_from_slice(&me);
    modes::with_parity(&body, 0)
}

/// What every receiver of an area hears in second `second`: each aircraft's two positions.
fn heard(second: u64, feeder: usize) -> Vec<Observation> {
    let mut heard = Vec::new();
    for address in 0x00a0_0000..0x00a0_0000 + AIRCRAFT {
        let at = LatLon {
            lat_deg: 33.0 + f64::from(address % 40) * 0.02 + (second % 100) as f64 * 1e-3,
            lon_deg: -84.6 + f64::from((address & 0xfff) / 40) * 0.02,
        };
        for odd in [false, true] {
            heard.push(Observation {
                format: format::MODE_S_LONG,
                // Each receiver's own counter: the message is what is the same.
                timestamp: second * 12_000_000 + u64::from(address) + feeder as u64 * 7,
                signal: feeder as u8,
                data: airborne(address, at, odd),
            });
        }
    }
    // And one reply only it heard.
    heard.push(Observation {
        format: format::MODE_S_SHORT,
        timestamp: second,
        signal: 1,
        data: modes::with_parity(&[4 << 3, 0, feeder as u8, second as u8], 0x00f0_0000),
    });
    heard
}

struct Trace {
    relay: Identity,
    feeders: Vec<(Identity, ReceiverInfo, Location)>,
    /// Each batch with its stamp, in the order taken in.
    batches: Vec<(Batch, Stamp)>,
    end_ms: u64,
}

fn trace() -> Result<Trace> {
    let relay = Identity::from_seed([7; 32]);
    let mut feeders = Vec::new();
    for n in 0..FEEDERS {
        let identity = Identity::from_seed([n as u8 + 10; 32]);
        // Two areas.
        let location = if n % 3 == 0 {
            Location {
                lat_e7: 419_000_000,
                lon_e7: -876_000_000,
                alt_m: 0,
                precision_m: 0,
            }
        } else {
            Location {
                lat_e7: 337_000_000,
                lon_e7: -844_000_000,
                alt_m: 0,
                precision_m: 0,
            }
        };
        let info = ReceiverInfo::sign(
            &identity,
            &ReceiverInfoContent {
                issued_ms: BASE_MS,
                location: Some(location),
                clock: Clock::Dump1090,
                software: "trace".to_owned(),
                relays: vec![relay.public()],
            },
        )
        .map_err(text)?;
        feeders.push((identity, info, location));
    }
    let mut batches = Vec::new();
    let mut ingest_seq = 0;
    for second in 0..SECONDS {
        for (n, (identity, _, _)) in feeders.iter().enumerate() {
            let batch = Batch::sign_with(
                identity,
                &BatchContent {
                    boot_id: 1,
                    sequence: second,
                    counter_epoch: 0,
                    wall_ms: BASE_MS + second * 1_000,
                    dropped: 0,
                    previous: [0; 32],
                    observations: heard(second, n),
                },
                tally_wire::Codec::Deflate,
            )
            .map_err(text)?;
            let stamp = Stamp {
                stamp_ms: BASE_MS + second * 1_000 + 10 * n as u64,
                ingest_seq,
            };
            ingest_seq += 1;
            batches.push((batch, stamp));
        }
    }
    Ok(Trace {
        relay,
        feeders,
        batches,
        end_ms: BASE_MS + (SECONDS + 7) * 1_000,
    })
}

/// What a relay made of a trace: its regional records, world parts and deduplicated stream, each
/// as bytes in the order made.
#[derive(Debug, PartialEq, Eq)]
struct Made {
    regional: Vec<Vec<u8>>,
    world: Vec<Vec<u8>>,
    stream: Vec<(u8, Vec<u8>)>,
}

/// A relay on `threads` (its ingest clock stopped, so only the trace's stamps say when), shown the
/// trace: each batch waiting `delay(n)` first.
fn run(trace: &Trace, threads: Threads, delay: impl Fn(usize) -> Duration) -> Result<Made> {
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(|| 0))
            .regional_boot(42)
            .staged(threads),
    );
    hub.network().adopt_identity(trace.relay.clone());
    hub.network().products.set_world(true);
    for (identity, info, location) in &trace.feeders {
        hub.publish_info(
            1,
            info.clone(),
            identity.public(),
            BASE_MS,
            Some(*location),
            true,
        );
    }
    for (n, (batch, stamp)) in trace.batches.iter().enumerate() {
        std::thread::sleep(delay(n));
        hub.ingest(Inbound {
            source: 2,
            batch: batch.clone(),
            origin: Origin::Elsewhere,
            verify: true,
            stamp: Some(*stamp),
            permit: None,
            refusal: None,
        });
    }
    hub.advance(trace.end_ms);
    let products = &hub.network().products;
    let started = Instant::now();
    while products.watermark_ms() < trace.end_ms {
        if started.elapsed() > Duration::from_secs(60) {
            return Err(format!(
                "the products reached {} of {}",
                products.watermark_ms(),
                trace.end_ms
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut made = Made {
        regional: Vec::new(),
        world: Vec::new(),
        stream: Vec::new(),
    };
    for record in products.tick(None) {
        match record {
            Record::RegionalBatch(regional) => made.regional.push(regional.as_bytes().to_vec()),
            Record::WorldPositions(world) => made.world.push(world.as_bytes().to_vec()),
            _ => {}
        }
    }
    let (stream, refused) = hub.take_deduplicated();
    assert_eq!(refused, 0);
    assert_eq!(products.report().epochs_refused, 0);
    made.stream = stream
        .into_iter()
        .map(|observation| (observation.format, observation.data))
        .collect();
    Ok(made)
}

#[test]
fn the_same_stamped_trace_makes_the_same_bytes_on_any_number_of_threads() -> Result {
    let trace = trace()?;
    let one = run(
        &trace,
        Threads {
            ingest: 1,
            message: 1,
        },
        |_| Duration::ZERO,
    )?;
    assert!(!one.regional.is_empty(), "no regional product");
    assert!(!one.world.is_empty(), "no world product");
    assert!(!one.stream.is_empty(), "no deduplicated stream");
    for (ingest, message) in [(2, 2), (8, 8), (8, 3)] {
        let many = run(&trace, Threads { ingest, message }, |_| Duration::ZERO)?;
        assert_eq!(
            one, many,
            "{ingest} ingest and {message} message threads differ"
        );
    }
    Ok(())
}

#[test]
fn delays_injected_between_batches_change_nothing() -> Result {
    let trace = trace()?;
    let threads = Threads {
        ingest: 4,
        message: 4,
    };
    let steady = run(&trace, threads, |_| Duration::ZERO)?;
    // Pseudorandom pauses: the workers, the shards and the sealer each fall behind and catch up
    // at different moments; only the stamps say what is in which epoch.
    let jittered = run(&trace, threads, |n| {
        Duration::from_micros((n as u64).wrapping_mul(2_654_435_761) % 3_000)
    })?;
    assert_eq!(steady.stream, jittered.stream, "the stream differs");
    assert_eq!(steady.regional.len(), jittered.regional.len());
    assert_eq!(
        steady.regional, jittered.regional,
        "the regional product differs"
    );
    assert_eq!(steady.world, jittered.world, "the world differs");
    Ok(())
}

#[test]
fn a_message_heard_by_many_receivers_on_many_workers_is_kept_once_a_window() -> Result {
    let trace = trace()?;
    let made = run(
        &trace,
        Threads {
            ingest: 8,
            message: 8,
        },
        |_| Duration::ZERO,
    )?;
    // Each second: every aircraft's two positions once, and each feeder's own reply once. A
    // position is new each second (the aircraft moved), so nothing is kept twice across them.
    let mut counts: HashMap<&[u8], usize> = HashMap::new();
    for (_, data) in &made.stream {
        *counts.entry(data.as_slice()).or_default() += 1;
    }
    assert!(
        counts.values().all(|count| *count == 1),
        "a message kept twice"
    );
    assert_eq!(
        made.stream.len(),
        SECONDS as usize * (2 * AIRCRAFT as usize + FEEDERS)
    );
    // Each area once per message: two areas hear every position.
    let mut regional = 0;
    for bytes in &made.regional {
        let record = tally_wire::RegionalBatch::from_bytes(bytes.clone()).map_err(text)?;
        regional += record.content().map_err(text)?.observations.len();
    }
    assert_eq!(
        regional,
        SECONDS as usize * (2 * 2 * AIRCRAFT as usize + FEEDERS)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_receivers_batches_reach_a_subscriber_in_order_described_first() -> Result {
    // The ingest clock stopped: signing these batches takes real seconds in a debug build, and
    // a subscriber is let go two seconds of inbound behind, which is not what this reads.
    let hub = Arc::new(Hub::clocked(8, Arc::new(|| 0)).staged(Threads {
        ingest: 8,
        message: 2,
    }));
    let listener = hub.listen(
        999,
        Filter::Subscription(tally_relay::subscription::Subscription {
            streams: Streams::RAW,
            regions: Vec::new(),
        }),
    );
    const RECEIVERS: usize = 40;
    const BATCHES: u64 = 25;
    let receivers: Vec<Identity> = (0..RECEIVERS)
        .map(|n| Identity::from_seed([n as u8 + 100; 32]))
        .collect();
    for sequence in 0..BATCHES {
        for receiver in &receivers {
            if sequence == 0 {
                let info = ReceiverInfo::sign(
                    receiver,
                    &ReceiverInfoContent {
                        issued_ms: 1,
                        location: None,
                        clock: Clock::Dump1090,
                        software: "order".to_owned(),
                        relays: Vec::new(),
                    },
                )
                .map_err(text)?;
                hub.publish_info(1, info, receiver.public(), 1, None, true);
            }
            let batch = Batch::sign(
                receiver,
                &BatchContent {
                    boot_id: 3,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: 0,
                    dropped: 0,
                    previous: [0; 32],
                    observations: heard(sequence, 0),
                },
            )
            .map_err(text)?;
            hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Elsewhere,
                verify: true,
                stamp: None,
                permit: None,
                refusal: None,
            });
        }
    }
    let mut items: Vec<Item> = Vec::new();
    let wanted = RECEIVERS * (BATCHES as usize + 1);
    let deadline = Instant::now() + Duration::from_secs(60);
    while items.len() < wanted {
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(60), listener.recv_many(&mut got, 512))
            .await
            .map_err(|_| "the subscriber stopped hearing".to_owned())?
            .map_err(|fell| format!("{fell:?}"))?;
        items.extend(got);
        if Instant::now() > deadline {
            return Err(format!("heard {} of {wanted}", items.len()));
        }
    }
    let mut seen: HashMap<tally_wire::PublicKey, (bool, Option<u64>)> = HashMap::new();
    for item in &items {
        match &*item.record {
            Record::ReceiverInfo(info) => {
                let key = info.receiver().map_err(text)?;
                seen.entry(key).or_default().0 = true;
            }
            Record::Batch(batch) => {
                let key = batch.receiver().map_err(text)?;
                let (described, last) = seen.entry(key).or_default();
                assert!(*described, "a batch before its receiver's description");
                assert_eq!(
                    batch.sequence(),
                    last.map_or(0, |last| last + 1),
                    "out of order"
                );
                *last = Some(batch.sequence());
            }
            _ => {}
        }
    }
    assert_eq!(seen.len(), RECEIVERS);
    assert!(seen.values().all(|(_, last)| *last == Some(BATCHES - 1)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscriber_that_falls_behind_is_let_go_whole_and_the_stream_refused_whole_counted()
-> Result {
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(|| 0))
            .queue_bytes(256 * 1024)
            .staged(Threads {
                ingest: 2,
                message: 2,
            }),
    );
    let raw = || {
        Filter::Subscription(tally_relay::subscription::Subscription {
            streams: Streams::RAW,
            regions: Vec::new(),
        })
    };
    let stalled = hub.listen(998, raw());
    let receiver = Identity::from_seed([3; 32]);
    let seconds = 20u64;
    for second in 0..seconds {
        let batch = Batch::sign(
            &receiver,
            &BatchContent {
                boot_id: 4,
                sequence: second,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: heard(second, 1),
            },
        )
        .map_err(text)?;
        hub.ingest(Inbound {
            source: 1,
            batch,
            origin: Origin::Elsewhere,
            verify: true,
            stamp: Some(Stamp {
                stamp_ms: BASE_MS + second * 1_000,
                ingest_seq: second,
            }),
            permit: None,
            refusal: None,
        });
    }
    let end = BASE_MS + (seconds + 1) * 1_000;
    hub.advance(end);
    let started = Instant::now();
    while hub.network().products.watermark_ms() < end {
        if started.elapsed() > Duration::from_secs(60) {
            return Err("the epochs never closed".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The stalled subscriber was let go whole: told it fell behind, holding nothing.
    let mut got = Vec::new();
    assert!(matches!(
        stalled.try_recv_many(&mut got, 1_000_000),
        Err(Fell::Behind(_))
    ));
    assert_eq!(stalled.queued_bytes(), 0);
    // Nobody took the deduplicated stream: the epochs past what is held were refused whole and
    // counted; those held are whole.
    let (stream, refused) = hub.take_deduplicated();
    let per_epoch = 2 * AIRCRAFT as usize + 1;
    assert!(refused > 0);
    assert_eq!(stream.len() % per_epoch, 0);
    assert_eq!(
        stream.len() / per_epoch + refused as usize,
        seconds as usize
    );
    assert_eq!(hub.network().products.report().stream_refused, refused);
    Ok(())
}

/// The areas within about 150 km of the simulator's centre, where its receivers and aircraft are.
fn mlat_areas() -> Result<Vec<tally_wire::Region>> {
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
            let area =
                tally_wire::Region::containing(&location, tally_wire::rendezvous::AREA_RESOLUTION)
                    .map_err(text)?;
            if !areas.contains(&area) {
                areas.push(area);
            }
        }
    }
    Ok(areas)
}

const MLAT_BOOT: u64 = 0xb007;

fn mlat_settings() -> tally_mlat::engine::Settings {
    tally_mlat::engine::Settings {
        regions: Vec::new(),
        settle_ms: tally_relay::mlat_host::SETTLE_MS,
        threads: 2,
        capacity: tally_mlat::engine::Capacity::default(),
    }
}

/// What a staged relay on `threads` hosting MLAT for `areas` signs from `arrivals` (each record
/// at its time, a batch stamped so): every `STEP_MS` of the trace's clock what has arrived is
/// ingested and every worker has taken it, then the host is asked and waited on. Its records,
/// provisional ones apart from the rest, each encoded in order.
fn mlat_run(
    arrivals: &[(u64, Record)],
    areas: &[tally_wire::Region],
    threads: Threads,
) -> Result<Signed> {
    use tally_relay::mlat_host::{HostedMlat, MlatHost, STEP_MS};
    let hub = Arc::new(Hub::clocked(8, Arc::new(|| 0)).staged(threads));
    let host = Arc::new(HostedMlat::new(
        Identity::from_seed([5; 32]),
        MLAT_BOOT,
        mlat_settings(),
    ));
    hub.network()
        .host_mlat(Arc::clone(&host) as Arc<dyn MlatHost>);
    host.set_areas(areas.to_vec(), Vec::new());
    let first = arrivals.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = arrivals.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut published = Vec::new();
    let mut next = 0;
    let mut now = first;
    while now <= until {
        while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at <= now) {
            match record {
                Record::ReceiverInfo(info) => {
                    // A description reaches the shards at once: what was handed in before it is
                    // taken first, as one connection's records are.
                    hub.flush();
                    let content = info.content().map_err(text)?;
                    hub.publish_info(
                        1,
                        info.clone(),
                        info.receiver().map_err(text)?,
                        content.issued_ms,
                        content.location,
                        true,
                    );
                }
                Record::Batch(batch) => {
                    hub.ingest(Inbound {
                        source: 2,
                        batch: batch.clone(),
                        origin: Origin::Elsewhere,
                        verify: true,
                        stamp: Some(Stamp {
                            stamp_ms: *at,
                            ingest_seq: next as u64,
                        }),
                        permit: None,
                        refusal: None,
                    });
                }
                _ => {}
            }
            next += 1;
        }
        hub.advance(now);
        hub.flush();
        published.extend(host.take_published(now));
        let started = Instant::now();
        while host.in_flight() > 0 {
            if started.elapsed() > Duration::from_secs(120) {
                return Err("the hosted MLAT never settled".to_owned());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        published.extend(host.take_signed());
        now += STEP_MS;
    }
    assert_eq!(host.refused(), 0);
    Ok(encoded(&published))
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

/// RFC-0177 §5 and invariant 1: the relay holds MLAT's raw once, in its raw shards, taken there by
/// the ingest workers and sealed from them (`held::Bin::seal_from`), and the hosted engine solves
/// those sealed bins. The same stamped trace makes the same clock models, positions and
/// provisional positions, byte for byte, on 1, 2 and 8 ingest workers, and they are what the
/// reference engine, holding all the raw itself, makes of the same raw at the same clocks
/// (`tally_mlat::replay`).
#[test]
fn hosted_mlat_makes_the_same_bytes_on_any_number_of_threads_and_the_reference_engines() -> Result {
    use tally_mlat::replay::{arrivals, replay, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let delivered = arrivals(&mut simulation, 3)?;
    let areas = mlat_areas()?;
    let one = mlat_run(
        &delivered,
        &areas,
        Threads {
            ingest: 1,
            message: 1,
        },
    )?;
    assert!(!one.0.is_empty(), "no provisional positions");
    let positions = one
        .1
        .iter()
        .filter_map(|bytes| Record::decode(bytes).ok().and_then(|(record, _)| record))
        .filter(|record| matches!(record, Record::Positions(_)))
        .count();
    assert!(positions > 0, "no positions");
    for (ingest, message) in [(2, 2), (8, 3)] {
        let many = mlat_run(&delivered, &areas, Threads { ingest, message })?;
        assert_eq!(
            one.1, many.1,
            "{ingest} ingest threads: models and positions differ"
        );
        assert_eq!(
            one.0, many.0,
            "{ingest} ingest threads: provisionals differ"
        );
    }
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine =
        tally_mlat::engine::Engine::new(Identity::from_seed([5; 32]), MLAT_BOOT, mlat_settings());
    engine.set_scope(tally_mlat::area::border_band(&areas), areas.clone());
    let reference: Vec<Record> = replay(
        &mut engine,
        &delivered,
        tally_relay::mlat_host::STEP_MS,
        until,
    )?
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
