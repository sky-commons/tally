//! The staged relay's invariants (RFC-0181, "Invariants the tests hold"), on the relay's own
//! threads: the same stamped trace gives byte-identical products and stream on 1, 2 and 8
//! threads; no consumer reads a clock (batches stamped by the relay's own ingest clock, with
//! delays injected inside every stage, make the same bytes as with none); a message heard by many
//! receivers on many workers is kept once a window, and copies up to two seconds apart are one;
//! each receiver's batches reach a subscriber in admitted order, described first; and what is let
//! go is let go whole, counted. The hosted MLAT's are in `staged_mlat.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tally_mlat_solver::modes::{self, LatLon};
use tally_relay::fanout::{Fell, Filter};
use tally_relay::hub::{Hub, Inbound, Item, Origin};
use tally_relay::ingest::{Pause, Stage, Stamp, Threads};
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

/// What a relay made of a trace: its regional records, world parts and deduplicated stream's
/// batches, each as signed bytes in the order made.
#[derive(Debug, PartialEq, Eq)]
struct Made {
    regional: Vec<Vec<u8>>,
    world: Vec<Vec<u8>>,
    stream: Vec<Vec<u8>>,
}

/// The deduplicated stream the relay signed since the products were last taken, each batch
/// checked as the relay's own, and how many of its epochs were refused whole so far.
fn stream_of(hub: &Hub) -> Result<(Vec<Observation>, u64)> {
    let products = &hub.network().products;
    let mut stream = Vec::new();
    for record in products.tick(None) {
        if let Record::RelayBatch(batch) = record {
            batch.verify_as_relay().map_err(text)?;
            stream.extend(batch.content().map_err(text)?.observations);
        }
    }
    Ok((stream, products.report().stream_refused))
}

/// The relay's key, the trace's world switched on and its feeders described: as the trace's
/// relay starts.
fn start(hub: &Hub, trace: &Trace) {
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
}

/// A trace's batch, as a link hands it in: stamped `stamp`, or by the ingest clock when `None`.
fn inbound(hub: &Hub, batch: &Batch, stamp: Option<Stamp>) -> Inbound {
    Inbound {
        source: 2,
        batch: batch.clone(),
        origin: Origin::Elsewhere,
        verify: true,
        stamp,
        in_flight: hub.in_flight_for(batch),
        refusal: None,
    }
}

/// Every worker ticks at `end_ms`, and once the products have sealed to it: what they made.
fn made(hub: &Hub, end_ms: u64) -> Result<Made> {
    hub.advance(end_ms);
    let products = &hub.network().products;
    let started = Instant::now();
    while products.watermark_ms() < end_ms {
        if started.elapsed() > Duration::from_secs(60) {
            return Err(format!(
                "the products reached {} of {end_ms}",
                products.watermark_ms()
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
            Record::RelayBatch(batch) => {
                batch.verify_as_relay().map_err(text)?;
                made.stream.push(batch.as_bytes().to_vec());
            }
            _ => {}
        }
    }
    assert_eq!(products.report().stream_refused, 0);
    assert_eq!(products.report().epochs_refused, 0);
    Ok(made)
}

/// A relay on `threads` (its ingest clock stopped, so only the trace's stamps say when), shown the
/// trace: each batch waiting `delay(n)` first.
fn run(trace: &Trace, threads: Threads, delay: impl Fn(usize) -> Duration) -> Result<Made> {
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(|| 0))
            .product_boots(42)
            .staged(threads)?,
    );
    start(&hub, trace);
    for (n, (batch, stamp)) in trace.batches.iter().enumerate() {
        std::thread::sleep(delay(n));
        hub.ingest(inbound(&hub, batch, Some(*stamp)));
    }
    made(&hub, trace.end_ms)
}

/// A relay on `threads` whose batches are stamped by its own ingest clock, never by the trace:
/// the clock reads each second of the trace while that second's batches are handed in (and
/// moves on once the ingest stage has taken them all, as a second passes once its batches have
/// arrived), and every stage is held up inside by `pause`: a worker between a batch's stamp and
/// its routing, a message thread before each envelope, the sealer and its pool before each
/// command and job.
fn run_clocked(trace: &Trace, threads: Threads, pause: Option<Pause>) -> Result<Made> {
    let clock = Arc::new(AtomicU64::new(BASE_MS));
    let reading = Arc::clone(&clock);
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(move || reading.load(Ordering::SeqCst)))
            .product_boots(42)
            .staged_pausing(threads, pause)?,
    );
    start(&hub, trace);
    for (second, batches) in trace.batches.chunks(FEEDERS).enumerate() {
        clock.store(BASE_MS + second as u64 * 1_000 + 100, Ordering::SeqCst);
        for (batch, _) in batches {
            hub.ingest(inbound(&hub, batch, None));
        }
        hub.flush();
    }
    clock.store(trace.end_ms, Ordering::SeqCst);
    made(&hub, trace.end_ms)
}

/// Pseudorandom delays inside every stage, up to `most_us` microseconds each, differing by stage
/// and by call: the workers, the shards and the sealer each fall behind and catch up at different
/// moments.
fn jitter(most_us: u64) -> Pause {
    let calls = Arc::new(AtomicU64::new(0));
    Arc::new(move |stage| {
        let n = calls.fetch_add(1, Ordering::Relaxed);
        let salt = match stage {
            Stage::Ingest => 1,
            Stage::Message => 2,
            Stage::Sealer => 3,
        };
        let us = n.wrapping_mul(2_654_435_761).wrapping_add(salt * 40_503) % most_us;
        std::thread::sleep(Duration::from_micros(us));
    })
}

#[test]
fn the_same_stamped_trace_makes_the_same_bytes_on_any_number_of_threads() -> Result {
    let trace = trace()?;
    let one = run(
        &trace,
        Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        },
        |_| Duration::ZERO,
    )?;
    assert!(!one.regional.is_empty(), "no regional product");
    assert!(!one.world.is_empty(), "no world product");
    assert!(!one.stream.is_empty(), "no deduplicated stream");
    for (ingest, message, seal) in [(2, 2, 2), (8, 8, 8), (8, 3, 5), (2, 4, 1)] {
        let threads = Threads {
            ingest,
            message,
            seal,
        };
        let many = run(&trace, threads, |_| Duration::ZERO)?;
        assert_eq!(
            one, many,
            "{ingest} ingest, {message} message and {seal} seal threads differ"
        );
    }
    Ok(())
}

/// RFC-0181 invariant 2 at the relay's own clock (the audit's 5.1): the stamps come from the
/// ingest clock as a relay's do, not from a trace, and delays are injected inside every stage
/// (after the stamp, in the message threads, in the sealer and its pool), not between batches.
/// The bytes made are the same as with no delay at all, on any number of threads: what is in
/// which epoch, and which copy is kept, follows the stamps and the batches alone, never which
/// worker took a batch first or when a stage got to it.
#[test]
fn stamped_by_the_ingest_clock_with_delays_inside_every_stage_the_bytes_are_the_same() -> Result {
    let trace = trace()?;
    let steady = run_clocked(
        &trace,
        Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        },
        None,
    )?;
    assert!(!steady.regional.is_empty(), "no regional product");
    assert!(!steady.world.is_empty(), "no world product");
    assert!(!steady.stream.is_empty(), "no deduplicated stream");
    for (ingest, message, seal) in [(4, 4, 4), (8, 3, 2)] {
        let threads = Threads {
            ingest,
            message,
            seal,
        };
        let delayed = run_clocked(&trace, threads, Some(jitter(2_000)))?;
        assert_eq!(
            steady, delayed,
            "{ingest} ingest, {message} message and {seal} seal threads, delayed inside, differ"
        );
    }
    Ok(())
}

/// The deduplication's window, by stamps (`exchange::DEDUP_WINDOW_MS`, the old relay's two 2 s
/// generations): copies of a message stamped up to two seconds after the copy kept are not kept
/// again, whichever epochs they fall in and whichever workers took them; one stamped past the
/// window is. With one epoch and the one before, the copy two seconds on was kept again.
#[test]
fn copies_of_a_message_up_to_two_seconds_apart_are_kept_once() -> Result {
    let hub = Arc::new(Hub::clocked(8, Arc::new(|| 0)).staged(Threads {
        ingest: 4,
        message: 4,
        seal: 4,
    })?);
    hub.network().adopt_identity(Identity::from_seed([59; 32]));
    let message = airborne(
        0x00a0_0001,
        LatLon {
            lat_deg: 33.0,
            lon_deg: -84.6,
        },
        false,
    );
    // After the first copy: at once, 0.999 s, 2 s (each the same message), then 3.5 s (past it).
    for (n, after_ms) in [0u64, 999, 2_000, 3_500].into_iter().enumerate() {
        let receiver = Identity::from_seed([n as u8 + 60; 32]);
        let batch = Batch::sign(
            &receiver,
            &BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: BASE_MS,
                dropped: 0,
                previous: [0; 32],
                observations: vec![Observation {
                    format: format::MODE_S_LONG,
                    timestamp: n as u64,
                    signal: 1,
                    data: message.clone(),
                }],
            },
        )
        .map_err(text)?;
        let stamp = Stamp {
            stamp_ms: BASE_MS + 400 + after_ms,
            ingest_seq: n as u64,
        };
        hub.ingest(inbound(&hub, &batch, Some(stamp)));
    }
    let end_ms = BASE_MS + 10_000;
    hub.advance(end_ms);
    let products = &hub.network().products;
    let started = Instant::now();
    while products.watermark_ms() < end_ms {
        if started.elapsed() > Duration::from_secs(60) {
            return Err("the epochs never closed".to_owned());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let (stream, refused) = stream_of(&hub)?;
    assert_eq!(refused, 0);
    let kept: Vec<u64> = stream
        .iter()
        .filter(|observation| observation.data == message)
        .map(|observation| observation.timestamp)
        .collect();
    assert_eq!(
        kept,
        vec![0, 3],
        "kept: the first copy, and the one past the window"
    );
    Ok(())
}

#[test]
fn delays_injected_between_batches_change_nothing() -> Result {
    let trace = trace()?;
    let threads = Threads {
        ingest: 4,
        message: 4,
        seal: 4,
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
            seal: 8,
        },
        |_| Duration::ZERO,
    )?;
    // Each second: every aircraft's two positions once, and each feeder's own reply once. A
    // position is new each second (the aircraft moved), so nothing is kept twice across them.
    let mut stream = Vec::new();
    for bytes in &made.stream {
        let batch = Batch::from_bytes(bytes.clone()).map_err(text)?;
        stream.extend(batch.content().map_err(text)?.observations);
    }
    let mut counts: HashMap<&[u8], usize> = HashMap::new();
    for observation in &stream {
        *counts.entry(observation.data.as_slice()).or_default() += 1;
    }
    assert!(
        counts.values().all(|count| *count == 1),
        "a message kept twice"
    );
    assert_eq!(
        stream.len(),
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
        seal: 2,
    })?);
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
            let in_flight = hub.in_flight_for(&batch);
            hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Elsewhere,
                verify: true,
                stamp: None,
                in_flight,
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
        items.extend(got.into_iter().map(tally_relay::fanout::Taken::into_item));
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
    // A budget of one feeder: the products hold some thirty-five epochs of this stream signed
    // (`budget::PerFeeder::planned`'s products, about 1.6 kB an epoch), so forty seconds of it
    // overflow.
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(|| 0))
            // No area taken, so no member's share beside the feeder's: the stores hold exactly
            // what it is planned.
            .memory_for_feeders(1, false)
            .queue_bytes(256 * 1024)
            .staged(Threads {
                ingest: 2,
                message: 2,
                seal: 2,
            })?,
    );
    let raw = || {
        Filter::Subscription(tally_relay::subscription::Subscription {
            streams: Streams::RAW,
            regions: Vec::new(),
        })
    };
    let stalled = hub.listen(998, raw());
    hub.network().adopt_identity(Identity::from_seed([4; 32]));
    let receiver = Identity::from_seed([3; 32]);
    let seconds = 40u64;
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
        let in_flight = hub.in_flight_for(&batch);
        hub.ingest(Inbound {
            source: 1,
            batch,
            origin: Origin::Elsewhere,
            verify: true,
            stamp: Some(Stamp {
                stamp_ms: BASE_MS + second * 1_000,
                ingest_seq: second,
            }),
            in_flight,
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
    // Nobody took the products: the epochs of the deduplicated stream past what the products'
    // budget holds were refused whole and counted; those held are whole.
    let (stream, refused) = stream_of(&hub)?;
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
