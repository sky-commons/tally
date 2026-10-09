//! RFC-0181 §9 and invariant 8, over real sockets: many feeders flood one staged relay at once and
//! its memory stays within its budget. Four times the feeders its budget admits connect together;
//! exactly the ceiling is admitted at Hello and the rest are turned away, and those admitted send
//! batches of distinct receptions as fast as their ingest ceiling lets them while a subscriber
//! never reads. Throughout, every decoded batch alive is charged by the store holding it, read at
//! the same instant, and the batch byte store and the delivery tags hold no more than they are
//! charged. No gauge's charge can pass its limit (`budget::Gauge`, its own tests) and the limits
//! together are the budget (`budget`'s tests), so what this watches for is the one way past the
//! budget: bytes held that no gauge was charged. The watch is shown to see such a holder first.
//!
//! A stage that stalls is held the same way, on the hub alone: what it holds past its share is
//! refused, and nothing it holds is uncharged.
//!
//! Its own binary: what it measures (`tally_wire::decoded::live`) is the process's, so no test of
//! another file runs beside these, and these run one at a time (`ALONE`), each once every decode
//! the one before it held is gone (`alone`): before, a test could start while the last test's
//! dropped relay was still letting its decodes go, and read them as its own uncharged.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tally_relay::budget::Store;
use tally_relay::fanout::{Fell, Filter};
use tally_relay::hub::{Hub, Inbound, Origin};
use tally_relay::ingest::{Stamp, Threads};
use tally_wire::batch::format;
use tally_wire::noise::{self, Session};
use tally_wire::{Batch, BatchContent, Identity, Observation, PublicKey, Record, Role, Streams};
use tokio::net::{TcpListener, TcpStream};

type Result<T = ()> = std::result::Result<T, String>;

/// Held by each test for its whole run: the decoded batches alive are the process's, so a test
/// watching them runs alone.
static ALONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Runs alone, once every decoded batch the test before it held is gone: a relay that is dropped
/// lets every decode go (its stages' threads end with it), and until they have, what they hold
/// is no store of this test's hub.
async fn alone() -> Result<tokio::sync::MutexGuard<'static, ()>> {
    let alone = ALONE.lock().await;
    let started = Instant::now();
    loop {
        let (batches, live) = tally_wire::decoded::live();
        if batches == 0 {
            return Ok(alone);
        }
        if started.elapsed() > Duration::from_secs(30) {
            return Err(format!(
                "{batches} decoded batches ({live} bytes) still alive from the test before"
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// 2026-10-04T00:00:00Z.
const BASE_MS: u64 = 1_791_244_800_000;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The feeders the budget admits, and how many times that connect.
const CEILING: usize = 16;
const OFFERED: usize = 4 * CEILING;
/// Receptions a batch, each distinct: about 20 KB signed, so a feeder's ceiling (256 KiB/s with
/// its burst) is a dozen batches a second.
const RECEPTIONS: u32 = 600;
/// How long the admitted feeders flood.
const FLOOD: Duration = Duration::from_secs(8);

fn busy_batch(receiver: &Identity, sequence: u64) -> Result<Batch> {
    Batch::sign(
        receiver,
        &BatchContent {
            boot_id: 7,
            sequence,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: (0..RECEPTIONS)
                .map(|n| Observation {
                    format: format::MODE_S_LONG,
                    timestamp: u64::from(n),
                    signal: 0,
                    // Distinct whatever the receiver and the batch: no reception is a copy.
                    data: [
                        &sequence.to_be_bytes()[..],
                        &n.to_be_bytes(),
                        &receiver.public().as_bytes()[..2],
                    ]
                    .concat(),
                })
                .collect(),
        },
    )
    .map_err(text)
}

async fn connect(
    address: std::net::SocketAddr,
    key: &PublicKey,
    identity: &Identity,
) -> Result<Session<TcpStream>> {
    let stream = TcpStream::connect(address).await.map_err(text)?;
    noise::connect(stream, identity, key, Role::Feeder)
        .await
        .map_err(text)
}

/// A decoded batch's slices are each charged their share of it, rounded down (`exchange::Slice::
/// share`): at most a byte a slice short of the batch, and a batch is never cut into more slices
/// than this.
const ROUNDING_PER_BATCH: usize = 64;
/// How long a holder must be seen uncharged, in every sample, before it is one: a hand-off
/// releases its charge a moment before it drops what it held, and a sample may fall between. A
/// holder that keeps anything (a queue, a cache) is seen in every sample while it holds it.
const UNCHARGED_FOR: Duration = Duration::from_millis(100);
/// How often the watch samples while the relay runs.
const SAMPLE_EVERY: Duration = Duration::from_millis(20);

/// Every decoded batch alive is charged by the store holding it, read at the same instant
/// (`Budget::decoded_held`), and the batch byte store and the delivery tags hold no more than
/// their gauges are charged. A store whose own charge cannot pass its limit by construction
/// (`Gauge::take`) holds the relay to its budget only if nothing holds bytes it was not charged:
/// that is what this watches for.
#[derive(Default)]
struct Watch {
    /// Since when every sample has seen something uncharged.
    since: Option<Instant>,
    most_live: usize,
}

impl Watch {
    fn sample(&mut self, hub: &Hub) -> Result {
        let report = hub.memory_report();
        let budget = hub.budget();
        let decoded = budget.decoded_held();
        self.most_live = self.most_live.max(decoded.live);
        let mut uncharged = Vec::new();
        if decoded.uncharged() > decoded.batches * ROUNDING_PER_BATCH {
            let stores: Vec<String> = Store::ALL
                .iter()
                .filter(|store| store.holds_decoded())
                .map(|store| format!("{store:?} {}", budget.gauge(*store).held()))
                .collect();
            uncharged.push(format!(
                "{} bytes of decoded batches alive that no store is charged ({decoded:?}; {}, \
                 oversize {})",
                decoded.uncharged(),
                stores.join(", "),
                budget.oversize().held()
            ));
        }
        for (store, held) in [
            (Store::Batches, report.batches_held),
            (Store::Delivery, report.delivery_held),
        ] {
            let charged = budget.gauge(store).held();
            if held > charged {
                uncharged.push(format!("{store:?} holds {held} bytes, charged {charged}"));
            }
        }
        if uncharged.is_empty() {
            self.since = None;
            return Ok(());
        }
        let since = *self.since.get_or_insert_with(Instant::now);
        if since.elapsed() >= UNCHARGED_FOR {
            return Err(format!(
                "uncharged in every sample for {:?}: {}",
                since.elapsed(),
                uncharged.join("; ")
            ));
        }
        Ok(())
    }
}

/// The watch sees a holder no gauge charges: batches decoded here and kept, beside an idle relay.
async fn assert_watch_sees_an_uncharged_holder(hub: &Hub) -> Result {
    let receiver = Identity::generate().map_err(text)?;
    let mut watch = Watch::default();
    watch.sample(hub)?;
    let kept: Vec<_> = (0..4)
        .map(|sequence| {
            let batch = busy_batch(&receiver, sequence)?;
            tally_wire::Decoded::from_verified(batch, 0, sequence)
                .map_err(|error| error.error.to_string())
        })
        .collect::<Result<_>>()?;
    let mut seen = None;
    let started = Instant::now();
    while seen.is_none() && started.elapsed() < 4 * UNCHARGED_FOR {
        seen = watch.sample(hub).err();
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    drop(kept);
    match seen {
        Some(_) => Ok(()),
        None => Err("four decoded batches no store charged went unseen".to_owned()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_stays_bounded_under_a_flood_of_many_feeders() -> Result {
    let _alone = alone().await?;
    let threads = Threads {
        ingest: 2,
        message: 2,
        seal: 2,
    };
    let hub = Arc::new(
        Hub::new(8)
            .max_connections(4 * OFFERED)
            // Every feeder here is on loopback, one address.
            .max_connections_per_address(4 * OFFERED)
            .max_member_bytes_per_sec(64 * 1024)
            .memory_for_feeders(CEILING, false)
            .staged(threads)?,
    );
    assert_eq!(hub.budget().ceiling(), CEILING);
    assert_watch_sees_an_uncharged_holder(&hub).await?;
    let identity = Identity::generate().map_err(text)?;
    let key = identity.public();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    // A subscriber to every raw batch that never reads: the fan-out's share fills and it is let go.
    let _stalled = hub.listen(
        u64::MAX,
        Filter::Subscription(tally_relay::subscription::Subscription {
            streams: Streams::RAW,
            regions: Vec::new(),
        }),
    );

    // Every feeder connects at once; each is admitted (told its rate limit) or turned away.
    let feeders: Vec<Identity> = (0..OFFERED)
        .map(|_| Identity::generate().map_err(text))
        .collect::<Result<_>>()?;
    let mut hellos = tokio::task::JoinSet::new();
    for feeder in feeders {
        hellos.spawn(async move {
            let mut session = connect(address, &key, &feeder).await?;
            let mut first = Vec::new();
            session.reader.recv(&mut first).await.map_err(text)?;
            let admitted = matches!(first.first(), Some(Record::RateLimit { .. }));
            Ok::<_, String>((feeder, session, admitted))
        });
    }
    let mut admitted = Vec::new();
    let mut refused = 0usize;
    while let Some(joined) = hellos.join_next().await {
        let (feeder, session, ok) = joined.map_err(text)??;
        if ok {
            admitted.push((feeder, session));
        } else {
            refused += 1;
        }
    }
    assert_eq!((admitted.len(), refused), (CEILING, OFFERED - CEILING));
    assert_eq!(
        hub.budget().reserved(),
        CEILING * hub.budget().per_feeder().total()
    );

    // The admitted flood: each sends batches as fast as its socket takes them.
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let mut floods = tokio::task::JoinSet::new();
    for (feeder, mut session) in admitted {
        let (stop, sent) = (Arc::clone(&stop), Arc::clone(&sent));
        floods.spawn(async move {
            let mut sequence = 0u64;
            let mut drain = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let Ok(batch) = busy_batch(&feeder, sequence) else {
                    break;
                };
                let bytes = batch.as_bytes().len() as u64;
                if session.writer.send(&[Record::Batch(batch)]).await.is_err() {
                    break;
                }
                sent.fetch_add(bytes, Ordering::Relaxed);
                sequence += 1;
                // Keep the relay's replies read, so only the relay's own stages hold anything.
                if let Ok(Ok(())) =
                    tokio::time::timeout(Duration::ZERO, session.reader.recv(&mut drain)).await
                {
                    drain.clear();
                }
                // Within its ingest ceiling, so it is admitted the whole time.
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
        });
    }
    let started = Instant::now();
    let mut watch = Watch::default();
    while started.elapsed() < FLOOD {
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    stop.store(true, Ordering::Relaxed);
    while floods.join_next().await.is_some() {}
    let stopped = Instant::now();
    while stopped.elapsed() < 2 * UNCHARGED_FOR {
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }

    // The flood was a flood: several times what the stages between ingest and the sealer are
    // given, so a store that did not hold to its share would have grown past it.
    let epochs = hub.budget().gauge(Store::Epochs).limit();
    let offered = usize::try_from(sent.load(Ordering::Relaxed)).map_err(text)?;
    assert!(
        offered > 2 * epochs,
        "only {offered} bytes offered against the epochs' {epochs}"
    );
    // The watch watched something: the flood's decoded batches, alive and charged.
    assert!(
        watch.most_live > CEILING * RECEPTIONS as usize,
        "the watch saw at most {} bytes of decoded batches alive",
        watch.most_live
    );
    Ok(())
}

/// RFC-0181 invariant 8, for the stages that can stall: a stage that never lets go cannot grow
/// the relay's memory past its budget. Here the epoch never closes (every batch is stamped in one
/// second and the ingest clock stands still), so the message exchange holds everything it is
/// given, and nobody reads the one subscriber's queue. Ten times what the budget gives the epochs
/// is ingested: the epoch is refused whole (counted) once its share is full, every decoded batch
/// still alive is charged by the store holding it, the stalled subscriber is let go as fallen
/// behind, holding nothing, and when the epoch does close what it held is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_stage_never_grows_past_the_budget() -> Result {
    let _alone = alone().await?;
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(|| 0))
            .memory_for_feeders(4, false)
            .staged(Threads {
                ingest: 2,
                message: 2,
                seal: 2,
            })?,
    );
    let stalled = hub.listen(
        998,
        Filter::Subscription(tally_relay::subscription::Subscription {
            streams: Streams::RAW,
            regions: Vec::new(),
        }),
    );
    let epochs = hub.budget().gauge(Store::Epochs);
    let fanout = hub.budget().gauge(Store::Fanout);
    let receivers: Vec<Identity> = (0..8u8)
        .map(|n| Identity::from_seed([n + 40; 32]))
        .collect();
    let mut watch = Watch::default();
    let mut ingested = 0usize;
    let mut sequence = 0u64;
    while ingested < 10 * epochs.limit().max(fanout.limit()) {
        for receiver in &receivers {
            let batch = busy_batch(receiver, sequence)?;
            ingested += batch.as_bytes().len();
            let in_flight = hub.in_flight_for(&batch);
            hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Elsewhere,
                verify: true,
                stamp: Some(Stamp {
                    stamp_ms: BASE_MS + 500,
                    ingest_seq: ingested as u64,
                }),
                in_flight,
                refusal: None,
            });
        }
        // The stages take each round in their own time, watched while they hold it.
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
        sequence += 1;
    }
    hub.flush();
    // The message threads take what the workers routed in their own time.
    let started = Instant::now();
    while epochs.refused() == 0 {
        if started.elapsed() > Duration::from_secs(60) {
            return Err("the epoch was never refused".to_owned());
        }
        watch.sample(&hub)?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Stalled: what is alive now is what the stalled stages hold, every byte of it charged.
    let stalled_at = Instant::now();
    while stalled_at.elapsed() < 2 * UNCHARGED_FOR {
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    assert!(
        watch.most_live > 0,
        "the stalled stages held no decoded batch: the watch watched nothing"
    );
    // The subscriber that never read was let go, holding nothing.
    let mut got = Vec::new();
    assert!(matches!(
        stalled.try_recv_many(&mut got, 1_000_000),
        Err(Fell::Behind(_))
    ));
    assert_eq!(stalled.queued_bytes(), 0);
    // When the epoch closes it is refused whole and counted, and what it held is let go.
    let end = BASE_MS + 2_000;
    hub.advance(end);
    let started = Instant::now();
    while hub.network().products.watermark_ms() < end {
        if started.elapsed() > Duration::from_secs(60) {
            return Err("the epochs never closed".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(hub.network().products.report().epochs_refused >= 1);
    assert_eq!(epochs.held(), 0);
    let closed = Instant::now();
    while closed.elapsed() < 2 * UNCHARGED_FOR {
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    let products = &hub.network().products;
    let mut stream = 0usize;
    for record in products.tick(None) {
        if let Record::RelayBatch(batch) = record {
            stream += batch.content().map_err(text)?.observations.len();
        }
    }
    assert_eq!(stream, 0);
    assert!(products.report().stream_refused >= 1);
    Ok(())
}
