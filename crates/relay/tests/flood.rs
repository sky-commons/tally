//! RFC-0181 §9 and invariant 8, over real sockets: many feeders flood one staged relay at once and
//! its memory stays within its budget. Four times the feeders its budget admits connect together;
//! exactly the ceiling is admitted at Hello and the rest are turned away, and those admitted send
//! batches of distinct receptions as fast as their ingest ceiling lets them while a subscriber
//! never reads. Throughout, every store's gauge stays within its limit, the gauges together within
//! what the budget leaves after its base, and every decoded batch alive is one some store holds.
//!
//! Its own binary: what it measures (`tally_wire::decoded::live`) is the process's, so no other
//! test may run beside it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tally_relay::budget::Store;
use tally_relay::fanout::Filter;
use tally_relay::hub::Hub;
use tally_relay::ingest::Threads;
use tally_wire::batch::format;
use tally_wire::noise::{self, Session};
use tally_wire::{Batch, BatchContent, Identity, Observation, PublicKey, Record, Role, Streams};
use tokio::net::{TcpListener, TcpStream};

type Result<T = ()> = std::result::Result<T, String>;

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

/// Every gauge within its limit, and the gauges together within the budget past its base.
fn assert_within(hub: &Hub) {
    let budget = hub.budget();
    let mut limits = 0usize;
    for store in Store::ALL {
        let gauge = budget.gauge(store);
        assert!(
            gauge.held() <= gauge.limit() && gauge.peak() <= gauge.limit(),
            "{store:?}: held {} and peak {} past its limit {}",
            gauge.held(),
            gauge.peak(),
            gauge.limit()
        );
        limits += gauge.limit();
    }
    for gauge in [budget.oversize(), budget.connection_buffers()] {
        assert!(gauge.peak() <= gauge.limit(), "{:?}", gauge.report());
        limits += gauge.limit();
    }
    assert!(
        limits <= budget.memory() - budget.base(),
        "the gauges' limits {limits} pass the budget's {} past its base",
        budget.memory() - budget.base()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_stays_bounded_under_a_flood_of_many_feeders() -> Result {
    let threads = Threads {
        ingest: 2,
        message: 2,
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
    let mut most_live = 0usize;
    while started.elapsed() < FLOOD {
        assert_within(&hub);
        let report = hub.memory_report();
        most_live = most_live.max(report.decoded_live_bytes);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.store(true, Ordering::Relaxed);
    while floods.join_next().await.is_some() {}
    assert_within(&hub);

    // The flood was a flood: several times what the stages between ingest and the sealer are
    // given, so a store that did not hold to its share would have grown past it.
    let epochs = hub.budget().gauge(Store::Epochs).limit();
    let offered = usize::try_from(sent.load(Ordering::Relaxed)).map_err(text)?;
    assert!(
        offered > 2 * epochs,
        "only {offered} bytes offered against the epochs' {epochs}"
    );
    // Every decoded batch alive was held by some store, charged there, beside the one batch each
    // ingest worker decodes (the relay's base): never more than the gauges' limits together.
    let charged: usize = Store::ALL
        .iter()
        .map(|store| hub.budget().gauge(*store).limit())
        .sum::<usize>()
        + hub.budget().oversize().limit();
    assert!(
        most_live <= charged,
        "{most_live} bytes of decoded batches alive at once, past the {charged} the stores hold"
    );
    Ok(())
}
