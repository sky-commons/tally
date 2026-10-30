//! RFC-0181 §9 and invariant 8, over real sockets: many feeders flood one staged relay at once and
//! its memory stays within its budget. Four times the feeders its budget admits connect together;
//! exactly the ceiling is admitted at Hello and the rest are turned away, and those admitted send
//! batches of distinct receptions as fast as their ingest ceiling lets them while a subscriber
//! never reads. Throughout, in every sample, every decoded batch alive is charged exactly once, for
//! exactly its footprint, by the charge inside it (`budget::Covered`: equality, so a decode charged
//! twice shows as surely as one charged never, `Covered::inexact`), and the batch byte store and
//! the delivery tags hold no more than they are charged. No gauge's charge can pass its limit
//! (`budget::Gauge`, its own tests) and the limits together are the budget (`budget`'s tests), so
//! what this watches for is the ways past the plan: bytes held that no gauge was charged, and bytes
//! charged twice, which the plan does not hold. The watch is shown to see each, one batch of it, in
//! the middle of the flood.
//!
//! A stage that stalls is held the same way, on the hub alone: what it holds past its share is
//! refused, and nothing it holds is uncharged.
//!
//! Its own binary: what it measures (`tally_wire::decoded::live`) is the process's, so no test of
//! another file runs beside these, and these run one at a time (`ALONE`), each once every decode
//! the one before it held is gone (`alone`): before, a test could start while the last test's
//! dropped relay was still letting its decodes go, and read them as its own uncharged.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tally_wire::clocks::recorded::aligned;

use tally_relay::budget::{Covered, Lapses, Store};
use tally_relay::fanout::{Fell, Filter};
use tally_relay::hub::{Hub, Inbound, Origin};
use tally_relay::ingest::{Stamp, Threads};
use tally_wire::batch::format;
use tally_wire::noise::{self, Session};
use tally_wire::{Batch, BatchContent, Identity, Observation, PublicKey, Record, Role, Streams};
use tokio::net::{TcpListener, TcpStream};

type Result<T = ()> = std::result::Result<T, String>;

/// How long a test waits for the event it asserts before calling it a hang: a guard on a relay
/// that never gets there, never a verdict on how fast the machine running the test is.
const HANG: Duration = Duration::from_secs(120);

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
        if started.elapsed() > HANG {
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
/// Receptions a batch, each distinct and long: about 20 KB signed, so a feeder's byte ceiling (256
/// KiB/s with its burst) is a dozen batches a second, and its receptions a second
/// (`ingest::FEEDER_RECEPTIONS_PER_SEC`, 1,800) hold it to no fewer: the flood is the bytes'.
const RECEPTIONS: u32 = 100;
/// Bytes of each reception's message.
const MESSAGE_BYTES: usize = 190;

/// The wall clock now, as a feeder signs its batches by (a relay's clock started now reads it).
fn wall_ms() -> u64 {
    tally_relay::clock::RelayClock::system().judged().ms()
}

/// A busy batch of `receiver`'s, signed at `wall_ms` by its feeder's clock.
fn busy_batch(receiver: &Identity, sequence: u64, wall_ms: u64) -> Result<Batch> {
    anchored_batch(
        receiver,
        &BatchContent {
            boot_id: 7,
            sequence,
            counter_epoch: 0,
            wall_ms,
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
                        &[0x5a; MESSAGE_BYTES - 14],
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

/// How long the watch goes on sampling once the relay has stopped, stalled or closed: what it
/// holds then is watched as it lets go.
const SAMPLE_AFTER: Duration = Duration::from_millis(200);
/// How often the watch samples while the relay runs.
const SAMPLE_EVERY: Duration = Duration::from_millis(20);

/// Every decoded batch alive is charged, read at the same instant (`Budget::decoded_held`), to the
/// batch; and each is charged exactly once for exactly its footprint (`Covered::inexact_decodes`),
/// to the byte, so a charge of a byte, or a second charge, is seen. One sample decides: a decode's
/// charge is inside it, made before it is counted alive and let go after it stops being counted,
/// so no holder's hand-off can leave it uncharged even for a moment, and the watch needs no
/// window. And the batch byte store and the delivery tags hold no more than their gauges are
/// charged. A store whose own charge cannot pass its limit by construction (`Gauge::take`) holds
/// the relay to its budget only if nothing holds bytes it was not charged and nothing is charged
/// twice: that is what this watches for.
///
/// Beside the samples the watch reads what [`Covered`] counted as each charge was made and each
/// decode let go (`Covered::lapses`): a decode charged a second time, and one let go that was
/// never charged. Those counters must not move over the test, but for the lapses the test makes
/// itself ([`Watch::allow`]).
struct Watch {
    most_live: usize,
    /// The process's lapses when the watch began, and those the test made itself since.
    lapses_from: Lapses,
}

impl Watch {
    fn new() -> Self {
        Self {
            most_live: 0,
            lapses_from: Covered::process().lapses(),
        }
    }

    /// The test itself made `lapses` (to show they are counted): not the relay's.
    fn allow(&mut self, lapses: Lapses) {
        self.lapses_from.charged_twice += lapses.charged_twice;
        self.lapses_from.never_covered += lapses.never_covered;
    }

    /// The hand-offs that lapsed since the watch began, the test's own aside.
    fn lapsed(&self) -> Lapses {
        let now = Covered::process().lapses();
        Lapses {
            charged_twice: now
                .charged_twice
                .saturating_sub(self.lapses_from.charged_twice),
            never_covered: now
                .never_covered
                .saturating_sub(self.lapses_from.never_covered),
        }
    }

    fn sample(&mut self, hub: &Hub) -> Result {
        let report = hub.memory_report();
        let budget = hub.budget();
        let decoded = budget.decoded_held();
        self.most_live = self.most_live.max(decoded.live);
        // Counted: decodes alive no charge holds, and stores holding past their charge.
        let mut uncharged = Vec::new();
        if decoded.uncharged_batches() > 0 || decoded.uncharged() > 0 {
            let stores: Vec<String> = Store::ALL
                .iter()
                .filter(|store| store.holds_decoded())
                .map(|store| format!("{store:?} {}", budget.gauge(*store).held()))
                .collect();
            uncharged.push(format!(
                "{} decoded batches ({} bytes) alive that no charge holds ({decoded:?}; {})",
                decoded.uncharged_batches(),
                decoded.uncharged(),
                stores.join(", "),
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
        // By the decode: charged other than once for exactly its footprint.
        let inexact = Covered::process().inexact_decodes();
        if !inexact.is_empty() {
            uncharged.push(format!(
                "{} decoded batches charged other than once for exactly their footprints, off by \
                 {} bytes ({decoded:?})",
                inexact.len(),
                inexact.iter().map(|(_, bytes)| bytes).sum::<usize>()
            ));
        }
        // Between the samples: every hand-off judged as it was made.
        let lapsed = self.lapsed();
        if lapsed != Lapses::default() {
            uncharged.push(format!(
                "{} decodes were charged twice, and {} were let go that no charge was ever made \
                 for",
                lapsed.charged_twice, lapsed.never_covered
            ));
        }
        if uncharged.is_empty() {
            return Ok(());
        }
        Err(format!("uncharged: {}", uncharged.join("; ")))
    }
}

/// The watch sees a decode no charge holds, of one batch, in one sample, and one charged a byte
/// for its footprint: a batch decoded here and kept, beside the relay in the middle of its flood,
/// the stores holding megabytes.
///
/// And it sees a lapse no sample is there for: a decode charged twice, and one let go that no
/// charge was ever made for, each counted once at the moment it happened, however soon after it
/// the decode goes.
async fn assert_watch_sees_one_leaked_batch(hub: &Hub) -> Result {
    let receiver = Identity::generate().map_err(text)?;
    let decode = |sequence| -> Result<Arc<tally_wire::Decoded>> {
        tally_wire::Decoded::from_verified(busy_batch(&receiver, sequence, 0)?, aligned(0), 0)
            .map_err(|error| error.error.to_string())
    };
    let kept = decode(0)?;
    let mut watch = Watch::new();
    // Charged by nothing: seen in the one sample.
    let uncovered = watch.sample(hub).err();
    let mut watch = Watch::new();
    // Charged a byte: entered, and still a batch held uncharged.
    Covered::process().own(&kept, 1);
    let short = watch.sample(hub).err();
    drop(kept);
    match (uncovered, short) {
        (Some(_), Some(short)) if short.contains("other than once") => {}
        (None, _) => return Err("one decoded batch no store charged went unseen".to_owned()),
        (_, short) => {
            return Err(format!(
                "one decoded batch charged a byte went unseen: {short:?}"
            ));
        }
    }
    // Between samples: a decode charged twice, and one that lived and went with no charge ever
    // made for it, both gone before any sample could see them.
    let mut watch = Watch::new();
    let twice = decode(1)?;
    Covered::process().own(&twice, twice.footprint());
    Covered::process().own(&twice, twice.footprint());
    drop(twice);
    drop(decode(2)?);
    let lapsed = watch.lapsed();
    if lapsed
        != (Lapses {
            charged_twice: 1,
            never_covered: 1,
        })
    {
        return Err(format!(
            "a decode charged twice, and one never charged, between samples: counted {lapsed:?}"
        ));
    }
    if watch.sample(hub).is_ok() {
        return Err("the watch passed the lapses it was not told of".to_owned());
    }
    Ok(())
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
        Hub::new(8, tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
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
                let Ok(batch) = busy_batch(&feeder, sequence, wall_ms()) else {
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
    // The flood runs by the bytes it offers, never by a span of the clock: halfway is the larger
    // of the epochs' share and the decodes' offered once, the whole of it twice, however long a
    // loaded machine takes to send it.
    let epochs = hub
        .budget()
        .gauge(Store::Epochs)
        .limit()
        .max(hub.budget().gauge(Store::Decoded).limit());
    let offered = || usize::try_from(sent.load(Ordering::Relaxed)).unwrap_or(usize::MAX);
    let started = Instant::now();
    let mut watch = Watch::new();
    while offered() <= epochs || watch.most_live <= CEILING * RECEPTIONS as usize {
        if started.elapsed() > HANG {
            return Err(format!(
                "the flood never got under way: {} bytes offered, at most {} alive",
                offered(),
                watch.most_live
            ));
        }
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    // Halfway, with every store busy: one batch held where no gauge sees it is seen.
    assert_watch_sees_one_leaked_batch(&hub).await?;
    // Let go, it is seen no more; the two lapses it made to be counted were its own.
    watch.allow(Lapses {
        charged_twice: 1,
        never_covered: 1,
    });
    let mut watch_after = Watch::new();
    while offered() <= 2 * epochs {
        if started.elapsed() > HANG {
            return Err(format!(
                "the flood offered only {} bytes against the stores' {epochs}",
                offered()
            ));
        }
        watch_after.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    watch.most_live = watch.most_live.max(watch_after.most_live);
    stop.store(true, Ordering::Relaxed);
    while floods.join_next().await.is_some() {}
    let stopped = Instant::now();
    while stopped.elapsed() < SAMPLE_AFTER {
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }

    // The flood was a flood: several times what the store of decodes and their bytes is given,
    // so a store that did not hold to its share would have grown past it.
    let decoded = hub.budget().gauge(Store::Decoded).limit();
    let offered = usize::try_from(sent.load(Ordering::Relaxed)).map_err(text)?;
    assert!(
        offered > 2 * decoded,
        "only {offered} bytes offered against the decoded store's {decoded}"
    );
    // Equality held to the end: every decode alive charged once, and nothing left over once the
    // flood is let go but what the relay still holds.
    assert_eq!(Covered::process().inexact(), (0, 0));
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
/// second and the ingest clock stands still), so the message exchange holds every decode it is
/// given, and nobody reads the one subscriber's queue. Ten times what the budget gives the decodes
/// is ingested: once the store of decodes is full, the subscriber keeping the most alive is let go
/// as fallen behind, holding nothing, and past that each further batch is refused before its
/// decode, counted; every decoded batch alive is charged exactly once throughout, and when the
/// epoch does close it is published or refused whole, and what it held is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_stage_never_grows_past_the_budget() -> Result {
    let _alone = alone().await?;
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(|| 0), tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
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
    // What waits for the sealer whatever it holds, charged when the exchange was made.
    let fixed = epochs.held();
    let decoded = hub.budget().gauge(Store::Decoded);
    let receivers: Vec<Identity> = (0..8u8)
        .map(|n| Identity::from_seed([n + 40; 32]))
        .collect();
    let mut watch = Watch::new();
    let mut ingested = 0usize;
    let mut sequence = 0u64;
    while ingested < 10 * decoded.limit() {
        for receiver in &receivers {
            let batch = busy_batch(receiver, sequence, BASE_MS + 500)?;
            ingested += batch.as_bytes().len();
            let in_flight = hub.in_flight_for(&batch);
            hub.ingest(Inbound {
                source: 1,
                batch,
                origin: Origin::Elsewhere,
                verify: true,
                stamp: Some(Stamp::recorded(
                    BASE_MS + 500,
                    ingested as u64,
                    BASE_MS + 500,
                    BASE_MS + 500,
                    true,
                )),
                arrived: None,
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
    // Stalled: the store of decodes is full and refuses, counted, and what is alive is what the
    // stalled stages hold, every byte of it charged once.
    assert!(decoded.refused() > 0, "the decoded store never refused");
    assert!(hub.memory_report().decoded_refused > 0);
    assert!(decoded.held() <= decoded.limit());
    let stalled_at = Instant::now();
    while stalled_at.elapsed() < SAMPLE_AFTER {
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
    // When the epoch closes, what it held is published and let go: the decodes with their last
    // holder, the epochs' own bytes with the word.
    let end = BASE_MS + 2_000;
    hub.advance(end);
    let started = Instant::now();
    while hub.network().products.watermark_ms() < end {
        if started.elapsed() > HANG {
            return Err("the epochs never closed".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let closed = Instant::now();
    while closed.elapsed() < SAMPLE_AFTER {
        watch.sample(&hub)?;
        tokio::time::sleep(SAMPLE_EVERY).await;
    }
    let products = &hub.network().products;
    let mut stream = 0usize;
    for record in products.tick() {
        if let Record::RelayBatch(batch) = record {
            stream += batch.content().map_err(text)?.observations.len();
        }
    }
    // Published, or refused whole and counted (the one epoch held the decodes' whole window, more
    // receptions than an epoch's fingerprints are sized for): never in part, and either way let go.
    assert!(
        stream > 0 || products.report().epochs_refused >= 1,
        "the stalled epoch was neither published nor refused"
    );
    assert_eq!(epochs.held(), fixed);
    let settled = Instant::now();
    while decoded.held() > 0 {
        if settled.elapsed() > Duration::from_secs(10) {
            return Err(format!("{} bytes of decodes still held", decoded.held()));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

/// The ingest pool is shared by network, not by connection, end to end through the production
/// path (`Hub::allowance` with the source `ingest::network_source` names for a connection's
/// address, as a link takes it). Twenty-four connections from one network each ask for room for a
/// large batch, over and over; four connections from another network do the same. The pool holds
/// three such batches at once, so it is contended throughout. Served in turn by source, the four
/// are served about as often as the twenty-four together; served first come first served (the
/// source ignored, as when `charge_for` had no caller) they would be served four times in
/// twenty-eight. Judged over a count of serves, never a span of the clock, so a loaded machine
/// weighs as many as an idle one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ingest_pool_is_shared_by_network_not_by_connection() -> Result {
    let hub = Arc::new(
        Hub::new(8, tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
            .memory_for_feeders(CEILING, false),
    );
    let batch = hub.budget().gauge(Store::Ingest).limit() / 3;
    let source = |address: &str, connection: u64| -> Result<u64> {
        let address: std::net::IpAddr = address.parse().map_err(text)?;
        Ok(tally_relay::ingest::network_source(
            tally_relay::ingest::group_of(Some(address)),
            connection,
        ))
    };
    let stop = Arc::new(AtomicBool::new(false));
    let greedy_served = Arc::new(AtomicU64::new(0));
    let honest_served = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for connection in 0..28u64 {
        let honest = connection < 4;
        let address = if honest {
            "198.51.100.1"
        } else {
            "203.0.113.9"
        };
        let allowance = hub.allowance(tally_relay::ingest::CREDIT, source(address, connection)?);
        let (stop, served) = (
            Arc::clone(&stop),
            Arc::clone(if honest {
                &honest_served
            } else {
                &greedy_served
            }),
        );
        tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let held = allowance.acquire(batch).await;
                served.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(1)).await;
                drop(held);
            }
        }));
    }
    const SERVES: u64 = 1_000;
    let started = Instant::now();
    while honest_served.load(Ordering::Relaxed) + greedy_served.load(Ordering::Relaxed) < SERVES {
        if started.elapsed() > HANG {
            return Err(format!(
                "the room served only {} batches",
                honest_served.load(Ordering::Relaxed) + greedy_served.load(Ordering::Relaxed)
            ));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stop.store(true, Ordering::Relaxed);
    for task in tasks {
        task.await.map_err(text)?;
    }
    let (honest, greedy) = (
        honest_served.load(Ordering::Relaxed),
        greedy_served.load(Ordering::Relaxed),
    );
    let share = honest as f64 / (honest + greedy).max(1) as f64;
    assert!(
        share > 0.3, // in turn about a half; first come first served, 4/28
        "the four-connection network was served {honest} times to the crowd's {greedy}: {share:.3} \
         of the room, where first come first served gives it a seventh"
    );
    Ok(())
}

/// `content` signed by `identity` as a feeder of this build signs it (RFC-0171 §3.6): anchored by
/// the relay its session is to as that relay's clock read its signed time, here the simulation's
/// anchoring relay (`tally_mlat_solver::sim::anchoring_relay`), which every relay these tests
/// start accepts.
fn anchored_batch(
    identity: &Identity,
    content: &BatchContent,
) -> std::result::Result<Batch, tally_wire::WireError> {
    anchored_batch_with(identity, content, tally_wire::Codec::Plain)
}

/// As `anchored_batch`, its receptions written by `codec`.
fn anchored_batch_with(
    identity: &Identity,
    content: &BatchContent,
    codec: tally_wire::Codec,
) -> std::result::Result<Batch, tally_wire::WireError> {
    let anchor =
        tally_wire::Anchor::sign(&tally_mlat_solver::sim::anchoring_relay(), content.wall_ms);
    Batch::sign_anchored(identity, content, codec, &[anchor])
}
