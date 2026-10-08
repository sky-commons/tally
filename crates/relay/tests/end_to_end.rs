//! A receiver's frames, end to end, over real sockets: a stand-in readsb serving BEAST, a real
//! feeder reading it, a real relay, and subscribers on both of the relay's outputs (RFC-0171 §10
//! steps 3 and 4); then the relay's streams, regions, engines and redirects (§3.6 to §3.8).
//!
//! Nothing here is timed. A test waits for what it is looking for, and the test runner's own
//! deadline is what fails one that never comes. That something did *not* happen is shown by order,
//! not by waiting a while: the relay's fan-out is in order, so a sentinel published after the
//! event is heard after anything the event let through.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tally_feed::config::Config;
use tally_relay::hub::Hub;
use tally_relay::link;
use tally_relay::mlat_host::{MlatHost, MlatReport};
use tally_wire::batch::ReceiverInfoContent;
use tally_wire::beast::Decoder;
use tally_wire::noise::{self, Session};
use tally_wire::{
    Batch, BatchContent, Clock, ClockModel, ClockModelContent, EnuCovariance, FaultProof, Frame,
    FrameKind, Identity, Location, Observation, ObservationSet, Positions, PublicKey, ReceiverInfo,
    Reception, Record, Region, RelayAddress, Role, Solution, SolutionsContent, Streams,
    TransmitTime,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Result<T = ()> = std::result::Result<T, String>;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn frames(count: u32) -> Result<Vec<Frame>> {
    (0..count)
        .map(|n| {
            let mut message = [0x8d; 14];
            message[1..5].copy_from_slice(&n.to_be_bytes());
            Frame::new(FrameKind::ModeSLong, 1_000 + u64::from(n), 100, &message).map_err(text)
        })
        .collect()
}

/// A stand-in readsb: whoever connects is sent `frames` as BEAST once `ready` says so, then the
/// stream stays open. A feeder seals what it hears once a second and a batch sealed before any
/// relay session is up is gone (RFC-0171 §3.1: its sequence says so), and a v2 feeder measures its
/// relays before it sends (RFC-0174 §2.2), so the frames are held until it is publishing.
async fn readsb(
    frames: Vec<Frame>,
    ready: tokio::sync::watch::Receiver<bool>,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut bytes = Vec::new();
            for frame in &frames {
                frame.encode_beast(&mut bytes);
            }
            let mut ready = ready.clone();
            tokio::spawn(async move {
                let _ = ready.wait_for(|ready| *ready).await;
                let _ = stream.write_all(&bytes).await;
                tokio::time::sleep(Duration::from_secs(3_600)).await;
            });
        }
    });
    Ok(address)
}

struct Relay {
    address: SocketAddr,
    beast_out: SocketAddr,
    key: tally_wire::PublicKey,
}

async fn relay(hub: Hub) -> Result<Relay> {
    relay_as(hub, Identity::generate().map_err(text)?).await
}

async fn relay_as(hub: Hub, identity: Identity) -> Result<Relay> {
    let key = identity.public();
    let hub = Arc::new(hub);
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    let beast = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let beast_out = beast.local_addr().map_err(text)?;
    tokio::spawn(link::serve_beast(beast, Arc::clone(&hub)));
    tokio::spawn(tally_relay::serve(listener, vec![identity], hub));
    Ok(Relay {
        address,
        beast_out,
        key,
    })
}

async fn subscribe(relay: &Relay) -> Result<Session<TcpStream>> {
    let stream = TcpStream::connect(relay.address).await.map_err(text)?;
    noise::connect(
        stream,
        &Identity::generate().map_err(text)?,
        &relay.key,
        Role::Subscriber,
    )
    .await
    .map_err(text)
}

fn state_dir() -> Result<std::path::PathBuf> {
    let mut name = [0; 8];
    getrandom(&mut name);
    let dir = std::env::temp_dir().join(format!("tally-e2e-{}", u64::from_be_bytes(name)));
    std::fs::create_dir_all(&dir).map_err(text)?;
    Ok(dir)
}

fn getrandom(bytes: &mut [u8]) {
    let identity = Identity::generate().map(|identity| identity.public());
    if let Ok(key) = identity {
        for (byte, random) in bytes.iter_mut().zip(key.as_bytes()) {
            *byte = *random;
        }
    }
}

#[tokio::test]
async fn a_receivers_frames_reach_both_outputs_signed_and_unchanged() -> Result {
    let sent = frames(500)?;
    let (publishing, ready) = tokio::sync::watch::channel(false);
    let source = readsb(sent.clone(), ready).await?;
    let relay = relay(Hub::new(8)).await?;
    let mut subscriber = subscribe(&relay).await?;
    let mut beast = TcpStream::connect(relay.beast_out).await.map_err(text)?;

    let dir = state_dir()?;
    let key_file = dir.join("key");
    tally_feed::init(&key_file)?;
    let feeder = Identity::from_base64(&std::fs::read_to_string(&key_file).map_err(text)?)
        .map_err(text)?
        .public();
    let location = Location {
        lat_e7: 374_100_000,
        lon_e7: -1_221_000_000,
        alt_m: 10,
        precision_m: 0,
    };
    tokio::spawn(tally_feed::run(Config {
        key_file,
        source: source.to_string(),
        uat: None,
        relays: vec![RelayAddress {
            key: relay.key,
            address: relay.address.to_string(),
        }],
        seeds: Vec::new(),
        state_dir: dir.clone(),
        location: Some(location),
        clock: Clock::Dump1090,
        ceiling: 1_000_000,
    }));

    // The subscriber gets the receiver's signed description and its batches, verified.
    let mut heard = Vec::new();
    let mut described = false;
    let mut named = false;
    {
        let mut records = Vec::new();
        while heard.len() < sent.len() || !named {
            records.clear();
            subscriber.reader.recv(&mut records).await.map_err(text)?;
            for record in &records {
                match record {
                    Record::Batch(batch) => {
                        batch.verify().map_err(text)?;
                        assert_eq!(batch.receiver().map_err(text)?, feeder);
                        let content = batch.content().map_err(text)?;
                        heard.extend(content.observations.iter().filter_map(|o| o.to_beast()));
                    }
                    Record::ReceiverInfo(info) => {
                        info.verify().map_err(text)?;
                        let content = info.content().map_err(text)?;
                        assert_eq!(content.location, Some(location));
                        described = true;
                        // Its description reached the relay over its session: it is publishing.
                        publishing.send_replace(true);
                        named |= content.relays.contains(&relay.key);
                    }
                    _ => {}
                }
            }
        }
    }
    assert_eq!(heard, sent);
    assert!(described, "no receiver info arrived");

    // The loopback output carries the same frames as plain BEAST, for a local readsb.
    let mut decoder = Decoder::new();
    let mut decoded = Vec::new();
    let mut buffer = vec![0; 64 * 1024];
    while decoded.len() < sent.len() {
        let length = beast.read(&mut buffer).await.map_err(text)?;
        if length == 0 {
            return Err(format!(
                "beast-out closed after {} of {} frames",
                decoded.len(),
                sent.len()
            ));
        }
        decoder.push(&buffer[..length], |frame| decoded.push(frame));
    }
    assert_eq!(decoded, sent);

    // The feeder's signed description names the relay it publishes to (above, `named`): what a
    // relay's credit counts it by (RFC-0174 §2.1).
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

fn batch(identity: &Identity, sequence: u64) -> Result<Batch> {
    Batch::sign(
        identity,
        &BatchContent {
            boot_id: 1,
            sequence,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: vec![tally_wire::Observation::from_beast(&frames(1)?[0])],
        },
    )
    .map_err(text)
}

#[tokio::test]
async fn a_feeder_publishing_someone_elses_batch_is_cut_off_and_nothing_is_forwarded() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let mut subscriber = subscribe(&relay).await?;
    let impostor = Identity::generate().map_err(text)?;
    let victim = Identity::generate().map_err(text)?;
    let stream = TcpStream::connect(relay.address).await.map_err(text)?;
    let mut session = noise::connect(stream, &impostor, &relay.key, Role::Feeder)
        .await
        .map_err(text)?;
    let honest = batch(&impostor, 0)?;
    session
        .writer
        .send(&[
            Record::Batch(honest.clone()),
            Record::Batch(batch(&victim, 0)?),
        ])
        .await
        .map_err(text)?;
    // The relay ends the session: the impostor's reads fail once what was in flight is read.
    ended(&mut session).await;
    // The subscriber saw the impostor's own batch, signed by it, and nothing in the victim's name
    // before a batch published after the session ended.
    let (_later, last) = sentinel(&relay).await?;
    let seen = batches_until(&mut subscriber, &last).await?;
    assert_eq!(seen, vec![honest, last]);
    Ok(())
}

#[tokio::test]
async fn a_batch_arriving_twice_is_forwarded_once() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let mut subscriber = subscribe(&relay).await?;
    let receiver = Identity::generate().map_err(text)?;
    let once = batch(&receiver, 0)?;
    let next = batch(&receiver, 1)?;
    // The same batch by two sessions of its receiver (a feeder that reconnected and resent): the
    // second once the first's copy is through, and following it with the receiver's next batch.
    let mut sessions = Vec::new();
    let mut heard = Vec::new();
    for sent in [vec![once.clone()], vec![once.clone(), next.clone()]] {
        let mut session = connect(&relay, &receiver, Role::Feeder).await?;
        let last = sent.last().cloned().ok_or("nothing to send")?;
        session
            .writer
            .send(&sent.into_iter().map(Record::Batch).collect::<Vec<_>>())
            .await
            .map_err(text)?;
        heard.extend(batches_until(&mut subscriber, &last).await?);
        sessions.push(session);
    }
    assert_eq!(heard, vec![once, next]);
    Ok(())
}

#[tokio::test]
async fn a_stalled_subscriber_is_dropped_and_the_others_keep_every_batch() -> Result {
    // A small subscriber queue (a megabyte, some dozen of these batches), so a subscriber that
    // stops reading falls behind quickly, and an ingest ceiling far above the flood this feeder
    // sends to make that happen.
    let relay = relay(
        Hub::new(8)
            .queue_bytes(1 << 20)
            .max_feeder_bytes_per_sec(1 << 30),
    )
    .await?;
    let mut fast = subscribe(&relay).await?;
    let stalled = subscribe(&relay).await?;
    let receiver = Identity::generate().map_err(text)?;
    let stream = TcpStream::connect(relay.address).await.map_err(text)?;
    let mut feeder = noise::connect(stream, &receiver, &relay.key, Role::Feeder)
        .await
        .map_err(text)?;
    // Big batches, enough to fill the stalled subscriber's socket buffers many times over.
    let big: Vec<tally_wire::Observation> = frames(2_000)?
        .iter()
        .map(tally_wire::Observation::from_beast)
        .collect();
    let total = 400u64;
    let (heard, mut done) = tokio::sync::mpsc::channel::<()>(1);
    let sending = tokio::spawn(async move {
        for sequence in 0..total {
            let signed = Batch::sign(
                &receiver,
                &BatchContent {
                    boot_id: 9,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: 0,
                    dropped: 0,
                    previous: [0; 32],
                    observations: big.clone(),
                },
            )
            .map_err(text)?;
            feeder
                .writer
                .send(&[Record::Batch(signed)])
                .await
                .map_err(text)?;
            // In step with the reading subscriber, so only the stalled one falls behind.
            if done.recv().await.is_none() {
                return Err("the reading subscriber stopped".to_owned());
            }
        }
        Ok::<_, String>(feeder)
    });
    let mut sequences = Vec::new();
    while sequences.len() < usize::try_from(total).unwrap_or(usize::MAX) {
        let mut got = Vec::new();
        fast.reader.recv(&mut got).await.map_err(text)?;
        for record in got {
            if let Record::Batch(batch) = record {
                sequences.push(batch.sequence());
                let _ = heard.send(()).await;
            }
        }
    }
    assert_eq!(sequences, (0..total).collect::<Vec<_>>());
    sending.await.map_err(text)??;

    // The stalled one was told it fell behind (or simply cut off) rather than slowing anyone.
    let mut stalled = stalled;
    loop {
        let mut got = Vec::new();
        match stalled.reader.recv(&mut got).await {
            Err(_) => break,
            Ok(())
                if got
                    .iter()
                    .any(|record| matches!(record, Record::Goodbye { .. })) =>
            {
                break;
            }
            Ok(()) => {}
        }
    }
    Ok(())
}

async fn connect(relay: &Relay, identity: &Identity, role: Role) -> Result<Session<TcpStream>> {
    let stream = TcpStream::connect(relay.address).await.map_err(text)?;
    noise::connect(stream, identity, &relay.key, role)
        .await
        .map_err(text)
}

/// Reads whole messages until one holds a record `done` accepts; returns every record read.
async fn until(
    session: &mut Session<TcpStream>,
    what: &str,
    mut done: impl FnMut(&Record) -> bool,
) -> Result<Vec<Record>> {
    let mut all = Vec::new();
    loop {
        let mut got = Vec::new();
        session
            .reader
            .recv(&mut got)
            .await
            .map_err(|error| format!("waiting for {what}: {error}"))?;
        let found = got.iter().any(&mut done);
        all.extend(got);
        if found {
            return Ok(all);
        }
    }
}

/// Reads until the relay ends the session.
async fn ended(session: &mut Session<TcpStream>) {
    let mut records = Vec::new();
    while session.reader.recv(&mut records).await.is_ok() {
        records.clear();
    }
}

/// A fresh feeder's own batch, published now: anything published before it reaches a subscriber
/// before it does.
async fn sentinel(relay: &Relay) -> Result<(Session<TcpStream>, Batch)> {
    let identity = Identity::generate().map_err(text)?;
    let mut session = connect(relay, &identity, Role::Feeder).await?;
    let last = batch(&identity, 0)?;
    session
        .writer
        .send(&[Record::Batch(last.clone())])
        .await
        .map_err(text)?;
    Ok((session, last))
}

/// Every batch a subscriber is sent, up to and including `last`.
async fn batches_until(session: &mut Session<TcpStream>, last: &Batch) -> Result<Vec<Batch>> {
    let heard = until(session, "the last batch", |record| {
        *record == Record::Batch(last.clone())
    })
    .await?;
    Ok(heard
        .into_iter()
        .filter_map(|record| match record {
            Record::Batch(batch) => Some(batch),
            _ => None,
        })
        .collect())
}

/// The receiver a batch or description is from.
fn author(record: &Record) -> Option<PublicKey> {
    match record {
        Record::Batch(batch) => batch.receiver().ok(),
        Record::ReceiverInfo(info) => info.receiver().ok(),
        _ => None,
    }
}

fn describes(record: &Record, receiver: PublicKey) -> bool {
    matches!(record, Record::ReceiverInfo(_)) && author(record) == Some(receiver)
}

fn info(identity: &Identity, location: Option<Location>) -> Result<ReceiverInfo> {
    ReceiverInfo::sign(
        identity,
        &ReceiverInfoContent {
            issued_ms: 1,
            location,
            clock: Clock::Dump1090,
            software: "test".to_owned(),
            relays: Vec::new(),
        },
    )
    .map_err(text)
}

/// A feeder session that has published its own description.
async fn described_feeder(
    relay: &Relay,
    identity: &Identity,
    location: Option<Location>,
) -> Result<Session<TcpStream>> {
    let mut session = connect(relay, identity, Role::Feeder).await?;
    session
        .writer
        .send(&[Record::ReceiverInfo(info(identity, location)?)])
        .await
        .map_err(text)?;
    Ok(session)
}

/// A subscriber whose `Subscribe` the relay has certainly applied: `beacon` is a receiver the
/// relay knows and the subscription covers, and the relay answers a `Subscribe` by describing the
/// receivers it covers, so the beacon's description arriving again is the acknowledgement. Also
/// returns that answer.
async fn subscribed(
    relay: &Relay,
    role: Role,
    streams: Streams,
    regions: Vec<Region>,
    beacon: PublicKey,
) -> Result<(Session<TcpStream>, Vec<Record>)> {
    let mut session = connect(relay, &Identity::generate().map_err(text)?, role).await?;
    until(&mut session, "the beacon", |record| {
        describes(record, beacon)
    })
    .await?;
    session
        .writer
        .send(&[Record::Subscribe { streams, regions }])
        .await
        .map_err(text)?;
    let answer = until(&mut session, "the subscription's answer", |record| {
        describes(record, beacon)
    })
    .await?;
    Ok((session, answer))
}

fn at(lat: f64, lon: f64) -> Location {
    Location {
        lat_e7: (lat * 1e7) as i32,
        lon_e7: (lon * 1e7) as i32,
        alt_m: 0,
        precision_m: 0,
    }
}

#[tokio::test]
async fn a_regional_subscriber_hears_only_receivers_inside_its_region() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let palo_alto = at(37.44, -122.14);
    let inside = Identity::generate().map_err(text)?;
    let outside = Identity::generate().map_err(text)?;
    let nowhere = Identity::generate().map_err(text)?;
    let mut inside_feed = described_feeder(&relay, &inside, Some(palo_alto)).await?;
    let mut outside_feed = described_feeder(&relay, &outside, Some(at(51.5, -0.12))).await?;
    let mut nowhere_feed = connect(&relay, &nowhere, Role::Feeder).await?;
    // A whole-world subscriber, to know when the relay has taken in what was published.
    let mut world = subscribe(&relay).await?;
    let mut described = HashSet::new();
    until(&mut world, "both descriptions", |record| {
        if let (Record::ReceiverInfo(_), Some(key)) = (record, author(record)) {
            described.insert(key);
        }
        described.len() == 2
    })
    .await?;

    let region = Region::containing(&palo_alto, 3).map_err(text)?;
    let (mut regional, answer) = subscribed(
        &relay,
        Role::Subscriber,
        Streams::RAW,
        vec![region],
        inside.public(),
    )
    .await?;
    for (session, identity) in [(&mut outside_feed, &outside), (&mut nowhere_feed, &nowhere)] {
        session
            .writer
            .send(&[Record::Batch(batch(identity, 0)?)])
            .await
            .map_err(text)?;
    }
    let mut published = HashSet::new();
    until(&mut world, "the outside batches", |record| {
        if let (Record::Batch(_), Some(key)) = (record, author(record)) {
            published.insert(key);
        }
        published.len() == 2
    })
    .await?;
    inside_feed
        .writer
        .send(&[Record::Batch(batch(&inside, 0)?)])
        .await
        .map_err(text)?;
    // The fan-out is in order, so anything from outside would have arrived before this.
    let mut heard = until(&mut regional, "the inside batch", |record| {
        matches!(record, Record::Batch(_)) && author(record) == Some(inside.public())
    })
    .await?;
    heard.extend(answer);
    let strangers: Vec<_> = heard
        .iter()
        .filter_map(author)
        .filter(|key| *key != inside.public())
        .collect();
    assert!(strangers.is_empty(), "heard from outside the region");
    Ok(())
}

#[tokio::test]
async fn two_receivers_hearing_one_message_are_one_copy_in_the_relays_signed_stream() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let (mut subscriber, _) = subscribed(
        &relay,
        Role::Subscriber,
        Streams::RAW.with(Streams::DEDUPLICATED),
        Vec::new(),
        beacon.public(),
    )
    .await?;
    let message = frames(1)?[0].message().to_vec();
    // A different message, heard after both copies: the deduplicated stream is gathered in the
    // order heard, so any second copy would be signed no later than this one.
    let after = frames(2)?[1].message().to_vec();
    let mut feeds = Vec::new();
    let mut receivers = HashSet::new();
    for (counter, data) in [(10, &message), (20, &message), (30, &after)] {
        if data == &after {
            // Both copies through the relay before the later message is sent.
            until(&mut subscriber, "both copies raw", |record| {
                if let (Record::Batch(_), Some(key)) = (record, author(record)) {
                    receivers.insert(key);
                }
                receivers.len() == 2
            })
            .await?;
        }
        let receiver = Identity::generate().map_err(text)?;
        let mut feed = connect(&relay, &receiver, Role::Feeder).await?;
        let signed = Batch::sign(
            &receiver,
            &BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: vec![Observation {
                    format: b'3',
                    timestamp: counter,
                    signal: 50,
                    data: data.clone(),
                }],
            },
        )
        .map_err(text)?;
        feed.writer
            .send(&[Record::Batch(signed)])
            .await
            .map_err(text)?;
        feeds.push(feed);
    }
    let copies = |records: &[Record], message: &[u8]| -> Result<(usize, Vec<Batch>)> {
        let mut copies = 0;
        let mut signed = Vec::new();
        for record in records {
            if let Record::RelayBatch(batch) = record {
                // Signed as the relay's own claim, which never passes as a receiver's batch.
                batch.verify_as_relay().map_err(text)?;
                assert!(
                    batch.verify().is_err(),
                    "a relay batch verified as a receiver's"
                );
                assert_eq!(batch.receiver().map_err(text)?, relay.key);
                let content = batch.content().map_err(text)?;
                copies += content
                    .observations
                    .iter()
                    .filter(|observation| observation.data == message)
                    .count();
                signed.push(batch.clone());
            }
        }
        Ok((copies, signed))
    };
    let heard = until(
        &mut subscriber,
        "the later message, deduplicated",
        |record| {
            matches!(record, Record::RelayBatch(batch)
            if batch.content().is_ok_and(|content| {
                content.observations.iter().any(|observation| observation.data == after)
            }))
        },
    )
    .await?;
    let (total, signed) = copies(&heard, &message)?;
    assert_eq!(signed.first().map(Batch::sequence), Some(0));
    assert_eq!(total, 1);
    assert_eq!(copies(&heard, &after)?.0, 1);
    Ok(())
}

fn positions(engine: &Identity, sequence: u64) -> Result<Positions> {
    solved(engine, sequence, 374_100_000)
}

/// A relay's hosted MLAT that publishes what the test hands it, signed by the relay's own key:
/// the one source of positions and clock models a relay originates (RFC-0174 §2.1).
#[derive(Default)]
struct Scripted {
    ready: std::sync::Mutex<Vec<Record>>,
}

impl Scripted {
    fn publish(&self, records: Vec<Record>) {
        if let Ok(mut ready) = self.ready.lock() {
            ready.extend(records);
        }
    }
}

impl MlatHost for Scripted {
    fn set_areas(&self, _: tally_wire::Regions, _: Vec<ReceiverInfo>) {}

    fn offer_description(&self, _: &ReceiverInfo) {}

    fn offer_batch(&self, _: &Arc<tally_wire::Decoded>, _: u64) {}

    fn sealed_bins(&self) -> Option<tally_mlat_solver::held::SealedBins> {
        None
    }

    fn take_published(&self, _: u64) -> Vec<Record> {
        self.ready
            .lock()
            .map(|mut ready| std::mem::take(&mut *ready))
            .unwrap_or_default()
    }

    fn cores(&self) -> u16 {
        1
    }

    fn report(&self) -> MlatReport {
        MlatReport::default()
    }
}

/// A relay hosting `mlat`, under `identity`.
async fn relay_hosting(identity: Identity, mlat: Arc<Scripted>) -> Result<Relay> {
    let hub = Hub::new(8);
    hub.network().host_mlat(mlat);
    relay_as(hub, identity).await
}

/// What a relay's own MLAT signs reaches each subscriber of its stream: final positions those
/// that asked for positions, provisional ones only those that asked for them, clock models those
/// that asked for models. (An engine publishing on its own session is the retired path: refused,
/// `no_session_but_a_member_publishes_positions_models_or_parts`.)
#[tokio::test]
async fn a_relays_own_mlat_reaches_the_subscribers_of_each_stream() -> Result {
    let identity = Identity::generate().map_err(text)?;
    let mlat = Arc::new(Scripted::default());
    let relay = relay_hosting(identity.clone(), Arc::clone(&mlat)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let subscriber = |streams| {
        subscribed(
            &relay,
            Role::Subscriber,
            streams,
            Vec::new(),
            beacon.public(),
        )
    };
    let (mut finals_only, _) = subscriber(Streams::RAW.with(Streams::POSITIONS)).await?;
    let (mut both, _) = subscriber(
        Streams::RAW
            .with(Streams::POSITIONS)
            .with(Streams::PROVISIONAL),
    )
    .await?;
    let (mut models, _) = subscriber(Streams::RAW.with(Streams::CLOCK_MODELS)).await?;
    let early = provisional(&identity, 0, 374_100_000)?;
    let late = solved(&identity, 0, 374_100_000)?;
    let model = clock_model(&identity, 0)?;
    mlat.publish(vec![
        Record::ClockModel(model.clone()),
        Record::Provisional(early.clone()),
        Record::Positions(late.clone()),
    ]);
    let heard = until(&mut both, "the final positions", |record| {
        *record == Record::Positions(late.clone())
    })
    .await?;
    assert!(heard.contains(&Record::Provisional(early.clone())));
    let heard = until(&mut finals_only, "the final positions", |record| {
        *record == Record::Positions(late.clone())
    })
    .await?;
    assert!(
        !heard
            .iter()
            .any(|record| matches!(record, Record::Provisional(_)))
    );
    until(&mut models, "the clock model", |record| {
        *record == Record::ClockModel(model.clone())
    })
    .await?;
    Ok(())
}

/// Positions, provisional positions, clock models and their parts come only from a relay: its own
/// MLAT, or a verified member. Any other session that publishes one (an engine's, the retired
/// standalone path; a feeder's; a subscriber's) is cut off, and nothing it sent is forwarded.
#[tokio::test]
async fn no_session_but_a_member_publishes_positions_models_or_parts() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let (mut subscriber, _) = subscribed(
        &relay,
        Role::Subscriber,
        Streams::RAW
            .with(Streams::POSITIONS)
            .with(Streams::PROVISIONAL)
            .with(Streams::CLOCK_MODELS),
        Vec::new(),
        beacon.public(),
    )
    .await?;
    let engine = Identity::generate().map_err(text)?;
    let refused = [
        Record::Positions(positions(&engine, 0)?),
        Record::Provisional(provisional(&engine, 0, 374_100_000)?),
        Record::ClockModel(clock_model(&engine, 0)?),
        Record::ClockModelPart(tally_wire::ClockModelPart::new([1; 32], 0, b"part")),
    ];
    for role in [Role::Engine, Role::Feeder, Role::Subscriber] {
        for record in &refused {
            let mut session = connect(&relay, &engine, role).await?;
            session
                .writer
                .send(std::slice::from_ref(record))
                .await
                .map_err(text)?;
            tokio::time::timeout(Duration::from_secs(10), ended(&mut session))
                .await
                .map_err(|_| format!("a {role:?} that published {record:?} was not cut off"))?;
        }
    }
    let (_feed, last) = sentinel(&relay).await?;
    let heard = until(&mut subscriber, "the sentinel", |record| {
        *record == Record::Batch(last.clone())
    })
    .await?;
    for record in &refused {
        assert!(!heard.contains(record), "{record:?} was forwarded");
    }
    Ok(())
}

/// A format 3 record of one solution over four receivers' receptions, at `lat_e7`.
fn solved(engine: &Identity, sequence: u64, lat_e7: i32) -> Result<Positions> {
    Positions::sign_solutions(
        engine,
        &SolutionsContent {
            boot_id: 1,
            sequence,
            issued_ms: 1_791_220_000_000,
            spec_version: 1,
            solutions: vec![solution(lat_e7)?],
        },
    )
    .map_err(text)
}

/// The same solution as a provisional record.
fn provisional(engine: &Identity, sequence: u64, lat_e7: i32) -> Result<Positions> {
    Positions::sign_provisional(
        engine,
        &SolutionsContent {
            boot_id: 1,
            sequence,
            issued_ms: 1_791_220_000_000,
            spec_version: 1,
            solutions: vec![solution(lat_e7)?],
        },
    )
    .map_err(text)
}

fn solution(lat_e7: i32) -> Result<Solution> {
    let receptions = (1..=4u8)
        .map(|seed| Reception {
            receiver: Identity::from_seed([seed; 32]).public(),
            epoch: 0,
            counter: u64::from(seed),
        })
        .collect();
    let solution = Solution {
        address: 0xa1b2c3,
        transmitted: TransmitTime::new(1_791_219_999_000, 0).map_err(text)?,
        lat_e7,
        lon_e7: -1_221_000_000,
        alt_hae_mm: Some(1_371_600),
        covariance: EnuCovariance {
            xx: 100.0,
            xy: 0.0,
            xz: 0.0,
            yy: 100.0,
            yz: 0.0,
            zz: 400.0,
        },
        clock_model: [1; 32],
        addressed: tally_wire::AddressedCitation::default(),
        observations: ObservationSet::new(vec![0x8d, 0xa1, 0xb2, 0xc3], receptions)
            .map_err(text)?,
    };
    Ok(solution)
}

fn clock_model(engine: &Identity, sequence: u64) -> Result<ClockModel> {
    ClockModel::sign(
        engine,
        &ClockModelContent {
            boot_id: 1,
            sequence,
            issued_ms: 1_791_220_000_000,
            spec_version: 1,
            inputs: [0; 32],
            model: b"a solver's model".to_vec(),
        },
    )
    .map(|signed| signed.manifest)
    .map_err(text)
}

#[tokio::test]
async fn a_fault_proof_from_anyone_is_checked_then_forwarded_and_a_false_one_ends_the_session()
-> Result {
    let relay = relay(Hub::new(8)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let (mut listener, _) = subscribed(
        &relay,
        Role::Subscriber,
        Streams::RAW.with(Streams::POSITIONS),
        Vec::new(),
        beacon.public(),
    )
    .await?;
    let (honest, liar) = (
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
    );
    let truth = solved(&honest, 0, 374_100_000)?;
    let lie = solved(&liar, 0, 374_900_000)?;
    let proof = FaultProof::new(&truth, 0, &lie, 0).map_err(text)?;

    // A plain subscriber proves the fault; the relay checks it and forwards it.
    let mut accuser = subscribe(&relay).await?;
    accuser
        .writer
        .send(&[Record::FaultProof(proof.clone())])
        .await
        .map_err(text)?;
    until(&mut listener, "the fault proof", |record| {
        *record == Record::FaultProof(proof.clone())
    })
    .await?;

    // Two solutions that agree prove nothing: the accusation ends the session and goes nowhere.
    let agreeing = solved(&liar, 1, 374_100_000)?;
    let false_proof = FaultProof::new(&truth, 0, &agreeing, 0).map_err(text)?;
    accuser
        .writer
        .send(&[Record::FaultProof(false_proof.clone())])
        .await
        .map_err(text)?;
    ended(&mut accuser).await;

    let other_lie = solved(&liar, 2, 373_000_000)?;
    let next = FaultProof::new(&truth, 0, &other_lie, 0).map_err(text)?;
    let mut again = subscribe(&relay).await?;
    again
        .writer
        .send(&[Record::FaultProof(next.clone())])
        .await
        .map_err(text)?;
    let heard = until(&mut listener, "the next fault proof", |record| {
        *record == Record::FaultProof(next.clone())
    })
    .await?;
    assert!(!heard.contains(&Record::FaultProof(false_proof)));
    Ok(())
}

#[tokio::test]
async fn at_capacity_a_subscriber_is_redirected_to_the_advertised_relays() -> Result {
    let hints = vec![
        RelayAddress {
            key: Identity::generate().map_err(text)?.public(),
            address: "relay-a.example:10900".to_owned(),
        },
        RelayAddress {
            key: Identity::generate().map_err(text)?.public(),
            address: "relay-b.example:10900".to_owned(),
        },
    ];
    let relay = relay(Hub::new(1).advertising(hints.clone())).await?;
    let beacon = Identity::generate().map_err(text)?;
    // A feeder is offered the same relays as soon as it connects.
    let mut feed = described_feeder(&relay, &beacon, None).await?;
    let offered = until(&mut feed, "a relay list", |record| {
        matches!(record, Record::RelayList(_))
    })
    .await?;
    assert!(offered.contains(&Record::RelayList(hints.clone())));
    // The one slot is certainly taken once its holder has been sent what the relay knows.
    let mut first = subscribe(&relay).await?;
    until(&mut first, "the beacon", |record| {
        describes(record, beacon.public())
    })
    .await?;
    let mut second = subscribe(&relay).await?;
    let told = until(&mut second, "a redirect", |record| {
        matches!(record, Record::Redirect { .. })
    })
    .await?;
    assert!(told.contains(&Record::Redirect {
        retry_after_secs: 600,
        hints,
    }));
    ended(&mut second).await;
    Ok(())
}

/// Reads until the session ends; returns the goodbye it was told, if any.
async fn told(session: &mut Session<TcpStream>) -> Result<Option<Record>> {
    let mut goodbye = None;
    loop {
        let mut got = Vec::new();
        if session.reader.recv(&mut got).await.is_err() {
            return Ok(goodbye);
        }
        if let Some(record) = got
            .into_iter()
            .find(|record| matches!(record, Record::Goodbye { .. }))
        {
            goodbye = Some(record);
        }
    }
}

#[tokio::test]
async fn a_key_the_operator_did_not_accept_as_a_relay_is_refused() -> Result {
    let accepted = Identity::generate().map_err(text)?;
    let relay = relay(Hub::new(8).accepting_relays([accepted.public()])).await?;
    let mut subscriber = subscribe(&relay).await?;
    let stranger = Identity::generate().map_err(text)?;
    let mut session = connect(&relay, &stranger, Role::Relay).await?;
    // Anyone's batch, as a relay would forward it: the stranger may not.
    let _ = session
        .writer
        .send(&[Record::Batch(batch(
            &Identity::generate().map_err(text)?,
            0,
        )?)])
        .await;
    // Asked to come back after one re-signing of offers (`directory::OWN_RESIGN_EVERY_MS`): a
    // relay not yet verified may be by then, so the wait is gossip's, never a day's.
    assert_eq!(
        told(&mut session).await?,
        Some(Record::Goodbye {
            reason: tally_wire::Reason::Refused,
            retry_after_secs: (tally_relay::directory::OWN_RESIGN_EVERY_MS / 1000) as u32,
        })
    );
    // The accepted key is served, as a directory link (RFC-0174 §2.5): a batch it sends is not
    // taken, and the subscriber hears neither it nor the stranger's before a feeder's own.
    let mut trusted = connect(&relay, &accepted, Role::Relay).await?;
    let forwarded = batch(&Identity::generate().map_err(text)?, 0)?;
    trusted
        .writer
        .send(&[Record::Batch(forwarded)])
        .await
        .map_err(text)?;
    let (_feeder, own) = sentinel(&relay).await?;
    assert_eq!(batches_until(&mut subscriber, &own).await?, vec![own]);
    Ok(())
}

#[tokio::test]
async fn a_batch_replayed_after_its_hash_is_forgotten_is_not_forwarded() -> Result {
    // A hash window short enough to pass several times inside the test.
    let window = Duration::from_millis(50);
    let relay = relay(Hub::new(8).remembering_hashes_for(window)).await?;
    let mut subscriber = subscribe(&relay).await?;
    let receiver = Identity::generate().map_err(text)?;
    let mut feed = connect(&relay, &receiver, Role::Feeder).await?;
    let old = batch(&receiver, 0)?;
    // Each send after a window rotates the hashes; two rotations forget the first batch's.
    for signed in [old.clone(), batch(&receiver, 100)?, batch(&receiver, 200)?] {
        feed.writer
            .send(&[Record::Batch(signed.clone())])
            .await
            .map_err(text)?;
        until(&mut subscriber, "a fresh batch", |record| {
            *record == Record::Batch(signed.clone())
        })
        .await?;
        tokio::time::sleep(window * 3).await;
    }
    let next = batch(&receiver, 201)?;
    feed.writer
        .send(&[Record::Batch(old.clone()), Record::Batch(next.clone())])
        .await
        .map_err(text)?;
    // The fan-out is in order, so the replay would have arrived before the next batch.
    let heard = until(&mut subscriber, "the next batch", |record| {
        *record == Record::Batch(next.clone())
    })
    .await?;
    assert!(
        !heard.contains(&Record::Batch(old)),
        "the replay was forwarded"
    );
    Ok(())
}

#[tokio::test]
async fn a_relays_own_batch_is_never_forwarded_as_a_receivers() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let mut subscriber = subscribe(&relay).await?;
    let feeder = Identity::generate().map_err(text)?;
    let mut session = connect(&relay, &feeder, Role::Feeder).await?;
    // Its own key, its own content, but signed in the relay domain.
    let derived = Batch::sign_as_relay(
        &feeder,
        &BatchContent {
            boot_id: 1,
            sequence: 0,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: vec![Observation::from_beast(&frames(1)?[0])],
        },
    )
    .map_err(text)?;
    derived.verify_as_relay().map_err(text)?;
    assert!(derived.verify().is_err());
    session
        .writer
        .send(&[Record::Batch(derived)])
        .await
        .map_err(text)?;
    told(&mut session).await?;
    let (_later, last) = sentinel(&relay).await?;
    assert_eq!(batches_until(&mut subscriber, &last).await?, vec![last]);
    Ok(())
}

#[tokio::test]
async fn a_subscribe_naming_too_many_regions_ends_the_session() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let mut session = subscribe(&relay).await?;
    let regions = (0..65)
        .map(|n| Region::containing(&at(f64::from(n) - 32.0, 0.0), 3).map_err(text))
        .collect::<Result<Vec<_>>>()?;
    session
        .writer
        .send(&[Record::Subscribe {
            streams: Streams::RAW,
            regions,
        }])
        .await
        .map_err(text)?;
    assert_eq!(
        told(&mut session).await?,
        Some(Record::Goodbye {
            reason: tally_wire::Reason::Protocol,
            retry_after_secs: 86_400,
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_feeder_over_its_ingest_ceiling_is_told_the_relay_is_full_and_dropped() -> Result {
    let relay = relay(Hub::new(8).max_feeder_bytes_per_sec(1)).await?;
    let receiver = Identity::generate().map_err(text)?;
    let mut feed = connect(&relay, &receiver, Role::Feeder).await?;
    let big: Vec<Observation> = frames(2_000)?.iter().map(Observation::from_beast).collect();
    // Just past the least burst and no further, so the relay has read everything sent when it
    // closes, and its goodbye is not lost to a reset.
    let mut sent = 0;
    let mut sequence = 0;
    while sent as u64 <= tally_relay::ceiling::MIN_BURST {
        let signed = Record::Batch(
            Batch::sign(
                &receiver,
                &BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: 0,
                    dropped: 0,
                    previous: [0; 32],
                    observations: big.clone(),
                },
            )
            .map_err(text)?,
        );
        let mut encoded = Vec::new();
        signed.encode(&mut encoded).map_err(text)?;
        sent += encoded.len();
        sequence += 1;
        feed.writer.send(&[signed]).await.map_err(text)?;
    }
    assert_eq!(
        told(&mut feed).await?,
        Some(Record::Goodbye {
            reason: tally_wire::Reason::Full,
            retry_after_secs: 60,
        })
    );
    Ok(())
}

#[tokio::test]
async fn beyond_the_connection_cap_a_connection_is_closed_before_its_handshake() -> Result {
    let relay = relay(Hub::new(8).max_connections(1)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let mut held = described_feeder(&relay, &beacon, None).await?;
    held.writer.send(&[Record::Heartbeat]).await.map_err(text)?;
    let mut second = TcpStream::connect(relay.address).await.map_err(text)?;
    let mut byte = [0; 1];
    let read = second.read(&mut byte).await;
    assert!(matches!(read, Ok(0) | Err(_)), "the relay answered");
    Ok(())
}

#[tokio::test]
async fn a_subscribe_sent_with_hello_decides_the_first_byte() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let palo_alto = at(37.44, -122.14);
    let outside = Identity::generate().map_err(text)?;
    let mut outside_feed = described_feeder(&relay, &outside, Some(at(51.5, -0.12))).await?;
    let mut world = subscribe(&relay).await?;
    until(&mut world, "the outside description", |record| {
        describes(record, outside.public())
    })
    .await?;
    let region = Region::containing(&palo_alto, 3).map_err(text)?;
    let stream = TcpStream::connect(relay.address).await.map_err(text)?;
    let mut regional = noise::connect_with(
        stream,
        &Identity::generate().map_err(text)?,
        &relay.key,
        Role::Subscriber,
        &[Record::Subscribe {
            streams: Streams::RAW,
            regions: vec![region],
        }],
    )
    .await
    .map_err(text)?;
    outside_feed
        .writer
        .send(&[Record::Batch(batch(&outside, 0)?)])
        .await
        .map_err(text)?;
    until(&mut world, "the outside batch", |record| {
        matches!(record, Record::Batch(_)) && author(record) == Some(outside.public())
    })
    .await?;
    let inside = Identity::generate().map_err(text)?;
    let mut inside_feed = described_feeder(&relay, &inside, Some(palo_alto)).await?;
    inside_feed
        .writer
        .send(&[Record::Batch(batch(&inside, 0)?)])
        .await
        .map_err(text)?;
    // Everything the regional subscriber was ever sent, up to the inside receiver's batch.
    let heard = until(&mut regional, "the inside batch", |record| {
        matches!(record, Record::Batch(_)) && author(record) == Some(inside.public())
    })
    .await?;
    assert!(
        heard
            .iter()
            .filter_map(author)
            .all(|key| key == inside.public()),
        "heard from outside the region"
    );
    assert!(
        heard
            .iter()
            .any(|record| describes(record, inside.public()))
    );
    Ok(())
}

#[tokio::test]
async fn beyond_its_addresss_cap_a_connection_is_closed_before_its_handshake_and_others_connect()
-> Result {
    let relay = relay(Hub::new(8)).await?;
    // Sixteen connections from one address that never begin a handshake hold its whole share.
    let mut held = Vec::new();
    for _ in 0..tally_relay::hub::DEFAULT_MAX_CONNECTIONS_PER_ADDRESS {
        held.push(TcpStream::connect(relay.address).await.map_err(text)?);
    }
    let mut seventeenth = TcpStream::connect(relay.address).await.map_err(text)?;
    let mut byte = [0; 1];
    let read = seventeenth.read(&mut byte).await;
    assert!(matches!(read, Ok(0) | Err(_)), "the relay answered");
    // Another address is still served, handshake and all.
    let socket = tokio::net::TcpSocket::new_v4().map_err(text)?;
    socket
        .bind("127.0.0.2:0".parse().map_err(text)?)
        .map_err(text)?;
    let stream = socket.connect(relay.address).await.map_err(text)?;
    let mut other = noise::connect(
        stream,
        &Identity::generate().map_err(text)?,
        &relay.key,
        Role::Feeder,
    )
    .await
    .map_err(text)?;
    until(&mut other, "the other address's greeting", |record| {
        matches!(record, Record::RateLimit { .. })
    })
    .await?;
    drop(held);
    Ok(())
}

#[tokio::test]
async fn a_feeder_is_told_its_rate_limit_and_the_relays_hints_first() -> Result {
    let hint = RelayAddress {
        key: Identity::generate().map_err(text)?.public(),
        address: "other.example:10900".to_owned(),
    };
    let ceiling = 100_000;
    let relay = relay(
        Hub::new(8)
            .advertising(vec![hint.clone()])
            .max_feeder_bytes_per_sec(ceiling),
    )
    .await?;
    let mut feed = connect(&relay, &Identity::generate().map_err(text)?, Role::Feeder).await?;
    let mut first = Vec::new();
    feed.reader.recv(&mut first).await.map_err(text)?;
    let (bytes_per_sec, burst) = tally_relay::ceiling::advertised(ceiling);
    assert!(bytes_per_sec < 100_000 && bytes_per_sec > 90_000);
    assert_eq!(
        first,
        vec![
            Record::RateLimit {
                bytes_per_sec,
                burst
            },
            Record::RelayList(vec![hint]),
        ]
    );
    Ok(())
}

/// Capacity is admission (RFC-0178 §9): a relay whose memory holds one feeder's share of every
/// store takes the first feeder and turns the second away at its Hello, pointed at the relays it
/// knows, before anything it sent is taken in; the first is served on, and leaving frees its slot.
#[tokio::test]
async fn a_feeder_beyond_the_memory_budget_is_refused_at_its_hello() -> Result {
    let hint = RelayAddress {
        key: Identity::generate().map_err(text)?.public(),
        address: "other.example:10900".to_owned(),
    };
    let one = tally_relay::budget::PerFeeder::planned(false).total();
    let hub = Hub::new(8)
        .advertising(vec![hint.clone()])
        .memory(tally_relay::budget::BASE_BYTES + one + one / 2, false);
    assert_eq!(hub.budget().ceiling(), 1);
    let relay = relay(hub).await?;
    let mut first = connect(&relay, &Identity::generate().map_err(text)?, Role::Feeder).await?;
    let mut greeting = Vec::new();
    first.reader.recv(&mut greeting).await.map_err(text)?;
    assert!(matches!(greeting.first(), Some(Record::RateLimit { .. })));
    let mut second = connect(&relay, &Identity::generate().map_err(text)?, Role::Feeder).await?;
    let mut refused = Vec::new();
    second.reader.recv(&mut refused).await.map_err(text)?;
    assert_eq!(
        refused.first(),
        Some(&Record::Redirect {
            retry_after_secs: 600,
            hints: vec![hint],
        })
    );
    // The first leaves; its slot is free for the next.
    drop(first);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut third = connect(&relay, &Identity::generate().map_err(text)?, Role::Feeder).await?;
        let mut answer = Vec::new();
        third.reader.recv(&mut answer).await.map_err(text)?;
        if matches!(answer.first(), Some(Record::RateLimit { .. })) {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err("the first feeder's slot was never freed".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Two engines' clock models of the same inputs that differ: a fault anyone proves with the two
/// manifests, which the relay checks and forwards; two that agree prove nothing.
#[tokio::test]
async fn a_model_fault_proof_is_checked_then_forwarded_and_a_false_one_ends_the_session() -> Result
{
    let relay = relay(Hub::new(8)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let (mut listener, _) = subscribed(
        &relay,
        Role::Subscriber,
        Streams::RAW.with(Streams::POSITIONS),
        Vec::new(),
        beacon.public(),
    )
    .await?;
    let model = |engine: &Identity, bytes: &[u8]| -> Result<ClockModel> {
        ClockModel::sign(
            engine,
            &ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1,
                spec_version: 1,
                inputs: [3; 32],
                model: bytes.to_vec(),
            },
        )
        .map(|signed| signed.manifest)
        .map_err(text)
    };
    let (honest, liar) = (
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
    );
    let truth = model(&honest, b"the model")?;
    let proof = FaultProof::models(&truth, &model(&liar, b"another")?).map_err(text)?;
    let mut accuser = subscribe(&relay).await?;
    accuser
        .writer
        .send(&[Record::FaultProof(proof.clone())])
        .await
        .map_err(text)?;
    until(&mut listener, "the model fault proof", |record| {
        *record == Record::FaultProof(proof.clone())
    })
    .await?;
    let agreeing = FaultProof::models(&truth, &model(&liar, b"the model")?).map_err(text)?;
    accuser
        .writer
        .send(&[Record::FaultProof(agreeing)])
        .await
        .map_err(text)?;
    ended(&mut accuser).await;
    Ok(())
}

/// RFC-0174's seam through a real relay: a probe sent with Hello is answered first, signed by the
/// relay, before anything else it says; and a delivery query on the same session is answered,
/// signed, naming the query's nonce. What the answers declare is each duty's.
#[tokio::test]
async fn a_probe_and_a_delivery_query_are_answered_signed_by_the_relay() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let feeder = Identity::generate().map_err(text)?;
    let stream = TcpStream::connect(relay.address).await.map_err(text)?;
    let mut session = noise::connect_with(
        stream,
        &feeder,
        &relay.key,
        Role::Feeder,
        &[Record::Echo(tally_wire::Echo { nonce: 7 })],
    )
    .await
    .map_err(text)?;
    let mut first = Vec::new();
    session.reader.recv(&mut first).await.map_err(text)?;
    let Some(Record::EchoReply(reply)) = first.first() else {
        return Err(format!("the first answer was {first:?}"));
    };
    reply.verify().map_err(text)?;
    assert_eq!(reply.signer().map_err(text)?, relay.key);
    assert_eq!(reply.content().map_err(text)?.nonce, 7);

    // The query carries the feeder's signed grant of tag keys to this relay, as every one does.
    let keys = tally_wire::TagKeys::sign(
        &feeder,
        &tally_wire::TagKeysContent {
            member: relay.key,
            current: tally_wire::TagKey {
                id: 1,
                key: [1; 32],
            },
            next: tally_wire::TagKey {
                id: 2,
                key: [2; 32],
            },
            switch_in_ms: 1_000,
        },
    )
    .map_err(text)?;
    let query = tally_wire::DeliveryQuery {
        nonce: [3; 32],
        receiver: feeder.public(),
        boot_id: 1,
        ranges: vec![tally_wire::SequenceRange { first: 0, last: 3 }],
        keys: Some(keys),
    };
    session
        .writer
        .send(&[Record::DeliveryQuery(query)])
        .await
        .map_err(text)?;
    let heard = until(&mut session, "the delivery answer", |record| {
        matches!(record, Record::DeliveryAnswer(_))
    })
    .await?;
    let Some(Record::DeliveryAnswer(answer)) = heard
        .iter()
        .find(|record| matches!(record, Record::DeliveryAnswer(_)))
    else {
        return Err("no answer".to_owned());
    };
    answer.verify().map_err(text)?;
    assert_eq!(answer.signer().map_err(text)?, relay.key);
    let content = answer.content().map_err(text)?;
    assert_eq!(
        (content.nonce, content.receiver),
        ([3; 32], feeder.public())
    );
    Ok(())
}
