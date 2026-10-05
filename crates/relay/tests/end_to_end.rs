//! A receiver's frames, end to end, over real sockets: a stand-in readsb serving BEAST, a real
//! feeder reading it, a real relay, and subscribers on both of the relay's outputs (RFC-0166 §10
//! steps 3 and 4); then the relay's streams, regions, engines and redirects (§3.6 to §3.8).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tally_feed::config::Config;
use tally_relay::hub::Hub;
use tally_relay::link;
use tally_wire::batch::ReceiverInfoContent;
use tally_wire::beast::Decoder;
use tally_wire::noise::{self, Session};
use tally_wire::{
    Batch, BatchContent, Clock, Frame, FrameKind, Identity, Location, Observation, Position,
    Positions, PositionsContent, PublicKey, ReceiverInfo, Record, Region, RelayAddress, Role,
    Streams,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

type Result<T = ()> = std::result::Result<T, String>;

const WAIT: Duration = Duration::from_secs(20);

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

/// A stand-in readsb: whoever connects is sent `frames` as BEAST, then the stream stays open.
async fn readsb(frames: Vec<Frame>) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut bytes = Vec::new();
            for frame in &frames {
                frame.encode_beast(&mut bytes);
            }
            tokio::spawn(async move {
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
    let identity = Identity::generate().map_err(text)?;
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
    let source = readsb(sent.clone()).await?;
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
        home: None,
        relay_count: 1,
        state_dir: dir.clone(),
        location: Some(location),
        clock: Clock::Dump1090,
        ceiling: 1_000_000,
    }));

    // The subscriber gets the receiver's signed description and its batches, verified.
    let mut heard = Vec::new();
    let mut described = false;
    timeout(WAIT, async {
        let mut records = Vec::new();
        while heard.len() < sent.len() {
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
                    }
                    _ => {}
                }
            }
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|_| format!("only {} of {} frames arrived", heard.len(), sent.len()))??;
    assert_eq!(heard, sent);
    assert!(described, "no receiver info arrived");

    // The loopback output carries the same frames as plain BEAST, for a local readsb.
    let mut decoder = Decoder::new();
    let mut decoded = Vec::new();
    let mut buffer = vec![0; 64 * 1024];
    timeout(WAIT, async {
        while decoded.len() < sent.len() {
            let length = beast.read(&mut buffer).await.map_err(text)?;
            if length == 0 {
                return Err("beast-out closed".to_owned());
            }
            decoder.push(&buffer[..length], |frame| decoded.push(frame));
        }
        Ok(())
    })
    .await
    .map_err(|_| format!("beast-out gave {} of {} frames", decoded.len(), sent.len()))??;
    assert_eq!(decoded, sent);

    // The feeder remembered the relay it anchored to.
    let anchor = std::fs::read_to_string(dir.join("anchor")).map_err(text)?;
    assert!(anchor.contains(&relay.key.to_base64()));
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
    let ended = timeout(WAIT, async {
        let mut records = Vec::new();
        while session.reader.recv(&mut records).await.is_ok() {}
    })
    .await;
    assert!(ended.is_ok(), "the relay kept the session");
    // The subscriber saw the impostor's own batch, signed by it, and nothing in the victim's name.
    let mut seen = Vec::new();
    timeout(Duration::from_secs(2), async {
        loop {
            let mut got = Vec::new();
            if subscriber.reader.recv(&mut got).await.is_err() {
                return;
            }
            seen.extend(got.into_iter().filter_map(|record| match record {
                Record::Batch(batch) => Some(batch),
                _ => None,
            }));
        }
    })
    .await
    .ok();
    assert_eq!(seen, vec![honest]);
    Ok(())
}

#[tokio::test]
async fn a_batch_arriving_twice_is_forwarded_once() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let mut subscriber = subscribe(&relay).await?;
    let receiver = Identity::generate().map_err(text)?;
    let once = batch(&receiver, 0)?;
    // Two relays forwarding the same batch: two Relay-role sessions publishing it.
    for _ in 0..2 {
        let stream = TcpStream::connect(relay.address).await.map_err(text)?;
        let mut session = noise::connect(
            stream,
            &Identity::generate().map_err(text)?,
            &relay.key,
            Role::Relay,
        )
        .await
        .map_err(text)?;
        session
            .writer
            .send(&[Record::Batch(once.clone())])
            .await
            .map_err(text)?;
        std::mem::forget(session);
    }
    let mut hashes = HashSet::new();
    let mut count = 0;
    timeout(Duration::from_secs(2), async {
        loop {
            let mut got = Vec::new();
            if subscriber.reader.recv(&mut got).await.is_err() {
                return;
            }
            for record in got {
                if let Record::Batch(batch) = record {
                    count += 1;
                    hashes.insert(batch.hash());
                }
            }
        }
    })
    .await
    .ok();
    assert_eq!((count, hashes.len()), (1, 1));
    Ok(())
}

#[tokio::test]
async fn a_stalled_subscriber_is_dropped_and_the_others_keep_every_batch() -> Result {
    // A small fan-out slack, so a subscriber that stops reading falls behind quickly.
    let relay = relay(Hub::with_capacity(8, 16)).await?;
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
            // Paced so the reading subscriber keeps up and only the stalled one falls behind.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok::<_, String>(feeder)
    });
    let mut sequences = Vec::new();
    timeout(Duration::from_secs(60), async {
        while sequences.len() < usize::try_from(total).unwrap_or(usize::MAX) {
            let mut got = Vec::new();
            fast.reader.recv(&mut got).await.map_err(text)?;
            sequences.extend(got.into_iter().filter_map(|record| match record {
                Record::Batch(batch) => Some(batch.sequence()),
                _ => None,
            }));
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|_| format!("the fast subscriber got {} of {total}", sequences.len()))??;
    assert_eq!(sequences, (0..total).collect::<Vec<_>>());
    sending.await.map_err(text)??;

    // The stalled one was told it fell behind (or simply cut off) rather than slowing anyone.
    let mut stalled = stalled;
    let mut ended = false;
    timeout(Duration::from_secs(20), async {
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
        ended = true;
    })
    .await
    .ok();
    assert!(ended, "the stalled subscriber was never dropped");
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
    timeout(WAIT, async {
        let mut all = Vec::new();
        loop {
            let mut got = Vec::new();
            session.reader.recv(&mut got).await.map_err(text)?;
            let found = got.iter().any(&mut done);
            all.extend(got);
            if found {
                return Ok(all);
            }
        }
    })
    .await
    .map_err(|_| format!("waited too long for {what}"))?
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
    let mut feeds = Vec::new();
    for counter in [10, 20] {
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
                    data: message.clone(),
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
    let copies = |records: &[Record]| -> Result<(usize, Vec<Batch>)> {
        let mut copies = 0;
        let mut signed = Vec::new();
        for record in records {
            if let Record::RelayBatch(batch) = record {
                batch.verify().map_err(text)?;
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
    let first = until(&mut subscriber, "the deduplicated stream", |record| {
        matches!(record, Record::RelayBatch(_))
    })
    .await?;
    let (mut total, signed) = copies(&first)?;
    assert_eq!(signed.first().map(Batch::sequence), Some(0));
    // A flush or two later, past the window: still the one copy.
    let mut later = Vec::new();
    timeout(Duration::from_millis(3_500), async {
        loop {
            let mut got = Vec::new();
            if subscriber.reader.recv(&mut got).await.is_err() {
                return;
            }
            later.extend(got);
        }
    })
    .await
    .ok();
    total += copies(&later)?.0;
    assert_eq!(total, 1);
    Ok(())
}

fn positions(engine: &Identity, sequence: u64) -> Result<Positions> {
    Positions::sign(
        engine,
        &PositionsContent {
            sequence,
            issued_ms: 1_791_220_000_000,
            positions: vec![Position {
                address: 0xa1b2c3,
                time_ms: 1_791_219_999_000,
                lat_e7: 374_100_000,
                lon_e7: -1_221_000_000,
                alt_ft: Some(4_500),
                sigma_m: 60,
                receivers: 5,
            }],
        },
    )
    .map_err(text)
}

#[tokio::test]
async fn an_engines_positions_reach_subscribers_and_a_forger_is_cut_off() -> Result {
    let relay = relay(Hub::new(8)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let (mut subscriber, _) = subscribed(
        &relay,
        Role::Subscriber,
        Streams::RAW.with(Streams::POSITIONS),
        Vec::new(),
        beacon.public(),
    )
    .await?;
    let engine = Identity::generate().map_err(text)?;
    let mut session = connect(&relay, &engine, Role::Engine).await?;
    let solved = positions(&engine, 0)?;
    session
        .writer
        .send(&[Record::Positions(solved.clone())])
        .await
        .map_err(text)?;
    until(&mut subscriber, "the engine's positions", |record| {
        *record == Record::Positions(solved.clone())
    })
    .await?;

    // Positions in another engine's name end the session, and are forwarded to no one.
    let forged = positions(&Identity::generate().map_err(text)?, 0)?;
    session
        .writer
        .send(&[Record::Positions(forged.clone())])
        .await
        .map_err(text)?;
    let ended = timeout(WAIT, async {
        let mut records = Vec::new();
        while session.reader.recv(&mut records).await.is_ok() {}
    })
    .await;
    assert!(ended.is_ok(), "the relay kept the forger's session");
    let mut again = connect(&relay, &engine, Role::Engine).await?;
    let next = positions(&engine, 1)?;
    again
        .writer
        .send(&[Record::Positions(next.clone())])
        .await
        .map_err(text)?;
    let heard = until(&mut subscriber, "the engine's next positions", |record| {
        *record == Record::Positions(next.clone())
    })
    .await?;
    assert!(!heard.contains(&Record::Positions(forged)));
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
    let ended = timeout(WAIT, async {
        let mut records = Vec::new();
        while second.reader.recv(&mut records).await.is_ok() {}
    })
    .await;
    assert!(ended.is_ok(), "the relay kept the redirected session");
    Ok(())
}
