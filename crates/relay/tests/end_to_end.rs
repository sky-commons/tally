//! A receiver's frames, end to end, over real sockets: a stand-in readsb serving BEAST, a real
//! feeder reading it, a real relay, and readers on both of the relay's outputs (RFC-0171 §10
//! steps 3 and 4); then the relay's streams, regions, engines and redirects (§3.6 to §3.8).
//!
//! Raw, sites and full clock models are a relay's, never a client's (§3.5, wire version 3): what a
//! relay is sent of them is read by an engine of a relay this one verified (a socket, for the raw
//! of the areas it solves) or, for what only member links carry, by a listener on the fan-out
//! with a relay link's filter ([`relay_view`]); what a client is sent, by a client.
//!
//! Nothing here is timed. A test waits for what it is looking for, and the test runner's own
//! deadline is what fails one that never comes. That something did *not* happen is shown by order,
//! not by waiting a while: the relay's fan-out is in order, so a sentinel published after the
//! event is heard after anything the event let through.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tally_feed::config::{Config, Key};
use tally_relay::directory::Group;
use tally_relay::fanout::{Filter, Listener};
use tally_relay::hub::Hub;
use tally_relay::link;
use tally_relay::mlat_host::{MlatHost, MlatReport};
use tally_relay::sharing::Deadlines;
use tally_relay::subscription::Subscription;
use tally_wire::beast::Decoder;
use tally_wire::noise::{self, Session};
use tally_wire::rendezvous::area_of;
use tally_wire::{
    Batch, BatchContent, Clock, ClockModel, ClockModelContent, EnuCovariance, FaultProof, Frame,
    FrameKind, Identity, Location, Observation, ObservationSet, Positions, ProviderOffer,
    ProviderOfferContent, PublicInfoContent, PublicKey, ReceiverInfo, ReceiverSite,
    ReceiverSiteContent, Reception, Record, Region, RelayAddress, Role, Solution, SolutionsContent,
    Streams, TransmitTime,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Result<T = ()> = std::result::Result<T, String>;

/// What a test that must name a deadline waits for an event before calling it a hang: a guard on a
/// relay that never gets there, never a verdict on how fast the machine running the test is.
const HANG: Duration = Duration::from_secs(120);

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
    hub: Arc<Hub>,
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
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    Ok(Relay {
        address,
        beast_out,
        key,
        hub,
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

/// Where the tests' placed receivers are (Palo Alto): the area a raw reader solves.
fn here() -> Location {
    at(37.44, -122.14)
}

/// Makes `engine` a relay `hub` verified at its address, solving the area of `place` with cores to
/// spare: a member, which alone may take raw, and then only of the areas it solves and their band
/// (RFC-0174 §2.3, `subscription::engine_grant`).
fn verify_engine(hub: &Hub, engine: &Identity, place: &Location) -> Result {
    let now = tally_relay::network::wall_ms();
    let offer = ProviderOffer::sign(
        engine,
        &ProviderOfferContent {
            address: "engine.example:10900".to_owned(),
            cell: area_of(place).map_err(text)?,
            products: Streams::RAW,
            stripes_of: 1,
            stripes: 1,
            mlat_cores: 8,
            feeder_slots: 0,
            network: 64_512,
            issued_ms: now,
            expires_ms: now + 600_000,
        },
    )
    .map_err(text)?;
    let key = engine.public();
    let group = Group::V4(u16::from_be_bytes([key.as_bytes()[0], key.as_bytes()[1]]));
    hub.network().directory.hold_verified(offer, group, now)?;
    Ok(())
}

/// A reader of `relay`'s raw around `place`, over a socket: an engine of a relay it verified,
/// subscribed to the raw of the area there (raw is a relay's, never a client's, RFC-0171 §3.5),
/// returned once the relay has certainly applied that (a beacon placed there has reached it), with
/// the beacon's session.
async fn raw_reader(
    relay: &Relay,
    place: Location,
) -> Result<(Session<TcpStream>, Session<TcpStream>)> {
    let beacon = Identity::generate().map_err(text)?;
    let beacon_feed = described_feeder(relay, &beacon, Some(place)).await?;
    let engine = Identity::generate().map_err(text)?;
    verify_engine(&relay.hub, &engine, &place)?;
    let mut session = connect(relay, &engine, Role::Engine).await?;
    session
        .writer
        .send(&[Record::Subscribe {
            streams: Streams::RAW,
            regions: vec![area_of(&place).map_err(text)?],
        }])
        .await
        .map_err(text)?;
    // Its site, which an engine places it by: in the answer when the relay already held it, else
    // routed to the engine by its own cell when it arrives.
    until(&mut session, "the beacon's site", |record| {
        matches!(record, Record::ReceiverSite(site) if site.receiver().ok() == Some(beacon.public()))
    })
    .await?;
    Ok((session, beacon_feed))
}

/// What the fan-out hands a relay-role link subscribed to `streams` of the whole world: what a
/// member's link is sent of them, which no test session can hold (its sharing groups carry them),
/// read in process. Raw comes with every receiver's description and site, located or not.
fn relay_view(relay: &Relay, streams: Streams) -> Listener {
    relay.hub.listen(
        u64::MAX - 1,
        Filter::Subscription(Subscription {
            streams,
            regions: Vec::new(),
        }),
    )
}

/// Reads a relay view until a record `done` accepts; returns every record read.
async fn relay_until(
    view: &Listener,
    what: &str,
    mut done: impl FnMut(&Record) -> bool,
) -> Result<Vec<Record>> {
    let mut all = Vec::new();
    loop {
        let mut taken = Vec::new();
        view.recv_many(&mut taken, 64)
            .await
            .map_err(|fell| format!("waiting for {what}: {fell:?}"))?;
        let records: Vec<Record> = taken
            .into_iter()
            .map(|one| (*one.into_item().record).clone())
            .collect();
        let found = records.iter().any(&mut done);
        all.extend(records);
        if found {
            return Ok(all);
        }
    }
}

/// Every batch a relay view is handed, up to and including `last`.
async fn relay_batches_until(view: &Listener, last: &Batch) -> Result<Vec<Batch>> {
    let heard = relay_until(view, "the last batch", |record| {
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

/// What no client may be sent (RFC-0171 §3.5): raw, a site, a description that carries one, the
/// deduplicated stream (its counters), or a full clock model.
fn relay_only(record: &Record) -> bool {
    match record {
        Record::ReceiverInfo(info) => info.carries_site(),
        Record::Batch(_)
        | Record::RelayBatch(_)
        | Record::RegionalBatch(_)
        | Record::ReceiverSite(_)
        | Record::ClockModel(_)
        | Record::ClockModelPart(_) => true,
        Record::Positions(positions) | Record::Provisional(positions) => !positions.is_tagged(),
        _ => false,
    }
}

/// Fails on the first record no client may be sent.
fn assert_client_safe(records: &[Record]) {
    for record in records {
        assert!(!relay_only(record), "a client was sent {record:?}");
    }
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
    let relay = relay(Hub::new(8, Deadlines::RELAY).serving_beast(1)).await?;
    let location = Location {
        lat_e7: 374_100_000,
        lon_e7: -1_221_000_000,
        alt_m: 10,
        precision_m: 0,
    };
    // The signed output is a relay's: an engine of one this relay verified, taking the raw of
    // the receiver's area. A client of the raw stream beside it.
    let (mut subscriber, _beacon) = raw_reader(&relay, location).await?;
    let mut client = subscribe(&relay).await?;
    let mut beast = TcpStream::connect(relay.beast_out).await.map_err(text)?;

    let dir = state_dir()?;
    let key_file = dir.join("key");
    tally_feed::init(&key_file)?;
    let feeder = Identity::from_base64(&std::fs::read_to_string(&key_file).map_err(text)?)
        .map_err(text)?
        .public();
    tokio::spawn(tally_feed::run(Config {
        key: Key::File(key_file),
        source: source.to_string(),
        uat: None,
        acars: Vec::new(),
        acars_ceiling: tally_feed::source::DEFAULT_ACARS_CEILING,
        relays: vec![RelayAddress {
            key: relay.key,
            address: relay.address.to_string(),
        }],
        seeds: Vec::new(),
        state_dir: dir.clone(),
        location: Some(location),
        clock: Clock::Dump1090,
        ceiling: 1_000_000,
        source_address: None,
        deflate_level: None,
    }));

    // The relay's reader gets the receiver's signed description (its public cell, no site), its
    // signed site, and its batches, verified.
    let mut heard = Vec::new();
    let mut described = false;
    let mut sited = false;
    let mut named = false;
    {
        let mut records = Vec::new();
        while heard.len() < sent.len() || !named || !sited {
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
                    Record::ReceiverInfo(info) if author(record) == Some(feeder) => {
                        info.verify().map_err(text)?;
                        assert!(
                            !info.carries_site(),
                            "a version 3 feeder described its site"
                        );
                        let content = info.public().map_err(text)?;
                        assert_eq!(
                            content.cell,
                            Some(Region::public_cell(&location).map_err(text)?)
                        );
                        described = true;
                        // Its description reached the relay over its session: it is publishing.
                        publishing.send_replace(true);
                        named |= content.relays.contains(&relay.key);
                    }
                    Record::ReceiverSite(site) if site.receiver().ok() == Some(feeder) => {
                        site.verify().map_err(text)?;
                        assert_eq!(site.content().map_err(text)?.location, location);
                        sited = true;
                    }
                    _ => {}
                }
            }
        }
    }
    assert_eq!(heard, sent);
    assert!(described, "no receiver info arrived");

    // The client of the raw stream is sent the receiver's public description and nothing of its
    // raw or its site: everything it was sent up to a receiver described after every batch.
    let later = Identity::generate().map_err(text)?;
    let _later_feed = described_feeder(&relay, &later, Some(location)).await?;
    let told = until(&mut client, "a later description", |record| {
        describes(record, later.public())
    })
    .await?;
    assert!(told.iter().any(|record| describes(record, feeder)));
    assert_client_safe(&told);

    // The loopback output carries the same messages as plain BEAST, for a local readsb, each in
    // its client form: no receiver's counter, no signal level.
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
    let client_form = sent
        .iter()
        .map(|frame| tally_wire::Frame::new(frame.kind(), 0, 0, frame.message()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(text)?;
    assert_eq!(decoded, client_form);
    assert!(
        sent.iter()
            .any(|frame| frame.timestamp() != 0 && frame.signal() != 0)
    );

    // The feeder's signed description names the relay it publishes to (above, `named`): what a
    // relay's credit counts it by (RFC-0174 §2.1).
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A stand-in acars_router serving `lines` on its TCP output, one a line, to whoever connects, again
/// every 100 ms: a batch sealed before the feeder's session is up is gone (as for [`readsb`]), and
/// the relay forwards a message it has already forwarded once.
async fn acars_router(lines: &'static str) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                while stream.write_all(lines.as_bytes()).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }
    });
    Ok(address)
}

/// acarsdec's, dumpvdl2's and dumphfdl's own lines, as acars_router serves them (shortened from
/// crates/feed/testdata, which cites each), go from a feeder's `--acars` through the relay to its
/// `--acars-out` in the one flat schema: the station, its signal, its frequency, its clock past the
/// second and the decoders' frame trees never leave it, and a frame with no ACARS (a ground
/// station's XID), a block acarsdec is still reassembling or a block with more to follow is never
/// published.
#[tokio::test]
async fn a_decoders_messages_reach_acars_out_without_the_receivers_fields() -> Result {
    const LINES: &str = concat!(
        r#"{"timestamp":1516206744.1849549,"station_id":"XX","channel":2,"freq":130.025,"#,
        r#""level":-22,"error":0,"mode":"2","label":"H1","block_id":"6","ack":false,"#,
        r##""tail":".N842UA","flight":"UA1412","msgno":"D04G","text":"#DFB"}"##,
        "\n",
        r#"{"timestamp":1516206745.1,"mode":"2","label":"H1","block_id":"8","ack":false,"#,
        r#""tail":".N842UA","flight":"UA1412","msgno":"D06A","text":"CD","end":true}"#,
        "\n",
        r#"{"timestamp":1516206745.5,"mode":"2","label":"H1","block_id":"7","ack":false,"#,
        r#""tail":".N842UA","flight":"UA1412","msgno":"D05A","text":"AB","assstat":"in progress"}"#,
        "\n",
        r#"{"vdl2":{"app":{"name":"dumpvdl2","ver":"2.1.1"},"station":"XX","freq":136975000,"#,
        r#""sig_level":-20.8,"t":{"sec":1645287903,"usec":757630},"#,
        r#""avlc":{"src":{"addr":"281658","type":"Ground station"},"xid":{"type":"GSIF"}}}}"#,
        "\n",
        r#"{"vdl2":{"app":{"name":"dumpvdl2","ver":"2.5.1"},"station":"XX","sig_level":-16.6,"#,
        r#""t":{"sec":1769990648,"usec":949234},"avlc":{"src":{"addr":"ABFDAF","type":"Aircraft"},"#,
        r#""dst":{"addr":"1144AA","type":"Ground station"},"acars":{"crc_ok":true,"more":false,"#,
        r#""reg":".N8719Q","mode":"2","label":"H1","blk_id":"3","ack":"!","flight":"WN2340","#,
        r#""msg_num":"D09","msg_num_seq":"A","msg_text":"ABS"}}}}"#,
        "\n",
        r#"{"hfdl":{"app":{"name":"dumphfdl","ver":"1.7.0"},"freq":17919000,"#,
        r#""sig_level":-9.873339,"station":"CS-KABQ-HFDL","t":{"sec":1769991943,"usec":852110},"#,
        r#""lpdu":{"dst":{"type":"Aircraft","id":223,"ac_info":{"icao":"A9CFF8"}},"#,
        r#""src":{"type":"Ground station","id":1,"name":"San Francisco, California"},"#,
        r#""hfnpdu":{"acars":{"more":false,"reg":".N731NK","mode":"2","label":"_d","blk_id":"D","#,
        r#""ack":"3","msg_text":""}}}}}"#,
        "\n",
    );
    let (_, ready) = tokio::sync::watch::channel(false);
    let source = readsb(Vec::new(), ready).await?;
    let router = acars_router(LINES).await?;
    let relay = relay(Hub::new(8, Deadlines::RELAY).serving_acars(1)).await?;
    let acars = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let acars_out = acars.local_addr().map_err(text)?;
    tokio::spawn(link::serve_acars(acars, Arc::clone(&relay.hub)));
    let mut out = TcpStream::connect(acars_out).await.map_err(text)?;

    let dir = state_dir()?;
    let key_file = dir.join("key");
    tally_feed::init(&key_file)?;
    tokio::spawn(tally_feed::run(Config {
        key: Key::File(key_file),
        source: source.to_string(),
        uat: None,
        acars: vec![router.to_string()],
        acars_ceiling: tally_feed::source::DEFAULT_ACARS_CEILING,
        relays: vec![RelayAddress {
            key: relay.key,
            address: relay.address.to_string(),
        }],
        seeds: Vec::new(),
        state_dir: dir.clone(),
        location: Some(here()),
        clock: Clock::Dump1090,
        ceiling: 1_000_000,
        source_address: None,
        deflate_level: None,
    }));

    let expected = HashSet::from([
        concat!(
            r#"{"ack":"!","block":"6","flight":"UA1412","kind":"acars","label":"H1","mode":"2","#,
            r##""msgnum":"D04G","reg":"N842UA","sublabel":"DF","t":1516206744,"##,
            r##""text":"#DFB"}"##
        )
        .to_owned(),
        concat!(
            r#"{"ack":"!","block":"3","flight":"WN2340","gs":"1144AA","icao":"ABFDAF","#,
            r#""kind":"vdl2","label":"H1","mode":"2","msgnum":"D09A","#,
            r#""reg":"N8719Q","t":1769990648,"text":"ABS"}"#
        )
        .to_owned(),
        concat!(
            r#"{"ack":"3","block":"D","gs":"1","kind":"hfdl","label":"_d","#,
            r#""mode":"2","reg":"N731NK","t":1769991943}"#
        )
        .to_owned(),
    ]);
    let mut heard = HashSet::new();
    let mut pending = Vec::new();
    let mut buffer = vec![0; 64 * 1024];
    while heard.len() < expected.len() {
        let length = tokio::time::timeout(Duration::from_secs(60), out.read(&mut buffer))
            .await
            .map_err(|_| format!("acars-out sent nothing for 60 s after {heard:?}"))?
            .map_err(text)?;
        if length == 0 {
            return Err(format!("acars-out closed after {heard:?}"));
        }
        pending.extend_from_slice(&buffer[..length]);
        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let line = String::from_utf8(line[..end].to_vec()).map_err(text)?;
            assert!(expected.contains(&line), "acars-out wrote {line}");
            heard.insert(line);
        }
    }
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
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    let subscriber = relay_view(&relay, Streams::RAW);
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
    let seen = relay_batches_until(&subscriber, &last).await?;
    assert_eq!(seen, vec![honest, last]);
    Ok(())
}

#[tokio::test]
async fn a_batch_arriving_twice_is_forwarded_once() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    let subscriber = relay_view(&relay, Streams::RAW);
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
        heard.extend(relay_batches_until(&subscriber, &last).await?);
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
        Hub::new(8, Deadlines::RELAY)
            .queue_bytes(1 << 20)
            .max_feeder_bytes_per_sec(1 << 30),
    )
    .await?;
    // Two readers of the raw (engines of relays this one verified: raw is a relay's), and the
    // feeder placed where they read.
    let (mut fast, _fast_beacon) = raw_reader(&relay, here()).await?;
    let (stalled, _stalled_beacon) = raw_reader(&relay, here()).await?;
    let receiver = Identity::generate().map_err(text)?;
    let mut feeder = placed(&relay, &receiver).await?;
    // Big batches, enough to fill the stalled subscriber's socket buffers many times over: few
    // receptions of long messages, so the feeder's receptions a second
    // (`ingest::FEEDER_RECEPTIONS_PER_SEC`) let the flood through in seconds.
    let big: Vec<tally_wire::Observation> = (0..100u32)
        .map(|n| tally_wire::Observation {
            format: tally_wire::batch::format::MODE_S_LONG,
            timestamp: 1_000 + u64::from(n),
            signal: 100,
            data: [0x8d_u8; 4]
                .into_iter()
                .chain(n.to_be_bytes())
                .cycle()
                .take(480)
                .collect(),
        })
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

/// A fresh feeder's own batch, published now, placed `here`: anything published before it reaches
/// a reader of that raw before it does.
async fn sentinel(relay: &Relay) -> Result<(Session<TcpStream>, Batch)> {
    let identity = Identity::generate().map_err(text)?;
    let mut session = placed(relay, &identity).await?;
    let last = batch(&identity, 0)?;
    session
        .writer
        .send(&[Record::Batch(last.clone())])
        .await
        .map_err(text)?;
    Ok((session, last))
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

/// A receiver's description as a feeder of wire version 3 signs it, issued at `issued_ms`: its
/// public cell, no site, naming `relays`.
fn info_naming(
    identity: &Identity,
    location: Option<Location>,
    issued_ms: u64,
    relays: Vec<PublicKey>,
) -> Result<ReceiverInfo> {
    ReceiverInfo::sign_public(
        identity,
        &PublicInfoContent {
            issued_ms,
            cell: location
                .as_ref()
                .map(Region::public_cell)
                .transpose()
                .map_err(text)?,
            clock: Clock::Dump1090,
            software: "test".to_owned(),
            relays,
        },
    )
    .map_err(text)
}

/// A receiver's site (relay-only), issued at `issued_ms`.
fn site(identity: &Identity, location: Location, issued_ms: u64) -> Result<ReceiverSite> {
    ReceiverSite::sign(
        identity,
        &ReceiverSiteContent {
            issued_ms,
            location,
            clock: Clock::Dump1090,
        },
    )
    .map_err(text)
}

/// A feeder session that has published its own description and, when located, its site, as a
/// feeder of wire version 3 does.
async fn described_feeder(
    relay: &Relay,
    identity: &Identity,
    location: Option<Location>,
) -> Result<Session<TcpStream>> {
    described_feeder_naming(relay, identity, location, Vec::new()).await
}

async fn described_feeder_naming(
    relay: &Relay,
    identity: &Identity,
    location: Option<Location>,
    relays: Vec<PublicKey>,
) -> Result<Session<TcpStream>> {
    let mut session = connect(relay, identity, Role::Feeder).await?;
    let mut records = vec![Record::ReceiverInfo(info_naming(
        identity, location, 1, relays,
    )?)];
    if let Some(location) = location {
        records.push(Record::ReceiverSite(site(identity, location, 1)?));
    }
    session.writer.send(&records).await.map_err(text)?;
    Ok(session)
}

/// A feeder session placed `here`: what an engine's raw is routed by.
async fn placed(relay: &Relay, identity: &Identity) -> Result<Session<TcpStream>> {
    described_feeder(relay, identity, Some(here())).await
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

/// A regional reader hears only receivers inside its region: an engine (a relay's) their raw, and
/// a client their public descriptions, routed by their public cells.
#[tokio::test]
async fn a_regional_subscriber_hears_only_receivers_inside_its_region() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    let palo_alto = here();
    let london = at(51.5, -0.12);
    let inside = Identity::generate().map_err(text)?;
    let outside = Identity::generate().map_err(text)?;
    let nowhere = Identity::generate().map_err(text)?;
    // Two readers of the raw: one solving the area inside, and one the area outside, which says
    // when the outside raw has been taken in.
    let (mut regional_raw, _inside_beacon) = raw_reader(&relay, palo_alto).await?;
    let (mut outside_raw, _outside_beacon) = raw_reader(&relay, london).await?;
    let mut inside_feed = described_feeder(&relay, &inside, Some(palo_alto)).await?;
    let mut outside_feed = described_feeder(&relay, &outside, Some(london)).await?;
    let mut nowhere_feed = described_feeder(&relay, &nowhere, None).await?;
    // A whole-world client, to know when the relay has taken in what was described.
    let mut world = subscribe(&relay).await?;
    let three = [inside.public(), outside.public(), nowhere.public()];
    let mut described = HashSet::new();
    until(&mut world, "the three descriptions", |record| {
        if let (Record::ReceiverInfo(_), Some(key)) = (record, author(record))
            && three.contains(&key)
        {
            described.insert(key);
        }
        described.len() == 3
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
    // Outside the region, located or not: a newer description each, and a batch.
    for (session, identity, location) in [
        (&mut outside_feed, &outside, Some(london)),
        (&mut nowhere_feed, &nowhere, None),
    ] {
        session
            .writer
            .send(&[
                Record::ReceiverInfo(info_naming(identity, location, 2, Vec::new())?),
                Record::Batch(batch(identity, 0)?),
            ])
            .await
            .map_err(text)?;
    }
    let renewed = |record: &Record, key: PublicKey| {
        matches!(record, Record::ReceiverInfo(info) if info.issued_ms().ok() == Some(2))
            && author(record) == Some(key)
    };
    let mut published = HashSet::new();
    until(&mut world, "the outside descriptions renewed", |record| {
        for key in [outside.public(), nowhere.public()] {
            if renewed(record, key) {
                published.insert(key);
            }
        }
        published.len() == 2
    })
    .await?;
    until(&mut outside_raw, "the outside batch", |record| {
        matches!(record, Record::Batch(_)) && author(record) == Some(outside.public())
    })
    .await?;
    inside_feed
        .writer
        .send(&[
            Record::ReceiverInfo(info_naming(&inside, Some(palo_alto), 2, Vec::new())?),
            Record::Batch(batch(&inside, 0)?),
        ])
        .await
        .map_err(text)?;
    // The fan-out is in order, so anything from outside would have arrived before these.
    let strangers = |heard: &[Record]| -> Vec<PublicKey> {
        heard
            .iter()
            .filter_map(author)
            .filter(|key| [outside.public(), nowhere.public()].contains(key))
            .collect()
    };
    let mut heard = until(&mut regional, "the inside description renewed", |record| {
        renewed(record, inside.public())
    })
    .await?;
    heard.extend(answer);
    assert!(
        strangers(&heard).is_empty(),
        "a client heard from outside the region"
    );
    assert_client_safe(&heard);
    let raw = until(&mut regional_raw, "the inside batch", |record| {
        matches!(record, Record::Batch(_)) && author(record) == Some(inside.public())
    })
    .await?;
    assert!(strangers(&raw).is_empty(), "raw from outside the region");
    Ok(())
}

#[tokio::test]
async fn two_receivers_hearing_one_message_are_one_copy_in_the_relays_signed_stream() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    // The deduplicated stream carries counters, so it is a relay's: read as a relay link is
    // handed it. A client asking for it beside.
    let subscriber = relay_view(&relay, Streams::RAW.with(Streams::DEDUPLICATED));
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let (mut client, _) = subscribed(
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
    // Everything the subscriber is sent from here on: an epoch may seal (and its signed batch
    // arrive) while the raw copies are still being read.
    let mut heard = Vec::new();
    for (counter, data) in [(10, &message), (20, &message), (30, &after)] {
        if data == &after {
            // Both copies through the relay before the later message is sent.
            heard.extend(
                relay_until(&subscriber, "both copies raw", |record| {
                    if let (Record::Batch(_), Some(key)) = (record, author(record)) {
                        receivers.insert(key);
                    }
                    receivers.len() == 2
                })
                .await?,
            );
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
    heard.extend(
        relay_until(&subscriber, "the later message, deduplicated", |record| {
            matches!(record, Record::RelayBatch(batch)
            if batch.content().is_ok_and(|content| {
                content.observations.iter().any(|observation| observation.data == after)
            }))
        })
        .await?,
    );
    let (total, signed) = copies(&heard, &message)?;
    assert_eq!(signed.first().map(Batch::sequence), Some(0));
    assert_eq!(total, 1);
    assert_eq!(copies(&heard, &after)?.0, 1);
    // The client was sent neither copy, raw or deduplicated: nothing of it up to a receiver
    // described after the deduplicated batch was signed.
    let later = Identity::generate().map_err(text)?;
    let _later_feed = described_feeder(&relay, &later, None).await?;
    let told = until(&mut client, "a later description", |record| {
        describes(record, later.public())
    })
    .await?;
    assert_client_safe(&told);
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
    fn set_areas(&self, _: tally_wire::Regions, _: Vec<tally_mlat::intake::SiteRecord>) {}

    fn offer_description(&self, _: &tally_mlat::intake::SiteRecord, _: u64) {}

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
    let hub = Hub::new(8, Deadlines::RELAY);
    hub.network().host_mlat(mlat);
    relay_as(hub, identity).await
}

/// What a reference engine signing as `identity` publishes over a short simulation, and the site
/// records it placed its receivers by.
fn engine_output(
    identity: &Identity,
) -> Result<(Vec<Record>, Vec<tally_mlat::intake::SiteRecord>)> {
    use tally_mlat::engine::{Capacity, Engine, Settings};
    use tally_mlat::replay::{arrivals, replay, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(23, 40.0));
    let delivered = arrivals(&mut simulation, 5)?;
    let sites = delivered
        .iter()
        .filter_map(|(_, record)| tally_mlat::intake::SiteRecord::of(record))
        .collect();
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = Engine::new(
        identity.clone(),
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            settle_ms: 1_000,
            threads: 2,
            capacity: Capacity::default(),
        },
    );
    let records = replay(&mut engine, &delivered, 100, until)?
        .into_iter()
        .map(|(_, record)| record)
        .collect();
    Ok((records, sites))
}

/// Reads until every positions record in `wanted` (by its bytes) is in; returns every record read.
async fn every_form(
    session: &mut Session<TcpStream>,
    what: &str,
    mut wanted: HashSet<Vec<u8>>,
) -> Result<Vec<Record>> {
    until(session, what, |record| {
        if let Record::Positions(positions) | Record::Provisional(positions) = record {
            wanted.remove(positions.as_bytes());
        }
        wanted.is_empty()
    })
    .await
}

/// What a relay's own MLAT signs reaches each reader of its stream. A client is sent the client
/// forms the relay checked against its own raw (`consistency`): final positions those that asked
/// for positions, provisional ones only those that asked for them, model summaries those that asked
/// for models, and never a raw solution or a full model, which are a relay link's. (An engine
/// publishing on its own session is the retired path: refused,
/// `no_session_but_a_member_publishes_positions_models_or_parts`.)
#[tokio::test]
async fn a_relays_own_mlat_reaches_the_subscribers_of_each_stream() -> Result {
    let identity = Identity::generate().map_err(text)?;
    let (records, sites) = engine_output(&identity)?;
    let mlat = Arc::new(Scripted::default());
    let relay = relay_hosting(identity.clone(), Arc::clone(&mlat)).await?;
    // The sites the engine placed its receivers by, as the relay holds them from their feeders.
    for site in &sites {
        relay.hub.network().consistency.site(site);
    }
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
    let relays = relay_view(
        &relay,
        Streams::POSITIONS
            .with(Streams::PROVISIONAL)
            .with(Streams::CLOCK_MODELS),
    );
    let of = |client: bool, provisional: bool| -> HashSet<Vec<u8>> {
        records
            .iter()
            .filter_map(|record| match record {
                Record::Positions(positions) if !provisional => Some(positions),
                Record::Provisional(positions) if provisional => Some(positions),
                _ => None,
            })
            .filter(|positions| positions.is_tagged() == client)
            .map(|positions| positions.as_bytes().to_vec())
            .collect()
    };
    let (finals, provisionals) = (of(true, false), of(true, true));
    let (raw_finals, summaries) = (
        of(false, false),
        records
            .iter()
            .filter(|record| matches!(record, Record::ClientClockModel(_)))
            .count(),
    );
    assert!(
        !finals.is_empty() && !provisionals.is_empty() && !raw_finals.is_empty() && summaries > 0,
        "the engine published too little to test"
    );
    mlat.publish(records.clone());

    // Every client form, checked; reading until each is in.
    let heard = every_form(
        &mut both,
        "every final and provisional client form",
        finals.union(&provisionals).cloned().collect(),
    )
    .await?;
    assert_client_safe(&heard);
    let heard = every_form(&mut finals_only, "every final client form", finals.clone()).await?;
    assert_client_safe(&heard);
    assert!(
        !heard
            .iter()
            .any(|record| matches!(record, Record::Provisional(_)))
    );
    let mut summaries_heard = 0;
    let heard = until(&mut models, "every model summary", |record| {
        summaries_heard += usize::from(matches!(record, Record::ClientClockModel(_)));
        summaries_heard == summaries
    })
    .await?;
    assert_client_safe(&heard);
    assert!(
        !heard
            .iter()
            .any(|record| matches!(record, Record::Positions(_) | Record::Provisional(_)))
    );
    // A relay link is handed the raw solutions and the full models.
    let mut missing = raw_finals;
    let heard = relay_until(&relays, "every raw final", |record| {
        if let Record::Positions(positions) = record {
            missing.remove(positions.as_bytes());
        }
        missing.is_empty()
    })
    .await?;
    assert!(
        heard
            .iter()
            .any(|record| matches!(record, Record::ClockModel(_)))
    );
    Ok(())
}

/// Positions, provisional positions, clock models and their parts come only from a relay: its own
/// MLAT, or a verified member. Any other session that publishes one (an engine's, the retired
/// standalone path; a feeder's; a subscriber's) is cut off, and nothing it sent is forwarded.
#[tokio::test]
async fn no_session_but_a_member_publishes_positions_models_or_parts() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    // What a relay link would be handed of them: every form, raw and full included.
    let subscriber = relay_view(
        &relay,
        Streams::RAW
            .with(Streams::POSITIONS)
            .with(Streams::PROVISIONAL)
            .with(Streams::CLOCK_MODELS),
    );
    let engine = Identity::generate().map_err(text)?;
    let refused = [
        Record::Positions(positions(&engine, 0)?),
        Record::Positions(solved_tagged(&engine, 1, 374_100_000)?),
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
            tokio::time::timeout(HANG, ended(&mut session))
                .await
                .map_err(|_| format!("a {role:?} that published {record:?} was not cut off"))?;
        }
    }
    let (_feed, last) = sentinel(&relay).await?;
    let heard = relay_until(&subscriber, "the sentinel", |record| {
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

/// The same solution as a client's final record: its receptions tagged under each receiver's
/// reception key (a site each, signed here).
fn solved_tagged(engine: &Identity, sequence: u64, lat_e7: i32) -> Result<Positions> {
    let keys: Vec<(PublicKey, tally_wire::ReceptionKey)> = (1..=4u8)
        .map(|seed| {
            let receiver = Identity::from_seed([seed; 32]);
            site(&receiver, here(), 1).map(|site| (receiver.public(), site.reception_key()))
        })
        .collect::<Result<_>>()?;
    let tagged = solution(lat_e7)?
        .tagged(|receiver| {
            keys.iter()
                .find(|(key, _)| key == receiver)
                .map(|(_, reception)| *reception)
        })
        .map_err(text)?;
    Positions::sign_tagged(
        engine,
        &tally_wire::TaggedSolutionsContent {
            boot_id: 1,
            sequence,
            issued_ms: 1_791_220_000_000,
            spec_version: 1,
            solutions: vec![tagged],
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
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
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
    // Of client forms: a client holds tagged positions, and a proof of them is one it may be sent.
    let truth = solved_tagged(&honest, 0, 374_100_000)?;
    let lie = solved_tagged(&liar, 0, 374_900_000)?;
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
    let agreeing = solved_tagged(&liar, 1, 374_100_000)?;
    let false_proof = FaultProof::new(&truth, 0, &agreeing, 0).map_err(text)?;
    accuser
        .writer
        .send(&[Record::FaultProof(false_proof.clone())])
        .await
        .map_err(text)?;
    ended(&mut accuser).await;

    let other_lie = solved_tagged(&liar, 2, 373_000_000)?;
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
    assert_client_safe(&heard);
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
    let relay = relay(Hub::new(1, Deadlines::RELAY).advertising(hints.clone())).await?;
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
    let relay = relay(Hub::new(8, Deadlines::RELAY).accepting_relays([accepted.public()])).await?;
    let subscriber = relay_view(&relay, Streams::RAW);
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
    // Asked to wait no longer than its own dial schedule's first step (`Backoff::FIRST`): a
    // relay not yet verified may be within seconds, as gossip goes, so the wait is gossip's,
    // never a re-signing's and never a day's; its own doubling spaces it out from there.
    assert_eq!(
        told(&mut session).await?,
        Some(Record::Goodbye {
            reason: tally_wire::Reason::Refused,
            retry_after_secs: tally_wire::backoff::Backoff::FIRST.as_secs() as u32,
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
    assert_eq!(relay_batches_until(&subscriber, &own).await?, vec![own]);
    Ok(())
}

#[tokio::test]
async fn a_batch_replayed_after_its_hash_is_forgotten_is_not_forwarded() -> Result {
    // A hash window short enough to pass several times inside the test.
    let window = Duration::from_millis(50);
    let relay = relay(Hub::new(8, Deadlines::RELAY).remembering_hashes_for(window)).await?;
    let subscriber = relay_view(&relay, Streams::RAW);
    let receiver = Identity::generate().map_err(text)?;
    let mut feed = connect(&relay, &receiver, Role::Feeder).await?;
    let old = batch(&receiver, 0)?;
    // Each send after a window rotates the hashes; two rotations forget the first batch's.
    for signed in [old.clone(), batch(&receiver, 100)?, batch(&receiver, 200)?] {
        feed.writer
            .send(&[Record::Batch(signed.clone())])
            .await
            .map_err(text)?;
        relay_until(&subscriber, "a fresh batch", |record| {
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
    let heard = relay_until(&subscriber, "the next batch", |record| {
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
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    let subscriber = relay_view(&relay, Streams::RAW);
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
    assert_eq!(relay_batches_until(&subscriber, &last).await?, vec![last]);
    Ok(())
}

#[tokio::test]
async fn a_subscribe_naming_too_many_regions_ends_the_session() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
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

/// A feeder past its ingest ceiling is told so (`Reason::OverCeiling`) and dropped: never that the
/// relay is full, which would excuse a relay told it its shortfalls (`link::End::Full`).
#[tokio::test]
async fn a_feeder_over_its_ingest_ceiling_is_told_it_is_over_and_dropped() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY).max_feeder_bytes_per_sec(1)).await?;
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
            reason: tally_wire::Reason::OverCeiling,
            retry_after_secs: 60,
        })
    );
    Ok(())
}

#[tokio::test]
async fn beyond_the_connection_cap_a_connection_is_closed_before_its_handshake() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY).max_connections(1)).await?;
    let beacon = Identity::generate().map_err(text)?;
    let mut held = described_feeder(&relay, &beacon, None).await?;
    held.writer.send(&[Record::Heartbeat]).await.map_err(text)?;
    let mut second = TcpStream::connect(relay.address).await.map_err(text)?;
    let mut byte = [0; 1];
    let read = second.read(&mut byte).await;
    assert!(matches!(read, Ok(0) | Err(_)), "the relay answered");
    Ok(())
}

/// A client's `Subscribe` sent with its Hello decides the first byte it is sent: of the raw
/// stream, the public descriptions of the receivers inside its region, and none outside, whether
/// described before it connected or after.
#[tokio::test]
async fn a_subscribe_sent_with_hello_decides_the_first_byte() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    let palo_alto = here();
    let london = at(51.5, -0.12);
    let outside = Identity::generate().map_err(text)?;
    let mut outside_feed = described_feeder(&relay, &outside, Some(london)).await?;
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
    // Outside, described again once the regional client is connected.
    outside_feed
        .writer
        .send(&[Record::ReceiverInfo(info_naming(
            &outside,
            Some(london),
            2,
            Vec::new(),
        )?)])
        .await
        .map_err(text)?;
    until(&mut world, "the outside description renewed", |record| {
        matches!(record, Record::ReceiverInfo(info) if info.issued_ms().ok() == Some(2))
            && author(record) == Some(outside.public())
    })
    .await?;
    let inside = Identity::generate().map_err(text)?;
    let _inside_feed = described_feeder(&relay, &inside, Some(palo_alto)).await?;
    // Everything the regional client was ever sent, up to the inside receiver's description.
    let heard = until(&mut regional, "the inside description", |record| {
        describes(record, inside.public())
    })
    .await?;
    assert!(
        heard
            .iter()
            .filter_map(author)
            .all(|key| key == inside.public()),
        "heard from outside the region"
    );
    assert_client_safe(&heard);
    Ok(())
}

#[tokio::test]
async fn beyond_its_addresss_cap_a_connection_is_closed_before_its_handshake_and_others_connect()
-> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
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
        Hub::new(8, Deadlines::RELAY)
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
                burst,
                wanted_per_sec: Some(tally_relay::ingest::FEEDER_RECEPTIONS_PER_SEC as u32),
            },
            Record::RelayList(vec![hint]),
        ]
    );
    Ok(())
}

/// Capacity is admission (RFC-0181 §9): a relay whose memory holds one feeder's share of every
/// store takes the first feeder and turns the second away at its Hello, pointed at the relays it
/// knows, before anything it sent is taken in; the first is served on, and leaving frees its slot.
#[tokio::test]
async fn a_feeder_beyond_the_memory_budget_is_refused_at_its_hello() -> Result {
    let hint = RelayAddress {
        key: Identity::generate().map_err(text)?.public(),
        address: "other.example:10900".to_owned(),
    };
    let hub = Hub::new(8, Deadlines::RELAY)
        .advertising(vec![hint.clone()])
        .memory_for_feeders(1, false);
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
    let deadline = std::time::Instant::now() + HANG;
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
/// manifests, which the relay checks and forwards to relays (it carries two full models, so no
/// client is sent it); two that agree prove nothing.
#[tokio::test]
async fn a_model_fault_proof_is_checked_then_forwarded_and_a_false_one_ends_the_session() -> Result
{
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
    let relays = relay_view(&relay, Streams::POSITIONS);
    let beacon = Identity::generate().map_err(text)?;
    let _beacon_feed = described_feeder(&relay, &beacon, None).await?;
    let (mut client, _) = subscribed(
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
    relay_until(&relays, "the model fault proof", |record| {
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
    // The client of positions was sent neither, up to a receiver described after both.
    let later = Identity::generate().map_err(text)?;
    let _later_feed = described_feeder(&relay, &later, None).await?;
    let told = until(&mut client, "a later description", |record| {
        describes(record, later.public())
    })
    .await?;
    assert!(
        !told
            .iter()
            .any(|record| matches!(record, Record::FaultProof(_)))
    );
    Ok(())
}

/// RFC-0174's seam through a real relay: a probe sent with Hello is answered first, signed by the
/// relay, before anything else it says; and a delivery query on the same session is answered,
/// signed, naming the query's nonce. What the answers declare is each duty's.
#[tokio::test]
async fn a_probe_and_a_delivery_query_are_answered_signed_by_the_relay() -> Result {
    let relay = relay(Hub::new(8, Deadlines::RELAY)).await?;
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

/// A relay that takes `areas`, advertising its own address so its offers can be verified, on
/// network `asn`, accepting `relays` on directory links, judging the members it shares with by
/// `deadlines`.
async fn taking(
    identity: Identity,
    areas: &[Region],
    asn: u32,
    relays: &[PublicKey],
    deadlines: Deadlines,
) -> Result<(Relay, Arc<Hub>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    let hub = Arc::new(
        Hub::new(8, deadlines)
            .advertising(vec![RelayAddress {
                key: identity.public(),
                address: address.to_string(),
            }])
            .accepting_relays(relays.iter().copied())
            .max_connections_per_address(256)
            .taking(areas.to_vec()),
    );
    hub.network().admission.configure(asn, true);
    let key = identity.public();
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    Ok((
        Relay {
            address,
            // No BEAST output here.
            beast_out: address,
            key,
            hub: Arc::clone(&hub),
        },
        hub,
    ))
}

/// RFC-0174 §2.5, "A relay's members are bounded": three relays take one area. The first holds
/// every member session its plan admits but one, so the first relay whose link brings it the
/// group's data is taken and the other is turned away with `Reason::Full`. The relay turned away
/// takes that as "this provider is full": it routes what it would have sent the full relay to the
/// next members of the area's trees, so the feeder's batches on the third relay reach the second
/// relay and its subscriber all the same, and it does not dial the full relay again for the wait
/// it was given (so the full relay turns each relay away once, never in a loop). The feed runs
/// past several receipt windows and their judgment, and routing around is no fault on either side
/// (§2.6, "it is not demoted for it"), judged relay by relay: the full relay
/// itself, which still takes the group's data over the session it admitted, and the second relay
/// each receipt a judged window; the third, the origin of the only feed, is owed nothing and
/// receipts none; every relay's judge weighed a window that could have demoted
/// (`member::Stats::judged`), and no relay files a shortfall or demotes another.
///
/// The relays judge one another by [`PATIENT`], not a relay's deadlines: the links are real and
/// the clock is the machine's, so under a relay's 4 s receipt grace a machine busy enough (a
/// four-core runner running two test binaries at once) delivers a record late and a shortfall is
/// filed for the machine's load, not for routing around. That a late or missing delivery is
/// filed under a relay's deadlines is the sharing tests' to show, on the simulation's clock
/// (`sharing::tests`: `a_member_that_does_not_forward_is_reported_and_demoted`,
/// `a_slow_member_is_reported_by_a_relays_deadlines_and_not_by_patient_ones`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_whose_members_are_full_is_routed_around_and_the_data_still_arrives() -> Result {
    use tally_relay::sharing::member::RECEIPT_WINDOW_SECONDS;
    let place = at(33.749, -84.388);
    let area = tally_wire::rendezvous::area_of(&place).map_err(text)?;
    let [full, next, third] = [
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
    ];
    let joining = [next.public(), third.public()];
    let (_, full_hub) = taking(full.clone(), &[area], 64_531, &joining, PATIENT).await?;
    let (next_relay, next_hub) = taking(next.clone(), &[area], 64_532, &[], PATIENT).await?;
    let (third_relay, third_hub) = taking(third.clone(), &[area], 64_533, &[], PATIENT).await?;
    // The full relay's member pool held, every session its plan admits but one.
    let mut held = Vec::new();
    while held.len() + 1 < full_hub.budget().members() {
        held.push(
            full_hub
                .budget()
                .reserve_member()
                .ok_or("the member pool held fewer sessions than planned")?,
        );
    }
    let full_address = {
        let advertised = full_hub.hints();
        advertised.first().ok_or("no address")?.address.clone()
    };
    for (identity, hub) in [(&next, &next_hub), (&third, &third_hub)] {
        tokio::spawn(link::upstream(
            tally_relay::config::Upstream {
                address: full_address.clone(),
                key: full.public(),
            },
            identity.clone(),
            Arc::clone(hub),
        ));
    }
    let keys = [full.public(), next.public(), third.public()];
    let hubs = [&full_hub, &next_hub, &third_hub];
    tokio::time::timeout(HANG, async {
        loop {
            let found = hubs.iter().zip(keys).all(|(hub, own)| {
                keys.iter()
                    .filter(|key| **key != own)
                    .all(|key| hub.network().directory.knows(key))
            });
            if found {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "the relays never verified one another's offers".to_owned())?;

    // A feeder of the area on the third relay, and a reader of its raw on the second, as the
    // second's relay links are handed it (raw is a relay's).
    let feeder = Identity::generate().map_err(text)?;
    let subscriber = relay_view(&next_relay, Streams::RAW);
    let mut feed = described_feeder(&third_relay, &feeder, Some(place)).await?;
    // Twelve seconds of batches: at least one whole receipt window, its receipts and its judgment
    // (`sharing::member::RECEIPT_WINDOW_SECONDS`, and `PATIENT`'s grace and judgment) fall
    // inside the run, and the full relay's 60 s wait outlasts it.
    let sent = 120;
    let author = feeder.public();
    let heard = tokio::spawn(async move {
        let mut sequences = std::collections::BTreeSet::new();
        let _ = relay_until(&subscriber, "the third relay's batches", |record| {
            if let Record::Batch(batch) = record
                && batch.receiver().ok() == Some(author)
            {
                sequences.insert(batch.sequence());
            }
            sequences.len() == sent
        })
        .await;
        sequences.len()
    });
    for sequence in 0..sent as u64 {
        let now = tally_relay::network::wall_ms();
        feed.writer
            .send(&[Record::Batch(fresh_batch(&feeder, sequence, now)?)])
            .await
            .map_err(text)?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let fed_until = tally_relay::network::wall_ms();
    let got = tokio::time::timeout(HANG, heard)
        .await
        .map_err(|_| "the third relay's batches never all reached the second".to_owned())?
        .map_err(text)?;
    assert_eq!(got, sent);
    // Past the judgment of the last window the feed reached.
    let window_ms = RECEIPT_WINDOW_SECONDS * 1000;
    let judged_at = fed_until - fed_until % window_ms
        + window_ms
        + PATIENT.receipt_grace_ms
        + PATIENT.judge_after_ms
        + 1_000;
    let wait = judged_at.saturating_sub(tally_relay::network::wall_ms());
    tokio::time::sleep(Duration::from_millis(wait)).await;

    // The full relay said so, and the one relay it turned away took it as full: routed around,
    // not dialled again, so it turned it away exactly once.
    let now = tally_relay::network::wall_ms();
    let turned_away = [&next_hub, &third_hub]
        .iter()
        .filter(|hub| hub.network().peers.full(now).contains(&full.public()))
        .count() as u64;
    let refused = full_hub.memory_report().members_refused;
    assert_eq!(
        (refused, turned_away),
        (1, 1),
        "the full relay turned links away {refused} times, {turned_away} relays hold it as full"
    );
    // Relay by relay: each owed the feed's data receipted a judged window, the origin receipted
    // none, and nobody took the route-around for a fault.
    let group = tally_relay::sharing::groups::GroupKey::new(area, tally_wire::Streams::RAW);
    for ((hub, own), name) in hubs.iter().zip(keys).zip(["full", "second", "third"]) {
        let (stats, _) = hub.network().sharing.stats();
        let owed = own != third.public();
        assert_eq!(
            stats.receipts > 0,
            owed,
            "the {name} relay signed {} receipts ({}owed the feed): {stats:?}",
            stats.receipts,
            if owed { "" } else { "not " }
        );
        // The judge sat: a window steady enough to demote was weighed, so the
        // shortfalls and demotions below are a verdict, not a judgment that never ran.
        assert!(
            stats.judged > 0,
            "the {name} relay judged no receipt window: {stats:?}"
        );
        assert_eq!(
            stats.shortfalls, 0,
            "the {name} relay filed a shortfall after a route-around: {stats:?}"
        );
        for key in keys.iter().filter(|key| **key != own) {
            assert!(
                !hub.network().sharing.groups.is_demoted(group, key),
                "the {name} relay demoted another after a route-around"
            );
        }
    }
    drop(held);
    Ok(())
}

/// What the route-around test's relays judge one another by: a relay's deadlines
/// (`Deadlines::RELAY`) each stretched past any delay a loaded machine adds to a delivery between
/// relays on one host, so a shortfall or demotion there is routing around failing and never the
/// machine's share of the CPU. A second is settled (no repair asked, and what came from above a
/// full parent counted as routed past it) 8 s after it ends, not 1.5 s; receipts are signed 15 s
/// after their window, not 4 s; judged 3 s after that, not 2 s; and a refusal's span is
/// stretched 5 s, not 1 s. Bounded above by the full relay's 60 s wait
/// (`link::MEMBERS_FULL_RETRY_SECS`), which the run, the window and its judgment must stay inside:
/// a relay that dialled it again would be turned away twice.
const PATIENT: Deadlines = Deadlines {
    repair_after_ms: 8_000,
    receipt_grace_ms: 15_000,
    judge_after_ms: 3_000,
    route_slack_ms: 5_000,
};

/// A batch of `identity`'s stamped `wall_ms`, as a live feeder sends one.
fn fresh_batch(identity: &Identity, sequence: u64, wall_ms: u64) -> Result<Batch> {
    Batch::sign(
        identity,
        &BatchContent {
            boot_id: 1,
            sequence,
            counter_epoch: 0,
            wall_ms,
            dropped: 0,
            previous: [0; 32],
            observations: vec![tally_wire::Observation::from_beast(&frames(1)?[0])],
        },
    )
    .map_err(text)
}
