//! What both end-to-end tests share: one receiver's signed traffic, a stand-in mlat-server that
//! speaks the server's side of the client protocol (mlat/jsonclient.py), a real engine, and the
//! checks of what the server heard and what the engine published.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use tally_mlat::config::Config;
use tally_mlat::modes::{crc, hex};
use tally_mlat::protocol::{Station, llh_to_ecef};
use tally_wire::batch::ReceiverInfoContent;
use tally_wire::{
    Batch, BatchContent, Clock, Identity, Location, Observation, Positions, PublicKey,
    ReceiverInfo, Region, RelayAddress,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

pub type Result<T = ()> = std::result::Result<T, String>;

pub const WAIT: Duration = Duration::from_secs(20);
pub const DELAY_MS: u64 = 100;
/// The Riddle's airborne position pair for ICAO 40621D, valid CRCs (as in src/modes.rs).
pub const EVEN: &str = "8d40621d58c382d690c8ac2863a7";
pub const ODD: &str = "8d40621d58c386435cc412692ad6";
/// The server's clock when the copies of the solved message reached it.
pub const SOLVED_AT: f64 = 1_791_220_000.5;

pub fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect()
}

/// An all-call reply (DF11) from ABCDEF, an aircraft that sends no ADS-B.
pub fn df11() -> Vec<u8> {
    let mut data = vec![0x5d, 0xab, 0xcd, 0xef];
    let parity = crc(&data);
    data.extend_from_slice(&[(parity >> 16) as u8, (parity >> 8) as u8, parity as u8]);
    data
}

pub fn location() -> Location {
    Location {
        lat_e7: 374_100_000,
        lon_e7: -1_221_000_000,
        alt_m: 10,
        precision_m: 0,
    }
}

/// Batch `k` of a receiver whose 12 MHz counter keeps time with the stand-in relay's clock: a
/// quarter second of receptions, alternately an even position, an odd one and a DF11.
pub fn batch(identity: &Identity, k: u64) -> Result<Batch> {
    let observations = (0..24u64)
        .map(|i| {
            let timestamp = 12_000_000 * 1_000 + k * 3_000_000 + i * 120_000;
            let data = match i % 3 {
                0 => bytes(EVEN),
                1 => bytes(ODD),
                _ => df11(),
            };
            Observation {
                format: if data.len() == 14 { b'3' } else { b'2' },
                timestamp,
                signal: 90,
                data,
            }
        })
        .collect();
    Batch::sign(
        identity,
        &BatchContent {
            boot_id: 7,
            sequence: k,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations,
        },
    )
    .map_err(text)
}

pub fn sent_timestamp(t: u64) -> bool {
    let raw = t + 768;
    raw >= 12_000_000 * 1_000 && (raw - 12_000_000 * 1_000).is_multiple_of(120_000)
}

/// The receiver's signed description: exact location, a dump1090 clock.
pub fn receiver_info(receiver: &Identity) -> Result<ReceiverInfo> {
    ReceiverInfo::sign(
        receiver,
        &ReceiverInfoContent {
            issued_ms: 1,
            location: Some(location()),
            clock: Clock::Dump1090,
            software: "stand-in".to_owned(),
            relays: Vec::new(),
        },
    )
    .map_err(text)
}

type Lines = tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>;

async fn next(lines: &mut Lines) -> Result<String> {
    lines
        .next_line()
        .await
        .map_err(text)?
        .ok_or_else(|| "the engine closed the connection".to_owned())
}

/// What the stand-in mlat-server saw.
pub struct Heard {
    handshake: Value,
    opening: Vec<String>,
    sync: Value,
    mlat: Value,
}

/// The stand-in mlat-server: accepts the handshake as mlat-server answers it, asks for both
/// aircraft, waits for a sync and an mlat message, and returns a solved position.
pub async fn server(listener: TcpListener) -> Result<Heard> {
    let (stream, _) = listener.accept().await.map_err(text)?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let handshake: Value = serde_json::from_str(&next(&mut lines).await?).map_err(text)?;
    let answer = "{\"compress\":\"none\",\"reconnect_in\":10.0,\"selective_traffic\":true,\
                  \"heartbeat\":true,\"return_results\":true,\"return_stats\":true,\
                  \"rate_reports\":true,\"motd\":\"\\n  stand-in\\n\"}\n";
    write.write_all(answer.as_bytes()).await.map_err(text)?;
    let mut opening = Vec::new();
    while opening.len() < 3 {
        opening.push(next(&mut lines).await?);
    }
    write
        .write_all(b"{\"start_sending\":[\"40621d\",\"abcdef\"]}\n")
        .await
        .map_err(text)?;
    let (mut sync, mut mlat) = (None, None);
    while sync.is_none() || mlat.is_none() {
        let line: Value = serde_json::from_str(&next(&mut lines).await?).map_err(text)?;
        if line.get("sync").is_some() {
            sync = Some(line);
        } else if line.get("mlat").is_some() {
            mlat = Some(line);
        }
    }
    let [x, y, z] = llh_to_ecef(37.5, -122.0, 3_000.0);
    let result = format!(
        "{{\"result\":{{\"@\":{SOLVED_AT},\"addr\":\"40621d\",\"n\":5,\"nd\":4,\
         \"cov\":[10000.0,0.0,0.0,10000.0,0.0,10000.0],\"ecef\":[{},{},{}]}}}}\n",
        x.round(),
        y.round(),
        z.round()
    );
    write.write_all(result.as_bytes()).await.map_err(text)?;
    // Keep the session open while the result is published.
    tokio::spawn(async move {
        while next(&mut lines).await.is_ok() {}
        drop(write);
    });
    Ok(Heard {
        handshake,
        opening,
        sync: sync.unwrap_or_default(),
        mlat: mlat.unwrap_or_default(),
    })
}

/// Starts the stand-in mlat-server; what it heard arrives on the channel.
pub async fn start_server() -> Result<(SocketAddr, mpsc::Receiver<Result<Heard>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    let (heard_out, heard) = mpsc::channel(1);
    tokio::spawn(async move {
        let _ = heard_out.send(server(listener).await).await;
    });
    Ok((address, heard))
}

/// Starts a real engine with a fresh key, reading `relay` and bridging to `server`. Returns its
/// public key and the directory holding the key file.
pub fn start_engine(
    relay: RelayAddress,
    server: SocketAddr,
    region: Region,
) -> Result<(PublicKey, PathBuf)> {
    let mut name = [0; 8];
    name.copy_from_slice(&Identity::generate().map_err(text)?.public().as_bytes()[..8]);
    let dir = std::env::temp_dir().join(format!("tally-mlat-e2e-{}", u64::from_be_bytes(name)));
    std::fs::create_dir_all(&dir).map_err(text)?;
    let key_file = dir.join("key");
    tally_mlat::keygen(&key_file)?;
    let engine = Identity::from_base64(&std::fs::read_to_string(&key_file).map_err(text)?)
        .map_err(text)?
        .public();
    tokio::spawn(tally_mlat::run(Config {
        key_file,
        relays: vec![relay],
        server: server.to_string(),
        regions: vec![region],
        delay: Duration::from_millis(DELAY_MS),
    }));
    Ok((engine, dir))
}

/// The handshake was mlat-client's for this receiver, and its DF17 pair became a sync message
/// and its DF11s mlat messages, each with the raw counter less mlat-client's 768-tick adjustment.
pub fn check_heard(heard: &Heard, receiver: &Identity) -> Result {
    let station = Station::of(&receiver.public(), Some(location()), Clock::Dump1090)
        .ok_or_else(|| "no station".to_owned())?;
    let hs = &heard.handshake;
    assert_eq!(hs["version"], 3);
    assert_eq!(hs["user"].as_str(), Some(station.user.as_str()));
    assert_eq!(hs["uuid"].as_str(), Some(station.uuid.as_str()));
    assert_eq!(
        (hs["lat"].as_f64(), hs["lon"].as_f64()),
        (Some(37.41), Some(-122.1))
    );
    assert_eq!(hs["alt"].as_f64(), Some(10.0));
    assert_eq!(hs["clock_type"], "dump1090");
    assert_eq!(hs["clock_frequency"], 12_000_000);
    assert!(hs["clock_epoch"].is_null());
    assert_eq!(hs["compress"], serde_json::json!(["none"]));
    assert_eq!(hs["udp_transport"], false);
    assert_eq!(hs["return_results"], true);
    assert_eq!(hs["return_result_format"], "ecef");
    assert_eq!(hs["selective_traffic"], true);
    assert_eq!(
        heard.opening,
        vec![
            r#"{"rate_report":{}}"#.to_owned(),
            r#"{"input_connected":"connected"}"#.to_owned(),
            r#"{"clock_reset":{"reason":"Decoder mode changed to BEAST","frequency":12000000,"epoch":null,"mode":"BEAST"}}"#.to_owned(),
        ]
    );
    let sync = &heard.sync["sync"];
    assert_eq!(
        (sync["em"].as_str(), sync["om"].as_str()),
        (Some(EVEN), Some(ODD))
    );
    let (et, ot) = (
        sync["et"].as_u64().unwrap_or(0),
        sync["ot"].as_u64().unwrap_or(0),
    );
    assert!(sent_timestamp(et) && sent_timestamp(ot), "{sync}");
    let mlat = &heard.mlat["mlat"];
    assert_eq!(mlat["m"].as_str(), Some(hex(&df11()).as_str()));
    assert!(sent_timestamp(mlat["t"].as_u64().unwrap_or(0)), "{mlat}");
    Ok(())
}

/// The server's result, published signed by the engine and dated when it was sent.
pub fn check_positions(signed: &Positions, engine: PublicKey) -> Result {
    signed.verify().map_err(text)?;
    assert_eq!(signed.engine().map_err(text)?, engine);
    let content = signed.content().map_err(text)?;
    assert_eq!(content.sequence, 0);
    let [position] = content.positions.as_slice() else {
        return Err(format!("{:?}", content.positions));
    };
    assert_eq!(position.address, 0x40621d);
    assert_eq!(position.time_ms, 1_791_220_000_500 - DELAY_MS);
    assert!((position.lat_e7 - 375_000_000).abs() < 100, "{position:?}");
    assert!(
        (position.lon_e7 + 1_220_000_000).abs() < 100,
        "{position:?}"
    );
    assert!((position.sigma_m as i64 - 141).abs() <= 1, "{position:?}");
    assert_eq!(position.receivers, 4);
    Ok(())
}
