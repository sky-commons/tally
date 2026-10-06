//! A Tally MLAT engine (RFC-0171 §3.8) that solves nothing itself. It subscribes to its regions'
//! raw batches and speaks mlat-client's protocol to a local, unmodified mlat-server
//! (github.com/wiedehopf/mlat-server, the server adsb.lol and others run) on behalf of every
//! receiver in them: one connection per receiver, the same handshake, and the same sync and mlat
//! messages mlat-client would send for what that receiver heard. The server's results come back
//! on those connections, and the engine signs them as `Positions` and publishes them to relays.
//!
//! - `modes`: the Mode S decoding mlat-client does (CRC, address, CPR flag, NUCp, altitude);
//! - `client`: mlat-client's reader filter and coordinator, which choose what to send;
//! - `protocol`: the client protocol's lines, byte for byte, and the server's answers;
//! - `playout`: replays every receiver on one timeline, so copies reach the server together;
//! - `station`: one receiver's mlat-server session;
//! - `relays` and `engine`: the Tally side.

pub mod client;
pub mod config;
pub mod engine;
pub mod modes;
pub mod playout;
pub mod protocol;
pub mod relays;
pub mod station;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tally_wire::Identity;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::config::Config;
use crate::engine::Engine;
use crate::station::Shared;

/// How often solved positions are signed and published.
const PUBLISH_EVERY: Duration = Duration::from_secs(1);
/// Records from relays waiting for the engine.
const INBOUND_BACKLOG: usize = 1_024;
/// Results from the server waiting for the engine.
const RESULT_BACKLOG: usize = 4_096;
/// Signed positions held for relay sessions that are momentarily slow: about a minute.
const POSITIONS_BACKLOG: usize = 64;

/// Creates the key file if it is missing, and prints the public key.
pub fn keygen(path: &Path) -> Result<(), String> {
    if path.exists() {
        println!("{}", load(path)?.public());
        return Ok(());
    }
    let identity = Identity::generate().map_err(|error| error.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    write_private(path, &format!("{}\n", identity.to_base64()))?;
    println!("{}", identity.public());
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

fn load(path: &Path) -> Result<Identity, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Identity::from_base64(&text).map_err(|error| format!("{}: {error}", path.display()))
}

pub async fn run(config: Config) -> Result<(), String> {
    let identity = load(&config.key_file)?;
    eprintln!("tally-mlat: engine {}", identity.public());
    let (inbound, mut records) = mpsc::channel(INBOUND_BACKLOG);
    let (outbound, _) = broadcast::channel(POSITIONS_BACKLOG);
    // The links live as long as this call: dropped, it ends them with it.
    let mut links = JoinSet::new();
    for relay in config.relays {
        links.spawn(relays::link(
            relay,
            identity.clone(),
            config.regions.clone(),
            inbound.clone(),
            outbound.clone(),
        ));
    }
    drop(inbound);
    let (results, mut solutions) = mpsc::channel(RESULT_BACKLOG);
    let shared = Shared {
        server: config.server,
        delay: config.delay,
        start: Instant::now(),
        results,
    };
    let mut engine = Engine::new(identity, config.regions, config.max_receivers, shared);
    let mut publish = tokio::time::interval(PUBLISH_EVERY);
    loop {
        tokio::select! {
            record = records.recv() => match record {
                Some(record) => {
                    engine.ingest(record);
                }
                None => return Err("every relay link ended".to_owned()),
            },
            solution = solutions.recv() => {
                if let Some(solution) = solution {
                    engine.solved(&solution);
                }
            }
            _ = publish.tick() => {
                engine.tick();
                for record in engine.flush(wall_ms())? {
                    // Never waits for a relay. An error only means no relay session is up now.
                    let _ = outbound.send(Arc::new(record));
                }
            }
        }
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
