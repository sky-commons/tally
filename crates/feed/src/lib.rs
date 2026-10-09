//! A Tally feeder (RFC-0171 §3.5): reads a receiver's own decoder, signs what it heard, and
//! publishes it to the two nearest healthy relays on different networks (RFC-0174 §2.2). It listens on no port, takes no orders from the network, and
//! changes nothing about the receiver's other feeds.

pub mod config;
pub mod delivery_check;
pub mod probe;
pub mod relays;
pub mod selection;
pub mod source;
pub mod uat;

use std::sync::Arc;

use tally_wire::Identity;
use tokio::sync::broadcast;

use crate::config::Config;
use crate::delivery_check::DeliveryChecker;
use crate::relays::{Directory, Publishing};
use crate::source::Batcher;

/// Batches held for relay sessions that are momentarily slow: about a minute.
const BATCH_BACKLOG: usize = 64;

pub fn init(path: &std::path::Path) -> Result<(), String> {
    if path.exists() {
        let identity = load(path)?;
        println!("{}", identity.public());
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
fn write_private(path: &std::path::Path, text: &str) -> Result<(), String> {
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
fn write_private(path: &std::path::Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

fn load(path: &std::path::Path) -> Result<Identity, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Identity::from_base64(&text).map_err(|error| format!("{}: {error}", path.display()))
}

pub async fn run(config: Config) -> Result<(), String> {
    let identity = load(&config.key_file)?;
    eprintln!("tally-feed: receiver {}", identity.public());
    let (inputs, batching) = start(identity, &config)?;
    tokio::spawn(source::read_beast(config.source, inputs.clone()));
    if let Some(uat) = config.uat {
        tokio::spawn(source::read_uat(uat, inputs.clone()));
    }
    drop(inputs);
    batching.await;
    Ok(())
}

/// Everything a feeder runs but its sources: the relay directory and its saving, the publisher
/// (probing, choosing, the sessions, the delivery checks) and the batcher that owns the chain.
/// Reads every field of `config` but `key_file`, `source` and `uat`, which are the caller's.
/// Returns the batcher's input, which the sources offer their receptions to, and the batcher
/// itself, which runs until every clone of the input is dropped. `run` feeds it from the
/// receiver's decoders; the load harness (`tally-load`) from the MLAT simulator, so each of its
/// feeders is this feeder.
pub fn start(
    identity: Identity,
    config: &Config,
) -> Result<(source::Inputs, impl Future<Output = ()> + Send + 'static), String> {
    let (batches, _) = broadcast::channel(BATCH_BACKLOG);
    let directory = Directory::new(
        config.state_dir.clone(),
        config.relays.clone(),
        config.seeds.clone(),
        identity.clone(),
        config.location,
        config.clock,
    )?;
    tokio::spawn(relays::keep_saved(Arc::clone(&directory)));
    // What the relays state of the wanted receptions a second they take: each session states its
    // relay's, and the batcher sheds to the least before it signs (F4 of sweep 6).
    let wanted = Arc::new(source::WantedCeilings::default());
    tokio::spawn(relays::run(Publishing {
        directory,
        identity: identity.clone(),
        batches: batches.clone(),
        ceiling: config.ceiling,
        wanted: Arc::clone(&wanted),
        checker: DeliveryChecker::load(&config.state_dir),
        checking: delivery_check::Checking::default(),
        prober: probe::measure,
        source_address: config.source_address,
    }));
    let (inputs, intake) = source::channel();
    let batching = source::batch(
        Batcher::new(identity, config.ceiling, config.clock)
            .shedding_to(wanted)
            .compressing_at(config.deflate_level),
        intake,
        batches,
    );
    Ok((inputs, batching))
}
