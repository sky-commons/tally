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
    tokio::spawn(relays::run(Publishing {
        directory,
        identity: identity.clone(),
        batches: batches.clone(),
        ceiling: config.ceiling,
        checker: DeliveryChecker::load(&config.state_dir),
        checking: delivery_check::Checking::default(),
        prober: probe::measure,
    }));
    let (inputs, intake) = source::channel();
    tokio::spawn(source::read_beast(config.source, inputs.clone()));
    if let Some(uat) = config.uat {
        tokio::spawn(source::read_uat(uat, inputs.clone()));
    }
    drop(inputs);
    source::batch(
        Batcher::new(identity, config.ceiling, config.clock),
        intake,
        batches,
    )
    .await;
    Ok(())
}
