//! A Tally feeder (RFC-0171 §3.5): reads a receiver's own decoder, signs what it heard, and
//! publishes it to the two nearest healthy relays on different networks (RFC-0174 §2.2). It listens on no port, takes no orders from the network, and
//! changes nothing about the receiver's other feeds.

pub mod acars;
pub mod config;
pub mod delivery_check;
pub mod health;
pub mod lines;
pub mod precision;
pub mod privilege;
pub mod probe;
pub mod relays;
pub mod selection;
pub mod source;
pub mod uat;

use std::sync::Arc;

use tally_wire::Identity;
use tokio::sync::broadcast;

use crate::config::{Config, Key};
use crate::delivery_check::DeliveryChecker;
use crate::health::Health;
use crate::relays::{Directory, Publishing};
use crate::source::Batcher;

/// Batches held for relay sessions that are momentarily slow: about a minute.
const BATCH_BACKLOG: usize = 64;

/// A station's page on the Tally site, by its key as a URL carries it (base64url, no padding).
pub const STATION_PAGE: &str = "https://tally.flightlines.ai/en/station/";

/// Where `public`'s numbers are shown: its station page.
pub fn station_link(public: &tally_wire::PublicKey) -> String {
    format!("{STATION_PAGE}{}/", public.to_base64url())
}

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

/// A fresh identity for a host that keeps its secrets in its own configuration (`--key-env`): its
/// secret, the text a key file holds, and its public key, the receiver's name. Nothing is written;
/// the caller prints both and the host stores the first.
pub fn new_key() -> Result<(String, tally_wire::PublicKey), String> {
    let identity = Identity::generate().map_err(|error| error.to_string())?;
    Ok((identity.to_base64(), identity.public()))
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

/// The receiver's identity, from its key file or its environment variable; a kept key file is
/// made first if it is missing.
fn load_key(key: &Key) -> Result<Identity, String> {
    match key {
        Key::File(path) => load(path),
        Key::Env(name) => from_env(name, std::env::var_os(name)),
        Key::Kept(path) => kept(path),
    }
}

/// The kept key at `path`, made now if there is none (`Key::Kept`).
fn kept(path: &std::path::Path) -> Result<Identity, String> {
    if path.exists() {
        return load(path);
    }
    let identity = Identity::generate().map_err(|error| error.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    write_private(path, &format!("{}\n", identity.to_base64()))?;
    eprintln!(
        "tally-feed: made this receiver's key, {}; keep it (back it up with the rest of the \
         receiver's configuration): it is the antenna's name for good",
        path.display()
    );
    Ok(identity)
}

/// An identity from the value of the environment variable `name`, which holds what a key file
/// holds (surrounding whitespace is trimmed, as a file's newline is). Every error names the
/// variable and never its value, nor the decoder's report of it, which can quote the secret's
/// characters: a container's logs are often shared.
fn from_env(name: &str, value: Option<std::ffi::OsString>) -> Result<Identity, String> {
    let value = value.ok_or_else(|| format!("--key-env {name}: the variable is not set"))?;
    let text = value
        .to_str()
        .ok_or_else(|| format!("--key-env {name}: the value is not text"))?
        .trim();
    if text.is_empty() {
        return Err(format!("--key-env {name}: the variable is empty"));
    }
    Identity::from_base64(text).map_err(|_| {
        format!(
            "--key-env {name}: not a key (expected the base64 text `tally-feed new-key` prints \
             on its first line)"
        )
    })
}

pub async fn run(config: Config) -> Result<(), String> {
    let identity = load_key(&config.key)?;
    let public = identity.public();
    eprintln!(
        "tally-feed: receiver {public}; its station page is {}",
        station_link(&public)
    );
    if let Some(location) = config.location
        && location.precision_m > 0
    {
        let published = precision::snap(location);
        eprintln!(
            "tally-feed: sending relays the position rounded to {} m: {:.7}, {:.7}",
            location.precision_m,
            f64::from(published.lat_e7) / 1e7,
            f64::from(published.lon_e7) / 1e7
        );
    }
    let health = Arc::new(Health::default());
    tokio::spawn(health::watch(Arc::clone(&health), config.state_dir.clone()));
    let (inputs, batching) = publish(identity, &config, Arc::clone(&health))?;
    tokio::spawn(source::read_beast(config.source, inputs.clone(), health));
    if let Some(uat) = config.uat {
        tokio::spawn(source::read_lines(
            uat,
            inputs.clone(),
            source::LineSource::Uat,
        ));
    }
    for acars in config.acars {
        tokio::spawn(source::read_lines(
            acars,
            inputs.clone(),
            source::LineSource::Acars,
        ));
    }
    drop(inputs);
    batching.await;
    Ok(())
}

/// Everything a feeder runs but its sources: the relay directory and its saving, the publisher
/// (probing, choosing, the sessions, the delivery checks) and the batcher that owns the chain.
/// Reads every field of `config` but `key`, `source`, `uat` and `acars`, which are the caller's.
/// Returns the batcher's input, which the sources offer their receptions to, and the batcher
/// itself, which runs until every clone of the input is dropped. `run` feeds it from the
/// receiver's decoders; the load harness (`tally-load`) from the MLAT simulator, so each of its
/// feeders is this feeder.
pub fn start(
    identity: Identity,
    config: &Config,
) -> Result<(source::Inputs, impl Future<Output = ()> + Send + 'static), String> {
    publish(identity, config, Arc::default())
}

/// The batcher `config` names: its ceiling, the ACARS share of it, the relays' wanted ceilings to
/// shed to, and its compression.
fn batcher(identity: Identity, config: &Config, wanted: Arc<source::WantedCeilings>) -> Batcher {
    Batcher::new(identity, config.ceiling, config.clock)
        .holding_acars_to(config.acars_ceiling)
        .shedding_to(wanted)
        .compressing_at(config.deflate_level)
}

/// `start`, telling `health` how many relay sessions are up.
fn publish(
    identity: Identity,
    config: &Config,
    health: Arc<Health>,
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
    // relay's, and the batcher sheds to the least before it signs.
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
        health,
    }));
    let batcher = batcher(identity, config, wanted);
    let (inputs, intake) = source::channel(batcher.ceilings());
    let batching = source::batch(batcher, intake, batches);
    Ok((inputs, batching))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceilings a run is configured with hold through the batcher it builds (`batcher`) and
    /// what that publishes: offered an ACARS flood and more BEAST than the ceiling at once, the
    /// messages take their configured share of the ceiling and ADS-B the rest of it.
    #[tokio::test]
    async fn adsb_keeps_the_ceiling_but_the_configured_acars_share() -> Result<(), String> {
        use tally_wire::batch::format;
        use tally_wire::{Frame, FrameKind, Observation, Record};
        let args = [
            "--key",
            "k",
            "--acars",
            "127.0.0.1:15555",
            "--ceiling",
            "64000",
            "--acars-ceiling",
            "20000",
        ];
        let config::Command::Run(config) = config::parse(args.iter().map(|arg| (*arg).to_owned()))?
        else {
            return Err("not a run".to_owned());
        };
        let started = std::time::Instant::now();
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let batcher = batcher(identity, &config, Arc::default());
        let (inputs, intake) = source::channel(batcher.ceilings());
        let (out, mut published) = broadcast::channel(1024);
        let batching = tokio::spawn(source::batch(batcher, intake, out));
        let line = format!(r#"{{"text":"{}","timestamp":1}}"#, "x".repeat(990));
        let line_cost = 10.0 + line.len() as f64;
        for _ in 0..200 {
            inputs.offer_acars(Observation {
                format: format::ACARS_JSON,
                timestamp: 1_000_000,
                signal: 0,
                data: line.clone().into_bytes(),
            });
        }
        // 72000 bytes of frames, past the 64000 a second.
        let frames = (1..=3_000u64)
            .map(|n| Frame::new(FrameKind::ModeSLong, n, 9, &[0x8d; 14]))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        for chunk in frames.chunks(500) {
            inputs.offer_frames(chunk.to_vec());
        }
        drop(inputs);
        batching.await.map_err(|error| error.to_string())?;
        let elapsed = started.elapsed().as_secs_f64();

        let (mut acars, mut adsb) = (0.0, 0.0);
        while let Ok(record) = published.try_recv() {
            let Record::Batch(batch) = &*record else {
                continue;
            };
            for observation in batch
                .content()
                .map_err(|error| error.to_string())?
                .observations
            {
                let cost = 10.0 + observation.data.len() as f64;
                if observation.format == format::ACARS_JSON {
                    acars += cost;
                } else {
                    adsb += cost;
                }
            }
        }
        // What either bucket refilled while the test ran, and one reception's rounding.
        let (share, ceiling) = (20_000.0, 64_000.0);
        let slack = elapsed * ceiling + 24.0;
        assert!(
            acars >= share - line_cost && acars <= share + elapsed * share + line_cost,
            "ACARS took {acars} of a {share} share"
        );
        assert!(
            adsb >= ceiling - acars - 24.0 && adsb <= ceiling - acars + slack,
            "ADS-B took {adsb} of {ceiling} beside ACARS's {acars}"
        );
        Ok(())
    }

    #[test]
    fn a_new_key_loads_from_the_environment_as_the_printed_public_key() -> Result<(), String> {
        let (secret, public) = new_key()?;
        // As a host's configuration may hold it: with a newline after it.
        let loaded = from_env("TALLY_KEY", Some(format!("{secret}\n").into()))?;
        assert_eq!(loaded.public(), public);
        assert_eq!(loaded.to_base64(), secret);
        Ok(())
    }

    #[test]
    fn a_kept_key_is_made_once_and_then_kept() -> Result<(), String> {
        let base = std::env::var_os("TEST_TMPDIR")
            .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
        let dir = base.join(format!("tally-kept-{}", std::process::id()));
        let path = dir.join("key");
        let made = kept(&path)?;
        let again = kept(&path)?;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(made.public(), again.public());
        Ok(())
    }

    #[test]
    fn the_station_link_carries_the_key_as_a_url_does() -> Result<(), String> {
        let public = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let link = station_link(&public);
        let key = link
            .strip_prefix(STATION_PAGE)
            .and_then(|rest| rest.strip_suffix('/'))
            .ok_or(link.clone())?;
        assert!(!key.contains(['+', '/', '=']), "{link}");
        assert_eq!(
            tally_wire::PublicKey::from_base64url(key).map_err(|error| error.to_string())?,
            public
        );
        Ok(())
    }

    #[test]
    fn a_bad_environment_key_names_the_variable_and_never_the_value() {
        let secret = "not-a-key-but-secret";
        for value in [None, Some(""), Some("  \n"), Some(secret), Some("AAAA")] {
            let refused = from_env("TALLY_KEY", value.map(Into::into))
                .err()
                .unwrap_or_default();
            assert!(refused.starts_with("--key-env TALLY_KEY: "), "{refused}");
            assert!(!refused.contains(secret), "{refused}");
        }
    }
}
