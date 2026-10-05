//! Which relays a feeder publishes to, and each session with one (RFC-0166 §3.5, §3.7).
//!
//! The rules are fixed here and no relay can change them: a home relay the owner pinned, an
//! anchor kept across restarts, the rest picked at random from relays the feeder knows of. A relay
//! that is unreachable is retried, never replaced in a hurry, since rushing to fresh relays during
//! an outage is how a feeder gets surrounded. A relay that says "leave me" is left; what it
//! suggests instead is only a hint, added to what the feeder knows.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::noise;
use tally_wire::{
    Clock, Identity, Location, PublicKey, Reason, ReceiverInfo, Record, RelayAddress, Role,
};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};

use crate::source::{TokenBucket, wall_ms};

const HEARTBEAT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a slot with no relay to pick waits before looking again.
const NOTHING_TO_PICK: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Home,
    Anchor,
    Random,
}

/// What the feeder knows of relays, which it is using, and what it says about itself.
pub struct Directory {
    state_dir: PathBuf,
    known: Mutex<Vec<RelayAddress>>,
    in_use: Mutex<Vec<Option<PublicKey>>>,
    identity: Identity,
    location: Option<Location>,
    clock: Clock,
    info: watch::Sender<Arc<Record>>,
}

impl Directory {
    pub fn new(
        state_dir: PathBuf,
        configured: Vec<RelayAddress>,
        slots: usize,
        identity: Identity,
        location: Option<Location>,
        clock: Clock,
    ) -> Result<Arc<Self>, String> {
        let mut known = read_relays(&state_dir.join("relays"));
        for relay in configured {
            if !known.iter().any(|known| known.key == relay.key) {
                known.push(relay);
            }
        }
        let info = sign_info(&identity, location, clock, &[])?;
        Ok(Arc::new(Self {
            state_dir,
            known: Mutex::new(known),
            in_use: Mutex::new(vec![None; slots]),
            identity,
            location,
            clock,
            info: watch::channel(Arc::new(Record::ReceiverInfo(info))).0,
        }))
    }

    pub fn info(&self) -> watch::Receiver<Arc<Record>> {
        self.info.subscribe()
    }

    /// The anchor kept from an earlier run, if it is still known.
    pub fn saved_anchor(&self) -> Option<RelayAddress> {
        let text = std::fs::read_to_string(self.state_dir.join("anchor")).ok()?;
        crate::config::parse_relay(text.trim()).ok()
    }

    pub fn save_anchor(&self, relay: &RelayAddress) {
        let text = format!("{}={}\n", relay.address, relay.key);
        self.write_state("anchor", &text);
    }

    /// Adds relays a relay offered. They are hints: they only widen what random slots pick from.
    pub fn learn(&self, relays: &[RelayAddress]) {
        let Ok(mut known) = self.known.lock() else {
            return;
        };
        let before = known.len();
        for relay in relays {
            if !known.iter().any(|known| known.key == relay.key) {
                known.push(relay.clone());
            }
        }
        if known.len() != before {
            let text: String = known
                .iter()
                .map(|relay| format!("{}={}\n", relay.address, relay.key))
                .collect();
            drop(known);
            self.write_state("relays", &text);
        }
    }

    /// A random known relay that no slot is using.
    pub fn pick(&self) -> Option<RelayAddress> {
        let known = self.known.lock().ok()?;
        let in_use = self.in_use.lock().ok()?;
        let taken: HashSet<PublicKey> = in_use.iter().flatten().copied().collect();
        let free: Vec<&RelayAddress> = known
            .iter()
            .filter(|relay| !taken.contains(&relay.key))
            .collect();
        if free.is_empty() {
            return None;
        }
        let mut bytes = [0; 8];
        let _ = getrandom::getrandom(&mut bytes);
        let at = usize::try_from(u64::from_be_bytes(bytes) % free.len() as u64).ok()?;
        free.get(at).map(|relay| (*relay).clone())
    }

    /// Records which relay a slot holds, and re-signs the receiver's description to say so.
    pub fn hold(&self, slot: usize, relay: Option<PublicKey>) {
        let relays: Vec<PublicKey> = {
            let Ok(mut in_use) = self.in_use.lock() else {
                return;
            };
            if let Some(held) = in_use.get_mut(slot) {
                *held = relay;
            }
            in_use.iter().flatten().copied().collect()
        };
        match sign_info(&self.identity, self.location, self.clock, &relays) {
            Ok(info) => {
                self.info.send_replace(Arc::new(Record::ReceiverInfo(info)));
            }
            Err(error) => eprintln!("tally-feed: signing receiver info: {error}"),
        }
    }

    fn write_state(&self, name: &str, text: &str) {
        let path = self.state_dir.join(name);
        let written = std::fs::create_dir_all(&self.state_dir)
            .and_then(|()| std::fs::write(path.with_extension("new"), text))
            .and_then(|()| std::fs::rename(path.with_extension("new"), &path));
        if let Err(error) = written {
            eprintln!("tally-feed: saving {}: {error}", path.display());
        }
    }
}

fn read_relays(path: &std::path::Path) -> Vec<RelayAddress> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .filter_map(|line| crate::config::parse_relay(line.trim()).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn sign_info(
    identity: &Identity,
    location: Option<Location>,
    clock: Clock,
    relays: &[PublicKey],
) -> Result<ReceiverInfo, String> {
    ReceiverInfo::sign(
        identity,
        &tally_wire::batch::ReceiverInfoContent {
            issued_ms: wall_ms(),
            location,
            clock,
            software: concat!("tally-feed ", env!("CARGO_PKG_VERSION")).to_owned(),
            relays: relays.to_vec(),
        },
    )
    .map_err(|error| error.to_string())
}

/// How a session ended.
enum Outcome {
    /// Try the same relay again, after at least this long.
    Retry(Duration),
    /// The relay asked to be left.
    Leave(Duration),
}

/// One slot of the relay set, for as long as the feeder runs.
pub async fn slot(
    index: usize,
    kind: SlotKind,
    mut relay: Option<RelayAddress>,
    directory: Arc<Directory>,
    identity: Identity,
    batches: broadcast::Sender<Arc<Record>>,
    ceiling: u32,
) {
    let mut backoff = Backoff::new();
    loop {
        let current = match relay.clone().or_else(|| directory.pick()) {
            Some(current) => current,
            None => {
                tokio::time::sleep(NOTHING_TO_PICK).await;
                continue;
            }
        };
        if kind == SlotKind::Anchor && relay.as_ref() != Some(&current) {
            directory.save_anchor(&current);
        }
        relay = Some(current.clone());
        directory.hold(index, Some(current.key));
        let outcome = session(
            &current,
            &identity,
            &directory,
            batches.subscribe(),
            ceiling,
        )
        .await;
        match outcome {
            Ok(Outcome::Retry(wait)) => backoff.at_least(wait),
            Ok(Outcome::Leave(wait)) => {
                // Only the owner's home relay is kept through a "leave me"; an anchor that retires
                // is replaced, and the new one saved.
                if kind != SlotKind::Home {
                    relay = None;
                    directory.hold(index, None);
                    backoff.reset();
                    continue;
                }
                backoff.at_least(wait);
            }
            Err(error) => eprintln!("tally-feed: relay {}: {error}", current.address),
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn session(
    relay: &RelayAddress,
    identity: &Identity,
    directory: &Directory,
    mut batches: broadcast::Receiver<Arc<Record>>,
    ceiling: u32,
) -> Result<Outcome, String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let session = match noise::connect(stream, identity, &relay.key, Role::Feeder).await {
        Ok(session) => session,
        Err(tally_wire::WireError::Refused {
            reason,
            retry_after_secs,
        }) => return Ok(goodbye(reason, retry_after_secs)),
        Err(error) => return Err(error.to_string()),
    };
    eprintln!("tally-feed: publishing to {}", relay.address);
    let (mut reader, mut writer) = (session.reader, session.writer);
    // The reader runs on its own: a read cut short by a select would lose its bytes.
    let (records_in, mut records) = mpsc::channel(16);
    let reading = tokio::spawn(async move {
        loop {
            let mut got = Vec::new();
            let message = match tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut got)).await {
                Ok(Ok(())) => Ok(got),
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("silent too long".to_owned()),
            };
            let failed = message.is_err();
            if records_in.send(message).await.is_err() || failed {
                return;
            }
        }
    });
    let result = publish(&mut writer, &mut records, &mut batches, directory, ceiling).await;
    reading.abort();
    result
}

async fn publish<S: tokio::io::AsyncWrite>(
    writer: &mut noise::Writer<S>,
    records: &mut mpsc::Receiver<Result<Vec<Record>, String>>,
    batches: &mut broadcast::Receiver<Arc<Record>>,
    directory: &Directory,
    ceiling: u32,
) -> Result<Outcome, String> {
    let mut info = directory.info();
    let first = Arc::clone(&info.borrow_and_update());
    writer
        .send(&[first])
        .await
        .map_err(|error| error.to_string())?;
    // A relay may ask for less than the owner's ceiling; batches over its request are skipped for
    // it alone, and their sequence numbers say so.
    let mut bucket = TokenBucket::new(ceiling);
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    loop {
        tokio::select! {
            batch = batches.recv() => match batch {
                Ok(batch) => {
                    let Record::Batch(signed) = &*batch else { continue };
                    if bucket.take(signed.as_bytes().len()) {
                        writer.send(&[batch]).await.map_err(|error| error.to_string())?;
                    }
                }
                // Batches this session could not keep up with are gone; gaps say so.
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return Err("source ended".to_owned()),
            },
            changed = info.changed() => {
                if changed.is_ok() {
                    let latest = Arc::clone(&info.borrow_and_update());
                    writer.send(&[latest]).await.map_err(|error| error.to_string())?;
                }
            }
            _ = heartbeat.tick() => {
                writer.send(&[Record::Heartbeat]).await.map_err(|error| error.to_string())?;
            }
            got = records.recv() => {
                let got = got.ok_or_else(|| "reader ended".to_owned())??;
                for record in got {
                    match record {
                        Record::RelayList(relays) => directory.learn(&relays),
                        Record::RateLimit { bytes_per_sec, .. } => {
                            bucket.set_rate(bytes_per_sec.min(ceiling));
                        }
                        Record::Redirect { retry_after_secs, hints } => {
                            directory.learn(&hints);
                            return Ok(Outcome::Leave(Duration::from_secs(retry_after_secs.into())));
                        }
                        Record::Goodbye { reason, retry_after_secs } => {
                            return Ok(goodbye(reason, retry_after_secs));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn goodbye(reason: Reason, retry_after_secs: u32) -> Outcome {
    let wait = Duration::from_secs(retry_after_secs.into());
    match reason {
        Reason::Leaving | Reason::Refused => Outcome::Leave(wait),
        _ => Outcome::Retry(wait),
    }
}
