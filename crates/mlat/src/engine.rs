//! The engine's centre: which receivers it multilaterates for, one mlat-server session per
//! receiver, and the signed positions it publishes (RFC-0166 §3.8).
//!
//! A receiver is used only on its own signed word: its `ReceiverInfo` verifies, gives an exact
//! location inside the engine's regions, and names a clock mlat-client knows. Each of its batches
//! must verify too, and a batch that arrives through two relays is used once (its hash is its
//! identity, §3.1). Results from the server are deduplicated (each comes back on the session of
//! every receiver that heard the message) and published about once a second.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant as StdInstant};

use tally_wire::batch::Hash;
use tally_wire::{
    Batch, Identity, Position, Positions, PositionsContent, PublicKey, ReceiverInfo, Record, Region,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::protocol::{Solution, Station};
use crate::station::{self, Received, Shared};

/// A position's sigma when the server gave no covariance. mlat-client reports -1 then; a
/// `Position` must carry a number, and 1 km is a deliberately weak claim (four receivers and a
/// poor geometry are worse than that only rarely, and a consumer trusts a small sigma more).
pub const DEFAULT_SIGMA_M: u32 = 1_000;
/// Positions per signed record: 30 bytes each, so a record stays inside one Noise message.
const POSITIONS_PER_RECORD: usize = 2_000;
/// Batches waiting for one receiver's session before newer ones are dropped: about a minute.
const RECEIVER_BACKLOG: usize = 64;
/// How long batch hashes and published results are remembered for deduplication.
const SEEN_WINDOW: Duration = Duration::from_secs(60);

/// Two generations of keys: each is remembered for one to two windows.
struct Seen<K> {
    current: HashSet<K>,
    previous: HashSet<K>,
    rotated: StdInstant,
}

impl<K: std::hash::Hash + Eq> Seen<K> {
    fn new() -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated: StdInstant::now(),
        }
    }

    /// True the first time `key` is offered within the window.
    fn insert(&mut self, key: K) -> bool {
        if self.rotated.elapsed() >= SEEN_WINDOW {
            self.previous = std::mem::take(&mut self.current);
            self.rotated = StdInstant::now();
        }
        if self.previous.contains(&key) {
            return false;
        }
        self.current.insert(key)
    }
}

struct Known {
    issued_ms: u64,
    station: Option<Station>,
    inbox: Option<mpsc::Sender<Received>>,
}

pub struct Engine {
    identity: Identity,
    regions: Vec<Region>,
    shared: Shared,
    receivers: HashMap<PublicKey, Known>,
    batches: Seen<Hash>,
    published: Seen<(u32, u64, i32, i32)>,
    pending: Vec<Position>,
    sequence: u64,
}

impl Engine {
    pub fn new(identity: Identity, regions: Vec<Region>, shared: Shared) -> Self {
        Self {
            identity,
            regions,
            shared,
            receivers: HashMap::new(),
            batches: Seen::new(),
            published: Seen::new(),
            pending: Vec::new(),
            sequence: 0,
        }
    }

    pub fn ingest(&mut self, record: Record) {
        let result = match record {
            Record::ReceiverInfo(info) => self.describe(&info),
            Record::Batch(batch) => self.receive(batch),
            _ => Ok(()),
        };
        if let Err(error) = result {
            eprintln!("tally-mlat: {error}");
        }
    }

    fn describe(&mut self, info: &ReceiverInfo) -> Result<(), String> {
        let key = info.receiver().map_err(|error| error.to_string())?;
        info.verify()
            .map_err(|error| format!("receiver info of {key}: {error}"))?;
        // A format this build cannot read says nothing it can use.
        let Ok(content) = info.content() else {
            return Ok(());
        };
        if self
            .receivers
            .get(&key)
            .is_some_and(|known| known.issued_ms >= content.issued_ms)
        {
            return Ok(());
        }
        let inside = content.location.is_some_and(|location| {
            self.regions.is_empty() || self.regions.iter().any(|region| region.covers(&location))
        });
        let station = Station::of(&key, content.location, content.clock).filter(|_| inside);
        let known = self.receivers.entry(key).or_insert(Known {
            issued_ms: 0,
            station: None,
            inbox: None,
        });
        known.issued_ms = content.issued_ms;
        if known.station != station {
            // The server learns a receiver's position and clock only in the handshake, so a
            // change is a new session; dropping the inbox ends the old one.
            known.station = station;
            known.inbox = None;
        }
        Ok(())
    }

    fn receive(&mut self, batch: Batch) -> Result<(), String> {
        let key = batch.receiver().map_err(|error| error.to_string())?;
        let Some(known) = self.receivers.get_mut(&key) else {
            return Ok(());
        };
        let Some(station) = known.station.clone() else {
            return Ok(());
        };
        batch
            .verify()
            .map_err(|error| format!("batch of {key}: {error}"))?;
        if !self.batches.insert(batch.hash()) {
            return Ok(());
        }
        let Ok(content) = batch.content() else {
            return Ok(());
        };
        let received = Received {
            arrival: Instant::now(),
            counter_epoch: content.counter_epoch,
            observations: content.observations,
        };
        let inbox = match &known.inbox {
            Some(inbox) if !inbox.is_closed() => inbox.clone(),
            _ => {
                let (inbox, receiving) = mpsc::channel(RECEIVER_BACKLOG);
                tokio::spawn(station::run(station, self.shared.clone(), receiving));
                known.inbox = Some(inbox.clone());
                inbox
            }
        };
        // A full inbox is a session that is behind; it loses this batch, not the engine.
        let _ = inbox.try_send(received);
        Ok(())
    }

    /// Takes a result from the server, once, as a position.
    pub fn solved(&mut self, solution: &Solution) {
        let Some(position) = position(solution, self.shared.delay) else {
            return;
        };
        let key = (
            position.address,
            position.time_ms,
            position.lat_e7,
            position.lon_e7,
        );
        if self.published.insert(key) {
            self.pending.push(position);
        }
    }

    /// Signs what has been solved since the last call, as `Positions` records.
    pub fn flush(&mut self, issued_ms: u64) -> Result<Vec<Record>, String> {
        let pending = std::mem::take(&mut self.pending);
        pending
            .chunks(POSITIONS_PER_RECORD)
            .map(|positions| {
                let content = PositionsContent {
                    sequence: self.sequence,
                    issued_ms,
                    positions: positions.to_vec(),
                };
                self.sequence += 1;
                Positions::sign(&self.identity, &content)
                    .map(Record::Positions)
                    .map_err(|error| error.to_string())
            })
            .collect()
    }
}

/// A server result as a `Position`. The server stamps a result with its own clock when the
/// message's copies reached it (`cluster_utc` in mlattrack.py), which the engine's replay put
/// `delay` after the transmission, so the delay is taken back off.
pub fn position(solution: &Solution, delay: Duration) -> Option<Position> {
    let delay_ms = i64::try_from(delay.as_millis()).ok()?;
    let at_ms = (solution.at * 1000.0).round();
    if !at_ms.is_finite() || !(-90.0..=90.0).contains(&solution.lat) {
        return None;
    }
    let time_ms = u64::try_from((at_ms as i64).checked_sub(delay_ms)?).ok()?;
    let mut lon = solution.lon;
    if lon > 180.0 {
        lon -= 360.0;
    }
    if !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    let alt_ft = solution
        .alt_ft
        .filter(|alt| alt.is_finite() && alt.abs() < 1e6)
        .map(|alt| alt.round() as i32);
    let sigma_m = solution
        .sigma_m
        .filter(|sigma| sigma.is_finite() && *sigma >= 0.0)
        .map_or(DEFAULT_SIGMA_M, |sigma| {
            sigma.round().min(f64::from(u32::MAX)) as u32
        });
    Some(Position {
        address: solution.address & 0x00ff_ffff,
        time_ms,
        lat_e7: (solution.lat * 1e7).round() as i32,
        lon_e7: (lon * 1e7).round() as i32,
        alt_ft,
        sigma_m,
        receivers: u16::try_from(solution.receivers).unwrap_or(u16::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solution() -> Solution {
        Solution {
            address: 0x40621d,
            at: 1_791_220_000.5,
            lat: 37.5,
            lon: -122.0,
            alt_ft: Some(9_842.4),
            sigma_m: Some(141.4),
            receivers: 4,
        }
    }

    #[test]
    fn a_result_is_dated_when_it_was_sent_not_when_the_server_saw_it() {
        let position = position(&solution(), Duration::from_millis(2_000));
        assert_eq!(
            position,
            Some(Position {
                address: 0x40621d,
                time_ms: 1_791_219_998_500,
                lat_e7: 375_000_000,
                lon_e7: -1_220_000_000,
                alt_ft: Some(9_842),
                sigma_m: 141,
                receivers: 4,
            })
        );
        let unknown = Solution {
            sigma_m: None,
            ..solution()
        };
        assert_eq!(
            super::position(&unknown, Duration::ZERO).map(|position| position.sigma_m),
            Some(DEFAULT_SIGMA_M)
        );
    }

    #[test]
    fn the_same_result_from_several_receivers_is_published_once_and_signed() -> Result<(), String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let (results, _) = mpsc::channel(1);
        let mut engine = Engine::new(
            identity.clone(),
            Vec::new(),
            Shared {
                server: String::new(),
                delay: Duration::ZERO,
                start: Instant::now(),
                results,
            },
        );
        for _ in 0..3 {
            engine.solved(&solution());
        }
        let records = engine.flush(5)?;
        let [Record::Positions(positions)] = records.as_slice() else {
            return Err(format!("{records:?}"));
        };
        positions.verify().map_err(|error| error.to_string())?;
        let content = positions.content().map_err(|error| error.to_string())?;
        assert_eq!((content.sequence, content.positions.len()), (0, 1));
        assert!(engine.flush(6)?.is_empty());
        engine.solved(&Solution {
            at: 1_791_220_001.0,
            ..solution()
        });
        let records = engine.flush(7)?;
        let [Record::Positions(next)] = records.as_slice() else {
            return Err(format!("{records:?}"));
        };
        assert_eq!(next.sequence(), 1);
        assert_eq!(
            next.engine().map_err(|error| error.to_string())?,
            identity.public()
        );
        Ok(())
    }
}
