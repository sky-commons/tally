//! The engine's centre: which receivers it multilaterates for, one mlat-server session per
//! receiver, and the signed positions it publishes (RFC-0171 §3.8).
//!
//! A receiver is used only on its own signed word: its `ReceiverInfo` verifies, gives an exact
//! location inside the engine's regions, and names a clock mlat-client knows. Nothing is kept for
//! any other receiver. At most `--max-receivers` are admitted (have a session) at once; beyond
//! that, up to `WAITING_PER_SLOT` times as many wait, the least recently heard forgotten first,
//! and their batches are only counted (their signature checked, their contents never used). A
//! place that frees goes to the most active waiting receiver, and an admitted receiver that has
//! sent no batch for `IDLE` yields its place to a waiting one that has. So which receivers hold
//! the places follows who is publishing, not who described itself first, and a receiver turned
//! away is admitted later without reconnecting. Throwaway keys that keep publishing real-looking
//! batches can still hold places: bounded by the cap, not prevented (RFC-0171 §4's residuals,
//! accepted by the ruling of §8.1). Each of an admitted receiver's batches must verify too, and is used once: a batch that arrives through two relays, or is replayed at any
//! later time, carries a (boot, sequence) already used or too far behind that boot's newest
//! (§3.1). Results from the server are deduplicated (each comes back on the session of every
//! receiver that heard the message) and published about once a second.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

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
/// The default `--max-receivers`: mlat-server sessions the engine holds at once.
pub const DEFAULT_MAX_RECEIVERS: usize = 1_000;
/// Positions per signed record: 30 bytes each, so a record stays inside one Noise message.
const POSITIONS_PER_RECORD: usize = 2_000;
/// Batches waiting for one receiver's session before newer ones are dropped: about a minute.
const RECEIVER_BACKLOG: usize = 64;
/// How long published results are remembered for deduplication.
const SEEN_WINDOW: Duration = Duration::from_secs(60);
/// How far behind a boot's newest sequence a batch may still arrive (two relays, or one relay's
/// reordering) and be used; anything older is a replay or too late to matter.
const REORDER: u64 = 64;
/// Boots remembered per receiver, most recent first. A receiver that restarts more often than
/// this within one session only weakens its own replay protection.
const BOOTS_PER_RECEIVER: usize = 8;
/// An admitted receiver that has sent no batch for this long yields its place to a waiting one
/// that has. Its session has ended by then (`station::GONE`). It is also the window batch
/// activity is counted over.
const IDLE: Duration = station::GONE;
/// Receivers waiting for a place, per place under the cap.
const WAITING_PER_SLOT: usize = 4;
/// How often receivers turned away by the cap are reported.
const CAP_REPORT_EVERY: Duration = Duration::from_secs(60);

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

/// The sequences of one boot already used: the newest, and which of the `REORDER` before it.
/// A boot's `sequence` names its batch (`BatchContent::boot_id`), so a batch that arrives through
/// two relays, a replay, and a second batch the receiver signed under a used number are all a
/// sequence seen before; no time window is involved, so a replay a minute later is still one.
struct Window {
    newest: u64,
    /// Bit `i` set: sequence `newest - i` was used.
    used: u64,
}

impl Window {
    fn new(sequence: u64) -> Self {
        Self {
            newest: sequence,
            used: 1,
        }
    }

    /// True the first time `sequence` is offered, if it is within `REORDER` of the newest.
    fn admit(&mut self, sequence: u64) -> bool {
        if sequence > self.newest {
            let ahead = sequence - self.newest;
            self.used = if ahead >= REORDER {
                0
            } else {
                self.used << ahead
            };
            self.used |= 1;
            self.newest = sequence;
            return true;
        }
        let behind = self.newest - sequence;
        if behind >= REORDER {
            return false;
        }
        let bit = 1 << behind;
        if self.used & bit != 0 {
            return false;
        }
        self.used |= bit;
        true
    }
}

/// Batches a receiver sent over the last one to two `IDLE` windows: two generations, like `Seen`.
struct Activity {
    since: Instant,
    current: u32,
    previous: u32,
}

impl Activity {
    fn new(now: Instant) -> Self {
        Self {
            since: now,
            current: 0,
            previous: 0,
        }
    }

    fn record(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.since);
        if elapsed >= IDLE * 2 {
            *self = Self::new(now);
        } else if elapsed >= IDLE {
            self.previous = self.current;
            self.current = 0;
            self.since += IDLE;
        }
        self.current = self.current.saturating_add(1);
    }

    fn recent(&self, now: Instant) -> u32 {
        let elapsed = now.saturating_duration_since(self.since);
        if elapsed >= IDLE * 2 {
            0
        } else if elapsed >= IDLE {
            self.current
        } else {
            self.current.saturating_add(self.previous)
        }
    }
}

/// A receiver inside the engine's regions: admitted, with a session (or one about to start), or
/// waiting for a place under the cap.
struct Known {
    issued_ms: u64,
    station: Station,
    inbox: Option<mpsc::Sender<Received>>,
    boots: VecDeque<(u64, Window)>,
    /// Its last description or counted batch: the least recently heard waiting one goes first.
    last_heard: Instant,
    last_batch: Option<Instant>,
    /// When it was given its place; `None` while it waits.
    admitted: Option<Instant>,
    activity: Activity,
}

impl Known {
    fn new(issued_ms: u64, station: Station, now: Instant) -> Self {
        Self {
            issued_ms,
            station,
            inbox: None,
            boots: VecDeque::new(),
            last_heard: now,
            last_batch: None,
            admitted: None,
            activity: Activity::new(now),
        }
    }

    fn heard_batch(&mut self, now: Instant) {
        self.last_heard = now;
        self.last_batch = Some(now);
        self.activity.record(now);
    }

    /// True when it has sent no batch for `IDLE`, counting a fresh place as a batch so a receiver
    /// just admitted is not turned out before it has had the chance to send one.
    fn quiet(&self, now: Instant) -> bool {
        self.last_batch
            .max(self.admitted)
            .is_none_or(|at| now.saturating_duration_since(at) >= IDLE)
    }

    /// How it ranks for a place: most batches lately, then most recently heard.
    fn rank(&self, now: Instant) -> (u32, Option<Instant>, Instant) {
        (self.activity.recent(now), self.last_batch, self.last_heard)
    }

    /// True when the batch numbered `sequence` in `boot` has not been used.
    fn admit(&mut self, boot: u64, sequence: u64) -> bool {
        let entry = match self.boots.iter().position(|(id, _)| *id == boot) {
            Some(at) => self.boots.remove(at).map(|(_, window)| window),
            None => None,
        };
        let (admitted, window) = match entry {
            Some(mut window) => (window.admit(sequence), window),
            None => {
                self.boots.truncate(BOOTS_PER_RECEIVER - 1);
                (true, Window::new(sequence))
            }
        };
        self.boots.push_front((boot, window));
        admitted
    }
}

/// Receivers that left the engine's regions, with the description that said so, so an older
/// description replayed later cannot bring them back. Bounded, oldest forgotten first.
struct Departed {
    issued: HashMap<PublicKey, u64>,
    order: VecDeque<PublicKey>,
    capacity: usize,
}

impl Departed {
    fn new(capacity: usize) -> Self {
        Self {
            issued: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&self, key: &PublicKey) -> Option<u64> {
        self.issued.get(key).copied()
    }

    fn insert(&mut self, key: PublicKey, issued_ms: u64) {
        if self.issued.insert(key, issued_ms).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.issued.remove(&oldest);
            }
        }
    }

    fn remove(&mut self, key: &PublicKey) {
        if self.issued.remove(key).is_some() {
            self.order.retain(|other| other != key);
        }
    }
}

pub struct Engine {
    identity: Identity,
    regions: Vec<Region>,
    shared: Shared,
    max_receivers: usize,
    /// Admitted receivers: at most `max_receivers`.
    receivers: HashMap<PublicKey, Known>,
    /// Receivers in the regions beyond the cap: at most `max_receivers * WAITING_PER_SLOT`, and
    /// empty whenever there is a free place.
    waiting: HashMap<PublicKey, Known>,
    departed: Departed,
    /// Receivers put on the waiting list since it was last reported, and when that was.
    turned_away: u64,
    reported: Option<Instant>,
    published: Seen<(u32, u64, i32, i32)>,
    pending: Vec<Position>,
    /// This process's boot: relays number an engine's positions per (engine, boot), so a restart
    /// starts its sequence again at 0 without colliding with what the last boot published.
    boot_id: u64,
    sequence: u64,
}

impl Engine {
    pub fn new(
        identity: Identity,
        regions: Vec<Region>,
        max_receivers: usize,
        shared: Shared,
    ) -> Self {
        Self {
            identity,
            regions,
            shared,
            max_receivers,
            receivers: HashMap::new(),
            waiting: HashMap::new(),
            departed: Departed::new(max_receivers),
            turned_away: 0,
            reported: None,
            published: Seen::new(),
            pending: Vec::new(),
            boot_id: new_boot_id(),
            sequence: 0,
        }
    }

    /// The boot id every `Positions` this engine signs carries.
    pub fn boot_id(&self) -> u64 {
        self.boot_id
    }

    /// Takes a record from a relay. True when it was a batch admitted for a receiver's session.
    pub fn ingest(&mut self, record: Record) -> bool {
        self.ingest_at(record, Instant::now())
    }

    fn ingest_at(&mut self, record: Record, now: Instant) -> bool {
        let result = match record {
            Record::ReceiverInfo(info) => self.describe(&info, now).map(|()| false),
            Record::Batch(batch) => self.receive(batch, now),
            // A relay's deduplicated stream is the relay's word, not a receiver's, and carries no
            // receiver's counter: it is never multilaterated. Only `Batch::verify` admits a batch.
            Record::RelayBatch(_) => Ok(false),
            _ => Ok(false),
        };
        result.unwrap_or_else(|error| {
            eprintln!("tally-mlat: {error}");
            false
        })
    }

    fn describe(&mut self, info: &ReceiverInfo, now: Instant) -> Result<(), String> {
        let key = info.receiver().map_err(|error| error.to_string())?;
        info.verify()
            .map_err(|error| format!("receiver info of {key}: {error}"))?;
        // A format this build cannot read says nothing it can use.
        let Ok(content) = info.content() else {
            return Ok(());
        };
        let newest = self
            .receivers
            .get(&key)
            .or_else(|| self.waiting.get(&key))
            .map(|known| known.issued_ms)
            .or_else(|| self.departed.get(&key));
        if newest.is_some_and(|issued_ms| issued_ms >= content.issued_ms) {
            return Ok(());
        }
        let inside = content.location.is_some_and(|location| {
            self.regions.is_empty() || self.regions.iter().any(|region| region.covers(&location))
        });
        let Some(station) = Station::of(&key, content.location, content.clock).filter(|_| inside)
        else {
            // Outside, or unusable: nothing is kept, a session it had ends with its inbox, and
            // its place goes to a waiting receiver.
            let admitted = self.receivers.remove(&key).is_some();
            let waited = self.waiting.remove(&key).is_some();
            if admitted || waited || self.departed.get(&key).is_some() {
                self.departed.insert(key, content.issued_ms);
            }
            if admitted {
                self.fill(now);
            }
            return Ok(());
        };
        self.departed.remove(&key);
        if let Some(known) = self.receivers.get_mut(&key) {
            known.issued_ms = content.issued_ms;
            known.last_heard = now;
            if known.station != station {
                // The server learns a receiver's position and clock only in the handshake, so a
                // change is a new session; dropping the inbox ends the old one.
                known.station = station;
                known.inbox = None;
            }
            return Ok(());
        }
        if let Some(waiting) = self.waiting.get_mut(&key) {
            waiting.issued_ms = content.issued_ms;
            waiting.last_heard = now;
            waiting.station = station;
            return Ok(());
        }
        let known = Known::new(content.issued_ms, station, now);
        if self.receivers.len() < self.max_receivers {
            self.admit(key, known, now);
        } else {
            self.wait(key, known);
            self.turn_away(now);
        }
        Ok(())
    }

    fn admit(&mut self, key: PublicKey, mut known: Known, now: Instant) {
        known.admitted = Some(now);
        self.receivers.insert(key, known);
    }

    /// Puts a receiver on the waiting list, forgetting the least recently heard beyond its bound.
    fn wait(&mut self, key: PublicKey, mut known: Known) {
        // Dropping the inbox ends a session it had.
        known.inbox = None;
        known.admitted = None;
        self.waiting.insert(key, known);
        let capacity = self.max_receivers.saturating_mul(WAITING_PER_SLOT);
        while self.waiting.len() > capacity {
            let stalest = self
                .waiting
                .iter()
                .min_by_key(|(_, known)| known.last_heard)
                .map(|(key, _)| *key);
            match stalest {
                Some(stalest) => self.waiting.remove(&stalest),
                None => break,
            };
        }
    }

    /// Gives free places to the most active waiting receivers.
    fn fill(&mut self, now: Instant) {
        while self.receivers.len() < self.max_receivers {
            let best = self
                .waiting
                .iter()
                .max_by_key(|(_, known)| known.rank(now))
                .map(|(key, _)| *key);
            let Some((key, known)) =
                best.and_then(|key| self.waiting.remove(&key).map(|known| (key, known)))
            else {
                return;
            };
            self.admit(key, known, now);
        }
    }

    /// Run about once a second: fills free places, and moves each admitted receiver that has sent
    /// no batch for `IDLE` to the waiting list in favour of a waiting one that has, the most active
    /// replacing the longest quiet.
    pub fn tick(&mut self) {
        self.tick_at(Instant::now());
    }

    fn tick_at(&mut self, now: Instant) {
        self.fill(now);
        let mut active = self
            .waiting
            .iter()
            .filter(|(_, known)| !known.quiet(now))
            .map(|(key, known)| (known.rank(now), *key))
            .collect::<Vec<_>>();
        if active.is_empty() {
            return;
        }
        active.sort_unstable_by_key(|(rank, _)| std::cmp::Reverse(*rank));
        let mut quiet = self
            .receivers
            .iter()
            .filter(|(_, known)| known.quiet(now))
            .map(|(key, known)| (known.last_batch.max(known.admitted), *key))
            .collect::<Vec<_>>();
        quiet.sort_unstable_by_key(|(since, _)| *since);
        for ((_, incoming), (_, outgoing)) in active.into_iter().zip(quiet) {
            let (Some(incoming_known), Some(outgoing_known)) = (
                self.waiting.remove(&incoming),
                self.receivers.remove(&outgoing),
            ) else {
                continue;
            };
            self.admit(incoming, incoming_known, now);
            self.wait(outgoing, outgoing_known);
        }
    }

    fn turn_away(&mut self, now: Instant) {
        self.turned_away += 1;
        if self
            .reported
            .is_none_or(|at| now.duration_since(at) >= CAP_REPORT_EVERY)
        {
            eprintln!(
                "tally-mlat: at --max-receivers {}: {} new receiver(s) put on the waiting list ({} \
                 waiting; a place goes to the most active)",
                self.max_receivers,
                self.turned_away,
                self.waiting.len()
            );
            self.turned_away = 0;
            self.reported = Some(now);
        }
    }

    /// True when the batch was admitted: new, live, and handed to its receiver's session (or
    /// lost to a session that is behind). A waiting receiver's batch is only counted, once, when
    /// its signature verifies; its contents are never read.
    fn receive(&mut self, batch: Batch, arrival: Instant) -> Result<bool, String> {
        let key = batch.receiver().map_err(|error| error.to_string())?;
        if let Some(waiting) = self.waiting.get_mut(&key) {
            batch
                .verify()
                .map_err(|error| format!("batch of {key}: {error}"))?;
            if waiting.admit(batch.boot_id(), batch.sequence()) {
                waiting.heard_batch(arrival);
            }
            return Ok(false);
        }
        let Some(known) = self.receivers.get_mut(&key) else {
            return Ok(false);
        };
        batch
            .verify()
            .map_err(|error| format!("batch of {key}: {error}"))?;
        if !known.admit(batch.boot_id(), batch.sequence()) {
            return Ok(false);
        }
        let Ok(content) = batch.content() else {
            return Ok(false);
        };
        known.heard_batch(arrival);
        let received = Received {
            arrival,
            counter_epoch: content.counter_epoch,
            observations: content.observations,
        };
        let inbox = match &known.inbox {
            Some(inbox) if !inbox.is_closed() => inbox.clone(),
            _ => {
                let (inbox, receiving) = mpsc::channel(RECEIVER_BACKLOG);
                tokio::spawn(station::run(
                    known.station.clone(),
                    self.shared.clone(),
                    receiving,
                ));
                known.inbox = Some(inbox.clone());
                inbox
            }
        };
        // A full inbox is a session that is behind; it loses this batch, not the engine.
        let _ = inbox.try_send(received);
        Ok(true)
    }

    /// Admitted receivers, each with at most one session.
    pub fn receivers(&self) -> usize {
        self.receivers.len()
    }

    /// Receivers waiting for a place under the cap.
    pub fn waiting(&self) -> usize {
        self.waiting.len()
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
                    boot_id: self.boot_id,
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

/// A boot id only has to differ from this engine's other boots; failing randomness from the
/// system, the clock does.
fn new_boot_id() -> u64 {
    let mut boot = [0; 8];
    if getrandom::getrandom(&mut boot).is_err() {
        // The low bits of the nanoseconds: what differs between two starts.
        boot = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64)
            .to_be_bytes();
    }
    u64::from_be_bytes(boot)
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
    use tally_wire::batch::ReceiverInfoContent;
    use tally_wire::{BatchContent, Clock, Location, Observation};

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

    fn engine(regions: Vec<Region>, max_receivers: usize) -> Result<Engine, String> {
        let (results, _) = mpsc::channel(1);
        Ok(Engine::new(
            Identity::generate().map_err(|error| error.to_string())?,
            regions,
            max_receivers,
            Shared {
                // Nothing listens on port 1: sessions fail to connect and retry, harmlessly.
                server: "127.0.0.1:1".to_owned(),
                delay: Duration::from_secs(2),
                start: Instant::now(),
                results,
            },
        ))
    }

    fn at(lat_e7: i32) -> Location {
        Location {
            lat_e7,
            lon_e7: -1_221_000_000,
            alt_m: 10,
            precision_m: 0,
        }
    }

    fn info(receiver: &Identity, issued_ms: u64, location: Location) -> Result<Record, String> {
        ReceiverInfo::sign(
            receiver,
            &ReceiverInfoContent {
                issued_ms,
                location: Some(location),
                clock: Clock::Dump1090,
                software: "test".to_owned(),
                relays: Vec::new(),
            },
        )
        .map(Record::ReceiverInfo)
        .map_err(|error| error.to_string())
    }

    fn content(boot_id: u64, sequence: u64) -> BatchContent {
        BatchContent {
            boot_id,
            sequence,
            counter_epoch: 0,
            wall_ms: 0,
            dropped: 0,
            previous: [0; 32],
            observations: vec![Observation {
                format: b'2',
                timestamp: 12_000_000 * (1_000 + sequence),
                signal: 1,
                data: vec![0; 7],
            }],
        }
    }

    fn batch(receiver: &Identity, boot_id: u64, sequence: u64) -> Result<Record, String> {
        Batch::sign(receiver, &content(boot_id, sequence))
            .map(Record::Batch)
            .map_err(|error| error.to_string())
    }

    fn region() -> Result<Region, String> {
        Region::containing(&at(374_100_000), 3).map_err(|error| error.to_string())
    }

    #[tokio::test]
    async fn a_batch_replayed_after_any_window_is_never_used_again() -> Result<(), String> {
        let receiver = Identity::generate().map_err(|error| error.to_string())?;
        let mut engine = engine(vec![region()?], 10)?;
        let start = Instant::now();
        engine.ingest_at(info(&receiver, 1, at(374_100_000))?, start);
        for sequence in 0..=100 {
            assert!(
                engine.ingest_at(batch(&receiver, 7, sequence)?, start),
                "{sequence}"
            );
        }
        // The same batch through a second relay, at once.
        assert!(!engine.ingest_at(batch(&receiver, 7, 100)?, start));
        // Two minutes later, past the minute a hash was once remembered for.
        let later = start + Duration::from_secs(120);
        assert!(!engine.ingest_at(batch(&receiver, 7, 50)?, later));
        assert!(!engine.ingest_at(batch(&receiver, 7, 99)?, later));
        // A second batch the receiver signed under a number already used is not used either.
        let mut twin = content(7, 98);
        twin.dropped = 1;
        let twin = Batch::sign(&receiver, &twin).map_err(|error| error.to_string())?;
        assert!(!engine.ingest_at(Record::Batch(twin), later));
        // Reordering within the allowance is fine; far behind the newest is not.
        assert!(engine.ingest_at(batch(&receiver, 7, 102)?, later));
        assert!(engine.ingest_at(batch(&receiver, 7, 101)?, later));
        assert!(!engine.ingest_at(batch(&receiver, 7, 102 - REORDER)?, later));
        // A restarted receiver's new boot starts its own numbering.
        assert!(engine.ingest_at(batch(&receiver, 8, 0)?, later));
        assert!(!engine.ingest_at(batch(&receiver, 8, 0)?, later));
        assert!(engine.ingest_at(batch(&receiver, 7, 103)?, later));
        Ok(())
    }

    fn identities(count: usize) -> Result<Vec<Identity>, String> {
        (0..count)
            .map(|_| Identity::generate().map_err(|error| error.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn only_receivers_inside_a_region_are_kept_and_at_most_the_cap() -> Result<(), String> {
        let mut engine = engine(vec![region()?], 2)?;
        let start = Instant::now();
        // Far outside the region: nothing is kept, and its batches go nowhere.
        let outside = Identity::generate().map_err(|error| error.to_string())?;
        engine.ingest_at(info(&outside, 1, at(-334_000_000))?, start);
        assert_eq!((engine.receivers(), engine.waiting()), (0, 0));
        assert!(!engine.ingest_at(batch(&outside, 1, 0)?, start));
        let inside = identities(3)?;
        for receiver in &inside {
            engine.ingest_at(info(receiver, 1, at(374_100_000))?, start);
        }
        // Two are admitted; the third waits, and its batches are counted, not used.
        assert_eq!((engine.receivers(), engine.waiting()), (2, 1));
        assert!(engine.ingest_at(batch(&inside[0], 1, 0)?, start));
        assert!(!engine.ingest_at(batch(&inside[2], 1, 0)?, start));
        // The first leaves the region: its place goes to the waiting one at once, and an older
        // description replayed cannot bring the first back.
        engine.ingest_at(info(&inside[0], 2, at(-334_000_000))?, start);
        assert_eq!((engine.receivers(), engine.waiting()), (2, 0));
        assert!(engine.ingest_at(batch(&inside[2], 1, 1)?, start));
        engine.ingest_at(info(&inside[0], 1, at(374_100_000))?, start);
        assert_eq!((engine.receivers(), engine.waiting()), (2, 0));
        Ok(())
    }

    #[tokio::test]
    async fn a_waiting_receiver_is_admitted_when_an_admitted_one_departs() -> Result<(), String> {
        let mut engine = engine(vec![region()?], 2)?;
        let start = Instant::now();
        let receivers = identities(4)?;
        for receiver in &receivers {
            engine.ingest_at(info(receiver, 1, at(374_100_000))?, start);
        }
        assert_eq!((engine.receivers(), engine.waiting()), (2, 2));
        // Of the two waiting, the one publishing gets the place, whoever described itself first.
        let (waiting_quiet, waiting_active) = (&receivers[2], &receivers[3]);
        for sequence in 0..2 {
            assert!(!engine.ingest_at(batch(waiting_active, 1, sequence)?, start));
        }
        // A replayed batch is counted once, so three copies of one do not outrank two batches.
        for _ in 0..3 {
            assert!(!engine.ingest_at(batch(waiting_quiet, 1, 0)?, start));
        }
        engine.ingest_at(info(&receivers[0], 2, at(-334_000_000))?, start);
        assert_eq!((engine.receivers(), engine.waiting()), (2, 1));
        assert!(engine.ingest_at(batch(waiting_active, 1, 2)?, start));
        assert!(!engine.ingest_at(batch(waiting_quiet, 1, 1)?, start));
        Ok(())
    }

    #[tokio::test]
    async fn a_full_engine_of_quiet_receivers_yields_to_an_active_waiting_one() -> Result<(), String>
    {
        let mut engine = engine(vec![region()?], 2)?;
        let start = Instant::now();
        let receivers = identities(3)?;
        for receiver in &receivers {
            engine.ingest_at(info(receiver, 1, at(374_100_000))?, start);
        }
        let newcomer = &receivers[2];
        assert!(!engine.ingest_at(batch(newcomer, 1, 0)?, start));
        // Before the idle limit, the admitted keep their places though they send nothing.
        let early = start + IDLE - Duration::from_secs(1);
        assert!(!engine.ingest_at(batch(newcomer, 1, 1)?, early));
        engine.tick_at(early);
        assert!(!engine.ingest_at(batch(newcomer, 1, 2)?, early));
        // Once it passes, the longest quiet yields to the receiver that is publishing.
        let later = start + IDLE + Duration::from_secs(1);
        assert!(!engine.ingest_at(batch(newcomer, 1, 3)?, later));
        engine.tick_at(later);
        assert_eq!((engine.receivers(), engine.waiting()), (2, 1));
        assert!(engine.ingest_at(batch(newcomer, 1, 4)?, later));
        // The one that yielded still waits with its description, and comes back by publishing
        // once a place is quiet again: no reconnect needed.
        let yielded = receivers[..2]
            .iter()
            .find(|receiver| {
                batch(receiver, 1, 0).is_ok_and(|record| !engine.ingest_at(record, later))
            })
            .ok_or("neither yielded")?;
        let stayed = receivers[..2]
            .iter()
            .find(|receiver| receiver.public() != yielded.public())
            .ok_or("neither stayed")?;
        // The one that stayed has kept quiet; the newcomer keeps publishing.
        let much_later = later + IDLE + Duration::from_secs(1);
        assert!(engine.ingest_at(batch(newcomer, 1, 5)?, much_later));
        assert!(!engine.ingest_at(batch(yielded, 1, 1)?, much_later));
        engine.tick_at(much_later);
        assert!(engine.ingest_at(batch(yielded, 1, 2)?, much_later));
        assert!(engine.ingest_at(batch(newcomer, 1, 6)?, much_later));
        assert!(!engine.ingest_at(batch(stayed, 1, 100)?, much_later));
        Ok(())
    }

    #[tokio::test]
    async fn the_waiting_list_is_bounded_forgetting_the_least_recently_heard() -> Result<(), String>
    {
        let mut engine = engine(vec![region()?], 1)?;
        let start = Instant::now();
        let receivers = identities(2 + WAITING_PER_SLOT)?;
        for (offset, receiver) in (0u64..).zip(&receivers) {
            let now = start + Duration::from_secs(offset);
            engine.ingest_at(info(receiver, 1, at(374_100_000))?, now);
        }
        assert_eq!(
            (engine.receivers(), engine.waiting()),
            (1, WAITING_PER_SLOT)
        );
        // The first to wait was the least recently heard, and is forgotten: its batches are
        // neither used nor counted.
        assert!(!engine.ingest_at(batch(&receivers[1], 1, 0)?, start));
        assert!(!engine.waiting.contains_key(&receivers[1].public()));
        assert!(engine.waiting.contains_key(&receivers[2].public()));
        Ok(())
    }

    #[tokio::test]
    async fn a_relays_deduplicated_batch_is_never_taken_for_a_receivers() -> Result<(), String> {
        let receiver = Identity::generate().map_err(|error| error.to_string())?;
        let mut engine = engine(Vec::new(), 10)?;
        let start = Instant::now();
        engine.ingest_at(info(&receiver, 1, at(374_100_000))?, start);
        // Even a batch naming a known receiver, under the relay's signature or as a RelayBatch.
        let relayed =
            Batch::sign_as_relay(&receiver, &content(1, 0)).map_err(|error| error.to_string())?;
        assert!(!engine.ingest_at(Record::RelayBatch(relayed.clone()), start));
        assert!(!engine.ingest_at(Record::Batch(relayed), start));
        assert!(engine.ingest_at(batch(&receiver, 1, 0)?, start));
        Ok(())
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
            DEFAULT_MAX_RECEIVERS,
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
        assert_eq!(
            (positions.boot_id(), next.boot_id()),
            (engine.boot_id(), engine.boot_id())
        );
        Ok(())
    }

    #[test]
    fn an_engine_started_again_with_the_same_key_is_a_new_boot_numbered_from_zero()
    -> Result<(), String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let start = || {
            let (results, _) = mpsc::channel(1);
            Engine::new(
                identity.clone(),
                Vec::new(),
                DEFAULT_MAX_RECEIVERS,
                Shared {
                    server: String::new(),
                    delay: Duration::ZERO,
                    start: Instant::now(),
                    results,
                },
            )
        };
        let mut signed = Vec::new();
        for _ in 0..2 {
            let mut engine = start();
            engine.solved(&solution());
            let records = engine.flush(5)?;
            let [Record::Positions(positions)] = records.as_slice() else {
                return Err(format!("{records:?}"));
            };
            positions.verify().map_err(|error| error.to_string())?;
            signed.push((positions.boot_id(), positions.sequence()));
        }
        let [(first, first_sequence), (second, second_sequence)] = signed.as_slice() else {
            return Err(format!("{signed:?}"));
        };
        assert_ne!(first, second);
        assert_eq!((*first_sequence, *second_sequence), (0, 0));
        Ok(())
    }
}
