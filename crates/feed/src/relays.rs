//! Which relays a feeder publishes to, and each session with one (RFC-0166 §3.5, §3.7).
//!
//! The rules are fixed here and no relay can change them: a home relay the owner pinned, an
//! anchor kept across restarts, the rest picked at random from relays the feeder knows of. A relay
//! that says "leave me" is left, and no slot dials it again until its `retry_after_secs` has
//! passed; what it suggests instead is only a hint, added to what the feeder knows.
//!
//! A relay that is unreachable is retried, never replaced in a hurry, since rushing to fresh relays
//! during an outage is how a feeder gets surrounded. That holds within fixed bounds, so a relay
//! that is gone for good does not hold its slot forever. A relay is reached when a session with it
//! gets to `Welcome`, and stays reached while that session is up; it is unreachable from the last
//! time it was reached, or, never reached, from when the slot first chose it.
//!
//! - A random slot gives up its relay once it has been continuously unreachable for an hour
//!   (`RANDOM_GIVES_UP`), and picks another; with no other to pick, it keeps retrying.
//! - The anchor gives up its relay after seven days continuously unreachable (`ANCHOR_GIVES_UP`),
//!   then a new anchor is chosen and saved; with no other to pick, it keeps retrying. When the
//!   anchor was last reached is saved beside it, so the seven days run across restarts.
//! - The home relay is the owner's, and is never given up.
//!
//! No relay can hold a slot past those bounds by asking it to wait. A random or anchor slot that is
//! asked to wait longer than what remains of its bound (a `Goodbye` or a refused handshake with a
//! long `retry_after_secs`, whatever its reason) takes it as "leave me": the relay is avoided for
//! its wait and the slot moves on. Every wait between dials is cut to what remains of the bound,
//! and the bound is checked again after it. The home relay is never given up, so the longest it is
//! waited for is a day (`HOME_WAITS_AT_MOST`), whatever it asks. A slot with nothing to pick looks
//! again within `NOTHING_TO_PICK_AT_MOST`, so relays learned meanwhile are not missed.
//!
//! When the anchor was last reached is a wall-clock time, and a clock before `PLAUSIBLE_SINCE_MS`
//! (a board with no real-time clock, booted before it has the time) is not one: no time is saved
//! while the clock reads earlier than that, and a saved time earlier than that or later than now
//! is read as unknown, so the anchor's count starts again at this run rather than at 1970.
//!
//! A session ends when the relay stops reading (a send waits at most `noise::WRITE_TIMEOUT`) and
//! when the reader fails (closed, or silent for `READ_TIMEOUT`), even while a send is pending.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
/// How long a session must stay up to count as having worked, so a later failure is retried soon.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);
/// How long a random slot's relay may be continuously unreachable before the slot picks another.
const RANDOM_GIVES_UP: Duration = Duration::from_secs(3_600);
/// How long the anchor may be continuously unreachable before a new anchor is chosen.
const ANCHOR_GIVES_UP: Duration = Duration::from_secs(7 * 24 * 3_600);
/// The longest the home relay is waited for between dials, whatever it asks: it is never given up,
/// so a relay asking for years would otherwise stop the slot for years.
const HOME_WAITS_AT_MOST: Duration = Duration::from_secs(24 * 3_600);
/// How long a slot with no relay to pick waits before looking again, at least.
const NOTHING_TO_PICK: Duration = Duration::from_secs(60);
/// And at most, before jitter, however long the relays it could pick asked to be left: relays
/// learned meanwhile by other slots are then picked up within it.
const NOTHING_TO_PICK_AT_MOST: Duration = Duration::from_secs(3_600);
/// 2026-01-01T00:00:00Z in wall-clock milliseconds. A wall clock earlier than this is wrong (this
/// code did not exist then), as on a board with no real-time clock before it has the time; a time
/// the anchor was reached is neither saved from such a clock nor believed if it is earlier.
pub const PLAUSIBLE_SINCE_MS: u64 = 1_767_225_600_000;
/// The most relays kept from any one source's hints. A relay's own list weighs no more than this,
/// however long it is.
const HINTS_PER_SOURCE: usize = 32;
/// The most learned relays kept in all; past it the oldest learned is forgotten first.
const HINTS_IN_ALL: usize = 512;
/// The state file of learned relays is written at most this often.
const SAVE_EVERY: Duration = Duration::from_secs(60);
/// How often a session says how many batches it did not send.
const REPORT_EVERY: Duration = Duration::from_secs(600);
/// How often a session re-signs and re-sends the receiver's description, so a relay that forgot it
/// (a restart, memory pressure) has it back within this long, not at the next change of relays.
const INFO_EVERY: Duration = Duration::from_secs(600);
/// The least burst a relay's rate limit is given: the largest record one message carries, so a
/// batch always fits, however small a burst the relay asked for.
const BURST_FLOOR: u32 = noise::MAX_PLAINTEXT as u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Home,
    Anchor,
    Random,
}

/// Where the feeder heard of a relay. A random slot first chooses a source, then a relay within
/// it, so no one relay's hints outweigh the owner's list, the seeds, or another relay's hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// The owner named it (`--relay`).
    Configured,
    /// Shipped in the binary.
    Seed,
    /// Hinted by this relay (`RelayList`, `Redirect`).
    Learned(PublicKey),
    /// Read from a state file written before sources were kept: learned, from whom unknown.
    Cached,
}

impl Source {
    fn is_learned(self) -> bool {
        matches!(self, Self::Learned(_) | Self::Cached)
    }
}

struct Known {
    relay: RelayAddress,
    source: Source,
}

/// What the feeder knows of relays, oldest first, and which each slot holds.
struct Relays {
    known: Vec<Known>,
    in_use: Vec<Option<RelayAddress>>,
    /// Relays that said "leave me", and until when no slot may pick them. Shared by every slot, so
    /// a relay one slot left is not picked straight back by another.
    avoided: HashMap<PublicKey, tokio::time::Instant>,
    /// Learned relays changed since the state file was last written.
    changed: bool,
}

impl Relays {
    /// Adds a relay not yet known, then forgets the oldest learned ones past the caps. False if
    /// its key was already known.
    fn add(&mut self, relay: RelayAddress, source: Source) -> bool {
        if self.known.iter().any(|known| known.relay.key == relay.key) {
            return false;
        }
        self.known.push(Known { relay, source });
        if source.is_learned() {
            if self.count(|each| each == source) > HINTS_PER_SOURCE {
                self.forget_oldest(|each| each == source);
            }
            if self.count(Source::is_learned) > HINTS_IN_ALL {
                self.forget_oldest(Source::is_learned);
            }
        }
        true
    }

    fn count(&self, which: impl Fn(Source) -> bool) -> usize {
        self.known
            .iter()
            .filter(|known| which(known.source))
            .count()
    }

    fn forget_oldest(&mut self, which: impl Fn(Source) -> bool) {
        if let Some(at) = self.known.iter().position(|known| which(known.source)) {
            self.known.remove(at);
        }
    }

    fn held(&self) -> Vec<PublicKey> {
        self.in_use
            .iter()
            .flatten()
            .map(|relay| relay.key)
            .collect()
    }

    /// A known relay no slot holds, on a host no slot holds, that has not asked to be left and is
    /// not `except`: a source chosen uniformly among the sources with such a relay, then one of its
    /// relays. `random(n)` is below `n`.
    fn choose(
        &mut self,
        now: tokio::time::Instant,
        except: Option<PublicKey>,
        mut random: impl FnMut(usize) -> usize,
    ) -> Option<RelayAddress> {
        self.avoided.retain(|_, until| *until > now);
        let keys: HashSet<PublicKey> = self.in_use.iter().flatten().map(|r| r.key).collect();
        let hosts: HashSet<String> = self.in_use.iter().flatten().map(host).collect();
        let mut sources: Vec<(Source, Vec<&RelayAddress>)> = Vec::new();
        for known in &self.known {
            if keys.contains(&known.relay.key)
                || hosts.contains(&host(&known.relay))
                || self.avoided.contains_key(&known.relay.key)
                || except == Some(known.relay.key)
            {
                continue;
            }
            match sources
                .iter_mut()
                .find(|(source, _)| *source == known.source)
            {
                Some((_, relays)) => relays.push(&known.relay),
                None => sources.push((known.source, vec![&known.relay])),
            }
        }
        if sources.is_empty() {
            return None;
        }
        let (_, relays) = sources.get(random(sources.len()))?;
        relays
            .get(random(relays.len()))
            .map(|relay| (*relay).clone())
    }

    /// The learned relays as the state file keeps them, oldest first: `HOST:PORT=KEY from KEY`, or
    /// the bare `HOST:PORT=KEY` of a relay learned from a relay not recorded.
    fn state(&self) -> String {
        let mut text = String::new();
        for known in &self.known {
            let line = format!("{}={}", known.relay.address, known.relay.key);
            match known.source {
                Source::Learned(from) => text.push_str(&format!("{line} from {from}\n")),
                Source::Cached => text.push_str(&format!("{line}\n")),
                Source::Configured | Source::Seed => {}
            }
        }
        text
    }
}

/// The part of `host:port` that names the machine, so two relays on one machine are one network.
/// Without DNS it is as near as the feeder can get to the RFC's "distinct networks".
fn host(relay: &RelayAddress) -> String {
    relay
        .address
        .rsplit_once(':')
        .map_or(relay.address.as_str(), |(host, _)| host)
        .to_ascii_lowercase()
}

/// Whether two relays are on one machine.
pub fn same_host(one: &RelayAddress, other: &RelayAddress) -> bool {
    host(one) == host(other)
}

/// A number below `n`, for choosing among relays.
fn random_below(n: usize) -> usize {
    let mut bytes = [0; 8];
    let _ = getrandom::getrandom(&mut bytes);
    let n = u64::try_from(n).unwrap_or(u64::MAX).max(1);
    usize::try_from(u64::from_be_bytes(bytes) % n).unwrap_or(0)
}

/// What the feeder knows of relays, which it is using, and what it says about itself.
pub struct Directory {
    state_dir: PathBuf,
    relays: Mutex<Relays>,
    identity: Identity,
    location: Option<Location>,
    clock: Clock,
    info: watch::Sender<Arc<Record>>,
}

impl Directory {
    pub fn new(
        state_dir: PathBuf,
        configured: Vec<RelayAddress>,
        seeds: Vec<RelayAddress>,
        slots: usize,
        identity: Identity,
        location: Option<Location>,
        clock: Clock,
    ) -> Result<Arc<Self>, String> {
        let mut relays = Relays {
            known: Vec::new(),
            in_use: vec![None; slots],
            avoided: HashMap::new(),
            changed: false,
        };
        for relay in configured {
            relays.add(relay, Source::Configured);
        }
        for relay in seeds {
            relays.add(relay, Source::Seed);
        }
        for (relay, source) in read_relays(&state_dir.join("relays")) {
            relays.add(relay, source);
        }
        let info = sign_info(&identity, location, clock, &[])?;
        Ok(Arc::new(Self {
            state_dir,
            relays: Mutex::new(relays),
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
        crate::config::parse_relay(text.lines().next()?.trim()).ok()
    }

    /// How long the saved anchor, if it is `relay`, has been unreachable: since the wall-clock time
    /// saved beside it. Zero for another relay, for a file from a build that saved no time
    /// (`HOST:PORT=KEY` alone), and for a time that cannot be right (before `PLAUSIBLE_SINCE_MS`,
    /// or after now, as when this run's clock is not yet set), whose count starts again at this run.
    pub fn anchor_unreached_for(&self, relay: &RelayAddress) -> Duration {
        self.anchor_unreached_at(relay, wall_ms())
    }

    /// As `anchor_unreached_for`, with the wall clock reading `now_ms`.
    fn anchor_unreached_at(&self, relay: &RelayAddress, now_ms: u64) -> Duration {
        let Ok(text) = std::fs::read_to_string(self.state_dir.join("anchor")) else {
            return Duration::ZERO;
        };
        let mut lines = text.lines();
        let saved = lines
            .next()
            .and_then(|line| crate::config::parse_relay(line.trim()).ok());
        if saved.is_none_or(|saved| saved.key != relay.key) {
            return Duration::ZERO;
        }
        lines
            .find_map(|line| {
                line.trim()
                    .strip_prefix("reached ")?
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .filter(|reached| (PLAUSIBLE_SINCE_MS..=now_ms).contains(reached))
            .map_or(Duration::ZERO, |reached| {
                Duration::from_millis(now_ms - reached)
            })
    }

    /// Saves `relay` as the anchor, last reached (or chosen) `unreached_for` ago:
    /// `HOST:PORT=KEY`, then `reached MS`, the wall-clock milliseconds of that time. With no
    /// plausible time (the clock, or that time, before `PLAUSIBLE_SINCE_MS`) only the relay is saved,
    /// and a later run counts from its own start.
    pub fn save_anchor(&self, relay: &RelayAddress, unreached_for: Duration) {
        self.save_anchor_at(relay, unreached_for, wall_ms());
    }

    /// The anchor was reached just now. With a plausible clock that time is saved; without one,
    /// any older time the file held is wrong now, so only the relay is saved and a later run counts
    /// from its own start.
    pub fn anchor_reached_now(&self, relay: &RelayAddress) {
        self.anchor_reached_at(relay, wall_ms());
    }

    fn anchor_reached_at(&self, relay: &RelayAddress, now_ms: u64) {
        let named = format!("{}={}\n", relay.address, relay.key);
        if now_ms < PLAUSIBLE_SINCE_MS {
            self.write_state("anchor", &named);
        } else {
            self.write_state("anchor", &format!("{named}reached {now_ms}\n"));
        }
    }

    /// As `save_anchor`, with the wall clock reading `now_ms`. This is the save when a slot takes an
    /// anchor, whose reach is unknown yet: with no plausible time, a file that already names this
    /// relay keeps what it knew.
    fn save_anchor_at(&self, relay: &RelayAddress, unreached_for: Duration, now_ms: u64) {
        let lost = u64::try_from(unreached_for.as_millis()).unwrap_or(u64::MAX);
        let reached = now_ms.saturating_sub(lost);
        let named = format!("{}={}\n", relay.address, relay.key);
        if reached < PLAUSIBLE_SINCE_MS {
            // The clock cannot say when it was last reached. If the file already names this relay,
            // it already says so, from a run whose clock could: keep it rather than erase it.
            let path = self.state_dir.join("anchor");
            if std::fs::read_to_string(path).is_ok_and(|saved| saved.starts_with(&named)) {
                return;
            }
            self.write_state("anchor", &named);
            return;
        }
        self.write_state("anchor", &format!("{named}reached {reached}\n"));
    }

    /// Adds relays that relay `from` offered. They are hints: they only widen what random slots
    /// pick from, and at most `HINTS_PER_SOURCE` of them count, its newest.
    pub fn learn(&self, from: PublicKey, offered: &[RelayAddress]) {
        let Ok(mut relays) = self.relays.lock() else {
            return;
        };
        let mut added = 0;
        for relay in offered {
            if added == HINTS_PER_SOURCE {
                break;
            }
            if relay.address.rsplit_once(':').is_some()
                && relays.add(relay.clone(), Source::Learned(from))
            {
                added += 1;
            }
        }
        if added > 0 {
            relays.changed = true;
        }
    }

    /// Writes the learned relays if they changed since the last write.
    pub fn save(&self) {
        let text = {
            let Ok(mut relays) = self.relays.lock() else {
                return;
            };
            if !relays.changed {
                return;
            }
            relays.changed = false;
            relays.state()
        };
        self.write_state("relays", &text);
    }

    /// Picks a random known relay for `slot` and holds it there, in one step, so two slots never
    /// pick the same relay or two relays on one host.
    pub fn claim(&self, slot: usize) -> Option<RelayAddress> {
        self.pick(slot, None)
    }

    /// As `claim`, for a slot giving up `current`: picks any relay but `current`, and if there is
    /// none, the slot keeps holding `current`.
    pub fn replace(&self, slot: usize, current: &RelayAddress) -> Option<RelayAddress> {
        self.pick(slot, Some(current))
    }

    fn pick(&self, slot: usize, except: Option<&RelayAddress>) -> Option<RelayAddress> {
        let mut relays = self.relays.lock().ok()?;
        let kept = relays.in_use.get_mut(slot).and_then(Option::take);
        let relay = relays.choose(
            tokio::time::Instant::now(),
            except.map(|relay| relay.key),
            random_below,
        );
        let held = match (&relay, except) {
            (None, Some(_)) => kept,
            _ => relay.clone(),
        };
        if let Some(slot) = relays.in_use.get_mut(slot) {
            *slot = held;
        }
        self.announce(&relays, true);
        relay
    }

    /// Records which relay a slot holds, and re-signs the receiver's description to say so.
    pub fn hold(&self, slot: usize, relay: Option<&RelayAddress>) {
        let Ok(mut relays) = self.relays.lock() else {
            return;
        };
        if let Some(held) = relays.in_use.get_mut(slot) {
            *held = relay.cloned();
        }
        self.announce(&relays, true);
    }

    /// Keeps every slot off `relay` for `wait`, or the backoff's first wait if that is longer; a
    /// longer wait already asked for stays.
    pub fn avoid(&self, relay: &PublicKey, wait: Duration) {
        let Ok(mut relays) = self.relays.lock() else {
            return;
        };
        let until = tokio::time::Instant::now() + wait.max(Backoff::FIRST);
        let entry = relays.avoided.entry(*relay).or_insert(until);
        *entry = (*entry).max(until);
    }

    /// How long until the soonest avoided relay may be picked again, if any is avoided.
    pub fn avoided_for(&self) -> Option<Duration> {
        let relays = self.relays.lock().ok()?;
        let now = tokio::time::Instant::now();
        relays
            .avoided
            .values()
            .filter(|until| **until > now)
            .map(|until| *until - now)
            .min()
    }

    /// The receiver's description signed afresh, with a new `issued_ms` and the relays held now.
    /// It is kept as the latest without waking the sessions, each of which re-sends on its own
    /// schedule.
    pub fn resign(&self) -> Option<Arc<Record>> {
        let relays = self.relays.lock().ok()?;
        self.announce(&relays, false)
    }

    /// Signs the receiver's description for the relays held now and makes it the latest. It runs
    /// under the relays lock, so the latest is always the newest signed and names what is held.
    fn announce(&self, relays: &Relays, wake: bool) -> Option<Arc<Record>> {
        match sign_info(&self.identity, self.location, self.clock, &relays.held()) {
            Ok(info) => {
                let record = Arc::new(Record::ReceiverInfo(info));
                let latest = Arc::clone(&record);
                self.info.send_if_modified(move |info| {
                    *info = latest;
                    wake
                });
                Some(record)
            }
            Err(error) => {
                eprintln!("tally-feed: signing receiver info: {error}");
                None
            }
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

    #[cfg(test)]
    fn known(&self) -> Vec<(RelayAddress, Source)> {
        self.relays.lock().map_or_else(
            |_| Vec::new(),
            |relays| {
                relays
                    .known
                    .iter()
                    .map(|known| (known.relay.clone(), known.source))
                    .collect()
            },
        )
    }
}

/// Saves what the feeder learns, at most once a minute, for as long as it runs.
pub async fn keep_saved(directory: Arc<Directory>) {
    let mut every = tokio::time::interval(SAVE_EVERY);
    loop {
        every.tick().await;
        directory.save();
    }
}

fn read_relays(path: &std::path::Path) -> Vec<(RelayAddress, Source)> {
    std::fs::read_to_string(path)
        .map(|text| text.lines().filter_map(read_relay).collect())
        .unwrap_or_default()
}

fn read_relay(line: &str) -> Option<(RelayAddress, Source)> {
    let line = line.trim();
    match line.split_once(" from ") {
        Some((relay, from)) => Some((
            crate::config::parse_relay(relay.trim()).ok()?,
            Source::Learned(PublicKey::from_base64(from.trim()).ok()?),
        )),
        None => Some((crate::config::parse_relay(line).ok()?, Source::Cached)),
    }
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

/// When a slot's relay was last reached. A session marks it at `Welcome` and again every
/// `INFO_EVERY` it stays up; after each session the slot asks how long it has been since, to decide
/// whether to give the relay up. The anchor's is saved beside it at each mark, so a restart does not
/// start its count again.
#[derive(Clone)]
pub struct Reach {
    unreached: Arc<Mutex<Unreached>>,
    anchor: Option<(Arc<Directory>, RelayAddress)>,
}

struct Unreached {
    since: tokio::time::Instant,
    /// Unreachable time carried in from before `since`: the anchor's, from an earlier run.
    before: Duration,
}

impl Reach {
    fn new(before: Duration, anchor: Option<(Arc<Directory>, RelayAddress)>) -> Self {
        Self {
            unreached: Arc::new(Mutex::new(Unreached {
                since: tokio::time::Instant::now(),
                before,
            })),
            anchor,
        }
    }

    /// The relay was reached now.
    pub fn mark(&self) {
        if let Ok(mut unreached) = self.unreached.lock() {
            unreached.since = tokio::time::Instant::now();
            unreached.before = Duration::ZERO;
        }
        if let Some((directory, relay)) = &self.anchor {
            directory.anchor_reached_now(relay);
        }
    }

    fn unreached_for(&self) -> Duration {
        self.unreached.lock().map_or(Duration::ZERO, |unreached| {
            unreached.before + unreached.since.elapsed()
        })
    }
}

/// How long a slot's relay may be continuously unreachable before the slot gives it up; never, for
/// the owner's home relay.
fn gives_up_after(kind: SlotKind) -> Option<Duration> {
    match kind {
        SlotKind::Home => None,
        SlotKind::Anchor => Some(ANCHOR_GIVES_UP),
        SlotKind::Random => Some(RANDOM_GIVES_UP),
    }
}

/// One slot of the relay set, for as long as the feeder runs.
pub async fn slot(
    index: usize,
    kind: SlotKind,
    relay: Option<RelayAddress>,
    directory: Arc<Directory>,
    identity: Identity,
    batches: broadcast::Sender<Arc<Record>>,
    ceiling: u32,
) {
    let sessions = Arc::clone(&directory);
    let dial = move |current: RelayAddress, reach: Reach| {
        let identity = identity.clone();
        let directory = Arc::clone(&sessions);
        let batches = batches.subscribe();
        async move { session(&current, &identity, &directory, batches, ceiling, &reach).await }
    };
    run_slot(index, kind, relay, &directory, dial).await;
}

/// The slot's rules, apart from how a session with a relay runs.
async fn run_slot<F, S>(
    index: usize,
    kind: SlotKind,
    mut relay: Option<RelayAddress>,
    directory: &Arc<Directory>,
    mut dial: F,
) where
    F: FnMut(RelayAddress, Reach) -> S,
    S: Future<Output = Result<Outcome, String>>,
{
    let mut backoff = Backoff::new();
    // The relay the slot is on and when it was last reached, kept until the slot moves.
    let mut on: Option<(PublicKey, Reach)> = None;
    loop {
        let current = match relay.clone() {
            Some(current) => {
                directory.hold(index, Some(&current));
                current
            }
            None => match directory.claim(index) {
                Some(current) => current,
                None => {
                    // Nothing to pick, perhaps because every relay asked to be left: wait until
                    // the soonest of those may be picked again, never less than a minute, and
                    // never more than an hour, so a relay learned meanwhile is not missed.
                    let left = directory.avoided_for().unwrap_or_default();
                    let wait = left.clamp(NOTHING_TO_PICK, NOTHING_TO_PICK_AT_MOST);
                    tokio::time::sleep(jittered(wait)).await;
                    continue;
                }
            },
        };
        relay = Some(current.clone());
        let reach = match &on {
            Some((key, reach)) if *key == current.key => reach.clone(),
            _ => {
                let reach = if kind == SlotKind::Anchor {
                    // The saved anchor carries its unreachable time over from the last run; a new
                    // one starts at zero. Either way the file now names it.
                    let before = directory.anchor_unreached_for(&current);
                    directory.save_anchor(&current, before);
                    Reach::new(before, Some((Arc::clone(directory), current.clone())))
                } else {
                    Reach::new(Duration::ZERO, None)
                };
                on = Some((current.key, reach.clone()));
                reach
            }
        };
        let started = tokio::time::Instant::now();
        let outcome = dial(current.clone(), reach.clone()).await;
        // A session that stayed up was a success: the next wait starts from the shortest again,
        // as it would for a first try, and only a relay's own retry_after lengthens it.
        if started.elapsed() >= HEALTHY_SESSION {
            backoff.reset();
        }
        let bound = gives_up_after(kind);
        let outcome = match outcome {
            // A slot that would give its relay up is not held past that by a relay asking it to
            // wait: a wait longer than what remains of the bound is "leave me".
            Ok(Outcome::Retry(wait))
                if bound
                    .is_some_and(|bound| wait > bound.saturating_sub(reach.unreached_for())) =>
            {
                Ok(Outcome::Leave(wait))
            }
            outcome => outcome,
        };
        match outcome {
            // What remains is honoured, as the home relay's is up to a day; the sleep is cut below.
            Ok(Outcome::Retry(wait)) => backoff.at_least(wait),
            Ok(Outcome::Leave(wait)) => {
                directory.avoid(&current.key, wait);
                // Only the owner's home relay is kept through a "leave me", and waited for; an
                // anchor that retires is replaced, and the new one saved. A slot moves to another
                // relay at once, since the one it left is avoided for as long as it asked.
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
        if let Some(next) = give_up(index, kind, &current, &reach, directory) {
            relay = Some(next);
            backoff.reset();
            continue;
        }
        // The wait is cut to what remains of the bound, and the bound checked again after it; once
        // past the bound with no other relay to pick, the slot keeps retrying at the backoff's pace.
        let wait = backoff.wait();
        let wait = match bound.map(|bound| bound.saturating_sub(reach.unreached_for())) {
            Some(left) if !left.is_zero() => wait.min(left),
            Some(_) => wait,
            None => wait.min(HOME_WAITS_AT_MOST),
        };
        tokio::time::sleep(wait).await;
        if let Some(next) = give_up(index, kind, &current, &reach, directory) {
            relay = Some(next);
            backoff.reset();
        }
    }
}

/// Gives up `current` for another relay if it has been unreachable past its slot's bound and there
/// is another to pick; with none, the slot keeps it.
fn give_up(
    index: usize,
    kind: SlotKind,
    current: &RelayAddress,
    reach: &Reach,
    directory: &Directory,
) -> Option<RelayAddress> {
    let unreached = reach.unreached_for();
    if gives_up_after(kind).is_none_or(|bound| unreached < bound) {
        return None;
    }
    let next = directory.replace(index, current)?;
    eprintln!(
        "tally-feed: relay {} unreachable for {} minutes; trying {} instead",
        current.address,
        unreached.as_secs() / 60,
        next.address
    );
    Some(next)
}

async fn session(
    relay: &RelayAddress,
    identity: &Identity,
    directory: &Directory,
    mut batches: broadcast::Receiver<Arc<Record>>,
    ceiling: u32,
    reach: &Reach,
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
    reach.mark();
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
    let result = publish(
        relay,
        &mut writer,
        &mut records,
        &mut batches,
        directory,
        ceiling,
        reach,
    )
    .await;
    reading.abort();
    result
}

/// How much one relay session sends of what the batcher sealed. The owner's ceiling is kept once,
/// by the batcher, so a relay that asked nothing gets every batch. A relay that asked for less than
/// the ceiling gets a bucket at its rate, deep enough that a whole batch always fits; the batches
/// over it are skipped for that relay alone, and their sequence numbers say so.
struct Pace {
    ceiling: u32,
    bucket: Option<TokenBucket>,
    skipped: u64,
}

impl Pace {
    fn new(ceiling: u32) -> Self {
        Self {
            ceiling,
            bucket: None,
            skipped: 0,
        }
    }

    /// A relay's `RateLimit`. One at or over the owner's ceiling asks for nothing the batcher
    /// does not already keep to.
    fn limit(&mut self, bytes_per_sec: u32, burst: u32) {
        self.bucket = (bytes_per_sec < self.ceiling)
            .then(|| TokenBucket::with_burst(bytes_per_sec, burst.max(BURST_FLOOR)));
    }

    /// True if a batch of `bytes` goes to this relay now; counted as skipped if not.
    fn admit(&mut self, bytes: usize, now: Instant) -> bool {
        let admitted = self
            .bucket
            .as_mut()
            .is_none_or(|bucket| bucket.take_at(bytes, now));
        if !admitted {
            self.skipped += 1;
        }
        admitted
    }
}

/// One session's sending half, with what the relay says while it sends. Every send is raced against
/// the reader, so a reader that fails (closed, silent too long) or a relay that says goodbye ends
/// the session at once, even while a send waits on a relay that stopped reading. A send cut short
/// leaves the writer mid-frame, which is why the session then ends.
struct Link<'a, S> {
    relay: &'a RelayAddress,
    writer: &'a mut noise::Writer<S>,
    records: &'a mut mpsc::Receiver<Result<Vec<Record>, String>>,
    directory: &'a Directory,
    pace: Pace,
}

impl<S: tokio::io::AsyncWrite> Link<'_, S> {
    /// Sends the records; `Some` if the relay ended the session before the send was done.
    async fn send<R>(&mut self, out: &[R]) -> Result<Option<Outcome>, String>
    where
        R: std::borrow::Borrow<Record> + Sync,
    {
        let sending = self.writer.send(out);
        tokio::pin!(sending);
        loop {
            tokio::select! {
                sent = &mut sending => return sent.map(|()| None).map_err(|error| error.to_string()),
                got = self.records.recv() => {
                    if let Some(outcome) = heard(self.relay, self.directory, &mut self.pace, got)? {
                        return Ok(Some(outcome));
                    }
                }
            }
        }
    }
}

/// Acts on what the reader passed on; `Some` if the relay ended the session, an error if the
/// reader failed or ended.
fn heard(
    relay: &RelayAddress,
    directory: &Directory,
    pace: &mut Pace,
    got: Option<Result<Vec<Record>, String>>,
) -> Result<Option<Outcome>, String> {
    let got = got.ok_or_else(|| "reader ended".to_owned())??;
    for record in got {
        match record {
            Record::RelayList(relays) => directory.learn(relay.key, &relays),
            Record::RateLimit {
                bytes_per_sec,
                burst,
            } => pace.limit(bytes_per_sec, burst),
            Record::Redirect {
                retry_after_secs,
                hints,
            } => {
                directory.learn(relay.key, &hints);
                return Ok(Some(Outcome::Leave(Duration::from_secs(
                    retry_after_secs.into(),
                ))));
            }
            Record::Goodbye {
                reason,
                retry_after_secs,
            } => return Ok(Some(goodbye(reason, retry_after_secs))),
            _ => {}
        }
    }
    Ok(None)
}

async fn publish<S: tokio::io::AsyncWrite>(
    relay: &RelayAddress,
    writer: &mut noise::Writer<S>,
    records: &mut mpsc::Receiver<Result<Vec<Record>, String>>,
    batches: &mut broadcast::Receiver<Arc<Record>>,
    directory: &Directory,
    ceiling: u32,
    reach: &Reach,
) -> Result<Outcome, String> {
    let mut link = Link {
        relay,
        writer,
        records,
        directory,
        pace: Pace::new(ceiling),
    };
    let mut info = directory.info();
    let first = Arc::clone(&info.borrow_and_update());
    if let Some(outcome) = link.send(&[first]).await? {
        return Ok(outcome);
    }
    let mut lagged = 0u64;
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    let mut report =
        tokio::time::interval_at(tokio::time::Instant::now() + REPORT_EVERY, REPORT_EVERY);
    let mut refresh =
        tokio::time::interval_at(tokio::time::Instant::now() + INFO_EVERY, INFO_EVERY);
    loop {
        let ended = tokio::select! {
            batch = batches.recv() => match batch {
                Ok(batch) => {
                    let Record::Batch(signed) = &*batch else { continue };
                    if link.pace.admit(signed.as_bytes().len(), Instant::now()) {
                        link.send(&[batch]).await?
                    } else {
                        None
                    }
                }
                // Batches this session could not keep up with are gone; gaps say so.
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    lagged += count;
                    None
                }
                Err(broadcast::error::RecvError::Closed) => return Err("source ended".to_owned()),
            },
            changed = info.changed() => {
                if changed.is_ok() {
                    let latest = Arc::clone(&info.borrow_and_update());
                    link.send(&[latest]).await?
                } else {
                    None
                }
            }
            _ = heartbeat.tick() => link.send(&[Record::Heartbeat]).await?,
            _ = refresh.tick() => {
                // Still up, so still reached.
                reach.mark();
                match directory.resign() {
                    Some(fresh) => link.send(&[fresh]).await?,
                    None => None,
                }
            }
            _ = report.tick() => {
                if link.pace.skipped > 0 || lagged > 0 {
                    eprintln!(
                        "tally-feed: relay {}: {} batches over its rate limit and {lagged} it was \
                         too slow for were not sent to it",
                        relay.address, link.pace.skipped
                    );
                    link.pace.skipped = 0;
                    lagged = 0;
                }
                None
            }
            got = link.records.recv() => heard(relay, directory, &mut link.pace, got)?,
        };
        if let Some(outcome) = ended {
            return Ok(outcome);
        }
    }
}

/// `wait` with the backoff's jitter, so feeders a relay sent away together do not return together.
fn jittered(wait: Duration) -> Duration {
    let mut backoff = Backoff::new();
    backoff.at_least(wait);
    backoff.wait()
}

fn goodbye(reason: Reason, retry_after_secs: u32) -> Outcome {
    let wait = Duration::from_secs(retry_after_secs.into());
    match reason {
        Reason::Leaving | Reason::Refused => Outcome::Leave(wait),
        _ => Outcome::Retry(wait),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Batcher;

    fn key() -> Result<PublicKey, String> {
        Ok(Identity::generate()
            .map_err(|error| error.to_string())?
            .public())
    }

    fn relay(address: &str) -> Result<RelayAddress, String> {
        Ok(RelayAddress {
            key: key()?,
            address: address.to_owned(),
        })
    }

    fn relays(prefix: &str, count: usize) -> Result<Vec<RelayAddress>, String> {
        (0..count)
            .map(|at| relay(&format!("{prefix}-{at}.example:10900")))
            .collect()
    }

    fn scratch() -> PathBuf {
        let base = std::env::var_os("TEST_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        base.join(format!("tally-feed-{:016x}", random_below(usize::MAX)))
    }

    fn directory_at(
        state_dir: PathBuf,
        configured: Vec<RelayAddress>,
        slots: usize,
    ) -> Result<Arc<Directory>, String> {
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        Directory::new(
            state_dir,
            configured,
            Vec::new(),
            slots,
            identity,
            None,
            Clock::Dump1090,
        )
    }

    fn from(directory: &Directory, source: Source) -> Vec<RelayAddress> {
        directory
            .known()
            .into_iter()
            .filter(|(_, each)| *each == source)
            .map(|(relay, _)| relay)
            .collect()
    }

    #[test]
    fn one_relays_hints_are_capped_and_all_hints_are_capped() -> Result<(), String> {
        let directory = directory_at(scratch(), relays("owner", 2)?, 4)?;
        let flooder = key()?;
        let flood = relays("flood", 1_000)?;
        directory.learn(flooder, &flood);
        directory.learn(flooder, &flood[500..]);
        let kept = from(&directory, Source::Learned(flooder));
        assert_eq!(kept.len(), HINTS_PER_SOURCE);
        // A second list from the same relay replaces its oldest, never adds to its share.
        assert_eq!(kept.first(), flood.get(500));
        let mut first = None;
        for _ in 0..40 {
            let hinter = key()?;
            first.get_or_insert(hinter);
            directory.learn(hinter, &relays("many", HINTS_PER_SOURCE)?);
        }
        let known = directory.known();
        let learned = known.iter().filter(|(_, source)| source.is_learned());
        assert_eq!(learned.count(), HINTS_IN_ALL);
        assert_eq!(from(&directory, Source::Configured).len(), 2);
        // The oldest learned went first: the flooder's, then the first hinter's.
        assert!(from(&directory, Source::Learned(flooder)).is_empty());
        let first = first.ok_or("no hinter")?;
        assert!(from(&directory, Source::Learned(first)).is_empty());
        Ok(())
    }

    #[test]
    fn a_random_slot_weighs_each_source_as_one() -> Result<(), String> {
        let owner = relay("owner.example:10900")?;
        let directory = directory_at(scratch(), vec![owner.clone()], 1)?;
        directory.learn(key()?, &relays("hinted", HINTS_PER_SOURCE)?);
        let trials = 4_000;
        let mut owners = 0;
        for _ in 0..trials {
            if directory.claim(0).as_ref() == Some(&owner) {
                owners += 1;
            }
        }
        // Uniform over relays would pick the owner's 1 time in 33; by source it is 1 in 2.
        assert!((1_600..=2_400).contains(&owners), "{owners} of {trials}");
        Ok(())
    }

    #[test]
    fn no_two_slots_hold_relays_on_one_host() -> Result<(), String> {
        let one = relay("Relay.Example:10900")?;
        let two = relay("relay.example:10901")?;
        let other = relay("other.example:10900")?;
        let directory = directory_at(scratch(), vec![one, two], 3)?;
        assert!(directory.claim(0).is_some());
        assert!(directory.claim(1).is_none(), "a second relay on one host");
        directory.learn(key()?, std::slice::from_ref(&other));
        assert_eq!(directory.claim(1), Some(other));
        assert!(directory.claim(2).is_none());
        // A held relay's host stays out of reach too.
        let fresh = directory_at(scratch(), vec![relay("home.example:1")?], 2)?;
        fresh.hold(0, Some(&relay("home.example:2")?));
        assert!(fresh.claim(1).is_none());
        Ok(())
    }

    #[test]
    fn learned_relays_are_saved_with_their_source() -> Result<(), String> {
        let state = scratch();
        let hinter = key()?;
        let hinted = relays("hinted", 3)?;
        let old = relay("old.example:10900")?;
        std::fs::create_dir_all(&state).map_err(|error| error.to_string())?;
        // The one-line format of an earlier build still reads, as learned from someone.
        std::fs::write(
            state.join("relays"),
            format!("{}={}\n", old.address, old.key),
        )
        .map_err(|error| error.to_string())?;
        let first = directory_at(state.clone(), relays("owner", 1)?, 4)?;
        first.learn(hinter, &hinted);
        first.save();
        let again = directory_at(state.clone(), Vec::new(), 4)?;
        assert_eq!(from(&again, Source::Learned(hinter)), hinted);
        assert_eq!(from(&again, Source::Cached), vec![old]);
        // The owner's relays come from the command line each run, never from the file.
        assert!(from(&again, Source::Configured).is_empty());
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    #[test]
    fn a_relay_that_asked_nothing_is_not_paced() {
        let mut pace = Pace::new(64_000);
        let now = Instant::now();
        assert!((0..100).all(|_| pace.admit(noise::MAX_PLAINTEXT, now)));
        // A relay asking for the ceiling or more asks for nothing.
        pace.limit(64_000, 0);
        assert!((0..100).all(|_| pace.admit(noise::MAX_PLAINTEXT, now)));
    }

    #[test]
    fn a_relay_that_asked_for_less_gets_fewer_batches_never_none() {
        let mut pace = Pace::new(64_000);
        pace.limit(16_000, 1_000);
        let start = Instant::now();
        let batch = 48 * 1024 + 4_000;
        let mut sent = Vec::new();
        for second in 0..600 {
            if pace.admit(batch, start + Duration::from_secs(second)) {
                sent.push(second);
            }
        }
        // About a third of a batch a second, and never a long silence.
        assert!((150..=250).contains(&sent.len()), "{} sent", sent.len());
        assert_eq!(pace.skipped, 600 - sent.len() as u64);
        assert!(sent.windows(2).all(|pair| pair[1] - pair[0] <= 5));
        assert_eq!(sent.first(), Some(&0));
    }

    /// Runs a slot whose every session ends with the relay saying "leave me, for `retry`", for
    /// `run` of paused time, and returns which relay it dialled and when.
    async fn dials_when_every_relay_redirects(
        kind: SlotKind,
        start: Option<RelayAddress>,
        directory: Arc<Directory>,
        retry: Duration,
        run: Duration,
    ) -> Vec<(PublicKey, Duration)> {
        let began = tokio::time::Instant::now();
        let log = Arc::new(Mutex::new(Vec::new()));
        let written = Arc::clone(&log);
        let slot = tokio::spawn(async move {
            let dial = move |relay: RelayAddress, _reach: Reach| {
                if let Ok(mut log) = written.lock() {
                    log.push((relay.key, began.elapsed()));
                }
                async move { Ok(Outcome::Leave(retry)) }
            };
            run_slot(0, kind, start, &directory, dial).await;
        });
        tokio::time::sleep(run).await;
        slot.abort();
        log.lock().map(|log| log.clone()).unwrap_or_default()
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_said_leave_is_not_dialled_again_until_its_retry_after()
    -> Result<(), String> {
        let only = relay("only.example:10900")?;
        let directory = directory_at(scratch(), vec![only.clone()], 1)?;
        let retry = Duration::from_secs(600);
        let dials = dials_when_every_relay_redirects(
            SlotKind::Random,
            None,
            directory,
            retry,
            Duration::from_secs(1_000),
        )
        .await;
        // Once at the start, then not before 600 s (and at most half again for jitter).
        assert_eq!(dials.len(), 2, "{dials:?}");
        assert!(dials.iter().all(|(key, _)| *key == only.key));
        let again = dials.get(1).map(|(_, at)| *at).ok_or("no second dial")?;
        assert!(
            again >= retry && again <= retry.mul_f64(1.5) + Duration::from_secs(1),
            "{again:?}"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn after_a_session_that_stayed_up_the_next_try_comes_soon() -> Result<(), String> {
        let only = relay("only.example:10900")?;
        let directory = directory_at(scratch(), vec![only], 1)?;
        let began = tokio::time::Instant::now();
        let log = Arc::new(Mutex::new(Vec::new()));
        let written = Arc::clone(&log);
        let slot = tokio::spawn(async move {
            let dial = move |_relay: RelayAddress, _reach: Reach| {
                let attempt = written.lock().map_or(0, |mut log| {
                    log.push(began.elapsed());
                    log.len()
                });
                async move {
                    // Six quick failures grow the wait; the seventh session stays up ten minutes.
                    if attempt == 7 {
                        tokio::time::sleep(Duration::from_secs(600)).await;
                    }
                    Err::<Outcome, String>("closed".to_owned())
                }
            };
            run_slot(0, SlotKind::Random, None, &directory, dial).await;
        });
        tokio::time::sleep(Duration::from_secs(1_200)).await;
        slot.abort();
        let dials = log.lock().map(|log| log.clone()).unwrap_or_default();
        let (long, next) = (
            dials.get(6).ok_or("no long session")?,
            dials.get(7).ok_or("no retry")?,
        );
        // The wait had grown past 30 s before the long session; after it, the next try is the
        // first wait again (1 s, up to half again of jitter), after the session's 600 s.
        let gap = *next - *long - Duration::from_secs(600);
        assert!(gap <= Duration::from_millis(1_500), "{gap:?} {dials:?}");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_slot_left_by_one_relay_moves_to_another_at_once() -> Result<(), String> {
        let one = relay("one.example:10900")?;
        let two = relay("two.example:10900")?;
        let directory = directory_at(scratch(), vec![one, two], 1)?;
        let retry = Duration::from_secs(600);
        let dials = dials_when_every_relay_redirects(
            SlotKind::Random,
            None,
            directory,
            retry,
            Duration::from_secs(500),
        )
        .await;
        // Both relays at once, then neither while both are avoided.
        assert_eq!(dials.len(), 2, "{dials:?}");
        let (first, second) = (dials.first().ok_or("none")?, dials.get(1).ok_or("one")?);
        assert_ne!(first.0, second.0);
        assert_eq!(first.1, second.1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_home_relay_is_kept_through_a_leave_and_waited_for() -> Result<(), String> {
        let home = relay("home.example:10900")?;
        let other = relay("other.example:10900")?;
        let directory = directory_at(scratch(), vec![other], 1)?;
        let retry = Duration::from_secs(600);
        let dials = dials_when_every_relay_redirects(
            SlotKind::Home,
            Some(home.clone()),
            directory,
            retry,
            Duration::from_secs(1_000),
        )
        .await;
        assert_eq!(dials.len(), 2, "{dials:?}");
        assert!(dials.iter().all(|(key, _)| *key == home.key));
        let again = dials.get(1).map(|(_, at)| *at).ok_or("no second dial")?;
        assert!(again >= retry, "{again:?}");
        Ok(())
    }

    #[test]
    fn an_avoided_relay_is_not_claimed_by_any_slot_until_its_wait_passes() -> Result<(), String> {
        let only = relay("only.example:10900")?;
        let directory = directory_at(scratch(), vec![only.clone()], 2)?;
        directory.avoid(&only.key, Duration::ZERO);
        // Even a relay that asked for no wait is avoided for the backoff's first.
        assert!(directory.claim(1).is_none());
        let left = directory.avoided_for().ok_or("not avoided")?;
        assert!(left > Duration::ZERO && left <= Backoff::FIRST);
        // A shorter wait asked later does not shorten a longer one.
        directory.avoid(&only.key, Duration::from_secs(600));
        directory.avoid(&only.key, Duration::from_secs(5));
        assert!(directory.avoided_for().ok_or("not avoided")? > Duration::from_secs(590));
        Ok(())
    }

    type Pipe = tokio::io::DuplexStream;

    /// A session over an in-memory pipe that buffers `buffer` bytes each way: the feeder's end, the
    /// relay's end, and the relay's key.
    async fn pipe(
        buffer: usize,
    ) -> Result<(noise::Session<Pipe>, noise::Session<Pipe>, PublicKey), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let feeder = Identity::generate().map_err(error)?;
        let relay_identity = Identity::generate().map_err(error)?;
        let relay_key = relay_identity.public();
        let (near, far) = tokio::io::duplex(buffer);
        let dial =
            tokio::spawn(
                async move { noise::connect(near, &feeder, &relay_key, Role::Feeder).await },
            );
        let accepted = noise::accept(far, &[relay_identity]).await.map_err(error)?;
        let session = dial
            .await
            .map_err(|error| error.to_string())?
            .map_err(error)?;
        Ok((session, accepted.session, relay_key))
    }

    /// A publishing session over an in-memory pipe, and the relay's end of it.
    async fn publishing(
        directory: Arc<Directory>,
    ) -> Result<
        (
            tokio::task::JoinHandle<Result<Outcome, String>>,
            noise::Reader<Pipe>,
            broadcast::Sender<Arc<Record>>,
            mpsc::Sender<Result<Vec<Record>, String>>,
        ),
        String,
    > {
        let (session, relay_end, relay_key) = pipe(1 << 20).await?;
        let (out, mut batches) = broadcast::channel(64);
        let (records_in, mut records) = mpsc::channel(16);
        let address = RelayAddress {
            key: relay_key,
            address: "relay.example:10900".to_owned(),
        };
        let mut writer = session.writer;
        let running = tokio::spawn(async move {
            publish(
                &address,
                &mut writer,
                &mut records,
                &mut batches,
                &directory,
                64_000,
                &Reach::new(Duration::ZERO, None),
            )
            .await
        });
        Ok((running, relay_end.reader, out, records_in))
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_re_sends_a_freshly_signed_receiver_info_every_ten_minutes()
    -> Result<(), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let directory = directory_at(scratch(), Vec::new(), 1)?;
        let (running, mut reader, _out, _records_in) = publishing(directory).await?;
        let began = tokio::time::Instant::now();
        let mut infos = Vec::new();
        while infos.len() < 3 {
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(700), reader.recv(&mut got))
                .await
                .map_err(|_| format!("only {} receiver infos arrived", infos.len()))?
                .map_err(error)?;
            for record in got {
                if let Record::ReceiverInfo(info) = record {
                    info.verify().map_err(error)?;
                    infos.push((began.elapsed(), info.content().map_err(error)?));
                }
            }
        }
        running.abort();
        let at: Vec<u64> = infos.iter().map(|(at, _)| at.as_secs()).collect();
        assert_eq!(at, vec![0, 600, 1_200]);
        let issued: Vec<u64> = infos.iter().map(|(_, content)| content.issued_ms).collect();
        assert!(
            issued.windows(2).all(|pair| pair[0] <= pair[1]),
            "{issued:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_feeder_at_its_ceiling_delivers_every_batch_to_a_relay_that_asked_nothing()
    -> Result<(), String> {
        let error = |error: tally_wire::WireError| error.to_string();
        let feeder = Identity::generate().map_err(error)?;
        let relay_identity = Identity::generate().map_err(error)?;
        let relay_key = relay_identity.public();
        let (near, far) = tokio::io::duplex(1 << 20);
        let dialler = feeder.clone();
        let dial =
            tokio::spawn(
                async move { noise::connect(near, &dialler, &relay_key, Role::Feeder).await },
            );
        let accepted = noise::accept(far, &[relay_identity]).await.map_err(error)?;
        let session = dial
            .await
            .map_err(|error| error.to_string())?
            .map_err(error)?;
        let directory = directory_at(scratch(), Vec::new(), 1)?;
        let (out, mut batches) = broadcast::channel(64);
        let (_records_in, mut records) = mpsc::channel(16);
        let address = RelayAddress {
            key: relay_key,
            address: "relay.example:10900".to_owned(),
        };
        let mut writer = session.writer;
        let publishing = tokio::spawn(async move {
            publish(
                &address,
                &mut writer,
                &mut records,
                &mut batches,
                &directory,
                64_000,
                &Reach::new(Duration::ZERO, None),
            )
            .await
        });
        // Batches as big as the batcher seals them, each near the whole second's ceiling.
        let mut batcher = Batcher::new(feeder, u32::MAX, Clock::Dump1090);
        let frame = |counter: u64| {
            tally_wire::Frame::new(tally_wire::FrameKind::ModeSLong, counter, 9, &[0x8d; 14])
                .map_err(|error| error.to_string())
        };
        let mut sent = 0;
        let mut counter = 1;
        while sent < 8 {
            batcher.observe(&frame(counter)?)?;
            counter += 1;
            if batcher.is_full() {
                let batch = batcher.seal()?.ok_or("no batch")?;
                assert!(batch.as_bytes().len() > 48 * 1024);
                let _ = out.send(Arc::new(Record::Batch(batch)));
                sent += 1;
            }
        }
        let mut reader = accepted.session.reader;
        let mut sequences = Vec::new();
        while sequences.len() < 8 {
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), reader.recv(&mut got))
                .await
                .map_err(|_| format!("only {} batches arrived", sequences.len()))?
                .map_err(error)?;
            for record in got {
                if let Record::Batch(batch) = record {
                    sequences.push(batch.sequence());
                }
            }
        }
        publishing.abort();
        assert_eq!(sequences, (0..8).collect::<Vec<u64>>());
        Ok(())
    }

    /// Runs a slot whose every session ends with `answer`, given the session's `Reach`, for `run`
    /// of paused time, and returns which relay it dialled and when.
    async fn dials(
        kind: SlotKind,
        start: Option<RelayAddress>,
        directory: Arc<Directory>,
        run: Duration,
        answer: fn(&Reach) -> Result<Outcome, String>,
    ) -> Vec<(PublicKey, Duration)> {
        let began = tokio::time::Instant::now();
        let log = Arc::new(Mutex::new(Vec::new()));
        let written = Arc::clone(&log);
        let slot = tokio::spawn(async move {
            let dial = move |relay: RelayAddress, reach: Reach| {
                if let Ok(mut log) = written.lock() {
                    log.push((relay.key, began.elapsed()));
                }
                let answered = answer(&reach);
                async move { answered }
            };
            run_slot(0, kind, start, &directory, dial).await;
        });
        tokio::time::sleep(run).await;
        slot.abort();
        log.lock().map(|log| log.clone()).unwrap_or_default()
    }

    fn unreachable(_reach: &Reach) -> Result<Outcome, String> {
        Err("connection refused".to_owned())
    }

    /// The first dial to a relay other than the first one dialled, and when.
    fn first_move(dials: &[(PublicKey, Duration)]) -> Option<(PublicKey, Duration)> {
        let (first, _) = dials.first()?;
        dials.iter().find(|(key, _)| key != first).copied()
    }

    #[tokio::test(start_paused = true)]
    async fn a_random_slot_gives_up_a_relay_unreachable_for_an_hour() -> Result<(), String> {
        let directory = directory_at(scratch(), relays("relay", 2)?, 1)?;
        let dials = dials(
            SlotKind::Random,
            None,
            directory,
            Duration::from_secs(3 * 3_600),
            unreachable,
        )
        .await;
        let (moved_to, at) = first_move(&dials).ok_or_else(|| format!("never moved {dials:?}"))?;
        // At the hour: not before it, and not a backoff after it, since the last wait is cut to
        // what remains of it.
        assert_eq!(at, RANDOM_GIVES_UP, "{dials:?}");
        // The new relay gets its own hour: no move back before it has had it.
        let moved = dials
            .iter()
            .position(|(key, _)| *key == moved_to)
            .ok_or("no move")?;
        assert!(
            dials
                .iter()
                .skip(moved)
                .take_while(|(_, when)| *when < at + RANDOM_GIVES_UP)
                .all(|(key, _)| *key == moved_to),
            "{dials:?}"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_random_slot_with_no_other_relay_keeps_retrying() -> Result<(), String> {
        let only = relay("only.example:10900")?;
        let directory = directory_at(scratch(), vec![only.clone()], 1)?;
        let run = Duration::from_secs(3 * 3_600);
        let dials = dials(SlotKind::Random, None, directory, run, unreachable).await;
        assert!(dials.iter().all(|(key, _)| *key == only.key));
        let last = dials.last().map(|(_, at)| *at).ok_or("no dials")?;
        assert!(last >= run - Duration::from_secs(451), "{last:?}");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_reaches_welcome_is_never_given_up() -> Result<(), String> {
        let directory = directory_at(scratch(), relays("relay", 2)?, 1)?;
        let dials = dials(
            SlotKind::Random,
            None,
            directory,
            Duration::from_secs(3 * 3_600),
            |reach| {
                reach.mark();
                Err("closed after Welcome".to_owned())
            },
        )
        .await;
        assert!(dials.len() > 10, "{dials:?}");
        assert_eq!(first_move(&dials), None);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_anchor_gives_up_after_seven_days_counted_across_restarts() -> Result<(), String> {
        let state = scratch();
        let (anchor, other) = (
            relay("anchor.example:10900")?,
            relay("other.example:10900")?,
        );
        std::fs::create_dir_all(&state).map_err(|error| error.to_string())?;
        // An earlier run last reached the anchor six days and 23 hours ago.
        let lost = ANCHOR_GIVES_UP - Duration::from_secs(3_600);
        let reached = wall_ms() - u64::try_from(lost.as_millis()).map_err(|e| e.to_string())?;
        std::fs::write(
            state.join("anchor"),
            format!("{}={}\nreached {reached}\n", anchor.address, anchor.key),
        )
        .map_err(|error| error.to_string())?;
        let directory = directory_at(state.clone(), vec![anchor.clone(), other.clone()], 1)?;
        assert_eq!(directory.saved_anchor().as_ref(), Some(&anchor));
        let dials = dials(
            SlotKind::Anchor,
            Some(anchor.clone()),
            Arc::clone(&directory),
            Duration::from_secs(3 * 3_600),
            unreachable,
        )
        .await;
        let (moved_to, at) = first_move(&dials).ok_or_else(|| format!("never moved {dials:?}"))?;
        assert_eq!(moved_to, other.key);
        // The hour left of its seven days, not seven days from this run's start: the last wait is
        // cut to what remains, so the move is at the hour (less the real milliseconds between
        // writing the file and reading it), never a backoff past it.
        let left = Duration::from_secs(3_600);
        assert!(at >= left - Duration::from_secs(1) && at <= left, "{at:?}");
        // The new anchor is saved, its own count started when it was chosen.
        assert_eq!(directory.saved_anchor(), Some(other.clone()));
        let unreached = directory.anchor_unreached_for(&other);
        assert!(unreached <= Duration::from_secs(60), "{unreached:?}");
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    #[tokio::test(start_paused = true)]
    async fn an_anchor_reached_is_saved_as_reached() -> Result<(), String> {
        let state = scratch();
        let anchor = relay("anchor.example:10900")?;
        let directory = directory_at(state.clone(), vec![anchor.clone()], 1)?;
        let _ = dials(
            SlotKind::Anchor,
            Some(anchor.clone()),
            Arc::clone(&directory),
            Duration::from_secs(10),
            |reach| {
                reach.mark();
                Err("closed after Welcome".to_owned())
            },
        )
        .await;
        assert_eq!(directory.saved_anchor().as_ref(), Some(&anchor));
        assert!(directory.anchor_unreached_for(&anchor) <= Duration::from_secs(60));
        // A file of an earlier build, with no time, starts the count again.
        std::fs::write(
            state.join("anchor"),
            format!("{}={}\n", anchor.address, anchor.key),
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(directory.saved_anchor().as_ref(), Some(&anchor));
        assert_eq!(directory.anchor_unreached_for(&anchor), Duration::ZERO);
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    #[tokio::test(start_paused = true)]
    async fn the_home_relay_is_never_given_up() -> Result<(), String> {
        let home = relay("home.example:10900")?;
        let directory = directory_at(scratch(), relays("other", 3)?, 1)?;
        let dials = dials(
            SlotKind::Home,
            Some(home.clone()),
            directory,
            ANCHOR_GIVES_UP + Duration::from_secs(24 * 3_600),
            unreachable,
        )
        .await;
        assert!(dials.len() > 1_000, "{}", dials.len());
        assert!(dials.iter().all(|(key, _)| *key == home.key));
        Ok(())
    }

    fn full_for_ever(_reach: &Reach) -> Result<Outcome, String> {
        Ok(goodbye(Reason::Full, u32::MAX))
    }

    #[tokio::test(start_paused = true)]
    async fn a_random_slot_asked_to_wait_past_its_bound_moves_on_at_once() -> Result<(), String> {
        let directory = directory_at(scratch(), relays("relay", 2)?, 1)?;
        let dials = dials(
            SlotKind::Random,
            None,
            directory,
            Duration::from_secs(10),
            full_for_ever,
        )
        .await;
        // Both relays at once, each then avoided for its wait, so neither again.
        assert_eq!(dials.len(), 2, "{dials:?}");
        let (first, second) = (dials.first().ok_or("none")?, dials.get(1).ok_or("one")?);
        assert_ne!(first.0, second.0);
        assert_eq!(first.1, second.1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_refused_for_ever_moves_the_anchor_on_at_once() -> Result<(), String> {
        let state = scratch();
        let (anchor, other) = (
            relay("anchor.example:10900")?,
            relay("other.example:10900")?,
        );
        let directory = directory_at(state.clone(), vec![anchor.clone(), other.clone()], 1)?;
        let dials = dials(
            SlotKind::Anchor,
            Some(anchor.clone()),
            Arc::clone(&directory),
            Duration::from_secs(10),
            // What `session` makes of `WireError::Refused { Full, u32::MAX }`.
            full_for_ever,
        )
        .await;
        assert_eq!(first_move(&dials), Some((other.key, Duration::ZERO)));
        assert_eq!(directory.saved_anchor(), Some(other));
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_within_the_bound_is_honoured_on_the_same_relay() -> Result<(), String> {
        let directory = directory_at(scratch(), relays("relay", 2)?, 1)?;
        let dials = dials(
            SlotKind::Random,
            None,
            directory,
            Duration::from_secs(1_000),
            |reach| {
                reach.mark();
                Ok(goodbye(Reason::Full, 600))
            },
        )
        .await;
        assert_eq!(dials.len(), 2, "{dials:?}");
        assert_eq!(first_move(&dials), None);
        let again = dials.get(1).map(|(_, at)| *at).ok_or("no second dial")?;
        assert!(again >= Duration::from_secs(600), "{again:?}");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_is_cut_to_what_remains_of_the_bound() -> Result<(), String> {
        let directory = directory_at(scratch(), relays("relay", 2)?, 1)?;
        let dials = dials(
            SlotKind::Random,
            None,
            directory,
            Duration::from_secs(3 * 3_600),
            // Fifty minutes, within the hour: honoured, but jitter may take it past the hour.
            |_reach| Ok(goodbye(Reason::Full, 3_000)),
        )
        .await;
        let (_, at) = first_move(&dials).ok_or_else(|| format!("never moved {dials:?}"))?;
        assert!(at <= RANDOM_GIVES_UP, "{at:?} {dials:?}");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_home_relay_asked_to_wait_for_ever_is_dialled_again_within_a_day()
    -> Result<(), String> {
        let home = relay("home.example:10900")?;
        let directory = directory_at(scratch(), relays("other", 2)?, 1)?;
        let dials = dials(
            SlotKind::Home,
            Some(home.clone()),
            directory,
            Duration::from_secs(3 * 24 * 3_600 + 60),
            full_for_ever,
        )
        .await;
        assert!(dials.len() >= 4, "{dials:?}");
        assert!(dials.iter().all(|(key, _)| *key == home.key));
        let gaps: Vec<Duration> = dials.windows(2).map(|two| two[1].1 - two[0].1).collect();
        assert!(
            gaps.iter().all(|gap| *gap <= HOME_WAITS_AT_MOST),
            "{gaps:?}"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_slot_with_nothing_to_pick_finds_a_relay_learned_meanwhile() -> Result<(), String> {
        let only = relay("only.example:10900")?;
        let directory = directory_at(scratch(), vec![only.clone()], 1)?;
        let fresh = relay("fresh.example:10900")?;
        let (learner, hinter, offered) = (Arc::clone(&directory), key()?, vec![fresh.clone()]);
        let learning = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            learner.learn(hinter, &offered);
        });
        let dials = dials(
            SlotKind::Random,
            None,
            directory,
            Duration::from_secs(2 * 3_600),
            |_reach| Ok(Outcome::Leave(Duration::from_secs(u32::MAX.into()))),
        )
        .await;
        learning.abort();
        let (moved_to, at) = first_move(&dials).ok_or_else(|| format!("never moved {dials:?}"))?;
        assert_eq!(moved_to, fresh.key);
        assert!(
            at <= Duration::from_secs(10) + NOTHING_TO_PICK_AT_MOST.mul_f64(1.5),
            "{at:?}"
        );
        Ok(())
    }

    fn anchor_file(
        state: &std::path::Path,
        anchor: &RelayAddress,
        reached: u64,
    ) -> Result<(), String> {
        std::fs::create_dir_all(state).map_err(|error| error.to_string())?;
        std::fs::write(
            state.join("anchor"),
            format!("{}={}\nreached {reached}\n", anchor.address, anchor.key),
        )
        .map_err(|error| error.to_string())
    }

    #[test]
    fn no_reached_time_is_saved_from_a_clock_that_is_not_set() -> Result<(), String> {
        let state = scratch();
        let anchor = relay("anchor.example:10900")?;
        let directory = directory_at(state.clone(), vec![anchor.clone()], 1)?;
        // A board with no real-time clock, booted in 1970, an hour before it had the time.
        directory.save_anchor_at(&anchor, Duration::ZERO, 3_600_000);
        let text = std::fs::read_to_string(state.join("anchor")).map_err(|e| e.to_string())?;
        assert!(!text.contains("reached"), "{text}");
        assert_eq!(directory.saved_anchor().as_ref(), Some(&anchor));
        assert_eq!(directory.anchor_unreached_for(&anchor), Duration::ZERO);
        // Nor a time that, counted back, falls before the floor.
        directory.save_anchor_at(&anchor, Duration::from_secs(60), PLAUSIBLE_SINCE_MS + 1_000);
        let text = std::fs::read_to_string(state.join("anchor")).map_err(|e| e.to_string())?;
        assert!(!text.contains("reached"), "{text}");
        // A set clock saves its time.
        let now = PLAUSIBLE_SINCE_MS + 86_400_000;
        directory.save_anchor_at(&anchor, Duration::from_secs(60), now);
        let text = std::fs::read_to_string(state.join("anchor")).map_err(|e| e.to_string())?;
        assert!(
            text.contains(&format!("reached {}", now - 60_000)),
            "{text}"
        );
        assert_eq!(
            directory.anchor_unreached_at(&anchor, now),
            Duration::from_secs(60)
        );
        // The next boot comes up in 1970 again: saving the same anchor keeps the time it knew.
        directory.save_anchor_at(&anchor, Duration::ZERO, 3_600_000);
        let text = std::fs::read_to_string(state.join("anchor")).map_err(|e| e.to_string())?;
        assert!(
            text.contains(&format!("reached {}", now - 60_000)),
            "{text}"
        );
        // Reached while the clock is not set: the time it knew is stale now, so it is dropped.
        directory.anchor_reached_at(&anchor, 3_600_000);
        let text = std::fs::read_to_string(state.join("anchor")).map_err(|e| e.to_string())?;
        assert!(!text.contains("reached"), "{text}");
        assert_eq!(directory.saved_anchor().as_ref(), Some(&anchor));
        // Reached with the clock set: that time is saved.
        directory.anchor_reached_at(&anchor, now + 5_000);
        let text = std::fs::read_to_string(state.join("anchor")).map_err(|e| e.to_string())?;
        assert!(text.contains(&format!("reached {}", now + 5_000)), "{text}");
        // A different anchor, saved while the clock is not set, starts without one.
        let other = relay("other.example:10900")?;
        directory.save_anchor_at(&other, Duration::ZERO, 3_600_000);
        let text = std::fs::read_to_string(state.join("anchor")).map_err(|e| e.to_string())?;
        assert!(!text.contains("reached"), "{text}");
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    #[test]
    fn a_saved_time_that_cannot_be_right_is_read_as_unknown() -> Result<(), String> {
        let state = scratch();
        let anchor = relay("anchor.example:10900")?;
        let directory = directory_at(state.clone(), vec![anchor.clone()], 1)?;
        let now = wall_ms();
        // Saved by a run whose clock read 1970.
        anchor_file(&state, &anchor, 3_600_000)?;
        assert_eq!(directory.anchor_unreached_for(&anchor), Duration::ZERO);
        // Later than now.
        anchor_file(&state, &anchor, now + 86_400_000)?;
        assert_eq!(directory.anchor_unreached_for(&anchor), Duration::ZERO);
        // A good time, read by a run whose clock is not yet set, is later than its now.
        anchor_file(&state, &anchor, PLAUSIBLE_SINCE_MS + 1_000)?;
        assert_eq!(
            directory.anchor_unreached_at(&anchor, 3_600_000),
            Duration::ZERO
        );
        // And read by a set clock, it counts.
        assert_eq!(
            directory.anchor_unreached_at(&anchor, PLAUSIBLE_SINCE_MS + 61_000),
            Duration::from_secs(60)
        );
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    #[tokio::test(start_paused = true)]
    async fn an_anchor_saved_with_a_1970_time_is_not_given_up_at_once() -> Result<(), String> {
        let state = scratch();
        let (anchor, other) = (
            relay("anchor.example:10900")?,
            relay("other.example:10900")?,
        );
        anchor_file(&state, &anchor, 3_600_000)?;
        let directory = directory_at(state.clone(), vec![anchor.clone(), other], 1)?;
        let dials = dials(
            SlotKind::Anchor,
            Some(anchor.clone()),
            Arc::clone(&directory),
            Duration::from_secs(2 * 3_600),
            unreachable,
        )
        .await;
        assert!(dials.len() > 1, "{dials:?}");
        assert_eq!(first_move(&dials), None);
        assert_eq!(directory.saved_anchor(), Some(anchor));
        std::fs::remove_dir_all(&state).map_err(|error| error.to_string())
    }

    /// What the reader passes on to a session, both ends.
    type Inbound = (
        mpsc::Sender<Result<Vec<Record>, String>>,
        mpsc::Receiver<Result<Vec<Record>, String>>,
    );

    /// A publishing session to a relay that completed the handshake and then stopped reading, over
    /// a pipe too small for even the first receiver info. The relay's end and the reader's sender
    /// are held for as long as the session runs.
    async fn stalled(
        directory: Arc<Directory>,
        records: Option<Inbound>,
    ) -> Result<Outcome, String> {
        let (session, _relay_end, relay_key) = pipe(64).await?;
        let (_out, mut batches) = broadcast::channel(64);
        let (_records_in, mut records) = records.unwrap_or_else(|| mpsc::channel(16));
        let address = RelayAddress {
            key: relay_key,
            address: "stalled.example:10900".to_owned(),
        };
        let mut writer = session.writer;
        publish(
            &address,
            &mut writer,
            &mut records,
            &mut batches,
            &directory,
            64_000,
            &Reach::new(Duration::ZERO, None),
        )
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_stops_reading_ends_the_session_by_the_deadline_and_is_retried()
    -> Result<(), String> {
        let directory = directory_at(scratch(), vec![relay("stalled.example:10900")?], 1)?;
        let began = tokio::time::Instant::now();
        let log = Arc::new(Mutex::new(Vec::new()));
        let written = Arc::clone(&log);
        let sessions = Arc::clone(&directory);
        let slot = tokio::spawn(async move {
            let dial = move |_relay: RelayAddress, _reach: Reach| {
                let written = Arc::clone(&written);
                let directory = Arc::clone(&sessions);
                async move {
                    let dialled = began.elapsed();
                    let ended = stalled(directory, None).await;
                    if let Ok(mut log) = written.lock() {
                        log.push((dialled, began.elapsed(), ended.is_err()));
                    }
                    ended
                }
            };
            run_slot(0, SlotKind::Random, None, &directory, dial).await;
        });
        tokio::time::sleep(Duration::from_secs(100)).await;
        slot.abort();
        let sessions = log.lock().map(|log| log.clone()).unwrap_or_default();
        let (first, second) = (
            sessions.first().ok_or("no session ended")?,
            sessions.get(1).ok_or("not retried")?,
        );
        // Ended in error at the write deadline, not before and not much after.
        assert!(first.2, "{sessions:?}");
        let lasted = first.1 - first.0;
        assert!(
            lasted >= noise::WRITE_TIMEOUT
                && lasted <= noise::WRITE_TIMEOUT + Duration::from_secs(1),
            "{lasted:?}"
        );
        // And the slot dialled again after the first wait, a second and up to half again.
        let gap = second.0 - first.1;
        assert!(gap <= Duration::from_millis(1_600), "{gap:?}");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_reader_ends_the_session_while_a_send_waits() -> Result<(), String> {
        let directory = directory_at(scratch(), Vec::new(), 1)?;
        let (records_in, records) = mpsc::channel(16);
        let reader = records_in.clone();
        let running = tokio::spawn(stalled(directory, Some((records_in, records))));
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!running.is_finished(), "ended before the reader failed");
        let failed_at = tokio::time::Instant::now();
        reader
            .send(Err("silent too long".to_owned()))
            .await
            .map_err(|error| error.to_string())?;
        let ended = tokio::time::timeout(Duration::from_secs(1), running)
            .await
            .map_err(|_| "the session waited on its send".to_owned())?
            .map_err(|error| error.to_string())?;
        assert_eq!(ended.err().as_deref(), Some("silent too long"));
        assert!(failed_at.elapsed() < Duration::from_secs(1));
        Ok(())
    }
}
