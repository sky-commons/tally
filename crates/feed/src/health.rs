//! Whether the feeder is doing its job: a session up with a relay, and its decoder talking. The
//! running feeder says so twice. Its log carries one warning when no relay has been reachable for
//! `UNREACHABLE_AFTER`, and one line when a relay is reachable again, never more. And it writes a
//! status file in its state directory every `STATUS_EVERY`, which `tally-feed health` reads and
//! judges (a container's `HEALTHCHECK`, packaging/container/Dockerfile): healthy when the file is
//! fresh, a relay session was up within `RELAY_WITHIN` and the decoder sent bytes within
//! `SOURCE_WITHIN`, and that it has had a clock to sign by: a configured relay heard (`--relay`
//! or a seed) or this host's clock synced, within `RELAY_WITHIN` (`source::RelayClocks`'s
//! sources; without either it signs by an unsynced host clock no relay vouches for). It also says,
//! without calling the feeder unhealthy, when its clock disagrees with a relay it publishes to
//! (`source::RelayClocks::disagreements`): every batch is still sent, and that relay judges whether
//! it can use it, so the owner sees a wrong clock rather than missing batches. readsb and dump1090-fa send a heartbeat on their BEAST output every 60 s
//! when no aircraft is heard (readsb's `--net-heartbeat`), so a decoder silent for five minutes
//! is a decoder that is gone or wedged, not a quiet sky.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

/// No relay reachable for this long is warned about, once.
pub const UNREACHABLE_AFTER: Duration = Duration::from_secs(10 * 60);
/// How often the status file is written and the warning considered.
pub const STATUS_EVERY: Duration = Duration::from_secs(10);
/// A status file older than this is a feeder that is not running.
pub const STATUS_WITHIN: u64 = 60;
/// No relay session for longer than this is unhealthy: a failover takes seconds, a relay that is
/// down a few backoff steps.
pub const RELAY_WITHIN: u64 = 120;
/// No bytes from the decoder for longer than this is unhealthy (five heartbeats missed).
pub const SOURCE_WITHIN: u64 = 300;

/// The status file's name in the state directory.
pub const STATUS_FILE: &str = "status";

/// What the sources and the publisher report, and the watcher reads.
pub struct Health {
    state: Mutex<State>,
    /// Wall-clock seconds the decoder last sent bytes; 0 if it never did.
    source_heard: AtomicU64,
    /// Since when (wall-clock seconds) no configured clock source has been reachable while this
    /// host's clock is unsynced (`source::RelayClocks::sourced`); 0 while one is.
    unsourced_since: AtomicU64,
    /// The relays a session measures whose clock this feeder's is outside, and by how far in
    /// milliseconds (positive ahead of it): `source::RelayClocks::disagreements`.
    disagreeing: Mutex<Vec<(tally_wire::PublicKey, i64)>>,
    /// The relays whose anchors this feeder's trusted reference disagrees with more than an
    /// honest relay's can, and by how far in milliseconds:
    /// `source::RelayClocks::anchor_disagreements`.
    anchors_disagreeing: Mutex<Vec<(tally_wire::PublicKey, i64)>>,
    /// Since when (wall-clock seconds) the batcher has carried no anchor
    /// (`source::RelayClocks::anchors`); 0 while it carries one.
    anchorless_since: AtomicU64,
    /// The batches signed with no anchor since the feeder started
    /// (`source::RelayClocks::unanchored`).
    unanchored: AtomicU64,
    /// The batches relay sessions were too slow for since the feeder started: each lost to that
    /// session as the sessions' channel moved past it (`RecvError::Lagged`).
    lagged: AtomicU64,
}

struct State {
    relays_up: usize,
    /// Since when no relay session has been up (the feeder's start, at first); none while one is.
    down_since: Option<Instant>,
    /// The wall-clock second a relay session was last up; 0 if none ever was.
    relay_seen_wall: u64,
    /// Whether the unreachable warning was given and not yet answered by a recovery.
    warned: bool,
    /// A recovery after the warning, not yet told: how long the feeder was without a relay.
    recovered: Option<Duration>,
}

/// A change the log is told about.
#[derive(Debug, PartialEq, Eq)]
pub enum Notice {
    /// No relay has been reachable for this long.
    Unreachable(Duration),
    /// A relay is reachable again, after this long without one.
    Recovered(Duration),
}

impl Default for Health {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                relays_up: 0,
                down_since: Some(Instant::now()),
                relay_seen_wall: 0,
                warned: false,
                recovered: None,
            }),
            source_heard: AtomicU64::new(0),
            unsourced_since: AtomicU64::new(0),
            disagreeing: Mutex::new(Vec::new()),
            anchors_disagreeing: Mutex::new(Vec::new()),
            anchorless_since: AtomicU64::new(0),
            unanchored: AtomicU64::new(0),
            lagged: AtomicU64::new(0),
        }
    }
}

impl Health {
    /// How many relay sessions are up now.
    pub fn relays_up(&self, count: usize) {
        let now = Instant::now();
        if let Ok(mut state) = self.state.lock() {
            if count > 0 || state.relays_up > 0 {
                state.relay_seen_wall = wall_secs();
            }
            match (state.down_since, count) {
                (Some(since), 1..) => {
                    if state.warned {
                        state.warned = false;
                        state.recovered = Some(now.saturating_duration_since(since));
                    }
                    state.down_since = None;
                }
                (None, 0) => state.down_since = Some(now),
                _ => {}
            }
            state.relays_up = count;
        }
    }

    /// Whether the batcher has a clock source now: a configured relay heard, or this host's
    /// clock synced (`source::RelayClocks::sourced`).
    pub fn clock_sourced(&self, sourced: bool) {
        if sourced {
            self.unsourced_since.store(0, Ordering::Relaxed);
        } else {
            let _ = self.unsourced_since.compare_exchange(
                0,
                wall_secs().max(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// The relays whose clock this feeder's disagrees with now, by how far
    /// (`source::RelayClocks::disagreements`).
    pub fn clock_disagrees(&self, disagreeing: Vec<(tally_wire::PublicKey, i64)>) {
        if let Ok(mut held) = self.disagreeing.lock() {
            *held = disagreeing;
        }
    }

    /// The relays whose anchors disagree with this feeder's clock now, and by how far
    /// (`source::RelayClocks::anchor_disagreements`): said, and their anchors left out of batches.
    pub fn anchor_disagrees(&self, disagreeing: Vec<(tally_wire::PublicKey, i64)>) {
        if let Ok(mut held) = self.anchors_disagreeing.lock() {
            *held = disagreeing;
        }
    }

    /// Whether the batcher carries an anchor now, and how many batches it has signed with none:
    /// none carried, its data is unusable at every relay (RFC-0171 §3.6).
    pub fn anchored(&self, carrying: bool, unanchored: u64) {
        self.unanchored.store(unanchored, Ordering::Relaxed);
        if carrying {
            self.anchorless_since.store(0, Ordering::Relaxed);
        } else {
            let _ = self.anchorless_since.compare_exchange(
                0,
                wall_secs().max(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// A relay session was too slow for `count` more batches, which it will never send.
    pub fn lagged(&self, count: u64) {
        self.lagged.fetch_add(count, Ordering::Relaxed);
    }

    /// The decoder sent bytes.
    pub fn source_heard(&self) {
        self.source_heard.store(wall_secs(), Ordering::Relaxed);
    }

    /// What the log is to be told now, if anything: once when no relay has been up for
    /// `UNREACHABLE_AFTER` (since the feeder started, or since the last one went), and once when
    /// one is up again after that warning.
    pub fn notice(&self) -> Option<Notice> {
        let now = Instant::now();
        let mut state = self.state.lock().ok()?;
        if let Some(down) = state.recovered.take() {
            return Some(Notice::Recovered(down));
        }
        let down = now.saturating_duration_since(state.down_since?);
        if !state.warned && down >= UNREACHABLE_AFTER {
            state.warned = true;
            return Some(Notice::Unreachable(down));
        }
        None
    }

    /// The status file's text, at wall-clock second `now`.
    fn status(&self, now: u64) -> String {
        let relay = self
            .state
            .lock()
            .map(|state| {
                if state.relays_up > 0 {
                    now
                } else {
                    state.relay_seen_wall
                }
            })
            .unwrap_or(0);
        let source = self.source_heard.load(Ordering::Relaxed);
        let unsourced = self.unsourced_since.load(Ordering::Relaxed);
        let anchorless = self.anchorless_since.load(Ordering::Relaxed);
        let unanchored = self.unanchored.load(Ordering::Relaxed);
        let lagged = self.lagged.load(Ordering::Relaxed);
        let disagreeing: String = self
            .disagreeing
            .lock()
            .map(|held| {
                held.iter()
                    .map(|(relay, off)| format!("clock-disagrees {} {off}\n", relay.to_base64url()))
                    .collect()
            })
            .unwrap_or_default();
        let anchors: String = self
            .anchors_disagreeing
            .lock()
            .map(|held| {
                held.iter()
                    .map(|(relay, off)| {
                        format!("anchor-disagrees {} {off}\n", relay.to_base64url())
                    })
                    .collect()
            })
            .unwrap_or_default();
        format!(
            "# tally-feed's status, rewritten every {}s while it runs and read by `tally-feed \
             health`: wall-clock seconds, 0 for never; each clock-disagrees line a relay and how \
             far this feeder's clock is outside its, and each anchor-disagrees line a relay and how \
             far its anchor is outside this feeder's reference, in milliseconds; lagged the \
             batches relay sessions were too slow for since it started.\nwritten \
             {now}\nrelay {relay}\nsource {source}\nclock-unsourced {unsourced}\nanchorless \
             {anchorless}\nunanchored {unanchored}\nlagged {lagged}\n{disagreeing}{anchors}",
            STATUS_EVERY.as_secs()
        )
    }
}

/// Tells the log what `health` notices, and keeps the status file in `state_dir`, for as long as
/// the feeder runs.
pub async fn watch(health: Arc<Health>, state_dir: PathBuf) {
    let path = state_dir.join(STATUS_FILE);
    let mut every = tokio::time::interval(STATUS_EVERY);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing = false;
    loop {
        every.tick().await;
        match health.notice() {
            Some(Notice::Unreachable(down)) => eprintln!(
                "tally-feed: warning: no relay has been reachable for {} minutes, so nothing this \
                 receiver hears is published. Check that this host can open outbound TCP \
                 connections to the relays (the seed list, or --relay); the feeder keeps trying \
                 and says so here when one answers.",
                down.as_secs() / 60
            ),
            Some(Notice::Recovered(down)) => eprintln!(
                "tally-feed: a relay is reachable again after {} minutes without one; publishing",
                down.as_secs().div_ceil(60)
            ),
            None => {}
        }
        match write_status(&path, &health.status(wall_secs())) {
            Ok(()) => failing = false,
            Err(error) if !failing => {
                failing = true;
                eprintln!("tally-feed: writing {}: {error}", path.display());
            }
            Err(_) => {}
        }
    }
}

/// Writes the status whole: a reader never sees half of one.
fn write_status(path: &Path, text: &str) -> std::io::Result<()> {
    let partial = path.with_extension("partial");
    std::fs::write(&partial, text)?;
    std::fs::rename(&partial, path)
}

/// `tally-feed health`: the verdict on the feeder whose state directory is `state_dir`, as the
/// line to print. `Ok` is healthy.
pub fn check(state_dir: &Path) -> Result<String, String> {
    let path = state_dir.join(STATUS_FILE);
    let text = std::fs::read_to_string(&path).map_err(|error| {
        format!(
            "{}: {error} (is tally-feed running with --state {}?)",
            path.display(),
            state_dir.display()
        )
    })?;
    judge(&text, wall_secs())
}

/// The verdict on a status file's `text` at wall-clock second `now`.
fn judge(text: &str, now: u64) -> Result<String, String> {
    let field = |name: &str| -> Result<u64, String> {
        text.lines()
            .filter_map(|line| line.split_once(' '))
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| value.trim().parse().ok())
            .ok_or_else(|| format!("the status file has no {name}"))
    };
    let (written, relay, source) = (field("written")?, field("relay")?, field("source")?);
    let ago = |at: u64| now.saturating_sub(at);
    if ago(written) > STATUS_WITHIN {
        return Err(format!(
            "unhealthy: the status was last written {}s ago; the feeder is not running",
            ago(written)
        ));
    }
    let mut wrong = Vec::new();
    if relay == 0 {
        wrong.push("no relay session yet".to_owned());
    } else if ago(relay) > RELAY_WITHIN {
        wrong.push(format!("no relay session for {}s", ago(relay)));
    }
    if source == 0 {
        wrong.push("nothing read from the decoder yet".to_owned());
    } else if ago(source) > SOURCE_WITHIN {
        wrong.push(format!(
            "nothing read from the decoder for {}s",
            ago(source)
        ));
    }
    // A status written before the line existed has none: nothing to judge.
    if let Ok(since) = field("clock-unsourced")
        && since > 0
        && ago(since) > RELAY_WITHIN
    {
        wrong.push(format!(
            "no configured clock source reachable, host unsynced, for {}s",
            ago(since)
        ));
    }
    // A status written before the lines existed has none: nothing to judge.
    if let Ok(since) = field("anchorless")
        && since > 0
        && ago(since) > RELAY_WITHIN
    {
        wrong.push(crate::relays::anchorless(
            ago(since),
            field("unanchored").unwrap_or(0),
        ));
    }
    // Said, never judged: a session too slow for some batches still sends the rest.
    let lagged = match field("lagged") {
        Ok(count) if count > 0 => {
            format!("; {count} batches relay sessions were too slow for since it started")
        }
        _ => String::new(),
    };
    // Said, never judged: every batch still goes, and the relay judges it.
    let notes: String = text
        .lines()
        .filter_map(|line| {
            let (said, rest): (fn(&str, i64) -> String, &str) =
                if let Some(rest) = line.strip_prefix("clock-disagrees ") {
                    (crate::relays::disagreeing, rest)
                } else {
                    (
                        crate::relays::anchor_disagreeing,
                        line.strip_prefix("anchor-disagrees ")?,
                    )
                };
            let (relay, off) = rest.split_once(' ')?;
            let off: i64 = off.trim().parse().ok()?;
            Some(format!("; {}", said(&format!("key {relay}"), off)))
        })
        .collect();
    let notes = format!("{lagged}{notes}");
    if wrong.is_empty() {
        Ok(format!(
            "healthy: publishing to a relay, decoder last heard {}s ago{notes}",
            ago(source)
        ))
    } else {
        Err(format!("unhealthy: {}{notes}", wrong.join("; ")))
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "the feeder's own host clock, which its health ages by"
)]
fn wall_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_relay_is_warned_about_once_and_its_return_once() {
        let health = Health::default();
        let mut said = Vec::new();
        // Twenty-five minutes with no relay, looked at every ten seconds.
        for _ in 0..150 {
            tokio::time::advance(STATUS_EVERY).await;
            said.extend(health.notice());
        }
        assert_eq!(said, vec![Notice::Unreachable(UNREACHABLE_AFTER)]);
        health.relays_up(1);
        for _ in 0..30 {
            tokio::time::advance(STATUS_EVERY).await;
            said.extend(health.notice());
        }
        assert_eq!(said.len(), 2, "{said:?}");
        assert_eq!(said[1], Notice::Recovered(150 * STATUS_EVERY));
    }

    #[tokio::test(start_paused = true)]
    async fn a_short_outage_says_nothing() {
        let health = Health::default();
        health.relays_up(2);
        tokio::time::advance(STATUS_EVERY).await;
        assert_eq!(health.notice(), None);
        health.relays_up(0);
        for _ in 0..59 {
            tokio::time::advance(STATUS_EVERY).await;
            assert_eq!(health.notice(), None);
        }
        health.relays_up(1);
        tokio::time::advance(STATUS_EVERY).await;
        assert_eq!(health.notice(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn the_status_judges_relay_and_decoder() {
        let health = Health::default();
        let now = wall_secs();
        assert!(judge(&health.status(now), now).is_err_and(|why| {
            why.contains("no relay session yet") && why.contains("nothing read from the decoder")
        }));
        health.relays_up(1);
        health.source_heard();
        assert!(judge(&health.status(now), now).is_ok());
        // The feeder stopped: its last status ages.
        let last = health.status(now);
        assert!(
            judge(&last, now + STATUS_WITHIN + 1).is_err_and(|why| why.contains("not running"))
        );
        // Relays gone two minutes and more, decoder still talking.
        health.relays_up(0);
        let later = now + RELAY_WITHIN + 1;
        health.source_heard.store(later, Ordering::Relaxed);
        assert!(
            judge(&health.status(later), later)
                .is_err_and(|why| why.contains("no relay session for"))
        );
        // A relay up, the decoder silent past its heartbeats.
        health.relays_up(1);
        let silent = later + SOURCE_WITHIN + 1;
        assert!(
            judge(&health.status(silent), silent)
                .is_err_and(|why| why.contains("nothing read from the decoder for"))
        );
        assert!(judge("written 1\n", 1).is_err_and(|why| why.contains("no relay")));
    }

    /// No configured relay heard and this host's clock unsynced, for longer than a failover: the
    /// verdict says so (the batcher signs by a clock nothing vouches for). A short gap, or a
    /// source back, says nothing.
    #[tokio::test(start_paused = true)]
    async fn no_clock_source_is_reported() {
        let health = Health::default();
        health.relays_up(1);
        health.source_heard();
        let now = wall_secs();
        health.clock_sourced(false);
        assert!(judge(&health.status(now), now).is_ok(), "a short gap");
        let later = now + RELAY_WITHIN + 1;
        health.source_heard.store(later, Ordering::Relaxed);
        assert!(
            judge(&health.status(later), later).is_err_and(
                |why| why.contains("no configured clock source reachable, host unsynced")
            )
        );
        health.clock_sourced(true);
        assert!(judge(&health.status(later), later).is_ok());
    }

    /// A feeder that carries no anchor for longer than a failover is unhealthy, and says its data
    /// is unusable and how many batches it signed with none: no relay can use them. A short gap,
    /// or an anchor back, says nothing.
    #[tokio::test(start_paused = true)]
    async fn carrying_no_anchor_is_reported_with_the_unanchored_count() {
        let health = Health::default();
        health.relays_up(1);
        health.source_heard();
        let now = wall_secs();
        health.anchored(false, 3);
        assert!(judge(&health.status(now), now).is_ok(), "a short gap");
        let later = now + RELAY_WITHIN + 1;
        health.source_heard.store(later, Ordering::Relaxed);
        assert!(judge(&health.status(later), later).is_err_and(|why| {
            why.contains("carrying no anchor for")
                && why.contains("data unusable")
                && why.contains("(3 batches signed unanchored)")
        }));
        health.anchored(true, 3);
        assert!(judge(&health.status(later), later).is_ok());
    }

    /// The batches relay sessions were too slow for are counted on the health surface, all told
    /// since the feeder started, and said, never judged. Before, they were only logged.
    #[tokio::test(start_paused = true)]
    async fn batches_a_session_was_too_slow_for_are_counted_never_judged() {
        let health = Health::default();
        health.relays_up(1);
        health.source_heard();
        let now = wall_secs();
        let quiet = judge(&health.status(now), now);
        assert!(quiet.is_ok_and(|said| !said.contains("too slow")));
        health.lagged(3);
        health.lagged(4);
        assert!(health.status(now).contains("\nlagged 7\n"));
        let said = judge(&health.status(now), now);
        assert!(
            said.as_ref()
                .is_ok_and(|said| said.contains("; 7 batches relay sessions were too slow for")),
            "{said:?}"
        );
    }

    /// A clock that disagrees with a relay is said on the health surface, with by how far and
    /// which way, and is no verdict: the feeder still sends every batch, and the relay judges it.
    #[tokio::test(start_paused = true)]
    async fn a_clock_that_disagrees_with_a_relay_is_reported_never_judged() -> Result<(), String> {
        let health = Health::default();
        health.relays_up(1);
        health.source_heard();
        let relay = tally_wire::Identity::from_seed([3; 32]).public();
        health.clock_disagrees(vec![(relay, -3_600_000)]);
        let now = wall_secs();
        let said = judge(&health.status(now), now)?;
        assert!(
            said.contains("your clock disagrees with relay")
                && said.contains(&relay.to_base64url())
                && said.contains("by 3600 s (behind it)"),
            "{said}"
        );
        health.clock_disagrees(Vec::new());
        assert!(!judge(&health.status(now), now)?.contains("disagrees"));
        // A relay's anchor that disagrees: said, with by how far, and left out of batches.
        health.anchor_disagrees(vec![(relay, 94_000)]);
        let said = judge(&health.status(now), now)?;
        assert!(
            said.contains("anchor disagrees with your reference")
                && said.contains(&relay.to_base64url())
                && said.contains("by 94 s"),
            "{said}"
        );
        Ok(())
    }

    #[test]
    fn the_status_file_is_read_back_from_the_state_directory() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("tally-health-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
        let now = wall_secs();
        write_status(
            &dir.join(STATUS_FILE),
            &format!("written {now}\nrelay {now}\nsource {now}\n"),
        )
        .map_err(|error| error.to_string())?;
        let verdict = check(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(verdict?.starts_with("healthy"));
        assert!(check(Path::new("/nonexistent/tally")).is_err());
        Ok(())
    }
}
