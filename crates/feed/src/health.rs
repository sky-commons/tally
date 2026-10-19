//! Whether the feeder is doing its job: a session up with a relay, and its decoder talking. The
//! running feeder says so twice. Its log carries one warning when no relay has been reachable for
//! `UNREACHABLE_AFTER`, and one line when a relay is reachable again, never more. And it writes a
//! status file in its state directory every `STATUS_EVERY`, which `tally-feed health` reads and
//! judges (a container's `HEALTHCHECK`, packaging/container/Dockerfile): healthy when the file is
//! fresh, a relay session was up within `RELAY_WITHIN` and the decoder sent bytes within
//! `SOURCE_WITHIN`. readsb and dump1090-fa send a heartbeat on their BEAST output every 60 s
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
        format!(
            "# tally-feed's status, rewritten every {}s while it runs and read by `tally-feed \
             health`: wall-clock seconds, 0 for never.\nwritten {now}\nrelay {relay}\nsource \
             {source}\n",
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
    if wrong.is_empty() {
        Ok(format!(
            "healthy: publishing to a relay, decoder last heard {}s ago",
            ago(source)
        ))
    } else {
        Err(format!("unhealthy: {}", wrong.join("; ")))
    }
}

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
