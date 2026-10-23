//! A feeder's signed clock against its relay's, end to end, over real sockets: a stand-in readsb
//! streaming BEAST, a real feeder (`tally_feed::run_on`) reading it, its host's wall clock one the
//! test steps ([`host`]), and a real relay on its own clocks (RFC-0171 §3.6). A feeder signs by
//! the clock its relay states (`RateLimit`'s `clock_ms`), run on by its host's monotonic clock
//! from when it was heard (`tally_feed::source::RelayClocks`); these show a step of the feeder's
//! host clock, either way, moves nothing the relay judges.
//!
//! A test waits for what it is looking for with a bounded poll of the relay's own record of the
//! receiver (`Hub::station`) or of its counters, and [`HANG`] fails one that never comes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use std::time::Instant;

use tally_feed::config::{Config, Key};
use tally_relay::hub::Hub;
use tally_relay::sharing::Deadlines;
use tally_relay::stations::StationReport;
use tally_wire::{Clock, Frame, FrameKind, Identity, Location, PublicKey, RelayAddress};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

type Result<T = ()> = std::result::Result<T, String>;

/// How long a test waits for an event before calling it a hang: past a relay's heartbeat (when it
/// states its clock again), with room; a guard on a relay or feeder that never gets there.
const HANG: Duration = Duration::from_secs(150);

/// Between two looks at the relay's record: a poll, never a wait standing in for an event.
const POLL: Duration = Duration::from_millis(50);

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// A stand-in readsb: whoever connects is sent a new frame every 20 ms for as long as it stays,
/// so the feeder seals a batch every second all through a test.
async fn readsb() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(20));
                for n in 0u32.. {
                    interval.tick().await;
                    let mut message = [0x8d; 14];
                    message[1..5].copy_from_slice(&n.to_be_bytes());
                    let Ok(frame) =
                        Frame::new(FrameKind::ModeSLong, 1_000 + u64::from(n), 100, &message)
                    else {
                        return;
                    };
                    let mut bytes = Vec::new();
                    frame.encode_beast(&mut bytes);
                    if stream.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok(address)
}

/// A feeder host whose wall clock is this machine's moved by `offset_ms`, which the test steps,
/// and whose monotonic clock is this machine's.
fn host(offset_ms: &Arc<AtomicI64>) -> tally_feed::source::HostClock {
    let offset = Arc::clone(offset_ms);
    let started = Instant::now();
    tally_feed::source::HostClock {
        wall: Arc::new(move || {
            let now = i64::try_from(tally_feed::source::wall_ms()).unwrap_or(i64::MAX);
            u64::try_from(now.saturating_add(offset.load(Ordering::Relaxed))).unwrap_or(0)
        }),
        monotonic: Arc::new(move || started.elapsed()),
        // Its kernel reports no sync: its own clock is never one of the sources it signs by.
        synced: Arc::new(|| None),
    }
}

struct Running {
    hub: Arc<Hub>,
    feeder: PublicKey,
    dir: std::path::PathBuf,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A relay on its own clocks and a real feeder on `host` publishing to it from a streaming readsb.
async fn running(host: tally_feed::source::HostClock) -> Result<Running> {
    running_on(Hub::new(8, Deadlines::RELAY), host).await
}

/// `running`, the relay's hub `hub`.
async fn running_on(hub: Hub, host: tally_feed::source::HostClock) -> Result<Running> {
    let identity = Identity::generate().map_err(text)?;
    let key = identity.public();
    let hub = Arc::new(hub);
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    let source = readsb().await?;
    let mut name = [0u8; 8];
    for (byte, random) in name
        .iter_mut()
        .zip(Identity::generate().map_err(text)?.public().as_bytes())
    {
        *byte = *random;
    }
    // Bazel's own scratch directory for the test, as every test's (std's when run by hand).
    let base = std::env::var_os("TEST_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("tally-clock-{}", u64::from_be_bytes(name)));
    std::fs::create_dir_all(&dir).map_err(text)?;
    let key_file = dir.join("key");
    tally_feed::init(&key_file)?;
    let feeder = Identity::from_base64(&std::fs::read_to_string(&key_file).map_err(text)?)
        .map_err(text)?
        .public();
    tokio::spawn(tally_feed::run_on(
        Config {
            key: Key::File(key_file),
            source: source.to_string(),
            uat: None,
            acars: Vec::new(),
            acars_ceiling: tally_feed::source::DEFAULT_ACARS_CEILING,
            relays: vec![RelayAddress {
                key,
                address: address.to_string(),
            }],
            seeds: Vec::new(),
            state_dir: dir.clone(),
            location: Some(Location {
                lat_e7: 374_100_000,
                lon_e7: -1_221_000_000,
                alt_m: 10,
                precision_m: 0,
            }),
            clock: Clock::Dump1090,
            ceiling: 1_000_000,
            source_address: None,
            deflate_level: None,
        },
        host,
    ));
    Ok(Running { hub, feeder, dir })
}

/// The relay's record of the feeder's receiver once `until` holds of it.
async fn station_until(
    running: &Running,
    what: &str,
    until: impl Fn(&StationReport) -> bool,
) -> Result<StationReport> {
    tokio::time::timeout(HANG, async {
        loop {
            if let Some(station) = running.hub.station(&running.feeder)
                && until(&station)
            {
                return station;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| format!("never {what}: {:?}", running.hub.station(&running.feeder)))
}

/// The feeder's sessions with the relay that forwarded a batch: one all through a test, since
/// nothing ends a session over a clock (RFC-0171 §3.6).
fn one_session(running: &Running) -> Result<u64> {
    Ok(running
        .hub
        .station(&running.feeder)
        .ok_or("no station")?
        .sessions)
}

/// The records the relay held as possession but could not use for their signed time, behind its
/// window or ahead of it (`late_records`, `ahead_records`): what a feeder signing by a stepped
/// clock makes, whether or not anything blames it. A station's `late_batches` counts only what is
/// blamed, and a batch ahead is never late, so these are what a test of the feeder's signed time
/// reads.
fn unusable(running: &Running) -> (u64, u64) {
    let report = running.hub.memory_report();
    (report.late_records, report.ahead_records)
}

/// In step, then its host's clock steps back 100 s, past what a relay takes in: it signs on by
/// the clock its relay stated, which its monotonic clock runs on, so nothing is late and nothing
/// refused, and its batches are taken all through. Before, the stated offset was held against the
/// host's wall clock, the step moved every batch 100 s behind, each was dropped as too old until
/// the relay stated its clock again.
#[tokio::test]
async fn a_feeder_whose_host_clock_steps_back_signs_on_and_nothing_is_late() -> Result {
    let offset = Arc::new(AtomicI64::new(0));
    let running = running(host(&offset)).await?;
    let before = station_until(&running, "taken in step", |station| station.batches > 2).await?;
    assert_eq!(before.late_batches, 0);
    let held = unusable(&running);
    offset.store(-100_000, Ordering::Relaxed);
    station_until(&running, "taken after the step", |station| {
        station.batches > before.batches + 5
    })
    .await?;
    let after = running.hub.station(&running.feeder).ok_or("no station")?;
    assert_eq!(after.late_batches, 0);
    // Every batch after the step usable: none behind the window, none ahead.
    assert_eq!(unusable(&running), held);
    assert_eq!(one_session(&running)?, 1);
    Ok(())
}

/// A Pi with no real-time clock boots 100 s behind, its kernel unsynced, beside its one relay.
/// An unsynced host is no clock source (RFC-0171 §3.6, as NTP never votes an undisciplined local
/// clock), so its one configured relay is its one source and it signs by that relay's clock once
/// it is heard: its batches are taken from the start, and none is refused. What it signed before
/// the relay was heard still went, and arrived late, held as possession: no clock decides what a
/// feeder sends. When NTP steps its clock to the real time nothing changes, since it never
/// signed by it.
#[tokio::test]
async fn a_pi_started_before_ntp_is_taken_from_the_start_and_never_refused() -> Result {
    let offset = Arc::new(AtomicI64::new(-100_000));
    let running = running(host(&offset)).await?;
    let before = station_until(&running, "taken before NTP", |station| station.batches > 5).await?;
    assert_eq!(one_session(&running)?, 1);
    let held = unusable(&running);
    offset.store(0, Ordering::Relaxed);
    let after = station_until(&running, "taken after the step", |station| {
        station.batches > before.batches + 5
    })
    .await?;
    // Nothing late since its relay was heard: only what it signed before, if anything. And
    // nothing after NTP's step unusable: it never signed by the clock that stepped.
    assert_eq!(after.late_batches, before.late_batches);
    assert_eq!(unusable(&running), held);
    assert_eq!(one_session(&running)?, 1);
    Ok(())
}

/// A feeder in step whose host's clock steps forward 100 s (a clock set by hand, a bad NTP
/// answer): zero refusals, nothing late, its batches taken all through.
#[tokio::test]
async fn a_feeder_whose_host_clock_steps_forward_is_never_refused() -> Result {
    let offset = Arc::new(AtomicI64::new(0));
    let running = running(host(&offset)).await?;
    let before = station_until(&running, "taken in step", |station| station.batches > 2).await?;
    let held = unusable(&running);
    offset.store(100_000, Ordering::Relaxed);
    station_until(&running, "taken after the step", |station| {
        station.batches > before.batches + 5
    })
    .await?;
    let after = running.hub.station(&running.feeder).ok_or("no station")?;
    assert_eq!(after.late_batches, before.late_batches);
    // A batch signed 100 s ahead is never late, only ahead: none was.
    assert_eq!(unusable(&running), held);
    assert_eq!(one_session(&running)?, 1);
    Ok(())
}

/// A relay whose host's clock steps, either way, by 100 s (its judging clock moving without its
/// monotonic one): it ends nothing and refuses no one. It counts the step and states its clock
/// again to its feeder. The feeder, whose own clock is unsynced and so no source, follows its one
/// configured relay (RFC-0171 §3.6); what it signed by the clock before the step is held, unused
/// if the step put it outside the window, and its one session goes on. When the relay's clock
/// steps back, the same session is taken again. Before, the relay slewed a step in the process
/// and ended on one that stayed, for its supervisor to start it again.
#[tokio::test]
async fn a_relay_whose_clock_steps_ends_nothing_and_refuses_no_one() -> Result {
    for step_ms in [100_000_i64, -100_000] {
        let offset_ms = Arc::new(AtomicI64::new(0));
        let started = Instant::now();
        let base = tally_feed::source::wall_ms();
        let clock = {
            let offset = Arc::clone(&offset_ms);
            tally_relay::clock::RelayClock::scripted_apart(
                Arc::new(move || {
                    tally_feed::source::wall_ms()
                        .saturating_add_signed(offset.load(Ordering::SeqCst))
                }),
                Arc::new(move || {
                    base + u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
                }),
            )
        };
        let running = running_on(
            Hub::on(8, clock, Deadlines::RELAY),
            host(&Arc::new(AtomicI64::new(0))),
        )
        .await?;
        let before =
            station_until(&running, "taken in step", |station| station.batches > 2).await?;
        offset_ms.store(step_ms, Ordering::SeqCst);
        // Stated again: the step is counted, and nothing is refused meanwhile.
        tokio::time::timeout(HANG, async {
            while running.hub.clock().steps() == 0 {
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .map_err(|_| format!("{step_ms}: the step was never counted"))?;
        assert_eq!(one_session(&running)?, 1, "{step_ms}");
        offset_ms.store(0, Ordering::SeqCst);
        let after = running.hub.station(&running.feeder).ok_or("no station")?;
        station_until(&running, "taken after the step back", |station| {
            station.batches > after.batches.max(before.batches) + 5
        })
        .await?;
        assert_eq!(running.hub.clock().steps(), 2, "{step_ms}");
        assert_eq!(one_session(&running)?, 1, "{step_ms}");
    }
    Ok(())
}
