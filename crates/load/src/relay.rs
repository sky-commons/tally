//! The relay under load: started here (`spawn`), or one already running; its CPU and memory read
//! from `/proc` (`Sample`), and the feeders it admitted and turned away from its stats listener
//! (`admission`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tally_wire::{Identity, RelayAddress};

/// A relay this harness started, killed when dropped, with the ClockBound segment its judging
/// clock is bounded by (`--clock-bound`), kept fresh while it runs.
pub struct Spawned {
    child: Child,
    pub address: RelayAddress,
    pub stats: String,
    pub log: PathBuf,
    /// Kept fresh until the relay is dropped.
    _clock: ClockSegment,
}

/// The bound the run's segment states: a synchronised clock within a millisecond, as ClockBound
/// says of a host whose chrony tracks its reference closely.
pub const SEGMENT_BOUND_NS: i64 = 1_000_000;
/// How often the segment is written again, and how long each writing holds: ClockBound's daemon
/// writes its segment every second, each sample void some seconds on, so a writer that stops is a
/// clock that stops judging, never one that judges on.
const SEGMENT_EVERY: Duration = Duration::from_millis(500);
const SEGMENT_VOID_AFTER_S: i64 = 10;

/// A ClockBound segment the harness writes for its relay, as ClockBound's daemon writes one
/// (`clock_bound_shm::ShmWriter`): synchronised within [`SEGMENT_BOUND_NS`], sampled now, written
/// again every [`SEGMENT_EVERY`] until dropped. Without it a load host with no ClockBound starts a
/// relay that judges no time, signs nothing and holds every batch as possession: what a run
/// measured then was a relay that did none of its work.
pub struct ClockSegment {
    pub path: PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ClockSegment {
    /// The segment at `path`, written now and kept fresh on a thread of its own (the writer maps
    /// the segment and is not `Send`, so that thread makes it, and this waits for its first
    /// writing).
    pub fn start(path: &Path) -> Result<Self, String> {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = std::sync::Arc::clone(&stop);
        let (ready, written) = std::sync::mpsc::channel();
        let at = path.to_owned();
        std::thread::Builder::new()
            .name("tally-load-clockbound".to_owned())
            .spawn(move || {
                let first = clock_bound_shm::ShmWriter::new(&at)
                    .map_err(|error| format!("{}: {error}", at.display()))
                    .and_then(|mut writer| write_segment(&mut writer).map(|()| writer));
                let mut writer = match first {
                    Ok(writer) => {
                        let _ = ready.send(Ok(()));
                        writer
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(SEGMENT_EVERY);
                    if let Err(error) = write_segment(&mut writer) {
                        eprintln!("tally-load: the ClockBound segment: {error}");
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        written
            .recv()
            .map_err(|_| "the ClockBound segment's writer ended".to_owned())??;
        Ok(Self {
            path: path.to_owned(),
            stop,
        })
    }
}

impl Drop for ClockSegment {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// One writing of the segment: synchronised within [`SEGMENT_BOUND_NS`], sampled now on the
/// clock ClockBound's client reads, void [`SEGMENT_VOID_AFTER_S`] on.
fn write_segment(writer: &mut clock_bound_shm::ShmWriter) -> Result<(), String> {
    use clock_bound_shm::ShmWrite as _;
    let now = clock_bound_shm::common::clock_gettime_safe(clock_bound_shm::common::CLOCK_MONOTONIC)
        .map_err(|error| format!("{error:?}"))?;
    let bound = clock_bound_shm::ClockErrorBound::new(
        now,
        now + nix::sys::time::TimeSpec::new(SEGMENT_VOID_AFTER_S, 0),
        SEGMENT_BOUND_NS,
        0,
        50_000,
        clock_bound_shm::ClockStatus::Synchronized,
        false,
    );
    writer.write(&bound);
    Ok(())
}

impl Spawned {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Whether it is still running; `Some` with how it ended if not.
    pub fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.to_string()),
            Ok(None) => None,
            Err(error) => Some(error.to_string()),
        }
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A free port on `host`: bound and released, for a child to take.
fn free_port(host: &str) -> Result<u16, String> {
    let listener = TcpListener::bind((host, 0)).map_err(|error| format!("{host}: {error}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

/// Starts `bin` as a relay for `feeders`, with a fresh key, listening at `listen` (port 0: a free
/// one) and serving its stats on loopback, hosting MLAT (`mlat`) or not (`--no-mlat`); `extra`
/// follows the harness's own arguments, so it overrides them. Returns once it accepts connections.
pub fn spawn(
    how: &crate::config::Spawn,
    feeders: usize,
    state_dir: &Path,
) -> Result<Spawned, String> {
    let crate::config::Spawn {
        bin,
        listen,
        max_upload,
        args: extra,
        mlat,
        fit,
        cores,
    } = how;
    let (mlat, fit, cores) = (*mlat, *fit, *cores);
    std::fs::create_dir_all(state_dir)
        .map_err(|error| format!("{}: {error}", state_dir.display()))?;
    let identity = Identity::generate().map_err(|error| error.to_string())?;
    let key_file = state_dir.join("relay.key");
    std::fs::write(&key_file, format!("{}\n", identity.to_base64()))
        .map_err(|error| format!("{}: {error}", key_file.display()))?;
    let (host, port) = listen
        .rsplit_once(':')
        .ok_or_else(|| format!("--relay-listen {listen}: expected HOST:PORT"))?;
    let port = match port {
        "0" => free_port(host)?,
        port => port
            .parse()
            .map_err(|_| format!("--relay-listen {listen}: bad port"))?,
    };
    let listen = format!("{host}:{port}");
    let stats = format!("127.0.0.1:{}", free_port("127.0.0.1")?);
    // Its judging clock is bounded by the run's own ClockBound segment, kept fresh while it runs.
    let clock = ClockSegment::start(&state_dir.join("clockbound-shm0"))?;
    // A feeder holds its session and, while it probes, a probe's; probes are brief, so a fifth
    // more than the feeders holds them (20,000 feeders: 20,000 held and none refused at 24,000,
    // RFC-0181 "The world baseline"). The relay plans Noise buffers for every connection the cap
    // allows (`Budget::connection_buffers`), so twice the feeders cost it 13 GB it never used.
    let connections = (feeders + feeders / 5 + 1024).to_string();
    let mut args: Vec<String> = vec![
        "--key".into(),
        key_file.display().to_string(),
        "--max-upload".into(),
        max_upload.into(),
        "--listen".into(),
        listen.clone(),
        "--stats-listen".into(),
        stats.clone(),
        "--max-connections".into(),
        connections.clone(),
        "--max-connections-per-address".into(),
        connections,
        "--clock-bound".into(),
        clock.path.display().to_string(),
    ];
    if !mlat {
        args.push("--no-mlat".into());
    } else {
        // Hosting MLAT solves nothing until the relay is chosen for an area (`Selection::solved`),
        // and it is chosen only among the relays that offer it: so it takes the two cells at the
        // centres of the simulation's clusters and advertises itself, under its own key, at the
        // address its feeders reach it by.
        let reach = match host {
            "0.0.0.0" | "[::]" | "::" => format!("127.0.0.1:{port}"),
            _ => listen.clone(),
        };
        for cell in CLUSTER_CELLS {
            args.extend(["--area".into(), (*cell).into()]);
        }
        args.extend([
            "--advertise".into(),
            format!("{reach}={}", identity.public()),
        ]);
    }
    args.extend(extra.iter().cloned());
    if fit {
        // A relay refuses memory that admits no feeder (`Budget::check`), so a run of none is
        // fitted to the least a relay starts with, one: its base is what is measured. Before, a
        // run of none was fitted to none and the relay refused to start.
        let fitted = feeders.max(1);
        let memory = fitted_memory(bin, &args, fitted, cores)?;
        eprintln!("tally-load: the relay's --memory is {memory} bytes, what {fitted} feeders need");
        args.extend(["--memory".into(), memory.to_string()]);
    }
    let log = state_dir.join("relay.log");
    let output =
        std::fs::File::create(&log).map_err(|error| format!("{}: {error}", log.display()))?;
    let errors = output.try_clone().map_err(|error| error.to_string())?;
    let mut command = Command::new(bin);
    // The relay dies with the harness, however the harness ends (an interrupt included), so no
    // load test leaves a relay behind.
    crate::os::die_with_parent(&mut command);
    if let Some(cores) = cores {
        // The relay on the first cores, the harness (its feeders, its simulation, its subscriber)
        // on the rest, so neither measures the other's work.
        let all = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        if cores >= all {
            return Err(format!(
                "--relay-cores {cores}: this host has {all}, and the harness needs one"
            ));
        }
        crate::os::run_on(&mut command, 0..cores);
        crate::os::keep_to(cores..all)?;
    }
    let child = command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors)
        .spawn()
        .map_err(|error| format!("{}: {error}", bin.display()))?;
    // Feeders reach it at a host they can connect to: a wildcard listen is reached on loopback.
    let reach = match host {
        "0.0.0.0" | "[::]" | "::" => format!("127.0.0.1:{port}"),
        _ => listen.clone(),
    };
    let mut spawned = Spawned {
        child,
        address: RelayAddress {
            key: identity.public(),
            address: reach.clone(),
        },
        stats,
        log,
        _clock: clock,
    };
    let reach: SocketAddr = reach
        .parse()
        .map_err(|_| format!("{reach}: not an address"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect_timeout(&reach, Duration::from_secs(1)).is_err() {
        if let Some(status) = spawned.exited() {
            return Err(format!(
                "the relay exited ({status}); see {}",
                spawned.log.display()
            ));
        }
        if Instant::now() > deadline {
            return Err(format!("the relay never listened at {reach}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(spawned)
}

/// The least `--memory` that admits `feeders` to the relay `bin` started with `args`: what
/// `tally-relay check` says it holds before any feeder and reserves for each
/// (`Budget::memory_for`), as an operator sizing a deploy for them reads it: on `cores` cores where
/// it will run on those (`--relay-cores`), as a deploy's check names its unit's.
fn fitted_memory(
    bin: &Path,
    args: &[String],
    feeders: usize,
    cores: Option<usize>,
) -> Result<u64, String> {
    let mut command = Command::new(bin);
    command.arg("check");
    if let Some(cores) = cores {
        command.args(["--cores".to_owned(), cores.to_string()]);
    }
    let output = command
        .args(args)
        .output()
        .map_err(|error| format!("{} check: {error}", bin.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} check refused: {}",
            bin.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let plan = String::from_utf8_lossy(&output.stdout);
    let line = |name: &str| -> Result<u64, String> {
        plan.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
            .ok_or_else(|| format!("{} check printed no {name}", bin.display()))
    };
    // The connections' cost out of what MLAT's share leaves, the seats' out of the share
    // (`Budget::memory_for`): the least that admits `feeders` connections and, hosting, a seat
    // for each.
    let connections = line("per-connection")? * feeders as u64;
    let share = line("mlat-share-percent")?;
    let total = if share == 0 {
        connections
    } else {
        let seats = line("per-seat")? * feeders as u64;
        (connections * 100)
            .div_ceil(100 - share)
            .max((seats * 100).div_ceil(share))
            + 200
    };
    Ok(line("before-feeders")? + total)
}

/// The cells at the centres of the simulation's two clusters, which a relay hosting MLAT under the
/// harness takes (`spawn`).
const CLUSTER_CELLS: &[&str] = &["801ffffffffffff", "8027fffffffffff"];

/// What the relay's peak resident memory came to beside the memory it is budgeted (`GET /memory`)
/// and the headroom it keeps below the memory it runs in (`budget::headroom_for`): the
/// allocator's free pages not yet returned, stacks and the kernel's socket buffers that no store
/// charges. Past the two, a relay sized for its load is throttled at `memory.high` or killed at
/// `memory.max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit {
    pub peak_bytes: u64,
    pub budget_bytes: u64,
    pub headroom_bytes: u64,
}

impl Fit {
    /// Whether the peak stayed within the budget and the headroom.
    pub fn within(&self) -> bool {
        self.peak_bytes <= self.budget_bytes + self.headroom_bytes
    }

    /// The peak beyond the budget, which the headroom must hold.
    pub fn over_budget(&self) -> u64 {
        self.peak_bytes.saturating_sub(self.budget_bytes)
    }
}

/// What the relay's stores and base are charged now (`GET /memory`): its base and every gauge's
/// bytes held, beside which its resident memory is what the allocator keeps and what no store
/// charges, which its headroom holds (`budget::headroom_for`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Charged {
    pub base: u64,
    pub held: u64,
    /// What the allocator serves now, in its arenas and mapped apart (`allocator.in_use`,
    /// `allocator.mapped`).
    pub in_use: u64,
    pub mapped: u64,
}

impl Charged {
    /// What its base and stores are charged together.
    pub fn total(&self) -> u64 {
        self.base + self.held
    }

    /// What the allocator serves beyond every store's charge: what the relay's base holds, which
    /// the measured base and its margin must cover (`within_base`).
    pub fn unplanned(&self) -> i64 {
        (self.in_use + self.mapped) as i64 - self.held as i64
    }

    /// Whether what no store charges is within what the base plans for it: the measured idle
    /// relay and its margin (`budget::MEASURED_IDLE_BYTES`, `budget::BASE_MARGIN_BYTES`). Past
    /// them a table grows that no store charges, and the base plans for none.
    pub fn within_base(&self) -> bool {
        self.unplanned()
            <= (tally_relay::budget::MEASURED_IDLE_BYTES + tally_relay::budget::BASE_MARGIN_BYTES)
                as i64
    }
}

/// What the relay may be resident at most, having been charged at most `peak` bytes for its base
/// and stores so far: those, and its headroom for them (`budget::headroom_for`). An allocator keeps
/// what was once in use for reuse, so what the relay holds follows the most it was charged, not
/// what it is charged now; past this it holds more than its plan keeps room for.
pub fn resident_allowed(peak: u64) -> u64 {
    peak + tally_relay::budget::headroom_for(usize::try_from(peak).unwrap_or(usize::MAX)) as u64
}

pub fn charged(stats: &str) -> Result<Charged, String> {
    let body = get(stats, "/memory")?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    let budget = json.get("budget").ok_or("no budget")?;
    let held = |gauge: Option<&serde_json::Value>| {
        gauge
            .and_then(|gauge| gauge.get("held"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    let stores: u64 = budget
        .get("stores")
        .and_then(serde_json::Value::as_array)
        .map_or(0, |stores| {
            stores.iter().map(|store| held(Some(store))).sum()
        });
    let rooms: u64 = ["connection_buffers", "member_links", "parity_assembly"]
        .iter()
        .map(|room| held(budget.get(room)))
        .sum();
    let allocator = |name: &str| {
        budget
            .get("allocator")
            .and_then(|allocator| allocator.get(name))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    Ok(Charged {
        base: budget
            .get("base")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        held: stores + rooms,
        in_use: allocator("in_use"),
        mapped: allocator("mapped"),
    })
}

/// What the relay did of its work over a run (`GET /memory`, `/products`, `/mlat`): what a run's
/// figures are worth only beside. A relay whose clock never judged holds every record as
/// possession and uses none, so its products and strike tables hold nothing and its memory is
/// not a working relay's (before 2026-10-23, every run on a host without ClockBound).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Worked {
    /// Records held while the relay could judge nothing.
    pub unjudged_records: u64,
    pub regional_signed: u64,
    /// What the relay's own strike tables hold (`Store::OwnStrikes`).
    pub own_strikes_held: u64,
    /// Where MLAT is hosted: what its plan guarantees (`MlatWorked`) and what it made of the load.
    pub mlat: Option<MlatWorked>,
}

/// What hosted MLAT did over a run (`GET /mlat`, and standing's part of `GET /memory`): what its
/// plan guarantees of any load, and what it made of this one. The raw pool is planned at what a
/// holder keeps of each seat at most (`arrived::Rates::MEASURED`), and what it refuses past its
/// bytes is counted (`batches_refused`): the positions and the records standing took are reported,
/// never asserted, since a run's timing moves them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlatWorked {
    pub steps: u64,
    /// Batches the engine took in, and those its pool refused whole past a cap.
    pub ingested: u64,
    pub batches_refused: u64,
    /// Clock fits tried (`steps_total.fits`).
    pub fits: u64,
    /// What a host within its plan never does: its tables past the `Arrived` store
    /// (`arrived_over`), a step's records refused for their stores (`overflowed`), a step not run
    /// for its working set (`steps_unreserved`).
    pub arrived_over: u64,
    pub overflowed: u64,
    pub steps_unreserved: u64,
    pub positions: u64,
    pub standing_taken: u64,
    pub standing_forgotten: u64,
    /// The seats its plan gives it (`seat_limit`) and those it held at the end, under its own
    /// cuts (`seats_taken`): what `//crates/load:plan_seats` holds within 15% of each other.
    pub seat_limit: u64,
    pub seats_taken: u64,
}

impl Worked {
    /// What the run did not do of its work, with feeders sending and, where hosted, MLAT: each
    /// a reason its figures are not a working relay's. None for a run of no feeder but that its
    /// clock judged. MLAT is held to what its plan guarantees whatever the timing: it stepped and
    /// took raw in, it tried clock fits wherever the simulation made `multilaterable`
    /// transmissions (heard by enough receivers to solve; a few feeders stand at the benchmark's
    /// density at each cluster's centre, `traffic::WORLD_FEEDERS`, so any more than a fix takes
    /// hear most in common), and no store of it went past its plan (standing forgot nothing for
    /// room, the engine's tables stayed within `Arrived`, no step's records or working set were
    /// refused). What it published is not held (`MlatWorked`): before, a run was failed for no
    /// positions, which a pool refusing its share by arrival order made pass or fail by timing.
    pub fn shortfalls(&self, feeders: usize, multilaterable: u64) -> Vec<String> {
        let mut short = Vec::new();
        if self.unjudged_records > 0 {
            short.push(format!(
                "{} records were held unjudged: the relay's clock did not judge",
                self.unjudged_records
            ));
        }
        if feeders == 0 {
            return short;
        }
        if self.regional_signed == 0 {
            short.push("no regional product was signed".to_owned());
        }
        if self.own_strikes_held == 0 {
            short.push("the relay's own strike tables held nothing".to_owned());
        }
        if let Some(mlat) = self.mlat {
            if mlat.steps == 0 || mlat.ingested == 0 {
                short.push(format!(
                    "MLAT stepped {} windows and took in {} batches",
                    mlat.steps, mlat.ingested
                ));
            }
            if multilaterable > 0 && mlat.fits == 0 {
                short.push(format!(
                    "MLAT tried no clock fit of {multilaterable} transmissions heard by enough \
                     receivers to solve"
                ));
            }
            if mlat.arrived_over + mlat.overflowed + mlat.steps_unreserved > 0 {
                short.push(format!(
                    "MLAT went past its plan: its tables past the arrived store {} times, {} \
                     steps' records refused, {} steps not run for their working set",
                    mlat.arrived_over, mlat.overflowed, mlat.steps_unreserved
                ));
            }
            if mlat.standing_forgotten > 0 {
                short.push(format!(
                    "standing forgot {} for room: its plan (`standing::Caps::of`) is short of \
                     what the seats bring",
                    mlat.standing_forgotten
                ));
            }
        }
        short
    }
}

/// What the relay at `stats` did (`Worked`): MLAT's part where it serves `/mlat` (it hosts MLAT).
pub fn worked(stats: &str) -> Result<Worked, String> {
    let json = |path: &str| -> Result<serde_json::Value, String> {
        serde_json::from_str(&get(stats, path)?).map_err(|error| format!("{path}: {error}"))
    };
    let number =
        |value: Option<&serde_json::Value>| value.and_then(serde_json::Value::as_u64).unwrap_or(0);
    let memory = json("/memory")?;
    let products = json("/products")?;
    let own_strikes_held = memory
        .get("budget")
        .and_then(|budget| budget.get("stores"))
        .and_then(serde_json::Value::as_array)
        .and_then(|stores| {
            stores.iter().find(|store| {
                store.get("store").and_then(serde_json::Value::as_str) == Some("own_strikes")
            })
        })
        .and_then(|store| store.get("held"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let mlat = if let Ok(report) = json("/mlat") {
        let standing = memory.get("standing");
        let total = |name: &str| number(report.get("steps_total").and_then(|t| t.get(name)));
        Some(MlatWorked {
            steps: number(report.get("steps")),
            ingested: number(report.get("ingested")),
            batches_refused: number(report.get("batches_refused")),
            fits: total("fits"),
            arrived_over: number(report.get("arrived_over")),
            overflowed: number(report.get("overflowed")),
            steps_unreserved: number(report.get("steps_unreserved")),
            positions: total("positions"),
            standing_taken: number(standing.and_then(|standing| standing.get("taken"))),
            standing_forgotten: number(standing.and_then(|standing| standing.get("forgotten"))),
            seat_limit: number(report.get("seat_limit")),
            seats_taken: number(report.get("seats_taken")),
        })
    } else {
        None
    };
    Ok(Worked {
        unjudged_records: number(memory.get("unjudged_records")),
        regional_signed: number(products.get("regional_signed")),
        own_strikes_held,
        mlat,
    })
}

/// The relay's memory budget (`GET /memory`, the budget's `memory`).
pub fn budget(stats: &str) -> Result<u64, String> {
    let body = get(stats, "/memory")?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    json.get("budget")
        .and_then(|budget| budget.get("memory"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{stats}/memory: no budget memory"))
}

/// A process's CPU and memory at one moment.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub at: Instant,
    /// User and system time, in clock ticks.
    pub ticks: u64,
    pub rss_kib: u64,
    pub peak_rss_kib: u64,
    pub threads: u64,
    pub fds: u64,
}

impl Sample {
    /// `pid`'s, or this process's (`None`).
    pub fn read(pid: Option<u32>) -> Result<Self, String> {
        let dir = match pid {
            Some(pid) => PathBuf::from(format!("/proc/{pid}")),
            None => PathBuf::from("/proc/self"),
        };
        let at = Instant::now();
        let stat = std::fs::read_to_string(dir.join("stat"))
            .map_err(|error| format!("{}: {error}", dir.display()))?;
        // The command name is in parentheses and may hold spaces: the fields follow the last ')'.
        let fields: Vec<&str> = stat
            .rsplit_once(')')
            .map(|(_, rest)| rest.split_whitespace().collect())
            .unwrap_or_default();
        let field = |at: usize| fields.get(at).and_then(|value| value.parse::<u64>().ok());
        // After the name: state (3), ..., utime (14), stime (15), ..., num_threads (20).
        let ticks = field(11).unwrap_or(0) + field(12).unwrap_or(0);
        let threads = field(17).unwrap_or(0);
        let status = std::fs::read_to_string(dir.join("status")).unwrap_or_default();
        let kib = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
        };
        let fds = std::fs::read_dir(dir.join("fd")).map_or(0, |entries| entries.count() as u64);
        Ok(Self {
            at,
            ticks,
            rss_kib: kib("VmRSS:"),
            peak_rss_kib: kib("VmHWM:"),
            threads,
            fds,
        })
    }

    /// Cores used on average from `before` to this sample.
    pub fn cores_since(&self, before: &Self, ticks_a_second: f64) -> f64 {
        let seconds = self.at.duration_since(before.at).as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        self.ticks.saturating_sub(before.ticks) as f64 / ticks_a_second / seconds
    }
}

/// Raises this process's open file limit to its hard limit (what an unprivileged process may),
/// and returns the limit now in force. A spawned relay inherits it.
pub fn raise_open_files() -> Result<u64, String> {
    let text = |error: std::io::Error| error.to_string();
    let (soft, hard) = tally_relay::os::open_files_limit().map_err(text)?;
    if soft < hard {
        tally_relay::os::set_open_files_limit(hard, hard).map_err(text)?;
    }
    Ok(soft.max(hard))
}

/// The kernel's clock ticks a second (`getconf CLK_TCK`), 100 if it cannot be asked.
pub fn ticks_a_second() -> f64 {
    Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(100.0)
}

/// What the relay says of its feeders (`GET /egress`): admitted and connected now, and turned
/// away since it started because its upload cap could not carry them.
#[derive(Clone, Copy, Debug, Default)]
pub struct Admission {
    pub feeders: u64,
    pub refused: u64,
    pub billed_bytes: u64,
    pub loopback_bytes: u64,
}

pub fn admission(stats: &str) -> Result<Admission, String> {
    let body = get(stats, "/egress")?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    let number = |name: &str| {
        json.get(name)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    Ok(Admission {
        feeders: number("feeders"),
        refused: number("refused_feeders"),
        billed_bytes: number("billed_bytes"),
        loopback_bytes: number("loopback_bytes"),
    })
}

/// What a relay hosting MLAT says of its steps' clock fits (`GET /mlat`, `steps_total`):
/// the clock fits tried and those of them that failed, since it started, and why the last failed.
#[derive(Clone, Debug, Default)]
pub struct Fits {
    /// Every fit tried, failed or not.
    pub fits: u64,
    pub unfitted: u64,
    /// Clocks the fits dropped as cut off from their gauge (`disconnected`).
    pub disconnected: u64,
    pub steps: u64,
    /// Every step's run as the governor judges it, its taking and its stepping, summed
    /// (`steps_total.ran_ms`), and the bytes MLAT published, its clock models and its positions raw
    /// and tagged (`clock_model_bytes`, `positions_bytes`, `tagged_positions_bytes`).
    pub ran_ms: u64,
    pub published_bytes: u64,
    /// Why a fit failed: the last step's first failure, else the run's first. The last step's
    /// alone said "none" whenever its own fits passed, however many had failed before it.
    pub reason: Option<String>,
}

impl Fits {
    /// The share of the fits tried between `before` and this that failed, if any were tried. The
    /// relay's `fits` counts every fit tried, those that failed among them (`unfitted`, the
    /// engine's refits), so the share is `unfitted / fits`. Before, it was taken over
    /// `fits + unfitted`, each failure counted twice in the whole: a window where about 87% of
    /// fits failed read 45%.
    pub fn failed_since(&self, before: &Self) -> Option<f64> {
        let tried = self.fits.saturating_sub(before.fits);
        let unfitted = self.unfitted.saturating_sub(before.unfitted);
        (tried > 0).then(|| unfitted.min(tried) as f64 / tried as f64)
    }

    /// The fits that succeeded between `before` and this.
    pub fn fitted_since(&self, before: &Self) -> u64 {
        let tried = self.fits.saturating_sub(before.fits);
        tried.saturating_sub(self.unfitted.saturating_sub(before.unfitted))
    }
}

pub fn fits(stats: &str) -> Result<Fits, String> {
    let body = get(stats, "/mlat")?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    let total = json.get("steps_total");
    let number = |name: &str| {
        total
            .and_then(|total| total.get(name))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    Ok(Fits {
        fits: number("fits"),
        unfitted: number("unfitted"),
        disconnected: number("disconnected"),
        ran_ms: number("ran_ms"),
        published_bytes: number("clock_model_bytes")
            + number("positions_bytes")
            + number("tagged_positions_bytes"),
        steps: json
            .get("steps")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        reason: ["last_step", "steps_total"].iter().find_map(|step| {
            json.get(step)
                .and_then(|step| step.get("unfitted_reason"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        }),
    })
}

/// A plain HTTP/1.1 GET over loopback; the body, de-chunked.
fn get(address: &str, path: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect(address).map_err(|error| format!("{address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{address}{path}: no body"))?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!(
            "{address}{path}: {}",
            head.lines().next().unwrap_or_default()
        ));
    }
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    Ok(if chunked {
        dechunk(body)
    } else {
        body.to_owned()
    })
}

fn dechunk(mut body: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = body.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if size == 0 || rest.len() < size {
            break;
        }
        out.push_str(&rest[..size]);
        body = rest[size..].trim_start_matches("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunked_body_is_read_whole() {
        assert_eq!(dechunk("4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n"), "{\"a\":1}");
    }

    /// `fits` counts every fit tried, so 348 of 400 failed is 87%, not the 46.5% of
    /// `348 / (400 + 348)`.
    #[test]
    fn the_failure_share_is_the_failed_over_the_fits_tried() {
        let before = Fits {
            fits: 100,
            unfitted: 2,
            ..Fits::default()
        };
        let now = Fits {
            fits: 500,
            unfitted: 350,
            ..Fits::default()
        };
        assert_eq!(now.failed_since(&before), Some(0.87));
        assert_eq!(now.fitted_since(&before), 52);
        assert_eq!(before.failed_since(&before), None);
    }

    /// The relay's peak resident memory is held to its budget and the headroom,
    /// and no more.
    #[test]
    fn a_peak_past_the_budget_and_its_headroom_fails_the_run() {
        let fit = |peak_bytes| Fit {
            peak_bytes,
            budget_bytes: 1_000,
            headroom_bytes: 100,
        };
        assert!(fit(900).within());
        assert!(fit(1_100).within());
        assert_eq!(fit(1_100).over_budget(), 100);
        assert!(!fit(1_101).within());
    }

    /// A run that did not do its work says what it did not: its clock judged nothing, it signed
    /// no product, its strike tables held nothing, MLAT stepped or took in nothing, tried no fit of
    /// a solvable scene, went past its plan, or standing forgot for room. What MLAT published is
    /// never held: a pool refusing above the mean by arrival order moves it. A run of no feeder is
    /// held only to its clock.
    #[test]
    fn a_run_that_did_not_work_says_what_it_did_not_do() {
        let working = Worked {
            unjudged_records: 0,
            regional_signed: 3,
            own_strikes_held: 4_096,
            mlat: Some(MlatWorked {
                steps: 2,
                ingested: 10,
                batches_refused: 4,
                fits: 3,
                positions: 9,
                standing_taken: 40,
                ..MlatWorked::default()
            }),
        };
        assert!(working.shortfalls(8, 100).is_empty());
        assert!(Worked::default().shortfalls(0, 0).is_empty());
        let mlat = working.mlat.unwrap_or_default();
        let broken = [
            Worked {
                unjudged_records: 1,
                ..working
            },
            Worked {
                regional_signed: 0,
                ..working
            },
            Worked {
                own_strikes_held: 0,
                ..working
            },
            Worked {
                mlat: Some(MlatWorked { steps: 0, ..mlat }),
                ..working
            },
            Worked {
                mlat: Some(MlatWorked {
                    ingested: 0,
                    ..mlat
                }),
                ..working
            },
            Worked {
                mlat: Some(MlatWorked { fits: 0, ..mlat }),
                ..working
            },
            Worked {
                mlat: Some(MlatWorked {
                    arrived_over: 1,
                    ..mlat
                }),
                ..working
            },
            Worked {
                mlat: Some(MlatWorked {
                    overflowed: 1,
                    ..mlat
                }),
                ..working
            },
            Worked {
                mlat: Some(MlatWorked {
                    steps_unreserved: 1,
                    ..mlat
                }),
                ..working
            },
            Worked {
                mlat: Some(MlatWorked {
                    standing_forgotten: 1,
                    ..mlat
                }),
                ..working
            },
        ];
        for worked in broken {
            assert_eq!(worked.shortfalls(8, 100).len(), 1, "{worked:?}");
        }
        // No positions, nothing standing took and batches refused by the pool are no shortfall.
        let refused = Worked {
            mlat: Some(MlatWorked {
                positions: 0,
                standing_taken: 0,
                batches_refused: 1_000,
                ..mlat
            }),
            ..working
        };
        assert!(refused.shortfalls(8, 100).is_empty());
        // With nothing heard by enough receivers to solve, MLAT is not asked to fit.
        let unsolvable = Worked {
            mlat: Some(MlatWorked { fits: 0, ..mlat }),
            ..working
        };
        assert!(unsolvable.shortfalls(8, 0).is_empty());
        assert_eq!(
            Worked {
                unjudged_records: 1,
                ..Worked::default()
            }
            .shortfalls(0, 0)
            .len(),
            1
        );
    }

    /// What the allocator serves beyond every store's charge is held to the measured base and
    /// its margin.
    #[test]
    fn what_no_store_charges_is_held_to_the_measured_base() {
        let base = (tally_relay::budget::MEASURED_IDLE_BYTES
            + tally_relay::budget::BASE_MARGIN_BYTES) as u64;
        let charged = |in_use| Charged {
            base: 0,
            held: 100 << 20,
            in_use,
            mapped: 10 << 20,
        };
        assert!(charged((90 << 20) + base).within_base());
        assert!(!charged((90 << 20) + base + 1).within_base());
        assert_eq!(charged(0).unplanned(), -(90 << 20));
    }

    /// The segment the harness writes reads, through the reader the relay's `--clock-bound`
    /// opens, as a synchronised clock within its bound: the run's relay judges.
    #[test]
    fn the_clock_segment_reads_as_a_synchronised_clock() -> Result<(), String> {
        let dir = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("clock-segment");
        std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
        let segment = ClockSegment::start(&dir.join("shm0"))?;
        let path = segment.path.display().to_string();
        let vmclock = dir.join("vmclock0").display().to_string();
        let reader = tally_wire::clock_bound::Reader::at(&path, &vmclock);
        let bound_ms = reader
            .read()
            .map_err(|why| format!("the segment judged nothing: {why:?}"))?;
        assert!(bound_ms <= 2, "a bound of {bound_ms} ms");
        Ok(())
    }

    /// What the relay may hold follows the most it was charged.
    #[test]
    fn the_resident_memory_allowed_follows_the_most_charged() {
        let headroom = tally_relay::budget::HEADROOM_BYTES as u64;
        assert_eq!(resident_allowed(0), headroom);
        let gib = 1u64 << 30;
        assert_eq!(
            resident_allowed(4 * gib),
            4 * gib + headroom + 4 * gib * tally_relay::budget::ALLOCATOR_PERCENT as u64 / 100
        );
    }

    #[test]
    fn this_process_reads_itself() -> Result<(), String> {
        let sample = Sample::read(None)?;
        assert!(sample.rss_kib > 0);
        assert!(sample.threads >= 1);
        assert!(sample.fds >= 1);
        Ok(())
    }
}
