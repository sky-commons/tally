//! The relay under load: started here (`spawn`), or one already running; its CPU and memory read
//! from `/proc` (`Sample`), and the feeders it admitted and turned away from its stats listener
//! (`admission`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tally_wire::{Identity, RelayAddress};

/// A relay this harness started, killed when dropped.
pub struct Spawned {
    child: Child,
    pub address: RelayAddress,
    pub stats: String,
    pub log: PathBuf,
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
    } = how;
    let (mlat, fit) = (*mlat, *fit);
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
        let memory = fitted_memory(bin, &args, feeders)?;
        eprintln!(
            "tally-load: the relay's --memory is {memory} bytes, what {feeders} feeders need"
        );
        args.extend(["--memory".into(), memory.to_string()]);
    }
    let log = state_dir.join("relay.log");
    let output =
        std::fs::File::create(&log).map_err(|error| format!("{}: {error}", log.display()))?;
    let errors = output.try_clone().map_err(|error| error.to_string())?;
    let mut command = Command::new(bin);
    // SAFETY: between fork and exec only `prctl` runs, which is async-signal-safe and touches no
    // memory of the parent's.
    unsafe {
        command.pre_exec(|| {
            // The relay dies with the harness, however the harness ends (an interrupt included),
            // so no load test leaves a relay behind.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
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
/// (`Budget::memory_for`), as an operator sizing a deploy for them reads it.
fn fitted_memory(bin: &Path, args: &[String], feeders: usize) -> Result<u64, String> {
    let output = Command::new(bin)
        .arg("check")
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
}

impl Charged {
    /// What its base and stores are charged together.
    pub fn total(&self) -> u64 {
        self.base + self.held
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
    let rooms: u64 = [
        "oversize",
        "connection_buffers",
        "member_links",
        "parity_assembly",
    ]
    .iter()
    .map(|room| held(budget.get(room)))
    .sum();
    Ok(Charged {
        base: budget
            .get("base")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        held: stores + rooms,
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
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for the call to fill and to read.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if limit.rlim_cur < limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
    }
    Ok(limit.rlim_cur)
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

/// What a relay hosting MLAT says of its window steps' clock fits (`GET /mlat`, `steps_total`):
/// the clock fits tried and those of them that failed, since it started, and why the last failed.
#[derive(Clone, Debug, Default)]
pub struct Fits {
    /// Every fit tried, failed or not.
    pub fits: u64,
    pub unfitted: u64,
    /// Clocks the fits dropped as cut off from their gauge (`disconnected`).
    pub disconnected: u64,
    pub steps: u64,
    pub reason: Option<String>,
}

impl Fits {
    /// The share of the fits tried between `before` and this that failed, if any were tried. The
    /// relay's `fits` counts every fit tried, those that failed among them (`unfitted`,
    /// `tally_mlat::window`), so the share is `unfitted / fits`. Before, it was taken over
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
        steps: json
            .get("steps")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        reason: json
            .get("last_step")
            .and_then(|last| last.get("unfitted_reason"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
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
