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
/// one) and serving its stats on loopback; `extra` follows the harness's own arguments, so it
/// overrides them. Returns once it accepts connections.
pub fn spawn(
    bin: &Path,
    listen: &str,
    max_upload: &str,
    extra: &[String],
    feeders: usize,
    state_dir: &Path,
) -> Result<Spawned, String> {
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
    // A feeder holds its session and, while it probes, a probe's.
    let connections = (2 * feeders + 1024).to_string();
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
        .arg("--key")
        .arg(&key_file)
        .args(["--max-upload", max_upload])
        .args(["--listen", &listen])
        .args(["--stats-listen", &stats])
        .args(["--max-connections", &connections])
        .args(["--max-connections-per-address", &connections])
        .args(["--mlat-threads", "0"])
        .args(extra)
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

    #[test]
    fn this_process_reads_itself() -> Result<(), String> {
        let sample = Sample::read(None)?;
        assert!(sample.rss_kib > 0);
        assert!(sample.threads >= 1);
        assert!(sample.fds >= 1);
        Ok(())
    }
}
