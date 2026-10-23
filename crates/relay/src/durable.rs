//! What a relay keeps across a restart (RFC-0171 §3.6): the one thing that lets a restarted
//! relay forward nothing it forwarded before. A strike table forgets what it took once its
//! records can no longer be used, and remembers the most it may have forgotten (its floor,
//! `strikes::Strikes`), so a record is new only above that floor. A restart forgets everything
//! in memory, so the floor is what must outlive the process: the replay cache of Kerberos
//! (RFC 4120 §3.2.3) and the strike register of TLS 1.3 (RFC 8446 §8.2) keep the same promise
//! the same way.
//!
//! **One state format, checked before it is trusted.** Every file the relay keeps (a lease, a
//! stop's dump, a table's checkpoint and its log) is one sealed form ([`StateDir::seal`]): a
//! format version, what kind of file it is, the key it was written under (named by a keyed hash
//! of a constant, so a file of another key is known at once), its layout (the table names and
//! how many of each, the ingest shards among them), the run that wrote it, its body, and a keyed
//! code over all of it (SipHash-2-4 under the directory's key, `tally_wire::decoded::keyed`). A
//! file is written as a stock checkpoint is: to a file beside it, synced, renamed over it, and
//! the directory synced, so it is the old one or the new one whole. A file that is missing, cut,
//! changed, of another key, version, kind or layout is never trusted: its table starts at the
//! fallback floor, never with no floor.
//!
//! - **A lease of signed time** ([`Lease`]). Each table keeps on disk an upper bound `H` of every
//!   signed time it has used: `H = t + L` (`tally_wire::budget::LEASE`, `lease_bound`), written
//!   and synced before the first record signed past the last `H` is used. It is renewed ahead, off
//!   the path that uses records, once a record comes within half a lease of it
//!   (`tally_wire::budget::lease_renews`, standard lease renewal), so a
//!   take waits on a write only when renewal fell behind. After a restart the table's floor is
//!   `H` (the higher of `H` and the fallback floor only when `H` is further ahead of the synced
//!   clock than a quick restart leaves it, [`Lease::begin`]), so nothing it used before is new
//!   again; the cost is the records signed in at most
//!   `L` above the last one used.
//! - **A checkpoint and a log, for tables of few records** ([`Log`]): a floor would suppress
//!   records signed long before they are sent (feeder figures, signed as of their hour), so such
//!   a table keeps its fingerprints themselves, as a replay cache does: each one used is appended
//!   to the log and synced first (one sync a record), and the log is folded into a fresh
//!   checkpoint once it outgrows the table, so neither grows without bound.
//! - **A dump on a graceful stop** (`Hub::stop`): every table's fingerprints and floor, read back
//!   once at the next start when every lease still holds the bound, and the run, it was written
//!   beside. It is consumed before it is used (renamed to a consumed name and the directory
//!   synced, [`StateDir::consume`]), and one that cannot be consumed is not used, so no dump is
//!   ever read back twice.
//! - **No state at all** ([`Durable::Fresh`]: no directory given, or any file above not
//!   trusted): the table starts at the fallback floor, `J + S + SKEW` once the clock is synced
//!   (`tally_wire::budget::FALLBACK_FLOOR`): the old process may have used records up to `S` ahead of its
//!   clock, which may have been `SKEW` ahead of this one's. RFC 8446 §8.2's rule for a server with
//!   no state. Its cost is that long with nothing new used here (possession still flows, so nobody
//!   is blamed).
//!
//! **One writer.** Only the process that holds the directory's lock writes in it: it takes an
//! exclusive `flock(2)` on `lock` as it opens the directory and holds it for its life, as
//! PostgreSQL and etcd hold theirs, and a relay that cannot take it does not start
//! ([`StateDir::open`]). Two relays on one volume (a rolling update's old and new pod) would
//! otherwise both write leases and dumps, each below what the other used.
//!
//! The directory is the systemd unit's `StateDirectory=tally-relay` (`$STATE_DIRECTORY`) or
//! `--state-dir`; on Kubernetes a small persistent volume with one writer, whose deployment
//! replaces its pod with the `Recreate` strategy. A state directory must never be restored from a
//! backup: an old lease is a floor too low.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

use tally_wire::FingerprintKey;
use tally_wire::decoded::keyed;

use tally_wire::budget::{LEASE_REACH, lease_bound, lease_renews};
use tally_wire::clocks::Judged;

/// How long the renewer sleeps when nothing asked it: its bound on noticing a directory gone.
const RENEWER_IDLE: Duration = Duration::from_millis(100);

/// A table's log is folded into a fresh checkpoint once it holds this many records and more than
/// twice the fingerprints its table holds: the log costs a sync a record and never grows past
/// what the table holds by more than this.
pub const LOG_COMPACT_RECORDS: u64 = 256;

/// What a relay keeps across a restart.
#[derive(Clone, Debug)]
pub enum Durable {
    /// Nothing, and nothing assumed: every table starts with no floor and needs no clock. A test's
    /// hub, which is never restarted, or is restarted by the test with a directory of its own.
    Off,
    /// No state: every table starts at the fallback floor (`tally_wire::budget::FALLBACK_FLOOR`) once the
    /// clock is synced.
    Fresh,
    /// A state directory: leases, a stop's dump, and the checkpoints and logs of the tables of few
    /// records.
    Dir(Arc<StateDir>),
}

/// What a state file is: part of what it is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Lease = 1,
    Dump = 2,
    Table = 3,
    Log = 4,
}

/// The first bytes of every state file.
const MAGIC: [u8; 8] = *b"tallyst\x01";

/// The state format's version: a file of another is not trusted.
pub const STATE_VERSION: u16 = 2;

/// The keyed code a sealed file ends with.
const CODE_LEN: usize = 16;

/// What the key's name is a keyed hash of ([`StateDir::seal`]).
const KEY_NAMED: &[u8] = b"tally relay state key";

/// One log record: the class of who delivered it (`strikes::Class`, whose ring holds it), its
/// signed time and fingerprint, and their keyed code.
const RECORD_LEN: usize = 1 + 8 + 8 + 16;

/// A state file as it was read: not there, there but not trusted (and why), or trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prior<T> {
    Missing,
    Refused(String),
    Valid(T),
}

impl<T> Prior<T> {
    /// What it holds when trusted.
    pub fn valid(self) -> Option<T> {
        match self {
            Self::Valid(value) => Some(value),
            Self::Missing | Self::Refused(_) => None,
        }
    }
}

/// A sealed file's parts, as checked ([`StateDir::unseal`]).
#[derive(Debug)]
pub struct Sealed<'a> {
    /// The run that wrote it ([`StateDir::run`]).
    pub run: u64,
    pub body: &'a [u8],
    /// Its sealed length: where what follows it (a log's records) starts.
    pub len: usize,
}

/// A relay's state directory: its path, its key and this run's id.
pub struct StateDir {
    path: PathBuf,
    /// The directory's lock, held for the life of the process (`flock`, exclusive).
    _lock: File,
    key: FingerprintKey,
    key_id: [u8; 16],
    run: u64,
    /// Every live lease, by name: one for each, renewed by the renewer.
    leases: Mutex<HashMap<String, Weak<Lease>>>,
    renewal: Arc<Renewal>,
    /// How many files this run has written beside their names: each its own ([`StateDir::write`]).
    written: AtomicU64,
}

impl std::fmt::Debug for StateDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateDir")
            .field("path", &self.path)
            .field("run", &self.run)
            .finish_non_exhaustive()
    }
}

/// What wakes the renewer, and whether it has stopped (`StateDir::quiesce`).
struct Renewal {
    asked: Mutex<bool>,
    wake: Condvar,
    closed: AtomicBool,
}

/// A table's lease of signed time, on disk (`tally_wire::budget::LEASE`).
pub struct Lease {
    dir: Arc<StateDir>,
    name: String,
    held_ms: AtomicU64,
    /// The run whose write the bound is.
    run: AtomicU64,
    /// The newest signed time a renewal ahead was asked for.
    wanted_ms: AtomicU64,
    writing: Mutex<()>,
    prior: Prior<(u64, u64)>,
    /// Where its tables start, decided once ([`Lease::begin`]).
    begun: Mutex<Option<LeaseStart>>,
}

/// Where the tables of a lease start ([`Lease::begin`]): the floor, and the bound when it was past
/// what the synced clock allows (the floor then, until the clock passes it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseStart {
    pub floor_ms: u64,
    pub ahead: Option<u64>,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("name", &self.name)
            .field("held_ms", &self.held_ms())
            .finish_non_exhaustive()
    }
}

/// What a table's checkpoint and log held at a start ([`StateDir::open_table`]): the dump the
/// checkpoint holds, and the records the log holds after it, each `(class, signed_ms,
/// fingerprint)`.
#[derive(Debug, PartialEq, Eq)]
pub struct TableState {
    pub dump: Vec<u8>,
    pub records: Vec<(u8, u64, u64)>,
}

/// A table's log of the records it used since its checkpoint ([`StateDir::begin_table`]).
pub struct Log {
    dir: Arc<StateDir>,
    name: String,
    /// Its table's windows (`strikes::Strikes::layout`), named by its checkpoint and its header.
    layout: String,
    file: File,
    generation: u64,
    records: u64,
    len: u64,
    /// Its checkpoint names another generation (a fold that wrote the checkpoint and not the
    /// log), or a failed append could not be cut back: nothing more is appended until a fold.
    stale: bool,
}

impl StateDir {
    /// The state directory at `path`, made if it is not there, its key read or made, a run id
    /// drawn and its lease renewer started.
    ///
    /// Its lock first: a directory another process holds is refused, an error, so a second relay
    /// on the same volume never starts.
    pub fn open(path: &Path) -> io::Result<Arc<Self>> {
        std::fs::create_dir_all(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path.join("lock"))?;
        // An exclusive lock taken without waiting (std's `File::try_lock`, `flock(2)` on Linux):
        // held until the file is closed, so a second open of the same path, in this process or
        // another, is refused.
        if let Err(error) = lock.try_lock() {
            if let std::fs::TryLockError::Error(error) = error {
                return Err(error);
            }
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "{} is held by another relay (its lock): one writer at a time",
                    path.display()
                ),
            ));
        }
        Self::probe(path)?;
        forget_temporaries(path)?;
        let key = key_at(path)?;
        let key_id = key
            .fingerprint(keyed::STATE_KEY_ID, KEY_NAMED)
            .to_le_bytes();
        let mut run = [0u8; 32];
        getrandom_seed(&mut run);
        let renewal = Arc::new(Renewal {
            asked: Mutex::new(false),
            wake: Condvar::new(),
            closed: AtomicBool::new(false),
        });
        let dir = Arc::new(Self {
            path: path.to_path_buf(),
            _lock: lock,
            key,
            key_id,
            run: u64::from_le_bytes(word(&run, 0)),
            leases: Mutex::new(HashMap::new()),
            renewal: Arc::clone(&renewal),
            written: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&dir);
        std::thread::Builder::new()
            .name("tally-lease".to_owned())
            .spawn(move || renew_while(&weak, &renewal))?;
        Ok(dir)
    }

    /// Whether a state directory can be made at `path` and written: it is made if it is not
    /// there, and a file written in it and synced. The file has no name (`O_TMPFILE`), so nothing
    /// is left in the directory whatever ends the probe: it goes when its descriptor closes, a
    /// kill included. A filesystem that has no unnamed files (`EOPNOTSUPP`, `EISDIR` before Linux
    /// 3.11) gets a named one, removed at once. Nothing else: no lock, no key, no renewer
    /// (`tally-relay check`'s, beside a live relay that holds the directory).
    pub fn probe(path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)?;
        match OpenOptions::new()
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_TMPFILE)
            .open(path)
        {
            Ok(mut unnamed) => {
                unnamed.write_all(b"tally")?;
                unnamed.sync_all()
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EOPNOTSUPP | libc::EISDIR | libc::EINVAL)
                ) =>
            {
                let probe = path.join(format!(".writable-{}", std::process::id()));
                let written = File::create(&probe).and_then(|file| file.sync_all());
                let removed = std::fs::remove_file(&probe);
                written.and(removed)
            }
            Err(error) => Err(error),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The strike tables' fingerprint key (`strikes::Shares`), made once and kept, and what every
    /// state file is sealed under. Readable by the relay alone.
    pub fn key(&self) -> FingerprintKey {
        self.key
    }

    /// This run's id: what every file it writes names as its writer.
    pub fn run(&self) -> u64 {
        self.run
    }

    /// `body` sealed as a state file of `kind` and `layout` (see the module): magic, version,
    /// kind, the key's name, the layout, this run, the body, and a keyed code over all of it.
    pub fn seal(&self, kind: Kind, layout: &str, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + layout.len() + body.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&STATE_VERSION.to_le_bytes());
        out.push(kind as u8);
        out.extend_from_slice(&self.key_id);
        let layout_len = u16::try_from(layout.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&layout_len.to_le_bytes());
        out.extend_from_slice(&layout.as_bytes()[..usize::from(layout_len)]);
        out.extend_from_slice(&self.run.to_le_bytes());
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(body);
        let code = self.key.fingerprint(keyed::STATE, &out);
        out.extend_from_slice(&code.to_le_bytes());
        out
    }

    /// `bytes` checked as a sealed state file of `kind` and `layout`: its parts, or why it is not
    /// one to trust.
    pub fn unseal<'a>(
        &self,
        bytes: &'a [u8],
        kind: Kind,
        layout: &str,
    ) -> Result<Sealed<'a>, String> {
        let mut cursor = Cursor { bytes, at: 0 };
        if cursor.take(MAGIC.len())? != MAGIC {
            return Err("not a state file".to_owned());
        }
        let version = u16::from_le_bytes([cursor.take(1)?[0], cursor.take(1)?[0]]);
        if version != STATE_VERSION {
            return Err(format!("format version {version}, not {STATE_VERSION}"));
        }
        if cursor.take(1)?[0] != kind as u8 {
            return Err(format!("not a {kind:?} file"));
        }
        if cursor.take(16)? != self.key_id {
            return Err("written under another key".to_owned());
        }
        let layout_len = u16::from_le_bytes([cursor.take(1)?[0], cursor.take(1)?[0]]);
        if cursor.take(usize::from(layout_len))? != layout.as_bytes() {
            return Err(format!("of another layout than {layout}"));
        }
        let run = u64::from_le_bytes(word(cursor.take(8)?, 0));
        let body_len = usize::try_from(u64::from_le_bytes(word(cursor.take(8)?, 0)))
            .map_err(|_| "a body past memory".to_owned())?;
        let body = cursor.take(body_len)?;
        let sealed = cursor.at;
        let code = cursor.take(CODE_LEN)?;
        let wanted = self.key.fingerprint(keyed::STATE, &bytes[..sealed]);
        if code != wanted.to_le_bytes() {
            return Err("its code does not match: changed or torn".to_owned());
        }
        Ok(Sealed {
            run,
            body,
            len: cursor.at,
        })
    }

    /// `body` written as the state file `name` of `kind` and `layout`, whole or not at all.
    pub fn write_state(&self, name: &str, kind: Kind, layout: &str, body: &[u8]) -> io::Result<()> {
        self.write(name, &self.seal(kind, layout, body))
    }

    /// The state file `name` of `kind` and `layout` as it is on disk: its writer's run and its
    /// body when it is trusted. A file that cannot be read is not trusted.
    pub fn read_state(&self, name: &str, kind: Kind, layout: &str) -> Prior<(u64, Vec<u8>)> {
        match self.read(name) {
            Ok(None) => Prior::Missing,
            Ok(Some(bytes)) => match self.unseal(&bytes, kind, layout) {
                Ok(sealed) => Prior::Valid((sealed.run, sealed.body.to_vec())),
                Err(why) => Prior::Refused(format!("{name}: {why}")),
            },
            Err(error) => Prior::Refused(format!("{name}: {error}")),
        }
    }

    /// `name` consumed: renamed to a consumed name and the directory synced, so it is never read
    /// back again. An error means it may still be read back, and must not be used.
    pub fn consume(&self, name: &str) -> io::Result<()> {
        std::fs::rename(
            self.path.join(name),
            self.path.join(format!("{name}.consumed")),
        )?;
        self.sync()
    }

    /// The lease named `name` (the same one while any holds it), and the bound and run it held
    /// before this start, as read.
    pub fn lease(self: &Arc<Self>, name: &str) -> (Arc<Lease>, Prior<(u64, u64)>) {
        let mut leases = self
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lease) = leases.get(name).and_then(Weak::upgrade) {
            let prior = lease.prior.clone();
            return (lease, prior);
        }
        let prior = match self.read_state(&lease_file(name), Kind::Lease, name) {
            Prior::Valid((run, body)) if body.len() == 8 => {
                Prior::Valid((u64::from_le_bytes(word(&body, 0)), run))
            }
            Prior::Valid(_) => Prior::Refused(format!("{name}: a lease of another length")),
            Prior::Missing => Prior::Missing,
            Prior::Refused(why) => Prior::Refused(why),
        };
        let (held, run) = prior.clone().valid().unwrap_or((0, 0));
        let lease = Arc::new(Lease {
            dir: Arc::clone(self),
            name: name.to_owned(),
            held_ms: AtomicU64::new(held),
            run: AtomicU64::new(run),
            wanted_ms: AtomicU64::new(0),
            writing: Mutex::new(()),
            prior: prior.clone(),
            begun: Mutex::new(None),
        });
        leases.insert(name.to_owned(), Arc::downgrade(&lease));
        (lease, prior)
    }

    /// The renewer stopped, and every lease's write in flight finished: no bound moves after this
    /// but by a take, which a stopping relay makes no more of (`strikes::Shares::close`). What a
    /// stop does before it writes its dump beside the bounds.
    pub fn quiesce(&self) {
        self.renewal.closed.store(true, Ordering::SeqCst);
        for lease in self.live_leases() {
            drop(lease.writing.lock());
        }
    }

    fn live_leases(&self) -> Vec<Arc<Lease>> {
        self.leases
            .lock()
            .map(|leases| leases.values().filter_map(Weak::upgrade).collect())
            .unwrap_or_default()
    }

    fn renew_soon(&self) {
        if let Ok(mut asked) = self.renewal.asked.lock() {
            *asked = true;
            self.renewal.wake.notify_one();
        }
    }

    /// What the table `name` of `layout` (its windows, `strikes::Strikes::layout`) holds, when
    /// its checkpoint and its log are trusted: the checkpoint's dump, and every record of the log
    /// up to the first that is cut or does not match (one torn by a crash was never used: a take
    /// uses a record only once it is synced). The log must be the one the checkpoint names (its
    /// generation): one missing, not trusted or of another generation may have held records used
    /// since the checkpoint, so the table is refused whole, and starts at the fallback floor.
    pub fn open_table(&self, name: &str, layout: &str) -> Prior<TableState> {
        let (_, body) = match self.read_state(&checkpoint_file(name), Kind::Table, layout) {
            Prior::Valid(valid) => valid,
            Prior::Missing => return Prior::Missing,
            Prior::Refused(why) => return Prior::Refused(why),
        };
        if body.len() < 8 {
            return Prior::Refused(format!("{name}: a checkpoint with no generation"));
        }
        let generation = u64::from_le_bytes(word(&body, 0));
        let dump = body[8..].to_vec();
        let log = match self.read(&log_file(name)) {
            Ok(Some(log)) => log,
            Ok(None) => return Prior::Refused(format!("{name}: its checkpoint's log is missing")),
            Err(error) => return Prior::Refused(format!("{name}: its log: {error}")),
        };
        let sealed = match self.unseal(&log, Kind::Log, layout) {
            Ok(sealed) => sealed,
            Err(why) => return Prior::Refused(format!("{name}: its log: {why}")),
        };
        if sealed.body.len() != 8 || u64::from_le_bytes(word(sealed.body, 0)) != generation {
            return Prior::Refused(format!(
                "{name}: its log is not the one its checkpoint names"
            ));
        }
        let mut records = Vec::new();
        for (index, record) in log[sealed.len..].chunks_exact(RECORD_LEN).enumerate() {
            let class = record[0];
            let signed = u64::from_le_bytes(word(record, 1));
            let fp = u64::from_le_bytes(word(record, 9));
            if record[17..] != self.record_code(generation, index as u64, class, signed, fp) {
                break;
            }
            records.push((class, signed, fp));
        }
        Prior::Valid(TableState { dump, records })
    }

    /// The table `name` of `layout` begun afresh from `dump` (everything it holds now): a
    /// checkpoint of a new generation, then an empty log of it.
    pub fn begin_table(self: &Arc<Self>, name: &str, layout: &str, dump: &[u8]) -> io::Result<Log> {
        let mut log = Log {
            dir: Arc::clone(self),
            name: name.to_owned(),
            layout: layout.to_owned(),
            file: File::open(&self.path)?,
            generation: 0,
            records: 0,
            len: 0,
            stale: true,
        };
        log.fold(dump)?;
        Ok(log)
    }

    fn record_code(
        &self,
        generation: u64,
        index: u64,
        class: u8,
        signed: u64,
        fp: u64,
    ) -> [u8; 16] {
        let mut input = [0u8; 33];
        input[..8].copy_from_slice(&generation.to_le_bytes());
        input[8..16].copy_from_slice(&index.to_le_bytes());
        input[16] = class;
        input[17..25].copy_from_slice(&signed.to_le_bytes());
        input[25..].copy_from_slice(&fp.to_le_bytes());
        self.key.fingerprint(keyed::STATE_LOG, &input).to_le_bytes()
    }

    /// `bytes` written as `name` whole or not at all: a file beside it, synced, renamed over it,
    /// and the directory synced. The file beside it is this write's alone ([`StateDir::temporary`]),
    /// so two writers of one name (a lease dropped while its renewer still writes it, and the
    /// lease made in its place) never write into one file and rename the other's half.
    fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let temporary = self.temporary(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, self.path.join(name))?;
        self.sync()
    }

    /// The file a write of `name` is made in before it is renamed over it: named by this run and
    /// the write's place in it, so no two writes share one. One a crash left is removed when the
    /// directory is next opened ([`forget_temporaries`]).
    fn temporary(&self, name: &str) -> PathBuf {
        let write = self.written.fetch_add(1, Ordering::Relaxed);
        self.path
            .join(format!("{name}.{:016x}-{write}{TEMPORARY}", self.run))
    }

    /// What `name` holds, if it is there.
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.path.join(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn sync(&self) -> io::Result<()> {
        File::open(&self.path)?.sync_all()
    }
}

/// A reader of a sealed file's parts in order.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).ok_or("cut short")?;
        let part = self.bytes.get(self.at..end).ok_or("cut short")?;
        self.at = end;
        Ok(part)
    }
}

/// The renewer: renews every lease asked for ahead ([`Lease::cover`]) until its directory is gone
/// or quiesced.
fn renew_while(dir: &Weak<StateDir>, renewal: &Renewal) {
    loop {
        // Woken by an ask, or idle only to see whether it should stop: it renews only when asked
        // (a take that asks again retries one that failed).
        let mut woken = false;
        if let Ok(asked) = renewal.asked.lock() {
            let (mut asked, _) = renewal
                .wake
                .wait_timeout_while(asked, RENEWER_IDLE, |asked| !*asked)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            woken = *asked;
            *asked = false;
        }
        if renewal.closed.load(Ordering::SeqCst) || dir.strong_count() == 0 {
            return;
        }
        // Held only while it renews, so a directory dropped lets go of its lock then.
        if !woken {
            continue;
        }
        let Some(dir) = dir.upgrade() else {
            return;
        };
        for lease in dir.live_leases() {
            let _ = lease.renew();
        }
    }
}

fn lease_file(name: &str) -> String {
    format!("{name}.lease")
}

fn checkpoint_file(name: &str) -> String {
    format!("{name}.strikes")
}

fn log_file(name: &str) -> String {
    format!("{name}.log")
}

impl Lease {
    /// The bound it holds now.
    pub fn held_ms(&self) -> u64 {
        self.held_ms.load(Ordering::Acquire)
    }

    /// The run whose write the bound is (none before any: 0).
    pub fn run(&self) -> u64 {
        self.run.load(Ordering::Acquire)
    }

    /// The bound and run it held before this start, as read.
    pub fn prior(&self) -> &Prior<(u64, u64)> {
        &self.prior
    }

    /// The lease made to cover a record signed at `signed_ms` before it is used. Inside the bound,
    /// nothing waits: a record within half a lease of it (`tally_wire::budget::lease_renews`) asks
    /// the renewer to move it on. Past it, a lease past `signed_ms` (`lease_bound`) is written and
    /// synced first. An error means the record
    /// must not be used: a restart could not know it was. After the directory is quiesced
    /// ([`StateDir::quiesce`]) it refuses every record: a stop's dump is written beside the bound
    /// as it stands, so a record used after it would be one the next start does not know of.
    pub fn cover(&self, signed_ms: u64) -> io::Result<()> {
        self.open()?;
        let held = self.held_ms();
        if signed_ms <= held {
            if lease_renews(signed_ms, held) {
                self.wanted_ms.fetch_max(signed_ms, Ordering::AcqRel);
                self.dir.renew_soon();
            }
            return Ok(());
        }
        let _writing = self
            .writing
            .lock()
            .map_err(|_| io::Error::other("a lease's lock was poisoned"))?;
        // A stop may have quiesced the directory while this one waited.
        self.open()?;
        // Another table sharing it, or the renewer, may have moved it while this one waited.
        if signed_ms <= self.held_ms() {
            return Ok(());
        }
        let to = lease_bound(signed_ms.max(self.wanted_ms.load(Ordering::Acquire)));
        self.write(to)
    }

    /// Refused once the directory is quiesced ([`Lease::cover`]).
    fn open(&self) -> io::Result<()> {
        if self.dir.renewal.closed.load(Ordering::SeqCst) {
            return Err(io::Error::other(
                "the relay is stopping: its state directory takes no more records",
            ));
        }
        Ok(())
    }

    /// Renewed ahead to the newest signed time asked for and a lease past it, when that is
    /// within half a lease of the bound (`tally_wire::budget::lease_renews`): the renewer's.
    fn renew(&self) -> io::Result<()> {
        let _writing = self
            .writing
            .lock()
            .map_err(|_| io::Error::other("a lease's lock was poisoned"))?;
        // A stop that quiesced the directory while this waited for the lock moves nothing more:
        // its dump is written beside the bound as it stands.
        if self.dir.renewal.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        let wanted = self.wanted_ms.load(Ordering::Acquire);
        let held = self.held_ms();
        if wanted == 0 || !lease_renews(wanted, held) {
            return Ok(());
        }
        self.write(lease_bound(wanted).max(held))
    }

    /// Where its tables start, decided once, by a synced clock reading `now` (every table of the
    /// lease asks, and all get the first answer): at the bound it held before this start when that
    /// is trusted; else at `fallback_ms`. A run takes records up to `S` ahead of its clock and its
    /// bound is `L` past the newest it took, so a bound up to `S + L` ahead
    /// (`tally_wire::budget::LEASE_REACH`) is a quick restart's, and is the floor even below the fallback. One further ahead was left
    /// by a run whose clock ran ahead, and that run may have used records up to it: then, and
    /// only then, the floor is the higher of the bound and the fallback (a bound past `S + L` may
    /// still be under the fallback's `S + K`), so no restart ever uses a record again, and the
    /// tables use nothing new until the clock passes it; it is named (`ahead`) for the caller to
    /// say so loudly. The bound stays on disk, so a start before then meets it again.
    pub fn begin(&self, now: Judged, fallback_ms: u64) -> LeaseStart {
        let mut begun = self
            .begun
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(start) = *begun {
            return start;
        }
        let start = match self.prior.clone().valid() {
            Some((held, _)) if LEASE_REACH.ahead(held, now) => LeaseStart {
                floor_ms: held.max(fallback_ms),
                ahead: Some(held),
            },
            Some((held, _)) => LeaseStart {
                floor_ms: held,
                ahead: None,
            },
            None => {
                // A bound read and not trusted is written over too, so the next start trusts what
                // this one began from, not a file it refused.
                if matches!(self.prior, Prior::Refused(_)) {
                    let _ = self.reset(fallback_ms);
                }
                LeaseStart {
                    floor_ms: fallback_ms,
                    ahead: None,
                }
            }
        };
        *begun = Some(start);
        start
    }

    /// The bound set to `to` whatever it held: a start that refused the bound it read (one past
    /// what a synced clock allows, `strikes::Strikes::begin`) puts its fallback floor in its place.
    pub fn reset(&self, to: u64) -> io::Result<()> {
        let _writing = self
            .writing
            .lock()
            .map_err(|_| io::Error::other("a lease's lock was poisoned"))?;
        self.wanted_ms.store(0, Ordering::Release);
        self.write(to)
    }

    fn write(&self, to: u64) -> io::Result<()> {
        self.dir.write_state(
            &lease_file(&self.name),
            Kind::Lease,
            &self.name,
            &to.to_le_bytes(),
        )?;
        self.held_ms.store(to, Ordering::Release);
        self.run.store(self.dir.run, Ordering::Release);
        Ok(())
    }
}

impl Log {
    /// The records appended since its checkpoint.
    pub fn records(&self) -> u64 {
        self.records
    }

    /// Whether it must be folded before anything more is appended.
    pub fn is_stale(&self) -> bool {
        self.stale
    }

    /// A record used, appended and synced before it is used. On an error the log is cut back to
    /// what it held, so a later record never follows a torn one; when even that fails it is stale
    /// until a fold. An error means the record must not be used.
    pub fn append(&mut self, class: u8, signed_ms: u64, fp: u64) -> io::Result<()> {
        if self.stale {
            return Err(io::Error::other("the table's log must be folded first"));
        }
        let mut record = [0u8; RECORD_LEN];
        record[0] = class;
        record[1..9].copy_from_slice(&signed_ms.to_le_bytes());
        record[9..17].copy_from_slice(&fp.to_le_bytes());
        record[17..].copy_from_slice(&self.dir.record_code(
            self.generation,
            self.records,
            class,
            signed_ms,
            fp,
        ));
        let written = self
            .file
            .write_all_at(&record, self.len)
            .and_then(|()| self.file.sync_data());
        if let Err(error) = written {
            if self
                .file
                .set_len(self.len)
                .and_then(|()| self.file.sync_data())
                .is_err()
            {
                self.stale = true;
            }
            return Err(error);
        }
        self.len += RECORD_LEN as u64;
        self.records += 1;
        Ok(())
    }

    /// Folded into a fresh checkpoint of everything its table holds now (`dump`), of a new
    /// generation, and an empty log of it beside: the checkpoint first. A crash between the two
    /// leaves the new checkpoint beside a log of another generation, which `StateDir::open_table`
    /// refuses: the table starts at the fallback floor, never at one that missed a record.
    pub fn fold(&mut self, dump: &[u8]) -> io::Result<()> {
        let mut seed = [0u8; 32];
        getrandom_seed(&mut seed);
        let generation = u64::from_le_bytes(word(&seed, 0));
        let mut checkpoint = Vec::with_capacity(8 + dump.len());
        checkpoint.extend_from_slice(&generation.to_le_bytes());
        checkpoint.extend_from_slice(dump);
        self.dir.write_state(
            &checkpoint_file(&self.name),
            Kind::Table,
            &self.layout,
            &checkpoint,
        )?;
        // The checkpoint names the new generation now: the log this holds is stale until the new
        // one is in its place.
        self.stale = true;
        let header = self
            .dir
            .seal(Kind::Log, &self.layout, &generation.to_le_bytes());
        self.dir.write(&log_file(&self.name), &header)?;
        let file = OpenOptions::new()
            .write(true)
            .open(self.dir.path.join(log_file(&self.name)))?;
        self.file = file;
        self.generation = generation;
        self.records = 0;
        self.len = header.len() as u64;
        self.stale = false;
        Ok(())
    }
}

/// What a key file holds after the key: a keyed hash of a constant under it, by which a key file
/// cut or changed is known.
const KEY_CHECKED: &[u8] = b"tally relay key check";

/// The key at `path`: read, or made once and kept. A key file that is not one (cut, changed,
/// another length) is said loudly and replaced by a fresh key: every file sealed under the old
/// one is then refused, and every table starts at the fallback floor, where a relay that refused
/// to start would be restarted into the same refusal for ever.
fn key_at(path: &Path) -> io::Result<FingerprintKey> {
    let at = path.join("strike.key");
    match std::fs::read(&at) {
        Ok(bytes) => {
            if let Some(key) = key_of(&bytes) {
                return Ok(key);
            }
            eprintln!(
                "tally-relay: {} is not a key (cut or changed): a fresh key made, and every \
                 table starts at the fallback floor",
                at.display()
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut seed = [0u8; 32];
    getrandom_seed(&mut seed);
    let key = FingerprintKey::from_bytes(seed);
    let mut bytes = seed.to_vec();
    bytes.extend_from_slice(
        &key.fingerprint(keyed::STATE_KEY_ID, KEY_CHECKED)
            .to_le_bytes(),
    );
    let temporary = path.join(format!("strike.key{TEMPORARY}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, &at)?;
    File::open(path)?.sync_all()?;
    Ok(key)
}

/// What every file a write is made in before its rename ends with ([`StateDir::temporary`]).
const TEMPORARY: &str = ".new";

/// Every file a write left beside its name in `path` removed: a run that crashed between making
/// one and renaming it. Only the directory's lock holder calls it, before it writes anything, so
/// no write in flight is among them.
fn forget_temporaries(path: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().ends_with(TEMPORARY) {
            continue;
        }
        // Only this relay's own temporary files end so; a directory named so is someone else's
        // (an operator's, a restore's), which is not removed and does not stop the start.
        if entry.file_type()?.is_dir() {
            eprintln!(
                "tally-relay: {}: a directory where a temporary file is written: left as it is",
                entry.path().display()
            );
            continue;
        }
        std::fs::remove_file(entry.path())?;
    }
    Ok(())
}

/// The key a key file's `bytes` hold, when they are one: its seed and the check under it.
fn key_of(bytes: &[u8]) -> Option<FingerprintKey> {
    let seed: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
    let key = FingerprintKey::from_bytes(seed);
    let check = key
        .fingerprint(keyed::STATE_KEY_ID, KEY_CHECKED)
        .to_le_bytes();
    (bytes.len() == 32 + check.len() && bytes[32..] == check).then_some(key)
}

fn word(bytes: &[u8], at: usize) -> [u8; 8] {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    word
}

/// Fresh key bytes from the operating system's randomness (`FingerprintKey::fresh_seed`, the
/// `getrandom` crate): no module of this crate allowed `unsafe` touches a key's bytes.
fn getrandom_seed(seed: &mut [u8; 32]) {
    *seed = FingerprintKey::fresh_seed();
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;

    /// A fresh directory under the test's temporary directory, gone when it is dropped.
    pub(crate) struct Scratch(pub PathBuf);

    impl Scratch {
        pub(crate) fn new(name: &str) -> Self {
            let base = std::env::var_os("TEST_TMPDIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let mut seed = [0u8; 32];
            getrandom_seed(&mut seed);
            let path = base.join(format!("{name}-{}", u64::from_le_bytes(word(&seed, 0))));
            Self(path)
        }

        /// The directory opened as a new process would: a relay dropped just before (the process
        /// before) may still hold it for as long as its renewer finishes a write, so a lock held
        /// is waited for, bounded, as a new process waits for the old one to exit.
        pub(crate) fn dir(&self) -> Result<Arc<StateDir>, String> {
            let mut opened = StateDir::open(&self.0);
            within(|| {
                if matches!(&opened, Err(error) if error.kind() == io::ErrorKind::WouldBlock) {
                    opened = StateDir::open(&self.0);
                }
                !matches!(&opened, Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            });
            opened.map_err(|error| error.to_string())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// Waits up to five seconds for `done`, polling: a bounded wait, never a sleep.
    pub(crate) fn within(mut done: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if done() {
                return true;
            }
            std::thread::yield_now();
        }
        done()
    }

    /// A lease is written and synced before the record it covers is used, read back after a
    /// restart as the bound it held and the run that wrote it, and moved only forward; a file of
    /// another kind, a torn one and a foreign one are no lease.
    #[test]
    fn a_lease_covers_ahead_and_is_read_back_after_a_restart() -> Result<(), String> {
        let scratch = Scratch::new("lease");
        let dir = scratch.dir()?;
        let (lease, before) = dir.lease("batches");
        assert_eq!(before, Prior::Missing);
        lease.cover(10_000).map_err(text)?;
        assert_eq!(lease.held_ms(), lease_bound(10_000));
        assert_eq!(lease.run(), dir.run());
        // The same lease while it is held.
        assert!(Arc::ptr_eq(&dir.lease("batches").0, &lease));
        let run = dir.run();
        drop(lease);
        drop(dir);
        let dir = scratch.dir()?;
        let (again, before) = dir.lease("batches");
        assert_eq!(before, Prior::Valid((lease_bound(10_000), run)));
        assert_eq!(again.held_ms(), lease_bound(10_000));
        // A file someone else wrote is no lease.
        std::fs::write(scratch.0.join("other.lease"), [1u8; 16]).map_err(text)?;
        assert!(matches!(dir.lease("other").1, Prior::Refused(_)));
        // Nor is a lease under another name, or one torn.
        std::fs::copy(
            scratch.0.join("batches.lease"),
            scratch.0.join("positions.lease"),
        )
        .map_err(text)?;
        assert!(matches!(dir.lease("positions").1, Prior::Refused(_)));
        let mut bytes = std::fs::read(scratch.0.join("batches.lease")).map_err(text)?;
        bytes.truncate(bytes.len() - 1);
        std::fs::write(scratch.0.join("clock_models.lease"), &bytes).map_err(text)?;
        assert!(matches!(dir.lease("clock_models").1, Prior::Refused(_)));
        Ok(())
    }

    /// A quiesced directory's lease covers nothing more, inside its bound or past it, and its bound
    /// stays where the stop's dump is written beside it. Before, a record was covered after the
    /// stop, and the next start resumed from a dump that did not know of it.
    #[test]
    fn a_lease_covers_nothing_once_its_directory_is_quiesced() -> Result<(), String> {
        let scratch = Scratch::new("lease-stopped");
        let dir = scratch.dir()?;
        let (lease, _) = dir.lease("batches");
        lease.cover(10_000).map_err(text)?;
        let held = lease.held_ms();
        dir.quiesce();
        assert!(lease.cover(10_000).is_err());
        assert!(lease.cover(held + 1).is_err());
        assert_eq!(lease.held_ms(), held);
        Ok(())
    }

    /// Every write is made in a file of its own beside its name, so two writers of one name never
    /// share one; and one a crash left is removed when the directory is next opened. Before, every
    /// write of a name was made in `<name>.new`.
    #[test]
    fn every_write_is_made_in_a_file_of_its_own_and_a_crashs_is_removed() -> Result<(), String> {
        let scratch = Scratch::new("temporaries");
        let dir = scratch.dir()?;
        let (first, second) = (
            dir.temporary("batches.lease"),
            dir.temporary("batches.lease"),
        );
        assert_ne!(first, second);
        std::fs::write(&first, b"torn").map_err(text)?;
        // A directory named as a temporary is left, and the start goes on.
        let stray = scratch.0.join(format!("restored{TEMPORARY}"));
        std::fs::create_dir_all(stray.join("inside")).map_err(text)?;
        drop(dir);
        let dir = scratch.dir()?;
        assert!(!first.exists());
        assert!(stray.join("inside").is_dir());
        std::fs::remove_dir_all(&stray).map_err(text)?;
        let (lease, _) = dir.lease("batches");
        lease.cover(10_000).map_err(text)?;
        let left: Vec<_> = std::fs::read_dir(&scratch.0)
            .map_err(text)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(TEMPORARY))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        Ok(())
    }

    /// A record used within half a lease of its bound asks the renewer to move it on, and the
    /// take that asked writes nothing itself: the bound moves ahead off its path. Before, every
    /// record past the bound wrote and synced the lease where it was used.
    #[test]
    fn a_lease_is_renewed_ahead_off_the_path_that_uses_records() -> Result<(), String> {
        let scratch = Scratch::new("lease-renewal");
        let dir = scratch.dir()?;
        let (lease, _) = dir.lease("batches");
        lease.cover(10_000).map_err(text)?;
        let first = lease.held_ms();
        // Further than half a lease below the bound: nothing asked.
        let half = lease_bound(0) / 2;
        assert!(!lease_renews(first - half, first) && lease_renews(first - half + 1, first));
        lease.cover(first - half).map_err(text)?;
        assert_eq!(lease.held_ms(), first);
        // Within it: returns at once, without writing, the bound moved by the renewer. The take
        // runs while this test holds the lease's write lock, so a take that wrote itself would
        // wait on it: it must return while the lock is held.
        let near = first - half / 2;
        let writing = lease.writing.lock().map_err(|_| "poisoned")?;
        let (returned, taken) = std::thread::scope(|scope| {
            let take = scope.spawn(|| lease.cover(near));
            let returned = within(|| take.is_finished());
            drop(writing);
            (returned, take.join())
        });
        assert!(returned, "the take waited to write the lease itself");
        taken.map_err(|_| "the take panicked")?.map_err(text)?;
        assert!(
            within(|| lease.held_ms() == lease_bound(near)),
            "not renewed ahead: {}",
            lease.held_ms()
        );
        // And on disk.
        drop(lease);
        drop(dir);
        let dir = scratch.dir()?;
        assert_eq!(dir.lease("batches").0.held_ms(), lease_bound(near));
        Ok(())
    }

    /// The fingerprint key is made once and is the same key at every start.
    #[test]
    fn the_key_is_kept() -> Result<(), String> {
        let scratch = Scratch::new("key");
        let first = scratch.dir()?.key();
        let second = scratch.dir()?.key();
        let input = [3u8; 32];
        assert_eq!(first.fingerprint(1, &input), second.fingerprint(1, &input));
        Ok(())
    }

    /// A sealed file is read back as it was written, and refused for any change: a bit of its body
    /// flipped, another kind, layout or format version, a key changed, or cut short.
    #[test]
    fn a_state_file_is_trusted_only_as_it_was_written() -> Result<(), String> {
        let scratch = Scratch::new("seal");
        let dir = scratch.dir()?;
        let sealed = dir.seal(Kind::Dump, "batches*2", b"what was held");
        let read = dir.unseal(&sealed, Kind::Dump, "batches*2")?;
        assert_eq!((read.run, read.body), (dir.run(), &b"what was held"[..]));
        let mut flipped = sealed.clone();
        let at = flipped.len() - CODE_LEN - 3;
        flipped[at] ^= 1;
        assert!(dir.unseal(&flipped, Kind::Dump, "batches*2").is_err());
        assert!(dir.unseal(&sealed, Kind::Lease, "batches*2").is_err());
        assert!(dir.unseal(&sealed, Kind::Dump, "batches*4").is_err());
        assert!(
            dir.unseal(&sealed[..sealed.len() - 1], Kind::Dump, "batches*2")
                .is_err()
        );
        let mut versioned = sealed.clone();
        versioned[MAGIC.len()] ^= 2;
        assert!(dir.unseal(&versioned, Kind::Dump, "batches*2").is_err());
        let other = Scratch::new("seal-other");
        assert!(
            other
                .dir()?
                .unseal(&sealed, Kind::Dump, "batches*2")
                .is_err()
        );
        Ok(())
    }

    /// A consumed file is never read again.
    #[test]
    fn a_consumed_file_is_gone() -> Result<(), String> {
        let scratch = Scratch::new("consume");
        let dir = scratch.dir()?;
        dir.write_state("strikes.dump", Kind::Dump, "x", b"body")
            .map_err(text)?;
        assert!(matches!(
            dir.read_state("strikes.dump", Kind::Dump, "x"),
            Prior::Valid(_)
        ));
        dir.consume("strikes.dump").map_err(text)?;
        assert_eq!(
            dir.read_state("strikes.dump", Kind::Dump, "x"),
            Prior::Missing
        );
        assert!(dir.consume("strikes.dump").is_err());
        Ok(())
    }

    /// A table's log holds every record appended since its checkpoint, read back after a restart
    /// up to the first torn one; a fold starts a new generation, after which the old log is not
    /// read; and a checkpoint that is gone or changed is no state.
    #[test]
    fn a_tables_log_is_read_back_to_its_last_whole_record() -> Result<(), String> {
        let scratch = Scratch::new("log");
        let dir = scratch.dir()?;
        let layout = "figures: retained 105000 ms";
        let mut log = dir.begin_table("figures", layout, b"dump").map_err(text)?;
        log.append(0, 10, 100).map_err(text)?;
        log.append(2, 20, 200).map_err(text)?;
        assert_eq!(log.records(), 2);
        assert_eq!(
            dir.open_table("figures", layout),
            Prior::Valid(TableState {
                dump: b"dump".to_vec(),
                records: vec![(0, 10, 100), (2, 20, 200)],
            })
        );
        // A torn last record is not read, nor anything after it.
        let path = scratch.0.join("figures.log");
        let bytes = std::fs::read(&path).map_err(text)?;
        std::fs::write(&path, &bytes[..bytes.len() - 1]).map_err(text)?;
        assert_eq!(
            dir.open_table("figures", layout)
                .valid()
                .map(|state| state.records),
            Some(vec![(0, 10, 100)])
        );
        // Folded: the checkpoint holds it all, the log nothing.
        let mut log = dir
            .begin_table("figures", layout, b"folded")
            .map_err(text)?;
        assert_eq!(
            dir.open_table("figures", layout),
            Prior::Valid(TableState {
                dump: b"folded".to_vec(),
                records: Vec::new(),
            })
        );
        log.append(1, 30, 300).map_err(text)?;
        assert_eq!(
            dir.open_table("figures", layout)
                .valid()
                .map(|state| state.records),
            Some(vec![(1, 30, 300)])
        );
        // A checkpoint of other windows is not read.
        assert!(matches!(
            dir.open_table("figures", "figures: retained 60000 ms"),
            Prior::Refused(_)
        ));
        // An old log beside a new checkpoint may have lost what the new one held: refused, not
        // read as empty.
        let new_log = std::fs::read(&path).map_err(text)?;
        std::fs::write(&path, &bytes).map_err(text)?;
        assert!(matches!(
            dir.open_table("figures", layout),
            Prior::Refused(_)
        ));
        // So is a checkpoint whose log is gone.
        std::fs::remove_file(&path).map_err(text)?;
        assert!(matches!(
            dir.open_table("figures", layout),
            Prior::Refused(_)
        ));
        std::fs::write(&path, &new_log).map_err(text)?;
        assert!(matches!(dir.open_table("figures", layout), Prior::Valid(_)));
        std::fs::remove_file(scratch.0.join("figures.strikes")).map_err(text)?;
        assert_eq!(dir.open_table("figures", layout), Prior::Missing);
        std::fs::write(scratch.0.join("figures.strikes"), b"not a checkpoint").map_err(text)?;
        assert!(matches!(
            dir.open_table("figures", layout),
            Prior::Refused(_)
        ));
        Ok(())
    }

    /// One relay writes a directory: a second open of it while the first holds it is refused, and
    /// it opens again once the first lets go.
    /// A probe of a live directory leaves it as it was, and names nothing in it that a probe
    /// killed before its removal would have left: its file has no name, so a stale entry of any
    /// name cannot refuse a writable directory either.
    #[test]
    fn a_probe_leaves_the_directory_as_it_was() -> Result<(), String> {
        let scratch = Scratch::new("probe");
        let dir = scratch.dir()?;
        let listing = || -> Result<Vec<std::ffi::OsString>, String> {
            let mut names = std::fs::read_dir(&scratch.0)
                .map_err(text)?
                .map(|entry| entry.map(|entry| entry.file_name()).map_err(text))
                .collect::<Result<Vec<_>, _>>()?;
            names.sort();
            Ok(names)
        };
        // What a probe killed between its write and its removal left, under this process's name.
        std::fs::create_dir(scratch.0.join(format!(".writable-{}", std::process::id())))
            .map_err(text)?;
        let before = listing()?;
        StateDir::probe(&scratch.0).map_err(text)?;
        assert_eq!(listing()?, before);
        drop(dir);
        Ok(())
    }

    #[test]
    fn a_state_directory_has_one_writer() -> Result<(), String> {
        let scratch = Scratch::new("lock");
        let first = StateDir::open(&scratch.0).map_err(text)?;
        let second = StateDir::open(&scratch.0);
        assert!(
            matches!(&second, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "a second writer opened it: {second:?}"
        );
        drop(first);
        scratch.dir()?;
        Ok(())
    }

    /// A key file cut or changed is no crash: a fresh key is made and kept, and what was sealed
    /// under the old one is refused, so every table starts at the fallback floor.
    #[test]
    fn a_corrupt_key_is_replaced_and_its_files_refused() -> Result<(), String> {
        let scratch = Scratch::new("key-corrupt");
        let dir = scratch.dir()?;
        let old = dir.key();
        dir.write_state("strikes.dump", Kind::Dump, "x", b"body")
            .map_err(text)?;
        drop(dir);
        let path = scratch.0.join("strike.key");
        let mut bytes = std::fs::read(&path).map_err(text)?;
        bytes[3] ^= 1;
        std::fs::write(&path, &bytes).map_err(text)?;
        let dir = scratch.dir()?;
        let input = [3u8; 32];
        assert_ne!(dir.key().fingerprint(1, &input), old.fingerprint(1, &input));
        assert!(matches!(
            dir.read_state("strikes.dump", Kind::Dump, "x"),
            Prior::Refused(_)
        ));
        let fresh = dir.key();
        drop(dir);
        assert_eq!(
            scratch.dir()?.key().fingerprint(1, &input),
            fresh.fingerprint(1, &input)
        );
        Ok(())
    }

    /// A lease read and not trusted is written over at begin with the fallback, so the next start
    /// trusts the floor this one began from.
    #[test]
    fn a_refused_lease_is_rewritten_at_begin() -> Result<(), String> {
        let scratch = Scratch::new("lease-refused");
        std::fs::create_dir_all(&scratch.0).map_err(text)?;
        std::fs::write(scratch.0.join("batches.lease"), [9u8; 40]).map_err(text)?;
        let dir = scratch.dir()?;
        let (lease, prior) = dir.lease("batches");
        assert!(matches!(prior, Prior::Refused(_)));
        let start = lease.begin(tally_wire::clocks::recorded::judged(100_000), 140_000);
        assert_eq!(start.floor_ms, 140_000);
        drop(lease);
        drop(dir);
        let dir = scratch.dir()?;
        assert!(matches!(dir.lease("batches").1, Prior::Valid((140_000, _))));
        Ok(())
    }

    /// A quick restart is no clock run ahead: a run that took a record `S` ahead of its clock
    /// left its bound `L` past it, which a start a moment later reads at `S + L` ahead of its
    /// clock, the floor with nothing flagged. Only a bound past that is named ahead. Before, the
    /// bound was compared against `S` alone, and a restart within `L` of such a take was flagged
    /// loudly.
    #[test]
    fn a_quick_restarts_lease_is_not_ahead() -> Result<(), String> {
        let now = 100_000;
        // `S + L`: 25 s and 2 s.
        let reach = LEASE_REACH
            .after(tally_wire::clocks::recorded::judged(now))
            .ms();
        assert_eq!(reach, now + 27_000);
        for (held, flagged) in [(reach, None), (reach + 1, Some(reach + 1))] {
            let scratch = Scratch::new("lease-quick");
            let dir = scratch.dir()?;
            let (lease, _) = dir.lease("batches");
            lease.reset(held).map_err(text)?;
            drop(lease);
            drop(dir);
            let dir = scratch.dir()?;
            let (lease, _) = dir.lease("batches");
            let start = lease.begin(tally_wire::clocks::recorded::judged(now), now + 40_000);
            assert_eq!(start.ahead, flagged, "{held}");
            assert_eq!(
                start.floor_ms,
                held.max(now + 40_000 * u64::from(flagged.is_some()))
            );
        }
        Ok(())
    }

    /// A renewal that finds the directory quiesced (a stop's dump about to be written beside the
    /// bound) moves nothing, though it was asked before.
    #[test]
    fn a_quiesced_directory_renews_nothing() -> Result<(), String> {
        let scratch = Scratch::new("lease-quiesced");
        let dir = scratch.dir()?;
        let (lease, _) = dir.lease("batches");
        lease.cover(10_000).map_err(text)?;
        let held = lease.held_ms();
        lease.wanted_ms.store(held, Ordering::Release);
        dir.quiesce();
        lease.renew().map_err(text)?;
        assert_eq!(lease.held_ms(), held);
        Ok(())
    }
}
