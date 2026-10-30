//! Every port the relay listens on (`--listen`, `--beast-out`, `--stats-listen`), served by one
//! accept loop ([`Acceptor`]) and counted by one gauge each ([`Gauge`], `GET /listeners`), and the
//! descriptors they may hold, which the relay asks the kernel for before it serves
//! ([`raise_open_files`]).
//!
//! On 2026-10-18 a relay with one local readsb on beast-out held 271 sockets in CLOSE-WAIT there:
//! the client hung up and reconnected whenever its input went quiet, and the relay, which only
//! wrote to it, learned of a hang-up only from a write that never came while nothing was flowing.
//! Its open-file limit (1024) ran out, every accept on every port failed with `EMFILE`, logged many
//! times a second, and the relay served nothing for two days while its supervisor thought it well.
//! So, here and nowhere else:
//!
//! - **Every accepted connection is a counted `Socket`.** [`Acceptor::next`] tunes the stream for
//!   its listener's role (`sockets`), wraps it in the upload cap's [`Socket`] and gives it its
//!   place among its listener's open connections ([`Open`]), which the socket holds until it is
//!   dropped. No listener can serve a stream any other way, so every one is counted and the
//!   count is what the relay holds.
//! - **A listener with a cap of its own refuses past it** ([`Acceptor::capped`]): beast-out at
//!   `--max-beast-clients`, the stats at [`crate::stats::MAX_CONNECTIONS`]. `--listen`'s are the
//!   hub's caps (`Hub::connection`), which its loop counts as refused here.
//! - **A connection the relay only writes to watches for its peer's end** ([`send_only`]): its
//!   read half is read (and what arrives dropped) beside every write, so a hang-up ends it at
//!   once, whether or not anything is flowing. Every Noise session reads already (its heartbeats
//!   and `READ_TIMEOUT`, `link`), and the stats' HTTP reads its idle connections, each held to
//!   [`Idle`] besides.
//! - **An accept that fails for want of resources never spins** ([`Acceptor::next`]): out of
//!   descriptors, kernel buffers or memory, it backs off from [`FIRST_BACKOFF`] doubling to
//!   [`MOST_BACKOFF`], said once when the run of failures starts and once when it ends, with how
//!   many and how long. An error that belongs to one connection (`ECONNABORTED` and the network
//!   errors Linux hands on from a connection that has already failed) is skipped quietly, as
//!   accept(2) says to. A listener that has accepted nothing for [`STARVED_AFTER`] ends the relay
//!   ([`Starved`]), saying why, so its supervisor starts a whole one rather than keep a process
//!   that serves no one.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, Sleep};

use crate::egress::{Egress, Socket};
use crate::sockets::Role;

/// The first wait after an accept failed for want of resources.
pub const FIRST_BACKOFF: Duration = Duration::from_millis(100);

/// The longest wait between two accepts that fail for want of resources: what a descriptor freed
/// waits at most to be used.
pub const MOST_BACKOFF: Duration = Duration::from_secs(1);

/// How long a listener may accept nothing, every try failing, before the relay ends for its
/// supervisor to restart it: a minute of `EMFILE` is not a burst that passes, and a relay that
/// cannot accept serves no one new while it seems alive.
pub const STARVED_AFTER: Duration = Duration::from_secs(60);

/// The descriptors the process holds beside its connections: its listeners, standard streams,
/// the runtime's event queue and wakers, the key files while they are read, and a connection
/// accepted on each port before it is refused. Far more than these need, so the limit asked for
/// ([`raise_open_files`]) is the connections' caps with room to spare.
pub const OTHER_DESCRIPTORS: usize = 256;

/// What accepts connections: a bound TCP listener, or a test's stand-in for one.
pub trait Accept: Send {
    fn accept(&mut self) -> impl Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send;

    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl Accept for TcpListener {
    fn accept(&mut self) -> impl Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send {
        TcpListener::accept(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpListener::local_addr(self)
    }
}

/// One listener's connections: those open now, and what its accepts have met.
pub struct Gauge {
    name: &'static str,
    open: AtomicUsize,
    accepted: AtomicU64,
    refused: AtomicU64,
    skipped: AtomicU64,
    failed: AtomicU64,
    failure_runs: AtomicU64,
    failing: AtomicBool,
}

impl Gauge {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            open: AtomicUsize::new(0),
            accepted: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            failure_runs: AtomicU64::new(0),
            failing: AtomicBool::new(false),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The connections it accepted that are open now.
    pub fn open(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    pub fn report(&self) -> ListenerReport {
        ListenerReport {
            name: self.name.to_owned(),
            open: self.open(),
            accepted: self.accepted.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            accept_errors_skipped: self.skipped.load(Ordering::Relaxed),
            accept_failures: self.failed.load(Ordering::Relaxed),
            accept_failure_runs: self.failure_runs.load(Ordering::Relaxed),
            failing: self.failing.load(Ordering::Relaxed),
        }
    }
}

/// One listener on `GET /listeners`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerReport {
    /// `listen`, `beast-out` or `stats`.
    pub name: String,
    /// Connections accepted here and open now.
    pub open: usize,
    /// Connections accepted since the relay started, those refused included.
    pub accepted: u64,
    /// Connections closed at once for a cap: the listener's own, or the hub's for `listen`.
    pub refused: u64,
    /// Accepts that failed for one connection's sake (`ECONNABORTED` and the like), skipped.
    pub accept_errors_skipped: u64,
    /// Accepts that failed for want of resources (or any other reason that is not one
    /// connection's), each followed by a wait.
    pub accept_failures: u64,
    /// Runs of such failures, each said once in the log.
    pub accept_failure_runs: u64,
    /// Whether the listener is in such a run now.
    pub failing: bool,
}

/// Every listener's gauge, in the order each was first served (`Hub::listeners`).
#[derive(Default)]
pub struct Listeners {
    gauges: Mutex<Vec<Arc<Gauge>>>,
}

impl Listeners {
    /// The gauge named `name`, made the first time it is asked for.
    pub fn gauge(&self, name: &'static str) -> Arc<Gauge> {
        let Ok(mut gauges) = self.gauges.lock() else {
            return Arc::new(Gauge::new(name));
        };
        if let Some(gauge) = gauges.iter().find(|gauge| gauge.name == name) {
            return Arc::clone(gauge);
        }
        let gauge = Arc::new(Gauge::new(name));
        gauges.push(Arc::clone(&gauge));
        gauge
    }

    pub fn report(&self) -> Vec<ListenerReport> {
        self.gauges
            .lock()
            .map(|gauges| gauges.iter().map(|gauge| gauge.report()).collect())
            .unwrap_or_default()
    }
}

/// One connection's place among its listener's open ones, held by its socket
/// (`Socket::holding`) and given back when the socket is dropped.
pub struct Open {
    gauge: Arc<Gauge>,
}

impl Open {
    /// A place, or `None` (and no place) when `cap` are open already.
    fn take(gauge: &Arc<Gauge>, cap: Option<usize>) -> Option<Self> {
        let before = gauge.open.fetch_add(1, Ordering::SeqCst);
        let open = Self {
            gauge: Arc::clone(gauge),
        };
        cap.is_none_or(|cap| before < cap).then_some(open)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        self.gauge.open.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A listener that could accept nothing for [`STARVED_AFTER`]: the relay ends on it.
#[derive(Debug)]
pub struct Starved {
    pub listener: &'static str,
    pub failures: u64,
    pub over: Duration,
    pub last: String,
}

impl std::fmt::Display for Starved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: accepted nothing for {} s ({} accepts failed, the last with {}); ending the \
             relay for its supervisor to start it again",
            self.listener,
            self.over.as_secs(),
            self.failures,
            self.last
        )
    }
}

/// What an accept error is to the loop.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// One connection's: it is gone, and the next accept is tried at once.
    Connection,
    /// The listener's or the process's (no descriptors, buffers or memory left, or a listener
    /// broken outright): the next accept waits.
    Listener,
}

impl Failure {
    /// accept(2): Linux hands on a connection's pending network error as accept's own, and says
    /// to retry on it as on `EAGAIN`; `ECONNABORTED` is a connection reset before it was taken.
    /// Everything else (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM` above all) recurs on the next try
    /// until something is freed, so it is waited out.
    fn of(error: &io::Error) -> Self {
        let connection = [
            libc::ECONNABORTED,
            libc::ECONNRESET,
            libc::EINTR,
            libc::EAGAIN,
            libc::EPROTO,
            libc::EPERM,
            libc::ENETDOWN,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
        ];
        match error.raw_os_error() {
            Some(code) if connection.contains(&code) => Self::Connection,
            _ => Self::Listener,
        }
    }
}

/// A run of accepts failing for the listener's sake, from its first failure.
struct Run {
    since: Instant,
    failures: u64,
    wait: Duration,
}

/// Where a listener's lines go: the log, or a test's record of them.
type Say = Box<dyn Fn(String) + Send + Sync>;

/// Accepts a listener's connections, each a counted [`Socket`] holding its place ([`Open`]),
/// refusing those past its cap and waiting out failures that recur (the module's rules).
pub struct Acceptor<L> {
    listener: L,
    gauge: Arc<Gauge>,
    egress: Arc<Egress>,
    role: Role,
    cap: Option<usize>,
    run: Option<Run>,
    say: Say,
}

impl<L: Accept> Acceptor<L> {
    /// Accepts on `listener`, counted on its `gauge` (`Listeners::gauge`), each stream's kernel
    /// buffers `role`'s (`sockets`) and its writes `egress`'s.
    pub fn new(listener: L, gauge: Arc<Gauge>, egress: Arc<Egress>, role: Role) -> Self {
        Self {
            listener,
            gauge,
            egress,
            role,
            cap: None,
            run: None,
            say: Box::new(|line| eprintln!("tally-relay: {line}")),
        }
    }

    /// Holds at most `cap` connections open; one past it is closed as it is accepted.
    #[must_use]
    pub fn capped(mut self, cap: usize) -> Self {
        self.cap = Some(cap);
        self
    }

    /// Its lines to `say` instead of the log: a test's record of what it said.
    #[must_use]
    pub fn saying(mut self, say: impl Fn(String) + Send + Sync + 'static) -> Self {
        self.say = Box::new(say);
        self
    }

    pub fn gauge(&self) -> &Arc<Gauge> {
        &self.gauge
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// A connection the caller refused after `next` gave it (the hub's caps, for `--listen`):
    /// counted as refused, and closed as it is dropped.
    pub fn refuse(&self, socket: Socket<TcpStream>) {
        self.gauge.refused.fetch_add(1, Ordering::Relaxed);
        drop(socket);
    }

    /// The next connection within the cap, or [`Starved`] once accepts have failed for
    /// [`STARVED_AFTER`] without one succeeding.
    pub async fn next(&mut self) -> Result<(Socket<TcpStream>, SocketAddr), Starved> {
        loop {
            let error = match self.listener.accept().await {
                Ok((stream, peer)) => {
                    self.recovered();
                    self.gauge.accepted.fetch_add(1, Ordering::Relaxed);
                    let Some(open) = Open::take(&self.gauge, self.cap) else {
                        self.gauge.refused.fetch_add(1, Ordering::Relaxed);
                        drop(stream);
                        continue;
                    };
                    crate::sockets::configure(&stream, self.role);
                    let socket = self.egress.socket(stream, Some(peer.ip())).holding(open);
                    return Ok((socket, peer));
                }
                Err(error) => error,
            };
            if Failure::of(&error) == Failure::Connection {
                self.gauge.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.gauge.failed.fetch_add(1, Ordering::Relaxed);
            let now = Instant::now();
            let run = match &mut self.run {
                Some(run) => run,
                None => {
                    self.gauge.failure_runs.fetch_add(1, Ordering::Relaxed);
                    self.gauge.failing.store(true, Ordering::Relaxed);
                    (self.say)(format!(
                        "{}: accept: {error}; retrying every {} ms to {} s, said again when it \
                         accepts",
                        self.gauge.name,
                        FIRST_BACKOFF.as_millis(),
                        MOST_BACKOFF.as_secs()
                    ));
                    self.run.insert(Run {
                        since: now,
                        failures: 0,
                        wait: FIRST_BACKOFF,
                    })
                }
            };
            run.failures += 1;
            let over = now.duration_since(run.since);
            if over >= STARVED_AFTER {
                return Err(Starved {
                    listener: self.gauge.name,
                    failures: run.failures,
                    over,
                    last: error.to_string(),
                });
            }
            let wait = run.wait;
            run.wait = (wait * 2).min(MOST_BACKOFF);
            tokio::time::sleep(wait).await;
        }
    }

    /// An accept succeeded: a run of failures, if one was under way, is over, and said so.
    fn recovered(&mut self) {
        if let Some(run) = self.run.take() {
            self.gauge.failing.store(false, Ordering::Relaxed);
            (self.say)(format!(
                "{}: accepting again after {} failed accepts over {:.1} s",
                self.gauge.name,
                run.failures,
                run.since.elapsed().as_secs_f64()
            ));
        }
    }
}

/// Serves a connection the relay only writes to: `send` writes to its write half while its read
/// half is read beside it, what arrives dropped, so the peer's end (an end of stream or an error)
/// ends the connection at once, whether or not anything is being written. Ended by its peer,
/// it is `Ok`; ended by `send`, it is what `send` returned.
pub async fn send_only<S, F, Fut>(stream: S, send: F) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite,
    F: FnOnce(WriteHalf<S>) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let (mut reader, writer) = tokio::io::split(stream);
    let ended = async move {
        let mut dropped = [0; 512];
        while let Ok(read) = reader.read(&mut dropped).await {
            if read == 0 {
                break;
            }
        }
    };
    tokio::select! {
        sent = send(writer) => sent,
        () = ended => Ok(()),
    }
}

/// A connection served request by request (the stats'), ended once nothing has moved either way
/// for its idle time: a client that connects and says nothing, or stops mid-request, holds its
/// place no longer.
pub struct Idle<S> {
    inner: S,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
}

impl<S> Idle<S> {
    pub fn new(inner: S, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }

    fn moved(&mut self) {
        let at = Instant::now() + self.idle;
        self.deadline.as_mut().reset(at);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Idle<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if buf.filled().len() > before {
                    this.moved();
                }
                Poll::Ready(result)
            }
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "idle too long",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Idle<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(written)) if written > 0) {
            this.moved();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Raises the process's open-file limit to at least `needed` (`Hub::descriptors`: every
/// connection its caps admit, and [`OTHER_DESCRIPTORS`]), within the hard limit, and returns the
/// limit now in force. A hard limit below `needed` is refused: the relay would run out of
/// descriptors before its caps turned anyone away, and stop accepting on every port.
pub fn raise_open_files(needed: usize) -> Result<u64, String> {
    let needed = u64::try_from(needed).unwrap_or(u64::MAX);
    let (soft, hard) =
        crate::os::open_files_limit().map_err(|error| format!("the open-file limit: {error}"))?;
    if soft >= needed {
        return Ok(soft);
    }
    if hard < needed {
        return Err(format!(
            "its connection caps need {needed} open files and its hard limit is {hard} (raise \
             LimitNOFILE, or lower --max-connections, --max-subscribers or --memory)"
        ));
    }
    crate::os::set_open_files_limit(needed, hard)
        .map_err(|error| format!("raising the open-file limit to {needed}: {error}"))?;
    Ok(needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// A listener whose accepts fail with `errno` until `until`, then are a real listener's.
    struct Failing {
        listener: TcpListener,
        errno: i32,
        until: Instant,
        tries: Arc<AtomicU64>,
    }

    impl Accept for Failing {
        async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
            self.tries.fetch_add(1, Ordering::Relaxed);
            if Instant::now() < self.until {
                return Err(io::Error::from_raw_os_error(self.errno));
            }
            self.listener.accept().await
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.listener.local_addr()
        }
    }

    fn egress() -> Arc<Egress> {
        Arc::new(Egress::new(crate::egress::Cap::NONE))
    }

    /// What an acceptor said, line by line.
    fn recorded() -> (
        Arc<Mutex<Vec<String>>>,
        impl Fn(String) + Send + Sync + 'static,
    ) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&lines);
        (lines, move |line| {
            if let Ok(mut lines) = record.lock() {
                lines.push(line);
            }
        })
    }

    #[test]
    fn a_connections_own_error_is_skipped_and_a_shortage_waited_out() {
        for skipped in [libc::ECONNABORTED, libc::EPROTO, libc::ENETUNREACH] {
            assert_eq!(
                Failure::of(&io::Error::from_raw_os_error(skipped)),
                Failure::Connection
            );
        }
        for shortage in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(
                Failure::of(&io::Error::from_raw_os_error(shortage)),
                Failure::Listener
            );
        }
    }

    // Paused: the waits pass at once, each exactly as long as it says.
    #[tokio::test(start_paused = true)]
    async fn an_accept_out_of_descriptors_backs_off_and_is_said_once_a_run() -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        let tries = Arc::new(AtomicU64::new(0));
        let failing = Failing {
            listener,
            errno: libc::EMFILE,
            until: Instant::now() + Duration::from_secs(5),
            tries: Arc::clone(&tries),
        };
        let (lines, say) = recorded();
        let listeners = Listeners::default();
        let mut acceptor =
            Acceptor::new(failing, listeners.gauge("test"), egress(), Role::Subscriber).saying(say);
        let _client = TcpStream::connect(address).await.map_err(text)?;
        let started = Instant::now();
        let (socket, _) = acceptor.next().await.map_err(text)?;
        // Waits of 0.1, 0.2, 0.4, 0.8 s and then a second each: eight failures in five seconds,
        // never a hot loop, and the ninth try accepts.
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert_eq!(tries.load(Ordering::Relaxed), 9);
        let said = lines.lock().map_err(text)?.clone();
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(said[0].contains("Too many open files"), "{said:?}");
        assert!(said[1].contains("after 8 failed accepts"), "{said:?}");
        let report = acceptor.gauge().report();
        assert_eq!(
            (
                report.accept_failures,
                report.accept_failure_runs,
                report.failing,
                report.open
            ),
            (8, 1, false, 1)
        );
        drop(socket);
        assert_eq!(acceptor.gauge().open(), 0);
        Ok(())
    }

    // Paused: the minute passes at once.
    #[tokio::test(start_paused = true)]
    async fn a_listener_that_accepts_nothing_for_a_minute_ends_the_relay() -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let failing = Failing {
            listener,
            errno: libc::EMFILE,
            until: Instant::now() + Duration::from_secs(3_600),
            tries: Arc::new(AtomicU64::new(0)),
        };
        let (lines, say) = recorded();
        let listeners = Listeners::default();
        let mut acceptor =
            Acceptor::new(failing, listeners.gauge("listen"), egress(), Role::Feeder).saying(say);
        let Err(starved) = acceptor.next().await else {
            return Err("an accept succeeded on a listener out of descriptors".to_owned());
        };
        assert!(starved.over >= STARVED_AFTER, "{starved}");
        assert!(starved.over < STARVED_AFTER + MOST_BACKOFF + MOST_BACKOFF);
        assert!(
            starved
                .to_string()
                .starts_with("listen: accepted nothing for 60 s")
        );
        // Said once, for the whole minute.
        assert_eq!(lines.lock().map_err(text)?.len(), 1);
        assert!(acceptor.gauge().report().failing);
        Ok(())
    }

    #[tokio::test]
    async fn a_listener_past_its_cap_refuses_the_next() -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        let listeners = Listeners::default();
        let mut acceptor = Acceptor::new(
            listener,
            listeners.gauge("capped"),
            egress(),
            Role::Subscriber,
        )
        .capped(1);
        let _first = TcpStream::connect(address).await.map_err(text)?;
        let held = acceptor.next().await.map_err(text)?;
        // The second is closed as it is accepted, and no connection is given while the first
        // holds the one place.
        let mut second = TcpStream::connect(address).await.map_err(text)?;
        let given = tokio::time::timeout(Duration::from_secs(1), acceptor.next()).await;
        assert!(given.is_err(), "a connection was given past the cap");
        // Once the first is gone, the third has its place.
        drop(held);
        let _third = TcpStream::connect(address).await.map_err(text)?;
        let _third_held = acceptor.next().await.map_err(text)?;
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), second.read(&mut byte))
            .await
            .map_err(text)?;
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        let report = acceptor.gauge().report();
        assert_eq!((report.accepted, report.refused, report.open), (3, 1, 1));
        Ok(())
    }

    #[tokio::test]
    async fn a_send_only_connection_ends_when_its_peer_hangs_up_with_nothing_to_send()
    -> Result<(), String> {
        let (near, far) = tokio::io::duplex(64);
        let serving = tokio::spawn(send_only(near, |_writer| async move {
            // Never writes: nothing is flowing.
            std::future::pending::<Result<(), String>>().await
        }));
        drop(far);
        let ended = tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .map_err(|_| "a hung-up peer was held".to_owned())?
            .map_err(text)?;
        assert_eq!(ended, Ok(()));
        Ok(())
    }

    // Paused: the idle time passes at once.
    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_is_ended_and_a_busy_one_kept() -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let (near, mut far) = tokio::io::duplex(64);
        let mut idle = Idle::new(near, Duration::from_secs(10));
        let mut byte = [0; 1];
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(8)).await;
            far.write_all(b"x").await.map_err(text)?;
            assert_eq!(idle.read(&mut byte).await.map_err(text)?, 1);
        }
        let read = idle.read(&mut byte).await;
        assert_eq!(
            read.map_err(|error| error.kind()),
            Err(io::ErrorKind::TimedOut)
        );
        Ok(())
    }
}
