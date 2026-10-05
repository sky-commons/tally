//! One Tally receiver's session with the mlat-server, for as long as the receiver is heard: the
//! TCP connection mlat-client would hold, the client state it would keep (`client.rs`), and the
//! replay that paces its receptions (`playout.rs`).
//!
//! Results come back the way mlat-client gets them: on this connection, because the handshake
//! sets `return_results`. mlat-server sends each result to every receiver that heard the message
//! (`forward_results` in mlat/coordinator.py), so every result reaches the engine through a
//! receiver that took part, with the solution's own covariance and receiver count, and nothing
//! about the server's configuration has to change. Its other outputs (`--basestation-*`,
//! `--write-csv`) were the alternative; they carry no covariance and need a flag on the server.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tally_wire::Observation;
use tally_wire::backoff::Backoff;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::client::Client;
use crate::playout::{Item, Playout};
use crate::protocol::{self, Request, Solution, Station, Welcome};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// mlat-server waits 15 s for a handshake (`process_handshake`); the engine waits as long for
/// the answer.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// `JsonServerConnection.inactivity_timeout`: the server heartbeats every 30 s.
const SERVER_SILENCE: Duration = Duration::from_secs(60);
/// A write the server does not take in this long means it has stopped reading: the session ends
/// and another is dialled. The engine never waits on it meanwhile (it hands batches over with
/// `try_send`, and a full inbox loses the batch).
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// The coordinator's heartbeat period.
const TICK: Duration = Duration::from_millis(500);
/// `ReceiverConnection.inactivity_timeout`: a receiver silent this long is a closed input.
const INPUT_SILENCE: Duration = Duration::from_secs(150);
/// A receiver silent this long is gone: its session ends, and a new one starts if it returns.
pub(crate) const GONE: Duration = Duration::from_secs(600);
/// mlat-server's lines are short; the longest is the motd.
const MAX_LINE: usize = 64 * 1024;

/// One verified batch's receptions, as the engine hands them to the receiver's session.
pub struct Received {
    pub arrival: Instant,
    pub counter_epoch: u32,
    pub observations: Vec<Observation>,
}

/// What every session shares.
#[derive(Clone)]
pub struct Shared {
    pub server: String,
    pub delay: Duration,
    /// The engine's monotonic origin: "now" is seconds since it, as for mlat-client's clock.
    pub start: Instant,
    pub results: mpsc::Sender<Solution>,
}

impl Shared {
    fn now(&self, at: Instant) -> f64 {
        at.duration_since(self.start).as_secs_f64()
    }
}

enum Ended {
    /// The engine dropped this receiver, or it has been silent too long.
    Finished,
    /// Reconnect, after at least this long.
    Retry(Duration),
}

/// Runs the receiver's session until the engine drops it or the receiver goes silent.
pub async fn run(station: Station, shared: Shared, inbox: mpsc::Receiver<Received>) {
    let server = shared.server.clone();
    let dial = move || {
        let server = server.clone();
        async move {
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server))
                .await
                .map_err(|_| "connect timed out".to_owned())?
                .map_err(|error| error.to_string())
        }
    };
    run_with(station, shared, inbox, dial).await;
}

/// `run`, over whatever `dial` connects to.
async fn run_with<F, D, S>(
    station: Station,
    shared: Shared,
    mut inbox: mpsc::Receiver<Received>,
    mut dial: F,
) where
    F: FnMut() -> D,
    D: Future<Output = Result<S, String>>,
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let mut backoff = Backoff::new();
    // The engine starts a session for a batch it is handing over, so the receiver was heard now.
    let mut state = Input::heard_at(Instant::now());
    loop {
        let outcome = match dial().await {
            Ok(stream) => {
                session(
                    stream,
                    &station,
                    &shared,
                    &mut inbox,
                    &mut state,
                    &mut backoff,
                )
                .await
            }
            Err(error) => Err(error),
        };
        match outcome {
            Ok(Ended::Finished) => return,
            Ok(Ended::Retry(wait)) => backoff.at_least(wait),
            Err(error) => eprintln!("tally-mlat: {} at {}: {error}", station.user, shared.server),
        }
        // mlat-client drops its input while the server is away; receptions meanwhile are gone.
        let wait = tokio::time::sleep(backoff.wait());
        tokio::pin!(wait);
        loop {
            tokio::select! {
                () = &mut wait => break,
                received = inbox.recv() => match received {
                    Some(received) => {
                        state.heard(&received);
                    }
                    None => return,
                },
            }
        }
        if state.silent_for(Instant::now()) > GONE {
            return;
        }
    }
}

/// What is known of the receiver's input across server sessions.
struct Input {
    last_heard: Instant,
    counter_epoch: Option<u32>,
}

impl Input {
    /// A receiver heard at `at`. Without it, a session's first tick could come before the batch
    /// that started it was taken from the inbox, and find the receiver gone.
    fn heard_at(at: Instant) -> Self {
        Self {
            last_heard: at,
            counter_epoch: None,
        }
    }

    /// Notes a batch; true when its counter epoch differs from the last one seen.
    fn heard(&mut self, received: &Received) -> bool {
        self.last_heard = received.arrival;
        let restarted = self
            .counter_epoch
            .is_some_and(|epoch| epoch != received.counter_epoch);
        self.counter_epoch = Some(received.counter_epoch);
        restarted
    }

    fn silent_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_heard)
    }
}

async fn session<S>(
    stream: S,
    station: &Station,
    shared: &Shared,
    inbox: &mut mpsc::Receiver<Received>,
    input: &mut Input,
    backoff: &mut Backoff,
) -> Result<Ended, String>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    send(&mut write, &station.handshake()).await?;
    let mut first = String::new();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, read_line(&mut read, &mut first))
        .await
        .map_err(|_| "no answer to the handshake".to_owned())??;
    let (split_sync, reconnect_in) = match protocol::welcome(&first)? {
        Welcome::Accepted {
            split_sync,
            reconnect_in,
        } => (split_sync, reconnect_in),
        Welcome::Denied {
            reasons,
            reconnect_in,
        } => {
            eprintln!(
                "tally-mlat: {} refused by {}: {}",
                station.user,
                shared.server,
                reasons.join("; ")
            );
            return Ok(Ended::Retry(seconds(reconnect_in)));
        }
    };
    backoff.reset();
    let retry = seconds(reconnect_in);

    // The reader runs on its own: a read cut short by a select would lose its bytes.
    let (lines_in, mut lines) = mpsc::channel::<Result<String, String>>(64);
    let reading = tokio::spawn(async move {
        loop {
            let mut line = String::new();
            let got = read_line(&mut read, &mut line).await.map(|()| line);
            let failed = got.is_err();
            if lines_in.send(got).await.is_err() || failed {
                return;
            }
        }
    });
    let result = serve(
        station, shared, inbox, input, &mut lines, &mut write, split_sync,
    )
    .await;
    reading.abort();
    result.map(|ended| match ended {
        Ended::Retry(wait) => Ended::Retry(wait.max(retry)),
        finished => finished,
    })
}

async fn serve<W: AsyncWrite + Unpin>(
    station: &Station,
    shared: &Shared,
    inbox: &mut mpsc::Receiver<Received>,
    input: &mut Input,
    lines: &mut mpsc::Receiver<Result<String, String>>,
    write: &mut W,
    split_sync: bool,
) -> Result<Ended, String> {
    let now = shared.now(Instant::now());
    let mut client = Client::new(station.mode, now);
    client.server_connected(split_sync, now, jitter());
    let mut playout = Playout::new(station.mode, shared.delay.as_secs_f64());
    let mut input_up = input.silent_for(Instant::now()) < INPUT_SILENCE;
    if input_up {
        client.input_connected();
    }
    let mut last_server = Instant::now();
    let mut tick = tokio::time::interval(TICK);
    loop {
        let due = playout
            .next_release()
            .map(|release| shared.start + Duration::from_secs_f64(release.max(0.0)));
        tokio::select! {
            received = inbox.recv() => {
                let Some(received) = received else {
                    return Ok(Ended::Finished);
                };
                let restarted = input.heard(&received);
                if restarted {
                    // A new counter epoch is a restarted counter: mlat-client sees it as its input
                    // closing and reopening, and tells the server so.
                    playout.clear();
                    playout.restart();
                    if input_up {
                        client.input_disconnected();
                    }
                    input_up = false;
                }
                if !input_up {
                    client.input_connected();
                    input_up = true;
                }
                // A batch too late to be replayed in time (a replay, or one held up past the
                // delay) is dropped by the playout rather than sent to the server as live.
                let _ = playout.push(shared.now(received.arrival), received.observations);
            }
            () = sleep_until(due), if due.is_some() => {
                let now = shared.now(Instant::now());
                while let Some(item) = playout.pop_due(now) {
                    match item {
                        Item::Observation(observation) => client.observe(&observation, now),
                        Item::ClockJump => client.clock_jump(now),
                    }
                }
            }
            _ = tick.tick() => {
                let at = Instant::now();
                if at.duration_since(last_server) > SERVER_SILENCE {
                    return Err("the server has been silent for a minute".to_owned());
                }
                let silent = input.silent_for(at);
                if silent > GONE {
                    return Ok(Ended::Finished);
                }
                if input_up && silent > INPUT_SILENCE {
                    client.input_disconnected();
                    playout.clear();
                    input_up = false;
                }
                client.heartbeat(shared.now(at), wall_secs(), jitter());
            }
            line = lines.recv() => {
                let line = line.ok_or_else(|| "server reader ended".to_owned())??;
                last_server = Instant::now();
                match protocol::request(&line) {
                    Ok(Request::StartSending(addresses)) => client.start_sending(&addresses),
                    Ok(Request::StopSending(addresses)) => client.stop_sending(&addresses),
                    Ok(Request::Result(solution)) => {
                        // A full queue means the engine is behind; this copy of the result is
                        // dropped, and other receivers of the same message carry it too.
                        let _ = shared.results.try_send(solution);
                    }
                    Ok(Request::Other) => {}
                    Err(error) => eprintln!("tally-mlat: {}: ignoring {line:?}: {error}", station.user),
                }
            }
        }
        let out = client.take_lines();
        if !out.is_empty() {
            let mut text = out.join("\n");
            text.push('\n');
            send(write, &text).await?;
        }
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// A timed-out write has left a line half sent, so the session ends with it.
async fn send<W: AsyncWrite + Unpin>(write: &mut W, text: &str) -> Result<(), String> {
    tokio::time::timeout(WRITE_TIMEOUT, write.write_all(text.as_bytes()))
        .await
        .map_err(|_| "the server stopped reading".to_owned())?
        .map_err(|error| error.to_string())
}

/// Reads one line into `line`, without its newline. An end of stream is an error.
async fn read_line<R>(read: &mut R, line: &mut String) -> Result<(), String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut limited = read.take(MAX_LINE as u64 + 1);
    let length = limited
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|error| error.to_string())?;
    if length == 0 {
        return Err("the server closed the connection".to_owned());
    }
    if bytes.last() != Some(&b'\n') {
        return Err(if length > MAX_LINE {
            "the server sent an overlong line".to_owned()
        } else {
            "the server closed the connection mid-line".to_owned()
        });
    }
    bytes.pop();
    *line = String::from_utf8(bytes).map_err(|_| "the server sent a line that is not UTF-8")?;
    Ok(())
}

fn seconds(value: Option<f64>) -> Duration {
    value
        .filter(|secs| secs.is_finite() && *secs > 0.0)
        .map_or(Duration::ZERO, |secs| {
            Duration::from_secs_f64(secs.min(86_400.0))
        })
}

pub fn wall_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

/// Python's `random.random()`, for the coordinator's spread of updates and reports. Without
/// randomness from the system there is no spread, which changes nothing that matters.
fn jitter() -> f64 {
    let mut bytes = [0; 4];
    let _ = getrandom::getrandom(&mut bytes);
    f64::from(u32::from_be_bytes(bytes)) / (f64::from(u32::MAX) + 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tally_wire::{Clock, Identity, Location};

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// An mlat-server that accepts the handshake, then sends a heartbeat every five seconds (so
    /// it is never silent) and never reads again.
    async fn stops_reading(stream: tokio::io::DuplexStream) {
        let (read, mut write) = tokio::io::split(stream);
        let mut read = BufReader::new(read);
        let mut handshake = String::new();
        if read_line(&mut read, &mut handshake).await.is_err() {
            return;
        }
        let welcome = "{\"compress\":\"none\",\"reconnect_in\":0.5,\"selective_traffic\":true,\
                       \"heartbeat\":true,\"return_results\":true}\n";
        if write.write_all(welcome.as_bytes()).await.is_err() {
            return;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if write
                .write_all(b"{\"heartbeat\":{\"server_time\":1}}\n")
                .await
                .is_err()
            {
                return;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_stops_reading_ends_the_session_and_another_is_dialled()
    -> Result<(), String> {
        let receiver = Identity::generate().map_err(text)?;
        let location = Location {
            lat_e7: 374_100_000,
            lon_e7: -1_221_000_000,
            alt_m: 10,
            precision_m: 0,
        };
        let station = Station::of(&receiver.public(), Some(location), Clock::Dump1090)
            .ok_or_else(|| "no station".to_owned())?;
        let (results, _solutions) = mpsc::channel(1);
        let shared = Shared {
            server: String::new(),
            delay: Duration::from_millis(100),
            start: Instant::now(),
            results,
        };
        let began = Instant::now();
        let dials = Arc::new(Mutex::new(Vec::new()));
        let dial = {
            let dials = Arc::clone(&dials);
            move || {
                if let Ok(mut dials) = dials.lock() {
                    dials.push(began.elapsed());
                }
                // A pipe far smaller than the lines the client sends once it is connected.
                let (near, far) = tokio::io::duplex(64);
                tokio::spawn(stops_reading(far));
                async move { Ok::<_, String>(near) }
            }
        };
        let (inbox, receiving) = mpsc::channel(4);
        let running = tokio::spawn(run_with(station, shared, receiving, dial));
        // The engine's side: a batch a second, handed over without ever waiting.
        let mut every = tokio::time::interval(Duration::from_secs(1));
        for _ in 0..40 {
            every.tick().await;
            let _ = inbox.try_send(Received {
                arrival: Instant::now(),
                counter_epoch: 0,
                observations: Vec::new(),
            });
        }
        running.abort();
        let dials = dials.lock().map(|dials| dials.clone()).map_err(text)?;
        let [first, second, ..] = dials.as_slice() else {
            return Err(format!("dialled only {dials:?}"));
        };
        assert_eq!(*first, Duration::ZERO);
        // The stalled write's deadline ended the first session, not the server's silence.
        assert!(
            *second >= WRITE_TIMEOUT && *second < SERVER_SILENCE,
            "{dials:?}"
        );
        Ok(())
    }
}
