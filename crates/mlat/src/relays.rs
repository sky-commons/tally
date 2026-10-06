//! The engine's sessions with Tally relays (RFC-0171 §3.8): it dials each as an `Engine`, asks
//! for its regions' raw stream in the same message as its Hello, and publishes its signed positions back on the same session. The
//! relays it uses are the operator's to name; a relay that says "leave me" is only left for as
//! long as it asks.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::noise;
use tally_wire::{
    Identity, Reader, Reason, Record, Region, RelayAddress, Role, Streams, WireError, Writer,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;

const HEARTBEAT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A session that stayed up this long worked: the wait after it starts from the shortest again,
/// however it ended.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// Keeps a session with one relay up for as long as the engine runs. What the relay sends goes
/// to `inbound`; every record on `outbound` is published to it.
///
/// Publishing never waits for a relay: each session reads `outbound` through its own broadcast
/// receiver, so a relay that stops reading only falls behind (and loses positions, which its
/// sequence gaps show) until its write deadline (`noise::WRITE_TIMEOUT`) ends the session.
pub async fn link(
    relay: RelayAddress,
    identity: Identity,
    regions: Vec<Region>,
    inbound: mpsc::Sender<Record>,
    outbound: broadcast::Sender<Arc<Record>>,
) {
    let address = relay.address.clone();
    let dial = move || {
        let relay = relay.clone();
        let identity = identity.clone();
        let regions = regions.clone();
        let inbound = inbound.clone();
        let outbound = outbound.subscribe();
        async move { session(&relay, &identity, &regions, inbound, outbound).await }
    };
    keep(&address, dial).await;
}

/// The link's rules, apart from how a session runs: every session that ends, however, is
/// followed by another after the backoff.
async fn keep<F, S>(address: &str, mut dial: F)
where
    F: FnMut() -> S,
    S: Future<Output = Result<Duration, String>>,
{
    let mut backoff = Backoff::new();
    loop {
        let started = Instant::now();
        let outcome = dial().await;
        if started.elapsed() >= HEALTHY_SESSION {
            backoff.reset();
        }
        match outcome {
            Ok(wait) => {
                backoff.reset();
                backoff.at_least(wait);
            }
            Err(error) => eprintln!("tally-mlat: relay {address}: {error}"),
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

/// One session; `Ok` with the wait the relay asked for when it ended the session itself.
async fn session(
    relay: &RelayAddress,
    identity: &Identity,
    regions: &[Region],
    inbound: mpsc::Sender<Record>,
    outbound: broadcast::Receiver<Arc<Record>>,
) -> Result<Duration, String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    // The subscription travels with the Hello, so the relay applies it before it sends anything.
    let subscribe = [Record::Subscribe {
        streams: Streams::RAW,
        regions: regions.to_vec(),
    }];
    let session =
        match noise::connect_with(stream, identity, &relay.key, Role::Engine, &subscribe).await {
            Ok(session) => session,
            Err(WireError::Refused {
                retry_after_secs, ..
            }) => return Ok(Duration::from_secs(retry_after_secs.into())),
            Err(error) => return Err(error.to_string()),
        };
    eprintln!("tally-mlat: subscribed to {}", relay.address);
    over(
        session.reader,
        session.writer,
        relay.address.clone(),
        inbound,
        outbound,
    )
    .await
}

/// An established session, until either side ends it or the relay stops reading.
async fn over<S>(
    mut reader: Reader<S>,
    mut writer: Writer<S>,
    address: String,
    inbound: mpsc::Sender<Record>,
    mut outbound: broadcast::Receiver<Arc<Record>>,
) -> Result<Duration, String>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    // The reader runs on its own: a read cut short by a select would lose its bytes.
    let (ended_in, mut ended) = mpsc::channel::<Result<Duration, String>>(1);
    let reading = tokio::spawn(async move {
        let outcome = loop {
            let mut got = Vec::new();
            match tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut got)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => break Err(error.to_string()),
                Err(_) => break Err("silent too long".to_owned()),
            }
            let mut leave = None;
            for record in got {
                match record {
                    // A receiver's own batches only: a `RelayBatch` is the relay's
                    // deduplicated stream, signed by the relay, and the engine never uses it.
                    Record::Batch(_) | Record::ReceiverInfo(_) => {
                        if inbound.send(record).await.is_err() {
                            return;
                        }
                    }
                    Record::Goodbye {
                        reason,
                        retry_after_secs,
                    } => {
                        let wait = Duration::from_secs(retry_after_secs.into());
                        // Every goodbye's wait is honoured; a refusal is also said in words.
                        if matches!(reason, Reason::Protocol | Reason::Version) {
                            eprintln!("tally-mlat: relay {address}: {}", refusal(reason, wait));
                        }
                        leave = Some(Ok(wait));
                    }
                    Record::Redirect {
                        retry_after_secs, ..
                    } => leave = Some(Ok(Duration::from_secs(retry_after_secs.into()))),
                    _ => {}
                }
            }
            if let Some(outcome) = leave {
                break outcome;
            }
        };
        let _ = ended_in.send(outcome).await;
    });
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    let result = loop {
        tokio::select! {
            record = outbound.recv() => match record {
                Ok(record) => {
                    if let Err(error) = writer.send(&[record]).await {
                        break Err(sent(&error));
                    }
                }
                // Positions this session could not keep up with are gone; sequence gaps say so.
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break Err("engine ended".to_owned()),
            },
            _ = heartbeat.tick() => {
                if let Err(error) = writer.send(&[Record::Heartbeat]).await {
                    break Err(sent(&error));
                }
            }
            outcome = ended.recv() => break outcome.unwrap_or_else(|| Err("reader ended".to_owned())),
        }
    };
    reading.abort();
    result
}

/// Why a send ended the session. A timed-out send has left the writer mid-message, so nothing
/// more can be sent on it.
fn sent(error: &WireError) -> String {
    match error {
        WireError::Timeout => format!(
            "the relay stopped reading: a send waited {}s",
            noise::WRITE_TIMEOUT.as_secs()
        ),
        error => error.to_string(),
    }
}

/// What a relay's `Goodbye` for a session it would not keep says, in words: the relay names only
/// the reason and how long to stay away, and this is the operator's one place to learn either.
fn refusal(reason: Reason, wait: Duration) -> String {
    let why = match reason {
        Reason::Version => "it does not speak this engine's protocol version; upgrade one of them",
        _ => {
            "it took something this engine sent as a protocol violation (a subscription to more \
             regions than it serves is one; see --region)"
        }
    };
    format!(
        "the relay ended the session ({reason:?}): {why}; waiting the {}s it asked for",
        wait.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tally_wire::{Position, Positions, PositionsContent};

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// About 3 KB of signed positions: two fill the stalled relay's pipe.
    fn positions(engine: &Identity, sequence: u64) -> Result<Arc<Record>, String> {
        let position = Position {
            address: 0x40621d,
            time_ms: 1,
            lat_e7: 0,
            lon_e7: 0,
            alt_ft: None,
            sigma_m: 1,
            receivers: 4,
        };
        let content = PositionsContent {
            boot_id: 1,
            sequence,
            issued_ms: 1,
            positions: vec![position; 100],
        };
        Ok(Arc::new(Record::Positions(
            Positions::sign(engine, &content).map_err(text)?,
        )))
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_stops_reading_ends_its_session_without_holding_up_publishing()
    -> Result<(), String> {
        let engine = Identity::generate().map_err(text)?;
        let relay = Identity::generate().map_err(text)?;
        let (outbound, _) = broadcast::channel::<Arc<Record>>(64);
        let (inbound, _records) = mpsc::channel(16);
        let mut healthy = outbound.subscribe();
        let began = Instant::now();
        let ends = Arc::new(Mutex::new(Vec::new()));
        let dial = {
            let (outbound, ends, engine) = (outbound.clone(), Arc::clone(&ends), engine.clone());
            move || {
                let (relay, engine, ends) = (relay.clone(), engine.clone(), Arc::clone(&ends));
                let (inbound, outbound) = (inbound.clone(), outbound.subscribe());
                async move {
                    let (near, far) = tokio::io::duplex(4_096);
                    let key = relay.public();
                    // The relay completes the handshake, then never reads again.
                    let held = tokio::spawn(async move {
                        let accepted = noise::accept(far, &[relay]).await;
                        std::future::pending::<()>().await;
                        drop(accepted);
                    });
                    let session = noise::connect(near, &engine, &key, Role::Engine)
                        .await
                        .map_err(text)?;
                    let outcome = over(
                        session.reader,
                        session.writer,
                        "stalled".to_owned(),
                        inbound,
                        outbound,
                    )
                    .await;
                    held.abort();
                    if let Ok(mut ends) = ends.lock() {
                        ends.push((began.elapsed(), outcome.clone()));
                    }
                    outcome
                }
            }
        };
        let linking = tokio::spawn(keep("stalled", dial));
        // The engine publishes once a second, and another relay's session gets every record.
        let mut publish = tokio::time::interval(Duration::from_secs(1));
        for sequence in 0..45 {
            publish.tick().await;
            outbound
                .send(positions(&engine, sequence)?)
                .map_err(|_| "no subscriber".to_owned())?;
            let record = healthy.try_recv().map_err(text)?;
            let Record::Positions(got) = record.as_ref() else {
                return Err(format!("{record:?}"));
            };
            assert_eq!(got.sequence(), sequence);
        }
        linking.abort();
        let ends = ends.lock().map(|ends| ends.clone()).map_err(text)?;
        let Some((at, Err(error))) = ends.first() else {
            return Err(format!("the stalled session never ended: {ends:?}"));
        };
        assert!(error.contains("stopped reading"), "{error}");
        // Ended by the write deadline, long before the read deadline would have.
        assert!(
            *at >= noise::WRITE_TIMEOUT && *at < noise::WRITE_TIMEOUT + Duration::from_secs(5),
            "{at:?}"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_dials_again_after_every_session_that_ends() {
        let dials = Arc::new(Mutex::new(Vec::new()));
        let began = Instant::now();
        let linking = tokio::spawn({
            let dials = Arc::clone(&dials);
            keep("failing", move || {
                if let Ok(mut dials) = dials.lock() {
                    dials.push(began.elapsed());
                }
                async { Err::<Duration, _>("the relay stopped reading".to_owned()) }
            })
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        linking.abort();
        let dials = dials.lock().map(|dials| dials.clone()).unwrap_or_default();
        // One second, then two, then four, each with up to half again of jitter.
        assert!(dials.len() >= 3, "{dials:?}");
        assert!(dials.windows(2).all(|pair| pair[1] > pair[0]), "{dials:?}");
    }

    #[test]
    fn a_relays_refusal_is_reported_in_words_with_its_wait() {
        let text = refusal(Reason::Protocol, Duration::from_secs(86_400));
        assert!(text.contains("Protocol"), "{text}");
        assert!(text.contains("--region"), "{text}");
        assert!(text.contains("86400s"), "{text}");
        assert!(refusal(Reason::Version, Duration::ZERO).contains("version"));
    }
}
