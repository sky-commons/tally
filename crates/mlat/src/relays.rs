//! The engine's sessions with Tally relays (RFC-0166 §3.8): it dials each as an `Engine`, asks
//! for its regions' raw stream, and publishes its signed positions back on the same session. The
//! relays it uses are the operator's to name; a relay that says "leave me" is only left for as
//! long as it asks.

use std::sync::Arc;
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::noise;
use tally_wire::{Identity, Reason, Record, Region, RelayAddress, Role, Streams};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

const HEARTBEAT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Keeps a session with one relay up for as long as the engine runs. What the relay sends goes
/// to `inbound`; every record on `outbound` is published to it.
pub async fn link(
    relay: RelayAddress,
    identity: Identity,
    regions: Vec<Region>,
    inbound: mpsc::Sender<Record>,
    outbound: broadcast::Sender<Arc<Record>>,
) {
    let mut backoff = Backoff::new();
    loop {
        match session(&relay, &identity, &regions, &inbound, outbound.subscribe()).await {
            Ok(wait) => {
                backoff.reset();
                backoff.at_least(wait);
            }
            Err(error) => eprintln!("tally-mlat: relay {}: {error}", relay.address),
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

/// One session; `Ok` with the wait the relay asked for when it ended the session itself.
async fn session(
    relay: &RelayAddress,
    identity: &Identity,
    regions: &[Region],
    inbound: &mpsc::Sender<Record>,
    mut outbound: broadcast::Receiver<Arc<Record>>,
) -> Result<Duration, String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let session = match noise::connect(stream, identity, &relay.key, Role::Engine).await {
        Ok(session) => session,
        Err(tally_wire::WireError::Refused {
            retry_after_secs, ..
        }) => return Ok(Duration::from_secs(retry_after_secs.into())),
        Err(error) => return Err(error.to_string()),
    };
    let (mut reader, mut writer) = (session.reader, session.writer);
    writer
        .send(&[Record::Subscribe {
            streams: Streams::RAW,
            regions: regions.to_vec(),
        }])
        .await
        .map_err(|error| error.to_string())?;
    eprintln!("tally-mlat: subscribed to {}", relay.address);
    // The reader runs on its own: a read cut short by a select would lose its bytes.
    let (ended_in, mut ended) = mpsc::channel::<Result<Duration, String>>(1);
    let inbound = inbound.clone();
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
                        leave = Some(match reason {
                            Reason::Protocol | Reason::Version => {
                                Err(format!("closed by the relay ({reason:?})"))
                            }
                            _ => Ok(wait),
                        });
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
                        break Err(error.to_string());
                    }
                }
                // Positions this session could not keep up with are gone; sequence gaps say so.
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break Err("engine ended".to_owned()),
            },
            _ = heartbeat.tick() => {
                if let Err(error) = writer.send(&[Record::Heartbeat]).await {
                    break Err(error.to_string());
                }
            }
            outcome = ended.recv() => break outcome.unwrap_or_else(|| Err("reader ended".to_owned())),
        }
    };
    reading.abort();
    result
}
