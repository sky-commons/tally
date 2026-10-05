//! One relay connection of each kind: a feeder publishing its own batches, a subscriber taking the
//! stream, another relay exchanging both ways, and the loopback BEAST output.

use std::sync::Arc;
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::noise::{self, Reader, Writer};
use tally_wire::{Identity, PublicKey, Reason, ReceiverInfo, Record, Role};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::{self, error::RecvError, error::TryRecvError};

use crate::config::Upstream;
use crate::hub::{Hub, Item};

/// A peer that says nothing for this long is gone. Every side heartbeats well inside it.
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const HEARTBEAT: Duration = Duration::from_secs(30);
/// The most records gathered into one send.
const SEND_BATCH: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whose batches a connection may publish.
#[derive(Clone, Copy)]
enum Accepts {
    /// A feeder publishes only its own.
    Own(PublicKey),
    /// A relay forwards anyone's, each still signed by its receiver.
    Any,
    /// A subscriber publishes nothing.
    Nothing,
}

pub async fn inbound<S>(stream: S, identities: &[Identity], hub: Arc<Hub>) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let accepted = noise::accept(stream, identities)
        .await
        .map_err(|error| error.to_string())?;
    let mut session = accepted.session;
    let source = hub.connection_id();
    match accepted.role {
        Role::Feeder => {
            exchange(
                &mut session.reader,
                &mut session.writer,
                &hub,
                source,
                Accepts::Own(accepted.peer),
                None,
            )
            .await
        }
        Role::Relay => {
            let (out, infos) = hub.peer();
            exchange(
                &mut session.reader,
                &mut session.writer,
                &hub,
                source,
                Accepts::Any,
                Some((out, infos)),
            )
            .await
        }
        Role::Subscriber => {
            let Some((out, infos, _slot)) = hub.subscribe() else {
                let _ = session
                    .writer
                    .send(&[Record::Goodbye {
                        reason: Reason::Full,
                        retry_after_secs: 600,
                    }])
                    .await;
                return Err("at subscriber capacity".to_owned());
            };
            exchange(
                &mut session.reader,
                &mut session.writer,
                &hub,
                source,
                Accepts::Nothing,
                Some((out, infos)),
            )
            .await
        }
        Role::Other(role) => {
            let _ = session
                .writer
                .send(&[Record::Goodbye {
                    reason: Reason::Protocol,
                    retry_after_secs: 86_400,
                }])
                .await;
            Err(format!("unknown role {role}"))
        }
    }
}

/// Keeps a link to a parent relay up for as long as the relay runs, backing off between tries.
pub async fn upstream(upstream: Upstream, identity: Identity, hub: Arc<Hub>) {
    let mut backoff = Backoff::new();
    loop {
        match upstream_once(&upstream, &identity, &hub).await {
            Ok(()) => backoff.reset(),
            Err(error) => eprintln!("tally-relay: upstream {}: {error}", upstream.address),
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn upstream_once(
    upstream: &Upstream,
    identity: &Identity,
    hub: &Arc<Hub>,
) -> Result<(), String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let mut session = noise::connect(stream, identity, &upstream.key, Role::Relay)
        .await
        .map_err(|error| error.to_string())?;
    let source = hub.connection_id();
    let (out, infos) = hub.peer();
    exchange(
        &mut session.reader,
        &mut session.writer,
        hub,
        source,
        Accepts::Any,
        Some((out, infos)),
    )
    .await
}

/// Runs a connection's two directions until either ends.
async fn exchange<S>(
    reader: &mut Reader<S>,
    writer: &mut Writer<S>,
    hub: &Hub,
    source: u64,
    accepts: Accepts,
    fan_out: Option<(broadcast::Receiver<Item>, Vec<ReceiverInfo>)>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Send,
{
    tokio::select! {
        result = read_loop(reader, hub, source, accepts) => result,
        result = write_loop(writer, source, fan_out) => result,
    }
}

async fn read_loop<S: AsyncRead>(
    reader: &mut Reader<S>,
    hub: &Hub,
    source: u64,
    accepts: Accepts,
) -> Result<(), String> {
    let mut records = Vec::new();
    loop {
        records.clear();
        tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut records))
            .await
            .map_err(|_| "silent too long".to_owned())?
            .map_err(|error| error.to_string())?;
        for record in records.drain(..) {
            ingest(record, hub, source, accepts)?;
        }
    }
}

fn ingest(record: Record, hub: &Hub, source: u64, accepts: Accepts) -> Result<(), String> {
    let allowed = |receiver: PublicKey| match accepts {
        Accepts::Own(peer) => receiver == peer,
        Accepts::Any => true,
        Accepts::Nothing => false,
    };
    match record {
        Record::Batch(batch) => {
            let receiver = batch.receiver().map_err(|error| error.to_string())?;
            if !allowed(receiver) {
                return Err(format!("published a batch signed by {receiver}"));
            }
            batch.verify().map_err(|error| error.to_string())?;
            hub.publish_batch(source, batch);
        }
        Record::ReceiverInfo(info) => {
            let receiver = info.receiver().map_err(|error| error.to_string())?;
            if !allowed(receiver) {
                return Err(format!("published receiver info signed by {receiver}"));
            }
            info.verify().map_err(|error| error.to_string())?;
            // A format this build cannot read still forwards; it just never replaces a known one.
            let issued_ms = info.content().map_or(0, |content| content.issued_ms);
            hub.publish_info(source, info, receiver, issued_ms);
        }
        _ => {}
    }
    Ok(())
}

async fn write_loop<S: AsyncWrite>(
    writer: &mut Writer<S>,
    source: u64,
    fan_out: Option<(broadcast::Receiver<Item>, Vec<ReceiverInfo>)>,
) -> Result<(), String> {
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    let Some((mut out, infos)) = fan_out else {
        loop {
            heartbeat.tick().await;
            writer
                .send(&[Record::Heartbeat])
                .await
                .map_err(|error| error.to_string())?;
        }
    };
    let infos: Vec<Record> = infos.into_iter().map(Record::ReceiverInfo).collect();
    writer
        .send(&infos)
        .await
        .map_err(|error| error.to_string())?;
    let mut pending: Vec<Arc<Record>> = Vec::with_capacity(SEND_BATCH);
    loop {
        tokio::select! {
            item = out.recv() => {
                match item {
                    Ok(item) => keep(&mut pending, item, source),
                    Err(RecvError::Lagged(_)) => return fell_behind(writer).await,
                    Err(RecvError::Closed) => return Ok(()),
                }
                while pending.len() < SEND_BATCH {
                    match out.try_recv() {
                        Ok(item) => keep(&mut pending, item, source),
                        Err(TryRecvError::Lagged(_)) => return fell_behind(writer).await,
                        Err(_) => break,
                    }
                }
                writer
                    .send(&pending)
                    .await
                    .map_err(|error| error.to_string())?;
                pending.clear();
            }
            _ = heartbeat.tick() => {
                writer
                    .send(&[Record::Heartbeat])
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

/// Never send a record back down the connection it came in on.
fn keep(pending: &mut Vec<Arc<Record>>, item: Item, source: u64) {
    if item.source != source {
        pending.push(item.record);
    }
}

async fn fell_behind<S: AsyncWrite>(writer: &mut Writer<S>) -> Result<(), String> {
    let _ = writer
        .send(&[Record::Goodbye {
            reason: Reason::Full,
            retry_after_secs: 30,
        }])
        .await;
    Err("fell behind the stream".to_owned())
}

/// Serves plain BEAST of every reception to whoever connects (a local readsb). Unauthenticated,
/// so the operator binds it to loopback.
pub async fn serve_beast(listener: TcpListener, hub: Arc<Hub>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let (out, _) = hub.peer();
        tokio::spawn(async move {
            if let Err(error) = beast_client(stream, out).await {
                eprintln!("tally-relay: beast-out {peer}: {error}");
            }
        });
    }
}

async fn beast_client<W: AsyncWrite + Unpin>(
    mut stream: W,
    mut out: broadcast::Receiver<Item>,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    loop {
        let item = match out.recv().await {
            Ok(item) => item,
            Err(RecvError::Lagged(missed)) => return Err(format!("fell behind by {missed}")),
            Err(RecvError::Closed) => return Ok(()),
        };
        let Record::Batch(batch) = &*item.record else {
            continue;
        };
        let Ok(content) = batch.content() else {
            continue;
        };
        bytes.clear();
        for frame in content
            .observations
            .iter()
            .filter_map(|observation| observation.to_beast())
        {
            frame.encode_beast(&mut bytes);
        }
        stream
            .write_all(&bytes)
            .await
            .map_err(|error| error.to_string())?;
    }
}
