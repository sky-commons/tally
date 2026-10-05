//! One relay connection of each kind: a feeder publishing its own batches, a subscriber taking
//! the streams it asked for, an MLAT engine doing both with its own positions, another relay
//! exchanging both ways, and the loopback BEAST output.

use std::sync::Arc;
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::noise::{self, Reader, Writer};
use tally_wire::{Identity, PublicKey, Reason, Record, Role};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::{self, error::RecvError, error::TryRecvError};
use tokio::sync::watch;

use crate::config::Upstream;
use crate::hub::{Hub, Item};
use crate::subscription::{Subscription, peer_wants};

/// A peer that says nothing for this long is gone. Every side heartbeats well inside it.
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const HEARTBEAT: Duration = Duration::from_secs(30);
/// The most records gathered into one send.
const SEND_BATCH: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a subscriber turned away at capacity is asked to stay away.
const FULL_RETRY_SECS: u32 = 600;

/// Who is on the other end, and so what it may publish.
#[derive(Clone, Copy)]
enum Peer {
    /// A feeder publishes only its own batches and description.
    Feeder(PublicKey),
    /// A relay forwards anyone's batches and positions, each still signed by its author.
    Relay,
    /// A subscriber publishes nothing.
    Subscriber,
    /// An engine publishes only its own positions.
    Engine(PublicKey),
}

impl Peer {
    fn may_publish_batch(self, receiver: PublicKey) -> bool {
        match self {
            Self::Feeder(peer) => receiver == peer,
            Self::Relay => true,
            Self::Subscriber | Self::Engine(_) => false,
        }
    }

    fn may_publish_positions(self, engine: PublicKey) -> bool {
        match self {
            Self::Engine(peer) => engine == peer,
            Self::Relay => true,
            Self::Subscriber | Self::Feeder(_) => false,
        }
    }
}

/// Which records on the fan-out a link is sent.
enum Wants {
    /// Another relay: everything but the deduplicated stream.
    Peer,
    /// A subscriber or engine: what it last subscribed to.
    Subscription(watch::Receiver<Subscription>),
}

impl Wants {
    fn wants(&self, item: &Item) -> bool {
        match self {
            Self::Peer => peer_wants(item),
            Self::Subscription(subscription) => subscription.borrow().wants(item),
        }
    }

    /// Resolves with the new subscription when it changes; a relay's never does.
    async fn changed(&mut self) -> Subscription {
        if let Self::Subscription(subscription) = self
            && subscription.changed().await.is_ok()
        {
            return subscription.borrow_and_update().clone();
        }
        std::future::pending().await
    }
}

/// A link's place in the fan-out: the stream, the descriptions known when it joined, and its
/// filter.
struct FanOut {
    out: broadcast::Receiver<Item>,
    infos: Vec<Item>,
    wants: Wants,
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
            // Relays it may also choose, as hints (RFC-0166 §3.7).
            let greeting = if hub.hints().is_empty() {
                Vec::new()
            } else {
                vec![Record::RelayList(hub.hints().to_vec())]
            };
            exchange(
                &mut session.reader,
                &mut session.writer,
                &hub,
                source,
                Peer::Feeder(accepted.peer),
                Serving {
                    greeting,
                    fan_out: None,
                    subscribe: None,
                },
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
                Peer::Relay,
                Serving {
                    greeting: Vec::new(),
                    fan_out: Some(FanOut {
                        out,
                        infos,
                        wants: Wants::Peer,
                    }),
                    subscribe: None,
                },
            )
            .await
        }
        Role::Subscriber | Role::Engine => {
            let peer = match accepted.role {
                Role::Engine => Peer::Engine(accepted.peer),
                _ => Peer::Subscriber,
            };
            // An engine is served as a subscriber is, and counts against the same cap.
            let Some((out, infos, _slot)) = hub.subscribe() else {
                let _ = session
                    .writer
                    .send(&[Record::Redirect {
                        retry_after_secs: FULL_RETRY_SECS,
                        hints: hub.hints().to_vec(),
                    }])
                    .await;
                return Err("at subscriber capacity".to_owned());
            };
            let (subscribe, subscription) = watch::channel(Subscription::default());
            exchange(
                &mut session.reader,
                &mut session.writer,
                &hub,
                source,
                peer,
                Serving {
                    greeting: Vec::new(),
                    fan_out: Some(FanOut {
                        out,
                        infos,
                        wants: Wants::Subscription(subscription),
                    }),
                    subscribe: Some(&subscribe),
                },
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
        Peer::Relay,
        Serving {
            greeting: Vec::new(),
            fan_out: Some(FanOut {
                out,
                infos,
                wants: Wants::Peer,
            }),
            subscribe: None,
        },
    )
    .await
}

/// What a connection is told and given, beside what it publishes.
struct Serving<'a> {
    /// Sent once, first.
    greeting: Vec<Record>,
    fan_out: Option<FanOut>,
    /// Where a subscriber's or engine's `Subscribe` records go, to steer its own fan-out.
    subscribe: Option<&'a watch::Sender<Subscription>>,
}

/// Runs a connection's two directions until either ends.
async fn exchange<S>(
    reader: &mut Reader<S>,
    writer: &mut Writer<S>,
    hub: &Hub,
    source: u64,
    peer: Peer,
    serving: Serving<'_>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let Serving {
        greeting,
        fan_out,
        subscribe,
    } = serving;
    tokio::select! {
        result = read_loop(reader, hub, source, peer, subscribe) => result,
        result = write_loop(writer, hub, source, greeting, fan_out) => result,
    }
}

async fn read_loop<S: AsyncRead>(
    reader: &mut Reader<S>,
    hub: &Hub,
    source: u64,
    peer: Peer,
    subscribe: Option<&watch::Sender<Subscription>>,
) -> Result<(), String> {
    let mut records = Vec::new();
    loop {
        records.clear();
        tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut records))
            .await
            .map_err(|_| "silent too long".to_owned())?
            .map_err(|error| error.to_string())?;
        for record in records.drain(..) {
            ingest(record, hub, source, peer, subscribe)?;
        }
    }
}

fn ingest(
    record: Record,
    hub: &Hub,
    source: u64,
    peer: Peer,
    subscribe: Option<&watch::Sender<Subscription>>,
) -> Result<(), String> {
    match record {
        Record::Batch(batch) => {
            let receiver = batch.receiver().map_err(|error| error.to_string())?;
            if !peer.may_publish_batch(receiver) {
                return Err(format!("published a batch signed by {receiver}"));
            }
            batch.verify().map_err(|error| error.to_string())?;
            hub.publish_batch(source, batch, receiver);
        }
        Record::ReceiverInfo(info) => {
            let receiver = info.receiver().map_err(|error| error.to_string())?;
            if !peer.may_publish_batch(receiver) {
                return Err(format!("published receiver info signed by {receiver}"));
            }
            info.verify().map_err(|error| error.to_string())?;
            // A format this build cannot read still forwards; it just never replaces a known one,
            // and places its receiver nowhere.
            let (issued_ms, place) = info
                .content()
                .map_or((0, None), |content| (content.issued_ms, content.location));
            hub.publish_info(source, info, receiver, issued_ms, place);
        }
        Record::Positions(positions) => {
            let engine = positions.engine().map_err(|error| error.to_string())?;
            if !peer.may_publish_positions(engine) {
                return Err(format!("published positions signed by {engine}"));
            }
            positions.verify().map_err(|error| error.to_string())?;
            hub.publish_positions(source, positions);
        }
        Record::Subscribe { streams, regions } => {
            if let Some(subscribe) = subscribe {
                subscribe.send_replace(Subscription { streams, regions });
            }
        }
        // Another relay's deduplicated stream is its own claim; this relay derives its own.
        _ => {}
    }
    Ok(())
}

async fn write_loop<S: AsyncWrite>(
    writer: &mut Writer<S>,
    hub: &Hub,
    source: u64,
    greeting: Vec<Record>,
    fan_out: Option<FanOut>,
) -> Result<(), String> {
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    writer
        .send(&greeting)
        .await
        .map_err(|error| error.to_string())?;
    let Some(FanOut {
        mut out,
        infos,
        mut wants,
    }) = fan_out
    else {
        loop {
            heartbeat.tick().await;
            writer
                .send(&[Record::Heartbeat])
                .await
                .map_err(|error| error.to_string())?;
        }
    };
    let infos: Vec<Arc<Record>> = infos
        .into_iter()
        .filter(|item| wants.wants(item))
        .map(|item| item.record)
        .collect();
    writer
        .send(&infos)
        .await
        .map_err(|error| error.to_string())?;
    let mut pending: Vec<Arc<Record>> = Vec::with_capacity(SEND_BATCH);
    loop {
        tokio::select! {
            item = out.recv() => {
                match item {
                    Ok(item) => keep(&mut pending, item, source, &wants),
                    Err(RecvError::Lagged(_)) => return fell_behind(writer).await,
                    Err(RecvError::Closed) => return Ok(()),
                }
                while pending.len() < SEND_BATCH {
                    match out.try_recv() {
                        Ok(item) => keep(&mut pending, item, source, &wants),
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
            subscription = wants.changed() => {
                // Describe the receivers the new subscription covers before any of their batches.
                let infos: Vec<Arc<Record>> = hub
                    .infos_for(&subscription)
                    .into_iter()
                    .map(|item| item.record)
                    .collect();
                writer
                    .send(&infos)
                    .await
                    .map_err(|error| error.to_string())?;
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

/// Never send a record back down the connection it came in on, nor one the link did not ask for.
fn keep(pending: &mut Vec<Arc<Record>>, item: Item, source: u64, wants: &Wants) {
    if item.source != source && wants.wants(&item) {
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
