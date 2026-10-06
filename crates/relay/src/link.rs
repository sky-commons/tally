//! One relay connection of each kind: a feeder publishing its own batches, a subscriber taking
//! the streams it asked for, an MLAT engine doing both with its own positions, another relay
//! exchanging both ways, and the loopback BEAST output.
//!
//! Every write has a deadline: a Noise `Writer::send` fails with `WireError::Timeout` after
//! `noise::WRITE_TIMEOUT`, leaving the writer mid-frame, and like any send error here that ends the
//! link (a subscriber's, an engine's, a feeder's greeting and heartbeats, an accepted relay's, an
//! upstream's, which then redials). A beast-out client's writes are held to `BEAST_WRITE_TIMEOUT`.
//! A peer that heartbeats but never reads therefore holds its slot no longer than the deadline.

use std::sync::Arc;
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::noise::{self, Accepted, Reader, Writer};
use tally_wire::{Identity, Location, PublicKey, Reason, ReceiverInfo, Record, Role};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::{self, error::RecvError, error::TryRecvError};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::ceiling::{self, Ceiling, Metered};
use crate::config::Upstream;
use crate::hub::{Hub, Item};
use crate::subscription::{Subscription, peer_wants};
use tally_wire::record::MAX_REGIONS;

/// A peer that says nothing for this long is gone. Every side heartbeats well inside it.
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const HEARTBEAT: Duration = Duration::from_secs(30);
/// The most records gathered into one send.
const SEND_BATCH: usize = 256;
/// The most record bytes gathered into one send (beyond the record that crosses it): what a link
/// holds of records the fan-out ring may already have let go, while a send waits on a slow peer.
const SEND_BYTES: usize = 4 * noise::MAX_PLAINTEXT;
/// The most description bytes in one send of a dump (beyond the description that crosses it): a
/// directory of tens of megabytes goes out as many sends, each well inside the write deadline.
const DUMP_BYTES: usize = 256 * 1024;
/// The least time between two changes of one session's subscription taking effect. Each change
/// costs a copy of every description held and a filter over it, so a `Subscribe` arriving sooner
/// is not an error but is held, replaced by any that follows it, until this has passed since the
/// last one took effect: however fast a peer resubscribes, the relay answers it at most once a
/// second, and the latest subscription always wins. The first change after joining is immediate.
pub const SUBSCRIBE_EVERY: Duration = Duration::from_secs(1);
/// How long one write to a beast-out client may take before the client is dropped: the same
/// deadline as a Noise session's.
const BEAST_WRITE_TIMEOUT: Duration = noise::WRITE_TIMEOUT;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a subscriber turned away at capacity is asked to stay away.
const FULL_RETRY_SECS: u32 = 600;
/// How long a peer refused outright (a key not accepted as a relay, a broken protocol) is asked to
/// stay away.
const REFUSED_RETRY_SECS: u32 = 86_400;
/// How long a connection that sent more than its ingest ceiling is asked to stay away.
const OVER_CEILING_RETRY_SECS: u32 = 60;
/// The longest a goodbye is given to reach a peer before the link is dropped anyway.
const FAREWELL_TIMEOUT: Duration = Duration::from_secs(5);

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

/// A feeder's own description, as it last sent it: given to the hub again when the hub has
/// forgotten it and the feeder is publishing (see `hub::RECEIVERS_REMEMBERED`).
struct Described {
    info: ReceiverInfo,
    issued_ms: u64,
    place: Option<Location>,
}

/// Which records on the fan-out a link is sent.
enum Wants {
    /// Another relay: everything but the deduplicated stream.
    Peer,
    /// A subscriber or engine: the subscription in effect, which the write side alone changes, so
    /// a newly covered receiver is described before any of its batches is let through.
    Subscription {
        current: Subscription,
        /// Every `Subscribe` the read side took, the latest only.
        updates: watch::Receiver<Subscription>,
        /// When the next change may take effect (`SUBSCRIBE_EVERY`).
        next: Instant,
    },
}

impl Wants {
    fn subscription(current: Subscription, updates: watch::Receiver<Subscription>) -> Self {
        Self::Subscription {
            current,
            updates,
            next: Instant::now(),
        }
    }

    fn wants(&self, item: &Item) -> bool {
        match self {
            Self::Peer => peer_wants(item),
            Self::Subscription { current, .. } => current.wants(item),
        }
    }

    /// Resolves with the latest subscription asked for, no sooner than `SUBSCRIBE_EVERY` after the
    /// last; a relay's never changes. It takes effect at `apply`, once the descriptions it newly
    /// covers are sent.
    async fn changed(&mut self) -> Subscription {
        if let Self::Subscription { updates, next, .. } = self {
            tokio::time::sleep_until(*next).await;
            if updates.changed().await.is_ok() {
                *next = Instant::now() + SUBSCRIBE_EVERY;
                return updates.borrow_and_update().clone();
            }
        }
        std::future::pending().await
    }

    fn apply(&mut self, subscription: Subscription) {
        if let Self::Subscription { current, .. } = self {
            *current = subscription;
        }
    }
}

/// What a link is sent from the fan-out: the descriptions known when it joined, sent before it
/// takes its place in the stream (see `Hub::subscribe`), and its filter.
struct FanOut {
    infos: Vec<Item>,
    wants: Wants,
}

/// Why a link ends.
enum End {
    /// The peer is told why first, so it knows whether and when to come back.
    Told {
        reason: Reason,
        retry_after_secs: u32,
        why: String,
    },
    /// Closed without a word: the peer broke a rule it cannot have broken by accident.
    Closed(String),
    /// Another relay said goodbye (or "leave me"), asking for this long before the next try.
    Departed { retry_after_secs: u32 },
}

impl From<String> for End {
    fn from(why: String) -> Self {
        Self::Closed(why)
    }
}

/// Sends a `Goodbye` with `reason`, bounded, before a session is dropped.
async fn goodbye<S: AsyncWrite>(writer: &mut Writer<S>, reason: Reason, retry_after_secs: u32) {
    let _ = tokio::time::timeout(
        FAREWELL_TIMEOUT,
        writer.send(&[Record::Goodbye {
            reason,
            retry_after_secs,
        }]),
    )
    .await;
}

/// Ends a session that is not yet exchanging: tells the peer if `end` says to, and says why.
async fn end_now<S: AsyncWrite>(writer: &mut Writer<S>, end: End) -> String {
    match end {
        End::Told {
            reason,
            retry_after_secs,
            why,
        } => {
            goodbye(writer, reason, retry_after_secs).await;
            why
        }
        End::Closed(why) => why,
        End::Departed { retry_after_secs } => {
            format!("the relay left, asking for {retry_after_secs} s")
        }
    }
}

pub async fn inbound<S>(stream: S, identities: &[Identity], hub: Arc<Hub>) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    // Every byte the peer sends is counted from the first, the handshake's included.
    let (stream, read) = Metered::new(stream);
    let Accepted {
        mut session,
        peer: key,
        role,
        first,
    } = noise::accept(stream, identities)
        .await
        .map_err(|error| error.to_string())?;
    let source = hub.connection_id();
    let peer = match role {
        Role::Feeder => Peer::Feeder(key),
        Role::Relay if hub.accepts_relay(&key) => Peer::Relay,
        Role::Relay => {
            goodbye(&mut session.writer, Reason::Refused, REFUSED_RETRY_SECS).await;
            return Err(format!("{key} is not a relay this one accepts"));
        }
        Role::Subscriber => Peer::Subscriber,
        Role::Engine => Peer::Engine(key),
        Role::Other(role) => {
            goodbye(&mut session.writer, Reason::Protocol, REFUSED_RETRY_SECS).await;
            return Err(format!("unknown role {role}"));
        }
    };
    let (subscribe, mut subscription) = watch::channel(Subscription::default());
    let steer = matches!(peer, Peer::Subscriber | Peer::Engine(_)).then_some(&subscribe);
    let mut described = None;
    // What came with Hello is acted on before anything is sent: a subscriber's first `Subscribe`
    // decides its first byte.
    for record in first {
        if let Err(end) = ingest(record, &hub, source, peer, steer, &mut described) {
            return Err(end_now(&mut session.writer, end).await);
        }
    }
    let (greeting, fan_out, _slot) = match peer {
        Peer::Feeder(_) => {
            // What the relay will take from it, less framing, so a feeder that keeps to it never
            // meets the ceiling.
            let (bytes_per_sec, burst) = ceiling::advertised(hub.feeder_bytes_per_sec());
            let mut greeting = vec![Record::RateLimit {
                bytes_per_sec,
                burst,
            }];
            // Relays it may also choose, as hints (RFC-0171 §3.7).
            if !hub.hints().is_empty() {
                greeting.push(Record::RelayList(hub.hints().to_vec()));
            }
            (greeting, None, None)
        }
        Peer::Relay => {
            let fan_out = FanOut {
                infos: hub.peer(),
                wants: Wants::Peer,
            };
            (Vec::new(), Some(fan_out), None)
        }
        Peer::Subscriber | Peer::Engine(_) => {
            let current = subscription.borrow_and_update().clone();
            // An engine is served as a subscriber is, and counts against the same cap.
            let Some((infos, slot)) = hub.subscribe(&current) else {
                let redirect = Record::Redirect {
                    retry_after_secs: FULL_RETRY_SECS,
                    hints: hub.hints().to_vec(),
                };
                let _ =
                    tokio::time::timeout(FAREWELL_TIMEOUT, session.writer.send(&[redirect])).await;
                return Err("at subscriber capacity".to_owned());
            };
            let fan_out = FanOut {
                infos,
                wants: Wants::subscription(current, subscription),
            };
            (Vec::new(), Some(fan_out), Some(slot))
        }
    };
    exchange(
        &mut session.reader,
        &mut session.writer,
        &hub,
        source,
        peer,
        Serving {
            greeting,
            fan_out,
            subscribe: steer,
            described,
            // A relay the operator accepted carries a whole region, as an upstream link does, so
            // like one it is not held to a feeder's ceiling; every other inbound peer is.
            ceiling: (!matches!(peer, Peer::Relay))
                .then(|| Ceiling::new(hub.feeder_bytes_per_sec(), read)),
        },
    )
    .await
    .map(|_| ())
}

/// How long an upstream link must stay up to count as having worked.
const HEALTHY_LINK: Duration = Duration::from_secs(60);
/// The longest a parent can make an upstream link wait before its next try.
const PARENT_WAITS_AT_MOST: Duration = Duration::from_secs(86_400);

/// Keeps a link to a parent relay up for as long as the relay runs, backing off between tries.
pub async fn upstream(upstream: Upstream, identity: Identity, hub: Arc<Hub>) {
    let mut backoff = Backoff::new();
    loop {
        let started = tokio::time::Instant::now();
        let outcome = upstream_once(&upstream, &identity, &hub).await;
        // A link that stayed up was a success: the next wait starts from the shortest again.
        if started.elapsed() >= HEALTHY_LINK {
            backoff.reset();
        }
        match outcome {
            Ok(None) => {}
            // The parent asked for a wait: the next try honours it, up to a day, as a feeder's
            // home relay is honoured.
            Ok(Some(wait)) => {
                let wait = wait.min(PARENT_WAITS_AT_MOST);
                eprintln!(
                    "tally-relay: upstream {} asked this relay to stay away {} s",
                    upstream.address,
                    wait.as_secs()
                );
                backoff.at_least(wait);
            }
            Err(error) => eprintln!("tally-relay: upstream {}: {error}", upstream.address),
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn upstream_once(
    upstream: &Upstream,
    identity: &Identity,
    hub: &Arc<Hub>,
) -> Result<Option<Duration>, String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let mut session = match noise::connect(stream, identity, &upstream.key, Role::Relay).await {
        Ok(session) => session,
        // A parent that does not accept this relay says how long to stay away.
        Err(tally_wire::WireError::Refused {
            retry_after_secs, ..
        }) => return Ok(Some(Duration::from_secs(retry_after_secs.into()))),
        Err(error) => return Err(error.to_string()),
    };
    let source = hub.connection_id();
    exchange(
        &mut session.reader,
        &mut session.writer,
        hub,
        source,
        Peer::Relay,
        Serving {
            greeting: Vec::new(),
            fan_out: Some(FanOut {
                infos: hub.peer(),
                wants: Wants::Peer,
            }),
            subscribe: None,
            described: None,
            // A parent the operator chose to dial carries what it carries.
            ceiling: None,
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
    /// A feeder's own description, if it sent one with its `Hello`.
    described: Option<Described>,
    /// What the peer may send, for a connection that dialled in.
    ceiling: Option<Ceiling>,
}

/// A `Goodbye` for the write side to send, and why the link ends.
type Farewell = (Record, String);

/// Runs a connection's two directions until either ends. When the read side ends with something
/// to tell the peer, the write side sends it, between whole messages, and ends the link.
async fn exchange<S>(
    reader: &mut Reader<S>,
    writer: &mut Writer<S>,
    hub: &Hub,
    source: u64,
    peer: Peer,
    serving: Serving<'_>,
) -> Result<Option<Duration>, String>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let Serving {
        greeting,
        fan_out,
        subscribe,
        described,
        ceiling,
    } = serving;
    let (farewell, mut farewells) = mpsc::channel::<Farewell>(1);
    let reading = async {
        match read_loop(reader, hub, source, peer, subscribe, described, ceiling).await {
            Ok(()) => Ok(None),
            Err(End::Closed(why)) => Err(why),
            Err(End::Departed { retry_after_secs }) => {
                Ok(Some(Duration::from_secs(retry_after_secs.into())))
            }
            Err(End::Told {
                reason,
                retry_after_secs,
                why,
            }) => {
                let goodbye = Record::Goodbye {
                    reason,
                    retry_after_secs,
                };
                let _ = farewell.send((goodbye, why.clone())).await;
                // The write side ends the link once it has said goodbye; this only bounds a write
                // side stuck on a peer that does not read.
                tokio::time::sleep(FAREWELL_TIMEOUT).await;
                Err(why)
            }
        }
    };
    tokio::select! {
        result = reading => result,
        result = write_loop(writer, hub, source, greeting, fan_out, &mut farewells) => {
            result.map(|()| None)
        }
    }
}

async fn read_loop<S: AsyncRead>(
    reader: &mut Reader<S>,
    hub: &Hub,
    source: u64,
    peer: Peer,
    subscribe: Option<&watch::Sender<Subscription>>,
    mut described: Option<Described>,
    mut ceiling: Option<Ceiling>,
) -> Result<(), End> {
    let mut records = Vec::new();
    loop {
        records.clear();
        tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut records))
            .await
            .map_err(|_| "silent too long".to_owned())?
            .map_err(|error| error.to_string())?;
        if ceiling.as_mut().is_some_and(|ceiling| !ceiling.within()) {
            return Err(End::Told {
                reason: Reason::Full,
                retry_after_secs: OVER_CEILING_RETRY_SECS,
                why: "sent more than its ingest ceiling".to_owned(),
            });
        }
        for record in records.drain(..) {
            ingest(record, hub, source, peer, subscribe, &mut described)?;
        }
    }
}

fn ingest(
    record: Record,
    hub: &Hub,
    source: u64,
    peer: Peer,
    subscribe: Option<&watch::Sender<Subscription>>,
    described: &mut Option<Described>,
) -> Result<(), End> {
    match record {
        Record::Batch(batch) => {
            let receiver = batch.receiver().map_err(|error| error.to_string())?;
            if !peer.may_publish_batch(receiver) {
                return Err(format!("published a batch signed by {receiver}").into());
            }
            // A receiver's signature only: a relay's deduplicated batch never passes as one.
            batch.verify().map_err(|error| error.to_string())?;
            let new = hub.publish_batch(source, batch, receiver);
            // A feeder's description pushed out while it was not yet publishing comes back now
            // that it is, as one that is.
            if new
                && let Some(own) = described.as_ref()
                && !hub.describes(&receiver)
            {
                hub.publish_info(
                    source,
                    own.info.clone(),
                    receiver,
                    own.issued_ms,
                    own.place,
                    true,
                );
            }
        }
        Record::ReceiverInfo(info) => {
            let receiver = info.receiver().map_err(|error| error.to_string())?;
            if !peer.may_publish_batch(receiver) {
                return Err(format!("published receiver info signed by {receiver}").into());
            }
            info.verify().map_err(|error| error.to_string())?;
            // A format this build cannot read still forwards; it just never replaces a known one,
            // and places its receiver nowhere.
            let (issued_ms, place) = info
                .content()
                .map_or((0, None), |content| (content.issued_ms, content.location));
            // Only a feeder's own is kept on its link: a relay forwards many receivers'.
            if matches!(peer, Peer::Feeder(_))
                && described
                    .as_ref()
                    .is_none_or(|own| issued_ms >= own.issued_ms)
            {
                *described = Some(Described {
                    info: info.clone(),
                    issued_ms,
                    place,
                });
            }
            hub.publish_info(source, info, receiver, issued_ms, place, false);
        }
        Record::Positions(positions) => {
            let engine = positions.engine().map_err(|error| error.to_string())?;
            if !peer.may_publish_positions(engine) {
                return Err(format!("published positions signed by {engine}").into());
            }
            positions.verify().map_err(|error| error.to_string())?;
            hub.publish_positions(source, positions, engine);
        }
        Record::Subscribe { streams, regions } => {
            if regions.len() > MAX_REGIONS {
                return Err(End::Told {
                    reason: Reason::Protocol,
                    retry_after_secs: REFUSED_RETRY_SECS,
                    why: format!("subscribed to {} regions", regions.len()),
                });
            }
            if let Some(subscribe) = subscribe {
                subscribe.send_replace(Subscription { streams, regions });
            }
        }
        // A relay this one links to leaves, saying when to come back; an upstream link honours it.
        Record::Goodbye {
            retry_after_secs, ..
        }
        | Record::Redirect {
            retry_after_secs, ..
        } if matches!(peer, Peer::Relay) => {
            return Err(End::Departed { retry_after_secs });
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
    farewells: &mut mpsc::Receiver<Farewell>,
) -> Result<(), String> {
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    writer
        .send(&greeting)
        .await
        .map_err(|error| error.to_string())?;
    let Some(FanOut { infos, mut wants }) = fan_out else {
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    writer
                        .send(&[Record::Heartbeat])
                        .await
                        .map_err(|error| error.to_string())?;
                }
                Some((goodbye, why)) = farewells.recv() => return say(writer, goodbye, why).await,
            }
        }
    };
    // The hub filtered these by what the link wanted when it joined, which is `wants` still. Sent
    // in parts before the link joins the fan-out, so nothing fills behind them (`Hub::subscribe`).
    let infos: Vec<Arc<Record>> = infos.into_iter().map(|item| item.record).collect();
    for part in parts(&infos) {
        writer.send(part).await.map_err(|error| error.to_string())?;
    }
    let mut out = hub.listen();
    let mut pending = Pending::default();
    loop {
        tokio::select! {
            item = out.recv() => {
                match item {
                    Ok(item) => pending.keep(item, source, &wants),
                    Err(RecvError::Lagged(_)) => return fell_behind(writer).await,
                    Err(RecvError::Closed) => return Ok(()),
                }
                while !pending.full() {
                    match out.try_recv() {
                        Ok(item) => pending.keep(item, source, &wants),
                        Err(TryRecvError::Lagged(_)) => return fell_behind(writer).await,
                        Err(_) => break,
                    }
                }
                writer
                    .send(&pending.records)
                    .await
                    .map_err(|error| error.to_string())?;
                pending.clear();
            }
            subscription = wants.changed() => {
                // Describe the receivers the new subscription covers before any of their batches:
                // in parts, keeping up with the fan-out between them under the subscription still
                // in effect, so a large directory never leaves the link fallen behind. A
                // description that changes meanwhile and only the new subscription covers reaches
                // it at its receiver's next description, as on joining (`Hub::subscribe`).
                let infos: Vec<Arc<Record>> = hub
                    .infos_for(&subscription)
                    .into_iter()
                    .map(|item| item.record)
                    .collect();
                for part in parts(&infos) {
                    writer
                        .send(part)
                        .await
                        .map_err(|error| error.to_string())?;
                    if !catch_up(writer, &mut out, &mut pending, source, &wants).await? {
                        return fell_behind(writer).await;
                    }
                }
                wants.apply(subscription);
            }
            Some((goodbye, why)) = farewells.recv() => return say(writer, goodbye, why).await,
            _ = heartbeat.tick() => {
                writer
                    .send(&[Record::Heartbeat])
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

/// Sends everything waiting on the fan-out that `wants` takes, until none is waiting. False when
/// the link has already fallen behind.
async fn catch_up<S: AsyncWrite>(
    writer: &mut Writer<S>,
    out: &mut broadcast::Receiver<Item>,
    pending: &mut Pending,
    source: u64,
    wants: &Wants,
) -> Result<bool, String> {
    loop {
        let mut drained = false;
        while !pending.full() {
            match out.try_recv() {
                Ok(item) => pending.keep(item, source, wants),
                Err(TryRecvError::Lagged(_)) => return Ok(false),
                Err(_) => {
                    drained = true;
                    break;
                }
            }
        }
        if !pending.records.is_empty() {
            writer
                .send(&pending.records)
                .await
                .map_err(|error| error.to_string())?;
            pending.clear();
        }
        if drained {
            return Ok(true);
        }
    }
}

/// `records` in consecutive parts of about `DUMP_BYTES` each, every part at least one record.
fn parts(records: &[Arc<Record>]) -> Vec<&[Arc<Record>]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (at, record) in records.iter().enumerate() {
        if at > start && bytes >= DUMP_BYTES {
            parts.push(&records[start..at]);
            start = at;
            bytes = 0;
        }
        bytes += size(record);
    }
    if start < records.len() {
        parts.push(&records[start..]);
    }
    parts
}

/// Sends the read side's goodbye, bounded, and ends the link with its reason.
async fn say<S: AsyncWrite>(
    writer: &mut Writer<S>,
    goodbye: Record,
    why: String,
) -> Result<(), String> {
    let _ = tokio::time::timeout(FAREWELL_TIMEOUT, writer.send(&[goodbye])).await;
    Err(why)
}

/// Records gathered for one send, at most `SEND_BATCH` of them and about `SEND_BYTES`.
#[derive(Default)]
struct Pending {
    records: Vec<Arc<Record>>,
    bytes: usize,
}

impl Pending {
    /// Never send a record back down the connection it came in on, nor one the link did not ask
    /// for.
    fn keep(&mut self, item: Item, source: u64, wants: &Wants) {
        if item.source != source && wants.wants(&item) {
            self.bytes += size(&item.record);
            self.records.push(item.record);
        }
    }

    fn full(&self) -> bool {
        self.records.len() >= SEND_BATCH || self.bytes >= SEND_BYTES
    }

    fn clear(&mut self) {
        self.records.clear();
        self.bytes = 0;
    }
}

/// A record's signed bytes, near enough its size on the wire.
fn size(record: &Record) -> usize {
    match record {
        Record::Batch(batch) | Record::RelayBatch(batch) => batch.as_bytes().len(),
        Record::ReceiverInfo(info) => info.as_bytes().len(),
        Record::Positions(positions) => positions.as_bytes().len(),
        _ => 0,
    }
}

async fn fell_behind<S: AsyncWrite>(writer: &mut Writer<S>) -> Result<(), String> {
    goodbye(writer, Reason::Full, 30).await;
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
        let out = hub.listen();
        tokio::spawn(async move {
            if let Err(error) = beast_client(stream, out, BEAST_WRITE_TIMEOUT).await {
                eprintln!("tally-relay: beast-out {peer}: {error}");
            }
        });
    }
}

/// Writes every reception to one client, each write held to `deadline`.
async fn beast_client<W: AsyncWrite + Unpin>(
    mut stream: W,
    mut out: broadcast::Receiver<Item>,
    deadline: Duration,
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
        tokio::time::timeout(deadline, stream.write_all(&bytes))
            .await
            .map_err(|_| "write timed out".to_owned())?
            .map_err(|error| error.to_string())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::beast::FrameKind;
    use tally_wire::{Batch, BatchContent, Frame, Observation, Streams};
    use tokio::time::timeout;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    #[tokio::test]
    async fn an_upstream_link_a_parent_refuses_waits_as_long_as_the_parent_asks()
    -> Result<(), String> {
        // A parent that accepts no relays: it refuses this one, asking for a day.
        let parent = Identity::generate().map_err(text)?;
        let parent_key = parent.public();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(text)?;
        let address = listener.local_addr().map_err(text)?.to_string();
        tokio::spawn(crate::serve(listener, vec![parent], Arc::new(Hub::new(8))));
        let child = Identity::generate().map_err(text)?;
        let upstream = Upstream {
            address,
            key: parent_key,
        };
        let asked = upstream_once(&upstream, &child, &Arc::new(Hub::new(8))).await?;
        assert_eq!(asked, Some(Duration::from_secs(REFUSED_RETRY_SECS.into())));
        Ok(())
    }

    #[tokio::test]
    async fn an_upstream_link_a_parent_says_goodbye_to_returns_the_parents_wait()
    -> Result<(), String> {
        // A parent that welcomes the link and then leaves, asking for 77 s.
        let parent = Identity::generate().map_err(text)?;
        let parent_key = parent.public();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(text)?;
        let address = listener.local_addr().map_err(text)?.to_string();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut accepted) = noise::accept(stream, &[parent]).await
            {
                let _ = accepted
                    .session
                    .writer
                    .send(&[Record::Goodbye {
                        reason: Reason::Full,
                        retry_after_secs: 77,
                    }])
                    .await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let child = Identity::generate().map_err(text)?;
        let upstream = Upstream {
            address,
            key: parent_key,
        };
        let asked = upstream_once(&upstream, &child, &Arc::new(Hub::new(8))).await?;
        assert_eq!(asked, Some(Duration::from_secs(77)));
        Ok(())
    }

    /// A batch of `count` distinct Mode S messages, well inside one message.
    fn batch(receiver: &Identity, sequence: u64, count: u32) -> Result<Batch, String> {
        let observations = (0..count)
            .map(|n| {
                let mut message = [0x8d; 14];
                message[1..5].copy_from_slice(&n.to_be_bytes());
                Frame::new(FrameKind::ModeSLong, u64::from(n), 100, &message)
                    .map(|frame| Observation::from_beast(&frame))
                    .map_err(text)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Batch::sign(
            receiver,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations,
            },
        )
        .map_err(text)
    }

    // Paused: time moves only when every task waits, so each deadline is met exactly.
    #[tokio::test(start_paused = true)]
    async fn a_subscriber_that_heartbeats_but_never_reads_is_dropped_at_the_write_deadline()
    -> Result<(), String> {
        let hub = Arc::new(Hub::new(1));
        let relay = Identity::generate().map_err(text)?;
        let relay_key = relay.public();
        let (near, far) = tokio::io::duplex(64 * 1024);
        let serving = tokio::spawn({
            let hub = Arc::clone(&hub);
            async move { inbound(far, &[relay], hub).await }
        });
        let session = noise::connect(
            near,
            &Identity::generate().map_err(text)?,
            &relay_key,
            Role::Subscriber,
        )
        .await
        .map_err(text)?;
        // It keeps its read deadline alive and never reads a byte.
        let unread = session.reader;
        let mut writer = session.writer;
        let beating = tokio::spawn(async move {
            while writer.send(&[Record::Heartbeat]).await.is_ok() {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        timeout(Duration::from_secs(10), async {
            while hub.subscribers() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "the subscriber was never served".to_owned())?;
        // Many times what the pipe holds, and far less than the fan-out's slack, so the relay's
        // write blocks rather than the subscriber falling behind.
        let receiver = Identity::generate().map_err(text)?;
        let started = Instant::now();
        for sequence in 0..64 {
            hub.publish_batch(999, batch(&receiver, sequence, 1_000)?, receiver.public());
        }
        let ended = timeout(noise::WRITE_TIMEOUT + Duration::from_secs(10), serving)
            .await
            .map_err(|_| "the relay kept the session past its write deadline".to_owned())?
            .map_err(text)?;
        let took = started.elapsed();
        assert!(
            matches!(&ended, Err(why) if why.contains("timed out")),
            "ended with {ended:?}"
        );
        // Virtual time: the send that blocked was the one started when the batches went out.
        assert!(
            took >= noise::WRITE_TIMEOUT && took < noise::WRITE_TIMEOUT + Duration::from_secs(1),
            "{took:?}"
        );
        // Its place is free for the next subscriber.
        assert_eq!(hub.subscribers(), 0);
        drop(unread);
        beating.abort();
        Ok(())
    }

    // Paused: time moves only when every task waits, so each deadline is met exactly.
    #[tokio::test(start_paused = true)]
    async fn a_beast_out_client_that_never_reads_is_dropped_at_its_deadline() -> Result<(), String>
    {
        let hub = Hub::new(1);
        let (unread, far) = tokio::io::duplex(1024);
        let client = tokio::spawn(beast_client(far, hub.listen(), Duration::from_millis(200)));
        let receiver = Identity::generate().map_err(text)?;
        hub.publish_batch(999, batch(&receiver, 0, 200)?, receiver.public());
        let ended = timeout(Duration::from_secs(5), client)
            .await
            .map_err(|_| "the client was kept past its deadline".to_owned())?
            .map_err(text)?;
        assert_eq!(ended, Err("write timed out".to_owned()));
        drop(unread);
        Ok(())
    }

    // Paused: time moves only when every task waits, so each deadline is met exactly.
    #[tokio::test(start_paused = true)]
    async fn a_session_changes_its_subscription_at_most_once_a_second() -> Result<(), String> {
        let (subscribe, updates) = watch::channel(Subscription::default());
        let mut wants = Wants::subscription(Subscription::default(), updates);
        let to = |streams| Subscription {
            streams,
            regions: Vec::new(),
        };
        // The first change takes effect at once.
        subscribe.send_replace(to(Streams::POSITIONS));
        let first = timeout(Duration::from_millis(200), wants.changed())
            .await
            .map_err(|_| "the first change was held".to_owned())?;
        assert_eq!(first, to(Streams::POSITIONS));
        // A burst after it is held until a second has passed, and only the last of it counts.
        for streams in [
            Streams::RAW,
            Streams::DEDUPLICATED,
            Streams::RAW.with(Streams::POSITIONS),
        ] {
            subscribe.send_replace(to(streams));
        }
        assert!(
            timeout(Duration::from_millis(800), wants.changed())
                .await
                .is_err(),
            "a change took effect within a second of the last"
        );
        let next = timeout(Duration::from_millis(500), wants.changed())
            .await
            .map_err(|_| "the held change never took effect".to_owned())?;
        assert_eq!(next, to(Streams::RAW.with(Streams::POSITIONS)));
        wants.apply(next);
        assert!(
            wants.wants(&Item {
                source: 1,
                record: Arc::new(Record::Positions(
                    tally_wire::Positions::sign(
                        &Identity::generate().map_err(text)?,
                        &tally_wire::PositionsContent {
                            boot_id: 1,
                            sequence: 0,
                            issued_ms: 0,
                            positions: Vec::new(),
                        },
                    )
                    .map_err(text)?
                )),
                cell: None,
            })
        );
        Ok(())
    }

    /// Counts what a subscriber reads in one `recv`, failing on a goodbye.
    async fn read_some<S: AsyncRead>(
        reader: &mut Reader<S>,
        infos: &mut usize,
        batches: &mut usize,
    ) -> Result<(), String> {
        let mut records = Vec::new();
        timeout(Duration::from_secs(20), reader.recv(&mut records))
            .await
            .map_err(|_| "the relay stopped sending".to_owned())?
            .map_err(text)?;
        for record in records {
            match record {
                Record::ReceiverInfo(_) => *infos += 1,
                Record::Batch(_) => *batches += 1,
                Record::Goodbye { reason, .. } => return Err(format!("dropped: {reason:?}")),
                _ => {}
            }
        }
        Ok(())
    }

    // Paused: time moves only when every task waits, so each deadline is met exactly.
    #[tokio::test(start_paused = true)]
    async fn a_subscriber_joining_a_large_directory_gets_all_of_it_and_is_not_dropped()
    -> Result<(), String> {
        use tally_wire::Clock;
        use tally_wire::batch::ReceiverInfoContent;
        const DESCRIBED: usize = 4_000;
        // A ring far smaller than the directory: one send of the whole of it would leave the
        // subscriber behind.
        const RING: usize = 16;
        let hub = Arc::new(Hub::with_capacity(1, RING));
        let author = Identity::generate().map_err(text)?;
        let info = ReceiverInfo::sign(
            &author,
            &ReceiverInfoContent {
                issued_ms: 1,
                location: None,
                clock: Clock::Dump1090,
                software: "x".repeat(200),
                relays: Vec::new(),
            },
        )
        .map_err(text)?;
        for _ in 0..DESCRIBED {
            let receiver = Identity::generate().map_err(text)?.public();
            hub.publish_info(999, info.clone(), receiver, 1, None, false);
        }
        let relay = Identity::generate().map_err(text)?;
        let relay_key = relay.public();
        let (near, far) = tokio::io::duplex(64 * 1024);
        let _serving = tokio::spawn({
            let hub = Arc::clone(&hub);
            async move { inbound(far, &[relay], hub).await }
        });
        let session = noise::connect(
            near,
            &Identity::generate().map_err(text)?,
            &relay_key,
            Role::Subscriber,
        )
        .await
        .map_err(text)?;
        let (mut reader, mut writer) = (session.reader, session.writer);
        timeout(Duration::from_secs(10), async {
            while hub.subscribers() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "the subscriber was never served".to_owned())?;
        // While its first send waits on it, the fan-out moves on by many times the ring.
        let receiver = Identity::generate().map_err(text)?;
        let mut sequence = 0;
        for _ in 0..4 * RING {
            hub.publish_batch(999, batch(&receiver, sequence, 1)?, receiver.public());
            sequence += 1;
        }
        let (mut infos, mut batches) = (0, 0);
        while infos < DESCRIBED {
            read_some(&mut reader, &mut infos, &mut batches).await?;
        }
        assert_eq!((infos, batches), (DESCRIBED, 0));
        // Joined the fan-out once the directory was sent.
        tokio::time::sleep(Duration::from_millis(100)).await;
        hub.publish_batch(999, batch(&receiver, sequence, 1)?, receiver.public());
        sequence += 1;
        while batches < 1 {
            read_some(&mut reader, &mut infos, &mut batches).await?;
        }
        // Changing what it wants sends the directory again, in parts, while batches keep coming
        // one per read: more of them during the dump than the ring holds, all delivered.
        writer
            .send(&[Record::Subscribe {
                streams: Streams::RAW,
                regions: Vec::new(),
            }])
            .await
            .map_err(text)?;
        let (mut again, mut during) = (0, 0);
        let mut published = 0;
        while again < DESCRIBED {
            read_some(&mut reader, &mut again, &mut during).await?;
            hub.publish_batch(999, batch(&receiver, sequence, 1)?, receiver.public());
            sequence += 1;
            published += 1;
        }
        assert!(published > RING, "only {published} batches during the dump");
        while during < published {
            read_some(&mut reader, &mut again, &mut during).await?;
        }
        assert_eq!((again, during), (DESCRIBED, published));
        Ok(())
    }
}
