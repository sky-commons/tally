//! One relay connection of each kind: a feeder publishing its own batches, a subscriber taking
//! the streams it asked for, an MLAT engine doing both with its own positions, another relay
//! exchanging both ways, and the loopback BEAST output.
//!
//! Every write has a deadline: a Noise `Writer::send` fails with `WireError::Timeout` after
//! `noise::WRITE_TIMEOUT`, leaving the writer mid-frame, and like any send error here that ends the
//! link (a subscriber's, an engine's, a feeder's greeting and heartbeats, an accepted relay's, an
//! upstream's, which then redials). A beast-out client's writes are held to `BEAST_WRITE_TIMEOUT`.
//! A peer that heartbeats but never reads therefore holds its slot no longer than the deadline.
//!
//! Every stream is an `egress::Socket`, so every byte written is counted and held to the upload cap.
//! Each record a link gathers is classified once (`egress::Class::of`) and waits for its class's
//! grant before it is sent (`send_data`), highest class first; a link the cap sheds is turned away
//! (`full`), and a feeder the cap cannot carry is turned away before it publishes anything.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tally_wire::backoff::Backoff;
use tally_wire::fault_proof::{FAULT_PROOF_FORMAT, MODEL_FAULT_PROOF_FORMAT};
use tally_wire::noise::{self, Accepted, Reader, Writer};
use tally_wire::{Identity, PublicKey, Reason, Record, Role, Tolerance};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::ceiling::{self, Ceiling, Metered};
use crate::config::Upstream;
use crate::egress::{Class, Kind, Link, Shed, Socket};
use crate::fanout::{Fell, Filter, Listener, Taken};
use crate::hub::{Description, Hub, Inbound, Item, Origin, OwnDescription, RelayTrust};
use crate::ingest::{Allowance, InFlight, Refusal};
use crate::network::{Asker, AskerRole};
use crate::subscription::{Subscription, directory_wants, on_directory_link};
use tally_wire::RelayAddress;
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
/// How long a peer turned away at capacity (the subscriber cap, or the upload cap) is asked to stay
/// away.
const FULL_RETRY_SECS: u32 = 600;
/// How long a peer refused outright (a broken protocol, a role it may not take) is asked to stay
/// away.
const REFUSED_RETRY_SECS: u32 = 86_400;
/// How long a relay refused because this one has not verified its offer is asked to stay away:
/// one re-signing of its offers (`directory::OWN_RESIGN_EVERY_MS`), by when its newest offer has
/// reached this relay and been verified, if it is going to be. A refusal for that is a wait for
/// gossip, not a verdict, so it is never the day a broken peer is given.
const UNVERIFIED_RETRY_SECS: u32 = (crate::directory::OWN_RESIGN_EVERY_MS / 1000) as u32;
/// How long a connection that sent more than its ingest ceiling is asked to stay away.
const OVER_CEILING_RETRY_SECS: u32 = 60;
/// How long a relay turned away because every member session the plan admits is held is asked to
/// stay away (`Reason::Full`): it routes what it would have sent this relay to the next members of
/// its trees meanwhile, and doubles the wait each time it is turned away again (`peers`).
const MEMBERS_FULL_RETRY_SECS: u32 = 60;
/// The longest a goodbye is given to reach a peer before the link is dropped anyway.
const FAREWELL_TIMEOUT: Duration = Duration::from_secs(5);
/// After a goodbye, the longest the relay keeps reading (and dropping) what the peer still sends
/// while it waits for the peer to hang up (`farewell`). A peer that has read the goodbye closes at
/// once; this only bounds one that never does.
const FAREWELL_LINGER: Duration = Duration::from_secs(5);

/// Who is on the other end. What each may send, be sent and subscribe to is decided by this
/// type's three rules alone ([`Peer::permit`], [`Peer::takes_reply`], [`Peer::grant`]), each an
/// exhaustive match, so a role added or changed decides all three in one place and no path
/// elsewhere can give a role more.
#[derive(Clone, Copy)]
enum Peer {
    /// A feeder publishes only its own batches and description.
    Feeder(PublicKey),
    /// A relay linked for the directory (`--upstream`, `--accept-relay`, RFC-0174 §2.5): offers
    /// and queries, probes and delivery checks, have-summaries; no data (`on_directory_link`).
    Relay,
    /// A subscriber (a client) publishes nothing, and reads what its credit allows (`credit`).
    Subscriber,
    /// An engine: another relay's MLAT taking an area's raw one hop (RFC-0174 §2.3), accepted
    /// only from a key whose offer this relay verified. It publishes nothing (its relay shares
    /// its positions through the sharing groups) and reads only raw within the border band of
    /// the areas it solves (`subscription::engine_grant`).
    Engine(PublicKey),
    /// A sharing group member (RFC-0174 §2.5), or a relay this one takes one-hop raw from: it
    /// forwards anyone's signed records, and is sent what is addressed to it (stripe slices,
    /// manifests, receipts, answers) and, as a relay link is, the directory.
    Member,
    /// A measurement session (`Role::Probe`): it may send only what `Role::may_send` allows
    /// (echoes and delivery queries), is answered, and is never admitted as a feeder or a
    /// subscriber. Anything else ends it with a goodbye.
    Probe,
}

/// What a peer's record meets ([`Peer::permit`]).
enum Permit {
    /// Taken in.
    Take,
    /// Not taken, and the session goes on: data on a directory link.
    Drop,
    /// The session ends.
    Refuse(End),
}

impl Peer {
    /// The peer as it stands now: a directory link whose offer this relay has since verified is a
    /// member, however its session was opened (a member's may open before the verification).
    fn now(self, hub: &Hub, key: &PublicKey) -> Self {
        match self {
            Self::Relay if hub.relay_trust(key) == Some(RelayTrust::Member) => Self::Member,
            peer => peer,
        }
    }

    /// Whether the peer may send `record`: the one rule, by role and by the key that signed it.
    /// Records anyone may send (a `Subscribe`, a heartbeat, a fault proof, which is checked on its
    /// own, and the network records, whose duties judge their asker) are taken from every role a
    /// probe is not.
    fn permit(self, record: &Record) -> Permit {
        // A delivery query of the retired form is answered on every link, never read and never
        // dropped unheard: its sender hears a Goodbye it already takes as "no answer".
        if let Some(Record::Goodbye {
            reason,
            retry_after_secs,
        }) = record.refusal()
        {
            return Permit::Refuse(End::Told {
                reason,
                retry_after_secs,
                why: "a delivery query of the retired form (RFC-0181 §7)".to_owned(),
            });
        }
        match self {
            Self::Member => Permit::Take,
            Self::Probe if Role::Probe.may_send(record) => Permit::Take,
            Self::Probe => Permit::Refuse(End::Told {
                reason: Reason::Protocol,
                retry_after_secs: REFUSED_RETRY_SECS,
                why: "a probe sent more than echoes and delivery queries".to_owned(),
            }),
            Self::Relay if on_directory_link(record) => Permit::Take,
            Self::Relay => Permit::Drop,
            Self::Feeder(own) => match (record, signer(record)) {
                (Record::Batch(_) | Record::ReceiverInfo(_), Some((_, Ok(key)))) if key == own => {
                    Permit::Take
                }
                _ => publishes_nothing(record),
            },
            Self::Subscriber | Self::Engine(_) => publishes_nothing(record),
        }
    }

    /// Whether a reply the network duties give (`Network::handle`) is sent to the peer: anything
    /// to a member; the directory to a directory link; to any other peer, only what is control
    /// to it (an echo's reply, a delivery answer, offers to a feeder that asked). A repair's
    /// batches and positions therefore reach only a member, and through the upload cap
    /// (`reply`).
    fn takes_reply(self, record: &Record, kind: Kind) -> bool {
        match self {
            Self::Member => true,
            Self::Relay => on_directory_link(record),
            Self::Feeder(_) | Self::Subscriber | Self::Engine(_) | Self::Probe => {
                Class::of(record, kind) == Class::Control
            }
        }
    }

    /// What the peer is served of the streams, given what it asked for: a subscriber what its
    /// credit allows; an engine raw within the border band of the areas it solves; every other
    /// role nothing, as it subscribes to nothing.
    fn grant(self, hub: &Hub, asker: &Asker, asked: Subscription, now_ms: u64) -> Subscription {
        match self {
            Self::Subscriber => hub.network().credit.admit(asker, asked, now_ms),
            Self::Engine(key) => {
                crate::subscription::engine_grant(&hub.network().directory, &key, &asked, now_ms)
            }
            Self::Feeder(_) | Self::Relay | Self::Member | Self::Probe => Subscription::nothing(),
        }
    }
}

/// What only the key that signed it may publish, by its kind: what it is called, and its signer.
fn signer(record: &Record) -> Option<(&'static str, Result<PublicKey, tally_wire::WireError>)> {
    match record {
        Record::Batch(batch) => Some(("a batch", batch.receiver())),
        Record::ReceiverInfo(info) => Some(("receiver info", info.receiver())),
        Record::Positions(positions) => Some(("positions", positions.engine())),
        Record::Provisional(positions) => Some(("provisional positions", positions.engine())),
        Record::ClockModel(model) => Some(("a clock model", model.engine())),
        _ => None,
    }
}

/// The permit of a role that publishes no data of its own: every signed record (and a clock
/// model's part, which travels only with its model) ends its session; the rest is taken.
fn publishes_nothing(record: &Record) -> Permit {
    match (record, signer(record)) {
        (Record::ClockModelPart(_), _) => {
            Permit::Refuse(End::Closed("published a clock model part".to_owned()))
        }
        (_, Some((what, Ok(key)))) => {
            Permit::Refuse(End::Closed(format!("published {what} signed by {key}")))
        }
        (_, Some((what, Err(error)))) => {
            Permit::Refuse(End::Closed(format!("published {what}: {error}")))
        }
        _ => Permit::Take,
    }
}

/// Held while a feeder is connected: its end ends the feeder's session in the station reports.
struct Feeding {
    hub: Arc<Hub>,
    receiver: PublicKey,
    source: u64,
}

impl Drop for Feeding {
    fn drop(&mut self) {
        self.hub.left(&self.receiver, self.source);
    }
}

/// A feeder's own description, as it last sent it: given to the hub again when the hub has
/// forgotten it and the feeder is publishing (see `hub::RECEIVERS_REMEMBERED`). Shared with each
/// batch the link hands the ingest stage, which acts on it there.
type Described = Arc<OwnDescription>;

/// Which records on the fan-out a link is sent.
enum Wants {
    /// Another relay: the directory only (`directory_wants`).
    Directory,
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
            Self::Directory => directory_wants(item),
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

    /// What the router offers a link that wants this.
    fn filter(&self) -> Filter {
        match self {
            Self::Directory => Filter::Directory,
            Self::Subscription { current, .. } => Filter::Subscription(current.clone()),
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
    /// Another relay said goodbye (or "leave me"), asking for this long before the next try, and
    /// whether it said it is full (`Reason::Full`).
    Departed(Away),
}

/// Why a relay this one dialled ended the session with a word: how long it asked to be left, and
/// whether it said it is full (`Reason::Full`: for a relay sending it data, it holds every member
/// session its plan admits, RFC-0174 §2.5), which the dialler takes as "this provider is full" and
/// routes around (`peers::Peers::refused_full`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Away {
    pub wait: Duration,
    pub full: bool,
}

impl Away {
    fn of(reason: Reason, retry_after_secs: u32) -> Self {
        Self {
            wait: Duration::from_secs(retry_after_secs.into()),
            full: reason == Reason::Full,
        }
    }
}

impl From<String> for End {
    fn from(why: String) -> Self {
        Self::Closed(why)
    }
}

/// The one way the relay ends a session with a last word (a `Goodbye` or a `Redirect`): every
/// path that tells a peer to leave comes here, and none closes the socket any other way.
///
/// It sends `last`, bounded by `FAREWELL_TIMEOUT`, ends the sending direction, then reads and drops
/// whatever the peer still sends until it hangs up, bounded by `FAREWELL_LINGER`, and only then
/// lets the session close. A socket closed with bytes unread is reset, and a reset discards what of
/// the last word the kernel had not yet sent, so a feeder still publishing when it is redirected
/// would otherwise never read why. A peer that does not take the last word in time is not waited
/// on further: the writer may be mid-message, and nothing more can be said.
async fn farewell<S>(reader: &mut Reader<S>, writer: &mut Writer<S>, last: Record)
where
    S: AsyncRead + AsyncWrite,
{
    let said = tokio::time::timeout(FAREWELL_TIMEOUT, writer.send(&[last])).await;
    if !matches!(said, Ok(Ok(()))) {
        return;
    }
    if writer.shutdown().await.is_err() {
        return;
    }
    let _ = tokio::time::timeout(FAREWELL_LINGER, reader.discard()).await;
}

/// A `Goodbye` with `reason`.
fn goodbye(reason: Reason, retry_after_secs: u32) -> Record {
    Record::Goodbye {
        reason,
        retry_after_secs,
    }
}

/// What a peer turned away for the relay's capacity is told: the relays it may try instead, or that
/// the relay is full if it knows none.
fn full(hub: &Hub) -> Record {
    if hub.hints().is_empty() {
        Record::Goodbye {
            reason: Reason::Full,
            retry_after_secs: FULL_RETRY_SECS,
        }
    } else {
        Record::Redirect {
            retry_after_secs: FULL_RETRY_SECS,
            hints: hub.hints().to_vec(),
        }
    }
}

/// Ends a session that is not yet exchanging: tells the peer if `end` says to, and says why.
async fn end_now<S>(reader: &mut Reader<S>, writer: &mut Writer<S>, end: End) -> String
where
    S: AsyncRead + AsyncWrite,
{
    match end {
        End::Told {
            reason,
            retry_after_secs,
            why,
        } => {
            farewell(reader, writer, goodbye(reason, retry_after_secs)).await;
            why
        }
        End::Closed(why) => why,
        End::Departed(away) => {
            format!("the relay left, asking for {} s", away.wait.as_secs())
        }
    }
}

pub async fn inbound<S>(
    stream: Socket<S>,
    identities: &[Identity],
    hub: Arc<Hub>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let link = stream.link();
    // Every byte the peer sends is counted from the first, the handshake's included, as every
    // byte sent it is (`Socket`).
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
        // A relay, by the one rule of relay trust (`Hub::relay_trust`): a member if this relay
        // verified its offer, a directory link if the operator accepted its key, else refused.
        Role::Relay => match hub.relay_trust(&key) {
            Some(RelayTrust::Member) => Peer::Member,
            Some(RelayTrust::Directory) => Peer::Relay,
            None => {
                let last = goodbye(Reason::Refused, UNVERIFIED_RETRY_SECS);
                farewell(&mut session.reader, &mut session.writer, last).await;
                return Err(format!(
                    "{key} is neither a relay whose offer this one verified nor one it accepts"
                ));
            }
        },
        Role::Subscriber => Peer::Subscriber,
        // An engine is another relay's MLAT (RFC-0174 §2.3): only a member, a relay whose offer
        // this one verified at its address, may take raw as one.
        Role::Engine => match hub.relay_trust(&key) {
            Some(RelayTrust::Member) => Peer::Engine(key),
            Some(RelayTrust::Directory) | None => {
                let last = goodbye(Reason::Refused, UNVERIFIED_RETRY_SECS);
                farewell(&mut session.reader, &mut session.writer, last).await;
                return Err(format!(
                    "{key} is not a relay whose offer this one verified"
                ));
            }
        },
        Role::Probe => Peer::Probe,
        Role::Other(role) => {
            let last = goodbye(Reason::Protocol, REFUSED_RETRY_SECS);
            farewell(&mut session.reader, &mut session.writer, last).await;
            return Err(format!("unknown role {role}"));
        }
    };
    let asker = Asker {
        role: match peer {
            Peer::Feeder(_) => AskerRole::Feeder,
            Peer::Relay | Peer::Member => AskerRole::Relay,
            Peer::Engine(_) => AskerRole::Engine,
            Peer::Subscriber => AskerRole::Client,
            Peer::Probe => AskerRole::Probe,
        },
        key,
        source,
        loopback: !link.billed(),
    };
    // Whatever this session was given (a client's credit, its free-tier place) ends with it.
    let _leaving = Leaving {
        hub: Arc::clone(&hub),
        source,
    };
    link.set_kind(match peer {
        Peer::Feeder(_) => Kind::Feeder,
        Peer::Relay | Peer::Member => Kind::Relay,
        Peer::Engine(_) => Kind::Engine,
        Peer::Subscriber => Kind::Taker,
        Peer::Probe => Kind::Probe,
    });
    // A probe or a delivery query that came with Hello is answered before anything else,
    // admission included: a feeder measuring relays learns how near a full one is, and that it is
    // full, from its signed reply, and a feeder checking its delivery asks members it does not
    // publish to, full or not.
    let (probes, first): (Vec<Record>, Vec<Record>) = first
        .into_iter()
        .partition(|record| matches!(record, Record::Echo(_) | Record::DeliveryQuery(_)));
    // A probe that sent anything else with its Hello broke its role: it is told so, unanswered.
    if role == Role::Probe && !first.is_empty() {
        let last = goodbye(Reason::Protocol, REFUSED_RETRY_SECS);
        farewell(&mut session.reader, &mut session.writer, last).await;
        return Err("a probe sent more than echoes and delivery queries".to_owned());
    }
    let mut echoed = Vec::new();
    for probe in probes {
        echoed.extend(
            hub.network()
                .handle(&hub, &asker, probe, crate::network::wall_ms()),
        );
    }
    if !echoed.is_empty() {
        session
            .writer
            .send(&echoed)
            .await
            .map_err(|error| error.to_string())?;
    }
    // A feeder is taken only while relay duties are on and the upload cap can carry what it
    // commits the relay to forward (`admission`), and is turned away before anything it sent is
    // taken in.
    let _admitted = match peer {
        Peer::Feeder(_) => match hub.network().admission.admit(&hub) {
            Some(admitted) => Some(admitted),
            None => {
                farewell(&mut session.reader, &mut session.writer, full(&hub)).await;
                return Err(
                    "turned away: no feeder slot (duties off, or the upload cap)".to_owned(),
                );
            }
        },
        _ => None,
    };
    // And only with its bytes reserved in every store (`budget`, RFC-0181 §9): a feeder the
    // relay's memory cannot hold is turned away now, never dropped from a store later.
    let _reserved = match peer {
        Peer::Feeder(_) => match hub.budget().reserve() {
            Some(reservation) => Some(reservation),
            None => {
                farewell(&mut session.reader, &mut session.writer, full(&hub)).await;
                return Err(format!(
                    "turned away: no spare slot (the memory budget holds {} feeders)",
                    hub.budget().ceiling()
                ));
            }
        },
        _ => None,
    };
    // What it may have in the ingest stage, carved from what it reserved (a member's, from its
    // pool, when it is one): the batches its Hello carries are charged like every other.
    let mut admitted = match peer {
        Peer::Feeder(_) => match hub.allowance(hub.budget().per_feeder().ingest) {
            Some(allowance) => Admitted {
                allowance: Some(allowance),
                ..Admitted::default()
            },
            None => {
                farewell(&mut session.reader, &mut session.writer, full(&hub)).await;
                return Err("turned away: no room for its ingest allowance".to_owned());
            }
        },
        // A relay that dialled in is admitted as a member once its offer is verified and it
        // brings data in (`Admitted::charge`).
        Peer::Member | Peer::Relay => Admitted {
            joins: true,
            ..Admitted::default()
        },
        Peer::Subscriber | Peer::Engine(_) | Peer::Probe => Admitted::default(),
    };
    // A feeder's session in the station reports ends with this connection, however it ends.
    let _feeding = match peer {
        Peer::Feeder(receiver) => Some(Feeding {
            hub: Arc::clone(&hub),
            receiver,
            source,
        }),
        _ => None,
    };
    // Before any `Subscribe`, the role is granted what it would be for the version 1 default: so a
    // client that never subscribes is held to its credit, and an engine to its band, from its
    // first byte.
    let initial = peer.grant(
        &hub,
        &asker,
        Subscription::default(),
        crate::network::wall_ms(),
    );
    let (subscribe, mut subscription) = watch::channel(initial);
    let steer = matches!(peer, Peer::Subscriber | Peer::Engine(_)).then_some(&subscribe);
    let mut described = None;
    // What came with Hello is acted on before anything is sent: a subscriber's first `Subscribe`
    // decides its first byte, and a network duty's answers (a probe's, before any) go first.
    let mut answers = Vec::new();
    let refusal = Arc::new(Refusal::default());
    for record in first {
        let in_flight = match admitted.charge(&hub, peer, &asker.key, &record).await {
            Ok(in_flight) => in_flight,
            Err(end) => return Err(end_now(&mut session.reader, &mut session.writer, end).await),
        };
        let ingested = ingest(
            record,
            &hub,
            source,
            (peer, &asker),
            steer,
            &mut described,
            (in_flight, &refusal),
        )
        .or_else(|unhandled| network(unhandled, &hub, &asker, &mut answers));
        if let Err(end) = ingested {
            return Err(end_now(&mut session.reader, &mut session.writer, end).await);
        }
    }
    let (mut greeting, fan_out, _slot) = match peer {
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
        // A relay link and a member's are sent the directory: the offers held, then each new one.
        // A member's data reaches it addressed, over its own session's mirror, this relay's dial.
        Peer::Relay | Peer::Member => (Vec::new(), Some(directory_fan_out()), None),
        // A probe is sent its answers and nothing else.
        Peer::Probe => (Vec::new(), None, None),
        // An engine takes no place among the subscribers (`Hub::engine`): it is a duty of the
        // network, bounded by its grant, and this relay's own one-hop raw links dial as one.
        Peer::Engine(_) => {
            let current = subscription.borrow_and_update().clone();
            let fan_out = FanOut {
                infos: hub.engine(&current),
                wants: Wants::subscription(current, subscription),
            };
            (Vec::new(), Some(fan_out), None)
        }
        Peer::Subscriber => {
            let current = subscription.borrow_and_update().clone();
            let Some((infos, slot)) = hub.subscribe(&current) else {
                let redirect = Record::Redirect {
                    retry_after_secs: FULL_RETRY_SECS,
                    hints: hub.hints().to_vec(),
                };
                farewell(&mut session.reader, &mut session.writer, redirect).await;
                return Err("at subscriber capacity".to_owned());
            };
            let fan_out = FanOut {
                infos,
                wants: Wants::subscription(current, subscription),
            };
            (Vec::new(), Some(fan_out), Some(slot))
        }
    };
    greeting.extend(answers);
    exchange(
        &mut session.reader,
        &mut session.writer,
        &hub,
        source,
        peer,
        &link,
        Serving {
            greeting,
            fan_out,
            subscribe: steer,
            described,
            refusal: Some(refusal),
            admitted,
            asker,
            // Each role its own ceiling, decided by the role its handshake established, never by
            // its key: a member publishes its groups' slices, a feeder one receiver's batches, an
            // engine and a subscriber only their subscriptions. A directory link is held to a
            // member's, as it becomes one the moment its offer is verified (`Peer::now`).
            ceiling: match peer {
                Peer::Relay | Peer::Member => Some(Ceiling::new(
                    hub.member_bytes_per_sec(),
                    read,
                    hub.ceiling_clock(),
                )),
                Peer::Feeder(_) | Peer::Subscriber | Peer::Engine(_) | Peer::Probe => Some(
                    Ceiling::new(hub.feeder_bytes_per_sec(), read, hub.ceiling_clock()),
                ),
            },
            outgoing: None,
        },
    )
    .await
    .map(|_| ())
}

/// How long a dialled link must stay up to count as having worked, so that the next dial after it
/// waits the shortest again: long enough that a peer which takes each session and drops it is
/// dialled at most once in this long, short enough that a duty link dropped for falling behind a
/// burst (an MLAT relay's raw) is back within a second, not after a wait grown by earlier drops.
const HEALTHY_LINK: Duration = Duration::from_secs(10);
/// The longest a peer can make a dialled link wait before its next try.
const PEER_WAITS_AT_MOST: Duration = Duration::from_secs(86_400);

/// The one dial loop's wait (every link this relay dials: an upstream, a sharing member, a one-hop
/// raw source): doubling from a second to five minutes (`Backoff`), back to a second after a link
/// that stayed up `HEALTHY_LINK`, and never shorter than a peer that refused or left asked for
/// (up to `PEER_WAITS_AT_MOST`). A peer that refuses at once is therefore dialled at most once per
/// wait it names, and one that drops every session at once is dialled less and less often.
struct Redial {
    backoff: Backoff,
    dials: Arc<std::sync::atomic::AtomicU64>,
}

impl Redial {
    fn new(dials: Arc<std::sync::atomic::AtomicU64>) -> Self {
        Self {
            backoff: Backoff::new(),
            dials,
        }
    }

    /// Counts a dial about to start.
    fn dialling(&self) -> tokio::time::Instant {
        self.dials
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokio::time::Instant::now()
    }

    /// Waits as the outcome of a session started at `started` says.
    async fn after(
        &mut self,
        started: tokio::time::Instant,
        outcome: Result<Option<Away>, String>,
        who: &str,
    ) {
        if started.elapsed() >= HEALTHY_LINK {
            self.backoff.reset();
        }
        match outcome {
            Ok(None) => {}
            Ok(Some(Away { wait, .. })) => {
                let wait = wait.min(PEER_WAITS_AT_MOST);
                eprintln!(
                    "tally-relay: {who} asked this relay to stay away {} s",
                    wait.as_secs()
                );
                self.backoff.at_least(wait);
            }
            Err(error) => eprintln!("tally-relay: {who}: {error}"),
        }
        tokio::time::sleep(self.backoff.wait()).await;
    }
}

/// A session's refusal by the peer at its handshake, as the wait it asked for and whether it said
/// it is full.
fn refused(error: tally_wire::WireError) -> Result<Option<Away>, String> {
    match error {
        tally_wire::WireError::Refused {
            reason,
            retry_after_secs,
        } => Ok(Some(Away::of(reason, retry_after_secs))),
        error => Err(error.to_string()),
    }
}

/// Keeps a link to a parent relay up for as long as the relay runs, backing off between tries.
pub async fn upstream(upstream: Upstream, identity: Identity, hub: Arc<Hub>) {
    let mut redial = Redial::new(hub.network().dials());
    let who = format!("upstream {}", upstream.address);
    loop {
        let started = redial.dialling();
        let outcome = upstream_once(&upstream, &identity, &hub).await;
        redial.after(started, outcome, &who).await;
    }
}

async fn upstream_once(
    upstream: &Upstream,
    identity: &Identity,
    hub: &Arc<Hub>,
) -> Result<Option<Away>, String> {
    // A place under the connection cap, as every session holds (`Hub::dialled`).
    let _slot = hub
        .dialled()
        .ok_or_else(|| "no connection slot to dial with (--max-connections)".to_owned())?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let peer = stream.peer_addr().ok().map(|address| address.ip());
    let stream = hub.egress().socket(stream, peer);
    let link = stream.link();
    link.set_kind(Kind::Relay);
    let mut session = match noise::connect(stream, identity, &upstream.key, Role::Relay).await {
        Ok(session) => session,
        // A parent that does not accept this relay says how long to stay away.
        Err(error) => return refused(error),
    };
    let source = hub.connection_id();
    exchange(
        &mut session.reader,
        &mut session.writer,
        hub,
        source,
        Peer::Relay,
        &link,
        Serving {
            greeting: Vec::new(),
            fan_out: Some(directory_fan_out()),
            subscribe: None,
            described: None,
            refusal: None,
            admitted: Admitted::default(),
            // A directory link carries offers and queries; only data is held to a ceiling.
            ceiling: None,
            asker: Asker {
                role: AskerRole::Relay,
                key: upstream.key,
                source,
                loopback: !link.billed(),
            },
            outgoing: None,
        },
    )
    .await
}

/// What a link to another relay is sent: the directory, every live offer held and then each new
/// one from the fan-out (`directory_wants`). The offers held are read once the link has joined the
/// fan-out (`write_loop`).
fn directory_fan_out() -> FanOut {
    FanOut {
        infos: Vec::new(),
        wants: Wants::Directory,
    }
}

/// Every live offer this relay holds, its own included, and the evidence they are ranked by.
fn live_offers(hub: &Hub) -> Vec<Arc<Record>> {
    let directory = &hub.network().directory;
    directory
        .live_offers(crate::network::wall_ms())
        .into_iter()
        .map(|offer| Arc::new(Record::ProviderOffer(offer)))
        .chain(
            directory
                .live_evidence()
                .into_iter()
                .map(|bundle| Arc::new(Record::EvidenceBundle(bundle))),
        )
        .collect()
}

/// A session this relay dials to another for RFC-0174's duties (`peers`): to a sharing group
/// member, as a relay, to send it what is addressed to it (`outgoing`); or to a relay that holds
/// raw an MLAT area here needs, as an engine subscribing `first` (a region-cut raw `Subscribe`).
/// What the far relay sends back is taken as a member's: anyone's signed records, published here.
/// Ends when `outgoing` closes; a failed or refused session is dialled again as `Redial` says.
///
/// A sharing member that turns the link away as full (`Reason::Full`, RFC-0174 §2.5) ends it: it
/// is this provider that is full, so the relay routes what it would have sent it to the next
/// members of its trees for as long as it asked, doubled on each refusal after
/// (`peers::Peers::refused_full`), and dials it again only once sharing addresses it again.
pub async fn member(
    relay: RelayAddress,
    identity: Identity,
    role: Role,
    first: Vec<Record>,
    hub: Arc<Hub>,
    mut outgoing: mpsc::Receiver<Vec<Record>>,
) {
    let mut redial = Redial::new(hub.network().dials());
    let who = format!("peer {}", relay.address);
    while !outgoing.is_closed() {
        let started = redial.dialling();
        let outcome = member_once(&relay, &identity, role, &first, &hub, &mut outgoing).await;
        if role == Role::Relay
            && let Ok(Some(away)) = outcome
            && away.full
        {
            let peers = &hub.network().peers;
            peers.refused_full(relay.key, away.wait, crate::network::wall_ms());
            let routed = peers
                .full_for(&relay.key, crate::network::wall_ms())
                .unwrap_or(away.wait);
            eprintln!(
                "tally-relay: {who} is full: routing around it for {} s",
                routed.as_secs()
            );
            return;
        }
        redial.after(started, outcome, &who).await;
    }
}

async fn member_once(
    relay: &RelayAddress,
    identity: &Identity,
    role: Role,
    first: &[Record],
    hub: &Arc<Hub>,
    outgoing: &mut mpsc::Receiver<Vec<Record>>,
) -> Result<Option<Away>, String> {
    // A place under the connection cap, as every session holds (`Hub::dialled`).
    let _slot = hub
        .dialled()
        .ok_or_else(|| "no connection slot to dial with (--max-connections)".to_owned())?;
    // A raw link brings another relay's raw in, so it is a member session: its place in the
    // members' pool is taken before it is dialled, never once data comes, so this relay never
    // dials a link it would then turn away itself. A member link this relay dialled only sends
    // (what the member sends it comes over its own dial), and takes none.
    let admitted = if role == Role::Engine {
        admit_member(hub).map_err(|end| match end {
            End::Told { why, .. } | End::Closed(why) => why,
            End::Departed(_) => "turned away".to_owned(),
        })?
    } else {
        Admitted::default()
    };
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    let address = stream.peer_addr().ok().map(|address| address.ip());
    let stream = hub.egress().socket(stream, address);
    let link = stream.link();
    link.set_kind(Kind::Relay);
    let mut session = match noise::connect_with(stream, identity, &relay.key, role, first).await {
        Ok(session) => session,
        Err(error) => return refused(error),
    };
    let source = hub.connection_id();
    let loopback = !link.billed();
    exchange(
        &mut session.reader,
        &mut session.writer,
        hub,
        source,
        Peer::Member,
        &link,
        Serving {
            greeting: Vec::new(),
            fan_out: None,
            subscribe: None,
            described: None,
            refusal: None,
            admitted,
            ceiling: None,
            asker: Asker {
                role: AskerRole::Relay,
                key: relay.key,
                source,
                loopback,
            },
            outgoing: Some(outgoing),
        },
    )
    .await
}

/// Ends a session's place in the network duties (its credit link, its free-tier place).
struct Leaving {
    hub: Arc<Hub>,
    source: u64,
}

impl Drop for Leaving {
    fn drop(&mut self) {
        self.hub.network().credit.left(self.source);
    }
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
    /// Where a batch refused by the ingest stage ends the connection: the one its `Hello`'s batches
    /// were handed with, if any.
    refusal: Option<Arc<Refusal>>,
    /// What it was admitted with: its ingest allowance and, a member, its reservation.
    admitted: Admitted,
    /// What the peer may send, for a connection that dialled in.
    ceiling: Option<Ceiling>,
    /// Who the peer is, as the network duties see it.
    asker: Asker,
    /// What the network duties address to this peer, for a member link this relay dialled.
    outgoing: Option<&'a mut mpsc::Receiver<Vec<Record>>>,
}

/// Replies the network duties give a peer, waiting for the write side. Beyond this many the newest
/// is dropped: a peer that floods queries gets fewer answers, never more of the relay's memory.
const REPLIES_WAITING: usize = 64;

/// A `Goodbye` for the write side to end on, and why the link ends.
type Farewell = (Record, String);

/// How the write side ended: on a failure, with nothing more to say, or between whole messages with
/// a last word for the peer, which `exchange` says through `farewell` once both directions are its
/// again.
enum Closing {
    Silent(String),
    Saying { last: Box<Record>, why: String },
}

impl From<String> for Closing {
    fn from(why: String) -> Self {
        Self::Silent(why)
    }
}

/// Runs a connection's two directions until either ends. When the read side ends with something
/// to tell the peer, the write side stops between whole messages, and the link ends with it said
/// (`farewell`); so does a write side that ends the link itself (shed, or fallen behind).
async fn exchange<S>(
    reader: &mut Reader<S>,
    writer: &mut Writer<S>,
    hub: &Arc<Hub>,
    source: u64,
    peer: Peer,
    link: &Arc<Link>,
    serving: Serving<'_>,
) -> Result<Option<Away>, String>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let Serving {
        greeting,
        fan_out,
        subscribe,
        described,
        refusal,
        admitted,
        ceiling,
        asker,
        outgoing,
    } = serving;
    let (telling, mut farewells) = mpsc::channel::<Farewell>(1);
    let (replying, mut replies) = mpsc::channel::<Vec<Record>>(REPLIES_WAITING);
    let reading = async {
        let reading = Reading {
            subscribe,
            asker,
            replies: replying,
            refusal: refusal.unwrap_or_default(),
            admitted,
        };
        match read_loop(reader, hub, source, peer, reading, described, ceiling).await {
            Ok(()) => Ok(None),
            Err(End::Closed(why)) => Err(why),
            Err(End::Departed(away)) => Ok(Some(away)),
            Err(End::Told {
                reason,
                retry_after_secs,
                why,
            }) => {
                let goodbye = Record::Goodbye {
                    reason,
                    retry_after_secs,
                };
                let _ = telling.send((goodbye, why.clone())).await;
                // The write side stops for the goodbye between messages; this only bounds a write
                // side stuck on a peer that does not read, which is then closed on with no word.
                tokio::time::sleep(FAREWELL_TIMEOUT).await;
                Err(why)
            }
        }
    };
    let closing = tokio::select! {
        result = reading => return result,
        result = write_loop(
            writer,
            hub,
            source,
            link,
            greeting,
            fan_out,
            Inputs {
                farewells: &mut farewells,
                replies: &mut replies,
                outgoing,
                client: (asker.role == AskerRole::Client && !asker.loopback).then_some(asker),
                steer: subscribe,
                peer: (peer, asker.key),
                vouched: (asker.role == AskerRole::Client
                    && hub.network().credit.vouches_for(&asker.key))
                .then_some(asker),
            },
        ) => result,
    };
    match closing {
        Ok(()) => Ok(None),
        Err(Closing::Silent(why)) => Err(why),
        Err(Closing::Saying { last, why }) => {
            farewell(reader, writer, *last).await;
            Err(why)
        }
    }
}

/// What the read side needs beside the peer: where its `Subscribe`s go, who it is to the network
/// duties, and where their replies go.
struct Reading<'a> {
    subscribe: Option<&'a watch::Sender<Subscription>>,
    asker: Asker,
    replies: mpsc::Sender<Vec<Record>>,
    /// Where the ingest stage says a batch's signature failed.
    refusal: Arc<Refusal>,
    admitted: Admitted,
}

/// What a connection that publishes batches was admitted with (RFC-0181 §2, §9): its allowance
/// in the ingest stage, carved from `Store::Ingest` within what it reserved, and a member
/// session's reservation from the members' pool and the pace the members share. A connection that
/// publishes none has neither, and a batch from it never reaches the stage (`Peer::permit`).
#[derive(Default)]
struct Admitted {
    allowance: Option<Allowance>,
    membership: Option<crate::budget::Reservation>,
    /// The members' shared rate (`ceiling::Pace`), which a member session's data waits for.
    pace: Option<Arc<crate::ceiling::Pace>>,
    /// Whether this session is admitted as a member once its peer is one (`admit_member`): a
    /// session over which another relay's data may come in (one that relay dialled, or this
    /// relay's own one-hop raw link). A session this relay dialled to send a member what is
    /// addressed to it, or to an upstream for the directory, carries none in, and never is.
    joins: bool,
}

impl Admitted {
    /// `record`'s charge (`in_flight`), a relay's session admitted as a member first
    /// (`admit_member`) when its offer is verified and this is the first data it brings in, for
    /// as long as it is one: a session that only speaks the directory holds no member's place.
    async fn charge(
        &mut self,
        hub: &Hub,
        peer: Peer,
        key: &PublicKey,
        record: &Record,
    ) -> Result<Option<InFlight>, End> {
        if self.joins
            && self.membership.is_none()
            && matches!(record, Record::Batch(_) | Record::ReceiverInfo(_))
            && matches!(peer.now(hub, key), Peer::Member)
        {
            *self = admit_member(hub)?;
        }
        Ok(self.in_flight(record).await)
    }

    /// A batch's charge from the allowance (`ingest::charge_of`), or a receiver description's
    /// (its bytes: it passes the ingest stage too, `Hub::describe`), waiting while the connection
    /// holds all of it; `None` for any other record, or a connection with no allowance.
    async fn in_flight(&self, record: &Record) -> Option<InFlight> {
        let bytes = match record {
            Record::Batch(batch) => crate::ingest::charge_of(batch),
            Record::ReceiverInfo(info) => info.as_bytes().len(),
            _ => return None,
        };
        let allowance = self.allowance.as_ref()?;
        // A member's waits first for the members' shared rate: together they bring in what was
        // planned for them, no more (`budget::Plan::with_members`).
        if let Some(pace) = &self.pace {
            let wire = match record {
                Record::Batch(batch) => batch.as_bytes().len(),
                _ => bytes,
            };
            pace.take(u64::try_from(wire).unwrap_or(u64::MAX)).await;
        }
        Some(allowance.acquire(bytes).await)
    }
}

/// A member session's admission: its own bytes (its ingest allowance) reserved from the members'
/// pool, sized at start for the member sessions the relay's plan admits (`budget::members_for`),
/// its allowance carved, and the members' shared pace. Past them it is turned away, counted, with
/// `Reason::Full` (RFC-0174 §2.5, "A relay's members are bounded"): the relay that dialled routes
/// around this one, to the next members of its trees, for the wait it is given.
fn admit_member(hub: &Hub) -> Result<Admitted, End> {
    let budget = hub.budget();
    let refused = |why: String| {
        hub.member_refused();
        End::Told {
            reason: Reason::Full,
            retry_after_secs: MEMBERS_FULL_RETRY_SECS,
            why,
        }
    };
    let membership = budget.reserve_member().ok_or_else(|| {
        refused(format!(
            "turned away: no spare member slot (the relay holds {} member sessions)",
            budget.members()
        ))
    })?;
    let allowance = hub.allowance(budget.plan().per_member()).ok_or_else(|| {
        refused("turned away: no room for a member's ingest allowance".to_owned())
    })?;
    Ok(Admitted {
        allowance: Some(allowance),
        membership: Some(membership),
        pace: Some(hub.member_pace()),
        joins: true,
    })
}

async fn read_loop<S: AsyncRead>(
    reader: &mut Reader<S>,
    hub: &Arc<Hub>,
    source: u64,
    peer: Peer,
    reading: Reading<'_>,
    mut described: Option<Described>,
    mut ceiling: Option<Ceiling>,
) -> Result<(), End> {
    let Reading {
        subscribe,
        asker,
        replies,
        refusal,
        mut admitted,
    } = reading;
    // The message being read and the records decoded from it, until each is handed on: carved for
    // as long as the connection is open (`ingest::BUFFERS_PER_CONNECTION`), a feeder's from what
    // it reserved, so a peer that trickles a message holds what was planned for it, no more.
    let _buffers = hub
        .connection_buffers(matches!(peer, Peer::Feeder(_)))
        .await;
    let mut records = Vec::new();
    let mut answers = Vec::new();
    loop {
        records.clear();
        // A batch the ingest stage refused (its signature) ends the session at once, whatever
        // is being read: the session is over, so a read cut short loses nothing.
        tokio::select! {
            read = tokio::time::timeout(READ_TIMEOUT, reader.recv(&mut records)) => {
                read.map_err(|_| "silent too long".to_owned())?
                    .map_err(|error| error.to_string())?;
            }
            why = refusal.refused() => return Err(End::Closed(why)),
        }
        if ceiling.as_mut().is_some_and(|ceiling| !ceiling.within()) {
            return Err(End::Told {
                reason: Reason::Full,
                retry_after_secs: OVER_CEILING_RETRY_SECS,
                why: "sent more than its ingest ceiling".to_owned(),
            });
        }
        for record in records.drain(..) {
            // Its charge from the connection's allowance before it is handed over: with the
            // allowance held, the socket is not read, and TCP holds the sender back (RFC-0181 §2).
            let in_flight = admitted.charge(hub, peer, &asker.key, &record).await?;
            if let Some(why) = refusal.now() {
                return Err(End::Closed(why));
            }
            ingest(
                record,
                hub,
                source,
                (peer, &asker),
                subscribe,
                &mut described,
                (in_flight, &refusal),
            )
            .or_else(|unhandled| network(unhandled, hub, &asker, &mut answers))?;
        }
        if !answers.is_empty() {
            // A full queue drops these answers: the peer asked faster than it reads.
            let _ = replies.try_send(std::mem::take(&mut answers));
        }
    }
}

/// What `ingest` hands on: a record that is a network duty's, or the end of the link.
enum Unhandled {
    Network(Record),
    End(End),
}

impl From<End> for Unhandled {
    fn from(end: End) -> Self {
        Self::End(end)
    }
}

impl From<String> for Unhandled {
    fn from(why: String) -> Self {
        Self::End(End::from(why))
    }
}

/// A record `ingest` left to the network duties (`network::Network::handle`): their replies are
/// kept for the write side.
fn network(
    unhandled: Unhandled,
    hub: &Hub,
    asker: &Asker,
    answers: &mut Vec<Record>,
) -> Result<(), End> {
    match unhandled {
        Unhandled::End(end) => Err(end),
        Unhandled::Network(record) => {
            answers.extend(
                hub.network()
                    .handle(hub, asker, record, crate::network::wall_ms()),
            );
            Ok(())
        }
    }
}

fn ingest(
    record: Record,
    hub: &Arc<Hub>,
    source: u64,
    (peer, asker): (Peer, &Asker),
    subscribe: Option<&watch::Sender<Subscription>>,
    described: &mut Option<Described>,
    (in_flight, refusal): (Option<InFlight>, &Arc<Refusal>),
) -> Result<(), Unhandled> {
    // Whether the peer may send it at all is its role's one rule (`Peer::permit`).
    let peer = peer.now(hub, &asker.key);
    match peer.permit(&record) {
        Permit::Take => {}
        Permit::Drop => {
            hub.network().refused_on_directory_link();
            return Ok(());
        }
        Permit::Refuse(end) => return Err(end.into()),
    }
    match record {
        Record::Batch(batch) => {
            // Its signature (a receiver's only: a relay's deduplicated batch never passes as one),
            // its admission and its decode are the ingest stage's, on a CPU worker; a refused
            // signature ends this connection there (`Refusal`). What follows admission (the
            // station counters, a forgotten description given again, the sharing duties) follows
            // there too, in the receiver's order.
            let origin = match peer {
                Peer::Feeder(_) => Origin::Feeder(described.clone()),
                Peer::Member | Peer::Relay => Origin::Peer(*asker),
                Peer::Subscriber | Peer::Engine(_) | Peer::Probe => Origin::Elsewhere,
            };
            // Charged from the connection's allowance before it came here: a peer that publishes
            // batches was admitted with one, and none other gets a batch past its permit.
            let Some(in_flight) = in_flight else {
                return Err(End::Told {
                    reason: Reason::Protocol,
                    retry_after_secs: REFUSED_RETRY_SECS,
                    why: "sent a batch on a connection admitted to publish none".to_owned(),
                }
                .into());
            };
            hub.ingest(Inbound {
                source,
                batch,
                origin,
                verify: true,
                stamp: None,
                in_flight,
                refusal: Some(Arc::clone(refusal)),
            });
        }
        Record::ReceiverInfo(info) => {
            let receiver = info.receiver().map_err(|error| error.to_string())?;
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
                *described = Some(Arc::new(OwnDescription {
                    info: info.clone(),
                    issued_ms,
                    place,
                }));
            }
            // Charged like a batch, and for the same reason: it passes the ingest stage.
            let Some(in_flight) = in_flight else {
                return Err(End::Told {
                    reason: Reason::Protocol,
                    retry_after_secs: REFUSED_RETRY_SECS,
                    why: "sent a description on a connection admitted to publish none".to_owned(),
                }
                .into());
            };
            hub.describe(Description {
                source,
                info,
                receiver,
                issued_ms,
                place,
                publishing: false,
                stamp: None,
                in_flight,
            });
        }
        Record::Positions(positions) => {
            let engine = positions.engine().map_err(|error| error.to_string())?;
            positions.verify().map_err(|error| error.to_string())?;
            share(hub, peer, asker, &Record::Positions(positions.clone()));
            hub.publish_positions(source, positions, engine);
        }
        Record::Provisional(positions) => {
            let engine = positions.engine().map_err(|error| error.to_string())?;
            positions.verify().map_err(|error| error.to_string())?;
            share(hub, peer, asker, &Record::Provisional(positions.clone()));
            hub.publish_provisional(source, positions, engine);
        }
        Record::ClockModel(model) => {
            let engine = model.engine().map_err(|error| error.to_string())?;
            model.verify().map_err(|error| error.to_string())?;
            hub.network().hold_model(&model);
            share(hub, peer, asker, &Record::ClockModel(model.clone()));
            hub.publish_clock_model(source, model, engine);
        }
        Record::ClockModelPart(part) => {
            hub.network().hold_part(&part);
            hub.publish_clock_model_part(source, part);
        }
        // Anyone may prove a fault, and every proof is checked before it is forwarded. One this
        // relay cannot judge (a proof format or a solver spec version it does not know) is not
        // forwarded and not held against the sender; one that proves nothing is a false
        // accusation and ends the session.
        Record::FaultProof(proof) => {
            if proof.format() != FAULT_PROOF_FORMAT && proof.format() != MODEL_FAULT_PROOF_FORMAT {
                return Ok(());
            }
            let spec = proof.spec_version().map_err(|error| error.to_string())?;
            let Some(tolerance) = Tolerance::for_spec(spec) else {
                return Ok(());
            };
            proof
                .check(&tolerance)
                .map_err(|error| format!("sent a fault proof that proves nothing: {error}"))?;
            share(hub, peer, asker, &Record::FaultProof(proof.clone()));
            hub.publish_fault_proof(source, proof);
        }
        Record::Subscribe { streams, regions } => {
            if regions.len() > MAX_REGIONS {
                return Err(End::Told {
                    reason: Reason::Protocol,
                    retry_after_secs: REFUSED_RETRY_SECS,
                    why: format!("subscribed to {} regions", regions.len()),
                }
                .into());
            }
            if let Some(subscribe) = subscribe {
                // What the peer may read is its role's grant (`Peer::grant`).
                let allowed = peer.grant(
                    hub,
                    asker,
                    Subscription { streams, regions },
                    crate::network::wall_ms(),
                );
                subscribe.send_replace(allowed);
            }
        }
        // A relay this one links to leaves or refuses it, saying when to come back and whether it
        // is full; the dial loop of a link this relay dialled (`member`, `Redial`) acts on it.
        Record::Goodbye {
            reason,
            retry_after_secs,
        } if matches!(peer, Peer::Relay | Peer::Member) => {
            return Err(End::Departed(Away::of(reason, retry_after_secs)).into());
        }
        Record::Redirect {
            retry_after_secs, ..
        } if matches!(peer, Peer::Relay | Peer::Member) => {
            return Err(End::Departed(Away::of(Reason::Leaving, retry_after_secs)).into());
        }
        // RFC-0174's records are the network duties' (`network`), whoever sent them.
        record @ (Record::Echo(_)
        | Record::EchoReply(_)
        | Record::DeliveryQuery(_)
        | Record::DeliveryAnswer(_)
        | Record::ProviderOffer(_)
        | Record::ProviderQuery(_)
        | Record::StripeAssignment(_)
        | Record::PieceManifest(_)
        | Record::HaveSummary(_)
        | Record::StripeReceipt(_)
        | Record::FirehoseCredential(_)
        | Record::EvidenceBundle(_)
        | Record::WorldPositions(_)
        | Record::WorldPrecise(_)
        | Record::RegionalBatch(_)
        | Record::Parity(_)
        | Record::BundleIndex(_)) => return Err(Unhandled::Network(record)),
        // Another relay's deduplicated stream is its own claim; this relay derives its own.
        _ => {}
    }
    Ok(())
}

/// Hands a record of data the network duties' sharing: a member's is a piece of its group,
/// passed on down this relay's stripes; a fault proof anyone else brought this relay first-hand
/// is seeded into its group by this relay, its origin.
fn share(hub: &Hub, peer: Peer, asker: &Asker, record: &Record) {
    let network = hub.network();
    let now_ms = crate::network::wall_ms();
    match peer {
        Peer::Member => network.from_peer(hub, asker, record, now_ms),
        Peer::Engine(_) | Peer::Feeder(_) | Peer::Subscriber => {
            network.originate(hub, record, now_ms);
        }
        Peer::Relay | Peer::Probe => {}
    }
}

/// What the write side is handed beside the fan-out: when to say goodbye, the network duties'
/// replies, what is addressed to the peer (a member link's `outgoing`), and, for a billed client,
/// who it is, so what it is sent keeps to its allowance (`credit`).
struct Inputs<'a> {
    farewells: &'a mut mpsc::Receiver<Farewell>,
    replies: &'a mut mpsc::Receiver<Vec<Record>>,
    outgoing: Option<&'a mut mpsc::Receiver<Vec<Record>>>,
    client: Option<Asker>,
    /// A client's subscription, which the write side re-admits as its credit changes.
    steer: Option<&'a watch::Sender<Subscription>>,
    /// Who the peer is, and its key: what replies it takes (`Peer::takes_reply`).
    peer: (Peer, PublicKey),
    /// A client this relay vouches for: signed a credential and this relay's evidence when its
    /// session starts and again before the credential lapses (`credit::RENEW_BEFORE_MS`).
    vouched: Option<Asker>,
}

/// How often a client's subscription is admitted again, so a credential that expires mid-session
/// (or credit that grows) takes effect without the client asking.
const READMIT_EVERY: Duration = Duration::from_secs(10);

/// The next records addressed to the peer, or never.
async fn addressed(outgoing: &mut Option<&mut mpsc::Receiver<Vec<Record>>>) -> Option<Vec<Record>> {
    match outgoing {
        Some(outgoing) => outgoing.recv().await,
        None => std::future::pending().await,
    }
}

/// A client's sends kept to its allowance's bytes a second (`credit::Allowance`), a second's worth
/// at once at most: a client that asks for more than it may read waits, and one that falls behind
/// the fan-out is dropped as any slow subscriber is.
struct ClientPace {
    client: Asker,
    rate: u64,
    tokens: f64,
    at: tokio::time::Instant,
    checked: tokio::time::Instant,
}

impl ClientPace {
    fn new(client: Asker, hub: &Hub) -> Self {
        let now = tokio::time::Instant::now();
        let rate = allowed(hub, &client);
        Self {
            client,
            rate,
            tokens: rate as f64,
            at: now,
            checked: now,
        }
    }

    async fn take(&mut self, hub: &Hub, bytes: usize) {
        let now = tokio::time::Instant::now();
        if now.duration_since(self.checked) >= Duration::from_secs(1) {
            self.rate = allowed(hub, &self.client);
            self.checked = now;
        }
        if self.rate == u64::MAX {
            return;
        }
        let rate = self.rate.max(1) as f64;
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * rate).min(rate);
        self.at = now;
        self.tokens -= bytes as f64;
        if self.tokens < 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(-self.tokens / rate)).await;
        }
    }
}

fn allowed(hub: &Hub, client: &Asker) -> u64 {
    let credit = &hub.network().credit;
    if !credit.rations() {
        return u64::MAX;
    }
    credit
        .allowance(&client.key, crate::network::wall_ms())
        .bytes_per_sec
}

// The write side's every input, each its own: what to say first, what to forward, what to answer
// and when to say goodbye.
async fn write_loop<S: AsyncWrite>(
    writer: &mut Writer<S>,
    hub: &Hub,
    source: u64,
    link: &Arc<Link>,
    greeting: Vec<Record>,
    fan_out: Option<FanOut>,
    inputs: Inputs<'_>,
) -> Result<(), Closing> {
    let Inputs {
        farewells,
        replies,
        mut outgoing,
        client,
        steer,
        peer,
        vouched,
    } = inputs;
    let mut readmit = tokio::time::interval(READMIT_EVERY);
    let mut revouch = tokio::time::interval(Duration::from_millis(
        crate::credit::CREDENTIAL_LIFETIME_MS - crate::credit::RENEW_BEFORE_MS,
    ));
    let mut pace = client.map(|client| ClientPace::new(client, hub));
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    let mut told = Told::new();
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
                Some((last, why)) = farewells.recv() => return Err(Closing::Saying { last: Box::new(last), why }),
                Some(answers) = replies.recv() => {
                    reply(writer, hub, link, peer, &mut told, answers).await?;
                }
                _ = revouch.tick(), if vouched.is_some() => {
                    vouch(writer, hub, vouched.as_ref()).await?;
                }
                // What is addressed to a member: a stripe slice, a manifest, a receipt.
                Some(records) = addressed(&mut outgoing) => {
                    let records = told.before_batches(hub, records);
                    send_data(writer, hub, link, Class::Forwarded, &records).await?;
                }
            }
        }
    };
    // The hub filtered these by what the link wanted when it joined, which is `wants` still. Sent
    // in parts before the link joins the fan-out, so nothing fills behind them (`Hub::subscribe`).
    let kind = link.kind();
    // A directory link joins the fan-out first and then reads the offers held, so an offer signed
    // or gossiped in between (each is published once) is in one or the other, never neither.
    let directory = matches!(wants, Wants::Directory);
    let early = directory.then(|| hub.listen(source, wants.filter()));
    let infos: Vec<Arc<Record>> = if directory {
        live_offers(hub)
    } else {
        infos.into_iter().map(|item| item.record).collect()
    };
    for part in parts(&infos) {
        send_data(writer, hub, link, described_class(kind), part).await?;
    }
    let out = early.unwrap_or_else(|| hub.listen(source, wants.filter()));
    let mut pending = Pending::new(kind);
    let mut taken = Vec::with_capacity(SEND_BATCH);
    loop {
        tokio::select! {
            got = out.recv_many(&mut taken, SEND_BATCH) => {
                match got {
                    Ok(()) => {}
                    // The directory a link is sent is held whole (`Directory`), so a directory
                    // link behind the fan-out is sent it again rather than dropped: what it
                    // missed is in what is held. A link of data has no such source; it goes.
                    Err(Fell::Resync) => resync_directory(writer, hub, link, kind).await?,
                    Err(Fell::Behind(_)) => return fell_behind(kind),
                }
                for item in taken.drain(..) {
                    pending.keep(item, source, &wants);
                }
                while !pending.full() {
                    match out.try_recv_many(&mut taken, SEND_BATCH) {
                        Ok(0) => break,
                        Ok(_) => {
                            for item in taken.drain(..) {
                                pending.keep(item, source, &wants);
                            }
                        }
                        Err(Fell::Resync) => resync_directory(writer, hub, link, kind).await?,
                        Err(Fell::Behind(_)) => return fell_behind(kind),
                    }
                }
                if let Some(pace) = pace.as_mut() {
                    pace.take(hub, pending.bytes).await;
                }
                pending.send(writer, hub, link).await?;
            }
            _ = readmit.tick(), if client.is_some() && steer.is_some() => {
                if let (Some(client), Some(steer)) = (client.as_ref(), steer)
                    && let Some(admitted) = hub
                        .network()
                        .credit
                        .readmit(client, crate::network::wall_ms())
                {
                    steer.send_replace(admitted);
                }
            }
            Some(records) = addressed(&mut outgoing) => {
                let records = told.before_batches(hub, records);
                send_data(writer, hub, link, Class::Forwarded, &records).await?;
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
                    send_data(writer, hub, link, described_class(kind), part).await?;
                    if !catch_up(writer, hub, link, &out, &mut pending, source, &wants).await? {
                        return fell_behind(kind);
                    }
                }
                wants.apply(subscription);
                out.set(wants.filter());
            }
            Some((last, why)) = farewells.recv() => return Err(Closing::Saying { last: Box::new(last), why }),
            Some(answers) = replies.recv() => {
                reply(writer, hub, link, peer, &mut told, answers).await?;
            }
            _ = revouch.tick(), if vouched.is_some() => {
                vouch(writer, hub, vouched.as_ref()).await?;
                // Linked by its own credential here now: admitted again at once, not at the next
                // `READMIT_EVERY`.
                if let (Some(client), Some(steer)) = (vouched.as_ref(), steer)
                    && let Some(admitted) = hub
                        .network()
                        .credit
                        .readmit(client, crate::network::wall_ms())
                {
                    steer.send_replace(admitted);
                }
            }
            () = link.shed() => return shed(hub),
            _ = heartbeat.tick() => {
                writer
                    .send(&[Record::Heartbeat])
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

/// What a member link (whose records are addressed to it, not filtered from the fan-out) has
/// told its peer of what its records depend on: the descriptions it carried, by receiver, as
/// issued.
struct Told {
    sent: HashMap<PublicKey, u64>,
    /// The clock models it carried, by id.
    models: std::collections::HashSet<[u8; 32]>,
}

/// Receivers a member link remembers describing; past it, it starts again (and describes again).
const DESCRIBED_REMEMBERED: usize = 65_536;

impl Told {
    fn new() -> Self {
        Self {
            sent: HashMap::new(),
            models: std::collections::HashSet::new(),
        }
    }

    /// `records` with what each depends on before it, as one session orders them for a
    /// subscriber: a batch's receiver described, as the link last described it or newer (the rule
    /// a subscription keeps, `Hub::subscribe`); a clock model's parts just before its manifest;
    /// and every model a positions record cites, once, before the first record citing it. A
    /// sharing group stripes records over several trees, so the peer may hold none of these: a
    /// relay that cannot place a receiver can neither solve its receptions nor pass its batches
    /// on, a manifest without its parts is no model, and a solution whose model has not come
    /// cannot be checked. Parts are in no group of their own; they ride with their manifest.
    fn before_batches(&mut self, hub: &Hub, records: Vec<Record>) -> Vec<Arc<Record>> {
        let network = hub.network();
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let cited: Vec<[u8; 32]> = match &record {
                // The group's own copy always goes (it is a stripe's piece); its parts once.
                Record::ClockModel(model) => {
                    if self.carry_model(model.id()) {
                        out.extend(
                            network
                                .parts_of(&model.id())
                                .into_iter()
                                .map(|part| Arc::new(Record::ClockModelPart(part))),
                        );
                    }
                    Vec::new()
                }
                Record::Positions(positions) | Record::Provisional(positions) => positions
                    .solutions()
                    .map(|content| {
                        content
                            .solutions
                            .iter()
                            .map(|solution| solution.clock_model)
                            .collect()
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            for id in cited {
                if self.models.contains(&id) {
                    continue;
                }
                if let Some(model) = network.model_records(&id) {
                    self.carry_model(id);
                    out.extend(model.into_iter().map(Arc::new));
                }
            }
            if let Record::Batch(batch) = &record
                && let Ok(receiver) = batch.receiver()
                && let Some((info, issued_ms)) = hub.description_of(&receiver)
                && self
                    .sent
                    .get(&receiver)
                    .is_none_or(|sent| *sent < issued_ms)
            {
                if self.sent.len() >= DESCRIBED_REMEMBERED {
                    self.sent.clear();
                }
                self.sent.insert(receiver, issued_ms);
                out.push(info);
            }
            out.push(Arc::new(record));
        }
        out
    }

    /// Whether model `id` is still to be carried on this link; it is from now on.
    fn carry_model(&mut self, id: [u8; 32]) -> bool {
        if self.models.len() >= DESCRIBED_REMEMBERED {
            self.models.clear();
        }
        self.models.insert(id)
    }
}

/// Sends the network duties' replies to the peer, each only if its role takes it
/// (`Peer::takes_reply`): what is control to it at once, as an echo's reply must be; the rest (a
/// repair's batches and positions, with what they depend on first, as on an addressed send, and
/// offers to a directory link) by class through the upload cap (`send_data`).
async fn reply<S: AsyncWrite>(
    writer: &mut Writer<S>,
    hub: &Hub,
    link: &Arc<Link>,
    (peer, key): (Peer, PublicKey),
    told: &mut Told,
    answers: Vec<Record>,
) -> Result<(), Closing> {
    let peer = peer.now(hub, &key);
    let kind = link.kind();
    let taken: Vec<Record> = answers
        .into_iter()
        .filter(|record| peer.takes_reply(record, kind))
        .collect();
    let mut control = Vec::new();
    let mut by_class: [Vec<Arc<Record>>; Class::ALL.len()] = Default::default();
    for record in told.before_batches(hub, taken) {
        match Class::of(&record, kind) {
            Class::Control => control.push(record),
            class => by_class[class as usize].push(record),
        }
    }
    if !control.is_empty() {
        writer
            .send(&control)
            .await
            .map_err(|error| Closing::Silent(error.to_string()))?;
    }
    for class in Class::ALL {
        let records = &by_class[class as usize];
        if !records.is_empty() {
            send_data(writer, hub, link, class, records).await?;
        }
    }
    Ok(())
}

/// Signs a vouched client a fresh credential and this relay's evidence (`Credit::vouch`), and
/// sends both: control, a few kilobytes a quarter hour.
async fn vouch<S: AsyncWrite>(
    writer: &mut Writer<S>,
    hub: &Hub,
    client: Option<&Asker>,
) -> Result<(), Closing> {
    let network = hub.network();
    let (Some(client), Some(identity)) = (client, network.identity()) else {
        return Ok(());
    };
    let Some((credential, evidence)) =
        network
            .credit
            .vouch(identity, client, crate::network::wall_ms())
    else {
        return Ok(());
    };
    writer
        .send(&[
            Record::FirehoseCredential(credential),
            Record::EvidenceBundle(evidence),
        ])
        .await
        .map_err(|error| Closing::Silent(error.to_string()))
}

/// The class of a dump of receiver descriptions to a link of `kind`: theirs, as a description is.
fn described_class(kind: Kind) -> Class {
    if kind.forwards() {
        Class::Raw
    } else {
        Class::Taker
    }
}

/// Sends records of one `class` a peer asked for, once the pacer grants their bytes. A link shed
/// while it waits is told the relay is full, and ends.
async fn send_data<S: AsyncWrite>(
    writer: &mut Writer<S>,
    hub: &Hub,
    link: &Arc<Link>,
    class: Class,
    records: &[Arc<Record>],
) -> Result<(), Closing> {
    match hub.egress().grant(link, class, wire_cost(records)).await {
        Ok(()) => writer
            .send(records)
            .await
            .map_err(|error| Closing::Silent(error.to_string())),
        Err(Shed) => shed(hub),
    }
}

/// Ends a link the upload cap shed: it is told the relay is full, pointed at the relays this one
/// knows.
fn shed(hub: &Hub) -> Result<(), Closing> {
    Err(Closing::Saying {
        last: Box::new(full(hub)),
        why: "shed: the upload cap cannot carry it".to_owned(),
    })
}

/// Sends everything waiting on the fan-out that `wants` takes, until none is waiting. False when
/// the link has already fallen behind.
async fn catch_up<S: AsyncWrite>(
    writer: &mut Writer<S>,
    hub: &Hub,
    link: &Arc<Link>,
    out: &Listener,
    pending: &mut Pending,
    source: u64,
    wants: &Wants,
) -> Result<bool, Closing> {
    let mut taken = Vec::with_capacity(SEND_BATCH);
    loop {
        let mut drained = false;
        while !pending.full() {
            match out.try_recv_many(&mut taken, SEND_BATCH) {
                Ok(0) => {
                    drained = true;
                    break;
                }
                Ok(_) => {
                    for item in taken.drain(..) {
                        pending.keep(item, source, wants);
                    }
                }
                Err(_) => return Ok(false),
            }
        }
        pending.send(writer, hub, link).await?;
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
        bytes += record.encoded_len();
    }
    if start < records.len() {
        parts.push(&records[start..]);
    }
    parts
}

/// Records gathered for one send, at most `SEND_BATCH` of them and about `SEND_BYTES`, each in its
/// class, classified once as it is kept.
struct Pending {
    kind: Kind,
    /// By class, highest first; order within a class is the fan-out's.
    by_class: [Vec<Arc<Record>>; Class::ALL.len()],
    /// The fan-out's charges of what is gathered (`budget::Store::Fanout`), held until it is
    /// sent: what waits on a slow socket here is still charged.
    charges: Vec<Arc<crate::budget::Charge>>,
    records: usize,
    bytes: usize,
}

impl Pending {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            by_class: Default::default(),
            charges: Vec::new(),
            records: 0,
            bytes: 0,
        }
    }

    /// Never send a record back down the connection it came in on, nor one the link did not ask
    /// for.
    fn keep(&mut self, taken: Taken, source: u64, wants: &Wants) {
        if taken.source != source && wants.wants(&taken) {
            let class = Class::of(&taken.record, self.kind);
            self.bytes += taken.record.encoded_len();
            self.records += 1;
            self.charges.push(taken.charge());
            self.by_class[class as usize].push(Arc::clone(&taken.record));
        }
    }

    fn full(&self) -> bool {
        self.records >= SEND_BATCH || self.bytes >= SEND_BYTES
    }

    /// Sends what is gathered, each class once granted, highest first, and empties it.
    async fn send<S: AsyncWrite>(
        &mut self,
        writer: &mut Writer<S>,
        hub: &Hub,
        link: &Arc<Link>,
    ) -> Result<(), Closing> {
        for class in Class::ALL {
            let records = &mut self.by_class[class as usize];
            if !records.is_empty() {
                send_data(writer, hub, link, class, records).await?;
                records.clear();
            }
        }
        // Sent: the fan-out's charge of it goes with the last holder.
        self.charges.clear();
        self.records = 0;
        self.bytes = 0;
        Ok(())
    }
}

/// What `records` cost on the wire, at most: each record's bytes and its three-byte header, and
/// for each Noise message (one per record at worst, and every half message at most) its tag and
/// two-byte length. The socket counts what is really written; this is what is granted first.
fn wire_cost(records: &[Arc<Record>]) -> usize {
    const MESSAGE_OVERHEAD: usize = 2 + 16;
    let bytes: usize = records.iter().map(|record| record.encoded_len()).sum();
    let messages = records
        .len()
        .min(bytes / (noise::MAX_PLAINTEXT / 2) + 1)
        .max(1);
    bytes + messages * MESSAGE_OVERHEAD
}

/// Sends a directory link that fell behind the fan-out the directory held now, whole.
async fn resync_directory<S: AsyncWrite>(
    writer: &mut Writer<S>,
    hub: &Hub,
    link: &Arc<Link>,
    kind: Kind,
) -> Result<(), Closing> {
    for part in parts(&live_offers(hub)) {
        send_data(writer, hub, link, described_class(kind), part).await?;
    }
    Ok(())
}

/// How long a subscriber that fell behind the stream is asked to stay away.
const FELL_BEHIND_RETRY_SECS: u32 = 30;

/// Ends a link that fell behind the stream (its queue past `fanout::BEHIND_MS` of inbound, or past
/// its bytes): it is told so (`Reason::FellBehind`), not that the relay is full. A subscriber is
/// asked to stay away a short while (`FELL_BEHIND_RETRY_SECS`), so a slow one does not churn; a
/// peer that forwards (an MLAT relay's raw link) is asked for nothing, since what it carries is a
/// duty and every second away is raw lost, and its own dial loop (`Redial`) paces it.
fn fell_behind(kind: Kind) -> Result<(), Closing> {
    let wait = if kind.forwards() {
        0
    } else {
        FELL_BEHIND_RETRY_SECS
    };
    Err(Closing::Saying {
        last: Box::new(goodbye(Reason::FellBehind, wait)),
        why: format!("fell behind the stream ({kind:?})"),
    })
}

/// Serves plain BEAST of every reception to whoever connects (a local readsb). Unauthenticated,
/// so the operator binds it to loopback.
pub async fn serve_beast(listener: TcpListener, hub: Arc<Hub>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let out = hub.listen(hub.connection_id(), Filter::Beast);
        let stream = hub.egress().socket(stream, Some(peer.ip()));
        // It takes data and gives none: a plain subscriber, to the cap.
        stream.link().set_kind(Kind::Taker);
        tokio::spawn(async move {
            if let Err(error) = beast_client(stream, out, BEAST_WRITE_TIMEOUT).await {
                eprintln!("tally-relay: beast-out {peer}: {error}");
            }
        });
    }
}

/// Writes every reception to one client, each write held to `deadline` and granted by the upload
/// cap as a plain subscriber's (a loopback client, the usual one, is never held to it).
async fn beast_client<W: AsyncWrite + Unpin>(
    mut stream: Socket<W>,
    out: Listener,
    deadline: Duration,
) -> Result<(), String> {
    let link = stream.link();
    let egress = Arc::clone(stream.egress());
    let mut bytes = Vec::new();
    // Held, with their charges, until their bytes are written.
    let mut items: Vec<Taken> = Vec::new();
    loop {
        items.clear();
        if let Err(fell) = out.recv_many(&mut items, SEND_BATCH).await {
            return Err(format!("fell behind ({fell:?})"));
        }
        bytes.clear();
        // Each batch's one decode (`hub::Item::decoded`); the router offers only batches with one.
        for decoded in items.iter().filter_map(|item| item.decoded.as_ref()) {
            for frame in decoded.views().filter_map(|view| view.to_beast()) {
                frame.encode_beast(&mut bytes);
            }
        }
        if bytes.is_empty() {
            continue;
        }
        if egress.grant(&link, Class::Taker, bytes.len()).await == Err(Shed) {
            return Err("shed: the upload cap cannot carry it".to_owned());
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
    use tally_wire::{Batch, BatchContent, Frame, Observation, RelayAddress, Streams};
    use tally_wire::{Location, ReceiverInfo};
    use tokio::time::timeout;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// RFC-0181 §7: a delivery query of the retired form is answered from every peer with a
    /// goodbye naming it (which an old feeder takes as "no answer"), never dropped unheard; an old
    /// answer, which no peer is owed a word for, is not.
    #[test]
    fn a_retired_delivery_query_is_refused_by_name_from_every_peer() -> Result<(), String> {
        use tally_wire::record::{KIND_POSSESSION_ANSWER, KIND_POSSESSION_QUERY};
        let key = Identity::from_seed([1; 32]).public();
        let peers = [
            Peer::Feeder(key),
            Peer::Relay,
            Peer::Subscriber,
            Peer::Engine(key),
            Peer::Member,
            Peer::Probe,
        ];
        for peer in peers {
            match peer.permit(&Record::Retired(KIND_POSSESSION_QUERY)) {
                Permit::Refuse(End::Told {
                    reason: Reason::Retired,
                    ..
                }) => {}
                _ => return Err("a retired query was not refused by name".to_owned()),
            }
            if let Permit::Refuse(End::Told { reason, .. }) =
                peer.permit(&Record::Retired(KIND_POSSESSION_ANSWER))
                && reason == Reason::Retired
            {
                return Err("a retired answer was refused as a query".to_owned());
            }
        }
        Ok(())
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
        let asked = upstream_once(&upstream, &child, &Arc::new(Hub::new(8)))
            .await?
            .map(|away| away.wait);
        // Neither accepted nor verified: asked to wait one re-signing of its offers, by when its
        // offer would have been verified if it is going to be.
        assert_eq!(
            asked,
            Some(Duration::from_secs(UNVERIFIED_RETRY_SECS.into()))
        );
        Ok(())
    }

    /// A relay that refuses this one (it never verified this relay's offer) is dialled once per
    /// wait it names, whatever the role dialled: never again at once, never in a loop. And a peer
    /// that drops every connection at once is dialled less and less often (`Redial`).
    #[tokio::test]
    async fn a_dial_that_is_refused_or_dropped_is_not_retried_in_a_hot_loop() -> Result<(), String>
    {
        for role in [Role::Engine, Role::Relay] {
            let far = Identity::generate().map_err(text)?;
            let far_key = far.public();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(text)?;
            let address = listener.local_addr().map_err(text)?.to_string();
            tokio::spawn(crate::serve(listener, vec![far], Arc::new(Hub::new(8))));
            // A relay taking an area, so a raw link has its place in the members' pool.
            let area = tally_wire::rendezvous::area_of(&tally_wire::Location {
                lat_e7: 337_490_000,
                lon_e7: -843_880_000,
                alt_m: 0,
                precision_m: 0,
            })
            .map_err(text)?;
            let hub = Arc::new(Hub::new(8).taking(vec![area]));
            let (_sender, outgoing) = mpsc::channel(1);
            let subscribe = Record::Subscribe {
                streams: Streams::RAW,
                regions: Vec::new(),
            };
            let dialling = tokio::spawn(member(
                RelayAddress {
                    key: far_key,
                    address,
                },
                Identity::generate().map_err(text)?,
                role,
                vec![subscribe],
                Arc::clone(&hub),
                outgoing,
            ));
            tokio::time::sleep(Duration::from_secs(3)).await;
            dialling.abort();
            assert_eq!(
                hub.network()
                    .dials()
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "{role:?}"
            );
        }
        // A peer that takes the connection and drops it unanswered.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(text)?;
        let address = listener.local_addr().map_err(text)?.to_string();
        let accepted = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counting = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counting.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                drop(stream);
            }
        });
        let hub = Arc::new(Hub::new(8));
        let (_sender, outgoing) = mpsc::channel(1);
        let dialling = tokio::spawn(member(
            RelayAddress {
                key: Identity::generate().map_err(text)?.public(),
                address,
            },
            Identity::generate().map_err(text)?,
            Role::Relay,
            Vec::new(),
            Arc::clone(&hub),
            outgoing,
        ));
        // Waits of 1, 2 and 4 s (each up to half again): at most three dials in four seconds.
        tokio::time::sleep(Duration::from_secs(4)).await;
        dialling.abort();
        let dials = hub
            .network()
            .dials()
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!((2..=3).contains(&dials), "{dials} dials in 4 s");
        assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), dials);
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
        // And that it said it is full, which a dialler of data routes around.
        assert_eq!(
            asked,
            Some(Away {
                wait: Duration::from_secs(77),
                full: true
            })
        );
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
        // The ingest clock stopped: signing the batches below takes real seconds in a debug
        // build, and a subscriber is let go two seconds of inbound behind, which is not what
        // this measures.
        let hub = Arc::new(Hub::clocked(1, Arc::new(|| 0)).max_upload(roomy()));
        let relay = Identity::generate().map_err(text)?;
        let relay_key = relay.public();
        let (near, far) = tokio::io::duplex(64 * 1024);
        let far = hub.egress().socket(far, None);
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
        let hub = Arc::new(Hub::new(1).max_upload(roomy()));
        let (unread, far) = tokio::io::duplex(1024);
        let far = hub.egress().socket(far, None);
        let out = hub.listen(hub.connection_id(), Filter::Beast);
        let client = tokio::spawn(beast_client(far, out, Duration::from_millis(200)));
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
                    tally_wire::Positions::sign_solutions(
                        &Identity::generate().map_err(text)?,
                        &tally_wire::SolutionsContent {
                            boot_id: 1,
                            sequence: 0,
                            issued_ms: 0,
                            spec_version: 1,
                            solutions: Vec::new(),
                        },
                    )
                    .map_err(text)?
                )),
                cell: None,
                points: None,
                decoded: None,
                stamp_ms: 0,
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
        // A queue far smaller than the directory: one send of the whole of it would leave the
        // subscriber behind. About `RING` of the small batches below.
        const RING: usize = 16;
        let hub = Arc::new(Hub::new(1).queue_bytes(RING * 512).max_upload(roomy()));
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
        let far = hub.egress().socket(far, None);
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

    /// A cap no test reaches.
    fn roomy() -> crate::egress::Cap {
        crate::egress::Cap::bytes_per_sec(1 << 30)
    }

    /// A stream that counts what reaches it: the bytes on the wire, beneath the relay's `Socket`.
    struct Tap {
        inner: tokio::io::DuplexStream,
        written: Arc<std::sync::atomic::AtomicU64>,
    }

    impl AsyncRead for Tap {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Tap {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let polled = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
            if let std::task::Poll::Ready(Ok(written)) = polled {
                self.written
                    .fetch_add(written as u64, std::sync::atomic::Ordering::Relaxed);
            }
            polled
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// One session with the relay over a pipe, billed: the dialler's end, what reached the pipe
    /// from the relay, the relay's side of the link, and the relay's serving task.
    struct Dialled {
        near: Option<tokio::io::DuplexStream>,
        written: Arc<std::sync::atomic::AtomicU64>,
        link: Arc<Link>,
        serving: tokio::task::JoinHandle<Result<(), String>>,
        relay_key: PublicKey,
    }

    fn dial_pipe(hub: &Arc<Hub>) -> Result<Dialled, String> {
        let relay = Identity::generate().map_err(text)?;
        let relay_key = relay.public();
        let (near, far) = tokio::io::duplex(1 << 20);
        let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let far = hub.egress().socket(
            Tap {
                inner: far,
                written: Arc::clone(&written),
            },
            None,
        );
        let link = far.link();
        let serving = tokio::spawn({
            let hub = Arc::clone(hub);
            async move { inbound(far, &[relay], hub).await }
        });
        Ok(Dialled {
            near: Some(near),
            written,
            link,
            serving,
            relay_key,
        })
    }

    async fn connected(
        dialled: &mut Dialled,
        role: Role,
    ) -> Result<noise::Session<tokio::io::DuplexStream>, String> {
        let near = dialled.near.take().ok_or("dialled twice")?;
        noise::connect(
            near,
            &Identity::generate().map_err(text)?,
            &dialled.relay_key,
            role,
        )
        .await
        .map_err(text)
    }

    /// The records of one message from the relay.
    async fn next(reader: &mut Reader<tokio::io::DuplexStream>) -> Result<Vec<Record>, String> {
        let mut records = Vec::new();
        timeout(Duration::from_secs(60), reader.recv(&mut records))
            .await
            .map_err(|_| "the relay sent nothing".to_owned())?
            .map_err(text)?;
        Ok(records)
    }

    async fn ended(
        serving: &mut tokio::task::JoinHandle<Result<(), String>>,
    ) -> Result<String, String> {
        let ended = timeout(Duration::from_secs(60), serving)
            .await
            .map_err(|_| "the session did not end".to_owned())?
            .map_err(text)?;
        Ok(format!("{ended:?}"))
    }

    fn written(dialled: &Dialled) -> u64 {
        dialled.written.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[tokio::test]
    async fn a_probe_is_answered_never_admitted_and_ended_when_it_sends_anything_else()
    -> Result<(), String> {
        let hub = Arc::new(Hub::new(8).max_upload(roomy()));
        hub.network()
            .adopt_identity(Identity::generate().map_err(text)?);
        let mut probe = dial_pipe(&hub)?;
        let mut session = connected(&mut probe, Role::Probe).await?;
        session
            .writer
            .send(&[Record::Echo(tally_wire::Echo { nonce: 7 })])
            .await
            .map_err(text)?;
        let mut replied = false;
        while !replied {
            let records = next(&mut session.reader).await?;
            assert!(
                records
                    .iter()
                    .all(|record| !matches!(record, Record::RateLimit { .. })),
                "a probe is not greeted as a feeder: {records:?}"
            );
            replied = records.iter().any(|record| {
                matches!(record, Record::EchoReply(reply)
                    if reply.content().is_ok_and(|content| content.nonce == 7))
            });
        }
        assert_eq!(hub.subscribers(), 0);
        // Anything else ends it, said in a goodbye.
        let receiver = Identity::generate().map_err(text)?;
        session
            .writer
            .send(&[Record::Batch(batch(&receiver, 0, 1)?)])
            .await
            .map_err(text)?;
        let mut told = None;
        while told.is_none() {
            told = next(&mut session.reader)
                .await?
                .into_iter()
                .find(|record| matches!(record, Record::Goodbye { .. }));
        }
        assert!(matches!(
            told,
            Some(Record::Goodbye {
                reason: Reason::Protocol,
                ..
            })
        ));
        let why = ended(&mut probe.serving).await?;
        assert!(why.contains("probe"), "{why}");
        Ok(())
    }

    async fn connected_as(
        dialled: &mut Dialled,
        role: Role,
        identity: &Identity,
    ) -> Result<noise::Session<tokio::io::DuplexStream>, String> {
        let near = dialled.near.take().ok_or("dialled twice")?;
        noise::connect(near, identity, &dialled.relay_key, role)
            .await
            .map_err(text)
    }

    /// A live offer of `relay`'s, for the area over Atlanta, held as verified by `hub`.
    fn verified(hub: &Hub, relay: &Identity) -> Result<(), String> {
        let now = crate::network::wall_ms();
        let cell = tally_wire::rendezvous::area_of(&Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        let offer = tally_wire::ProviderOffer::sign(
            relay,
            &tally_wire::ProviderOfferContent {
                address: "engine.example:10900".to_owned(),
                cell,
                products: Streams::RAW,
                stripes_of: 1,
                stripes: 1,
                mlat_cores: 8,
                feeder_slots: 0,
                network: 64_512,
                issued_ms: now,
                expires_ms: now + 600_000,
            },
        )
        .map_err(text)?;
        hub.network()
            .directory
            .hold_verified(offer, crate::directory::Group::V4(7), now)?;
        Ok(())
    }

    #[tokio::test]
    async fn an_engine_is_a_verified_relays_takes_no_subscriber_place_and_publishes_nothing()
    -> Result<(), String> {
        // One subscriber place, taken.
        let hub = Arc::new(Hub::new(1).max_upload(roomy()));
        let mut subscriber = dial_pipe(&hub)?;
        let _subscribed = connected(&mut subscriber, Role::Subscriber).await?;
        timeout(Duration::from_secs(10), async {
            while hub.subscribers() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "the subscriber was never served".to_owned())?;
        // An unverified key is refused as an engine.
        let stranger = Identity::generate().map_err(text)?;
        let mut refused = dial_pipe(&hub)?;
        let _ = connected_as(&mut refused, Role::Engine, &stranger).await;
        let why = ended(&mut refused.serving).await?;
        assert!(why.contains("verified"), "{why}");
        // A relay whose offer this one verified is served as an engine, beyond the subscriber
        // cap: this relay's own one-hop raw links dial as engines.
        let engine = Identity::generate().map_err(text)?;
        verified(&hub, &engine)?;
        let before = hub.listening();
        let mut dialled = dial_pipe(&hub)?;
        let mut session = connected_as(&mut dialled, Role::Engine, &engine).await?;
        timeout(Duration::from_secs(10), async {
            while hub.listening() == before {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "the engine was never served".to_owned())?;
        assert_eq!(hub.subscribers(), 1);
        // Positions it signs itself end its session: its relay shares them through the groups.
        let solved = tally_wire::Positions::sign_solutions(
            &engine,
            &tally_wire::SolutionsContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1,
                spec_version: 3,
                solutions: Vec::new(),
            },
        )
        .map_err(text)?;
        session
            .writer
            .send(&[Record::Positions(solved)])
            .await
            .map_err(text)?;
        let why = ended(&mut dialled.serving).await?;
        assert!(why.contains("published positions"), "{why}");
        Ok(())
    }

    #[tokio::test]
    async fn a_relay_with_no_feeder_slot_answers_a_probe_and_gives_it_none() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8).max_upload(roomy()));
        hub.network()
            .adopt_identity(Identity::generate().map_err(text)?);
        // Duties off: no feeder slot, so a feeder is turned away.
        hub.network().admission.configure(64_512, false);
        let mut feeder = dial_pipe(&hub)?;
        let mut turned = connected(&mut feeder, Role::Feeder).await?;
        let mut redirected = false;
        while !redirected {
            redirected = next(&mut turned.reader)
                .await?
                .iter()
                .any(|record| matches!(record, Record::Goodbye { .. } | Record::Redirect { .. }));
        }
        // A probe is answered all the same, and takes nothing.
        let mut probe = dial_pipe(&hub)?;
        let mut session = connected(&mut probe, Role::Probe).await?;
        session
            .writer
            .send(&[Record::Echo(tally_wire::Echo { nonce: 9 })])
            .await
            .map_err(text)?;
        let mut reply = None;
        while reply.is_none() {
            reply = next(&mut session.reader)
                .await?
                .into_iter()
                .find_map(|record| match record {
                    Record::EchoReply(reply) => reply.content().ok(),
                    _ => None,
                });
        }
        let reply = reply.ok_or("no reply")?;
        assert_eq!((reply.nonce, reply.headroom.feeder_slots), (9, 0));
        assert_eq!(hub.egress().report().feeders, 0);
        assert_eq!(hub.subscribers(), 0);
        assert_eq!(probe.link.kind(), Kind::Probe);
        Ok(())
    }

    #[tokio::test]
    async fn a_repairs_data_goes_only_to_a_member_and_through_the_cap() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8).max_upload(roomy()));
        let relay = Identity::generate().map_err(text)?;
        let receiver = Identity::generate().map_err(text)?;
        let echo = hub
            .network()
            .admission
            .echo(&hub, Some(&relay), tally_wire::Echo { nonce: 4 }, 1)
            .ok_or("no echo reply")?;
        let answers = || -> Result<Vec<Record>, String> {
            Ok(vec![
                Record::EchoReply(echo.clone()),
                Record::Batch(batch(&receiver, 0, 1)?),
            ])
        };
        for (peer, data) in [(Peer::Relay, false), (Peer::Member, true)] {
            let (near, far) = tokio::io::duplex(1 << 20);
            let far = hub.egress().socket(far, None);
            let link = far.link();
            link.set_kind(Kind::Relay);
            let accepting = tokio::spawn({
                let relay = relay.clone();
                async move { noise::accept(far, &[relay]).await }
            });
            let mut near = noise::connect(
                near,
                &Identity::generate().map_err(text)?,
                &relay.public(),
                Role::Relay,
            )
            .await
            .map_err(text)?;
            let mut accepted = accepting.await.map_err(text)?.map_err(text)?;
            let key = Identity::generate().map_err(text)?.public();
            let mut told = Told::new();
            reply(
                &mut accepted.session.writer,
                &hub,
                &link,
                (peer, key),
                &mut told,
                answers()?,
            )
            .await
            .map_err(|_| "the reply failed".to_owned())?;
            accepted
                .session
                .writer
                .send(&[Record::Heartbeat])
                .await
                .map_err(text)?;
            let mut got = Vec::new();
            while !got.contains(&Record::Heartbeat) {
                got.extend(next(&mut near.reader).await?);
            }
            assert!(
                got.iter()
                    .any(|record| matches!(record, Record::EchoReply(_)))
            );
            assert_eq!(
                got.iter().any(|record| matches!(record, Record::Batch(_))),
                data,
                "{got:?}"
            );
            // The member's batch was granted by the cap, in the raw class; the relay link's never
            // asked it.
            let raw = hub
                .egress()
                .report()
                .classes
                .iter()
                .find(|class| class.class == Class::Raw)
                .map_or(0, |class| class.asked_bytes_per_sec);
            assert_eq!(raw > 0, data, "raw asked {raw} B/s");
        }
        Ok(())
    }

    // Paused: the heartbeat comes without waiting thirty real seconds.
    #[tokio::test(start_paused = true)]
    async fn every_byte_a_session_writes_is_counted_whatever_wrote_it() -> Result<(), String> {
        let hint = RelayAddress {
            key: Identity::generate().map_err(text)?.public(),
            address: "elsewhere.example:10900".to_owned(),
        };
        let hub = Arc::new(Hub::new(8).advertising(vec![hint]).max_upload(roomy()));
        let egress = Arc::clone(hub.egress());
        let mut counted = 0;

        // A feeder: the handshake, its rate limit and hints, a heartbeat; then it publishes a
        // batch signed by someone else and is closed without a word.
        let mut feeder = dial_pipe(&hub)?;
        let mut session = connected(&mut feeder, Role::Feeder).await?;
        let greeting = next(&mut session.reader).await?;
        assert!(matches!(greeting.first(), Some(Record::RateLimit { .. })));
        assert!(matches!(greeting.get(1), Some(Record::RelayList(_))));
        let beat = next(&mut session.reader).await?;
        assert_eq!(beat, vec![Record::Heartbeat]);
        let stranger = Identity::generate().map_err(text)?;
        session
            .writer
            .send(&[Record::Batch(batch(&stranger, 0, 1)?)])
            .await
            .map_err(text)?;
        ended(&mut feeder.serving).await?;
        assert!(
            egress.billed() > counted,
            "the feeder's session counted nothing"
        );
        assert_eq!(egress.billed() - counted, written(&feeder));
        counted = egress.billed();

        // A key claiming to be a relay that the operator did not accept: told so, in a goodbye.
        let mut stranger_relay = dial_pipe(&hub)?;
        let _ = connected(&mut stranger_relay, Role::Relay).await;
        ended(&mut stranger_relay.serving).await?;
        assert!(written(&stranger_relay) > 0);
        assert_eq!(egress.billed() - counted, written(&stranger_relay));
        counted = egress.billed();

        // A subscriber: the directory, the batches it asked for, and the redirect it is shed with.
        let mut subscriber = dial_pipe(&hub)?;
        let mut session = connected(&mut subscriber, Role::Subscriber).await?;
        while hub.subscribers() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let receiver = Identity::generate().map_err(text)?;
        hub.publish_batch(999, batch(&receiver, 0, 100)?, receiver.public());
        let mut got_batch = false;
        while !got_batch {
            got_batch = next(&mut session.reader)
                .await?
                .iter()
                .any(|record| matches!(record, Record::Batch(_)));
        }
        egress.shed_link(&subscriber.link);
        let mut told = None;
        while told.is_none() {
            told = next(&mut session.reader)
                .await?
                .into_iter()
                .find(|record| matches!(record, Record::Redirect { .. }));
        }
        assert!(matches!(
            told,
            Some(Record::Redirect {
                retry_after_secs,
                hints
            }) if retry_after_secs > 0 && hints.len() == 1
        ));
        ended(&mut subscriber.serving).await?;
        assert!(subscriber.link.sent() > 0);
        assert_eq!(egress.billed() - counted, written(&subscriber));
        counted = egress.billed();

        // A key claiming to be an engine whose offer this relay never verified: told so, in a
        // goodbye.
        let mut engine = dial_pipe(&hub)?;
        let _ = connected(&mut engine, Role::Engine).await;
        ended(&mut engine.serving).await?;
        assert!(written(&engine) > 0);
        assert_eq!(egress.billed() - counted, written(&engine));
        Ok(())
    }

    #[tokio::test]
    async fn an_upstream_link_beast_out_and_the_stats_are_counted_as_loopback() -> Result<(), String>
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // An upstream link, to a parent that reads what it is sent and then leaves.
        let parent = Identity::generate().map_err(text)?;
        let parent_key = parent.public();
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?.to_string();
        let parent_read = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(text)?;
            let (stream, read) = Metered::new(stream);
            let mut accepted = noise::accept(stream, &[parent]).await.map_err(text)?;
            let mut records = Vec::new();
            accepted
                .session
                .reader
                .recv(&mut records)
                .await
                .map_err(text)?;
            accepted
                .session
                .writer
                .send(&[Record::Goodbye {
                    reason: Reason::Leaving,
                    retry_after_secs: 1,
                }])
                .await
                .map_err(text)?;
            // Everything the child sent, to its end.
            while accepted.session.reader.recv(&mut records).await.is_ok() {}
            Ok::<u64, String>(read.load(std::sync::atomic::Ordering::Relaxed))
        });
        let child = Arc::new(Hub::new(8));
        let upstream = Upstream {
            address,
            key: parent_key,
        };
        let asked = upstream_once(&upstream, &Identity::generate().map_err(text)?, &child)
            .await?
            .map(|away| away.wait);
        assert_eq!(asked, Some(Duration::from_secs(1)));
        let read = parent_read.await.map_err(text)??;
        assert!(read > 0);
        // Loopback, and counted to the byte: no cap held it, not even the hub's empty one.
        assert_eq!(child.egress().loopback(), read);
        assert_eq!(child.egress().billed(), 0);

        // Beast-out.
        let hub = Arc::new(Hub::new(8));
        let beast = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let beast_address = beast.local_addr().map_err(text)?;
        tokio::spawn(serve_beast(beast, Arc::clone(&hub)));
        let mut client = TcpStream::connect(beast_address).await.map_err(text)?;
        let receiver = Identity::generate().map_err(text)?;
        let mut sequence = 0;
        let mut received = 0u64;
        let mut buffer = vec![0; 1 << 16];
        while received == 0 {
            hub.publish_batch(999, batch(&receiver, sequence, 10)?, receiver.public());
            sequence += 1;
            if let Ok(Ok(n)) = timeout(Duration::from_millis(50), client.read(&mut buffer)).await {
                received += n as u64;
            }
        }
        while hub.egress().loopback() > received {
            let n = timeout(Duration::from_secs(5), client.read(&mut buffer))
                .await
                .map_err(|_| "beast-out counted bytes it never sent".to_owned())?
                .map_err(text)?;
            received += n as u64;
        }
        assert_eq!(hub.egress().loopback(), received);

        // The stats endpoint, which reports the cap.
        let hub = Arc::new(Hub::new(8));
        let stats = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let stats_address = stats.local_addr().map_err(text)?;
        tokio::spawn(crate::stats::serve(stats, Arc::clone(&hub)));
        let mut stream = TcpStream::connect(stats_address).await.map_err(text)?;
        stream
            .write_all(b"GET /egress HTTP/1.1\r\nHost: stats\r\nConnection: close\r\n\r\n")
            .await
            .map_err(text)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.map_err(text)?;
        assert_eq!(hub.egress().loopback(), response.len() as u64);
        let text_response = String::from_utf8(response).map_err(text)?;
        let (_, body) = text_response.split_once("\r\n\r\n").ok_or("no body")?;
        let report: crate::egress::EgressReport = serde_json::from_str(body).map_err(text)?;
        assert_eq!(report.max_upload_bytes_per_sec, 0);
        assert_eq!(report.billed_bytes, 0);
        assert_eq!(report.classes.len(), crate::egress::Class::ALL.len());
        Ok(())
    }

    // Paused: time moves only when every task waits, so nothing here waits real seconds.
    /// A feeder turned away while it is already publishing reads why. Over TCP, a relay that
    /// closed with the feeder's batches unread would reset the connection, which discards whatever
    /// of the redirect was not yet sent and fails the feeder's next write or read. The relay ends
    /// the sending direction and reads until the feeder hangs up instead, so the feeder's writes
    /// all land, and it reads the redirect and then a clean end of stream, never a reset.
    #[tokio::test]
    async fn a_feeder_redirected_while_it_publishes_reads_the_redirect_and_a_clean_end()
    -> Result<(), String> {
        let hint = RelayAddress {
            key: Identity::generate().map_err(text)?.public(),
            address: "elsewhere.example:10900".to_owned(),
        };
        let hub = Arc::new(Hub::new(8).advertising(vec![hint.clone()]));
        // Duties off: every feeder is turned away at admission, pointed at the relays known.
        hub.network().admission.configure(0, false);
        let relay = Identity::generate().map_err(text)?;
        let relay_key = relay.public();
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        tokio::spawn(crate::serve(listener, vec![relay], hub));

        let feeder = Identity::generate().map_err(text)?;
        let stream = TcpStream::connect(address).await.map_err(text)?;
        let mut session = noise::connect(stream, &feeder, &relay_key, Role::Feeder)
            .await
            .map_err(text)?;
        // It publishes as a feeder does, not reading, past where the relay stopped taking batches.
        for sequence in 0..8 {
            session
                .writer
                .send(&[Record::Batch(batch(&feeder, sequence, 100)?)])
                .await
                .map_err(|error| format!("publishing batch {sequence}: {error}"))?;
        }
        let mut told = Vec::new();
        loop {
            let mut got = Vec::new();
            match timeout(Duration::from_secs(60), session.reader.recv(&mut got)).await {
                Ok(Ok(())) => told.extend(got),
                Ok(Err(tally_wire::WireError::Io(error)))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                other => return Err(format!("{other:?} after {told:?}")),
            }
        }
        assert_eq!(
            told,
            vec![Record::Redirect {
                retry_after_secs: FULL_RETRY_SECS,
                hints: vec![hint],
            }]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_feeder_the_cap_cannot_carry_is_turned_away_before_it_publishes() -> Result<(), String>
    {
        let accepted = Identity::generate().map_err(text)?;
        let hint = RelayAddress {
            key: Identity::generate().map_err(text)?.public(),
            address: "elsewhere.example:10900".to_owned(),
        };
        // Room for one feeder's raw to one relay link, and not for a second's.
        let cap = crate::egress::Cap::bytes_per_sec(
            crate::egress::FEEDER_COMMITMENT_BYTES_PER_SEC * 3 / 2,
        );
        let hub = Arc::new(
            Hub::new(8)
                .accepting_relays([accepted.public()])
                .advertising(vec![hint])
                .max_upload(cap),
        );
        let out = hub.listen(u64::MAX, Filter::Everything);

        // A billed relay link: what feeders send is forwarded to it.
        let mut relay = dial_pipe(&hub)?;
        let near = relay.near.take().ok_or("no pipe")?;
        let _relay_session = noise::connect(near, &accepted, &relay.relay_key, Role::Relay)
            .await
            .map_err(text)?;
        while relay.link.kind() != Kind::Relay {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The first feeder fits: told its rate limit, and what it publishes is taken in.
        let mut first = dial_pipe(&hub)?;
        let first_identity = Identity::generate().map_err(text)?;
        let near = first.near.take().ok_or("no pipe")?;
        let mut feeding = noise::connect(near, &first_identity, &first.relay_key, Role::Feeder)
            .await
            .map_err(text)?;
        let greeting = next(&mut feeding.reader).await?;
        assert!(matches!(greeting.first(), Some(Record::RateLimit { .. })));
        feeding
            .writer
            .send(&[Record::Batch(batch(&first_identity, 0, 10)?)])
            .await
            .map_err(text)?;
        let mut items = Vec::new();
        timeout(Duration::from_secs(60), out.recv_many(&mut items, 1))
            .await
            .map_err(|_| "the feeder's batch was not taken in".to_owned())?
            .map_err(|fell| format!("{fell:?}"))?;
        assert!(matches!(&*items[0].record, Record::Batch(_)));

        // The second does not fit: pointed at the relays this one knows, and nothing it sent with
        // its hello is taken in.
        let mut second = dial_pipe(&hub)?;
        let second_identity = Identity::generate().map_err(text)?;
        let near = second.near.take().ok_or("no pipe")?;
        let mut refused = noise::connect_with(
            near,
            &second_identity,
            &second.relay_key,
            Role::Feeder,
            &[Record::Batch(batch(&second_identity, 0, 10)?)],
        )
        .await
        .map_err(text)?;
        let refusal = next(&mut refused.reader).await?;
        assert!(matches!(
            refusal.first(),
            Some(Record::Redirect { retry_after_secs, hints })
                if *retry_after_secs > 0 && hints.len() == 1
        ));
        let why = ended(&mut second.serving).await?;
        assert!(why.contains("upload cap"), "{why}");
        assert!(out.try_recv().is_none());
        assert_eq!(hub.egress().report().refused_feeders, 1);
        // The first is still served.
        assert!(!first.serving.is_finished());
        Ok(())
    }
}
