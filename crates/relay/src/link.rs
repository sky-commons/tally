//! One relay connection of each kind: a feeder publishing its own batches, a subscriber taking
//! the streams it asked for, an MLAT engine doing both with its own positions, another relay
//! exchanging both ways, and the loopback BEAST output.
//!
//! Every write has a deadline: a Noise `Writer::send` fails with `WireError::Timeout` after
//! `noise::WRITE_TIMEOUT`, leaving the writer mid-frame, and like any send error here that ends the
//! link (a subscriber's, an engine's, a feeder's greeting and heartbeats, an accepted relay's, an
//! upstream's, which then redials). A beast-out or acars-out client's writes are held to
//! `LOCAL_WRITE_TIMEOUT`.
//! A peer that heartbeats but never reads therefore holds its slot no longer than the deadline.
//!
//! Every stream is an `egress::Socket`, so every byte written is counted and held to the upload cap.
//! Each record a link gathers is classified once (`egress::Class::of`) and waits for its class's
//! grant before it is sent (`send_data`), highest class first; a link the cap sheds is turned away
//! (`full`), and a feeder the cap cannot carry is turned away before it publishes anything.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tally_wire::clocks::{Judged, Raw};

use tally_wire::backoff::Backoff;
use tally_wire::noise::{self, Accepted, Reader, Writer};
use tally_wire::{ClientRecord, NoiseKey, PublicKey, Reason, Record, Role};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::ceiling::{self, Ceiling, Metered};
use crate::config::Upstream;
use crate::egress::{Class, Kind, Link, Shed, Socket};
use crate::fanout::{Fell, Filter, Listener, Taken};
use crate::hub::{Connection, Description, Hub, Inbound, Item, Origin, OwnDescription, RelayTrust};
use crate::ingest::{Allowance, InFlight, RecordPace, Refusal};
use crate::network::{Asker, AskerRole};
use crate::outbound::{Column, Sendable, Typed};
use crate::peers::Queued;
use crate::subscription::{ClientSubscription, Subscription, directory_wants, on_directory_link};
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
/// How long one write to a beast-out or acars-out client may take before the client is dropped: the
/// same deadline as a Noise session's.
const LOCAL_WRITE_TIMEOUT: Duration = noise::WRITE_TIMEOUT;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a peer turned away at capacity (the subscriber cap, or the upload cap) is asked to stay
/// away.
const FULL_RETRY_SECS: u32 = 600;
/// How long a peer refused outright (a broken protocol, a role it may not take) is asked to stay
/// away.
const REFUSED_RETRY_SECS: u32 = 86_400;
/// How long a relay refused because this one has not verified its offer is asked to stay away: no
/// longer than the dialler's own schedule waits (`Backoff`, from a second, doubling to five
/// minutes). A refusal for that is a wait for gossip, not a verdict. Offers spread and are verified
/// within seconds, and two relays learn of each other in either order, so a member dials one that
/// has not verified it yet as often as not; asked to stay away a re-signing (a minute), its slice
/// for that member waited a minute, past the repair horizon (`sharing::Deadlines::horizon_ms`), and
/// reached it that late or, past its link's share (`peers::WAITING_PER_LINK_BYTES`), not at all.
/// Its doubling still spaces out a relay whose offer
/// is never verified, and it is never the day a broken peer is given.
const UNVERIFIED_RETRY_SECS: u32 = Backoff::FIRST.as_secs() as u32;
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

/// The longest a farewell takes (`farewell`): what a stopping relay waits for its sessions.
pub const FAREWELL_MOST: Duration = FAREWELL_TIMEOUT.saturating_add(FAREWELL_LINGER);

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
    /// (echoes, delivery queries and a timed heartbeat), is answered, and is never admitted as a feeder or a
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
                why: "a probe sent more than echoes, delivery queries and a timed heartbeat"
                    .to_owned(),
            }),
            Self::Relay if on_directory_link(record) => Permit::Take,
            Self::Relay => Permit::Drop,
            Self::Feeder(own) => match (record, signer(record)) {
                (
                    Record::Batch(_) | Record::ReceiverInfo(_) | Record::ReceiverSite(_),
                    Some((_, Ok(key))),
                ) if key == own => Permit::Take,
                _ => publishes_nothing(record),
            },
            Self::Subscriber | Self::Engine(_) => publishes_nothing(record),
        }
    }

    /// Whether a reply the network duties give (`Network::handle`) is sent to the peer: to a
    /// relay, member or not, only the directory; to any other peer, only what is control to it
    /// (an echo's reply, a delivery answer, offers to a feeder that asked). Data never goes back
    /// down the session it was asked for on: the far end of a member's session is the link that
    /// member dialled, which takes no data in (`member`), so a repair page sent there would end
    /// it. Sharing sends one over this relay's own member link to the asker instead (`peers`).
    fn takes_reply(self, record: &Record, kind: Kind) -> bool {
        match self {
            Self::Member | Self::Relay => on_directory_link(record),
            Self::Feeder(_) | Self::Subscriber | Self::Engine(_) | Self::Probe => {
                Class::of(record, kind) == Class::Control
            }
        }
    }

    /// What the peer is served of the streams, given what it asked for: a subscriber what its
    /// credit allows; an engine raw within the border band of the areas it solves; every other
    /// role nothing, as it subscribes to nothing.
    fn grant(self, hub: &Hub, asker: &Asker, asked: Subscription, now: Judged) -> Subscription {
        match self {
            // A client's regions no finer than a public cell (`Subscription::for_client`).
            Self::Subscriber => {
                hub.network()
                    .credit
                    .admit(asker, asked.for_client().into_subscription(), now)
            }
            Self::Engine(key) => {
                crate::subscription::engine_grant(&hub.network().directory, &key, &asked, now)
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
        Record::ReceiverSite(site) => Some(("a receiver site", site.receiver())),
        Record::Positions(positions) => Some(("positions", positions.engine())),
        Record::Provisional(positions) => Some(("provisional positions", positions.engine())),
        Record::ClockModel(model) => Some(("a clock model", model.engine())),
        Record::ClientClockModel(model) => Some(("a clock model", model.signer())),
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

/// Held while a feeder is connected: it is connected in the station reports from its start, and
/// its end ends the feeder's session there.
struct Feeding {
    hub: Arc<Hub>,
    receiver: PublicKey,
    source: u64,
}

impl Feeding {
    fn open(
        hub: Arc<Hub>,
        receiver: PublicKey,
        source: u64,
        address: Option<std::net::IpAddr>,
    ) -> Self {
        hub.opened(&receiver, source, address);
        Self {
            hub,
            receiver,
            source,
        }
    }
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

/// Which records on the fan-out a link is sent. A client's and an engine's are different
/// types, so no client path can route by what only a relay may (`ClientSubscription`).
enum Wants {
    /// Another relay: the directory only (`directory_wants`).
    Directory,
    /// An engine: its subscription in effect, by its receivers' sites (`Subscription::wants`).
    Engine {
        current: Subscription,
        changes: Changes,
    },
    /// A client: its subscription in effect, by each item's client place, and only what has a
    /// client form (`ClientSubscription::serves`).
    Client {
        current: ClientSubscription,
        changes: Changes,
    },
}

/// The subscriptions a link's read side took, which its write side alone applies, so a newly
/// covered receiver is described before anything placed by it is let through.
struct Changes {
    /// Every `Subscribe` the read side took, the latest only.
    updates: watch::Receiver<Subscription>,
    /// When the next change may take effect (`SUBSCRIBE_EVERY`).
    next: Instant,
}

impl Changes {
    fn new(updates: watch::Receiver<Subscription>) -> Self {
        Self {
            updates,
            next: Instant::now(),
        }
    }
}

impl Wants {
    fn engine(current: Subscription, updates: watch::Receiver<Subscription>) -> Self {
        Self::Engine {
            current,
            changes: Changes::new(updates),
        }
    }

    fn client(current: ClientSubscription, updates: watch::Receiver<Subscription>) -> Self {
        Self::Client {
            current,
            changes: Changes::new(updates),
        }
    }

    fn wants(&self, item: &Item) -> bool {
        match self {
            Self::Directory => directory_wants(item),
            Self::Engine { current, .. } => current.wants(item),
            Self::Client { current, .. } => item
                .client
                .as_ref()
                .is_some_and(|client| current.serves(client)),
        }
    }

    /// Resolves with the latest subscription asked for, no sooner than `SUBSCRIBE_EVERY` after the
    /// last; a relay's never changes. It takes effect at `apply`, once the descriptions it newly
    /// covers are sent.
    async fn changed(&mut self) -> Subscription {
        if let Self::Engine { changes, .. } | Self::Client { changes, .. } = self {
            tokio::time::sleep_until(changes.next).await;
            if changes.updates.changed().await.is_ok() {
                changes.next = Instant::now() + SUBSCRIBE_EVERY;
                return changes.updates.borrow_and_update().clone();
            }
        }
        std::future::pending().await
    }

    /// The descriptions `subscription` covers, to send before it takes effect: an engine's by
    /// their sites, a client's by their public cells (`Hub::client_infos`).
    fn infos(&self, hub: &Hub, subscription: &Subscription) -> Vec<Item> {
        match self {
            Self::Directory => Vec::new(),
            Self::Engine { .. } => hub.engine(subscription),
            Self::Client { .. } => hub.client_infos(&subscription.clone().for_client()),
        }
    }

    fn apply(&mut self, subscription: Subscription) {
        match self {
            Self::Directory => {}
            Self::Engine { current, .. } => *current = subscription,
            // Clamped again however it came: a client's regions are no finer than a public cell.
            Self::Client { current, .. } => *current = subscription.for_client(),
        }
    }

    /// What the router offers a link that wants this.
    fn filter(&self) -> Filter {
        match self {
            Self::Directory => Filter::Directory,
            Self::Engine { current, .. } => Filter::Subscription(current.clone()),
            Self::Client { current, .. } => Filter::Client(current.clone()),
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
    /// The peer is turned away for this relay's capacity at its admission as a member
    /// (`admit_member`), told so (`Reason::Full`), and, a relay that dialled in, noted as routing
    /// around this one for the wait it is given (`turning_away`): the one end that exempts a peer
    /// from its shortfalls. Never a refusal of what the peer did (its ceiling overrun is
    /// `Reason::OverCeiling`): before, every `Full` this relay said was noted, so a parent that
    /// overran its child's ceiling to be turned away delivered nothing and was never filed short.
    Full(capacity::AtAdmission),
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
///
/// The last word is a `ClientRecord` (a `Goodbye` or a `Redirect`): what every peer, a client
/// included, may be sent, so no path ends a client's session saying more.
async fn farewell<S>(reader: &mut Reader<S>, writer: &mut Writer<S>, last: ClientRecord)
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
fn goodbye(reason: Reason, retry_after_secs: u32) -> ClientRecord {
    ClientRecord::Goodbye {
        reason,
        retry_after_secs,
    }
}

/// How long a peer told this relay is stopping is asked to wait before it comes back: a restart's
/// worth. A feeder goes to its other relays meanwhile.
const LEAVING_RETRY_SECS: u32 = 30;

/// How every session ends once the relay is stopping (`Hub::leaving`): told so
/// (`Reason::Leaving`).
fn leaving() -> Closing {
    Closing::Saying {
        last: Box::new(goodbye(Reason::Leaving, LEAVING_RETRY_SECS)),
        why: "the relay is stopping".to_owned(),
    }
}

/// The clock this relay states to a feeder now (`RateLimit`'s `clock_ms` and `error_ms`): its
/// judging clock, and its error bound (`u64::MAX` while the host reports it unsynced). What the
/// feeder signs by, and reports a disagreement with; it is judged by it for usability alone, and
/// nothing is refused for it.
fn stated_clock(hub: &Hub) -> (u64, u64) {
    (
        hub.clock().judged().ms(),
        hub.clock().error_ms().unwrap_or(u64::MAX),
    )
}

/// Notes, when this relay turns a relay that dialled it (a member, a directory link that may be
/// one, another relay's MLAT) away at its admission for want of a member's room (`refused`), that
/// the relay turned away now routes its slice past this one for the wait the one rule gives
/// (`sharing::full::Wait`, the rule its `peers::Peers::refused_full` applies to the same
/// refusal): this relay files no shortfall against it for those windows (RFC-0174 §2.5). It takes
/// a [`capacity::AtAdmission`], which only `admit_member` makes, so nothing else can excuse a
/// peer: not the word said, and not a link the upload cap shed, which the peer chooses by
/// what it asks for (a peer flooding queries is the one the cap sheds).
fn turning_away(hub: &Hub, peer: Peer, key: &PublicKey, refused: &capacity::AtAdmission) {
    if matches!(peer, Peer::Member | Peer::Relay | Peer::Engine(_)) {
        hub.network()
            .sharing
            .turned_away(*key, refused.wait(), hub.now().ms());
    }
}

/// The one refusal for this relay's own capacity that excuses a peer its shortfalls
/// ([`turning_away`]): a member turned away at its admission (`admit_member`) for want of a
/// member's slot or room. Its fields are this module's, so it is made only by
/// [`AtAdmission::member_refused`], which only `admit_member` calls; an end of any other kind (a
/// ceiling overrun, a shed, falling behind) cannot be one.
mod capacity {
    use std::time::Duration;

    use tally_wire::{ClientRecord, Reason};

    pub(super) struct AtAdmission {
        retry_after_secs: u32,
        why: String,
    }

    impl AtAdmission {
        /// A member turned away at its admission: `admit_member`'s alone.
        pub(super) fn member_refused(retry_after_secs: u32, why: String) -> Self {
            Self {
                retry_after_secs,
                why,
            }
        }

        /// What the peer is told: this relay is full.
        pub(super) fn last(&self) -> ClientRecord {
            super::goodbye(Reason::Full, self.retry_after_secs)
        }

        /// How long it is asked to stay away, the wait it routes around this relay for.
        pub(super) fn wait(&self) -> Duration {
            Duration::from_secs(self.retry_after_secs.into())
        }

        pub(super) fn why(&self) -> &str {
            &self.why
        }

        pub(super) fn into_why(self) -> String {
            self.why
        }
    }
}

/// What a peer turned away for the relay's capacity is told: the relays it may try instead, or that
/// the relay is full if it knows none.
fn full(hub: &Hub) -> ClientRecord {
    if hub.hints().is_empty() {
        ClientRecord::Goodbye {
            reason: Reason::Full,
            retry_after_secs: FULL_RETRY_SECS,
        }
    } else {
        ClientRecord::Redirect {
            retry_after_secs: FULL_RETRY_SECS,
            hints: hub.hints().to_vec(),
        }
    }
}

/// Ends a session `peer` (`key`) dialled that is not yet exchanging: tells the peer if `end` says
/// to (`turning_away` first, for a capacity refusal), and says why.
/// How a connection the ingest stage refused ends (`ingest::Refusal`): closed without a word,
/// since what it refuses (a batch that does not verify or cannot be read) is no accident.
fn refused_end(why: String) -> End {
    End::Closed(why)
}

async fn end_now<S>(
    reader: &mut Reader<S>,
    writer: &mut Writer<S>,
    (hub, peer, key): (&Hub, Peer, &PublicKey),
    end: End,
) -> String
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
        End::Full(refused) => {
            turning_away(hub, peer, key, &refused);
            farewell(reader, writer, refused.last()).await;
            refused.into_why()
        }
        End::Closed(why) => why,
        End::Departed(away) => {
            format!("the relay left, asking for {} s", away.wait.as_secs())
        }
    }
}

/// Serves one connection accepted under `connection` (`Hub::connection`): its handshake, its
/// admission by its role, and then the session.
///
/// Until it takes a place of its role's own, it holds one under the connection cap
/// (`Connection::general`): a feeder gives it up once it holds its reservation, a subscriber its
/// place among the subscribers, a relay once it is admitted as a member (`admit_member`), so each
/// role is bounded by its own cap and never takes another's. Its Noise buffers, both directions
/// (`ingest::BUFFERS_PER_CONNECTION`), are carved before its handshake from the room planned for
/// every connection but a feeder's, and a feeder's are moved to what its reservation planned
/// (`Store::Buffers`) once it holds one; carved for the whole session, so what a send to a slow
/// reader holds is planned as what a read holds.
pub async fn inbound<S>(
    stream: Socket<S>,
    identities: &[impl tally_wire::Handshakes],
    hub: Arc<Hub>,
    mut connection: Connection,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + crate::sockets::Tunable,
{
    let link = stream.link();
    // Its kernel buffers are a feeder's until it holds a place counted for a larger role
    // (`sockets`): a subscriber's, a member's or an engine's.
    let tuner = crate::sockets::Tunable::tuner(&stream);
    let mut general = connection.general();
    // Whose turn it waits in for room (`ingest::network_source`): its network group's.
    let waits =
        crate::ingest::network_source(crate::ingest::group_of(Some(connection.address())), 0);
    let buffers = hub.connection_buffers(false, waits).await;
    // Every byte the peer sends is counted from the first, the handshake's included, as every
    // byte sent it is (`Socket`).
    let (stream, read) = Metered::new(stream);
    // Its turn at the handshake: only as many run at once as the runtime's cores are planned to
    // carry (`cores::handshakes_in_flight`), so a reconnect storm is admitted at a planned pace
    // and never takes the sessions already served with it.
    let turn = hub.handshake().await;
    // What came with its Hello stays in its message, decoded a record at a time as each is acted
    // on (`noise::Message`).
    let accepted = noise::accept_message(stream, identities).await;
    // The raw monotonic clock as its Hello's message came off the socket, before any pacing:
    // what this relay's own anchor in a batch it carried is aged by (`Inbound::arrived`).
    let first_arrived = hub.clock().raw();
    drop(turn);
    let Accepted {
        mut session,
        peer: key,
        role,
        mut first,
    } = accepted.map_err(|error| error.to_string())?;
    // What its write side may carry, by the role its handshake established and the version it
    // agreed (`outbound`): a client link sends `ClientRecord`s alone. A relay or an engine older
    // than version 3 has no column: the handshake refused it (`tally_wire::least_version`), and
    // the type makes this side refuse it too.
    let column = Column::of(role, session.version).map_err(|too_old| too_old.to_string())?;
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
        address: Some(connection.address()),
    };
    // Its place in the network duties, from before its `Hello`'s records are acted on.
    let leaving = Leaving::join(&hub, &asker);
    link.set_kind(match peer {
        Peer::Feeder(_) => Kind::Feeder,
        Peer::Relay | Peer::Member => Kind::Relay,
        Peer::Engine(_) => Kind::Engine,
        Peer::Subscriber => Kind::Taker,
        Peer::Probe => Kind::Probe,
    });
    // The records a second it may send, from its first, by its role and
    // its network group (`Paces`).
    let paces = Paces::of(&hub, peer, asker.address)?;
    // The echoes and delivery queries that lead what came with Hello are answered before anything
    // else, admission included: a feeder measuring relays learns how near a full one is, and that
    // it is full, from its signed reply, and a feeder checking its delivery asks members it does
    // not publish to, full or not. A probe that sent anything else with its Hello broke its role:
    // it is told so, unanswered. Any other role's other records are taken once it is admitted.
    let probing = |record: &Record| matches!(record, Record::Echo(_) | Record::DeliveryQuery(_));
    let mut echoed = Vec::new();
    while let Some(probe) = first.next_if(probing).map_err(|error| error.to_string())? {
        let pace = paces.take(&hub, peer, &asker.key).await;
        echoed.extend(
            hub.network()
                .handle(&hub, &asker, probe, hub.stamp_now(), pace.as_deref()),
        );
    }
    if role == Role::Probe && !first.is_read() {
        let last = goodbye(Reason::Protocol, REFUSED_RETRY_SECS);
        farewell(&mut session.reader, &mut session.writer, last).await;
        return Err("a probe sent more than echoes and delivery queries with its Hello".to_owned());
    }
    if !echoed.is_empty() {
        crate::outbound::send_as(column, &mut session.writer, echoed)
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
    // What it may have in the ingest stage (a member's, when it is one): the batches its Hello
    // carries are charged like every other.
    let mut admitted = match peer {
        Peer::Feeder(_) => Admitted {
            allowance: Some(hub.allowance(
                crate::ingest::CREDIT,
                crate::ingest::network_source(crate::ingest::group_of(asker.address), source),
            )),
            ..Admitted::default()
        },
        // A relay that dialled in is admitted as a member once its offer is verified and it
        // brings data in (`Admitted::charge`), and holds its place under the connection cap
        // until then.
        Peer::Member | Peer::Relay => Admitted {
            joins: true,
            _general: general.take(),
            tuner: Some(tuner),
            ..Admitted::default()
        },
        Peer::Subscriber | Peer::Engine(_) | Peer::Probe => Admitted::default(),
    };
    // A feeder admitted holds its place by its reservation: its buffers are what that planned,
    // and it gives up its place under the connection cap.
    let _buffers = match peer {
        Peer::Feeder(_) => {
            let planned = hub.connection_buffers(true, waits).await;
            drop((buffers, general.take()));
            planned
        }
        _ => buffers,
    };
    // A feeder is connected in the station reports from here, whether or not it ever sends a
    // batch, and its session there ends with this connection, however it ends.
    let _feeding = match peer {
        Peer::Feeder(receiver) => Some(Feeding::open(
            Arc::clone(&hub),
            receiver,
            source,
            asker.address,
        )),
        _ => None,
    };
    // Before any `Subscribe`, the role is granted what it would be for the version 1 default: so a
    // client that never subscribes is held to its credit, and an engine to its band, from its
    // first byte.
    let initial = peer.grant(&hub, &asker, Subscription::default(), hub.now());
    let (subscribe, mut subscription) = watch::channel(initial);
    let steer = matches!(peer, Peer::Subscriber | Peer::Engine(_)).then_some(&subscribe);
    let mut described = None;
    // What came with Hello is acted on before anything is sent: a subscriber's first `Subscribe`
    // decides its first byte, and a network duty's answers (a probe's, before any) go first: they
    // wait for the write side as every later record's do, within the connection's room, and it
    // sends them straight after the greeting (`write_loop`).
    let replies = Replies::new(peer, &link);
    let refusal = Arc::new(Refusal::default());
    loop {
        let record = match first.next() {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(error) => return Err(error.to_string()),
        };
        let pace = paces.take(&hub, peer, &asker.key).await;
        let in_flight = match admitted
            .charge(&hub, (peer, &asker.key, source), &record)
            .await
        {
            Ok(in_flight) => in_flight,
            Err(end) => {
                return Err(end_now(
                    &mut session.reader,
                    &mut session.writer,
                    (&hub, peer, &asker.key),
                    end,
                )
                .await);
            }
        };
        let ingested = ingest(
            record,
            &hub,
            source,
            (peer, &asker),
            steer,
            &mut described,
            (in_flight, &refusal, first_arrived),
        )
        .or_else(|unhandled| {
            network(
                unhandled,
                (&hub, &asker, pace.as_deref()),
                &replies.replying,
            )
        });
        if let Err(end) = ingested {
            return Err(end_now(
                &mut session.reader,
                &mut session.writer,
                (&hub, peer, &asker.key),
                end,
            )
            .await);
        }
    }
    let (greeting, fan_out, _slot) = match peer {
        Peer::Feeder(_) => {
            // What the relay will take from it, less framing, so a feeder that keeps to it never
            // meets the ceiling.
            let (bytes_per_sec, burst) = ceiling::advertised(hub.feeder_bytes_per_sec());
            // And the wanted receptions a second its receiver is held to, which it sheds to
            // before it signs: past them a batch is dropped here (`ingest::ReceptionCeilings`).
            // And its clock, the one it judges the feeder's signed clock by, so a feeder signs by
            // it (`strikes::feeder_clock`, RFC-0171 §3.6).
            let (clock_ms, error_ms) = stated_clock(&hub);
            let mut greeting = vec![Record::RateLimit {
                bytes_per_sec,
                burst,
                wanted_per_sec: Some(
                    u32::try_from(crate::ingest::FEEDER_RECEPTIONS_PER_SEC).unwrap_or(u32::MAX),
                ),
                clock_ms: Some(clock_ms),
                error_ms: Some(error_ms),
            }];
            // This relay's freshness anchor, the newest it states (RFC-0171 §3.6): what the
            // feeder puts in each batch it signs, so every hop can bound its age by a clock it
            // trusts. Then one a period (`write_loop`). None while its clock is not judging.
            if let Some(anchor) = hub.anchor() {
                greeting.push(Record::Anchor(anchor));
            }
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
        // It is given an engine's buffers while it holds one of the engines' places
        // (`Hub::engine_place`), as many as the member sessions planned; past them it is served
        // as any connection, at a feeder's.
        Peer::Engine(_) => {
            let current = subscription.borrow_and_update().clone();
            let fan_out = FanOut {
                infos: hub.engine(&current),
                wants: Wants::engine(current, subscription),
            };
            let place = hub.engine_place();
            if place.is_some() {
                tuner.set(crate::sockets::Role::Engine);
            }
            (Vec::new(), Some(fan_out), place)
        }
        Peer::Subscriber => {
            let current = subscription.borrow_and_update().clone().for_client();
            let Some((infos, slot)) = hub.subscribe(&current) else {
                let redirect = ClientRecord::Redirect {
                    retry_after_secs: FULL_RETRY_SECS,
                    hints: hub.hints().to_vec(),
                };
                farewell(&mut session.reader, &mut session.writer, redirect).await;
                return Err("at subscriber capacity".to_owned());
            };
            // Its place is among the subscribers now, and its buffers a subscriber's.
            drop(general.take());
            tuner.set(crate::sockets::Role::Subscriber);
            let fan_out = FanOut {
                infos,
                wants: Wants::client(current, subscription),
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
        &link,
        Serving {
            column,
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
            paces,
            outgoing: None,
            replies,
            leaving,
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
pub async fn upstream(upstream: Upstream, identity: NoiseKey, hub: Arc<Hub>) {
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
    identity: &impl tally_wire::Handshakes,
    hub: &Arc<Hub>,
) -> Result<Option<Away>, String> {
    // A place under the connection cap (`Hub::dialled`), and the session's buffers.
    let _slot = hub
        .dialled()
        .ok_or_else(|| "no connection slot to dial with (--max-connections)".to_owned())?;
    let _buffers = hub
        .connection_buffers(false, crate::ingest::RELAY_SOURCE)
        .await;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&upstream.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    // A directory link carries offers and queries, never data: a feeder's buffers.
    crate::sockets::configure(&stream, crate::sockets::Role::Feeder);
    let peer = stream.peer_addr().ok().map(|address| address.ip());
    let stream = hub.egress().socket(stream, peer);
    let link = stream.link();
    link.set_kind(Kind::Relay);
    let mut session = match noise::connect(stream, identity, &upstream.key, Role::Relay).await {
        Ok(session) => session,
        // A parent that does not accept this relay says how long to stay away.
        Err(error) => return refused(error),
    };
    // A parent older than version 3 is no relay of this one's (`outbound::Column::of`).
    let column = Column::of(Role::Relay, session.version).map_err(|too_old| too_old.to_string())?;
    let source = hub.connection_id();
    let asker = Asker {
        role: AskerRole::Relay,
        key: upstream.key,
        source,
        loopback: !link.billed(),
        address: peer,
    };
    exchange(
        &mut session.reader,
        &mut session.writer,
        hub,
        source,
        Peer::Relay,
        &link,
        Serving {
            column,
            leaving: Leaving::join(hub, &asker),
            greeting: Vec::new(),
            fan_out: Some(directory_fan_out()),
            subscribe: None,
            described: None,
            refusal: None,
            admitted: Admitted::default(),
            // A directory link carries offers and queries; only data is held to a ceiling. Its
            // records wait for the directory's pace, shared by every directory link, whoever
            // dialled (`Paces`).
            ceiling: None,
            paces: Paces::shared(peer),
            asker,
            outgoing: None,
            replies: Replies::new(Peer::Relay, &link),
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
        .live_offers(hub.now())
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
/// A relay that turns the link away as full (`Reason::Full`, RFC-0174 §2.5 and §2.6), a sharing
/// member's or a raw source's, ends it: it is this provider that is full, so the relay routes what
/// it would have sent it to the next members of its trees, and dials no raw from it, for as long
/// as it asked, doubled on each refusal after (`peers::Peers::refused_full`); it dials it again
/// only once sharing addresses it again, or `selection` names it as a raw source once its wait has
/// passed. The relay that refused it applies the same wait to the same refusal
/// (`turning_away`), so neither files a shortfall against the other for the windows it covers.
pub async fn member(
    relay: RelayAddress,
    identity: NoiseKey,
    role: Role,
    first: Vec<Record>,
    hub: Arc<Hub>,
    mut outgoing: mpsc::Receiver<Queued>,
) {
    let mut redial = Redial::new(hub.network().dials());
    let who = format!("peer {}", relay.address);
    while !outgoing.is_closed() {
        let started = redial.dialling();
        let outcome = member_once(&relay, &identity, role, &first, &hub, &mut outgoing).await;
        if let Ok(Some(away)) = outcome
            && away.full
        {
            let peers = &hub.network().peers;
            let now = crate::sharing::Now::from(hub.stamp_now());
            peers.refused_full(relay.key, away.wait, now);
            let routed = peers.full_for(&relay.key, now).unwrap_or(away.wait);
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
    identity: &impl tally_wire::Handshakes,
    role: Role,
    first: &[Record],
    hub: &Arc<Hub>,
    outgoing: &mut mpsc::Receiver<Queued>,
) -> Result<Option<Away>, String> {
    // A raw link brings another relay's raw in, so it is a member session: its place in the
    // members' pool is taken before it is dialled, never once data comes, so this relay never
    // dials a link it would then turn away itself. A member link this relay dialled only sends
    // (what the member sends it comes over its own dial), and takes none: it holds a place under
    // the connection cap instead (`Hub::dialled`).
    let source = hub.connection_id();
    let admitted =
        if role == Role::Engine {
            admit_member(hub, source).map_err(|end| match end {
                End::Told { why, .. } | End::Closed(why) => why,
                End::Full(refused) => refused.into_why(),
                End::Departed(_) => "turned away".to_owned(),
            })?
        } else {
            Admitted {
                _general: Some(hub.dialled().ok_or_else(|| {
                    "no connection slot to dial with (--max-connections)".to_owned()
                })?),
                ..Admitted::default()
            }
        };
    let _buffers = hub
        .connection_buffers(false, crate::ingest::RELAY_SOURCE)
        .await;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&relay.address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    crate::sockets::configure(&stream, crate::sockets::Role::Member);
    let address = stream.peer_addr().ok().map(|address| address.ip());
    let stream = hub.egress().socket(stream, address);
    let link = stream.link();
    link.set_kind(Kind::Relay);
    let mut session = match noise::connect_with(stream, identity, &relay.key, role, first).await {
        Ok(session) => session,
        Err(error) => return refused(error),
    };
    // A member older than version 3 is no member of this one's (`outbound::Column::of`).
    let column = Column::of(role, session.version).map_err(|too_old| too_old.to_string())?;
    let asker = Asker {
        role: AskerRole::Relay,
        key: relay.key,
        source,
        loopback: !link.billed(),
        address,
    };
    let leaving = Leaving::join(hub, &asker);
    exchange(
        &mut session.reader,
        &mut session.writer,
        hub,
        source,
        Peer::Member,
        &link,
        Serving {
            column,
            greeting: Vec::new(),
            fan_out: None,
            subscribe: None,
            described: None,
            refusal: None,
            admitted,
            ceiling: None,
            // What it sends back is a member's, paced as every member's is (`Paces`).
            paces: Paces::shared(address),
            asker,
            outgoing: Some(outgoing),
            replies: Replies::new(Peer::Member, &link),
            leaving,
        },
    )
    .await
}

/// A session's place in the network duties: joined when it is made (`Network::joined`), and
/// ended, whatever it was given (a client's credit, its free-tier place, a peer's records'
/// shares), when it is dropped (`Network::left`). Every session holds one ([`Serving::leaving`]),
/// inbound and both kinds this relay dials, so none joins without leaving or leaves unjoined.
struct Leaving {
    hub: Arc<Hub>,
    source: u64,
}

impl Leaving {
    fn join(hub: &Arc<Hub>, asker: &Asker) -> Self {
        Self {
            hub: Arc::clone(hub),
            source: asker.source,
        }
    }
}

impl Drop for Leaving {
    fn drop(&mut self) {
        self.hub.network().left(self.source);
    }
}

/// What a connection is told and given, beside what it publishes.
struct Serving<'a> {
    /// What its write side may carry, by the peer's role and version (`outbound::Column`).
    column: Column,
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
    /// The records a second the peer may send, and a feeder's receptions (`Paces`).
    paces: Paces,
    /// Who the peer is, as the network duties see it.
    asker: Asker,
    /// What the network duties address to this peer, for a member link this relay dialled.
    outgoing: Option<&'a mut mpsc::Receiver<Queued>>,
    /// Where the network duties' replies wait for the write side: made before the `Hello`'s
    /// records are handled, so their answers wait there as every later record's do.
    replies: Replies,
    /// Its place in the network duties, left when the session ends.
    leaving: Leaving,
}

/// Replies the network duties give a peer, waiting for the write side, by count; their bytes are
/// held to `ingest::REPLIES_BYTES` ([`ReplyRoom`]). Beyond either the newest is dropped: a peer
/// that floods queries gets fewer answers, never more of the relay's memory.
const REPLIES_WAITING: usize = 64;

/// What one connection's replies waiting for its write side allocate (each record's own and its
/// slot, `Record::allocated`; before, their encoded bytes, which their slots passed), held to
/// `ingest::REPLIES_BYTES`, the room carved for them with its buffers
/// (`ingest::BUFFERS_PER_CONNECTION`). A reply holds its bytes until it is written or let go
/// ([`Reply`]), so the bound holds whatever the write side waits on.
#[derive(Default)]
struct ReplyRoom {
    waiting: std::sync::atomic::AtomicUsize,
}

impl ReplyRoom {
    /// The answers to one record that fit the room now, in order, holding their bytes; the rest
    /// are dropped. `None` when none fit.
    fn offer(self: &Arc<Self>, answers: Vec<Record>) -> Option<Reply> {
        use std::sync::atomic::Ordering;
        let mut bytes = 0;
        let mut records = Vec::with_capacity(answers.len());
        for record in answers {
            // What it allocates of its own and its slot in the reply, made exactly as long below.
            let len = record.allocated() + crate::footprint::vec::<Record>(1);
            let taken = self
                .waiting
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |waiting| {
                    let after = waiting.checked_add(len)?;
                    (after <= crate::ingest::REPLIES_BYTES).then_some(after)
                })
                .is_ok();
            if !taken {
                break;
            }
            bytes += len;
            records.push(record);
        }
        records.shrink_to_fit();
        let reply = Reply {
            records,
            bytes,
            room: Arc::clone(self),
        };
        (!reply.records.is_empty()).then_some(reply)
    }

    /// Bytes of replies waiting now.
    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.waiting.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// The network duties' answers to one record, each one the peer takes, waiting for the write side
/// with their bytes held in the connection's [`ReplyRoom`] until they are written or let go.
struct Reply {
    records: Vec<Record>,
    bytes: usize,
    room: Arc<ReplyRoom>,
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.room
            .waiting
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

/// A connection's replies from the network duties, from the read side ([`Replying`]) to the write
/// side, within its [`ReplyRoom`].
struct Replies {
    replying: Replying,
    waiting: mpsc::Receiver<Reply>,
}

impl Replies {
    fn new(peer: Peer, link: &Arc<Link>) -> Self {
        let (sender, waiting) = mpsc::channel::<Reply>(REPLIES_WAITING);
        Self {
            replying: Replying {
                sender,
                room: Arc::default(),
                peer,
                link: Arc::clone(link),
            },
            waiting,
        }
    }
}

/// What the write side is to end on: a last word between whole messages (`Closing::Saying`, or
/// `Closing::Turning` for a member refused at its admission), and why the link ends.
type Farewell = Closing;

/// How the write side ended: on a failure, with nothing more to say, or between whole messages with
/// a last word for the peer, which `exchange` says through `farewell` once both directions are its
/// again.
enum Closing {
    Silent(String),
    Saying {
        last: Box<ClientRecord>,
        why: String,
    },
    /// As `Saying`, a member refused at its admission (`End::Full`): a relay that dialled in is
    /// noted as routing around this one (`turning_away`) as it is said. Nothing else is: a link
    /// the upload cap sheds ends `Saying`.
    Turning(capacity::AtAdmission),
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
        column,
        greeting,
        fan_out,
        subscribe,
        described,
        refusal,
        admitted,
        ceiling,
        paces,
        asker,
        outgoing,
        replies: Replies {
            replying,
            waiting: mut replies,
        },
        leaving: _leaving,
    } = serving;
    // A relay that dialled this one and is told it is full routes its slice past it
    // (`turning_away`); one this relay dialled is only ever sent to, and routes nothing.
    let dialled_in = outgoing.is_none();
    let turned_away = |refused: &capacity::AtAdmission| {
        if dialled_in {
            turning_away(hub, peer, &asker.key, refused);
        }
    };
    let (telling, mut farewells) = mpsc::channel::<Farewell>(1);
    let refusal = refusal.unwrap_or_default();
    let drift = Arc::clone(&refusal);
    let reading = async {
        let reading = Reading {
            subscribe,
            asker,
            replies: replying,
            refusal,
            admitted,
        };
        match read_loop(
            reader,
            hub,
            source,
            peer,
            reading,
            described,
            (ceiling, paces),
        )
        .await
        {
            Ok(()) => Ok(None),
            Err(End::Closed(why)) => Err(why),
            Err(End::Departed(away)) => Ok(Some(away)),
            Err(End::Told {
                reason,
                retry_after_secs,
                why,
            }) => {
                let last = Box::new(goodbye(reason, retry_after_secs));
                // Said by the write side (`Closing::Saying`, below).
                let _ = telling
                    .send(Closing::Saying {
                        last,
                        why: why.clone(),
                    })
                    .await;
                // The write side stops for the goodbye between messages; this only bounds a write
                // side stuck on a peer that does not read, which is then closed on with no word.
                tokio::time::sleep(FAREWELL_TIMEOUT).await;
                Err(why)
            }
            Err(End::Full(refused)) => {
                let why = refused.why().to_owned();
                // Said by the write side (`Closing::Turning`, below), which notes the refusal as
                // full (`turning_away`) as it says it.
                let _ = telling.send(Closing::Turning(refused)).await;
                tokio::time::sleep(FAREWELL_TIMEOUT).await;
                Err(why)
            }
        }
    };
    let inputs = Inputs {
        farewells: &mut farewells,
        replies: &mut replies,
        outgoing,
        client: (asker.role == AskerRole::Client && !asker.loopback).then_some(asker),
        steer: subscribe,
        vouched: (asker.role == AskerRole::Client && hub.network().credit.vouches_for(&asker.key))
            .then_some(asker),
        drift,
    };
    // The write side typed by the link's column (`outbound`): a client's holds and sends
    // `ClientRecord`s alone.
    let writing = async {
        match column {
            Column::Sites => {
                write_loop::<S, Arc<Record>>(
                    Typed::new(&mut *writer),
                    hub,
                    source,
                    link,
                    greeting,
                    fan_out,
                    inputs,
                )
                .await
            }
            Column::Client => {
                write_loop::<S, Arc<ClientRecord>>(
                    Typed::new(&mut *writer),
                    hub,
                    source,
                    link,
                    greeting,
                    fan_out,
                    inputs,
                )
                .await
            }
        }
    };
    let closing = tokio::select! {
        result = reading => return result,
        result = writing => result,
    };
    match closing {
        Ok(()) => Ok(None),
        Err(Closing::Silent(why)) => Err(why),
        Err(Closing::Saying { last, why }) => {
            farewell(reader, writer, *last).await;
            Err(why)
        }
        Err(Closing::Turning(refused)) => {
            turned_away(&refused);
            farewell(reader, writer, refused.last()).await;
            Err(refused.into_why())
        }
    }
}

/// What the read side needs beside the peer: where its `Subscribe`s go, who it is to the network
/// duties, and where their replies go.
struct Reading<'a> {
    subscribe: Option<&'a watch::Sender<Subscription>>,
    asker: Asker,
    replies: Replying,
    /// Where the ingest stage says a batch's signature failed.
    refusal: Arc<Refusal>,
    admitted: Admitted,
}

/// Where the read side hands the network duties' replies to the write side: each record's answers
/// as soon as it is handled, only those the peer takes (`Peer::takes_reply`), within the
/// connection's [`ReplyRoom`].
struct Replying {
    sender: mpsc::Sender<Reply>,
    room: Arc<ReplyRoom>,
    peer: Peer,
    link: Arc<Link>,
}

impl Replying {
    /// The answers to one record, handed on now: those the peer takes, as many as the room holds.
    /// A full queue or room drops them: the peer asked faster than it reads.
    fn hand_on(&self, hub: &Hub, key: &PublicKey, mut answers: Vec<Record>) {
        if answers.is_empty() {
            return;
        }
        let (peer, kind) = (self.peer.now(hub, key), self.link.kind());
        answers.retain(|record| peer.takes_reply(record, kind));
        if let Some(reply) = self.room.offer(answers) {
            let _ = self.sender.try_send(reply);
        }
    }
}

/// What a connection that publishes batches was admitted with (RFC-0181 §2, §9): its allowance
/// in the ingest stage (a count of records, each charged to the one ingest pool, `Store::Ingest`),
/// and a member session's place among those planned and the pace the members share. A connection that
/// publishes none has neither, and a batch from it never reaches the stage (`Peer::permit`).
#[derive(Default)]
struct Admitted {
    allowance: Option<Allowance>,
    /// A member's place: its reservation from the members' pool and its part of the products'
    /// records, held as one (`network::Membership`).
    membership: Option<crate::network::Membership>,
    /// The members' shared rate (`ingest::MemberPace`), in bytes and in receptions, of which this
    /// session is held to an even share: what a member session's data waits for.
    pace: Option<crate::ingest::MemberSession>,
    /// Whether this session is admitted as a member once its peer is one (`admit_member`): a
    /// session over which another relay's data may come in (one that relay dialled, or this
    /// relay's own one-hop raw link). A session this relay dialled to send a member what is
    /// addressed to it, or to an upstream for the directory, carries none in, and never is.
    joins: bool,
    /// Its place under the connection cap (`hub::Connection::general`, `Hub::dialled`), held
    /// until it holds a member's (`admit_member`, which replaces this admission whole).
    _general: Option<crate::hub::Slot>,
    /// The session's socket buffers, a feeder's until it is admitted as a member, then a
    /// member's (`sockets`); `None` for a session that never may be one.
    tuner: Option<crate::sockets::Tuner>,
}

impl Admitted {
    /// `record`'s charge (`in_flight`), a relay's session admitted as a member first
    /// (`admit_member`) when its offer is verified and this is the first data it brings in, for
    /// as long as it is one: a session that only speaks the directory holds no member's place.
    async fn charge(
        &mut self,
        hub: &Hub,
        (peer, key, source): (Peer, &PublicKey, u64),
        record: &Record,
    ) -> Result<Option<InFlight>, End> {
        // Any data a member brings in admits it, whatever comes first (positions or clock models
        // before any batch included): only what a directory link carries does not.
        if self.joins
            && self.membership.is_none()
            && !crate::subscription::on_directory_link(record)
            && matches!(peer.now(hub, key), Peer::Member)
        {
            let tuner = self.tuner;
            *self = admit_member(hub, source)?;
            self.tuner = tuner;
            if let Some(tuner) = tuner {
                tuner.set(crate::sockets::Role::Member);
            }
        }
        Ok(self.in_flight(record).await)
    }

    /// A batch's charge from the allowance (`ingest::charge_of`), or a receiver description's
    /// (its bytes: it passes the ingest stage too, `Hub::describe`), waiting while the connection
    /// holds all of it; `None` for any other record, or a connection with no allowance.
    async fn in_flight(&self, record: &Record) -> Option<InFlight> {
        let bytes = match record {
            Record::Batch(batch) => crate::ingest::charge_of(batch),
            Record::ReceiverInfo(info) => crate::ingest::floored(info.as_bytes().len()),
            Record::ReceiverSite(site) => crate::ingest::floored(site.as_bytes().len()),
            _ => return None,
        };
        let allowance = self.allowance.as_ref()?;
        // A member's waits first for the members' shared rate: together they bring in what was
        // planned for them, no more (`budget::Plan::with_members`), in the bytes the stores are
        // planned in (`ingest::rate_cost`), whatever its batches inflate or pad to.
        if let Some(pace) = &self.pace {
            let (charged, receptions) = match record {
                Record::Batch(batch) => (
                    crate::ingest::rate_cost(batch),
                    batch.receptions().unwrap_or(0),
                ),
                Record::ReceiverInfo(info) => (info.as_bytes().len(), 0),
                Record::ReceiverSite(site) => (site.as_bytes().len(), 0),
                _ => (bytes, 0),
            };
            pace.take(
                u64::try_from(charged).unwrap_or(u64::MAX),
                u64::try_from(receptions).unwrap_or(u64::MAX),
            )
            .await;
        }
        Some(allowance.acquire(bytes).await)
    }
}

/// A member session's admission: one of the member sessions the relay's plan admits
/// (`budget::members_for`), its ingest allowance, and the members' shared pace. Past them it is turned away, counted, with
/// `Reason::Full` (RFC-0174 §2.5, "A relay's members are bounded"): the relay that dialled routes
/// around this one, to the next members of its trees, for the wait it is given.
fn admit_member(hub: &Hub, source: u64) -> Result<Admitted, End> {
    let budget = hub.budget();
    let refused = |why: String| {
        hub.member_refused();
        End::Full(capacity::AtAdmission::member_refused(
            MEMBERS_FULL_RETRY_SECS,
            why,
        ))
    };
    let membership = budget.reserve_member().ok_or_else(|| {
        refused(format!(
            "turned away: no spare member slot (the relay holds {} member sessions)",
            budget.members()
        ))
    })?;
    let allowance = hub.allowance(
        crate::ingest::RECORDS_IN_FLIGHT,
        crate::ingest::member_source(source),
    );
    Ok(Admitted {
        allowance: Some(allowance),
        membership: Some(hub.network().admit_member(source, membership)),
        pace: Some(hub.member_pace().session()),
        joins: true,
        _general: None,
        tuner: None,
    })
}

/// What a connection's records wait for, each role at what it legitimately
/// sends (`ingest`'s `RolePace`s, each with its reason), and what the cores plan for every session
/// (`cores::Sessions`): a feeder's own, at its byte ceiling over `ingest::RECORD_BYTES`; a
/// subscriber's, an engine's and a probe's own, at their role's pace, each starting with what its
/// network group is granted of its burst (`ingest::BurstGrants`); every member
/// session's one pace, the members' records a second (`Hub::member_records`); and a directory
/// link's, its network group's share of the directory's rate (`Hub::directory_records`), kept across that group's links, whoever dialled. A relay that dialled in is a
/// directory link until its offer makes it a member (`Peer::now`), so each record waits for the
/// pace of what its sender is when it is read. A feeder's receptions are never waited for here:
/// it is told its wanted receptions a second (`RateLimit`) and the relay drops a batch past them
/// (`ingest::ReceptionCeilings`), so its socket is read at its records' and bytes' pace alone.
struct Paces {
    /// The role's own pace, for a connection that dialled in as a feeder, subscriber, engine or
    /// probe; none for a relay's, whose paces are shared.
    own: Option<Arc<RecordPace>>,
    /// What its own pace allocates (`ingest::OWN_PACE_BYTES`), and a feeder's entry in the station
    /// connections (`stations::CONNECTION_BYTES`), charged to `Store::Paces` for the session, from
    /// the room the plan holds for what every connection holds of its own
    /// (`ingest::OWN_BYTES_PER_CONNECTION`).
    _charge: crate::budget::Charge,
    /// The network group of the session's address: what its directory share is kept by.
    group: Option<crate::ingest::Group>,
    /// Its place in its group's directory share, taken the first time it sends as a directory
    /// link and held for the session.
    directory: std::sync::OnceLock<Option<crate::ingest::DirectoryLink>>,
}

impl Paces {
    /// Its paces, or why it has none: the paces' store has no room for its own (it holds every
    /// connection's the caps allow, so only a relay past its caps meets this).
    fn of(hub: &Hub, peer: Peer, address: Option<std::net::IpAddr>) -> Result<Self, String> {
        let group = crate::ingest::group_of(address);
        let grants = hub.burst_grants();
        let own = match peer {
            Peer::Feeder(_) => {
                let rate = hub.feeder_records_per_sec();
                Some(
                    crate::ingest::RolePace {
                        per_minute: rate.saturating_mul(60),
                        burst: rate,
                    }
                    .session(grants, group),
                )
            }
            Peer::Subscriber => Some(crate::ingest::SUBSCRIBER_RECORDS.session(grants, group)),
            Peer::Engine(_) => Some(crate::ingest::ENGINE_RECORDS.session(grants, group)),
            Peer::Probe => Some(crate::ingest::PROBE_RECORDS.session(grants, group)),
            Peer::Relay | Peer::Member => None,
        };
        // A feeder's station connection entry (`Feeding`) lives within its session, as this does.
        let station = match peer {
            Peer::Feeder(_) => crate::stations::CONNECTION_BYTES,
            _ => 0,
        };
        let charge = match own {
            Some(_) => hub
                .budget()
                .gauge(crate::budget::Store::Paces)
                .try_charge(crate::ingest::OWN_PACE_BYTES + station)
                .ok_or("the relay holds no room for this connection's pace")?,
            None => crate::budget::Charge::none(),
        };
        Ok(Self {
            own: own.map(Arc::new),
            _charge: charge,
            group,
            directory: std::sync::OnceLock::new(),
        })
    }

    /// A session with another relay this relay dialled, at `address`: the shared paces only.
    fn shared(address: Option<std::net::IpAddr>) -> Self {
        Self {
            own: None,
            _charge: crate::budget::Charge::none(),
            group: crate::ingest::group_of(address),
            directory: std::sync::OnceLock::new(),
        }
    }

    /// Waits for `record`'s place: the pace of what its sender is now. The pace it was taken by,
    /// for the work it brings beyond its token to be owed to.
    async fn take(&self, hub: &Hub, peer: Peer, key: &PublicKey) -> Option<Arc<RecordPace>> {
        let pace = match peer.now(hub, key) {
            Peer::Member => Some(hub.member_records()),
            Peer::Relay => self
                .directory
                .get_or_init(|| hub.directory_records().join(self.group))
                .as_ref()
                .map(crate::ingest::DirectoryLink::pace),
            Peer::Feeder(_) | Peer::Subscriber | Peer::Engine(_) | Peer::Probe => self.own.clone(),
        };
        if let Some(pace) = &pace {
            pace.take().await;
        }
        pace
    }
}

async fn read_loop<S: AsyncRead>(
    reader: &mut Reader<S>,
    hub: &Arc<Hub>,
    source: u64,
    peer: Peer,
    reading: Reading<'_>,
    mut described: Option<Described>,
    (mut ceiling, paces): (Option<Ceiling>, Paces),
) -> Result<(), End> {
    let Reading {
        subscribe,
        asker,
        replies,
        refusal,
        mut admitted,
    } = reading;
    loop {
        // A batch the ingest stage refused (its signature) ends the session at once, whatever
        // is being read: the session is over, so a read cut short loses nothing. The message read
        // is the session's buffers' (carved for as long as it is open: `inbound`,
        // `upstream_once`, `member_once`), and its records are decoded one at a time as each is
        // handed on (`noise::Message`), never all of them at once.
        let mut message = tokio::select! {
            read = tokio::time::timeout(READ_TIMEOUT, reader.recv_message()) => {
                read.map_err(|_| "silent too long".to_owned())?
                    .map_err(|error| error.to_string())?
            }
            refused = refusal.refused() => return Err(refused_end(refused)),
        };
        // The raw monotonic clock as the message came off the socket, before its records are
        // paced or charged: what this relay's own anchor in a batch it carries is aged by
        // (`Inbound::arrived`), so this relay's own pacing of a backlog never ages it.
        let arrived = hub.clock().raw();
        if ceiling.as_mut().is_some_and(|ceiling| !ceiling.within()) {
            return Err(over_ceiling());
        }
        while let Some(record) = message.next().map_err(|error| error.to_string())? {
            // Its place in the connection's records a second: past it, the socket is not
            // read until the pace allows it.
            let pace = paces.take(hub, peer, &asker.key).await;
            // Its charge from the connection's allowance before it is handed over: with the
            // allowance held, the socket is not read, and TCP holds the sender back (RFC-0181 §2).
            let in_flight = admitted
                .charge(hub, (peer, &asker.key, source), &record)
                .await?;
            if let Some(refused) = refusal.now() {
                return Err(refused_end(refused));
            }
            ingest(
                record,
                hub,
                source,
                (peer, &asker),
                subscribe,
                &mut described,
                (in_flight, &refusal, arrived),
            )
            .or_else(|unhandled| network(unhandled, (hub, &asker, pace.as_deref()), &replies))?;
        }
    }
}

/// How a connection that sent more than its ingest ceiling ends: told so (`Reason::OverCeiling`),
/// never that this relay is full, so it is never excused its shortfalls (`End::Full`).
fn over_ceiling() -> End {
    End::Told {
        reason: Reason::OverCeiling,
        retry_after_secs: OVER_CEILING_RETRY_SECS,
        why: "sent more than its ingest ceiling".to_owned(),
    }
}

/// What `ingest` hands on: a record that is a network duty's, or the end of the link.
enum Unhandled {
    Network(Record),
    /// An answer of the link's own, sent back as a network duty's reply is.
    Answer(Record),
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
/// handed to the write side at once (`Replying::hand_on`), never gathered across a message whose
/// records are paced.
/// The work a record brings beyond its one token (each signature inside an evidence bundle) is
/// owed to the pace it was taken by (`pace`), and paid before the connection's next record.
fn network(
    unhandled: Unhandled,
    (hub, asker, pace): (&Hub, &Asker, Option<&RecordPace>),
    replies: &Replying,
) -> Result<(), End> {
    match unhandled {
        Unhandled::End(end) => Err(end),
        Unhandled::Answer(record) => {
            replies.hand_on(hub, &asker.key, vec![record]);
            Ok(())
        }
        Unhandled::Network(record) => {
            let answers = hub
                .network()
                .handle(hub, asker, record, hub.stamp_now(), pace);
            replies.hand_on(hub, &asker.key, answers);
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
    (in_flight, refusal, arrived): (Option<InFlight>, &Arc<Refusal>, Raw),
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
                Peer::Feeder(_) => Origin::Feeder(
                    described.clone(),
                    crate::ingest::group_of(asker.address),
                    asker.address,
                ),
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
                arrived: Some(arrived),
                in_flight,
                refusal: Some(Arc::clone(refusal)),
            });
        }
        Record::ReceiverInfo(info) => {
            let receiver = info.receiver().map_err(|error| error.to_string())?;
            info.verify().map_err(|error| error.to_string())?;
            // A format this build cannot read still forwards; it just never replaces a known one,
            // and places its receiver nowhere. A format 1 description carries its site (`place`);
            // a format 2 one is paired with its `ReceiverSite` (`Hub::keep_site`).
            let issued_ms = info.issued_ms().unwrap_or(0);
            let place = info.content().ok().and_then(|content| content.location);
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
                    site: described.as_ref().and_then(|own| own.site.clone()),
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
        Record::ReceiverSite(site) => {
            let receiver = site.receiver().map_err(|error| error.to_string())?;
            site.verify().map_err(|error| error.to_string())?;
            // A feeder's own is kept on its link beside its description, given again with it.
            if matches!(peer, Peer::Feeder(_))
                && let Some(own) = described.as_ref()
            {
                *described = Some(Arc::new(OwnDescription {
                    site: Some(site.clone()),
                    ..OwnDescription::clone(own)
                }));
            }
            // Charged like a description, and for the same reason.
            let Some(in_flight) = in_flight else {
                return Err(End::Told {
                    reason: Reason::Protocol,
                    retry_after_secs: REFUSED_RETRY_SECS,
                    why: "sent a site on a connection admitted to publish none".to_owned(),
                }
                .into());
            };
            hub.keep_site(source, site, receiver, None, in_flight);
        }
        // A piece of a group's data: taken in by the one intake each kind has (`Hub::take_piece`,
        // which a piece this relay rebuilt from parity takes too), shared as its sender's role says.
        record @ (Record::Positions(_)
        | Record::Provisional(_)
        | Record::ClockModel(_)
        | Record::ClientClockModel(_)
        | Record::FaultProof(_)) => {
            hub.take_piece(
                source,
                crate::strikes::Deliverer::Peer(asker.key),
                record,
                |record| share(hub, peer, asker, record),
                || {},
            )?;
        }
        Record::ClockModelPart(part) => {
            hub.network().hold_part(&part);
            hub.publish_clock_model_part(source, part);
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
                let allowed = peer.grant(hub, asker, Subscription { streams, regions }, hub.now());
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
        // A heartbeat that asks for this relay's clock (NTP's on-wire exchange, RFC 5905 §8):
        // answered at once with its send time echoed, when it was taken, and this relay's error
        // bound; its own send time is written as it is sent (`reply`).
        Record::TimedHeartbeat(times) if times.echo.is_none() => {
            let answer = tally_wire::HeartbeatTimes {
                sent_ms: 0,
                echo: Some((times.sent_ms, hub.now().ms())),
                error_ms: Some(hub.clock().error_ms().unwrap_or(u64::MAX)),
            };
            return Err(Unhandled::Answer(Record::TimedHeartbeat(answer)));
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
        | Record::ClientRegionalBatch(_)
        | Record::Parity(_)
        | Record::BundleIndex(_)
        | Record::MlatCut(_)) => return Err(Unhandled::Network(record)),
        // Another relay's deduplicated stream and feeder figures are its own claims; this relay
        // derives and signs its own.
        _ => {}
    }
    Ok(())
}

/// Hands a record of data the network duties' sharing: a member's is a piece of its group,
/// passed on down this relay's stripes; a fault proof anyone else brought this relay first-hand
/// is seeded into its group by this relay, its origin.
fn share(hub: &Hub, peer: Peer, asker: &Asker, record: &Record) {
    let network = hub.network();
    let now = hub.stamp_now();
    match peer {
        Peer::Member => network.from_peer(hub, asker, record, now),
        Peer::Engine(_) | Peer::Feeder(_) | Peer::Subscriber => {
            network.originate(hub, record, now);
        }
        Peer::Relay | Peer::Probe => {}
    }
}

/// What the write side is handed beside the fan-out: when to say goodbye, the network duties'
/// replies, what is addressed to the peer (a member link's `outgoing`), and, for a billed client,
/// who it is, so what it is sent keeps to its allowance (`credit`).
struct Inputs<'a> {
    farewells: &'a mut mpsc::Receiver<Farewell>,
    replies: &'a mut mpsc::Receiver<Reply>,
    outgoing: Option<&'a mut mpsc::Receiver<Queued>>,
    client: Option<Asker>,
    /// A client's subscription, which the write side re-admits as its credit changes.
    steer: Option<&'a watch::Sender<Subscription>>,
    /// A client this relay vouches for: signed a credential and this relay's evidence when its
    /// session starts and again before the credential lapses (`credit::RENEW_BEFORE_MS`).
    vouched: Option<Asker>,
    /// Whether a feeder's clock drifted from this relay's (`ingest::Refusal::drifted`): its
    /// `RateLimit` is said again at the next heartbeat, the relay's clock stated anew.
    drift: Arc<Refusal>,
}

/// How often a client's subscription is admitted again, so a credential that expires mid-session
/// (or credit that grows) takes effect without the client asking.
const READMIT_EVERY: Duration = Duration::from_secs(10);

/// The next send addressed to the peer, or never. Its charges (`peers::Queued`) are held until
/// its records are written.
async fn addressed(outgoing: &mut Option<&mut mpsc::Receiver<Queued>>) -> Option<Queued> {
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
    credit.allowance(&client.key, hub.now()).bytes_per_sec
}

// The write side's every input, each its own: what to say first, what to forward, what to answer
// and when to say goodbye.
async fn write_loop<S: AsyncWrite, P: Sendable>(
    mut writer: Typed<'_, S, P>,
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
        vouched,
        drift,
    } = inputs;
    // A feeder's rate limit, said again with this relay's clock as it now reads whenever the
    // feeder's clock drifted (`drift`): so a feeder signing by the clock it was told corrects it
    // over a long session instead of drifting until it is refused. Only then, so a feeder that
    // predates the stated clock (and restarts its pacing at each `RateLimit`) hears it again only
    // while its own clock is off.
    let restate = greeting.iter().find_map(|record| match record {
        Record::RateLimit {
            bytes_per_sec,
            burst,
            wanted_per_sec,
            ..
        } => Some((*bytes_per_sec, *burst, *wanted_per_sec)),
        _ => None,
    });
    let mut readmit = tokio::time::interval(READMIT_EVERY);
    let mut revouch = tokio::time::interval(Duration::from_millis(
        crate::credit::CREDENTIAL_LIFETIME_MS - crate::credit::RENEW_BEFORE_MS,
    ));
    let mut pace = client.map(|client| ClientPace::new(client, hub));
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    // A feeder (the one link greeted with its rate limit) is sent this relay's newest freshness
    // anchor each period (`Hub::anchor`, RFC-0171 §3.6), so the feeder always has one heard within
    // the `2P` it may sign by one (`tally_wire::budget::ANCHOR_HELD`, in `tally_wire::budget::ANCHOR_BEHIND`).
    let anchors = restate.is_some();
    let mut anchor_tick = tokio::time::interval(Duration::from_millis(
        tally_wire::budget::ANCHOR_PERIOD
            .span::<tally_wire::clocks::Judged>()
            .ms(),
    ));
    anchor_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Its first tick is now, and the greeting carried the anchor of now.
    anchor_tick.reset();
    // The steps of the relay's judging clock seen when the clock was last stated: a step since is
    // said to the feeder at the next heartbeat, with the clock as it now reads (nothing ends).
    let mut steps = hub.clock().steps();
    let mut told = Told::new();
    let writer = &mut writer;
    writer
        .send_records(greeting)
        .await
        .map_err(|error| error.to_string())?;
    // The answers to what came with its `Hello`, before anything of the streams.
    while let Ok(answers) = replies.try_recv() {
        reply(writer, hub, link, answers).await?;
    }
    let Some(FanOut { infos, mut wants }) = fan_out else {
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    let mut records = vec![Record::Heartbeat];
                    let stepped = hub.clock().steps() != steps;
                    if let Some((bytes_per_sec, burst, wanted_per_sec)) = restate
                        && (drift.take_drift() || stepped)
                    {
                        steps = hub.clock().steps();
                        let (clock_ms, error_ms) = stated_clock(hub);
                        records.push(Record::RateLimit {
                            bytes_per_sec,
                            burst,
                            wanted_per_sec,
                            clock_ms: Some(clock_ms),
                            error_ms: Some(error_ms),
                        });
                    }
                    writer
                        .send_records(records)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                _ = anchor_tick.tick(), if anchors => {
                    if let Some(anchor) = hub.anchor() {
                        writer
                            .send_records([Record::Anchor(anchor)])
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                }
                Some(closing) = farewells.recv() => return Err(closing),
                () = hub.leaving() => return Err(leaving()),
                Some(answers) = replies.recv() => {
                    reply(writer, hub, link, answers).await?;
                }
                _ = revouch.tick(), if vouched.is_some() => {
                    vouch(writer, hub, vouched.as_ref()).await?;
                }
                // What is addressed to a member: a stripe slice, a manifest, a receipt.
                Some(addressed) = addressed(&mut outgoing) => {
                    let (records, written) = addressed.into_parts();
                    let records = typed::<P>(told.before_batches(hub, records));
                    send_data(writer, hub, link, Class::Forwarded, &records).await?;
                    drop(written);
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
    let infos: Vec<P> = if directory {
        typed::<P>(live_offers(hub))
    } else {
        infos.iter().filter_map(P::of_item).collect()
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
                pending.send(writer, (hub, link), pace.as_mut(), &out).await?;
            }
            _ = readmit.tick(), if client.is_some() && steer.is_some() => {
                if let (Some(client), Some(steer)) = (client.as_ref(), steer)
                    && let Some(admitted) = hub
                        .network()
                        .credit
                        .readmit(client, hub.now())
                {
                    steer.send_replace(admitted);
                }
            }
            Some(addressed) = addressed(&mut outgoing) => {
                let (records, written) = addressed.into_parts();
                let records = typed::<P>(told.before_batches(hub, records));
                send_data(writer, hub, link, Class::Forwarded, &records).await?;
                drop(written);
            }
            subscription = wants.changed() => {
                // Describe the receivers the new subscription covers before any of their batches:
                // in parts, keeping up with the fan-out between them under the subscription still
                // in effect, so a large directory never leaves the link fallen behind. A
                // description that changes meanwhile and only the new subscription covers reaches
                // it at its receiver's next description, as on joining (`Hub::subscribe`).
                let infos: Vec<P> = wants
                    .infos(hub, &subscription)
                    .iter()
                    .filter_map(P::of_item)
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
            Some(closing) = farewells.recv() => return Err(closing),
            () = hub.leaving() => return Err(leaving()),
            Some(answers) = replies.recv() => {
                reply(writer, hub, link, answers).await?;
            }
            _ = revouch.tick(), if vouched.is_some() => {
                vouch(writer, hub, vouched.as_ref()).await?;
                // Linked by its own credential here now: admitted again at once, not at the next
                // `READMIT_EVERY`.
                if let (Some(client), Some(steer)) = (vouched.as_ref(), steer)
                    && let Some(admitted) = hub
                        .network()
                        .credit
                        .readmit(client, hub.now())
                {
                    steer.send_replace(admitted);
                }
            }
            () = link.shed() => return shed(hub),
            _ = heartbeat.tick() => {
                writer
                    .send_records([Record::Heartbeat])
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
                Record::Positions(positions) | Record::Provisional(positions) => {
                    crate::network::solved(positions)
                        .map(|solved| solved.into_iter().map(|one| one.clock_model).collect())
                        .unwrap_or_default()
                }
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
                && let Some((described, issued_ms)) = hub.description_of(&receiver)
                && self
                    .sent
                    .get(&receiver)
                    .is_none_or(|sent| *sent < issued_ms)
            {
                if self.sent.len() >= DESCRIBED_REMEMBERED {
                    self.sent.clear();
                }
                self.sent.insert(receiver, issued_ms);
                // Its description and its site: the link's column keeps the site off a member
                // that does not carry sites (`outbound`).
                out.extend(described);
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

/// Sends the network duties' replies to the peer (only those it takes, `Replying::hand_on`): what
/// is control to it at once, as an echo's reply must be; the rest (offers to a directory link) by
/// class through the upload cap (`send_data`). Their bytes stay held in the connection's
/// [`ReplyRoom`] until they are written.
async fn reply<S: AsyncWrite, P: Sendable>(
    writer: &mut Typed<'_, S, P>,
    hub: &Hub,
    link: &Arc<Link>,
    mut answers: Reply,
) -> Result<(), Closing> {
    let kind = link.kind();
    let mut control = Vec::new();
    let mut by_class: [Vec<P>; Class::ALL.len()] = Default::default();
    for record in typed::<P>(
        std::mem::take(&mut answers.records)
            .into_iter()
            .map(|record| match record {
                // A heartbeat's answer carries the moment it is written (NTP's `T3`).
                Record::TimedHeartbeat(mut times) if times.echo.is_some() => {
                    times.sent_ms = hub.now().ms();
                    Record::TimedHeartbeat(times)
                }
                record => record,
            })
            .map(Arc::new)
            .collect(),
    ) {
        match Class::of_kind(record.kind(), kind) {
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
async fn vouch<S: AsyncWrite, P: Sendable>(
    writer: &mut Typed<'_, S, P>,
    hub: &Hub,
    client: Option<&Asker>,
) -> Result<(), Closing> {
    let network = hub.network();
    let Some(client) = client else {
        return Ok(());
    };
    let at = hub.judged_now();
    let Some((credential, evidence)) = network.with_signing(at, |signing| {
        signing.and_then(|identity| network.credit.vouch(identity, client, at.judged()))
    }) else {
        return Ok(());
    };
    writer
        .send_records([
            Record::FirehoseCredential(credential),
            Record::EvidenceBundle(evidence),
        ])
        .await
        .map_err(|error| Closing::Silent(error.to_string()))
}

/// What a link's column carries of `records`, in order; the rest is withheld (`outbound`).
fn typed<P: Sendable>(records: Vec<Arc<Record>>) -> Vec<P> {
    records.into_iter().filter_map(P::of_record).collect()
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
async fn send_data<S: AsyncWrite, P: Sendable>(
    writer: &mut Typed<'_, S, P>,
    hub: &Hub,
    link: &Arc<Link>,
    class: Class,
    records: &[P],
) -> Result<(), Closing> {
    if records.is_empty() {
        return Ok(());
    }
    match hub.egress().grant(link, class, wire_cost(records)).await {
        Ok(()) => writer
            .send(records)
            .await
            .map_err(|error| Closing::Silent(error.to_string())),
        Err(Shed) => shed(hub),
    }
}

/// Ends a link the upload cap shed: it is told the relay is full, pointed at the relays this one
/// knows. It is never excused its shortfalls (`turning_away`): the cap sheds the peer asking
/// the most of its class, which a peer chooses (one flooding `ProviderQuery`s is it), so a shed
/// excused would be a way to deliver nothing and never be filed short.
fn shed(hub: &Hub) -> Result<(), Closing> {
    Err(Closing::Saying {
        last: Box::new(full(hub)),
        why: "shed: the upload cap cannot carry it".to_owned(),
    })
}

/// Sends everything waiting on the fan-out that `wants` takes, until none is waiting. False when
/// the link has already fallen behind.
async fn catch_up<S: AsyncWrite, P: Sendable>(
    writer: &mut Typed<'_, S, P>,
    hub: &Hub,
    link: &Arc<Link>,
    out: &Listener,
    pending: &mut Pending<P>,
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
        pending.send(writer, (hub, link), None, out).await?;
        if drained {
            return Ok(true);
        }
    }
}

/// `records` in consecutive parts of about `DUMP_BYTES` each, every part at least one record.
fn parts<P: Sendable>(records: &[P]) -> Vec<&[P]> {
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
/// class, classified once as it is kept, each in its link's column's type (`outbound`).
struct Pending<P> {
    kind: Kind,
    /// By class, highest first; order within a class is the fan-out's.
    by_class: [Vec<P>; Class::ALL.len()],
    /// What the link holds of the fan-out's items gathered (`fanout::Hold`: their charges to
    /// `budget::Store::Fanout`, and their bytes in its subscriber's hand), held until they are
    /// sent: what waits on a slow socket here is still charged, and ranks the link.
    holds: Vec<crate::fanout::Hold>,
    /// When the first of them was taken: they are sent within `fanout::BEHIND_MS` of it, or the
    /// link has fallen behind.
    since: Option<Instant>,
    records: usize,
    bytes: usize,
}

/// How long items taken from the fan-out may wait on a subscriber's link (for its client's pace,
/// for the upload cap's grant, for the peer to read them) before it has fallen behind: what a queue
/// may hold of inbound (`fanout::BEHIND_MS`), so what a stalled socket holds in hand is held no
/// longer than what it could have queued. A link the fan-out resynchronises instead of letting go
/// (a directory link, `fanout::Fell::Resync`) is not held to it: what it is sent is held whole
/// elsewhere and sent again, so a slow peer there is no reason to end it, and its send keeps the
/// writer's own deadline (`noise::WRITE_TIMEOUT`). Before, every link was held to it, so a slow
/// peer's directory or member session ended two seconds into a slow send, as fallen behind, and a
/// sharing member was dropped with it.
const IN_HAND_MS: Duration = Duration::from_millis(crate::fanout::BEHIND_MS);

impl<P: Sendable> Pending<P> {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            by_class: Default::default(),
            holds: Vec::new(),
            since: None,
            records: 0,
            bytes: 0,
        }
    }

    /// Never send a record back down the connection it came in on, nor one the link did not ask
    /// for.
    /// Only what the link's column carries of it (`Sendable::of_item`), the rest withheld.
    fn keep(&mut self, taken: Taken, source: u64, wants: &Wants) {
        if taken.source != source
            && wants.wants(&taken)
            && let Some(record) = P::of_item(&taken)
        {
            let class = Class::of_kind(record.kind(), self.kind);
            self.bytes += record.encoded_len();
            self.records += 1;
            self.by_class[class as usize].push(record);
            self.holds.push(taken.hold());
            self.since.get_or_insert_with(Instant::now);
        }
    }

    fn full(&self) -> bool {
        self.records >= SEND_BATCH || self.bytes >= SEND_BYTES
    }

    /// Sends what is gathered, its client's pace first (`pace`), each class once granted, highest
    /// first, and empties it: within `IN_HAND_MS` of taking the first unless the fan-out
    /// resynchronises the link (`fanout::Listener::resyncs`), and only while the fan-out has not let
    /// the link go (`out`, `fanout::Listener::fallen`). Past either the link has fallen behind:
    /// told so if nothing of a message is written, else closed on mid-message.
    async fn send<S: AsyncWrite>(
        &mut self,
        writer: &mut Typed<'_, S, P>,
        (hub, link): (&Hub, &Arc<Link>),
        pace: Option<&mut ClientPace>,
        out: &Listener,
    ) -> Result<(), Closing> {
        let Some(since) = self.since else {
            return Ok(());
        };
        let kind = self.kind;
        let writing = std::sync::atomic::AtomicBool::new(false);
        let sending = async {
            if let Some(pace) = pace {
                pace.take(hub, self.bytes).await;
            }
            for class in Class::ALL {
                let records = &mut self.by_class[class as usize];
                if records.is_empty() {
                    continue;
                }
                if let Err(Shed) = hub.egress().grant(link, class, wire_cost(records)).await {
                    return shed(hub);
                }
                writing.store(true, std::sync::atomic::Ordering::Relaxed);
                writer
                    .send(records)
                    .await
                    .map_err(|error| Closing::Silent(error.to_string()))?;
                writing.store(false, std::sync::atomic::Ordering::Relaxed);
                records.clear();
            }
            Ok(())
        };
        let deadline = (!out.resyncs()).then(|| since + IN_HAND_MS);
        let held_to = async {
            match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, sending).await.ok(),
                None => Some(sending.await),
            }
        };
        let ended = tokio::select! {
            sent = held_to => sent,
            () = out.fallen() => None,
        };
        match ended {
            Some(sent) => sent?,
            None if writing.load(std::sync::atomic::Ordering::Relaxed) => {
                return Err(Closing::Silent(format!(
                    "fell behind the stream ({kind:?}): a send of what it took outlived {} ms",
                    crate::fanout::BEHIND_MS
                )));
            }
            None => return fell_behind(kind),
        }
        // Sent: the fan-out's charge of it goes with the last holder.
        self.holds.clear();
        self.since = None;
        self.records = 0;
        self.bytes = 0;
        Ok(())
    }
}

/// What `records` cost on the wire, at most: each record's bytes and its three-byte header, and
/// for each Noise message (one per record at worst, and every half message at most) its tag and
/// two-byte length. The socket counts what is really written; this is what is granted first.
fn wire_cost<P: Sendable>(records: &[P]) -> usize {
    const MESSAGE_OVERHEAD: usize = 2 + 16;
    let bytes: usize = records.iter().map(|record| record.encoded_len()).sum();
    let messages = records
        .len()
        .min(bytes / (noise::MAX_PLAINTEXT / 2) + 1)
        .max(1);
    bytes + messages * MESSAGE_OVERHEAD
}

/// Sends a directory link that fell behind the fan-out the directory held now, whole.
async fn resync_directory<S: AsyncWrite, P: Sendable>(
    writer: &mut Typed<'_, S, P>,
    hub: &Hub,
    link: &Arc<Link>,
    kind: Kind,
) -> Result<(), Closing> {
    for part in parts(&typed::<P>(live_offers(hub))) {
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

/// A loopback output of every reception in a local decoder's own format, unauthenticated and
/// never billed: plain BEAST (`--beast-out`) or ACARS-family JSON lines (`--acars-out`). Each
/// writes a reception's client form (`tally_wire::ClientObsView`) and nothing of the receiver
/// that heard it, since what is decoded from here is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalOutput {
    /// Each 1090 MHz reception as a BEAST frame, its counter and signal level zero: what a local
    /// readsb reads, and through it a public map and `tally-api`.
    Beast,
    /// Each ACARS, VDL2 or HFDL message as the feeder published it (only the message, nothing of
    /// its receiver) and a newline, as acars_router's TCP outputs write them (all three kinds on
    /// one port): what the map image's collector reads. Each is held to the rule first
    /// (`tally_wire::acars::line`: exactly its own projection), so a feeder's line that is not
    /// one message as a feeder publishes it is never written.
    Acars,
}

impl LocalOutput {
    fn flag(self) -> &'static str {
        match self {
            Self::Beast => "--beast-out",
            Self::Acars => "--acars-out",
        }
    }

    /// Its listener's gauge, on `GET /listeners`.
    fn gauge(self) -> &'static str {
        match self {
            Self::Beast => "beast-out",
            Self::Acars => "acars-out",
        }
    }

    fn clients(self, hub: &Hub) -> usize {
        match self {
            Self::Beast => hub.beast_clients(),
            Self::Acars => hub.acars_clients(),
        }
    }

    /// Appends what it writes of one batch's receptions to `bytes`: the receptions of its kind,
    /// each in its client form; nothing of any other.
    fn encode(self, decoded: &tally_wire::Decoded, bytes: &mut Vec<u8>) {
        let views = decoded.views().map(tally_wire::ClientObsView::from);
        match self {
            Self::Beast => {
                for frame in views.filter_map(|view| view.to_beast()) {
                    frame.encode_beast(bytes);
                }
            }
            Self::Acars => {
                for line in views.filter_map(|view| view.to_acars_line()) {
                    bytes.extend_from_slice(line.as_bytes());
                    bytes.push(b'\n');
                }
            }
        }
    }
}

/// Serves plain BEAST of every reception to whoever connects (a local readsb, which a public map
/// and `tally-api` read), at most `Hub::beast_clients` at once (`--max-beast-clients`), as
/// [`serve_local`] serves either output.
pub async fn serve_beast(listener: TcpListener, hub: Arc<Hub>) -> std::io::Result<Infallible> {
    serve_local(listener, hub, LocalOutput::Beast).await
}

/// Serves every ACARS, VDL2 and HFDL message as a JSON line to whoever connects (the map image's
/// collector), at most `Hub::acars_clients` at once (`--max-acars-clients`), as
/// [`serve_local`] serves either output.
pub async fn serve_acars(listener: TcpListener, hub: Arc<Hub>) -> std::io::Result<Infallible> {
    serve_local(listener, hub, LocalOutput::Acars).await
}

/// Serves `output` to whoever connects, at most its clients at once: one past them is closed as it
/// is accepted (`listeners::Acceptor`, its gauge on `GET /listeners`). It is unauthenticated and
/// never billed, so a listener bound anywhere but loopback is refused before anything is served
/// (`sockets::loopback_only`), as the stats endpoint's is. Otherwise it returns only when its
/// listener has accepted nothing for `listeners::STARVED_AFTER`, which ends the relay.
pub async fn serve_local(
    listener: TcpListener,
    hub: Arc<Hub>,
    output: LocalOutput,
) -> std::io::Result<Infallible> {
    crate::sockets::loopback_only(&listener, output.flag())?;
    let mut acceptor = crate::listeners::Acceptor::new(
        listener,
        hub.listeners().gauge(output.gauge()),
        Arc::clone(hub.egress()),
        crate::sockets::Role::Subscriber,
    )
    .capped(output.clients(&hub));
    loop {
        let (stream, peer) = match acceptor.next().await {
            Ok(accepted) => accepted,
            Err(starved) => return Err(std::io::Error::other(starved.to_string())),
        };
        let out = hub.listen(hub.connection_id(), Filter::Local);
        // It takes data and gives none: a plain subscriber, to the cap.
        stream.link().set_kind(Kind::Taker);
        tokio::spawn(async move {
            if let Err(error) = local_client(stream, out, LOCAL_WRITE_TIMEOUT, output).await {
                eprintln!("tally-relay: {} {peer}: {error}", output.gauge());
            }
        });
    }
}

/// Writes every reception of `output`'s kind to one client, each write held to `deadline` and
/// granted by the upload cap as a plain subscriber's (a loopback client, the usual one, is never
/// held to it), at most `SEND_BYTES` (beyond the batch that crosses it) at a time. The client
/// sends nothing, and the relay only writes to it, so its end is read for
/// (`listeners::send_only`): a client that hangs up is let go at once, not at the next write,
/// which may not come while nothing is received. Ended by the client, it is `Ok`.
async fn local_client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: Socket<S>,
    out: Listener,
    deadline: Duration,
    output: LocalOutput,
) -> Result<(), String> {
    let link = stream.link();
    let egress = Arc::clone(stream.egress());
    crate::listeners::send_only(stream, |mut stream| async move {
        let mut bytes = Vec::new();
        let mut items: Vec<Taken> = Vec::new();
        loop {
            if let Err(fell) = out.recv_many(&mut items, SEND_BATCH).await {
                return Err(format!("fell behind ({fell:?})"));
            }
            let mut taken = items.drain(..).peekable();
            while taken.peek().is_some() {
                bytes.clear();
                // Their charges are held until their bytes are written; their decodes are not,
                // once encoded (`fanout::Taken::hold`), so none waits on the socket beside a
                // charge its subscriber may let go.
                let mut holds: Vec<crate::fanout::Hold> = Vec::new();
                while bytes.len() < SEND_BYTES
                    && let Some(item) = taken.next()
                {
                    // Each batch's one decode (`hub::Item::decoded`); the router offers only
                    // batches with one.
                    if let Some(decoded) = item.decoded.as_ref() {
                        output.encode(decoded, &mut bytes);
                    }
                    holds.push(item.hold());
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
                drop(holds);
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_wire::Identity;
    use tally_wire::beast::FrameKind;
    use tally_wire::clocks::recorded::judged;
    use tally_wire::{Batch, BatchContent, Frame, Observation, RelayAddress, Streams};
    use tally_wire::{Location, ReceiverInfo};
    use tokio::time::timeout;

    /// The relay's clock now, as a relay started now reads it: what a test signs its records by.
    fn now_ms() -> u64 {
        crate::clock::RelayClock::system().judged().ms()
    }

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// A connection's place from loopback, as `serve` takes one before a handshake.
    fn loopback(hub: &Hub) -> Result<Connection, String> {
        hub.connection(std::net::Ipv4Addr::LOCALHOST.into())
            .ok_or_else(|| "no connection place".to_owned())
    }

    /// A reconnect storm is admitted at the planned handshake pace (`cores::handshakes_in_flight`):
    /// of sixty feeders that all reconnect at once, only the cap's four are in their handshake at
    /// any moment, the rest wait their turn in arrival order, and every one is served. Paused
    /// time: every client takes 10 ms to send its first bytes, so all sixty connections are in
    /// their handshake together unless the cap holds them (uncapped the peak is sixty).
    #[tokio::test(start_paused = true)]
    async fn a_reconnect_storm_is_admitted_at_the_planned_handshake_pace() -> Result<(), String> {
        let storm = 60;
        let permits = 4;
        let hub = Arc::new(
            Hub::new(8, crate::sharing::Deadlines::RELAY)
                .max_connections_per_address(storm * 2)
                .max_connections(storm * 2)
                .max_upload(roomy())
                .handshakes_capped(permits),
        );
        let relay = NoiseKey::of(Identity::generate().map_err(text)?);
        let relay_key = relay.public();
        let mut feeders = Vec::new();
        for _ in 0..storm {
            let (near, far) = tokio::io::duplex(64 * 1024);
            let far = hub.egress().socket(far, None);
            let connection = loopback(&hub)?;
            let (hub, relay) = (Arc::clone(&hub), relay.clone());
            tokio::spawn(async move { inbound(far, &[relay], hub, connection).await });
            feeders.push(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let session = noise::connect(
                    near,
                    &Identity::generate().map_err(text)?,
                    &relay_key,
                    Role::Probe,
                )
                .await
                .map_err(text)?;
                Ok::<_, String>(session)
            }));
        }
        let mut sessions = Vec::new();
        for feeder in feeders {
            sessions.push(feeder.await.map_err(text)??);
        }
        let report = hub.handshake_report();
        assert_eq!(report.begun, storm as u64, "every connection was served");
        assert_eq!(report.permits, permits);
        assert_eq!(report.peak, permits, "the cap was reached and never passed");
        assert_eq!(
            report.planned_per_sec,
            crate::cores::handshake_pace_of(permits)
        );
        drop(sessions);
        Ok(())
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
        tokio::spawn(crate::serve(
            listener,
            vec![parent],
            Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY)),
        ));
        let child = Identity::generate().map_err(text)?;
        let upstream = Upstream {
            address,
            key: parent_key,
        };
        let asked = upstream_once(
            &upstream,
            &child,
            &Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY)),
        )
        .await?
        .map(|away| away.wait);
        // Neither accepted nor verified: asked to wait gossip's time (its own schedule's first
        // step), never a re-signing's, so a member whose offer is still spreading is not kept out.
        assert_eq!(
            asked,
            Some(Duration::from_secs(UNVERIFIED_RETRY_SECS.into()))
        );
        Ok(())
    }

    /// Waits for `dials` to reach three, and says how long that took from `since`, before the
    /// first: two waits of the dial schedule (1 s, then 2 s, each up to half again, `Backoff`)
    /// lie between the first dial and the third, so it is 3 s at least however slow the machine,
    /// where a loop that redials at once takes milliseconds. A dial loop that never dials a third
    /// time fails it at `HANG`.
    async fn third_dial(
        dials: &std::sync::atomic::AtomicU64,
        since: Instant,
        settled: impl Fn(u64) -> bool,
    ) -> Result<Duration, String> {
        const HANG: Duration = Duration::from_secs(120);
        timeout(HANG, async {
            loop {
                let dialled = dials.load(std::sync::atomic::Ordering::Relaxed);
                if dialled >= 3 && settled(dialled) {
                    return since.elapsed();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "never dialled three times".to_owned())
    }

    /// A relay that refuses this one (it never verified this relay's offer, so it asks gossip's
    /// wait, no longer than the dial schedule's own) and a peer that drops every connection at
    /// once are each dialled less and less often, whatever the role dialled: never again at once,
    /// never in a loop (`Redial`). Held by the dials counted and the schedule's waits, which a
    /// loaded machine can only lengthen: never by how many dials fit a span of the wall clock.
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
            tokio::spawn(crate::serve(
                listener,
                vec![far],
                Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY)),
            ));
            // A relay taking an area, so a raw link has its place in the members' pool.
            let area = tally_wire::rendezvous::area_of(&tally_wire::Location {
                lat_e7: 337_490_000,
                lon_e7: -843_880_000,
                alt_m: 0,
                precision_m: 0,
            })
            .map_err(text)?;
            let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).taking(vec![area]));
            let (_sender, outgoing) = mpsc::channel(1);
            let subscribe = Record::Subscribe {
                streams: Streams::RAW,
                regions: Vec::new(),
            };
            let since = Instant::now();
            let dialling = tokio::spawn(member(
                RelayAddress {
                    key: far_key,
                    address,
                },
                NoiseKey::of(Identity::generate().map_err(text)?),
                role,
                vec![subscribe],
                Arc::clone(&hub),
                outgoing,
            ));
            let took = third_dial(&hub.network().dials(), since, |_| true).await?;
            dialling.abort();
            assert!(
                took >= Duration::from_secs(3),
                "{role:?}: three dials in {took:?}"
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
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
        let (_sender, outgoing) = mpsc::channel(1);
        let since = Instant::now();
        let dialling = tokio::spawn(member(
            RelayAddress {
                key: Identity::generate().map_err(text)?.public(),
                address,
            },
            NoiseKey::of(Identity::generate().map_err(text)?),
            Role::Relay,
            Vec::new(),
            Arc::clone(&hub),
            outgoing,
        ));
        // Every dial counted reached the peer: waited for until the peer has taken as many as were
        // counted, the next dial seconds away.
        let took = third_dial(&hub.network().dials(), since, |dialled| {
            accepted.load(std::sync::atomic::Ordering::Relaxed) == dialled
        })
        .await?;
        dialling.abort();
        assert!(took >= Duration::from_secs(3), "three dials in {took:?}");
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
        let asked = upstream_once(
            &upstream,
            &child,
            &Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY)),
        )
        .await?;
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
        batch_signed_at(receiver, sequence, count, now_ms())
    }

    /// As `batch`, signed at `wall_ms`.
    fn batch_signed_at(
        receiver: &Identity,
        sequence: u64,
        count: u32,
        wall_ms: u64,
    ) -> Result<Batch, String> {
        let observations = (0..count)
            .map(|n| {
                let mut message = [0x8d; 14];
                message[1..5].copy_from_slice(&n.to_be_bytes());
                Frame::new(FrameKind::ModeSLong, u64::from(n), 100, &message)
                    .map(|frame| Observation::from_beast(&frame))
                    .map_err(text)
            })
            .collect::<Result<Vec<_>, _>>()?;
        crate::anchors::anchored(
            receiver,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms,
                dropped: 0,
                previous: [0; 32],
                observations,
            },
        )
        .map_err(text)
    }

    /// Receivers' descriptions and relays' feeder figures, the whole world.
    fn figures_wanted() -> Record {
        Record::Subscribe {
            streams: Streams::RAW.with(Streams::FEEDER_FIGURES),
            regions: Vec::new(),
        }
    }

    /// A relay's feeder figures, `count` receivers of one area, issued at the start of the hour
    /// `hub`'s clock is in (figures are of whole hours, and the relay takes them inside its window,
    /// `strikes::Window::figures`), told apart by `nonce` (in their counts): a record a client
    /// subscribed to them is sent.
    fn figures(hub: &Hub, relay: &Identity, nonce: u64, count: usize) -> Result<Record, String> {
        let issued_ms =
            hub.now().ms() / tally_wire::FIGURES_BUCKET_MS * tally_wire::FIGURES_BUCKET_MS;
        let place = tally_wire::Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        };
        let cell = tally_wire::Region::public_cell(&place).map_err(text)?;
        let area = tally_wire::rendezvous::area_of_public(cell).ok_or("no area")?;
        let mut feeders: Vec<tally_wire::FeederFigure> = (0..count)
            .map(|n| {
                let mut seed = [3; 32];
                seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
                tally_wire::FeederFigure {
                    receiver: Identity::from_seed(seed).public(),
                    cell: Some(cell),
                    uptime_permille: 1000,
                    messages: n as u64,
                    aircraft: 1 + nonce as u32,
                    range_m: None,
                    coverage_dkm2: 0,
                    unique_coverage_dkm2: 0,
                    mlat_positions: 0,
                    standing: false,
                }
            })
            .collect();
        feeders.sort_by_key(|figure| *figure.receiver.as_bytes());
        tally_wire::FeederFigures::sign(
            relay,
            &tally_wire::FeederFiguresContent {
                issued_ms,
                window_for_ms: tally_wire::FIGURES_BUCKET_MS,
                area: Some(area),
                feeders,
            },
        )
        .map(Record::FeederFigures)
        .map_err(text)
    }

    /// RFC-0181 §8: a subscriber that keeps its read deadline alive and never reads holds what
    /// its link took from the fan-out no longer than a queue may hold inbound
    /// (`fanout::BEHIND_MS`): its send is given up then, and the session ends as fallen behind.
    /// Before, the send held the items' charges, unranked, for the whole write deadline (30 s).
    // Paused: time moves only when every task waits, so each deadline is met exactly.
    #[tokio::test(start_paused = true)]
    async fn a_subscriber_that_heartbeats_but_never_reads_is_dropped_once_behind()
    -> Result<(), String> {
        // The ingest clock stopped: signing the batches below takes real seconds in a debug
        // build, and a subscriber is let go two seconds of inbound behind, which is not what
        // this measures.
        let hub = Arc::new(
            Hub::clocked(1, Arc::new(|| 0), crate::sharing::Deadlines::RELAY).max_upload(roomy()),
        );
        let relay = Identity::generate().map_err(text)?;
        let relay_key = relay.public();
        let (near, far) = tokio::io::duplex(64 * 1024);
        let far = hub.egress().socket(far, None);
        let serving = tokio::spawn({
            let hub = Arc::clone(&hub);
            async move { inbound(far, &[relay], Arc::clone(&hub), loopback(&hub)?).await }
        });
        let session = noise::connect_with(
            near,
            &Identity::generate().map_err(text)?,
            &relay_key,
            Role::Subscriber,
            &[figures_wanted()],
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
        let signer = Identity::generate().map_err(text)?;
        let records = (0..64)
            .map(|issued| figures(&hub, &signer, issued, 600))
            .collect::<Result<Vec<_>, _>>()?;
        let started = Instant::now();
        for record in records {
            hub.publish_own(record);
        }
        let ended = timeout(noise::WRITE_TIMEOUT, serving)
            .await
            .map_err(|_| "the relay kept the session to its write deadline".to_owned())?
            .map_err(text)?;
        let took = started.elapsed();
        assert!(
            matches!(&ended, Err(why) if why.contains("fell behind")),
            "ended with {ended:?}"
        );
        // Virtual time: the send that blocked was the one started when the batches went out.
        assert!(
            took >= IN_HAND_MS && took < IN_HAND_MS + Duration::from_secs(1),
            "{took:?}"
        );
        // Its place is free for the next subscriber.
        assert_eq!(hub.subscribers(), 0);
        drop(unread);
        beating.abort();
        Ok(())
    }

    /// The BEAST output is raw, relay-only data: a listener bound anywhere but loopback is refused
    /// before anything is served.
    #[tokio::test]
    async fn beast_out_off_loopback_is_refused() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
        let listener = TcpListener::bind("0.0.0.0:0").await.map_err(text)?;
        let refused = timeout(Duration::from_secs(5), serve_beast(listener, hub))
            .await
            .map_err(|_| "an off-loopback BEAST output was served".to_owned())?;
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::InvalidInput),
            "{refused:?}"
        );
        Ok(())
    }

    // Paused: time moves only when every task waits, so each deadline is met exactly.
    #[tokio::test(start_paused = true)]
    async fn a_beast_out_client_that_never_reads_is_dropped_at_its_deadline() -> Result<(), String>
    {
        let hub = Arc::new(Hub::new(1, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        let (unread, far) = tokio::io::duplex(1024);
        let far = hub.egress().socket(far, None);
        let out = hub.listen(hub.connection_id(), Filter::Local);
        let client = tokio::spawn(local_client(
            far,
            out,
            Duration::from_millis(200),
            LocalOutput::Beast,
        ));
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

    /// A feeder's ACARS-family lines pass through the relay unchanged: its batch reaches every
    /// taker as it signed it, acars-out writes each line that is its own projection
    /// (`tally_wire::acars::line`) and a newline, and nothing else (the 1090 MHz frame of its
    /// next batch; what a hostile feeder shaped to look like one: a newline, two objects, trailing
    /// text, a line separator, an unclosed object, a receiver's field, a time past the second, a
    /// decoder's tree, a key twice); beast-out writes the frame and none of the lines.
    #[tokio::test]
    async fn acars_lines_pass_through_unchanged_and_acars_out_writes_each_as_a_line()
    -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let hub = Arc::new(Hub::new(4, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        let everything = hub.listen(u64::MAX, Filter::Everything);
        let mut readers = Vec::new();
        for output in [LocalOutput::Acars, LocalOutput::Beast] {
            let (near, far) = tokio::io::duplex(1 << 16);
            let far = hub.egress().socket(far, None);
            let out = hub.listen(hub.connection_id(), Filter::Local);
            tokio::spawn(local_client(far, out, Duration::from_secs(5), output));
            readers.push(near);
        }
        let good = br#"{"icao":"A1B2C3","kind":"vdl2","label":"H1","t":1696500000}"#;
        let acars = |data: &[u8]| Observation {
            format: tally_wire::batch::format::ACARS_JSON,
            timestamp: 5,
            signal: 0,
            data: data.to_vec(),
        };
        let frame = Frame::new(FrameKind::ModeSLong, 7, 100, &[0x8d; 14]).map_err(text)?;
        let receiver = Identity::generate().map_err(text)?;
        let signed = crate::anchors::anchored(
            &receiver,
            &BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: now_ms(),
                dropped: 0,
                previous: [0; 32],
                observations: vec![
                    acars(good),
                    acars(b"{\"a\":1}\n{\"forged\":2}"),
                    acars(b"{\"a\":1}{\"forged\":2}"),
                    acars(b"{\"a\":1} [2]"),
                    acars("{\"a\":\"\u{2028}{\\\"forged\\\":2}\"}".as_bytes()),
                    acars(b"{\"unclosed\":1"),
                    acars(
                        "{\"kind\":\"acars\",\"label\":\"H1\",\"t\":1,\"text\":\"\u{85}\"}"
                            .as_bytes(),
                    ),
                    // One message, but not as the feeder publishes it: the receiver's level, the
                    // time past the second, a decoder's tree, a key twice.
                    acars(br#"{"kind":"acars","label":"H1","level":-20,"t":1}"#),
                    acars(br#"{"kind":"vdl2","label":"H1","t":1.5}"#),
                    acars(br#"{"avlc":{"src":{}},"kind":"vdl2","label":"H1","t":1}"#),
                    acars(br#"{"kind":"acars","label":"H1","t":1,"text":"x","text":"y"}"#),
                    acars(good),
                ],
            },
        )
        .map_err(text)?;
        let frames = crate::anchors::anchored(
            &receiver,
            &BatchContent {
                boot_id: 1,
                sequence: 1,
                counter_epoch: 0,
                wall_ms: now_ms(),
                dropped: 0,
                previous: signed.hash(),
                observations: vec![Observation::from_beast(&frame)],
            },
        )
        .map_err(text)?;
        assert!(hub.publish_batch(999, signed.clone(), receiver.public()));
        assert!(hub.publish_batch(999, frames, receiver.public()));

        let deadline = Instant::now() + Duration::from_secs(10);
        let forwarded = loop {
            if let Some(item) = everything.try_recv()
                && let Record::Batch(batch) = &*item.record
            {
                break batch.clone();
            }
            if Instant::now() > deadline {
                return Err("the batch never reached a taker".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(forwarded.as_bytes(), signed.as_bytes());

        let mut expected = Vec::new();
        for _ in 0..2 {
            expected.extend_from_slice(good);
            expected.push(b'\n');
        }
        let mut beast = Vec::new();
        frame_without_receiver(&frame)?.encode_beast(&mut beast);
        for (reader, expected) in readers.iter_mut().zip([expected, beast]) {
            let mut read = vec![0; expected.len()];
            timeout(Duration::from_secs(10), reader.read_exact(&mut read))
                .await
                .map_err(|_| "a local output wrote nothing".to_owned())?
                .map_err(text)?;
            assert_eq!(read, expected);
            // And nothing more.
            let mut more = [0; 1];
            assert!(
                timeout(Duration::from_millis(100), reader.read(&mut more))
                    .await
                    .is_err()
            );
        }
        Ok(())
    }

    /// A frame as a local output writes it: its message, no counter, no signal level.
    fn frame_without_receiver(frame: &Frame) -> Result<Frame, String> {
        Frame::new(frame.kind(), 0, 0, frame.message()).map_err(text)
    }

    /// Waits (a bounded poll) until `holds` of `hub`'s listener `name` is true of its count of
    /// open connections.
    async fn open_on(
        hub: &Hub,
        name: &'static str,
        holds: impl Fn(usize) -> bool,
    ) -> Result<(), String> {
        let gauge = hub.listeners().gauge(name);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !holds(gauge.open()) {
            if Instant::now() > deadline {
                return Err(format!("{name} holds {} open", gauge.open()));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }

    /// The defect of 2026-10-18: a local readsb that hangs up and reconnects whenever its input
    /// goes quiet, with nothing flowing, left a socket in CLOSE-WAIT each time, since a client
    /// that is only written to was let go only by a write. Its end is read for now, so however
    /// often it comes and goes the relay holds nothing of it.
    #[tokio::test]
    async fn a_beast_out_client_that_comes_and_goes_with_nothing_flowing_leaves_nothing_held()
    -> Result<(), String> {
        let hub = Arc::new(Hub::new(1, crate::sharing::Deadlines::RELAY).serving_beast(2));
        let beast = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = beast.local_addr().map_err(text)?;
        tokio::spawn(serve_beast(beast, Arc::clone(&hub)));
        for _ in 0..50 {
            let client = TcpStream::connect(address).await.map_err(text)?;
            open_on(&hub, "beast-out", |open| open == 1).await?;
            drop(client);
            open_on(&hub, "beast-out", |open| open == 0).await?;
        }
        // Its place in the fan-out is let go with it.
        assert_eq!(hub.listening(), 0);
        let report = hub.listeners().gauge("beast-out").report();
        assert_eq!((report.accepted, report.refused), (50, 0));
        Ok(())
    }

    #[tokio::test]
    async fn a_beast_out_client_past_the_cap_is_closed_as_it_connects() -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let hub = Arc::new(Hub::new(1, crate::sharing::Deadlines::RELAY).serving_beast(2));
        let beast = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = beast.local_addr().map_err(text)?;
        tokio::spawn(serve_beast(beast, Arc::clone(&hub)));
        let _first = TcpStream::connect(address).await.map_err(text)?;
        let _second = TcpStream::connect(address).await.map_err(text)?;
        open_on(&hub, "beast-out", |open| open == 2).await?;
        let mut third = TcpStream::connect(address).await.map_err(text)?;
        let mut byte = [0; 1];
        let read = timeout(Duration::from_secs(10), third.read(&mut byte))
            .await
            .map_err(|_| "the third client was served".to_owned())?;
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        let report = hub.listeners().gauge("beast-out").report();
        assert_eq!((report.open, report.refused), (2, 1));
        Ok(())
    }

    // Paused: time moves only when every task waits, so each deadline is met exactly.
    #[tokio::test(start_paused = true)]
    async fn a_session_changes_its_subscription_at_most_once_a_second() -> Result<(), String> {
        let (subscribe, updates) = watch::channel(Subscription::default());
        let mut wants = Wants::engine(Subscription::default(), updates);
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
                client: None,
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
                Record::FeederFigures(_) => *batches += 1,
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
        const DESCRIBED: usize = 4_000;
        // A queue far smaller than the directory: one send of the whole of it would leave the
        // subscriber behind. About `RING` of the small batches below.
        const RING: usize = 16;
        // The ingest clock is the paused runtime's, so a queue's age (`fanout::BEHIND_MS`) is
        // read in the same time as every deadline here, however slowly a loaded host runs it.
        let started = tokio::time::Instant::now();
        let clock: crate::clock::Script =
            Arc::new(move || 1_000_000 + u64::try_from(started.elapsed().as_millis()).unwrap_or(0));
        let hub = Arc::new(
            Hub::clocked(1, clock, crate::sharing::Deadlines::RELAY)
                .queue_bytes(RING * 512)
                .max_upload(roomy()),
        );
        let author = Identity::generate().map_err(text)?;
        // Format 2: what a client is sent of a description (a format 1 one is relay-only).
        let info = ReceiverInfo::sign_public(
            &author,
            &tally_wire::batch::PublicInfoContent {
                issued_ms: 1,
                cell: None,
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
            async move { inbound(far, &[relay], Arc::clone(&hub), loopback(&hub)?).await }
        });
        let session = noise::connect_with(
            near,
            &Identity::generate().map_err(text)?,
            &relay_key,
            Role::Subscriber,
            &[figures_wanted()],
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
        // While its first send waits on it, the fan-out moves on by many times the ring: data a
        // client takes (a relay's figures; receivers' raw is relay-only), one small record each.
        let signer = Identity::generate().map_err(text)?;
        let mut sequence = 0;
        for _ in 0..4 * RING {
            hub.publish_own(figures(&hub, &signer, sequence, 1)?);
            sequence += 1;
        }
        let (mut infos, mut batches) = (0, 0);
        while infos < DESCRIBED {
            read_some(&mut reader, &mut infos, &mut batches).await?;
        }
        assert_eq!((infos, batches), (DESCRIBED, 0));
        // Joined the fan-out once the directory was sent.
        tokio::time::sleep(Duration::from_millis(100)).await;
        hub.publish_own(figures(&hub, &signer, sequence, 1)?);
        sequence += 1;
        while batches < 1 {
            read_some(&mut reader, &mut infos, &mut batches).await?;
        }
        // Changing what it wants sends the directory again, in parts, while batches keep coming
        // one per read: more of them during the dump than the ring holds, all delivered.
        writer.send(&[figures_wanted()]).await.map_err(text)?;
        let (mut again, mut during) = (0, 0);
        let mut published = 0;
        while again < DESCRIBED {
            read_some(&mut reader, &mut again, &mut during).await?;
            hub.publish_own(figures(&hub, &signer, sequence, 1)?);
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

    /// RFC-0171 §3.6: a member's copy is usable by this relay's own clock alone, within the peer
    /// window (`strikes::Window::PEER`: 76 s behind, 25 s ahead), and nothing it carries or says
    /// changes that; outside it the copy is possession only (counted late, never forwarded), and
    /// nobody is refused or blamed for it. Before, a member's mark (`Record::LateCopy`) decided
    /// it, and a forged one was refused as a forgery, ending the link of whoever passed it on.
    #[test]
    fn a_member_links_copy_is_usable_by_this_relays_clock_alone() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
        let out = hub.listen(u64::MAX, Filter::Everything);
        let receiver = Identity::generate().map_err(text)?;
        let asker = Asker {
            role: AskerRole::Relay,
            key: Identity::generate().map_err(text)?.public(),
            source: 7,
            loopback: true,
            address: None,
        };
        let refusal = Arc::new(Refusal::default());
        let mut described = None;
        let mut read = |peer: Peer, record: Record| {
            let in_flight = match &record {
                Record::Batch(batch) => Some(hub.in_flight_for(batch)),
                _ => None,
            };
            ingest(
                record,
                &hub,
                7,
                (peer, &asker),
                None,
                &mut described,
                (in_flight, &refusal, hub.clock().raw()),
            )
            .map_err(|_| "unhandled".to_owned())
        };
        let forwarded = |out: &Listener| {
            let mut count = 0;
            while out.try_recv().is_some() {
                count += 1;
            }
            count
        };
        let behind = crate::strikes::Window::PEER
            .behind_span()
            .duration()
            .as_millis() as u64;
        // Just inside the peer window: used, forwarded.
        let inside = batch_signed_at(&receiver, 0, 1, now_ms() - behind + 5_000)?;
        read(Peer::Member, Record::Batch(inside))?;
        assert_eq!((hub.memory_report().late_records, forwarded(&out)), (0, 1));
        // Just past it, though a feeder's own relay would still use it: possession only.
        let past = batch_signed_at(&receiver, 1, 1, now_ms() - behind - 5_000)?;
        read(Peer::Member, Record::Batch(past))?;
        assert_eq!((hub.memory_report().late_records, forwarded(&out)), (1, 0));
        // A fresh one: used, and nobody refused for anything.
        let fresh = batch_signed_at(&receiver, 2, 1, now_ms())?;
        read(Peer::Member, Record::Batch(fresh))?;
        assert_eq!(forwarded(&out), 1);
        assert!(
            refusal.now().is_none(),
            "a member was refused over usability"
        );
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

    impl crate::sockets::Tunable for Tap {}

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
        dial_pipe_holding(hub, 1 << 20)
    }

    /// As `dial_pipe`, the pipe holding `bytes` each way: a small one, so a peer that does not
    /// read holds the relay's sends.
    fn dial_pipe_holding(hub: &Arc<Hub>, bytes: usize) -> Result<Dialled, String> {
        let relay = Identity::generate().map_err(text)?;
        let relay_key = relay.public();
        let (near, far) = tokio::io::duplex(bytes);
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
            async move { inbound(far, &[relay], Arc::clone(&hub), loopback(&hub)?).await }
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
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
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

    /// RFC-0181 §9: each role is held to its own cap, never another's. A relay whose
    /// connection cap is one still answers the next peer while a feeder is connected: the feeder
    /// gave its place under the cap up once it held its reservation. When the feeders, the
    /// subscribers and the members shared the cap, the next connection (a member's among them)
    /// was closed on before its handshake, with no word to route around it by.
    #[tokio::test]
    async fn a_connected_feeder_holds_no_place_under_the_connection_cap() -> Result<(), String> {
        let hub = Arc::new(
            Hub::new(8, crate::sharing::Deadlines::RELAY)
                .max_upload(roomy())
                .max_connections(1),
        );
        hub.network()
            .adopt_identity(Identity::generate().map_err(text)?);
        let mut feeding = dial_pipe(&hub)?;
        let _feeder = connected(&mut feeding, Role::Feeder).await?;
        let here = std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST);
        timeout(Duration::from_secs(60), async {
            while hub.budget().reserved() == 0 || hub.connection(here).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "the feeder still holds the only place under the cap".to_owned())?;
        // And the next peer is served: a probe is answered.
        let mut probing = dial_pipe(&hub)?;
        let mut probe = connected(&mut probing, Role::Probe).await?;
        probe
            .writer
            .send(&[Record::Echo(tally_wire::Echo { nonce: 9 })])
            .await
            .map_err(text)?;
        let mut replied = false;
        while !replied {
            replied = next(&mut probe.reader).await?.iter().any(|record| {
                matches!(record, Record::EchoReply(reply)
                    if reply.content().is_ok_and(|content| content.nonce == 9))
            });
        }
        // The probe holds the cap's one place now: a third is closed before its handshake.
        assert!(hub.connection(here).is_none());
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
        let now = now_ms();
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
        hub.network().directory.hold_verified(
            offer,
            crate::directory::Group::V4(7),
            judged(now),
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn an_engine_is_a_verified_relays_takes_no_subscriber_place_and_publishes_nothing()
    -> Result<(), String> {
        // One subscriber place, taken.
        let hub = Arc::new(Hub::new(1, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
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
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
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

    /// A reply is control or the directory, to a member's session too: data never goes back down
    /// the session it was asked for on, whose far end (the link a member dialled) takes none in.
    /// A repair page goes over this relay's own member link to the asker (`sharing`, `peers`).
    #[tokio::test]
    async fn no_data_goes_back_down_the_session_it_was_asked_on() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        let relay = Identity::generate().map_err(text)?;
        let receiver = Identity::generate().map_err(text)?;
        let echo = hub
            .network()
            .admission
            .echo(
                &hub,
                Some(&relay.signing()),
                tally_wire::Echo { nonce: 4 },
                1,
            )
            .ok_or("no echo reply")?;
        // From here the relay's key only answers handshakes.
        let relay = NoiseKey::of(relay);
        let answers = || -> Result<Vec<Record>, String> {
            Ok(vec![
                Record::EchoReply(echo.clone()),
                Record::Batch(batch(&receiver, 0, 1)?),
            ])
        };
        for peer in [Peer::Relay, Peer::Member] {
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
            let mut replies = Replies::new(peer, &link);
            replies.replying.hand_on(&hub, &key, answers()?);
            let waiting = replies.waiting.try_recv().map_err(text)?;
            reply(
                &mut Typed::<_, Arc<Record>>::new(&mut accepted.session.writer),
                &hub,
                &link,
                waiting,
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
            assert!(
                !got.iter().any(|record| matches!(record, Record::Batch(_))),
                "{got:?}"
            );
            // Nor was the cap asked for it.
            let raw = hub
                .egress()
                .report()
                .classes
                .iter()
                .find(|class| class.class == Class::Raw)
                .map_or(0, |class| class.asked_bytes_per_sec);
            assert_eq!(raw, 0, "raw asked {raw} B/s");
        }
        Ok(())
    }

    /// RFC-0171 §3.6: a relay states its freshness anchor to a feeder in its greeting and then
    /// one each period, signed by its key at its judging clock's reading (a new one once the
    /// clock has moved a period), and none while its clock is not judging: the feeder signs no
    /// batch by an anchor the relay could not have signed.
    #[tokio::test(start_paused = true)]
    async fn a_relay_states_its_anchor_to_its_feeder_each_period_while_it_judges()
    -> Result<(), String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        const AT_MS: u64 = 1_800_000_000_000;
        let judging = Arc::new(AtomicU64::new(AT_MS));
        let reading = Arc::clone(&judging);
        let clock =
            crate::clock::RelayClock::scripted(Arc::new(move || reading.load(Ordering::SeqCst)));
        let hub = Arc::new(
            Hub::on(8, clock.clone(), crate::sharing::Deadlines::RELAY).max_upload(roomy()),
        );
        let me = Identity::from_seed([90; 32]);
        hub.network().adopt_identity(crate::signer::twin(&me));
        let feeder = Identity::generate().map_err(text)?;
        let mut dialled = dial_pipe(&hub)?;
        let mut session = connected_as(&mut dialled, Role::Feeder, &feeder).await?;
        let anchors_in = |records: &[Record]| -> Vec<tally_wire::Anchor> {
            records
                .iter()
                .filter_map(|record| match record {
                    Record::Anchor(anchor) => Some(*anchor),
                    _ => None,
                })
                .collect()
        };
        let greeting = next(&mut session.reader).await?;
        let first = anchors_in(&greeting);
        assert_eq!(first.len(), 1, "{greeting:?}");
        assert_eq!((first[0].relay, first[0].j_ms), (me.public(), AT_MS));
        first[0].verify().map_err(text)?;
        // A period on, its clock a period on: a new anchor of that reading.
        judging.store(
            AT_MS
                + tally_wire::budget::ANCHOR_PERIOD
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            Ordering::SeqCst,
        );
        let mut next_anchor = Vec::new();
        for _ in 0..3 {
            next_anchor = anchors_in(&next(&mut session.reader).await?);
            if !next_anchor.is_empty() {
                break;
            }
        }
        assert_eq!(
            next_anchor.first().map(|anchor| anchor.j_ms),
            Some(
                AT_MS
                    + tally_wire::budget::ANCHOR_PERIOD
                        .span::<tally_wire::clocks::Judged>()
                        .ms()
            )
        );
        // Its clock unsynced: no anchor through the next heartbeat (thirty periods).
        clock.set_error(None);
        loop {
            let got = next(&mut session.reader).await?;
            assert!(anchors_in(&got).is_empty(), "{got:?}");
            if got.contains(&Record::Heartbeat) {
                break;
            }
        }
        Ok(())
    }

    /// RFC-0171 §3.6, the twenty-third sweep's finding 3: a feeder's batch is aged by this relay's
    /// own anchor in it as the message carrying it came off the socket, never after this relay's
    /// own pacing. A feeder held to one record a second sends a backlog of batches in one message,
    /// each signed with the relay's anchor of that moment; the relay's pacing takes the last of
    /// them in more than `FEEDER_BEHIND` (so they are too old by their signed time, unused) and
    /// `OWN_ANCHOR_OLDEST` later, while the relay issues an anchor a period and its ring lets the
    /// batches' go. None is blamed on the feeder. Before, the raw clock was read after the pacing,
    /// and every batch the pacing held past `OWN_ANCHOR_OLDEST` was blamed.
    #[tokio::test(start_paused = true)]
    async fn a_backlog_the_relays_pacing_holds_past_its_anchors_age_is_never_blamed()
    -> Result<(), String> {
        use tally_wire::budget::{FEEDER_BEHIND, OWN_ANCHOR_OLDEST};
        const AT_MS: u64 = 1_800_000_000_000;
        let start = tokio::time::Instant::now();
        let elapsed = move || start.elapsed().as_millis() as u64;
        let clock = crate::clock::RelayClock::scripted_raw(
            Arc::new(move || AT_MS + elapsed()),
            Arc::new(move || AT_MS + elapsed()),
            Arc::new(move || 1 + elapsed()),
        );
        let hub = Arc::new(
            Hub::on(8, clock, crate::sharing::Deadlines::RELAY)
                .max_upload(roomy())
                // One record a second (`ingest::records_per_sec`).
                .max_feeder_bytes_per_sec(crate::ingest::RECORD_BYTES),
        );
        assert_eq!(hub.feeder_records_per_sec(), 1);
        hub.network()
            .adopt_identity(crate::signer::twin(&Identity::from_seed([91; 32])));
        hub.begin_strikes();
        let feeder = Identity::generate().map_err(text)?;
        let mut dialled = dial_pipe(&hub)?;
        let mut session = connected_as(&mut dialled, Role::Feeder, &feeder).await?;
        // Long enough since its first anchor that it remembers every one an honest batch carries.
        let settled = OWN_ANCHOR_OLDEST.duration() + Duration::from_secs(2);
        while start.elapsed() < settled {
            if let Err(error) = next(&mut session.reader).await {
                return Err(format!(
                    "settling: {error}: {:?}",
                    ended(&mut dialled.serving).await
                ));
            }
        }
        let own = hub.anchor().ok_or("no anchor issued")?;
        let signed_ms = AT_MS + start.elapsed().as_millis() as u64;
        let backlog = FEEDER_BEHIND
            .duration()
            .max(OWN_ANCHOR_OLDEST.duration())
            .as_secs()
            + 10;
        let batches = (0..backlog)
            .map(|sequence| {
                Batch::sign_anchored(
                    &feeder,
                    &BatchContent {
                        boot_id: 1,
                        sequence,
                        counter_epoch: 0,
                        wall_ms: signed_ms,
                        dropped: 0,
                        previous: [0; 32],
                        observations: Vec::new(),
                    },
                    tally_wire::batch::Codec::Plain,
                    &[own],
                )
                .map(Record::Batch)
                .map_err(text)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Err(error) = session.writer.send(&batches).await {
            return Err(format!("{error}: {:?}", ended(&mut dialled.serving).await));
        }
        // Every batch taken in at its pace, the last a backlog's seconds after it arrived; the
        // relay's sends read meanwhile, so its writes never hold its reads.
        let sent = start.elapsed();
        let taken = sent + Duration::from_secs(backlog + 5);
        while start.elapsed() < taken {
            if let Err(error) = next(&mut session.reader).await {
                return Err(format!("{error}: {:?}", ended(&mut dialled.serving).await));
            }
        }
        // Those the pacing took in past `FEEDER_BEHIND` were too old to use, and counted late.
        assert!(
            hub.memory_report().late_records > 0,
            "{:?}",
            hub.memory_report()
        );
        let blamed = hub
            .station(&feeder.public())
            .map_or(0, |station| station.late_batches);
        assert_eq!(blamed, 0, "blamed for the relay's own pacing");
        Ok(())
    }

    /// A step of the relay's own judging clock ends nothing: it states its new clock to its
    /// feeder with the next heartbeat, before any batch of the feeder's drifts from it (RFC-0171
    /// §3.6). Before, a step ended the relay.
    #[tokio::test(start_paused = true)]
    async fn a_step_of_the_relays_clock_is_stated_to_its_feeder_at_once() -> Result<(), String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        const AT_MS: u64 = 1_800_000_000_000;
        let judging = Arc::new(AtomicU64::new(AT_MS));
        let reading = Arc::clone(&judging);
        let clock = crate::clock::RelayClock::scripted_apart(
            Arc::new(move || reading.load(Ordering::SeqCst)),
            Arc::new(|| 5_000),
        );
        let hub = Arc::new(Hub::on(8, clock, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        let feeder = Identity::generate().map_err(text)?;
        let mut dialled = dial_pipe(&hub)?;
        let mut session = connected_as(&mut dialled, Role::Feeder, &feeder).await?;
        let _greeting = next(&mut session.reader).await?;
        let batch = crate::anchors::anchored(
            &feeder,
            &BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: AT_MS,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(text)?;
        session
            .writer
            .send(&[Record::Batch(batch)])
            .await
            .map_err(text)?;
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        // Stepped forward 100 s, and nothing sent since.
        judging.store(AT_MS + 100_000, Ordering::SeqCst);
        let stated = next(&mut session.reader).await?;
        let Some(Record::RateLimit {
            clock_ms: Some(clock_ms),
            ..
        }) = stated.get(1)
        else {
            return Err(format!("the step was not stated: {stated:?}"));
        };
        assert_eq!(*clock_ms, AT_MS + 100_000);
        assert_eq!(hub.clock().steps(), 1);
        // Once.
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        Ok(())
    }

    /// RFC-0171 §3.6: a relay states its clock in its greeting, and again with its next
    /// heartbeat whenever its feeder signed a batch by a clock drifting from it (more than half
    /// the tolerance off), so a feeder signing by the clock it was told corrects it over a long
    /// session instead of drifting until it is refused; while the feeder's clock agrees, a
    /// heartbeat comes alone. Only a feeder that signed in step since the clock was last stated is
    /// told again: one that stays off after it was told reads no `clock_ms` (0.5.2, 0.6.x), and
    /// every `RateLimit` starts its pace again, so it is not sent one with each heartbeat; nor is
    /// one whose clock was off from the start.
    #[tokio::test(start_paused = true)]
    async fn a_relay_states_its_clock_again_when_its_feeders_clock_drifts() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        let feeder = Identity::generate().map_err(text)?;
        let mut dialled = dial_pipe(&hub)?;
        let mut session = connected_as(&mut dialled, Role::Feeder, &feeder).await?;
        let greeting = next(&mut session.reader).await?;
        assert!(matches!(
            greeting.first(),
            Some(Record::RateLimit {
                clock_ms: Some(_),
                ..
            })
        ));
        let signed = |sequence: u64, off_ms: u64| {
            crate::anchors::anchored(
                &feeder,
                &BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: hub.now().ms() - off_ms,
                    dropped: 0,
                    previous: [0; 32],
                    observations: Vec::new(),
                },
            )
            .map_err(text)
        };
        // In step with the relay: the heartbeat comes alone.
        session
            .writer
            .send(&[Record::Batch(signed(0, 0)?)])
            .await
            .map_err(text)?;
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        // Seven seconds behind: taken, and the relay's clock stated again with the next beat.
        session
            .writer
            .send(&[Record::Batch(signed(1, 7_000)?)])
            .await
            .map_err(text)?;
        let restated = next(&mut session.reader).await?;
        let before = hub.now();
        assert_eq!(restated.first(), Some(&Record::Heartbeat));
        let Some(Record::RateLimit {
            clock_ms: Some(clock_ms),
            ..
        }) = restated.get(1)
        else {
            return Err(format!("no clock stated again: {restated:?}"));
        };
        assert!(
            clock_ms.abs_diff(before.ms()) < 1_000,
            "{clock_ms} against {before:?}"
        );
        // Once, not with every heartbeat after.
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        // Still off after it was told: it reads no stated clock, and is not told again.
        session
            .writer
            .send(&[Record::Batch(signed(2, 7_000)?)])
            .await
            .map_err(text)?;
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        // In step again, then off: told again.
        session
            .writer
            .send(&[Record::Batch(signed(3, 0)?)])
            .await
            .map_err(text)?;
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        session
            .writer
            .send(&[Record::Batch(signed(4, 7_000)?)])
            .await
            .map_err(text)?;
        let again = next(&mut session.reader).await?;
        assert!(
            matches!(again.get(1), Some(Record::RateLimit { .. })),
            "not told again: {again:?}"
        );
        // In step, then its host's clock steps back 100 s, past what a relay takes in: the batch
        // is only counted late, but the feeder is told the relay's clock again, and a batch signed
        // by it is taken.
        session
            .writer
            .send(&[Record::Batch(signed(5, 0)?)])
            .await
            .map_err(text)?;
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        session
            .writer
            .send(&[Record::Batch(signed(6, 100_000)?)])
            .await
            .map_err(text)?;
        let stepped = next(&mut session.reader).await?;
        assert!(
            matches!(
                stepped.get(1),
                Some(Record::RateLimit {
                    clock_ms: Some(_),
                    ..
                })
            ),
            "a feeder stepped back was not told: {stepped:?}"
        );
        session
            .writer
            .send(&[Record::Batch(signed(7, 0)?)])
            .await
            .map_err(text)?;
        assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        let station = hub.station(&feeder.public()).ok_or("no station")?;
        assert_eq!((station.batches, station.late_batches), (7, 1));
        // A feeder whose clock is off from the start is never told again.
        let old = Identity::generate().map_err(text)?;
        let mut dialled = dial_pipe(&hub)?;
        let mut session = connected_as(&mut dialled, Role::Feeder, &old).await?;
        let _greeting = next(&mut session.reader).await?;
        for sequence in 0..3 {
            let batch = crate::anchors::anchored(
                &old,
                &BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: hub.now().ms() - 7_000,
                    dropped: 0,
                    previous: [0; 32],
                    observations: Vec::new(),
                },
            )
            .map_err(text)?;
            session
                .writer
                .send(&[Record::Batch(batch)])
                .await
                .map_err(text)?;
            assert_eq!(next(&mut session.reader).await?, vec![Record::Heartbeat]);
        }
        // And every one of its batches taken and used, though never told: 7 s behind is within
        // what a relay takes. Before, this read the records ahead, which a batch behind never is.
        let station = hub.station(&old.public()).ok_or("no station")?;
        assert_eq!((station.batches, station.late_batches), (3, 0));
        let report = hub.memory_report();
        assert_eq!((report.ahead_records, report.late_records), (0, 1));
        Ok(())
    }

    // Paused: the heartbeat comes without waiting thirty real seconds.
    #[tokio::test(start_paused = true)]
    async fn every_byte_a_session_writes_is_counted_whatever_wrote_it() -> Result<(), String> {
        let hint = RelayAddress {
            key: Identity::generate().map_err(text)?.public(),
            address: "elsewhere.example:10900".to_owned(),
        };
        let hub = Arc::new(
            Hub::new(8, crate::sharing::Deadlines::RELAY)
                .advertising(vec![hint])
                .max_upload(roomy()),
        );
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

        // A subscriber: the directory, the data it asked for, and the redirect it is shed with.
        let mut subscriber = dial_pipe(&hub)?;
        let near = subscriber.near.take().ok_or("dialled twice")?;
        let mut session = noise::connect_with(
            near,
            &Identity::generate().map_err(text)?,
            &subscriber.relay_key,
            Role::Subscriber,
            &[figures_wanted()],
        )
        .await
        .map_err(text)?;
        while hub.subscribers() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        hub.publish_own(figures(&hub, &Identity::generate().map_err(text)?, 1, 100)?);
        let mut got_batch = false;
        while !got_batch {
            got_batch = next(&mut session.reader)
                .await?
                .iter()
                .any(|record| matches!(record, Record::FeederFigures(_)));
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
        let child = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
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
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).serving_beast(1));
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
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
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
        let hub =
            Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).advertising(vec![hint.clone()]));
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
            Hub::new(8, crate::sharing::Deadlines::RELAY)
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

    /// A connection that overruns its ingest ceiling is told so (`Reason::OverCeiling`), never
    /// that this relay is full. A relay that dialled in and is turned away as full is noted as
    /// routing around this one and owes it nothing for that wait (`turning_away`), so a parent
    /// that overran its child's ceiling to be turned away delivered nothing and was never filed
    /// short. Its ceiling's clock stands still, so what it sends past its burst is over.
    #[tokio::test(start_paused = true)]
    async fn a_peer_over_its_ceiling_is_told_so_never_that_the_relay_is_full() -> Result<(), String>
    {
        let still = std::time::Instant::now();
        let hub = Arc::new(
            Hub::new(1, crate::sharing::Deadlines::RELAY)
                .max_upload(roomy())
                .max_feeder_bytes_per_sec(1_000)
                .ceiling_clock_from(Arc::new(move || still)),
        );
        let mut dialled = dial_pipe(&hub)?;
        let mut session = connected(&mut dialled, Role::Subscriber).await?;
        // Records of which three fill a message: four messages are past the burst
        // (`ceiling::MIN_BURST`).
        let list: Vec<RelayAddress> = (0..70)
            .map(|index| RelayAddress {
                key: dialled.relay_key,
                address: format!("{index:0>255}"),
            })
            .collect();
        let records = vec![Record::RelayList(list); 12];
        let sending = tokio::spawn(async move {
            let _ = session.writer.send(&records).await;
            session
        });
        let mut session = sending.await.map_err(text)?;
        let mut told = None;
        while told.is_none() {
            told = next(&mut session.reader)
                .await?
                .into_iter()
                .find(|record| matches!(record, Record::Goodbye { .. }));
        }
        assert!(
            matches!(
                told,
                Some(Record::Goodbye {
                    reason: Reason::OverCeiling,
                    ..
                })
            ),
            "{told:?}"
        );
        let why = ended(&mut dialled.serving).await?;
        assert!(why.contains("ceiling"), "{why}");
        Ok(())
    }

    /// A link the upload cap sheds is told the relay is full and is never excused its
    /// shortfalls: it ends `Saying`, never `Turning`, the end `turning_away` notes. The cap sheds
    /// the peer asking the most of its class, so before, a peer flooding `ProviderQuery`s made
    /// itself the one shed, was noted as routing around this relay, and owed nothing for it.
    #[test]
    fn a_link_the_cap_sheds_is_told_full_and_never_excused() {
        let hub = Hub::new(1, crate::sharing::Deadlines::RELAY);
        match shed(&hub) {
            Err(Closing::Saying { last, why }) => {
                assert_eq!(*last, full(&hub));
                assert!(why.contains("upload cap"), "{why}");
            }
            Err(Closing::Turning(_)) => panic!("a shed link is excused its shortfalls"),
            Err(Closing::Silent(why)) => panic!("a shed link is told nothing: {why}"),
            Ok(()) => panic!("a shed link goes on"),
        }
    }

    /// The one end that excuses a peer its shortfalls (`End::Full`, noted by `turning_away`)
    /// is this relay's own capacity at a member's admission; an overrun of the peer's ceiling is
    /// an end that tells it so and notes nothing.
    #[test]
    fn only_a_capacity_refusal_turns_a_relay_away_as_full() {
        // A hub that plans no member session has no member slot.
        let hub = Hub::new(1, crate::sharing::Deadlines::RELAY);
        assert!(matches!(admit_member(&hub, 0), Err(End::Full(_))));
        assert!(matches!(
            over_ceiling(),
            End::Told {
                reason: Reason::OverCeiling,
                ..
            }
        ));
    }

    /// A directory link whose peer reads slowly is not ended two seconds into a send, as a
    /// subscriber's is: what it is sent is held whole and resent if it overflows, so its send
    /// keeps the writer's deadline (`noise::WRITE_TIMEOUT`). Here its peer reads nothing for five
    /// seconds while the relay's send of new offers waits on the pipe, then reads them all, and
    /// the link is still up. Before, every link was held to the subscriber's `IN_HAND_MS`, and a
    /// slow peer's directory or member session ended as fallen behind.
    #[tokio::test(start_paused = true)]
    async fn a_slow_directory_link_keeps_its_write_deadline() -> Result<(), String> {
        let peer = Identity::generate().map_err(text)?;
        let hub = Arc::new(
            Hub::new(1, crate::sharing::Deadlines::RELAY)
                .max_upload(roomy())
                .accepting_relays([peer.public()]),
        );
        let mut dialled = dial_pipe_holding(&hub, 4 * 1024)?;
        let near = dialled.near.take().ok_or("dialled twice")?;
        let mut session = noise::connect(near, &peer, &dialled.relay_key, Role::Relay)
            .await
            .map_err(text)?;
        timeout(Duration::from_secs(10), async {
            while hub.listening() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "the directory link never joined the fan-out".to_owned())?;
        // Offers from relays enough to fill the pipe many times over.
        let now = now_ms();
        let cell = tally_wire::rendezvous::area_of(&Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        const OFFERS: usize = 60;
        for at in 0..OFFERS {
            let relay = Identity::generate().map_err(text)?;
            let offer = tally_wire::ProviderOffer::sign(
                &relay,
                &tally_wire::ProviderOfferContent {
                    address: format!("relay{at}.example:10900"),
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
            hub.publish_own(Record::ProviderOffer(offer));
        }
        // Its peer reads nothing for five seconds: well past a subscriber's two.
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            !dialled.serving.is_finished(),
            "the directory link ended while its peer was slow: {}",
            ended(&mut dialled.serving).await?
        );
        // Then it reads, and every offer arrives, with no goodbye.
        let mut offers = 0;
        while offers < OFFERS {
            for record in next(&mut session.reader).await? {
                match record {
                    Record::ProviderOffer(_) => offers += 1,
                    Record::Goodbye { reason, .. } => return Err(format!("told {reason:?}")),
                    _ => {}
                }
            }
        }
        assert!(!dialled.serving.is_finished());
        Ok(())
    }

    /// Every record `reader` is sent until it has been quiet for half a second (at most `limit`
    /// messages).
    async fn drain(
        reader: &mut Reader<tokio::io::DuplexStream>,
        limit: usize,
    ) -> Result<Vec<Record>, String> {
        let mut all = Vec::new();
        for _ in 0..limit {
            let mut records = Vec::new();
            match timeout(Duration::from_millis(500), reader.recv(&mut records)).await {
                Ok(Ok(())) => all.extend(records),
                Ok(Err(error)) => return Err(text(error)),
                Err(_) => break,
            }
        }
        Ok(all)
    }

    /// What no client may read, as bytes: each site's coordinates and its finest cell.
    fn site_canaries(sites: &[Location]) -> Result<Vec<Vec<u8>>, String> {
        let mut canaries = Vec::new();
        for site in sites {
            canaries.push(site.lat_e7.to_be_bytes().to_vec());
            canaries.push(site.lon_e7.to_be_bytes().to_vec());
            let point = tally_wire::Region::point(site).map_err(text)?;
            canaries.push(point.as_u64().to_be_bytes().to_vec());
        }
        Ok(canaries)
    }

    /// No byte a client is sent says a site: no site-bearing record, no raw batch, and no
    /// coordinate or finest cell of a site anywhere in what it reads.
    fn assert_no_site(records: &[Record], canaries: &[Vec<u8>]) -> Result<(), String> {
        for record in records {
            assert!(!crate::outbound::bears_site(record), "{record:?}");
            assert!(
                crate::outbound::client_form(record).is_some(),
                "a relay-only record reached a client: kind {}",
                record.kind()
            );
            let mut bytes = Vec::new();
            record.encode(&mut bytes).map_err(text)?;
            for canary in canaries {
                assert!(
                    !bytes
                        .windows(canary.len())
                        .any(|window| window == canary.as_slice()),
                    "a site's bytes in kind {}",
                    record.kind()
                );
            }
        }
        Ok(())
    }

    /// THE CANARY, over real sessions: an old feeder describes itself in format 1 (its site in the
    /// description) and a new one in format 2 with its site apart; both send raw. A subscriber in
    /// the fan-out, and one joining after (the directory's answer), read every stream a client
    /// may ask for and never a site, a raw batch, or a site's bytes; the old feeder's description
    /// reaches no client at all. A version 3 relay's engine is sent both sites, the format 1
    /// description among them.
    #[tokio::test]
    async fn a_client_never_reads_a_site_and_a_relay_of_version_three_does() -> Result<(), String> {
        use tally_wire::batch::{PublicInfoContent, ReceiverInfoContent};
        let peer = Identity::generate().map_err(text)?;
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        verified(&hub, &peer)?;
        let every = Streams::RAW
            .with(Streams::POSITIONS)
            .with(Streams::PROVISIONAL)
            .with(Streams::CLOCK_MODELS)
            .with(Streams::DEDUPLICATED)
            .with(Streams::REGIONAL)
            .with(Streams::WORLD)
            .with(Streams::WORLD_PRECISE)
            .with(Streams::FEEDER_FIGURES);
        let subscribe = Record::Subscribe {
            streams: every,
            regions: Vec::new(),
        };
        let mut early = dial_pipe(&hub)?;
        let mut watching = connected(&mut early, Role::Subscriber).await?;
        watching
            .writer
            .send(std::slice::from_ref(&subscribe))
            .await
            .map_err(text)?;
        while hub.subscribers() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (old_site, new_site) = (
            Location {
                lat_e7: 338_012_345,
                lon_e7: -843_012_345,
                alt_m: 88,
                precision_m: 0,
            },
            Location {
                lat_e7: 337_501_234,
                lon_e7: -843_887_654,
                alt_m: 301,
                precision_m: 0,
            },
        );
        let canaries = site_canaries(&[old_site, new_site])?;
        // The old feeder: format 1, its site in its description.
        let old = Identity::generate().map_err(text)?;
        let mut old_feed = dial_pipe(&hub)?;
        let mut session = connected_as(&mut old_feed, Role::Feeder, &old).await?;
        let described = ReceiverInfo::sign(
            &old,
            &ReceiverInfoContent {
                issued_ms: now_ms(),
                location: Some(old_site),
                clock: tally_wire::Clock::Dump1090,
                software: "tally-feed 0.2".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(text)?;
        session
            .writer
            .send(&[
                Record::ReceiverInfo(described),
                Record::Batch(batch(&old, 0, 20)?),
            ])
            .await
            .map_err(text)?;
        // The new feeder: its public cell described, its site apart.
        let new = Identity::generate().map_err(text)?;
        let mut new_feed = dial_pipe(&hub)?;
        let mut new_session = connected_as(&mut new_feed, Role::Feeder, &new).await?;
        let now = now_ms();
        let public = ReceiverInfo::sign_public(
            &new,
            &PublicInfoContent {
                issued_ms: now,
                cell: Some(tally_wire::Region::public_cell(&new_site).map_err(text)?),
                clock: tally_wire::Clock::Dump1090,
                software: "tally-feed 0.3".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(text)?;
        let site = tally_wire::ReceiverSite::sign(
            &new,
            &tally_wire::ReceiverSiteContent {
                issued_ms: now,
                location: new_site,
                clock: tally_wire::Clock::Dump1090,
            },
        )
        .map_err(text)?;
        new_session
            .writer
            .send(&[
                Record::ReceiverInfo(public),
                Record::ReceiverSite(site),
                Record::Batch(batch(&new, 0, 20)?),
            ])
            .await
            .map_err(text)?;
        // The fan-out's client: the new feeder's public description, and nothing of a site.
        let mut read = Vec::new();
        timeout(Duration::from_secs(30), async {
            loop {
                let more = drain(&mut watching.reader, 64).await?;
                read.extend(more);
                if read
                    .iter()
                    .any(|record| matches!(record, Record::ReceiverInfo(info) if info.receiver().ok() == Some(new.public())))
                {
                    return Ok::<(), String>(());
                }
            }
        })
        .await
        .map_err(|_| "the subscriber was never sent the new feeder's description".to_owned())??;
        read.extend(drain(&mut watching.reader, 64).await?);
        assert_no_site(&read, &canaries)?;
        assert!(!read.iter().any(|record| matches!(record, Record::ReceiverInfo(info) if info.receiver().ok() == Some(old.public()))));
        // A client joining now: the directory's answer.
        let mut late = dial_pipe(&hub)?;
        let mut joining = connected(&mut late, Role::Subscriber).await?;
        joining.writer.send(&[subscribe]).await.map_err(text)?;
        let answered = drain(&mut joining.reader, 64).await?;
        assert!(
            answered
                .iter()
                .any(|record| matches!(record, Record::ReceiverInfo(_))),
            "the joining client was answered nothing"
        );
        assert_no_site(&answered, &canaries)?;
        // A version 3 relay's engine, taking the area's raw, is sent both sites: the format 1
        // description and the new site.
        let mut relay_link = dial_pipe(&hub)?;
        let mut relay_session = connected_as(&mut relay_link, Role::Engine, &peer).await?;
        relay_session
            .writer
            .send(&[Record::Subscribe {
                streams: Streams::RAW,
                regions: vec![tally_wire::rendezvous::area_of(&new_site).map_err(text)?],
            }])
            .await
            .map_err(text)?;
        // Read until both sites have come, under a bounded deadline rather than a quiet spell: an
        // unoptimised build under load can be slower to answer than any one silence.
        let mut to_relay = Vec::new();
        let both = |read: &[Record]| {
            let kinds = |wanted: fn(&Record) -> bool| {
                read.iter()
                    .any(|record| crate::outbound::bears_site(record) && wanted(record))
            };
            kinds(|record| matches!(record, Record::ReceiverInfo(_)))
                && kinds(|record| matches!(record, Record::ReceiverSite(_)))
        };
        let _ = timeout(Duration::from_secs(30), async {
            while !both(&to_relay) {
                let mut records = Vec::new();
                relay_session
                    .reader
                    .recv(&mut records)
                    .await
                    .map_err(text)?;
                to_relay.extend(records);
            }
            Ok::<(), String>(())
        })
        .await;
        let sites: Vec<&Record> = to_relay
            .iter()
            .filter(|record| crate::outbound::bears_site(record))
            .collect();
        assert!(
            sites
                .iter()
                .any(|record| matches!(record, Record::ReceiverInfo(_))),
            "the old feeder's format 1 description never reached a relay: {:?}",
            to_relay
                .iter()
                .map(|record| (record.kind(), crate::outbound::bears_site(record)))
                .collect::<Vec<_>>()
        );
        assert!(
            sites
                .iter()
                .any(|record| matches!(record, Record::ReceiverSite(_))),
            "the new feeder's site never reached a relay"
        );
        Ok(())
    }

    /// A connection's replies waiting for its write side allocate at most `ingest::REPLIES_BYTES`
    /// (each record's own and its slot, the reply made exactly as long), carved with its buffers: answers past it are dropped, in order, and
    /// what a reply holds is the room's again once it is written or let go. Before, replies were
    /// gathered and queued uncharged, up to 64 lists of up to 32 offers each.
    #[test]
    fn a_connections_waiting_replies_hold_no_more_than_their_room() {
        let room = Arc::new(ReplyRoom::default());
        let echo = |nonce| Record::Echo(tally_wire::Echo { nonce });
        let one = echo(0).allocated() + crate::footprint::vec::<Record>(1);
        let fit = crate::ingest::REPLIES_BYTES / one;
        let first = room.offer((0..fit as u64 + 5).map(echo).collect());
        assert_eq!(first.as_ref().map(|reply| reply.records.len()), Some(fit));
        assert_eq!(
            first.as_ref().map(|reply| reply.records.capacity()),
            Some(fit)
        );
        assert_eq!(room.waiting(), fit * one);
        // Full: the next answers are dropped whole.
        assert!(room.offer(vec![echo(1)]).is_none());
        drop(first);
        assert_eq!(room.waiting(), 0);
        let again = room.offer(vec![echo(2)]);
        assert_eq!(room.waiting(), one);
        drop(again);
        assert_eq!(room.waiting(), 0);
    }

    /// Each record's answers are handed to the write side as soon as the record is handled,
    /// never gathered across the message: a probe that sends forty echoes in one message, paced
    /// at eight a second, hears its first answer at once. Before, every answer to a message waited
    /// until its last record was read, about five seconds here and minutes for a 64 KiB message.
    #[tokio::test(start_paused = true)]
    async fn each_records_answers_are_sent_as_it_is_handled() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        hub.network()
            .adopt_identity(Identity::generate().map_err(text)?);
        let mut probe = dial_pipe(&hub)?;
        let mut session = connected(&mut probe, Role::Probe).await?;
        let echoes: Vec<Record> = (0..40)
            .map(|nonce| Record::Echo(tally_wire::Echo { nonce }))
            .collect();
        let started = Instant::now();
        session.writer.send(&echoes).await.map_err(text)?;
        loop {
            let answered = next(&mut session.reader)
                .await?
                .iter()
                .any(|record| matches!(record, Record::EchoReply(_)));
            if answered {
                break;
            }
        }
        let took = started.elapsed();
        assert!(took < Duration::from_secs(1), "first answer after {took:?}");
        Ok(())
    }

    /// A connection's records a second are held to its role's pace whatever
    /// their bytes: a probe that sends forty echoes in one message (each a signature the relay
    /// makes) is answered over 32 s (`ingest::PROBE_RECORDS`: a round of eight at once, then one
    /// a second), not at once. Before, every role but a relay's was paced at a feeder's eight a
    /// second, and none of them was planned in the cores.
    #[tokio::test(start_paused = true)]
    async fn a_connections_records_are_paced_whatever_their_bytes() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(roomy()));
        hub.network()
            .adopt_identity(Identity::generate().map_err(text)?);
        let pace = crate::ingest::PROBE_RECORDS;
        let mut probe = dial_pipe(&hub)?;
        let mut session = connected(&mut probe, Role::Probe).await?;
        const ECHOES: u64 = 40;
        let echoes: Vec<Record> = (0..ECHOES)
            .map(|nonce| Record::Echo(tally_wire::Echo { nonce }))
            .collect();
        let started = Instant::now();
        session.writer.send(&echoes).await.map_err(text)?;
        let mut replies = 0;
        while replies < ECHOES {
            replies += next(&mut session.reader)
                .await?
                .iter()
                .filter(|record| matches!(record, Record::EchoReply(_)))
                .count() as u64;
        }
        let took = started.elapsed();
        let paced = Duration::from_secs((ECHOES - pace.burst) * 60 / pace.per_minute);
        assert!(
            took >= paced && took < paced + Duration::from_secs(1),
            "{ECHOES} echoes answered in {took:?}"
        );
        Ok(())
    }

    /// A batch of `count` wanted receptions (`tally_wire::modes::wanted_reception`): DF4 altitude
    /// replies, each with its address in its parity.
    fn wanted_batch(receiver: &Identity, sequence: u64, count: u32) -> Result<Batch, String> {
        let observations = (0..count)
            .map(|n| {
                let [_, _, hi, lo] = n.to_be_bytes();
                let message = tally_wire::modes::with_parity(&[0x20, 0, hi, lo], 0x00ab_cdef);
                Frame::new(FrameKind::ModeSShort, u64::from(n) + 1, 100, &message)
                    .map(|frame| Observation::from_beast(&frame))
                    .map_err(text)
            })
            .collect::<Result<Vec<_>, _>>()?;
        crate::anchors::anchored(
            receiver,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms: now_ms(),
                dropped: 0,
                previous: [0; 32],
                observations,
            },
        )
        .map_err(text)
    }

    /// RFC-0181 §10: a feeder is told its receiver's wanted receptions a second in
    /// its `RateLimit`, and past them the relay drops its batches, counted, by its batches' stamps,
    /// while its read loop takes every batch at once: six batches of 1,200 wanted sent together
    /// (7,200, twice the ceiling's two seconds) are all taken, those past the ceiling dropped whole
    /// and counted with their wanted receptions; and a feeder sending as many receptions MLAT never
    /// uses is held to nothing. Before, the read loop waited before each batch for every reception
    /// it stated, wanted or not, so a real-time feeder fell seconds behind and its raw went stale.
    #[tokio::test]
    async fn past_its_wanted_ceiling_a_feeders_batches_are_dropped_never_waited_for()
    -> Result<(), String> {
        const BATCHES: u64 = 6;
        const EACH: u32 = 1_200;
        let rate = crate::ingest::FEEDER_RECEPTIONS_PER_SEC;
        // The pace is the one ceiling MLAT's raw holder holds a receiver to.
        assert_eq!(
            rate,
            tally_mlat_solver::held::Rates::MEASURED.ceiling_per_s as u64
        );
        assert!(BATCHES * u64::from(EACH) > rate * crate::ingest::FEEDER_RECEPTIONS_BURST_SECS);
        // The ceiling is the batches' stamps' (`ingest::ReceptionCeilings`): every batch stamped at
        // one instant, so what is kept and dropped is the burst's alone, however long the machine
        // takes between reading one batch and the next.
        let at = now_ms();
        let hub = Arc::new(
            Hub::clocked(8, Arc::new(move || at), crate::sharing::Deadlines::RELAY)
                .max_upload(roomy()),
        );
        let mut sent = Vec::new();
        for wanted in [true, false] {
            let feeder = Identity::generate().map_err(text)?;
            let mut dialled = dial_pipe(&hub)?;
            let mut session = connected_as(&mut dialled, Role::Feeder, &feeder).await?;
            let greeting = next(&mut session.reader).await?;
            assert!(
                matches!(
                    greeting.first(),
                    Some(Record::RateLimit { wanted_per_sec: Some(told), .. })
                        if u64::from(*told) == rate
                ),
                "{greeting:?}"
            );
            let batches = (0..BATCHES)
                .map(|sequence| {
                    if wanted {
                        wanted_batch(&feeder, sequence, EACH)
                    } else {
                        batch(&feeder, sequence, EACH)
                    }
                    .map(Record::Batch)
                })
                .collect::<Result<Vec<_>, _>>()?;
            session.writer.send(&batches).await.map_err(text)?;
            sent.push((feeder.public(), session, dialled));
        }
        // Every batch is taken, kept or dropped, without the read loop waiting for any.
        let (wanted_feeder, unwanted_feeder) = (sent[0].0, sent[1].0);
        let kept = |key: &PublicKey| hub.station(key).map_or(0, |station| station.batches);
        timeout(Duration::from_secs(60), async {
            while kept(&wanted_feeder) + hub.over_reception_ceiling().batches < BATCHES
                || kept(&unwanted_feeder) < BATCHES
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| {
            format!(
                "batches still unread: kept {} and {}, dropped {:?}",
                kept(&wanted_feeder),
                kept(&unwanted_feeder),
                hub.over_reception_ceiling()
            )
        })?;
        let over = hub.over_reception_ceiling();
        let ceiling = rate * crate::ingest::FEEDER_RECEPTIONS_BURST_SECS;
        assert!(
            kept(&wanted_feeder) >= ceiling / u64::from(EACH) && over.batches >= 1,
            "kept {}, dropped {over:?}",
            kept(&wanted_feeder)
        );
        assert_eq!(over.wanted, over.batches * u64::from(EACH));
        // The receptions MLAT never uses count against nothing.
        assert_eq!(kept(&unwanted_feeder), BATCHES);
        Ok(())
    }

    /// A session starts with `ingest::SESSION_BURST` of its role's burst and the
    /// rest only as its network group is granted it (`ingest::BurstGrants`), and the grant is kept
    /// by group across its sessions: a subscriber that reconnects at once finds its group's grants
    /// spent, so its new session holds no evidence's worth of burst. Before, every connection
    /// started with its role's whole burst (136 tokens), however often its peer dialled.
    #[tokio::test(start_paused = true)]
    async fn a_reconnecting_subscriber_does_not_refill_its_burst() -> Result<(), String> {
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY);
        let pace = crate::ingest::SUBSCRIBER_RECORDS;
        let group = Some(std::net::IpAddr::from([198, 51, 100, 7]));
        let neighbour = Some(std::net::IpAddr::from([198, 51, 9, 9]));
        let elsewhere = Some(std::net::IpAddr::from([203, 0, 113, 7]));
        let held = |paces: &Paces| paces.own.as_ref().map_or(0, |own| own.available());
        let mut sessions = 0;
        let mut granted = 0;
        loop {
            let paces = Paces::of(&hub, Peer::Subscriber, group)?;
            sessions += 1;
            let holds = held(&paces);
            if holds < pace.burst {
                // Past the group's grants: the base alone (the grants were whole bundles).
                assert_eq!(holds, crate::ingest::SESSION_BURST);
                break;
            }
            granted += holds - crate::ingest::SESSION_BURST;
            assert!(sessions < 100, "every reconnect refilled its burst");
        }
        assert_eq!(
            granted,
            crate::ingest::GROUP_BURST_GRANTS.burst / (pace.burst - crate::ingest::SESSION_BURST)
                * (pace.burst - crate::ingest::SESSION_BURST)
        );
        // Spent: the next session from that group starts with the base alone, and so does one from
        // another address in the same network.
        assert_eq!(
            held(&Paces::of(&hub, Peer::Subscriber, group)?),
            crate::ingest::SESSION_BURST
        );
        assert_eq!(
            held(&Paces::of(&hub, Peer::Subscriber, neighbour)?),
            crate::ingest::SESSION_BURST
        );
        // Another network's subscriber still has its whole burst.
        assert_eq!(
            held(&Paces::of(&hub, Peer::Subscriber, elsewhere)?),
            pace.burst
        );
        // A probe's whole burst is the base: it never waits on a grant.
        assert_eq!(
            held(&Paces::of(&hub, Peer::Probe, group)?),
            crate::ingest::PROBE_RECORDS.burst
        );
        // The group's grants come back at their rate: a minute later, two bundles' worth.
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(held(&Paces::of(&hub, Peer::Subscriber, group)?), pace.burst);
        assert_eq!(
            Paces::of(&hub, Peer::Subscriber, None)?
                .own
                .as_ref()
                .map(|own| own.per_minute_rate()),
            Some(pace.per_minute)
        );
        Ok(())
    }

    /// A session's own pace is charged to the paces' store what it allocates, read from the
    /// allocator, with its group's grant beside it (`ingest::BurstGrants`), and given back when
    /// the session ends; a relay's session, whose paces are shared, is charged nothing of its own.
    /// Before, a connection's pace state was charged to no store.
    #[tokio::test(start_paused = true)]
    async fn a_sessions_own_pace_is_charged_what_it_allocates() -> Result<(), String> {
        use tally_counting::Counting;
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY);
        let store = hub.budget().gauge(crate::budget::Store::Paces);
        let address = Some(std::net::IpAddr::from([198, 51, 100, 7]));
        let before = store.held();
        let base = Counting::live();
        let paces = Paces::of(&hub, Peer::Subscriber, address)?;
        let charged = store.held() - before;
        assert_eq!(Counting::since(base), charged as isize);
        assert!(charged >= crate::ingest::OWN_PACE_BYTES);
        assert!(charged <= crate::ingest::PACE_BYTES_PER_CONNECTION);
        // The session gone, its own pace goes; its group's grant, spent, is kept for its next.
        drop(paces);
        assert_eq!(
            store.held() - before,
            charged - crate::ingest::OWN_PACE_BYTES
        );
        assert_eq!(Counting::since(base), (store.held() - before) as isize);
        let relay = Paces::of(&hub, Peer::Relay, address)?;
        assert_eq!(Counting::since(base), (store.held() - before) as isize);
        assert_eq!(
            store.held() - before,
            charged - crate::ingest::OWN_PACE_BYTES
        );
        drop(relay);
        Ok(())
    }

    /// Every directory link's group has its own share of the directory's rate,
    /// kept across its links: a link that owes for its evidence (`credit::check`) waits on its own
    /// group's share alone, and its debt outlives its session, so its group's next link pays it;
    /// another group's link is let in at once. Before, every link shared one pace: one link's
    /// bundles owed 128 tokens each to it, so one hostile link held every other link's gossip back,
    /// and kept doing so after it hung up.
    #[tokio::test(start_paused = true)]
    async fn a_directory_links_debt_is_its_groups_alone_and_outlives_its_session()
    -> Result<(), String> {
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY);
        let hostile = Some(std::net::IpAddr::from([198, 51, 100, 7]));
        let honest = Some(std::net::IpAddr::from([203, 0, 113, 7]));
        let paces = hub.directory_records();
        let rate = crate::ingest::DIRECTORY_RECORDS.per_minute;
        let key = Identity::generate().map_err(text)?.public();
        let started = Instant::now();
        {
            let link = Paces::of(&hub, Peer::Relay, hostile)?;
            let pace = link
                .take(&hub, Peer::Relay, &key)
                .await
                .ok_or("a directory link is paced")?;
            // An hour of its share owed at once, as a flood of bundles would owe it.
            pace.owe(rate * 60);
            assert_eq!(paces.groups_linked(), 1);
            // Another network's link is let in at once, its share whole.
            let other = Paces::of(&hub, Peer::Relay, honest)?;
            for _ in 0..100 {
                other.take(&hub, Peer::Relay, &key).await;
            }
            assert_eq!(started.elapsed(), Duration::ZERO);
            assert_eq!(paces.groups_linked(), 2);
        }
        // Both hung up: each group's pace is held while it has not refilled (the indebted one
        // owing an hour), so a reconnect finds it as it was.
        assert_eq!((paces.groups_linked(), paces.groups_held()), (0, 2));
        // The hostile group's next link pays its debt; a new honest link waits for nothing.
        let honest_again = Paces::of(&hub, Peer::Relay, honest)?;
        honest_again.take(&hub, Peer::Relay, &key).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        let hostile_again = Paces::of(&hub, Peer::Relay, hostile)?;
        hostile_again.take(&hub, Peer::Relay, &key).await;
        assert!(
            started.elapsed() >= Duration::from_secs(60 * 60),
            "the debt was forgiven after {:?}",
            started.elapsed()
        );
        Ok(())
    }
}
