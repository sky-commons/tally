//! What a relay sends: the one place every byte it writes is counted and paced to the operator's
//! upload cap, and the fixed priorities that decide whose bytes go first (RFC-0171 §3.6: taking
//! data in costs a relay only its server; what it sends out is billed, so it is capped).
//!
//! A speed cap bounds the bill as hard as a monthly budget does (a relay can never send more than
//! the cap times the seconds in a month) and never goes dark: when more is asked for than the cap
//! carries, lower-priority traffic goes slower, and the peers that cost the most and forward
//! nothing are shed. The rules, decided here and nowhere else:
//!
//! - **Counted and capped at the socket.** Every stream the relay writes to is a [`Socket`], and a
//!   `Socket` counts each byte its inner stream accepts and lets none through that the cap has not
//!   paid for: handshakes, greetings, heartbeats, goodbyes, redirects and every record, on every
//!   role's connection, the upstream links, beast-out and the stats listener. A connection cannot
//!   be served without one ([`crate::link::inbound`] takes a `Socket`), so no path writes around
//!   the cap. A peer on loopback is counted apart (`loopback_bytes`) and never capped: those bytes
//!   never leave the host, so no bill counts them. Every other peer is billed, a private address
//!   included. With no cap (`Cap::NONE`), a billed write fails: nothing billed may leave.
//! - **One bucket.** The cap fills one token bucket of [`Cap::bucket`] bytes (a second of the cap,
//!   at least `MIN_BUCKET`); every billed byte written is taken from it. Over any window of `t`,
//!   the relay sends at most the bucket plus the cap times `t` ([`Cap::most_in`]).
//! - **Strict priority classes** ([`Class`]), each record classified once, when its link gathers
//!   it ([`Class::of`]), highest first: control, positions and clock models, raw to relay links
//!   and engines, the rest of what relay links and engines are sent, provisional positions, and
//!   plain subscribers. A data record waits for a grant from the bucket ([`Egress::grant`]); a
//!   class is granted nothing while a higher class waits, so lower classes get what higher ones
//!   leave. Control is never queued: it is what a socket writes beyond its link's grants, and it
//!   may draw the last [`Cap::reserve`] bytes of the bucket, which data never touches, so it always
//!   gets through.
//! - **Fair within a class.** Grants within a class go by start-time fair queuing per peer, in
//!   quanta of at most `GRANT_QUANTUM`, so one peer's large send never holds up another's.
//! - **Shed, lowest class first.** Once a grant has waited `SHED_AFTER`, one waiting peer is shed
//!   every `SHED_EVERY`: from the lowest class anyone waits in, the one asking the most of it (by
//!   bytes asked for over `RATE_WINDOW`). Plain subscribers are the lowest class, so a peer that
//!   forwards (a relay link, an engine) is never shed while a plain subscriber waits. The old rule,
//!   the most bytes sent, picked the subscriber forwarding to everyone else.
//! - **Admission.** A new feeder is accepted only while the cap's headroom (the cap less what
//!   control and the forwarding classes ask for) covers what it commits the relay to forward
//!   ([`Egress::admit_feeder`]); past that it is turned away, never accepted for data the relay
//!   cannot deliver.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tally_wire::Record;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::time::{Instant, Sleep};

/// The bucket holds this long of the cap: after a quiet moment, this much may go at once.
pub const BURST: Duration = Duration::from_secs(1);

/// The smallest bucket, so a send of the largest grant fits under a small cap.
pub const MIN_BUCKET: u64 = 64 * 1024;

/// The share of the bucket only control may draw: data stops short of it.
pub const CONTROL_RESERVE_PERCENT: u64 = 2;

/// The least control reserve, whatever the cap: a handshake and a goodbye with room to spare.
pub const MIN_CONTROL_RESERVE: u64 = 4 * 1024;

/// The most one grant gives a peer at a time, so peers in one class take turns.
pub const GRANT_QUANTUM: u64 = 16 * 1024;

/// The most spare feeder slots counted one by one: more than any relay's cap carries.
const MAX_COUNTED_SLOTS: u32 = 1 << 20;

/// How long a grant may wait before the peers waiting may be shed.
pub const SHED_AFTER: Duration = Duration::from_secs(2);

/// The least time between two peers shed, so one shed shows before the next.
pub const SHED_EVERY: Duration = Duration::from_millis(250);

/// The window the rates are measured over (an exponential average with this time constant).
pub const RATE_WINDOW: Duration = Duration::from_secs(10);

/// What one feeder commits the relay to forward to each relay link and engine, before its own
/// rate is known: 100 kbps, the top of RFC-0171 §5's per-feeder upload (box-01 measured 64 kbps).
pub const FEEDER_COMMITMENT_BYTES_PER_SEC: u64 = 12_500;

/// The longest month, which a monthly bound is stated for.
pub const SECONDS_A_MONTH: u64 = 31 * 86_400;

/// The least control a starved socket waits for at once.
const CONTROL_STEP: u64 = 256;

/// Tokens are kept in billionths of a byte, so a refill of any cap over any interval is exact.
const SCALE: u128 = 1_000_000_000;

/// The most the relay may send a second to billed peers (`--max-upload`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    bytes_per_sec: u64,
}

impl Cap {
    /// Nothing billed may leave: what a hub has until the operator names a cap. Loopback peers are
    /// still served.
    pub const NONE: Self = Self { bytes_per_sec: 0 };

    pub const fn bytes_per_sec(bytes_per_sec: u64) -> Self {
        Self { bytes_per_sec }
    }

    pub const fn rate(self) -> u64 {
        self.bytes_per_sec
    }

    pub const fn is_none(self) -> bool {
        self.bytes_per_sec == 0
    }

    /// What the bucket holds when full.
    pub fn bucket(self) -> u64 {
        if self.is_none() {
            return 0;
        }
        let burst = u128::from(self.bytes_per_sec) * BURST.as_nanos() / SCALE;
        u64::try_from(burst).unwrap_or(u64::MAX).max(MIN_BUCKET)
    }

    /// The bottom of the bucket, which only control draws.
    pub fn reserve(self) -> u64 {
        if self.is_none() {
            return 0;
        }
        (self.bucket() / 100 * CONTROL_RESERVE_PERCENT).max(MIN_CONTROL_RESERVE)
    }

    /// The most the relay can send to billed peers over any window of `window`: the bucket and
    /// the cap times the window.
    pub fn most_in(self, window: Duration) -> u64 {
        let refilled = u128::from(self.bytes_per_sec) * window.as_nanos() / SCALE;
        u64::try_from(refilled)
            .unwrap_or(u64::MAX)
            .saturating_add(self.bucket())
    }

    /// The most a month (of 31 days) can bill.
    pub fn most_a_month(self) -> u64 {
        self.most_in(Duration::from_secs(SECONDS_A_MONTH))
    }

    /// A rate as `--max-upload` takes it: `10Mbit/s`, `2MB/s`, `500kbit/s`, `1.5Gbit/s`, or the
    /// binary `KiB/s`, `MiB/s` and `GiB/s`. `kB`, `MB` and `GB` (and the bit units) are decimal,
    /// as hosts and links state them. `0` (with a unit) is no cap: nothing billed leaves.
    pub fn parse(text: &str) -> Result<Self, String> {
        let wrong = || {
            format!(
                "--max-upload {text}: expected a rate such as 10Mbit/s or 2MB/s (kbit, Mbit, \
                 Gbit, kB, MB, GB, KiB, MiB or GiB, a second)"
            )
        };
        let amount = text.strip_suffix("/s").ok_or_else(wrong)?;
        let split = amount
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .ok_or_else(wrong)?;
        let (number, unit) = amount.split_at(split);
        // Bits a second scale to bytes by an eighth.
        let (scale, eighths): (u128, bool) = match unit {
            "kbit" => (1_000, true),
            "Mbit" => (1_000_000, true),
            "Gbit" => (1_000_000_000, true),
            "kB" | "KB" => (1_000, false),
            "MB" => (1_000_000, false),
            "GB" => (1_000_000_000, false),
            "KiB" => (1 << 10, false),
            "MiB" => (1 << 20, false),
            "GiB" => (1 << 30, false),
            _ => return Err(wrong()),
        };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() || fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Err(wrong());
        }
        let whole: u128 = whole.parse().map_err(|_| wrong())?;
        let thousandths: u128 = format!("{fraction:0<3}").parse().map_err(|_| wrong())?;
        let divisor = if eighths { 8_000 } else { 1_000 };
        let bytes = (whole * 1000 + thousandths)
            .checked_mul(scale)
            .map(|scaled| scaled / divisor)
            .ok_or_else(wrong)?;
        u64::try_from(bytes)
            .map(Self::bytes_per_sec)
            .map_err(|_| wrong())
    }
}

/// A count of bytes as a person reads a bill: decimal, to two places, rounded up, since every figure
/// it prints is a ceiling (what a cap allows at most) and must never read lower than the truth.
pub fn decimal(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "kB"),
    ];
    for (size, unit) in UNITS {
        if bytes >= size {
            let hundredths = (u128::from(bytes) * 100).div_ceil(u128::from(size));
            return format!("{}.{:02} {unit}", hundredths / 100, hundredths % 100);
        }
    }
    format!("{bytes} B")
}

/// What a byte is for, highest priority first. A class is granted nothing while a higher one
/// waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Handshakes, greetings (`RateLimit`, `RelayList`), heartbeats, `Goodbye` and `Redirect`:
    /// what keeps every session alive. Never queued; it draws the bucket's reserve.
    Control,
    /// Positions, clock models (and their parts) and fault proofs to a relay link or an engine:
    /// what this relay's engines originate and the final positions and models it forwards.
    Positions,
    /// Raw batches, with the receiver descriptions they travel with, to a relay link or an engine:
    /// the border raw MLAT needs.
    Raw,
    /// The rest of what a peer that forwards is sent: the deduplicated stream.
    Forwarded,
    /// Provisional positions to a relay link (`Record::Provisional`): below the final positions
    /// and the raw they are solved from, since a final one follows each, and above plain
    /// subscribers.
    Provisional,
    /// Everything a plain subscriber (or a beast-out client) is sent: it takes and forwards
    /// nothing. The only class shed heaviest first while anything waits in it.
    Taker,
}

impl Class {
    /// Every class, highest first.
    pub const ALL: [Self; 6] = [
        Self::Control,
        Self::Positions,
        Self::Raw,
        Self::Forwarded,
        Self::Provisional,
        Self::Taker,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// The class of `record` sent to a peer of `kind`: decided here, once, as the link gathers it.
    pub fn of(record: &Record, kind: Kind) -> Self {
        Self::of_kind(record.kind(), kind)
    }

    /// The class of a record of kind `record` (its kind byte, `tally_wire::record::KINDS`) sent to
    /// a peer of `kind`: the one table of every kind's priority (RFC-0171 §3.6, RFC-0174 §2.10).
    ///
    /// - **Control** keeps sessions and the network's duties running: the session's own records,
    ///   the measurements and delivery checks, the directory's queries, a sharing tree's
    ///   assignments, have-summaries and receipts (each a few bytes, and what repairs and credit
    ///   wait on), and a client's credential. Every role is sent it first.
    /// - To a peer that forwards (a relay or an engine), data by what MLAT needs first: positions,
    ///   clock models and fault proofs; then raw and the descriptions it travels with; then
    ///   everything else that is shared (the deduplicated stream, the directory's offers and
    ///   evidence, a group's piece manifests and parity, the products); then provisional
    ///   positions, which a final one follows.
    /// - To any other peer, data is a taker's: it forwards nothing. Offers and evidence are
    ///   control to it, as the answer to what it asked (a feeder's query, a client's vouching).
    pub fn of_kind(record: u8, kind: Kind) -> Self {
        use tally_wire::record::{
            KIND_BATCH, KIND_BUNDLE_INDEX, KIND_CLOCK_MODEL, KIND_CLOCK_MODEL_PART,
            KIND_DELIVERY_ANSWER, KIND_DELIVERY_QUERY, KIND_ECHO, KIND_ECHO_REPLY,
            KIND_EVIDENCE_BUNDLE, KIND_FAULT_PROOF, KIND_FIREHOSE_CREDENTIAL, KIND_GOODBYE,
            KIND_HAVE_SUMMARY, KIND_HEARTBEAT, KIND_HELLO, KIND_PARITY, KIND_PIECE_MANIFEST,
            KIND_POSITIONS, KIND_PROVIDER_OFFER, KIND_PROVIDER_QUERY, KIND_PROVISIONAL,
            KIND_RATE_LIMIT, KIND_RECEIVER_INFO, KIND_REDIRECT, KIND_REGIONAL_BATCH,
            KIND_RELAY_BATCH, KIND_RELAY_LIST, KIND_STRIPE_ASSIGNMENT, KIND_STRIPE_RECEIPT,
            KIND_SUBSCRIBE, KIND_WELCOME, KIND_WORLD_POSITIONS, KIND_WORLD_PRECISE,
        };
        let forwards = kind.forwards();
        match record {
            KIND_HELLO
            | KIND_WELCOME
            | KIND_HEARTBEAT
            | KIND_REDIRECT
            | KIND_RELAY_LIST
            | KIND_RATE_LIMIT
            | KIND_GOODBYE
            | KIND_SUBSCRIBE
            | KIND_ECHO
            | KIND_ECHO_REPLY
            | KIND_DELIVERY_QUERY
            | KIND_DELIVERY_ANSWER
            | KIND_PROVIDER_QUERY
            | KIND_STRIPE_ASSIGNMENT
            | KIND_HAVE_SUMMARY
            | KIND_STRIPE_RECEIPT
            | KIND_FIREHOSE_CREDENTIAL => Self::Control,
            KIND_PROVIDER_OFFER | KIND_EVIDENCE_BUNDLE if !forwards => Self::Control,
            _ if !forwards => Self::Taker,
            KIND_POSITIONS | KIND_CLOCK_MODEL | KIND_CLOCK_MODEL_PART | KIND_FAULT_PROOF => {
                Self::Positions
            }
            KIND_BATCH | KIND_RECEIVER_INFO => Self::Raw,
            KIND_PROVISIONAL => Self::Provisional,
            KIND_RELAY_BATCH | KIND_PROVIDER_OFFER | KIND_EVIDENCE_BUNDLE | KIND_PIECE_MANIFEST
            | KIND_PARITY | KIND_REGIONAL_BATCH | KIND_BUNDLE_INDEX | KIND_WORLD_POSITIONS
            | KIND_WORLD_PRECISE => Self::Forwarded,
            // A kind this build does not know is never sent; were it, it would wait with the
            // rest of what is shared.
            _ => Self::Forwarded,
        }
    }
}

/// Who a link is to, as the pacer sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Not yet known: the handshake is under way.
    Unknown,
    /// Publishes, and is sent only control.
    Feeder,
    /// Another relay, dialled in or dialled out: forwards what it is sent.
    Relay,
    /// An MLAT engine: another relay's MLAT taking an area's raw one hop, which it turns into
    /// positions its relay shares (RFC-0174 §2.3).
    Engine,
    /// A plain subscriber or a beast-out client: takes and forwards nothing.
    Taker,
    /// A measurement session (`Role::Probe`): sent only its answers, which are control, and never
    /// counted as a feeder.
    Probe,
}

impl Kind {
    /// A relay link or an engine: what it is sent comes back to the network.
    pub const fn forwards(self) -> bool {
        matches!(self, Self::Relay | Self::Engine)
    }

    const fn from_u8(byte: u8) -> Self {
        match byte {
            1 => Self::Feeder,
            2 => Self::Relay,
            3 => Self::Engine,
            4 => Self::Taker,
            5 => Self::Probe,
            _ => Self::Unknown,
        }
    }
}

/// One connection: what it has cost, what it has been granted, and whether it is shed.
pub struct Link {
    id: u64,
    billed: bool,
    kind: AtomicU8,
    /// Billed bytes written to it.
    sent: AtomicU64,
    /// Bytes granted to it and not yet written.
    credit: AtomicU64,
    shed: AtomicBool,
    wake: Notify,
}

impl Link {
    fn new(id: u64, billed: bool) -> Self {
        Self {
            id,
            billed,
            kind: AtomicU8::new(Kind::Unknown as u8),
            sent: AtomicU64::new(0),
            credit: AtomicU64::new(0),
            shed: AtomicBool::new(false),
            wake: Notify::new(),
        }
    }

    pub fn billed(&self) -> bool {
        self.billed
    }

    pub fn kind(&self) -> Kind {
        Kind::from_u8(self.kind.load(Ordering::Acquire))
    }

    /// Who this link is to, once its handshake says.
    pub fn set_kind(&self, kind: Kind) {
        self.kind.store(kind as u8, Ordering::Release);
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn is_shed(&self) -> bool {
        self.shed.load(Ordering::Acquire)
    }

    /// Resolves once this link has been shed.
    pub async fn shed(&self) {
        loop {
            let woken = self.wake.notified();
            if self.is_shed() {
                return;
            }
            woken.await;
        }
    }
}

/// A grant refused: the link was shed while it waited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shed;

/// A rate: an exponential average of bytes a second over `RATE_WINDOW`.
#[derive(Clone, Copy, Debug, Default)]
struct Rate {
    per_sec: f64,
    at: Option<Instant>,
}

impl Rate {
    fn at(&self, now: Instant) -> f64 {
        match self.at {
            Some(at) => {
                let elapsed = now.saturating_duration_since(at).as_secs_f64();
                self.per_sec * (-elapsed / RATE_WINDOW.as_secs_f64()).exp()
            }
            None => 0.0,
        }
    }

    fn add(&mut self, now: Instant, bytes: u64) {
        self.per_sec = self.at(now) + bytes as f64 / RATE_WINDOW.as_secs_f64();
        self.at = Some(now);
    }
}

/// A data send waiting for its grant.
struct Waiter {
    ticket: u64,
    link: Arc<Link>,
    remaining: u64,
    /// Its start tag in its class's fair queue.
    start: u64,
    since: Instant,
    done: Option<oneshot::Sender<()>>,
}

/// One class's queue and what it has carried.
#[derive(Default)]
struct Lane {
    /// The start tag of the last grant: where a peer that was idle starts again.
    virtual_time: u64,
    waiting: Vec<Waiter>,
    granted: Rate,
    asked: Rate,
    shed: u64,
}

/// What the pacer keeps of one peer, by class.
#[derive(Default)]
struct Peer {
    /// Each class's finish tag: where this peer's next send in that class starts.
    finish: [u64; 6],
    asked: [Rate; 6],
}

/// The bucket and the queues: every decision about whose bytes go when, at an instant the caller
/// names, so it is tested without a clock.
struct Pacer {
    cap: Cap,
    /// Tokens, in billionths of a byte, at most the bucket.
    level: u128,
    refilled: Instant,
    lanes: [Lane; 6],
    peers: HashMap<u64, Peer>,
    last_shed: Option<Instant>,
    next_ticket: u64,
}

impl Pacer {
    fn new(cap: Cap, now: Instant) -> Self {
        Self {
            cap,
            level: u128::from(cap.bucket()) * SCALE,
            refilled: now,
            lanes: Default::default(),
            peers: HashMap::new(),
            last_shed: None,
            next_ticket: 0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled).as_nanos();
        let full = u128::from(self.cap.bucket()) * SCALE;
        self.level = self
            .level
            .saturating_add(elapsed.saturating_mul(u128::from(self.cap.rate())))
            .min(full);
        self.refilled = self.refilled.max(now);
    }

    /// Whole bytes in the bucket.
    fn bytes(&self) -> u64 {
        u64::try_from(self.level / SCALE).unwrap_or(u64::MAX)
    }

    /// When the bucket will hold `bytes`.
    fn when_holding(&self, bytes: u64) -> Instant {
        let target = u128::from(bytes) * SCALE;
        if self.level >= target || self.cap.is_none() {
            return self.refilled;
        }
        let nanos = (target - self.level).div_ceil(u128::from(self.cap.rate()));
        self.refilled + Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    fn take(&mut self, bytes: u64) {
        self.level = self.level.saturating_sub(u128::from(bytes) * SCALE);
    }

    /// Queues `bytes` of data for `link` in `class`, telling `done` when all are granted.
    fn ask(
        &mut self,
        now: Instant,
        link: Arc<Link>,
        class: Class,
        bytes: u64,
        done: oneshot::Sender<()>,
    ) -> u64 {
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        let lane = &mut self.lanes[class.index()];
        let peer = self.peers.entry(link.id).or_default();
        peer.asked[class.index()].add(now, bytes);
        lane.asked.add(now, bytes);
        let start = lane.virtual_time.max(peer.finish[class.index()]);
        lane.waiting.push(Waiter {
            ticket,
            link,
            remaining: bytes,
            start,
            since: now,
            done: Some(done),
        });
        ticket
    }

    /// Takes a send off its queue (it was granted, cancelled or shed).
    fn cancel(&mut self, ticket: u64) {
        for lane in &mut self.lanes {
            lane.waiting.retain(|waiter| waiter.ticket != ticket);
        }
    }

    /// The highest class anyone waits in.
    fn highest_waiting(&self) -> Option<Class> {
        Class::ALL
            .into_iter()
            .find(|class| !self.lanes[class.index()].waiting.is_empty())
    }

    /// The next waiter of `class` by fair queuing: the least start tag, the oldest on a tie.
    fn head(&self, class: Class) -> Option<usize> {
        self.lanes[class.index()]
            .waiting
            .iter()
            .enumerate()
            .min_by_key(|(_, waiter)| (waiter.start, waiter.ticket))
            .map(|(at, _)| at)
    }

    /// What the head of the highest class needs before its next grant.
    fn head_needs(&self) -> Option<u64> {
        let class = self.highest_waiting()?;
        let at = self.head(class)?;
        Some(
            self.lanes[class.index()].waiting[at]
                .remaining
                .min(GRANT_QUANTUM),
        )
    }

    /// Grants what the bucket holds above the reserve: to the highest class waiting, in turn
    /// within it, a quantum at a time. A class waits while a higher one does.
    fn dispatch(&mut self, now: Instant) {
        self.refill(now);
        let reserve = self.cap.reserve();
        while let Some(class) = self.highest_waiting() {
            let Some(at) = self.head(class) else {
                break;
            };
            let available = self.bytes().saturating_sub(reserve);
            let lane = &mut self.lanes[class.index()];
            let waiter = &mut lane.waiting[at];
            let give = waiter.remaining.min(GRANT_QUANTUM);
            if available < give {
                break;
            }
            waiter.remaining -= give;
            waiter.link.credit.fetch_add(give, Ordering::AcqRel);
            lane.virtual_time = waiter.start;
            waiter.start += give;
            let finish = waiter.start;
            let link = waiter.link.id;
            let complete = waiter.remaining == 0;
            lane.granted.add(now, give);
            if complete {
                let mut waiter = lane.waiting.swap_remove(at);
                if let Some(done) = waiter.done.take() {
                    let _ = done.send(());
                }
            }
            self.peers.entry(link).or_default().finish[class.index()] = finish;
            self.take(give);
        }
    }

    /// One waiting peer to shed, if a grant has waited `SHED_AFTER` and none was shed in the last
    /// `SHED_EVERY`: from the lowest class anyone waits in, the one asking most of it.
    fn shed_at(&mut self, now: Instant) -> Option<Arc<Link>> {
        let oldest = self
            .lanes
            .iter()
            .flat_map(|lane| lane.waiting.iter().map(|waiter| waiter.since))
            .min()?;
        if now.saturating_duration_since(oldest) < SHED_AFTER {
            return None;
        }
        if self
            .last_shed
            .is_some_and(|last| now.saturating_duration_since(last) < SHED_EVERY)
        {
            return None;
        }
        let class = Class::ALL
            .into_iter()
            .rev()
            .find(|class| !self.lanes[class.index()].waiting.is_empty())?;
        let peers = &self.peers;
        let lane = &mut self.lanes[class.index()];
        let asking = |waiter: &Waiter| {
            peers
                .get(&waiter.link.id)
                .map_or(0.0, |peer| peer.asked[class.index()].at(now))
        };
        let at = lane
            .waiting
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                asking(a)
                    .total_cmp(&asking(b))
                    .then(b.ticket.cmp(&a.ticket))
            })
            .map(|(at, _)| at)?;
        let waiter = lane.waiting.swap_remove(at);
        lane.shed += 1;
        self.last_shed = Some(now);
        self.peers.remove(&waiter.link.id);
        // Its `done` is dropped with it: the send it waited for learns it was shed.
        Some(waiter.link)
    }

    /// When the pacer next has something to do: grant the head, or shed.
    fn next_at(&self) -> Option<Instant> {
        let grant = self
            .head_needs()
            .map(|needs| self.when_holding(needs + self.cap.reserve()));
        let oldest = self
            .lanes
            .iter()
            .flat_map(|lane| lane.waiting.iter().map(|waiter| waiter.since))
            .min();
        let shed = oldest.map(|oldest| {
            let after = oldest + SHED_AFTER;
            self.last_shed
                .map_or(after, |last| after.max(last + SHED_EVERY))
        });
        match (grant, shed) {
            (Some(grant), Some(shed)) => Some(grant.min(shed)),
            (grant, shed) => grant.or(shed),
        }
    }

    /// Takes up to `want` bytes for control, down to the bucket's bottom: what is taken.
    fn take_control(&mut self, now: Instant, want: u64) -> u64 {
        self.refill(now);
        let taken = want.min(self.bytes());
        self.take(taken);
        if taken > 0 {
            self.lanes[Class::Control.index()].granted.add(now, taken);
            self.lanes[Class::Control.index()].asked.add(now, taken);
        }
        taken
    }

    /// Gives back control bytes taken and not written.
    fn give_back(&mut self, bytes: u64) {
        let full = u128::from(self.cap.bucket()) * SCALE;
        self.level = (self.level + u128::from(bytes) * SCALE).min(full);
    }

    /// The forwarding classes' and control's demand, in bytes a second.
    fn committed(&self, now: Instant) -> f64 {
        [
            Class::Control,
            Class::Positions,
            Class::Raw,
            Class::Forwarded,
        ]
        .into_iter()
        .map(|class| self.lanes[class.index()].asked.at(now))
        .sum()
    }

    fn forget(&mut self, link: u64) {
        self.peers.remove(&link);
    }
}

/// One class as `GET /egress` reports it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassReport {
    pub class: Class,
    /// Granted (for control, written) over `RATE_WINDOW`, in bytes a second.
    pub bytes_per_sec: u64,
    /// Asked for over `RATE_WINDOW`, in bytes a second: above `bytes_per_sec` while it waits.
    pub asked_bytes_per_sec: u64,
    /// Sends waiting for a grant now, and their bytes not yet granted.
    pub waiting: u64,
    pub queued_bytes: u64,
    /// Peers shed from this class since the relay started.
    pub shed: u64,
}

/// The cap and what it carries, as `GET /egress` reports it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EgressReport {
    /// `--max-upload`, in bytes a second.
    pub max_upload_bytes_per_sec: u64,
    /// The most the cap lets out in a 31-day month.
    pub most_a_month_bytes: u64,
    /// Billed bytes sent since the relay started.
    pub billed_bytes: u64,
    /// Bytes sent to loopback peers since the relay started, which no bill counts.
    pub loopback_bytes: u64,
    /// What the cap has left after control and the forwarding classes, in bytes a second.
    pub headroom_bytes_per_sec: u64,
    /// Every class, highest first.
    pub classes: Vec<ClassReport>,
    /// Feeders turned away because the headroom did not cover them.
    pub refused_feeders: u64,
    /// Feeders admitted and connected now.
    pub feeders: u64,
}

/// The relay's egress: its cap, its pacer, and every link it writes to.
pub struct Egress {
    cap: Cap,
    pacer: Mutex<Pacer>,
    /// Wakes the pacing task: a send began waiting.
    wake: Arc<Notify>,
    pacing: AtomicBool,
    links: Mutex<HashMap<u64, Weak<Link>>>,
    next_link: AtomicU64,
    billed: AtomicU64,
    loopback: AtomicU64,
    feeders: AtomicUsize,
    refused_feeders: AtomicU64,
}

impl Egress {
    pub fn new(cap: Cap) -> Self {
        Self {
            cap,
            pacer: Mutex::new(Pacer::new(cap, Instant::now())),
            wake: Arc::new(Notify::new()),
            pacing: AtomicBool::new(false),
            links: Mutex::new(HashMap::new()),
            next_link: AtomicU64::new(0),
            billed: AtomicU64::new(0),
            loopback: AtomicU64::new(0),
            feeders: AtomicUsize::new(0),
            refused_feeders: AtomicU64::new(0),
        }
    }

    pub fn cap(&self) -> Cap {
        self.cap
    }

    /// Billed bytes sent since the relay started.
    pub fn billed(&self) -> u64 {
        self.billed.load(Ordering::Relaxed)
    }

    /// Bytes sent to loopback peers since the relay started.
    pub fn loopback(&self) -> u64 {
        self.loopback.load(Ordering::Relaxed)
    }

    /// `stream`, counted and capped: billed unless `peer` is a loopback address. A stream with no
    /// address (a pipe) is billed.
    pub fn socket<S>(self: &Arc<Self>, stream: S, peer: Option<IpAddr>) -> Socket<S> {
        let billed = !peer.is_some_and(|peer| peer.to_canonical().is_loopback());
        let link = Arc::new(Link::new(
            self.next_link.fetch_add(1, Ordering::Relaxed),
            billed,
        ));
        if let Ok(mut links) = self.links.lock() {
            links.retain(|_, link| link.strong_count() > 0);
            links.insert(link.id, Arc::downgrade(&link));
        }
        Socket {
            inner: stream,
            link,
            egress: Arc::clone(self),
            waiting: None,
        }
    }

    /// Waits until `bytes` of `class` data may go to `link`: at once for a loopback link, else
    /// once the pacer grants them. `Shed` when the link is shed first.
    pub async fn grant(
        self: &Arc<Self>,
        link: &Arc<Link>,
        class: Class,
        bytes: usize,
    ) -> Result<(), Shed> {
        if link.is_shed() {
            return Err(Shed);
        }
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        // Control is never queued, and with no cap the socket refuses whatever is billed.
        if !link.billed || class == Class::Control || bytes == 0 || self.cap.is_none() {
            return Ok(());
        }
        let (done, granted) = oneshot::channel();
        let ticket = {
            let Ok(mut pacer) = self.pacer.lock() else {
                return Ok(());
            };
            let now = Instant::now();
            let ticket = pacer.ask(now, Arc::clone(link), class, bytes, done);
            pacer.dispatch(now);
            ticket
        };
        let waiting = Waiting {
            egress: self,
            ticket,
        };
        self.start_pacing();
        self.wake.notify_one();
        let outcome = tokio::select! {
            granted = granted => granted.map_err(|_| Shed),
            () = link.shed() => Err(Shed),
        };
        drop(waiting);
        outcome
    }

    /// Starts the task that grants, sheds and wakes, once.
    fn start_pacing(self: &Arc<Self>) {
        if !self.pacing.swap(true, Ordering::AcqRel) {
            tokio::spawn(pace(Arc::downgrade(self), Arc::clone(&self.wake)));
        }
    }

    /// One look at the pacer: grants what the bucket holds, sheds if a send has waited too long,
    /// and says when to look again.
    fn tick(&self, now: Instant) -> Option<Instant> {
        let (shed, next) = {
            let Ok(mut pacer) = self.pacer.lock() else {
                return None;
            };
            pacer.dispatch(now);
            let shed = pacer.shed_at(now);
            if shed.is_some() {
                pacer.dispatch(now);
            }
            (shed, pacer.next_at())
        };
        if let Some(link) = shed {
            self.shed_link(&link);
        }
        next
    }

    /// Accepts a new feeder while the cap's headroom covers what it commits the relay to forward:
    /// `FEEDER_COMMITMENT_BYTES_PER_SEC` to each billed relay link and engine, or the feeders'
    /// average share of the raw asked for if more. The raw already committed is what is asked
    /// for, or what the feeders admitted commit, if more, so a feeder that has not yet sent much
    /// still holds its place. `None`, counted, when the headroom does not cover it.
    pub fn admit_feeder(self: &Arc<Self>) -> Option<Admitted> {
        let admitted = self.admits_feeder_at(Instant::now());
        if !admitted {
            self.refused_feeders.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.feeders.fetch_add(1, Ordering::AcqRel);
        Some(Admitted {
            egress: Arc::clone(self),
        })
    }

    fn admits_feeder_at(&self, now: Instant) -> bool {
        self.admits_after(now, 0)
    }

    /// Whether one more feeder would be taken with `more` feeders beyond those connected: the one
    /// rule `admit_feeder` applies and `feeder_slots` counts with.
    fn admits_after(&self, now: Instant, more: u32) -> bool {
        let forwarders = self.forwarders() as f64;
        if forwarders == 0.0 {
            // Nothing it sends is committed to anyone: plain subscribers are shed before they
            // cost it.
            return true;
        }
        let Ok(pacer) = self.pacer.lock() else {
            return true;
        };
        let feeders = self.feeders.load(Ordering::Acquire) as f64 + f64::from(more);
        let per_feeder = FEEDER_COMMITMENT_BYTES_PER_SEC as f64 * forwarders;
        let raw = pacer.lanes[Class::Raw.index()].asked.at(now);
        let others = pacer.committed(now) - raw;
        let committed = others + raw.max(feeders * per_feeder);
        let commitment = if feeders > 0.0 {
            (raw / feeders).max(per_feeder)
        } else {
            per_feeder
        };
        commitment <= self.cap.rate() as f64 - committed
    }

    /// How many more feeders `admit_feeder` would take now, one after another, by its own rule:
    /// what a relay declares as its spare feeder capacity (RFC-0174 §2.2). Unbounded
    /// (`u32::MAX`) while nothing the relay sends is committed to anyone.
    pub fn feeder_slots(&self) -> u32 {
        if self.forwarders() == 0 {
            return u32::MAX;
        }
        let now = Instant::now();
        let mut slots = 0;
        while slots < MAX_COUNTED_SLOTS && self.admits_after(now, slots) {
            slots += 1;
        }
        slots
    }

    /// Billed relay links and engines connected now.
    fn forwarders(&self) -> usize {
        self.links.lock().map_or(0, |links| {
            links
                .values()
                .filter_map(Weak::upgrade)
                .filter(|link| link.billed && link.kind().forwards() && !link.is_shed())
                .count()
        })
    }

    /// Counts `bytes` written to `link`.
    fn count(&self, link: &Link, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        if link.billed {
            self.billed.fetch_add(bytes, Ordering::Relaxed);
            link.sent.fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.loopback.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Ends `link` for the cap: whatever it waits on learns it was shed.
    pub(crate) fn shed_link(&self, link: &Link) {
        if !link.shed.swap(true, Ordering::AcqRel) {
            link.wake.notify_waiters();
        }
        if let Ok(mut pacer) = self.pacer.lock() {
            pacer.forget(link.id);
        }
    }

    pub fn report(&self) -> EgressReport {
        let now = Instant::now();
        let (classes, committed) = self.pacer.lock().map_or_else(
            |_| (Vec::new(), 0.0),
            |mut pacer| {
                pacer.refill(now);
                let classes = Class::ALL
                    .into_iter()
                    .map(|class| {
                        let lane = &pacer.lanes[class.index()];
                        ClassReport {
                            class,
                            bytes_per_sec: lane.granted.at(now) as u64,
                            asked_bytes_per_sec: lane.asked.at(now) as u64,
                            waiting: lane.waiting.len() as u64,
                            queued_bytes: lane.waiting.iter().map(|waiter| waiter.remaining).sum(),
                            shed: lane.shed,
                        }
                    })
                    .collect();
                (classes, pacer.committed(now))
            },
        );
        EgressReport {
            max_upload_bytes_per_sec: self.cap.rate(),
            most_a_month_bytes: self.cap.most_a_month(),
            billed_bytes: self.billed(),
            loopback_bytes: self.loopback(),
            headroom_bytes_per_sec: (self.cap.rate() as f64 - committed).max(0.0) as u64,
            classes,
            refused_feeders: self.refused_feeders.load(Ordering::Relaxed),
            feeders: self.feeders.load(Ordering::Acquire) as u64,
        }
    }
}

/// Grants and sheds for as long as the egress lives, waking when a send begins waiting or the
/// pacer next has something to do.
async fn pace(egress: Weak<Egress>, wake: Arc<Notify>) {
    loop {
        let next = match egress.upgrade() {
            Some(egress) => egress.tick(Instant::now()),
            None => return,
        };
        match next {
            Some(at) => {
                tokio::select! {
                    () = tokio::time::sleep_until(at) => {}
                    () = wake.notified() => {}
                }
            }
            None => wake.notified().await,
        }
    }
}

/// A send waiting for its grant: taken off the queue however the wait ends.
struct Waiting<'a> {
    egress: &'a Egress,
    ticket: u64,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Ok(mut pacer) = self.egress.pacer.lock() {
            pacer.cancel(self.ticket);
        }
    }
}

/// Held for as long as an admitted feeder is connected.
pub struct Admitted {
    egress: Arc<Egress>,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        self.egress.feeders.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A stream the relay writes to: every byte its inner stream accepts is counted, and a billed one
/// writes only what its link was granted or what the bucket's control reserve allows.
pub struct Socket<S> {
    inner: S,
    link: Arc<Link>,
    egress: Arc<Egress>,
    /// While the bucket is empty, when control may next be taken.
    waiting: Option<Pin<Box<Sleep>>>,
}

impl<S> Socket<S> {
    pub fn link(&self) -> Arc<Link> {
        Arc::clone(&self.link)
    }

    pub fn egress(&self) -> &Arc<Egress> {
        &self.egress
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Socket<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Socket<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.link.billed {
            let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
            if let Poll::Ready(Ok(written)) = polled {
                this.egress.count(&this.link, written);
            }
            return polled;
        }
        if this.egress.cap.is_none() {
            return Poll::Ready(Err(io::Error::other(
                "the relay has no --max-upload: nothing billed may leave",
            )));
        }
        let want = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let credit = this.link.credit.load(Ordering::Acquire).min(want);
        // Beyond its grants, a socket writes control, from the bucket down to its bottom.
        let control = if credit < want {
            let now = Instant::now();
            let Ok(mut pacer) = this.egress.pacer.lock() else {
                return Poll::Ready(Err(io::Error::other("the pacer failed")));
            };
            let taken = pacer.take_control(now, want - credit);
            if credit + taken == 0 {
                let at = pacer.when_holding(CONTROL_STEP.min(want));
                drop(pacer);
                let sleep = this
                    .waiting
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
                sleep.as_mut().reset(at);
                if sleep.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            taken
        } else {
            0
        };
        let allowed = usize::try_from(credit + control).unwrap_or(buf.len());
        let polled = Pin::new(&mut this.inner).poll_write(cx, &buf[..allowed]);
        let written = match &polled {
            Poll::Ready(Ok(written)) => u64::try_from(*written).unwrap_or(u64::MAX),
            _ => 0,
        };
        let from_credit = written.min(credit);
        this.link.credit.fetch_sub(from_credit, Ordering::AcqRel);
        let unused = control.saturating_sub(written - from_credit);
        if unused > 0
            && let Ok(mut pacer) = this.egress.pacer.lock()
        {
            pacer.give_back(unused);
        }
        if written > 0 {
            this.egress
                .count(&this.link, usize::try_from(written).unwrap_or(usize::MAX));
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

impl<S> Drop for Socket<S> {
    fn drop(&mut self) {
        if let Ok(mut pacer) = self.egress.pacer.lock() {
            pacer.forget(self.link.id);
        }
    }
}

/// A TCP listener whose every accepted stream is a [`Socket`]: what the stats endpoint serves on.
/// Bound to loopback, as it should be, nothing it writes is capped; on any other address its
/// responses are control, capped like any.
pub struct Listener {
    listener: TcpListener,
    egress: Arc<Egress>,
}

impl Listener {
    pub fn new(listener: TcpListener, egress: Arc<Egress>) -> Self {
        Self { listener, egress }
    }
}

impl axum::serve::Listener for Listener {
    type Io = Socket<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => return (self.egress.socket(stream, Some(peer.ip())), peer),
                Err(error) => {
                    eprintln!("tally-relay: stats accept: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    const MB: u64 = 1_000_000;

    fn link(id: u64) -> Arc<Link> {
        Arc::new(Link::new(id, true))
    }

    /// A send of `bytes` for `link` in `class`, and what learns of its grant.
    fn ask(
        pacer: &mut Pacer,
        now: Instant,
        link: &Arc<Link>,
        class: Class,
        bytes: u64,
    ) -> oneshot::Receiver<()> {
        let (done, granted) = oneshot::channel();
        pacer.ask(now, Arc::clone(link), class, bytes, done);
        granted
    }

    fn granted(receiver: &mut oneshot::Receiver<()>) -> bool {
        receiver.try_recv().is_ok()
    }

    /// Every kind this build knows, its class to a peer that forwards and to one that does not:
    /// one table, checked against the wire's own list of kinds, so a kind added there and not
    /// here fails.
    #[test]
    fn every_record_kind_has_its_priority_class() {
        use Class::{Control as C, Forwarded as F, Positions as P, Provisional as V, Raw as R};
        use tally_wire::record::KINDS;
        const T: Class = Class::Taker;
        let table: [(u8, &str, Class, Class); 33] = [
            (0x01, "Hello", C, C),
            (0x02, "Welcome", C, C),
            (0x03, "Batch", R, T),
            (0x04, "ReceiverInfo", R, T),
            (0x05, "Heartbeat", C, C),
            (0x06, "Redirect", C, C),
            (0x07, "RelayList", C, C),
            (0x08, "RateLimit", C, C),
            (0x09, "Goodbye", C, C),
            (0x0a, "Subscribe", C, C),
            (0x0b, "RelayBatch", F, T),
            (0x0c, "Positions", P, T),
            (0x0d, "ClockModel", P, T),
            (0x0e, "FaultProof", P, T),
            (0x0f, "ClockModelPart", P, T),
            (0x10, "Provisional", V, T),
            (0x11, "Echo", C, C),
            (0x12, "EchoReply", C, C),
            (0x13, "DeliveryQuery", C, C),
            (0x14, "DeliveryAnswer", C, C),
            (0x15, "ProviderOffer", F, C),
            (0x16, "ProviderQuery", C, C),
            (0x17, "StripeAssignment", C, C),
            // A group's pieces are its data, shared like the rest (RFC-0174 §2.5).
            (0x18, "PieceManifest", F, T),
            (0x19, "HaveSummary", C, C),
            (0x1a, "StripeReceipt", C, C),
            (0x1b, "FirehoseCredential", C, C),
            (0x1c, "EvidenceBundle", F, C),
            (0x1d, "WorldPositions", F, T),
            (0x1e, "RegionalBatch", F, T),
            (0x1f, "Parity", F, T),
            (0x20, "BundleIndex", F, T),
            (0x21, "WorldPrecise", F, T),
        ];
        let kinds: Vec<u8> = table.iter().map(|(kind, ..)| *kind).collect();
        assert_eq!(
            kinds,
            KINDS.to_vec(),
            "the table names every kind, in order"
        );
        for (kind, name, forwarding, other) in table {
            for peer in [Kind::Relay, Kind::Engine] {
                assert_eq!(Class::of_kind(kind, peer), forwarding, "{name} to {peer:?}");
            }
            for peer in [Kind::Feeder, Kind::Taker, Kind::Probe, Kind::Unknown] {
                assert_eq!(Class::of_kind(kind, peer), other, "{name} to {peer:?}");
            }
        }
    }

    #[test]
    fn a_rate_reads_in_the_units_hosts_and_links_state() -> Result<(), String> {
        assert_eq!(Cap::parse("10Mbit/s")?.rate(), 1_250_000);
        assert_eq!(Cap::parse("2MB/s")?.rate(), 2_000_000);
        assert_eq!(Cap::parse("500kbit/s")?.rate(), 62_500);
        assert_eq!(Cap::parse("1.5Gbit/s")?.rate(), 187_500_000);
        assert_eq!(Cap::parse("250kB/s")?.rate(), 250_000);
        assert_eq!(Cap::parse("1MiB/s")?.rate(), 1 << 20);
        assert_eq!(Cap::parse("0Mbit/s")?, Cap::NONE);
        for wrong in [
            "10Mbit",
            "10/s",
            "Mbit/s",
            "10Mbps",
            "10Tbit/s",
            "1.0001MB/s",
            "-1MB/s",
        ] {
            assert!(Cap::parse(wrong).is_err(), "{wrong} parsed");
        }
        Ok(())
    }

    #[test]
    fn the_cap_bounds_the_month() {
        // 10 Mbit/s for 31 days, and a second's burst: about 3.35 TB.
        let cap = Cap::bytes_per_sec(1_250_000);
        assert_eq!(cap.most_a_month(), 1_250_000 * SECONDS_A_MONTH + 1_250_000);
        assert_eq!(decimal(cap.most_a_month()), "3.35 TB");
        assert_eq!(decimal(1_250_000 * 30 * 86_400), "3.24 TB");
        assert_eq!(Cap::NONE.most_a_month(), 0);
        // A small cap still has room for the largest grant and the control reserve.
        let small = Cap::bytes_per_sec(1_000);
        assert_eq!(small.bucket(), MIN_BUCKET);
        assert!(small.bucket() - small.reserve() >= GRANT_QUANTUM);
    }

    #[test]
    fn the_cap_is_never_exceeded_over_any_window() {
        let cap = Cap::bytes_per_sec(MB);
        let start = Instant::now();
        let mut pacer = Pacer::new(cap, start);
        let links: Vec<Arc<Link>> = (0..4).map(link).collect();
        let mut asked = Vec::new();
        // Far more asked for than the cap carries, in every class, and control taken as it can.
        for (n, link) in links.iter().enumerate() {
            for class in [Class::Positions, Class::Raw, Class::Taker] {
                asked.push(ask(&mut pacer, start, link, class, 20 * MB + n as u64));
            }
        }
        // Every 10 ms for 30 s: what left, against the bound for every window ending now.
        let step = Duration::from_millis(10);
        let mut sent_at: Vec<(Instant, u64)> = vec![(start, 0)];
        let mut sent = 0;
        let mut now = start;
        for _ in 0..3_000 {
            now += step;
            pacer.dispatch(now);
            sent += pacer.take_control(now, 700);
            // What dispatch granted is the credit it handed out.
            let credit: u64 = links
                .iter()
                .map(|link| link.credit.swap(0, Ordering::AcqRel))
                .sum();
            sent += credit;
            for &(at, then) in &sent_at {
                assert!(
                    sent - then <= cap.most_in(now - at),
                    "{} bytes in {:?}",
                    sent - then,
                    now - at
                );
            }
            sent_at.push((now, sent));
        }
        // And the cap was used: within a bucket of its rate times the time.
        assert!(sent + cap.bucket() >= cap.rate() * 30, "only {sent} sent");
        drop(asked);
    }

    #[test]
    fn a_flood_of_plain_subscribers_never_delays_positions() {
        let cap = Cap::bytes_per_sec(MB);
        let start = Instant::now();
        let mut pacer = Pacer::new(cap, start);
        // Every subscriber asks for far more than the cap, before the engine's positions arrive.
        let subscribers: Vec<Arc<Link>> = (0..50).map(link).collect();
        let mut flood: Vec<_> = subscribers
            .iter()
            .map(|subscriber| ask(&mut pacer, start, subscriber, Class::Taker, 10 * MB))
            .collect();
        let relay = link(100);
        let mut now = start;
        for round in 0..100 {
            now += Duration::from_millis(100);
            let mut positions = ask(&mut pacer, now, &relay, Class::Positions, 8_000);
            // Granted the instant it is asked for, whatever waits below it: the bucket refilled
            // more than it needs since the last round.
            pacer.dispatch(now);
            assert!(granted(&mut positions), "round {round}: positions waited");
            assert!(pacer.lanes[Class::Positions.index()].waiting.is_empty());
        }
        // The subscribers had only what positions left.
        let taken: u64 = subscribers
            .iter()
            .map(|subscriber| subscriber.credit.load(Ordering::Acquire))
            .sum();
        assert!(taken <= cap.most_in(now - start) - 100 * 8_000);
        assert!(flood.iter_mut().all(|receiver| !granted(receiver)));
    }

    #[test]
    fn a_class_is_granted_nothing_while_a_higher_one_waits() {
        let cap = Cap::bytes_per_sec(MIN_BUCKET);
        let start = Instant::now();
        let mut pacer = Pacer::new(cap, start);
        // Drain the bucket to its reserve.
        pacer.take(cap.bucket() - cap.reserve());
        let subscriber = link(1);
        let relay = link(2);
        let mut taking = ask(&mut pacer, start, &subscriber, Class::Taker, 100);
        let mut raw = ask(&mut pacer, start, &relay, Class::Raw, 60_000);
        // Enough for the subscriber's 100 bytes, not for the relay's first quantum: nobody goes.
        let now = start + Duration::from_millis(100);
        pacer.dispatch(now);
        assert_eq!(subscriber.credit.load(Ordering::Acquire), 0);
        assert!(!granted(&mut taking));
        // Once the relay's raw is all granted, the subscriber's turn.
        let mut now = now;
        while !granted(&mut raw) {
            now += Duration::from_millis(100);
            pacer.dispatch(now);
        }
        pacer.dispatch(now + Duration::from_secs(1));
        assert!(granted(&mut taking));
    }

    #[test]
    fn peers_in_one_class_take_turns_by_bytes() {
        let cap = Cap::bytes_per_sec(MB);
        let start = Instant::now();
        let mut pacer = Pacer::new(cap, start);
        pacer.take(pacer.bytes() - cap.reserve());
        // One asks for a lot at once, two others for a little at a time, again and again.
        let heavy = link(1);
        let light = [link(2), link(3)];
        let _heavy = ask(&mut pacer, start, &heavy, Class::Raw, 100 * MB);
        let mut light_asks: Vec<_> = light
            .iter()
            .map(|light| ask(&mut pacer, start, light, Class::Raw, 4_000))
            .collect();
        let mut now = start;
        for _ in 0..1_000 {
            now += Duration::from_millis(10);
            pacer.dispatch(now);
            for (at, receiver) in light_asks.iter_mut().enumerate() {
                if granted(receiver) {
                    *receiver = ask(&mut pacer, now, &light[at], Class::Raw, 4_000);
                }
            }
        }
        // Each of the three had about a third: fair by bytes, not by sends.
        let shares: Vec<u64> = [&heavy, &light[0], &light[1]]
            .iter()
            .map(|link| link.credit.load(Ordering::Acquire))
            .collect();
        let total: u64 = shares.iter().sum();
        for share in &shares {
            let third = total / 3;
            assert!(
                share.abs_diff(third) <= third / 10 + GRANT_QUANTUM,
                "shares {shares:?}"
            );
        }
    }

    #[test]
    fn plain_subscribers_are_shed_first_and_the_heaviest_of_them_first() {
        let cap = Cap::bytes_per_sec(MB);
        let start = Instant::now();
        let mut pacer = Pacer::new(cap, start);
        pacer.take(pacer.bytes() - cap.reserve());
        // A relay link waiting for forwarding data, which forwards to everyone else, and has been
        // sent the most of anyone; two plain subscribers, one asking for far more.
        let relay = link(1);
        relay.sent.store(1_000 * MB, Ordering::Relaxed);
        let light = link(2);
        let heavy = link(3);
        let _forwarded = ask(&mut pacer, start, &relay, Class::Forwarded, 50 * MB);
        let _light = ask(&mut pacer, start, &light, Class::Taker, MB);
        let _heavy = ask(&mut pacer, start, &heavy, Class::Taker, 20 * MB);
        // Nobody before a grant has waited `SHED_AFTER`.
        assert!(pacer.shed_at(start + SHED_AFTER / 2).is_none());
        // Then the heaviest plain subscriber, and not again within `SHED_EVERY`.
        let at = start + SHED_AFTER;
        let first = pacer.shed_at(at).map(|link| link.id);
        assert_eq!(first, Some(heavy.id));
        assert!(pacer.shed_at(at + SHED_EVERY / 2).is_none());
        // Then the other plain subscriber; the relay link only once no taker waits.
        let second = pacer.shed_at(at + SHED_EVERY).map(|link| link.id);
        assert_eq!(second, Some(light.id));
        let third = pacer.shed_at(at + 2 * SHED_EVERY).map(|link| link.id);
        assert_eq!(third, Some(relay.id));
        assert_eq!(pacer.lanes[Class::Taker.index()].shed, 2);
        assert_eq!(pacer.lanes[Class::Forwarded.index()].shed, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_feeder_is_turned_away_once_the_headroom_does_not_cover_it() {
        let egress = Arc::new(Egress::new(Cap::bytes_per_sec(100_000)));
        // No relay link or engine: a feeder commits the relay to nothing.
        let unbound: Vec<_> = (0..10).map(|_| egress.admit_feeder()).collect();
        assert!(unbound.iter().all(Option::is_some));
        drop(unbound);
        // Two billed relay links: each feeder commits 25 kB/s of the 100 kB/s. A loopback engine
        // is not billed, and is owed nothing.
        let relays: Vec<Socket<()>> = (0..2).map(|_| egress.socket((), None)).collect();
        for relay in &relays {
            relay.link.set_kind(Kind::Relay);
        }
        let local = egress.socket((), Some(IpAddr::from([127, 0, 0, 1])));
        local.link.set_kind(Kind::Engine);
        let held: Vec<_> = (0..4).map(|_| egress.admit_feeder()).collect();
        assert!(held.iter().all(Option::is_some));
        assert!(egress.admit_feeder().is_none());
        // One leaves: room for one again.
        drop(held);
        // What is asked for counts when it is more than the feeders commit.
        if let Ok(mut pacer) = egress.pacer.lock() {
            pacer.lanes[Class::Raw.index()]
                .asked
                .add(Instant::now(), 800_000);
        }
        assert!(egress.admit_feeder().is_none());
        assert_eq!(egress.report().refused_feeders, 2);
        // The relay links leave: nothing is committed to anyone.
        drop(relays);
        assert!(egress.admit_feeder().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_billed_socket_writes_no_faster_than_the_cap_and_loopback_is_never_held()
    -> Result<(), String> {
        let cap = Cap::bytes_per_sec(100_000);
        let egress = Arc::new(Egress::new(cap));
        let (far, mut near) = tokio::io::duplex(1 << 24);
        let drain = tokio::spawn(async move {
            let mut sink = tokio::io::sink();
            tokio::io::copy(&mut near, &mut sink).await
        });
        let mut billed = egress.socket(far, None);
        let started = Instant::now();
        // Ten seconds of the cap, written as control (no grant): it takes the time it must.
        let bytes = vec![0u8; 1_000_000];
        billed
            .write_all(&bytes)
            .await
            .map_err(|error| error.to_string())?;
        let took = started.elapsed();
        assert!(
            egress.billed() <= cap.most_in(took),
            "{} in {took:?}",
            egress.billed()
        );
        assert!(took >= Duration::from_secs(9), "{took:?}");
        // A loopback socket under no cap at all writes at once.
        let none = Arc::new(Egress::new(Cap::NONE));
        let (far, _near) = tokio::io::duplex(1 << 24);
        let mut local = none.socket(far, Some(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
        let started = Instant::now();
        local
            .write_all(&bytes)
            .await
            .map_err(|error| error.to_string())?;
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!((none.loopback(), none.billed()), (1_000_000, 0));
        // A grant to a loopback link is at once, too, and a billed write with no cap fails.
        assert_eq!(
            none.grant(&local.link(), Class::Taker, 1 << 30).await,
            Ok(())
        );
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap_or(IpAddr::from([0; 4]));
        assert!(!none.socket((), Some(mapped)).link.billed);
        let (far, _near) = tokio::io::duplex(64);
        let mut refused = none.socket(far, None);
        assert!(refused.write_all(b"x").await.is_err());
        drop(billed);
        drain.abort();
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_grant_waits_its_turn_and_a_shed_link_learns_it() {
        let cap = Cap::bytes_per_sec(MB);
        let egress = Arc::new(Egress::new(cap));
        let subscriber = egress.socket((), None).link();
        subscriber.set_kind(Kind::Taker);
        // Most of the bucket goes at once; a second and a half more waits its pace, inside
        // `SHED_AFTER`.
        let started = Instant::now();
        assert_eq!(
            egress.grant(&subscriber, Class::Taker, 900_000).await,
            Ok(())
        );
        assert_eq!(
            egress.grant(&subscriber, Class::Taker, 1_500_000).await,
            Ok(())
        );
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(1_300) && took < SHED_AFTER,
            "{took:?}"
        );
        // A plain subscriber asking far beyond the cap is shed once its grant has waited.
        let outcome = egress.grant(&subscriber, Class::Taker, 100_000_000).await;
        assert_eq!(outcome, Err(Shed));
        assert!(subscriber.is_shed());
        assert_eq!(egress.report().classes[Class::Taker.index()].shed, 1);
    }
}
