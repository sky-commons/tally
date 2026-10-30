//! What a relay reports about each receiver it forwards for (RFC-0173 §2.5): how often it has fed
//! this relay directly, when it was first and last heard, how many batches and observations were
//! forwarded for it, and how many of its sequences never arrived. These are counts of the relay's
//! own traffic, not about aircraft; a receiver's public cell and software come from its own signed
//! description, which the hub holds (`Hub::stations`).
//!
//! No figure about a feeder is computed here (RFC-0174 §2.12: no relay computes, stores or vouches
//! for a feeder's uptime, message rate, planes heard, range, coverage or MLAT help). A rate is a
//! client's to derive: `tally-api` takes the change in `observations` between two reports.
//!
//! The table is bounded like the relay's others (`Bounded`), at the receiver figure
//! (`budget::Plan::receivers`: the receivers the records a second the relay admits may be within
//! the longest an honest receiver goes between batches): a receiver is active whenever a batch
//! of it is forwarded, so a churn of throwaway keys forgets itself oldest first and a receiver that
//! keeps publishing keeps its place. It is one table in one order of activity for the whole relay,
//! never a share of the figure in each raw shard: receivers land in shards by a keyed hash, so a
//! shard's receivers are a random draw, and a shard held to an even share of the figure is over
//! full on every batch while another has room, forgetting a receiver that publishes within the
//! gap (at 64 receivers, one row a shard, a sixth of them). One order forgets only past the
//! figure, and the figure counts every receiver that published within the gap. Only a batch its
//! key signed creates a row: one forwarded, one judged here for the first time from its feeder
//! (`Stations::first_judged`, usable or not), or one blamed on it (`Stations::too_old`). A row
//! pushed out loses what it held, its last judged batch with it, so a repeat that comes after is
//! judged anew (RFC-0171 §3.6).
//!
//! Beside the table, the feeder connections open now, by the receiver key each one's Noise
//! handshake proved (RFC-0171 §3.2): a feeder whose decoder sends nothing seals no batch, so it
//! has no row, yet it is connected, and a report says so (`connected`, with no batch forwarded).
//! These are bounded by the feeder connections the relay admits, and each goes with its
//! connection, so no stranger grows them by inventing keys and none of them pushes a row out.
//! Each is charged with its connection's own state ([`CONNECTION_BYTES`], `ingest::
//! OWN_BYTES_PER_CONNECTION`, the paces' store), and what they allocate goes as they go
//! (`footprint::Tree`, each receiver's list exactly as long as its connections).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tally_wire::budget::policy;
use tally_wire::clocks::{Moment, Mono};
use tally_wire::{PublicKey, Region};

use crate::bounded::Bounded;
use crate::footprint::Tree;

/// One open feeder connection, in its receiver's list: its id, when it opened, and the address it
/// came from.
type Connection = (u64, Mono, Option<IpAddr>);

/// What one open feeder connection allocates in the station connections at most: its share of the
/// tree of receivers (a tree of `n` entries is planned at no more than `n` times one's,
/// `footprint::btree_planned`) and its place in its receiver's list, which is kept exactly as long
/// as its connections. Charged with the connection's own state for its session
/// (`ingest::OWN_BYTES_PER_CONNECTION`). Before, the map grew with every receiver that ever
/// connected and was charged nowhere.
pub const CONNECTION_BYTES: usize =
    Tree::<PublicKey, Vec<Connection>>::bytes_planned(1) + std::mem::size_of::<Connection>();

/// What the station rows allocate at most for `receivers` receivers (`Bounded::planned_bytes` of
/// one table at the figure), charged whole to `budget::Store::Stations` at the figure the budget
/// holds. The rows' feeder connections are each a connection's, and bounded by the connections
/// admitted.
pub const fn planned_bytes(receivers: usize) -> usize {
    Stations::planned_bytes(receivers)
}

/// What [`planned_bytes`] takes for each receiver at most (`Bounded::bytes_per_key`): the store's
/// share of a receiver (`budget::Store::Stations`).
pub const BYTES_PER_RECEIVER: usize = Bounded::<PublicKey, Tally>::bytes_per_key();

/// What [`planned_bytes`] takes beside [`BYTES_PER_RECEIVER`] for each: the table's fixed part
/// (`Bounded::fixed_bytes`) and the one row a figure of none is held at. So [`planned_bytes`] of
/// any figure is at most this and the figure's receivers' (a test holds it).
pub const FIXED_BYTES: usize = Bounded::<PublicKey, Tally>::fixed_bytes() + BYTES_PER_RECEIVER;

/// The station rows of `receivers` receivers charged whole to `gauge` (`budget::Store::Stations`):
/// what a hub holds for them while the budget stands. A store whose limit is below them is charged
/// nothing, and a start refuses it (`Hub::fixed_charged`).
pub fn charge(
    gauge: &std::sync::Arc<crate::budget::Gauge>,
    receivers: usize,
) -> crate::budget::Charge {
    let mut charge = gauge.empty();
    let planned = planned_bytes(receivers);
    if gauge.limit() >= planned {
        let _ = charge.try_grow(planned);
    }
    charge
}

/// A receiver is online while a batch of it was forwarded this recently. A feeder seals once a
/// second, so this is many missed seals, never one slow one.
pub const ONLINE_WITHIN_MS: u64 = 30_000;

/// Every station's report, as `GET /stations` serves it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StationsReport {
    /// Unix milliseconds by the relay's judging clock as the report was made: the time every
    /// instant in it is on.
    pub now_ms: u64,
    pub stations: Vec<StationReport>,
}

/// One receiver as this relay knows it, as `GET /stations/{key}` serves it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StationReport {
    /// The receiver's public key, as tally prints it (base64).
    pub key: String,
    /// A batch of it was forwarded within `ONLINE_WITHIN_MS`.
    pub online: bool,
    /// A feeder connection of it to this relay is open now, whether or not it sends batches.
    pub connected: bool,
    /// Unix milliseconds when the oldest of its open feeder connections to this relay opened;
    /// `None` when none is open. Every instant of a report is timed on the relay's monotonic clock
    /// and stated on its judging clock as the report is made ([`Stations::report`]), so a step of
    /// the host's clock between moves none of them off the report's `now_ms`. Absent from a relay older than this field, read as `None`.
    #[serde(default)]
    pub connected_since_ms: Option<u64>,
    /// How many times it has fed this relay directly: a connection that forwarded a new batch.
    pub sessions: u64,
    /// Unix milliseconds of the first and the newest batch of it forwarded; for a receiver
    /// connected that has had no batch forwarded (`batches` 0), both are when it connected.
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub batches: u64,
    /// Sequences of its current and earlier boots that were skipped and have not arrived late.
    pub gaps: u64,
    /// Batches its feeder sent signed longer ago than this relay takes (`strikes::feeder_clock`'s
    /// `TooOld`: a clock behind, or a batch held past the feeder's backlog) and carrying this
    /// relay's own anchor older than an honest batch's can be (`strikes::blame`), each held
    /// unused: its owner's sign that its clock is behind or its batches held too long. Its feeder
    /// is told this relay's clock again at its next heartbeat (`ingest::Refusal::drifted`), never
    /// that a batch was late. Absent from a relay older than this field, read as 0.
    #[serde(default)]
    pub late_batches: u64,
    pub observations: u64,
    /// The public cell (H3 resolution 6, `Region::public_cell`, as its H3 index in hex) its newest
    /// description says it is in, if the relay holds one that says and a batch of it was
    /// forwarded: a receiver only connected is placed nowhere. Never its site: what this report
    /// serves is a client's (RFC-0171 §3.5), so nothing finer than the public cell, and no
    /// altitude, is in it.
    pub cell: Option<String>,
    /// The feeder software its newest description names.
    pub software: Option<String>,
    /// The address (no port) its connected session came from, as the socket saw it; `null` while
    /// no session of it is connected. An address is a session's, never the receiver's: once the
    /// session ends the address may be anyone's (a dynamic IP reassigned), so it goes with it.
    /// Who feeds from where is the operator's to know, never the public's: this report is served
    /// on loopback only (`config::parse_loopback`), and `tally-api` answers a client only the
    /// connected stations of the client's own address (`GET /v1/me`).
    pub address: Option<String>,
}

/// How a station report names a cell: its H3 index in lowercase hex, as H3's own tools print it.
pub fn cell_name(cell: Region) -> String {
    format!("{:x}", cell.as_u64())
}

/// One receiver's running counts.
#[derive(Clone, Debug)]
struct Tally {
    sessions: u64,
    /// The connection currently feeding it directly, if one is.
    session: Option<u64>,
    /// The address `session` connected from, held only while `session` is.
    address: Option<IpAddr>,
    first_seen: Mono,
    last_seen: Mono,
    batches: u64,
    gaps: u64,
    late_batches: u64,
    observations: u64,
    /// Its newest boot and the highest sequence forwarded in it.
    stream: Option<(u64, u64)>,
    /// The last boot judged here from its feeder (not the newest: a batch of any other boot
    /// replaces it) and the highest sequence of that boot first judged, usable or not: a batch of
    /// that boot at or below it is a repeat (a resend, an audit's owed batch) and is never blamed
    /// again (`first_judged`).
    judged: Option<(u64, u64)>,
}

impl Tally {
    fn new(now: Mono) -> Self {
        Self {
            sessions: 0,
            session: None,
            address: None,
            first_seen: now,
            last_seen: now,
            batches: 0,
            gaps: 0,
            late_batches: 0,
            observations: 0,
            stream: None,
            judged: None,
        }
    }

    fn forwarded(&mut self, boot: u64, sequence: u64, observations: u64, now: Mono) {
        // A row made by late batches alone (`Stations::too_old`) starts at its first forwarded.
        if self.batches == 0 {
            self.first_seen = now;
        }
        self.last_seen = self.last_seen.latest(now);
        self.batches += 1;
        self.observations += observations;
        self.stream = Some(match self.stream {
            Some((known, newest)) if known == boot => {
                if sequence > newest {
                    self.gaps += sequence - newest - 1;
                    (boot, sequence)
                } else {
                    // A late batch fills a gap counted when its successor arrived.
                    self.gaps = self.gaps.saturating_sub(1);
                    (boot, newest)
                }
            }
            // A new boot, or the first seen: where it starts is not a gap.
            _ => (boot, sequence),
        });
    }

    fn report(
        &self,
        key: &PublicKey,
        connected_since: Option<Mono>,
        address: Option<String>,
        now: Moment,
    ) -> StationReport {
        // A row with no batch forwarded (only late ones dropped) reads as its connection does.
        let (first_seen, last_seen) = match connected_since {
            Some(since) if self.batches == 0 => (since, since),
            _ => (self.first_seen, self.last_seen),
        };
        StationReport {
            key: key.to_base64(),
            online: self.batches > 0
                && now.mono().since(self.last_seen) <= policy::<_, ONLINE_WITHIN_MS>(),
            connected: connected_since.is_some(),
            connected_since_ms: connected_since.map(|since| stated(since, now)),
            sessions: self.sessions,
            first_seen_ms: stated(first_seen, now),
            last_seen_ms: stated(last_seen, now),
            batches: self.batches,
            gaps: self.gaps,
            late_batches: self.late_batches,
            observations: self.observations,
            cell: None,
            software: None,
            address,
        }
    }
}

/// A receiver connected that has had no batch forwarded: what its report says.
/// An instant `at` timed on the monotonic clock, stated on the judging clock by the report's
/// instant `now` (`Moment::at`): Unix milliseconds, as a report serves them, whatever the host's
/// clock did since `at` was timed.
fn stated(at: Mono, now: Moment) -> u64 {
    now.at(at).judged().ms()
}

fn connected_only(
    key: &PublicKey,
    since: Mono,
    address: Option<String>,
    now: Moment,
) -> StationReport {
    let since_ms = stated(since, now);
    StationReport {
        key: key.to_base64(),
        online: false,
        connected: true,
        connected_since_ms: Some(since_ms),
        sessions: 0,
        first_seen_ms: since_ms,
        last_seen_ms: since_ms,
        batches: 0,
        gaps: 0,
        late_batches: 0,
        observations: 0,
        cell: None,
        software: None,
        address,
    }
}

pub struct Stations {
    table: Bounded<PublicKey, Tally>,
    /// The feeder connections open now, by receiver: each one's id, when it opened, and the
    /// address it came from ([`CONNECTION_BYTES`] each at most).
    connections: Tree<PublicKey, Vec<Connection>>,
}

impl Stations {
    /// What one shard's rows allocate at most at `capacity` rows (`Bounded::planned_bytes`).
    pub const fn planned_bytes(capacity: usize) -> usize {
        Bounded::<PublicKey, Tally>::planned_bytes(capacity)
    }

    pub fn new(capacity: usize) -> Self {
        Self {
            table: Bounded::new(capacity),
            connections: Tree::new(),
        }
    }

    /// The rows it holds at most.
    pub fn capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Holds at most `capacity` rows from now, the least recently active forgotten past it
    /// (`Bounded::set_capacity`): what a budget resized to another receiver figure tells it.
    pub fn set_capacity(&mut self, capacity: usize) {
        self.table.set_capacity(capacity);
    }

    /// When the oldest open feeder connection of `receiver` opened, if one is open.
    fn connected_since(&self, receiver: &PublicKey) -> Option<Mono> {
        self.connections
            .get(receiver)?
            .iter()
            .map(|(_, opened, _)| *opened)
            .min()
    }

    /// The address of the newest open feeder connection of `receiver`, if one is open and its
    /// address is known.
    fn connected_address(&self, receiver: &PublicKey) -> Option<IpAddr> {
        self.connections
            .get(receiver)?
            .iter()
            .max_by_key(|(id, opened, _)| (*opened, *id))
            .and_then(|(_, _, address)| *address)
    }

    /// The address a report names: the session that fed it, else its newest open connection's.
    fn address_of(&self, receiver: &PublicKey, tally: Option<&Tally>) -> Option<String> {
        tally
            .and_then(|tally| tally.address)
            .or_else(|| self.connected_address(receiver))
            .map(|address| address.to_string())
    }

    /// Connection `source`, its Noise handshake proving it is `receiver`'s feeder, was admitted
    /// at `now` from `address`: the receiver is connected from now until it leaves, whether or
    /// not it sends. An IPv4 client of a dual-stack socket is named as IPv4.
    pub fn opened(&mut self, receiver: PublicKey, source: u64, now: Mono, address: Option<IpAddr>) {
        let open = self.connections.entry(receiver).or_default();
        if !open.iter().any(|(id, _, _)| *id == source) {
            // Exactly as long as its connections (`CONNECTION_BYTES`).
            open.reserve_exact(1);
            open.push((source, now, address.map(|address| address.to_canonical())));
        }
    }

    /// A new batch of `receiver` was forwarded: the activity that keeps its row.
    pub fn forwarded(
        &mut self,
        receiver: PublicKey,
        boot: u64,
        sequence: u64,
        observations: u64,
        now: Mono,
    ) {
        if let Some(tally) = self.table.get_mut(&receiver) {
            tally.forwarded(boot, sequence, observations, now);
            self.table.touch(&receiver);
        } else {
            let mut tally = Tally::new(now);
            tally.forwarded(boot, sequence, observations, now);
            self.table.insert_active(receiver, tally);
        }
    }

    /// Whether batch `(boot, sequence)` of `receiver` is judged here for the first time from its
    /// feeder: of another boot than the last boot judged, or above the highest sequence of that
    /// boot judged before. Its boot is then the last boot judged and its sequence the highest. A
    /// feeder sends its batches in order, so a repeat (a resend after a stall, a batch an audit
    /// held back) is at or below it and is blamed at most once, when it first came; a batch first
    /// seen out of order is not blamed at all, which only undercounts. Its row made at `now` if
    /// it has none, as `too_old` makes one.
    ///
    /// One boot is held, the last judged: a batch of another boot replaces it. So where a
    /// receiver's batches of two boots interleave (a repeat of its earlier boot's batch after its
    /// later boot's was judged), the repeat is judged anew and may be blamed again: the one case
    /// it overcounts, bounded by the batches of the earlier boot that come again after the later
    /// one began. Its row holds no more, so a churn of boots grows nothing.
    pub fn first_judged(
        &mut self,
        receiver: PublicKey,
        boot: u64,
        sequence: u64,
        now: Mono,
    ) -> bool {
        let Some(tally) = self.table.get_mut(&receiver) else {
            let mut tally = Tally::new(now);
            tally.judged = Some((boot, sequence));
            self.table.insert_active(receiver, tally);
            return true;
        };
        match tally.judged {
            Some((held_boot, held)) if held_boot == boot && sequence <= held => false,
            _ => {
                tally.judged = Some((boot, sequence));
                true
            }
        }
    }

    /// A batch of `receiver` its feeder signed longer ago than this relay takes was dropped at
    /// `now` (`strikes::FeederClock::TooOld`), and blamed on it by the one rule that blames
    /// (`blame`, `strikes::blame`, taken by value so one blame counts once): counted against it, so
    /// its owner reads it (`late_batches`), its row made if it has none. Nothing counts a batch
    /// against its receiver without a blame, which nothing but that rule makes:
    ///
    /// ```compile_fail,E0061
    /// # fn count(stations: &mut tally_relay::stations::Stations, key: tally_wire::PublicKey, now: tally_wire::clocks::Mono) {
    /// stations.too_old(key, now);
    /// # }
    /// ```
    ///
    /// ```compile_fail,E0603
    /// # fn count(stations: &mut tally_relay::stations::Stations, key: tally_wire::PublicKey, now: tally_wire::clocks::Mono) {
    /// stations.too_old(tally_relay::strikes::Blame(()), key, now);
    /// # }
    /// ```
    ///
    /// ```compile_fail,E0382
    /// # fn count(stations: &mut tally_relay::stations::Stations, key: tally_wire::PublicKey, now: tally_wire::clocks::Mono) {
    /// # use tally_relay::strikes::{OwnAnchor, blame};
    /// // One blame counts once.
    /// if let Some(blame) = blame(true, true, OwnAnchor::Absent) {
    ///     stations.too_old(blame, key, now);
    ///     stations.too_old(blame, key, now);
    /// }
    /// # }
    /// ```
    pub fn too_old(&mut self, _blame: crate::strikes::Blame, receiver: PublicKey, now: Mono) {
        if let Some(tally) = self.table.get_mut(&receiver) {
            tally.late_batches += 1;
        } else {
            let mut tally = Tally::new(now);
            tally.late_batches = 1;
            self.table.insert_active(receiver, tally);
        }
    }

    /// Connection `source`, a feeder publishing as `receiver` from `address`, just had a new batch
    /// forwarded: the first one on it counts a session, and its address is the receiver's. An IPv4
    /// client of a dual-stack socket is named as IPv4 (`::ffff:a.b.c.d` is `a.b.c.d`).
    pub fn fed_by(&mut self, receiver: &PublicKey, source: u64, address: Option<IpAddr>) {
        if let Some(tally) = self.table.get_mut(receiver)
            && tally.session != Some(source)
        {
            tally.session = Some(source);
            tally.sessions += 1;
            tally.address = address.map(|address| address.to_canonical());
        }
    }

    /// Connection `source` of a feeder publishing as `receiver` ended, and its address with it. A
    /// newer connection of the same receiver stays its session, with its own address, and keeps
    /// it connected.
    pub fn left(&mut self, receiver: &PublicKey, source: u64) {
        if let Some(tally) = self.table.get_mut(receiver)
            && tally.session == Some(source)
        {
            tally.session = None;
            tally.address = None;
        }
        if let Some(open) = self.connections.get_mut(receiver) {
            open.retain(|(id, _, _)| *id != source);
            open.shrink_to_fit();
            if open.is_empty() {
                self.connections.remove(receiver);
            }
        }
    }

    /// `receiver`'s report, without the public cell and software its description carries: its row,
    /// or, connected with no batch forwarded, what its connection alone says. Its instants, timed
    /// on the monotonic clock, are stated on the judging clock by `now`, the relay's clocks read
    /// together as the report is made.
    pub fn report(&self, receiver: &PublicKey, now: Moment) -> Option<StationReport> {
        let since = self.connected_since(receiver);
        match self.table.get(receiver) {
            Some(tally) => {
                Some(tally.report(receiver, since, self.address_of(receiver, Some(tally)), now))
            }
            None => since
                .map(|since| connected_only(receiver, since, self.address_of(receiver, None), now)),
        }
    }

    /// Every receiver held or connected, with its key, unordered, stated as [`Stations::report`]
    /// states one.
    pub fn reports(&self, now: Moment) -> Vec<(PublicKey, StationReport)> {
        self.rows().reports(now)
    }

    /// Every receiver held or connected, copied as it stands, to be stated after its lock is let
    /// go ([`Rows::reports`]): the table is one for the relay and every batch marks it, so a
    /// report holds its lock for a copy of each row, never for the words a report spells.
    pub fn rows(&self) -> Rows {
        let held = self.table.iter().map(|(key, tally)| Row {
            key: *key,
            tally: Some(tally.clone()),
            since: self.connected_since(key),
            address: tally.address.or_else(|| self.connected_address(key)),
        });
        let connected = self
            .connections
            .keys()
            .filter(|key| self.table.get(key).is_none())
            .filter_map(|key| {
                Some(Row {
                    key: *key,
                    tally: None,
                    since: Some(self.connected_since(key)?),
                    address: self.connected_address(key),
                })
            });
        Rows(held.chain(connected).collect())
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

/// One receiver held or connected as [`Stations::rows`] copied it: its row, if it has one, when
/// its oldest open connection opened, and the address a report names.
struct Row {
    key: PublicKey,
    tally: Option<Tally>,
    since: Option<Mono>,
    address: Option<IpAddr>,
}

/// Every receiver held or connected, copied out of the table ([`Stations::rows`]).
pub struct Rows(Vec<Row>);

impl Rows {
    /// Each stated as [`Stations::report`] states one, with its key, unordered.
    pub fn reports(self, now: Moment) -> Vec<(PublicKey, StationReport)> {
        self.0
            .into_iter()
            .filter_map(|row| {
                let address = row.address.map(|address| address.to_string());
                let report = match &row.tally {
                    Some(tally) => tally.report(&row.key, row.since, address, now),
                    None => connected_only(&row.key, row.since?, address, now),
                };
                Some((row.key, report))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use tally_wire::Identity;
    use tally_wire::clocks::recorded::{aligned, mono as m};

    fn key() -> Result<PublicKey, String> {
        Ok(Identity::generate()
            .map_err(|error| error.to_string())?
            .public())
    }

    /// What the open feeder connections allocate is within what their sessions are charged for
    /// them, [`CONNECTION_BYTES`] each, however many receivers connected and left before (each
    /// several times, some receivers with several connections at once); and once every
    /// connection has left, nothing. Before, the map kept its table at the most receivers that
    /// were ever connected at once, and nothing was charged for it.
    #[test]
    fn the_open_connections_allocate_within_their_charge() -> Result<(), String> {
        use tally_counting::Counting;
        let keys = (0..64).map(|_| key()).collect::<Result<Vec<_>, String>>()?;
        let mut stations = Stations::new(8);
        // The test's own list of what is open, allocated before the count starts.
        let mut open = Vec::with_capacity(keys.len() + 8);
        let base = Counting::live();
        let mut source = 0;
        for round in 0..4u64 {
            // Every receiver once, the first eight twice over.
            for (at, receiver) in keys.iter().chain(&keys[..8]).enumerate() {
                source += 1;
                stations.opened(*receiver, source, m(round * 1_000 + at as u64), None);
                open.push((*receiver, source));
                let live = Counting::since(base);
                assert!(
                    live <= (open.len() * CONNECTION_BYTES) as isize,
                    "{live} for {} connections",
                    open.len()
                );
            }
            // Most leave; a few stay, and what they hold is within their charge.
            for (receiver, source) in open.drain(..open.len() - 3) {
                stations.left(&receiver, source);
            }
            let live = Counting::since(base);
            assert!(
                live <= (3 * CONNECTION_BYTES) as isize,
                "{live} for 3 connections"
            );
            for (receiver, source) in open.drain(..) {
                stations.left(&receiver, source);
            }
            assert_eq!(Counting::since(base), 0);
        }
        // One receiver with many connections at once, all but one gone: its list is as long as
        // the one left.
        for at in 0..64u64 {
            stations.opened(keys[0], 1_000 + at, m(10_000 + at), None);
        }
        for at in 1..64u64 {
            stations.left(&keys[0], 1_000 + at);
        }
        let live = Counting::since(base);
        assert!(
            live <= CONNECTION_BYTES as isize,
            "{live} for one connection"
        );
        stations.left(&keys[0], 1_000);
        assert_eq!(Counting::since(base), 0);
        Ok(())
    }

    /// The relay counts its own traffic and computes no figure from it: a report carries counts
    /// and instants, never a feeder's rate (RFC-0174 §2.12).
    #[test]
    fn a_report_carries_counts_and_no_feeder_figure() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        stations.forwarded(receiver, 1, 0, 5, m(1_000));
        let report = stations
            .report(&receiver, aligned(2_000))
            .ok_or("no report")?;
        let json = serde_json::to_value(&report).map_err(|error| error.to_string())?;
        let fields: Vec<&str> = json
            .as_object()
            .ok_or("not an object")?
            .keys()
            .map(String::as_str)
            .collect();
        for figure in [
            "messages_per_sec",
            "uptime",
            "aircraft",
            "range_m",
            "coverage_km2",
        ] {
            assert!(!fields.contains(&figure), "{figure} in {fields:?}");
        }
        Ok(())
    }

    #[test]
    fn counts_batches_and_observations() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        // One batch of 50 a second for twelve seconds, from t = 1,000 s.
        for n in 0..12 {
            stations.forwarded(receiver, 7, n, 50, m(1_000_000 + n * 1000));
        }
        let report = stations
            .report(&receiver, aligned(1_011_500))
            .ok_or("no report")?;
        assert_eq!(
            (report.batches, report.observations, report.gaps),
            (12, 600, 0)
        );
        assert_eq!(
            (report.first_seen_ms, report.last_seen_ms),
            (1_000_000, 1_011_000)
        );
        assert!(report.online);
        // Long after, the receiver is offline.
        let later = stations
            .report(&receiver, aligned(1_011_000 + ONLINE_WITHIN_MS + 1))
            .ok_or("no report")?;
        assert!(!later.online);
        Ok(())
    }

    #[test]
    fn a_skipped_sequence_is_a_gap_until_it_arrives_late_and_a_new_boot_is_none()
    -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        stations.forwarded(receiver, 1, 10, 1, m(0));
        stations.forwarded(receiver, 1, 14, 1, m(0));
        let gaps = |stations: &Stations| {
            stations
                .report(&receiver, aligned(0))
                .map(|report| report.gaps)
        };
        assert_eq!(gaps(&stations), Some(3));
        stations.forwarded(receiver, 1, 12, 1, m(0));
        assert_eq!(gaps(&stations), Some(2));
        // A reboot starts again at 0, and joining mid-stream is no gap either.
        stations.forwarded(receiver, 2, 0, 1, m(0));
        stations.forwarded(receiver, 2, 1, 1, m(0));
        assert_eq!(gaps(&stations), Some(2));
        Ok(())
    }

    #[test]
    fn a_session_is_a_connection_that_forwarded_and_ends_only_as_itself() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        // No row until a batch: a connection alone creates nothing.
        stations.opened(receiver, 5, m(0), None);
        stations.fed_by(&receiver, 5, None);
        assert!(stations.is_empty());
        stations.forwarded(receiver, 1, 0, 1, m(0));
        stations.fed_by(&receiver, 5, None);
        stations.fed_by(&receiver, 5, None);
        // The feeder reconnects before its old connection is noticed gone.
        stations.opened(receiver, 6, m(0), None);
        stations.fed_by(&receiver, 6, None);
        stations.left(&receiver, 5);
        let report = stations.report(&receiver, aligned(0)).ok_or("no report")?;
        assert_eq!((report.sessions, report.connected), (2, true));
        stations.left(&receiver, 6);
        let report = stations.report(&receiver, aligned(0)).ok_or("no report")?;
        assert_eq!((report.sessions, report.connected), (2, false));
        Ok(())
    }

    /// The address is the connected session's, without its port, an IPv4 client of a dual-stack
    /// socket named as IPv4; none before the receiver fed this relay directly and none once its
    /// session ended, since the address may then be a stranger's.
    #[test]
    fn the_address_is_the_connected_sessions_only() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        let address = |stations: &Stations| {
            stations
                .report(&receiver, aligned(0))
                .and_then(|report| report.address)
        };
        stations.forwarded(receiver, 1, 0, 1, m(0));
        assert_eq!(address(&stations), None);
        let home: IpAddr = "::ffff:203.0.113.7".parse().map_err(|_| "not an address")?;
        stations.fed_by(&receiver, 5, Some(home));
        assert_eq!(address(&stations).as_deref(), Some("203.0.113.7"));
        // The same session again changes nothing; a new one from elsewhere is the address now,
        // even before the old one is noticed gone.
        let away: IpAddr = "2001:db8::1".parse().map_err(|_| "not an address")?;
        stations.fed_by(&receiver, 5, Some(away));
        assert_eq!(address(&stations).as_deref(), Some("203.0.113.7"));
        stations.fed_by(&receiver, 6, Some(away));
        stations.left(&receiver, 5);
        assert_eq!(address(&stations).as_deref(), Some("2001:db8::1"));
        // A session that ends takes its address with it.
        stations.left(&receiver, 6);
        assert_eq!(address(&stations), None);
        let report = stations.report(&receiver, aligned(0)).ok_or("no report")?;
        assert!(!report.connected);
        Ok(())
    }

    /// A feeder whose decoder sends nothing seals no batch, yet its handshake proved its key: it
    /// is reported connected with nothing forwarded, placed nowhere, until its connection ends.
    #[test]
    fn a_connected_feeder_that_sends_nothing_is_reported_until_it_leaves() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        stations.opened(receiver, 5, m(1_000), None);
        // A second connection of it, before the first is noticed gone, keeps the older instant.
        stations.opened(receiver, 6, m(4_000), None);
        // No row: the table holds only receivers a batch of which was forwarded.
        assert!(stations.is_empty());
        let report = stations
            .report(&receiver, aligned(9_000))
            .ok_or("no report")?;
        assert_eq!(
            (
                report.online,
                report.connected,
                report.connected_since_ms,
                report.batches,
                report.sessions,
                report.first_seen_ms,
                report.last_seen_ms,
                report.cell
            ),
            (false, true, Some(1_000), 0, 0, 1_000, 1_000, None)
        );
        assert_eq!(stations.reports(aligned(9_000)).len(), 1);
        stations.left(&receiver, 5);
        let report = stations
            .report(&receiver, aligned(9_000))
            .ok_or("no report")?;
        assert_eq!(report.connected_since_ms, Some(4_000));
        stations.left(&receiver, 6);
        assert_eq!(stations.report(&receiver, aligned(9_000)), None);
        assert!(stations.reports(aligned(9_000)).is_empty());
        Ok(())
    }

    /// A feeder that fed and whose decoder then went quiet, still connected, is connected and not
    /// online; once its connection ends it is neither, and its row and counts stay.
    #[test]
    fn a_feeder_that_went_quiet_is_connected_and_then_offline() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        stations.opened(receiver, 5, m(0), None);
        stations.forwarded(receiver, 1, 0, 10, m(1_000));
        stations.fed_by(&receiver, 5, None);
        let quiet = stations
            .report(&receiver, aligned(1_000 + ONLINE_WITHIN_MS + 1))
            .ok_or("no report")?;
        assert_eq!(
            (
                quiet.online,
                quiet.connected,
                quiet.connected_since_ms,
                quiet.batches
            ),
            (false, true, Some(0), 1)
        );
        stations.left(&receiver, 5);
        let gone = stations
            .report(&receiver, aligned(1_000 + ONLINE_WITHIN_MS + 1))
            .ok_or("no report")?;
        assert_eq!(
            (
                gone.online,
                gone.connected,
                gone.connected_since_ms,
                gone.last_seen_ms
            ),
            (false, false, None, 1_000)
        );
        assert_eq!(stations.reports(aligned(0)).len(), 1);
        Ok(())
    }

    #[test]
    fn the_table_is_bounded_and_keeps_the_receiver_that_publishes() -> Result<(), String> {
        let honest = key()?;
        let mut stations = Stations::new(4);
        for n in 0..40 {
            stations.forwarded(honest, 1, n, 1, m(0));
            stations.forwarded(key()?, 1, 0, 1, m(0));
            assert!(stations.len() <= 4);
        }
        assert!(stations.report(&honest, aligned(0)).is_some());
        Ok(())
    }

    /// Each instant, timed on the monotonic clock, is served on the judging clock as the report
    /// reads it: three hours apart, every instant is three hours on, and online is measured on
    /// the monotonic clock alone.
    #[test]
    fn a_reports_instants_are_on_the_judging_clock_it_is_made_by() -> Result<(), String> {
        use tally_wire::clocks::recorded::moment;
        let hours = 3 * 3_600_000;
        let receiver = key()?;
        let mut stations = Stations::new(8);
        stations.opened(receiver, 5, m(500), None);
        stations.forwarded(receiver, 1, 0, 10, m(1_000));
        stations.forwarded(receiver, 1, 1, 10, m(2_000));
        let report = stations
            .report(&receiver, moment(3_000, 3_000 + hours))
            .ok_or("no report")?;
        assert_eq!(
            (
                report.connected_since_ms,
                report.first_seen_ms,
                report.last_seen_ms,
                report.online
            ),
            (Some(500 + hours), 1_000 + hours, 2_000 + hours, true)
        );
        let (_, listed) = stations
            .reports(moment(3_000, 3_000 + hours))
            .pop()
            .ok_or("no reports")?;
        assert_eq!(listed, report);
        // Online by the monotonic clock: the judging one stepped back changes nothing of it.
        let back = stations
            .report(&receiver, moment(2_000 + ONLINE_WITHIN_MS, 0))
            .ok_or("no report")?;
        assert!(back.online);
        Ok(())
    }
}
