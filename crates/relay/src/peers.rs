//! The sessions this relay dials for RFC-0174's duties (`link::member`), kept by key:
//!
//! - **Sharing members** (§2.5): what `sharing` addresses to a member (a stripe slice, a
//!   manifest, a receipt, an assignment) goes down a session to that member, dialled as a relay
//!   at the address its verified offer names. A member link carries only what is addressed to it,
//!   never the fan-out, so a group's records travel its trees and not all-to-all. A link idle for
//!   `IDLE_MS` is closed. A member that turns the link away as full (`Reason::Full`: it holds
//!   every member session its plan admits, RFC-0174 §2.5) is not dialled again until the wait it
//!   named has passed, doubled on each refusal that follows within the wait after it, up to
//!   [`FULL_WAIT_MAX_MS`] ([`Peers::refused_full`]); meanwhile sharing routes what it would have
//!   sent it to the members beneath it in its trees ([`Peers::full`], `sharing::member`), so the
//!   data still reaches the area's other members.
//! - **What waits for a member link is charged until it is written** (RFC-0181 §9). What sharing
//!   addresses a member comes charged to its store (`sharing::Addressed`, charged in its outbox);
//!   that charge is never let go on the way: it moves into the send queued for the link
//!   ([`Queued`]), beside a charge of the send's bytes to the link's own share
//!   ([`WAITING_PER_LINK_BYTES`]: its records' encoded bytes and their place in the queue), and
//!   the link drops both only once the records are written (`link::member`). A send past the
//!   link's share is dropped whole, the newest, its charges with it, and counted
//!   ([`Peers::refused`]); a member's repair asks again. So however many member links are slow,
//!   what waits for them is inside the budget, and one slow member holds at most its share.
//! - **One-hop raw** (§2.3): for each area this relay solves, a session to every other relay that
//!   offers the area's raw, dialled as an engine subscribing `RAW` cut to the area and its border
//!   band (`selection::raw_sources`). What it sends is published here as a member's, so the hosted
//!   MLAT sees it. The set is kept exactly what `selection` says, refreshed each `RAW_EVERY_MS`.
//!   The far relay takes the session only because it verified this relay's offer, grants it raw
//!   only within the band of the areas this relay solves by the same ranking
//!   (`subscription::engine_grant`), and gives it no place among its subscribers (`Hub::engine`).
//!   A raw source that turns the link away as full is routed around as a full member is, by the
//!   same record and the same doubling wait (`Peers::refused_full`): it is not dialled again
//!   until its wait has passed, and the other sources are kept meanwhile (each relay's raw is its
//!   own feeders', so there is no other to take its place; RFC-0174 §2.6).

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tally_wire::{Identity, PublicKey, Record, RelayAddress, Role, Streams};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::budget::{Charge, Gauge, Store};
use crate::hub::Hub;
use crate::selection::RawSource;

/// How long a member link may go unused before it is closed.
pub const IDLE_MS: u64 = 5 * 60 * 1000;
/// Sends waiting for one member link, at most; beyond it the newest are dropped (a member's
/// repair asks again). What bounds the queue's memory is its bytes (`WAITING_PER_LINK_BYTES`,
/// and the store's gauge); this bounds its slots.
const WAITING_PER_LINK: usize = 1_024;
/// The bytes waiting for one member link, at most (`Queued::bytes`), and what each member session
/// the relay plans is planned for its link (`budget::Plan::member_links`), so one slow member holds
/// no more than this. A link gets one send a network tick (`network::TICK`, 100 ms), a stripe
/// slice of a kilobyte or so each: some 256 of them, 25 s of sends, far past the point
/// (`sharing::member::REPAIR_AFTER_MS`) where the member asks again for what it lacks, so a link
/// this far behind holds nothing its member still waits for. (At 1 MiB, a relay taking a base
/// cell planned 2 GiB for its 2,048 member links alone.)
pub const WAITING_PER_LINK_BYTES: usize = 256 << 10;

/// A send queued for a member's link: the records, and their charges (the store's, as sharing
/// charged them, and the link's share), held until the link has written them (`into_parts`).
#[derive(Debug)]
pub struct Queued {
    records: Vec<Record>,
    written: Written,
}

/// The charges a send holds until its link has written it: dropped then, and not before.
#[derive(Debug, Default)]
pub struct Written {
    _store: Vec<Charge>,
    _link: Charge,
    _links: Charge,
}

impl Queued {
    /// What `records` cost while they wait: each one's encoded bytes and its slot, and the send's.
    pub fn bytes(records: &[Record]) -> usize {
        records
            .iter()
            .fold(std::mem::size_of::<Self>(), |sum, record| {
                sum.saturating_add(record.encoded_len() + std::mem::size_of::<Record>())
            })
    }

    /// The records, and the charge to drop once they are written.
    pub fn into_parts(self) -> (Vec<Record>, Written) {
        (self.records, self.written)
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }
}
/// How often the one-hop raw links are made to match `selection` again.
pub const RAW_EVERY_MS: u64 = 1_000;
pub use crate::sharing::full::FULL_WAIT_MAX_MS;
use crate::sharing::full::Wait;

/// `sends` to `member` as one send for its link: their store charges moved into it, and its bytes
/// charged to the link's share, `waiting`, and to the room every link's share comes from, `links`
/// (`budget::Plan::member_links`). `None` when either is full (the charges dropped with the
/// sends); nothing is queued for a send addressed to another member.
fn queued(
    (waiting, links): (&Arc<Gauge>, &Arc<Gauge>),
    member: &PublicKey,
    sends: Vec<crate::sharing::Addressed>,
) -> Option<Queued> {
    let (records, store): (Vec<Record>, Vec<Charge>) = sends
        .into_iter()
        .filter(|sent| sent.to == *member)
        .map(|sent| (sent.record, sent.charge))
        .unzip();
    let bytes = Queued::bytes(&records);
    let link = waiting.try_charge(bytes)?;
    let all = links.try_charge(bytes)?;
    Some(Queued {
        records,
        written: Written {
            _store: store,
            _link: link,
            _links: all,
        },
    })
}

struct Held {
    sender: mpsc::Sender<Queued>,
    task: JoinHandle<()>,
    used_ms: u64,
    /// The link's share of the store (`WAITING_PER_LINK_BYTES`): what its waiting sends hold.
    waiting: Arc<Gauge>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub struct Peers {
    members: Mutex<HashMap<PublicKey, Held>>,
    raw: Mutex<HashMap<(PublicKey, Vec<u64>), Held>>,
    full: Mutex<HashMap<PublicKey, Wait>>,
    /// Sends dropped whole for room, since start.
    refused: AtomicU64,
}

impl Peers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends dropped whole for room (the link's share of the store), since start.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// The member `key` turned this relay's link away as full, asking it to stay away `asked`:
    /// routed around, and not dialled, for that long, or for twice the wait it was last given if
    /// it refuses again within that wait of its end (at most `FULL_WAIT_MAX_MS`), so a full member
    /// is tried less and less often and never in a loop.
    pub fn refused_full(&self, key: PublicKey, asked: Duration, now_ms: u64) {
        let Ok(mut full) = self.full.lock() else {
            return;
        };
        let last = full.get(&key).copied();
        full.insert(key, Wait::after(last, asked, now_ms));
    }

    /// The members full now: routed around until their wait ends. A member's record is forgotten
    /// once a wait as long again has passed with no refusal, so its next one starts afresh.
    pub fn full(&self, now_ms: u64) -> BTreeSet<PublicKey> {
        let Ok(mut full) = self.full.lock() else {
            return BTreeSet::new();
        };
        full.retain(|_, held| held.remembered(now_ms));
        full.iter()
            .filter(|(_, held)| held.holds(now_ms))
            .map(|(key, _)| *key)
            .collect()
    }

    /// How long `key` is routed around from `now_ms`, if it is full.
    pub fn full_for(&self, key: &PublicKey, now_ms: u64) -> Option<Duration> {
        let full = self.full.lock().ok()?;
        let held = full.get(key)?;
        held.holds(now_ms)
            .then(|| Duration::from_millis(held.until_ms - now_ms))
    }

    /// Sends what sharing addressed the member `relay.key` (`sends`, each charged to its store) to
    /// it at `relay.address`, dialling it if no link is up, the charges held until the link has
    /// written them; nothing to a member full now (`refused_full`), or past its link's share
    /// (counted). A send addressed to another member is not this link's, and is let go. Must be
    /// called within the runtime.
    pub fn send(
        &self,
        hub: &Arc<Hub>,
        identity: &Identity,
        relay: RelayAddress,
        sends: Vec<crate::sharing::Addressed>,
        now_ms: u64,
    ) {
        if self.full_for(&relay.key, now_ms).is_some() {
            return;
        }
        let Ok(mut members) = self.members.lock() else {
            return;
        };
        let dead = members
            .get(&relay.key)
            .is_some_and(|held| held.task.is_finished() || held.sender.is_closed());
        if dead {
            members.remove(&relay.key);
        }
        let key = relay.key;
        let held = members.entry(key).or_insert_with(|| {
            let (sender, outgoing) = mpsc::channel(WAITING_PER_LINK);
            let task = tokio::spawn(crate::link::member(
                relay,
                identity.clone(),
                Role::Relay,
                Vec::new(),
                Arc::clone(hub),
                outgoing,
            ));
            Held {
                sender,
                task,
                used_ms: now_ms,
                waiting: Gauge::new(Store::Batches, WAITING_PER_LINK_BYTES),
            }
        });
        held.used_ms = now_ms;
        let links = hub.budget().member_links();
        let sent = queued((&held.waiting, &links), &key, sends)
            .is_some_and(|queued| held.sender.try_send(queued).is_ok());
        if !sent {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Makes the one-hop raw links exactly `sources`: new ones dialled, gone ones closed.
    pub fn keep_raw(
        &self,
        hub: &Arc<Hub>,
        identity: &Identity,
        sources: Vec<RawSource>,
        now_ms: u64,
    ) {
        let Ok(mut raw) = self.raw.lock() else {
            return;
        };
        let wanted: HashMap<(PublicKey, Vec<u64>), RawSource> = sources
            .into_iter()
            .map(|source| {
                let regions = source
                    .regions
                    .iter()
                    .map(|region| region.as_u64())
                    .collect();
                ((source.relay.key, regions), source)
            })
            .collect();
        raw.retain(|key, held| wanted.contains_key(key) && !held.task.is_finished());
        for (key, source) in wanted {
            // A source that said it is full is not dialled until its wait has passed.
            if raw.contains_key(&key) || self.full_for(&key.0, now_ms).is_some() {
                continue;
            }
            // The sender is held and never sent on: the link lives while it does.
            let (sender, outgoing) = mpsc::channel(1);
            let subscribe = Record::Subscribe {
                streams: Streams::RAW,
                regions: source.regions.clone(),
            };
            let task = tokio::spawn(crate::link::member(
                source.relay,
                identity.clone(),
                Role::Engine,
                vec![subscribe],
                Arc::clone(hub),
                outgoing,
            ));
            raw.insert(
                key,
                Held {
                    sender,
                    task,
                    used_ms: now_ms,
                    // Never sent on: nothing waits.
                    waiting: Gauge::new(Store::Batches, 0),
                },
            );
        }
    }

    /// Closes member links idle past `IDLE_MS`.
    pub fn expire(&self, now_ms: u64) {
        if let Ok(mut members) = self.members.lock() {
            members.retain(|_, held| {
                now_ms.saturating_sub(held.used_ms) <= IDLE_MS && !held.task.is_finished()
            });
        }
    }

    /// Member links up now, and one-hop raw links.
    pub fn counts(&self) -> (usize, usize) {
        (
            self.members.lock().map_or(0, |members| members.len()),
            self.raw.lock().map_or(0, |raw| raw.len()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A member that says it is full is routed around for the wait it asked, then tried again;
    /// turned away again within that wait of its end, the wait doubles, up to the most; and a
    /// refusal long after starts afresh. Never a loop, whatever it asks.
    #[test]
    fn a_full_member_is_routed_around_for_its_wait_doubled_on_each_refusal() -> Result<(), String> {
        let peers = Peers::new();
        let key = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let asked = Duration::from_secs(60);
        let t0 = 1_000_000;
        peers.refused_full(key, asked, t0);
        assert!(peers.full(t0).contains(&key));
        assert!(peers.full(t0 + 59_999).contains(&key));
        assert!(!peers.full(t0 + 60_000).contains(&key));
        // Turned away again as soon as it is tried: twice as long.
        peers.refused_full(key, asked, t0 + 60_000);
        assert_eq!(
            peers.full_for(&key, t0 + 60_000),
            Some(Duration::from_secs(120))
        );
        // And again, and again: doubling, never past the most.
        let mut now = t0 + 180_000;
        for _ in 0..10 {
            peers.refused_full(key, asked, now);
            now += peers
                .full_for(&key, now)
                .map_or(0, |wait| wait.as_millis() as u64);
        }
        assert!(peers.full_for(&key, now - 1).is_some());
        peers.refused_full(key, asked, now);
        assert_eq!(
            peers.full_for(&key, now),
            Some(Duration::from_millis(FULL_WAIT_MAX_MS))
        );
        // A wait of zero is still a wait.
        let other = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        peers.refused_full(other, Duration::ZERO, t0);
        assert!(peers.full(t0).contains(&other));
        // Long after its last wait ended, a refusal starts afresh at what it asks.
        let later = now + 3 * FULL_WAIT_MAX_MS;
        assert!(peers.full(later).is_empty());
        peers.refused_full(key, asked, later);
        assert_eq!(peers.full_for(&key, later), Some(asked));
        Ok(())
    }

    /// What sharing addressed `member`, `count` heartbeats each charged to `store` as its outbox
    /// charges a send: its encoded bytes.
    fn addressed(
        store: &Arc<Gauge>,
        member: PublicKey,
        count: usize,
    ) -> Vec<crate::sharing::Addressed> {
        (0..count)
            .filter_map(|_| {
                let charge = store.try_charge(Record::Heartbeat.encoded_len())?;
                Some(crate::sharing::Addressed {
                    to: member,
                    record: Record::Heartbeat,
                    charge,
                })
            })
            .collect()
    }

    /// Sweep 3, N15: what sharing addressed a member keeps its store charge all the way into the
    /// link's queue, beside a charge to the link's share, and both are released only when the
    /// link drops them, once written. Past the link's share the newest is dropped whole, its
    /// charges with it, and the store holds nothing of it.
    #[test]
    fn a_send_is_charged_until_written_and_a_link_holds_its_share_at_most() -> Result<(), String> {
        let member = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let store = Gauge::new(Store::Batches, 64 << 20);
        let waiting = Gauge::new(Store::Batches, WAITING_PER_LINK_BYTES);
        // The room every link's share comes from: a link past it is refused too.
        let links = Gauge::new(Store::Batches, 2 * WAITING_PER_LINK_BYTES);
        let one = Record::Heartbeat.encoded_len();
        let bytes = Queued::bytes(&[Record::Heartbeat, Record::Heartbeat]);
        let Some(send) = queued((&waiting, &links), &member, addressed(&store, member, 2)) else {
            return Err("an empty share refused a send".into());
        };
        assert_eq!(
            (store.held(), waiting.held(), links.held()),
            (2 * one, bytes, bytes)
        );
        // Handed to the link, which writes the records and only then drops the charges.
        let (records, written) = send.into_parts();
        assert_eq!(records, vec![Record::Heartbeat; 2]);
        assert_eq!(store.held(), 2 * one, "released before it was written");
        drop(written);
        assert_eq!((store.held(), waiting.held(), links.held()), (0, 0, 0));
        // A link that never writes: its share fills, and a send past it holds nothing anywhere.
        let mut kept = Vec::new();
        while let Some(send) = queued((&waiting, &links), &member, addressed(&store, member, 2)) {
            kept.push(send);
        }
        assert_eq!(kept.len(), WAITING_PER_LINK_BYTES / bytes);
        assert_eq!(store.held(), kept.len() * 2 * one);
        assert!(waiting.held() <= WAITING_PER_LINK_BYTES);
        assert_eq!(links.held(), waiting.held());
        // A second link's share fills the room, and a third finds none left.
        let second = Gauge::new(Store::Batches, WAITING_PER_LINK_BYTES);
        while let Some(send) = queued((&second, &links), &member, addressed(&store, member, 2)) {
            kept.push(send);
        }
        let third = Gauge::new(Store::Batches, WAITING_PER_LINK_BYTES);
        assert!(queued((&third, &links), &member, addressed(&store, member, 2)).is_none());
        assert!(links.held() <= 2 * WAITING_PER_LINK_BYTES);
        drop(kept);
        assert_eq!((store.held(), waiting.held(), links.held()), (0, 0, 0));
        Ok(())
    }

    /// Sweep 3, N15, over a real link: sends to a member that never answers wait charged, never
    /// past the link's share (the rest refused, counted, their charges let go); and when the
    /// link is closed, everything it held is released.
    #[tokio::test]
    async fn sends_waiting_for_a_member_link_are_charged_and_released_with_it() -> Result<(), String>
    {
        // A relay taking an area: it plans member sessions, and room for what waits for their
        // links (`budget::Plan::member_links`). One taking none plans none, and sends nothing.
        let area = tally_wire::Region::containing(
            &tally_wire::Location {
                lat_e7: 337_490_000,
                lon_e7: -843_880_000,
                alt_m: 0,
                precision_m: 0,
            },
            4,
        )
        .map_err(|error| error.to_string())?;
        let hub = Arc::new(Hub::new(8).taking(vec![area]));
        assert!(hub.budget().member_links().limit() >= WAITING_PER_LINK_BYTES);
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let peers = Peers::new();
        let store = Gauge::new(Store::Batches, 64 << 20);
        // Nothing listens there: the link dials and waits, writing nothing.
        let relay = RelayAddress {
            key: Identity::generate()
                .map_err(|error| error.to_string())?
                .public(),
            address: "127.0.0.1:9".to_owned(),
        };
        let per_send = 64;
        let bytes = Queued::bytes(&vec![Record::Heartbeat; per_send]);
        let sends = 2 * WAITING_PER_LINK_BYTES / bytes;
        for _ in 0..sends {
            let charged = addressed(&store, relay.key, per_send);
            peers.send(&hub, &identity, relay.clone(), charged, 0);
        }
        let kept = WAITING_PER_LINK_BYTES / bytes;
        assert_eq!(
            store.held(),
            kept * per_send * Record::Heartbeat.encoded_len()
        );
        assert_eq!(peers.refused(), (sends - kept) as u64);
        // Idle past `IDLE_MS`: closed, and what waited for it released.
        peers.expire(IDLE_MS + 1);
        tokio::task::yield_now().await;
        assert_eq!(peers.counts().0, 0);
        assert_eq!(store.held(), 0);
        assert_eq!(hub.budget().member_links().held(), 0);
        Ok(())
    }

    /// Sweep 3, N18: a raw source that turned the link away as full is not dialled while its wait
    /// lasts, and is once it has passed; the other sources are kept meanwhile.
    #[tokio::test]
    async fn a_full_raw_source_is_routed_around_for_its_wait() -> Result<(), String> {
        let hub = Arc::new(Hub::new(8));
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let peers = Peers::new();
        let source = |key: PublicKey| RawSource {
            relay: RelayAddress {
                key,
                address: "127.0.0.1:9".to_owned(),
            },
            regions: Vec::new(),
        };
        let full = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let open = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let t0 = 1_000_000;
        peers.refused_full(full, Duration::from_secs(60), t0);
        peers.keep_raw(&hub, &identity, vec![source(full), source(open)], t0);
        assert_eq!(peers.counts().1, 1, "a full source was dialled");
        peers.keep_raw(
            &hub,
            &identity,
            vec![source(full), source(open)],
            t0 + 59_999,
        );
        assert_eq!(
            peers.counts().1,
            1,
            "a full source was dialled within its wait"
        );
        peers.keep_raw(
            &hub,
            &identity,
            vec![source(full), source(open)],
            t0 + 60_000,
        );
        assert_eq!(peers.counts().1, 2);
        Ok(())
    }
}
