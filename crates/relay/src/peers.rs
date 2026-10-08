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
//! - **One-hop raw** (§2.3): for each area this relay solves, a session to every other relay that
//!   offers the area's raw, dialled as an engine subscribing `RAW` cut to the area and its border
//!   band (`selection::raw_sources`). What it sends is published here as a member's, so the hosted
//!   MLAT sees it. The set is kept exactly what `selection` says, refreshed each `RAW_EVERY_MS`.
//!   The far relay takes the session only because it verified this relay's offer, grants it raw
//!   only within the band of the areas this relay solves by the same ranking
//!   (`subscription::engine_grant`), and gives it no place among its subscribers (`Hub::engine`).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tally_wire::{Identity, PublicKey, Record, RelayAddress, Role, Streams};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::hub::Hub;
use crate::selection::RawSource;

/// How long a member link may go unused before it is closed.
pub const IDLE_MS: u64 = 5 * 60 * 1000;
/// Sends waiting for one member link; beyond it the newest are dropped (a member's repair asks
/// again).
const WAITING_PER_LINK: usize = 1_024;
/// How often the one-hop raw links are made to match `selection` again.
pub const RAW_EVERY_MS: u64 = 1_000;
/// The longest a member that said it is full is routed around, however often it says so.
pub const FULL_WAIT_MAX_MS: u64 = 30 * 60 * 1000;

/// A member that turned this relay's link away as full: routed around until `until_ms`, and the
/// wait it was given, which the next refusal doubles.
#[derive(Clone, Copy, Debug)]
struct Full {
    until_ms: u64,
    wait_ms: u64,
}

struct Held {
    sender: mpsc::Sender<Vec<Record>>,
    task: JoinHandle<()>,
    used_ms: u64,
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
    full: Mutex<HashMap<PublicKey, Full>>,
}

impl Peers {
    pub fn new() -> Self {
        Self::default()
    }

    /// The member `key` turned this relay's link away as full, asking it to stay away `asked`:
    /// routed around, and not dialled, for that long, or for twice the wait it was last given if
    /// it refuses again within that wait of its end (at most `FULL_WAIT_MAX_MS`), so a full member
    /// is tried less and less often and never in a loop.
    pub fn refused_full(&self, key: PublicKey, asked: Duration, now_ms: u64) {
        let asked_ms = u64::try_from(asked.as_millis())
            .unwrap_or(u64::MAX)
            .clamp(1_000, FULL_WAIT_MAX_MS);
        let Ok(mut full) = self.full.lock() else {
            return;
        };
        let wait_ms = match full.get(&key) {
            Some(last) if now_ms <= last.until_ms.saturating_add(last.wait_ms) => last
                .wait_ms
                .saturating_mul(2)
                .max(asked_ms)
                .min(FULL_WAIT_MAX_MS),
            _ => asked_ms,
        };
        full.insert(
            key,
            Full {
                until_ms: now_ms.saturating_add(wait_ms),
                wait_ms,
            },
        );
    }

    /// The members full now: routed around until their wait ends. A member's record is forgotten
    /// once a wait as long again has passed with no refusal, so its next one starts afresh.
    pub fn full(&self, now_ms: u64) -> BTreeSet<PublicKey> {
        let Ok(mut full) = self.full.lock() else {
            return BTreeSet::new();
        };
        full.retain(|_, held| now_ms <= held.until_ms.saturating_add(held.wait_ms));
        full.iter()
            .filter(|(_, held)| now_ms < held.until_ms)
            .map(|(key, _)| *key)
            .collect()
    }

    /// How long `key` is routed around from `now_ms`, if it is full.
    pub fn full_for(&self, key: &PublicKey, now_ms: u64) -> Option<Duration> {
        let full = self.full.lock().ok()?;
        let held = full.get(key)?;
        (now_ms < held.until_ms).then(|| Duration::from_millis(held.until_ms - now_ms))
    }

    /// Sends `records` to the member `key` at `address`, dialling it if no link is up; nothing to
    /// a member full now (`refused_full`). Must be called within the runtime.
    pub fn send(
        &self,
        hub: &Arc<Hub>,
        identity: &Identity,
        relay: RelayAddress,
        records: Vec<Record>,
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
            }
        });
        held.used_ms = now_ms;
        let _ = held.sender.try_send(records);
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
            if raw.contains_key(&key) {
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
}
