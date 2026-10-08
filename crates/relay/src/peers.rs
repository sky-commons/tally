//! The sessions this relay dials for RFC-0174's duties (`link::member`), kept by key:
//!
//! - **Sharing members** (§2.5): what `sharing` addresses to a member (a stripe slice, a
//!   manifest, a receipt, an assignment) goes down a session to that member, dialled as a relay
//!   at the address its verified offer names. A member link carries only what is addressed to it,
//!   never the fan-out, so a group's records travel its trees and not all-to-all. A link idle for
//!   `IDLE_MS` is closed.
//! - **One-hop raw** (§2.3): for each area this relay solves, a session to every other relay that
//!   offers the area's raw, dialled as an engine subscribing `RAW` cut to the area and its border
//!   band (`selection::raw_sources`). What it sends is published here as a member's, so the hosted
//!   MLAT sees it. The set is kept exactly what `selection` says, refreshed each `RAW_EVERY_MS`.
//!   The far relay takes the session only because it verified this relay's offer, grants it raw
//!   only within the band of the areas this relay solves by the same ranking
//!   (`subscription::engine_grant`), and gives it no place among its subscribers (`Hub::engine`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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
}

impl Peers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends `records` to the member `key` at `address`, dialling it if no link is up. Must be
    /// called within the runtime.
    pub fn send(
        &self,
        hub: &Arc<Hub>,
        identity: &Identity,
        relay: RelayAddress,
        records: Vec<Record>,
        now_ms: u64,
    ) {
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
