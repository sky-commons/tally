//! The receiver side of an engine (RFC-0171 §3.8.1, RFC-0177 §5): which receivers take part, the
//! sequences each has used, their open raw (`tally_mlat_solver::held::Open`) and what each batch
//! says to provisional solving (`provisional::notes_of`). Everything here belongs to one receiver,
//! so it splits by receiver: an engine that holds its own raw keeps one [`Intake`] (`Engine::new`),
//! and a relay keeps one per raw shard, each touched by the ingest worker that owns the shard's
//! receivers, while the engine it feeds (`Engine::hosted`) holds only the sealed bins. One
//! receiver's word decides its part whichever intake holds it, so the same raw split any way
//! seals to the same bins (`held::Bin::seal_from`) and solves to the same bytes.
//!
//! - A receiver takes part on its own signed word only: its newest `ReceiverInfo` verifies, places
//!   it inside the engine's regions, and names a clock the solver specification knows with a
//!   location no coarser than it allows (`tally_mlat_solver::obs::MAX_SITE_PRECISION_M`).
//! - A batch is used once: from a receiver that takes part, with a (boot, sequence) not already used
//!   and not too far behind that boot's newest (§3.1).
//! - **Room is shared and refusal is whole.** The receivers described across every intake of one
//!   engine are bounded by one count ([`Seats`], `Capacity::receivers`): a new receiver beyond it
//!   is refused whole and counted. A receiver's raw of a bin beyond its share is refused whole
//!   (`held::Limits`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tally_mlat_solver::held::{Fragment, Limits, Open};
use tally_mlat_solver::obs::MAX_SITE_PRECISION_M;
use tally_mlat_solver::{Site, Timebase};
use tally_wire::{Clock, Decoded, Location, PublicKey, ReceiverInfo, Region};

use crate::engine::{Dropped, Ingested};
use crate::provisional::{Note, notes_of};

/// How far behind a boot's newest sequence a batch may still arrive (two relays, or one relay's
/// reordering) and be used; anything older is a replay or too late to matter.
const REORDER: u64 = 64;
/// Boots remembered per receiver, most recent first. A receiver that restarts more often than
/// this within one window only weakens its own replay protection.
const BOOTS_PER_RECEIVER: usize = 8;

/// The places for described receivers, shared by every intake of one engine: a receiver takes one
/// when it is first described and gives it back when it is forgotten.
#[derive(Debug)]
pub struct Seats {
    taken: AtomicUsize,
    limit: usize,
}

impl Seats {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            taken: AtomicUsize::new(0),
            limit,
        })
    }

    /// A place, if one is free.
    fn take(&self) -> bool {
        self.taken
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < self.limit).then_some(taken + 1)
            })
            .is_ok()
    }

    fn give_back(&self, places: usize) {
        let _ = self
            .taken
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                Some(taken.saturating_sub(places))
            });
    }

    /// Places taken now.
    pub fn taken(&self) -> usize {
        self.taken.load(Ordering::Acquire)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

/// A receiver's newest description: when it was issued, its bytes (which decide between two
/// issued in the same millisecond, so the order they arrive in does not), and its site if it
/// takes part.
struct Described {
    issued_ms: u64,
    bytes: Vec<u8>,
    /// What it declared, so a change of the engine's regions re-decides whether it takes part.
    location: Option<Location>,
    clock: Clock,
    site: Option<Site>,
    /// The sequences used per boot, most recent boot first.
    boots: VecDeque<(u64, Sequences)>,
}

/// The sequences of one boot already used: the newest, and which of the `REORDER` before it.
struct Sequences {
    newest: u64,
    /// Bit `i` set: sequence `newest - i` was used.
    used: u64,
}

impl Sequences {
    fn new(sequence: u64) -> Self {
        Self {
            newest: sequence,
            used: 1,
        }
    }

    /// True the first time `sequence` is offered, if it is within `REORDER` of the newest.
    fn admit(&mut self, sequence: u64) -> bool {
        if sequence > self.newest {
            let ahead = sequence - self.newest;
            self.used = if ahead >= REORDER {
                0
            } else {
                self.used << ahead
            };
            self.used |= 1;
            self.newest = sequence;
            return true;
        }
        let behind = self.newest - sequence;
        if behind >= REORDER {
            return false;
        }
        let bit = 1 << behind;
        if self.used & bit != 0 {
            return false;
        }
        self.used |= bit;
        true
    }
}

impl Described {
    /// True when the batch numbered `sequence` in `boot` has not been used.
    fn admit(&mut self, boot: u64, sequence: u64) -> bool {
        let found = self
            .boots
            .iter()
            .position(|(id, _)| *id == boot)
            .and_then(|at| self.boots.remove(at));
        let (admitted, sequences) = match found {
            Some((_, mut sequences)) => (sequences.admit(sequence), sequences),
            None => {
                self.boots.truncate(BOOTS_PER_RECEIVER - 1);
                (true, Sequences::new(sequence))
            }
        };
        self.boots.push_front((boot, sequences));
        admitted
    }
}

/// What a description did: what it was, and whether its receiver stopped taking part (what it
/// heard is then forgotten here, and its holder forgets it in the sealed bins).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Description {
    pub ingested: Ingested,
    pub left: bool,
}

/// One holder's receivers and their open raw (module docs).
pub struct Intake {
    seats: Arc<Seats>,
    /// The engine's regions: a receiver inside one takes part (empty: every receiver with a
    /// location). `None`: no engine runs, and no receiver takes part.
    regions: Option<Vec<Region>>,
    receivers: BTreeMap<PublicKey, Described>,
    /// Receivers refused for room, at most as many as there are places.
    refused: BTreeSet<PublicKey>,
    open: Open,
    dropped: Dropped,
}

impl Intake {
    /// Receivers placed in `seats`, raw bounded by `limits` (its byte bound is the open raw's own;
    /// a holder that seals passes what is left of its whole bound to each batch), taking part in
    /// `regions`.
    pub fn new(seats: Arc<Seats>, limits: Limits, regions: Option<Vec<Region>>) -> Self {
        Self {
            seats,
            regions,
            receivers: BTreeMap::new(),
            refused: BTreeSet::new(),
            open: Open::new(limits),
            dropped: Dropped::default(),
        }
    }

    /// Receptions held open (copies included).
    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Bytes of open raw, as allocated.
    pub fn bytes(&self) -> usize {
        self.open.bytes()
    }

    /// Whether `receiver` is described, and whether it takes part (one refused for room is
    /// described, and takes no part).
    pub fn described(&self, receiver: &PublicKey) -> Option<bool> {
        self.receivers
            .get(receiver)
            .map(|described| described.site.is_some())
            .or_else(|| self.refused.contains(receiver).then_some(false))
    }

    /// Receivers taking part now.
    pub fn taking_part(&self) -> usize {
        self.receivers
            .values()
            .filter(|described| described.site.is_some())
            .count()
    }

    /// The sites of the receivers taking part, in key order.
    pub fn sites(&self) -> impl Iterator<Item = Site> + '_ {
        self.receivers.values().filter_map(|known| known.site)
    }

    /// What was refused since the last call.
    pub fn take_dropped(&mut self) -> Dropped {
        std::mem::take(&mut self.dropped)
    }

    /// A receiver's description (verified here: it is the receiver's own word). An error is one
    /// that does not verify.
    pub fn describe(&mut self, info: &ReceiverInfo) -> Result<Description, String> {
        let ignored = Description {
            ingested: Ingested::Ignored,
            left: false,
        };
        let key = info.receiver().map_err(|error| error.to_string())?;
        info.verify()
            .map_err(|error| format!("receiver info of {key}: {error}"))?;
        // A format this build cannot read says nothing it can use.
        let Ok(content) = info.content() else {
            return Ok(ignored);
        };
        if let Some(known) = self.receivers.get(&key)
            && (known.issued_ms, known.bytes.as_slice()) >= (content.issued_ms, info.as_bytes())
        {
            return Ok(ignored);
        }
        let site = self.site(key, content.location, content.clock);
        if !self.receivers.contains_key(&key) && !self.seats.take() {
            // Full: a receiver that takes part displaces the first here that does not (its place
            // passes to it); otherwise it is refused whole, and counted.
            let Some(idle) = self
                .receivers
                .iter()
                .find(|(_, known)| known.site.is_none())
                .map(|(key, _)| *key)
                .filter(|_| site.is_some())
            else {
                self.dropped.receivers += 1;
                if self.refused.len() < self.seats.limit() {
                    self.refused.insert(key);
                }
                return Ok(Description {
                    ingested: Ingested::Refused,
                    left: false,
                });
            };
            self.receivers.remove(&idle);
        }
        self.refused.remove(&key);
        let known = self.receivers.entry(key).or_insert_with(|| Described {
            issued_ms: 0,
            bytes: Vec::new(),
            location: None,
            clock: content.clock,
            site: None,
            boots: VecDeque::new(),
        });
        known.issued_ms = content.issued_ms;
        known.bytes = info.as_bytes().to_vec();
        known.location = content.location;
        known.clock = content.clock;
        let left = known.site.is_some() && site.is_none();
        known.site = site;
        if left {
            // It left the regions or became unusable: what it heard is no longer used.
            known.boots.clear();
            self.open.forget_receiver(&key);
        }
        Ok(Description {
            ingested: Ingested::Described,
            left,
        })
    }

    /// The engine's regions are now `regions` (`None`: no engine runs). Every receiver described
    /// is decided again on its own signed word; the receivers that stopped taking part, whose raw
    /// here is forgotten (their holder forgets them in the sealed bins).
    pub fn set_scope(&mut self, regions: Option<Vec<Region>>) -> Vec<PublicKey> {
        self.regions = regions;
        let decided: Vec<(PublicKey, Option<Site>)> = self
            .receivers
            .iter()
            .map(|(key, known)| (*key, self.site(*key, known.location, known.clock)))
            .collect();
        let mut left = Vec::new();
        for (key, site) in decided {
            let Some(known) = self.receivers.get_mut(&key) else {
                continue;
            };
            let gone = known.site.is_some() && site.is_none();
            known.site = site;
            if gone {
                known.boots.clear();
                self.open.forget_receiver(&key);
                left.push(key);
            }
        }
        left
    }

    /// A new engine begins: nothing it holds is the old one's. The descriptions stay (they are the
    /// receivers' word, not the engine's); the sequences used and the open raw go.
    pub fn restart(&mut self, limits: Limits) {
        for known in self.receivers.values_mut() {
            known.boots.clear();
        }
        self.open = Open::new(limits);
        self.dropped = Dropped::default();
    }

    /// The site a declared location and clock give, if the receiver takes part.
    fn site(&self, key: PublicKey, location: Option<Location>, clock: Clock) -> Option<Site> {
        let regions = self.regions.as_ref()?;
        let location = location?;
        let inside = regions.is_empty() || regions.iter().any(|region| region.covers(&location));
        let usable = Timebase::of(clock).is_some() && location.precision_m <= MAX_SITE_PRECISION_M;
        (inside && usable).then_some(Site {
            receiver: key,
            clock,
            location,
        })
    }

    /// Takes a batch whose signature its holder verified and which it decoded once: used once per
    /// (boot, sequence), held only from a receiver that takes part, its open raw growing to `room`
    /// bytes at most. What it did, and what it says to provisional solving (nothing unless it was
    /// taken).
    pub fn ingest_verified(&mut self, batch: &Decoded, room: usize) -> (Ingested, Vec<Note>) {
        let key = batch.receiver();
        let Some(known) = self.receivers.get_mut(&key) else {
            return (Ingested::Ignored, Vec::new());
        };
        if known.site.is_none() {
            return (Ingested::Ignored, Vec::new());
        }
        if !known.admit(batch.boot_id(), batch.sequence()) {
            return (Ingested::Replayed, Vec::new());
        }
        let notes = notes_of(batch);
        let added = self.open.add_decoded_within(batch, room);
        self.dropped.late += added.late as u64;
        self.dropped.refused += added.refused as u64;
        (
            Ingested::Batch {
                new: added.new,
                filtered: added.filtered,
            },
            notes,
        )
    }

    /// A batch of a format this build cannot read: it uses its sequence and holds nothing.
    pub fn use_sequence(&mut self, receiver: &PublicKey, boot: u64, sequence: u64) -> Ingested {
        match self.receivers.get_mut(receiver) {
            Some(known) if known.site.is_some() => {
                if known.admit(boot, sequence) {
                    Ingested::Ignored
                } else {
                    Ingested::Replayed
                }
            }
            _ => Ingested::Ignored,
        }
    }

    /// Takes every open bin up to `bin` for sealing: from here on raw for them is late.
    pub fn take_through(&mut self, bin: i64) -> Vec<Fragment> {
        self.open.take_through(bin)
    }

    /// Forgets every open bin before `bin`.
    pub fn forget_before(&mut self, bin: i64) {
        self.open.forget_before(bin);
    }
}

impl Drop for Intake {
    fn drop(&mut self) {
        self.seats.give_back(self.receivers.len());
    }
}
