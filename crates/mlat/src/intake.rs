//! The receiver side of an engine (RFC-0171 §3.8.1, RFC-0181 §5): which receivers take part, the
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
//! - **Room is shared, refusal is whole, and neither depends on order** (RFC-0181 §9). The
//!   receivers seated across every intake of one engine are bounded by one count ([`Seats`],
//!   `Capacity::receivers`), and who is seated is a function of who is described: the best ranked
//!   (taking part first, then a draw no feeder can choose, [`draw`]), whatever order they came in
//!   and whichever intake took them. A receiver outranked is refused whole (none of its raw held)
//!   and counted, and one that loses its seat to a better ranked one is let go whole. A receiver's
//!   raw of a bin beyond its share is refused whole (`held::Limits`); the holder's bytes are
//!   checked on each whole bin as it is sealed (`held::Bin::seal_within`), never on arrival.
//! - **The rank is no feeder's to choose** (RFC-0171 §9, critic 4: standing counts places, not
//!   keys, and is a bar, not a ranking). Taking part is the bar. Among the receivers over it the
//!   seat goes by a keyed hash of the receiver's key under a secret this process drew
//!   ([`draw`], `tally_wire::FingerprintKey::process`, the message fingerprint's own key): a key is
//!   free, so ranking by the key itself let anyone grind keys that outrank every honest receiver and
//!   take the seats from them with one description each. Under a secret it cannot do better than
//!   chance, whatever it grinds. Neither tenure nor standing serves instead: tenure (first come)
//!   rewards whoever floods first and is decided by arrival order, which RFC-0181 §9 forbids;
//!   receiver standing (RFC-0174 §2.12) is earned only by receptions the seated engine solves, so
//!   ranking by it would keep a receiver once seated seated forever and one never seated out, and it
//!   is a bar the merge applies to solutions, not an order of who may be heard.
//! - **A batch before its receiver's description** waits for it ([`Intake::hold_orphan`]): a batch
//!   can reach a holder before its receiver's description (a repair, a rebuild from parity, a link
//!   that died between them, or a description that takes effect at the next step), and is forwarded
//!   once, so one turned away is lost to MLAT. It is held, within `ORPHANS_PER_RECEIVER` a receiver
//!   and the intake's bound on receivers, for `ORPHAN_MS` of its holder's steps
//!   ([`Intake::expire_orphans`]), and taken when the description comes ([`Intake::take_orphans`]),
//!   by whichever holder: an engine holding its own raw and a relay's raw shards alike.
//! - **Late by the stamp** (`held::Closing`): an intake whose raw arrives on threads of its own
//!   while its holder steps on another ([`Intake::closing`], a relay's raw shards) refuses as late
//!   the raw stamped at or after the step that takes its bin, so a batch that raced ahead of that
//!   step is late exactly as one that came after it.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tally_mlat_solver::held::{Closing, Fragment, Limits, Open};
use tally_mlat_solver::obs::MAX_SITE_PRECISION_M;
use tally_mlat_solver::{Site, Timebase};
use tally_wire::{Clock, Decoded, FingerprintKey, Location, PublicKey, ReceiverInfo, Regions};

use crate::engine::{Dropped, Ingested};
use crate::provisional::{Note, notes_of};

/// How far behind a boot's newest sequence a batch may still arrive (two relays, or one relay's
/// reordering) and be used; anything older is a replay or too late to matter.
const REORDER: u64 = 64;
/// Boots remembered per receiver, most recent first. A receiver that restarts more often than
/// this within one window only weakens its own replay protection.
const BOOTS_PER_RECEIVER: usize = 8;
/// Batches held for one receiver not yet described, at most (module docs): the oldest goes first.
pub const ORPHANS_PER_RECEIVER: usize = 64;
/// Receivers whose batches an intake holds waiting for a description, at most, unless its holder
/// says otherwise ([`Intake::orphan_receivers`]): one more is dropped, counted.
pub const ORPHAN_RECEIVERS: usize = 4_096;
/// How long, by its holder's steps, a batch waits for its receiver's description: as long as what
/// it says to provisional solving can still be weighed in time and its raw is not yet late (a bin's
/// settling and a step). A description later than that is not coming by the same way.
pub const ORPHAN_MS: u64 = 3_000;

/// A batch waiting for its receiver's description, stamped when it came, with what its holder
/// charged for holding it (dropped when the batch is let go).
struct Orphan {
    batch: Arc<Decoded>,
    stamp_ms: u64,
    _hold: Box<dyn Any + Send>,
}

/// What holding, expiring or taking batches waiting for a description let go.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Orphaned {
    /// Dropped for room: beyond `ORPHANS_PER_RECEIVER` a receiver, or the intake's receivers.
    pub dropped: u64,
    /// Expired: waited `ORPHAN_MS` and no description came.
    pub expired: u64,
}

/// Where a described receiver stands for room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// It has a seat: it takes part if its own word places it inside the engine's regions.
    Seated,
    /// Described, but outranked for a seat: it takes no part, and is seated when it ranks among
    /// the best again.
    Waiting,
    /// Outranked even among the waiting: forgotten (its description too).
    Gone,
}

/// The domain of the seat draw under the process key (`tally_wire::decoded::keyed`).
const SEAT_DOMAIN: u8 = tally_wire::decoded::keyed::SEAT_DRAW;

/// A receiver's draw for a seat (module docs): a keyed hash of its key under `secret`, the same for
/// every intake of one engine, unknown outside the process, so no key can be ground to win it.
pub fn draw_under(secret: &FingerprintKey, key: &PublicKey) -> u128 {
    secret.fingerprint(SEAT_DOMAIN, key.as_bytes())
}

/// [`draw_under`] this process's secret (`FingerprintKey::process`): what [`Seats::new`] ranks by.
pub fn draw(key: &PublicKey) -> u128 {
    draw_under(FingerprintKey::process(), key)
}

/// What decides who is seated: receivers that take part before those that do not, then by their
/// draw (module docs), then by key (two draws of 128 bits never meet in practice; the key makes
/// the order total). A receiver's rank is its own word and the relay's secret, never when it came.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    idle: bool,
    draw: u128,
    key: PublicKey,
}

#[derive(Default)]
struct Places {
    seated: BTreeSet<Rank>,
    waiting: BTreeSet<Rank>,
    ranks: HashMap<PublicKey, Rank>,
}

impl Places {
    fn place(&self, key: &PublicKey) -> Place {
        match self.ranks.get(key) {
            Some(rank) if self.seated.contains(rank) => Place::Seated,
            Some(_) => Place::Waiting,
            None => Place::Gone,
        }
    }
}

/// The seats for described receivers, shared by every intake of one engine (RFC-0181 §9). Who is
/// seated is a function of who is described, never of the order they came in or of which intake
/// took them: the `limit` best ranked ([`Rank`]: taking part first, then the draw), and up to `limit`
/// more waiting; beyond that the worst ranked are forgotten with their descriptions, which bounds
/// what is remembered. A change re-settles every place, and says whose place changed, so each
/// intake holding one of them settles it ([`Intake::settle`]). One limit: a receiver forgotten is
/// not brought back when the ranks above it change later (a description moving another out of the
/// regions); only its next description, or the relay's own on a change of areas, ranks it again.
#[derive(Debug)]
pub struct Seats {
    limit: usize,
    /// What the draw is keyed by: this process's secret, or a test's.
    secret: FingerprintKey,
    places: Mutex<Places>,
}

impl std::fmt::Debug for Places {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Places")
            .field("seated", &self.seated.len())
            .field("waiting", &self.waiting.len())
            .finish()
    }
}

impl Seats {
    /// `limit` seats, drawn for under this process's secret ([`draw`]).
    pub fn new(limit: usize) -> Arc<Self> {
        Self::keyed(limit, *FingerprintKey::process())
    }

    /// `limit` seats, drawn for under `secret`: for a test that needs the same seats twice, or
    /// different secrets to differ.
    pub fn keyed(limit: usize, secret: FingerprintKey) -> Arc<Self> {
        Arc::new(Self {
            limit,
            secret,
            places: Mutex::new(Places::default()),
        })
    }

    fn places(&self) -> std::sync::MutexGuard<'_, Places> {
        self.places
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ranks `key` (taking part or `idle`) among the described and settles every place. Every
    /// other receiver whose place changed (its holder settles `key` itself).
    fn rank(&self, key: PublicKey, idle: bool) -> Vec<PublicKey> {
        let mut places = self.places();
        let seated = match places.ranks.remove(&key) {
            Some(old) => {
                places.waiting.remove(&old);
                places.seated.remove(&old)
            }
            None => false,
        };
        let rank = Rank {
            idle,
            draw: draw_under(&self.secret, &key),
            key,
        };
        places.ranks.insert(key, rank);
        if seated {
            places.seated.insert(rank);
        } else {
            places.waiting.insert(rank);
        }
        let mut changed = self.settle(&mut places);
        changed.retain(|other| *other != key);
        changed
    }

    /// Forgets `keys` (their intake is gone) and settles every place: whose changed.
    fn remove(&self, keys: impl Iterator<Item = PublicKey>) -> Vec<PublicKey> {
        let mut places = self.places();
        for key in keys {
            if let Some(rank) = places.ranks.remove(&key) {
                places.seated.remove(&rank);
                places.waiting.remove(&rank);
            }
        }
        self.settle(&mut places)
    }

    /// Seats the best ranked waiting while there is a seat or they outrank someone seated, and
    /// forgets the worst waiting beyond `limit` of them. Whose place changed.
    fn settle(&self, places: &mut Places) -> Vec<PublicKey> {
        let mut changed = Vec::new();
        while let Some(best) = places.waiting.first().copied() {
            if places.seated.len() < self.limit {
                places.waiting.remove(&best);
                places.seated.insert(best);
                changed.push(best.key);
                continue;
            }
            match places.seated.last().copied() {
                Some(worst) if best < worst => {
                    places.waiting.remove(&best);
                    places.seated.remove(&worst);
                    places.seated.insert(best);
                    places.waiting.insert(worst);
                    changed.extend([best.key, worst.key]);
                }
                _ => break,
            }
        }
        while places.waiting.len() > self.limit {
            let Some(worst) = places.waiting.pop_last() else {
                break;
            };
            places.ranks.remove(&worst.key);
            changed.push(worst.key);
        }
        changed.sort_unstable();
        changed.dedup();
        changed
    }

    /// Where `key` stands now.
    pub fn place(&self, key: &PublicKey) -> Place {
        self.places().place(key)
    }

    /// Seats taken now.
    pub fn taken(&self) -> usize {
        self.places().seated.len()
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
    /// Its site, if its own word places it inside the engine's regions with a usable clock.
    site: Option<Site>,
    /// Whether it holds a seat ([`Seats`]): it takes part when it is seated and has a site.
    seated: bool,
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

/// What a description or a change of regions did: what it was, the receivers here that stopped
/// taking part (what they heard is forgotten here, and their holder forgets them in the sealed
/// bins), and the receivers whose seat changed that this intake does not hold (their own intakes
/// settle them, [`Intake::settle`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    pub ingested: Ingested,
    pub left: Vec<PublicKey>,
    pub moved: Vec<PublicKey>,
}

/// One holder's receivers and their open raw (module docs).
pub struct Intake {
    seats: Arc<Seats>,
    /// The engine's regions: a receiver inside one takes part (empty: every receiver with a
    /// location). `None`: no engine runs, and no receiver takes part.
    regions: Option<Regions>,
    receivers: BTreeMap<PublicKey, Described>,
    open: Open,
    /// How lateness is decided by the stamp, if it is (`closing`); kept across a restart.
    closing: Option<Closing>,
    dropped: Dropped,
    /// Batches of receivers not described yet, by receiver, oldest first (module docs).
    orphans: BTreeMap<PublicKey, VecDeque<Orphan>>,
    orphan_receivers: usize,
}

impl Described {
    fn taking_part(&self) -> bool {
        self.seated && self.site.is_some()
    }
}

impl Intake {
    /// Receivers seated in `seats`, raw bounded by `limits` (its byte bound is the open raw's own;
    /// a holder whose raw is split checks its whole bound when it seals, `Bin::seal_within`),
    /// taking part in `regions`.
    pub fn new(seats: Arc<Seats>, limits: Limits, regions: Option<Regions>) -> Self {
        Self {
            seats,
            regions,
            receivers: BTreeMap::new(),
            open: Open::new(limits),
            closing: None,
            dropped: Dropped::default(),
            orphans: BTreeMap::new(),
            orphan_receivers: ORPHAN_RECEIVERS,
        }
    }

    /// Holds batches waiting for a description of at most `receivers` receivers (a relay's raw
    /// shards share `ORPHAN_RECEIVERS` among them).
    #[must_use]
    pub fn orphan_receivers(mut self, receivers: usize) -> Self {
        self.orphan_receivers = receivers;
        self
    }

    /// Holds `batch`, stamped `stamp_ms`, of a receiver not described here, until its description
    /// comes or `ORPHAN_MS` of steps pass; `hold` is what its holder charged for it, let go with
    /// it. The oldest of the receiver's goes first beyond `ORPHANS_PER_RECEIVER`, and a receiver
    /// beyond the intake's bound is not held: each counted.
    pub fn hold_orphan(
        &mut self,
        batch: &Arc<Decoded>,
        stamp_ms: u64,
        hold: Box<dyn Any + Send>,
    ) -> Orphaned {
        let mut orphaned = Orphaned::default();
        let key = batch.receiver();
        if self.receivers.contains_key(&key) {
            return orphaned;
        }
        if !self.orphans.contains_key(&key) && self.orphans.len() >= self.orphan_receivers {
            orphaned.dropped += 1;
            return orphaned;
        }
        let waiting = self.orphans.entry(key).or_default();
        if waiting.len() >= ORPHANS_PER_RECEIVER {
            waiting.pop_front();
            orphaned.dropped += 1;
        }
        waiting.push_back(Orphan {
            batch: Arc::clone(batch),
            stamp_ms,
            _hold: hold,
        });
        orphaned
    }

    /// Lets go every batch that has waited `ORPHAN_MS` by the step at `now_ms`.
    pub fn expire_orphans(&mut self, now_ms: u64) -> Orphaned {
        let mut orphaned = Orphaned::default();
        self.orphans.retain(|_, waiting| {
            let before = waiting.len();
            waiting.retain(|orphan| orphan.stamp_ms.saturating_add(ORPHAN_MS) > now_ms);
            orphaned.expired += (before - waiting.len()) as u64;
            !waiting.is_empty()
        });
        orphaned
    }

    /// The batches that waited for `receiver`'s description, oldest first, each with its stamp:
    /// for its holder to take now that it is described (their holds let go).
    pub fn take_orphans(&mut self, receiver: &PublicKey) -> Vec<(Arc<Decoded>, u64)> {
        self.orphans
            .remove(receiver)
            .map(|waiting| {
                waiting
                    .into_iter()
                    .map(|orphan| (orphan.batch, orphan.stamp_ms))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Batches waiting for a description.
    pub fn orphans(&self) -> usize {
        self.orphans.values().map(VecDeque::len).sum()
    }

    /// Raw late by its stamp under `closing` (module docs): for an intake whose holder steps on a
    /// thread of its own, by the stamp watermark.
    #[must_use]
    pub fn closing(mut self, closing: Closing) -> Self {
        self.open = Open::new(self.open.limits()).closing(closing);
        self.closing = Some(closing);
        self
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

    /// Whether `receiver` is described, and whether it takes part (one waiting for a seat is
    /// described, and takes no part).
    pub fn described(&self, receiver: &PublicKey) -> Option<bool> {
        self.receivers.get(receiver).map(Described::taking_part)
    }

    /// Receivers taking part now.
    pub fn taking_part(&self) -> usize {
        self.receivers
            .values()
            .filter(|described| described.taking_part())
            .count()
    }

    /// The sites of the receivers taking part, in key order.
    pub fn sites(&self) -> impl Iterator<Item = Site> + '_ {
        self.receivers
            .values()
            .filter(|known| known.seated)
            .filter_map(|known| known.site)
    }

    /// What was refused since the last call.
    pub fn take_dropped(&mut self) -> Dropped {
        std::mem::take(&mut self.dropped)
    }

    /// A receiver's description (verified here: it is the receiver's own word). An error is one
    /// that does not verify.
    pub fn describe(&mut self, info: &ReceiverInfo) -> Result<Description, String> {
        self.describe_after(info, None)
    }

    /// As `describe`, at a step of a holder whose earlier steps are not all done: what a receiver
    /// that stops taking part (it, or one whose seat it changed) held in the bins through `kept`
    /// stays for those steps to take, as they would have had they run in their turn
    /// (`held::Open::forget_receiver_after`); its holder forgets it in the sealed bins at this
    /// step. `None`: everything it held here goes now.
    pub fn describe_after(
        &mut self,
        info: &ReceiverInfo,
        kept: Option<i64>,
    ) -> Result<Description, String> {
        let ignored = Description {
            ingested: Ingested::Ignored,
            left: Vec::new(),
            moved: Vec::new(),
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
        let fresh = !self.receivers.contains_key(&key);
        let known = self.receivers.entry(key).or_insert_with(|| Described {
            issued_ms: 0,
            bytes: Vec::new(),
            location: None,
            clock: content.clock,
            site: None,
            seated: false,
            boots: VecDeque::new(),
        });
        let was = known.taking_part();
        known.issued_ms = content.issued_ms;
        known.bytes = info.as_bytes().to_vec();
        known.location = content.location;
        known.clock = content.clock;
        known.site = site;
        let changed = self.seats.rank(key, site.is_none());
        let mut description = self.settle_all(changed, kept);
        if self.settle_was(&key, was, kept) {
            description.left.push(key);
        }
        let seated = self.receivers.get(&key).is_some_and(|known| known.seated);
        if fresh && !seated {
            // Beyond the seats and outranked: refused whole, and counted.
            self.dropped.receivers += 1;
        }
        description.ingested = if seated {
            Ingested::Described
        } else {
            Ingested::Refused
        };
        Ok(description)
    }

    /// Settles every receiver of `changed` this intake holds; the rest are another intake's.
    fn settle_all(&mut self, changed: Vec<PublicKey>, kept: Option<i64>) -> Description {
        let mut description = Description {
            ingested: Ingested::Ignored,
            left: Vec::new(),
            moved: Vec::new(),
        };
        for other in changed {
            if self.receivers.contains_key(&other) {
                if self.settle_after(&other, kept) {
                    description.left.push(other);
                }
            } else {
                description.moved.push(other);
            }
        }
        description
    }

    /// Brings `receiver` to the place the seats give it now: seated or waiting, or forgotten
    /// with its description. True when it stopped taking part (what it heard is forgotten here,
    /// and its holder forgets it in the sealed bins). A receiver that loses its seat is refused
    /// whole from then on, and counted. Settling twice, or late, is settling once: it reads where
    /// the receiver stands now.
    pub fn settle(&mut self, receiver: &PublicKey) -> bool {
        self.settle_after(receiver, None)
    }

    /// As `settle`, its raw through `kept` left for the steps already due (`describe_after`).
    pub fn settle_after(&mut self, receiver: &PublicKey, kept: Option<i64>) -> bool {
        let was = self
            .receivers
            .get(receiver)
            .is_some_and(Described::taking_part);
        self.settle_was(receiver, was, kept)
    }

    fn settle_was(&mut self, receiver: &PublicKey, was: bool, kept: Option<i64>) -> bool {
        let place = self.seats.place(receiver);
        let Some(known) = self.receivers.get_mut(receiver) else {
            return false;
        };
        let seated = place == Place::Seated;
        if known.seated && !seated {
            self.dropped.receivers += 1;
        }
        known.seated = seated;
        let now = known.taking_part();
        if place == Place::Gone {
            self.receivers.remove(receiver);
        }
        let left = was && !now;
        if left || place == Place::Gone {
            // It stopped taking part: what it heard is no longer used.
            if let Some(known) = self.receivers.get_mut(receiver) {
                known.boots.clear();
            }
            match kept {
                Some(kept) => self.open.forget_receiver_after(receiver, kept),
                None => self.open.forget_receiver(receiver),
            }
        }
        left
    }

    /// The engine's regions are now `regions` (`None`: no engine runs). Every receiver described
    /// is decided again on its own signed word, and ranked again for its seat: the receivers here
    /// that stopped taking part, whose raw here is forgotten (their holder forgets them in the
    /// sealed bins), and those of other intakes whose seat changed.
    pub fn set_scope(&mut self, regions: Option<Regions>) -> Description {
        self.regions = regions;
        let decided: Vec<(PublicKey, Option<Site>, bool)> = self
            .receivers
            .iter()
            .map(|(key, known)| {
                (
                    *key,
                    self.site(*key, known.location, known.clock),
                    known.taking_part(),
                )
            })
            .collect();
        let mut changed = Vec::new();
        for (key, site, _) in &decided {
            if let Some(known) = self.receivers.get_mut(key) {
                known.site = *site;
            }
            changed.extend(self.seats.rank(*key, site.is_none()));
        }
        changed.sort_unstable();
        changed.dedup();
        let mut description = Description {
            ingested: Ingested::Ignored,
            left: Vec::new(),
            moved: Vec::new(),
        };
        for other in changed {
            if !self.receivers.contains_key(&other) {
                description.moved.push(other);
            }
        }
        for (key, _, was) in decided {
            if self.settle_was(&key, was, None) {
                description.left.push(key);
            }
        }
        description
    }

    /// A new engine begins: nothing it holds is the old one's. The descriptions stay (they are the
    /// receivers' word, not the engine's); the sequences used and the open raw go.
    pub fn restart(&mut self, limits: Limits) {
        for known in self.receivers.values_mut() {
            known.boots.clear();
        }
        self.open = match self.closing {
            Some(closing) => Open::new(limits).closing(closing),
            None => Open::new(limits),
        };
        self.dropped = Dropped::default();
        self.orphans.clear();
    }

    /// The site a declared location and clock give, if the receiver takes part.
    fn site(&self, key: PublicKey, location: Option<Location>, clock: Clock) -> Option<Site> {
        let regions = self.regions.as_ref()?;
        let location = location?;
        let inside = regions.is_empty() || regions.covers(&location);
        let usable = Timebase::of(clock).is_some() && location.precision_m <= MAX_SITE_PRECISION_M;
        (inside && usable).then_some(Site {
            receiver: key,
            clock,
            location,
        })
    }

    /// Takes a batch whose signature its holder verified and which it decoded once: used once per
    /// (boot, sequence), held only from a receiver that takes part, within its own share of a bin
    /// (`Limits::per_receiver_bin`; the holder's whole bound is checked when it seals). What it
    /// did, and what it says to provisional solving (nothing unless it was taken).
    pub fn ingest_verified(&mut self, batch: &Decoded) -> (Ingested, Vec<Note>) {
        self.ingest_verified_taking(batch, &mut |_| true)
    }

    /// As `ingest_verified`, every byte of open raw asked of `take` before it is allocated
    /// (`held::Open::add_decoded_taking`): for a holder charged for its open raw as it grows. A
    /// byte refused refuses the batch's raw of its bin, counted with the receiver's raw refused
    /// for its share; what it says to provisional solving is told all the same.
    pub fn ingest_verified_taking(
        &mut self,
        batch: &Decoded,
        take: &mut dyn FnMut(usize) -> bool,
    ) -> (Ingested, Vec<Note>) {
        self.ingest_verified_taking_at(batch, None, take)
    }

    /// As `ingest_verified_taking`, the batch taken as stamped `stamp_ms` when given (never earlier
    /// than its own stamp, `held::Open::add_decoded_taking_at`): a batch that waited for its
    /// receiver's description, taken as of the step that let it in.
    pub fn ingest_verified_taking_at(
        &mut self,
        batch: &Decoded,
        stamp_ms: Option<u64>,
        take: &mut dyn FnMut(usize) -> bool,
    ) -> (Ingested, Vec<Note>) {
        let key = batch.receiver();
        let Some(known) = self.receivers.get_mut(&key) else {
            return (Ingested::Ignored, Vec::new());
        };
        if !known.taking_part() {
            return (Ingested::Ignored, Vec::new());
        }
        if !known.admit(batch.boot_id(), batch.sequence()) {
            return (Ingested::Replayed, Vec::new());
        }
        let notes = notes_of(batch);
        let added = match stamp_ms {
            Some(stamp_ms) => self.open.add_decoded_taking_at(batch, stamp_ms, take),
            None => self.open.add_decoded_taking(batch, take),
        };
        self.dropped.late += added.late as u64;
        self.dropped.refused += added.refused as u64;
        self.dropped.ahead += added.ahead as u64;
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
            Some(known) if known.taking_part() => {
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
        // The intakes of one engine go together; the places this frees settle whoever is left.
        let _ = self.seats.remove(self.receivers.keys().copied());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    fn secret(seed: u8) -> FingerprintKey {
        FingerprintKey::from_bytes([seed; 32])
    }

    /// Who is seated, waiting and forgotten is a function of who is described: the same in any
    /// order of arrival, taking part ranked before idle, then by the draw. While nobody is
    /// forgotten (at most twice the seats described), changes of rank on the way change nothing
    /// either.
    #[test]
    fn who_is_seated_depends_on_who_is_described_never_on_the_order() {
        let keys: Vec<PublicKey> = (0..12u8)
            .map(|seed| Identity::from_seed([seed; 32]).public())
            .collect();
        // Every third idle.
        let idle = |n: usize| n.is_multiple_of(3);
        let outcome = |order: &[usize], limit: usize, detour: bool| -> Vec<Place> {
            let seats = Seats::keyed(limit, secret(9));
            for n in order {
                if detour {
                    // Described first as taking part, then decided: a change of rank on the way.
                    let _ = seats.rank(keys[*n], !idle(*n));
                }
                let _ = seats.rank(keys[*n], idle(*n));
            }
            keys.iter().map(|key| seats.place(key)).collect()
        };
        let mut ranked: Vec<(bool, u128, PublicKey)> = (0..keys.len())
            .map(|n| (idle(n), draw_under(&secret(9), &keys[n]), keys[n]))
            .collect();
        ranked.sort_unstable();
        let expected = |limit: usize| -> Vec<Place> {
            keys.iter()
                .map(|key| {
                    let at = ranked.iter().position(|(_, _, k)| k == key).unwrap_or(0);
                    if at < limit {
                        Place::Seated
                    } else if at < 2 * limit {
                        Place::Waiting
                    } else {
                        Place::Gone
                    }
                })
                .collect()
        };
        let mut order: Vec<usize> = (0..keys.len()).collect();
        for round in 0..20u64 {
            // A pseudorandom permutation each round.
            for i in (1..order.len()).rev() {
                let j = ((round + 1) * 2_654_435_761 * (i as u64 + 7) % (i as u64 + 1)) as usize;
                order.swap(i, j);
            }
            let reversed: Vec<usize> = order.iter().rev().copied().collect();
            for order in [&order, &reversed] {
                // Four seats, four waiting, the rest forgotten.
                assert_eq!(outcome(order, 4, false), expected(4), "{order:?}");
                // Seven seats: nobody forgotten, so ranks may change on the way.
                assert_eq!(outcome(order, 7, false), expected(7), "{order:?}");
                assert_eq!(
                    outcome(order, 7, true),
                    expected(7),
                    "{order:?} with detours"
                );
            }
        }
    }

    /// RFC-0171 §9 (critic 4) and the audit's grinding attack: a seat is not won by choosing a
    /// key. Keys that sort first win no more seats than any others; who is seated follows the
    /// relay's secret, so the same receivers under another secret are seated differently, and
    /// nobody outside the process can tell in advance which.
    #[test]
    fn a_seat_is_not_won_by_choosing_a_key() {
        let mut keys: Vec<PublicKey> = (0..64u8)
            .map(|seed| Identity::from_seed([seed; 32]).public())
            .collect();
        keys.sort_unstable();
        const LIMIT: usize = 8;
        let seated = |secret: FingerprintKey| -> Vec<PublicKey> {
            let seats = Seats::keyed(LIMIT, secret);
            for key in &keys {
                let _ = seats.rank(*key, false);
            }
            keys.iter()
                .filter(|key| seats.place(key) == Place::Seated)
                .copied()
                .collect()
        };
        let first = seated(secret(1));
        let second = seated(secret(2));
        assert_eq!((first.len(), second.len()), (LIMIT, LIMIT));
        // The keys a grinder would choose (the least) are not what is seated.
        assert_ne!(first, keys[..LIMIT].to_vec());
        assert_ne!(second, keys[..LIMIT].to_vec());
        // Another secret, other seats.
        assert_ne!(first, second);
        // Under one secret the seats are the best draws, whatever the keys.
        let mut draws: Vec<(u128, PublicKey)> = keys
            .iter()
            .map(|key| (draw_under(&secret(1), key), *key))
            .collect();
        draws.sort_unstable();
        let mut best: Vec<PublicKey> = draws[..LIMIT].iter().map(|(_, key)| *key).collect();
        best.sort_unstable();
        assert_eq!(first, best);
    }
}
