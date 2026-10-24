//! A client's positions are checked here, because a client cannot check them (wire version 3).
//!
//! A client is sent each solution tagged (`tally_wire::TaggedSolution`): its receptions as tags, no
//! counters, and no clock model it could map a counter through. So it cannot tell whether a
//! solution agrees with its own receptions under its own model (`standing::consistent`), and the
//! merge rule needs that: only a consistent solution refuses a superset that disagrees with it, so
//! a lying smaller solution a client took on trust would refuse an honest bigger one.
//!
//! A relay holds what the check needs: the full clock models (relay-only, in the relay's one store
//! of decoded models, `models::Models`, which the checks read and never feed), the raw twin of
//! every tagged solution (an engine publishes both forms, the raw first), and the site-bearing
//! records the tags are made under. So before a tagged record reaches a client link, the relay
//! rematches each of its solutions to the receptions of its raw twin (`publish::rematch`), each
//! receiver's tag keyed by the site-bearing record the model's scope names (by its site id, never
//! the receiver's current record, so a site re-signed mid-window still rematches), and passes the
//! record only when every solution is under its model and consistent with its own receptions
//! (`standing::under`, `standing::consistent`). A record it cannot check (a model, a twin or a
//! site it does not hold) waits with the positions awaiting their models (`Hub::forward_positions`)
//! and is then passed on to relays alone, counted: a client is never sent what no relay checked.
//!
//! **What drives the twins** (RFC-0181, "The positions checks"). The checks are handed every raw
//! positions record the relay forwards, from its members and its own engine, of anywhere in the
//! world (`Hub::hold_twins`): not its feeders' receivers' share of them. So the twins are sized by
//! what drives them, the MLAT records a second the relay admits, over the time a twin is held
//! ([`TWIN_SECONDS`], Little's law): the members' rate, which every member session's batches and
//! MLAT records spend (`budget::Plan::member_paced_bytes_per_sec`, `ingest::MemberPace`), and its
//! own engine's raw at its seats ([`OWN_RAW_BYTES_PER_SEAT_PER_SEC`]). A receiver of the figure costs them nothing.
//!
//! **What is held.** A raw solution is held only where it can be checked and someone may be sent
//! it: its model is in the store (so of a tile one of the relay's areas owns, `models`), and a
//! client's subscription covers its place (the hub's `wanted`). Anything else is not held, so its
//! tagged twin is unknown and goes to relays alone. A raw record with a solution held is kept whole
//! and compact, as its own signed bytes (each reception the wire's twelve bytes), and each held
//! solution is an entry keyed by a keyed fingerprint of its model, aircraft and transmit time
//! ([`Fingerprint`]), pointing into it.
//!
//! **Fair, never evicting.** Each class (the relay's own engine, the members together) has its own
//! room, its records' bytes and its entries, each the class's rate over the hold. Among the members
//! each session holds at most an even share of their room (the room over the sessions holding
//! twins now): a record past its source's share, or past its class's room, is refused and counted
//! ([`ConsistencyReport`]), and nothing anyone holds is ever let go for it. Twins leave only when
//! their hold is over.
//!
//! Memory is bounded in bytes. The sites (one entry per receiver, `Store::Consistency`) are sized
//! from the receiver figure, and the twins (`Store::Twins`) from the rates; each table at its caps is
//! charged whole to its store (`Consistency::size_for`).

use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tally_mlat::intake::SiteRecord;
use tally_mlat_solver::Reach;
use tally_mlat_solver::publish;
use tally_mlat_solver::standing::{Claimed, consistent, under};
use tally_wire::clocks::Mono;
use tally_wire::{Positions, PublicKey, ReceptionKey, SiteId, Solution, TransmitTime};

use crate::bounded::Bounded;
use crate::budget::{Charge, Gauge};
use crate::models::Models;

/// The site-bearing records held for each receiver: its own, and one re-signed beside it while a
/// model naming the first may still be checked.
pub const SITES_PER_RECEIVER: usize = 2;
/// How long a raw solution is held for its tagged twin: the hub holds a tagged record that long at
/// most for what its check needs (`hub::AWAITING_MS`), and an engine publishes the tagged form
/// right after the raw.
pub const TWIN_SECONDS: usize = crate::hub::AWAITING_MS.as_secs() as usize;
const TWIN_MS: u64 = crate::hub::AWAITING_MS.as_millis() as u64;

// The wire's own bounds on a raw positions record (format 3 and 4, `tally_wire::positions`).

/// The least a raw record is on the wire beside its solutions: format, engine key, boot id,
/// sequence, issued time, specification, its three counts and its signature.
pub const RECORD_WIRE_LEAST: usize = 1 + 32 + 8 + 8 + 8 + 2 + 3 * 2 + 64;
/// The least one solution adds to a raw record: its address, an empty message's length, its
/// transmit time, place, covariance, model index, addressed citation and count, and one reception
/// (index, epoch, counter) whose receiver's key another solution of the record already put in its
/// table.
pub const SOLUTION_WIRE_LEAST: usize = 4 + 1 + 8 + 4 + 3 * 4 + 6 * 4 + 2 + 32 + 4 + 1 + 12;
/// The most one solution adds to a raw record beside its receptions: [`SOLUTION_WIRE_LEAST`]'s
/// fields with a long Mode S message, and its model's id in the record's table.
pub const SOLUTION_WIRE_MOST: usize = SOLUTION_WIRE_LEAST - 12 + tally_wire::modes::LONG + 32;
/// The most one reception adds to a raw record: its index, epoch and counter, and its receiver's
/// key in the record's table.
pub const RAW_RECEPTION_WIRE_MOST: usize = 2 + 4 + 6 + 32;

/// The receptions a seat's raw keeps a second at most (`held::KEPT_CEILING_PER_S`), so its own
/// engine solves no more of them.
const KEPT_PER_SEAT_PER_SEC: usize = tally_mlat_solver::held::KEPT_CEILING_PER_S;
/// The fewest receptions a solution cites (`solve::MIN_RECEIVERS_WITH_ALTITUDE`).
const CITED_LEAST: usize = tally_mlat_solver::solve::MIN_RECEIVERS_WITH_ALTITUDE;
/// The raw bytes a second the relay's own engine publishes for each seat at most: the seat's share
/// of the transmissions it solves (its kept receptions, each in a transmission of [`CITED_LEAST`]
/// seats' at least), each a final and a provisional, each solution at its most and each kept
/// reception in both. Only the raw form is held, so only it is counted.
pub const OWN_RAW_BYTES_PER_SEAT_PER_SEC: usize =
    KEPT_PER_SEAT_PER_SEC.div_ceil(CITED_LEAST) * 2 * SOLUTION_WIRE_MOST
        + KEPT_PER_SEAT_PER_SEC * 2 * RAW_RECEPTION_WIRE_MOST;

/// The seconds of its own engine's raw the relay's room holds: the hold, and the step whose
/// records the engine publishes at once (`models::STEP_MS`).
pub const OWN_SECONDS: usize = TWIN_SECONDS + crate::models::STEP_MS.div_ceil(1_000) as usize;
/// The seconds of the members' MLAT pace the members' room holds: the hold, and the second of
/// burst the pace allows beside it (`ceiling::burst`, at least `ceiling::MIN_BURST`, held apart).
pub const MEMBER_SECONDS: usize = TWIN_SECONDS + 1;

/// What a raw record held takes beside its signed bytes: its `Arc`.
const RECORD_HELD_EXTRA: usize = tally_wire::footprint::arc::<Positions>();

/// What `wire` bytes of raw records take held, at most: their bytes, and each record's `Arc`, a
/// record being [`RECORD_WIRE_LEAST`] at least.
pub const fn held_of(wire: usize) -> usize {
    (wire * (RECORD_WIRE_LEAST + RECORD_HELD_EXTRA)).div_ceil(RECORD_WIRE_LEAST)
}

/// The receiver figure the checks hold before a budget sizes them (`Consistency::new`).
const UNSIZED_RECEIVERS: usize = 64;

/// A raw solution's identity for its tagged twin, keyed (`Consistency::fingerprint`): its model,
/// aircraft and transmit time, a stranger unable to choose two that meet.
pub type Fingerprint = u128;

/// What the checks are sized from (`Budget::consistency_sizing`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizing {
    /// The receiver figure (`Plan::receivers`): the sites.
    pub receivers: usize,
    /// The member sessions the relay holds (`Plan::members`): the sources the members' room is
    /// shared between.
    pub members: usize,
    /// The members' pace, the most of their MLAT records' wire bytes a second
    /// (`Plan::member_paced_bytes_per_sec`).
    pub members_bytes_per_sec: usize,
    /// Its own engine's raw, wire bytes a second (its seats at [`OWN_RAW_BYTES_PER_SEAT_PER_SEC`]).
    pub own_bytes_per_sec: usize,
}

/// One class's room: the bytes of the raw records it holds, and their solutions held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoomCaps {
    pub bytes: usize,
    pub twins: usize,
}

impl RoomCaps {
    /// The room `wire` bytes of raw records take held ([`held_of`]), and the most solutions they
    /// carry ([`SOLUTION_WIRE_LEAST`] each at least).
    pub const fn of(wire: usize) -> Self {
        Self {
            bytes: held_of(wire),
            twins: wire / SOLUTION_WIRE_LEAST,
        }
    }

    /// What it takes planned, beside the table's fixed part: its bytes, and each entry at most.
    pub const fn planned(&self) -> usize {
        self.bytes + self.twins * Bounded::<Fingerprint, Twin>::bytes_per_key()
    }

    /// [`RoomCaps::of`] rounded up, so a rate's plan is linear in its units.
    const fn unit(wire: usize) -> usize {
        held_of(wire)
            + wire.div_ceil(SOLUTION_WIRE_LEAST) * Bounded::<Fingerprint, Twin>::bytes_per_key()
    }
}

/// What the checks hold at most (`Caps::of`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub sites: usize,
    /// The relay's own engine's raw, over [`OWN_SECONDS`].
    pub own: RoomCaps,
    /// The members' MLAT pace's, over [`MEMBER_SECONDS`] and its least burst.
    pub members: RoomCaps,
    /// The member sessions holding twins at once, at most: each member session, and as many again
    /// whose twins outlive a session that ended (a member reconnecting).
    pub sources: usize,
}

/// The sources the members' room is kept by, for `members` member sessions.
const fn sources_for(members: usize) -> usize {
    2 * members + 1
}

impl Caps {
    pub const fn of(sizing: Sizing) -> Self {
        Self {
            sites: sizing.receivers * SITES_PER_RECEIVER,
            own: RoomCaps::of(sizing.own_bytes_per_sec * OWN_SECONDS),
            members: if sizing.members_bytes_per_sec == 0 {
                RoomCaps { bytes: 0, twins: 0 }
            } else {
                RoomCaps::of(
                    sizing.members_bytes_per_sec * MEMBER_SECONDS
                        + crate::ceiling::MIN_BURST as usize,
                )
            },
            sources: sources_for(sizing.members),
        }
    }

    /// What the sites allocate at most (`Store::Consistency`).
    pub const fn sites_bytes(&self) -> usize {
        Bounded::<SiteId, ReceptionKey>::planned_bytes(self.sites)
    }

    /// What the twins allocate at most (`Store::Twins`): the table at both rooms' entries, the
    /// rooms' records, the sources' table, and the one record decoded in hand ([`WORKING_BYTES`]).
    pub const fn twins_bytes(&self) -> usize {
        Bounded::<Fingerprint, Twin>::planned_bytes(self.own.twins + self.members.twins)
            + self.own.bytes
            + self.members.bytes
            + Bounded::<u64, Held>::planned_bytes(self.sources)
            + WORKING_BYTES
    }
}

/// What a check or a raw record's decode holds while the checks' lock is held: a raw record's
/// solutions decoded (each reception decoded is four times its twelve wire bytes) and a tagged
/// record's, and the rematched solution, some multiples of the largest record body.
pub const WORKING_BYTES: usize = 16 * tally_wire::record::MAX_BODY;

/// What one receiver of the figure costs the sites' store (`budget::Store::Consistency`).
pub const BYTES_PER_RECEIVER: usize =
    SITES_PER_RECEIVER * Bounded::<SiteId, ReceptionKey>::bytes_per_key();
/// What the sites' store holds whatever the figure.
pub const FIXED_BYTES: usize = Bounded::<SiteId, ReceptionKey>::fixed_bytes();

/// What the sites allocate at most at a receiver figure of `receivers`.
pub const fn planned_bytes(receivers: usize) -> usize {
    Bounded::<SiteId, ReceptionKey>::planned_bytes(receivers * SITES_PER_RECEIVER)
}

/// What one seat of the relay's own engine costs the twins' store (`budget::Store::Twins`).
pub const TWIN_BYTES_PER_SEAT: usize = RoomCaps::unit(OWN_RAW_BYTES_PER_SEAT_PER_SEC * OWN_SECONDS);

/// What one planned feeder's worth of the members' rate costs the twins' store: the pace it is
/// worth (`budget::PLANNED_CHARGED_BYTES_PER_SEC`, which its MLAT records spend by their signed
/// bytes) over the members' hold.
pub const TWIN_BYTES_PER_MEMBER_FEEDER: usize =
    RoomCaps::unit(crate::budget::PLANNED_CHARGED_BYTES_PER_SEC * MEMBER_SECONDS);

/// What the twins' store holds whatever the rates, for `members` member sessions: the table's
/// fixed part, the members' least burst where there are members, the sources' table and the one
/// record in hand.
pub const fn twins_fixed_bytes(members: usize) -> usize {
    Bounded::<Fingerprint, Twin>::fixed_bytes()
        + if members == 0 {
            0
        } else {
            RoomCaps::unit(crate::ceiling::MIN_BURST as usize)
        }
        + Bounded::<u64, Held>::planned_bytes(sources_for(members))
        + WORKING_BYTES
}

/// Whose a raw record is: the relay's own engine's, or a member's (any other session, a record
/// rebuilt from a group's parity among them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Own,
    Members,
}

/// A held solution: the raw record it is in, its place there, and whose it is.
pub struct Twin {
    raw: Arc<Positions>,
    index: u16,
    class: Class,
    source: u64,
    at_ms: u64,
    /// The bytes of its record it carries: the record's held bytes on its last twin, which is let
    /// go last of them; nothing on the rest.
    bytes: usize,
}

#[derive(Default)]
struct Room {
    caps: RoomCaps,
    bytes: usize,
    twins: usize,
}

struct Inner {
    sites: Bounded<SiteId, ReceptionKey>,
    twins: Bounded<Fingerprint, Twin>,
    own: Room,
    members: Room,
    /// What each member source holds of the members' room.
    sources: Bounded<u64, Held>,
}

/// What a member source holds of the members' room: its records' bytes and its twins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub bytes: usize,
    pub twins: usize,
}

impl Inner {
    fn room(&mut self, class: Class) -> &mut Room {
        match class {
            Class::Own => &mut self.own,
            Class::Members => &mut self.members,
        }
    }

    /// Lets go of every twin whose hold is over by `now_ms`.
    fn expire(&mut self, now_ms: u64) {
        while let Some((_, twin)) = self.twins.first() {
            if twin.at_ms.saturating_add(TWIN_MS) > now_ms {
                break;
            }
            let Some((_, twin)) = self.twins.pop_first() else {
                break;
            };
            let room = self.room(twin.class);
            room.twins -= 1;
            room.bytes -= twin.bytes;
            if twin.class == Class::Members
                && let Some(held) = self.sources.get_mut(&twin.source)
            {
                held.bytes -= twin.bytes;
                held.twins -= 1;
                if held.twins == 0 {
                    self.sources.remove(&twin.source);
                }
            }
        }
    }
}

/// What a tagged record's check says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every solution rematched and consistent: a client may be sent it.
    Passes,
    /// A solution rematched and is not under its model or not consistent with its receptions: it
    /// is never sent.
    Fails,
    /// Something the check needs is not held (yet).
    Unknown,
}

/// What the checks have held and refused since the relay started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ConsistencyReport {
    /// Tagged records never sent to a client: they failed, or could not be checked in time.
    pub refused: u64,
    /// Raw solutions held for their twins.
    pub held: u64,
    /// Raw solutions not held: no model of theirs in the store, or no client's subscription
    /// covers their place.
    pub unwanted: u64,
    /// Raw solutions refused because their member source held its share of the members' room.
    pub over_share: u64,
    /// Raw solutions refused because their class's room was full.
    pub full: u64,
    /// The bytes held now, in the records' and the entries' own count.
    pub bytes: usize,
}

#[derive(Default)]
struct Counts {
    refused: AtomicU64,
    held: AtomicU64,
    unwanted: AtomicU64,
    over_share: AtomicU64,
    full: AtomicU64,
}

/// The checks of client positions (module docs).
pub struct Consistency {
    models: Arc<Models>,
    keys: (std::hash::RandomState, std::hash::RandomState),
    inner: Mutex<Inner>,
    counts: Counts,
    /// The tables' caps now, and what the sites and the twins are charged to their stores
    /// (`Consistency::size_for`).
    caps: Mutex<(Caps, Charge, Charge)>,
}

impl Consistency {
    /// The checks over the relay's store of decoded models `models`, before a budget sizes them
    /// (`Consistency::size_for`): at [`UNSIZED_RECEIVERS`] and a members' room of their least
    /// burst, charged to no store. A test's that builds them alone; a relay's are sized before it
    /// starts.
    pub fn new(models: Arc<Models>) -> Self {
        Self::with_caps(
            models,
            Caps::of(Sizing {
                receivers: UNSIZED_RECEIVERS,
                members: 1,
                members_bytes_per_sec: 1,
                own_bytes_per_sec: 0,
            }),
        )
    }

    pub fn with_caps(models: Arc<Models>, caps: Caps) -> Self {
        Self {
            models,
            keys: (std::hash::RandomState::new(), std::hash::RandomState::new()),
            inner: Mutex::new(Inner {
                sites: Bounded::new(caps.sites),
                twins: Bounded::new(caps.own.twins + caps.members.twins),
                own: Room {
                    caps: caps.own,
                    ..Room::default()
                },
                members: Room {
                    caps: caps.members,
                    ..Room::default()
                },
                sources: Bounded::new(caps.sources),
            }),
            counts: Counts::default(),
            caps: Mutex::new((caps, Charge::none(), Charge::none())),
        }
    }

    /// Sizes every table for `sizing` (`Caps::of`) and charges what the sites hold at most to
    /// `sites` (`budget::Store::Consistency`) and what the twins hold at most to `twins`
    /// (`budget::Store::Twins`), each whole: false, the tables left as they were and charged
    /// nothing, when a store refuses it (the relay's start then fails, `Network::fixed_charged`).
    /// Twins held past a smaller room stay until their hold is over; nothing new is held past it.
    pub fn size_for(&self, sizing: Sizing, sites: &Arc<Gauge>, twins: &Arc<Gauge>) -> bool {
        let caps = Caps::of(sizing);
        let mut held = self
            .caps
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        held.1 = Charge::none();
        held.2 = Charge::none();
        // A first charge is admitted past an empty store's limit (`Gauge::take`), so the plan is
        // asked whether it fits first: tables charged whole either fit or the relay does not start.
        let charged = |gauge: &Arc<Gauge>, bytes: usize| {
            let mut charge = gauge.empty();
            (charge.fits(bytes) && charge.try_grow(bytes)).then_some(charge)
        };
        let Some(sites_charge) = charged(sites, caps.sites_bytes()) else {
            return false;
        };
        let Some(twins_charge) = charged(twins, caps.twins_bytes()) else {
            return false;
        };
        {
            let mut inner = self.inner();
            for _ in inner.sites.set_capacity(caps.sites) {}
            // Never fewer entries than held: a smaller room refuses new twins until the held ones'
            // hold is over, and lets go of none.
            let entries = (caps.own.twins + caps.members.twins).max(inner.twins.len());
            for _ in inner.twins.set_capacity(entries) {}
            let sources = caps.sources.max(inner.sources.len());
            for _ in inner.sources.set_capacity(sources) {}
            inner.own.caps = caps.own;
            inner.members.caps = caps.members;
        }
        *held = (caps, sites_charge, twins_charge);
        true
    }

    /// Whether what the checks hold at most is charged to their stores in full
    /// (`Network::fixed_charged`).
    pub fn charged_in_full(&self) -> Result<(), String> {
        let held = self
            .caps
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (caps, sites, twins) = &*held;
        if sites.bytes() >= caps.sites_bytes() && twins.bytes() >= caps.twins_bytes() {
            Ok(())
        } else {
            Err(format!(
                "the checks of client positions need {} bytes for their sites and {} for their \
                 twins, and their stores hold {} and {}",
                caps.sites_bytes(),
                caps.twins_bytes(),
                sites.bytes(),
                twins.bytes()
            ))
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// What the checks have held and refused (module docs).
    /// What the checks hold at most, as last sized (`Consistency::size_for`).
    pub fn caps(&self) -> Caps {
        self.caps
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0
    }

    pub fn report(&self) -> ConsistencyReport {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let bytes = {
            let inner = self.inner();
            inner.own.bytes
                + inner.members.bytes
                + inner.twins.len() * Bounded::<Fingerprint, Twin>::bytes_per_key()
        };
        ConsistencyReport {
            refused: load(&self.counts.refused),
            held: load(&self.counts.held),
            unwanted: load(&self.counts.unwanted),
            over_share: load(&self.counts.over_share),
            full: load(&self.counts.full),
            bytes,
        }
    }

    /// Tagged records never sent to a client: they failed, or could not be checked in time.
    pub fn refused(&self) -> u64 {
        self.counts.refused.load(Ordering::Relaxed)
    }

    /// Counts a tagged record not sent (`refused`).
    pub fn refuse(&self) {
        self.counts.refused.fetch_add(1, Ordering::Relaxed);
    }

    /// A site-bearing record the relay took: its key, by its id, for the models that name it.
    pub fn site(&self, record: &SiteRecord) {
        self.inner()
            .sites
            .insert_active(record.site_id(), record.reception_key());
    }

    /// A raw solution's key: its model, aircraft and transmit time, under the checks' own keys.
    fn fingerprint(
        &self,
        model: &[u8; 32],
        address: u32,
        transmitted: TransmitTime,
    ) -> Fingerprint {
        let key = (model, address, transmitted);
        (u128::from(self.keys.0.hash_one(key)) << 64) | u128::from(self.keys.1.hash_one(key))
    }

    /// A raw positions record the relay forwarded, from session `source`, the relay's own engine's
    /// (`Class::Own`) or a member's, at `now` by the monotonic clock: each solution whose model is
    /// in the store and that `wanted` (a client's subscription covers its place) held for its twin
    /// for [`TWIN_SECONDS`], within its class's room and, a member's, its source's share of it
    /// (module docs); the rest counted, never held.
    pub fn raw(
        &self,
        positions: &Positions,
        (source, class): (u64, Class),
        now: Mono,
        wanted: impl Fn(&Solution) -> bool,
    ) {
        if positions.is_tagged() {
            return;
        }
        let Ok(content) = positions.solutions() else {
            return;
        };
        let mut keys = Vec::new();
        for (index, solution) in content.solutions.iter().enumerate() {
            let checkable = self.models.get(&solution.clock_model).is_some() && wanted(solution);
            match u16::try_from(index) {
                Ok(index) if checkable => keys.push((
                    self.fingerprint(
                        &solution.clock_model,
                        solution.address,
                        solution.transmitted,
                    ),
                    index,
                )),
                _ => {
                    self.counts.unwanted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        drop(content);
        if keys.is_empty() {
            return;
        }
        let mut inner = self.inner();
        inner.expire(now.ms());
        // A solution the record repeats, or one held already, is held once.
        keys.sort_unstable_by_key(|(key, _)| *key);
        keys.dedup_by_key(|(key, _)| *key);
        keys.retain(|(key, _)| inner.twins.get(key).is_none());
        let Some(last) = keys.len().checked_sub(1) else {
            return;
        };
        let twins = keys.len() as u64;
        let bytes =
            RECORD_HELD_EXTRA + tally_wire::footprint::vec::<u8>(positions.as_bytes().len());
        if class == Class::Members {
            // An even share of the members' room among the sources holding twins now, this one
            // among them.
            let known = inner.sources.get(&source).copied();
            let sharing = inner.sources.len() + usize::from(known.is_none());
            let caps = inner.members.caps;
            let mine = known.unwrap_or_default();
            let full = known.is_none() && inner.sources.len() >= inner.sources.capacity();
            if full
                || mine.bytes + bytes > caps.bytes / sharing.max(1)
                || mine.twins + keys.len() > caps.twins / sharing.max(1)
            {
                self.counts.over_share.fetch_add(twins, Ordering::Relaxed);
                return;
            }
        }
        // Within its share, and refused still when the room has no more (a source that held its
        // share before another came keeps it).
        let room = inner.room(class);
        if room.bytes + bytes > room.caps.bytes || room.twins + keys.len() > room.caps.twins {
            self.counts.full.fetch_add(twins, Ordering::Relaxed);
            return;
        }
        if class == Class::Members {
            let mine = inner.sources.get(&source).copied().unwrap_or_default();
            inner.sources.insert(
                source,
                Held {
                    bytes: mine.bytes + bytes,
                    twins: mine.twins + keys.len(),
                },
            );
        }
        let room = inner.room(class);
        room.bytes += bytes;
        room.twins += keys.len();
        // Its own copy, exactly its bytes: the hub's may have room to spare.
        let raw = Arc::new(positions.clone());
        for (at, (key, index)) in keys.into_iter().enumerate() {
            inner.twins.insert_active(
                key,
                Twin {
                    raw: Arc::clone(&raw),
                    index,
                    class,
                    source,
                    at_ms: now.ms(),
                    bytes: if at == last { bytes } else { 0 },
                },
            );
        }
        self.counts.held.fetch_add(twins, Ordering::Relaxed);
    }

    /// Whether a client may be sent `positions` (module docs). A raw record is never a client's:
    /// it fails.
    pub fn check(&self, positions: &Positions) -> Verdict {
        if !positions.is_tagged() {
            return Verdict::Fails;
        }
        let Ok(content) = positions.tagged_solutions() else {
            return Verdict::Fails;
        };
        let reach = if positions.is_provisional() {
            Reach::Carried
        } else {
            Reach::Window
        };
        let inner = self.inner();
        // Each raw record a tagged one's solutions are in, decoded once.
        let mut decoded: Vec<(Arc<Positions>, Vec<Solution>)> = Vec::new();
        let mut verdict = Verdict::Passes;
        for tagged in &content.solutions {
            let Some(held) = self.models.get(&tagged.clock_model) else {
                verdict = Verdict::Unknown;
                continue;
            };
            if held.spec() != content.spec_version {
                return Verdict::Fails;
            }
            let model = held.model();
            let key = self.fingerprint(&tagged.clock_model, tagged.address, tagged.transmitted);
            let Some(twin) = inner.twins.get(&key) else {
                verdict = Verdict::Unknown;
                continue;
            };
            let at = match decoded
                .iter()
                .position(|(raw, _)| Arc::ptr_eq(raw, &twin.raw))
            {
                Some(at) => at,
                None => {
                    let Ok(solutions) = twin.raw.solutions() else {
                        verdict = Verdict::Unknown;
                        continue;
                    };
                    decoded.push((Arc::clone(&twin.raw), solutions.solutions));
                    decoded.len() - 1
                }
            };
            let Some(raw) = decoded[at].1.get(usize::from(twin.index)) else {
                verdict = Verdict::Unknown;
                continue;
            };
            // The fingerprint names it; it is still the same solution's, or nothing is known.
            if (raw.clock_model, raw.address, raw.transmitted)
                != (tagged.clock_model, tagged.address, tagged.transmitted)
            {
                verdict = Verdict::Unknown;
                continue;
            }
            let receptions = raw.observations.receptions().to_vec();
            // Each receiver's key is the record its model's scope names, by site id.
            let key_of = |receiver: &PublicKey| -> Option<ReceptionKey> {
                let site = model.scope.iter().find(|site| site.receiver == *receiver)?;
                inner.sites.get(&site.id).copied()
            };
            let Some(raw) = publish::rematch(tagged, receptions, key_of) else {
                verdict = Verdict::Unknown;
                continue;
            };
            if !under(model, &raw, content.spec_version)
                || !consistent(model, reach, &raw.observations, &Claimed::of(&raw))
            {
                return Verdict::Fails;
            }
        }
        verdict
    }
}

#[cfg(test)]
mod tests;
