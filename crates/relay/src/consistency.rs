//! A client's positions are checked here, because a client cannot check them (wire version 4).
//!
//! A client is sent each fix tagged (`tally_wire::TaggedFix`, positions format 8): its receptions
//! as tags, no counters, and no clock model it could map a counter through. So it cannot tell
//! whether a fix agrees with its own receptions under its own model (`standing::consistent`), and
//! the merge rule needs that: only a consistent fix refuses a superset that disagrees with it, so a
//! lying smaller fix a client took on trust would refuse an honest bigger one.
//!
//! A relay holds what the check needs: the full clock models (relay-only, in the relay's one store
//! of decoded models, `models::Models`, which the checks read and never feed), the raw twin of
//! every tagged record, and the site-bearing records the tags are made under. An engine publishes
//! each step's records back to back (RFC-0174 §2.4, "MLAT in seconds", decision D5): its models,
//! then each fix record raw (format 7) and at once its tagged twin (format 8), the same fixes in
//! the same order. A link carries records in the order they were sent, so the raw a tagged record
//! is the twin of is the last raw record its own link brought. So the checks hold **one raw record
//! a link**, the last one ([`Consistency::raw`]), and nothing else: before a tagged record reaches
//! a client link, the relay pairs it with that record ([`Consistency::check`]), tags each of the
//! raw's fixes as a client is sent it (`tally_wire::Fix::tagged`, each receiver's tag keyed by the
//! site-bearing record the model's scope names, by its site id, never the receiver's current
//! record, so a site re-signed mid-window still pairs) and passes the record only when every fix
//! is the tagged one's twin, under its model and consistent with its own receptions
//! (`standing::under`, `standing::consistent`). A record it cannot check (a model, a twin or a
//! site it does not hold) waits with the positions awaiting their models (`Hub::forward_positions`)
//! and is then passed on to relays alone, counted: a client is never sent what no relay checked.
//!
//! **What drives the twins** (RFC-0181, "The positions checks"). Nothing but the links: each link
//! that may bring raw positions (the relay's own engine, where it hosts MLAT, and each member
//! session, `budget::Plan::twin_links`) holds one record at most, of at most the largest positions
//! record, while its twin is on its way. There is no hold to wait out, no rate and no room to share:
//! a link's next raw record takes the place of its last, and a link that ends lets its own go
//! ([`Consistency::forget`]). Before, every raw solution a client might want was held for the
//! hub's whole wait for a model (`hub::AWAITING_MS`) in a table keyed by fingerprint, sized from
//! the members' pace and the relay's own seats at twice their rate (a final and a provisional of
//! each transmission), which charged a seat ten megabytes for what one record does now.
//!
//! Memory is bounded in bytes. The sites (one entry per receiver, `Store::Consistency`) are sized
//! from the receiver figure, and the twins (`Store::Twins`) from the links; each table at its caps
//! is charged whole to its store (`Consistency::size_for`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tally_mlat::intake::SiteRecord;
use tally_mlat_solver::standing::{Claimed, consistent, under};
use tally_wire::key::KEY_LEN;
use tally_wire::{Positions, PublicKey, ReceptionKey, SiteId};

use crate::bounded::Bounded;
use crate::budget::{Charge, Gauge};
use crate::models::Models;

/// The site-bearing records held for each receiver: its own, and one re-signed beside it while a
/// model naming the first may still be checked.
pub const SITES_PER_RECEIVER: usize = 2;

// The wire's own bounds on a positions record (formats 7 and 8, `tally_wire::positions`).

/// The least a raw record is on the wire beside its fixes: format, engine key, boot id, sequence,
/// issued time, specification, its three counts and its signature.
pub const RECORD_WIRE_LEAST: usize = 1 + 32 + 8 + 8 + 8 + 2 + 3 * 2 + 64;
/// The least one fix adds to a record: its models' count and one model's index, which another fix
/// of the record already put in its table, considered count, one reception (index, epoch, counter)
/// whose receiver's key another fix of the record already put in its table, a used mask's byte,
/// its address, an empty message's length, its transmit time, place and covariance.
pub const SOLUTION_WIRE_LEAST: usize = 1 + 2 + 2 + 12 + 1 + 4 + 1 + 8 + 4 + 3 * 4 + 6 * 4;
/// The most one fix adds to a record beside its receptions: [`SOLUTION_WIRE_LEAST`]'s fields with
/// a long Mode S message, and its first model's id in the record's table.
pub const SOLUTION_WIRE_MOST: usize = SOLUTION_WIRE_LEAST - 12 + tally_wire::modes::LONG + 32;
/// The most a reception adds to a fix's cited models, in either format: a fix cites one model for
/// each area of its used hearers (`tally_wire::Fix::models`), so at most one a reception beyond
/// the first, its index in the fix and its id in the record's table.
pub const MODEL_RECEPTION_WIRE_MOST: usize = 2 + 32;
/// The most one reception adds to a raw record: its index, epoch and counter, its receiver's key
/// in the record's table, its bit of the used mask (a byte, rounded up), and the model its area
/// may add ([`MODEL_RECEPTION_WIRE_MOST`]).
pub const RAW_RECEPTION_WIRE_MOST: usize = 2 + 4 + 6 + 32 + 1 + MODEL_RECEPTION_WIRE_MOST;
/// The most one reception adds to a tagged record: its tag, its bit of the used mask, and the model
/// its area may add ([`MODEL_RECEPTION_WIRE_MOST`]).
pub const TAGGED_RECEPTION_WIRE_MOST: usize = 16 + 1 + MODEL_RECEPTION_WIRE_MOST;

/// The positions bytes a second an engine publishes for each of its seats, raw and tagged
/// together: the seat's share of the fixes published (`standing::PUBLISHED`, one transmission an
/// aircraft a slot), each fix at its most and each reception it considered, once raw and once
/// tagged, for every fix its engine publishes of a transmission
/// (`standing::FIXES_PER_TRANSMISSION`: its fast fix and its complete one, each held here at the
/// whole set's receptions). What a member's positions are paced at
/// (`budget::Plan::member_positions_bytes_per_sec`) and what the relay's own engine's records of a
/// step take (`mlat_host::PUBLISHED_BYTES_PER_SEAT`). Before, every kept reception was planned in
/// a transmission solved of the fewest receivers a fix cites, and five superseded fixes of each.
pub const POSITIONS_BYTES_PER_SEAT_PER_SEC: usize = (crate::standing::FIXES_PER_TRANSMISSION
    * (crate::standing::PUBLISHED.published_per_ks * 2 * SOLUTION_WIRE_MOST
        + crate::standing::PUBLISHED.considered_per_ks
            * (RAW_RECEPTION_WIRE_MOST + TAGGED_RECEPTION_WIRE_MOST)))
    .div_ceil(1_000);

/// What a raw record held takes at most: its `Arc` and its signed bytes, at most the largest
/// positions record (`tally_wire::positions::MAX_POSITIONS_LEN`, half a body, so a fault proof
/// can carry two).
pub const RECORD_HELD_MOST: usize = tally_wire::footprint::arc::<Positions>()
    + tally_wire::footprint::vec::<u8>(tally_wire::positions::MAX_POSITIONS_LEN);

/// The receiver figure the checks hold before a budget sizes them (`Consistency::new`).
const UNSIZED_RECEIVERS: usize = 64;

/// What the checks are sized from (`Budget::consistency_sizing`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizing {
    /// The receiver figure (`Plan::receivers`): the sites.
    pub receivers: usize,
    /// The links that may bring raw positions (`Plan::twin_links`): the relay's own engine where
    /// it hosts MLAT, and each member session.
    pub links: usize,
}

/// What the checks hold at most (`Caps::of`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub sites: usize,
    /// Links holding a raw record at once: each link, and one more for a link that ended while
    /// the session that replaces it is already sending (the least recently active let go past it).
    pub links: usize,
}

impl Caps {
    pub const fn of(sizing: Sizing) -> Self {
        Self {
            sites: sizing.receivers * SITES_PER_RECEIVER,
            links: links_held(sizing.links),
        }
    }

    /// What the sites allocate at most (`Store::Consistency`).
    pub const fn sites_bytes(&self) -> usize {
        Bounded::<SiteId, ReceptionKey>::planned_bytes(self.sites)
    }

    /// What the twins allocate at most (`Store::Twins`): the table of links, each link's record at
    /// its most, and the one record decoded in hand ([`WORKING_BYTES`]).
    pub const fn twins_bytes(&self) -> usize {
        Bounded::<u64, Arc<Positions>>::planned_bytes(self.links)
            + self.links * RECORD_HELD_MOST
            + WORKING_BYTES
    }
}

/// The links the twins' table holds for `links` links ([`Caps::links`]).
const fn links_held(links: usize) -> usize {
    links + 1
}

/// What a check holds while the checks' lock is held: a raw record's fixes decoded (each reception
/// decoded is four times its twelve wire bytes) and a tagged record's, and the tagged form of the
/// raw, some multiples of the largest record body.
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

/// What the twins' store holds for `links` links (`Caps::twins_bytes`), whatever the seats and the
/// rates: one record a link.
pub const fn twins_fixed_bytes(links: usize) -> usize {
    Caps::of(Sizing {
        receivers: 0,
        links,
    })
    .twins_bytes()
}

struct Inner {
    sites: Bounded<SiteId, ReceptionKey>,
    /// Each link's last raw record, by its session.
    raw: Bounded<u64, Arc<Positions>>,
}

/// What a tagged record's check says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every fix paired with its raw twin and consistent: a client may be sent it.
    Passes,
    /// A fix paired and is not its raw twin's tagged form, or not under its model, or not
    /// consistent with its receptions: it is never sent.
    Fails,
    /// Something the check needs is not held (yet).
    Unknown,
}

/// What the checks have held and refused since the relay started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ConsistencyReport {
    /// Tagged records never sent to a client: they failed, or could not be checked in time.
    pub refused: u64,
    /// Raw records held for their twins.
    pub held: u64,
    /// Links' records let go because more links held one than planned (`Caps::links`).
    pub evicted: u64,
    /// The bytes held now, in the records' own count.
    pub bytes: usize,
}

#[derive(Default)]
struct Counts {
    refused: AtomicU64,
    held: AtomicU64,
    evicted: AtomicU64,
}

/// The checks of client positions (module docs).
pub struct Consistency {
    models: Arc<Models>,
    inner: Mutex<Inner>,
    counts: Counts,
    /// The tables' caps now, and what the sites and the twins are charged to their stores
    /// (`Consistency::size_for`).
    caps: Mutex<(Caps, Charge, Charge)>,
}

impl Consistency {
    /// The checks over the relay's store of decoded models `models`, before a budget sizes them
    /// (`Consistency::size_for`): at [`UNSIZED_RECEIVERS`] and one link, charged to no store. A
    /// test's that builds them alone; a relay's are sized before it starts.
    pub fn new(models: Arc<Models>) -> Self {
        Self::with_caps(
            models,
            Caps::of(Sizing {
                receivers: UNSIZED_RECEIVERS,
                links: 1,
            }),
        )
    }

    pub fn with_caps(models: Arc<Models>, caps: Caps) -> Self {
        Self {
            models,
            inner: Mutex::new(Inner {
                sites: Bounded::new(caps.sites),
                raw: Bounded::new(caps.links),
            }),
            counts: Counts::default(),
            caps: Mutex::new((caps, Charge::none(), Charge::none())),
        }
    }

    /// Sizes every table for `sizing` (`Caps::of`) and charges what the sites hold at most to
    /// `sites` (`budget::Store::Consistency`) and what the twins hold at most to `twins`
    /// (`budget::Store::Twins`), each whole: false, the tables left as they were and charged
    /// nothing, when a store refuses it (the relay's start then fails, `Network::fixed_charged`).
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
            for _ in inner.raw.set_capacity(caps.links) {
                self.counts.evicted.fetch_add(1, Ordering::Relaxed);
            }
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

    /// What the checks hold at most, as last sized (`Consistency::size_for`).
    pub fn caps(&self) -> Caps {
        self.caps
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0
    }

    /// What the checks have held and refused (module docs).
    pub fn report(&self) -> ConsistencyReport {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let bytes = self
            .inner()
            .raw
            .values()
            .map(|raw| tally_wire::footprint::arc::<Positions>() + raw.allocated())
            .sum();
        ConsistencyReport {
            refused: load(&self.counts.refused),
            held: load(&self.counts.held),
            evicted: load(&self.counts.evicted),
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

    /// A raw positions record the relay forwarded, from session `source` (the relay's own engine's
    /// or a member's): held as that link's one record for its tagged twin, which follows it on the
    /// same link (module docs), in place of the last one. A tagged record is not held.
    pub fn raw(&self, positions: &Positions, source: u64) {
        if positions.is_tagged() || !positions.is_fix() {
            return;
        }
        // Its own copy, exactly its bytes: the hub's may have room to spare.
        let raw = Arc::new(positions.clone());
        let mut inner = self.inner();
        if inner.raw.insert_active(source, raw).is_some() {
            self.counts.evicted.fetch_add(1, Ordering::Relaxed);
        }
        self.counts.held.fetch_add(1, Ordering::Relaxed);
    }

    /// The link `source` ended: its record, if one is held, is let go.
    pub fn forget(&self, source: u64) {
        self.inner().raw.remove(&source);
    }

    /// Whether a client may be sent `positions`, a tagged record that came on session `source`
    /// (module docs): paired with the last raw record that link brought, which stays held until the
    /// link's next raw record (the hub asks again of a record that waited for a model,
    /// `Hub::forward_positions`). A raw record is never a client's: it fails.
    pub fn check(&self, positions: &Positions, source: u64) -> Verdict {
        if !positions.is_tagged() {
            return Verdict::Fails;
        }
        let inner = self.inner();
        let Some(raw) = inner.raw.get(&source).cloned() else {
            return Verdict::Unknown;
        };
        // Its twin is the same engine's, of the same boot, signed at the same time, the record
        // just before it (`tally_mlat::fix`, `sign_pair`: raw at a sequence, tagged at the next). Before,
        // the sequence was not read, and of two records a step signed with as many fixes the
        // second raw was taken for the first's twin and the honest first failed. Both headers are
        // read in place, the engine's key compared as bytes, and either record decoded only once
        // the raw is the twin: a record waiting in the hub is checked again each time a record
        // goes out (`Hub::release_awaiting`), and before, each check decoded it and the link's
        // last raw record whole, every receiver's key decompressed, which held the relay's duties
        // thread at a core at 500 feeders hosting MLAT (2026-10-26).
        if raw.as_bytes().get(1..1 + KEY_LEN) != positions.as_bytes().get(1..1 + KEY_LEN)
            || raw.boot_id() != positions.boot_id()
            || raw.sequence().checked_add(1) != Some(positions.sequence())
            || raw.issued_ms().ok() != positions.issued_ms().ok()
        {
            return Verdict::Unknown;
        }
        let Ok(content) = positions.tagged_fixes() else {
            return Verdict::Fails;
        };
        let Ok(twin) = raw.fixes() else {
            return Verdict::Unknown;
        };
        if twin.sequence.checked_add(1) != Some(content.sequence)
            || twin.issued_ms != content.issued_ms
            || twin.spec_version != content.spec_version
            || twin.fixes.len() != content.fixes.len()
        {
            return Verdict::Unknown;
        }
        let Ok(engine) = raw.engine() else {
            return Verdict::Unknown;
        };
        let mut verdict = Verdict::Passes;
        for (fix, tagged) in twin.fixes.iter().zip(&content.fixes) {
            let cited = match self.models.cited(&fix.models, engine) {
                Ok(Some(cited)) => cited,
                // Models that cannot be one fix's: no fix is under them.
                Ok(None) => return Verdict::Fails,
                Err(_) => {
                    verdict = Verdict::Unknown;
                    continue;
                }
            };
            if cited
                .models()
                .iter()
                .any(|model| model.spec() != content.spec_version)
            {
                return Verdict::Fails;
            }
            let models = tally_mlat_solver::standing::ModelRef::models(&cited);
            // Each receiver's key is the record the scope of a model it cites names, by site id
            // (a boundary receiver is in the scope of each model that keeps it, under one site).
            let key_of = |receiver: &PublicKey| -> Option<ReceptionKey> {
                let site = cited.models().iter().find_map(|model| {
                    model
                        .model()
                        .prepared
                        .model
                        .scope
                        .iter()
                        .find(|site| site.receiver == *receiver)
                })?;
                inner.sites.get(&site.id).copied()
            };
            let Ok(tagged_twin) = fix.tagged(key_of) else {
                verdict = Verdict::Unknown;
                continue;
            };
            if tagged_twin != *tagged
                || !under(&models, fix, content.spec_version)
                || !consistent(&models, fix.used(), &Claimed::of(fix))
            {
                return Verdict::Fails;
            }
        }
        verdict
    }
}

#[cfg(test)]
mod tests;
