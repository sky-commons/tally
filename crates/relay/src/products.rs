//! The two products (RFC-0174 §2.11): the regional product (each area's receptions deduplicated
//! once, as `RegionalBatch` records this relay signs as their origin, beside the area's raw,
//! positions and clock models) and the world product in its two feeds (one fix per aircraft per
//! second, by `tally_wire::products::world_choice`, offered at the top of the area tree by a relay
//! that has gathered every area's positions): live as `WorldPositions`, sealed `WORLD_SETTLE_MS`
//! after its second with MLAT by provisional fixes, and precise as `WorldPrecise`, sealed
//! `WORLD_PRECISE_SETTLE_MS` after with MLAT by final fixes only.
//!
//! # The regional product
//!
//! A relay is the origin of the regional product for the receivers that chose it: those whose
//! newest signed description ([`Products::described`]) names this relay among their relays. Their
//! receptions are grouped by the receiver's area (the H3 cell of its signed location at
//! `rendezvous::AREA_RESOLUTION`), and each area keeps one copy of each message heard within
//! [`DEDUP_WINDOW_MS`], as the hub's deduplicated stream does across the whole relay. Once a
//! second every area's copies are signed as `RegionalBatch` records: the relay's own stream (one
//! random boot id a process, one sequence from 0 across its areas), cut to fit a record. The
//! signature is the origin's and covers the cell, so any relay forwards the record unchanged and
//! a subscriber's regions cut it by the cell it names. A relay forwards a peer's regional batch
//! once, unchanged, when the cell is inside an area it takes (the area's group: every relay that
//! takes it), so regional data travels within its area's relays and no further.
//!
//! # The world product
//!
//! Every relay that gathers the world ([`Products::set_world`]) holds, for each second of
//! transmit time not yet sealed, one fix per aircraft: the best by `world_choice`'s order
//! (`WorldFix::ranks_above`, a total order) of every candidate it was shown, whatever order they
//! came in. The candidates are, from public signed records
//! only:
//!
//! - **ADS-B positions** decoded from regional batches (its own and its peers'), by
//!   [`regional_fixes`]: per aircraft, its newest airborne position in the record decoded globally
//!   (CPR, the solver's own decoder, `tally_mlat_solver::modes`) with the latest airborne position
//!   of the other parity before it in the same record, so one record is all a reader needs to
//!   decode it again. Its time is the record's signed wall clock (a regional batch carries no
//!   receiver's counter a reader could place), its input set `products::adsb_input_set` of the
//!   two messages, its covariance the position's type code's containment radius taken as two
//!   sigma, its altitude the GNSS height when the message carries one (a barometric altitude is
//!   not a height above the ellipsoid, so the fix states none).
//! - **MLAT finals and provisionals**, from `Positions` records (final, format 3) and
//!   `Provisional` ones (format 4), by [`positions_fixes`]: each solution as published, its input
//!   set the merge rule's (`products::input_set`, over the observation set and the cited model's
//!   inputs hash), so a solution waits here until its model's manifest has been shown.
//!
//! Each fix cites its origin record's hash and its index there, so a reader holding that record
//! derives the same fix ([`check_fix`]). A second is sealed once, [`WORLD_SETTLE_MS`] after it
//! ends (a provisional arrives at most about 3 s after its transmission, RFC-0171 §3.8.1): its
//! fixes, ascending by address, are signed as `WorldPositions` parts of at most
//! `MAX_WORLD_FIXES`. A candidate for a sealed second is late and dropped, so no aircraft has two
//! fixes in one second. A final MLAT fix comes 7 to 47 s after its transmission, after its second
//! is sealed, so in the world product an MLAT target is drawn by its provisional fix; its final
//! fix is in the positions stream the world fix's origin belongs to. Two relays shown the same
//! records before a second's seal publish the same fixes for it, byte for byte, in any order.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};
use std::sync::Mutex;

use tally_mlat_solver::modes::{self, AltitudeKind};
use tally_wire::batch::{Hash, format};
use tally_wire::positions::{EnuCovariance, TransmitTime};
use tally_wire::products::{MAX_REGIONAL_OBSERVATIONS, MAX_WORLD_FIXES, adsb_input_set, input_set};
use tally_wire::rendezvous::area_of;
use tally_wire::{
    Batch, ClockModel, Identity, Observation, Positions, PublicKey, ReceiverInfo, Record, Region,
    RegionalBatch, RegionalBatchContent, WireError, WorldFix, WorldPositions,
    WorldPositionsContent, WorldPrecise,
};

use crate::bounded::Bounded;
use crate::network::{Asker, AskerRole};

/// How often each area's copies are signed: a feeder seals once a second, and so does an origin.
pub const REGIONAL_EVERY_MS: u64 = 1_000;
/// How long a message heard in an area is remembered as heard: the hub's own window for its
/// deduplicated stream.
pub const DEDUP_WINDOW_MS: u64 = 2_000;
/// How long after a second of transmit time ends its world fixes are sealed: a provisional fix is
/// published at most about 3.0 s after its transmission (RFC-0171 §3.8.1, measured), and a
/// regional batch within a second of its receptions.
pub const WORLD_SETTLE_MS: u64 = 4_000;
/// How long after a second of transmit time ends its precise world fixes are sealed: once every
/// final fix of it has surely arrived (`tally_wire::products::FINAL_FIX_ARRIVED_MS`, derived
/// there).
pub const WORLD_PRECISE_SETTLE_MS: u64 = tally_wire::products::FINAL_FIX_ARRIVED_MS;
/// How far past the relay's own clock a fix's second may be and still be held.
const WORLD_AHEAD_SECONDS: u64 = 2;
/// How far before the relay's own clock a fix's second may be before the first seal.
const WORLD_BEHIND_SECONDS: u64 = 240;
/// The most aircraft held for one second: several times the world's airborne fleet.
pub const MAX_WORLD_AIRCRAFT: usize = 50_000;
/// The most fixes held across every open second.
pub const MAX_WORLD_HELD: usize = 400_000;
/// The receivers' areas remembered (the hub's own count of receivers held).
const RECEIVERS_LOCATED: usize = crate::hub::RECEIVERS_REMEMBERED;
/// The relays remembered per receiver: a feeder names two, a v1 feeder up to its slots.
const RELAYS_PER_RECEIVER: usize = 8;
/// The areas an origin holds receptions for at once.
pub const MAX_AREAS: usize = 4_096;
/// The bytes an origin holds for its areas' unsigned copies and the keys that deduplicate them.
pub const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
/// What holding one copy costs besides its bytes, and one remembered message: the hub's numbers.
const COPY_OVERHEAD: usize = 96;
const KEY_COST: usize = 64;
/// Regional batches remembered by hash, so each is forwarded and decoded once.
const REGIONAL_REMEMBERED: usize = 200_000;
/// How old, or how far ahead, a peer's regional batch may be by its signed wall clock.
const REGIONAL_MAX_AGE_MS: u64 = 60_000;
const REGIONAL_MAX_AHEAD_MS: u64 = 10_000;
/// Peers' regional batches waiting for the next tick to be forwarded.
const FORWARD_HELD: usize = 4_096;
/// Clock models remembered: their id and inputs hash. A world-scale relay publishes some 3,800
/// a 40 s stride, and a provisional cites one up to 90 s old.
const MODELS_REMEMBERED: usize = 50_000;
/// Positions records waiting for a model they cite, and for how long.
const WAITING_HELD: usize = 4_096;
const WAITING_MS: u64 = 30_000;
/// Fixes derived from origins this relay holds, by (origin, index), to check a peer's world fix
/// that cites one of them.
const DERIVED_REMEMBERED: usize = 200_000;

/// What the relay's products have done, for operators and tests (served on `--stats-listen`,
/// `GET /products`). Every record or reception the products let go is counted here by why: none
/// is dropped silently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProductsReport {
    /// Regional batches signed as origin.
    pub regional_signed: u64,
    /// Peers' regional batches forwarded.
    pub regional_forwarded: u64,
    /// Receptions not held for want of room (`MAX_PENDING_BYTES`).
    pub regional_skipped: u64,
    /// Receptions dropped unsigned with an area forgotten for room (`MAX_AREAS`).
    pub regional_area_forgotten: u64,
    /// Receptions dropped at a seal because the relay had no key to sign them with yet.
    pub regional_unsigned: u64,
    /// Receptions too large for any regional batch.
    pub regional_oversized: u64,
    /// Peers' regional batches older or further ahead than a regional batch may be.
    pub regional_stale: u64,
    /// Peers' regional batches taken but not forwarded for room (`FORWARD_HELD`).
    pub regional_forward_full: u64,
    /// World records signed (live).
    pub world_signed: u64,
    /// Precise world records signed.
    pub precise_signed: u64,
    /// Fixes offered after their second was sealed.
    pub world_late: u64,
    /// Fixes whose second is too far before or after the relay's clock to be held.
    pub world_out_of_window: u64,
    /// Fixes not held for want of room (`MAX_WORLD_HELD`, `MAX_WORLD_AIRCRAFT`).
    pub world_skipped: u64,
    /// Peers' world fixes that disagree with the origin they cite.
    pub world_refuted: u64,
    /// Positions records not held to wait for their model, for room (`WAITING_HELD`).
    pub positions_waiting_full: u64,
    /// Positions records whose model never came within `WAITING_MS`.
    pub positions_waiting_expired: u64,
    /// Positions records whose fixes could not be derived (a malformed solution set).
    pub positions_underivable: u64,
}

pub struct Products {
    state: Mutex<State>,
}

impl Default for Products {
    fn default() -> Self {
        Self::new()
    }
}

/// A receiver's area and the relays it said it publishes to.
struct Located {
    area: Region,
    relays: Vec<PublicKey>,
}

/// One area's copies not yet signed.
#[derive(Default)]
struct Area {
    /// Each message heard, by fingerprint, and when it was first heard.
    heard: HashMap<u128, u64>,
    copies: Vec<Observation>,
    /// What `heard` and `copies` cost against `MAX_PENDING_BYTES`.
    bytes: usize,
}

/// One world product being gathered: its open seconds, and when they are sealed.
struct Gatherer {
    /// Whether this relay gathers it.
    on: bool,
    settle_ms: u64,
    /// The precise product takes no provisional fix.
    finals_only: bool,
    /// Open seconds, each aircraft's best fix so far.
    fixes: BTreeMap<u64, BTreeMap<u32, WorldFix>>,
    held: usize,
    sealed_through: Option<u64>,
}

impl Gatherer {
    fn new(settle_ms: u64, finals_only: bool) -> Self {
        Self {
            on: false,
            settle_ms,
            finals_only,
            fixes: BTreeMap::new(),
            held: 0,
            sealed_through: None,
        }
    }
}

struct State {
    keys: (RandomState, RandomState),
    boot_id: u64,
    sequence: u64,
    own: Option<PublicKey>,
    taken: Vec<Region>,
    /// The live world product and the precise one.
    live: Gatherer,
    precise: Gatherer,
    located: Bounded<PublicKey, Located>,
    areas: Bounded<Region, Area>,
    pending_bytes: usize,
    last_regional_second: Option<u64>,
    /// Regional batches seen, own and peers', by hash.
    regional_seen: Bounded<Hash, ()>,
    /// With the connection each came in on, so it is never sent back down it.
    forward: Vec<(u64, RegionalBatch)>,
    /// A model's id, and the hash of its inputs.
    models: Bounded<Hash, Hash>,
    /// Positions waiting for the model they cite, by its id: when each arrived, and the record.
    waiting: HashMap<Hash, Vec<(u64, Positions)>>,
    waiting_count: usize,
    derived: Bounded<(Hash, u16), u64>,
    report: ProductsReport,
}

impl Products {
    pub fn new() -> Self {
        let keys = (RandomState::new(), RandomState::new());
        // The standard library's per-process random keys: random per start, which is all a boot
        // id must be (as the hub's deduplicated stream takes its own).
        let boot_id = RandomState::new().build_hasher().finish();
        Self {
            state: Mutex::new(State {
                keys,
                boot_id,
                sequence: 0,
                own: None,
                taken: Vec::new(),
                live: Gatherer::new(WORLD_SETTLE_MS, false),
                precise: Gatherer::new(WORLD_PRECISE_SETTLE_MS, true),
                located: Bounded::new(RECEIVERS_LOCATED),
                areas: Bounded::new(MAX_AREAS),
                pending_bytes: 0,
                last_regional_second: None,
                regional_seen: Bounded::new(REGIONAL_REMEMBERED),
                forward: Vec::new(),
                models: Bounded::new(MODELS_REMEMBERED),
                waiting: HashMap::new(),
                waiting_count: 0,
                derived: Bounded::new(DERIVED_REMEMBERED),
                report: ProductsReport::default(),
            }),
        }
    }

    /// The areas this relay takes (the operator's, as `Selection::set_taken`): a peer's regional
    /// batch for a cell inside one is forwarded.
    pub fn set_taken(&self, areas: Vec<Region>) {
        if let Ok(mut state) = self.state.lock() {
            state.taken = areas;
        }
    }

    /// Whether this relay gathers and publishes the live world product: a relay at the top of the
    /// area tree, holding every area's positions and regional data.
    pub fn set_world(&self, world: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.live.on = world;
        }
    }

    /// Whether this relay gathers and publishes the precise world product.
    pub fn set_world_precise(&self, precise: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.precise.on = precise;
        }
    }

    pub fn report(&self) -> ProductsReport {
        self.state
            .lock()
            .map(|state| state.report)
            .unwrap_or_default()
    }

    /// A receiver's newest signed description (verified by the hub): where its area is, and
    /// whether it chose this relay. A receiver that declares no location has no area and is in
    /// no regional product.
    pub fn described(&self, info: &ReceiverInfo) {
        let (Ok(receiver), Ok(content)) = (info.receiver(), info.content()) else {
            return;
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        match content.location.map(|location| area_of(&location)) {
            Some(Ok(area)) => {
                let mut relays = content.relays;
                relays.truncate(RELAYS_PER_RECEIVER);
                state
                    .located
                    .insert_active(receiver, Located { area, relays });
            }
            _ => {
                state.located.remove(&receiver);
            }
        }
    }

    /// A receiver's batch: when the receiver chose this relay, its receptions join its area's
    /// regional dedup.
    pub fn batch(&self, batch: &Batch, receiver: &PublicKey, now_ms: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(own) = state.own else {
            return;
        };
        let area = match state.located.get(receiver) {
            Some(located) if located.relays.contains(&own) => located.area,
            _ => return,
        };
        state.located.touch(receiver);
        let Ok(content) = batch.content() else {
            return;
        };
        for observation in content.observations {
            state.offer_copy(area, observation, now_ms);
        }
    }

    /// A clock model's manifest (verified): the inputs hash its solutions' input sets are made
    /// with. Positions waiting for it are taken now.
    pub fn clock_model(&self, model: &ClockModel, now_ms: u64) {
        let Ok(manifest) = model.manifest() else {
            return;
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let id = model.id();
        state.models.insert(id, manifest.inputs);
        if let Some(waiting) = state.waiting.remove(&id) {
            state.waiting_count -= waiting.len();
            for (arrived, positions) in waiting {
                if now_ms.saturating_sub(arrived) <= WAITING_MS {
                    state.take_positions(positions, arrived);
                }
            }
        }
    }

    /// Final or provisional positions (verified): candidates for the world product.
    pub fn positions(&self, positions: &Positions, now_ms: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.take_positions(positions.clone(), now_ms);
        }
    }

    /// A world record a peer sent. A relay that gathers the world takes its fixes as candidates,
    /// except one that disagrees with an origin this relay holds. Nothing is sent back.
    pub fn world_from(&self, asker: &Asker, world: WorldPositions, now_ms: u64) -> Vec<Record> {
        if asker.role != AskerRole::Relay || world.verify().is_err() {
            return Vec::new();
        }
        if let Ok(content) = world.content() {
            self.take_world(content, false, now_ms);
        }
        Vec::new()
    }

    /// A precise world record a peer sent: as `world_from`, into the precise product.
    pub fn precise_from(&self, asker: &Asker, world: WorldPrecise, now_ms: u64) -> Vec<Record> {
        if asker.role != AskerRole::Relay || world.verify().is_err() {
            return Vec::new();
        }
        if let Ok(content) = world.content() {
            self.take_world(content, true, now_ms);
        }
        Vec::new()
    }

    fn take_world(&self, content: WorldPositionsContent, precise: bool, now_ms: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let on = if precise {
            state.precise.on
        } else {
            state.live.on
        };
        if !on {
            return;
        }
        for fix in content.fixes {
            if fix.transmitted.unix_ms / 1_000 != content.second || (precise && fix.provisional) {
                continue;
            }
            let derived = state.derived.get(&(fix.origin, fix.origin_index)).copied();
            match derived {
                Some(digest) if digest != state.digest(&fix) => state.report.world_refuted += 1,
                _ => state.offer_to(fix, precise, now_ms),
            }
        }
    }

    /// A regional batch a peer sent: once, its ADS-B positions become world candidates, and when
    /// its cell is inside an area this relay takes it is forwarded unchanged ([`Products::take_forward`],
    /// never down the connection it came in on). Nothing is sent back.
    pub fn regional_from(
        &self,
        asker: &Asker,
        regional: RegionalBatch,
        now_ms: u64,
    ) -> Vec<Record> {
        if asker.role != AskerRole::Relay || regional.verify().is_err() {
            return Vec::new();
        }
        let Ok(content) = regional.content() else {
            return Vec::new();
        };
        let fresh = content.wall_ms.saturating_add(REGIONAL_MAX_AGE_MS) >= now_ms
            && content.wall_ms <= now_ms.saturating_add(REGIONAL_MAX_AHEAD_MS);
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        if !fresh {
            state.report.regional_stale += 1;
            return Vec::new();
        }
        if state.regional_seen.get(&regional.hash()).is_some() {
            return Vec::new();
        }
        state.regional_seen.insert(regional.hash(), ());
        state.take_regional(&regional, now_ms);
        let taken = state.taken.iter().any(|area| area.contains(content.cell));
        if taken {
            if state.forward.len() < FORWARD_HELD {
                state.forward.push((asker.source, regional));
            } else {
                state.report.regional_forward_full += 1;
            }
        }
        Vec::new()
    }

    /// Peers' regional batches to forward unchanged, each with the connection it came in on: the
    /// hub's fan-out sends it to every other.
    pub fn take_forward(&self) -> Vec<(u64, RegionalBatch)> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        let forward = std::mem::take(&mut state.forward);
        state.report.regional_forwarded += forward.len() as u64;
        forward
    }

    /// The products due now, signed as this relay's: each area's copies once a second, and every
    /// world second whose seal has come.
    pub fn tick(&self, identity: Option<&Identity>, now_ms: u64) -> Vec<Record> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        state.own = identity.map(Identity::public);
        let mut out = Vec::new();
        let second = now_ms / REGIONAL_EVERY_MS;
        if state.last_regional_second != Some(second) {
            state.last_regional_second = Some(second);
            for regional in state.seal_regional(identity, now_ms) {
                out.push(Record::RegionalBatch(regional));
            }
        }
        state.expire_waiting(now_ms);
        for (second, fixes) in state.seal(false, now_ms) {
            if let Some(identity) = identity {
                let parts = world_parts(identity, second, fixes);
                state.report.world_signed += parts.len() as u64;
                out.extend(parts.into_iter().map(Record::WorldPositions));
            }
        }
        for (second, fixes) in state.seal(true, now_ms) {
            if let Some(identity) = identity {
                let parts = precise_parts(identity, second, fixes);
                state.report.precise_signed += parts.len() as u64;
                out.extend(parts.into_iter().map(Record::WorldPrecise));
            }
        }
        out
    }
}

impl State {
    fn fingerprint(&self, observation: &Observation) -> u128 {
        let half = |keys: &RandomState| {
            let mut hasher = keys.build_hasher();
            hasher.write_u8(observation.format);
            hasher.write(&observation.data);
            hasher.finish()
        };
        (u128::from(half(&self.keys.0)) << 64) | u128::from(half(&self.keys.1))
    }

    /// One reception for `area`: kept when its message was not heard there within the window.
    fn offer_copy(&mut self, area: Region, observation: Observation, now_ms: u64) {
        let fingerprint = self.fingerprint(&observation);
        if self.areas.get(&area).is_none() {
            while self.areas.len() >= MAX_AREAS {
                let Some((_, forgotten)) = self.areas.pop_first() else {
                    break;
                };
                self.pending_bytes -= forgotten.bytes;
                self.report.regional_area_forgotten += forgotten.copies.len() as u64;
            }
            self.areas.insert(area, Area::default());
        }
        self.areas.touch(&area);
        let Some(held) = self.areas.get_mut(&area) else {
            return;
        };
        let heard = held.heard.get(&fingerprint).copied();
        if heard.is_some_and(|heard| now_ms.saturating_sub(heard) < DEDUP_WINDOW_MS) {
            return;
        }
        let cost =
            if heard.is_some() { 0 } else { KEY_COST } + observation.data.len() + COPY_OVERHEAD;
        if self.pending_bytes + cost > MAX_PENDING_BYTES {
            self.report.regional_skipped += 1;
            return;
        }
        held.heard.insert(fingerprint, now_ms);
        held.copies.push(observation);
        held.bytes += cost;
        self.pending_bytes += cost;
    }

    /// Every area's copies as signed regional batches, and the messages heard a window ago
    /// forgotten. Without an identity the copies are dropped.
    fn seal_regional(&mut self, identity: Option<&Identity>, now_ms: u64) -> Vec<RegionalBatch> {
        let mut sealed = Vec::new();
        let mut cells: Vec<(Region, Vec<Observation>)> = Vec::new();
        let mut released = 0;
        let mut idle = Vec::new();
        let held: Vec<Region> = self.areas.iter().map(|(cell, _)| *cell).collect();
        for cell in held {
            let Some(area) = self.areas.get_mut(&cell) else {
                continue;
            };
            let copies = std::mem::take(&mut area.copies);
            let before = area.heard.len();
            area.heard
                .retain(|_, heard| now_ms.saturating_sub(*heard) < DEDUP_WINDOW_MS);
            let freed = (before - area.heard.len()) * KEY_COST
                + copies
                    .iter()
                    .map(|copy| copy.data.len() + COPY_OVERHEAD)
                    .sum::<usize>();
            area.bytes -= freed;
            released += freed;
            if area.heard.is_empty() {
                idle.push(cell);
            }
            if !copies.is_empty() {
                cells.push((cell, copies));
            }
        }
        self.pending_bytes -= released;
        for cell in idle {
            if let Some(area) = self.areas.remove(&cell) {
                self.pending_bytes -= area.bytes;
            }
        }
        let Some(identity) = identity else {
            self.report.regional_unsigned += cells
                .iter()
                .map(|(_, copies)| copies.len() as u64)
                .sum::<u64>();
            return sealed;
        };
        // In cell order, so the stream's sequence follows one rule.
        cells.sort_by_key(|(cell, _)| cell.as_u64());
        for (cell, copies) in cells {
            let mut todo: Vec<Vec<Observation>> = copies
                .chunks(MAX_REGIONAL_OBSERVATIONS)
                .rev()
                .map(<[Observation]>::to_vec)
                .collect();
            while let Some(chunk) = todo.pop() {
                let content = RegionalBatchContent {
                    cell,
                    boot_id: self.boot_id,
                    sequence: self.sequence,
                    wall_ms: now_ms,
                    observations: chunk,
                };
                match RegionalBatch::sign(identity, &content) {
                    Ok(regional) => {
                        self.sequence += 1;
                        self.report.regional_signed += 1;
                        self.regional_seen.insert(regional.hash(), ());
                        self.take_regional(&regional, now_ms);
                        sealed.push(regional);
                    }
                    // A copy too large for any record is not deliverable; drop it.
                    Err(_) if content.observations.len() <= 1 => {
                        self.report.regional_oversized += content.observations.len() as u64;
                    }
                    Err(_) => {
                        let mut first = content.observations;
                        let second = first.split_off(first.len() / 2);
                        todo.push(second);
                        todo.push(first);
                    }
                }
            }
        }
        sealed
    }

    /// A regional batch's ADS-B fixes, as candidates and as what a peer's citing fix must equal.
    fn take_regional(&mut self, regional: &RegionalBatch, now_ms: u64) {
        let Ok(fixes) = regional_fixes(regional) else {
            return;
        };
        for fix in fixes {
            self.remember(&fix);
            self.offer_fix(fix, now_ms);
        }
    }

    fn take_positions(&mut self, positions: Positions, now_ms: u64) {
        let models = &self.models;
        match positions_fixes(&positions, |id| models.get(id).copied()) {
            Ok(Derived::Fixes(fixes)) => {
                for fix in fixes {
                    self.remember(&fix);
                    self.offer_fix(fix, now_ms);
                }
            }
            Ok(Derived::NeedsModel(id)) => {
                if self.waiting_count < WAITING_HELD {
                    self.waiting
                        .entry(id)
                        .or_default()
                        .push((now_ms, positions));
                    self.waiting_count += 1;
                } else {
                    self.report.positions_waiting_full += 1;
                }
            }
            Err(_) => self.report.positions_underivable += 1,
        }
    }

    fn expire_waiting(&mut self, now_ms: u64) {
        let mut count = 0;
        let mut expired = 0;
        self.waiting.retain(|_, records| {
            let before = records.len();
            records.retain(|(arrived, _)| now_ms.saturating_sub(*arrived) <= WAITING_MS);
            expired += (before - records.len()) as u64;
            count += records.len();
            !records.is_empty()
        });
        self.waiting_count = count;
        self.report.positions_waiting_expired += expired;
    }

    fn digest(&self, fix: &WorldFix) -> u64 {
        let mut hasher = self.keys.0.build_hasher();
        hasher.write_u32(fix.address);
        hasher.write_u64(fix.transmitted.unix_ms);
        hasher.write_u32(fix.transmitted.sub_ms_ps);
        hasher.write_i32(fix.lat_e7);
        hasher.write_i32(fix.lon_e7);
        hasher.write_i32(fix.alt_hae_mm.unwrap_or(i32::MIN));
        hasher.write_u8(u8::from(fix.alt_hae_mm.is_some()));
        hasher.write_i32(fix.pressure_altitude_ft.unwrap_or(i32::MIN));
        hasher.write_u8(u8::from(fix.pressure_altitude_ft.is_some()));
        for term in fix.covariance.terms() {
            hasher.write_u32(term.to_bits());
        }
        hasher.write_u8(u8::from(fix.provisional));
        hasher.write_u8(u8::from(fix.mlat));
        hasher.write(&fix.input_set);
        hasher.finish()
    }

    fn remember(&mut self, fix: &WorldFix) {
        let digest = self.digest(fix);
        self.derived.insert((fix.origin, fix.origin_index), digest);
    }

    /// One candidate, for each world product that takes it.
    fn offer_fix(&mut self, fix: WorldFix, now_ms: u64) {
        self.offer_to(fix, false, now_ms);
        if !fix.provisional {
            self.offer_to(fix, true, now_ms);
        }
    }

    /// One candidate for one product: held when its second is open and it ranks above the
    /// aircraft's best so far.
    fn offer_to(&mut self, fix: WorldFix, precise: bool, now_ms: u64) {
        let gatherer = if precise {
            &mut self.precise
        } else {
            &mut self.live
        };
        if !gatherer.on || (gatherer.finals_only && fix.provisional) {
            return;
        }
        let second = fix.transmitted.unix_ms / 1_000;
        let now_second = now_ms / 1_000;
        let floor = gatherer
            .sealed_through
            .unwrap_or_else(|| now_second.saturating_sub(WORLD_BEHIND_SECONDS));
        if second <= floor && gatherer.sealed_through.is_some() {
            self.report.world_late += 1;
            return;
        }
        if second < floor || second > now_second + WORLD_AHEAD_SECONDS {
            self.report.world_out_of_window += 1;
            return;
        }
        let held_total = self.live.held + self.precise.held;
        let gatherer = if precise {
            &mut self.precise
        } else {
            &mut self.live
        };
        let aircraft = gatherer.fixes.entry(second).or_default();
        let full = held_total >= MAX_WORLD_HELD || aircraft.len() >= MAX_WORLD_AIRCRAFT;
        match aircraft.get_mut(&fix.address) {
            Some(held) => {
                if fix.ranks_above(held) {
                    *held = fix;
                }
            }
            None if full => {
                self.report.world_skipped += 1;
            }
            None => {
                aircraft.insert(fix.address, fix);
                gatherer.held += 1;
            }
        }
    }

    /// Every second of one product whose seal has come, each with its fixes ascending by
    /// address; later candidates for them are late.
    fn seal(&mut self, precise: bool, now_ms: u64) -> Vec<(u64, Vec<WorldFix>)> {
        let gatherer = if precise {
            &mut self.precise
        } else {
            &mut self.live
        };
        // Second `s` is due once `(s + 1) * 1000 + settle` has passed.
        let Some(due) = (now_ms.saturating_sub(gatherer.settle_ms) / 1_000).checked_sub(1) else {
            return Vec::new();
        };
        if !gatherer.on {
            gatherer.fixes.clear();
            gatherer.held = 0;
            gatherer.sealed_through = Some(due);
            return Vec::new();
        }
        let open = gatherer.fixes.split_off(&(due + 1));
        let sealed = std::mem::replace(&mut gatherer.fixes, open);
        gatherer.sealed_through = Some(
            gatherer
                .sealed_through
                .map_or(due, |through| through.max(due)),
        );
        sealed
            .into_iter()
            .map(|(second, aircraft)| {
                gatherer.held -= aircraft.len();
                (second, aircraft.into_values().collect())
            })
            .collect()
    }
}

/// One second's final fixes, ascending by address, as signed precise parts of at most
/// `MAX_WORLD_FIXES`.
pub fn precise_parts(identity: &Identity, second: u64, fixes: Vec<WorldFix>) -> Vec<WorldPrecise> {
    fixes
        .chunks(MAX_WORLD_FIXES)
        .enumerate()
        .filter_map(|(part, chunk)| {
            WorldPrecise::sign(
                identity,
                &WorldPositionsContent {
                    second,
                    part: u16::try_from(part).ok()?,
                    fixes: chunk.to_vec(),
                },
            )
            .ok()
        })
        .collect()
}

/// One second's fixes, ascending by address, as signed parts of at most `MAX_WORLD_FIXES`.
pub fn world_parts(identity: &Identity, second: u64, fixes: Vec<WorldFix>) -> Vec<WorldPositions> {
    fixes
        .chunks(MAX_WORLD_FIXES)
        .enumerate()
        .filter_map(|(part, chunk)| {
            WorldPositions::sign(
                identity,
                &WorldPositionsContent {
                    second,
                    part: u16::try_from(part).ok()?,
                    fixes: chunk.to_vec(),
                },
            )
            .ok()
        })
        .collect()
}

/// What a `Positions` record yields for the world product.
#[derive(Clone, Debug, PartialEq)]
pub enum Derived {
    /// One fix per solution, in the record's order.
    Fixes(Vec<WorldFix>),
    /// A solution cites a model whose inputs are not known yet: this one.
    NeedsModel(Hash),
}

/// The world fixes of a final (`Positions`) or provisional (`Provisional`) record: each solution
/// as published, its input set the merge rule's over its observations and the inputs hash of the
/// model it cites (`inputs_of`, by model id).
pub fn positions_fixes(
    positions: &Positions,
    inputs_of: impl Fn(&Hash) -> Option<Hash>,
) -> Result<Derived, WireError> {
    let content = positions.solutions()?;
    let origin = positions.hash();
    let source = positions.engine()?;
    let provisional = positions.is_provisional();
    let mut fixes = Vec::with_capacity(content.solutions.len());
    for (index, solution) in content.solutions.iter().enumerate() {
        let Some(inputs) = inputs_of(&solution.clock_model) else {
            return Ok(Derived::NeedsModel(solution.clock_model));
        };
        fixes.push(WorldFix {
            address: solution.address,
            transmitted: solution.transmitted,
            lat_e7: solution.lat_e7,
            lon_e7: solution.lon_e7,
            alt_hae_mm: solution.alt_hae_mm,
            pressure_altitude_ft: pressure_ft(solution.observations.message()),
            covariance: solution.covariance,
            provisional,
            mlat: true,
            input_set: input_set(&solution.observations, &inputs),
            source,
            origin,
            origin_index: u16::try_from(index).map_err(|_| WireError::Oversize(index))?,
        });
    }
    Ok(Derived::Fixes(fixes))
}

/// The ADS-B world fixes of a regional batch: per aircraft, its newest airborne position in the
/// record (by index) that decodes globally with the latest airborne position of the other parity
/// before it in the record. Ascending by address.
pub fn regional_fixes(regional: &RegionalBatch) -> Result<Vec<WorldFix>, WireError> {
    let content = regional.content()?;
    let origin = regional.hash();
    let source = regional.signer()?;
    let transmitted = TransmitTime::new(content.wall_ms, 0)?;
    // Each aircraft's latest even and odd airborne position so far, by index.
    let mut latest: HashMap<u32, [Option<usize>; 2]> = HashMap::new();
    let mut fixes: BTreeMap<u32, WorldFix> = BTreeMap::new();
    for (index, observation) in content.observations.iter().enumerate() {
        if observation.format != format::MODE_S_LONG {
            continue;
        }
        let (Some(position), Some(address)) = (
            modes::airborne_position(&observation.data),
            modes::address(&observation.data),
        ) else {
            continue;
        };
        let parity = usize::from(position.odd);
        let slots = latest.entry(address).or_default();
        let pair = slots[1 - parity];
        slots[parity] = Some(index);
        let Some(pair) = pair.and_then(|at| content.observations.get(at)) else {
            continue;
        };
        let Some(paired) = modes::airborne_position(&pair.data) else {
            continue;
        };
        let Ok(origin_index) = u16::try_from(index) else {
            break;
        };
        let decoded =
            adsb_fix(&position, &paired).map(|(lat_e7, lon_e7, alt_hae_mm, covariance)| WorldFix {
                address,
                transmitted,
                lat_e7,
                lon_e7,
                alt_hae_mm,
                pressure_altitude_ft: pressure_ft(&observation.data),
                covariance,
                provisional: false,
                mlat: false,
                input_set: adsb_input_set(&observation.data, &pair.data),
                source,
                origin,
                origin_index,
            });
        if let Some(fix) = decoded {
            fixes.insert(address, fix);
        }
    }
    Ok(fixes.into_values().collect())
}

/// The pressure altitude a message carries, feet (an AC13 reply's, or an airborne position's
/// barometric altitude); none for a GNSS height or no altitude.
fn pressure_ft(message: &[u8]) -> Option<i32> {
    modes::altitude(message)
        .filter(|altitude| altitude.kind == AltitudeKind::Barometric)
        .map(|altitude| altitude.feet)
}

/// Two sigma, as a 95% radius is taken here.
const SIGMAS_IN_CONTAINMENT: f64 = 2.0;
/// A GNSS height's sigma over its horizontal one.
const VERTICAL_OVER_HORIZONTAL: f64 = 1.5;
/// Millimetres in a foot.
const MM_PER_FOOT: f64 = 304.8;

/// A position decoded with its pair: degrees times 10^7, the GNSS height in millimetres when the
/// message carries one, and the covariance its type code's containment radius states. `None`
/// when the pair does not decode or the type code states no containment.
fn adsb_fix(
    position: &modes::AirbornePosition,
    paired: &modes::AirbornePosition,
) -> Option<(i32, i32, Option<i32>, EnuCovariance)> {
    let (even, odd) = if position.odd {
        (paired, position)
    } else {
        (position, paired)
    };
    let decoded = modes::cpr_global(
        (even.lat_cpr, even.lon_cpr),
        (odd.lat_cpr, odd.lon_cpr),
        position.odd,
    )?;
    let containment = modes::containment_m(position.type_code)?;
    let lat_e7 = degrees_e7(decoded.lat_deg, 90.0)?;
    let lon_e7 = degrees_e7(decoded.lon_deg, 180.0)?;
    let alt_hae_mm = match position.altitude {
        Some(altitude) if altitude.kind == AltitudeKind::Gnss => {
            let mm = (f64::from(altitude.feet) * MM_PER_FOOT).round();
            (mm.abs() < f64::from(i32::MAX)).then_some(mm as i32)
        }
        _ => None,
    };
    let sigma = containment / SIGMAS_IN_CONTAINMENT;
    let horizontal = (sigma * sigma) as f32;
    let vertical = if alt_hae_mm.is_some() {
        let up = sigma * VERTICAL_OVER_HORIZONTAL;
        (up * up) as f32
    } else {
        0.0
    };
    Some((
        lat_e7,
        lon_e7,
        alt_hae_mm,
        EnuCovariance {
            xx: horizontal,
            xy: 0.0,
            xz: 0.0,
            yy: horizontal,
            yz: 0.0,
            zz: vertical,
        },
    ))
}

fn degrees_e7(degrees: f64, limit: f64) -> Option<i32> {
    (degrees.is_finite() && degrees.abs() <= limit).then(|| (degrees * 1e7).round() as i32)
}

/// Checks a world fix against the record it cites, as any reader can: the record's hash is the
/// fix's origin, its signature verifies, and the fix is exactly what the record yields at the
/// cited index ([`regional_fixes`], or [`positions_fixes`] with the cited model's inputs from
/// `inputs_of`).
pub fn check_fix(
    fix: &WorldFix,
    origin: &Record,
    inputs_of: impl Fn(&Hash) -> Option<Hash>,
) -> Result<(), WireError> {
    let refuted = |value| WireError::Invalid {
        field: "world fix",
        value,
    };
    let derived = match origin {
        Record::RegionalBatch(regional) => {
            if regional.hash() != fix.origin {
                return Err(refuted(0));
            }
            regional.verify()?;
            regional_fixes(regional)?
                .into_iter()
                .find(|derived| derived.origin_index == fix.origin_index)
        }
        Record::Positions(positions) | Record::Provisional(positions) => {
            if positions.hash() != fix.origin {
                return Err(refuted(0));
            }
            positions.verify()?;
            match positions_fixes(positions, inputs_of)? {
                Derived::Fixes(fixes) => fixes.get(usize::from(fix.origin_index)).copied(),
                Derived::NeedsModel(_) => return Err(refuted(1)),
            }
        }
        _ => return Err(refuted(2)),
    };
    if derived.as_ref() == Some(fix) {
        Ok(())
    } else {
        Err(refuted(3))
    }
}

#[cfg(test)]
#[path = "products_tests.rs"]
mod tests;
