//! RFC-0174's relay duties, behind one seam: every new record a link takes in is handed here
//! ([`Network::handle`]); every description, batch, position and clock model the hub forwards is
//! shown here ([`Network::on_info`], [`Network::on_batch`], [`Network::on_positions`],
//! [`Network::on_clock_model`]); where a record came from is told here
//! ([`Network::from_feeder`], [`Network::from_peer`]), so sharing knows what it originates and
//! what a member sent; and one task ([`run`]) ticks the duties that act on time and carries what
//! they address to other relays over the sessions `peers` keeps. The hub holds one `Network` and
//! never learns what is inside it.
//!
//! The duties, one file set each:
//! - `admission`: capacity, what an `EchoReply` declares, whether a feeder is taken.
//! - `delivery`: the batches held for proofs of possession, and `DeliveryAnswer`s.
//! - `directory`: `ProviderOffer`s held, checked, gossiped and answered.
//! - `selection`: the areas this relay takes, and the areas it is an MLAT relay for.
//! - `sharing`: groups, striped trees, fixed seeding, parent bundles, stripe receipts.
//! - `credit`: firehose credentials, evidence bundles, the free tier.
//! - `products`: the regional and world products.
//! - `standing`: receiver standing, from verified fixes.
//! - `mlat_host`: the MLAT this relay runs for its areas (one program).
//! - `peers`: the sessions it dials to sharing members and to the relays its MLAT takes raw from.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tally_wire::{
    Batch, ClockModel, ClockModelPart, Identity, Positions, PublicKey, ReceiverInfo, Record,
    Region, RelayAddress,
};

use crate::admission::Admission;
use crate::credit::Credit;
use crate::delivery::Delivery;
use crate::directory::Directory;
use crate::hub::Hub;
use crate::mlat_host::MlatHost;
use crate::peers::Peers;
use crate::products::Products;
use crate::selection::Selection;
use crate::sharing::Sharing;
use crate::standing::Standing;

/// How often the timed duties run: often enough for provisional positions, which a hosted MLAT
/// publishes about a second after a transmission (RFC-0171 §3.8.1).
pub const TICK: Duration = Duration::from_millis(100);
/// How often receivers with standing are counted as corroborated for credit.
const CORROBORATE_EVERY_MS: u64 = 10_000;
/// Clock models held for member links, at most: a member link carries a model (its parts, then
/// its manifest) before the first record citing it (`link`'s `Told`), and a model's first part
/// names its tile, its group.
const MODELS_HELD: usize = 4_096;

/// One clock model as held: its manifest once seen, and its parts.
struct HeldModel {
    id: [u8; 32],
    manifest: Option<ClockModel>,
    parts: Vec<ClockModelPart>,
}

/// Who sent a record a duty is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asker {
    pub role: AskerRole,
    /// The key its handshake proved.
    pub key: PublicKey,
    /// The hub's id of its connection.
    pub source: u64,
    /// It is on loopback: never billed, so never rationed (`credit`), as the egress counts it.
    pub loopback: bool,
}

/// What the asker's handshake established it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AskerRole {
    Feeder,
    /// Another relay, dialled in or out.
    Relay,
    /// A client (a plain subscriber).
    Client,
    /// Another relay's hosted MLAT taking an area's raw one hop (`peers`): the one session that
    /// handshakes as `Role::Engine`. There is no engine program apart from a relay.
    Engine,
    /// A measurement session (`Role::Probe`): echoes and delivery queries only.
    Probe,
}

/// Every RFC-0174 duty of one relay.
pub struct Network {
    identity: OnceLock<Identity>,
    pub admission: Admission,
    pub delivery: Delivery,
    pub directory: Directory,
    pub selection: Selection,
    pub sharing: Sharing,
    pub credit: Credit,
    pub products: Products,
    pub standing: Standing,
    pub peers: Peers,
    mlat: OnceLock<Arc<dyn MlatHost>>,
    /// The areas last handed the hosted MLAT.
    mlat_areas: Mutex<Vec<Region>>,
    corroborated_ms: AtomicU64,
    /// Recent clock models, oldest first.
    models: Mutex<std::collections::VecDeque<HeldModel>>,
    /// Group records members sent this relay, and records of data a directory link sent it (not
    /// taken: a relay link carries only the directory).
    shared_in: AtomicU64,
    data_on_directory_links: AtomicU64,
    /// Dials this relay's own links have started (`link::Redial`): upstreams, members, raw.
    dials: Arc<AtomicU64>,
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

impl Network {
    pub fn new() -> Self {
        Self {
            identity: OnceLock::new(),
            admission: Admission::new(),
            delivery: Delivery::new(),
            directory: Directory::new(),
            selection: Selection::new(),
            sharing: Sharing::new(),
            credit: Credit::new(),
            products: Products::new(),
            standing: Standing::new(),
            peers: Peers::new(),
            mlat: OnceLock::new(),
            mlat_areas: Mutex::new(Vec::new()),
            corroborated_ms: AtomicU64::new(0),
            models: Mutex::new(std::collections::VecDeque::new()),
            shared_in: AtomicU64::new(0),
            data_on_directory_links: AtomicU64::new(0),
            dials: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Group records members have sent this relay.
    pub fn shared_in(&self) -> u64 {
        self.shared_in.load(Ordering::Relaxed)
    }

    /// The count of dials this relay's own links have started, shared with each dial loop.
    pub fn dials(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dials)
    }

    /// Records of data directory links have sent this relay, none of them taken.
    pub fn data_on_directory_links(&self) -> u64 {
        self.data_on_directory_links.load(Ordering::Relaxed)
    }

    /// A record of data came on a directory link, and was not taken.
    pub fn refused_on_directory_link(&self) {
        self.data_on_directory_links.fetch_add(1, Ordering::Relaxed);
    }

    /// The key the relay signs its network records with (its newest), once it serves.
    pub fn adopt_identity(&self, identity: Identity) {
        self.credit.adopt_identity(identity.public());
        let _ = self.identity.set(identity);
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.get()
    }

    /// The MLAT this relay runs (one program); none when its MLAT duty is off.
    pub fn host_mlat(&self, host: Arc<dyn MlatHost>) {
        let _ = self.mlat.set(host);
    }

    pub fn mlat(&self) -> Option<&Arc<dyn MlatHost>> {
        self.mlat.get()
    }

    /// A record a link took in that is a duty's: what to send back down that link (a reply), in
    /// order. A duty that has nothing to say returns nothing; a record no duty takes is dropped.
    pub fn handle(&self, hub: &Hub, asker: &Asker, record: Record, now_ms: u64) -> Vec<Record> {
        let identity = self.identity();
        match record {
            Record::Echo(echo) => self
                .admission
                .echo(hub, identity, echo, now_ms)
                .map(Record::EchoReply)
                .into_iter()
                .collect(),
            Record::DeliveryQuery(query) => {
                let point = hub.point_of(&query.receiver);
                // A relay's own answer is its own word, never credit evidence (`credit`).
                self.delivery
                    .answer_at(&self.selection, identity, &query, point, now_ms)
                    .map(Record::DeliveryAnswer)
                    .into_iter()
                    .collect()
            }
            Record::DeliveryAnswer(_) => Vec::new(),
            Record::ProviderOffer(offer) => {
                self.directory.offered(asker, offer, now_ms);
                Vec::new()
            }
            Record::ProviderQuery(query) => self
                .directory
                .query(&query, now_ms)
                .into_iter()
                .map(Record::ProviderOffer)
                .collect(),
            Record::StripeAssignment(assignment) => {
                self.sharing.assigned(asker, assignment, now_ms)
            }
            Record::PieceManifest(manifest) => self.sharing.manifest(asker, manifest, now_ms),
            Record::HaveSummary(have) => self.sharing.have(asker, have, now_ms),
            Record::StripeReceipt(receipt) => {
                self.credit.record_receipt(receipt.clone(), now_ms);
                self.sharing.receipt(asker, receipt, now_ms)
            }
            Record::FirehoseCredential(credential) => {
                self.credit.presented(asker, credential, now_ms);
                Vec::new()
            }
            // A client presents its relay's evidence for its own credit; a relay gossips every
            // relay's for the directory's ranking (`directory::State::tier`), which its clients'
            // credit may use too.
            Record::EvidenceBundle(bundle) => {
                if asker.role == AskerRole::Relay {
                    self.directory.evidence(&bundle, now_ms);
                }
                self.credit.evidence(asker, bundle, now_ms);
                Vec::new()
            }
            Record::WorldPositions(world) => self.products.world_from(asker, world, now_ms),
            Record::WorldPrecise(world) => self.products.precise_from(asker, world, now_ms),
            Record::RegionalBatch(regional) => {
                let record = Record::RegionalBatch(regional.clone());
                self.from_peer(hub, asker, &record, now_ms);
                self.products.regional_from(asker, regional, now_ms)
            }
            Record::Parity(chunk) => self.sharing.parity_chunk(asker, chunk, now_ms),
            // A bundler's index: checked, and passed on to whoever reads the parent cell.
            Record::BundleIndex(index) => {
                if asker.role == AskerRole::Relay && index.verify().is_ok() {
                    hub.publish_as(asker.source, Record::BundleIndex(index));
                }
                Vec::new()
            }
            Record::EchoReply(_) => Vec::new(),
            _ => Vec::new(),
        }
    }

    /// A receiver's description the hub kept (newer than what it held, verified).
    pub fn on_info(&self, info: &ReceiverInfo, now_ms: u64) {
        self.credit.described(info.clone(), now_ms);
        self.products.described(info);
        if let Some(mlat) = self.mlat() {
            mlat.offer(&Record::ReceiverInfo(info.clone()), now_ms);
        }
    }

    /// A receiver's batch the hub forwarded (new, verified).
    pub fn on_batch(&self, batch: &Batch, receiver: &PublicKey, now_ms: u64) {
        self.delivery.hold(batch, now_ms);
        self.products.batch(batch, receiver, now_ms);
        self.standing.batch(batch, now_ms);
        if let Some(mlat) = self.mlat() {
            mlat.offer(&Record::Batch(batch.clone()), now_ms);
        }
    }

    /// Final or provisional positions the hub forwarded (new, verified).
    pub fn on_positions(&self, positions: &Positions, now_ms: u64) {
        self.products.positions(positions, now_ms);
        self.standing.positions(positions, now_ms);
    }

    /// A clock model manifest or part the hub forwarded (new, verified or checked).
    pub fn on_clock_model(&self, record: &Record, now_ms: u64) {
        if let Record::ClockModel(model) = record {
            self.products.clock_model(model, now_ms);
        }
        self.standing.model(record, now_ms);
    }

    /// A record this relay is the first relay to hold (its own feeder's batch, an engine's or its
    /// own MLAT's positions and models, its own regional batches, a fault proof brought to it):
    /// it is the origin, and seeds it into the record's sharing group.
    pub fn originate(&self, hub: &Hub, record: &Record, now_ms: u64) {
        if let Some((cell, product)) = crate::sharing::group_of(record, self.point_for(hub, record))
        {
            self.sharing.originate(record, cell, product, now_ms);
        }
    }

    /// A batch this relay's own feeder published.
    pub fn from_feeder(&self, hub: &Hub, batch: &Batch, now_ms: u64) {
        self.originate(hub, &Record::Batch(batch.clone()), now_ms);
    }

    /// Where a record's group is reckoned from, when the record does not say: a batch's
    /// receiver's place, as described; a clock model's tile centre, from its inline bytes or its
    /// first part (`hold_part`).
    fn point_for(&self, hub: &Hub, record: &Record) -> Option<Region> {
        match record {
            Record::Batch(batch) => batch.receiver().ok().and_then(|key| hub.point_of(&key)),
            Record::ClockModel(model) => self.model_point_of(model),
            Record::FaultProof(proof) => proof
                .models_of()
                .ok()
                .and_then(|[model, _]| self.model_point_of(&model)),
            _ => None,
        }
    }

    /// The held entry of model `id`, made when new (the oldest forgotten past `MODELS_HELD`).
    fn with_model<T>(&self, id: [u8; 32], act: impl FnOnce(&mut HeldModel) -> T) -> Option<T> {
        let mut held = self.models.lock().ok()?;
        if let Some(model) = held.iter_mut().find(|model| model.id == id) {
            return Some(act(model));
        }
        if held.len() >= MODELS_HELD {
            held.pop_front();
        }
        held.push_back(HeldModel {
            id,
            manifest: None,
            parts: Vec::new(),
        });
        held.back_mut().map(act)
    }

    /// Holds a clock model's part (one too large for its manifest has them), for member links and
    /// for the model's group (its first part names its tile).
    pub fn hold_part(&self, part: &ClockModelPart) {
        let Ok(id) = part.model() else {
            return;
        };
        self.with_model(id, |model| {
            if !model
                .parts
                .iter()
                .any(|known| known.index().ok() == part.index().ok())
            {
                model.parts.push(part.clone());
            }
        });
    }

    /// Holds a clock model's manifest, for the member links that carry a record citing it.
    pub fn hold_model(&self, manifest: &ClockModel) {
        self.with_model(manifest.id(), |model| {
            model.manifest.get_or_insert_with(|| manifest.clone());
        });
    }

    /// The parts held of model `id`, in index order.
    pub fn parts_of(&self, id: &[u8; 32]) -> Vec<ClockModelPart> {
        let mut parts = self
            .models
            .lock()
            .ok()
            .and_then(|held| {
                held.iter()
                    .find(|model| model.id == *id)
                    .map(|model| model.parts.clone())
            })
            .unwrap_or_default();
        parts.sort_by_key(|part| part.index().unwrap_or(u16::MAX));
        parts
    }

    /// Model `id` as a link carries it, parts first then manifest, when its manifest is held.
    pub fn model_records(&self, id: &[u8; 32]) -> Option<Vec<Record>> {
        let manifest = self
            .models
            .lock()
            .ok()?
            .iter()
            .find(|model| model.id == *id)?
            .manifest
            .clone()?;
        let mut records: Vec<Record> = self
            .parts_of(id)
            .into_iter()
            .map(Record::ClockModelPart)
            .collect();
        records.push(Record::ClockModel(manifest));
        Some(records)
    }

    /// A model's tile centre: from its inline bytes, or its first part's when it has parts.
    fn model_point_of(&self, model: &ClockModel) -> Option<Region> {
        let manifest = model.manifest().ok()?;
        if manifest.parts.is_empty() {
            return tile_point(&manifest.inline);
        }
        let first = self.parts_of(&model.id()).into_iter().next()?;
        (first.index().ok()? == 0).then_some(())?;
        tile_point(first.data())
    }

    /// A group record a member sent this one: a piece of its group, pushed on down this relay's
    /// stripes, and the sender corroborated first-hand.
    pub fn from_peer(&self, hub: &Hub, asker: &Asker, record: &Record, now_ms: u64) {
        let point = self.point_for(hub, record);
        let Some((cell, product)) = crate::sharing::group_of(record, point) else {
            return;
        };
        if self
            .sharing
            .groups
            .members(cell, product)
            .contains(&asker.key)
        {
            self.shared_in.fetch_add(1, Ordering::Relaxed);
            self.credit.corroborate_relay(asker.key, now_ms);
            self.sharing
                .received(&asker.key, record, cell, product, now_ms);
        }
    }

    /// What the timed duties publish now, each into the hub's fan-out.
    pub fn tick(&self, hub: &Hub, now_ms: u64) -> Vec<Record> {
        let identity = self.identity();
        let mut out = Vec::new();
        out.extend(self.directory.tick(hub, identity, now_ms));
        out.extend(self.sharing.tick(hub, identity, now_ms));
        out.extend(self.products.tick(identity, now_ms));
        self.standing.tick(now_ms);
        let last = self.corroborated_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= CORROBORATE_EVERY_MS {
            self.corroborated_ms.store(now_ms, Ordering::Relaxed);
            for receiver in self.standing.agreeing(now_ms) {
                self.credit.corroborate_receiver(receiver, now_ms);
            }
        }
        if let Some(mlat) = self.mlat() {
            let areas = self.selection.mlat_areas(&self.directory, now_ms);
            let changed = self
                .mlat_areas
                .lock()
                .map(|mut held| {
                    let changed = *held != areas;
                    held.clone_from(&areas);
                    changed
                })
                .unwrap_or(false);
            if changed {
                mlat.set_areas(areas, hub.descriptions());
            }
            let published = mlat.take_published(now_ms);
            // A model's parts come before its manifest; held first, they place it.
            for record in &published {
                match record {
                    Record::ClockModelPart(part) => self.hold_part(part),
                    Record::ClockModel(model) => self.hold_model(model),
                    _ => {}
                }
            }
            for record in published {
                // This relay originated it: seeded into the sharing group of its area.
                self.originate(hub, &record, now_ms);
                out.push(record);
            }
        }
        // Its own regional batches, likewise (every other record the duties publish is a
        // product for clients, or the directory's).
        for record in &out {
            if matches!(record, Record::RegionalBatch(_)) {
                self.originate(hub, record, now_ms);
            }
        }
        out
    }

    /// What the duties address to other relays now, each down a session to that relay (`peers`):
    /// sharing's sends to its members, and the one-hop raw links of this relay's MLAT areas.
    fn carry(&self, hub: &Arc<Hub>, now_ms: u64, raw_due: bool) {
        let Some(identity) = self.identity() else {
            return;
        };
        let mut by_member: BTreeMap<PublicKey, Vec<Record>> = BTreeMap::new();
        for (member, record) in self.sharing.take_outbox() {
            by_member.entry(member).or_default().push(record);
        }
        for (member, records) in by_member {
            let Some(address) = self.directory.address_of(&member) else {
                continue;
            };
            let relay = RelayAddress {
                key: member,
                address,
            };
            self.peers.send(hub, identity, relay, records, now_ms);
        }
        self.peers.expire(now_ms);
        if raw_due {
            let sources = if self.mlat().is_some() {
                self.selection.raw_sources(&self.directory, now_ms)
            } else {
                Vec::new()
            };
            self.peers.keep_raw(hub, identity, sources, now_ms);
        }
    }
}

/// Runs the timed duties for as long as the relay runs: every `TICK`, what they publish goes into
/// the hub's fan-out as the relay's own, and what they address to other relays goes to them.
pub async fn run(hub: Arc<Hub>) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut raw_ms = 0;
    loop {
        tick.tick().await;
        let now_ms = wall_ms();
        for record in hub.network().tick(&hub, now_ms) {
            hub.publish_own(record);
        }
        // Positions held for their models past the wait go out even with nothing new coming.
        hub.release_awaiting();
        for (source, regional) in hub.network().products.take_forward() {
            hub.publish_as(source, Record::RegionalBatch(regional));
        }
        let raw_due = now_ms.saturating_sub(raw_ms) >= crate::peers::RAW_EVERY_MS;
        if raw_due {
            raw_ms = now_ms;
        }
        hub.network().carry(&hub, now_ms, raw_due);
    }
}

/// The finest cells a positions record or a clock model places aircraft at, for routing by
/// region: each solution's position; a model's tile centre. `None` for anything else, or a model
/// whose bytes are not all in its manifest (its parts carry the rest), which goes whole-world.
pub fn points_of(record: &Record) -> Option<Arc<[Region]>> {
    let points: Vec<Region> = match record {
        Record::Positions(positions) | Record::Provisional(positions) => {
            let content = positions.solutions().ok()?;
            let mut points: Vec<Region> = content
                .solutions
                .iter()
                .filter_map(|solution| {
                    Region::point(&tally_wire::Location {
                        lat_e7: solution.lat_e7,
                        lon_e7: solution.lon_e7,
                        alt_m: 0,
                        precision_m: 0,
                    })
                    .ok()
                })
                .collect();
            points.sort_by_key(|point| point.as_u64());
            points.dedup();
            points
        }
        Record::ClockModel(model) => vec![model_point(model)?],
        _ => return None,
    };
    Some(points.into())
}

/// The finest cell of a clock model's tile centre, when the model's bytes are in its manifest.
pub fn model_point(model: &tally_wire::ClockModel) -> Option<Region> {
    tile_point(&model.manifest().ok()?.inline)
}

/// The finest cell of the centre of the tile a model's encoding leads with
/// (`tally_mlat::area::centre`, the one projection, which also decides who fits it).
fn tile_point(prefix: &[u8]) -> Option<Region> {
    let tile = tally_mlat_solver::publish::tile_of(prefix).ok()?;
    Region::point(&tally_mlat::area::centre(tile)).ok()
}

pub fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_mlat_solver::geo::{self, Geodetic};
    use tally_mlat_solver::tile::{LEVELS, Tile};
    use tally_wire::rendezvous::area_of_cell;

    /// A model is routed by the area that fits its tile: the region `model_point` places it at is
    /// in the one area whose MLAT relays own the tile (`tally_mlat::window::owns`), wherever the
    /// tile is and at every level, because both read the one projection.
    #[test]
    fn a_model_is_routed_to_the_area_whose_relays_fit_its_tile() -> Result<(), String> {
        let mut checked = 0;
        for lat in (-80..=80).step_by(7) {
            for lon in (-179..=179).step_by(11) {
                let point = geo::to_ecef(Geodetic {
                    lat_deg: f64::from(lat) + 0.37,
                    lon_deg: f64::from(lon) + 0.61,
                    height_m: 10_000.0,
                });
                let mm = point.map(|axis| (axis * 1000.0).round() as i64);
                for level in 0..LEVELS {
                    let tile = Tile::containing(level, mm);
                    let routed = tile_point(&tile.bytes()).ok_or("no point")?;
                    let area = area_of_cell(routed).ok_or("no area")?;
                    assert!(
                        tally_mlat::window::owns(&[area], tile),
                        "{tile:?} routed to {area:?}, which does not fit it"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 1_000);
        Ok(())
    }
}
