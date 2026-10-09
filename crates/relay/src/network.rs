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
    Batch, ClockModel, ClockModelPart, Decoded, Identity, Positions, PublicKey, ReceiverInfo,
    Record, Region, Regions, RelayAddress,
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
    /// The address its connection came from (or was dialled at), as the socket saw it: what a
    /// duty that rations strangers buckets them by (its network group, `directory::Group`), since
    /// a key is free and an address in another network is not. `None` for a stream with no
    /// address.
    pub address: Option<std::net::IpAddr>,
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

/// A member session's admission (`Network::admit_member`): its reservation from the members'
/// pool and its part of the products' records, held together for as long as it is a member.
#[must_use = "the member's place is given up as soon as it is dropped"]
pub struct Membership {
    _records: crate::products::RecordsPart,
    _reservation: crate::budget::Reservation,
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
    pub products: Arc<Products>,
    pub standing: Arc<Standing>,
    pub peers: Peers,
    mlat: OnceLock<Arc<dyn MlatHost>>,
    /// The areas last handed the hosted MLAT, and the generation of the choice they came from.
    mlat_areas: Mutex<(u64, Regions)>,
    corroborated_ms: AtomicU64,
    /// Recent clock models, oldest first.
    models: Mutex<std::collections::VecDeque<HeldModel>>,
    /// Group records members sent this relay, and records of data a directory link sent it (not
    /// taken: a relay link carries only the directory).
    shared_in: AtomicU64,
    data_on_directory_links: AtomicU64,
    /// Overload cuts (`mlat_host::Cut`) this relay sent a relay holding its areas (one count a
    /// relay it addressed), took from one, and refused (not signed by the relay that sent it, or
    /// from one holding none of this relay's areas).
    cuts_sent: AtomicU64,
    cuts_received: AtomicU64,
    cuts_refused: AtomicU64,
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
            products: Arc::new(Products::new()),
            standing: Arc::new(Standing::new()),
            peers: Peers::new(),
            mlat: OnceLock::new(),
            mlat_areas: Mutex::new((0, Regions::default())),
            corroborated_ms: AtomicU64::new(0),
            models: Mutex::new(std::collections::VecDeque::new()),
            shared_in: AtomicU64::new(0),
            data_on_directory_links: AtomicU64::new(0),
            cuts_sent: AtomicU64::new(0),
            cuts_received: AtomicU64::new(0),
            cuts_refused: AtomicU64::new(0),
            dials: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Every duty's store charged to its gauge of `budget` (`budget::Store`), the gauge's limit its
    /// share and its only bound: the one batch byte store (sharing), the room parities are
    /// reassembled in (`budget::Budget::parity_assembly`), the delivery tags, and what the products
    /// hold. Called again when the budget is resized; the gauges are the budget's own
    /// for its life, so whoever holds one sees the new limit.
    pub fn charge_to(&self, budget: &crate::budget::Budget) {
        use crate::budget::Store;
        self.sharing.charge_to(budget.gauge(Store::Batches));
        self.sharing.assemble_in(budget.parity_assembly());
        self.delivery.charge_to(budget.gauge(Store::Delivery));
        self.products.charge_to(budget);
    }

    /// Group records members have sent this relay.
    pub fn shared_in(&self) -> u64 {
        self.shared_in.load(Ordering::Relaxed)
    }

    /// The overload cuts sent, taken and refused (`Network::publish_cuts`, `Network::take_cut`).
    pub fn cuts(&self) -> (u64, u64, u64) {
        (
            self.cuts_sent.load(Ordering::Relaxed),
            self.cuts_received.load(Ordering::Relaxed),
            self.cuts_refused.load(Ordering::Relaxed),
        )
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
        self.products.adopt_identity(&identity);
        let _ = self.identity.set(identity);
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.get()
    }

    /// The MLAT this relay runs (one program); none when its MLAT duty is off.
    pub fn host_mlat(&self, host: Arc<dyn MlatHost>) {
        // Standing reads the engine's raw: one store of raw per relay (RFC-0181 §5), and runs on
        // its threads (`Standing::start`).
        if let Some(sealed) = host.sealed_bins() {
            self.standing.read_bins(sealed);
            if let Err(error) = Standing::start(&self.standing, host.gate()) {
                eprintln!("tally-relay: {error}");
            }
        }
        let _ = self.mlat.set(host);
    }

    pub fn mlat(&self) -> Option<&Arc<dyn MlatHost>> {
        self.mlat.get()
    }

    /// A record a link took in that is a duty's: what to send back down that link (a reply), in
    /// order. A duty that has nothing to say returns nothing; a record no duty takes is dropped.
    /// `pace` is the pace the record was taken by, to which a duty owes the work it brings beyond
    /// its one token (each signature inside an evidence bundle, `credit::check`).
    pub fn handle(
        &self,
        hub: &Hub,
        asker: &Asker,
        record: Record,
        now_ms: u64,
        pace: Option<&crate::ingest::RecordPace>,
    ) -> Vec<Record> {
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
                // A relay's own answer is its own word, never credit evidence (`credit`). By the
                // ingest clock, the clock delivery held each batch by (`on_batch`).
                self.delivery
                    .answer_at(
                        &self.selection,
                        identity,
                        &query,
                        // Rationed by the prober's key, never its connection, and a stranger's
                        // by its network group (`delivery`).
                        (
                            point,
                            asker.key,
                            asker.address.map(crate::directory::Group::of),
                        ),
                        hub.now_ms(),
                    )
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
            // Sharing answers nothing down the link a message came in on: what it sends, a repair
            // page to the asker too, goes over this relay's own member links (`sharing`).
            Record::StripeAssignment(assignment) => {
                self.sharing.assigned(asker, assignment, now_ms);
                Vec::new()
            }
            Record::PieceManifest(manifest) => {
                self.sharing.manifest(asker, manifest, now_ms);
                Vec::new()
            }
            Record::HaveSummary(have) => {
                self.sharing.have(asker, have, now_ms);
                Vec::new()
            }
            Record::StripeReceipt(receipt) => {
                self.credit.record_receipt(receipt.clone(), now_ms);
                self.sharing.receipt(asker, receipt, now_ms);
                Vec::new()
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
                    self.directory.evidence(&bundle, now_ms, pace);
                }
                self.credit.evidence(asker, bundle, now_ms, pace);
                Vec::new()
            }
            // The products take a record in by its stamp against their watermark, so it is
            // stamped by the ingest clock their watermark comes from (`products::Records`).
            Record::WorldPositions(world) => {
                self.products.world_from(asker, world, hub.now_ms());
                Vec::new()
            }
            Record::WorldPrecise(world) => {
                self.products.precise_from(asker, world, hub.now_ms());
                Vec::new()
            }
            Record::RegionalBatch(regional) => {
                let record = Record::RegionalBatch(regional.clone());
                self.from_peer(hub, asker, &record, now_ms);
                self.products.regional_from(asker, regional, hub.now_ms());
                Vec::new()
            }
            Record::Parity(chunk) => {
                self.sharing.parity_chunk(asker, chunk, now_ms);
                Vec::new()
            }
            // A bundler's index: checked, and passed on to whoever reads the parent cell.
            Record::BundleIndex(index) => {
                if asker.role == AskerRole::Relay && index.verify().is_ok() {
                    hub.publish_as(asker.source, Record::BundleIndex(index));
                }
                Vec::new()
            }
            Record::MlatCut(cut) => {
                self.take_cut(asker, &cut, now_ms);
                Vec::new()
            }
            Record::EchoReply(_) => Vec::new(),
            _ => Vec::new(),
        }
    }

    /// Publishes the overload cuts the hosted MLAT decided (`MlatHost::take_cuts`), each signed by
    /// this relay and addressed, down the member links `carry` keeps, to every relay holding an
    /// area it solves (`Selection::raw_sources`: the relays offering the area's raw), which offer it
    /// to their hosts (`Network::take_cut`) to apply at the same step. A cut is a few bytes sent
    /// once, ahead of its step by `mlat_host::CUT_LEAD_STEPS`; one that cannot reach a relay in time
    /// is that relay's `cuts_late`, counted and never silent.
    pub fn publish_cuts(&self, cuts: Vec<crate::mlat_host::Cut>, now_ms: u64) {
        if cuts.is_empty() {
            return;
        }
        let Some(identity) = self.identity() else {
            return;
        };
        let sources = self.selection.raw_sources(&self.directory, now_ms);
        for cut in cuts {
            let content = tally_wire::MlatCutContent {
                from_ms: cut.from_ms,
                seats: cut.seats,
            };
            let Ok(signed) = tally_wire::MlatCut::sign(identity, &content) else {
                continue;
            };
            for source in &sources {
                if self
                    .sharing
                    .address(source.relay.key, Record::MlatCut(signed.clone()))
                {
                    self.cuts_sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// An overload cut `asker`, a relay this one verified, sent: taken by the hosted MLAT when it
    /// is signed by the relay that sent it and that relay holds an area this relay solves, else
    /// refused and counted. Whoever signs a cut can ask for fewer seats on a relay that took its
    /// word, so only a relay whose raw this one links to is heard.
    fn take_cut(&self, asker: &Asker, cut: &tally_wire::MlatCut, now_ms: u64) {
        let Some(mlat) = self.mlat() else {
            return;
        };
        let content = cut.content();
        let heard = asker.role == AskerRole::Relay
            && cut.verify().is_ok()
            && cut.signer().is_ok_and(|signer| signer == asker.key)
            && self
                .selection
                .raw_sources(&self.directory, now_ms)
                .iter()
                .any(|source| source.relay.key == asker.key);
        match content {
            Ok(content) if heard => {
                self.cuts_received.fetch_add(1, Ordering::Relaxed);
                mlat.offer_cut(crate::mlat_host::Cut {
                    from_ms: content.from_ms,
                    origin: asker.key,
                    seats: content.seats,
                });
            }
            _ => {
                self.cuts_refused.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A receiver's description the hub kept (newer than what it held, verified). The hosted
    /// MLAT is offered it by the hub, through the ingest stage, stamped there as the receiver's
    /// batches are (`Hub::describe`).
    pub fn on_info(&self, info: &ReceiverInfo, now_ms: u64) {
        self.credit.described(info.clone(), now_ms);
        self.products.described(info);
    }

    /// The one decode of a receiver's batch the hub forwarded (new, verified), when this build
    /// reads its format, stamped `stamp_ms` by the ingest clock: MLAT reads the decode and nothing
    /// else (and standing reads MLAT's sealed bins). The regional product reads it through the
    /// message exchange (`exchange`), not here, and delivery tags the batch where its receiver's
    /// place is read, as it is shared (`originate`, `from_peer`), so the batch is not passed here.
    pub fn on_batch(&self, decoded: Option<&Arc<Decoded>>, stamp_ms: u64) {
        let Some(decoded) = decoded else {
            return;
        };
        if let Some(mlat) = self.mlat() {
            mlat.offer_batch(decoded, stamp_ms);
        }
    }

    /// Final or provisional positions the hub forwarded (new, verified), handed in by the
    /// session `source` (the hub's id of its connection, `hub::RELAY_ITSELF` for the relay's own),
    /// at `now_ms` by the ingest clock (the products take them in by it, and charge them to that
    /// session, `products::From`).
    pub fn on_positions(&self, positions: &Positions, source: u64, now_ms: u64) {
        self.products.positions(positions, source, now_ms);
        self.standing.positions(positions, now_ms);
    }

    /// A clock model manifest or part the hub forwarded (new, verified or checked), handed in by
    /// the session `source`.
    pub fn on_clock_model(&self, record: &Record, source: u64, now_ms: u64) {
        if let Record::ClockModel(model) = record {
            self.products.clock_model(model, source, now_ms);
        }
        self.standing.model(record, now_ms);
    }

    /// A session opened, as `asker`. Called once for every session, as it starts. It is given
    /// no part of the products' records by opening: only a member's admission gives one
    /// ([`Network::admit_member`]).
    pub fn joined(&self, asker: &Asker) {
        let _ = asker;
    }

    /// The session `source`, a relay's, is admitted as a member with `membership`, its
    /// reservation from the members' pool (`budget::Budget::reserve_member`): from now until the
    /// [`Membership`] returned is dropped it holds that reservation and a part of the peers'
    /// share of the products' records (`products::Products::member`), the two as one, so the
    /// sessions with a part are bounded as the members are, and no directory link, engine or
    /// other session that is no member divides a member's part.
    pub fn admit_member(&self, source: u64, membership: crate::budget::Reservation) -> Membership {
        Membership {
            _records: self.products.member(source),
            _reservation: membership,
        }
    }

    /// The session `source` closed: whatever it was given ends with it (a client's credit, its
    /// free-tier place). A member's part of the products' records ends with its [`Membership`].
    /// Called once for every session, as it ends, whichever side dialled.
    pub fn left(&self, source: u64) {
        self.credit.left(source);
    }

    /// A record this relay is the first relay to hold (its own feeder's batch, an engine's or its
    /// own MLAT's positions and models, its own regional batches, a fault proof brought to it):
    /// it is the origin, and seeds it into the record's sharing group.
    pub fn originate(&self, hub: &Hub, record: &Record, now_ms: u64) {
        let point = self.point_for(hub, record);
        self.tag(record, point, now_ms);
        if let Some((cell, product)) = crate::sharing::group_of(record, point) {
            self.sharing.originate(record, cell, product, now_ms);
        }
    }

    /// A batch this relay's own feeder published.
    pub fn from_feeder(&self, hub: &Hub, batch: &Batch, now_ms: u64) {
        self.originate(hub, &Record::Batch(batch.clone()), now_ms);
    }

    /// A batch from a feeder or a peer, its receiver's place `point` (as its group is reckoned
    /// from it), at `now_ms` by the ingest clock: delivery tags it if its receiver is of the
    /// areas this relay takes (`delivery`).
    fn tag(&self, record: &Record, point: Option<Region>, now_ms: u64) {
        if let Record::Batch(batch) = record {
            self.delivery.hold(&self.selection, batch, point, now_ms);
        }
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
        self.tag(record, point, now_ms);
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
        // The products seal by the watermark as epochs close (`products::Sealer`); this takes
        // what they signed.
        out.extend(self.products.tick(identity));
        self.standing.tick(self.products.watermark_ms());
        let last = self.corroborated_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= CORROBORATE_EVERY_MS {
            self.corroborated_ms.store(now_ms, Ordering::Relaxed);
            for receiver in self.standing.agreeing(now_ms) {
                self.credit.corroborate_receiver(receiver, now_ms);
            }
        }
        if let Some(mlat) = self.mlat() {
            // The choice is recomputed only when what it follows moved (`Selection::solved`), and
            // handed on only when it came out different.
            let (generation, areas) = self.selection.solved(&self.directory, now_ms);
            let changed = self
                .mlat_areas
                .lock()
                .map(|mut held| {
                    if held.0 == generation {
                        return false;
                    }
                    held.0 = generation;
                    let changed = held.1 != areas;
                    held.1 = areas.clone();
                    changed
                })
                .unwrap_or(false);
            if changed {
                // Standing holds raw for the areas the hosted MLAT does, and for no other.
                self.standing.set_areas(&areas);
                mlat.set_areas(areas, hub.descriptions());
            }
            self.publish_cuts(mlat.take_cuts(), now_ms);
            let published = mlat.take_published(self.products.watermark_ms());
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
        // Each send carries its charge (`sharing::Addressed`) to the link, which holds it until
        // the send is written (`peers`).
        let mut by_member: BTreeMap<PublicKey, Vec<crate::sharing::Addressed>> = BTreeMap::new();
        for sent in self.sharing.take_outbox() {
            by_member.entry(sent.to).or_default().push(sent);
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

/// Starts the timed duties on a thread of their own ("tally-duties"), for as long as the runtime
/// that started them runs: every `TICK` after the last pass ended, what they publish goes into the
/// hub's fan-out as the relay's own, and what they address to other relays goes to them (a link
/// they open is spawned on that runtime, `runtime`).
///
/// Never on the async runtime's workers. A pass is synchronous work whose size follows what the
/// relay holds and was handed (a window step's positions and models published at once, the
/// sharing groups' manifests and parity, the directory), and a runtime worker held by it holds
/// every task woken from it there with it: a pass that took ten seconds on a runtime worker held
/// the subscribers' writers and feeders' readers it woke for those ten seconds, and raw's p99 went
/// to seconds while the stages idled (sweep 6). The runtime does I/O only, as the ingest workers'
/// and message threads' own threads already keep it (`ingest`).
///
/// The thread ends when the runtime does (the task holding its lifeline is dropped with it), so a
/// relay a test runs and drops leaves no duties behind.
pub fn start(hub: Arc<Hub>, runtime: tokio::runtime::Handle) {
    let (lifeline, alive) = std::sync::mpsc::channel::<()>();
    runtime.spawn(async move {
        let _lifeline = lifeline;
        std::future::pending::<()>().await
    });
    let spawned = std::thread::Builder::new()
        .name("tally-duties".to_owned())
        .spawn(move || {
            let _runtime = runtime.enter();
            let mut raw_ms = 0;
            loop {
                match alive.recv_timeout(TICK) {
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
                pass(&hub, &mut raw_ms);
            }
        });
    if let Err(error) = spawned {
        // The relay cannot run without its duties (its products would never be published).
        panic!("tally-relay: the timed duties did not start: {error}");
    }
}

/// One pass of the timed duties (`start`).
fn pass(hub: &Arc<Hub>, raw_ms: &mut u64) {
    hub.idle();
    let now_ms = wall_ms();
    for record in hub.network().tick(hub, now_ms) {
        hub.publish_own(record);
    }
    // Positions held for their models past the wait go out even with nothing new coming.
    hub.release_awaiting();
    for (source, regional) in hub.network().products.take_forward() {
        hub.publish_as(source, Record::RegionalBatch(regional));
    }
    let raw_due = now_ms.saturating_sub(*raw_ms) >= crate::peers::RAW_EVERY_MS;
    if raw_due {
        *raw_ms = now_ms;
    }
    hub.network().carry(hub, now_ms, raw_due);
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

    /// A hosted MLAT whose every ask takes `pass_ms`: a pass of the duties as long as one that
    /// publishes a window step's solutions.
    struct Slow {
        pass_ms: u64,
        asked: AtomicU64,
    }

    impl MlatHost for Slow {
        fn set_areas(&self, _: Regions, _: Vec<tally_wire::ReceiverInfo>) {}

        fn offer_description(&self, _: &tally_wire::ReceiverInfo, _: u64) {}

        fn offer_batch(&self, _: &Arc<tally_wire::Decoded>, _: u64) {}

        fn take_published(&self, _: u64) -> Vec<Record> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(self.pass_ms));
            Vec::new()
        }

        fn cores(&self) -> u16 {
            1
        }

        fn report(&self) -> crate::mlat_host::MlatReport {
            crate::mlat_host::MlatReport::default()
        }

        fn sealed_bins(&self) -> Option<tally_mlat_solver::held::SealedBins> {
            None
        }
    }

    /// Sweep 6: a pass of the timed duties, however long, holds no task of the async runtime. Before,
    /// the duties ran as a runtime task, and a pass that published a window step's solutions held its
    /// worker ten seconds with every task woken there: raw's p99 went to seconds. Here the runtime
    /// has one thread, and a task on it keeps its 10 ms beat through passes of a second each.
    #[test]
    fn a_long_pass_of_the_duties_holds_no_task_of_the_runtime() -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let hub = Arc::new(Hub::new(8));
        let slow = Arc::new(Slow {
            pass_ms: 1_000,
            asked: AtomicU64::new(0),
        });
        hub.network()
            .host_mlat(Arc::clone(&slow) as Arc<dyn MlatHost>);
        let longest = runtime.block_on(async {
            start(Arc::clone(&hub), tokio::runtime::Handle::current());
            let started = std::time::Instant::now();
            let mut last = std::time::Instant::now();
            let mut longest = Duration::ZERO;
            while started.elapsed() < Duration::from_millis(2_500) {
                tokio::time::sleep(Duration::from_millis(10)).await;
                longest = longest.max(last.elapsed());
                last = std::time::Instant::now();
            }
            longest
        });
        assert!(slow.asked.load(Ordering::SeqCst) >= 1, "no pass ran");
        assert!(
            longest < Duration::from_millis(500),
            "a runtime task waited {longest:?} behind a pass"
        );
        Ok(())
    }
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
                        tally_mlat::window::owns(&Regions::new([area]), tile),
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
