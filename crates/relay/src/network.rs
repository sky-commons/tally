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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tally_wire::clocks::Judged;

use tally_wire::{
    Batch, ClockModel, ClockModelPart, Decoded, Identity, Positions, PublicKey, ReceiverInfo,
    Record, Region, Regions, RelayAddress, Signing,
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
use crate::sharing::{Now, Rebuilt, Sharing};
use crate::signer::Signer;
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

impl Asker {
    /// Whose share what it delivers is charged to (`strikes::Deliverer`): the relay's own when it
    /// is the relay itself handing in what it rebuilt (`hub::RELAY_ITSELF`), else the peer's key.
    pub fn deliverer(&self) -> crate::strikes::Deliverer {
        if self.source == crate::hub::RELAY_ITSELF {
            crate::strikes::Deliverer::Relay
        } else {
            crate::strikes::Deliverer::Peer(self.key)
        }
    }
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
    /// A measurement session (`Role::Probe`): echoes, delivery queries and a timed heartbeat only.
    Probe,
}

/// A member session's admission (`Network::admit_member`): its reservation from the members'
/// pool and its part of the products' records, held together for as long as it is a member.
#[must_use = "the member's place is given up as soon as it is dropped"]
pub struct Membership {
    _records: crate::products::RecordsPart,
    _reservation: crate::budget::Reservation,
}

/// What a regional batch's intake made of it (`Network::take_regional`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regional {
    /// Its signature checked and its signed time inside the window: taken into its group.
    Passed,
    /// Signed outside this relay's window of time: held in its group all the same, as every copy
    /// is (possession never reads a clock), but never used by the products.
    Late,
    /// Its signature or form failed, or its signed time cannot be read: refused.
    Refused,
    /// New, and no room to take it in: let go, never held in its group as had, so the group asks
    /// for it again; a member that delivered it is credited for it (`Network::no_room_from_peer`).
    Full,
}

/// Every RFC-0174 duty of one relay.
pub struct Network {
    /// The relay's key, once it serves, as everything it signs reaches it (`signer`): the one
    /// copy the duties hold.
    signer: OnceLock<Signer>,
    /// The relay's one clock: what its signer signs while synced.
    clock: crate::clock::RelayClock,
    pub admission: Admission,
    pub delivery: Delivery,
    /// The feeder figures of the receivers it hosts or carries (`figures`).
    pub figures: crate::figures::Figures,
    /// The checks a client's positions pass before a client is sent them (`consistency`).
    pub consistency: crate::consistency::Consistency,
    pub directory: Directory,
    pub selection: Selection,
    pub sharing: Sharing,
    pub credit: Credit,
    /// The freshness anchors this relay verified and the one it issues (`anchors`).
    pub anchors: crate::anchors::Anchors,
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
    /// The areas each relay that signed a cut solves, as the directory named them when last asked
    /// (`Network::solved_by`), so a flood of cuts costs one choice per relay and directory.
    cut_signers: Mutex<HashMap<PublicKey, (crate::directory::Version, Regions)>>,
    /// Dials this relay's own links have started (`link::Redial`): upstreams, members, raw.
    dials: Arc<AtomicU64>,
}

impl Network {
    /// Every duty of a relay, its sharing judging deliverers by `deadlines` (a relay's
    /// `sharing::Deadlines::RELAY`), its directory by the relay's one clock (`clock`).
    pub fn new(deadlines: crate::sharing::Deadlines, clock: crate::clock::RelayClock) -> Self {
        Self {
            signer: OnceLock::new(),
            clock: clock.clone(),
            admission: Admission::new(),
            delivery: Delivery::new(),
            figures: crate::figures::Figures::new(),
            consistency: crate::consistency::Consistency::new(),
            directory: Directory::on(clock),
            selection: Selection::new(),
            sharing: Sharing::new(deadlines),
            credit: Credit::new(),
            anchors: crate::anchors::Anchors::new(),
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
            cut_signers: Mutex::new(HashMap::new()),
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
        self.figures.charge_to(budget.gauge(Store::Figures));
        self.products.charge_to(budget);
        self.credit.charge_to(&budget.gauge(Store::Credit));
        self.anchors.charge_to(&budget.gauge(Store::Anchors));
    }

    /// Whether the stores allocated whole at start (the anchor cache) are charged in full: a relay
    /// whose budget cannot hold them refuses to start.
    pub fn fixed_charged(&self) -> Result<(), String> {
        self.anchors.charged_in_full()
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

    /// The relay's signer, the key it signs its network records with (its newest), once it
    /// serves (`serve_as`): no duty holds the key but through it.
    pub fn adopt_signer(&self, signer: Signer) {
        self.credit.adopt_identity(signer.public());
        self.products.adopt_signer(&signer);
        let _ = self.signer.set(signer);
    }

    /// As [`Network::adopt_signer`], `identity` moved into a signer on the relay's clock (a
    /// test's relay, which has no MLAT host to share it with).
    pub fn adopt_identity(&self, identity: Identity) {
        self.adopt_signer(crate::signer::on(identity, self.clock.clone()));
    }

    /// The relay's signer, once it serves: its key while its clock is synced
    /// (`Signer::with`), and its public key always.
    pub fn signer(&self) -> Option<&Signer> {
        self.signer.get()
    }

    /// `then` given the key to sign with for this one call: none before the relay serves, or
    /// when `at`, the reading the record states its time by, was taken while its clock did not
    /// judge, or while its clock does not judge now (`signer::with`).
    pub fn with_signing<T>(
        &self,
        at: impl Into<crate::strikes::Now>,
        then: impl FnOnce(Option<&Signing<'_>>) -> T,
    ) -> T {
        match self.signer() {
            Some(signer) => crate::signer::with(signer, at, then),
            None => then(None),
        }
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
        now: impl Into<Now>,
        pace: Option<&crate::ingest::RecordPace>,
    ) -> Vec<Record> {
        let now = now.into();
        let now_ms = now.judged().ms();
        match record {
            Record::Echo(echo) => self
                .with_signing(now, |identity| {
                    self.admission.echo(hub, identity, echo, now_ms)
                })
                .map(Record::EchoReply)
                .into_iter()
                .collect(),
            Record::DeliveryQuery(query) => {
                // By its public cell, as its batches are tagged (`point_for`): a feeder is a
                // client, and its answer must not turn on which area its site lies in.
                let point = hub.public_cell_of(&query.receiver);
                // A relay's own answer is its own word, never credit evidence (`credit`). Its
                // tags are read by `M`, the clock delivery held each batch by (`tag`), and it is
                // issued by `J`.
                self.with_signing(now, |identity| {
                    self.delivery.answer_at(
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
                        Now::from(hub.stamp_now()),
                    )
                })
                .map(Record::DeliveryAnswer)
                .into_iter()
                .collect()
            }
            Record::DeliveryAnswer(_) => Vec::new(),
            // An offer's lifetime and its date are judged by the clock, so none is taken while it
            // does not judge: its signer gossips it again.
            Record::ProviderOffer(offer) => {
                if now.judging() {
                    self.directory.offered(asker, offer, now.judged());
                }
                Vec::new()
            }
            Record::ProviderQuery(query) => self
                .directory
                .query(&query, now.judged())
                .into_iter()
                .map(Record::ProviderOffer)
                .collect(),
            // Sharing answers nothing down the link a message came in on: what it sends, a repair
            // page to the asker too, goes over this relay's own member links (`sharing`).
            Record::StripeAssignment(assignment) => {
                self.sharing.assigned(asker, assignment, now);
                Vec::new()
            }
            Record::PieceManifest(manifest) => {
                self.sharing.manifest(asker, manifest, now);
                Vec::new()
            }
            Record::HaveSummary(have) => {
                self.sharing.have(asker, have, now);
                Vec::new()
            }
            Record::StripeReceipt(receipt) => {
                self.credit
                    .record_receipt(receipt.clone(), crate::strikes::Now::from(now));
                self.sharing.receipt(asker, receipt, now);
                Vec::new()
            }
            Record::FirehoseCredential(credential) => {
                self.credit.presented(asker, credential, now.judged());
                Vec::new()
            }
            // A client presents its relay's evidence for its own credit; a relay gossips every
            // relay's for the directory's ranking (`directory::State::tier`), which its clients'
            // credit may use too.
            // Its age is judged by the clock, so none is taken while it does not judge.
            Record::EvidenceBundle(bundle) => {
                if !now.judging() {
                    return Vec::new();
                }
                if asker.role == AskerRole::Relay {
                    self.directory.evidence(&bundle, now.judged(), pace);
                }
                self.credit.evidence(asker, bundle, now.judged(), pace);
                Vec::new()
            }
            // The products take every input by one stamp, both clocks read together
            // (`Hub::stamp_now`): its monotonic reading orders it against their watermark
            // (`products::Records`), its judging one judges its fixes, as for positions and every
            // other input (`on_positions`).
            Record::WorldPositions(world) => {
                self.products.world_from(asker, world, hub.stamp_now());
                Vec::new()
            }
            Record::WorldPrecise(world) => {
                self.products.precise_from(asker, world, hub.stamp_now());
                Vec::new()
            }
            // The regional product, and its client form: the one intake each has
            // (`take_regional`), received into its group from the member that sent it.
            // One that fails its check is refused in its group, so no repair asks for it again.
            record @ (Record::RegionalBatch(_) | Record::ClientRegionalBatch(_)) => {
                let refused = record.clone();
                let taken = self.take_regional(hub, asker, record, |record| {
                    self.from_peer(hub, asker, record, now);
                });
                // One outside the window of time was held in its group, as every copy is.
                match taken {
                    Regional::Refused => self.refused_from_peer(hub, asker, &refused, now),
                    Regional::Full => self.no_room_from_peer(hub, asker.key, &refused, now),
                    Regional::Passed | Regional::Late => {}
                }
                Vec::new()
            }
            Record::Parity(chunk) => {
                self.sharing.parity_chunk(asker, chunk, now);
                Vec::new()
            }
            // A bundler's index: checked, and passed on to whoever reads the parent cell.
            Record::BundleIndex(index) => {
                if asker.role == AskerRole::Relay && index.verify().is_ok() {
                    hub.publish_as(asker.source, asker.deliverer(), Record::BundleIndex(index));
                }
                Vec::new()
            }
            Record::MlatCut(cut) => {
                self.take_cut(asker, &cut, now.judged());
                Vec::new()
            }
            Record::EchoReply(_) => Vec::new(),
            _ => Vec::new(),
        }
    }

    /// Publishes the overload cuts the hosted MLAT decided (`MlatHost::take_cuts`), each signed by
    /// this relay and addressed, down the member links `carry` keeps, to every relay holding an
    /// area it solves (`Selection::raw_sources`: the relays offering the area's raw), which offer it
    /// to their hosts (`Network::take_cut`) to apply at the same stamped step. A cut is a few
    /// hundred bytes; a standing one is announced again every `CUT_REFRESH_STEPS`, so a relay that
    /// was down, or started late, learns it at the next, and a cut not announced again expires
    /// (`mlat_host::CUT_TTL_MS`). One that reaches a relay after its step is that relay's
    /// `cuts_late`, counted and never silent.
    pub fn publish_cuts(&self, cuts: Vec<crate::mlat_host::Cut>, at: crate::strikes::Now) {
        if cuts.is_empty() {
            return;
        }
        let Some(signer) = self.signer().filter(|signer| at.judges() && signer.signs()) else {
            return;
        };
        let now = at.judged();
        let sources = self.selection.raw_sources(&self.directory, now);
        for cut in cuts {
            let content = tally_wire::MlatCutContent {
                from_ms: cut.from_ms,
                below: cut.below,
                areas: cut.areas,
            };
            let Ok(signed) = crate::signer::sign_with(signer, at, |identity| {
                tally_wire::MlatCut::sign(identity, &content)
            }) else {
                continue;
            };
            let mut reached = HashSet::new();
            for source in &sources {
                if reached.insert(source.relay.key)
                    && self
                        .sharing
                        .address(source.relay.key, Record::MlatCut(signed.clone()))
                {
                    self.cuts_sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// The areas `relay` solves by its verified offers (`selection::areas_solved_by`), as the
    /// directory holds them now: remembered per relay for as long as the directory's offers stay
    /// as they were.
    fn solved_by(&self, relay: &PublicKey, now: Judged) -> Regions {
        const REMEMBERED: usize = 128;
        let version = self.directory.version(now);
        if let Some(regions) = self.cut_signers.lock().ok().and_then(|held| {
            held.get(relay)
                .filter(|(held, _)| *held == version)
                .map(|(_, regions)| regions.clone())
        }) {
            return regions;
        }
        let regions = crate::selection::areas_solved_by(&self.directory, relay, now);
        if let Ok(mut held) = self.cut_signers.lock() {
            if held.len() >= REMEMBERED {
                held.clear();
            }
            held.insert(*relay, (version, regions.clone()));
        }
        regions
    }

    /// An overload cut `asker`, a relay this one verified, sent: taken by the hosted MLAT for the
    /// areas of it that `asker` solves, the first `MLAT_RELAYS_PER_AREA` of the offers covering
    /// each (`selection::mlat_relays`), when it is signed by the relay that sent it; else refused
    /// and counted. A cut is keyed by area and only the relays that solve an area may cut it: a
    /// relay that merely offers raw, or holds nothing of the area, cannot cut its solving, and one
    /// of the area's relays cannot cut an area it does not solve.
    fn take_cut(&self, asker: &Asker, cut: &tally_wire::MlatCut, now: Judged) {
        let Some(mlat) = self.mlat() else {
            return;
        };
        let heard = asker.role == AskerRole::Relay
            && cut.verify().is_ok()
            && cut.signer().is_ok_and(|signer| signer == asker.key);
        let content = cut.content().ok().filter(|_| heard);
        let taken = content.and_then(|content| {
            let held = self.solved_by(&asker.key, now);
            let areas: Vec<Region> = content
                .areas
                .iter()
                .copied()
                .filter(|area| held.contains(*area))
                .collect();
            (!areas.is_empty()).then_some(crate::mlat_host::Cut {
                from_ms: content.from_ms,
                origin: asker.key,
                below: content.below,
                areas,
            })
        });
        match taken {
            Some(cut) => {
                self.cuts_received.fetch_add(1, Ordering::Relaxed);
                mlat.offer_cut(cut);
            }
            None => {
                self.cuts_refused.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A receiver's description the hub kept (newer than what it held, verified), in either
    /// format, or a site it paired with one, with `site`, the site record in force with it (a
    /// format 1 description, or the `ReceiverSite` paired with a format 2 one; `None` while none
    /// is), and `place`, that site's location. Every site the relay adopts comes here, whichever
    /// order it came in, so what checks a client's positions (`consistency`) holds every site the
    /// hosted MLAT is offered. The hosted MLAT is offered it by the hub, through the ingest stage,
    /// stamped there as the receiver's batches are (`Hub::describe`).
    pub fn on_info(
        &self,
        info: &ReceiverInfo,
        site: Option<&tally_mlat::intake::SiteRecord>,
        place: Option<tally_wire::Location>,
        now: crate::strikes::Now,
    ) {
        if let Ok(receiver) = info.receiver() {
            self.figures
                .described(&receiver, info.public_cell().ok().flatten());
        }
        if let Some(site) = site {
            self.consistency.site(site);
        }
        self.credit.described(info.clone(), now);
        self.products.described(info, place);
    }

    /// The one decode of a receiver's batch the hub forwarded (new, verified), when this build
    /// reads its format, stamped `stamp_ms` by the ingest clock: MLAT reads the decode and nothing
    /// else (and standing reads MLAT's sealed bins). The regional product reads it through the
    /// message exchange (`exchange`), not here, and delivery tags the batch where its receiver's
    /// place is read, as it is shared (`originate`, `from_peer`), so the batch is not passed here.
    /// Its freshness is judged by its stamp's judging clock, the clock every signed time is
    /// compared with (`Hub::now_ms`); MLAT steps by its monotonic one (`ingest::Stamp`).
    pub fn on_batch(
        &self,
        decoded: Option<&Arc<Decoded>>,
        public: Option<Region>,
        stamp: crate::ingest::Stamp,
    ) {
        let Some(decoded) = decoded else {
            return;
        };
        // The feeder figures, on the ingest worker that owns the receiver's shard: a batch's own
        // clock judged against the relay's.
        self.figures.batch(decoded, public, stamp.judged());
        if let Some(mlat) = self.mlat() {
            mlat.offer_batch(decoded, stamp.mono_ms());
        }
    }

    /// Final or provisional positions the hub forwarded (new, verified), handed in by the
    /// session `source` (the hub's id of its connection, `hub::RELAY_ITSELF` for the relay's own),
    /// at `now_ms` by the relay's clock (the products take them in by it, and charge them to that
    /// session, `products::From`; the figures judge their freshness by it).
    /// The products take them in by the monotonic clock their records are stamped and sealed by;
    /// the figures and standing judge their signed times by the judging clock (`ingest::Stamp`).
    pub fn on_positions(&self, positions: &Positions, source: u64, now: crate::ingest::Stamp) {
        // A tagged record (a client's form) is its raw twin's solutions again: the products and
        // standing weigh the raw one.
        if positions.is_tagged() {
            return;
        }
        self.consistency.raw(positions);
        self.figures.positions(positions, now.judged());
        self.products.positions(positions, source, now);
        self.standing.positions(positions, now.judged());
    }

    /// A clock model manifest or part the hub forwarded (new, verified or checked), handed in by
    /// the session `source`.
    pub fn on_clock_model(&self, record: &Record, source: u64, now: crate::ingest::Stamp) {
        if let Record::ClockModel(model) = record {
            self.products.clock_model(model, source, now);
        }
        self.consistency.model(record);
        self.standing.model(record, now.judged());
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
    pub fn originate(&self, hub: &Hub, record: &Record, now: impl Into<Now>) {
        let now = now.into();
        let point = self.point_for(hub, record);
        self.tag(record, point, now);
        if let Some((cell, product)) = crate::sharing::group_of(record, point) {
            self.sharing.originate(record, cell, product, now);
        }
    }

    /// A batch this relay's own feeder published.
    pub fn from_feeder(&self, hub: &Hub, batch: &Batch, now: impl Into<Now>) {
        self.originate(hub, &Record::Batch(batch.clone()), now);
    }

    /// A batch from a feeder or a peer, its receiver's place `point` (as its group is reckoned
    /// from it), at `now`: delivery tags it if its receiver is of the areas this relay takes
    /// (`delivery`). Its tags are kept by `M` (`Now::mono_ms`), as everything the relay holds is,
    /// so a step of `J` keeps none past its window.
    fn tag(&self, record: &Record, point: Option<Region>, now: Now) {
        if let Record::Batch(batch) = record {
            self.delivery
                .hold(&self.selection, batch, point, now.mono_ms());
        }
    }

    /// Where a record's group is reckoned from, when the record does not say: a batch's
    /// receiver's public cell, as described (never its site: the area a batch is grouped, tagged
    /// and answered for is its public cell's, `rendezvous::area_of_public`, as a feeder picks its
    /// relays by); a clock model's tile centre, from its inline bytes or its first part
    /// (`hold_part`).
    fn point_for(&self, hub: &Hub, record: &Record) -> Option<Region> {
        match record {
            Record::Batch(batch) => batch
                .receiver()
                .ok()
                .and_then(|key| hub.public_cell_of(&key)),
            Record::ClockModel(model) => self.model_point_of(model),
            Record::ClientClockModel(model) => self.client_model_area(model),
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

    /// The area a client clock model is routed and grouped by: the area its full model's tile
    /// centre lies in (`ClientClockModelContent::model`), when that is held (an engine publishes the
    /// full model first, so it is). An area, never the centre: a client is routed nothing finer
    /// than a public cell, and a client model is for the area's clients.
    pub fn client_model_area(&self, model: &tally_wire::ClientClockModel) -> Option<Region> {
        let id = model.content().ok()?.model;
        let manifest = self
            .models
            .lock()
            .ok()?
            .iter()
            .find(|held| held.id == id)?
            .manifest
            .clone()?;
        tally_wire::rendezvous::area_of_cell(self.model_point_of(&manifest)?)
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
    pub fn from_peer(&self, hub: &Hub, asker: &Asker, record: &Record, now: impl Into<Now>) {
        let now = now.into();
        let point = self.point_for(hub, record);
        self.tag(record, point, now);
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
            self.credit.corroborate_relay(asker.key, now.judged());
            self.sharing
                .received(&asker.key, record, cell, product, now);
        }
    }

    /// A group record this relay rebuilt from its group's parity (`sharing::member`'s rebuild,
    /// `Hub::take_rebuilt`), judged and taken in as a member's would be: tagged for delivery as
    /// one is (`tag`), and held and pushed on down its stripe in the group that rebuilt it now that
    /// it passed (`Sharing::passed_on`), but not received into its group again, and no member
    /// corroborated by it, since none sent it.
    pub fn rebuilt(&self, hub: &Hub, rebuilt: Rebuilt, record: &Record, now: impl Into<Now>) {
        let now = now.into();
        let point = self.point_for(hub, record);
        self.tag(record, point, now);
        self.sharing.passed_on(rebuilt, record, now.judged().ms());
    }

    /// A regional batch, or its client form, that `asker` sent or this relay rebuilt from its
    /// group's parity (`Hub::take_rebuilt`): the one intake each has. Its signature is checked
    /// first, and only one that passes is taken into its group by `share`, as where it came from
    /// says, so one that fails travels no further; one signed outside this relay's window of time
    /// (`Hub::in_window`, RFC-0171 §3.6) is unusable here: held in its group as every copy is, so
    /// no receipt turns on this relay's clock, and used no further; one whose
    /// signed time cannot be read is refused. A regional batch in the window then goes to
    /// the products, which forward it unchanged when its cell is in an area this relay takes
    /// (`Products::take_forward`), once (`Hub::publish_as`); its client form is forwarded to this
    /// relay's clients while fresh (a relay's own word).
    pub fn take_regional(
        &self,
        hub: &Hub,
        asker: &Asker,
        record: Record,
        share: impl FnOnce(&Record),
    ) -> Regional {
        // One reading of both clocks, and whether the judging one judged, for every judgement of
        // this intake: its window, what is passed on, and the products' stamp.
        let stamp = hub.stamp_now();
        let now = crate::strikes::Now::from(stamp);
        match record {
            Record::RegionalBatch(regional) => {
                let Some(regional) = crate::products::Verified::of(regional) else {
                    return Regional::Refused;
                };
                let window = hub.in_window(regional.batch().wall_ms().ok(), now);
                if window == crate::hub::InWindow::Unreadable {
                    return Regional::Refused;
                }
                if window == crate::hub::InWindow::Late {
                    share(&Record::RegionalBatch(regional.batch().clone()));
                    return Regional::Late;
                }
                // Judged by what is passed on by hash before it is held in its group or used, so
                // its lease covers it (`Hub::take_passed_on`): a restart, graceful or not, never
                // merges it into the world again, where the products' own memory of it
                // (`regional_seen`) is gone. Only a new one is used; the products forward it once
                // from here (`Hub::forward_taken`). One there was no room for is let go, never
                // held as had, so its group asks for it again.
                let batch = regional.batch().clone();
                let verdict =
                    hub.take_passed_on(batch.hash(), batch.wall_ms().ok(), asker.deliverer(), now);
                match verdict {
                    crate::strikes::Verdict::Full => Regional::Full,
                    crate::strikes::Verdict::New => {
                        share(&Record::RegionalBatch(batch));
                        self.products.regional_from(asker, regional, stamp);
                        Regional::Passed
                    }
                    crate::strikes::Verdict::Duplicate => {
                        share(&Record::RegionalBatch(batch));
                        Regional::Passed
                    }
                    crate::strikes::Verdict::Late
                    | crate::strikes::Verdict::Unjudged
                    | crate::strikes::Verdict::Ahead
                    | crate::strikes::Verdict::Unanchored => {
                        share(&Record::RegionalBatch(batch));
                        Regional::Late
                    }
                }
            }
            Record::ClientRegionalBatch(regional) => {
                if regional.verify().is_err() {
                    return Regional::Refused;
                }
                let window = hub.in_window(regional.wall_ms().ok(), now);
                if window == crate::hub::InWindow::Unreadable {
                    return Regional::Refused;
                }
                if window == crate::hub::InWindow::Late {
                    share(&Record::ClientRegionalBatch(regional));
                    return Regional::Late;
                }
                // Inside the relay's one window for what relays sign: fresh to its clients.
                let record = Record::ClientRegionalBatch(regional);
                share(&record);
                hub.publish_as(asker.source, asker.deliverer(), record);
                Regional::Passed
            }
            _ => Regional::Refused,
        }
    }

    /// A record `asker` sent that this relay refused: its group's member counts it as had and
    /// never pushes it on (`sharing::Sharing::refused`). Only a member of the group's refusal is
    /// noted, as only a member's piece is received (`from_peer`): a stranger adds nothing to a
    /// group, not even an entry saying what it lacks.
    pub fn refused_from_peer(
        &self,
        hub: &Hub,
        asker: &Asker,
        record: &Record,
        now: impl Into<Now>,
    ) {
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
            self.sharing.refused(record, cell, product, now);
        }
    }

    /// A record peer `from` delivered that this relay had no room to take in
    /// (`strikes::Verdict::Full`): when `from` is a member of its group, credited there as its
    /// deliverer, so its receipt is not short for this relay's want of room
    /// (`sharing::Sharing::credit`).
    pub fn no_room_from_peer(
        &self,
        hub: &Hub,
        from: PublicKey,
        record: &Record,
        now: impl Into<Now>,
    ) {
        let point = self.point_for(hub, record);
        let Some((cell, product)) = crate::sharing::group_of(record, point) else {
            return;
        };
        if self.sharing.groups.members(cell, product).contains(&from) {
            self.sharing.credit(from, record, cell, product, now);
        }
    }

    /// What the timed duties hand on now: what they publish, each into the hub's fan-out as the
    /// relay's own, and the records the sharing groups rebuilt from parity, each taken in as a
    /// member's piece is (`Hub::take_rebuilt`).
    pub fn tick(&self, hub: &Hub, now: impl Into<Now>) -> crate::sharing::Ticked {
        let now = now.into();
        let now_ms = now.judged().ms();
        let signer = self.signer();
        // What the tables of what was taken have passed is let go, used or not; and every table
        // begun, once the clock is synced (`Hub::begin_strikes`).
        hub.sweep_strikes();
        // Nothing this relay signs is signed by a clock not synced (RFC-0171 §3.6): every duty
        // signs through its signer (`signer::Signer`), and the engine is not stepped meanwhile.
        // Whether the clock judged is `now`'s, read with it, never the clock read again later.
        let synced = now.judging();
        let mut out = Vec::new();
        // The directory's lifetimes and ranks are judged by the clock: not while it does not judge.
        if synced {
            out.extend(
                self.directory
                    .tick(hub, signer, crate::strikes::Now::from(now)),
            );
        }
        let crate::sharing::Ticked {
            rebuilt,
            unreadable,
            published,
        } = self.sharing.tick(hub, signer, now);
        out.extend(published);
        // The products seal by the watermark as epochs close (`products::Sealer`); this takes
        // what they signed.
        out.extend(self.products.tick());
        // Standing settles transmissions by their signed transmit times, so by the judging clock
        // at the products' watermark (the time the forwarded fixes were taken in by), and not at
        // all by one read while the clock did not judge.
        let watermark = self.products.watermark();
        if let Some(at) = watermark.judging_at() {
            self.standing.tick(at.judged());
        }
        // The feeder figures, signed as this relay's own claim, for its clients: by the judging
        // clock as `now` read it, and never by one read while it did not judge.
        if synced && self.figures.due(now.judged()) {
            self.with_signing(now, |identity| {
                if let Some(identity) = identity {
                    let standing: std::collections::HashSet<PublicKey> =
                        self.standing.agreeing(now.judged()).into_iter().collect();
                    out.extend(
                        self.figures
                            .sign(identity, now.judged(), |key| standing.contains(key))
                            .into_iter()
                            .map(Record::FeederFigures),
                    );
                }
            });
        }
        // Credit counts corroboration by the judging clock: not while it does not judge.
        let last = self.corroborated_ms.load(Ordering::Relaxed);
        if synced && now_ms.saturating_sub(last) >= CORROBORATE_EVERY_MS {
            self.corroborated_ms.store(now_ms, Ordering::Relaxed);
            for receiver in self.standing.agreeing(now.judged()) {
                self.credit.corroborate_receiver(receiver, now.judged());
            }
        }
        if let Some(mlat) = self.mlat() {
            // The choice is recomputed only when what it follows moved (`Selection::solved`), and
            // handed on only when it came out different.
            let (generation, areas) = self.selection.solved(&self.directory, now.judged());
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
                mlat.set_areas(areas, hub.site_records());
            }
            self.publish_cuts(mlat.take_cuts(), crate::strikes::Now::from(now));
            // Asked every tick: the host steps nothing and signs nothing by a watermark that is
            // not judging, and collapses the steps it passed meanwhile once it judges again.
            let published = mlat.take_published(self.products.watermark());
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
                self.originate(hub, &record, now);
                out.push(record);
            }
        }
        // Its own regional batches, likewise (every other record the duties publish is a
        // product for clients, or the directory's).
        for record in &out {
            if matches!(
                record,
                Record::RegionalBatch(_) | Record::ClientRegionalBatch(_)
            ) {
                self.originate(hub, record, now);
            }
        }
        crate::sharing::Ticked {
            rebuilt,
            unreadable,
            published: out,
        }
    }

    /// What the duties address to other relays now, each down a session to that relay (`peers`):
    /// sharing's sends to its members, and the one-hop raw links of this relay's MLAT areas.
    fn carry(&self, hub: &Arc<Hub>, now: Now, raw_due: bool) {
        // The key for the links' handshakes, which sign no record.
        let Some(identity) = self.signer().map(Signer::handshake) else {
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
            self.peers.send(hub, &identity, relay, records, now);
        }
        self.peers.expire(now);
        if raw_due {
            let sources = if self.mlat().is_some() {
                self.selection.raw_sources(&self.directory, now.judged())
            } else {
                Vec::new()
            };
            self.peers.keep_raw(hub, &identity, sources, now);
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
/// to seconds while the stages idled. The runtime does I/O only, as the ingest workers'
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
            let mut raw_at = None;
            loop {
                match alive.recv_timeout(TICK) {
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
                pass(&hub, &mut raw_at);
            }
        });
    if let Err(error) = spawned {
        // The relay cannot run without its duties (its products would never be published).
        panic!("tally-relay: the timed duties did not start: {error}");
    }
}

/// One pass of the timed duties (`start`). The one-hop raw links are refreshed every `peers::RAW_EVERY_MS` of the monotonic clock since
/// `raw_at`: a cadence, which judges nothing, so a relay's clock standing still (a test's script
/// between its steps) never stops it.
pub(crate) fn pass(hub: &Arc<Hub>, raw_at: &mut Option<std::time::Instant>) {
    hub.idle();
    // The relay's one clock, which this read also watches for a real step (`serve`).
    let now = hub.stamp_now();
    let ticked = hub.network().tick(hub, now);
    for record in ticked.published {
        hub.publish_own(record);
    }
    for (rebuilt, record) in ticked.rebuilt {
        hub.take_rebuilt(rebuilt, record);
    }
    for rebuilt in ticked.unreadable {
        hub.refuse_rebuilt(rebuilt);
    }
    // Positions held for their models past the wait go out even with nothing new coming.
    hub.release_awaiting(None);
    for (source, _, regional) in hub.network().products.take_forward() {
        hub.forward_taken(source, Record::RegionalBatch(regional));
    }
    let raw_due = raw_at.is_none_or(|at| {
        at.elapsed() >= std::time::Duration::from_millis(crate::peers::RAW_EVERY_MS)
    });
    if raw_due {
        *raw_at = Some(std::time::Instant::now());
    }
    hub.network().carry(hub, now.into(), raw_due);
}

/// The finest cells a positions record or a clock model places aircraft at, for routing by
/// region: each solution's position; a model's tile centre. `None` for anything else, or a model
/// whose bytes are not all in its manifest (its parts carry the rest), which goes whole-world.
pub fn points_of(record: &Record) -> Option<Arc<[Region]>> {
    let points: Vec<Region> = match record {
        Record::Positions(positions) | Record::Provisional(positions) => {
            let solved = solved(positions)?;
            let mut points: Vec<Region> = solved
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

/// Where one solution of a positions record placed its aircraft, and the model it cites: what
/// routing and sharing read of a record, raw (format 3, 4) or tagged (format 5, 6) alike.
#[derive(Clone, Copy, Debug)]
pub struct Solved {
    pub lat_e7: i32,
    pub lon_e7: i32,
    pub clock_model: [u8; 32],
}

/// The solutions of a positions record of either form, as routing reads them (`Solved`).
pub fn solved(positions: &Positions) -> Option<Vec<Solved>> {
    if positions.is_tagged() {
        let content = positions.tagged_solutions().ok()?;
        Some(
            content
                .solutions
                .iter()
                .map(|solution| Solved {
                    lat_e7: solution.lat_e7,
                    lon_e7: solution.lon_e7,
                    clock_model: solution.clock_model,
                })
                .collect(),
        )
    } else {
        let content = positions.solutions().ok()?;
        Some(
            content
                .solutions
                .iter()
                .map(|solution| Solved {
                    lat_e7: solution.lat_e7,
                    lon_e7: solution.lon_e7,
                    clock_model: solution.clock_model,
                })
                .collect(),
        )
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tally_mlat_solver::geo::{self, Geodetic};
    use tally_wire::Identity;

    /// A hosted MLAT whose every ask lasts until the runtime's task has beaten while it lasted
    /// (`beats` moved past where it stood when the ask began): a pass of the duties as long as
    /// one that publishes a window step's solutions, held for as long as it takes to see whether
    /// the runtime's tasks go on meanwhile. Seen, it says so in `beat_seen`; a pass that holds the
    /// runtime's only thread can never see one, and gives up at `HANG`.
    struct Slow {
        beats: AtomicU64,
        beat_seen: std::sync::atomic::AtomicBool,
        asked: AtomicU64,
    }

    /// How long a test waits for the event it asserts before calling it a hang.
    const HANG: Duration = Duration::from_secs(120);

    impl MlatHost for Slow {
        fn set_areas(&self, _: Regions, _: Vec<tally_mlat::intake::SiteRecord>) {}

        fn offer_description(&self, _: &tally_mlat::intake::SiteRecord, _: u64) {}

        fn offer_batch(&self, _: &Arc<tally_wire::Decoded>, _: u64) {}

        fn take_published(&self, _: crate::products::Watermark) -> Vec<Record> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.beat_seen.load(Ordering::SeqCst) {
                return Vec::new();
            }
            let before = self.beats.load(Ordering::SeqCst);
            let since = std::time::Instant::now();
            while since.elapsed() < HANG {
                if self.beats.load(Ordering::SeqCst) > before {
                    self.beat_seen.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
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

    /// A pass of the timed duties, however long, holds no task of the async runtime. Before,
    /// the duties ran as a runtime task, and a pass that published a window step's solutions held its
    /// worker ten seconds with every task woken there: raw's p99 went to seconds. Here the runtime
    /// has one thread, and a pass lasts until a task on it has beaten: it ends only if the runtime
    /// went on while it ran, which no pass on the runtime's own thread can see (it gives up at
    /// `HANG`, unseen). Held by that event, never by how long a beat took on a loaded machine.
    #[test]
    fn a_long_pass_of_the_duties_holds_no_task_of_the_runtime() -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let hub = Arc::new(Hub::new(8, crate::sharing::Deadlines::RELAY));
        let slow = Arc::new(Slow {
            beats: AtomicU64::new(0),
            beat_seen: std::sync::atomic::AtomicBool::new(false),
            asked: AtomicU64::new(0),
        });
        hub.network()
            .host_mlat(Arc::clone(&slow) as Arc<dyn MlatHost>);
        runtime.block_on(async {
            start(Arc::clone(&hub), tokio::runtime::Handle::current());
            let started = std::time::Instant::now();
            while !slow.beat_seen.load(Ordering::SeqCst) && started.elapsed() < HANG {
                tokio::time::sleep(Duration::from_millis(10)).await;
                slow.beats.fetch_add(1, Ordering::SeqCst);
            }
        });
        assert!(slow.asked.load(Ordering::SeqCst) >= 1, "no pass ran");
        assert!(
            slow.beat_seen.load(Ordering::SeqCst),
            "no runtime task ran while a pass did"
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

    /// Takes every cut offered, as a hosted MLAT would.
    #[derive(Default)]
    struct Recording {
        cuts: Mutex<Vec<crate::mlat_host::Cut>>,
    }

    impl MlatHost for Recording {
        fn set_areas(&self, _: Regions, _: Vec<tally_mlat::intake::SiteRecord>) {}

        fn offer_description(&self, _: &tally_mlat::intake::SiteRecord, _: u64) {}

        fn offer_batch(&self, _: &Arc<tally_wire::Decoded>, _: u64) {}

        fn take_published(&self, _: crate::products::Watermark) -> Vec<Record> {
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

        fn offer_cut(&self, cut: crate::mlat_host::Cut) {
            if let Ok(mut cuts) = self.cuts.lock() {
                cuts.push(cut);
            }
        }
    }

    /// RFC-0181 §10: a cut is keyed by area, and only an area's own MLAT relays (the first
    /// `MLAT_RELAYS_PER_AREA` of the offers covering it) may cut it, and only for the areas they
    /// solve. A relay that offers the area's raw but ranks outside them, a cut signed by another
    /// key than the sender's, and a cut naming an area its signer does not solve change nothing,
    /// where before a cut was accepted from any relay linked for any of the host's areas and
    /// applied to all of them.
    #[test]
    fn only_an_areas_own_mlat_relays_may_cut_it_and_only_that_area() -> Result<(), String> {
        use crate::directory::Group;
        use tally_wire::{ProviderOffer, ProviderOfferContent, Streams};
        let text = |error: &dyn std::fmt::Display| error.to_string();
        let here = tally_wire::rendezvous::area_at(51.5, -0.1).map_err(|e| text(&e))?;
        let elsewhere = tally_wire::rendezvous::area_at(48.8, 2.3).map_err(|e| text(&e))?;
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY);
        let network = hub.network();
        let me = Identity::from_seed([60; 32]);
        network.adopt_identity(crate::signer::twin(&me));
        network.directory.adopt_own_key(me.public());
        let recording = Arc::new(Recording::default());
        network.host_mlat(Arc::clone(&recording) as Arc<dyn MlatHost>);
        let now = hub.now();
        let strong: Vec<Identity> = (0..5u8)
            .map(|n| Identity::from_seed([70 + n; 32]))
            .collect();
        let hostile = Identity::from_seed([80; 32]);
        let offer = |relay: &Identity, cell: Region, cores: u16, group: u32| {
            ProviderOffer::sign(
                relay,
                &ProviderOfferContent {
                    address: format!("{}:7450", relay.public().to_base64url()),
                    cell,
                    products: Streams::RAW,
                    stripes_of: 1,
                    stripes: 1,
                    mlat_cores: cores,
                    feeder_slots: 10,
                    network: group,
                    issued_ms: now.ms(),
                    expires_ms: now.later(tally_wire::budget::policy::<_, 600_000>()).ms(),
                },
            )
            .map_err(|e| text(&e))
        };
        for (group, relay) in strong.iter().enumerate() {
            network
                .directory
                .hold_verified(
                    offer(relay, here, 64, 1 + group as u32)?,
                    Group::V4(group as u16),
                    now,
                )
                .map_err(|e| text(&e))?;
        }
        // The hostile relay offers the same raw, with one core to its name.
        network
            .directory
            .hold_verified(offer(&hostile, here, 1, 99)?, Group::V4(99), now)
            .map_err(|e| text(&e))?;
        let solvers = crate::selection::mlat_relays(here, &network.directory, now);
        assert_eq!(solvers.len(), tally_wire::rendezvous::MLAT_RELAYS_PER_AREA);
        assert!(!solvers.contains(&hostile.public()), "{solvers:?}");
        let legit = strong
            .iter()
            .find(|relay| solvers.contains(&relay.public()))
            .ok_or("no solver")?;
        // Elsewhere, every strong relay but the one chosen above offers, and the hostile one.
        for (group, relay) in strong.iter().enumerate() {
            if relay.public() != legit.public() {
                network
                    .directory
                    .hold_verified(
                        offer(relay, elsewhere, 64, 1 + group as u32)?,
                        Group::V4(group as u16),
                        now,
                    )
                    .map_err(|e| text(&e))?;
            }
        }
        network
            .directory
            .hold_verified(offer(&hostile, elsewhere, 1, 99)?, Group::V4(99), now)
            .map_err(|e| text(&e))?;
        let solved_elsewhere = crate::selection::mlat_relays(elsewhere, &network.directory, now);
        assert!(
            !solved_elsewhere.contains(&legit.public()),
            "{solved_elsewhere:?}"
        );
        let asker = |relay: &Identity| Asker {
            role: AskerRole::Relay,
            key: relay.public(),
            source: 5,
            loopback: true,
            address: None,
        };
        let send =
            |signer: &Identity, sender: &Identity, areas: Vec<Region>| -> Result<(), String> {
                let signed = tally_wire::MlatCut::sign(
                    signer,
                    &tally_wire::MlatCutContent {
                        from_ms: 10_000,
                        below: 7,
                        areas,
                    },
                )
                .map_err(|e| text(&e))?;
                network.handle(
                    &hub,
                    &asker(sender),
                    Record::MlatCut(signed),
                    hub.stamp_now(),
                    None,
                );
                Ok(())
            };
        let taken = || {
            recording
                .cuts
                .lock()
                .map(|cuts| cuts.clone())
                .unwrap_or_default()
        };
        // An out-ranked relay that offers the raw cannot cut the area, nor a solver cut an area
        // it does not solve, nor one key sign for another.
        send(&hostile, &hostile, vec![here])?;
        send(legit, legit, vec![elsewhere])?;
        send(&hostile, legit, vec![here])?;
        assert!(taken().is_empty(), "{:?}", taken());
        assert_eq!(network.cuts(), (0, 0, 3));
        // An area's own relay cuts it, and of a cut naming two areas only the one it solves.
        send(legit, legit, vec![here])?;
        let mut both = vec![here, elsewhere];
        both.sort_by_key(|area| area.as_u64());
        send(legit, legit, both)?;
        let cuts = taken();
        assert_eq!(cuts.len(), 2, "{cuts:?}");
        assert_eq!(cuts[0].areas, vec![here]);
        assert_eq!(cuts[1].origin, legit.public());
        assert_eq!(cuts[1].areas, vec![here], "an area it does not solve");
        assert_eq!(network.cuts(), (0, 2, 3));
        Ok(())
    }
}
