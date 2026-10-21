//! Provisional positions (RFC-0171 §3.8.1, RFC-0174 §2.4): a final position comes 7 to 47 s after
//! its transmission (the stride), so the engine also solves each target's transmissions about a
//! second after they are heard, under the newest model it has published of a tile holding their
//! receivers, carried past that model's knots (`tally_mlat_solver::Reach::Carried`, crate docs
//! § Provisional solutions), and publishes them as `Record::Provisional`. A final position of the
//! same transmission supersedes each one (`tally_merge`).
//!
//! - **What is solved** is what a window would solve: the replies (never the ADS-B positions,
//!   which sync clocks) of an aircraft no ADS-B position of which was heard in the last
//!   `ADSB_HORIZON_MS` (the span of a window), or which is in its bin's calibration sample
//!   (`tally_mlat_solver::held::sampled`).
//! - **When**: a transmission is due once `SETTLE_MS` has passed by the engine's clock since the
//!   first of its receptions arrived, and it holds enough receivers to be solved (until then its
//!   receptions wait, to `KEPT_PAST_SETTLE_MS`: the rest may be a hop away, on another relay). A feeder seals a batch once a second, so a transmission's
//!   receptions reach the engine spread over that second by the receivers' sealing phases, plus
//!   the network's spread; mlat-server's 0.9 s (adsb.lol's `MLAT_DELAY`) is for clients that
//!   stream, and a second and a tenth collects what a second's batching spreads. What arrives later
//!   is not waited for: the final position has it.
//! - **Which model**: of the newest published model of each tile (at most one per tile, at most
//!   `MAX_CARRY_PS` carried), the one whose members are the most of the receivers heard, ties to
//!   the newest window and then the lower tile. Each provisional names its model, and is a
//!   deterministic function of the model, its receptions and the spec, as a final one is, so the
//!   fault proofs that hold finals hold provisionals.
//! - **How many**: at most one per aircraft per second, the first due in each second of its
//!   receptions' earliest wall clock: about the rate a window solves (crate docs, § Targets).
//! - **Checked**: every one is read back and verified with the model carried (`verify_reach`)
//!   against the receptions it was solved from, as any checker would
//!   (`publish::solve_published`); one that fails is dropped and counted.
//! - **Published twice**: raw (format 4, relay-only) and tagged (format 6, what a client is sent),
//!   each reception's tag under the reception key of the record its model's scope names
//!   (`Carried::keys`), numbered in the one provisional sequence, raw first.
//! - **Sharded by aircraft** (RFC-0181 §3): everything but the models belongs to one aircraft, so
//!   it is held in [`SHARDS`] address shards over a keyed hash of the address ([`shard_of`]), each
//!   weighed and stepped on its own; the models ([`Book`]) are the engine's, shared read-only with
//!   every shard. The due work of all shards, ascending by aircraft, is one job ([`Plan::job`]), so
//!   any split of the shards over threads solves to the same bytes. The hash is keyed by this
//!   process's secret (`tally_wire::FingerprintKey::process`, the message fingerprint's), because
//!   a feeder chooses the addresses it reports: under a fixed hash it could craft addresses that all
//!   fall in one shard and make it the hot one.
//! - **Weighed in the order of the batches, never of their arrival**: what a batch says
//!   ([`notes_of`]) is told and held until a step weighs it ([`Shard::read`], [`Shard::keep`]),
//!   every batch in [`Order`] (its stamp, then its receiver, boot and sequence), so the same
//!   batches between two steps weigh the same however they were interleaved.
//! - **Bounded, whole**: receptions waiting by count, the engine's `Capacity::waiting` (a share a
//!   receiver, `WAITING_BYTES` each, what a relay reserves for them). A batch's replies to be solved
//!   are kept or refused together, in every shard at once ([`admit`]), counted, in the order of the
//!   batches: what is held never depends on which shard's notes landed first.
//!   A model is forgotten once it can be carried no further.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tally_mlat_solver::held::sampled;
use tally_mlat_solver::scope::{GRID_MS, Window, bin_of};
use tally_mlat_solver::{
    Calibrated, Citation, ClockModel as Model, MAX_CARRY_PS, ObservationId, Reach, Reception, Tile,
    Transmission, Unpublished, modes, publish,
};
use tally_wire::batch::Hash;
use tally_wire::{Decoded, Identity, Positions, PublicKey, Record, TaggedSolution};

use crate::window::{Keys, Part, pack_with, parallel, solutions_content};

/// How long after the first of a transmission's receptions arrives it is solved.
pub const SETTLE_MS: u64 = 1_100;
/// How long after an aircraft's last ADS-B position it is a target again: a window's span.
pub const ADSB_HORIZON_MS: u64 =
    (tally_mlat_solver::scope::BEFORE as u64 + 1 + tally_mlat_solver::scope::AFTER as u64)
        * GRID_MS;
/// How long a waiting reception is kept past its settling time when no model can carry it, or
/// while too few receivers of its transmission have come to solve it.
const KEPT_PAST_SETTLE_MS: u64 = 1_000;
/// How long a reception may wait, at most: its settling, kept past it, and the step it is read in.
/// What a receiver may have waiting is its wanted receptions over this
/// (`engine::Capacity::waiting`).
pub const WAITING_MS: u64 = SETTLE_MS + KEPT_PAST_SETTLE_MS + 1_000;
/// A waiting reception as allocated, at most: its entry in its aircraft's list (a vector, so up to
/// twice its size while the list doubles) and its message's own allocation (14 bytes, with the
/// allocator's header, rounded).
pub const WAITING_BYTES: usize = 2 * std::mem::size_of::<Waiting>() + 32;

/// A published tile model, carried for provisional solutions.
pub struct Carried {
    pub tile: Tile,
    pub window: Window,
    /// The signed manifest's id, which a provisional cites.
    pub id: Hash,
    /// Its scope's reception keys: what a provisional under it is tagged with for clients. Empty
    /// when one was missing; its provisionals are then published raw only.
    pub keys: Keys,
    pub model: Model,
    pub calibrated: Calibrated,
}

impl Carried {
    /// The wall clock past which the model can be carried no further.
    fn spent_ms(&self) -> u64 {
        (self.window.last.max(0) as u64 + 1) * GRID_MS + (MAX_CARRY_PS / 1_000_000_000) as u64
    }
}

struct Waiting {
    reception: Reception,
    arrived_ms: u64,
}

/// What provisional solving did since the last time it was asked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Transmissions chosen for solving.
    pub transmissions: usize,
    pub solved: usize,
    pub unsolved: usize,
    pub rejected: usize,
    /// Receptions no model held could map, given up on.
    pub unmodelled: usize,
    /// Receptions dropped for room.
    pub dropped: usize,
    /// Raw records (relay-only) and tagged records (what a client is sent).
    pub records: usize,
    pub tagged_records: usize,
    /// Solutions published raw that could not be tagged.
    pub untagged: usize,
}

impl Part for Report {
    fn add(&mut self, other: &Report) {
        self.transmissions += other.transmissions;
        self.solved += other.solved;
        self.unsolved += other.unsolved;
        self.rejected += other.rejected;
        self.unmodelled += other.unmodelled;
        self.dropped += other.dropped;
        self.records += other.records;
        self.tagged_records += other.tagged_records;
        self.untagged += other.untagged;
    }
}

/// Address shards of provisional solving: fixed, so an aircraft's shard never depends on how many
/// threads run. Equal to a relay's exchange shards (`tally_relay::exchange::SHARDS`).
pub const SHARDS: usize = 256;

/// The domain of the address shard under the process key (`tally_wire::decoded::keyed`).
const SHARD_DOMAIN: u8 = tally_wire::decoded::keyed::ADDRESS_SHARD;

/// The address shard of an ICAO address: a keyed hash under this process's secret (module docs),
/// uniform whatever addresses a feeder chooses, never geography, so neither a dense sky nor a
/// crafted one makes a hot shard. The same for every thread of one process, so an aircraft's shard
/// never depends on who asks.
pub fn shard_of(address: u32) -> usize {
    let mixed =
        tally_wire::FingerprintKey::process().fingerprint(SHARD_DOMAIN, &address.to_le_bytes());
    (mixed % SHARDS as u128) as usize
}

/// Where a batch stands in the order its notes are weighed: its stamp (when its holder took it),
/// then its receiver, boot and sequence, which a receiver uses once. A function of the batch, never
/// of which thread told it or when, so batches stamped between two steps weigh in one order
/// however they raced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Order {
    pub stamp_ms: u64,
    pub receiver: PublicKey,
    pub boot: u64,
    pub sequence: u64,
}

impl Order {
    /// `batch` taken at `stamp_ms` by its holder's clock.
    pub fn of(batch: &Decoded, stamp_ms: u64) -> Self {
        Self {
            stamp_ms,
            receiver: batch.receiver(),
            boot: batch.boot_id(),
            sequence: batch.sequence(),
        }
    }
}

/// What one batch would add to one address shard, read and not yet kept ([`Shard::read`]): its
/// replies to be solved there. Kept or refused whole with the batch's in every other shard
/// ([`admit`]).
pub struct Taken {
    pub order: Order,
    replies: Vec<(u32, Waiting)>,
}

impl Taken {
    /// Receptions it would add.
    pub fn len(&self) -> usize {
        self.replies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.replies.is_empty()
    }
}

/// Which batches' replies are refused, whole, in every address shard at once: in `order`, each
/// batch's replies (`sizes`, its total over every shard, ascending by [`Order`]) are kept while the
/// receptions waiting (`waiting`, every shard's after the last step) and those kept before it fit
/// `most` (the engine's `Capacity::waiting`); a batch that does not fit is refused, all of it. A
/// function of the batches, their order and the engine's capacity alone.
pub fn admit(
    waiting: usize,
    sizes: impl IntoIterator<Item = (Order, usize)>,
    most: usize,
) -> BTreeSet<Order> {
    let mut total = waiting;
    let mut refused = BTreeSet::new();
    for (order, size) in sizes {
        if total.saturating_add(size) > most {
            refused.insert(order);
        } else {
            total += size;
        }
    }
    refused
}

/// `takens` of every shard, each batch's sizes summed across them, ascending by order: what
/// [`admit`] decides on.
pub fn sizes<'a>(takens: impl IntoIterator<Item = &'a Taken>) -> BTreeMap<Order, usize> {
    let mut sizes: BTreeMap<Order, usize> = BTreeMap::new();
    for taken in takens {
        *sizes.entry(taken.order).or_default() += taken.len();
    }
    sizes
}

/// The models provisional solving carries: the newest published model of each tile, and which
/// tiles each receiver is a member of. Changed only by the engine (a window step's models, and
/// forgetting what is spent); read by every address shard, shared.
#[derive(Clone, Default)]
pub struct Book {
    models: BTreeMap<Tile, Arc<Carried>>,
    by_receiver: BTreeMap<PublicKey, BTreeSet<Tile>>,
}

impl Book {
    /// Takes a published model: the newest of its tile replaces the one held.
    pub fn adopt(&mut self, carried: Carried) {
        if self
            .models
            .get(&carried.tile)
            .is_some_and(|held| held.window.last >= carried.window.last)
        {
            return;
        }
        self.forget_model(carried.tile);
        for site in &carried.model.scope {
            self.by_receiver
                .entry(site.receiver)
                .or_default()
                .insert(carried.tile);
        }
        self.models.insert(carried.tile, Arc::new(carried));
    }

    fn forget_model(&mut self, tile: Tile) {
        let Some(held) = self.models.remove(&tile) else {
            return;
        };
        for site in &held.model.scope {
            if let Some(tiles) = self.by_receiver.get_mut(&site.receiver) {
                tiles.remove(&tile);
                if tiles.is_empty() {
                    self.by_receiver.remove(&site.receiver);
                }
            }
        }
    }

    /// Forgets every model that can be carried no further by `now_ms`.
    fn forget_spent(&mut self, now_ms: u64) {
        let spent: Vec<Tile> = self
            .models
            .iter()
            .filter(|(_, held)| held.spent_ms() < now_ms)
            .map(|(tile, _)| *tile)
            .collect();
        for tile in spent {
            self.forget_model(tile);
        }
    }

    /// Models held now.
    pub fn len(&self) -> usize {
        self.models.len()
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// The model the most of `list`'s receivers are members of (module docs).
    fn model_for(&self, list: &[Waiting]) -> Option<Arc<Carried>> {
        let receivers: BTreeSet<PublicKey> =
            list.iter().map(|one| one.reception.receiver).collect();
        let mut counts: BTreeMap<Tile, usize> = BTreeMap::new();
        for receiver in &receivers {
            for tile in self.by_receiver.get(receiver).into_iter().flatten() {
                *counts.entry(*tile).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .filter_map(|(tile, count)| self.models.get(&tile).map(|held| (count, held)))
            .max_by(|(a, x), (b, y)| {
                a.cmp(b)
                    .then(x.window.last.cmp(&y.window.last))
                    .then(y.tile.cmp(&x.tile))
            })
            .map(|(_, held)| Arc::clone(held))
    }
}

/// One address shard's state: the receptions of its aircraft waiting to be solved, when each was
/// last heard with an ADS-B position, and the last second each was solved in. Everything here
/// belongs to one aircraft, so it splits by address ([`shard_of`]): an engine that hears its own
/// batches keeps all [`SHARDS`] ([`Provisional`]), and a relay keeps them apart, each weighed and
/// stepped on whichever thread takes it (`tally_relay::mlat_host`), and the same notes in the same
/// order solve to the same bytes either way.
#[derive(Default)]
pub struct Shard {
    waiting: BTreeMap<u32, Vec<Waiting>>,
    count: usize,
    /// The newest wall clock of each aircraft's ADS-B position.
    adsb: BTreeMap<u32, u64>,
    /// The last second each aircraft was solved in.
    solved_second: BTreeMap<u32, u64>,
    report: Report,
}

/// One address shard's due transmissions, each with its aircraft and model, and what the shard
/// let go since it was last asked.
#[derive(Default)]
pub struct Due {
    pub work: Vec<(u32, Arc<Carried>, Transmission)>,
    pub report: Report,
}

impl Shard {
    /// Reads what a batch the engine admitted says of this shard's aircraft (`notes`, every one of
    /// them of this shard, in the batch's order), the batch at `order` (its stamp is when it
    /// arrived): its ADS-B positions are heard now, and its replies to be solved are handed back,
    /// to be kept ([`Shard::keep`]) or refused ([`Shard::refuse`]) with the batch's in every other
    /// shard ([`admit`]). Read in [`Order`], the batches of one step give the same whatever shard
    /// or thread reads them.
    pub fn read(&mut self, batch: &Decoded, notes: &[Note], order: Order) -> Taken {
        let now_ms = order.stamp_ms;
        let receiver = batch.receiver();
        let wall_ms = batch.wall_ms();
        let observations = batch.observations();
        let mut taken: Vec<(u32, Waiting)> = Vec::new();
        for note in notes {
            match *note {
                Note::Position(address) => {
                    let newest = self.adsb.entry(address).or_insert(wall_ms);
                    *newest = (*newest).max(wall_ms);
                }
                Note::Reply(address, index) => {
                    let Some(obs) = observations.get(index as usize) else {
                        continue;
                    };
                    if !self.target(address, wall_ms) {
                        continue;
                    }
                    taken.push((
                        address,
                        Waiting {
                            reception: Reception {
                                receiver,
                                epoch: batch.counter_epoch(),
                                observation: batch.view(obs).to_observation(),
                                wall_ms,
                            },
                            arrived_ms: now_ms,
                        },
                    ));
                }
            }
        }
        Taken {
            order,
            replies: taken,
        }
    }

    /// Keeps a batch's replies [`admit`] let in.
    pub fn keep(&mut self, taken: Taken) {
        self.count += taken.replies.len();
        for (address, waiting) in taken.replies {
            self.waiting.entry(address).or_default().push(waiting);
        }
    }

    /// Lets go of a batch's replies [`admit`] refused, counted.
    pub fn refuse(&mut self, taken: Taken) {
        self.report.dropped += taken.replies.len();
    }

    /// Receptions waiting here now.
    pub fn waiting(&self) -> usize {
        self.count
    }

    /// Whether a reply of `address` heard at `wall_ms` is a target's (module docs).
    fn target(&self, address: u32, wall_ms: u64) -> bool {
        let quiet = self
            .adsb
            .get(&address)
            .is_none_or(|newest| wall_ms.saturating_sub(*newest) > ADSB_HORIZON_MS);
        quiet || sampled(address, bin_of(wall_ms))
    }

    /// Hands out this shard's transmissions due by `now_ms` under `book`'s models, ascending by
    /// address, and forgets what can no longer be solved; with what it let go since last asked.
    pub fn due(&mut self, now_ms: u64, book: &Book) -> Due {
        self.adsb
            .retain(|_, newest| now_ms.saturating_sub(*newest) <= 2 * ADSB_HORIZON_MS);
        let settled = now_ms.saturating_sub(SETTLE_MS);
        let mut work = Vec::new();
        let addresses: Vec<u32> = self
            .waiting
            .iter()
            .filter(|(_, list)| list.iter().any(|one| one.arrived_ms <= settled))
            .map(|(address, _)| *address)
            .collect();
        for address in addresses {
            let Some(list) = self.waiting.remove(&address) else {
                continue;
            };
            self.count -= list.len();
            let kept = self.solve_due(address, list, settled, book, &mut work);
            if !kept.is_empty() {
                self.count += kept.len();
                self.waiting.insert(address, kept);
            }
        }
        self.solved_second
            .retain(|_, second| now_ms / 1000 <= *second + ADSB_HORIZON_MS / 1000);
        Due {
            work,
            report: std::mem::take(&mut self.report),
        }
    }

    /// What it let go since the last call.
    pub fn take_report(&mut self) -> Report {
        std::mem::take(&mut self.report)
    }

    /// One aircraft's waiting receptions: its due transmissions handed out (the first of each
    /// second), and what is not yet due kept.
    fn solve_due(
        &mut self,
        address: u32,
        list: Vec<Waiting>,
        settled: u64,
        book: &Book,
        work: &mut Vec<(u32, Arc<Carried>, Transmission)>,
    ) -> Vec<Waiting> {
        let expired = |one: &Waiting| one.arrived_ms + KEPT_PAST_SETTLE_MS <= settled;
        let Some(carried) = book.model_for(&list) else {
            let before = list.len();
            let kept: Vec<Waiting> = list.into_iter().filter(|one| !expired(one)).collect();
            self.report.unmodelled += before - kept.len();
            return kept;
        };
        let receptions: Vec<Reception> = list.iter().map(|one| one.reception.clone()).collect();
        let arrived: BTreeMap<ObservationId, u64> = list
            .iter()
            .map(|one| (one.reception.id(), one.arrived_ms))
            .collect();
        let grouping = tally_mlat_solver::group_reach(&carried.model, &receptions, Reach::Carried);
        let mut used: BTreeSet<ObservationId> = BTreeSet::new();
        for transmission in grouping.transmissions {
            let first = transmission
                .receptions
                .iter()
                .filter_map(|timed| arrived.get(&timed.id))
                .min()
                .copied()
                .unwrap_or(u64::MAX);
            if first > settled {
                continue;
            }
            // Fewer receivers than any solve takes: what else heard it is still on its way (from
            // the relays that hold those receivers, RFC-0174 §2.3), so it waits until it can be
            // solved or expires; it never takes the aircraft's second meanwhile.
            let receivers: BTreeSet<PublicKey> = transmission
                .receptions
                .iter()
                .map(|timed| timed.id.receiver)
                .collect();
            if receivers.len() < tally_mlat_solver::solve::MIN_RECEIVERS_WITH_ALTITUDE {
                continue;
            }
            used.extend(transmission.receptions.iter().map(|timed| timed.id));
            let second = transmission
                .receptions
                .iter()
                .map(|timed| timed.wall_ms / 1000)
                .min()
                .unwrap_or(0);
            if self
                .solved_second
                .get(&address)
                .is_some_and(|last| *last >= second)
            {
                continue;
            }
            self.solved_second.insert(address, second);
            work.push((address, Arc::clone(&carried), transmission));
        }
        let (_, rest): (Vec<Waiting>, Vec<Waiting>) = list
            .into_iter()
            .partition(|one| used.contains(&one.reception.id()));
        let (gone, kept): (Vec<Waiting>, Vec<Waiting>) = rest.into_iter().partition(expired);
        self.report.unmodelled += gone.len();
        kept
    }
}

/// What a provisional step needs of the engine, owned: who signs, the next sequence, and the
/// models to carry, so the step (weighing what was heard, finding what is due in every address
/// shard, solving) runs off the engine's thread.
pub struct Plan {
    pub identity: Identity,
    pub boot_id: u64,
    pub now_ms: u64,
    pub issued_ms: u64,
    pub threads: usize,
    pub sequence: u64,
    pub book: Arc<Book>,
}

impl Plan {
    /// The job of every address shard's due work (any split of the shards, in any order): the
    /// transmissions ascending by aircraft, as one holder of every shard hands them out, so the
    /// same shards solve to the same bytes however they were stepped. What the shards let go is
    /// the job's report.
    pub fn job(self, parts: Vec<Due>) -> Job {
        let mut report = Report::default();
        let mut work: Vec<(u32, Arc<Carried>, Transmission)> = Vec::new();
        for part in parts {
            report.add(&part.report);
            work.extend(part.work);
        }
        // Stable: an aircraft's transmissions keep the order its shard handed them out in.
        work.sort_by_key(|(address, _, _)| *address);
        Job {
            identity: self.identity,
            boot_id: self.boot_id,
            issued_ms: self.issued_ms,
            threads: self.threads.max(1),
            sequence: self.sequence,
            work: work
                .into_iter()
                .map(|(_, carried, transmission)| (carried, transmission))
                .collect(),
            report,
        }
    }
}

/// A batch told and not yet weighed: what [`notes_of`] read of it, at its place in the order.
type Told = (Order, Arc<Decoded>, Vec<Note>);

/// The provisional side of the engine's state: the models it carries and the next sequence, and
/// the address shards when the engine hears its own batches (`Provisional::new`), with what they
/// were told and have not weighed; a hosted engine's host holds the shards (`Provisional::hosted`).
pub struct Provisional {
    book: Arc<Book>,
    shards: Vec<Shard>,
    told: Vec<Told>,
    sequence: u64,
    report: Report,
    /// Receptions waiting in `shards`, at most.
    most_waiting: usize,
}

/// A provisional step's work, owned.
pub struct Job {
    pub identity: Identity,
    pub boot_id: u64,
    pub issued_ms: u64,
    pub threads: usize,
    pub sequence: u64,
    /// The transmissions, each with its model and the receptions it was grouped from.
    pub work: Vec<(Arc<Carried>, Transmission)>,
    /// What the address shards let go, reported with the step.
    pub report: Report,
}

/// A finished provisional step.
pub struct Outcome {
    pub records: Vec<Record>,
    pub sequence: u64,
    pub report: Report,
}

/// What one reception of a batch says to provisional solving (`notes_of`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// An ADS-B airborne position of this aircraft: it is not a target for a while.
    Position(u32),
    /// A reply of this aircraft, by its index in the batch: solved if the aircraft is a target.
    Reply(u32, u32),
}

impl Note {
    /// The aircraft it is of.
    pub fn address(&self) -> u32 {
        match *self {
            Note::Position(address) | Note::Reply(address, _) => address,
        }
    }

    /// Its address shard.
    pub fn shard(&self) -> usize {
        shard_of(self.address())
    }
}

/// What a batch says to provisional solving, in the batch's order: each aircraft whose ADS-B
/// airborne position it carries (once: every reception of a batch has its wall clock, so a second
/// says nothing more), and each reply MLAT solves, by index. A function of the batch alone, so the
/// thread that holds the batch reads it (a relay's raw shard, RFC-0181 §5) and the address shards
/// only weigh what it says (`Shard::read`). A reception in no product (an ACARS-family message)
/// says nothing.
pub fn notes_of(batch: &Decoded) -> Vec<Note> {
    let mut notes = Vec::new();
    let mut positions: Vec<u32> = Vec::new();
    for (index, observation) in batch.views().enumerate() {
        if !tally_wire::batch::format::in_products(observation.format) {
            continue;
        }
        let data = observation.data;
        let Some(address) = modes::address(data) else {
            continue;
        };
        match modes::downlink_format(data) {
            Some(17 | 18) => {
                if modes::airborne_position(data).is_some()
                    && let Err(at) = positions.binary_search(&address)
                {
                    positions.insert(at, address);
                    notes.push(Note::Position(address));
                }
            }
            Some(0 | 4 | 5 | 11 | 16 | 20 | 21) => {
                notes.push(Note::Reply(address, index as u32));
            }
            _ => {}
        }
    }
    notes
}

/// `notes` grouped by address shard: the shards ascending, each shard's notes in the batch's
/// order, as runs of one sorted list (`notes` is sorted in place, each note's shard hashed once).
pub fn by_shard(notes: &mut [Note]) -> Vec<(usize, std::ops::Range<usize>)> {
    // Stable: a shard's notes keep the batch's order.
    notes.sort_by_cached_key(Note::shard);
    let mut runs: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
    let mut previous: Option<(u32, usize)> = None;
    for (at, note) in notes.iter().enumerate() {
        let shard = match previous {
            Some((address, shard)) if address == note.address() => shard,
            _ => note.shard(),
        };
        previous = Some((note.address(), shard));
        match runs.last_mut() {
            Some((last, range)) if *last == shard => range.end = at + 1,
            _ => runs.push((shard, at..at + 1)),
        }
    }
    runs
}

impl Provisional {
    /// Provisional solving that hears its own batches: every address shard here, at most
    /// `most_waiting` receptions waiting in them (the engine's `Capacity::waiting`).
    pub fn new(most_waiting: usize) -> Self {
        Self {
            book: Arc::default(),
            shards: (0..SHARDS).map(|_| Shard::default()).collect(),
            told: Vec::new(),
            sequence: 0,
            report: Report::default(),
            most_waiting,
        }
    }

    /// Provisional solving whose address shards its host holds: the models and the sequence.
    pub fn hosted() -> Self {
        Self {
            shards: Vec::new(),
            ..Self::new(0)
        }
    }

    /// Takes a published model: the newest of its tile replaces the one held.
    pub fn adopt(&mut self, carried: Carried) {
        Arc::make_mut(&mut self.book).adopt(carried);
    }

    /// Models held now.
    pub fn models(&self) -> usize {
        self.book.len()
    }

    /// Takes a batch the engine admitted, arrived at `now_ms`.
    pub fn hear(&mut self, batch: &Arc<Decoded>, now_ms: u64) {
        self.hear_notes(batch, notes_of(batch), now_ms);
    }

    /// Takes what [`notes_of`] read of a batch the engine admitted, arrived at `now_ms`: the same
    /// as `hear`, with the reading done wherever the batch was held. Held until the next step
    /// weighs it, in [`Order`] (module docs). Nothing for a hosted engine.
    pub fn hear_notes(&mut self, batch: &Arc<Decoded>, notes: Vec<Note>, now_ms: u64) {
        if self.shards.is_empty() || notes.is_empty() {
            return;
        }
        self.told
            .push((Order::of(batch, now_ms), Arc::clone(batch), notes));
    }

    /// Weighs everything told, in [`Order`], as a host holding the shards apart does
    /// (`tally_relay::mlat_host`): every batch read in every shard it speaks to, then kept or
    /// refused whole by [`admit`].
    fn weigh(&mut self) {
        let mut told = std::mem::take(&mut self.told);
        told.sort_unstable_by_key(|(order, _, _)| *order);
        let waiting: usize = self.shards.iter().map(Shard::waiting).sum();
        let mut read: Vec<(usize, Taken)> = Vec::new();
        for (order, batch, mut notes) in told {
            for (shard, range) in by_shard(&mut notes) {
                read.push((shard, self.shards[shard].read(&batch, &notes[range], order)));
            }
        }
        let refused = admit(
            waiting,
            sizes(read.iter().map(|(_, taken)| taken)),
            self.most_waiting,
        );
        for (shard, taken) in read {
            if refused.contains(&taken.order) {
                self.shards[shard].refuse(taken);
            } else {
                self.shards[shard].keep(taken);
            }
        }
    }

    /// What a step at `now_ms` needs, the spent models forgotten first.
    pub fn plan(
        &mut self,
        now_ms: u64,
        identity: &Identity,
        boot_id: u64,
        issued_ms: u64,
        threads: usize,
    ) -> Plan {
        Arc::make_mut(&mut self.book).forget_spent(now_ms);
        Plan {
            identity: identity.clone(),
            boot_id,
            now_ms,
            issued_ms,
            threads: threads.max(1),
            sequence: self.sequence,
            book: Arc::clone(&self.book),
        }
    }

    /// Hands out the transmissions due by `now_ms` in every address shard here, and forgets what
    /// can no longer be solved. `None` when nothing is due.
    pub fn due(
        &mut self,
        now_ms: u64,
        identity: &Identity,
        boot_id: u64,
        issued_ms: u64,
        threads: usize,
    ) -> Option<Job> {
        self.weigh();
        let plan = self.plan(now_ms, identity, boot_id, issued_ms, threads);
        let parts: Vec<Due> = self
            .shards
            .iter_mut()
            .map(|shard| shard.due(now_ms, &plan.book))
            .collect();
        let mut job = plan.job(parts);
        self.report.add(&std::mem::take(&mut job.report));
        (!job.work.is_empty()).then_some(job)
    }

    /// Takes a finished job: its records are the next in this boot's provisional sequence.
    pub fn apply(&mut self, outcome: &Outcome) {
        self.sequence = outcome.sequence;
        self.report.add(&outcome.report);
    }

    /// What provisional solving did since the last call.
    pub fn take_report(&mut self) -> Report {
        let mut report = std::mem::take(&mut self.report);
        for shard in &mut self.shards {
            report.add(&shard.take_report());
        }
        report
    }
}

impl Job {
    pub fn run(self) -> Outcome {
        let (solved, mut report) = parallel(self.threads, &self.work, solve_one);
        let mut solutions: Vec<tally_wire::Solution> = Vec::new();
        let mut tagged: Vec<TaggedSolution> = Vec::new();
        for (solution, tag) in solved.into_iter().flatten() {
            match tag {
                Some(tag) => tagged.push(tag),
                None => report.untagged += 1,
            }
            solutions.push(solution);
        }
        let content = |sequence: u64| (self.boot_id, sequence, self.issued_ms);
        let records = pack_with(
            self.sequence,
            solutions,
            Positions::fitting,
            |sequence, run: &[tally_wire::Solution]| {
                Positions::sign_provisional(
                    &self.identity,
                    &solutions_content(content(sequence), run),
                )
            },
        );
        let sequence = self.sequence + records.len() as u64;
        let tagged = pack_with(
            sequence,
            tagged,
            Positions::fitting_tagged,
            |sequence, run: &[TaggedSolution]| {
                Positions::sign_tagged_provisional(
                    &self.identity,
                    &solutions_content(content(sequence), run),
                )
            },
        );
        report.records = records.len();
        report.tagged_records = tagged.len();
        report.add(&self.report);
        Outcome {
            sequence: sequence + tagged.len() as u64,
            records: records
                .into_iter()
                .chain(tagged)
                .map(Record::Provisional)
                .collect(),
            report,
        }
    }
}

/// Solves one transmission under its carried model, to the wire's form, verified as any checker
/// would (`publish::solve_published`).
fn solve_one(
    (carried, transmission): &(Arc<Carried>, Transmission),
    report: &mut Report,
) -> Option<(tally_wire::Solution, Option<TaggedSolution>)> {
    report.transmissions += 1;
    match publish::solve_published(
        &carried.calibrated,
        transmission,
        carried.id,
        Citation::default(),
    ) {
        Ok((_, wire)) => {
            report.solved += 1;
            let solution = tally_wire::Solution {
                addressed: tally_wire::AddressedCitation::default(),
                ..wire
            };
            let tagged = solution
                .tagged(|receiver| carried.keys.get(receiver).copied())
                .ok();
            Some((solution, tagged))
        }
        Err(Unpublished::Refuted(_)) => {
            report.rejected += 1;
            None
        }
        Err(_) => {
            report.unsolved += 1;
            None
        }
    }
}

#[cfg(test)]
#[path = "provisional_tests.rs"]
mod tests;
