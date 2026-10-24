//! Sharing groups under a virtual clock: many members, each a `Member`, exchanging messages over
//! links of a fixed delay, ticked every `network::TICK`. Deterministic: keys come from seeds,
//! every map is ordered, and the event queue breaks ties by the order things were sent.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::sync::Arc;
use tally_wire::clocks::recorded::judged;

use tally_wire::batch::Hash;
use tally_wire::sharing::receipt_digest;
use tally_wire::{
    Batch, BatchContent, Identity, Location, PieceManifest, PieceManifestContent, PublicKey,
    Record, Region, Streams,
};

use super::bundles::{BundleIndex, Bundles, Omission, children};
use super::groups::{GroupKey, Groups};
use super::member::{Arrival, Deadlines, Member, Message, Outgoing, Piece};
use super::parity::Parity;
use super::seeds::{
    SEED_COPIES, SEED_ROTATION_SECONDS, SEEDS, epoch_of, is_seed, seed_members, seeded_bytes,
};
use super::stripes::{DATA_STRIPES, FANOUT, Layout, STRIPES, data_stripe};
use crate::budget::{Gauge, Store};
use crate::network::{Asker, AskerRole};

type Outcome = Result<(), String>;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn area() -> Result<Region, String> {
    Region::containing(
        &Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        },
        3,
    )
    .map_err(text)
}

fn identity(index: usize) -> Identity {
    let mut seed = [7u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
    Identity::from_seed(seed)
}

fn keys(count: usize) -> Vec<PublicKey> {
    (0..count).map(|index| identity(index).public()).collect()
}

/// When the simulation starts: a few seconds into a rotation epoch.
const START_MS: u64 = 1_800_000_000 * 1000 + 3_000;
const TICK_MS: u64 = 250;

struct Event {
    to: usize,
    from: usize,
    message: Message,
}

/// What a member's hub tells its member of a record it refused (`Sim::refusing`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Telling {
    /// Nothing: the record is only dropped.
    Nothing,
    /// That its deliverer sent it (`Member::refused`): noted, and pushed on unheld.
    Delivered,
    /// That it refused it, naming no deliverer (`Member::refuse`), as for a record rebuilt from
    /// parity that it judged bad: never pushed on.
    Refused,
}

struct Sim {
    group: GroupKey,
    members: Vec<Member>,
    keys: Vec<PublicKey>,
    index: BTreeMap<PublicKey, usize>,
    now: u64,
    next_tick: u64,
    delay_ms: u64,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    events: BTreeMap<u64, Event>,
    seq: u64,
    /// Members that left: they send and take nothing.
    down: BTreeSet<usize>,
    /// Members that take but forward nothing they did not originate.
    silent: BTreeSet<usize>,
    /// Members that forward what they did not originate this much later than the rest: slow, not
    /// silent.
    slow: BTreeMap<usize, u64>,
    /// What every member judges its deliverers by.
    deadlines: Deadlines,
    /// The first time each member held each record, and how many times it was handed one.
    held_at: BTreeMap<(usize, Hash), u64>,
    handed: BTreeMap<(usize, Hash), u32>,
    /// Every record originated: when, and by whom.
    originated: BTreeMap<Hash, (u64, usize)>,
    /// Copies of its own records each member sent into the group (to a seed), beside those it
    /// pushed down its own subtree as any member would.
    seed_copies: Vec<u64>,
    /// The members each member's own records were seeded to.
    seeded_to: Vec<BTreeSet<usize>>,
    receipts: Vec<(usize, usize, tally_wire::StripeReceipt)>,
    receiver: Identity,
    sequence: u64,
    /// (member, origin): the member's hub drops every record of that origin it is handed, and
    /// tells its member so as the [`Telling`] says.
    refusing: Option<(usize, usize, Telling)>,
    /// How far every member's judging clock reads from the simulation's (its monotonic clock):
    /// zero but in a test of a step.
    judge_step_ms: i64,
    /// Each record's encoded length.
    lens: BTreeMap<Hash, usize>,
    /// The observations each record originated carries: none but in a test of records' size.
    observations: usize,
    /// How far each member's judging clock reads from the rest's, beside the step: none but in a
    /// test of clocks apart.
    skew_ms: BTreeMap<usize, i64>,
    /// Members whose judging clock does not judge yet, as at a boot before it syncs: how far it
    /// reads from the simulation's, and the simulation's moment it judges from (reading true).
    booting: BTreeMap<usize, (i64, u64)>,
}

impl Sim {
    /// Member `i`'s two clocks now: the simulation's, and its judging clock moved by the step and
    /// by its own skew.
    fn at(&self, i: usize) -> super::Now {
        if let Some(&(off_ms, judges_from)) = self.booting.get(&i)
            && self.now < judges_from
        {
            return super::Now::from(crate::ingest::Stamp::recorded(
                self.now,
                0,
                self.now.saturating_add_signed(off_ms),
                self.now,
                false,
            ));
        }
        let skew = self.skew_ms.get(&i).copied().unwrap_or(0);
        super::Now::from(crate::ingest::Stamp::recorded(
            self.now,
            0,
            self.now
                .saturating_add_signed(self.judge_step_ms)
                .saturating_add_signed(skew),
            self.now,
            true,
        ))
    }

    /// `count` members judging by a relay's deadlines, each message `delay_ms` on its way: the
    /// clock is the simulation's, so no machine's load moves a delivery past a deadline.
    fn new(count: usize, delay_ms: u64) -> Result<Self, String> {
        Self::judging_by(count, delay_ms, Deadlines::RELAY)
    }

    /// As `new`, every member judging by `deadlines`.
    fn judging_by(count: usize, delay_ms: u64, deadlines: Deadlines) -> Result<Self, String> {
        let group = GroupKey::new(area()?, Streams::RAW);
        let keys = keys(count);
        let mut members: Vec<Member> = (0..count)
            .map(|i| {
                Member::new(
                    crate::signer::synced(identity(i)),
                    Gauge::unlimited(Store::Batches),
                    deadlines,
                )
            })
            .collect();
        let index = keys.iter().enumerate().map(|(i, key)| (*key, i)).collect();
        let mut sim = Self {
            group,
            members: Vec::new(),
            keys: keys.clone(),
            index,
            now: START_MS,
            next_tick: START_MS,
            delay_ms,
            queue: BinaryHeap::new(),
            events: BTreeMap::new(),
            seq: 0,
            down: BTreeSet::new(),
            silent: BTreeSet::new(),
            slow: BTreeMap::new(),
            deadlines,
            held_at: BTreeMap::new(),
            handed: BTreeMap::new(),
            originated: BTreeMap::new(),
            seed_copies: vec![0; count],
            seeded_to: vec![BTreeSet::new(); count],
            receipts: Vec::new(),
            receiver: identity(10_000),
            sequence: 0,
            refusing: None,
            judge_step_ms: 0,
            skew_ms: BTreeMap::new(),
            booting: BTreeMap::new(),
            lens: BTreeMap::new(),
            observations: 0,
        };
        let mut sends = Vec::new();
        for (i, member) in members.iter_mut().enumerate() {
            sends.push((i, member.set_members(group, &keys, &[], START_MS)));
        }
        sim.members = members;
        for (i, out) in sends {
            sim.send(i, out);
        }
        Ok(sim)
    }

    fn layout(&self) -> Layout {
        Layout::new(self.group.cell, self.group.product, &self.keys, &[])
    }

    fn send(&mut self, from: usize, out: Vec<Outgoing>) {
        if self.down.contains(&from) {
            return;
        }
        for outgoing in out {
            let Some(&to) = self.index.get(&outgoing.to) else {
                continue;
            };
            let forwarded = match &outgoing.message {
                Message::Piece { hash, .. } => {
                    self.originated.get(hash).map(|(_, origin)| *origin) != Some(from)
                }
                Message::Parity(_) => true,
                _ => false,
            };
            if forwarded && self.silent.contains(&from) {
                continue;
            }
            let late_ms = if forwarded {
                self.slow.get(&from).copied().unwrap_or(0)
            } else {
                0
            };
            if let Message::Piece { hash, .. } = &outgoing.message
                && !forwarded
            {
                let own_child = self.members[from]
                    .layout(self.group)
                    .and_then(|layout| {
                        layout.place(
                            data_stripe(hash),
                            epoch_of(self.now / 1000),
                            &self.keys[from],
                        )
                    })
                    .is_some_and(|place| place.children.contains(&outgoing.to));
                if !own_child {
                    self.seed_copies[from] += 1;
                    self.seeded_to[from].insert(to);
                }
            }
            if let Message::Receipt(receipt) = &outgoing.message {
                self.receipts.push((from, to, receipt.clone()));
            }
            self.seq += 1;
            self.queue
                .push(Reverse((self.now + self.delay_ms + late_ms, self.seq)));
            self.events.insert(
                self.seq,
                Event {
                    to,
                    from,
                    message: outgoing.message,
                },
            );
        }
    }

    /// What member `i` newly holds, handed to its relay; one it rebuilt from parity is judged
    /// there and passed on (`Hub::take_rebuilt`): every one here passes.
    fn collect(&mut self, i: usize) {
        let mut out = Vec::new();
        for delivered in self.members[i].take_delivered() {
            *self.handed.entry((i, delivered.hash)).or_default() += 1;
            self.held_at.entry((i, delivered.hash)).or_insert(self.now);
            if delivered.arrival == Arrival::Rebuilt {
                out.extend(self.members[i].pass_on(
                    delivered.group,
                    delivered.hash,
                    delivered.piece.clone(),
                    self.now,
                ));
            }
        }
        self.send(i, out);
    }

    /// Originates `count` new records at member `origin`, now.
    fn originate(&mut self, origin: usize, count: usize) -> Result<Vec<Hash>, String> {
        let mut hashes = Vec::new();
        for _ in 0..count {
            self.sequence += 1;
            let batch = crate::anchors::anchored(
                &self.receiver,
                &BatchContent {
                    boot_id: 1,
                    sequence: self.sequence,
                    counter_epoch: 0,
                    wall_ms: self.now,
                    dropped: 0,
                    previous: [0; 32],
                    observations: (0..self.observations)
                        .map(|n| {
                            let mut state = self.sequence * 1_000_003 + n as u64;
                            tally_wire::Observation {
                                format: b'3',
                                timestamp: n as u64,
                                signal: 0,
                                data: (0..14)
                                    .map(|_| {
                                        state = state
                                            .wrapping_mul(6_364_136_223_846_793_005)
                                            .wrapping_add(1);
                                        (state >> 56) as u8
                                    })
                                    .collect(),
                            }
                        })
                        .collect(),
                },
            )
            .map_err(text)?;
            let record = Record::Batch(batch);
            let piece = Piece::of(&record).ok_or("no piece")?;
            let hash = piece.hash().ok_or("no hash")?;
            self.originated.insert(hash, (self.now, origin));
            self.lens.insert(hash, piece.len());
            hashes.push(hash);
            if self.down.contains(&origin) {
                continue;
            }
            let at = self.at(origin);
            let out = self.members[origin].originate(self.group, hash, piece, at);
            self.collect(origin);
            self.send(origin, out);
        }
        Ok(hashes)
    }

    /// Runs every event and tick up to `until`.
    fn run_until(&mut self, until: u64) {
        loop {
            let next_event = self.queue.peek().map(|Reverse((at, _))| *at);
            let event_first = next_event.is_some_and(|at| at <= self.next_tick);
            if event_first {
                let Some(Reverse((at, seq))) = self.queue.pop() else {
                    break;
                };
                if at > until {
                    self.queue.push(Reverse((at, seq)));
                    break;
                }
                self.now = at;
                let Some(event) = self.events.remove(&seq) else {
                    continue;
                };
                if self.down.contains(&event.to) {
                    continue;
                }
                if let (Some((member, origin, tell)), Message::Piece { group, hash, piece }) =
                    (self.refusing, &event.message)
                    && member == event.to
                    && self
                        .originated
                        .get(hash)
                        .is_some_and(|(_, by)| *by == origin)
                {
                    let at = self.at(member);
                    match tell {
                        Telling::Nothing => {}
                        Telling::Delivered => {
                            let from = self.keys[event.from];
                            let out = self.members[member].refused(
                                from,
                                *group,
                                (*hash, piece.clone()),
                                at,
                            );
                            self.send(member, out);
                        }
                        Telling::Refused => self.members[member].refuse(*group, *hash, at),
                    }
                    continue;
                }
                let from = self.keys[event.from];
                let at = self.at(event.to);
                let out = self.members[event.to].receive(from, event.message, at);
                self.collect(event.to);
                self.send(event.to, out);
            } else {
                if self.next_tick > until {
                    break;
                }
                self.now = self.next_tick;
                self.next_tick += TICK_MS;
                for i in 0..self.members.len() {
                    if self.down.contains(&i) {
                        continue;
                    }
                    let at = self.at(i);
                    let out = self.members[i].tick(at);
                    self.collect(i);
                    self.send(i, out);
                }
            }
        }
        self.now = self.now.max(until);
    }

    /// Feeds `per_second` records from each of `origins` every second for `seconds`, at an
    /// offset into each second that is not a tick.
    fn feed(&mut self, origins: &[usize], per_second: usize, seconds: u64) -> Outcome {
        let start = self.now - self.now % 1000 + 1000;
        for second in 0..seconds {
            for (k, origin) in origins.iter().enumerate() {
                let at = start + second * 1000 + 37 + 61 * k as u64;
                self.run_until(at);
                self.originate(*origin, per_second)?;
            }
        }
        Ok(())
    }

    fn live(&self) -> Vec<usize> {
        (0..self.members.len())
            .filter(|i| !self.down.contains(i))
            .collect()
    }

    /// Every live member was handed every record originated by a live origin, once, and still
    /// holds those within the horizon (older ones it has let go, as it should).
    fn everyone_holds_everything(&self, excluded: &BTreeSet<usize>) -> Outcome {
        let horizon_ms = self.deadlines.horizon_seconds() * 1000;
        for (hash, (at, origin)) in &self.originated {
            if self.down.contains(origin) {
                continue;
            }
            for i in self.live().into_iter().filter(|i| !excluded.contains(i)) {
                if at + horizon_ms > self.now && !self.members[i].holds(self.group, hash) {
                    return Err(format!(
                        "member {i} of {} lacks a record from {origin}",
                        self.members.len()
                    ));
                }
                let handed = self.handed.get(&(i, *hash)).copied().unwrap_or(0);
                if handed != 1 {
                    return Err(format!("member {i} was handed a record {handed} times"));
                }
            }
        }
        Ok(())
    }

    /// A member that forwards in its home stripe (has children there), and originates nothing.
    fn interior_with_children(&self, avoid: &[usize]) -> Option<(usize, u8)> {
        let layout = self.layout();
        let epoch = epoch_of(self.now / 1000);
        (0..self.members.len())
            .filter(|i| !avoid.contains(i))
            .find_map(|i| {
                let homes = layout.homes(&self.keys[i]);
                let home = *homes.first()?;
                let place = layout.place(home, epoch, &self.keys[i])?;
                (homes.len() == 1 && place.children.len() >= 2 && place.parent.is_some())
                    .then_some((i, home))
            })
    }
}

#[test]
fn a_group_of_one_two_three_and_fifty_delivers_everything_once() -> Outcome {
    for count in [1, 2, 3, 50] {
        let mut sim = Sim::new(count, 20)?;
        let origins: Vec<usize> = (0..count.min(5)).collect();
        sim.feed(&origins, 3, 6)?;
        let end = sim.now + 10_000;
        sim.run_until(end);
        sim.everyone_holds_everything(&BTreeSet::new())?;
        if sim.originated.len() != origins.len() * 3 * 6 {
            return Err(format!("{} records", sim.originated.len()));
        }
        let rebuilt: u64 = sim.members.iter().map(|m| m.stats().rebuilt).sum();
        let asked: u64 = sim.members.iter().map(|m| m.stats().repairs_asked).sum();
        if rebuilt != 0 || asked != 0 {
            return Err(format!(
                "a healthy group of {count} rebuilt {rebuilt} and asked for repair {asked} times"
            ));
        }
    }
    Ok(())
}

#[test]
fn every_member_computes_the_same_tree() -> Outcome {
    let cell = area()?;
    for count in [1, 2, 3, 4, 5, 7, 12, 50, 51] {
        let members = keys(count);
        let mut reversed = members.clone();
        reversed.reverse();
        let mut doubled = members.clone();
        doubled.extend(members.iter().copied());
        let layout = Layout::new(cell, Streams::RAW, &members, &[]);
        if Layout::new(cell, Streams::RAW, &reversed, &[]) != layout
            || Layout::new(cell, Streams::RAW, &doubled, &[]) != layout
        {
            return Err(format!("the trees of {count} depend on the input order"));
        }
        for epoch in [0, 1, 2] {
            for stripe in 0..STRIPES {
                let mut roots = 0;
                let mut reached = BTreeSet::new();
                for key in &members {
                    let place = layout.place(stripe, epoch, key).ok_or("no place")?;
                    match place.parent {
                        None => roots += 1,
                        Some(parent) => {
                            let of_parent = layout.place(stripe, epoch, &parent).ok_or("parent")?;
                            if !of_parent.children.contains(key) {
                                return Err("a parent does not name its child".into());
                            }
                        }
                    }
                    for child in &place.children {
                        if !reached.insert(*child) {
                            return Err("a member has two parents".into());
                        }
                    }
                }
                if roots != 1 || reached.len() != count - 1 {
                    return Err(format!(
                        "stripe {stripe} of {count}: {roots} roots, {} reached",
                        reached.len()
                    ));
                }
                if layout.seed(stripe, epoch)
                    != layout.members().into_iter().find(|key| {
                        layout
                            .place(stripe, epoch, key)
                            .is_some_and(|p| p.parent.is_none())
                    })
                {
                    return Err("the seed is not the root".into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn each_member_is_interior_in_exactly_one_stripe() -> Outcome {
    let cell = area()?;
    for count in 4..=60 {
        let members = keys(count);
        let layout = Layout::new(cell, Streams::POSITIONS, &members, &[]);
        for epoch in [0, 5] {
            for key in &members {
                let homes = layout.homes(key);
                if homes.len() != 1 {
                    return Err(format!("{count}: a member has {} homes", homes.len()));
                }
                for stripe in 0..STRIPES {
                    let place = layout.place(stripe, epoch, key).ok_or("no place")?;
                    if !place.children.is_empty() && stripe != homes[0] {
                        return Err(format!("{count}: a member forwards outside its home"));
                    }
                }
            }
        }
        // Each stripe's interior members differ from every other stripe's.
        let mut seen = BTreeSet::new();
        for stripe in 0..STRIPES {
            for key in layout.interior(stripe) {
                if !seen.insert(*key) {
                    return Err("two stripes share an interior member".into());
                }
            }
            if layout.interior(stripe).is_empty() {
                return Err(format!("{count}: stripe {stripe} has no interior"));
            }
        }
    }
    // Fewer members than stripes: every stripe still has one forwarder, and each member is one.
    for count in 1..STRIPES as usize {
        let layout = Layout::new(cell, Streams::POSITIONS, &keys(count), &[]);
        for stripe in 0..STRIPES {
            if layout.interior(stripe).len() != 1 {
                return Err(format!(
                    "{count}: stripe {stripe} without its one forwarder"
                ));
            }
        }
    }
    // A member that withdrew is a leaf everywhere.
    let members = keys(12);
    let layout = Layout::new(cell, Streams::RAW, &members, &members[..1]);
    if !layout.homes(&members[0]).is_empty() {
        return Err("a withdrawn member forwards".into());
    }
    Ok(())
}

#[test]
fn adding_a_member_moves_few_others() -> Outcome {
    let cell = area()?;
    let members = keys(40);
    let before = Layout::new(cell, Streams::RAW, &members, &[]);
    let after = Layout::new(cell, Streams::RAW, &keys(41), &[]);
    let moved = members
        .iter()
        .filter(|key| before.homes(key) != after.homes(key))
        .count();
    if moved > members.len() / 4 {
        return Err(format!("{moved} of 40 changed home"));
    }
    Ok(())
}

#[test]
fn a_popular_areas_sources_still_send_one_copy_into_seeds_seeds() -> Outcome {
    let cell = area()?;
    for count in 1..=60 {
        let seeds = seed_members(cell, Streams::RAW, &keys(count), 1_000);
        if seeds.len() != count.min(SEEDS) {
            return Err(format!("{count} members, {} seeds", seeds.len()));
        }
    }
    // What an origin sends into the group does not grow with it: one copy of each record, to at
    // most `SEEDS` seeds (besides what it pushes down its own subtree, its duty as any
    // member's).
    let mut sent = Vec::new();
    for count in [5, 50] {
        let mut sim = Sim::new(count, 20)?;
        // An origin that is no stripe's seed now, so every record leaves it.
        let layout = sim.layout();
        let epoch = epoch_of(sim.now / 1000 + 1);
        let origin = (0..count)
            .find(|i| (0..STRIPES).all(|s| layout.seed(s, epoch) != Some(sim.keys[*i])))
            .ok_or("every member seeds")?;
        sim.feed(&[origin], 10, 3)?;
        let end = sim.now + 8_000;
        sim.run_until(end);
        sim.everyone_holds_everything(&BTreeSet::new())?;
        sent.push(sim.seed_copies[origin]);
        if sim.seeded_to[origin].len() > SEEDS {
            return Err(format!("seeded to {} members", sim.seeded_to[origin].len()));
        }
    }
    // `SEED_COPIES` copy of each record, whatever the group's size.
    let copies = 30 * SEED_COPIES as u64;
    if sent != [copies, copies] {
        return Err(format!("the origin seeded {sent:?} copies of 30 records"));
    }
    // What that costs it: the copy and the parity stripe beside it, one stripe's worth more.
    if seeded_bytes(3 * 1024) != 4 * 1024 || u64::from(STRIPES) != u64::from(DATA_STRIPES) + 1 {
        return Err("seeded bytes are not one copy and its parity".into());
    }
    Ok(())
}

#[test]
fn seeds_rotate_by_a_rule_anyone_can_check() -> Outcome {
    let cell = area()?;
    let members = keys(24);
    let layout = Layout::new(cell, Streams::RAW, &members, &[]);
    let mut rotated = false;
    for epoch in 0..8u64 {
        let second = epoch * SEED_ROTATION_SECONDS + 7;
        for stripe in 0..STRIPES {
            let seed = layout.seed(stripe, epoch).ok_or("no seed")?;
            if !layout.interior(stripe).contains(&seed) {
                return Err("a seed outside its stripe's interior".into());
            }
            if !is_seed(cell, Streams::RAW, &members, stripe, second, &seed) {
                return Err("a seed its own rule refuses".into());
            }
            let other = members
                .iter()
                .find(|key| **key != seed)
                .ok_or("one member")?;
            if is_seed(cell, Streams::RAW, &members, stripe, second, other) {
                return Err("a second seed accepted".into());
            }
            if epoch > 0 && layout.seed(stripe, epoch - 1) != Some(seed) {
                rotated = true;
            }
        }
    }
    if !rotated {
        return Err("the seeds never rotated".into());
    }
    Ok(())
}

/// A record this relay's hub refused (a batch of a format it reads that does not decode, from a
/// relay that forwards it raw) is counted as had: no repair asks for it again, where one only
/// dropped is asked for every repair interval.
#[test]
fn a_refused_record_is_never_asked_for_again() -> Outcome {
    let mut asked = Vec::new();
    for tell in [Telling::Nothing, Telling::Delivered] {
        let mut sim = Sim::new(8, 20)?;
        let member = 5;
        sim.refusing = Some((member, 0, tell));
        sim.feed(&[0, 1], 3, 4)?;
        let end = sim.now + 30_000;
        sim.run_until(end);
        let lacking = sim
            .originated
            .iter()
            .filter(|(_, (_, origin))| *origin == 0)
            .filter(|(hash, _)| !sim.members[member].holds(sim.group, hash))
            .count();
        if lacking == 0 {
            return Err("the member holds what its hub refused".into());
        }
        asked.push(sim.members[member].stats().repairs_asked);
    }
    if !(asked[0] > 0 && asked[1] == 0) {
        return Err(format!("repairs asked, dropped then refused: {asked:?}"));
    }
    Ok(())
}

#[test]
fn a_parent_leaving_loses_no_data_with_parity() -> Outcome {
    let mut sim = Sim::new(20, 20)?;
    let origins = [0, 1, 2];
    let (leaver, home) = sim
        .interior_with_children(&origins)
        .ok_or("no interior member with children")?;
    sim.feed(&origins, 4, 3)?;
    sim.down.insert(leaver);
    sim.feed(&origins, 4, 6)?;
    let end = sim.now + 15_000;
    sim.run_until(end);
    sim.everyone_holds_everything(&BTreeSet::new())?;
    let rebuilt: u64 = sim.members.iter().map(|m| m.stats().rebuilt).sum();
    if rebuilt == 0 {
        return Err(format!("nothing rebuilt after stripe {home}'s member left"));
    }
    // Every record a survivor rebuilt was of the stripe the leaver forwarded: it cost one stripe.
    for (i, member) in sim.members.iter().enumerate() {
        if sim.down.contains(&i) {
            continue;
        }
        let asked = member.stats().repairs_asked;
        if asked != 0 {
            return Err(format!("member {i} needed {asked} repairs beyond parity"));
        }
    }
    // The leaver's children reported it, and the group dropped it from the trees.
    let live = sim.live();
    if !live
        .iter()
        .all(|i| sim.members[*i].is_demoted(sim.group, &sim.keys[leaver]))
    {
        return Err("the group kept a member that left".into());
    }
    Ok(())
}

#[test]
fn a_member_that_does_not_forward_is_reported_and_demoted() -> Outcome {
    let mut sim = Sim::new(16, 20)?;
    let origins = [0, 1, 2, 3];
    let (silent, _) = sim
        .interior_with_children(&origins)
        .ok_or("no interior member with children")?;
    sim.silent.insert(silent);
    sim.feed(&origins, 3, 20)?;
    let end = sim.now + 15_000;
    sim.run_until(end);
    let key = sim.keys[silent];
    for i in sim.live() {
        if i == silent {
            continue;
        }
        if !sim.members[i].is_demoted(sim.group, &key) {
            return Err(format!(
                "member {i} still trusts the member that does not forward"
            ));
        }
        let layout = sim.members[i].layout(sim.group).ok_or("no layout")?;
        if layout.contains(&key) {
            return Err("a demoted member is still in the trees".into());
        }
        for other in sim.live() {
            if other != silent && sim.members[i].is_demoted(sim.group, &sim.keys[other]) {
                return Err(format!("member {i} demoted {other}, who forwards"));
            }
        }
    }
    let shortfalls: u64 = sim.members.iter().map(|m| m.stats().shortfalls).sum();
    if shortfalls == 0 {
        return Err("nobody reported a shortfall".into());
    }
    // The honest members still have everything (the silent member's stripe by parity, then by
    // its replacement).
    sim.everyone_holds_everything(&[silent].into())?;
    Ok(())
}

/// RFC-0171 §3.6: a demotion lasts `DEMOTION_MS` by the relay's monotonic clock
/// (`member::MonoDeadline`), whatever its judging clock does. A member that does not forward is
/// demoted, then forwards again, and every member's judging clock steps back a minute: a second
/// past the demotion's length by the monotonic clock, nobody holds it demoted. Before, a demotion
/// ended by the judging clock, and a step back stretched it by the step.
#[test]
fn a_step_back_of_the_judging_clock_stretches_no_demotion() -> Outcome {
    let mut sim = Sim::new(16, 20)?;
    let origins = [0, 1, 2, 3];
    let (silent, _) = sim
        .interior_with_children(&origins)
        .ok_or("no interior member with children")?;
    sim.silent.insert(silent);
    sim.feed(&origins, 3, 20)?;
    let end = sim.now + 15_000;
    sim.run_until(end);
    let key = sim.keys[silent];
    if !sim
        .live()
        .into_iter()
        .any(|i| i != silent && sim.members[i].is_demoted(sim.group, &key))
    {
        return Err("nobody demoted the member that does not forward".into());
    }
    sim.silent.clear();
    sim.judge_step_ms = -60_000;
    sim.run_until(end + super::groups::DEMOTION_MS + 1_000);
    if let Some(i) = sim
        .live()
        .into_iter()
        .find(|i| sim.members[*i].is_demoted(sim.group, &key))
    {
        return Err(format!(
            "member {i} still holds it demoted past its demotion"
        ));
    }
    Ok(())
}

/// The deadlines decide the verdict, and they are the member's given value, not the clock's: a
/// member that forwards every record it did not originate 6 s late is reported short by a relay's
/// deadlines (`Deadlines::RELAY`, whose 4 s receipt grace the last seconds of each window miss),
/// and by deadlines whose grace outlasts its lag, the same deliveries on the same clock are no
/// shortfall: every member judges, and nobody is reported or demoted.
#[test]
fn a_slow_member_is_reported_by_a_relays_deadlines_and_not_by_patient_ones() -> Outcome {
    const LATE_MS: u64 = 6_000;
    let origins = [0, 1, 2, 3];
    let run = |deadlines: Deadlines| -> Result<(Sim, usize), String> {
        let mut sim = Sim::judging_by(16, 20, deadlines)?;
        let (slow, _) = sim
            .interior_with_children(&origins)
            .ok_or("no interior member with children")?;
        sim.slow.insert(slow, LATE_MS);
        sim.feed(&origins, 3, 10)?;
        let end = sim.now + 15_000;
        sim.run_until(end);
        Ok((sim, slow))
    };
    // Reported short in a flooded receipt naming it: what a shortfall is.
    let reported = |sim: &Sim, slow: usize| {
        sim.receipts.iter().any(|(_, to, receipt)| {
            *to != slow
                && receipt
                    .content()
                    .is_ok_and(|content| content.parent == sim.keys[slow])
        })
    };

    let (sim, slow) = run(Deadlines::RELAY)?;
    let shortfalls: u64 = sim.members.iter().map(|m| m.stats().shortfalls).sum();
    if shortfalls == 0 || !reported(&sim, slow) {
        return Err(format!(
            "a member {LATE_MS} ms late was not reported short by a relay's deadlines \
             ({shortfalls} shortfalls)"
        ));
    }

    let patient = Deadlines {
        receipt_grace: tally_wire::budget::policy::<_, { LATE_MS + 4_000 }>(),
        ..Deadlines::RELAY
    };
    let (sim, slow) = run(patient)?;
    let unjudged: Vec<usize> = sim
        .live()
        .into_iter()
        .filter(|i| sim.members[*i].stats().judged == 0)
        .collect();
    if !unjudged.is_empty() {
        return Err(format!("members that judged no window: {unjudged:?}"));
    }
    let shortfalls: u64 = sim.members.iter().map(|m| m.stats().shortfalls).sum();
    if shortfalls != 0 || reported(&sim, slow) {
        return Err(format!(
            "{shortfalls} shortfalls of a member whose lag the grace outlasts"
        ));
    }
    for i in sim.live() {
        for other in sim.live() {
            if sim.members[i].is_demoted(sim.group, &sim.keys[other]) {
                return Err(format!("member {i} demoted {other}, who delivered in time"));
            }
        }
    }
    sim.everyone_holds_everything(&BTreeSet::new())?;
    Ok(())
}

#[test]
fn receipts_verify_and_name_what_was_delivered() -> Outcome {
    let mut sim = Sim::new(9, 20)?;
    sim.feed(&[0, 1], 5, 6)?;
    let end = sim.now + 12_000;
    sim.run_until(end);
    if sim.receipts.is_empty() {
        return Err("no receipts".into());
    }
    for (from, to, receipt) in &sim.receipts {
        receipt.verify().map_err(text)?;
        let content = receipt.content().map_err(text)?;
        if receipt.signer().map_err(text)? != sim.keys[*from] {
            return Err("a receipt signed by someone else".into());
        }
        // Sent to the deliverer, or flooded as a shortfall (none in a healthy group).
        if content.parent != sim.keys[*to] {
            return Err("a receipt sent to someone it does not name".into());
        }
        if content.records == 0 || content.bytes == 0 {
            return Err("an empty receipt".into());
        }
        // Only listed records are credited: the digest is over records the child holds.
        let held = sim
            .originated
            .keys()
            .filter(|hash| sim.handed.contains_key(&(*from, **hash)))
            .count();
        if content.records as usize > held {
            return Err("a receipt for more than was held".into());
        }
        if content.digest == receipt_digest(&[]) {
            return Err("a receipt over nothing".into());
        }
    }
    let shortfalls: u64 = sim.members.iter().map(|m| m.stats().shortfalls).sum();
    if shortfalls != 0 {
        return Err(format!("{shortfalls} shortfalls in a healthy group"));
    }
    Ok(())
}

fn shortfalls(sim: &Sim) -> u64 {
    sim.members.iter().map(|m| m.stats().shortfalls).sum()
}

fn demoted_any(sim: &Sim) -> Option<(usize, usize)> {
    sim.live().into_iter().find_map(|i| {
        sim.live()
            .into_iter()
            .find(|j| sim.members[i].is_demoted(sim.group, &sim.keys[*j]))
            .map(|j| (i, j))
    })
}

/// RFC-0171 §3.6: who delivered what is kept to its window's judgment, on `M`, however late the
/// judging clock reaches the window's end. Origins whose clocks read 7 s ahead of the rest have
/// their records' windows end, by this relay's clock, after a horizon on `M` from when the records
/// came; and origins 10 s ahead, with every clock then stepped 5 s back, later still. Every window
/// still signed is receipted whole: nobody is reported short and nobody demoted. Before, the
/// senders were let go a horizon after they came, by `M`, while the receipt was signed by `J` at
/// the window's end and its grace, so it found none and reported its honest parent short.
#[test]
fn origins_clocks_ahead_and_a_step_back_report_nobody_short() -> Outcome {
    for (skew_ms, step_ms) in [(7_000i64, 0i64), (10_000, -5_000)] {
        let mut sim = Sim::new(16, 20)?;
        let origins = [0, 1, 2, 3];
        for origin in origins {
            sim.skew_ms.insert(origin, skew_ms);
        }
        sim.feed(&origins, 3, 6)?;
        sim.judge_step_ms = step_ms;
        sim.feed(&origins, 3, 6)?;
        let end = sim.now + 30_000;
        sim.run_until(end);
        if shortfalls(&sim) != 0 {
            return Err(format!(
                "{} shortfalls with origins {skew_ms} ms ahead and a {step_ms} ms step",
                shortfalls(&sim)
            ));
        }
        if let Some((i, j)) = demoted_any(&sim) {
            return Err(format!(
                "member {i} demoted {j} with origins {skew_ms} ms ahead"
            ));
        }
        // Not a quiet pass: the windows were receipted, by every member but the origins.
        if skew_ms == 7_000
            && sim
                .receipts
                .iter()
                .all(|(from, _, _)| origins.contains(from))
        {
            return Err("no member but an origin signed a receipt".into());
        }
    }
    Ok(())
}

/// RFC-0171 §3.6: a member that restarts within a receipt window signs no receipt for that window
/// (it never saw what was delivered before the restart), and does sign one for each window after,
/// which it saw whole. When it began is its first judging reading: its clock at boot reads a
/// minute behind, then a minute ahead, without judging, for its first second. Nobody is reported
/// short, and the restarted member signs receipts for the windows after. Before, its first
/// reading of any kind was when it began: a clock behind put that before the window the restart
/// cut, whose receipt then reported its parent short; one ahead skipped every window it saw whole.
#[test]
fn a_restart_within_a_window_is_dated_by_its_first_judging_reading() -> Outcome {
    let origins = [0, 1, 2, 3];
    let restarted = 9;
    for off_ms in [-60_000i64, 60_000] {
        let mut sim = Sim::new(16, 20)?;
        sim.feed(&origins, 3, 6)?;
        // Into a window, two seconds past its start.
        while (sim.now / 1000) % super::member::RECEIPT_WINDOW_SECONDS != 2 {
            sim.feed(&origins, 3, 1)?;
        }
        let booted = sim.now;
        sim.booting.insert(restarted, (off_ms, booted + 1_000));
        sim.members[restarted] = Member::new(
            crate::signer::synced(identity(restarted)),
            Gauge::unlimited(Store::Batches),
            Deadlines::RELAY,
        );
        let at = sim.at(restarted);
        let keys = sim.keys.clone();
        let out = sim.members[restarted].set_members(sim.group, &keys, &[], at);
        sim.send(restarted, out);
        sim.feed(&origins, 3, 15)?;
        let end = sim.now + 15_000;
        sim.run_until(end);
        if shortfalls(&sim) != 0 {
            return Err(format!(
                "{} shortfalls after a restart booting {off_ms} ms off",
                shortfalls(&sim)
            ));
        }
        if !sim.receipts.iter().any(|(from, _, receipt)| {
            *from == restarted
                && receipt
                    .content()
                    .is_ok_and(|content| content.first_second * 1000 > booted)
        }) {
            return Err(format!(
                "the member restarted {off_ms} ms off signed no receipt for a window after"
            ));
        }
    }
    Ok(())
}

/// RFC-0171 §3.6: a window's receipts fall due on `M`, a grace after the judging clock was first
/// read past its end, so a step of that clock forward brings no window due before what was
/// still arriving for it came. Records travel 400 ms a hop; just after a window ends, every
/// member's judging clock steps 4 s forward, past the window and its grace. Nobody is reported
/// short. Before, the receipts were due by `J` at the window's end and its grace, so the step made
/// them due at once, before the last second's records reached the leaves.
#[test]
fn a_step_forward_of_the_judging_clock_brings_no_window_due_at_once() -> Outcome {
    let mut sim = Sim::new(16, 400)?;
    let origins = [0, 1, 2, 3];
    sim.feed(&origins, 3, 6)?;
    while (sim.now / 1000 + 1) % super::member::RECEIPT_WINDOW_SECONDS != 0 {
        sim.feed(&origins, 3, 1)?;
    }
    let ended = (sim.now / 1000 + 1) * 1000;
    sim.run_until(ended + 100);
    sim.judge_step_ms = 4_000;
    let end = sim.now + 20_000;
    sim.run_until(end);
    if shortfalls(&sim) != 0 {
        return Err(format!(
            "{} shortfalls after a step forward of the judging clock",
            shortfalls(&sim)
        ));
    }
    if sim.receipts.is_empty() {
        return Err("no receipts".into());
    }
    Ok(())
}

/// RFC-0174 §2.5: an origin's record that a member's relay refuses (it reads its format, and it
/// does not decode) is no fault of the honest members that carry it. The member notes who
/// delivered it, holds it owed by nobody, and pushes it on unheld, so neither its parent nor the
/// member itself is reported short, and nobody is demoted. Before, it noted no sender and pushed it
/// no further, so its own receipt reported its parent short of it and its children reported it.
#[test]
fn an_origins_refused_record_demotes_no_honest_forwarder() -> Outcome {
    let origins = [0, 1, 2, 3];
    // The same run without the refusal first: the stripes origin 0's records travel (the run is
    // deterministic), and a member that forwards in one of them.
    let mut dry = Sim::new(16, 20)?;
    dry.feed(&origins, 3, 10)?;
    let stripes: BTreeSet<u8> = dry
        .originated
        .iter()
        .filter(|(_, (_, origin))| *origin == 0)
        .map(|(hash, _)| data_stripe(hash))
        .collect();
    let layout = dry.layout();
    let epoch = epoch_of(dry.now / 1000);
    let refuser = (0..dry.members.len())
        .filter(|i| !origins.contains(i))
        .find(|i| {
            stripes.iter().any(|stripe| {
                layout
                    .place(*stripe, epoch, &dry.keys[*i])
                    .is_some_and(|place| !place.children.is_empty() && place.parent.is_some())
            })
        })
        .ok_or("no member forwards origin 0's records")?;
    let mut sim = Sim::new(16, 20)?;
    sim.refusing = Some((refuser, 0, Telling::Delivered));
    sim.feed(&origins, 3, 10)?;
    let near = sim.now + 1_000;
    sim.run_until(near);
    let refused = sim
        .originated
        .iter()
        .filter(|(hash, (_, origin))| {
            *origin == 0 && sim.members[refuser].has_refused(sim.group, hash)
        })
        .count();
    if refused == 0 {
        return Err("the member refused nothing".into());
    }
    let end = sim.now + 15_000;
    sim.run_until(end);
    if shortfalls(&sim) != 0 {
        return Err(format!(
            "{} shortfalls for an origin's refused records",
            shortfalls(&sim)
        ));
    }
    if let Some((i, j)) = demoted_any(&sim) {
        return Err(format!(
            "member {i} demoted {j} for an origin's refused record"
        ));
    }
    Ok(())
}

/// RFC-0174 §2.5: a refused record is pushed on only once a manifest lists it, since only then is
/// a child owed it. A member's parent hands it a record no manifest lists, which its relay refuses
/// (its signature fails): it goes no further, is held charged meanwhile, and is let go a horizon
/// later. Before, every refused record was pushed down the tree at once, so a member could flood
/// the whole group with records nobody vouched for.
#[test]
fn a_refused_record_no_manifest_lists_goes_no_further() -> Outcome {
    let mut sim = Sim::new(16, 20)?;
    sim.feed(&[0, 1], 3, 2)?;
    let record = Record::Batch(
        crate::anchors::anchored(
            &identity(10_001),
            &BatchContent {
                boot_id: 9,
                sequence: 1,
                counter_epoch: 0,
                wall_ms: sim.now,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(text)?,
    );
    let piece = Piece::of(&record).ok_or("no piece")?;
    let hash = piece.hash().ok_or("no hash")?;
    let layout = sim.layout();
    let epoch = epoch_of(sim.now / 1000);
    let (member, parent) = (0..sim.members.len())
        .find_map(|i| {
            let place = layout.place(data_stripe(&hash), epoch, &sim.keys[i])?;
            (!place.children.is_empty())
                .then_some(place.parent)
                .flatten()
                .map(|parent| (i, parent))
        })
        .ok_or("no member forwards in the record's stripe")?;
    let at = sim.at(member);
    let before = sim.members[member].held_bytes();
    let out = sim.members[member].refused(parent, sim.group, (hash, piece), at);
    if !out.is_empty() {
        return Err(format!(
            "pushed on to {} members, listed by no manifest",
            out.len()
        ));
    }
    if !sim.members[member].has_refused(sim.group, &hash) {
        return Err("not counted refused".into());
    }
    let member_ref = &sim.members[member];
    if member_ref.held_bytes() <= before || member_ref.held_bytes() != member_ref.counted_bytes() {
        return Err(format!(
            "held {} (before {before}), counted {}",
            member_ref.held_bytes(),
            member_ref.counted_bytes()
        ));
    }
    let end = sim.now + Deadlines::RELAY.horizon_ms() + 10_000;
    sim.run_until(end);
    if sim.handed.keys().any(|(_, handed)| *handed == hash) {
        return Err("the record reached another member".into());
    }
    let member_ref = &sim.members[member];
    if member_ref.held_bytes() != member_ref.counted_bytes() {
        return Err(format!(
            "held {}, counted {} past the horizon",
            member_ref.held_bytes(),
            member_ref.counted_bytes()
        ));
    }
    Ok(())
}

/// RFC-0174 §2.5: a record a member refused is owed by nobody in its reckoning, so it reports
/// nobody short of it, whoever did or did not deliver it. A leaf of every stripe an origin's
/// records travel refuses each of them naming no deliverer (`Member::refuse`, as for a record
/// rebuilt from parity and judged bad), so none is noted delivered and none goes further: its
/// receipts report nobody short. Were a refused record owed, every receipt to its parent would
/// report that parent short of the origin's records.
#[test]
fn a_record_refused_with_no_deliverer_is_owed_by_nobody() -> Outcome {
    let origins = [0, 1, 2, 3];
    // The same run without the refusal first: the stripes origin 0's records travel and the
    // epochs they span (the run is deterministic), and a member that is a leaf in all of them.
    let mut dry = Sim::new(16, 20)?;
    dry.feed(&origins, 3, 10)?;
    let travelled: BTreeSet<(u8, u64)> = dry
        .originated
        .iter()
        .filter(|(_, (_, origin))| *origin == 0)
        .map(|(hash, (at, _))| (data_stripe(hash), epoch_of(at / 1000)))
        .collect();
    let layout = dry.layout();
    let refuser = (0..dry.members.len())
        .filter(|i| !origins.contains(i))
        .find(|i| {
            travelled.iter().all(|(stripe, epoch)| {
                layout
                    .place(*stripe, *epoch, &dry.keys[*i])
                    .is_some_and(|place| place.children.is_empty() && place.parent.is_some())
            })
        })
        .ok_or("no member is a leaf of every stripe origin 0's records travel")?;
    let mut sim = Sim::new(16, 20)?;
    sim.refusing = Some((refuser, 0, Telling::Refused));
    sim.feed(&origins, 3, 10)?;
    let near = sim.now + 1_000;
    sim.run_until(near);
    let refused = sim
        .originated
        .iter()
        .filter(|(hash, (_, origin))| {
            *origin == 0 && sim.members[refuser].has_refused(sim.group, hash)
        })
        .count();
    if refused == 0 {
        return Err("the member refused nothing".into());
    }
    let end = sim.now + 15_000;
    sim.run_until(end);
    if shortfalls(&sim) != 0 {
        return Err(format!(
            "{} shortfalls for records refused with no deliverer",
            shortfalls(&sim)
        ));
    }
    // Not a quiet pass: the refuser receipted its parents.
    if !sim.receipts.iter().any(|(from, _, _)| *from == refuser) {
        return Err("the refuser signed no receipt".into());
    }
    Ok(())
}

/// RFC-0174 §2.5: a member with no room to hold what it is delivered still reckons it: who
/// delivered it, and how long it is, from the store's floor for what the groups reckon by
/// (`member::reckoning_floor`), which records never take. Every member's store holds a fraction of
/// the group's records; nobody is reported short, and each receipt counts the bytes of every
/// record it names. Before, a member noted a sender only when the store had room to hold the
/// record, and counted a record it did not hold as no bytes.
#[test]
fn a_full_store_still_credits_what_it_could_not_hold() -> Outcome {
    let origins = [0, 1, 2, 3];
    // What the group holds and reckons at most with room for all of it.
    // Records of a size the plan is made for, beside which a record's reckoning is small.
    const OBSERVATIONS: usize = 200;
    let mut open = Sim::new(16, 20)?;
    open.observations = OBSERVATIONS;
    open.feed(&origins, 3, 10)?;
    let end = open.now + 15_000;
    let (mut held, mut reckoned) = (0, 0);
    while open.now < end {
        let next = open.now + 250;
        open.run_until(next);
        for member in &open.members {
            held = held.max(member.held_bytes());
            reckoned = reckoned.max(member.reckoning_bytes().0);
        }
    }
    // A store whose floor holds twice that reckoning, with room beside it for less than what is
    // held.
    let mut limit = held / 8;
    while super::member::reckoning_floor(limit) < 2 * reckoned {
        limit += held / 8;
    }
    let free = limit - super::member::reckoning_floor(limit);
    if free >= held {
        return Err(format!(
            "a store of {limit} with its floor of {} holds all {held} bytes",
            super::member::reckoning_floor(limit)
        ));
    }
    let mut sim = Sim::new(16, 20)?;
    sim.observations = OBSERVATIONS;
    for member in &mut sim.members {
        member.charge_to(Gauge::new(Store::Batches, limit));
    }
    sim.feed(&origins, 3, 10)?;
    let end = sim.now + 15_000;
    sim.run_until(end);
    let refused: u64 = sim.members.iter().map(|m| m.stats().refused).sum();
    if refused == 0 {
        return Err("no store was full".into());
    }
    if shortfalls(&sim) != 0 {
        return Err(format!("{} shortfalls of full stores", shortfalls(&sim)));
    }
    let lens: BTreeSet<usize> = sim.lens.values().copied().collect();
    let [len] = lens.into_iter().collect::<Vec<_>>()[..] else {
        return Err("records of different lengths".into());
    };
    for (_, _, receipt) in &sim.receipts {
        let content = receipt.content().map_err(text)?;
        if content.stripe != super::stripes::PARITY_STRIPE
            && content.bytes != u64::from(content.records) * len as u64
        {
            return Err(format!(
                "a receipt for {} records counts {} bytes, not {}",
                content.records,
                content.bytes,
                u64::from(content.records) * len as u64
            ));
        }
    }
    Ok(())
}

#[test]
fn cut_through_latency_per_hop_is_bounded() -> Outcome {
    let delay = 20;
    let mut sim = Sim::new(50, delay)?;
    sim.run_until(START_MS + 2_123);
    let origin = 7;
    let hashes = sim.originate(origin, 30)?;
    let born = sim.now;
    sim.run_until(born + 3_000);
    let layout = sim.layout();
    let depth = (0..STRIPES).map(|s| layout.depth(s)).max().unwrap_or(0) as u64;
    for hash in &hashes {
        for i in 0..sim.members.len() {
            let at = sim.held_at.get(&(i, *hash)).ok_or("not delivered")?;
            let took = at - born;
            // One hop from the origin to the seed, then one a level, each the link's delay and
            // nothing more: no hop waits for a tick or a batch.
            if took % delay != 0 {
                return Err(format!("{took} ms is not a whole number of hops"));
            }
            if took > (1 + depth) * delay {
                return Err(format!("{took} ms over {depth} levels"));
            }
        }
    }
    if depth > 4 {
        return Err(format!("trees of 50 are {depth} deep at fanout {FANOUT}"));
    }
    Ok(())
}

#[test]
fn parity_rebuilds_any_one_stripe() -> Outcome {
    let receiver = identity(1);
    let mut records = Vec::new();
    for sequence in 0..20 {
        let batch = crate::anchors::anchored(
            &receiver,
            &BatchContent {
                boot_id: 1,
                sequence,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(text)?;
        let piece = Piece::of(&Record::Batch(batch)).ok_or("no piece")?;
        records.push((piece.hash().ok_or("hash")?, piece));
    }
    let pieces: Vec<(Hash, &Piece)> = records.iter().map(|(h, b)| (*h, b)).collect();
    let parity = Parity::build([9; 32], area()?, Streams::RAW, 5, &pieces);
    for missing in 0..DATA_STRIPES {
        let others: Vec<(Hash, &Piece)> = pieces
            .iter()
            .filter(|(hash, _)| data_stripe(hash) != missing)
            .copied()
            .collect();
        let rebuilt = parity.rebuild(missing, &others).ok_or("not rebuilt")?;
        let mut expected: Vec<&(Hash, Piece)> = records
            .iter()
            .filter(|(hash, _)| data_stripe(hash) == missing)
            .collect();
        expected.sort_by_key(|(hash, _)| *hash);
        let expected: Vec<Vec<u8>> = expected
            .into_iter()
            .map(|(_, piece)| {
                let mut bytes = Vec::new();
                piece.encode_into(&mut bytes);
                bytes
            })
            .collect();
        if rebuilt != expected {
            return Err(format!("stripe {missing} rebuilt wrong"));
        }
        // A rebuilt batch is the batch, its piece the same as the one held.
        for bytes in &rebuilt {
            let piece = Piece::from_encoded(bytes.clone()).ok_or("not a piece")?;
            if !records.iter().any(|(_, held)| *held == piece) {
                return Err("rebuilt a piece not held".into());
            }
        }
        // Missing a record of a second stripe too: refused, never a wrong answer.
        let fewer: Vec<(Hash, &Piece)> = others.iter().skip(1).copied().collect();
        if parity.rebuild(missing, &fewer).is_some() {
            return Err("rebuilt from too little".into());
        }
    }
    Ok(())
}

/// A rebuilt batch's piece is a slice of its record's allocation (`Piece::from_encoded`), and the
/// group is charged for all of that allocation, its header too, whatever capacity the rebuilt
/// bytes grew to: what an allocator counting each byte sees of it is within its charge
/// (`Piece::held_len`), which is the whole record's shared bytes. Before, the batch was read as
/// though its slice were all of its allocation, and the record's header went uncharged.
#[test]
fn a_rebuilt_batchs_piece_is_charged_its_whole_record() -> Outcome {
    use tally_counting::Counting;
    use tally_wire::footprint;
    let (_, held) = record(&identity(3), 1, START_MS)?;
    // Rebuilt bytes, with room to spare beside them, as a parity's XOR leaves them.
    let mut encoded = Vec::with_capacity(4 * held.len());
    held.encode_into(&mut encoded);
    let len = encoded.len();
    // The rebuilt bytes are the piece's to keep or let go: counted as its own.
    let base = Counting::live() - encoded.capacity() as isize;
    let piece = Piece::from_encoded(encoded).ok_or("not a piece")?;
    let counted = Counting::since(base);
    assert_eq!(piece, held);
    assert_eq!(
        piece.held_len(),
        footprint::arc::<Batch>() + footprint::shared_bytes(len) + tally_wire::batch::KEPT_BYTES,
    );
    assert!(
        counted <= piece.held_len() as isize,
        "{counted} allocated, {} charged",
        piece.held_len()
    );
    drop(piece);
    assert_eq!(Counting::since(base), 0);
    Ok(())
}

#[test]
fn the_area_tree_is_fixed() -> Outcome {
    let area = area()?;
    let parent = area.ancestor(2).ok_or("no parent")?;
    let kids = children(parent);
    if kids.len() != 7 || !kids.contains(&area) {
        return Err(format!("{} children", kids.len()));
    }
    if kids.iter().any(|kid| kid.ancestor(2) != Some(parent)) {
        return Err("a child of another parent".into());
    }
    // A pentagon (base cell 4) has six children.
    let pentagon = Region::from_u64(0x0800_9fff_ffff_ffff).map_err(text)?;
    if children(pentagon).len() != 6 {
        return Err(format!(
            "a pentagon has {} children",
            children(pentagon).len()
        ));
    }
    let bundles = Bundles::new();
    bundles.set_gathered(&kids[1..]);
    if bundles.complete(parent) {
        return Err("complete without a child".into());
    }
    bundles.set_gathered(&kids);
    if !bundles.complete(parent) || !bundles.offerable().contains(&parent) {
        return Err("not complete with every child".into());
    }
    let grand = area.ancestor(1).ok_or("no grandparent")?;
    if bundles.complete(grand) {
        return Err("a grandparent complete from one of its children".into());
    }
    for sibling in children(grand) {
        if sibling != parent {
            bundles.set_held(sibling, true);
        }
    }
    if !bundles.complete(grand) {
        return Err("children held as bundles do not complete their parent".into());
    }
    Ok(())
}

#[test]
fn a_bundle_that_omits_a_child_is_detected() -> Outcome {
    let area = area()?;
    let parent = area.ancestor(2).ok_or("no parent")?;
    let kids = children(parent);
    let second = 1_800_000_123;
    let mut manifests = Vec::new();
    let mut records = Vec::new();
    for (k, kid) in kids.iter().enumerate().take(4) {
        let origin = identity(500 + k);
        let mut hashes = vec![[k as u8 + 1; 32], [k as u8 + 100; 32]];
        hashes.sort();
        records.extend(hashes.iter().copied());
        manifests.push(
            PieceManifest::sign(
                &origin,
                &PieceManifestContent {
                    cell: *kid,
                    product: Streams::POSITIONS,
                    second,
                    hashes,
                },
            )
            .map_err(text)?,
        );
    }
    let index = BundleIndex::build(parent, Streams::POSITIONS, second, &manifests);
    index
        .check(&manifests, &records, &manifests)
        .map_err(|o| format!("{o:?}"))?;
    // A child left out of the index.
    let mut dropped = index.clone();
    let gone = dropped.children.remove(2).0;
    if dropped.check(&manifests, &records, &[]) != Err(Omission::MissingChild(gone)) {
        return Err("an index without a child passed".into());
    }
    // A child's manifest left out, its digest honest about the rest: the reader who saw the
    // manifest from the cell's own group catches it.
    let partial: Vec<PieceManifest> = manifests[1..].to_vec();
    let quiet = BundleIndex::build(parent, Streams::POSITIONS, second, &partial);
    if quiet.check(&partial, &records, &manifests) != Err(Omission::Manifest(manifests[0].hash())) {
        return Err("a bundle without a manifest passed".into());
    }
    // A manifest left out but the digest kept: the digest no longer matches.
    if index.check(&partial, &records, &[]) != Err(Omission::Digest(kids[0])) {
        return Err("a digest over a manifest the bundle lacks passed".into());
    }
    // A listed record left out.
    if index.check(&manifests, &records[1..], &[]) != Err(Omission::Record(records[0])) {
        return Err("a bundle without a record passed".into());
    }
    // A cell that is not a child.
    let mut stray = index.clone();
    stray.children[0].0 = area.ancestor(1).ok_or("no grandparent")?;
    if !matches!(
        stray.check(&manifests, &records, &[]),
        Err(Omission::StrayChild(_))
    ) {
        return Err("a stray child passed".into());
    }
    Ok(())
}

#[test]
fn groups_hold_members_until_they_lapse_or_are_demoted() -> Outcome {
    let groups = Groups::new();
    let cell = area()?;
    let key = GroupKey::new(cell, Streams::RAW);
    let members = keys(3);
    let start = super::Now::from(0);
    groups.admit(key, members[0], start.after(1_000), false);
    groups.admit(key, members[1], start.after(2_000), true);
    groups.admit(key, members[2], start.after(2_000), false);
    if groups.members(cell, Streams::RAW).len() != 3
        || groups.leaves_only(key) != vec![members[1]]
        || !groups.members(cell, Streams::POSITIONS).is_empty()
    {
        return Err("membership".into());
    }
    groups.demote(key, members[2], start.after(5_000));
    groups.expire(1_500);
    if groups.members(cell, Streams::RAW) != vec![members[1]] {
        return Err("lapse or demotion not honoured".into());
    }
    groups.expire(6_000);
    if !groups.members(cell, Streams::RAW).is_empty() || !groups.keys().is_empty() {
        return Err("nothing should remain".into());
    }
    Ok(())
}

/// RFC-0171 §3.6: an ask keeps its relay a member for `ASK_LIFETIME_MS`, and a demotion keeps a
/// member out for `DEMOTION_MS`, both by the relay's monotonic clock. A forward step of the judging
/// clock longer than an ask's life lapses no membership, a backward step stretches no demotion,
/// and each ends on time by the monotonic clock. Before, both were put on the judging clock: the
/// step forward dropped the asking relay from its groups, and the step back held a member out a
/// minute longer.
#[test]
fn asks_and_demotions_lapse_by_the_monotonic_clock() -> Outcome {
    use super::groups::{ASK_LIFETIME_MS, DEMOTION_MS};
    let sharing = super::Sharing::new(Deadlines::RELAY);
    let cell = area()?;
    sharing.take_areas_for_test(vec![cell]);
    let assignment = tally_wire::StripeAssignment {
        cell,
        product: Streams::RAW,
        stripes_of: STRIPES,
        stripes: 1,
    };
    let relay = Asker {
        role: AskerRole::Relay,
        key: identity(1).public(),
        source: 1,
        loopback: false,
        address: None,
    };
    // Asked while the judging clock reads two minutes ahead of the monotonic one: the ask's life
    // is counted from the monotonic clock's reading, not the judging clock's.
    let start = super::Now::from(crate::ingest::Stamp::recorded(
        START_MS,
        0,
        START_MS + 120_000,
        START_MS,
        true,
    ));
    sharing.assigned(&relay, assignment, start);
    let stepped = |ahead_ms: u64, judge_step_ms: i64| {
        super::Now::from(crate::ingest::Stamp::recorded(
            START_MS + ahead_ms,
            0,
            (START_MS + ahead_ms).saturating_add_signed(judge_step_ms),
            START_MS + ahead_ms,
            true,
        ))
    };
    let _ = sharing
        .groups
        .expire(stepped(1_000, ASK_LIFETIME_MS as i64 + 60_000));
    if sharing.groups.members(cell, Streams::RAW) != vec![relay.key] {
        return Err("a forward step of the judging clock lapsed an ask".into());
    }
    let _ = sharing.groups.expire(stepped(ASK_LIFETIME_MS, -60_000));
    if !sharing.groups.members(cell, Streams::RAW).is_empty() {
        return Err("an ask outlived its life by the monotonic clock".into());
    }
    let key = GroupKey::new(cell, Streams::RAW);
    let demoted = identity(2).public();
    sharing
        .groups
        .admit(key, demoted, super::MonoDeadline::NEVER, false);
    let at = stepped(ASK_LIFETIME_MS, 120_000);
    sharing.groups.demote(key, demoted, at.after(DEMOTION_MS));
    let _ = sharing
        .groups
        .expire(stepped(ASK_LIFETIME_MS + DEMOTION_MS, -60_000));
    if sharing.groups.members(cell, Streams::RAW) != vec![demoted] {
        return Err("a backward step of the judging clock stretched a demotion".into());
    }
    Ok(())
}

#[test]
fn the_seam_admits_relays_that_ask_and_ignores_clients() -> Outcome {
    let sharing = super::Sharing::new(Deadlines::RELAY);
    let cell = area()?;
    sharing.take_areas_for_test(vec![cell]);
    let assignment = tally_wire::StripeAssignment {
        cell,
        product: Streams::RAW,
        stripes_of: STRIPES,
        stripes: 1,
    };
    let relay = Asker {
        role: AskerRole::Relay,
        key: identity(1).public(),
        source: 1,
        loopback: false,
        address: None,
    };
    let client = Asker {
        role: AskerRole::Client,
        key: identity(2).public(),
        source: 2,
        loopback: false,
        address: None,
    };
    sharing.assigned(&client, assignment, 1_000);
    sharing.assigned(&relay, assignment, 1_000);
    if sharing.groups.members(cell, Streams::RAW) != vec![relay.key] {
        return Err("the seam's membership".into());
    }
    // Before the relay serves (no identity yet), group records are taken without effect.
    sharing.originate(&Record::Heartbeat, cell, Streams::RAW, 1_000);
    if !sharing.take_outbox().is_empty() {
        return Err("an outbox before serving".into());
    }
    Ok(())
}

/// An ask books its asker only in a group this relay holds (an area it takes, a product it
/// shares), charged to the store while it is held, and not past the store's room: a relay naming
/// cells this relay does not take, or asking past the room, holds nothing here. Before, every
/// cell named was booked, uncharged.
#[test]
fn an_ask_is_booked_only_for_a_group_held_and_charged() -> Outcome {
    use super::groups::{ASK_BYTES, ASK_LIFETIME_MS};
    let sharing = super::Sharing::new(Deadlines::RELAY);
    let cell = area()?;
    let elsewhere = children(cell.ancestor(2).ok_or("no parent")?)
        .into_iter()
        .find(|other| *other != cell)
        .ok_or("one child")?;
    sharing.take_areas_for_test(vec![cell]);
    let gauge = Gauge::new(Store::Batches, 1 << 20);
    sharing.charge_to(Arc::clone(&gauge));
    let ask = |cell: Region, product: Streams| tally_wire::StripeAssignment {
        cell,
        product,
        stripes_of: STRIPES,
        stripes: 1,
    };
    let asker = |index: usize| Asker {
        role: AskerRole::Relay,
        key: identity(index).public(),
        source: index as u64,
        loopback: false,
        address: None,
    };
    sharing.assigned(&asker(1), ask(elsewhere, Streams::RAW), START_MS);
    sharing.assigned(&asker(1), ask(cell, Streams(0x8000)), START_MS);
    if !sharing.groups.keys().is_empty() || sharing.groups.asks().0 != 0 {
        return Err("an ask for a group not held was booked".into());
    }
    let before = gauge.held();
    sharing.assigned(&asker(1), ask(cell, Streams::RAW), START_MS);
    sharing.assigned(&asker(1), ask(cell, Streams::RAW), START_MS + 1);
    if sharing.groups.members(cell, Streams::RAW) != vec![asker(1).key]
        || gauge.held() - before != ASK_BYTES
    {
        return Err(format!(
            "one ask held charged {}, not {ASK_BYTES}",
            gauge.held() - before
        ));
    }
    // Past the store's room, no more asks are held.
    let full = Gauge::new(Store::Batches, ASK_BYTES * 3 / 2);
    sharing.charge_to(Arc::clone(&full));
    sharing.assigned(&asker(2), ask(cell, Streams::RAW), START_MS);
    if sharing.groups.members(cell, Streams::RAW).len() != 1 || sharing.groups.asks().1 != 1 {
        return Err("an ask past the store's room was held".into());
    }
    // Lapsed, its charge is let go.
    let _ = sharing.groups.expire(START_MS + ASK_LIFETIME_MS + 10);
    if full.held() != 0 || !sharing.groups.keys().is_empty() {
        return Err(format!("{} bytes held by lapsed asks", full.held()));
    }
    Ok(())
}

/// A receiver's batch as a group carries it: its hash and its encoding.
fn record(receiver: &Identity, sequence: u64, wall_ms: u64) -> Result<(Hash, Piece), String> {
    let batch = crate::anchors::anchored(
        receiver,
        &BatchContent {
            boot_id: 1,
            sequence,
            counter_epoch: 0,
            wall_ms,
            dropped: 0,
            previous: [0; 32],
            observations: Vec::new(),
        },
    )
    .map_err(text)?;
    let piece = Piece::of(&Record::Batch(batch)).ok_or("no piece")?;
    let hash = piece.hash().ok_or("no hash")?;
    Ok((hash, piece))
}

fn manifest(
    origin: &Identity,
    group: GroupKey,
    second: u64,
    hashes: &[Hash],
) -> Result<PieceManifest, String> {
    let mut hashes = hashes.to_vec();
    hashes.sort();
    PieceManifest::sign(
        origin,
        &PieceManifestContent {
            cell: group.cell,
            product: group.product,
            second,
            hashes,
        },
    )
    .map_err(text)
}

fn relay(key: PublicKey) -> Asker {
    Asker {
        role: AskerRole::Relay,
        key,
        source: 1,
        loopback: false,
        address: None,
    }
}

/// A relay's verified offer for `cell`, held in the hub's directory.
fn hold_offer(
    hub: &crate::hub::Hub,
    relay: &Identity,
    cell: Region,
    stripes: u32,
    now_ms: u64,
) -> Outcome {
    let offer = tally_wire::ProviderOffer::sign(
        relay,
        &tally_wire::ProviderOfferContent {
            address: "relay.example:7450".to_owned(),
            cell,
            products: Streams(
                Streams::RAW.0
                    | Streams::POSITIONS.0
                    | Streams::PROVISIONAL.0
                    | Streams::CLOCK_MODELS.0
                    | Streams::REGIONAL.0,
            ),
            stripes_of: STRIPES,
            stripes,
            mlat_cores: 0,
            feeder_slots: 0,
            network: 0,
            issued_ms: now_ms,
            expires_ms: now_ms + 10 * 60 * 1000,
        },
    )
    .map_err(text)?;
    let first = relay.public().as_bytes()[0];
    hub.network().directory.hold_verified(
        offer,
        crate::directory::Group::of(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10, first, 0, 1,
        ))),
        judged(now_ms),
    )?;
    Ok(())
}

#[test]
fn a_have_summary_at_the_end_of_time_is_refused_not_a_panic() -> Outcome {
    let me = identity(0);
    let group = GroupKey::new(area()?, Streams::RAW);
    let mut member = unlimited(crate::signer::twin(&me));
    let members = keys(3);
    let _ = member.set_members(group, &members, &[], START_MS);
    let origin = identity(1);
    let (hash, piece) = record(&identity(10_000), 1, START_MS)?;
    let second = START_MS / 1000;
    let _ = member.receive(members[1], Message::Piece { group, hash, piece }, START_MS);
    let _ = member.receive(
        members[1],
        Message::Manifest(manifest(&origin, group, second, &[hash])?),
        START_MS,
    );
    // `first_second + len * 8` wraps here: the old answer panicked inside `BTreeMap::range`.
    for first_second in [u64::MAX, u64::MAX - 3, u64::MAX - 100] {
        let have = tally_wire::HaveSummary {
            cell: group.cell,
            product: group.product,
            first_second,
            seconds: vec![0; 64],
        };
        let out = member.receive(members[2], Message::Have(have), START_MS + 5_000);
        if !out.is_empty() {
            return Err("answered a summary past the end of time".into());
        }
    }
    // An honest summary is still answered.
    let have = tally_wire::HaveSummary {
        cell: group.cell,
        product: group.product,
        first_second: second - 3,
        seconds: vec![0; 2],
    };
    if member
        .receive(members[2], Message::Have(have), START_MS + 6_000)
        .is_empty()
    {
        return Err("an honest summary went unanswered".into());
    }
    Ok(())
}

#[test]
fn a_poisoned_lock_does_not_end_sharing() -> Outcome {
    let hub = crate::hub::Hub::new(8, crate::sharing::Deadlines::RELAY);
    let cell = area()?;
    hub.network().selection.set_taken(vec![cell]);
    let sharing = super::Sharing::new(Deadlines::RELAY);
    let me = identity(0);
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&me))),
        0,
        START_MS,
    );
    // A panic while the member and the outbox are held poisons both locks.
    for poison in 0..2 {
        let _ = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _member = sharing.member.lock();
                    let _outbox = sharing.outbox.lock();
                    let _assembling = sharing.assembling.lock();
                    panic!("poisoned on purpose ({poison})");
                })
                .join()
        });
    }
    if !sharing.member.is_poisoned() {
        return Err("the lock was not poisoned".into());
    }
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&me))),
        0,
        START_MS + 1_000,
    );
    if sharing.layout(cell, Streams::RAW).is_none() {
        return Err("sharing ended with a poisoned lock".into());
    }
    let batch = record(&identity(10_000), 1, START_MS)?
        .1
        .record()
        .ok_or("no record")?;
    sharing.originate(&batch, cell, Streams::RAW, START_MS + 1_100);
    let _ = sharing.take_outbox();
    Ok(())
}

#[test]
fn a_region_coarser_than_an_area_is_shared_in_its_areas_groups() -> Outcome {
    let hub = crate::hub::Hub::new(8, crate::sharing::Deadlines::RELAY);
    let area = area()?;
    let region = area.ancestor(1).ok_or("no region")?;
    hub.network().selection.set_taken(vec![region]);
    let sharing = &hub.network().sharing;
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&identity(0)))),
        0,
        START_MS,
    );
    // Every record of the area routes to the area's group (`group_of`), and the relay is in it.
    if sharing.layout(area, Streams::RAW).is_none() {
        return Err("no group for an area under the region taken".into());
    }
    if sharing.layout(region, Streams::RAW).is_some() {
        return Err("a group for the region itself, which no record routes to".into());
    }
    Ok(())
}

#[test]
fn manifests_are_taken_from_members_each_within_its_own_share() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let mut member = unlimited(identity(0));
    let members = keys(3);
    let _ = member.set_members(group, &members, &[], START_MS);
    let second = START_MS / 1000;
    // A stranger's manifest is not taken, however well it is signed.
    let stranger = identity(99);
    let _ = member.receive(
        members[1],
        Message::Manifest(manifest(&stranger, group, second, &[[1; 32]])?),
        START_MS,
    );
    if !member.manifests(group, second).is_empty() {
        return Err("took a stranger's manifest".into());
    }
    // A member flooding one second fills only its own share of it.
    let flooder = identity(1);
    for n in 0..200u8 {
        let _ = member.receive(
            members[1],
            Message::Manifest(manifest(&flooder, group, second, &[[n; 32]])?),
            START_MS,
        );
    }
    if member.manifests(group, second).len() != super::member::MAX_MANIFESTS_PER_ORIGIN_SECOND {
        return Err(format!(
            "held {} of the flood",
            member.manifests(group, second).len()
        ));
    }
    let honest = manifest(&identity(2), group, second, &[[7; 32]])?;
    let _ = member.receive(members[2], Message::Manifest(honest.clone()), START_MS);
    if !member.manifests(group, second).contains(&honest) {
        return Err("a flood crowded out another origin's manifest".into());
    }
    // A second past the clock's allowance is not taken, so the horizon bounds what is held.
    let ahead = second + tally_wire::budget::K.duration().as_secs() + 1;
    let _ = member.receive(
        members[2],
        Message::Manifest(manifest(&identity(2), group, ahead, &[[8; 32]])?),
        START_MS,
    );
    if !member.manifests(group, ahead).is_empty() {
        return Err("took a manifest from the future".into());
    }
    Ok(())
}

/// A relay serving `cell` with `origins` in its groups by their verified offers, its batch store's
/// gauge `limit` bytes: what the seam's parity reassembly is checked against.
fn serving_with_members(
    cell: Region,
    origins: &[&Identity],
    limit: usize,
) -> Result<(crate::hub::Hub, super::Sharing, Arc<Gauge>), String> {
    let hub = crate::hub::Hub::new(8, crate::sharing::Deadlines::RELAY);
    hub.network().selection.set_taken(vec![cell]);
    let sharing = super::Sharing::new(Deadlines::RELAY);
    let gauge = Gauge::new(Store::Batches, limit);
    sharing.charge_to(Arc::clone(&gauge));
    for origin in origins {
        hold_offer(&hub, origin, cell, 0b1111, START_MS)?;
    }
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&identity(0)))),
        0,
        START_MS,
    );
    Ok((hub, sharing, gauge))
}

/// `count` hashes, as many in each data stripe as the others but for rounding.
fn hashes(count: usize, salt: u8) -> Vec<Hash> {
    (0..count)
        .map(|index| {
            let mut hash = [salt; 32];
            // The stripe is read from the leading bytes (`stripe_of`): the index leads.
            hash[..8].copy_from_slice(&(index as u64).to_le_bytes());
            hash
        })
        .collect()
}

/// RFC-0174 §2.5, "A parity is checked against its manifest": a parity is reassembled only for an
/// origin manifest the relay holds, from a relay its group knows, no longer than that manifest's
/// records allow, and only as its origin cuts it (in order from the start, whole chunks but the
/// last); each chunk is charged as it arrives, never its declared whole ahead of it.
///
/// And in a room of its own, sized as the budget plans it from the members' rate
/// (`assembly_room`), never the batch store: a member that never finishes its parities fills its
/// own part of that room and no more, the batch store holds none of it, and another sender's
/// parity is still taken.
#[test]
fn a_parity_is_reassembled_in_its_own_room_only_as_its_origin_cuts_it() -> Outcome {
    use tally_wire::sharing::{MAX_PARITY_CHUNK, MAX_PARITY_LEN};
    let cell = area()?;
    let group = GroupKey::new(cell, Streams::RAW);
    let (origin, other) = (identity(1), identity(3));
    let asker = relay(origin.public());
    // The batch store as small as a relay's may be; the room as the budget plans it at the
    // members' default rate.
    let (hub, sharing, gauge) = serving_with_members(cell, &[&origin, &other], 4 << 20)?;
    let rate = 1 << 20;
    let room = Gauge::new(Store::Batches, super::assembly_room(rate));
    sharing.assemble_in(Arc::clone(&room));
    let part = super::sender_part(room.limit());
    let second = START_MS / 1000;
    let now = START_MS + 300;
    let held = |sharing: &super::Sharing| {
        let assembly = super::locks::lock(&sharing.assembling);
        // What the room is charged is what the assembly allocates, whatever it holds.
        assert_eq!(room.held(), assembly.allocated());
        assembly
            .senders
            .values()
            .map(|sender| sender.parities.len())
            .sum::<usize>()
    };
    // What one sender's part is charged now.
    let sender_held = |sharing: &super::Sharing, key: &PublicKey| {
        super::locks::lock(&sharing.assembling)
            .senders
            .get(key)
            .map_or(0, super::Sender::held)
    };
    // The batch store's charge once the member's sends to the group (a manifest flooded, an
    // assignment) are let go, as the links would take them.
    let batches = |sharing: &super::Sharing| {
        drop(sharing.take_outbox());
        gauge.held()
    };
    let signed_with = |origin: &Identity, salt: u8| {
        let mut listed = hashes(tally_wire::sharing::MAX_PIECES, 5);
        listed.iter_mut().for_each(|hash| hash[31] = salt);
        manifest(origin, group, second, &listed)
    };
    let signed = signed_with(&origin, 0)?;
    sharing.manifest(&asker, signed.clone(), now);
    let chunk = |manifest: Hash, total: usize, offset: usize, len: usize| {
        Ok::<_, String>(tally_wire::ParityChunk {
            manifest,
            cell,
            product: Streams::RAW,
            second,
            lens: vec![u32::try_from(total).map_err(text)?; usize::from(DATA_STRIPES)],
            total: u32::try_from(total).map_err(text)?,
            offset: u32::try_from(offset).map_err(text)?,
            bytes: vec![1; len],
        })
    };
    let total = 3 * MAX_PARITY_CHUNK + 10;
    // A manifest nobody signed: nothing held, nothing charged.
    sharing.parity_chunk(&asker, chunk([3; 32], total, 0, MAX_PARITY_CHUNK)?, now);
    // A whole longer than the manifest's records allow is refused.
    let too_long = manifest(
        &origin,
        group,
        second,
        &hashes(usize::from(DATA_STRIPES) * 4, 6),
    )?;
    sharing.manifest(&asker, too_long.clone(), now);
    sharing.parity_chunk(
        &asker,
        chunk(
            too_long.hash(),
            MAX_PARITY_LEN as usize,
            0,
            MAX_PARITY_CHUNK,
        )?,
        now,
    );
    // A relay the group does not know is refused for a manifest it does hold.
    sharing.parity_chunk(
        &relay(identity(2).public()),
        chunk(signed.hash(), total, 0, MAX_PARITY_CHUNK)?,
        now,
    );
    // Off the origin's cut: a start shorter than a chunk and not the whole, or one not at a
    // chunk's place.
    sharing.parity_chunk(&asker, chunk(signed.hash(), total, 0, 100)?, now);
    sharing.parity_chunk(
        &asker,
        chunk(signed.hash(), total, 100, MAX_PARITY_CHUNK)?,
        now,
    );
    if held(&sharing) != 0 || room.held() != 0 {
        return Err("a chunk refused by its manifest, its sender or its cut was held".into());
    }
    // A start of a held manifest is charged what it brought, never the whole declared.
    sharing.parity_chunk(
        &asker,
        chunk(signed.hash(), total, 0, MAX_PARITY_CHUNK)?,
        now,
    );
    let first = room.held();
    if held(&sharing) != 1 || !(MAX_PARITY_CHUNK..2 * MAX_PARITY_CHUNK).contains(&first) {
        return Err(format!(
            "a whole first chunk of a {total}-byte parity is charged {first} bytes"
        ));
    }
    // The start again begins it again: charged once.
    sharing.parity_chunk(
        &asker,
        chunk(signed.hash(), total, 0, MAX_PARITY_CHUNK)?,
        now,
    );
    if room.held() != first || held(&sharing) != 1 {
        return Err("a start sent twice was charged twice".into());
    }
    // A chunk out of its place (the second skipped) lets the parity go: it can never be whole.
    sharing.parity_chunk(
        &asker,
        chunk(signed.hash(), total, 2 * MAX_PARITY_CHUNK, MAX_PARITY_CHUNK)?,
        now,
    );
    if held(&sharing) != 0 || room.held() != 0 {
        return Err("a parity missing a chunk was still held".into());
    }
    // A stalled parity is let go after its time, and its charge with it.
    sharing.parity_chunk(
        &asker,
        chunk(signed.hash(), total, 0, MAX_PARITY_CHUNK)?,
        now,
    );
    let later = now + super::PARITY_ASSEMBLY_MS + 1;
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&identity(0)))),
        0,
        later,
    );
    if held(&sharing) != 0 || room.held() != 0 {
        return Err(format!(
            "a stalled parity still held: {} assembling, {} bytes charged",
            held(&sharing),
            room.held()
        ));
    }
    // A whole parity in its cut is taken as the member's, and the room holds none of it after.
    let now = later;
    for offset in (0..total).step_by(MAX_PARITY_CHUNK) {
        let len = MAX_PARITY_CHUNK.min(total - offset);
        sharing.parity_chunk(&asker, chunk(signed.hash(), total, offset, len)?, now);
    }
    if held(&sharing) != 0 || room.held() != 0 {
        return Err("a whole parity was still reassembling".into());
    }

    // A member that never finishes: the longest parity's chunks, sent past its part. It holds
    // its part at most, then the parity is let go whole; the batch store holds none of it.
    let stalled = signed_with(&origin, 2)?;
    sharing.manifest(&asker, stalled.clone(), now);
    let before = batches(&sharing);
    let longest = MAX_PARITY_LEN as usize;
    let mut peak = 0;
    for offset in (0..longest - MAX_PARITY_CHUNK).step_by(MAX_PARITY_CHUNK) {
        sharing.parity_chunk(
            &asker,
            chunk(stalled.hash(), longest, offset, MAX_PARITY_CHUNK)?,
            now,
        );
        peak = peak.max(sender_held(&sharing, &origin.public()));
        held(&sharing);
    }
    if peak > part || peak + 2 * MAX_PARITY_CHUNK < part {
        return Err(format!(
            "one sender held {peak} bytes reassembling, its part {part} of {} B",
            room.limit()
        ));
    }
    if batches(&sharing) != before {
        return Err(format!(
            "reassembling charged the batch store: {before} then {} bytes",
            batches(&sharing)
        ));
    }
    // Another sender's parity is its own: taken and finished whatever the first did.
    sharing.parity_chunk(
        &asker,
        chunk(stalled.hash(), longest, 0, MAX_PARITY_CHUNK)?,
        now,
    );
    let theirs = signed_with(&other, 0)?;
    sharing.manifest(&relay(other.public()), theirs.clone(), now);
    sharing.parity_chunk(
        &relay(other.public()),
        chunk(theirs.hash(), total, 0, MAX_PARITY_CHUNK)?,
        now,
    );
    if held(&sharing) != 2 {
        return Err("another sender was refused for the first's part".into());
    }
    Ok(())
}

/// What the room is planned as holds everything the members' rate brings while a parity waits,
/// at what it is charged: every chunk whole (the cut taken), each an unfinished parity's first
/// (the most a chunk is charged).
#[test]
fn the_assembly_room_holds_what_the_members_rate_brings_while_a_parity_waits() -> Outcome {
    use tally_wire::sharing::MAX_PARITY_CHUNK;
    let rate: usize = 1 << 20;
    let brought = rate * (super::PARITY_ASSEMBLY_MS / 1000) as usize + rate;
    let chunks = brought.div_ceil(MAX_PARITY_CHUNK);
    let charged = brought
        + chunks * super::ASSEMBLING_PER_CHUNK_BYTES
        + crate::footprint::Tree::<PublicKey, super::Sender>::bytes_planned(0);
    if super::assembly_room(rate) < charged {
        return Err(format!(
            "the room {} is less than the {charged} B the rate brings while a parity waits",
            super::assembly_room(rate)
        ));
    }
    if super::sender_part(super::assembly_room(rate)) < 2 * rate {
        return Err("a sender's part holds less than two seconds of the members' rate".into());
    }
    Ok(())
}

#[test]
fn a_false_parity_is_dropped_and_a_true_one_after_it_rebuilds() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let me = identity(0);
    let members = keys(4);
    let mut member = unlimited(me);
    let _ = member.set_members(group, &members, &[], START_MS);
    let origin = identity(1);
    let receiver = identity(10_000);
    let mut pieces = Vec::new();
    for sequence in 0..24 {
        pieces.push(record(&receiver, sequence, START_MS)?);
    }
    let second = START_MS / 1000;
    let hashes: Vec<Hash> = pieces.iter().map(|(hash, _)| *hash).collect();
    let signed = manifest(&origin, group, second, &hashes)?;
    let lost = data_stripe(&hashes[0]);
    let _ = member.receive(members[1], Message::Manifest(signed.clone()), START_MS);
    for (hash, bytes) in &pieces {
        if data_stripe(hash) != lost {
            let message = Message::Piece {
                group,
                hash: *hash,
                piece: bytes.clone(),
            };
            let _ = member.receive(members[1], message, START_MS);
        }
    }
    let views: Vec<(Hash, &Piece)> = pieces.iter().map(|(h, b)| (*h, b)).collect();
    let good = Parity::build(signed.hash(), group.cell, group.product, second, &views);
    let mut bad = good.clone();
    for byte in &mut bad.xor {
        *byte ^= 0x5a;
    }
    let _ = member.receive(members[2], Message::Parity(Arc::new(bad)), START_MS);
    let rebuild_at = (second + 1) * 1000 + super::member::REBUILD_AFTER_MS;
    let _ = member.tick(rebuild_at);
    if member.stats().rebuilt != 0 {
        return Err("rebuilt from a false parity".into());
    }
    let _ = member.receive(members[3], Message::Parity(Arc::new(good)), rebuild_at + 10);
    let _ = member.tick(rebuild_at + 250);
    let missing = hashes
        .iter()
        .filter(|hash| data_stripe(hash) == lost)
        .count() as u64;
    // Each held, or rebuilt and awaiting its relay's judgment.
    let had = |hash: &Hash| member.holds(group, hash) || member.judging(group, hash);
    if member.stats().rebuilt != missing || !hashes.iter().all(had) {
        return Err(format!(
            "rebuilt {} of {missing} after the true parity came",
            member.stats().rebuilt
        ));
    }
    Ok(())
}

/// A parity rebuilds its stripe's whole slice, the records already held beside those missing. A
/// member that holds part of a stripe when the true parity comes (one of its records arrived, the
/// rest did not yet) rebuilds the rest from it and keeps it: the parity is not taken for false, so
/// the member that delivered it is not reported short of it.
#[test]
fn a_true_parity_rebuilds_the_rest_of_a_stripe_partly_held_and_is_kept() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(4);
    let mut member = unlimited(identity(0));
    let _ = member.set_members(group, &members, &[], START_MS);
    let origin = identity(1);
    let receiver = identity(10_000);
    let mut pieces = Vec::new();
    for sequence in 0..24 {
        pieces.push(record(&receiver, sequence, START_MS)?);
    }
    let second = START_MS / 1000;
    let hashes: Vec<Hash> = pieces.iter().map(|(hash, _)| *hash).collect();
    let signed = manifest(&origin, group, second, &hashes)?;
    let lost = data_stripe(&hashes[0]);
    let in_lost = hashes
        .iter()
        .filter(|hash| data_stripe(hash) == lost)
        .count() as u64;
    if in_lost < 2 {
        return Err(format!("{in_lost} records in the stripe, not a part of it"));
    }
    let _ = member.receive(members[1], Message::Manifest(signed.clone()), START_MS);
    // Every other stripe whole, and of this one only the first record.
    for (hash, bytes) in &pieces {
        if data_stripe(hash) != lost || *hash == hashes[0] {
            let message = Message::Piece {
                group,
                hash: *hash,
                piece: bytes.clone(),
            };
            let _ = member.receive(members[1], message, START_MS);
        }
    }
    let views: Vec<(Hash, &Piece)> = pieces.iter().map(|(h, b)| (*h, b)).collect();
    let parity = Parity::build(signed.hash(), group.cell, group.product, second, &views);
    let _ = member.receive(members[2], Message::Parity(Arc::new(parity)), START_MS);
    let _ = member.tick((second + 1) * 1000 + super::member::REBUILD_AFTER_MS);
    // Each held, or rebuilt and awaiting its relay's judgment.
    let had = |hash: &Hash| member.holds(group, hash) || member.judging(group, hash);
    if member.stats().rebuilt != in_lost - 1 || !hashes.iter().all(had) {
        return Err(format!(
            "rebuilt {} of the {} the stripe lacked",
            member.stats().rebuilt,
            in_lost - 1
        ));
    }
    if !member.holds_parity(group, &signed.hash()) {
        return Err("a true parity was let go for a stripe held in part".into());
    }
    Ok(())
}

/// A record rebuilt from parity is held and handed to the relay, and pushed on down its stripe only
/// once the relay judged it and passed it on (`Member::pass_on`), as a piece a member sent is
/// pushed on only once its relay took it in. One the relay refuses is let go and never travels:
/// before, `rebuild` pushed it to the stripe's children at once, so a record its relay would
/// refuse (a false fault proof, positions that do not verify) went on to every member below.
#[test]
fn a_rebuilt_record_is_pushed_on_only_once_its_relay_passed_it() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(24);
    let receiver = identity(10_000);
    let mut pieces = Vec::new();
    for sequence in 0..24 {
        pieces.push(record(&receiver, sequence, START_MS)?);
    }
    let second = START_MS / 1000;
    let hashes: Vec<Hash> = pieces.iter().map(|(hash, _)| *hash).collect();
    let lost = data_stripe(&hashes[0]);
    // The member that rebuilds is interior in the stripe lost, so it has children to push to; the
    // manifest's and the parity's senders are two others.
    let layout = Layout::new(group.cell, group.product, &members, &[]);
    let me = *layout
        .interior(lost)
        .first()
        .ok_or("the stripe lost has no interior")?;
    let index = members
        .iter()
        .position(|key| *key == me)
        .ok_or("not a member")?;
    let others: Vec<usize> = (0..members.len()).filter(|other| *other != index).collect();
    let mut member = unlimited(identity(index));
    let _ = member.set_members(group, &members, &[], START_MS);
    let signed = manifest(&identity(others[0]), group, second, &hashes)?;
    let _ = member.receive(
        members[others[0]],
        Message::Manifest(signed.clone()),
        START_MS,
    );
    for (hash, bytes) in &pieces {
        if data_stripe(hash) != lost {
            let message = Message::Piece {
                group,
                hash: *hash,
                piece: bytes.clone(),
            };
            let _ = member.receive(members[others[0]], message, START_MS);
        }
    }
    let views: Vec<(Hash, &Piece)> = pieces.iter().map(|(h, b)| (*h, b)).collect();
    let parity = Parity::build(signed.hash(), group.cell, group.product, second, &views);
    let _ = member.receive(
        members[others[1]],
        Message::Parity(Arc::new(parity)),
        START_MS,
    );
    let now = (second + 1) * 1000 + super::member::REBUILD_AFTER_MS;
    let ticked = member.tick(now);
    let rebuilt: Vec<Hash> = member
        .take_delivered()
        .into_iter()
        .filter(|delivered| delivered.arrival == Arrival::Rebuilt)
        .map(|delivered| delivered.hash)
        .collect();
    if rebuilt.len() < 2 {
        return Err(format!(
            "rebuilt {} records of the stripe lost",
            rebuilt.len()
        ));
    }
    let pieces_of = |out: &[Outgoing], hash: &Hash| {
        out.iter()
            .filter(
                |sent| matches!(&sent.message, Message::Piece { hash: sent, .. } if sent == hash),
            )
            .count()
    };
    if rebuilt.iter().any(|hash| pieces_of(&ticked, hash) > 0) {
        return Err("a rebuilt record was pushed on before its relay judged it".into());
    }
    // Held apart until judged: not among the records it holds, so none is answered to a repair.
    if rebuilt
        .iter()
        .any(|hash| member.holds(group, hash) || !member.judging(group, hash))
    {
        return Err("a rebuilt record was held as judged before its relay judged it".into());
    }
    // Its relay refuses the first: let go, and never passed on.
    let (refused, passed) = (rebuilt[0], rebuilt[1]);
    member.refuse(group, refused, now);
    if member.holds(group, &refused) {
        return Err("a rebuilt record its relay refused is still held".into());
    }
    let piece_of = |hash: &Hash| {
        pieces
            .iter()
            .find(|(held, _)| held == hash)
            .map(|(_, piece)| piece.clone())
            .ok_or("not a record of the manifest")
    };
    if pieces_of(
        &member.pass_on(group, refused, piece_of(&refused)?, now),
        &refused,
    ) > 0
    {
        return Err("a rebuilt record its relay refused was pushed on".into());
    }
    // The second passed: pushed on to the stripe's children.
    if pieces_of(
        &member.pass_on(group, passed, piece_of(&passed)?, now),
        &passed,
    ) == 0
    {
        return Err("a rebuilt record its relay passed was not pushed on".into());
    }
    if !member.holds(group, &passed) || member.judging(group, &passed) {
        return Err("a rebuilt record its relay passed is not held".into());
    }
    Ok(())
}

/// A record a member delivered while there was no room to take it is credited to that member
/// (`Member::credit`), and when parity later rebuilds it and its relay passes it, the record held
/// keeps that credit: its earlier sender is still a deliverer of it, and its receipts count it had.
/// Before, the rebuilt record was held with no senders, its credit was left behind beside it, and
/// the member that delivered it first was reported short.
#[test]
fn a_rebuilt_record_keeps_the_credit_of_its_earlier_sender() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(24);
    let receiver = identity(10_000);
    let mut pieces = Vec::new();
    for sequence in 0..24 {
        pieces.push(record(&receiver, sequence, START_MS)?);
    }
    let second = START_MS / 1000;
    let hashes: Vec<Hash> = pieces.iter().map(|(hash, _)| *hash).collect();
    let lost = data_stripe(&hashes[0]);
    let layout = Layout::new(group.cell, group.product, &members, &[]);
    let me = *layout
        .interior(lost)
        .first()
        .ok_or("the stripe lost has no interior")?;
    let index = members
        .iter()
        .position(|key| *key == me)
        .ok_or("not a member")?;
    let others: Vec<usize> = (0..members.len()).filter(|other| *other != index).collect();
    let mut member = unlimited(identity(index));
    let _ = member.set_members(group, &members, &[], START_MS);
    let signed = manifest(&identity(others[0]), group, second, &hashes)?;
    let _ = member.receive(
        members[others[0]],
        Message::Manifest(signed.clone()),
        START_MS,
    );
    let earlier = members[others[2]];
    for (hash, bytes) in &pieces {
        if data_stripe(hash) == lost {
            // Delivered while there was no room: credited, not held.
            member.credit(earlier, group, (*hash, 100), START_MS);
        } else {
            let message = Message::Piece {
                group,
                hash: *hash,
                piece: bytes.clone(),
            };
            let _ = member.receive(members[others[0]], message, START_MS);
        }
    }
    let views: Vec<(Hash, &Piece)> = pieces.iter().map(|(h, b)| (*h, b)).collect();
    let parity = Parity::build(signed.hash(), group.cell, group.product, second, &views);
    let _ = member.receive(
        members[others[1]],
        Message::Parity(Arc::new(parity)),
        START_MS,
    );
    let now = (second + 1) * 1000 + super::member::REBUILD_AFTER_MS;
    let _ = member.tick(now);
    let rebuilt: Vec<Hash> = member
        .take_delivered()
        .into_iter()
        .filter(|delivered| delivered.arrival == Arrival::Rebuilt)
        .map(|delivered| delivered.hash)
        .collect();
    let passed = *rebuilt.first().ok_or("nothing rebuilt")?;
    if !member.delivered(group, &passed, &earlier) {
        return Err("its earlier sender was not credited before it was rebuilt".into());
    }
    let piece = pieces
        .iter()
        .find(|(held, _)| *held == passed)
        .map(|(_, piece)| piece.clone())
        .ok_or("not a record of the manifest")?;
    let _ = member.pass_on(group, passed, piece, now);
    if !member.holds(group, &passed) {
        return Err("the rebuilt record its relay passed is not held".into());
    }
    if !member.delivered(group, &passed, &earlier) {
        return Err("the rebuilt record dropped its earlier sender's credit".into());
    }
    Ok(())
}

/// The hub gives each rebuilt record's verdict back to the group that rebuilt it, by the handle the
/// tick handed out with it (`Rebuilt`), never by reckoning the group again from the record: a
/// batch whose receiver this relay never saw described has no cell to reckon from, so before,
/// the verdict reached no group. A batch that passes is held and pushed down its stripe; a forged
/// one is refused, let go and never rebuilt again; one with no room in ingest is let go,
/// counted, and rebuilt again by the next tick.
#[test]
fn a_rebuilt_records_verdict_reaches_the_group_that_rebuilt_it() -> Outcome {
    use crate::hub::Hub;
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(24);
    let receiver = identity(10_000);
    let now = crate::clock::RelayClock::system().judged().ms();
    let second = now / 1000;
    let mut records: Vec<Record> = Vec::new();
    for sequence in 0..40 {
        let (_, piece) = record(&receiver, sequence, now)?;
        records.push(piece.record().ok_or("no record")?);
    }
    // The first is forged: its signature no longer verifies, though its bytes are a batch.
    if let Some(Record::Batch(batch)) = records.first_mut() {
        let mut bytes = batch.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        *batch = Batch::from_bytes(bytes).map_err(text)?;
    }
    let pieces: Vec<(Hash, Piece)> = records
        .iter()
        .map(|record| {
            let piece = Piece::of(record).ok_or("no piece")?;
            Ok((piece.hash().ok_or("no hash")?, piece))
        })
        .collect::<Result<_, String>>()?;
    let lost = data_stripe(&pieces[0].0);
    let in_lost: Vec<usize> = (0..pieces.len())
        .filter(|at| data_stripe(&pieces[*at].0) == lost)
        .collect();
    if in_lost.len() < 3 {
        return Err(format!("{} records in the stripe lost", in_lost.len()));
    }
    // This relay is interior in the stripe lost, so a record it passes has children to go to.
    let layout = Layout::new(group.cell, group.product, &members, &[]);
    let me = *layout.interior(lost).first().ok_or("no interior")?;
    let index = members
        .iter()
        .position(|key| *key == me)
        .ok_or("not a member")?;
    let others: Vec<usize> = (0..members.len()).filter(|other| *other != index).collect();
    let hub = Arc::new(Hub::new(8, Deadlines::RELAY).taking(vec![group.cell]));
    hub.network().adopt_identity(identity(index));
    let _ = hub.network().tick(&hub, now);
    let sharing = &hub.network().sharing;
    let hashes: Vec<Hash> = pieces.iter().map(|(hash, _)| *hash).collect();
    let signed = manifest(&identity(others[0]), group, second, &hashes)?;
    let views: Vec<(Hash, &Piece)> = pieces.iter().map(|(h, p)| (*h, p)).collect();
    let parity = Parity::build(signed.hash(), group.cell, group.product, second, &views);
    sharing
        .member_for_test(|member| {
            let _ = member.set_members(group, &members, &[], now);
            let _ = member.receive(members[others[0]], Message::Manifest(signed.clone()), now);
            for (hash, piece) in &pieces {
                if data_stripe(hash) != lost {
                    let message = Message::Piece {
                        group,
                        hash: *hash,
                        piece: piece.clone(),
                    };
                    let _ = member.receive(members[others[0]], message, now);
                }
            }
            let _ = member.receive(members[others[1]], Message::Parity(Arc::new(parity)), now);
        })
        .ok_or("no member")?;
    let rebuild_at = (second + 1) * 1000 + super::member::REBUILD_AFTER_MS;
    let rebuilt = sharing.tick_member_for_test(rebuild_at);
    drop(sharing.take_outbox());
    let handle = |at: usize| {
        rebuilt
            .iter()
            .find(|(rebuilt, _)| rebuilt.hash == pieces[at].0)
            .map(|(rebuilt, record)| (*rebuilt, record.clone()))
            .ok_or(format!("record {at} was not rebuilt"))
    };
    let (forged, passed, no_room) = (
        handle(in_lost[0])?,
        handle(in_lost[1])?,
        handle(in_lost[2])?,
    );
    let state = |hash: &Hash| {
        sharing
            .member_for_test(|member| (member.holds(group, hash), member.judging(group, hash)))
            .unwrap_or_default()
    };
    // No room in ingest: let go, counted, and not held.
    let ingest = hub.budget().gauge(Store::Ingest);
    let full = ingest
        .try_charge(ingest.limit() - 1)
        .ok_or("ingest's room was not free")?;
    hub.take_rebuilt(no_room.0, no_room.1);
    drop(full);
    if hub.memory_report().rebuilt_no_room != 1 || state(&no_room.0.hash) != (false, false) {
        return Err("a rebuilt record with no room was not let go from its group".into());
    }
    // Forged: refused, counted, and not held.
    hub.take_rebuilt(forged.0, forged.1);
    hub.flush();
    if hub.memory_report().rebuilt_refused != 1 || state(&forged.0.hash) != (false, false) {
        return Err("a forged rebuilt record is still held in its group".into());
    }
    // Passed: held, and pushed down its stripe to its children.
    let record = passed.1.clone();
    hub.take_rebuilt(passed.0, passed.1);
    hub.flush();
    if state(&passed.0.hash) != (true, false) {
        return Err("a rebuilt record that passed is not held in its group".into());
    }
    let sent = sharing
        .take_outbox()
        .into_iter()
        .filter(|addressed| addressed.record == record)
        .count();
    if sent == 0 {
        return Err("a rebuilt record that passed was not pushed down its stripe".into());
    }
    // The next rebuild: only the one let go for want of room is rebuilt again.
    let again: Vec<Hash> = sharing
        .tick_member_for_test(rebuild_at + 250)
        .into_iter()
        .map(|(rebuilt, _)| rebuilt.hash)
        .collect();
    if again != vec![no_room.0.hash] {
        return Err(format!(
            "rebuilt again {} records, not the one let go alone",
            again.len()
        ));
    }
    Ok(())
}

#[test]
fn repair_is_answered_only_to_members_of_the_trees() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let mut member = unlimited(identity(0));
    let members = keys(3);
    let _ = member.set_members(group, &members, &[], START_MS);
    let (hash, piece) = record(&identity(10_000), 1, START_MS)?;
    let second = START_MS / 1000;
    let _ = member.receive(members[1], Message::Piece { group, hash, piece }, START_MS);
    let _ = member.receive(
        members[1],
        Message::Manifest(manifest(&identity(1), group, second, &[hash])?),
        START_MS,
    );
    let have = tally_wire::HaveSummary {
        cell: group.cell,
        product: group.product,
        first_second: second - 3,
        seconds: vec![0; 2],
    };
    let stranger = identity(77).public();
    if !member
        .receive(stranger, Message::Have(have.clone()), START_MS + 3_000)
        .is_empty()
    {
        return Err("paged data to a relay outside the group".into());
    }
    if member
        .receive(members[2], Message::Have(have), START_MS + 3_000)
        .is_empty()
    {
        return Err("a member went unanswered".into());
    }
    Ok(())
}

#[test]
fn a_relay_that_only_asked_is_in_no_tree() -> Outcome {
    let hub = crate::hub::Hub::new(8, crate::sharing::Deadlines::RELAY);
    let cell = area()?;
    hub.network().selection.set_taken(vec![cell]);
    let sharing = &hub.network().sharing;
    let offered = identity(1);
    hold_offer(&hub, &offered, cell, 0b1111, START_MS)?;
    let asker = relay(identity(2).public());
    // An ask is held only in the store's room: this hub plans none for sharing.
    sharing.charge_to(Gauge::unlimited(Store::Batches));
    // An ask is booked only for an area the relay takes, as its tick reads the selection.
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&identity(0)))),
        0,
        START_MS,
    );
    sharing.assigned(
        &asker,
        tally_wire::StripeAssignment {
            cell,
            product: Streams::RAW,
            stripes_of: STRIPES,
            stripes: 1,
        },
        START_MS,
    );
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&identity(0)))),
        0,
        START_MS,
    );
    let layout = sharing.layout(cell, Streams::RAW).ok_or("no layout")?;
    if !layout.contains(&offered.public()) || layout.contains(&asker.key) {
        return Err("the tree is not the offers held".into());
    }
    // It still may send the group's records.
    if !sharing
        .groups
        .members(cell, Streams::RAW)
        .contains(&asker.key)
    {
        return Err("an asker may not send records".into());
    }
    Ok(())
}

/// Withdrawal paces itself on `M`: the judging clock stepping back an hour between two
/// withdrawals neither holds the second back for that hour nor lets it come before its pace.
#[test]
fn a_judging_clock_step_back_does_not_hold_the_next_withdrawal_for_an_hour() -> Outcome {
    use super::withdrawal::{WITHDRAW_EVERY_MS, Withdrawal, order};
    let me = identity(0).public();
    let regions: Vec<Region> = children(area()?.ancestor(2).ok_or("no parent")?);
    let ordered = order(&regions, &me);
    let at = |judged: u64, mono: u64| {
        super::Now::from(crate::ingest::Stamp::recorded(
            mono, 0, judged, judged, true,
        ))
    };
    let hour = 3_600_000;
    let mut withdrawal = Withdrawal::default();
    withdrawal.observe(1, &regions, &me, at(START_MS + hour, 1_000));
    withdrawal.observe(2, &regions, &me, at(START_MS + hour, 1_100));
    if withdrawal.withdrawn() != &ordered[..1] {
        return Err(format!("withdrew {:?}", withdrawal.withdrawn()));
    }
    // `J` steps back an hour; just short of the pace on `M`, nothing more.
    withdrawal.observe(
        3,
        &regions,
        &me,
        at(START_MS, 1_100 + WITHDRAW_EVERY_MS - 1),
    );
    if withdrawal.withdrawn().len() != 1 {
        return Err("withdrew again before its pace on M".into());
    }
    withdrawal.observe(
        4,
        &regions,
        &me,
        at(START_MS + 1, 1_100 + WITHDRAW_EVERY_MS),
    );
    if withdrawal.withdrawn() != &ordered[..2] {
        return Err("the step back of J held the next withdrawal".into());
    }
    Ok(())
}

#[test]
fn a_full_cap_withdraws_regions_one_at_a_time_in_a_fixed_order_and_takes_them_back() -> Outcome {
    use super::withdrawal::{RESTORE_AFTER_MS, WITHDRAW_EVERY_MS, Withdrawal, order};
    let me = identity(0).public();
    let area = area()?;
    let regions: Vec<Region> = children(area.ancestor(2).ok_or("no parent")?);
    let ordered = order(&regions, &me);
    let mut shuffled = regions.clone();
    shuffled.reverse();
    if order(&shuffled, &me) != ordered {
        return Err("the order depends on the input's".into());
    }
    let mut withdrawal = Withdrawal::default();
    let mut now = START_MS;
    withdrawal.observe(5, &regions, &me, super::Now::from(now));
    if !withdrawal.withdrawn().is_empty() {
        return Err("withdrew with nothing newly shed".into());
    }
    now += 100;
    withdrawal.observe(6, &regions, &me, super::Now::from(now));
    now += 100;
    withdrawal.observe(7, &regions, &me, super::Now::from(now));
    if withdrawal.withdrawn() != &ordered[..1] {
        return Err(format!("withdrew {:?}", withdrawal.withdrawn()));
    }
    now += WITHDRAW_EVERY_MS;
    withdrawal.observe(8, &regions, &me, super::Now::from(now));
    if withdrawal.withdrawn() != &ordered[..2] || !withdrawal.covers(ordered[1]) {
        return Err("the second region is not the order's next".into());
    }
    now += RESTORE_AFTER_MS;
    withdrawal.observe(8, &regions, &me, super::Now::from(now));
    if withdrawal.withdrawn() != &ordered[..1] {
        return Err("the last withdrawn was not taken back first".into());
    }
    // Through the seam: the relay is a leaf in the trees of what it withdrew from.
    let hub = crate::hub::Hub::new(8, crate::sharing::Deadlines::RELAY);
    hub.network().selection.set_taken(vec![area]);
    for index in 1..6 {
        hold_offer(&hub, &identity(index), area, 0b1111, START_MS)?;
    }
    let sharing = &hub.network().sharing;
    let mine = identity(0);
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&mine))),
        0,
        START_MS,
    );
    let homes = |sharing: &super::Sharing| {
        sharing
            .layout(area, Streams::RAW)
            .map(|layout| layout.homes(&mine.public()))
            .unwrap_or_default()
    };
    if homes(sharing).is_empty() {
        return Err("forwarded nothing before withdrawing".into());
    }
    let _ = sharing.tick_shed(
        &hub,
        Some(&crate::signer::synced(crate::signer::twin(&mine))),
        1,
        START_MS + 1_000,
    );
    if !sharing.withdrawn(area) || !homes(sharing).is_empty() {
        return Err("still forwarding in a withdrawn area".into());
    }
    Ok(())
}

/// A member charged to no budget: a test's, whose store has no bound.
fn unlimited(identity: Identity) -> Member {
    Member::new(
        crate::signer::synced(identity),
        Gauge::unlimited(Store::Batches),
        Deadlines::RELAY,
    )
}

/// The one batch byte store is held by its gauge alone (RFC-0181 §9): every record and parity a
/// member holds is charged before it is held and released as it is let go, so driven to its limit
/// the gauge reads exactly the bytes the groups hold, counted afresh from what they hold, and a
/// record past it is refused whole and counted, by the member and the gauge alike.
#[test]
fn a_member_holds_records_for_its_repair_horizon_shared_and_its_gauge_is_what_it_holds() -> Outcome
{
    use super::member::RECEIPT_WINDOW_SECONDS;
    // The horizon is sharing's own duties end to end, not a round minute.
    let relay = Deadlines::RELAY;
    let horizon_seconds = relay.horizon_seconds();
    if relay.horizon_ms()
        != RECEIPT_WINDOW_SECONDS * 1000
            + relay.receipt_grace.ms()
            + relay.judge_after.ms()
            + relay.repair_after.ms()
        || !(12..=15).contains(&horizon_seconds)
    {
        return Err(format!("a horizon of {horizon_seconds} s"));
    }
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(4);
    let receiver = identity(10_000);
    let (hash, piece) = record(&receiver, 1, START_MS)?;
    let len = piece.len();
    // The store's share: room for two such records a second over the horizon.
    let limit = 2 * len * horizon_seconds as usize;
    let gauge = Gauge::new(Store::Batches, limit);
    let mut member = Member::new(
        crate::signer::synced(identity(0)),
        std::sync::Arc::clone(&gauge),
        Deadlines::RELAY,
    );
    let _ = member.set_members(group, &members, &[], START_MS);
    let _ = member.originate(group, hash, piece.clone(), START_MS);
    // What it holds and hands on is the batch itself: its bytes are the batch's, not a copy.
    let delivered = member.take_delivered();
    let (Some(super::member::Piece::Batch(held)), super::member::Piece::Batch(original)) =
        (delivered.first().map(|delivered| &delivered.piece), &piece)
    else {
        return Err("a batch held as something else".into());
    };
    if held.as_bytes().as_ptr() != original.as_bytes().as_ptr() {
        return Err("a batch's bytes copied into the group".into());
    }
    // Charged what holding it allocates (`footprint`): its place in the group's tree of records,
    // the shared batch and its bytes, counted afresh the same.
    let first = member.held_bytes();
    if first != member.counted_bytes()
        || gauge.held() != member.charged_bytes()
        || first <= piece.held_len()
    {
        return Err(format!(
            "{first} bytes held of {len}, {} counted, the gauge charged {}",
            member.counted_bytes(),
            gauge.held()
        ));
    }
    // Driven to its limit: past it a record is refused whole, and counted.
    let mut taken = 1;
    for sequence in 2..(2 * horizon_seconds + 10) {
        let (hash, piece) = record(&receiver, sequence, START_MS)?;
        let _ = member.originate(group, hash, piece, START_MS);
        if member.holds(group, &hash) {
            taken += 1;
        }
    }
    if gauge.held() > limit || member.stats().refused == 0 || gauge.refused() == 0 {
        return Err(format!(
            "{} bytes charged of {limit}, {} refused, the gauge refused {}",
            gauge.held(),
            member.stats().refused,
            gauge.refused()
        ));
    }
    // Filled to within what one more record allocates at most (a node of the tree and its own).
    if limit - gauge.held() >= 2 * first {
        return Err(format!(
            "{} bytes charged of {limit}: room was left",
            gauge.held()
        ));
    }
    if taken < 2
        || gauge.held() != member.charged_bytes()
        || member.held_bytes() != member.counted_bytes()
        || member.group_bytes() != member.counted_bytes()
    {
        return Err(format!(
            "{taken} records of {len} bytes held, {} counted, {} charged",
            member.counted_bytes(),
            gauge.held()
        ));
    }
    // A tick a second on signs the manifest and builds the parity of what it originated: the
    // parity is held only if the gauge takes it, and the gauge is still what the groups hold.
    let _ = member.tick(START_MS + 1_000 + super::member::MANIFEST_DELAY_MS);
    if gauge.held() != member.charged_bytes()
        || member.held_bytes() != member.counted_bytes()
        || gauge.held() > limit
    {
        return Err(format!(
            "{} charged with the parity, {} counted",
            gauge.held(),
            member.counted_bytes()
        ));
    }
    // Within the horizon it is held; past it, let go, and its bytes released with it.
    let _ = member.tick(START_MS + horizon_seconds * 1000);
    if !member.holds(group, &hash) {
        return Err("let go within the horizon".into());
    }
    let _ = member.tick(START_MS + horizon_seconds * 1000 + 1_001);
    if member.holds(group, &hash) {
        return Err("held past the horizon".into());
    }
    // What its books remember of the trees' change (`Group::steady`) is let go two horizons on.
    let _ = member.tick(START_MS + 2 * horizon_seconds * 1000 + 1_001);
    if member.held_bytes() != 0
        || member.reckoning_bytes().0 != 0
        || gauge.held() != member.charged_bytes()
    {
        return Err(format!(
            "held past the horizon: {} bytes, {} charged",
            member.held_bytes(),
            gauge.held()
        ));
    }
    Ok(())
}

/// A member originating two records a second, ticked every 100 ms, through `seconds` of its
/// monotonic clock, its judging clock stepped by `step_ms` from second 30 on, into a store of
/// `limit` bytes: the most its gauge was charged, and how many records went unseeded.
fn originate_through_a_step(
    step_ms: i64,
    seconds: u64,
    limit: usize,
) -> Result<(usize, u64), String> {
    let group = GroupKey::new(area()?, Streams::RAW);
    let receiver = identity(10_000);
    let gauge = Gauge::new(Store::Batches, limit);
    let mut member = Member::new(
        crate::signer::synced(identity(0)),
        Arc::clone(&gauge),
        Deadlines::RELAY,
    );
    let _ = member.set_members(group, &keys(4), &[], START_MS);
    let (mut most, mut unseeded) = (0, 0);
    for tenth in 0..seconds * 10 {
        let mono_ms = START_MS + tenth * 100;
        let judge_ms = if tenth >= 300 {
            mono_ms.saturating_add_signed(step_ms)
        } else {
            mono_ms
        };
        let now = super::Now::from(crate::ingest::Stamp::recorded(
            mono_ms, 0, judge_ms, mono_ms, true,
        ));
        if tenth % 5 == 0 {
            let (hash, piece) = record(&receiver, tenth, judge_ms)?;
            let _ = member.originate(group, hash, piece, now);
            if !member.holds(group, &hash) {
                unseeded += 1;
            }
        }
        let _ = member.tick(now);
        most = most.max(gauge.held());
    }
    Ok((most, unseeded))
}

/// RFC-0171 §3.6: what a group holds is kept by the relay's monotonic clock (`member::Now`), so a
/// step of its judging clock moves no retention. A member taking two records a second into a
/// store with room for what it holds in step (a horizon's records and their parities, with one
/// second's slack) takes every one through a step of the judging clock a minute back and a minute
/// ahead, and holds within that room. Before, a group kept its records by the judging clock,
/// and its tick was due by it: a step back held every record a minute past its horizon and
/// stalled the tick that lets them go, the store filled, and the records after went unseeded.
#[test]
fn a_step_of_the_judging_clock_leaves_a_full_store_no_fuller() -> Outcome {
    let (in_step, unseeded) = originate_through_a_step(0, 120, usize::MAX)?;
    if unseeded != 0 {
        return Err(format!("{unseeded} unseeded with no bound"));
    }
    let (_, piece) = record(&identity(10_000), 0, START_MS)?;
    // The room the groups held in step, and the ledgers' floor of such a store beside it (no
    // ledger entry is made here: the member originates every record).
    let limit = in_step + 2 * piece.len() + super::member::reckoning_floor(2 * in_step);
    for step_ms in [-60_000, 60_000] {
        let (most, unseeded) = originate_through_a_step(step_ms, 120, limit)?;
        if unseeded != 0 || most > limit {
            return Err(format!(
                "a {step_ms} ms step: {unseeded} unseeded, {most} bytes held of {in_step} in step"
            ));
        }
    }
    Ok(())
}

/// RFC-0171 §3.6: a group's tick is due by the monotonic clock, so a step of the judging clock
/// never stalls the tick that lets its records go. A member that took records until its judging
/// clock stepped a minute back, and nothing after, holds none a horizon on by the monotonic clock.
/// Before, the tick was due by the judging clock, and a group with nothing new waited out the
/// step holding everything.
#[test]
fn a_step_back_stalls_no_tick_and_a_quiet_group_lets_go_on_time() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let receiver = identity(10_000);
    let gauge = Gauge::unlimited(Store::Batches);
    let mut member = Member::new(
        crate::signer::synced(identity(0)),
        Arc::clone(&gauge),
        Deadlines::RELAY,
    );
    let _ = member.set_members(group, &keys(4), &[], START_MS);
    for second in 0..30 {
        let now = START_MS + second * 1_000;
        let (hash, piece) = record(&receiver, second, now)?;
        let _ = member.originate(group, hash, piece, now);
        let _ = member.tick(now);
    }
    let stepped = START_MS + 30_000;
    let horizon_ms = Deadlines::RELAY.horizon_seconds() * 1000;
    let mut mono_ms = stepped;
    while mono_ms <= stepped + horizon_ms + 1_000 {
        let _ = member.tick(super::Now::from(crate::ingest::Stamp::recorded(
            mono_ms,
            0,
            mono_ms - 60_000,
            mono_ms,
            true,
        )));
        mono_ms += 100;
    }
    if member.held_bytes() != 0 || gauge.held() != 0 {
        return Err(format!(
            "{} bytes held a horizon after the step",
            member.held_bytes()
        ));
    }
    Ok(())
}

/// Every resolution-0 cell: the whole world, as the public relay takes it.
fn world() -> Result<Vec<Region>, String> {
    (0..122u64)
        .map(|base| Region::from_u64(0x0800_0000_0000_0000 | (base << 45) | ((1 << 45) - 1)))
        .collect::<Result<_, _>>()
        .map_err(text)
}

/// The class of defect behind the public relay that burned its whole CPU limit with no feeder at
/// all: every 100 ms tick laid out the trees of every area it takes (41,162 areas under the
/// world's 122 cells, five groups each) and visited every one. Idle work follows activity, never
/// the areas taken: with the world taken and nothing flowing, a minute of ticks (its own offers
/// re-signed on the way) lays out no tree, visits no group and holds none; the MLAT choice is
/// computed once; and one other relay's offer for one area costs that area's groups and nothing
/// more. Counted by sharing's own work (`Sharing::work`), not by the clock.
#[test]
fn a_tick_with_the_world_taken_and_nothing_flowing_does_no_work() -> Outcome {
    let me = identity(0);
    let hub = crate::hub::Hub::new(8, crate::sharing::Deadlines::RELAY).advertising(vec![
        tally_wire::RelayAddress {
            key: me.public(),
            address: "198.51.100.7:7450".to_owned(),
        },
    ]);
    let network = hub.network();
    network.adopt_identity(crate::signer::twin(&me));
    let world = world()?;
    if world.iter().any(|cell| cell.resolution() != 0)
        || tally_wire::rendezvous::areas_of(world[0])
            .map_err(text)?
            .len()
            < 300
    {
        return Err("not the world's resolution-0 cells".into());
    }
    network.selection.set_taken(world.clone());
    let sharing = &network.sharing;
    let mut now = START_MS;
    let _ = network.tick(&hub, now);
    let (generation, _) = network.selection.solved(&network.directory, judged(now));
    for _ in 0..600 {
        now += 100;
        let _ = network.tick(&hub, now);
    }
    let work = sharing.work();
    if work != super::Work::default() {
        return Err(format!("a minute of idle ticks did work: {work:?}"));
    }
    if network.selection.solved(&network.directory, judged(now)).0 != generation {
        return Err("the MLAT choice was computed again with nothing changed".into());
    }
    // Every place taken is offered, under the relay's own key: the 122 cells, none cut. A cap
    // on the count once cut the public relay's offers to its first 64 cells, half the world.
    let offered = network.directory.cells_of(&me.public(), judged(now));
    if tally_wire::Regions::new(offered.iter().copied()) != tally_wire::Regions::world()
        || offered.len() != world.len()
    {
        return Err(format!("the world taken, {} cells offered", offered.len()));
    }
    // Every area taken still has its trees, this relay alone, computed when asked.
    let area = area()?;
    let layout = sharing.layout(area, Streams::RAW).ok_or("no trees")?;
    if layout.members() != vec![me.public()] {
        return Err("the trees of an idle area are not this relay alone".into());
    }
    // One other relay offers one area: that area's groups are laid out and held, and no other.
    hold_offer(&hub, &identity(1), area, 0b1111, now)?;
    now += 100;
    let _ = network.tick(&hub, now);
    let products = super::SHARED_PRODUCTS.len();
    let work = sharing.work();
    if work.laid_out != products as u64 || work.held_groups != products {
        return Err(format!("one area offered cost {work:?}"));
    }
    if !sharing
        .layout(area, Streams::RAW)
        .is_some_and(|layout| layout.contains(&identity(1).public()))
    {
        return Err("the other relay is not in the area's trees".into());
    }
    // Ticks with nothing due visit nothing, the held groups included.
    let visited = work.visited;
    for _ in 0..5 {
        now += 100;
        let _ = network.tick(&hub, now);
    }
    if sharing.work().visited != visited || sharing.work().laid_out != work.laid_out {
        return Err(format!("idle ticks did work: {:?}", sharing.work()));
    }
    Ok(())
}

/// RFC-0174 §2.5, a relay's members are bounded: a member that turned this relay's link away as
/// full is routed around, never addressed. A record whose stripe it seeds goes instead to the
/// members beneath it in that stripe's tree (its children, and in place of one full too, that
/// one's), so the rest of the tree still receives it from this relay; a manifest goes to those
/// beneath it in every stripe; and once it is no longer full it is the seed again, the trees
/// unchanged throughout.
#[test]
fn a_full_member_is_routed_around_to_the_members_beneath_it() -> Outcome {
    use super::seeds::epoch_of;
    use super::stripes::{DATA_STRIPES, data_stripe};
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(12);
    let me = members[0];
    let mut member = unlimited(identity(0));
    let _ = member.set_members(group, &members, &[], START_MS);
    let layout = member.layout(group).ok_or("no trees")?.clone();
    let epoch = epoch_of(START_MS / 1000);
    // A data stripe whose seed is another member with children of its own.
    let (stripe, seed) = (0..DATA_STRIPES)
        .filter_map(|stripe| Some((stripe, layout.seed(stripe, epoch)?)))
        .find(|(stripe, seed)| {
            *seed != me
                && layout
                    .place(*stripe, epoch, seed)
                    .is_some_and(|place| place.children.iter().any(|child| *child != me))
        })
        .ok_or("no seed with children")?;
    let children: BTreeSet<PublicKey> = layout
        .place(stripe, epoch, &seed)
        .ok_or("the seed has no place")?
        .children
        .into_iter()
        .filter(|child| *child != me)
        .collect();
    let receiver = identity(10_000);
    let in_stripe = |from: u64| -> Result<(Hash, Piece), String> {
        (from..from + 1_000)
            .map(|sequence| record(&receiver, sequence, START_MS))
            .find(|made| {
                made.as_ref()
                    .is_ok_and(|(hash, _)| data_stripe(hash) == stripe)
            })
            .ok_or("no record in the stripe")?
    };
    let sent_to = |out: &[Outgoing]| -> BTreeSet<PublicKey> { out.iter().map(|o| o.to).collect() };

    // Not full: the record goes to its stripe's seed.
    let (hash, piece) = in_stripe(1)?;
    let out = member.originate(group, hash, piece, START_MS);
    if !sent_to(&out).contains(&seed) {
        return Err("the seed was not sent its stripe".into());
    }

    // Full: never addressed; its children are sent the record in its place.
    member.set_full(BTreeSet::from([seed]));
    let (hash, piece) = in_stripe(1_000)?;
    let out = member.originate(group, hash, piece, START_MS);
    let to = sent_to(&out);
    if to.contains(&seed) || !children.is_subset(&to) {
        return Err(format!(
            "a full seed's record went to {} members, {} of its {} children, the seed {}",
            to.len(),
            children.intersection(&to).count(),
            children.len(),
            if to.contains(&seed) {
                "among them"
            } else {
                "not"
            }
        ));
    }
    // A child full too is passed over for its own children.
    let child = *children.iter().next().ok_or("no child")?;
    let grandchildren: BTreeSet<PublicKey> = layout
        .place(stripe, epoch, &child)
        .map(|place| {
            place
                .children
                .into_iter()
                .filter(|key| *key != me)
                .collect()
        })
        .unwrap_or_default();
    member.set_full(BTreeSet::from([seed, child]));
    let (hash, piece) = in_stripe(2_000)?;
    let to = sent_to(&member.originate(group, hash, piece, START_MS));
    if to.contains(&seed) || to.contains(&child) || !grandchildren.is_subset(&to) {
        return Err("a full child's place was not taken by its children".into());
    }
    // A manifest is never addressed to it either; its trees are what every relay lays out.
    let out = member.tick(START_MS + 2_000);
    if out
        .iter()
        .any(|outgoing| outgoing.to == seed || outgoing.to == child)
    {
        return Err("a full member was addressed by the tick".into());
    }
    if member.layout(group) != Some(&layout) {
        return Err("routing around a full member changed the trees".into());
    }
    // No longer full: the seed is sent its stripe again.
    member.set_full(BTreeSet::new());
    let (hash, piece) = in_stripe(3_000)?;
    if !sent_to(&member.originate(group, hash, piece, START_MS + 2_000)).contains(&seed) {
        return Err("the seed was not sent its stripe once it had room".into());
    }
    Ok(())
}

/// RFC-0174 §2.5: a member asks for repair only those that can answer it. Never one it routes
/// around as full (an ask to it goes nowhere), nor one it turned away as full while that one routes
/// around it (it sends nothing to a member full to it, its answer included): every ask goes to a
/// member that answers. Once the wait is over and the full one has room, both are asked again.
/// Before, the ask rotated over every member, and a full member that had one link admitted
/// repaired at the pace its asks happened to reach that one.
#[test]
fn repair_is_asked_only_of_members_that_can_answer() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(4);
    let (refused, full, open) = (members[1], members[2], members[3]);
    let mut member = unlimited(identity(0));
    let _ = member.set_members(group, &members, &[], START_MS);
    member.turned_away(refused, std::time::Duration::from_secs(60), START_MS);
    member.set_full(BTreeSet::from([full]));
    let asked = |member: &mut Member, from_ms: u64, to_ms: u64| -> BTreeMap<PublicKey, usize> {
        let mut asked = BTreeMap::new();
        let mut now = from_ms;
        while now < to_ms {
            for outgoing in member.tick(now) {
                if matches!(outgoing.message, Message::Have(_)) {
                    *asked.entry(outgoing.to).or_insert(0) += 1;
                }
            }
            now += TICK_MS;
        }
        asked
    };
    // While the one it turned away routes around it (its wait, then the slack its `Goodbye` took
    // to reach it) and the other is full: only the open one.
    let slack = Deadlines::RELAY.route_slack.ms();
    let during = asked(&mut member, START_MS, START_MS + 60_000 + slack);
    if during.keys().ne([&open]) {
        return Err(format!(
            "asked {} of the one it turned away, {} of the full one, {} of the open one",
            during.get(&refused).unwrap_or(&0),
            during.get(&full).unwrap_or(&0),
            during.get(&open).unwrap_or(&0)
        ));
    }
    // The wait over, and the full one with room: every member is asked in turn again.
    member.set_full(BTreeSet::new());
    let after = asked(&mut member, START_MS + 60_000 + slack, START_MS + 241_000);
    let every: BTreeSet<&PublicKey> = [&refused, &full, &open].into_iter().collect();
    if after.keys().ne(every) {
        return Err(format!("after the wait, asked {after:?}"));
    }
    Ok(())
}

/// RFC-0174 §2.5 and §2.6: a member full to its parent is routed around, and that is no fault on
/// either side of it. X turns its parent P away as full; P sends what X would have had straight to
/// X's children, for the wait the one rule gives both (`full::Wait`). Over several receipt windows
/// and their judgment nobody files a shortfall: X, against P, which it turned away; X's children,
/// against X, whose records came from above it before any repair could have. Nobody is demoted,
/// the trees never change, every member but X holds every record, and P holds the receipts of
/// X's children for what it delivered to them past X.
#[test]
fn routing_around_a_full_member_files_no_shortfall_and_demotes_nobody() -> Outcome {
    let mut sim = Sim::new(16, 20)?;
    let origins = [0, 1, 2, 3];
    let layout = sim.layout();
    let epoch = epoch_of(sim.now / 1000);
    // A member X with children in a data stripe, under a parent P: the one P has the fewest other
    // children beside, so X's word alone would weigh most in P's judgment.
    let (stripe, x, p, children) = (0..DATA_STRIPES)
        .flat_map(|stripe| (0..sim.keys.len()).map(move |x| (stripe, x)))
        .filter(|(_, x)| !origins.contains(x))
        .filter_map(|(stripe, x)| {
            let place = layout.place(stripe, epoch, &sim.keys[x])?;
            let parent = place.parent?;
            let p = *sim.index.get(&parent)?;
            let siblings = layout.place(stripe, epoch, &parent)?.children.len();
            (!place.children.is_empty()).then_some((siblings, stripe, x, p, place.children))
        })
        .min_by_key(|(siblings, ..)| *siblings)
        .map(|(_, stripe, x, p, children)| (stripe, x, p, children))
        .ok_or("no member with children under a parent")?;
    let (x_key, p_key) = (sim.keys[x], sim.keys[p]);
    // X turned P's link away as full: P routes around X, and X keeps the same wait for P.
    sim.members[p].set_full(BTreeSet::from([x_key]));
    sim.members[x].turned_away(p_key, std::time::Duration::from_secs(60), sim.now);
    sim.feed(&origins, 3, 15)?;
    let end = sim.now + 12_000;
    sim.run_until(end);

    let receipts: u64 = sim.members.iter().map(|m| m.stats().receipts).sum();
    if receipts == 0 {
        return Err("no receipt was signed".into());
    }
    // "nobody is demoted" is a verdict only from a judge that sat: every member
    // weighed a window whose shortfalls could have demoted.
    let unjudged: Vec<usize> = sim
        .live()
        .into_iter()
        .filter(|i| sim.members[*i].stats().judged == 0)
        .collect();
    if !unjudged.is_empty() {
        return Err(format!("members that judged no window: {unjudged:?}"));
    }
    let shortfalls: Vec<(usize, u64)> = sim
        .members
        .iter()
        .enumerate()
        .map(|(i, m)| (i, m.stats().shortfalls))
        .filter(|(_, count)| *count > 0)
        .collect();
    if !shortfalls.is_empty() {
        return Err(format!(
            "shortfalls filed after a route-around (X {x}, P {p}): {shortfalls:?}"
        ));
    }
    for i in sim.live() {
        for other in sim.live() {
            if sim.members[i].is_demoted(sim.group, &sim.keys[other]) {
                return Err(format!("member {i} demoted {other} after a route-around"));
            }
        }
        if sim.members[i].layout(sim.group) != Some(&layout) {
            return Err(format!("member {i}'s trees changed after a route-around"));
        }
    }
    sim.everyone_holds_everything(&[x].into())?;
    // P's delivery past X is evidenced: each of X's children signed it a receipt in X's stripe.
    for child in &children {
        let signed = sim.receipts.iter().any(|(from, to, receipt)| {
            sim.keys[*from] == *child
                && *to == p
                && receipt
                    .content()
                    .is_ok_and(|content| content.parent == p_key && content.stripe == stripe)
        });
        if !signed {
            return Err("a child fed past its full parent signed its deliverer no receipt".into());
        }
    }
    Ok(())
}

/// The relays a member holds as turned away are bounded (`member::TURNED_AWAY_HELD`): one more
/// lets go the one whose last span ended first; and what they allocate, as an allocator counting
/// each byte sees it, is within what they are charged to the store. With no room in the store, a
/// refusal is not noted, counted. Before, every key ever turned away within the forgetting was
/// held, and charged nowhere.
#[test]
fn the_relays_turned_away_are_bounded_and_charged() -> Outcome {
    use super::member::TURNED_AWAY_HELD;
    use tally_counting::Counting;
    let keys: Vec<PublicKey> = (1..=TURNED_AWAY_HELD + 10)
        .map(|index| identity(index).public())
        .collect();
    let asked = std::time::Duration::from_secs(60);
    let mut member = unlimited(identity(0));
    let base = Counting::live();
    for (at, key) in keys.iter().enumerate() {
        member.turned_away(*key, asked, START_MS + at as u64);
    }
    let (held, charged) = member.turned_away_held();
    let allocated = Counting::since(base);
    if held != TURNED_AWAY_HELD {
        return Err(format!("{held} relays held as turned away"));
    }
    if allocated > charged as isize {
        return Err(format!("{allocated} allocated, {charged} charged"));
    }
    // The first turned away went first; the last is held.
    if member.turned_away_spans(&keys[0]) != 0
        || member.turned_away_spans(&keys[keys.len() - 1]) != 1
    {
        return Err("the oldest was not the one let go".into());
    }
    // No room at all (a store already full: an empty one admits its first charge whatever its
    // limit): nothing noted, counted.
    let gauge = Gauge::new(Store::Batches, 1);
    let _filled = gauge
        .try_charge(1)
        .ok_or("an empty store refused its first byte")?;
    let mut full = Member::new(crate::signer::synced(identity(0)), gauge, Deadlines::RELAY);
    full.turned_away(keys[0], asked, START_MS);
    if full.turned_away_held() != (0, 0) || full.stats().turned_away_unheld != 1 {
        return Err("a refusal past the store's room was held".into());
    }
    Ok(())
}

/// A relay turned away again and again while it waits holds one span of routing
/// around this one, not one a refusal, and a receipt check still finds exactly the moments the
/// spans cover: inside the wait, within its slack after, and nothing past it.
#[test]
fn refusals_while_a_relay_waits_are_one_span_and_found_by_search() -> Outcome {
    let mut member = unlimited(identity(0));
    let turned = identity(1).public();
    let asked = std::time::Duration::from_secs(60);
    // A refusal every 10 ms through the first wait: each lands inside the span the last gave.
    for step in 0..6_000u64 {
        member.turned_away(turned, asked, START_MS + step * 10);
    }
    let spans = member.turned_away_spans(&turned);
    if spans != 1 {
        return Err(format!("6,000 refusals inside one wait held {spans} spans"));
    }
    if !member.routed_around_by(&turned, START_MS + 30_000, START_MS + 31_000)
        || !member.routed_around_by(&turned, START_MS - 5_000, START_MS)
    {
        return Err("a window inside the wait was not found".into());
    }
    // Long after every wait is over and remembered, a refusal starts a span of its own, and the
    // gap between them is no span's.
    let later = START_MS + 3_600_000;
    member.turned_away(turned, asked, later);
    let spans = member.turned_away_spans(&turned);
    if spans != 2 {
        return Err(format!("a refusal past the wait made {spans} spans, not 2"));
    }
    if member.routed_around_by(&turned, later - 600_000, later - 590_000) {
        return Err("the gap between two waits was taken for routing around".into());
    }
    if !member.routed_around_by(&turned, later + 1_000, later + 2_000) {
        return Err("the second wait was not found".into());
    }
    Ok(())
}

/// A repair page is never handed back down the link the summary came in on (the
/// seam's `have` returns nothing), so no page waits uncharged in a link's replies. It waits in
/// the outbox addressed to the asker, each record charged to the batch store from when it is
/// queued until whoever carries it lets it go (`peers` holds the charge until the link writes it).
#[test]
fn a_repair_page_waits_charged_in_the_outbox_addressed_to_the_asker() -> Outcome {
    let cell = area()?;
    let group = GroupKey::new(cell, Streams::RAW);
    let (origin, asker) = (identity(1), identity(3));
    let (_hub, sharing, gauge) = serving_with_members(cell, &[&origin, &asker], usize::MAX)?;
    let now = START_MS + 300;
    let second = START_MS / 1000;
    let (hash, piece) = record(&identity(10_000), 1, START_MS)?;
    let batch = piece.record().ok_or("no record")?;
    sharing.manifest(
        &relay(origin.public()),
        manifest(&origin, group, second, &[hash])?,
        now,
    );
    sharing.received(&origin.public(), &batch, cell, Streams::RAW, now);
    // What the member sent the group so far is taken, as the links would.
    drop(sharing.take_outbox());
    let before = gauge.held();
    let member_before = sharing
        .member_for_test(|member| member.charged_bytes())
        .ok_or("no member")?;
    let have = tally_wire::HaveSummary {
        cell,
        product: Streams::RAW,
        first_second: second,
        seconds: vec![0],
    };
    sharing.have(&relay(asker.public()), have, now + 2_000);
    let page = sharing.take_outbox();
    let to_asker: Vec<&super::Addressed> = page
        .iter()
        .filter(|sent| sent.to == asker.public())
        .collect();
    if !to_asker
        .iter()
        .any(|sent| matches!(sent.record, Record::Batch(_)))
    {
        return Err(format!("the asker was sent no page: {} sends", page.len()));
    }
    // Each send is charged what its record allocates (its slot was the outbox's, let go as the
    // page was taken).
    for sent in &page {
        if sent.charge.bytes() != sent.record.allocated() {
            return Err(format!(
                "a send allocating {} bytes waits charged {}",
                sent.record.allocated(),
                sent.charge.bytes()
            ));
        }
    }
    let charged: usize = page.iter().map(|sent| sent.charge.bytes()).sum();
    // Answering notes when the asker was answered, in the group's books, charged with them.
    let booked = sharing
        .member_for_test(|member| member.charged_bytes())
        .ok_or("no member")?
        - member_before;
    let before = before + booked;
    if gauge.held() != before + charged {
        return Err(format!(
            "the store holds {} with the page waiting, {before} before and {charged} for it",
            gauge.held()
        ));
    }
    drop(page);
    if gauge.held() != before {
        return Err("the page's charge outlived it".into());
    }
    Ok(())
}

/// One pass of the timed duties (`network::pass`) gives every record its group rebuilt a verdict:
/// the tick's rebuilt records are each taken in (`Hub::take_rebuilt`), so a true batch is held
/// in its group as the relay admitted it, its place charged and not its bytes again (the admitted
/// batch's bytes carry their own charge, `Batch::owned_by`), and a forged one is refused, counted.
/// A pass that let the tick's rebuilt records go would leave each held apart, unjudged, until the
/// horizon.
#[test]
fn a_duties_pass_gives_every_record_its_group_rebuilt_a_verdict() -> Outcome {
    use crate::hub::Hub;
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(4);
    let hub = Arc::new(Hub::new(8, Deadlines::RELAY).taking(vec![group.cell]));
    hub.network().adopt_identity(identity(0));
    let now = crate::clock::RelayClock::system().judged().ms();
    let _ = hub.network().tick(&hub, now);
    // A second whose rebuild wait is past by the pass's own clock.
    let second = now / 1000 - 2;
    let receiver = identity(10_000);
    // Batches with receptions, so a batch's bytes are more than its shared batch (`Piece::held_len`).
    let mut records: Vec<Record> = Vec::new();
    for sequence in 0..24u8 {
        let observations = (0..4u8)
            .map(|n| tally_wire::Observation {
                format: b'3',
                timestamp: u64::from(sequence) * 10 + u64::from(n),
                signal: 0,
                data: vec![n; 14],
            })
            .collect();
        let batch = crate::anchors::anchored(
            &receiver,
            &BatchContent {
                boot_id: 1,
                sequence: u64::from(sequence),
                counter_epoch: 0,
                wall_ms: second * 1000,
                dropped: 0,
                previous: [0; 32],
                observations,
            },
        )
        .map_err(text)?;
        records.push(Record::Batch(batch));
    }
    // The first, whose stripe is lost, is forged.
    if let Some(Record::Batch(batch)) = records.first_mut() {
        let mut bytes = batch.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        *batch = Batch::from_bytes(bytes).map_err(text)?;
    }
    let sharing = &hub.network().sharing;
    let lost = sharing.fill_for_rebuild(
        group,
        &members,
        (&identity(1), members[2]),
        &records,
        second,
        now,
    )?;
    let in_lost: Vec<Hash> = records
        .iter()
        .filter_map(|record| Piece::of(record).and_then(|piece| piece.hash()))
        .filter(|hash| data_stripe(hash) == lost)
        .collect();
    if in_lost.len() < 2 {
        return Err(format!("{} records in the stripe lost", in_lost.len()));
    }
    crate::network::pass(&hub, &mut None);
    hub.flush();
    let state = |hash: &Hash| {
        sharing
            .member_for_test(|member| {
                (
                    member.judging(group, hash),
                    member.has_refused(group, hash),
                    member.held_len_of(group, hash),
                )
            })
            .unwrap_or((false, false, None))
    };
    if hub.network().sharing.stats().0.rebuilt != in_lost.len() as u64 {
        return Err("the pass rebuilt nothing".into());
    }
    let (forged, true_ones) = (in_lost[0], &in_lost[1..]);
    if state(&forged) != (false, true, None) {
        return Err(format!("the forged rebuilt batch: {:?}", state(&forged)));
    }
    for hash in true_ones {
        if state(hash) != (false, false, Some(crate::footprint::arc::<Batch>())) {
            return Err(format!(
                "a true rebuilt batch was not held as admitted: {:?}",
                state(hash)
            ));
        }
    }
    if hub.memory_report().rebuilt_refused != 1 {
        return Err("the forged rebuilt batch was not counted refused".into());
    }
    // What the member is charged is what its groups hold, counted afresh: each rebuilt copy's
    // whole charge let go as it was judged, none of it left behind.
    let (charged, counted, kept) = sharing
        .member_for_test(|member| {
            (
                member.held_bytes(),
                member.counted_bytes(),
                member.group_bytes(),
            )
        })
        .ok_or("no member")?;
    if charged != counted || kept != counted {
        return Err(format!(
            "charged {charged} bytes, the groups count {kept}, and hold {counted}"
        ));
    }
    Ok(())
}

/// RFC-0181 "Memory is charged once": a member's groups are charged what they allocate
/// (`footprint`), their trees of records, credits and parities and each entry's own (its piece,
/// its parity, its list of senders as it grows), through records originated and received, copies
/// from many members, credits for want of room, parities and the horizon passing: after every
/// step the charge is what is counted afresh from the groups. Before, a record credited was charged
/// a third of what its entry allocated and each sender after the first nothing at all.
#[test]
fn a_members_charge_is_what_its_groups_allocate_as_they_churn() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(12);
    let gauge = Gauge::new(Store::Batches, usize::MAX);
    let mut member = Member::new(
        crate::signer::synced(identity(0)),
        std::sync::Arc::clone(&gauge),
        Deadlines::RELAY,
    );
    let _ = member.set_members(group, &members, &[], START_MS);
    let receiver = identity(10_000);
    let same = |member: &Member, step: &str| -> Outcome {
        if member.held_bytes() != member.counted_bytes()
            || gauge.held() != member.charged_bytes()
            || member.reckoning_bytes().0 != member.counted_reckoning_bytes()
            || member.group_bytes() != member.held_bytes()
        {
            return Err(format!(
                "{step}: {} charged, {} counted, {} by the groups, the gauge {}",
                member.held_bytes(),
                member.counted_bytes(),
                member.group_bytes(),
                gauge.held()
            ));
        }
        Ok(())
    };
    let mut sequence = 0;
    for second in 0..40u64 {
        let now = START_MS + second * 1_000;
        for _ in 0..30 {
            sequence += 1;
            let (hash, piece) = record(&receiver, sequence, now)?;
            match sequence % 4 {
                // Originated here.
                0 => {
                    let _ = member.originate(group, hash, piece, now);
                }
                // Received, then copies of it from up to eleven more members.
                1 | 2 => {
                    let copies = 1 + (sequence % 11) as usize;
                    for from in &members[1..=copies] {
                        let _ = member.receive(
                            *from,
                            Message::Piece {
                                group,
                                hash,
                                piece: piece.clone(),
                            },
                            now,
                        );
                    }
                }
                // Credited for want of room by many members, then some of them received.
                _ => {
                    for from in &members[1..12] {
                        member.credit(*from, group, (hash, 100), now);
                    }
                    if sequence % 8 == 3 {
                        let _ = member.receive(
                            members[5],
                            Message::Piece {
                                group,
                                hash,
                                piece: piece.clone(),
                            },
                            now,
                        );
                    }
                }
            }
            same(&member, &format!("record {sequence}"))?;
        }
        // Manifests signed and parities built, and the horizon passing.
        let _ = member.tick(now + super::member::MANIFEST_DELAY_MS);
        same(&member, &format!("second {second}"))?;
    }
    let held = member.held_bytes();
    let _ = member.tick(START_MS + 40_000 + Deadlines::RELAY.horizon_ms() + 2_000);
    same(&member, "past the horizon")?;
    if held == 0 || member.held_bytes() >= held {
        return Err(format!("{held} held, then {}", member.held_bytes()));
    }
    Ok(())
}

/// RFC-0181 §7: a record a member has no room to hold is still credited to the member that sent
/// it, as a link refused for want of room credits it, so its receipts never report its parent
/// short. Before, the record's growth refused, its sender was never noted.
#[test]
fn a_record_refused_for_room_is_credited_to_its_sender() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(4);
    let gauge = Gauge::new(Store::Batches, 1 << 20);
    let mut member = Member::new(
        crate::signer::synced(identity(0)),
        std::sync::Arc::clone(&gauge),
        Deadlines::RELAY,
    );
    let _ = member.set_members(group, &members, &[], START_MS);
    let receiver = identity(10_000);
    // One record credited first, so the credits' tree has a place for the next.
    let (first, _) = record(&receiver, 1, START_MS)?;
    member.credit(members[2], group, (first, 100), START_MS);
    let (hash, piece) = record(&receiver, 2, START_MS)?;
    // Room for less than the record itself.
    let fill = gauge.limit() - gauge.held() - piece.held_len();
    let filled = gauge.try_charge(fill).ok_or("no room to fill")?;
    let _ = member.receive(members[1], Message::Piece { group, hash, piece }, START_MS);
    if member.held_len_of(group, &hash).is_some() {
        return Err("held with no room".into());
    }
    if !member.delivered(group, &hash, &members[1]) {
        return Err("its sender was not credited".into());
    }
    drop(filled);
    Ok(())
}

/// RFC-0181 §7: a parity a member has no room to hold is credited to the member that sent it,
/// as a record refused for room is, so its receipts never report that member short of it.
/// Before, the parity's growth refused, its sender was never noted.
#[test]
fn a_parity_refused_for_room_is_credited_to_its_sender() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(4);
    let gauge = Gauge::new(Store::Batches, 1 << 20);
    let mut member = Member::new(
        crate::signer::synced(identity(0)),
        std::sync::Arc::clone(&gauge),
        Deadlines::RELAY,
    );
    let _ = member.set_members(group, &members, &[], START_MS);
    let (origin, receiver) = (identity(1), identity(10_000));
    let mut pieces = Vec::new();
    for sequence in 0..24 {
        pieces.push(record(&receiver, sequence, START_MS)?);
    }
    let second = START_MS / 1000;
    let hashes: Vec<Hash> = pieces.iter().map(|(hash, _)| *hash).collect();
    let signed = manifest(&origin, group, second, &hashes)?;
    let _ = member.receive(members[1], Message::Manifest(signed.clone()), START_MS);
    let views: Vec<(Hash, &Piece)> = pieces.iter().map(|(h, b)| (*h, b)).collect();
    let parity = Parity::build(signed.hash(), group.cell, group.product, second, &views);
    let id = parity.id();
    // One record credited first, so the credits' tree has a place for the next.
    member.credit(members[3], group, (hashes[0], 100), START_MS);
    // Room for less than the parity's own bytes.
    let fill = gauge.limit() - gauge.held() - parity.xor.len();
    let filled = gauge.try_charge(fill).ok_or("no room to fill")?;
    let _ = member.receive(members[2], Message::Parity(Arc::new(parity)), START_MS);
    if !member.delivered(group, &id, &members[2]) {
        return Err("its sender was not credited".into());
    }
    drop(filled);
    Ok(())
}

/// RFC-0181 §10: a group's plan covers each record as it is really held, by its parent and the
/// one more member a repair or a late copy brings it from, and each record credited for want of
/// room by as many: what the groups allocate beside the records' signed bytes is within
/// `PIECE_ENTRY_BYTES` a record. Before, a record was planned with one sender and a credit not at
/// all.
#[test]
fn a_groups_plan_covers_its_records_held_or_credited_by_their_planned_senders() -> Outcome {
    use super::member::{GROUP_TREES_BYTES, PIECE_ENTRY_BYTES, PLANNED_SENDERS};
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(1 + PLANNED_SENDERS);
    let receiver = identity(10_000);
    for credited in [false, true] {
        let gauge = Gauge::new(Store::Batches, usize::MAX);
        let mut member = Member::new(
            crate::signer::synced(identity(0)),
            std::sync::Arc::clone(&gauge),
            Deadlines::RELAY,
        );
        let _ = member.set_members(group, &members, &[], START_MS);
        let count = 500;
        let mut signed = 0;
        for sequence in 0..count {
            let (hash, piece) = record(&receiver, sequence, START_MS)?;
            for from in &members[1..] {
                if credited {
                    member.credit(*from, group, (hash, 100), START_MS);
                } else {
                    let _ = member.receive(
                        *from,
                        Message::Piece {
                            group,
                            hash,
                            piece: piece.clone(),
                        },
                        START_MS,
                    );
                }
            }
            if let Some(held) = member.held_len_of(group, &hash) {
                signed += held - crate::footprint::arc::<tally_wire::Batch>();
            }
        }
        let entries = member.group_bytes() - signed;
        let planned = count as usize * PIECE_ENTRY_BYTES + GROUP_TREES_BYTES;
        if entries > planned {
            return Err(format!(
                "credited {credited}: {entries} allocated beside the signed bytes, {planned} planned"
            ));
        }
    }
    Ok(())
}

/// A small generator for the churn tests, allocating nothing.
fn mixed(state: &mut u64, below: u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (*state >> 33) % below.max(1)
}

/// A send for a member no address is held for, while the clock does not judge, is queued again
/// for at most the group's horizon on `M` from when it first was (`Deadlines::horizon_ms`), counted
/// once however often it is, and let go past it, counted. Before, it was queued again for as long
/// as the clock did not judge, and counted at every carry.
#[test]
fn a_send_with_no_address_waits_a_horizon_at_most() -> Outcome {
    use tally_wire::StripeAssignment;
    let to = identity(1).public();
    let gauge = Gauge::unlimited(Store::Batches);
    let sharing = super::Sharing::new(Deadlines::RELAY);
    sharing.charge_to(Arc::clone(&gauge));
    let record = Record::StripeAssignment(StripeAssignment {
        cell: area()?,
        product: Streams::RAW,
        stripes_of: 4,
        stripes: 0b1010,
    });
    // Unsynced: the judging clock an hour ahead of `M`, not judging.
    let unjudged = |mono_ms: u64| {
        super::Now::from(crate::ingest::Stamp::recorded(
            mono_ms,
            0,
            mono_ms + 3_600_000,
            mono_ms,
            false,
        ))
    };
    if !sharing.address(to, record) {
        return Err("not queued".into());
    }
    let horizon = Deadlines::RELAY.horizon_ms();
    // Carried every tick up to the horizon: waiting still, counted once.
    let mut at = START_MS;
    while at < START_MS + horizon {
        let sent = sharing.take_outbox();
        if sent.len() != 1 {
            return Err(format!("{} sends waiting at {at}", sent.len()));
        }
        sharing.unaddressed(sent, unjudged(at));
        at += TICK_MS;
    }
    if sharing.unaddressed_counts() != (1, 0) {
        return Err(format!(
            "(queued again, let go) {:?} within the horizon",
            sharing.unaddressed_counts()
        ));
    }
    // Past it: let go, counted, and its charge given back.
    let sent = sharing.take_outbox();
    sharing.unaddressed(sent, unjudged(START_MS + horizon));
    if !sharing.take_outbox().is_empty() {
        return Err("a send waited past the horizon".into());
    }
    if sharing.unaddressed_counts() != (1, 1) {
        return Err(format!(
            "(queued again, let go) {:?} past the horizon",
            sharing.unaddressed_counts()
        ));
    }
    if gauge.held() != 0 {
        return Err(format!("{} bytes held after it went", gauge.held()));
    }
    Ok(())
}

/// RFC-0181 "Memory is charged once": the outbox is charged what it allocates, each send's
/// record what it allocates (`Record::allocated`) and the queue's slots theirs, read from an
/// allocator counting this thread's bytes as sends are queued and taken in any mix; a send past
/// the store's share is refused whole, and nothing is held once the sends are let go. Before,
/// a send was charged its encoded length and the queue's slots nothing.
#[test]
fn the_outbox_is_charged_what_it_allocates_as_it_churns() -> Outcome {
    use tally_counting::Counting;
    use tally_wire::{HaveSummary, ParityChunk, StripeAssignment};
    let cell = area()?;
    let to = identity(1).public();
    let mut records = vec![
        Record::HaveSummary(HaveSummary {
            cell,
            product: Streams::RAW,
            first_second: 10,
            seconds: vec![0xff; 40],
        }),
        Record::StripeAssignment(StripeAssignment {
            cell,
            product: Streams::RAW,
            stripes_of: 4,
            stripes: 0b1010,
        }),
    ];
    records.extend(
        ParityChunk::chunks(
            [3; 32],
            cell,
            Streams::RAW,
            12,
            vec![1, 2, 3, 4],
            &[5; 3_000],
        )
        .map_err(text)?
        .into_iter()
        .map(Record::Parity),
    );
    let gauge = Gauge::new(Store::Batches, 40_000);
    let sharing = super::Sharing::new(Deadlines::RELAY);
    sharing.charge_to(Arc::clone(&gauge));
    let base = Counting::live();
    let mut state = 9;
    let mut refused = 0;
    for round in 0..4_000u64 {
        if mixed(&mut state, 9) == 0 {
            drop(sharing.take_outbox());
        } else {
            let record = records[mixed(&mut state, records.len() as u64) as usize].clone();
            if !sharing.address(to, record) {
                refused += 1;
            }
        }
        let allocated = super::locks::lock(&sharing.outbox).allocated();
        assert_eq!(gauge.held(), allocated, "round {round}");
        assert!(gauge.peak() <= gauge.limit());
        let live = Counting::since(base);
        assert!(
            live >= 0 && live as usize == allocated,
            "{live} allocated, {allocated} charged, round {round}"
        );
    }
    assert!(refused > 0, "the store's share was never full");
    drop(sharing.take_outbox());
    assert_eq!(gauge.held(), 0);
    assert_eq!(Counting::since(base), 0);
    Ok(())
}

/// RFC-0181 "Memory is charged once": the parities being reassembled are charged what their
/// trees, their pieces' deques and each piece really allocate, read from an allocator counting
/// this thread's bytes, as senders start, continue, break off, finish and let parities expire in
/// any mix; no sender holds past its part and the room is never charged past; and nothing is held
/// once every parity is gone. Before, each piece and parity was charged an assumed overhead that
/// their vectors and maps passed.
#[test]
fn the_parities_being_reassembled_are_charged_what_they_allocate() -> Outcome {
    use tally_counting::Counting;
    use tally_wire::ParityChunk;
    use tally_wire::sharing::MAX_PARITY_CHUNK;
    const SLOTS: usize = 20;
    let cell = area()?;
    let senders = keys(5);
    let room = Gauge::new(Store::Batches, super::assembly_room(256 << 10));
    let part = super::sender_part(room.limit());
    // Each slot a sender's parity: its whole, and where its next chunk starts.
    let mut totals = [0usize; SLOTS];
    let mut next = [0usize; SLOTS];
    let mut state = 13;
    for total in &mut totals {
        *total = (1 + mixed(&mut state, 6) as usize) * MAX_PARITY_CHUNK
            - mixed(&mut state, 3) as usize * 700;
    }
    let base = Counting::live();
    let mut assembly = super::Assembly::default();
    let mut whole = 0;
    let mut now = START_MS;
    for round in 0..6_000u64 {
        let slot = mixed(&mut state, SLOTS as u64) as usize;
        let sender = senders[slot % senders.len()];
        // Now and then a sender starts again, or skips a chunk.
        if mixed(&mut state, 23) == 0 {
            next[slot] = 0;
        } else if mixed(&mut state, 41) == 0 {
            next[slot] += MAX_PARITY_CHUNK;
        }
        if next[slot] >= totals[slot] {
            next[slot] = 0;
        }
        let (offset, total) = (next[slot], totals[slot]);
        let len = MAX_PARITY_CHUNK.min(total - offset);
        let chunk = ParityChunk {
            manifest: [slot as u8; 32],
            cell,
            product: Streams::RAW,
            second: 7,
            lens: vec![1, 2, 3, 4],
            total: total as u32,
            offset: offset as u32,
            bytes: vec![round as u8; len],
        };
        let got = assembly.take(
            &room,
            sender,
            chunk,
            (offset == 0).then_some(total),
            offset + len,
            now,
        );
        next[slot] = offset + len;
        if let Some(done) = got {
            whole += 1;
            next[slot] = 0;
            drop(done);
        }
        if round % 700 == 699 {
            now += super::PARITY_ASSEMBLY_MS;
            assembly.expire(now);
        }
        let allocated = assembly.allocated();
        assert_eq!(room.held(), allocated, "round {round}");
        assert!(room.peak() <= room.limit());
        for held in assembly.senders.values() {
            assert!(held.held() <= part, "a sender past its part");
        }
        let live = Counting::since(base);
        assert!(
            live >= 0 && live as usize <= allocated,
            "{live} allocated, {allocated} charged, round {round}"
        );
    }
    assert!(whole > 0, "no parity was ever whole");
    drop(assembly);
    assert_eq!(room.held(), 0);
    assert_eq!(Counting::since(base), 0);
    Ok(())
}

/// RFC-0171 §3.6: a member signs no manifest and no receipt while its relay's clock is unsynced
/// (`signer::Signer::with`): what it originated waits, and its manifest goes out at the first
/// tick after the clock is synced. Before, the member held the key itself and signed by whatever
/// the clock read.
#[test]
fn a_member_signs_nothing_while_its_relays_clock_is_unsynced() -> Outcome {
    let clock = crate::clock::RelayClock::scripted(std::sync::Arc::new(|| START_MS));
    let signer = crate::signer::on(identity(0), clock.clone());
    let mut member = Member::new(signer, Gauge::unlimited(Store::Batches), Deadlines::RELAY);
    let group = GroupKey::new(area()?, Streams::RAW);
    let _ = member.set_members(group, &keys(4), &[], START_MS);
    let (hash, piece) = record(&identity(10_000), 1, START_MS)?;
    let _ = member.originate(group, hash, piece, START_MS);
    let manifests = |out: &[super::member::Outgoing]| {
        out.iter()
            .filter(|sent| matches!(sent.message, Message::Manifest(_) | Message::Receipt(_)))
            .count()
    };
    clock.set_error(None);
    let mut unsynced = 0;
    for second in 1..=3 {
        unsynced += manifests(&member.tick(START_MS + second * 1_000));
    }
    if unsynced != 0 {
        return Err(format!("{unsynced} signed while unsynced"));
    }
    clock.set_error(Some(5));
    let mut synced = 0;
    for second in 4..=6 {
        synced += manifests(&member.tick(START_MS + second * 1_000));
    }
    if synced == 0 {
        return Err("nothing signed once synced".into());
    }
    Ok(())
}
