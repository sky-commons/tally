//! Sharing groups under a virtual clock: many members, each a `Member`, exchanging messages over
//! links of a fixed delay, ticked every `network::TICK`. Deterministic: keys come from seeds,
//! every map is ordered, and the event queue breaks ties by the order things were sent.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::sync::Arc;

use tally_wire::batch::Hash;
use tally_wire::sharing::receipt_digest;
use tally_wire::{
    Batch, BatchContent, Identity, Location, PieceManifest, PieceManifestContent, PublicKey,
    Record, Region, Streams,
};

use super::bundles::{BundleIndex, Bundles, Omission, children};
use super::groups::{GroupKey, Groups};
use super::member::{Member, Message, Outgoing, Piece};
use super::parity::Parity;
use super::seeds::{
    SEED_COPIES, SEED_ROTATION_SECONDS, SEEDS, epoch_of, is_seed, seed_members, seeded_bytes,
};
use super::stripes::{DATA_STRIPES, FANOUT, Layout, STRIPES, data_stripe};
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
}

impl Sim {
    fn new(count: usize, delay_ms: u64) -> Result<Self, String> {
        let group = GroupKey::new(area()?, Streams::RAW);
        let keys = keys(count);
        let mut members: Vec<Member> = (0..count).map(|i| Member::new(identity(i))).collect();
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
            held_at: BTreeMap::new(),
            handed: BTreeMap::new(),
            originated: BTreeMap::new(),
            seed_copies: vec![0; count],
            seeded_to: vec![BTreeSet::new(); count],
            receipts: Vec::new(),
            receiver: identity(10_000),
            sequence: 0,
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
                .push(Reverse((self.now + self.delay_ms, self.seq)));
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

    fn collect(&mut self, i: usize) {
        for delivered in self.members[i].take_delivered() {
            *self.handed.entry((i, delivered.hash)).or_default() += 1;
            self.held_at.entry((i, delivered.hash)).or_insert(self.now);
        }
    }

    /// Originates `count` new records at member `origin`, now.
    fn originate(&mut self, origin: usize, count: usize) -> Result<Vec<Hash>, String> {
        let mut hashes = Vec::new();
        for _ in 0..count {
            self.sequence += 1;
            let batch = Batch::sign(
                &self.receiver,
                &BatchContent {
                    boot_id: 1,
                    sequence: self.sequence,
                    counter_epoch: 0,
                    wall_ms: self.now,
                    dropped: 0,
                    previous: [0; 32],
                    observations: Vec::new(),
                },
            )
            .map_err(text)?;
            let record = Record::Batch(batch);
            let piece = Piece::of(&record).ok_or("no piece")?;
            let hash = piece.hash().ok_or("no hash")?;
            self.originated.insert(hash, (self.now, origin));
            hashes.push(hash);
            if self.down.contains(&origin) {
                continue;
            }
            let out = self.members[origin].originate(self.group, hash, piece, self.now);
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
                let from = self.keys[event.from];
                let out = self.members[event.to].receive(from, event.message, self.now);
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
                    let out = self.members[i].tick(self.now);
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
        let horizon_ms = super::member::HORIZON_SECONDS * 1000;
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
        let batch = Batch::sign(
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
    groups.admit(key, members[0], 1_000, false);
    groups.admit(key, members[1], 2_000, true);
    groups.admit(key, members[2], 2_000, false);
    if groups.members(cell, Streams::RAW).len() != 3
        || groups.leaves_only(key) != vec![members[1]]
        || !groups.members(cell, Streams::POSITIONS).is_empty()
    {
        return Err("membership".into());
    }
    groups.demote(key, members[2], 5_000);
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

#[test]
fn the_seam_admits_relays_that_ask_and_ignores_clients() -> Outcome {
    let sharing = super::Sharing::new();
    let cell = area()?;
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
    };
    let client = Asker {
        role: AskerRole::Client,
        key: identity(2).public(),
        source: 2,
        loopback: false,
    };
    let _ = sharing.assigned(&client, assignment, 1_000);
    let _ = sharing.assigned(&relay, assignment, 1_000);
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

/// A receiver's batch as a group carries it: its hash and its encoding.
fn record(receiver: &Identity, sequence: u64, wall_ms: u64) -> Result<(Hash, Piece), String> {
    let batch = Batch::sign(
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
        now_ms,
    )?;
    Ok(())
}

#[test]
fn a_have_summary_at_the_end_of_time_is_refused_not_a_panic() -> Outcome {
    let me = identity(0);
    let group = GroupKey::new(area()?, Streams::RAW);
    let mut member = Member::new(me.clone());
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
    let hub = crate::hub::Hub::new(8);
    let cell = area()?;
    hub.network().selection.set_taken(vec![cell]);
    let sharing = super::Sharing::new();
    let me = identity(0);
    let _ = sharing.tick_shed(&hub, Some(&me), 0, START_MS);
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
    let _ = sharing.tick_shed(&hub, Some(&me), 0, START_MS + 1_000);
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
    let hub = crate::hub::Hub::new(8);
    let area = area()?;
    let region = area.ancestor(1).ok_or("no region")?;
    hub.network().selection.set_taken(vec![region]);
    let sharing = &hub.network().sharing;
    let _ = sharing.tick_shed(&hub, Some(&identity(0)), 0, START_MS);
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
    let mut member = Member::new(identity(0));
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
    let ahead = second + super::member::SKEW_SECONDS + 1;
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

#[test]
fn overlapping_parity_chunks_are_counted_once_and_a_stalled_parity_expires() -> Outcome {
    let sharing = super::Sharing::new();
    let asker = relay(identity(1).public());
    let cell = area()?;
    let chunk = |offset: u32, bytes: Vec<u8>, manifest: Hash| tally_wire::ParityChunk {
        manifest,
        cell,
        product: Streams::RAW,
        second: START_MS / 1000,
        lens: vec![0; usize::from(DATA_STRIPES)],
        total: 100,
        offset,
        bytes,
    };
    let manifest = [3; 32];
    let _ = sharing.parity_chunk(&asker, chunk(0, vec![1; 60], manifest), START_MS);
    let _ = sharing.parity_chunk(&asker, chunk(0, vec![1; 60], manifest), START_MS);
    // Sixty bytes of a hundred are covered: the parity is not whole.
    if !super::locks::lock(&sharing.assembling).contains_key(&(asker.key, manifest)) {
        return Err("a parity counted whole from one chunk sent twice".into());
    }
    let _ = sharing.parity_chunk(&asker, chunk(60, vec![1; 40], manifest), START_MS);
    if super::locks::lock(&sharing.assembling).contains_key(&(asker.key, manifest)) {
        return Err("a whole parity still assembling".into());
    }
    // One left with a gap is dropped once it has had its time.
    let stalled = [4; 32];
    let _ = sharing.parity_chunk(&asker, chunk(0, vec![1; 60], stalled), START_MS);
    let later = START_MS + super::PARITY_ASSEMBLY_MS + 1;
    let _ = sharing.parity_chunk(&asker, chunk(0, vec![1; 10], [5; 32]), later);
    if super::locks::lock(&sharing.assembling).contains_key(&(asker.key, stalled)) {
        return Err("a stalled parity never expired".into());
    }
    Ok(())
}

#[test]
fn a_false_parity_is_dropped_and_a_true_one_after_it_rebuilds() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let me = identity(0);
    let members = keys(4);
    let mut member = Member::new(me);
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
    if member.stats().rebuilt != missing || !hashes.iter().all(|hash| member.holds(group, hash)) {
        return Err(format!(
            "rebuilt {} of {missing} after the true parity came",
            member.stats().rebuilt
        ));
    }
    Ok(())
}

#[test]
fn repair_is_answered_only_to_members_of_the_trees() -> Outcome {
    let group = GroupKey::new(area()?, Streams::RAW);
    let mut member = Member::new(identity(0));
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
    let hub = crate::hub::Hub::new(8);
    let cell = area()?;
    hub.network().selection.set_taken(vec![cell]);
    let sharing = &hub.network().sharing;
    let offered = identity(1);
    hold_offer(&hub, &offered, cell, 0b1111, START_MS)?;
    let asker = relay(identity(2).public());
    let _ = sharing.assigned(
        &asker,
        tally_wire::StripeAssignment {
            cell,
            product: Streams::RAW,
            stripes_of: STRIPES,
            stripes: 1,
        },
        START_MS,
    );
    let _ = sharing.tick_shed(&hub, Some(&identity(0)), 0, START_MS);
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
    withdrawal.observe(5, &regions, &me, now);
    if !withdrawal.withdrawn().is_empty() {
        return Err("withdrew with nothing newly shed".into());
    }
    now += 100;
    withdrawal.observe(6, &regions, &me, now);
    now += 100;
    withdrawal.observe(7, &regions, &me, now);
    if withdrawal.withdrawn() != &ordered[..1] {
        return Err(format!("withdrew {:?}", withdrawal.withdrawn()));
    }
    now += WITHDRAW_EVERY_MS;
    withdrawal.observe(8, &regions, &me, now);
    if withdrawal.withdrawn() != &ordered[..2] || !withdrawal.covers(ordered[1]) {
        return Err("the second region is not the order's next".into());
    }
    now += RESTORE_AFTER_MS;
    withdrawal.observe(8, &regions, &me, now);
    if withdrawal.withdrawn() != &ordered[..1] {
        return Err("the last withdrawn was not taken back first".into());
    }
    // Through the seam: the relay is a leaf in the trees of what it withdrew from.
    let hub = crate::hub::Hub::new(8);
    hub.network().selection.set_taken(vec![area]);
    for index in 1..6 {
        hold_offer(&hub, &identity(index), area, 0b1111, START_MS)?;
    }
    let sharing = &hub.network().sharing;
    let mine = identity(0);
    let _ = sharing.tick_shed(&hub, Some(&mine), 0, START_MS);
    let homes = |sharing: &super::Sharing| {
        sharing
            .layout(area, Streams::RAW)
            .map(|layout| layout.homes(&mine.public()))
            .unwrap_or_default()
    };
    if homes(sharing).is_empty() {
        return Err("forwarded nothing before withdrawing".into());
    }
    let _ = sharing.tick_shed(&hub, Some(&mine), 1, START_MS + 1_000);
    if !sharing.withdrawn(area) || !homes(sharing).is_empty() {
        return Err("still forwarding in a withdrawn area".into());
    }
    Ok(())
}

#[test]
fn a_member_holds_records_for_its_repair_horizon_shared_and_refuses_past_its_capacity() -> Outcome {
    use super::member::{
        HORIZON_MS, HORIZON_SECONDS, JUDGE_AFTER_MS, RECEIPT_GRACE_MS, RECEIPT_WINDOW_SECONDS,
        REPAIR_AFTER_MS, held_bytes_for,
    };
    // The horizon is sharing's own duties end to end, not a round minute.
    if HORIZON_MS
        != RECEIPT_WINDOW_SECONDS * 1000 + RECEIPT_GRACE_MS + JUDGE_AFTER_MS + REPAIR_AFTER_MS
        || !(12..=15).contains(&HORIZON_SECONDS)
    {
        return Err(format!("a horizon of {HORIZON_SECONDS} s"));
    }
    let group = GroupKey::new(area()?, Streams::RAW);
    let members = keys(4);
    let mut member = Member::new(identity(0));
    let _ = member.set_members(group, &members, &[], START_MS);
    let receiver = identity(10_000);
    let (hash, piece) = record(&receiver, 1, START_MS)?;
    let len = piece.len();
    // Sized by time: room for two such records a second over the horizon.
    member.set_capacity(held_bytes_for(2 * len as u64));
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
    if member.held_bytes() != len {
        return Err(format!("{} bytes held of {len}", member.held_bytes()));
    }
    // Past the capacity a record is refused whole, and counted.
    let mut taken = 1;
    for sequence in 2..(2 * HORIZON_SECONDS + 10) {
        let (hash, piece) = record(&receiver, sequence, START_MS)?;
        let _ = member.originate(group, hash, piece, START_MS);
        if member.holds(group, &hash) {
            taken += 1;
        }
    }
    if member.held_bytes() > held_bytes_for(2 * len as u64) || member.stats().refused == 0 {
        return Err(format!(
            "{} bytes held, {} refused",
            member.held_bytes(),
            member.stats().refused
        ));
    }
    if taken as usize * len != member.held_bytes() {
        return Err("a record held in part".into());
    }
    // Within the horizon it is held; past it, let go, and its bytes with it.
    let _ = member.tick(START_MS + HORIZON_SECONDS * 1000);
    if !member.holds(group, &hash) {
        return Err("let go within the horizon".into());
    }
    let _ = member.tick(START_MS + HORIZON_SECONDS * 1000 + 1_001);
    if member.holds(group, &hash) || member.held_bytes() != 0 {
        return Err(format!(
            "held past the horizon: {} bytes",
            member.held_bytes()
        ));
    }
    Ok(())
}
