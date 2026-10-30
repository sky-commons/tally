//! What `tally_wire::footprint` says a collection allocates is what it allocates (RFC-0181
//! "Memory is charged once"): every store charges its maps, sets, vectors and deques by it, and a
//! store is sized on its charge. Measured by an allocator that counts every byte asked of it, as
//! each collection grows, churns and shrinks: a vector or deque and a hash map exactly, a B-tree
//! at most. The only test in this binary, so nothing else allocates while it measures.

use std::collections::{BTreeMap, HashMap, VecDeque};

use tally_wire::footprint::{
    Deque, Table, Tree, btree, btree_planned, exact, shared_bytes, table_per_entry, vec,
};

use tally_counting::CountingAll;

#[global_allocator]
static GLOBAL: CountingAll = CountingAll;

/// Starts a measure of the peak: the bytes live now.
fn peak_mark() -> isize {
    CountingAll::peak_base()
}

/// The most live at once since `mark` (a [`peak_mark`]), above it.
fn peak_since(mark: isize) -> usize {
    usize::try_from(CountingAll::peak_since(mark)).unwrap_or(0)
}

/// The bytes allocated since `base`.
fn since(base: isize) -> usize {
    usize::try_from(CountingAll::since(base)).unwrap_or(0)
}

/// A small generator that allocates nothing (splitmix64).
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// A key of `N` bytes from a number, so maps of keys of any size are built.
fn key<const N: usize>(n: u64) -> [u8; N] {
    let mut key = [0; N];
    for (at, byte) in key.iter_mut().enumerate() {
        *byte = (n >> ((at % 8) * 8)) as u8 ^ (at as u8);
    }
    key
}

/// A value of `size_of::<V>()` that allocates nothing.
trait Value: Copy {
    fn of(n: u64) -> Self;
}

impl Value for () {
    fn of(_: u64) -> Self {}
}

impl Value for u16 {
    fn of(n: u64) -> Self {
        n as u16
    }
}

impl Value for u64 {
    fn of(n: u64) -> Self {
        n
    }
}

impl<const N: usize> Value for [u64; N] {
    fn of(n: u64) -> Self {
        [n; N]
    }
}

impl<const N: usize> Value for [u8; N] {
    fn of(n: u64) -> Self {
        key(n)
    }
}

/// A map of `N`-byte keys to `V`, churned: grown to a size, most of it removed, grown again,
/// shrunk now and then. Its table is what `Table` says throughout, and no insert grows it by more
/// than `Table::growth` foretold.
fn hash_map<const N: usize, V: Value>(mix: &mut Mix, removed: &mut Vec<[u8; N]>) {
    let base = CountingAll::live();
    let mut map: HashMap<[u8; N], V> = HashMap::new();
    let mut table = Table::default();
    let mut next = 0u64;
    for round in 0..400u64 {
        let target = mix.below(600) as usize + 1;
        while map.len() < target {
            let grows = table.growth::<[u8; N], V>(map.len(), map.capacity());
            let before = since(base);
            let mark = peak_mark();
            map.insert(key(next), V::of(next));
            next += 1;
            table.inserted(map.capacity());
            assert!(
                since(base) <= before + grows,
                "an insert grew [u8; {N}] map past its foretold growth"
            );
            // Its peak too: the new table beside the old while it moves the entries.
            assert!(
                peak_since(mark) <= grows,
                "an insert held [u8; {N}] map's old and new tables past its foretold growth"
            );
            assert_eq!(since(base), table.bytes::<[u8; N], V>(), "[u8; {N}] map");
        }
        removed.clear();
        let keep = mix.below(map.len() as u64 + 1) as usize;
        removed.extend(map.keys().skip(keep).copied());
        for gone in removed.iter() {
            map.remove(gone);
        }
        assert_eq!(since(base), table.bytes::<[u8; N], V>(), "[u8; {N}] map");
        if round % 9 == 0 {
            let to = mix.below(map.len() as u64 * 2 + 1) as usize;
            map.shrink_to(to);
            table.shrunk::<[u8; N], V>(map.len(), to);
            assert_eq!(since(base), table.bytes::<[u8; N], V>(), "[u8; {N}] map");
        }
    }
    map.clear();
    map.shrink_to(0);
    table.shrunk::<[u8; N], V>(0, 0);
    assert_eq!(since(base), 0);
    assert_eq!(table.bytes::<[u8; N], V>(), 0);
}

/// A map kept within four times its entries (`Table::kept`) as it churns: what it allocates is
/// what `Table` says, and never more than `table_per_entry` of four for each entry it holds.
fn kept_map<const N: usize, V: Value>(mix: &mut Mix, removed: &mut Vec<[u8; N]>) {
    let base = CountingAll::live();
    let mut map: HashMap<[u8; N], V> = HashMap::new();
    let mut table = Table::default();
    let mut next = 0u64;
    let per_entry = table_per_entry::<[u8; N], V>(4);
    let within = |len: usize, bytes: usize| bytes <= len * per_entry;
    for _ in 0..400u64 {
        let target = mix.below(800) as usize + 1;
        while map.len() < target {
            let grows = table.growth::<[u8; N], V>(map.len(), map.capacity());
            let before = since(base);
            let mark = peak_mark();
            map.insert(key(next), V::of(next));
            next += 1;
            table.inserted(map.capacity());
            assert!(since(base) <= before + grows);
            assert!(peak_since(mark) <= grows);
            assert_eq!(since(base), table.bytes::<[u8; N], V>());
            assert!(
                within(map.len(), since(base)),
                "{} for {}",
                since(base),
                map.len()
            );
        }
        // Removed a few at a time or most at once, kept after each removal.
        let keep = mix.below(map.len() as u64 + 1) as usize;
        removed.clear();
        removed.extend(map.keys().skip(keep).copied());
        let step = mix.below(64) as usize + 1;
        for gone in removed.chunks(step) {
            for one in gone {
                map.remove(one);
            }
            table.kept(&mut map, 4);
            assert_eq!(
                since(base),
                table.bytes::<[u8; N], V>(),
                "[u8; {N}] kept map"
            );
            assert!(
                within(map.len(), since(base)),
                "{} for {}",
                since(base),
                map.len()
            );
        }
    }
    map.clear();
    table.kept(&mut map, 4);
    assert_eq!(since(base), 0);
}

/// Maps of a few tiny entries, each made as a store makes one and kept within `per` its entries:
/// hashbrown makes them with its least buckets (sixteen for one byte), whatever their capacity is
/// kept within, and `table_per_entry` still holds them.
fn small_map<const N: usize, V: Value>(per: usize) {
    let base = CountingAll::live();
    let per_entry = table_per_entry::<[u8; N], V>(per);
    let most = if N == 1 { 200 } else { 40 };
    for len in 1..=most {
        let mut map: HashMap<[u8; N], V> = HashMap::new();
        let mut table = Table::default();
        for next in 0..len as u64 {
            map.insert(key(next), V::of(next));
            table.inserted(map.capacity());
        }
        table.kept(&mut map, per);
        assert_eq!(since(base), table.bytes::<[u8; N], V>());
        assert!(
            since(base) <= len * per_entry,
            "[u8; {N}] of {} bytes: {} for {len}, {per_entry} each",
            size_of::<([u8; N], V)>(),
            since(base)
        );
        drop(map);
    }
    assert_eq!(since(base), 0);
}

/// A B-tree of `N`-byte keys to `V`, churned in random and in rising order: it never allocates
/// more than `btree` of its length, nor than its plan.
fn btree_map<const N: usize, V: Value>(mix: &mut Mix, removed: &mut Vec<[u8; N]>) {
    let base = CountingAll::live();
    let mut map: BTreeMap<[u8; N], V> = BTreeMap::new();
    let mut next = 0u64;
    let mut most = 0usize;
    for round in 0..300u64 {
        let target = mix.below(2_000) as usize + 1;
        while map.len() < target {
            // Rising keys half the rounds, random the rest.
            let n = if round % 2 == 0 { next } else { mix.next() };
            next += 1;
            map.insert(key(n), V::of(n));
            assert!(
                since(base) <= btree::<[u8; N], V>(map.len()),
                "[u8; {N}] tree"
            );
            most = most.max(since(base));
        }
        removed.clear();
        // Removed from the front, the back or at random: every way a node empties.
        let keep = mix.below(map.len() as u64 + 1) as usize;
        match round % 3 {
            0 => removed.extend(map.keys().skip(keep).copied()),
            1 => removed.extend(map.keys().take(map.len() - keep).copied()),
            _ => removed.extend(map.keys().filter(|_| mix.below(2) == 0).copied()),
        }
        for gone in removed.iter() {
            map.remove(gone);
            assert!(
                since(base) <= btree::<[u8; N], V>(map.len()),
                "[u8; {N}] tree of {} values, {} long: {} > {}",
                std::mem::size_of::<V>(),
                map.len(),
                since(base),
                btree::<[u8; N], V>(map.len())
            );
        }
        map.retain(|_, _| mix.below(4) != 0);
        assert!(
            since(base) <= btree::<[u8; N], V>(map.len()),
            "[u8; {N}] tree"
        );
        assert!(btree::<[u8; N], V>(map.len()) <= btree_planned::<[u8; N], V>(map.len()));
    }
    assert!(most > 0);
    drop(map);
    assert_eq!(since(base), 0);
}

/// A `Tree` churned as the B-tree above: within what it says it allocates, and nothing once
/// emptied, however it was emptied.
fn tree<const N: usize, V: Value>(mix: &mut Mix, removed: &mut Vec<[u8; N]>) {
    let base = CountingAll::live();
    let mut map: Tree<[u8; N], V> = Tree::new();
    for round in 0..200u64 {
        for _ in 0..mix.below(1_500) {
            let n = mix.next();
            map.insert(key(n), V::of(n));
            assert!(since(base) <= map.bytes(), "[u8; {N}] tree");
        }
        removed.clear();
        let keep = if round % 4 == 0 {
            0
        } else {
            mix.below(map.len() as u64 + 1) as usize
        };
        removed.extend(map.keys().skip(keep).copied());
        if round % 8 == 4 {
            map.retain(|_, _| false);
        } else {
            for gone in removed.iter() {
                map.remove(gone);
                assert!(since(base) <= map.bytes(), "[u8; {N}] tree");
            }
        }
        assert!(since(base) <= map.bytes(), "[u8; {N}] tree");
        if map.is_empty() {
            assert_eq!(since(base), 0, "an emptied [u8; {N}] tree kept a node");
        }
    }
    map.clear();
    assert_eq!(since(base), 0);
}

/// A `Tree` split as a store splits one (what is due taken off): each half within what it says
/// it allocates, and nothing once both are gone.
fn split_tree<const N: usize, V: Value>(mix: &mut Mix) {
    let base = CountingAll::live();
    let mut map: Tree<[u8; N], V> = Tree::new();
    for round in 0..100u64 {
        for _ in 0..mix.below(1_000) {
            let n = mix.next();
            map.insert(key(n), V::of(n));
        }
        let at = key(mix.next());
        let later = map.split_off(&at);
        assert!(
            since(base) <= map.bytes() + later.bytes(),
            "[u8; {N}] split"
        );
        if round % 2 == 0 {
            drop(later);
        } else {
            drop(std::mem::replace(&mut map, later));
        }
        assert!(since(base) <= map.bytes(), "[u8; {N}] split");
        if round % 5 == 0 {
            drop(map.take());
            assert_eq!(since(base), 0, "a taken [u8; {N}] tree kept a node");
        }
    }
    drop(map);
    assert_eq!(since(base), 0);
}

/// A `Deque` churned every way a store changes one: exactly what it says it allocates, never more
/// than its length keeps ([`Deque::bytes_at_most`]) after anything that lets entries go, grown by
/// exactly what [`Deque::growth`] said, and nothing once cleared or taken.
fn churned_deque<T: Value, const L: usize>(mix: &mut Mix) {
    let base = CountingAll::live();
    let mut deque: Deque<T, L> = Deque::new();
    let check = |deque: &Deque<T, L>, shrunk: bool| {
        assert_eq!(since(base), deque.bytes(), "deque of {}", deque.len());
        // What holders charging each entry its share pay together covers it, grown or shrunk.
        assert!(
            deque.bytes()
                <= deque.len() * (size_of::<T>() + Deque::<T, L>::SPARE_PER_ENTRY)
                    + Deque::<T, L>::SPARE_FIXED,
            "{} kept for {} past its entries' shares",
            deque.capacity(),
            deque.len()
        );
        if shrunk {
            assert!(
                deque.bytes() <= Deque::<T, L>::bytes_at_most(deque.len()),
                "{} kept for {}",
                deque.capacity(),
                deque.len()
            );
        }
    };
    for round in 0..3_000u64 {
        // A burst in, then a drain: what a queue behind and caught up does.
        let burst = if round % 97 == 0 {
            2_000
        } else {
            mix.below(30)
        };
        // What the whole burst grows it by, foretold.
        let after = deque.bytes() + deque.growth_by(burst as usize);
        for at in 0..burst {
            let before = deque.bytes() + deque.growth();
            match mix.below(3) {
                0 => deque.push_back(T::of(at)),
                1 => deque.push_front(T::of(at)),
                _ => {
                    let index = mix.below(deque.len() as u64 + 1) as usize;
                    deque.insert(index, T::of(at));
                }
            }
            assert_eq!(deque.bytes(), before, "grown past its growth");
            check(&deque, false);
        }
        assert_eq!(deque.bytes(), after, "a burst grown past what was foretold");
        let drain = if round % 97 == 1 {
            deque.len() as u64
        } else {
            mix.below(32)
        };
        for _ in 0..drain {
            match mix.below(3) {
                0 => {
                    deque.pop_front();
                }
                1 => {
                    deque.pop_back();
                }
                _ if !deque.is_empty() => {
                    let index = mix.below(deque.len() as u64) as usize;
                    deque.remove(index);
                }
                _ => {}
            }
            check(&deque, true);
        }
        match round % 11 {
            3 => {
                let mut n = 0u64;
                deque.retain(|_| {
                    n += 1;
                    !n.is_multiple_of(3)
                });
                check(&deque, true);
            }
            7 => {
                let mut n = 0u64;
                let before = deque.len();
                let taken = deque
                    .take_where(|_| {
                        n += 1;
                        n.is_multiple_of(2)
                    })
                    .len();
                assert_eq!(taken + deque.len(), before);
                check(&deque, true);
            }
            _ => {}
        }
        if round % 500 == 499 {
            if round % 1_000 == 999 {
                deque.clear();
            } else {
                drop(deque.take());
            }
            assert_eq!(since(base), 0, "an emptied deque kept its slots");
        }
    }
    drop(deque);
    assert_eq!(since(base), 0);
}

/// One way of signing a batch, as a test of what it allocates calls it.
type Signing<'a> = dyn Fn() -> Result<tally_wire::Batch, tally_wire::WireError> + 'a;

#[test]
fn every_collection_allocates_what_its_footprint_says() -> Result<(), String> {
    let mut mix = Mix(0x7a11_f00d);
    // Room for every key a churn removes, made before any measures.
    let mut removed8: Vec<[u8; 8]> = Vec::with_capacity(4_096);
    let mut removed32: Vec<[u8; 32]> = Vec::with_capacity(4_096);
    let mut removed33: Vec<[u8; 33]> = Vec::with_capacity(4_096);
    let mut removed40: Vec<[u8; 40]> = Vec::with_capacity(4_096);

    // A vector and a deque: their capacity, as they grow, churn and shrink.
    let base = CountingAll::live();
    let mut list: Vec<(u64, [u8; 32])> = Vec::new();
    let mut deque: VecDeque<(u32, u32)> = VecDeque::new();
    for round in 0..2_000u64 {
        for _ in 0..mix.below(40) {
            list.push((round, key(round)));
            deque.push_back((round as u32, 1));
        }
        for _ in 0..mix.below(40) {
            list.pop();
            deque.pop_front();
        }
        if round % 13 == 0 {
            list.shrink_to(list.len() + mix.below(8) as usize);
            deque.shrink_to(deque.len().max(2));
        }
        assert_eq!(
            since(base),
            vec::<(u64, [u8; 32])>(list.capacity()) + vec::<(u32, u32)>(deque.capacity())
        );
    }
    drop((list, deque));
    assert_eq!(since(base), 0);

    // Hash maps of the keys and values the stores keep, and some of every alignment.
    hash_map::<8, [u8; 24]>(&mut mix, &mut removed8);
    hash_map::<8, u16>(&mut mix, &mut removed8);
    hash_map::<32, u64>(&mut mix, &mut removed32);
    hash_map::<32, [u64; 6]>(&mut mix, &mut removed32);
    hash_map::<33, [u64; 6]>(&mut mix, &mut removed33);
    hash_map::<40, [u64; 3]>(&mut mix, &mut removed40);
    hash_map::<32, ()>(&mut mix, &mut removed32);
    kept_map::<8, [u8; 24]>(&mut mix, &mut removed8);
    kept_map::<32, [u64; 6]>(&mut mix, &mut removed32);
    kept_map::<33, [u64; 6]>(&mut mix, &mut removed33);
    kept_map::<40, [u64; 3]>(&mut mix, &mut removed40);
    kept_map::<32, ()>(&mut mix, &mut removed32);
    for per in [1, 2, 4] {
        small_map::<1, ()>(per);
        small_map::<2, ()>(per);
        small_map::<1, u16>(per);
        small_map::<4, ()>(per);
        small_map::<8, u64>(per);
    }

    // B-trees likewise.
    btree_map::<8, u64>(&mut mix, &mut removed8);
    btree_map::<8, u16>(&mut mix, &mut removed8);
    btree_map::<32, ()>(&mut mix, &mut removed32);
    btree_map::<32, u64>(&mut mix, &mut removed32);
    btree_map::<32, [u64; 6]>(&mut mix, &mut removed32);
    btree_map::<32, [u64; 9]>(&mut mix, &mut removed32);
    btree_map::<33, [u64; 6]>(&mut mix, &mut removed33);
    btree_map::<40, [u8; 3]>(&mut mix, &mut removed40);
    tree::<32, [u64; 6]>(&mut mix, &mut removed32);
    tree::<32, ()>(&mut mix, &mut removed32);
    split_tree::<8, u64>(&mut mix);
    split_tree::<32, [u64; 6]>(&mut mix);

    // Deques as the stores keep them: four slots kept at least, and one for many short ones.
    churned_deque::<[u64; 6], 4>(&mut mix);
    churned_deque::<u16, 4>(&mut mix);
    churned_deque::<[u8; 24], 1>(&mut mix);
    churned_deque::<u64, 1>(&mut mix);

    // Records as a queue holds them once read off the wire: what each allocates is what
    // `Record::allocated` says, a batch's shared bytes at most.
    records_allocate_what_they_say().map_err(|error| error.to_string())?;
    // And batches as they are signed (a feeder's, its anchored form, a relay's from its draft):
    // their bytes made exact before they are shared, so what they keep is what they say.
    signed_batches_allocate_what_they_say().map_err(|error| error.to_string())?;

    // Bytes made exact, then cloned and sliced as a piece's are.
    let base = CountingAll::live();
    for len in [1usize, 40, 1_000, 65_536] {
        let mut encoded = Vec::new();
        for n in 0..len {
            encoded.push(n as u8);
        }
        let held = tally_wire::Bytes::from(exact(encoded));
        let sliced = held.slice(3.min(len)..);
        let copy = held.clone();
        assert!(
            since(base) <= shared_bytes(len),
            "{} for {len} bytes",
            since(base)
        );
        drop((held, sliced, copy));
        assert_eq!(since(base), 0);
    }
    Ok(())
}

/// Every kind of record a store or queue holds, read off the wire: what reading one keeps
/// allocated is what [`tally_wire::Record::allocated`] says (a batch's shared bytes at most, the
/// rest exactly), and nothing once it is let go.
fn records_allocate_what_they_say() -> Result<(), Box<dyn std::error::Error>> {
    use tally_wire::{
        BatchContent, HaveSummary, Identity, Location, ParityChunk, Record, Region, RelayAddress,
        Streams, StripeReceipt, StripeReceiptContent,
    };
    let identity = Identity::from_seed([9; 32]);
    let cell = Region::containing(
        &Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        },
        3,
    )?;
    let mut records = vec![
        Record::Batch(tally_wire::Batch::sign(
            &identity,
            &BatchContent {
                boot_id: 1,
                sequence: 2,
                counter_epoch: 1,
                wall_ms: 1_000,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )?),
        Record::HaveSummary(HaveSummary {
            cell,
            product: Streams::RAW,
            first_second: 10,
            seconds: vec![0xff; 37],
        }),
        Record::RelayList(vec![
            RelayAddress {
                key: identity.public(),
                address: "relay.example:4100".into(),
            };
            3
        ]),
        Record::Subscribe {
            streams: Streams::RAW,
            regions: vec![cell; 5],
        },
        Record::StripeReceipt(StripeReceipt::sign(
            &identity,
            &StripeReceiptContent {
                parent: identity.public(),
                cell,
                product: Streams::RAW,
                stripe: 3,
                stripes_of: 4,
                first_second: 100,
                last_second: 160,
                records: 900,
                bytes: 1 << 20,
                digest: tally_wire::sharing::receipt_digest(&[[1; 32]]),
                issued_ms: 170_000,
            },
        )?),
    ];
    let xor = vec![7u8; 3 * tally_wire::sharing::MAX_PARITY_CHUNK / 2];
    records.extend(
        ParityChunk::chunks([3; 32], cell, Streams::RAW, 12, vec![1, 2, 3, 4], &xor)?
            .into_iter()
            .map(Record::Parity),
    );
    let mut encoded = Vec::new();
    for record in &records {
        let mut out = Vec::new();
        record.encode(&mut out)?;
        encoded.push(out);
    }
    drop(records);
    for bytes in &encoded {
        let base = CountingAll::live();
        let (record, _) = Record::decode(bytes, tally_wire::record::MAX_VERSION)?;
        let record = record.ok_or_else(|| "a record this build reads".to_owned())?;
        let kept = since(base);
        match record {
            Record::Batch(_) => assert!(kept <= record.allocated(), "{kept} for a batch"),
            _ => assert_eq!(kept, record.allocated(), "kind {}", record.kind()),
        }
        drop(record);
        assert_eq!(since(base), 0);
    }
    Ok(())
}

/// Every way a batch is signed (`Batch::sign`, `Batch::sign_anchored`, `Batch::sign_relay_draft`):
/// what the signed batch keeps allocated is no more than [`tally_wire::Batch::allocated`] says, at
/// every number of receptions (so at every spare capacity its bytes grew to), and nothing once it
/// is let go. Before, the signed bytes were shared with the capacity they grew to, so a batch the
/// relay signed kept up to twice what it was charged.
fn signed_batches_allocate_what_they_say() -> Result<(), tally_wire::WireError> {
    use tally_wire::{
        Anchor, Batch, BatchContent, BatchDraft, Identity, ObsView, Observation, batch::Codec,
    };
    let identity = Identity::from_seed([11; 32]);
    let anchors = [
        Anchor::sign(&identity, 1_000),
        Anchor::sign(&identity, 2_000),
    ];
    for count in [1usize, 3, 7, 20, 61, 150, 400] {
        let observations: Vec<Observation> = (0..count)
            .map(|n| Observation {
                format: b'3',
                timestamp: n as u64 + 1,
                signal: 100,
                data: vec![n as u8; 14],
            })
            .collect();
        let content = BatchContent {
            boot_id: 1,
            sequence: count as u64,
            counter_epoch: 0,
            wall_ms: 1_000,
            dropped: 0,
            previous: [0; 32],
            observations,
        };
        let draft = BatchDraft {
            boot_id: 1,
            sequence: count as u64,
            counter_epoch: 0,
            wall_ms: 1_000,
            dropped: 0,
            previous: [0; 32],
            observations: content.observations.iter().map(ObsView::from).collect(),
        };
        let signers: [(&str, &Signing); 3] = [
            ("sign", &|| Batch::sign(&identity, &content)),
            ("sign_anchored", &|| {
                Batch::sign_anchored(&identity, &content, Codec::Plain, &anchors)
            }),
            ("sign_relay_draft", &|| {
                Batch::sign_relay_draft(&identity, &draft)
            }),
        ];
        for (how, sign) in signers {
            let base = CountingAll::live();
            let batch = sign()?;
            let kept = since(base);
            assert!(
                kept <= batch.allocated(),
                "{how} of {count} receptions keeps {kept}, charged {}",
                batch.allocated()
            );
            drop(batch);
            assert_eq!(since(base), 0, "{how}");
        }
    }
    Ok(())
}
