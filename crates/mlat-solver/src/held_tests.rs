use super::*;
use crate::sim::{self, Rng, Scenario};
use tally_wire::{Identity, Observation};

/// A DF11 all-call reply of `address`, which MLAT uses.
fn df11(address: u32) -> Vec<u8> {
    let body = [
        (11 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    modes::with_parity(&body, 0)
}

fn content(wall_ms: u64, messages: &[(u8, Vec<u8>, u64)]) -> BatchContent {
    BatchContent {
        boot_id: 1,
        sequence: 0,
        counter_epoch: 3,
        wall_ms,
        dropped: 0,
        previous: [0; 32],
        observations: messages
            .iter()
            .map(|(format, data, timestamp)| Observation {
                format: *format,
                timestamp: *timestamp,
                signal: 0,
                data: data.clone(),
            })
            .collect(),
    }
}

/// `count` replies of distinct addresses, timestamps from `first`.
fn replies(count: u64, first: u64) -> Vec<(u8, Vec<u8>, u64)> {
    (0..count)
        .map(|n| (format::MODE_S_SHORT, df11(0x400000 + n as u32), first + n))
        .collect()
}

#[test]
fn what_mlat_uses_is_held_once_in_24_bytes_and_the_rest_is_never_held() {
    assert_eq!(size_of::<Record>(), 24);
    assert_eq!(size_of::<Raw>(), 28);
    let key = Identity::from_seed([1; 32]).public();
    let mut held = Held::new(usize::MAX);
    let reply = df11(0x40621d);
    let added = held.add(
        key,
        &content(
            9_000,
            &[
                (format::MODE_S_SHORT, reply.clone(), 10),
                (format::MODE_S_SHORT, vec![0x5d, 1, 2, 3, 4, 5, 6], 11),
                (b'1', vec![1, 2], 12),
            ],
        ),
    );
    assert_eq!((added.new, added.filtered), (1, 2));
    // The same reception again, in an earlier batch: held once, with the earlier wall clock.
    held.add(
        key,
        &content(6_000, &[(format::MODE_S_SHORT, reply.clone(), 10)]),
    );
    held.seal_through(1);
    let bins = held.bins(0, 10);
    assert_eq!(bins.len(), 1);
    assert_eq!(bins[0].records.len(), 1);
    assert_eq!(bins[0].wall_ms(&bins[0].records[0]), 6_000);
    assert!(held.contains(&bins[0].id(0)));
    // A sealed bin takes nothing more: late, for every reader alike.
    let late = held.add(key, &content(7_000, &[(format::MODE_S_SHORT, reply, 99)]));
    assert_eq!((late.late, late.new), (1, 0));
    held.forget_before(2);
    assert!(held.is_empty());
    assert_eq!(held.bytes(), Held::new(usize::MAX).bytes());
}

/// Beyond its bytes, a receiver's raw of the bin is refused whole: none of it is held, every
/// reception of it counted, and the bytes stay within the limit.
#[test]
fn beyond_its_bytes_a_receivers_raw_of_the_bin_is_refused_whole() {
    let first = Identity::from_seed([1; 32]).public();
    let second = Identity::from_seed([2; 32]).public();
    let mut held = Held::new(4_000);
    let taken = held.add(first, &content(1, &replies(10, 0)));
    assert_eq!(taken.new, 10);
    let refused = held.add(second, &content(1, &replies(400, 100)));
    assert_eq!((refused.new, refused.refused), (0, 400));
    assert!(held.bytes() <= 4_000, "{}", held.bytes());
    // Refused for the bin: a later batch of it there is refused too, and counted.
    let again = held.add(second, &content(2, &replies(1, 900)));
    assert_eq!(again.refused, 1);
    held.seal_through(0);
    let bins = held.bins(0, 0);
    assert_eq!(bins[0].receivers, vec![first]);
    assert_eq!(bins[0].records.len(), 10);
}

/// Over its count in a bin, a receiver's raw of the bin is refused whole, what it held there
/// included, in whatever order its batches came; other receivers and other bins are untouched.
#[test]
fn over_its_count_a_receivers_bin_is_refused_whole_in_any_order() {
    let busy = Identity::from_seed([1; 32]).public();
    let quiet = Identity::from_seed([2; 32]).public();
    let batches = [
        content(1_000, &replies(4, 0)),
        content(2_000, &replies(4, 10)),
        content(6_000, &replies(3, 20)),
    ];
    let limits = Limits {
        bytes: usize::MAX,
        per_receiver_bin: 6,
    };
    let mut sealed = Vec::new();
    for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0]] {
        let mut held = Held::with(limits, 1, SealedBins::new());
        held.add(quiet, &content(1_500, &replies(2, 50)));
        let mut refused = 0;
        for at in order {
            refused += held.add(busy, &batches[at]).refused;
        }
        assert_eq!(refused, 8, "{order:?}");
        held.seal_through(1);
        let bins = held.bins(0, 1);
        assert_eq!(bins[0].receivers, vec![quiet]);
        assert_eq!(bins[1].receivers, vec![busy]);
        sealed.push(bins);
    }
    assert!(sealed.windows(2).all(|pair| pair[0] == pair[1]));
}

/// Receptions of a small simulated sky, every one twice in a later batch of the same bin, and a
/// few in batches whose wall clocks put them in the next bin.
fn sky(seed: u64) -> Vec<Reception> {
    let scenario = Scenario {
        duration_s: 12.0,
        receivers: 14,
        adsb_aircraft: 10,
        modes_aircraft: 6,
        reception_probability: 0.8,
        ..Scenario::new(seed)
    };
    let mut rng = Rng::new(seed ^ 0x5eed);
    let mut out = Vec::new();
    sim::run_into(&scenario, &mut |reception, _| {
        if rng.uniform() < 0.3 {
            let mut copy = reception.clone();
            copy.wall_ms += 1_000 + (rng.uniform() * 3_000.0) as u64;
            out.push(copy);
        }
        out.push(reception);
    });
    out
}

/// Each reception added as a batch of its own to whichever holder `owner` names.
fn fill(receptions: &[Reception], opens: &mut [Open], owner: impl Fn(&PublicKey) -> usize) {
    for reception in receptions {
        opens[owner(&reception.receiver)].add(
            reception.receiver,
            &BatchContent {
                boot_id: 0,
                sequence: 0,
                counter_epoch: reception.epoch,
                wall_ms: reception.wall_ms,
                dropped: 0,
                previous: [0; 32],
                observations: vec![reception.observation.clone()],
            },
        );
    }
}

/// RFC-0178 invariant 4: sealing the raw of a bin split among owners by receiver, in any split,
/// on any number of threads, gives the bin one whole holder seals, byte for byte.
#[test]
fn sealing_any_split_by_receiver_gives_the_whole_holders_bin() {
    for seed in [3, 17, 91] {
        let receptions = sky(seed);
        let mut whole = Held::new(usize::MAX);
        for reception in &receptions {
            whole.add_one(reception);
        }
        whole.seal_through(i64::MAX - 1);
        let expected = whole.bins(i64::MIN, i64::MAX - 1);
        assert!(expected.len() >= 3);
        assert!(expected.iter().any(|bin| !bin.candidates.is_empty()));
        let mut rng = Rng::new(seed);
        for parts in [1usize, 2, 3, 7] {
            // A random owner for each receiver.
            let mut owners: BTreeMap<PublicKey, usize> = BTreeMap::new();
            for reception in &receptions {
                owners
                    .entry(reception.receiver)
                    .or_insert_with(|| (rng.next_u64() % parts as u64) as usize);
            }
            for threads in [1usize, 2, 8, 32] {
                let mut opens: Vec<Open> =
                    (0..parts).map(|_| Open::new(Limits::UNBOUNDED)).collect();
                fill(&receptions, &mut opens, |key| owners[key]);
                let mut fragments: BTreeMap<i64, Vec<Fragment>> = BTreeMap::new();
                for open in &mut opens {
                    for fragment in open.take_through(i64::MAX - 1) {
                        fragments.entry(fragment.bin()).or_default().push(fragment);
                    }
                }
                let sealed: Vec<Bin> = fragments
                    .into_iter()
                    .map(|(bin, fragments)| Bin::seal_from(bin, fragments, threads))
                    .collect();
                assert_eq!(sealed.len(), expected.len());
                for (got, want) in sealed.iter().zip(&expected) {
                    assert!(
                        got == want.as_ref(),
                        "seed {seed}, {parts} parts, {threads} threads, bin {}",
                        want.bin
                    );
                    assert_eq!(format!("{got:?}"), format!("{want:?}"));
                }
            }
        }
    }
}

/// A receiver forgotten is gone from every bin, open and sealed, as if it had never been heard
/// (bar thinning's choice among what was kept), and the bytes come back.
#[test]
fn a_receiver_forgotten_is_gone_from_every_bin() {
    let receptions = sky(5);
    let gone = receptions[0].receiver;
    let mut held = Held::new(usize::MAX);
    for reception in &receptions {
        held.add_one(reception);
    }
    held.seal_through(bin_of(receptions[0].wall_ms));
    held.forget_receiver(&gone);
    held.seal_through(i64::MAX - 1);
    for bin in held.bins(i64::MIN, i64::MAX - 1) {
        assert!(bin.receiver(&gone).is_none());
    }
    assert_eq!(held.open_bytes(), 0);
    let bins = held.bins(i64::MIN, i64::MAX - 1);
    let reopened =
        Held::new(usize::MAX).bytes() + bins.iter().map(|bin| bin.bytes()).sum::<usize>();
    assert!(held.bytes() > reopened && held.bytes() < reopened + bins.len() * 1_024);
}

/// The handle a reader keeps sees what its holder seals and forgets, and nothing open.
#[test]
fn a_reader_of_the_sealed_bins_sees_what_the_holder_seals_and_forgets() {
    let receptions = sky(7);
    let sealed = SealedBins::new();
    let mut held = Held::with(Limits::UNBOUNDED, 2, sealed.clone());
    for reception in &receptions {
        held.add_one(reception);
    }
    assert!(sealed.is_empty());
    let first = bin_of(receptions.iter().map(|r| r.wall_ms).min().unwrap_or(0));
    held.seal_through(first + 1);
    assert_eq!(sealed.numbers(), vec![first, first + 1]);
    assert_eq!(sealed.bytes(), held.bytes() - held.open_bytes());
    let id = sealed.bins(first, first)[0].id(0);
    assert!(sealed.contains(&id));
    held.forget_before(first + 1);
    assert_eq!(sealed.numbers(), vec![first + 1]);
    assert!(!sealed.contains(&id));
}

/// What admission reserves for a receiver's sealed raw (`SEALED_BYTES_PER_RECORD`) covers what a
/// bin of a dense sky really allocates per record kept.
#[test]
fn a_sealed_bin_costs_what_admission_reserves() {
    let scenario = Scenario {
        duration_s: 15.0,
        receivers: 60,
        adsb_aircraft: 80,
        modes_aircraft: 40,
        reception_probability: 0.6,
        named: false,
        ..Scenario::new(41)
    };
    let mut held = Held::new(usize::MAX);
    sim::run_into(&scenario, &mut |reception, _| {
        held.add_one(&reception);
    });
    held.seal_through(i64::MAX - 1);
    let bins = held.bins(i64::MIN, i64::MAX - 1);
    let records: usize = bins.iter().map(|bin| bin.records.len()).sum();
    let bytes: usize = bins.iter().map(|bin| bin.bytes()).sum();
    assert!(records > 10_000, "{records}");
    assert!(
        bytes <= records * SEALED_BYTES_PER_RECORD,
        "{} bytes a record",
        bytes as f64 / records as f64
    );
}

/// Open raw costs what admission reserves: 28 bytes a reception and the per-receiver allowance.
#[test]
fn open_raw_costs_what_admission_reserves() {
    let keys: Vec<PublicKey> = (0..50u8)
        .map(|seed| Identity::from_seed([seed; 32]).public())
        .collect();
    let mut held = Held::new(usize::MAX);
    let per_receiver = 1_000;
    for (n, key) in keys.iter().enumerate() {
        for batch in 0..5u64 {
            held.add(
                *key,
                &content(
                    batch * 1_000,
                    &replies(per_receiver / 5, n as u64 * 10_000 + batch * 1_000),
                ),
            );
        }
    }
    let reserved = keys.len()
        * (per_receiver as usize * OPEN_BYTES_PER_RECEPTION + OPEN_BYTES_PER_RECEIVER_BIN);
    assert!(
        held.open_bytes() <= reserved,
        "{} > {reserved}",
        held.open_bytes()
    );
    assert!(held.open_bytes() >= keys.len() * per_receiver as usize * OPEN_BYTES_PER_RECEPTION);
}

#[test]
fn a_receivers_cost_follows_its_rates() {
    let cost = Rates::MEASURED.cost(2_000);
    // A bin and its settling of wanted raw at the ceiling, 28 bytes each, and three open bins'
    // allowance.
    assert_eq!(
        cost.open,
        1_800 * 7 * OPEN_BYTES_PER_RECEPTION + 3 * OPEN_BYTES_PER_RECEIVER_BIN
    );
    assert_eq!(
        cost.sealed,
        150 * 5 * SEALED_BINS_HELD as usize * SEALED_BYTES_PER_RECORD
    );
    let limits = Limits::for_receivers(20_000, Rates::MEASURED, 2_000);
    assert_eq!(limits.bytes, 20_000 * cost.total());
    assert_eq!(limits.per_receiver_bin, 9_000);
}

/// A bin sealed within a holder's bytes (`Bin::seal_within`) refuses the receivers with the most
/// records, whole, until it fits; and the bin and what it refused are the same however the raw was
/// split among owners, whatever order it came in, and on any number of threads.
#[test]
fn a_bin_sealed_within_its_room_refuses_the_busiest_receivers_whole_whatever_the_split() {
    let keys: Vec<PublicKey> = (1..=6u8)
        .map(|seed| Identity::from_seed([seed; 32]).public())
        .collect();
    // Receiver n hears 20 + 10n replies of the bin, the same aircraft as the others.
    let batch = |n: usize| content(1_000 + n as u64, &replies(20 + 10 * n as u64, 0));
    let whole = |order: &[usize], owners: usize| -> Vec<Fragment> {
        let mut opens: Vec<Open> = (0..owners).map(|_| Open::new(Limits::UNBOUNDED)).collect();
        for n in order {
            opens[n % owners].add(keys[*n], &batch(*n));
        }
        opens
            .iter_mut()
            .flat_map(|open| open.take_through(0))
            .collect()
    };
    let unbounded = Bin::seal_from(0, whole(&[0, 1, 2, 3, 4, 5], 1), 1);
    let cost = SealedBins::cost(&unbounded);
    // Room for about half of it: the busiest receivers go first.
    let room = cost / 2;
    let (reference, refused) = Bin::seal_within(0, whole(&[0, 1, 2, 3, 4, 5], 1), 1, room);
    assert!(SealedBins::cost(&reference) <= room);
    assert!(refused > 0);
    assert!(!reference.receivers.is_empty());
    // Whole and busiest first: every receiver kept hears less than every one refused.
    let kept: Vec<usize> = (0..keys.len())
        .filter(|n| reference.receiver(&keys[*n]).is_some())
        .collect();
    let gone: Vec<usize> = (0..keys.len()).filter(|n| !kept.contains(n)).collect();
    assert!(!gone.is_empty());
    assert!(
        kept.iter().all(|k| gone.iter().all(|g| k < g)),
        "{kept:?} {gone:?}"
    );
    for (order, owners, threads) in [
        (vec![5, 4, 3, 2, 1, 0], 1, 1),
        (vec![2, 0, 5, 1, 4, 3], 3, 4),
        (vec![0, 1, 2, 3, 4, 5], 6, 2),
    ] {
        let (bin, again) = Bin::seal_within(0, whole(&order, owners), threads, room);
        assert_eq!(
            bin, reference,
            "{order:?} over {owners} owners on {threads} threads"
        );
        assert_eq!(again, refused);
    }
    // With room for all of it, nothing is refused.
    let (all, none) = Bin::seal_within(0, whole(&[0, 1, 2, 3, 4, 5], 1), 1, cost);
    assert_eq!((all, none), (unbounded, 0));
}
