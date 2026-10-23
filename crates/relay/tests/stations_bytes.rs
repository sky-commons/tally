//! The station rows cost no more than the store they are charged to (`stations::PLANNED_BYTES`,
//! `budget::Store::Stations`, RFC-0181 "Memory is charged once"): one shard's rows at their cap,
//! churned past it, allocate what `Stations::planned_bytes` says at most, at every instant (a
//! churned table grows past twice its keys, and holds its old buckets and new ones as it does), and
//! within three times of it.
//! Measured by an allocator that counts every byte asked of it, the only test in this binary so
//! nothing else allocates while it measures.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use tally_relay::stations::Stations;
use tally_relay::strikes::{OwnAnchor, blame};
use tally_wire::Identity;
use tally_wire::clocks::recorded;

#[global_allocator]
static GLOBAL: tally_counting::CountingAll = tally_counting::CountingAll;

#[test]
fn a_shards_station_rows_at_their_cap_allocate_what_is_planned() {
    let shard = tally_relay::stations::STATIONS_REMEMBERED.div_ceil(tally_relay::exchange::SHARDS);
    // Each side of where a table's buckets double, and a shard's own cap.
    for capacity in [
        1usize, 7, 13, 14, 27, 28, 100, 111, 112, 113, 223, 224, 225, 1_000, 1_791, 1_792, 3_583,
        3_584, shard,
    ] {
        // Every key made before any is measured, and twice the cap of them, so the rows churn.
        let keys: Vec<_> = (0..2 * capacity as u64 + 2)
            .map(|n| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&n.to_be_bytes());
                Identity::from_seed(seed).public()
            })
            .collect();
        let base = tally_counting::CountingAll::live();
        let mark = tally_counting::CountingAll::peak_base();
        let mut stations = Stations::new(capacity);
        for (n, key) in keys.iter().enumerate() {
            let at = recorded::mono(1_000 + n as u64);
            stations.forwarded(*key, 1, n as u64, 10, at);
            let _ = stations.first_judged(*key, 1, n as u64, at);
            if let Some(blame) = blame(true, true, OwnAnchor::Absent) {
                stations.too_old(blame, *key, at);
            }
        }
        assert_eq!(stations.len(), capacity);
        let held = usize::try_from(tally_counting::CountingAll::since(base)).unwrap_or(0);
        let peak = usize::try_from(tally_counting::CountingAll::peak_since(mark)).unwrap_or(0);
        let planned = Stations::planned_bytes(capacity);
        assert!(
            peak <= planned,
            "{capacity} rows: {peak} at the peak, {planned} planned"
        );
        // The plan is the worst instant (a table grown past twice its keys, beside the one before
        // it); a table just past a doubling holds a third of that, and below a hundred rows its
        // fixed overhead is most of it. Never looser than three times.
        assert!(
            capacity < 100 || held * 3 >= planned,
            "{capacity} rows: {held} held, {planned} planned: the plan is loose"
        );
        drop(stations);
        assert_eq!(
            tally_counting::CountingAll::since(base),
            0,
            "{capacity} rows outlived their table"
        );
        eprintln!("{capacity} rows: {held} held, {peak} at the peak, {planned} planned");
    }
}
