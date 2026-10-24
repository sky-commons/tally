//! The station rows cost no more than the store they are charged to (`stations::planned_bytes`,
//! `budget::Store::Stations`, RFC-0181 "Memory is charged once"): the rows at the receiver figure,
//! one table for the relay, churned past it, allocate what
//! `Stations::planned_bytes` says at most, at every instant (its pages, the list of them, and its
//! table of slots made anew beside the old one, never let grow on its own), and within twice of
//! it; a smaller figure gives back what it held past it.
//! Measured by an allocator that counts every byte asked of it, the only test in this binary so
//! nothing else allocates while it measures.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use tally_relay::bounded::PAGE;
use tally_relay::stations::Stations;
use tally_relay::strikes::{OwnAnchor, blame};
use tally_wire::Identity;
use tally_wire::clocks::recorded;

#[global_allocator]
static GLOBAL: tally_counting::CountingAll = tally_counting::CountingAll;

#[test]
fn the_station_rows_at_the_figure_allocate_what_is_planned() {
    // A world relay's figure (some 100,000 receivers), and each side of a page and of where the
    // table of slots doubles.
    for capacity in [
        1usize,
        7,
        13,
        14,
        PAGE - 1,
        PAGE,
        PAGE + 1,
        111,
        112,
        113,
        223,
        224,
        225,
        1_000,
        1_791,
        1_792,
        3_583,
        3_584,
        100_000,
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
        // The plan is the worst instant (the table of slots made anew beside the old one); the
        // rows at the figure hold more than half of it past a few pages.
        assert!(
            capacity < 2 * PAGE || held * 2 >= planned,
            "{capacity} rows: {held} held, {planned} planned: the plan is loose"
        );
        // A smaller figure forgets past it and gives back what it held.
        stations.set_capacity(capacity.div_ceil(2));
        assert_eq!(stations.len(), capacity.div_ceil(2));
        let after = usize::try_from(tally_counting::CountingAll::since(base)).unwrap_or(0);
        assert!(
            after <= Stations::planned_bytes(capacity.div_ceil(2)),
            "{capacity} rows halved: {after} held"
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
