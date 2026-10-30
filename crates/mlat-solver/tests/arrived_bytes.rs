//! A holder of raw reports the bytes it really allocated (RFC-0181 §5 and invariant 8): admission is
//! sized on `Arrived::bytes`, so it must count what is in memory, never an estimate below it.
//! Measured by an allocator that counts every byte asked of it, the only test in this binary so
//! nothing else allocates while it measures.

use tally_mlat_solver::arrived::{Arrived, Limits, SLICE_MS};
use tally_mlat_solver::sim::{self, Scenario};

/// The system's allocator, counting the bytes live and the allocations.
#[global_allocator]
static GLOBAL: tally_counting::CountingAll = tally_counting::CountingAll;

fn live() -> (isize, isize) {
    (
        tally_counting::CountingAll::live(),
        tally_counting::CountingAll::allocations(),
    )
}

/// `accounted` covers `allocated` bytes in `allocations` allocations: never below what was asked
/// for, and above it by no more than each allocation's own cost (16 bytes) and a sliver.
fn covers(what: &str, accounted: usize, allocated: isize, allocations: isize) {
    let allocated = allocated.max(0) as usize;
    let allocations = allocations.max(0) as usize;
    eprintln!(
        "{what}: accounted {accounted}, allocated {allocated} in {allocations} allocations ({:.3})",
        accounted as f64 / allocated.max(1) as f64
    );
    assert!(accounted >= allocated, "{what}: {accounted} < {allocated}");
    assert!(
        accounted <= allocated + allocations * 16 + allocated / 20 + 16_384,
        "{what}: {accounted} far above {allocated}"
    );
}

#[test]
fn a_holders_bytes_are_what_it_allocated() {
    let scenario = Scenario {
        duration_s: 40.0,
        receivers: 80,
        adsb_aircraft: 60,
        modes_aircraft: 30,
        reception_probability: 0.7,
        named: false,
        ..Scenario::new(23)
    };
    let mut simulation = sim::run(&scenario);
    let arrivals = sim::arrivals(&mut simulation, 24);
    let (before, allocations_before) = live();
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    let mut sealed = 0;
    // Each measurement is (accounted, allocated, allocations), reported only once all are taken:
    // a report prints, and libtest's capture of it allocates, which a later one would count.
    let mut measured: [(usize, isize, isize); 3] = [(0, 0, 0); 3];
    let mut taken = 0;
    for arrival in &arrivals {
        if arrival.at_ms / SLICE_MS > sealed {
            sealed = arrival.at_ms / SLICE_MS;
            arrived.seal(sealed * SLICE_MS);
            // Twice: filling, and once raw is let go as fast as it comes.
            if taken < 2 && arrived.len() > 20_000 * (taken + 1) {
                let (now, allocations) = live();
                measured[taken] = (
                    arrived.bytes(),
                    now - before,
                    allocations - allocations_before,
                );
                taken += 1;
            }
        }
        arrived.admit(arrival.batch, arrival.at_ms, &arrival.receptions);
    }
    let (now, allocations) = live();
    measured[2] = (
        arrived.bytes(),
        now - before,
        allocations - allocations_before,
    );
    assert_eq!(taken, 2, "the holder never held twice 20,000 receptions");
    for (what, (accounted, allocated, allocations)) in
        ["held", "held", "end"].into_iter().zip(measured)
    {
        covers(what, accounted, allocated, allocations);
    }
    assert!(arrived.len() > 20_000, "{}", arrived.len());
}
