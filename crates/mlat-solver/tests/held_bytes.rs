//! A holder of raw reports the bytes it really allocated (RFC-0181 §5 and invariant 8): admission is
//! sized on `Held::bytes`, so it must count what is in memory, never an estimate below it. Measured
//! by an allocator that counts every byte asked of it, the only test in this binary so nothing
//! else allocates while it measures.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use tally_mlat_solver::held::{Held, Limits, SealedBins};
use tally_mlat_solver::sim::{self, Scenario};
use tally_wire::clocks::recorded::aligned;

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
/// for, and above it by no more than each allocation's own cost (16 bytes, what the accounting adds
/// for the allocator's header) and a sliver.
fn covers(what: &str, accounted: usize, allocated: isize, allocations: isize) {
    let allocated = allocated.max(0) as usize;
    let allocations = allocations.max(0) as usize;
    eprintln!(
        "{what}: accounted {accounted}, allocated {allocated} in {allocations} allocations ({:.3})",
        accounted as f64 / allocated.max(1) as f64
    );
    assert!(accounted >= allocated, "{what}: {accounted} < {allocated}");
    assert!(
        accounted <= allocated + allocations * 16 + allocated / 20 + 4_096,
        "{what}: {accounted} far above {allocated}"
    );
}

#[test]
fn a_holders_bytes_are_what_it_allocated() {
    let scenario = Scenario {
        duration_s: 21.0,
        receivers: 80,
        adsb_aircraft: 60,
        modes_aircraft: 30,
        reception_probability: 0.7,
        named: false,
        ..Scenario::new(23)
    };
    let simulation = sim::run(&scenario);
    let (before, allocations_before) = live();
    let mut held = Held::with(Limits::UNBOUNDED, 4, SealedBins::new());
    for reception in &simulation.receptions {
        held.add_one(reception, aligned(reception.wall_ms));
    }
    let (open, allocations) = live();
    covers(
        "open",
        held.bytes(),
        open - before,
        allocations - allocations_before,
    );
    held.seal_through(i64::MAX - 1);
    let (sealed, allocations) = live();
    covers(
        "sealed",
        held.bytes(),
        sealed - before,
        allocations - allocations_before,
    );
    assert!(held.len() > 20_000, "{}", held.len());
}
