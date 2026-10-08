//! A holder of raw reports the bytes it really allocated (RFC-0181 §5 and invariant 8): admission is
//! sized on `Held::bytes`, so it must count what is in memory, never an estimate below it. Measured
//! by an allocator that counts every byte asked of it, the only test in this binary so nothing
//! else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use tally_mlat_solver::held::{Held, Limits, SealedBins};
use tally_mlat_solver::sim::{self, Scenario};

/// The system's allocator, counting the bytes live and the allocations.
struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static ALLOCATIONS: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call is the system allocator's, with the same arguments; the counters are atomics.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn live() -> (isize, isize) {
    (
        LIVE.load(Ordering::Relaxed),
        ALLOCATIONS.load(Ordering::Relaxed),
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
        held.add_one(reception);
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
