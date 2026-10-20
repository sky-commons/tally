//! A receiver's feeder figures row costs no more than the charge it takes (`figures::
//! PER_RECEIVER_BYTES`, RFC-0181 "Memory is charged once"): the store is sized on the charge, so it
//! must cover what a row at every cap really allocates. Measured by an allocator that counts every
//! byte asked of it, the only test in this binary so nothing else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use tally_mlat_solver::modes;
use tally_relay::figures::{Figures, MAX_PER_FEEDER, PER_RECEIVER_BYTES, WINDOW_HOURS};
use tally_wire::{Batch, BatchContent, Decoded, Identity, Location, Observation, Region};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call is the system allocator's, with the same arguments; the counter is atomic.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
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

const HOUR_MS: u64 = tally_wire::FIGURES_BUCKET_MS;
const T: u64 = 497_561 * HOUR_MS;

/// An airborne position of `address` at (`lat`, `lon`), even or odd, as a DF17.
fn airborne(address: u32, lat: f64, lon: f64, odd: bool) -> Vec<u8> {
    let (lat_cpr, lon_cpr) = modes::cpr_encode(
        modes::LatLon {
            lat_deg: lat,
            lon_deg: lon,
        },
        odd,
    );
    let me = modes::encode_airborne_position(11, 0x0c38, odd, lat_cpr, lon_cpr);
    let mut body = vec![
        (17 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    body.extend_from_slice(&me);
    modes::with_parity(&body, 0)
}

fn batch(
    who: &Identity,
    sequence: u64,
    wall_ms: u64,
    messages: Vec<Vec<u8>>,
) -> std::sync::Arc<Decoded> {
    let observations = messages
        .into_iter()
        .enumerate()
        .map(|(n, data)| Observation {
            format: b'3',
            timestamp: 1_000 + n as u64,
            signal: 100,
            data,
        })
        .collect();
    let content = BatchContent {
        boot_id: 1,
        sequence,
        counter_epoch: 0,
        wall_ms,
        dropped: 0,
        previous: [0; 32],
        observations,
    };
    let batch = Batch::sign(who, &content).unwrap_or_else(|error| panic!("{error}"));
    Decoded::from_verified(batch, wall_ms, sequence).unwrap_or_else(|error| panic!("{error:?}"))
}

/// One receiver's row at every cap: a batch every minute of the window and the hour after it (the
/// most its minutes hold between two hourly signings), and more aircraft, each placed by its own
/// pair in a coverage cell of its own, than a row holds.
#[test]
fn a_full_row_costs_no_more_than_its_charge() {
    let figures = Figures::new();
    let feeder = Identity::from_seed([7; 32]);
    let public = Region::public_cell(&Location {
        lat_e7: 375_000_000,
        lon_e7: -1_222_500_000,
        alt_m: 0,
        precision_m: 0,
    })
    .unwrap_or_else(|error| panic!("{error}"));
    // Built before the count: the batches are the test's, not the row's.
    let aircraft = (MAX_PER_FEEDER + 64) as u32;
    let mut batches = Vec::new();
    for n in 0..aircraft {
        // Spread over a few hundred kilometres: a coverage cell (about 16 km across) each.
        let lat = 35.5 + f64::from(n / 24) * 0.17;
        let lon = -124.5 + f64::from(n % 24) * 0.2;
        let at = T + u64::from(n) * 1_000;
        batches.push(batch(
            &feeder,
            u64::from(n),
            at,
            vec![
                airborne(0x10_0000 + n, lat, lon, false),
                airborne(0x10_0000 + n, lat, lon, true),
            ],
        ));
    }
    let minutes = (WINDOW_HOURS + 1) * 60;
    for minute in 0..minutes {
        let at = T + minute * 60_000 + 30_000;
        batches.push(batch(&feeder, u64::from(aircraft) + minute, at, Vec::new()));
    }
    let before = LIVE.load(Ordering::Relaxed);
    for decoded in &batches {
        figures.batch(decoded, Some(public), decoded.wall_ms());
    }
    let row = LIVE.load(Ordering::Relaxed) - before;
    assert_eq!(figures.rows(), 1);
    eprintln!("a full row: {row} bytes of {PER_RECEIVER_BYTES} charged");
    assert!(
        row <= PER_RECEIVER_BYTES as isize,
        "a full row allocates {row} bytes, above its charge of {PER_RECEIVER_BYTES}"
    );
    drop(batches);
}
