//! The figures are a function of the records: the same records, in any order across receivers,
//! give the same board, and each figure counts what its definition says and nothing else.

use super::*;
use tally_wire::{
    AddressedCitation, BatchContent, EnuCovariance, Identity, Observation, ObservationSet,
    Reception, Solution, SolutionsContent, TransmitTime,
};

pub(crate) const T: u64 = 1_791_220_000_000;

pub(crate) fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}

fn df17(address: u32, me: [u8; 7]) -> Vec<u8> {
    let mut body = vec![
        (17 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    body.extend_from_slice(&me);
    modes::with_parity(&body, 0)
}

pub(crate) fn df11(address: u32) -> Vec<u8> {
    let body = [
        (11 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    modes::with_parity(&body, 0)
}

/// An airborne position of `address` at `place`, even or odd.
pub(crate) fn airborne(address: u32, place: LatLon, odd: bool) -> Vec<u8> {
    let (lat, lon) = modes::cpr_encode(
        modes::LatLon {
            lat_deg: place.lat,
            lon_deg: place.lon,
        },
        odd,
    );
    df17(
        address,
        modes::encode_airborne_position(11, 0x0c38, odd, lat, lon),
    )
}

pub(crate) fn batch(who: &Identity, sequence: u64, wall_ms: u64, messages: &[Vec<u8>]) -> Record {
    let observations = messages
        .iter()
        .enumerate()
        .map(|(n, data)| Observation {
            format: if data.len() == 14 { b'3' } else { b'2' },
            timestamp: 1_000 + n as u64,
            signal: 100,
            data: data.clone(),
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
    match Batch::sign(who, &content) {
        Ok(batch) => Record::Batch(batch),
        Err(error) => panic!("{error}"),
    }
}

/// A final position of `address` at `place`, at `at_ms`, citing one reception of each receiver.
pub(crate) fn position(
    engine: &Identity,
    sequence: u64,
    address: u32,
    place: LatLon,
    at_ms: u64,
    receivers: &[&Identity],
) -> Record {
    let receptions = receivers
        .iter()
        .enumerate()
        .map(|(n, who)| Reception {
            receiver: who.public(),
            epoch: 0,
            counter: 5_000 + n as u64,
        })
        .collect();
    let observations = match ObservationSet::new(df11(address), receptions) {
        Ok(set) => set,
        Err(error) => panic!("{error}"),
    };
    let solution = Solution {
        address,
        transmitted: TransmitTime {
            unix_ms: at_ms,
            sub_ms_ps: 0,
        },
        lat_e7: (place.lat * 1e7).round() as i32,
        lon_e7: (place.lon * 1e7).round() as i32,
        alt_hae_mm: None,
        covariance: EnuCovariance {
            xx: 100.0,
            xy: 0.0,
            xz: 0.0,
            yy: 100.0,
            yz: 0.0,
            zz: 100.0,
        },
        clock_model: [1; 32],
        addressed: AddressedCitation {
            hash: [2; 32],
            count: 3,
        },
        observations,
    };
    let content = SolutionsContent {
        boot_id: 9,
        sequence,
        issued_ms: at_ms,
        spec_version: 3,
        solutions: vec![solution],
    };
    match Positions::sign_solutions(engine, &content) {
        Ok(positions) => Record::Positions(positions),
        Err(error) => panic!("{error}"),
    }
}

pub(crate) const A_AT: LatLon = LatLon {
    lat: 37.5,
    lon: -122.25,
};
pub(crate) const B_AT: LatLon = LatLon {
    lat: 37.52,
    lon: -122.22,
};
/// Heard by A, and by B in a checked format at the same second: shared.
pub(crate) const X: (u32, LatLon) = (
    0xa1b2c3,
    LatLon {
        lat: 37.9,
        lon: -122.4,
    },
);
/// Heard by A alone.
pub(crate) const Y: (u32, LatLon) = (
    0xabcdef,
    LatLon {
        lat: 38.6,
        lon: -121.0,
    },
);
/// Solved by MLAT from A's, B's and C's receptions.
pub(crate) const Z: (u32, LatLon) = (
    0xc0ffee,
    LatLon {
        lat: 37.6,
        lon: -122.1,
    },
);

/// Feeders A and B (located) and C (unlocated), and two MLAT relays publishing the same position.
pub(crate) fn records() -> Vec<Record> {
    let (a, b, c) = (identity(7), identity(8), identity(9));
    let (one, two) = (identity(20), identity(21));
    vec![
        batch(
            &a,
            0,
            T,
            &[airborne(X.0, X.1, false), airborne(Y.0, Y.1, false)],
        ),
        batch(
            &a,
            1,
            T + 1_000,
            &[airborne(X.0, X.1, true), airborne(Y.0, Y.1, true)],
        ),
        batch(&b, 0, T + 1_000, &[df11(X.0), df11(X.0), df11(Z.0)]),
        batch(&c, 0, T + 2_000, &[df11(Z.0)]),
        position(&one, 0, Z.0, Z.1, T + 2_000, &[&a, &b, &c]),
        position(&two, 0, Z.0, Z.1, T + 2_000, &[&a, &b, &c]),
    ]
}

/// The merge's verdict, as a test states it: whether it accepts every final position, and whose
/// receptions its raw holds.
pub(crate) struct Says {
    pub accepts: bool,
    pub raw_of: fn(&PublicKey) -> bool,
}

impl Verdict for Says {
    fn accepted(&self, _: &Solution) -> bool {
        self.accepts
    }

    fn heard(&self, reception: &Reception, _: &[u8], _: u64) -> bool {
        (self.raw_of)(&reception.receiver)
    }
}

/// A merge that accepts every position and holds every receiver's raw.
pub(crate) const ALL: Says = Says {
    accepts: true,
    raw_of: |_| true,
};

pub(crate) fn ledger_by(records: &[Record], verdict: &Says) -> Ledger {
    let mut ledger = Ledger::default();
    ledger.locate([(identity(7).public(), A_AT), (identity(8).public(), B_AT)]);
    for record in records {
        ledger.ingest(record, T + 2_000, verdict);
    }
    ledger
}

pub(crate) fn ledger(records: &[Record]) -> Ledger {
    ledger_by(records, &ALL)
}

pub(crate) fn standing(key: &PublicKey) -> bool {
    *key == identity(7).public() || *key == identity(8).public()
}

fn cell_km2(place: LatLon) -> f64 {
    place
        .cell(COVERAGE_RESOLUTION)
        .map_or(0.0, CellIndex::area_km2)
}

fn stats(board: &Board, seed: u8) -> FeederStats {
    match board.feeder(&identity(seed).public()) {
        Some(stats) => stats,
        None => panic!("no stats for {seed}"),
    }
}

/// A feeder's area is the network's own (`area_at`), named as a path names it.
#[test]
fn a_feeders_area_is_the_networks_area() -> Result<(), String> {
    let board = ledger(&records()).board(T + 60_000, standing);
    let named = stats(&board, 7).area.ok_or("no area")?;
    let area = area_at(A_AT.lat, A_AT.lon).map_err(|error| error.to_string())?;
    assert_eq!(named, format!("{:x}", area.as_u64()));
    let cell = parse_area(&named).ok_or("not an area")?;
    assert_eq!(u64::from(cell), area.as_u64());
    Ok(())
}

#[test]
fn each_figure_counts_what_it_says() {
    let board = ledger(&records()).board(T + 60_000, standing);
    let a = stats(&board, 7);
    // A's pair of X and of Y, B's two of X and one of Z, C's one of Z.
    assert_eq!((a.messages, a.aircraft, a.mlat_positions), (4, 2, 1));
    let b = stats(&board, 8);
    assert_eq!((b.messages, b.aircraft, b.mlat_positions), (3, 2, 1));
    // X's cell is heard by A and B, Z's by all three; Y's by A alone.
    let x_y_z = cell_km2(X.1) + cell_km2(Y.1) + cell_km2(Z.1);
    assert!((a.coverage_km2 - tenths(x_y_z)).abs() < 1e-9);
    assert!((a.unique_coverage_km2 - tenths(cell_km2(Y.1))).abs() < 1e-9);
    assert!(b.unique_coverage_km2 == 0.0 && b.coverage_km2 > 0.0);
    // A's farthest is Y, about 160 km off; C states no place, so it has no range and no area.
    let y_range = A_AT.distance_m(Y.1);
    assert!(
        a.range_m
            .is_some_and(|range| (range - y_range).abs() < 1_000.0)
    );
    let c = stats(&board, 9);
    assert_eq!((c.range_m, c.area.as_deref(), c.ranks), (None, None, None));
    assert_eq!(c.mlat_positions, 1);
    // The window began with the first record.
    assert_eq!(board.window_for_ms, 60_000);
    assert!((a.uptime - 1.0).abs() < 1e-9);
}

#[test]
fn the_same_records_in_another_order_give_the_same_board() {
    let records = records();
    // Across receivers and relays in any order; A's own two batches keep theirs.
    let ordered: Vec<Record> = [4, 3, 0, 5, 2, 1]
        .into_iter()
        .map(|n| records[n].clone())
        .collect();
    assert_eq!(
        ledger(&records).board(T + 60_000, standing),
        ledger(&ordered).board(T + 60_000, standing)
    );
}

#[test]
fn only_feeders_with_standing_are_ranked_and_by_what_only_they_add() -> Result<(), String> {
    let board = ledger(&records()).board(T + 60_000, standing);
    let (a, b) = (stats(&board, 7), stats(&board, 8));
    assert_eq!(a.area, b.area, "A and B share an area");
    let area = parse_area(a.area.as_deref().ok_or("no area")?).ok_or("not an area")?;
    // A adds sky no one else hears; their MLAT help ties, so unique coverage breaks it.
    assert_eq!(
        a.ranks,
        Some(Ranks {
            unique_coverage: 1,
            mlat: 1,
            of: 2
        })
    );
    assert_eq!(b.ranks.map(|r| (r.unique_coverage, r.mlat)), Some((2, 2)));
    let boards = board.leaderboard(&area).ok_or("no board")?;
    assert_eq!(boards.ranked, 2);
    assert_eq!(boards.by_unique_coverage[0].key, a.key);
    let listed = board.leaderboards();
    assert_eq!(listed.areas.len(), 1);
    assert_eq!(listed.areas[0].area, area.to_string());
    // Without standing, nobody is ranked anywhere.
    let none = ledger(&records()).board(T + 60_000, |_| false);
    assert!(none.leaderboards().areas.is_empty() && stats(&none, 7).ranks.is_none());
    assert!(!stats(&none, 7).standing);
    Ok(())
}

#[test]
fn a_late_or_stale_or_unaccepted_record_counts_for_nothing() {
    let (a, one) = (identity(7), identity(20));
    let mut ledger = Ledger::default();
    // A batch whose clock is three minutes from the API's.
    ledger.ingest(&batch(&a, 0, T - 180_000, &[df11(X.0)]), T, &ALL);
    // A position the merge did not accept (a convicted signer's, say).
    let refused = Says {
        accepts: false,
        raw_of: |_| true,
    };
    ledger.ingest(&position(&one, 0, Z.0, Z.1, T, &[&a]), T, &refused);
    let board = ledger.board(T + 60_000, |_| true);
    assert!(board.feeder(&a.public()).is_none());
    // A reception for a second already settled counts as a message, not as coverage.
    let mut ledger = Ledger::default();
    ledger.ingest(&batch(&a, 0, T, &[df11(X.0)]), T, &ALL);
    ledger.settle(T + 60_000);
    ledger.ingest(&position(&one, 0, X.0, X.1, T, &[&a]), T + 60_000, &ALL);
    let board = ledger.board(T + 90_000, |_| true);
    let late = stats(&board, 7);
    assert_eq!((late.messages, late.mlat_positions), (1, 1));
    assert_eq!(late.coverage_km2, 0.0);
}

#[test]
fn uptime_is_the_share_of_minutes_with_a_batch() {
    let a = identity(7);
    let mut ledger = Ledger::default();
    for (sequence, minute) in [(0, 0), (1, 2)] {
        let at = T + minute * 60_000;
        ledger.ingest(&batch(&a, sequence, at, &[df11(X.0)]), at, &ALL);
    }
    let board = ledger.board(T + 4 * 60_000, |_| false);
    let stats = stats(&board, 7);
    // Four minutes since the first batch, two of them with one.
    assert!((stats.uptime - 0.5).abs() < 1e-9, "{}", stats.uptime);
    assert!((stats.messages_per_sec - 2.0 / 240.0).abs() < 1e-12);
}

#[test]
fn the_window_forgets_a_day_old_feeder() {
    let a = identity(7);
    let mut ledger = Ledger::default();
    ledger.ingest(&batch(&a, 0, T, &[df11(X.0)]), T, &ALL);
    let board = ledger.board(T + (WINDOW_HOURS + 1) * HOUR_MS, |_| true);
    assert!(board.feeder(&a.public()).is_none());
}

/// MLAT help and coverage come only from what the merge accepted, and only for a reception the
/// receiver's own signed raw holds: a position the merge refused places nothing and credits no
/// one, and a key cited for a reception it never published earns neither.
#[test]
fn mlat_credits_only_accepted_fixes_and_receptions_in_the_receivers_own_raw() {
    let only_a_and_b = Says {
        accepts: true,
        raw_of: |key| *key == identity(7).public() || *key == identity(8).public(),
    };
    let board = ledger_by(&records(), &only_a_and_b).board(T + 60_000, standing);
    assert_eq!(stats(&board, 7).mlat_positions, 1);
    // C's reception is not in its raw as the merge holds it: no MLAT help. (It still covers Z's
    // cell: its own batch heard Z, which the accepted fix places.)
    assert_eq!(stats(&board, 9).mlat_positions, 0);
    let refused = Says {
        accepts: false,
        raw_of: |_| true,
    };
    let board = ledger_by(&records(), &refused).board(T + 60_000, standing);
    for seed in [7, 8, 9] {
        assert_eq!(stats(&board, seed).mlat_positions, 0, "{seed}");
    }
    // Z is placed by MLAT alone: refused, its cell is nobody's, and A covers X's and Y's only.
    let a = stats(&board, 7);
    assert!((a.coverage_km2 - tenths(cell_km2(X.1) + cell_km2(Y.1))).abs() < 1e-9);
}

/// A row is a receiver's own batches': a position citing a key that never published one makes
/// no row, so no figure and no rank.
#[test]
fn a_citation_never_makes_a_row() {
    let (a, ghost, one) = (identity(7), identity(30), identity(20));
    let mut ledger = Ledger::default();
    ledger.ingest(&batch(&a, 0, T, &[df11(Z.0)]), T, &ALL);
    ledger.ingest(&position(&one, 0, Z.0, Z.1, T, &[&a, &ghost]), T, &ALL);
    let board = ledger.board(T + 60_000, |_| true);
    assert!(board.feeder(&ghost.public()).is_none());
    assert_eq!(stats(&board, 7).mlat_positions, 1);
}

#[test]
fn a_path_names_an_area_only_at_the_area_resolution() {
    let area = area_name(A_AT);
    assert!(area.as_deref().and_then(parse_area).is_some());
    let fine = A_AT.cell(COVERAGE_RESOLUTION).map(|cell| cell.to_string());
    assert!(fine.as_deref().and_then(parse_area).is_none());
    assert!(parse_area("not-a-cell").is_none());
}
