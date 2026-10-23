//! The API serves what the operator's relays signed, the newest of each receiver, and ranks it:
//! nothing else counts, and the same records in any order give the same board.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use super::*;
use tally_wire::clocks::recorded::judged;
use tally_wire::{FeederFiguresContent, Identity, Location};

/// An hour's start: figures are issued at one (`tally_wire::FIGURES_BUCKET_MS`).
pub(crate) const T: u64 = 497_561 * H;
/// The bucket figures are counted and issued in.
pub(crate) const H: u64 = tally_wire::FIGURES_BUCKET_MS;

pub(crate) fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}

/// The relay the operator names.
pub(crate) fn relay() -> Identity {
    identity(20)
}

/// The public cell of a receiver near 37.5, -122.25.
fn cell() -> Region {
    Region::public_cell(&Location {
        lat_e7: 375_000_000,
        lon_e7: -1_222_500_000,
        alt_m: 0,
        precision_m: 0,
    })
    .unwrap_or_else(|error| panic!("{error}"))
}

fn figure(seed: u8, cell: Option<Region>) -> FeederFigure {
    FeederFigure {
        receiver: identity(seed).public(),
        cell,
        uptime_permille: 1000,
        messages: 1,
        aircraft: 1,
        range_m: None,
        coverage_dkm2: 2640,
        unique_coverage_dkm2: 0,
        mlat_positions: 1,
        standing: false,
    }
}

/// `signer`'s record of `feeders`, issued at `issued_ms` (an hour's start) over the hour before.
pub(crate) fn signed(
    signer: &Identity,
    issued_ms: u64,
    mut feeders: Vec<FeederFigure>,
) -> FeederFigures {
    feeders.sort_by_key(|figure| *figure.receiver.as_bytes());
    let area = feeders
        .first()
        .and_then(|figure| figure.cell)
        .and_then(tally_wire::rendezvous::area_of_public);
    FeederFigures::sign(
        signer,
        &FeederFiguresContent {
            issued_ms,
            window_for_ms: H,
            area,
            feeders,
        },
    )
    .unwrap_or_else(|error| panic!("{error}"))
}

/// Feeders A (7) and B (8), placed and with standing, and C (9), which names no cell; one
/// relay's two records, a minute into its window.
pub(crate) fn records() -> Vec<FeederFigures> {
    let a = FeederFigure {
        messages: 4,
        aircraft: 2,
        range_m: Some(164_133),
        coverage_dkm2: 7895,
        unique_coverage_dkm2: 2632,
        standing: true,
        ..figure(7, Some(cell()))
    };
    let b = FeederFigure {
        messages: 2,
        aircraft: 2,
        range_m: Some(12_000),
        coverage_dkm2: 5263,
        unique_coverage_dkm2: 0,
        standing: true,
        ..figure(8, Some(cell()))
    };
    vec![
        signed(&relay(), T + H, vec![a, b]),
        signed(&relay(), T + H, vec![figure(9, None)]),
    ]
}

/// A ledger trusting the relay, having read `records` at `T` and a minute.
pub(crate) fn ledger(records: &[FeederFigures]) -> Ledger {
    let mut ledger = Ledger::trusting([relay().public()]);
    for record in records {
        ledger.ingest(record, crate::mlat::Now::at(T + H, true));
    }
    ledger
}

fn stats(board: &Board, seed: u8) -> FeederStats {
    board
        .feeder(&identity(seed).public())
        .unwrap_or_else(|| panic!("no figures of {seed}"))
}

#[test]
fn each_figure_is_what_the_relay_signed() {
    let board = ledger(&records()).board(judged(T + H));
    let a = stats(&board, 7);
    assert_eq!(
        (a.messages, a.aircraft, a.range_m, a.mlat_positions),
        (4, 2, Some(164_133.0), 1)
    );
    assert_eq!((a.coverage_km2, a.unique_coverage_km2), (789.5, 263.2));
    assert_eq!(a.uptime, 1.0);
    assert!((a.messages_per_sec - 4.0 / 3600.0).abs() < 1e-12);
    let area =
        tally_wire::rendezvous::area_of_public(cell()).map(|area| format!("{:x}", area.as_u64()));
    assert_eq!(a.area, area);
    let c = stats(&board, 9);
    assert_eq!((c.area, c.standing, c.ranks), (None, false, None));
}

#[test]
fn the_same_records_in_another_order_give_the_same_board() {
    let mut reversed = records();
    reversed.reverse();
    assert_eq!(
        ledger(&records()).board(judged(T + H)),
        ledger(&reversed).board(judged(T + H))
    );
}

/// Only receivers the relay says have standing are ranked, by what only they add.
#[test]
fn only_feeders_with_standing_are_ranked() -> Result<(), String> {
    let board = ledger(&records()).board(judged(T + H));
    let ranks = stats(&board, 7).ranks.ok_or("a unranked")?;
    assert_eq!((ranks.unique_coverage, ranks.mlat, ranks.of), (1, 1, 2));
    assert_eq!(
        stats(&board, 8).ranks.ok_or("b unranked")?.unique_coverage,
        2
    );
    let listed = board.leaderboards();
    assert_eq!(listed.areas.len(), 1);
    assert_eq!(listed.areas[0].ranked, 2);
    Ok(())
}

/// `records`, with A's and B's standing as `a` and `b` say.
pub(crate) fn records_standing(a: bool, b: bool) -> Vec<FeederFigures> {
    let mut records = records();
    let mut content = records[0]
        .content()
        .unwrap_or_else(|error| panic!("{error}"));
    for figure in &mut content.feeders {
        figure.standing = if figure.receiver == identity(7).public() {
            a
        } else {
            b
        };
    }
    records[0] = signed(&relay(), content.issued_ms, content.feeders);
    records
}

/// An area too new for standing is listed all the same: its receivers counted, none ranked, each
/// of them unranked. C names no cell, so no area holds it.
#[test]
fn an_area_with_feeders_but_none_ranked_is_listed_with_its_receivers() -> Result<(), String> {
    let board = ledger(&records_standing(false, false)).board(judged(T + H));
    let named = stats(&board, 7).area.ok_or("no area")?;
    let listed = board.leaderboards();
    assert_eq!(listed.areas.len(), 1);
    let only = &listed.areas[0];
    assert_eq!(
        (only.area.as_str(), only.ranked, only.receivers),
        (named.as_str(), 0, 2)
    );
    let area = parse_area(&named).ok_or("not an area")?;
    let boards = board.leaderboard(&area).ok_or("no board")?;
    assert_eq!((boards.ranked, boards.receivers), (0, 2));
    assert!(boards.by_unique_coverage.is_empty() && boards.by_mlat.is_empty());
    let mut keys = [stats(&board, 7).key, stats(&board, 8).key];
    keys.sort();
    let unranked: Vec<&str> = boards.unranked.iter().map(|one| one.key.as_str()).collect();
    assert_eq!(unranked, keys);
    Ok(())
}

/// `unranked` is exactly the area's feeders without standing: a ranked feeder is never in it.
#[test]
fn unranked_lists_exactly_the_feeders_without_standing() -> Result<(), String> {
    let board = ledger(&records_standing(true, false)).board(judged(T + H));
    let (a, b) = (stats(&board, 7), stats(&board, 8));
    let area = parse_area(a.area.as_deref().ok_or("no area")?).ok_or("not an area")?;
    let boards = board.leaderboard(&area).ok_or("no board")?;
    assert_eq!((boards.ranked, boards.receivers), (1, 2));
    assert_eq!(boards.unranked, vec![UnrankedFeeder { key: b.key }]);
    for entry in boards.by_unique_coverage.iter().chain(&boards.by_mlat) {
        assert!(boards.unranked.iter().all(|one| one.key != entry.key));
    }
    assert_eq!(boards.by_unique_coverage[0].key, a.key);
    // With standing for both, nobody is unranked.
    let both = ledger(&records()).board(judged(T + H));
    let boards = both.leaderboard(&area).ok_or("no board")?;
    assert_eq!((boards.ranked, boards.receivers), (2, 2));
    assert!(boards.unranked.is_empty());
    Ok(())
}

/// Areas are listed the most ranked first, then the most feeders, then by area.
#[test]
fn areas_are_listed_by_ranked_then_receivers() -> Result<(), String> {
    let far_cell = Region::public_cell(&Location {
        lat_e7: 515_000_000,
        lon_e7: -1_000_000,
        alt_m: 0,
        precision_m: 0,
    })
    .map_err(|error| error.to_string())?;
    let far = |standing| {
        signed(
            &relay(),
            T + H,
            vec![FeederFigure {
                standing,
                ..figure(10, Some(far_cell))
            }],
        )
    };
    // Nobody ranked: A's and B's area holds two receivers, D's one.
    let mut unranked = records_standing(false, false);
    unranked.push(far(false));
    let board = ledger(&unranked).board(judged(T + H));
    let listed: Vec<(u32, u32)> = board
        .leaderboards()
        .areas
        .iter()
        .map(|area| (area.ranked, area.receivers))
        .collect();
    assert_eq!(listed, [(0, 2), (0, 1)]);
    // D ranked: its area of one comes first.
    let mut d_ranked = records_standing(false, false);
    d_ranked.push(far(true));
    let board = ledger(&d_ranked).board(judged(T + H));
    let listed = board.leaderboards();
    assert_eq!(
        Some(listed.areas[0].area.clone()),
        tally_wire::rendezvous::area_of_public(far_cell).map(|area| format!("{:x}", area.as_u64()))
    );
    assert_eq!((listed.areas[1].ranked, listed.areas[1].receivers), (0, 2));
    Ok(())
}

/// A record that does not verify, one another key signed, one dated past the clock, or one too
/// old counts for nothing.
#[test]
fn only_the_operators_relays_fresh_signed_figures_count() {
    let mut ledger = Ledger::trusting([relay().public()]);
    let stranger = signed(&identity(21), T, vec![figure(7, None)]);
    ledger.ingest(&stranger, crate::mlat::Now::at(T, true));
    let ahead = signed(&relay(), T + H, vec![figure(7, None)]);
    const {
        assert!(
            H > tally_wire::budget::K
                .span::<tally_wire::clocks::Judged>()
                .ms()
        )
    };
    ledger.ingest(&ahead, crate::mlat::Now::at(T, true));
    let old = signed(&relay(), T - 2 * STALE_MS - H, vec![figure(7, None)]);
    ledger.ingest(&old, crate::mlat::Now::at(T, true));
    let mut bytes = signed(&relay(), T, vec![figure(7, None)])
        .as_bytes()
        .to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    if let Ok(forged) = FeederFigures::from_bytes(bytes) {
        ledger.ingest(&forged, crate::mlat::Now::at(T, true));
    }
    assert_eq!(ledger.board(judged(T)).feeder(&identity(7).public()), None);
}

/// A figure is judged ahead by the error budget's one tolerance between two judging clocks
/// (`tally_wire::budget::K`): one issued `K` ahead of the API's clock is taken, one a
/// millisecond further is not. Before, a bound of the API's own (120 s) took records a relay's
/// clock could never have issued.
#[test]
fn a_figure_is_judged_ahead_by_the_budget() {
    let k = tally_wire::budget::K
        .span::<tally_wire::clocks::Judged>()
        .ms();
    let mut ledger = Ledger::trusting([relay().public()]);
    // Issued as of an hour's start (`H`), read by an API clock just before it.
    let issued = T + H;
    ledger.ingest(
        &signed(&relay(), issued, vec![figure(7, None)]),
        crate::mlat::Now::at(issued - k - 1, true),
    );
    assert_eq!(
        ledger.board(judged(issued)).feeder(&identity(7).public()),
        None
    );
    ledger.ingest(
        &signed(&relay(), issued, vec![figure(7, None)]),
        crate::mlat::Now::at(issued - k, true),
    );
    assert!(
        ledger
            .board(judged(issued))
            .feeder(&identity(7).public())
            .is_some()
    );
}

/// The newest record of a receiver stands, from whichever of the operator's relays signed it; at
/// one instant, the lesser key's.
#[test]
fn a_receivers_newest_figure_stands() {
    let (one, two) = (identity(20), identity(21));
    let mut ledger = Ledger::trusting([one.public(), two.public()]);
    let with = |messages| FeederFigure {
        messages,
        ..figure(7, None)
    };
    ledger.ingest(
        &signed(&one, T + H, vec![with(5)]),
        crate::mlat::Now::at(T + H, true),
    );
    ledger.ingest(
        &signed(&two, T, vec![with(9)]),
        crate::mlat::Now::at(T + H, true),
    );
    assert_eq!(stats(&ledger.board(judged(T + H)), 7).messages, 5);
    ledger.ingest(
        &signed(&two, T + 2 * H, vec![with(9)]),
        crate::mlat::Now::at(T + 2 * H, true),
    );
    assert_eq!(stats(&ledger.board(judged(T + 2 * H)), 7).messages, 9);
    let lesser = if one.public().as_bytes() < two.public().as_bytes() {
        &one
    } else {
        &two
    };
    let expect = if std::ptr::eq(lesser, &one) { 3 } else { 4 };
    ledger.ingest(
        &signed(&one, T + 3 * H, vec![with(3)]),
        crate::mlat::Now::at(T + 3 * H, true),
    );
    ledger.ingest(
        &signed(&two, T + 3 * H, vec![with(4)]),
        crate::mlat::Now::at(T + 3 * H, true),
    );
    assert_eq!(stats(&ledger.board(judged(T + 3 * H)), 7).messages, expect);
}

#[test]
fn a_figure_not_reissued_is_forgotten() {
    let mut ledger = ledger(&records());
    assert!(
        ledger
            .board(judged(T + H + STALE_MS))
            .feeder(&identity(7).public())
            .is_some()
    );
    assert_eq!(
        ledger
            .board(judged(T + H + 1 + STALE_MS))
            .feeder(&identity(7).public()),
        None
    );
}

#[test]
fn a_path_names_an_area_only_at_the_area_resolution() {
    let area = tally_wire::rendezvous::area_of_public(cell())
        .map(|area| format!("{:x}", area.as_u64()))
        .unwrap_or_default();
    assert!(parse_area(&area).is_some());
    assert!(parse_area(&format!("{:x}", cell().as_u64())).is_none());
    assert!(parse_area("not a cell").is_none());
}
