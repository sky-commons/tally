//! The positions checks' twins cost no more than the store they are charged to (RFC-0181, "The
//! positions checks"; `consistency::Caps::twins_bytes`, `budget::Store::Twins`): one raw record a
//! link (RFC-0174 §2.4, decision D5), each the largest positions record, filled past the links
//! planned by more links than that, each sending record after record, so a link's next record
//! takes the place of its last and a link past the plan lets the least recently active one go,
//! counted. Measured by an allocator that counts every byte asked of it, in one test so nothing
//! else in the binary allocates while it measures.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use std::sync::Arc;

use tally_relay::consistency::{Caps, Consistency, ConsistencyReport, Sizing, WORKING_BYTES};
use tally_relay::models::Models;
use tally_wire::{Identity, Positions};

#[global_allocator]
static GLOBAL: tally_counting::CountingAll = tally_counting::CountingAll;

/// The most the twins' plan may be above what they hold at rest, filled: each record planned at
/// the largest positions record, held at its own bytes a little below it, and the links' table
/// made at an eighth more than its keys.
const SLACK_PERCENT: usize = 125;

/// The links the twins are planned for here.
const LINKS: usize = 4;

/// The records each link sends in turn: its next takes the place of its last.
const RECORDS_PER_LINK: u64 = 3;

/// A raw record of `count` fixes of `receptions` receptions each, of aircraft `first..`, sent on
/// link `link` (its sequence), all cited by receivers the record's table holds once.
fn record(link: u64, sequence: u64, count: u32, receptions: u8) -> Result<Positions, String> {
    let receivers: Vec<_> = (0..receptions)
        .map(|at| Identity::from_seed([at.wrapping_add(100); 32]).public())
        .collect();
    let fixes = (0..count)
        .map(|address| {
            let set = tally_wire::ObservationSet::new(
                Vec::new(),
                receivers
                    .iter()
                    .map(|receiver| tally_wire::Reception {
                        receiver: *receiver,
                        epoch: 0,
                        counter: u64::from(address),
                    })
                    .collect(),
            )
            .map_err(|e| e.to_string())?;
            Ok(tally_wire::Fix {
                address,
                transmitted: tally_wire::TransmitTime::new(1_000, 0).map_err(|e| e.to_string())?,
                lat_e7: 374_000_000,
                lon_e7: -1_221_000_000,
                alt_hae_mm: None,
                covariance: tally_wire::EnuCovariance {
                    xx: 1.0,
                    xy: 0.0,
                    xz: 0.0,
                    yy: 1.0,
                    yz: 0.0,
                    zz: 1.0,
                },
                models: vec![[7; 32]],
                sets: tally_wire::FixSets::new(set.clone(), set).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Positions::sign_fix(
        &Identity::from_seed([9; 32]),
        &tally_wire::FixesContent {
            boot_id: link,
            sequence,
            issued_ms: 1,
            spec_version: 1,
            fixes,
        },
    )
    .map_err(|e| e.to_string())
}

/// The most fixes of `receptions` receptions a record carries inside the largest positions record.
fn most_fixes(receptions: u8) -> Result<u32, String> {
    let mut count = 1;
    while record(0, 0, count + 1, receptions).is_ok_and(|positions| {
        positions.as_bytes().len() <= tally_wire::positions::MAX_POSITIONS_LEN
    }) {
        count += 1;
    }
    Ok(count)
}

/// What `links` links each sending [`RECORDS_PER_LINK`] records of `count` fixes of `receptions`
/// receptions in turn allocate in checks of `caps`: at their peak, and held at rest once sent.
fn filled(
    caps: Caps,
    links: usize,
    count: u32,
    receptions: u8,
) -> Result<(usize, usize, ConsistencyReport), String> {
    let made = (0..RECORDS_PER_LINK)
        .flat_map(|sequence| (0..links as u64).map(move |link| (link, sequence)))
        .map(|(link, sequence)| Ok((link, record(link, sequence, count, receptions)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let models = Arc::new(Models::new());
    let mark = tally_counting::CountingAll::peak_base();
    let base = tally_counting::CountingAll::live();
    let rest;
    let report;
    {
        let checks = Consistency::with_caps(models, caps);
        for (link, positions) in &made {
            checks.raw(positions, *link);
        }
        rest = usize::try_from(tally_counting::CountingAll::since(base)).unwrap_or(usize::MAX);
        report = checks.report();
    }
    let peak = usize::try_from(tally_counting::CountingAll::peak_since(mark)).unwrap_or(0);
    Ok((peak, rest, report))
}

/// Holds one fill to the plan of `caps`: the links past the plan let go, counted, the peak within
/// the plan, at rest within its tables, and the tables no looser than the slack.
fn within(caps: Caps, (peak, rest, report): (usize, usize, ConsistencyReport), what: &str) {
    let planned = caps.twins_bytes() + caps.sites_bytes();
    let tables = planned - WORKING_BYTES;
    println!("{what}: {peak} at the peak, {rest} at rest, {planned} planned: {report:?} {caps:?}");
    assert!(report.evicted > 0 && report.held > 0, "{what}: {report:?}");
    assert!(
        peak <= planned,
        "{what}: {peak} at the peak, {planned} planned"
    );
    assert!(
        rest <= tables,
        "{what}: {rest} at rest, the tables {tables}"
    );
    assert!(
        tables * 100 <= rest * SLACK_PERCENT,
        "{what}: the plan is loose: {rest} at rest, the tables {tables}"
    );
}

#[test]
fn the_twins_allocate_no_more_than_they_are_charged() -> Result<(), String> {
    let caps = Caps::of(Sizing {
        receivers: 0,
        links: LINKS,
    });
    // Twice the links planned, so the table is full and lets go of the least recently active.
    let links = 2 * caps.links;
    // The largest positions records, of fixes cited by one reception (the most fixes) and by
    // many (the most receptions): a record held is its bytes, whatever it carries.
    for receptions in [1, 40] {
        let count = most_fixes(receptions)?;
        within(
            caps,
            filled(caps, links, count, receptions)?,
            &format!("{count} fixes of {receptions} receptions"),
        );
    }
    Ok(())
}
