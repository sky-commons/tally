//! The figures count what their definitions say, from the relay-only records a relay holds, and
//! sign nothing a site can be read from.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use super::*;
use tally_wire::Identity;
use tally_wire::clocks::recorded::{aligned, judged};
use tally_wire::rendezvous::AREA_RESOLUTION;
use tally_wire::{
    BatchContent, EnuCovariance, Fix, FixSets, FixesContent, Location, Observation, ObservationSet,
    Reception, TransmitTime,
};

const T: u64 = 1_791_220_000_000;
/// A minute into the hour after `T`'s: when the figures of `T`'s hour are first signed.
const NEXT_HOUR: u64 = (T / HOUR_MS + 1) * HOUR_MS + 60_000;

fn identity(seed: u8) -> Identity {
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

fn df11(address: u32) -> Vec<u8> {
    let body = [
        (11 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    modes::with_parity(&body, 0)
}

/// An airborne position of `address` at `place`, even or odd.
fn airborne(address: u32, place: LatLon, odd: bool) -> Vec<u8> {
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

fn batch(who: &Identity, sequence: u64, wall_ms: u64, messages: &[Vec<u8>]) -> Arc<Decoded> {
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
    let batch = crate::anchors::anchored(who, &content).unwrap_or_else(|error| panic!("{error}"));
    Decoded::from_verified(batch, aligned(wall_ms), sequence)
        .unwrap_or_else(|error| panic!("{error:?}"))
}

/// An ACARS-family message's batch, which no figure counts.
fn acars(who: &Identity, sequence: u64, wall_ms: u64) -> Arc<Decoded> {
    let content = BatchContent {
        boot_id: 1,
        sequence,
        counter_epoch: 0,
        wall_ms,
        dropped: 0,
        previous: [0; 32],
        observations: vec![Observation {
            format: tally_wire::batch::format::ACARS_JSON,
            timestamp: 5,
            signal: 0,
            data: br#"{"kind":"acars","label":"H1","t":1}"#.to_vec(),
        }],
    };
    let batch = crate::anchors::anchored(who, &content).unwrap_or_else(|error| panic!("{error}"));
    Decoded::from_verified(batch, aligned(wall_ms), sequence)
        .unwrap_or_else(|error| panic!("{error:?}"))
}

/// An MLAT fix of `address` at `place`, at `at_ms`, citing one reception of each receiver.
fn position(
    engine: &Identity,
    sequence: u64,
    address: u32,
    place: LatLon,
    at_ms: u64,
    receivers: &[&Identity],
) -> Positions {
    let receptions = receivers
        .iter()
        .enumerate()
        .map(|(n, who)| Reception {
            receiver: who.public(),
            epoch: 0,
            counter: 5_000 + n as u64,
        })
        .collect();
    let observations =
        ObservationSet::new(df11(address), receptions).unwrap_or_else(|error| panic!("{error}"));
    let fix = Fix {
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
        models: vec![[1; 32]],
        sets: FixSets::new(observations.clone(), observations)
            .unwrap_or_else(|error| panic!("{error}")),
    };
    let content = FixesContent {
        boot_id: 9,
        sequence,
        issued_ms: at_ms,
        spec_version: 7,
        fixes: vec![fix],
    };
    Positions::sign_fix(engine, &content).unwrap_or_else(|error| panic!("{error}"))
}

/// A site, exact: what no figure may carry or be measured from.
const A_SITE: LatLon = LatLon {
    lat: 37.512_345_6,
    lon: -122.251_234_5,
};
const B_SITE: LatLon = LatLon {
    lat: 37.52,
    lon: -122.22,
};
/// Heard by A, placed by its own pair, and by B in a checked format at the same second.
const X: (u32, LatLon) = (
    0xa1b2c3,
    LatLon {
        lat: 37.9,
        lon: -122.4,
    },
);
/// Heard by A alone.
const Y: (u32, LatLon) = (
    0xabcdef,
    LatLon {
        lat: 38.6,
        lon: -121.0,
    },
);
/// Solved by MLAT from A's, B's and C's receptions.
const Z: (u32, LatLon) = (
    0xc0ffee,
    LatLon {
        lat: 37.6,
        lon: -122.1,
    },
);

fn public(site: LatLon) -> Region {
    Region::public_cell(&Location {
        lat_e7: (site.lat * 1e7).round() as i32,
        lon_e7: (site.lon * 1e7).round() as i32,
        alt_m: 77,
        precision_m: 0,
    })
    .unwrap_or_else(|error| panic!("{error}"))
}

/// A and B feed, B an ACARS message too; C is cited by MLAT but never fed here; two engines
/// publish Z.
fn fed() -> Figures {
    let (a, b, c) = (identity(7), identity(8), identity(9));
    let figures = Figures::new();
    let now = T + 5_000;
    figures.batch(
        &batch(
            &a,
            0,
            T,
            &[
                airborne(X.0, X.1, false),
                airborne(X.0, X.1, true),
                airborne(Y.0, Y.1, false),
                airborne(Y.0, Y.1, true),
                df11(Z.0),
            ],
        ),
        Some(public(A_SITE)),
        judged(now),
    );
    figures.batch(
        &batch(&b, 0, T + 500, &[df11(X.0), df11(Z.0)]),
        Some(public(B_SITE)),
        judged(now),
    );
    figures.batch(&acars(&b, 1, T + 600), Some(public(B_SITE)), judged(now));
    for engine in [identity(20), identity(21)] {
        figures.positions(
            &position(&engine, 0, Z.0, Z.1, T + 1_000, &[&a, &b, &c]),
            judged(now),
        );
    }
    figures
}

fn figure_of(figures: &Figures, seed: u8) -> FeederFigure {
    let (_, _, areas) = figures.compute(judged(NEXT_HOUR), |_| true);
    let key = identity(seed).public();
    areas
        .values()
        .flat_map(|(_, figures)| figures.iter())
        .find(|figure| figure.receiver == key)
        .copied()
        .unwrap_or_else(|| panic!("no figure of {seed}"))
}

fn km2(place: LatLon) -> u32 {
    let area = place
        .cell(COVERAGE_RESOLUTION)
        .map_or(0.0, CellIndex::area_km2);
    (area * 10.0).round() as u32
}

#[test]
fn each_figure_counts_what_it_says() {
    let figures = fed();
    let a = figure_of(&figures, 7);
    assert_eq!(a.messages, 5);
    assert_eq!(a.aircraft, 3);
    assert_eq!(a.mlat_positions, 1, "two engines' one position counts once");
    // One minute with a batch, of the minutes from the first observed to the hour's end.
    let observed = (NEXT_HOUR / HOUR_MS * HOUR_MS - T).div_ceil(60_000);
    assert_eq!(u64::from(a.uptime_permille), 1000 / observed);
    assert_eq!(a.cell, Some(public(A_SITE)));
    // X, Y and Z's cells; Y's and Z's... only A placed Y.
    assert!(a.coverage_dkm2 >= km2(X.1) + km2(Y.1));
    assert!(a.unique_coverage_dkm2 >= km2(Y.1));
    let b = figure_of(&figures, 8);
    // Not its ACARS message: none of the products.
    assert_eq!(b.messages, 2);
    assert_eq!(b.aircraft, 2);
    assert_eq!(b.mlat_positions, 1);
    // B heard X near A's placing of it, and Z by MLAT: neither cell is B's alone.
    assert_eq!(b.unique_coverage_dkm2, 0);
    assert_eq!(b.coverage_dkm2, km2(X.1) + km2(Z.1));
}

/// The range is measured from the public cell's centre, never from the site.
#[test]
fn the_range_is_from_the_public_cell_never_the_site() {
    let figures = fed();
    let a = figure_of(&figures, 7);
    let centre = LatLon::centre_of(public(A_SITE)).unwrap_or_else(|| panic!("no centre"));
    let farthest = [X.1, Y.1, Z.1]
        .iter()
        .map(|place| centre.distance_m(*place))
        .fold(0.0, f64::max);
    assert_eq!(a.range_m, Some(farthest.round() as u32));
    let from_site = [X.1, Y.1, Z.1]
        .iter()
        .map(|place| A_SITE.distance_m(*place))
        .fold(0.0, f64::max);
    assert_ne!(a.range_m, Some(from_site.round() as u32));
}

/// A receiver an engine cites but whose batches never reached this relay gets no row, and one
/// that never heard the aircraft is not credited for it.
#[test]
fn a_citation_never_makes_a_row_nor_credits_an_aircraft_not_heard() {
    let figures = fed();
    let (_, _, areas) = figures.compute(judged(NEXT_HOUR), |_| true);
    let c = identity(9).public();
    assert!(
        areas
            .values()
            .all(|(_, figures)| figures.iter().all(|figure| figure.receiver != c))
    );
    let d = identity(10);
    figures.batch(
        &batch(&d, 0, T, &[df11(X.0)]),
        Some(public(B_SITE)),
        judged(T + 5_000),
    );
    figures.positions(
        &position(&identity(20), 1, 0x00_beef, Z.1, T + 2_000, &[&d]),
        judged(T + 5_000),
    );
    assert_eq!(figure_of(&figures, 10).mlat_positions, 0);
}

/// A row is made only within the store: past it a receiver is refused, counted.
#[test]
fn a_row_past_the_store_is_refused() {
    let figures = Figures::new();
    figures.charge_to(Gauge::new(Store::Figures, PER_RECEIVER_BYTES));
    figures.batch(&batch(&identity(7), 0, T, &[df11(X.0)]), None, judged(T));
    figures.batch(&batch(&identity(8), 0, T, &[df11(X.0)]), None, judged(T));
    assert_eq!(figures.rows(), 1);
    assert_eq!(figures.refused(), 1);
}

/// What is signed holds no byte of a site: no coordinate, no altitude, no finest cell.
#[test]
fn the_signed_figures_carry_no_site() -> Result<(), String> {
    let figures = fed();
    let relay = identity(30);
    let signed = figures.sign(&relay, judged(NEXT_HOUR), |_| true);
    assert!(!signed.is_empty());
    for record in signed {
        record.verify().map_err(|error| error.to_string())?;
        let bytes = record.as_bytes();
        for site in [A_SITE, B_SITE] {
            let location = Location {
                lat_e7: (site.lat * 1e7).round() as i32,
                lon_e7: (site.lon * 1e7).round() as i32,
                alt_m: 77,
                precision_m: 0,
            };
            let point = Region::point(&location).map_err(|error| error.to_string())?;
            for canary in [
                location.lat_e7.to_be_bytes().to_vec(),
                location.lon_e7.to_be_bytes().to_vec(),
                point.as_u64().to_be_bytes().to_vec(),
            ] {
                assert!(!bytes.windows(canary.len()).any(|window| window == canary));
            }
        }
        let content = record.content().map_err(|error| error.to_string())?;
        let area = content
            .area
            .ok_or("an unplaced record of placed receivers")?;
        assert_eq!(area.resolution(), AREA_RESOLUTION);
        // The one area rule: each receiver's public cell's parent, never the area its cell's
        // centre or its site lies in.
        for figure in &content.feeders {
            let cell = figure.cell.ok_or("a placed figure with no cell")?;
            assert_eq!(tally_wire::rendezvous::area_of_public(cell), Some(area));
        }
    }
    Ok(())
}

/// Figures are of whole hours, published once an hour as of its start: nothing of the hour now is
/// in them, two records signed within one hour are the same whatever was heard between, and the
/// finest a client can difference out of any two is an hour.
#[test]
fn figures_are_whole_hours_published_hourly() -> Result<(), String> {
    let text = |error: tally_wire::WireError| error.to_string();
    let figures = fed();
    let relay = identity(30);
    // Within the hour it was heard in: not yet.
    assert!(
        figures
            .sign(&relay, judged(T + 60_000), |_| true)
            .is_empty()
    );
    let first = figures.sign(&relay, judged(NEXT_HOUR), |_| true);
    assert!(!first.is_empty());
    let boundary = NEXT_HOUR / HOUR_MS * HOUR_MS;
    for record in &first {
        let content = record.content().map_err(text)?;
        assert_eq!(content.issued_ms, boundary);
        assert!(content.window_for_ms.is_multiple_of(HOUR_MS));
    }
    // More heard in the hour now: the hour's record is unchanged until it has passed.
    figures.batch(
        &batch(&identity(7), 1, NEXT_HOUR, &[df11(Y.0), df11(X.0)]),
        Some(public(A_SITE)),
        judged(NEXT_HOUR + 1_000),
    );
    let again = figures.sign(&relay, judged(NEXT_HOUR + 30 * 60_000), |_| true);
    let contents = |records: &[FeederFigures]| -> Result<Vec<_>, String> {
        records
            .iter()
            .map(|record| record.content().map_err(text))
            .collect()
    };
    assert_eq!(contents(&again)?, contents(&first)?);
    let later = figures.sign(&relay, judged(NEXT_HOUR + HOUR_MS), |_| true);
    assert_ne!(contents(&later)?, contents(&first)?);
    // Due once an hour, at the first tick of each that signs them: a tick that could not sign
    // them (no key, the clock stopped judging) leaves them due. Before, asking took the hour, and
    // an hour whose signing found no key was lost.
    let hourly = Figures::new();
    assert!(hourly.due(judged(NEXT_HOUR)));
    assert!(
        hourly.due(judged(NEXT_HOUR + 1_000)),
        "asking took the hour"
    );
    let _ = hourly.sign(&relay, judged(NEXT_HOUR + 1_000), |_| true);
    assert!(!hourly.due(judged(NEXT_HOUR + 59 * 60_000 - 60_000)));
    assert!(hourly.due(judged(NEXT_HOUR + HOUR_MS)));
    assert!(hourly.due(judged(NEXT_HOUR + HOUR_MS + 60_000)));
    let _ = hourly.sign(&relay, judged(NEXT_HOUR + HOUR_MS + 60_000), |_| true);
    assert!(!hourly.due(judged(NEXT_HOUR + HOUR_MS + 120_000)));
    Ok(())
}

#[test]
fn a_day_old_feeder_is_forgotten_and_its_charge_let_go() {
    let figures = Figures::new();
    let gauge = Gauge::new(Store::Figures, PER_RECEIVER_BYTES);
    figures.charge_to(Arc::clone(&gauge));
    figures.batch(
        &batch(&identity(7), 0, T, &[df11(X.0)]),
        Some(public(A_SITE)),
        judged(T),
    );
    let (_, _, areas) = figures.compute(judged(T + (WINDOW_HOURS + 1) * HOUR_MS), |_| true);
    assert!(areas.is_empty());
    assert_eq!(figures.rows(), 0);
    figures.batch(
        &batch(
            &identity(8),
            0,
            T + (WINDOW_HOURS + 1) * HOUR_MS,
            &[df11(X.0)],
        ),
        None,
        judged(T + (WINDOW_HOURS + 1) * HOUR_MS),
    );
    assert_eq!(figures.rows(), 1);
    assert_eq!(gauge.held(), figures.counted());
}

/// The store holds what the rows and their shards' tables allocate, read from each table's
/// buckets, as receivers come in waves and are forgotten: each row its [`ROW_BYTES`], each table
/// what it allocates and no more than [`PER_RECEIVER_BYTES`] leaves it for each row, and nothing
/// once every row is forgotten. Before, each row was charged its fixed bytes and its slot in its
/// shard's table nothing, which kept every bucket a wave grew it to.
#[test]
fn the_rows_tables_are_charged_what_they_allocate_as_receivers_come_and_go() {
    let figures = Figures::new();
    let gauge = Gauge::unlimited(Store::Figures);
    figures.charge_to(Arc::clone(&gauge));
    let mut now = T;
    for wave in 0..4u64 {
        let receivers = [40, 255, 3, 120][wave as usize];
        for seed in 0..receivers {
            let who = Identity::from_seed([seed as u8 ^ wave as u8; 32]);
            figures.batch(&batch(&who, wave, now, &[df11(X.0)]), None, judged(now));
            assert_eq!(gauge.held(), figures.counted());
        }
        assert!(gauge.held() <= figures.rows() * PER_RECEIVER_BYTES);
        now += (WINDOW_HOURS + 1) * HOUR_MS;
        let _ = figures.compute(judged(now), |_| true);
        assert_eq!(figures.rows(), 0);
        assert_eq!(gauge.held(), 0);
        assert_eq!(figures.counted(), 0);
    }
}

/// A receiver that names no public cell still has its figures, in a record of no area, which
/// only a subscriber to the whole world is sent.
#[test]
fn a_receiver_with_no_cell_is_figured_in_a_record_of_no_area() -> Result<(), String> {
    let figures = Figures::new();
    figures.batch(
        &batch(&identity(7), 0, T, &[df11(X.0)]),
        None,
        judged(T + 1_000),
    );
    let signed = figures.sign(&identity(30), judged(NEXT_HOUR), |_| false);
    assert_eq!(signed.len(), 1);
    let content = signed[0].content().map_err(|error| error.to_string())?;
    assert_eq!(content.area, None);
    assert_eq!(content.feeders.len(), 1);
    assert_eq!(
        (content.feeders[0].cell, content.feeders[0].messages),
        (None, 1)
    );
    Ok(())
}

/// The figures judge a batch's and an MLAT fix's own signed time by the error budget's windows
/// (`tally_wire::budget::Window::FIGURES` and `Window::FIGURES_POSITIONS`), never a tolerance of
/// their own: a batch as old as its origin may use it is counted, one older or further ahead than
/// any copy may be used is not; a fix as late as a fix may arrive (`FIX_ARRIVED`) is counted, one
/// later is not. Before, one 120 s either way of the relay's clock counted
/// both, records no relay could have used.
#[test]
fn the_figures_judge_signed_times_by_the_budgets_windows() {
    use tally_wire::budget::{FEEDER_BEHIND, FIX_ARRIVED, PEER_AHEAD};
    let now = T + 600_000;
    let figures = Figures::new();
    let rows = |figures: &Figures| figures.rows();
    figures.batch(
        &batch(
            &identity(7),
            0,
            now - FEEDER_BEHIND.span::<tally_wire::clocks::Judged>().ms() - 1,
            &[df11(X.0)],
        ),
        None,
        judged(now),
    );
    figures.batch(
        &batch(
            &identity(8),
            0,
            now + PEER_AHEAD.span::<tally_wire::clocks::Judged>().ms() + 1,
            &[df11(X.0)],
        ),
        None,
        judged(now),
    );
    assert_eq!(rows(&figures), 0, "a batch outside the window was counted");
    let fed = identity(9);
    figures.batch(
        &batch(
            &fed,
            0,
            now - FEEDER_BEHIND.span::<tally_wire::clocks::Judged>().ms(),
            &[df11(Z.0), df11(Z.0 + 1)],
        ),
        None,
        judged(now),
    );
    assert_eq!(rows(&figures), 1);
    figures.positions(
        &position(
            &identity(20),
            0,
            Z.0,
            Z.1,
            now - FIX_ARRIVED.span::<tally_wire::clocks::Judged>().ms() - 1,
            &[&fed],
        ),
        judged(now),
    );
    figures.positions(
        &position(
            &identity(20),
            1,
            Z.0 + 1,
            Z.1,
            now - FIX_ARRIVED.span::<tally_wire::clocks::Judged>().ms(),
            &[&fed],
        ),
        judged(now),
    );
    let (_, _, areas) = figures.compute(judged(now + HOUR_MS), |_| true);
    let positions: u64 = areas
        .values()
        .flat_map(|(_, figures)| figures.iter())
        .filter(|figure| figure.receiver == fed.public())
        .map(|figure| figure.mlat_positions)
        .sum();
    assert_eq!(positions, 1);
}
