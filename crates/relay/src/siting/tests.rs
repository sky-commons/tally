//! The location check against skies of simulated traffic and receivers of every kind: a quiet
//! indoor one, one that hears far through a window, a busy rooftop one, one with no traffic near
//! it. A correct site is never held wrong; a site as far off as ours once was is.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use super::*;
use tally_wire::Identity;

/// A fixed start: an epoch's beginning, so a sky of `EPOCH_MS` falls in one.
const T0: u64 = 41_000 * EPOCH_MS;
const MINUTE_MS: u64 = 60_000;

/// San Francisco International Airport: a public place to put a test receiver.
const SFO: (f64, f64) = (37.6213, -122.3790);
/// The location tally-pi was first set up with, a guess near Livermore, about 45 km from where
/// it really was (2026-11-03).
const GUESSED: (f64, f64) = (37.66, -121.87);

/// A small, fixed pseudorandom sequence (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// One aircraft position: where, how high, which aircraft, when.
#[derive(Clone, Copy, Debug)]
struct Sample {
    lat: f64,
    lon: f64,
    feet: i32,
    address: u32,
    at_ms: u64,
}

fn place(centre: (f64, f64), east_km: f64, north_km: f64) -> (f64, f64) {
    let lat = centre.0 + north_km / 111.195;
    let lon = centre.1 + east_km / (111.195 * centre.0.to_radians().cos());
    (lat, lon)
}

fn site(at: (f64, f64), alt_m: i32) -> Site {
    Site {
        lat: at.0,
        lon: at.1,
        alt_m: Some(alt_m),
    }
}

/// A sky over `hours` from `T0`: `flights` aircraft on straight tracks, each 40 minutes long and
/// sampled once a minute, starting anywhere within `reach_km` of `centre`; three in ten low
/// (2,000 to 12,000 ft), the rest cruising (28,000 to 40,000 ft). No position falls within
/// `empty_km` of `centre`: a place no aircraft passes near.
fn sky(centre: (f64, f64), reach_km: f64, flights: u32, hours: u64, empty_km: f64) -> Vec<Sample> {
    let mut rng = Rng(0x5eed_0000 + u64::from(flights));
    let mut samples = Vec::new();
    for flight in 0..flights {
        let (mut east, mut north) = (
            (rng.unit() * 2.0 - 1.0) * reach_km,
            (rng.unit() * 2.0 - 1.0) * reach_km,
        );
        let heading = rng.unit() * std::f64::consts::TAU;
        let feet = if rng.unit() < 0.3 {
            2_000 + (rng.unit() * 10_000.0) as i32
        } else {
            28_000 + (rng.unit() * 12_000.0) as i32
        };
        let start = T0 + (rng.unit() * (hours * 3_600_000) as f64) as u64;
        for minute in 0..40 {
            east += 13.8 * heading.sin();
            north += 13.8 * heading.cos();
            if east.hypot(north) < empty_km {
                continue;
            }
            let (lat, lon) = place(centre, east, north);
            samples.push(Sample {
                lat,
                lon,
                feet,
                address: 0xa0_0000 + flight,
                at_ms: start + minute * MINUTE_MS,
            });
        }
    }
    samples
}

/// What a receiver at `at` with its antenna `antenna_m` up hears of `sky`: every position within
/// its reach on that bearing (`reach_km`) and within the radio horizon.
fn hears(
    sky: &[Sample],
    at: (f64, f64),
    antenna_m: f64,
    reach_km: impl Fn(f64) -> f64,
) -> Vec<Sample> {
    let true_site = site(at, 0);
    sky.iter()
        .copied()
        .filter(|sample| {
            let distance = true_site.distance_km(sample.lat, sample.lon);
            let bearing = true_site.bearing_deg(sample.lat, sample.lon);
            distance <= reach_km(bearing)
                && distance <= horizon_km(antenna_m, f64::from(sample.feet) * 0.3048)
        })
        .collect()
}

/// The judgment of a receiver that heard `heard` and claims `claimed`, at the end of the sky.
fn judged(heard: &[Sample], claimed: Site) -> Judgment {
    let mut kept = Heard::default();
    kept.set_site(Some(claimed));
    for sample in heard {
        kept.heard(
            sample.lat,
            sample.lon,
            Some(sample.feet),
            sample.address,
            sample.at_ms,
        );
    }
    let aircraft: std::collections::BTreeSet<u32> =
        heard.iter().map(|sample| sample.address).collect();
    kept.judge(T0 + EPOCH_MS - 1, aircraft.len())
}

/// A busy region's traffic, about as dense as the Bay Area's in the day: some 300 aircraft up at
/// once within 400 km.
fn bay_sky() -> Vec<Sample> {
    sky(SFO, 600.0, 9_000, 12, 0.0)
}

/// How far a receiver hears on a bearing.
type Reach = dyn Fn(f64) -> f64;

fn omni(km: f64) -> impl Fn(f64) -> f64 {
    move |_| km
}

/// Our own first receiver as it was: an indoor antenna that hears some 30 km, set up with a
/// guessed location 45 km off. Held wrong by about that, and the site it really has fits.
#[test]
fn a_quiet_receiver_set_up_45_km_off_is_found_wrong() {
    let sky = bay_sky();
    let heard = hears(&sky, SFO, 5.0, omni(30.0));
    let off = site(SFO, 0).distance_km(GUESSED.0, GUESSED.1);
    assert!((40.0..50.0).contains(&off), "{off}");
    match judged(&heard, site(GUESSED, -22)) {
        Judgment::Wrong {
            off_km,
            by: Evidence::NearField,
        } => assert!((35..=55).contains(&off_km), "{off_km}"),
        other => panic!("the guessed site was judged {other:?}"),
    }
    assert_eq!(judged(&heard, site(SFO, -22)), Judgment::Fits);
}

/// A site wrong by as much in any direction is found, for a quiet receiver; one wrong by less
/// than its own reach may not be, and is never said to be wrong by more than it is.
#[test]
fn a_quiet_receivers_site_is_found_wrong_in_every_direction() {
    let sky = bay_sky();
    let heard = hears(&sky, SFO, 5.0, omni(30.0));
    for bearing in (0..360).step_by(45) {
        let (east, north) = (
            50.0 * f64::from(bearing).to_radians().sin(),
            50.0 * f64::from(bearing).to_radians().cos(),
        );
        let claimed = place(SFO, east, north);
        match judged(&heard, site(claimed, 0)) {
            Judgment::Wrong { off_km, .. } => {
                assert!((40..=60).contains(&off_km), "{bearing}: {off_km}");
            }
            other => panic!("50 km off at {bearing} degrees was judged {other:?}"),
        }
        let near = place(SFO, east / 10.0, north / 10.0);
        assert_eq!(
            judged(&heard, site(near, 0)),
            Judgment::Fits,
            "5 km off at {bearing}"
        );
    }
}

/// Correct sites are never held wrong, whatever the antenna: quiet and indoor, a window that
/// hears 150 km east and 20 km elsewhere, a busy rooftop that hears to the horizon, one whose
/// hills block the west past 30 km.
#[test]
fn a_correct_site_fits_whatever_the_antenna() {
    let sky = bay_sky();
    let window = |bearing: f64| {
        if (45.0..135.0).contains(&bearing) {
            150.0
        } else {
            20.0
        }
    };
    let hills = |bearing: f64| {
        if (240.0..300.0).contains(&bearing) {
            30.0
        } else {
            400.0
        }
    };
    let receivers: [(&str, f64, Box<Reach>); 4] = [
        ("quiet", 5.0, Box::new(omni(25.0))),
        ("window", 5.0, Box::new(window)),
        ("rooftop", 30.0, Box::new(omni(450.0))),
        ("hills", 30.0, Box::new(hills)),
    ];
    for (name, antenna, reach) in receivers {
        let heard = hears(&sky, SFO, antenna, reach);
        assert!(heard.len() > 100, "{name} heard {}", heard.len());
        assert_eq!(judged(&heard, site(SFO, 10)), Judgment::Fits, "{name}");
    }
}

/// A receiver with no traffic near it, that hears only far away (a valley no route crosses), is
/// never held wrong: it cannot be told from one that is elsewhere, so it is unjudged.
#[test]
fn a_receiver_with_no_traffic_near_it_is_never_held_wrong() {
    let quiet_valley = sky(SFO, 600.0, 9_000, 12, 60.0);
    for reach in [80.0, 150.0, 400.0] {
        let heard = hears(&quiet_valley, SFO, 10.0, omni(reach));
        let judgment = judged(&heard, site(SFO, 10));
        assert!(
            !matches!(judgment, Judgment::Wrong { .. }),
            "reach {reach}: {judgment:?}"
        );
    }
}

/// A busy receiver's site hundreds of kilometres off (its longitude's sign dropped, a typo of a
/// degree or more) puts much of what it hears past the horizon, and is found wrong.
#[test]
fn a_busy_receiver_far_off_is_past_the_horizon() {
    let sky = bay_sky();
    let heard = hears(&sky, SFO, 30.0, omni(450.0));
    let claimed = place(SFO, 0.0, -350.0);
    match judged(&heard, site(claimed, 10)) {
        Judgment::Wrong { off_km, .. } => assert!(off_km >= 25, "{off_km}"),
        other => panic!("350 km off was judged {other:?}"),
    }
}

/// A quiet receiver whose site is hundreds of kilometres off (a degree or more mistyped) hears
/// nothing near it, and is found wrong by about as far.
#[test]
fn a_quiet_receiver_far_off_hears_nothing_near() {
    let sky = bay_sky();
    let heard = hears(&sky, SFO, 5.0, omni(30.0));
    for (east, north) in [(0.0, 300.0), (-250.0, -150.0), (120.0, 0.0)] {
        let off = f64::hypot(east, north);
        match judged(&heard, site(place(SFO, east, north), 0)) {
            Judgment::Wrong { off_km, .. } => {
                assert!(
                    (f64::from(off_km) - off).abs() <= 0.25 * off,
                    "{off}: {off_km}"
                );
            }
            other => panic!("{off} km off was judged {other:?}"),
        }
    }
}

/// Too little heard is unjudged, never wrong.
#[test]
fn too_little_heard_is_unjudged() {
    let sky = sky(SFO, 600.0, 300, 12, 0.0);
    let heard = hears(&sky, SFO, 5.0, omni(30.0));
    assert_eq!(judged(&heard, site(GUESSED, 0)), Judgment::Unjudged);
    assert_eq!(judged(&[], site(GUESSED, 0)), Judgment::Unjudged);
}

/// What is kept is the claimed site's: a new site (more than a kilometre away) starts it over and
/// is a new generation; the same site with a new altitude keeps it.
#[test]
fn a_new_site_starts_over() {
    let sky = bay_sky();
    let heard = hears(&sky, SFO, 5.0, omni(30.0));
    let mut kept = Heard::default();
    kept.set_site(Some(site(GUESSED, 0)));
    for sample in &heard {
        kept.heard(
            sample.lat,
            sample.lon,
            Some(sample.feet),
            sample.address,
            sample.at_ms,
        );
    }
    let now = T0 + EPOCH_MS - 1;
    assert!(matches!(kept.judge(now, 500), Judgment::Wrong { .. }));
    let generation = kept.generation();
    kept.set_site(Some(site(place(GUESSED, 0.3, 0.3), 40)));
    assert_eq!(kept.generation(), generation, "within a kilometre");
    assert!(matches!(kept.judge(now, 500), Judgment::Wrong { .. }));
    kept.set_site(Some(site(SFO, 0)));
    assert_ne!(kept.generation(), generation);
    assert_eq!(kept.judge(now, 500), Judgment::Unjudged);
}

/// Two epochs are kept, by the batches' own clocks: what was heard before them is not judged,
/// and a position from before them is not kept.
#[test]
fn only_the_last_two_epochs_are_judged() {
    let sky = bay_sky();
    let heard = hears(&sky, SFO, 5.0, omni(30.0));
    let mut kept = Heard::default();
    kept.set_site(Some(site(GUESSED, 0)));
    for sample in &heard {
        kept.heard(
            sample.lat,
            sample.lon,
            Some(sample.feet),
            sample.address,
            sample.at_ms,
        );
    }
    assert!(matches!(
        kept.judge(T0 + EPOCH_MS + 1, 500),
        Judgment::Wrong { .. }
    ));
    assert_eq!(kept.judge(T0 + 2 * EPOCH_MS + 1, 500), Judgment::Unjudged);
    // Positions from three epochs on, then one from the first: it is not kept.
    let later = |sample: &Sample| sample.at_ms + 3 * EPOCH_MS;
    for sample in heard.iter().take(10) {
        kept.heard(
            sample.lat,
            sample.lon,
            Some(sample.feet),
            sample.address,
            later(sample),
        );
    }
    kept.heard(SFO.0, SFO.1, Some(30_000), 1, T0);
    assert_eq!(kept.judge(T0 + 3 * EPOCH_MS + 1, 500), Judgment::Unjudged);
}

/// What is kept is the same size however much is heard: the charge a row takes covers it.
#[test]
fn what_is_kept_is_bounded() {
    let sky = sky(SFO, 600.0, 20_000, 24, 0.0);
    let mut kept = Heard::default();
    kept.set_site(Some(site(SFO, 0)));
    for sample in &sky {
        kept.heard(
            sample.lat,
            sample.lon,
            Some(sample.feet),
            sample.address,
            sample.at_ms,
        );
    }
    let held: usize = std::mem::size_of::<Heard>()
        + kept
            .epochs
            .iter()
            .flatten()
            .map(|epoch| {
                epoch
                    .grid
                    .as_ref()
                    .map_or(0, |grid| grid.len() * std::mem::size_of::<Cell>())
            })
            .sum::<usize>();
    assert!(held <= MAX_BYTES, "{held} of {MAX_BYTES}");
}

/// A site is held wrong only after `WRONG_AFTER` judgments in a row found it so, taken back after
/// `CLEARED_AFTER` that did not, and at once when it moves. What is said is a distance and a
/// state, never a place.
#[test]
fn a_site_is_held_wrong_after_a_run_and_taken_back_when_it_moves() {
    let key = Identity::from_seed([3; 32]).public();
    let wrong = Judgment::Wrong {
        off_km: 45,
        by: Evidence::NearField,
    };
    let mut verdicts = Verdicts::default();
    for _ in 1..WRONG_AFTER {
        verdicts.judged(vec![(key, 1, wrong)]);
        assert!(verdicts.misplaced().is_empty());
        assert_eq!(
            verdicts.check(&key).map(|check| check.state),
            Some(CheckState::Unjudged)
        );
    }
    verdicts.judged(vec![(key, 1, wrong)]);
    assert!(verdicts.misplaced().contains(&key));
    assert_eq!(
        verdicts.check(&key),
        Some(LocationCheck {
            state: CheckState::Wrong,
            off_km: Some(45),
        })
    );
    // One judgment that does not find it wrong keeps it held.
    verdicts.judged(vec![(key, 1, Judgment::Unjudged)]);
    assert!(verdicts.misplaced().contains(&key));
    // The site moved: taken back at once, and judged anew.
    verdicts.judged(vec![(key, 2, Judgment::Unjudged)]);
    assert!(verdicts.misplaced().is_empty());
    for _ in 0..WRONG_AFTER {
        verdicts.judged(vec![(key, 2, wrong)]);
    }
    assert!(verdicts.misplaced().contains(&key));
    for _ in 0..CLEARED_AFTER {
        verdicts.judged(vec![(key, 2, Judgment::Fits)]);
    }
    assert!(verdicts.misplaced().is_empty());
    assert_eq!(
        verdicts.check(&key).map(|check| check.state),
        Some(CheckState::Fits)
    );
    // A receiver with no row any more is forgotten.
    verdicts.judged(Vec::new());
    assert_eq!(verdicts.check(&key), None);
    let said = serde_json::to_string(&LocationCheck {
        state: CheckState::Wrong,
        off_km: Some(45),
    });
    assert_eq!(
        said.ok().as_deref(),
        Some(r#"{"state":"wrong","off_km":45}"#)
    );
}
