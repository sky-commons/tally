//! Receiver clocks: how a raw counter becomes a linear count, what a clock is (a receiver's
//! counter within one counter epoch), and the specification's version.

use tally_wire::{Clock, PublicKey};

/// The version of this crate's specification (the module docs of `lib.rs`). A published fix or
/// pair model names it; two engines agree exactly only under the same version. Versions 1 to 7
/// were the joint clock model's (the tile models, then their trailing window); version 8 is the
/// pairwise path (crate docs, § The pairwise path): one pair model per area, fitted at its refit
/// edge over the trailing window, and every fix normalised by the pairs of the area its used
/// hearers name.
pub const SPEC_VERSION: u16 = 8;

// Relays judge fault proofs by the tolerance the wire sets per version: a version the wire does
// not know would make every proof of it unjudgeable (as bumping to 4 once did in `tally-merge`).
const _: () = assert!(
    tally_wire::Tolerance::for_spec(SPEC_VERSION).is_some(),
    "tally_wire::Tolerance::for_spec does not know this SPEC_VERSION"
);

/// Picoseconds per second.
pub const PS: i128 = 1_000_000_000_000;
/// Nanoseconds in a day, the period of a GPS time-of-day stamp.
pub const DAY_NS: i64 = 86_400_000_000_000;

/// How a receiver's raw 48-bit counter counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Timebase {
    /// A free-running 12 MHz counter: dump1090/readsb, Beast, Radarcape in 12 MHz mode.
    Mhz12,
    /// A Radarcape's GPS time stamp: seconds of the UTC day in the upper 18 bits, nanoseconds in
    /// the lower 30.
    GpsNanos,
}

impl Timebase {
    /// The timebase a receiver's declared clock implies. `Unknown` and `Other` have no known tick
    /// rate, so their receptions are never used.
    pub fn of(clock: Clock) -> Option<Self> {
        match clock {
            Clock::Dump1090 | Clock::Beast | Clock::Radarcape12Mhz => Some(Self::Mhz12),
            Clock::RadarcapeGps => Some(Self::GpsNanos),
            Clock::Unknown | Clock::Other(_) => None,
        }
    }

    /// Whether the clock is disciplined to GNSS time, which makes it a fix's reference by
    /// preference (crate docs, § The pairwise path, the adjustment).
    pub fn disciplined(self) -> bool {
        self == Self::GpsNanos
    }

    /// The knot spacing (5 s nominal) in linear counts.
    pub fn knot_counts(self) -> i64 {
        match self {
            Self::Mhz12 => 60_000_000,
            Self::GpsNanos => 5_000_000_000,
        }
    }

    /// Ten seconds in linear counts: how far apart an even and an odd CPR position heard by one
    /// receiver may be and still be paired.
    pub fn pair_counts(self) -> i64 {
        2 * self.knot_counts()
    }

    /// Picoseconds in `counts`, rounded toward negative infinity (12 MHz: 250 000 / 3 ps each).
    pub fn elapsed_ps(self, counts: i128) -> i128 {
        match self {
            // In 64 bits whenever the product fits them (some 36 days of counts either way): the
            // same quotient, without 128-bit division's call.
            Self::Mhz12 => match i64::try_from(counts) {
                Ok(small) if small.unsigned_abs() <= (i64::MAX / 250_000) as u64 => {
                    i128::from((small * 250_000).div_euclid(3))
                }
                _ => (counts * 250_000).div_euclid(3),
            },
            Self::GpsNanos => counts * 1000,
        }
    }

    /// Counts in `ps` picoseconds, rounded toward negative infinity: the inverse of `elapsed_ps`
    /// to within a count.
    pub fn counts_of_ps(self, ps: i128) -> i64 {
        let counts = match self {
            // In 64 bits whenever they hold it, as `elapsed_ps`.
            Self::Mhz12 => match i64::try_from(ps) {
                Ok(small) if small.unsigned_abs() <= (i64::MAX / 3) as u64 => {
                    i128::from((small * 3).div_euclid(250_000))
                }
                _ => (ps * 3).div_euclid(250_000),
            },
            Self::GpsNanos => match i64::try_from(ps) {
                Ok(small) => i128::from(small.div_euclid(1000)),
                Err(_) => ps.div_euclid(1000),
            },
        };
        i64::try_from(counts).unwrap_or(if counts < 0 { i64::MIN } else { i64::MAX })
    }

    /// Seconds in `counts`, as a float (used only inside least squares, never for a decision).
    pub fn seconds(self, counts: i64) -> f64 {
        match self {
            Self::Mhz12 => counts as f64 / 12_000_000.0,
            Self::GpsNanos => counts as f64 * 1e-9,
        }
    }

    /// The raw counter as a linear count, without unwrapping: the counter itself for 12 MHz, the
    /// nanosecond of the day for GPS (`None` if the stamp is not a valid time of day).
    pub fn linear(self, raw: u64) -> Option<i64> {
        match self {
            Self::Mhz12 => i64::try_from(raw).ok(),
            Self::GpsNanos => {
                let seconds = raw >> 30;
                let nanos = raw & 0x3fff_ffff;
                (seconds < 86_400 && nanos < 1_000_000_000)
                    .then(|| (seconds * 1_000_000_000 + nanos) as i64)
            }
        }
    }

    /// The raw counter as the linear count nearest `near`: a GPS time of day is moved by whole
    /// days to lie within half a day of `near` (`(near - t + DAY/2) div DAY` days, floored); a
    /// 12 MHz count is taken as it is (its 48 bits wrap after 271 days, and a feeder bumps its
    /// counter epoch long before).
    pub fn linear_near(self, raw: u64, near: i64) -> Option<i64> {
        let value = self.linear(raw)?;
        Some(match self {
            Self::Mhz12 => value,
            Self::GpsNanos => value + DAY_NS * (near - value + DAY_NS / 2).div_euclid(DAY_NS),
        })
    }

    /// The default timing noise before a pair model estimates it, seconds.
    pub fn default_noise_s(self) -> f64 {
        match self {
            // What any clock is taken as until its own receptions estimate it: the worst common
            // class (a dump1090-class dongle, about 500 ns), so a clock heard too little to
            // estimate is never taken as better than it may be. A GNSS declaration is the
            // feeder's word, not a measurement: version 3 took a GNSS clock at 30 ns, and one
            // whose counter was noise (OpenSky's data has them) lost its tile's robust start.
            Self::Mhz12 | Self::GpsNanos => 500e-9,
        }
    }

    /// The most a clock's noise is estimated at, seconds (`sync::GAUGE_NOISE_MOST_S`): ten times
    /// the worst common class. A clock noisier than this is held to it, and its points beyond
    /// it carry no weight in its pairs, rather than it being taken at its noise.
    pub fn noise_ceiling_s(self) -> f64 {
        crate::sync::GAUGE_NOISE_MOST_S
    }

    /// Random-walk process noise per knot interval: (phase seconds, rate dimensionless).
    pub fn process_noise(self) -> (f64, f64) {
        match self {
            Self::Mhz12 => (10e-9, 5e-9),
            Self::GpsNanos => (5e-9, 0.5e-9),
        }
    }

    /// One standard deviation of a clock's offset second difference over consecutive knots,
    /// seconds: the integrated random walk that restates the two process noises,
    /// `sqrt((rate * spacing)^2 + 2 * phase^2)` (28.7 ns for 12 MHz, 7.5 ns for GPS).
    pub fn curvature_sigma_s(self) -> f64 {
        let (phase, rate) = self.process_noise();
        let spacing = KNOT_PS as f64 * 1e-12;
        ((rate * spacing) * (rate * spacing) + 2.0 * phase * phase).sqrt()
    }
}

/// The nominal spacing of a clock's knots, picoseconds: 5 s.
pub const KNOT_PS: i128 = 5_000_000_000_000;

const _: () = assert!(
    KNOT_PS
        == tally_wire::budget::MODEL_KNOT
            .span::<tally_wire::clocks::Judged>()
            .ms() as i128
            * 1_000_000_000,
    "tally_wire::budget::MODEL_KNOT is not this knot spacing"
);

/// One clock: a receiver's counter within one counter epoch. A counter jump inside the epoch
/// changes the clock's offset only (crate docs, § The pairwise path, jumps), so it stays one
/// clock, published from the count after its newest jump (`PairClock::from`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockKey {
    pub receiver: PublicKey,
    pub epoch: u32,
}

/// How far past its models' trailing edge a fix may be carried (crate docs, § Areas):
/// `tally_wire::budget::MAX_CARRY`, 14.6 s, a spec constant. A fix is solved under the models of
/// the newest edge of the refit grid its areas' models are all held at, at most one edge behind
/// the newest, and its receptions are signed at most `MLAT_AHEAD` ahead of the clock they arrive
/// by, so a fix's receptions are never further than this past the models' edge; one further is
/// past what the models say anything of.
pub const MAX_CARRY_PS: i128 = tally_wire::budget::MAX_CARRY_MS as i128 * (PS / 1000);

/// A reception's time on its fix's timeline (crate docs, § The pairwise path, the adjustment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelTime {
    /// Its clock's linear count.
    pub linear: i64,
    /// Its arrival, picoseconds after the timeline's zero.
    pub ps: i128,
    /// Nominal picoseconds past the last knot of the pairs it was read through: zero within
    /// them, and what the carry's process noise grows with past them.
    pub carried_ps: i128,
}
