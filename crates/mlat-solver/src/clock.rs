//! Receiver clocks: how a raw counter becomes a linear count, and the published clock model that
//! maps a linear count to model time with integer arithmetic only: per clock, offsets at knots a
//! fixed nominal spacing apart, linearly interpolated, so model time and its uncertainty are
//! continuous in time.

use tally_wire::{Clock, PublicKey};

use crate::scope::{Citation, Window};

/// The version of this crate's specification (the module docs of `lib.rs`). A published solution
/// or clock model names it; two engines agree exactly only under the same version. Version 2 added
/// the gauge's rate and the sync aircraft's position biases.
pub const SPEC_VERSION: u16 = 3;

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

    /// Whether the clock is disciplined to GNSS time, which makes it the gauge by preference.
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
            Self::Mhz12 => (counts * 250_000).div_euclid(3),
            Self::GpsNanos => counts * 1000,
        }
    }

    /// Counts in `ps` picoseconds, rounded toward negative infinity: the inverse of `elapsed_ps`
    /// to within a count.
    pub fn counts_of_ps(self, ps: i128) -> i64 {
        let counts = match self {
            Self::Mhz12 => (ps * 3).div_euclid(250_000),
            Self::GpsNanos => ps.div_euclid(1000),
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

    /// The default timing noise before the clock model estimates it, seconds.
    pub fn default_noise_s(self) -> f64 {
        match self {
            // What a 12 MHz clock is taken as until its own receptions estimate it: the worst
            // common class (a dump1090-class dongle, about 500 ns), so a clock heard too little
            // to estimate is never taken as better than it may be.
            Self::Mhz12 => 500e-9,
            Self::GpsNanos => 30e-9,
        }
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

/// One clock: a receiver's counter within one counter epoch, between two jumps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockKey {
    pub receiver: PublicKey,
    pub epoch: u32,
    /// 0 for the counter from the epoch's start; one more after each detected jump.
    pub piece: u16,
}

/// One clock of a model: its knots and what it was fitted with.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockPiece {
    pub key: ClockKey,
    pub timebase: Timebase,
    /// The linear count at which this piece begins (the jump that split it off), or `None` for
    /// the first piece of an epoch.
    pub begins: Option<i64>,
    /// The linear count at which the next piece begins, or `None` for the last.
    pub ends: Option<i64>,
    /// The receiver's antenna, ECEF millimetres, as the model was fitted with it.
    pub site_mm: [i64; 3],
    /// One standard deviation of the antenna position, millimetres (from its declared precision).
    pub site_sigma_mm: i64,
    /// One standard deviation of a reception's timing noise, picoseconds, as estimated.
    pub noise_ps: i64,
    /// The linear count of knot 0: the gauge's anchor, mapped into this clock by its coarse
    /// offset (crate docs, § Knots).
    pub base: i64,
    /// The index of the first knot; the knots are `first .. first + offsets_ps.len()`.
    pub first: i32,
    /// The offset at each knot, picoseconds; all zero for the gauge.
    pub offsets_ps: Vec<i64>,
}

impl ClockPiece {
    /// The index one past the last knot.
    pub fn end(&self) -> i32 {
        self.first + self.offsets_ps.len() as i32
    }
}

/// A detected counter jump: the clock was split at `at` (the first reception after it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Jump {
    pub receiver: PublicKey,
    pub epoch: u32,
    pub at: i64,
    /// The step seen in the residuals, picoseconds (the later counter reads late by this much).
    pub step_ps: i64,
}

/// What one bias of a sync aircraft's reported position is along (crate docs, § Sync events).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BiasKind {
    /// Its GNSS position's error east, near constant over a window.
    East,
    /// And north.
    North,
    /// Its pressure altitude minus its height above the ellipsoid.
    Barometric,
    /// Its GNSS height's error.
    GnssHeight,
}

impl BiasKind {
    pub fn byte(self) -> u8 {
        match self {
            Self::East => 0,
            Self::North => 1,
            Self::Barometric => 2,
            Self::GnssHeight => 3,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::East),
            1 => Some(Self::North),
            2 => Some(Self::Barometric),
            3 => Some(Self::GnssHeight),
            _ => None,
        }
    }
}

/// One bias of one sync aircraft, millimetres.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bias {
    pub address: u32,
    pub kind: BiasKind,
    pub mm: i64,
}

/// The gauge's rate is stated in parts per this: femto, so 30 ppm is 3 x 10^10 and a 65 s window
/// rounds to well under a picosecond.
pub const RATE_SCALE: i128 = 1_000_000_000_000_000;

/// A clock model: the clocks of one tile's members over one canonical window, relative to the
/// tile's gauge (crate docs, § Tiles and § The clock model), shared by every aircraft assigned
/// the tile.
#[derive(Clone, Debug, PartialEq)]
pub struct ClockModel {
    pub spec: u16,
    /// The tile the model is shared by (crate docs, § Tiles).
    pub tile: crate::tile::Tile,
    pub window: Window,
    /// The tile's members as their signed descriptions placed them, sorted by key.
    pub scope: Vec<crate::obs::Site>,
    /// The input set the model is a function of.
    pub input: Citation,
    /// The clock that defines model time.
    pub gauge: ClockKey,
    /// Unix nanoseconds at model time zero.
    pub origin_unix_ns: u64,
    /// The gauge's rate error, parts per `RATE_SCALE`: model time is the gauge's nominal time
    /// from its anchor (plus a clock's offset) times `1 + gauge_rate / RATE_SCALE`, so a
    /// free-running gauge's frequency error does not scale every time difference.
    pub gauge_rate: i64,
    /// Sorted by key.
    pub pieces: Vec<ClockPiece>,
    /// Every sync aircraft's position biases, sorted by (address, kind).
    pub biases: Vec<Bias>,
    /// Sorted.
    pub jumps: Vec<Jump>,
    /// Clocks (receiver, counter epoch) dropped from the tile for misbehaving: more jumps than a
    /// fit declares. Sorted.
    pub dropped: Vec<(PublicKey, u32)>,
}

/// How far past a clock's last knot a provisional solution may carry a model (crate docs,
/// § Provisional solutions): 90 s, the longest a final model can be behind the newest raw at
/// stride 8 (a stride of 40 s, the window's last bin, its settling time and a world-scale step of
/// some 35 s). Beyond it the model says nothing.
pub const MAX_CARRY_PS: i128 = 90 * PS;

/// What a model maps: only the counts between its clocks' knots (a final solution), or also up
/// to `MAX_CARRY_PS` past the last knot of each epoch's last piece, along its last interval
/// (a provisional solution).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    Window,
    Carried,
}

/// A raw counter mapped through the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelTime {
    /// Index into `ClockModel::pieces`.
    pub piece: usize,
    /// The knot that starts the interval the count is in.
    pub knot: i32,
    /// The linear count.
    pub linear: i64,
    /// Model time, picoseconds after the gauge's anchor.
    pub ps: i128,
    /// Nominal picoseconds since the start of the interval, in `[0, KNOT_PS)`; past `KNOT_PS`
    /// when carried, the interval being the piece's last.
    pub into_ps: i128,
    /// Nominal picoseconds past the piece's last knot: zero within the model's knots.
    pub carried_ps: i128,
}

impl ModelTime {
    /// How far into its interval, as a fraction (for least squares, never for a decision).
    pub fn fraction(&self) -> f64 {
        self.into_ps as f64 / KNOT_PS as f64
    }
}

impl ClockModel {
    /// The pieces of one receiver's epoch, as an index range.
    pub fn pieces_of(&self, receiver: &PublicKey, epoch: u32) -> std::ops::Range<usize> {
        let start = self
            .pieces
            .partition_point(|piece| (piece.key.receiver, piece.key.epoch) < (*receiver, epoch));
        let end = self
            .pieces
            .partition_point(|piece| (piece.key.receiver, piece.key.epoch) <= (*receiver, epoch));
        start..end
    }

    /// Model time of a reception, by integer arithmetic only:
    ///
    /// 1. The raw counter becomes a linear count (`Timebase::linear_near`, near the epoch's first
    ///    piece's `base`).
    /// 2. The piece is the one whose `[begins, ends)` holds it.
    /// 3. `e = elapsed_ps(linear - base)` (floored) and the interval is `k = floor(e / KNOT_PS)`;
    ///    the model says nothing unless knots `k` and `k + 1` are both the piece's.
    /// 4. With `u = e - k KNOT_PS`, `t = e + o_k + floor((o_{k+1} - o_k) u / KNOT_PS)`.
    /// 5. Model time is `t + floor(t gauge_rate / RATE_SCALE)`.
    pub fn time(&self, receiver: &PublicKey, epoch: u32, raw: u64) -> Option<ModelTime> {
        self.time_reach(receiver, epoch, raw, Reach::Window)
    }

    /// As `time`, and with `Reach::Carried` also a count past the last knot `L` of its epoch's
    /// last piece, by at most `MAX_CARRY_PS` of nominal time: step 3 then takes the last interval,
    /// `k = L - 1`, so `u` runs past `KNOT_PS` and step 4 extends that interval's line. The piece
    /// needs two knots.
    pub fn time_reach(
        &self,
        receiver: &PublicKey,
        epoch: u32,
        raw: u64,
        reach: Reach,
    ) -> Option<ModelTime> {
        let range = self.pieces_of(receiver, epoch);
        let first = self.pieces.get(range.start)?;
        let linear = first.timebase.linear_near(raw, first.base)?;
        let index = range.clone().find(|index| {
            let piece = &self.pieces[*index];
            piece.begins.is_none_or(|begins| linear >= begins)
                && piece.ends.is_none_or(|ends| linear < ends)
        })?;
        let piece = &self.pieces[index];
        let elapsed = piece
            .timebase
            .elapsed_ps(i128::from(linear) - i128::from(piece.base));
        let knot = i32::try_from(elapsed.div_euclid(KNOT_PS)).ok()?;
        if knot < piece.first {
            return None;
        }
        let (knot, carried) = if knot + 1 < piece.end() {
            (knot, 0)
        } else {
            let last = piece.end() - 1;
            let carried = elapsed - i128::from(last) * KNOT_PS;
            let carriable = reach == Reach::Carried
                && piece.ends.is_none()
                && piece.offsets_ps.len() >= 2
                && carried <= MAX_CARRY_PS;
            if !carriable {
                return None;
            }
            (last - 1, carried)
        };
        let into = elapsed - i128::from(knot) * KNOT_PS;
        let at = (knot - piece.first) as usize;
        let (left, right) = (
            i128::from(piece.offsets_ps[at]),
            i128::from(piece.offsets_ps[at + 1]),
        );
        let ps = elapsed + left + ((right - left) * into).div_euclid(KNOT_PS);
        let ps = ps + (ps * i128::from(self.gauge_rate)).div_euclid(RATE_SCALE);
        Some(ModelTime {
            piece: index,
            knot,
            linear,
            ps,
            into_ps: into,
            carried_ps: carried,
        })
    }

    /// One reception's timing noise variance in metres squared: the receiver's estimated noise
    /// plus its antenna position uncertainty.
    pub fn noise_m2(&self, piece: usize) -> f64 {
        self.pieces.get(piece).map_or(0.0, |piece| {
            let noise = piece.noise_ps as f64 * 1e-12 * crate::geo::C;
            let site = piece.site_sigma_mm as f64 / 1000.0;
            noise * noise + site * site
        })
    }

    /// The piece that is the gauge.
    pub fn gauge_piece(&self) -> Option<&ClockPiece> {
        self.pieces.iter().find(|piece| piece.key == self.gauge)
    }
}
