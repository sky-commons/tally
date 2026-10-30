//! A pair's blocks (crate docs, § The pairwise path, blocks): every second of signed wall clock
//! of the window, each pair's points of the events new in it, judged by a robust line and scale of
//! the block's own and its four predecessors' points, and summed once: what a refit re-sums in
//! ascending block order, so its passes cost each pair its knots, never its points. A block is a
//! function of the raw of the seconds it reads alone, so it is held between refits by what it read
//! (`BlockCache`), built again only when that changed, and the same in every window holding it.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{Clock, KNOT_NS, median, median_of_magnitudes, ns_per_count};
use crate::clock::{ClockKey, Timebase};
use crate::geo::C;
use crate::sync::{self, Reader};

/// Blocks a block's robust line, scale and jump test pool: its own and the four before it.
pub const LINE_BLOCKS: u64 = 5;
/// How far before a window's first second its inputs reach, milliseconds: what its first block's
/// pooled predecessors read (`LINE_BLOCKS - 1` blocks, each reading `sync::LOOK_BACK_S` back).
pub const READ_BACK_MS: u64 = (LINE_BLOCKS - 1 + sync::LOOK_BACK_S) * 1000;
/// Seconds a block reads after its own: its events' span (`sync::SPAN_AFTER_S`).
const READ_AFTER_S: u64 = sync::SPAN_AFTER_S;
/// The fewest pooled points a block's robust line is drawn through: fewer, and the block has no
/// inliers.
pub const LINE_LEAST: usize = 4;
/// The least robust scale a block's cutoff is read at, nanoseconds: two clocks at the noise floor
/// (`sync::MIN_NOISE_S`).
const SCALE_FLOOR_NS: f64 = sync::MIN_NOISE_S * 1e9 * std::f64::consts::SQRT_2;

/// One co-heard event as a pair's point, raw: its two counts, each hearer's range from the event's
/// prior in nanoseconds of light time, its event's hearers and its aircraft.
#[derive(Clone, Copy, Debug)]
pub(super) struct RawPoint {
    pub(super) la: i64,
    pub(super) lb: i64,
    pub(super) range_a: f64,
    pub(super) range_b: f64,
    pub(super) hearers: u32,
    pub(super) address: u32,
}

/// One aircraft's inliers of a unit: the plain and weighted sums of their regressors
/// `z = (1 - f, f, r, range_a, -range_b)` and the sum of their squared weights.
#[derive(Clone, Copy, Debug)]
pub(super) struct Sums {
    pub(super) address: u32,
    pub(super) plain: [f64; 5],
    pub(super) weighted: [f64; 5],
    pub(super) ww: f64,
}

/// A block's inliers within one knot interval of `a`'s grid: their sufficient statistics about the
/// block's robust line, which in the interval's own coordinate `f` is `alpha + beta f`.
#[derive(Clone, Debug)]
pub(super) struct Unit {
    /// The interval's index on `a`'s knot grid: its first knot is count `knot * knot_counts`.
    pub(super) knot: i64,
    pub(super) alpha: f64,
    pub(super) beta: f64,
    /// `sum w0 z zᵀ` and `sum z zᵀ`, upper triangle row by row (`at`), `w0 = 2 / hearers`.
    pub(super) weighted: [f64; 15],
    pub(super) plain: [f64; 15],
    /// `sum w0²`.
    pub(super) ww: f64,
    /// By address, ascending.
    pub(super) aircraft: Vec<Sums>,
}

/// The place of `z_r z_s` (`r <= s`) in a unit's upper triangle.
pub(super) const fn at(r: usize, s: usize) -> usize {
    let (r, s) = if r <= s { (r, s) } else { (s, r) };
    r * 5 - r * (r + 1) / 2 + s
}

/// A step in a block's pooled residuals past `sync::JUMP_THRESHOLD`: its score, the second its
/// first point after lies in, and the counts either side of it on each clock.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Step {
    pub(super) score: f64,
    pub(super) second: u64,
    pub(super) a: (i64, i64),
    pub(super) b: (i64, i64),
}

/// One pair's block of one second.
#[derive(Clone, Debug)]
pub(super) struct PairBlock {
    /// Its first point's counts (least `a` count, then `b`): what its points' `x` and `y` are read
    /// from.
    pub(super) refs: (i64, i64),
    /// Its own points, inliers and outliers.
    pub(super) points: u32,
    /// The most counts of its own points on each clock, and the least of its pooled points': what
    /// a clock's kept segment (`from`) is checked against.
    pub(super) high: (i64, i64),
    pub(super) pooled_low: (i64, i64),
    /// By knot, ascending.
    pub(super) units: Vec<Unit>,
    /// Of its pooled residuals' steps past the threshold, the largest located in each second.
    pub(super) steps: Vec<Step>,
}

/// How a block stands against its clocks' kept segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kept {
    /// No point it pools is before either segment's start: it stands as built.
    Whole,
    /// None of its own points is in the segments.
    Gone,
    /// Some point it pools is before a start: it is built again from the kept points alone.
    Cut,
}

impl PairBlock {
    pub(super) fn kept(&self, from: (Option<i64>, Option<i64>)) -> Kept {
        let before = |value: i64, from: Option<i64>| from.is_some_and(|from| value < from);
        if before(self.high.0, from.0) || before(self.high.1, from.1) {
            Kept::Gone
        } else if before(self.pooled_low.0, from.0) || before(self.pooled_low.1, from.1) {
            Kept::Cut
        } else {
            Kept::Whole
        }
    }

    /// Bytes it holds, as allocated.
    pub(super) fn bytes(&self) -> usize {
        use tally_wire::footprint::vec;
        size_of::<Self>()
            + vec::<Unit>(self.units.capacity())
            + self
                .units
                .iter()
                .map(|unit| vec::<Sums>(unit.aircraft.capacity()))
                .sum::<usize>()
            + vec::<Step>(self.steps.capacity())
    }
}

/// Every step of `residuals` past `sync::JUMP_THRESHOLD` (crate docs, § The pairwise path, jumps):
/// at each split with `sync::JUMP_SIDE` residuals either side, the medians of those before and
/// after compared against the residuals' own consecutive scatter. `(index of the first after,
/// score)`.
fn steps(residuals: &[f64]) -> Vec<(usize, f64)> {
    let side = sync::JUMP_SIDE;
    let n = residuals.len();
    if n < 2 * side + 1 {
        return Vec::new();
    }
    // Each step's magnitude by its bits: a sign-free float's bits order as `f64::total_cmp`
    // orders it, so their median is `median`'s, found among integers.
    let mut differences: Vec<u64> = residuals
        .windows(2)
        .map(|w| (w[1] - w[0]).abs().to_bits())
        .collect();
    let scale =
        (1.4826 * median_of_magnitudes(&mut differences) / std::f64::consts::SQRT_2).max(10.0);
    // A median of five's spread, two of them apart.
    let spread = scale * (std::f64::consts::PI / (2.0 * side as f64) * 2.0).sqrt();
    let medians: Vec<f64> = residuals.windows(side).map(median_of_side).collect();
    (side..=n - side)
        .filter_map(|at| {
            let score = (medians[at] - medians[at - side]).abs() / spread;
            (score > sync::JUMP_THRESHOLD).then_some((at, score))
        })
        .collect()
}

/// The median of a window of `sync::JUMP_SIDE` residuals (finite), as [`median`] gives it but for
/// the sign of a zero, which no difference of two medians sees: the middle of them sorted, by a
/// sorting network.
fn median_of_side(window: &[f64]) -> f64 {
    const _: () = assert!(sync::JUMP_SIDE == 5);
    let [mut a, mut b, mut c, mut d, mut e] =
        [window[0], window[1], window[2], window[3], window[4]];
    let order = |x: &mut f64, y: &mut f64| {
        let (low, high) = (x.min(*y), x.max(*y));
        *x = low;
        *y = high;
    };
    order(&mut a, &mut b);
    order(&mut d, &mut e);
    order(&mut c, &mut e);
    order(&mut c, &mut d);
    order(&mut a, &mut d);
    order(&mut a, &mut c);
    order(&mut b, &mut e);
    order(&mut b, &mut d);
    order(&mut b, &mut c);
    c
}

/// A point as its block reads it: nanoseconds from the block's first point.
struct Read {
    second: u64,
    x: f64,
    y: f64,
    point: RawPoint,
}

/// The block of second `own` of a pair of clocks `timebases`, from the pair's points of its
/// pooled seconds (`own - LINE_BLOCKS + 1 ..= own`, each with its second), those before a kept
/// segment's start already left out (crate docs, § The pairwise path, blocks): `None` when it has
/// no point of its own.
pub(super) fn build(
    own: u64,
    pooled: &[(u64, RawPoint)],
    (ta, tb): (Timebase, Timebase),
) -> Option<PairBlock> {
    let refs = pooled
        .iter()
        .filter(|(second, _)| *second == own)
        .map(|(_, p)| (p.la, p.lb))
        .min()?;
    let (ka, kb) = (ns_per_count(ta), ns_per_count(tb));
    let mut read: Vec<Read> = pooled
        .iter()
        .map(|(second, p)| {
            let x = (p.la - refs.0) as f64 * ka - p.range_a;
            let y = (p.lb - refs.1) as f64 * kb - p.range_b - x;
            Read {
                second: *second,
                x,
                y,
                point: *p,
            }
        })
        .collect();
    read.sort_by(|p, q| {
        p.x.total_cmp(&q.x)
            .then(p.point.la.cmp(&q.point.la))
            .then(p.point.lb.cmp(&q.point.lb))
            .then(p.point.address.cmp(&q.point.address))
            .then(p.second.cmp(&q.second))
    });
    let mut high = (i64::MIN, i64::MIN);
    let mut pooled_low = (i64::MAX, i64::MAX);
    let mut points = 0u32;
    for one in &read {
        let p = &one.point;
        pooled_low = (pooled_low.0.min(p.la), pooled_low.1.min(p.lb));
        if one.second == own {
            points += 1;
            high = (high.0.max(p.la), high.1.max(p.lb));
        }
    }
    let mut block = PairBlock {
        refs,
        points,
        high,
        pooled_low,
        units: Vec::new(),
        steps: Vec::new(),
    };
    let n = read.len();
    if n < LINE_LEAST {
        return Some(block);
    }
    // The line through the medians of the two halves, and the residuals' robust scale about it.
    let half = n / 2;
    let (mut xl, mut yl): (Vec<f64>, Vec<f64>) = read[..half].iter().map(|p| (p.x, p.y)).unzip();
    let (mut xr, mut yr): (Vec<f64>, Vec<f64>) = read[half..].iter().map(|p| (p.x, p.y)).unzip();
    let (mxl, myl, mxr, myr) = (
        median(&mut xl),
        median(&mut yl),
        median(&mut xr),
        median(&mut yr),
    );
    let slope = if mxr > mxl {
        (myr - myl) / (mxr - mxl)
    } else {
        0.0
    };
    let residuals: Vec<f64> = read
        .iter()
        .map(|p| p.y - (myl + slope * (p.x - mxl)))
        .collect();
    let mut magnitudes: Vec<u64> = residuals.iter().map(|r| r.abs().to_bits()).collect();
    let scale = (1.4826 * median_of_magnitudes(&mut magnitudes)).max(SCALE_FLOOR_NS);
    // Of the steps, the largest located in each second (ties to the earliest).
    let mut best: BTreeMap<u64, Step> = BTreeMap::new();
    for (cut, score) in steps(&residuals) {
        let (before, after) = (&read[cut - 1].point, &read[cut].point);
        let step = Step {
            score,
            second: read[cut].second,
            a: (before.la.min(after.la), before.la.max(after.la)),
            b: (before.lb.min(after.lb), before.lb.max(after.lb)),
        };
        let entry = best.entry(step.second).or_insert(step);
        if score > entry.score {
            *entry = step;
        }
    }
    block.steps = best.into_values().collect();
    // Its own inliers, by knot interval of `a`'s grid.
    let kc = ta.knot_counts();
    let mut units: BTreeMap<i64, (Unit, BTreeMap<u32, Sums>)> = BTreeMap::new();
    for (one, residual) in read.iter().zip(&residuals) {
        if one.second != own || residual.abs() > sync::SYNC_CUTOFF * scale {
            continue;
        }
        let p = &one.point;
        let q0 = p.la.div_euclid(kc);
        let into = (p.la - q0 * kc) as f64 * ka - p.range_a;
        let (knot, into) = if into < 0.0 {
            (q0 - 1, into + KNOT_NS)
        } else if into >= KNOT_NS {
            (q0 + 1, into - KNOT_NS)
        } else {
            (q0, into)
        };
        let f = into / KNOT_NS;
        let (unit, aircraft) = units.entry(knot).or_insert_with(|| {
            // The block's line in the interval's coordinate: `x = start + f KNOT`.
            let start = (knot * kc - refs.0) as f64 * ka;
            (
                Unit {
                    knot,
                    alpha: myl + slope * (start - mxl),
                    beta: slope * KNOT_NS,
                    weighted: [0.0; 15],
                    plain: [0.0; 15],
                    ww: 0.0,
                    aircraft: Vec::new(),
                },
                BTreeMap::new(),
            )
        });
        let r = one.y - (unit.alpha + unit.beta * f);
        let z = [1.0 - f, f, r, p.range_a, -p.range_b];
        let w0 = 2.0 / f64::from(p.hearers);
        for i in 0..5 {
            for j in i..5 {
                unit.plain[at(i, j)] += z[i] * z[j];
                unit.weighted[at(i, j)] += w0 * z[i] * z[j];
            }
        }
        unit.ww += w0 * w0;
        let sums = aircraft.entry(p.address).or_insert(Sums {
            address: p.address,
            plain: [0.0; 5],
            weighted: [0.0; 5],
            ww: 0.0,
        });
        for i in 0..5 {
            sums.plain[i] += z[i];
            sums.weighted[i] += w0 * z[i];
        }
        sums.ww += w0 * w0;
    }
    block.units = units
        .into_values()
        .map(|(mut unit, aircraft)| {
            unit.aircraft = aircraft.into_values().collect();
            unit
        })
        .collect();
    Some(block)
}

/// One second's points, by pair of window clocks `(a, b)`, `a < b`, and its events.
#[derive(Default)]
struct Second {
    events: usize,
    pairs: BTreeMap<(u32, u32), Vec<RawPoint>>,
}

/// One refit's raw as the blocks read it: the inputs read once, and each second's points, read when
/// a block asks for them.
pub(super) struct Raw<'r> {
    reader: Reader<'r>,
    /// Each read clock's window clock, `u32::MAX` for none.
    window_of: Vec<u32>,
    /// Each window clock's network pairs above it, ascending.
    above: Vec<Vec<u32>>,
    seconds: BTreeMap<u64, Second>,
}

impl<'r> Raw<'r> {
    pub(super) fn new(reader: Reader<'r>, window_of: Vec<u32>, above: Vec<Vec<u32>>) -> Self {
        Self {
            reader,
            window_of,
            above,
            seconds: BTreeMap::new(),
        }
    }

    pub(super) fn finish(self) {
        self.reader.finish();
    }

    fn second(&mut self, second: u64) -> &Second {
        if !self.seconds.contains_key(&second) {
            let events = self.reader.events(second);
            let mut out = Second {
                events: events.len(),
                pairs: BTreeMap::new(),
            };
            let mut hears: Vec<(u32, i64, f64)> = Vec::new();
            for event in &events {
                hears.clear();
                for (index, range_m) in &event.hearers {
                    let rx = &self.reader.rxs[*index as usize];
                    let clock = self.window_of[rx.clock];
                    if clock != u32::MAX {
                        hears.push((clock, rx.linear, range_m / C * 1e9));
                    }
                }
                hears.sort_by_key(|(clock, _, _)| *clock);
                let hearers = event.hearers.len() as u32;
                for (i, (a, la, range_a)) in hears.iter().enumerate() {
                    let above = &self.above[*a as usize];
                    for (b, lb, range_b) in &hears[i + 1..] {
                        if above.binary_search(b).is_err() {
                            continue;
                        }
                        out.pairs.entry((*a, *b)).or_default().push(RawPoint {
                            la: *la,
                            lb: *lb,
                            range_a: *range_a,
                            range_b: *range_b,
                            hearers,
                            address: event.address,
                        });
                    }
                }
            }
            self.seconds.insert(second, out);
        }
        &self.seconds[&second]
    }

    /// The events of `second`.
    pub(super) fn events(&mut self, second: u64) -> usize {
        self.second(second).events
    }

    /// The pairs with points in `second`.
    pub(super) fn pairs(&mut self, second: u64) -> Vec<(u32, u32)> {
        self.second(second).pairs.keys().copied().collect()
    }

    /// The block of `pair` (window clocks, with their timebases) at `own`, its pooled points those
    /// in its clocks' kept segments from `from` (`None`: every point).
    pub(super) fn block(
        &mut self,
        pair: (u32, u32),
        own: u64,
        timebases: (Timebase, Timebase),
        from: (Option<i64>, Option<i64>),
    ) -> Option<PairBlock> {
        let mut pooled: Vec<(u64, RawPoint)> = Vec::new();
        for second in own.saturating_sub(LINE_BLOCKS - 1)..=own {
            if let Some(list) = self.second(second).pairs.get(&pair) {
                pooled.extend(
                    list.iter()
                        .filter(|p| {
                            from.0.is_none_or(|from| p.la >= from)
                                && from.1.is_none_or(|from| p.lb >= from)
                        })
                        .map(|p| (second, *p)),
                );
            }
        }
        build(own, &pooled, timebases)
    }
}

/// What a block of a second read: a digest of every reception of the inputs in the seconds it is a
/// function of, by a key of this holder's (`BlockCache::key`), so a block built again from the same
/// receptions is never built, and one whose receptions changed always is.
type Digest = u128;

/// The blocks of an area held between its refits (crate docs, § The pairwise path, blocks): each
/// second's, by what it read, and by pair.
pub(super) struct BlockCache {
    /// The key its digests are made under, drawn once for this holder: no feeder can aim a
    /// reception at a collision it cannot see.
    key: [u64; 2],
    seconds: BTreeMap<u64, Held>,
}

impl Default for BlockCache {
    fn default() -> Self {
        use std::hash::{BuildHasher, Hasher};
        let state = std::collections::hash_map::RandomState::new();
        let draw = |salt: u64| {
            let mut hasher = state.build_hasher();
            hasher.write_u64(salt);
            hasher.finish()
        };
        Self {
            key: [draw(1), draw(2)],
            seconds: BTreeMap::new(),
        }
    }
}

/// One second's blocks.
pub(super) struct Held {
    digest: Digest,
    pub(super) events: usize,
    pub(super) pairs: BTreeMap<(ClockKey, ClockKey), Arc<PairBlock>>,
}

/// One 64-bit lane of a reception's digest: its words mixed under `key`.
fn lane(key: u64, words: &[u64]) -> u64 {
    let mut h = key ^ 0x9e37_79b9_7f4a_7c15;
    for word in words {
        h = (h ^ word).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        h ^= h >> 31;
    }
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 29)
}

impl BlockCache {
    /// Every block it holds is let go: the scope changed, and with it what a block is of.
    pub(super) fn clear(&mut self) {
        self.seconds.clear();
    }

    /// Bytes it holds, as allocated.
    pub(super) fn bytes(&self) -> usize {
        use tally_wire::footprint::btree;
        btree::<u64, Held>(self.seconds.len())
            + self
                .seconds
                .values()
                .map(|held| {
                    btree::<(ClockKey, ClockKey), Arc<PairBlock>>(held.pairs.len())
                        + held
                            .pairs
                            .values()
                            .map(|block| block.bytes())
                            .sum::<usize>()
                })
                .sum::<usize>()
    }

    /// Each second's digest of the receptions `reader` read, from `first` on.
    fn digests(&self, reader: &Reader<'_>) -> BTreeMap<u64, Digest> {
        let mut out: BTreeMap<u64, Digest> = BTreeMap::new();
        for rx in &reader.rxs {
            let key = rx.receiver.as_bytes();
            let word = |at: usize| u64::from_le_bytes(key[at..at + 8].try_into().unwrap_or([0; 8]));
            let hash = reader.hash(rx.message);
            let hashed =
                |at: usize| u64::from_le_bytes(hash[at..at + 8].try_into().unwrap_or([0; 8]));
            let words = [
                word(0),
                word(8),
                word(16),
                word(24),
                u64::from(rx.epoch),
                rx.linear as u64,
                rx.wall_ms,
                hashed(0),
                hashed(8),
                hashed(16),
            ];
            let digest =
                u128::from(lane(self.key[0], &words)) << 64 | u128::from(lane(self.key[1], &words));
            let entry = out.entry(rx.wall_ms / 1000).or_insert(0);
            *entry = entry.wrapping_add(digest);
        }
        out
    }

    /// The blocks of the window's seconds `[first, end)` for the window's clocks `clocks` and their
    /// pairs `above` (`Raw`): each second's held when what it read is unchanged, else built from
    /// `raw` and held. Every second outside the window is let go. Returns how many seconds were
    /// built and how many reused.
    pub(super) fn update(
        &mut self,
        raw: &mut Raw<'_>,
        clocks: &[Clock],
        (first, end): (u64, u64),
    ) -> (usize, usize) {
        let digests = self.digests(&raw.reader);
        let of = |second: u64| digests.get(&second).copied().unwrap_or(0);
        self.seconds
            .retain(|second, _| (first..end).contains(second));
        let (mut built, mut reused) = (0, 0);
        for second in first..end {
            // What it reads: its pooled seconds and theirs, from `READ_BACK_MS` before it to
            // `READ_AFTER_S` after, each digest at its place.
            let mut digest: Digest = 0;
            for read in second.saturating_sub(READ_BACK_MS / 1000)..=second + READ_AFTER_S {
                digest = digest
                    .wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013b)
                    .wrapping_add(of(read));
            }
            if self
                .seconds
                .get(&second)
                .is_some_and(|held| held.digest == digest)
            {
                reused += 1;
                continue;
            }
            built += 1;
            let events = raw.events(second);
            let mut pairs = BTreeMap::new();
            for (a, b) in raw.pairs(second) {
                let (ca, cb) = (&clocks[a as usize], &clocks[b as usize]);
                if let Some(block) =
                    raw.block((a, b), second, (ca.timebase, cb.timebase), (None, None))
                {
                    pairs.insert((ca.key, cb.key), Arc::new(block));
                }
            }
            self.seconds.insert(
                second,
                Held {
                    digest,
                    events,
                    pairs,
                },
            );
        }
        (built, reused)
    }

    /// The second's blocks.
    pub(super) fn second(&self, second: u64) -> Option<&Held> {
        self.seconds.get(&second)
    }
}
