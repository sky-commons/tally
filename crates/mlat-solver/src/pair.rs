//! The pairwise clock-sync path (crate docs, § The pairwise path): every refit fits each pair of
//! clocks that co-heard the window's sync events in closed form, the clocks' noise and rates at
//! the fixed point of the pairs fitted under them, and publishes them as one [`PairModel`]; a
//! holder of the window verifies it once ([`crate::verify::verify_pair_model`]); every fix is
//! normalised by a weighted least-squares adjustment over the published pairs among its hearers
//! ([`Prepared::normalise`]), and a verifier holding the verified model and the fix's receptions
//! alone checks it ([`crate::verify::verify_pair_fix`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use tally_wire::{PublicKey, Region};

use crate::clock::{ClockKey, KNOT_PS, ModelTime, SPEC_VERSION, Timebase};
use crate::geo::{self, C};
use crate::linalg::{self, Cholesky, Matrix, Vec3};
use crate::obs::{ObservationId, Reception, Site};
use crate::scope::{Citation, Frontier, Inputs, Trailing};
use crate::solve::{self, Item, Problem};
use crate::sync::{self, ReadCache};
use crate::verify::PairModelFailure;

mod blocks;

use blocks::{BlockCache, Kept, PairBlock, Raw, Step};
pub use blocks::{LINE_BLOCKS, LINE_LEAST, READ_BACK_MS};

/// The receivers each receiver keeps as its pairs' other ends: its nearest usable receivers within
/// `PAIR_BASELINE_MM` by exact integer squared distance between millimetre sites, ties to the
/// lower key (`Network`).
pub const PAIR_NEIGHBOURS: usize = 40;
/// The longest baseline a pair may have, millimetres (`sync::MAX_RANGE_M`).
pub const PAIR_BASELINE_MM: i64 = 600_000_000;
/// The edge of the cubes the network's spatial index buckets sites in, millimetres.
const CELL_MM: i64 = PAIR_BASELINE_MM / 4;
/// Rounds of jump attribution a refit makes at most (`settle`).
pub const JUMP_ROUNDS_MOST: usize = 4;
/// Pairs of a clock whose jumps must agree on its time before the clock is given it.
pub const JUMP_AGREE_LEAST: usize = 2;
/// A loop-closure residual above this many standard deviations rejects its pair from a fix.
pub const LOOP_Z: f64 = 5.0;
/// Pairs a fix rejects at most.
pub const LOOP_REJECTS_MOST: usize = 8;
/// Clocks outside a fix's hearers that may join its split hearer graph.
pub const BRIDGES_MOST: usize = 3;
/// The prior on a clock's absolute rate error: a GNSS-disciplined timebase, and a free-running
/// one (dimensionless).
pub const GNSS_RATE_SIGMA: f64 = 1e-9;
pub const FREE_RATE_SIGMA: f64 = 200e-6;
/// The degrees of freedom a pair's own between-aircraft inflation is shrunk toward the pooled by.
pub const KAPPA_PRIOR_DOF: f64 = 20.0;
/// Fixed-point passes a refit makes at most before it publishes nothing.
pub const PASSES_MOST: usize = 6;
/// How far a pair's published knots may sit from their optimum under the published noise and
/// rates: the squared Mahalanobis length of the Gauss-Newton step (`verify_pair_model`).
pub const PAIR_OPTIMALITY_TOLERANCE: f64 = 1e-4;
/// The same of the rates, a clock: the step's squared length over the rate system is at most this
/// times the clocks.
pub const RATE_OPTIMALITY_TOLERANCE: f64 = 1e-4;
/// The relative difference a published derived value (a pair's covariance and slope, a clock's
/// rate variances) may have from the verifier's.
pub const DERIVED_TOLERANCE: f64 = 1e-6;
/// The same of an inflation, a pair's or the pooled: a chi-square of residuals, which the rates'
/// last step moves by far less than this.
pub const KAPPA_TOLERANCE: f64 = 1e-3;
/// The most knots a pair holds: the knot intervals of `a`'s grid a window's points can lie in, its
/// span and the batching either side of it, one interval more than the span alone.
pub const PAIR_KNOTS_MOST: usize =
    (tally_wire::budget::TRAILING_WINDOW_MS as i128 * 1_000_000_000 / KNOT_PS) as usize + 3;

/// The grouping gate, picoseconds: 3 ms, the light time across 900 km, more than any two
/// receivers that can hear one aircraft are apart (each within 450 km of it), and far less than
/// the shortest interval between two identical transmissions (an all-call squitter repeats after
/// 0.8 s at the earliest).
pub const GATE_PS: i128 = 3_000_000_000;

/// The most receivers a fix is solved from (crate docs, § Solving, the cap): the knee of accuracy
/// against a fix's cost at world density. A transmission heard by more is solved from this many of
/// them, chosen by their sites alone (`Models::capped`), so a fix's cost is bounded whatever the
/// density.
pub const HEARERS_MOST: usize = 32;

const KNOT_NS: f64 = (KNOT_PS / 1000) as f64;
const NS2_TO_M2: f64 = C * C * 1e-18;
/// How far a refit keeps a clock's noise from its estimate either way before taking the estimate:
/// half the verifier's band.
const NOISE_HOLD: f64 = crate::verify::NOISE_BAND / 2.0;

/// Which pairs of receivers exist: decided by their site records alone, each receiver's
/// `PAIR_NEIGHBOURS` nearest within `PAIR_BASELINE_MM` (what it keeps), a pair when either keeps
/// the other. An area's network (`Network::of_area`) has the pairs its own receivers keep alone,
/// so each pair is fitted where an end that keeps it is (crate docs, § Areas). A receiver joining
/// or leaving changes only the pairs of receivers that count it among their nearest.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Network {
    neighbours: BTreeMap<PublicKey, Vec<PublicKey>>,
    kept: BTreeMap<PublicKey, Vec<PublicKey>>,
    pairs: usize,
}

fn distance2_mm(a: [i64; 3], b: [i64; 3]) -> i128 {
    (0..3)
        .map(|axis| {
            let d = i128::from(a[axis]) - i128::from(b[axis]);
            d * d
        })
        .sum()
}

impl Network {
    /// The network of `sites` (crate docs, § The pairwise path, the network): every receiver's
    /// kept pairs.
    pub fn of(sites: &[Site]) -> Self {
        Self::keeping(sites, |_| true)
    }

    /// The network of `area` over `sites`: the pairs each of its receivers (`area::of`) keeps,
    /// among every receiver of `sites`. Over an area's members (`scope::Sites::members`) it is
    /// what it is over every site, since a member's kept receivers are members.
    pub fn of_area(sites: &[Site], area: Region) -> Self {
        Self::keeping(sites, |site| crate::area::of(site) == Some(area))
    }

    fn keeping(sites: &[Site], keeper: impl Fn(&Site) -> bool) -> Self {
        let mut usable: Vec<(PublicKey, [i64; 3], bool)> = sites
            .iter()
            .filter(|site| site.usable())
            .map(|site| (site.receiver, site.mm(), keeper(site)))
            .collect();
        usable.sort_by_key(|site| site.0);
        usable.dedup_by(|a, b| a.0 == b.0);
        let cell = |mm: [i64; 3]| mm.map(|axis| axis.div_euclid(CELL_MM));
        let mut grid: HashMap<[i64; 3], Vec<usize>> = HashMap::new();
        for (at, (_, mm, _)) in usable.iter().enumerate() {
            grid.entry(cell(*mm)).or_default().push(at);
        }
        let baseline2 = i128::from(PAIR_BASELINE_MM) * i128::from(PAIR_BASELINE_MM);
        let mut neighbours: BTreeMap<PublicKey, BTreeSet<PublicKey>> = BTreeMap::new();
        let mut kept: BTreeMap<PublicKey, Vec<PublicKey>> = BTreeMap::new();
        let mut found: Vec<(i128, PublicKey)> = Vec::new();
        for (i, (key, mm, keeps)) in usable.iter().enumerate() {
            if !keeps {
                continue;
            }
            found.clear();
            let home = cell(*mm);
            let mut ring: i64 = 0;
            loop {
                for dx in -ring..=ring {
                    for dy in -ring..=ring {
                        for dz in -ring..=ring {
                            if dx.abs().max(dy.abs()).max(dz.abs()) != ring {
                                continue;
                            }
                            let Some(list) = grid.get(&[home[0] + dx, home[1] + dy, home[2] + dz])
                            else {
                                continue;
                            };
                            for j in list {
                                if *j == i {
                                    continue;
                                }
                                let d2 = distance2_mm(*mm, usable[*j].1);
                                if d2 <= baseline2 {
                                    found.push((d2, usable[*j].0));
                                }
                            }
                        }
                    }
                }
                // Every site within `ring` cells' width is found.
                let reach = i128::from(ring) * i128::from(CELL_MM);
                let within = found.iter().filter(|(d2, _)| *d2 <= reach * reach).count();
                if within >= PAIR_NEIGHBOURS || reach >= i128::from(PAIR_BASELINE_MM) {
                    break;
                }
                ring += 1;
            }
            found.sort_unstable();
            let mut mine: Vec<PublicKey> = found
                .iter()
                .take(PAIR_NEIGHBOURS)
                .map(|(_, other)| *other)
                .collect();
            for other in &mine {
                neighbours.entry(*key).or_default().insert(*other);
                neighbours.entry(*other).or_default().insert(*key);
            }
            mine.sort_unstable();
            kept.insert(*key, mine);
        }
        let pairs = neighbours.values().map(BTreeSet::len).sum::<usize>() / 2;
        Self {
            neighbours: neighbours
                .into_iter()
                .map(|(key, set)| (key, set.into_iter().collect()))
                .collect(),
            kept,
            pairs,
        }
    }

    /// Bytes it holds, as allocated: each receiver's neighbours and kept pairs.
    pub fn bytes(&self) -> usize {
        use tally_wire::footprint::{btree, vec};
        let lists = |map: &BTreeMap<PublicKey, Vec<PublicKey>>| {
            btree::<PublicKey, Vec<PublicKey>>(map.len())
                + map
                    .values()
                    .map(|list| vec::<PublicKey>(list.capacity()))
                    .sum::<usize>()
        };
        lists(&self.neighbours) + lists(&self.kept)
    }

    /// The receivers `receiver` keeps as its pairs' other ends, ascending: none for one that is
    /// not a keeper of this network.
    pub fn kept(&self, receiver: &PublicKey) -> &[PublicKey] {
        self.kept.get(receiver).map_or(&[], Vec::as_slice)
    }

    /// Whether receivers `a` and `b` are a pair.
    pub fn has(&self, a: &PublicKey, b: &PublicKey) -> bool {
        self.neighbours
            .get(a)
            .is_some_and(|list| list.binary_search(b).is_ok())
    }

    /// A receiver's pairs' other ends, ascending.
    pub fn neighbours(&self, receiver: &PublicKey) -> &[PublicKey] {
        self.neighbours.get(receiver).map_or(&[], Vec::as_slice)
    }

    pub fn len(&self) -> usize {
        self.pairs
    }

    pub fn is_empty(&self) -> bool {
        self.pairs == 0
    }
}

/// One clock of the window, or of a published model, as the pairs read it.
#[derive(Clone, Debug)]
struct Clock {
    key: ClockKey,
    timebase: Timebase,
    site: Vec3,
    site_mm: [i64; 3],
    site_m2: f64,
    /// The lowest linear count of its sync receptions in the window: what a fix's raw is unwrapped
    /// near.
    lowest: i64,
    /// The latest Unix nanoseconds its `lowest` count can have been heard at ([`heard_bound`]).
    heard_ns: u64,
}

/// The latest Unix nanoseconds a clock's count `lowest` can have been heard at, by the wall clocks
/// of the batches that carried its sync receptions in the window, `heard` (linear count, batch
/// wall clock in milliseconds): a batch is signed after the receptions it carries, so each was
/// heard at or before its batch's wall clock, and `lowest` at or before that less the clock's
/// nominal time from it to the reception. The least of these is the bound (crate docs, § The
/// pairwise path, the adjustment: what dates a free-running reference's reading).
fn heard_bound(timebase: Timebase, lowest: i64, heard: impl Iterator<Item = (i64, u64)>) -> u64 {
    heard
        .map(|(linear, wall_ms)| {
            let wall_ns = i128::from(wall_ms) * 1_000_000;
            let since_ps = timebase.elapsed_ps(i128::from(linear) - i128::from(lowest));
            // In 64 bits whenever they hold it: the same quotient, without the 128-bit call.
            let since_ns =
                i64::try_from(since_ps).map_or(since_ps / 1000, |ps| i128::from(ps / 1000));
            u64::try_from(wall_ns - since_ns).unwrap_or(0)
        })
        .min()
        .unwrap_or(0)
}

/// The window as the pairs read it (crate docs, § The pairwise path, the window): its clocks,
/// every pair of them the network names with enough points to fit, and each one's blocks.
struct Window {
    /// In key order: every clock with a sync reception in the window's own seconds.
    clocks: Vec<Clock>,
    /// The window's seconds of wall clock, `[first, end)`.
    seconds: (u64, u64),
    events: usize,
    /// Every candidate pair, ascending, `a < b`.
    keys: Vec<(u32, u32)>,
    /// Each candidate's blocks in the window, ascending by second.
    blocks: Vec<Vec<(u64, Arc<PairBlock>)>>,
    slots: HashMap<(u32, u32), u32>,
    /// Each clock's candidates, by index into `keys`, ascending.
    of_clock: Vec<Vec<u32>>,
    /// Seconds whose blocks were built, and reused from the area's last refit.
    built: usize,
    reused: usize,
}

/// The blocks found for each pair of scope indices (the lower first) across a read: each block
/// with the second it was held at.
type FoundBlocks = BTreeMap<(u32, u32), Vec<(u64, Arc<PairBlock>)>>;

impl Window {
    /// The window of `inputs`, its blocks the area's held ones where what they read is unchanged
    /// (`blocks::BlockCache`), and the raw the rest are read from.
    fn read<'r>(inputs: &'r Inputs, cache: &'r mut PairCache) -> (Self, Raw<'r>) {
        let PairCache {
            read,
            network,
            blocks,
        } = cache;
        let network = PairCache::network_of(network, blocks, inputs.area, &inputs.scope);
        let reader = sync::Reader::new(inputs, read);
        let first_ms = inputs.trailing.first_ms();
        let (first, end) = (first_ms / 1000, inputs.trailing.edge_ms / 1000);
        // The window's clocks: those heard in its own seconds, each with its lowest count there
        // and the latest that count can have been heard at.
        let mut window_of = vec![u32::MAX; reader.clocks.len()];
        let mut clocks: Vec<Clock> = Vec::new();
        let mut heard: Vec<Vec<(i64, u64)>> = Vec::new();
        for rx in &reader.rxs {
            if rx.wall_ms < first * 1000 || rx.wall_ms >= end * 1000 {
                continue;
            }
            let site = &reader.clocks[rx.clock];
            if window_of[rx.clock] == u32::MAX {
                window_of[rx.clock] = clocks.len() as u32;
                let sigma = site.sigma_mm as f64 / 1000.0;
                clocks.push(Clock {
                    key: rx.key(),
                    timebase: site.timebase,
                    site: site.ecef,
                    site_mm: site.mm,
                    site_m2: sigma * sigma,
                    lowest: rx.linear,
                    heard_ns: 0,
                });
                heard.push(Vec::new());
            }
            let at = window_of[rx.clock] as usize;
            clocks[at].lowest = clocks[at].lowest.min(rx.linear);
            heard[at].push((rx.linear, rx.wall_ms));
        }
        for (clock, heard) in clocks.iter_mut().zip(heard) {
            clock.heard_ns = heard_bound(clock.timebase, clock.lowest, heard.into_iter());
        }
        let index: BTreeMap<ClockKey, u32> = clocks
            .iter()
            .enumerate()
            .map(|(at, clock)| (clock.key, at as u32))
            .collect();
        let mut by_receiver: BTreeMap<PublicKey, Vec<u32>> = BTreeMap::new();
        for (at, clock) in clocks.iter().enumerate() {
            by_receiver
                .entry(clock.key.receiver)
                .or_default()
                .push(at as u32);
        }
        let above: Vec<Vec<u32>> = clocks
            .iter()
            .enumerate()
            .map(|(a, clock)| {
                let mut list: Vec<u32> = network
                    .neighbours(&clock.key.receiver)
                    .iter()
                    .flat_map(|other| by_receiver.get(other).map_or(&[][..], Vec::as_slice))
                    .copied()
                    .filter(|b| *b > a as u32)
                    .collect();
                list.sort_unstable();
                list
            })
            .collect();
        let mut raw = Raw::new(reader, window_of, above);
        let (built, reused) = blocks.update(&mut raw, &clocks, (first, end));
        let mut events = 0;
        let mut found: FoundBlocks = BTreeMap::new();
        for second in first..end {
            let Some(held) = blocks.second(second) else {
                continue;
            };
            events += held.events;
            for ((ka, kb), block) in &held.pairs {
                if let (Some(a), Some(b)) = (index.get(ka), index.get(kb)) {
                    found
                        .entry((*a, *b))
                        .or_default()
                        .push((second, Arc::clone(block)));
                }
            }
        }
        // A pair with fewer points than a span needs is never valid.
        found.retain(|_, list| {
            list.iter()
                .map(|(_, block)| block.points as usize)
                .sum::<usize>()
                >= sync::SPAN_RECEPTIONS_LEAST
        });
        let mut keys = Vec::with_capacity(found.len());
        let mut blocks_of = Vec::with_capacity(found.len());
        let mut slots = HashMap::with_capacity(found.len());
        let mut of_clock: Vec<Vec<u32>> = vec![Vec::new(); clocks.len()];
        for (at, (key, list)) in found.into_iter().enumerate() {
            slots.insert(key, at as u32);
            of_clock[key.0 as usize].push(at as u32);
            of_clock[key.1 as usize].push(at as u32);
            keys.push(key);
            blocks_of.push(list);
        }
        (
            Self {
                clocks,
                seconds: (first, end),
                events,
                keys,
                blocks: blocks_of,
                slots,
                of_clock,
                built,
                reused,
            },
            raw,
        )
    }

    fn index(&self) -> BTreeMap<ClockKey, u32> {
        self.clocks
            .iter()
            .enumerate()
            .map(|(at, clock)| (clock.key, at as u32))
            .collect()
    }

    /// The candidate of window clocks `(a, b)`, `a < b`.
    fn slot(&self, key: (u32, u32)) -> Option<u32> {
        self.slots.get(&key).copied()
    }
}

/// The noise (whole, nanoseconds) and rate of every window clock a pass fits under.
struct Conditions {
    noise_ns: Vec<f64>,
    rates: Vec<f64>,
}

/// Nanoseconds a linear count is, nominally.
fn ns_per_count(timebase: Timebase) -> f64 {
    match timebase {
        Timebase::Mhz12 => 1000.0 / 12.0,
        Timebase::GpsNanos => 1.0,
    }
}

fn curvature_ns2(timebase: Timebase) -> f64 {
    let sigma = timebase.curvature_sigma_s() * 1e9;
    sigma * sigma
}

fn process_noise(timebase: Timebase) -> (f64, f64) {
    let (phase, rate) = timebase.process_noise();
    ((phase * 1e9) * (phase * 1e9), rate * rate)
}

fn default_noise_ns(timebase: Timebase) -> f64 {
    timebase.default_noise_s() * 1e9
}

/// The median of `values` (reordered): the middle one, or the mean of the middle two.
fn median(values: &mut [f64]) -> f64 {
    let n = values.len();
    if n == 0 {
        return 0.0;
    }
    let (below, middle, _) = values.select_nth_unstable_by(n / 2, f64::total_cmp);
    if n % 2 == 1 {
        *middle
    } else {
        let below = below
            .iter()
            .copied()
            .max_by(f64::total_cmp)
            .unwrap_or(*middle);
        0.5 * (below + *middle)
    }
}

/// [`median`] of sign-free floats given by their bits (`f64::to_bits`), which order as the floats
/// do.
fn median_of_magnitudes(bits: &mut [u64]) -> f64 {
    let n = bits.len();
    if n == 0 {
        return 0.0;
    }
    let (below, middle, _) = bits.select_nth_unstable(n / 2);
    let middle = f64::from_bits(*middle);
    if n % 2 == 1 {
        middle
    } else {
        let below = below.iter().copied().max().map_or(middle, f64::from_bits);
        0.5 * (below + middle)
    }
}

/// The interval a point is in and how far into it: what both its value and its basis weights are.
fn locate(intervals: usize, x: f64) -> (usize, f64) {
    let u = x / KNOT_NS;
    let i = (u.floor().max(0.0) as usize).min(intervals - 1);
    (i, u - i as f64)
}

/// Linear counts of `timebase` in `ps` picoseconds, rounded toward negative infinity.
fn counts_in(timebase: Timebase, ps: i128) -> i128 {
    match timebase {
        Timebase::Mhz12 => (ps * 3).div_euclid(250_000),
        Timebase::GpsNanos => ps.div_euclid(1000),
    }
}

/// Why a candidate pair is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// Fewer than `sync::SPAN_RECEPTIONS_LEAST` points in its kept segments.
    TooFew,
    /// Its normal matrix is not positive definite.
    Singular,
    /// Its span needs more than `PAIR_KNOTS_MOST` knots.
    Long,
    /// A jump in its residuals that no clock of it was given.
    Unattributed,
}

/// The most entries a pair's sums are over: its knots, its two rates and its constant.
const SUMS_MOST: usize = PAIR_KNOTS_MOST + 3;

/// One aircraft's inliers of a pair over the window: their count, weight and squared weight, and
/// the plain and weighted sums of their residuals' coefficients (`PairSums`).
#[derive(Clone, Copy, Debug)]
struct AircraftSums {
    n: f64,
    w: f64,
    ww: f64,
    plain: [f64; SUMS_MOST],
    weighted: [f64; SUMS_MOST],
}

/// One pair's window, summed (crate docs, § The pairwise path, a pair's fit): its blocks' units
/// re-summed in ascending block order. A point's residual is linear in
/// `θ = (k - k⁰, ρ_a, ρ_b, 1)`, the knots from the centre `k⁰` (the pair's own fit at no rate, so
/// every sum is of quantities near the residuals' size, never of the curve's), so every quantity
/// a fit reads is a quadratic form of these sums in `θ`: `sum w0 v vᵀ` and `sum v vᵀ` over the
/// inliers, and each aircraft's `sum v` and `sum w0 v`.
#[derive(Clone, Debug)]
struct PairSums {
    anchor_a: i64,
    anchor_b: i64,
    /// Its knots: `intervals + 1`, the first at `anchor_a`.
    size: usize,
    centre: Vec<f64>,
    /// The curvature prior's scale on the pair's points (`sum w0 / (n sigma_c²)`).
    prior: f64,
    weighted: [[f64; SUMS_MOST]; SUMS_MOST],
    plain: [[f64; SUMS_MOST]; SUMS_MOST],
    /// In address order.
    aircraft: Vec<AircraftSums>,
    /// `sum w0` and `sum w0²` over the inliers.
    w: f64,
    ww: f64,
    inliers: usize,
    points: usize,
}

/// The curvature prior's normal matrix over `size` knots at `scale`: each interior knot's second
/// difference.
fn prior_normal(size: usize, scale: f64) -> Matrix {
    let mut normal = Matrix::zeros(size);
    for j in 1..size.saturating_sub(1) {
        let d = [(j - 1, 1.0), (j, -2.0), (j + 1, 1.0)];
        for (r, a) in d {
            for (s, b) in d {
                normal.add(r, s, scale * a * b);
            }
        }
    }
    normal
}

impl PairSums {
    /// The sums of a pair's blocks (`blocks`, ascending by second, its clocks' timebases
    /// `timebases`), with the prior's curvature variance `curvature_var` and the noise variance its
    /// centre is fitted at `var_centre`.
    fn of(
        blocks: &[&PairBlock],
        (ta, tb): (Timebase, Timebase),
        curvature_var: f64,
        var_centre: f64,
    ) -> Result<Self, Invalid> {
        let points: usize = blocks.iter().map(|block| block.points as usize).sum();
        if points < sync::SPAN_RECEPTIONS_LEAST {
            return Err(Invalid::TooFew);
        }
        let mut knots = blocks
            .iter()
            .flat_map(|block| &block.units)
            .map(|unit| unit.knot);
        let Some(first) = knots.next() else {
            return Err(Invalid::Singular);
        };
        let (low, high) = knots.fold((first, first), |(low, high), knot| {
            (low.min(knot), high.max(knot))
        });
        let size = usize::try_from(high - low + 2).unwrap_or(usize::MAX);
        if size > PAIR_KNOTS_MOST {
            return Err(Invalid::Long);
        }
        let (ka, kb) = (ns_per_count(ta), ns_per_count(tb));
        let anchor_a = low * ta.knot_counts();
        // `b`'s anchor where `b` reads what `a` reads at its anchor, by the first block's first
        // point, so the curve is near zero and every sum near the residuals' size.
        let refs = blocks[0].refs;
        let since_ps = ta.elapsed_ps(i128::from(refs.0) - i128::from(anchor_a));
        let anchor_b = i64::try_from(i128::from(refs.1) - counts_in(tb, since_ps))
            .map_err(|_| Invalid::Long)?;
        let shift = |block: &PairBlock| {
            (block.refs.1 - anchor_b) as f64 * kb - (block.refs.0 - anchor_a) as f64 * ka
        };
        // The centre: the knots' fit at no rate under `var_centre`.
        let (mut w, mut ww, mut n) = (0.0, 0.0, 0.0);
        for unit in blocks.iter().flat_map(|block| &block.units) {
            let m = |r, s| unit.weighted[blocks::at(r, s)];
            let p = |r, s| unit.plain[blocks::at(r, s)];
            w += m(0, 0) + 2.0 * m(0, 1) + m(1, 1);
            n += p(0, 0) + 2.0 * p(0, 1) + p(1, 1);
            ww += unit.ww;
        }
        let prior = w / (n * curvature_var);
        let mut normal = prior_normal(size, var_centre * prior);
        let mut rhs = vec![0.0; size];
        for block in blocks {
            let delta = shift(block);
            for unit in &block.units {
                let i = (unit.knot - low) as usize;
                let m = |r, s| unit.weighted[blocks::at(r, s)];
                let c = [unit.alpha + delta, unit.alpha + unit.beta + delta, 1.0];
                for (side, knot) in [(0, i), (1, i + 1)] {
                    for (other, column) in [(0, i), (1, i + 1)] {
                        normal.add(knot, column, m(side, other));
                    }
                    rhs[knot] += (0..3).map(|q| m(side, q) * c[q]).sum::<f64>();
                }
            }
        }
        let centre = normal.cholesky().ok_or(Invalid::Singular)?.solve(&rhs);
        // The sums in `θ`: each unit's regressors `z = (1 - f, f, r, range_a, -range_b)` as
        // `v = T z`, `T` its knots' and the constant's rows.
        let one = size + 2;
        let mut weighted = [[0.0; SUMS_MOST]; SUMS_MOST];
        let mut plain = [[0.0; SUMS_MOST]; SUMS_MOST];
        let mut aircraft: BTreeMap<u32, AircraftSums> = BTreeMap::new();
        for block in blocks {
            let delta = shift(block);
            for unit in &block.units {
                let i = (unit.knot - low) as usize;
                let d0 = unit.alpha + delta - centre[i];
                let d1 = unit.alpha + unit.beta + delta - centre[i + 1];
                // Each row of `T`: its place in `θ`, and its coefficients on `z`.
                let rows: [(usize, [f64; 5]); 5] = [
                    (i, [-1.0, 0.0, 0.0, 0.0, 0.0]),
                    (i + 1, [0.0, -1.0, 0.0, 0.0, 0.0]),
                    (size, [0.0, 0.0, 0.0, 1.0, 0.0]),
                    (size + 1, [0.0, 0.0, 0.0, 0.0, 1.0]),
                    (one, [d0, d1, 1.0, 0.0, 0.0]),
                ];
                for (target, upper) in [(&mut weighted, &unit.weighted), (&mut plain, &unit.plain)]
                {
                    // `T M`: each row's coefficients against `M`'s columns.
                    let mut tm = [[0.0; 5]; 5];
                    for (row, (_, coefficients)) in rows.iter().enumerate() {
                        for column in 0..5 {
                            tm[row][column] = (0..5)
                                .filter(|q| coefficients[*q] != 0.0)
                                .map(|q| coefficients[q] * upper[blocks::at(q, column)])
                                .sum();
                        }
                    }
                    for (r, (place_r, _)) in rows.iter().enumerate() {
                        for (place_s, coefficients) in &rows {
                            let value: f64 = (0..5)
                                .filter(|q| coefficients[*q] != 0.0)
                                .map(|q| tm[r][q] * coefficients[q])
                                .sum();
                            target[*place_r][*place_s] += value;
                        }
                    }
                }
                for sums in &unit.aircraft {
                    let entry = aircraft.entry(sums.address).or_insert(AircraftSums {
                        n: 0.0,
                        w: 0.0,
                        ww: 0.0,
                        plain: [0.0; SUMS_MOST],
                        weighted: [0.0; SUMS_MOST],
                    });
                    entry.n += sums.plain[0] + sums.plain[1];
                    entry.w += sums.weighted[0] + sums.weighted[1];
                    entry.ww += sums.ww;
                    for (place, coefficients) in &rows {
                        entry.plain[*place] +=
                            (0..5).map(|q| coefficients[q] * sums.plain[q]).sum::<f64>();
                        entry.weighted[*place] += (0..5)
                            .map(|q| coefficients[q] * sums.weighted[q])
                            .sum::<f64>();
                    }
                }
            }
        }
        Ok(Self {
            anchor_a,
            anchor_b,
            size,
            centre,
            prior,
            weighted,
            plain,
            aircraft: aircraft.into_values().collect(),
            w,
            ww,
            inliers: n.round() as usize,
            points,
        })
    }

    /// The knots' normal matrix and right-hand side in `k - k⁰` under noise variance `var` and
    /// rates `rates`.
    fn normal(&self, var: f64, rates: (f64, f64)) -> (Matrix, Vec<f64>) {
        let size = self.size;
        let mut normal = prior_normal(size, self.prior);
        for r in 0..size {
            for s in 0..size {
                normal.add(r, s, self.weighted[r][s] / var);
            }
        }
        let rest = [rates.0, rates.1, 1.0];
        let curvature = prior_normal(size, self.prior).mul_vec(&self.centre);
        let rhs = (0..size)
            .map(|r| {
                -(0..3)
                    .map(|q| self.weighted[r][size + q] * rest[q])
                    .sum::<f64>()
                    / var
                    - curvature[r]
            })
            .collect();
        (normal, rhs)
    }

    /// The pair's fit under noise variance `var` and rates `rates`: its knots' optimum, assessed.
    fn solve(&self, var: f64, rates: (f64, f64)) -> Option<PairFit> {
        let (normal, rhs) = self.normal(var, rates);
        let step = normal.cholesky()?.solve(&rhs);
        let knots: Vec<f64> = self.centre.iter().zip(&step).map(|(c, s)| c + s).collect();
        self.assess(var, rates, knots)
    }

    /// Everything about the pair at `knots` under noise variance `var` and rates `rates`: what a
    /// fit ends with and a verifier checks.
    fn assess(&self, var: f64, rates: (f64, f64), knots: Vec<f64>) -> Option<PairFit> {
        let size = self.size;
        let intervals = size - 1;
        if knots.len() != size {
            return None;
        }
        let (normal, rhs) = self.normal(var, rates);
        let cholesky = normal.cholesky()?;
        let inverse = cholesky.inverse_triangular();
        let mut theta = [0.0; SUMS_MOST];
        for r in 0..size {
            theta[r] = knots[r] - self.centre[r];
        }
        theta[size] = rates.0;
        theta[size + 1] = rates.1;
        theta[size + 2] = 1.0;
        let m = size + 3;
        let moved = normal.mul_vec(&theta[..size]);
        let q: Vec<f64> = moved.iter().zip(&rhs).map(|(m, r)| m - r).collect();
        let step = cholesky.solve(&q);
        let distance: f64 = step.iter().zip(&q).map(|(s, g)| s * g).sum();
        let dot = |a: &[f64], b: &[f64]| -> f64 { a.iter().zip(b).map(|(x, y)| x * y).sum() };
        let form = |gram: &[[f64; SUMS_MOST]; SUMS_MOST], x: &[f64; SUMS_MOST]| -> f64 {
            (0..m)
                .map(|r| x[r] * (0..m).map(|s| gram[r][s] * x[s]).sum::<f64>())
                .sum()
        };
        // The range regressors (`sum w φ d`), their own information and the gradient.
        let v: [Vec<f64>; 2] = [0, 1].map(|side| {
            (0..size)
                .map(|r| -self.weighted[r][size + side] / var)
                .collect()
        });
        let dwd = [
            self.weighted[size][size] / var,
            self.weighted[size][size + 1] / var,
            self.weighted[size + 1][size + 1] / var,
        ];
        let gradient = [0, 1].map(|side| {
            (0..m)
                .map(|s| self.weighted[size + side][s] * theta[s])
                .sum::<f64>()
                / var
        });
        let u = [cholesky.solve(&v[0]), cholesky.solve(&v[1])];
        let explained = [dot(&v[0], &u[0]), dot(&v[0], &u[1]), dot(&v[1], &u[1])];
        let range_info = [
            dwd[0] - explained[0],
            dwd[1] - explained[1],
            dwd[2] - explained[2],
        ];
        // Reduced: what the gradient is once the knots are at their optimum, to first order.
        let gradient = [gradient[0] + dot(&u[0], &q), gradient[1] + dot(&u[1], &q)];
        // The trace of the fit's hat matrix over the inliers: the degrees of freedom the knots take.
        let mut leverage = 0.0;
        for r in 0..size {
            for s in 0..size {
                leverage += inverse.get(r, s) * self.weighted[r][s] / var;
            }
        }
        let whole = form(&self.plain, &theta).max(0.0);
        let (mut within, mut shared, mut chi) = (whole, 0.0, 0.0);
        let mut heard = 0usize;
        for one in &self.aircraft {
            if one.n <= 0.0 {
                continue;
            }
            heard += 1;
            let sum: f64 = (0..m).map(|r| one.plain[r] * theta[r]).sum();
            within -= sum * sum / one.n;
            // What the knots explain of its mean: `bᵀ N⁻¹ (w b)` over its count, `b` its knot
            // regressors' sums.
            let mut explained = 0.0;
            for r in 0..size {
                for s in 0..size {
                    explained += one.plain[r] * inverse.get(r, s) * one.weighted[s] / var;
                }
            }
            shared += explained / one.n;
            // Between aircraft: its weighted mean residual against its own variance.
            let weighted: f64 = (0..m).map(|r| one.weighted[r] * theta[r]).sum();
            chi += weighted * weighted / (var * one.ww);
        }
        let within = within.max(0.0);
        let inliers = self.inliers;
        // The residual degrees of freedom, as a weighted least-squares fit's are counted: the
        // inliers less the trace of the hat matrix (and, within, less the aircraft means and plus
        // what of the knots they hold).
        let dofs = [
            (inliers as f64 - leverage).max(1.0),
            (inliers as f64 - heard as f64 - leverage + shared).max(1.0),
        ];
        let mut cov = vec![0.0; size * size];
        for r in 0..size {
            for s in 0..size {
                cov[r * size + s] = inverse.get(r, s);
            }
        }
        let length = intervals as f64 * KNOT_NS;
        let slope = (knots[intervals] - knots[0]) / length;
        let slope_var =
            (cov[intervals * size + intervals] + cov[0] - 2.0 * cov[intervals]) / (length * length);
        Some(PairFit {
            anchor_a: self.anchor_a,
            anchor_b: self.anchor_b,
            knots,
            cov,
            chi,
            dof: heard.saturating_sub(1),
            scatter: [(whole / dofs[0], dofs[0]), (within / dofs[1], dofs[1])],
            slope,
            slope_var: slope_var.max(1e-30),
            kappa: 1.0,
            range_info,
            explained,
            gradient,
            distance,
            inliers,
            points: self.points,
            share: self.ww / self.w.max(f64::MIN_POSITIVE),
        })
    }
}

/// One pair's fit, everything the model publishes of it and what the clocks' noise and rates are
/// estimated from.
#[derive(Clone, Debug)]
struct PairFit {
    anchor_a: i64,
    anchor_b: i64,
    knots: Vec<f64>,
    /// Its covariance before inflation, row major, nanoseconds².
    cov: Vec<f64>,
    /// Its aircraft means' chi-square against their own variances, and its degrees of freedom.
    chi: f64,
    dof: usize,
    /// The inliers' mean squared residual and its degrees of freedom, what the fit leaves them:
    /// whole, and within each aircraft.
    scatter: [(f64, f64); 2],
    slope: f64,
    slope_var: f64,
    kappa: f64,
    /// Its information on the two clocks' rates from the points' ranges, the knots profiled out
    /// (`S`: aa, ab, bb), and the part the knots explain (`dᵀWd - S`).
    range_info: [f64; 3],
    explained: [f64; 3],
    /// The gradient of its weighted sum of squares in the two rates, reduced by the knots'.
    gradient: [f64; 2],
    /// The squared Mahalanobis length of its knots' Gauss-Newton step (zero at a fit's own end).
    distance: f64,
    inliers: usize,
    points: usize,
    /// What its own points alone, under their own variances, give its curve's variance as a
    /// multiple of its covariance's: `sum w^2 var / sum w` over its inliers (crate docs, § The
    /// pairwise path, the adjustment).
    share: f64,
}

/// What a candidate pair's blocks give under its clocks' kept segments.
#[derive(Clone, Debug)]
enum Outcome {
    Fit(Box<PairSums>),
    /// A step in its pooled residuals, the counts either side of it on each clock.
    Jump {
        a: (i64, i64),
        b: (i64, i64),
    },
    Invalid(Invalid),
}

/// A candidate's blocks under its clocks' kept segments starting at `from`, and what they give: its
/// sums, the largest step located in the window's seconds, or why it is not valid. A block a
/// segment's start cuts is built again from the raw of its kept points ([`blocks::Kept`]).
fn evaluate(window: &Window, raw: &mut Raw<'_>, at: u32, from: &[Option<i64>]) -> Outcome {
    let (a, b) = window.keys[at as usize];
    let (ca, cb) = (&window.clocks[a as usize], &window.clocks[b as usize]);
    let timebases = (ca.timebase, cb.timebase);
    let kept = (from[a as usize], from[b as usize]);
    let mut owned: Vec<Arc<PairBlock>> = Vec::new();
    for (second, block) in &window.blocks[at as usize] {
        match block.kept(kept) {
            Kept::Whole => owned.push(Arc::clone(block)),
            Kept::Gone => {}
            Kept::Cut => {
                if let Some(block) = raw.block((a, b), *second, timebases, kept) {
                    owned.push(Arc::new(block));
                }
            }
        }
    }
    let blocks: Vec<&PairBlock> = owned.iter().map(Arc::as_ref).collect();
    let points: usize = blocks.iter().map(|block| block.points as usize).sum();
    if points < sync::SPAN_RECEPTIONS_LEAST {
        return Outcome::Invalid(Invalid::TooFew);
    }
    let (first, end) = window.seconds;
    let step = blocks
        .iter()
        .flat_map(|block| &block.steps)
        .filter(|step| (first..end).contains(&step.second))
        .fold(None::<&Step>, |best, step| match best {
            Some(best) if best.score >= step.score => Some(best),
            _ => Some(step),
        });
    if let Some(step) = step {
        return Outcome::Jump {
            a: step.a,
            b: step.b,
        };
    }
    let curvature = curvature_ns2(ca.timebase) + curvature_ns2(cb.timebase);
    let centre = default_noise_ns(ca.timebase).powi(2) + default_noise_ns(cb.timebase).powi(2);
    match PairSums::of(&blocks, timebases, curvature, centre) {
        Ok(sums) => Outcome::Fit(Box::new(sums)),
        Err(why) => Outcome::Invalid(why),
    }
}

/// A clock's jump from its pairs' (crate docs, § The pairwise path, jumps): of the intervals its
/// pairs' jumps lie in (each `(last count before, first after]` on this clock), the first count
/// after of the one most of the others contain, ties to the earliest, when at least
/// `JUMP_AGREE_LEAST` do.
fn attribute(intervals: &mut [(i64, i64)]) -> Option<i64> {
    intervals.sort_unstable_by_key(|(lo, hi)| (*hi, *lo));
    let mut best: Option<(usize, i64)> = None;
    for (_, hi) in intervals.iter() {
        let agree = intervals
            .iter()
            .filter(|(lo_q, hi_q)| lo_q < hi && hi <= hi_q)
            .count();
        if best.is_none_or(|(most, _)| agree > most) {
            best = Some((agree, *hi));
        }
    }
    best.filter(|(agree, _)| *agree >= JUMP_AGREE_LEAST)
        .map(|(_, hi)| hi)
}

/// Every candidate of `keys` under its clocks' kept segments, with each clock's jumps attributed
/// from its pairs' (crate docs, § The pairwise path, jumps): from no jump at all, each round
/// evaluates the pairs, gives each clock whose pairs agree on a jump after its present segment's
/// start that jump, and evaluates its pairs again, at most `JUMP_ROUNDS_MOST` rounds; a pair with
/// a jump no clock is given is `Invalid::Unattributed`. A function of the raw alone: neither the
/// noise nor the rates enter it. Returns each clock's segment start too.
fn settle(
    window: &Window,
    raw: &mut Raw<'_>,
    keys: &[u32],
) -> (BTreeMap<u32, Outcome>, Vec<Option<i64>>) {
    let mut from: Vec<Option<i64>> = vec![None; window.clocks.len()];
    let mut outcomes: BTreeMap<u32, Outcome> = keys
        .iter()
        .map(|at| (*at, evaluate(window, raw, *at, &from)))
        .collect();
    for _ in 0..JUMP_ROUNDS_MOST {
        let mut intervals: BTreeMap<u32, Vec<(i64, i64)>> = BTreeMap::new();
        for (at, outcome) in &outcomes {
            if let Outcome::Jump { a, b } = outcome {
                let (ka, kb) = window.keys[*at as usize];
                intervals.entry(ka).or_default().push(*a);
                intervals.entry(kb).or_default().push(*b);
            }
        }
        let mut changed: Vec<u32> = Vec::new();
        for (clock, list) in &mut intervals {
            if let Some(at) = attribute(list)
                && from[*clock as usize].is_none_or(|start| at > start)
            {
                from[*clock as usize] = Some(at);
                changed.push(*clock);
            }
        }
        if changed.is_empty() {
            break;
        }
        let again: BTreeSet<u32> = changed
            .iter()
            .flat_map(|clock| window.of_clock[*clock as usize].iter().copied())
            .filter(|at| outcomes.contains_key(at))
            .collect();
        for at in again {
            outcomes.insert(at, evaluate(window, raw, at, &from));
        }
    }
    for outcome in outcomes.values_mut() {
        if matches!(outcome, Outcome::Jump { .. }) {
            *outcome = Outcome::Invalid(Invalid::Unattributed);
        }
    }
    (outcomes, from)
}

/// The pooled between-aircraft inflation: every pair's chi-square over every pair's degrees of
/// freedom.
fn pooled<'a>(fits: impl Iterator<Item = &'a PairFit>) -> f64 {
    let (chi, dof) = fits.fold((0.0, 0usize), |(chi, dof), fit| {
        (chi + fit.chi, dof + fit.dof)
    });
    if dof == 0 { 1.0 } else { chi / dof as f64 }
}

/// A pair's inflation: its own chi-square shrunk toward the pooled by `KAPPA_PRIOR_DOF`, at least
/// one.
fn kappa_of(fit: &PairFit, pooled: f64) -> f64 {
    ((fit.chi + KAPPA_PRIOR_DOF * pooled) / (fit.dof as f64 + KAPPA_PRIOR_DOF)).max(1.0)
}

/// A symmetric sparse system over the clocks: its diagonal and one entry per pair, applied in one
/// fixed order.
struct Sparse {
    diag: Vec<f64>,
    off: Vec<(u32, u32, f64)>,
}

impl Sparse {
    fn new(n: usize) -> Self {
        Self {
            diag: vec![0.0; n],
            off: Vec::new(),
        }
    }

    fn apply(&self, x: &[f64]) -> Vec<f64> {
        let mut y: Vec<f64> = self.diag.iter().zip(x).map(|(d, v)| d * v).collect();
        for (a, b, v) in &self.off {
            y[*a as usize] += v * x[*b as usize];
            y[*b as usize] += v * x[*a as usize];
        }
        y
    }

    /// Each clock's connected component under the entries, by its lowest clock.
    fn components(&self) -> Vec<u32> {
        let n = self.diag.len();
        let mut parent: Vec<u32> = (0..n as u32).collect();
        fn root(parent: &mut [u32], mut at: u32) -> u32 {
            while parent[at as usize] != at {
                parent[at as usize] = parent[parent[at as usize] as usize];
                at = parent[at as usize];
            }
            at
        }
        for (a, b, _) in &self.off {
            let (ra, rb) = (root(&mut parent, *a), root(&mut parent, *b));
            if ra != rb {
                parent[ra.max(rb) as usize] = ra.min(rb);
            }
        }
        (0..n as u32).map(|at| root(&mut parent, at)).collect()
    }

    /// `1ᵀ A 1` over each component (`components`), at its root (zero at a clock that is none).
    fn component_sums(&self, components: &[u32]) -> Vec<f64> {
        let mut sums = vec![0.0; self.diag.len()];
        for (at, d) in self.diag.iter().enumerate() {
            sums[components[at] as usize] += d;
        }
        for (a, _, v) in &self.off {
            sums[components[*a as usize] as usize] += 2.0 * v;
        }
        sums
    }

    /// `A x = b` by conjugate gradients in fixed order, preconditioned by the diagonal and each
    /// component's constant (crate docs, § The pairwise path, solving the clocks' systems).
    fn solve(&self, b: &[f64]) -> Vec<f64> {
        let n = b.len();
        let components = self.components();
        let sums = self.component_sums(&components);
        let mut totals = vec![0.0; n];
        let mut precondition = |r: &[f64]| -> Vec<f64> {
            totals.fill(0.0);
            for (at, value) in r.iter().enumerate() {
                totals[components[at] as usize] += value;
            }
            r.iter()
                .enumerate()
                .map(|(at, value)| {
                    let c = components[at] as usize;
                    let coarse = if sums[c] > 0.0 {
                        totals[c] / sums[c]
                    } else {
                        0.0
                    };
                    let d = self.diag[at];
                    (if d > 0.0 { value / d } else { 0.0 }) + coarse
                })
                .collect()
        };
        let dot = |a: &[f64], b: &[f64]| -> f64 { a.iter().zip(b).map(|(x, y)| x * y).sum() };
        let mut x = vec![0.0; n];
        let mut r = b.to_vec();
        let mut z = precondition(&r);
        let mut p = z.clone();
        let mut rz = dot(&r, &z);
        let start = rz;
        if start <= 0.0 {
            return x;
        }
        for _ in 0..4 * n + 100 {
            let ap = self.apply(&p);
            let pap = dot(&p, &ap);
            if pap <= 0.0 {
                break;
            }
            let alpha = rz / pap;
            for at in 0..n {
                x[at] += alpha * p[at];
                r[at] -= alpha * ap[at];
            }
            z = precondition(&r);
            let next = dot(&r, &z);
            if next <= start * 1e-28 {
                break;
            }
            let beta = next / rz;
            rz = next;
            for at in 0..n {
                p[at] = z[at] + beta * p[at];
            }
        }
        x
    }
}

/// A pair's weight in a clock noise system at `estimate`: its scatter's degrees of freedom over
/// the square of its two clocks' summed variance (`noise_estimate`).
fn noise_weight(fit: &PairFit, scatter: usize, estimate: &[f64], (a, b): (u32, u32)) -> f64 {
    let (_, dof) = fit.scatter[scatter];
    let (ea, eb) = (estimate[a as usize], estimate[b as usize]);
    let var = ea * ea + eb * eb;
    dof / (var * var).max(1.0)
}

/// The fewest degrees of freedom [`white_estimate`] reads a clock's noise estimate at: a clock its
/// pairs barely tell apart from its neighbours (fewer, or none, as in a component without an odd
/// cycle) is read at twice its estimate, the variance of Student's t at four.
pub const WHITE_DOF_LEAST: f64 = 4.0;

/// Each clock's white noise, nanoseconds, as a fix reads its receptions at: its within-aircraft
/// estimate ([`noise_estimate`], scatter 1) times `ν / (ν - 2)`, the variance of Student's t at
/// the estimate's own degrees of freedom (`ν = 2 σ̂⁴ / Var(σ̂²)`, at least [`WHITE_DOF_LEAST`]), so
/// an error read against an estimated variance is covered as one read against the true variance
/// would be. `Var(σ̂²)` is the estimate's from its system: each pair's mean square has variance
/// `2 s² / dof`, so the estimates' covariance is twice the inverse of the system's normal matrix,
/// held dense and factored once. Before (2026-10-26), the estimate was read as if it were the
/// variance itself, and the sparse scenes' fixes were covered 0.91 to 0.93 where world density's
/// were 0.945: their clocks' noise rests on few pairs of few points, so is often read low.
fn white_estimate<'a>(
    clocks: &[Clock],
    fits: impl Iterator<Item = ((u32, u32), &'a PairFit)> + Clone,
) -> Vec<f64> {
    let mut estimate = noise_estimate(clocks, fits.clone(), 1);
    let n = clocks.len();
    let mut normal = crate::linalg::Matrix::zeros(n);
    for (at, clock) in clocks.iter().enumerate() {
        normal.add(at, at, noise_prior(clock).0);
    }
    for ((a, b), fit) in fits {
        let w = noise_weight(fit, 1, &estimate, (a, b));
        let (a, b) = (a as usize, b as usize);
        normal.add(a, a, w);
        normal.add(b, b, w);
        normal.add(a, b, w);
        normal.add(b, a, w);
    }
    let Some(factored) = normal.cholesky() else {
        return estimate;
    };
    let inverse = factored.inverse_diagonal();
    let (low, high) = (sync::MIN_NOISE_S * 1e9, sync::GAUGE_NOISE_MOST_S * 1e9);
    for (value, inverse) in estimate.iter_mut().zip(&inverse) {
        let variance = *value * *value;
        let dof = (variance * variance / inverse).max(WHITE_DOF_LEAST);
        *value = (variance * dof / (dof - 2.0)).sqrt().clamp(low, high);
    }
    estimate
}

/// A clock's weak prior in a noise system, at its timebase's default: its weight and its
/// variance.
fn noise_prior(clock: &Clock) -> (f64, f64) {
    let default = default_noise_ns(clock.timebase);
    (
        1e-3 / (default * default * default * default),
        default * default,
    )
}

/// How many times [`noise_estimate`] at most weighs its pairs again at its own estimate.
const NOISE_REWEIGHTS_MOST: usize = 50;

/// Each clock's noise from its pairs' inlier scatter (`sigma_a^2 + sigma_b^2` against a pair's
/// mean squared residual), weighed by its degrees of freedom over the square of
/// `sigma_a^2 + sigma_b^2` at the estimate itself (a mean square's precision, read at the noise it
/// is of, never at its own value, which would weigh a pair the more the less it happened to
/// scatter): from each timebase's default, weighed again at the last estimate until no clock's
/// variance moves by more than `1e-9` of itself, at most `NOISE_REWEIGHTS_MOST` times, so the
/// estimate is a function of the pairs alone. A weak prior at its timebase's default holds a clock
/// no pair informs; held to the fit's floor and ceiling. `scatter` 0 is the whole, 1 within each
/// aircraft. Nanoseconds.
fn noise_estimate<'a>(
    clocks: &[Clock],
    fits: impl Iterator<Item = ((u32, u32), &'a PairFit)> + Clone,
    scatter: usize,
) -> Vec<f64> {
    let n = clocks.len();
    let low = sync::MIN_NOISE_S * 1e9;
    let high = sync::GAUGE_NOISE_MOST_S * 1e9;
    let mut estimate: Vec<f64> = clocks
        .iter()
        .map(|clock| default_noise_ns(clock.timebase))
        .collect();
    for _ in 0..NOISE_REWEIGHTS_MOST {
        let mut system = Sparse::new(n);
        let mut rhs = vec![0.0; n];
        for (at, clock) in clocks.iter().enumerate() {
            let (weak, default) = noise_prior(clock);
            system.diag[at] += weak;
            rhs[at] += weak * default;
        }
        for ((a, b), fit) in fits.clone() {
            let (ms, _) = fit.scatter[scatter];
            let w = noise_weight(fit, scatter, &estimate, (a, b));
            system.diag[a as usize] += w;
            system.diag[b as usize] += w;
            system.off.push((a, b, w));
            rhs[a as usize] += w * ms;
            rhs[b as usize] += w * ms;
        }
        let next: Vec<f64> = system
            .solve(&rhs)
            .into_iter()
            .map(|v| v.max(low * low).sqrt().clamp(low, high))
            .collect();
        let moved = next
            .iter()
            .zip(&estimate)
            .any(|(new, old)| (new * new - old * old).abs() > 1e-9 * old * old);
        estimate = next;
        if !moved {
            break;
        }
    }
    estimate
}

/// The rates' system at `rates`: each clock's prior, each valid pair's slope (`rho_b - rho_a`
/// against its variance times its inflation) and its points' ranges (`S` and the reduced
/// gradient over its inflation), each pair fitted at `rates`; the Hessian and the gradient.
fn rate_system<'a>(
    clocks: &[Clock],
    rates: &[f64],
    fits: impl Iterator<Item = ((u32, u32), &'a PairFit)>,
) -> (Sparse, Vec<f64>) {
    let n = clocks.len();
    let mut system = Sparse::new(n);
    let mut gradient = vec![0.0; n];
    for (at, clock) in clocks.iter().enumerate() {
        let sigma = if clock.timebase.disciplined() {
            GNSS_RATE_SIGMA
        } else {
            FREE_RATE_SIGMA
        };
        system.diag[at] += 1.0 / (sigma * sigma);
        gradient[at] += rates[at] / (sigma * sigma);
    }
    for ((a, b), fit) in fits {
        let (a, b) = (a as usize, b as usize);
        let w = 1.0 / (fit.slope_var * fit.kappa);
        let e = rates[b] - rates[a] - fit.slope;
        gradient[b] += w * e;
        gradient[a] -= w * e;
        let s = fit.range_info.map(|value| value / fit.kappa);
        system.diag[a] += w + s[0];
        system.diag[b] += w + s[2];
        system.off.push((a as u32, b as u32, s[1] - w));
        gradient[a] += fit.gradient[0] / fit.kappa;
        gradient[b] += fit.gradient[1] / fit.kappa;
    }
    (system, gradient)
}

/// A clock's rate variance and its component's common one (crate docs, § The pairwise path,
/// rates): the inverse of its diagonal, and of the component's `1ᵀ H 1`.
fn rate_variances(system: &Sparse) -> (Vec<f64>, Vec<f64>) {
    let components = system.components();
    let sums = system.component_sums(&components);
    let own = system.diag.iter().map(|d| 1.0 / d).collect();
    let common = components.iter().map(|c| 1.0 / sums[*c as usize]).collect();
    (own, common)
}

/// What a refit's pairs did.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub clocks: usize,
    pub events: usize,
    pub candidates: usize,
    pub valid: usize,
    /// The valid pairs' points, and of them inliers.
    pub points: usize,
    pub inliers: usize,
    pub jumped: usize,
    pub unattributed: usize,
    pub inflated: usize,
    pub passes: usize,
    /// Passes followed by another because a clock's whole noise changed, and because the rates'
    /// step moved a pair's knots.
    pub again_noise: usize,
    pub again_rates: usize,
    /// Pair solves after the first pass's.
    pub refitted: usize,
    /// Seconds whose blocks were built, and held from the area's last refit.
    pub blocks_built: usize,
    pub blocks_reused: usize,
    /// Nanoseconds reading the window (its blocks), and fitting.
    pub read_ns: u64,
    pub fit_ns: u64,
}

/// Why a refit publishes no model.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum PairError {
    #[error("no valid pair")]
    Empty,
    #[error("the noise and rates did not reach their fixed point in {PASSES_MOST} passes")]
    NotConverged,
}

/// A published clock of a pair model.
#[derive(Clone, Debug, PartialEq)]
pub struct PairClock {
    pub key: ClockKey,
    /// The lowest linear count of its sync receptions in the window.
    pub lowest: i64,
    /// The latest Unix nanoseconds `lowest` can have been heard at, by the wall clocks of the
    /// batches that carried its sync receptions in the window (`heard_bound`): what dates a
    /// free-running clock's readings.
    pub heard_ns: u64,
    /// The first count of its kept segment: the count after its newest attributed jump.
    pub from: Option<i64>,
    /// Its noise, nanoseconds: whole (what weighs its pairs' points) and within each aircraft
    /// (what its receptions carry in a fix).
    pub noise_ns: f64,
    pub white_ns: f64,
    /// Its absolute rate error (dimensionless), the inverse of its row's diagonal in the rates'
    /// system, and of its component's `1ᵀ H 1`.
    pub rate: f64,
    /// Its rate's variances, published as single precision (`f32`): a variance weighs and is
    /// never a datum, so its own rounding (a relative 2⁻²⁴) sits far inside
    /// `DERIVED_TOLERANCE`, and the engine solves under what it publishes.
    pub rate_var: f32,
    pub common_var: f32,
}

/// A published pair: `b`'s nominal time less `a`'s at one instant as a function of `a`'s,
/// nanoseconds from the anchors, linear between knots `KNOT_PS` apart from `a`'s anchor, which is
/// a knot of `a`'s grid (crate docs, § The pairwise path, a pair's fit).
#[derive(Clone, Debug, PartialEq)]
pub struct ClockPair {
    /// Indices into `PairModel::clocks`, `a < b`.
    pub a: u32,
    pub b: u32,
    pub anchor_a: i64,
    pub anchor_b: i64,
    pub knots: Vec<f64>,
    /// The knots' covariance before inflation, nanoseconds², upper triangle row by row. It and
    /// every other variance and multiple below are single precision, as a clock's rate variances
    /// are (`PairClock::rate_var`); the slope is a datum the rates' system reads, so it stays
    /// double, as the knots do.
    pub cov: Vec<f32>,
    pub slope: f64,
    pub slope_var: f32,
    pub kappa: f32,
    /// Its curve's variance from its own points alone as a multiple of its covariance's
    /// (crate docs, § The pairwise path, the adjustment).
    pub share: f32,
}

/// One area's pairwise clock model at one refit edge (crate docs, § The pairwise path, the
/// model): what it is a function of, every clock and every valid pair.
#[derive(Clone, Debug, PartialEq)]
pub struct PairModel {
    pub spec: u16,
    /// The area it is fitted for (crate docs, § Areas).
    pub area: Region,
    pub trailing: Trailing,
    /// The area's members by their signed site records, sorted by key (`scope::Sites::members`).
    pub scope: Vec<Site>,
    pub frontier: Vec<Frontier>,
    pub input: Citation,
    /// The pooled between-aircraft inflation, single precision (`ClockPair::cov`).
    pub kappa: f32,
    /// Every clock with a valid pair, sorted by key.
    pub clocks: Vec<PairClock>,
    /// Every valid pair, sorted.
    pub pairs: Vec<ClockPair>,
}

impl PairModel {
    /// Every list at its length: what a model is held as wherever it is held, so the engine that
    /// fitted it and a relay that decoded it hold the same bytes of it.
    pub fn shrink_to_fit(&mut self) {
        self.scope.shrink_to_fit();
        self.frontier.shrink_to_fit();
        self.clocks.shrink_to_fit();
        self.pairs.shrink_to_fit();
        for pair in &mut self.pairs {
            pair.knots.shrink_to_fit();
            pair.cov.shrink_to_fit();
        }
    }
}

fn upper(cov: &[f64], size: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(size * (size + 1) / 2);
    for r in 0..size {
        for s in r..size {
            out.push(cov[r * size + s]);
        }
    }
    out
}

fn full(upper: &[f32], size: usize) -> Vec<f64> {
    let mut out = vec![0.0; size * size];
    let mut at = 0;
    for r in 0..size {
        for s in r..size {
            out[r * size + s] = f64::from(upper[at]);
            out[s * size + r] = f64::from(upper[at]);
            at += 1;
        }
    }
    out
}

/// What a fitter keeps of an area between refits: the read's memos, the network of the last
/// scope, and the blocks of its last window (crate docs, § The pairwise path, blocks).
#[derive(Default)]
pub struct PairCache {
    read: ReadCache,
    network: Option<(Region, Vec<Site>, Network)>,
    blocks: BlockCache,
}

impl PairCache {
    /// Bytes it holds, as allocated: the read's memos, the network with the scope it is of, and
    /// the blocks.
    pub fn bytes(&self) -> usize {
        self.read.bytes()
            + self.network.as_ref().map_or(0, |(_, scope, network)| {
                tally_wire::footprint::vec::<Site>(scope.capacity()) + network.bytes()
            })
            + self.blocks.bytes()
    }

    /// The network of `scope` in `area`, held while the scope is; a new scope lets every held
    /// block go, since which pairs a block holds is the network's.
    fn network_of<'n>(
        held: &'n mut Option<(Region, Vec<Site>, Network)>,
        blocks: &mut BlockCache,
        area: Region,
        scope: &[Site],
    ) -> &'n Network {
        if held
            .as_ref()
            .is_none_or(|(held_area, sites, _)| *held_area != area || sites != scope)
        {
            *held = Some((area, scope.to_vec(), Network::of_area(scope, area)));
            blocks.clear();
        }
        &held.as_ref().unwrap_or_else(|| unreachable!("set above")).2
    }
}

/// A fitted model and what its refit did.
pub struct Fitted {
    pub model: PairModel,
    pub stats: Stats,
}

/// Fits the area's pair model at its refit edge from the window `inputs` (crate docs, § The
/// pairwise path, the fixed point): its blocks (held in `cache` where what they read is
/// unchanged) and the jumps they show, then the noise and rates at the fixed point of the pairs
/// fitted under them, sought from those of `warm` (the area's previous model) where it holds a
/// clock, else its timebase's default noise and no rate. Each pass solves every valid pair from
/// its sums, estimates the noise and takes a Newton step of the rates; once a pass settles, each
/// pair is published as the verifier assesses it.
pub fn fit(
    inputs: &Inputs,
    warm: Option<&PairModel>,
    cache: &mut PairCache,
) -> Result<Fitted, PairError> {
    let started = std::time::Instant::now();
    let (window, mut raw) = Window::read(inputs, cache);
    let read_ns = started.elapsed().as_nanos() as u64;
    let n = window.clocks.len();
    let index = window.index();
    let mut conditions = Conditions {
        noise_ns: window
            .clocks
            .iter()
            .map(|clock| default_noise_ns(clock.timebase))
            .collect(),
        rates: vec![0.0; n],
    };
    let mut white_ns: Vec<f64> = conditions.noise_ns.clone();
    if let Some(warm) = warm {
        for clock in &warm.clocks {
            if let Some(at) = index.get(&clock.key) {
                conditions.noise_ns[*at as usize] = clock.noise_ns;
                conditions.rates[*at as usize] = clock.rate;
                white_ns[*at as usize] = clock.white_ns;
            }
        }
    }
    let all: Vec<u32> = (0..window.keys.len() as u32).collect();
    let (outcomes, from) = settle(&window, &mut raw, &all);
    raw.finish();
    let valid: Vec<(u32, &PairSums)> = outcomes
        .iter()
        .filter_map(|(at, outcome)| match outcome {
            Outcome::Fit(sums) => Some((*at, sums.as_ref())),
            _ => None,
        })
        .collect();
    if valid.is_empty() {
        return Err(PairError::Empty);
    }
    let var_of = |noise: &[f64], (a, b): (u32, u32)| {
        let (sa, sb) = (noise[a as usize], noise[b as usize]);
        sa * sa + sb * sb
    };
    let rates_of = |rates: &[f64], (a, b): (u32, u32)| (rates[a as usize], rates[b as usize]);
    // How far rates `to` move a pair fitted at rates `from` from its optimum: `Δᵀ (dᵀWd - S) Δ`.
    let drift = |fit: &PairFit, from: (f64, f64), to: (f64, f64)| {
        let (da, db) = (to.0 - from.0, to.1 - from.1);
        let e = fit.explained;
        da * da * e[0] + 2.0 * da * db * e[1] + db * db * e[2]
    };
    let mut again = [0usize; 2];
    let mut refitted = 0usize;
    for pass in 0..PASSES_MOST {
        let mut fits: Vec<((u32, u32), PairFit)> = Vec::with_capacity(valid.len());
        for (at, sums) in &valid {
            let key = window.keys[*at as usize];
            let fit = sums
                .solve(
                    var_of(&conditions.noise_ns, key),
                    rates_of(&conditions.rates, key),
                )
                .ok_or(PairError::NotConverged)?;
            fits.push((key, fit));
        }
        if pass > 0 {
            refitted += fits.len();
        }
        let kappa = pooled(fits.iter().map(|(_, fit)| fit));
        for (_, fit) in &mut fits {
            fit.kappa = kappa_of(fit, kappa);
        }
        let whole = noise_estimate(&window.clocks, fits.iter().map(|(key, fit)| (*key, fit)), 0);
        let within = white_estimate(&window.clocks, fits.iter().map(|(key, fit)| (*key, fit)));
        let (system, gradient) = rate_system(
            &window.clocks,
            &conditions.rates,
            fits.iter().map(|(key, fit)| (*key, fit)),
        );
        let step = system.solve(&gradient);
        let rates: Vec<f64> = conditions
            .rates
            .iter()
            .zip(&step)
            .map(|(rate, step)| rate - step)
            .collect();
        // Held within half the verifier's band of its estimate either way, else the estimate.
        let hold = |held: f64, estimate: f64| {
            if held >= (1.0 - NOISE_HOLD) * estimate && held <= (1.0 + NOISE_HOLD) * estimate {
                held
            } else {
                estimate
            }
        };
        let noise_ns: Vec<f64> = conditions
            .noise_ns
            .iter()
            .zip(&whole)
            .map(|(held, estimate)| hold(*held, *estimate))
            .collect();
        white_ns = white_ns
            .iter()
            .zip(&within)
            .map(|(held, estimate)| hold(*held, *estimate))
            .collect();
        let moved = fits
            .iter()
            .map(|(key, fit)| {
                drift(
                    fit,
                    rates_of(&conditions.rates, *key),
                    rates_of(&rates, *key),
                )
            })
            .fold(0.0, f64::max);
        let noise_held = noise_ns == conditions.noise_ns;
        let rates_held = moved <= PAIR_OPTIMALITY_TOLERANCE / 10.0;
        again[0] += usize::from(!noise_held);
        again[1] += usize::from(!rates_held);
        if noise_held && rates_held {
            // What is published of each pair is its assessment at the published noise and rates,
            // at its own knots: the verifier's computation, so its inflation, covariance and slope
            // are the verifier's to the bit.
            let mut replayed: Vec<((u32, u32), PairFit)> = Vec::with_capacity(fits.len());
            for ((_, sums), (key, fit)) in valid.iter().zip(&fits) {
                match sums.assess(
                    var_of(&noise_ns, *key),
                    rates_of(&rates, *key),
                    fit.knots.clone(),
                ) {
                    Some(again) if again.distance <= PAIR_OPTIMALITY_TOLERANCE => {
                        replayed.push((*key, again));
                    }
                    _ => break,
                }
            }
            if replayed.len() == fits.len() {
                // At the precision they are published at (`ClockPair::cov`), so the rates'
                // variances are made of what the verifier reads, as its are.
                let kappa = single(pooled(replayed.iter().map(|(_, fit)| fit)));
                for (_, fit) in &mut replayed {
                    fit.kappa = single(kappa_of(fit, kappa));
                    fit.slope_var = single(fit.slope_var);
                }
                let (system, _) = rate_system(
                    &window.clocks,
                    &rates,
                    replayed.iter().map(|(key, fit)| (*key, fit)),
                );
                let (rate_var, common_var) = rate_variances(&system);
                let stats = Stats {
                    clocks: n,
                    events: window.events,
                    candidates: window.keys.len(),
                    valid: replayed.len(),
                    points: replayed.iter().map(|(_, fit)| fit.points).sum(),
                    inliers: replayed.iter().map(|(_, fit)| fit.inliers).sum(),
                    jumped: from.iter().flatten().count(),
                    unattributed: outcomes
                        .values()
                        .filter(|outcome| {
                            matches!(outcome, Outcome::Invalid(Invalid::Unattributed))
                        })
                        .count(),
                    inflated: replayed.iter().filter(|(_, fit)| fit.kappa > 1.0).count(),
                    passes: pass + 1,
                    again_noise: again[0],
                    again_rates: again[1],
                    refitted,
                    blocks_built: window.built,
                    blocks_reused: window.reused,
                    read_ns,
                    fit_ns: started.elapsed().as_nanos() as u64 - read_ns,
                };
                let model = assemble(
                    inputs,
                    &window,
                    &replayed,
                    &Conditions {
                        noise_ns: conditions.noise_ns.clone(),
                        rates,
                    },
                    &from,
                    &white_ns,
                    (&rate_var, &common_var),
                    kappa,
                );
                return Ok(Fitted { model, stats });
            }
            again[1] += 1;
        }
        conditions.noise_ns = noise_ns;
        conditions.rates = rates;
    }
    Err(PairError::NotConverged)
}

#[allow(clippy::too_many_arguments, reason = "the parts of one refit")]
fn assemble(
    inputs: &Inputs,
    window: &Window,
    valid: &[((u32, u32), PairFit)],
    conditions: &Conditions,
    from: &[Option<i64>],
    white_ns: &[f64],
    (rate_var, common_var): (&[f64], &[f64]),
    kappa: f64,
) -> PairModel {
    let used: BTreeSet<u32> = valid.iter().flat_map(|((a, b), _)| [*a, *b]).collect();
    let renumber: BTreeMap<u32, u32> = used
        .iter()
        .enumerate()
        .map(|(new, old)| (*old, new as u32))
        .collect();
    let clocks = used
        .iter()
        .map(|at| {
            let at = *at as usize;
            PairClock {
                key: window.clocks[at].key,
                lowest: window.clocks[at].lowest,
                heard_ns: window.clocks[at].heard_ns,
                from: from[at],
                noise_ns: conditions.noise_ns[at],
                white_ns: white_ns[at],
                rate: conditions.rates[at],
                rate_var: rate_var[at] as f32,
                common_var: common_var[at] as f32,
            }
        })
        .collect();
    let pairs = valid
        .iter()
        .map(|((a, b), fit)| ClockPair {
            a: renumber[a],
            b: renumber[b],
            anchor_a: fit.anchor_a,
            anchor_b: fit.anchor_b,
            knots: fit.knots.clone(),
            cov: upper(&fit.cov, fit.knots.len())
                .into_iter()
                .map(|value| value as f32)
                .collect(),
            slope: fit.slope,
            slope_var: fit.slope_var as f32,
            kappa: fit.kappa as f32,
            share: fit.share as f32,
        })
        .collect();
    PairModel {
        spec: SPEC_VERSION,
        area: inputs.area,
        trailing: inputs.trailing,
        scope: inputs.scope.clone(),
        frontier: inputs.frontier.clone(),
        input: inputs.citation,
        kappa: kappa as f32,
        clocks,
        pairs,
    }
}

/// `value` at the single precision a model publishes its variances and multiples in
/// (`ClockPair::cov`).
fn single(value: f64) -> f64 {
    f64::from(value as f32)
}

fn relative(a: f64, b: f64) -> f64 {
    let scale = a.abs().max(b.abs());
    if scale == 0.0 {
        0.0
    } else {
        (a - b).abs() / scale
    }
}

/// The checks of a pair model against the window `inputs` (`verify::verify_pair_model`, crate
/// docs, § The pairwise path, verifying a model).
pub(crate) fn check_model(
    inputs: &Inputs,
    model: &PairModel,
    cache: &mut PairCache,
) -> Vec<PairModelFailure> {
    let mut failures = Vec::new();
    if model.area != inputs.area
        || model.trailing != inputs.trailing
        || model.scope != inputs.scope
        || model.frontier != inputs.frontier
        || model.input != inputs.citation
    {
        failures.push(PairModelFailure::Inputs);
        return failures;
    }
    if !model.clocks.windows(2).all(|w| w[0].key < w[1].key)
        || !model
            .pairs
            .windows(2)
            .all(|w| (w[0].a, w[0].b) < (w[1].a, w[1].b))
        || model
            .pairs
            .iter()
            .any(|pair| pair.a >= pair.b || pair.b as usize >= model.clocks.len())
    {
        failures.push(PairModelFailure::Unordered);
        return failures;
    }
    let (window, mut raw) = Window::read(inputs, cache);
    let index = window.index();
    let n = window.clocks.len();
    // The window index of each model clock.
    let mut at_of: Vec<u32> = Vec::with_capacity(model.clocks.len());
    let mut conditions = Conditions {
        noise_ns: window
            .clocks
            .iter()
            .map(|clock| default_noise_ns(clock.timebase))
            .collect(),
        rates: vec![0.0; n],
    };
    for clock in &model.clocks {
        let Some(at) = index.get(&clock.key) else {
            failures.push(PairModelFailure::Clock(clock.key));
            continue;
        };
        if window.clocks[*at as usize].lowest != clock.lowest
            || window.clocks[*at as usize].heard_ns != clock.heard_ns
        {
            failures.push(PairModelFailure::Clock(clock.key));
        }
        at_of.push(*at);
        conditions.noise_ns[*at as usize] = clock.noise_ns;
        conditions.rates[*at as usize] = clock.rate;
    }
    if !failures.is_empty() {
        raw.finish();
        return failures;
    }
    // The jumps and the drops: the rule's, replayed over every candidate from no jump.
    let all: Vec<u32> = (0..window.keys.len() as u32).collect();
    let (outcomes, from) = settle(&window, &mut raw, &all);
    raw.finish();
    let local: BTreeMap<u32, u32> = at_of
        .iter()
        .enumerate()
        .map(|(new, old)| (*old, new as u32))
        .collect();
    for (clock, at) in model.clocks.iter().zip(&at_of) {
        if clock.from != from[*at as usize] {
            failures.push(PairModelFailure::Jump(clock.key));
        }
    }
    // Every published pair at its published knots.
    let mut published: BTreeMap<u32, PairFit> = BTreeMap::new();
    for pair in &model.pairs {
        let key = (at_of[pair.a as usize], at_of[pair.b as usize]);
        let (ka, kb) = (
            model.clocks[pair.a as usize].key,
            model.clocks[pair.b as usize].key,
        );
        let fail = |why: &'static str| PairModelFailure::Pair { a: ka, b: kb, why };
        let Some(at) = window.slot(key) else {
            failures.push(fail("not a pair of the window"));
            continue;
        };
        let Some(Outcome::Fit(sums)) = outcomes.get(&at) else {
            // The rule finds it not valid: a drop, said below.
            continue;
        };
        if (sums.anchor_a, sums.anchor_b) != (pair.anchor_a, pair.anchor_b) {
            failures.push(fail("anchors"));
            continue;
        }
        if pair.knots.len() != sums.size {
            failures.push(fail("knots"));
            continue;
        }
        let (sa, sb) = (
            conditions.noise_ns[key.0 as usize],
            conditions.noise_ns[key.1 as usize],
        );
        let rates = (
            conditions.rates[key.0 as usize],
            conditions.rates[key.1 as usize],
        );
        let Some(fit) = sums.assess(sa * sa + sb * sb, rates, pair.knots.clone()) else {
            failures.push(fail("singular"));
            continue;
        };
        if fit.distance > PAIR_OPTIMALITY_TOLERANCE {
            failures.push(fail("not optimal"));
        }
        let size = pair.knots.len();
        let cov = upper(&fit.cov, size);
        let (mut difference, mut norm) = (0.0, 0.0);
        for (mine, theirs) in cov.iter().zip(&pair.cov) {
            let theirs = f64::from(*theirs);
            difference += (mine - theirs) * (mine - theirs);
            norm += mine * mine;
        }
        if pair.cov.len() != cov.len()
            || (difference / norm.max(f64::MIN_POSITIVE)).sqrt() > DERIVED_TOLERANCE
        {
            failures.push(fail("covariance"));
        }
        if relative(fit.slope, pair.slope) > DERIVED_TOLERANCE
            || relative(fit.slope_var, f64::from(pair.slope_var)) > DERIVED_TOLERANCE
        {
            failures.push(fail("slope"));
        }
        if relative(fit.share, f64::from(pair.share)) > DERIVED_TOLERANCE {
            failures.push(fail("share"));
        }
        published.insert(at, fit);
    }
    // A pair the rule finds valid and the model does not publish, or the other way round.
    let named: BTreeSet<u32> = model
        .pairs
        .iter()
        .filter_map(|pair| window.slot((at_of[pair.a as usize], at_of[pair.b as usize])))
        .collect();
    for (at, outcome) in &outcomes {
        if matches!(outcome, Outcome::Fit(_)) != named.contains(at) {
            let (a, b) = window.keys[*at as usize];
            failures.push(PairModelFailure::Dropped {
                a: window.clocks[a as usize].key,
                b: window.clocks[b as usize].key,
            });
        }
    }
    if !failures.is_empty() {
        return failures;
    }
    let kappa = pooled(published.values());
    if relative(kappa, f64::from(model.kappa)) > KAPPA_TOLERANCE {
        failures.push(PairModelFailure::Kappa);
    }
    for (pair, (_, fit)) in model.pairs.iter().zip(published.iter_mut()) {
        let own = kappa_of(fit, f64::from(model.kappa));
        // The rates' system is made of what the model publishes, each checked.
        fit.kappa = f64::from(pair.kappa);
        fit.slope = pair.slope;
        fit.slope_var = f64::from(pair.slope_var);
        if relative(own, f64::from(pair.kappa)) > KAPPA_TOLERANCE {
            failures.push(PairModelFailure::Pair {
                a: model.clocks[pair.a as usize].key,
                b: model.clocks[pair.b as usize].key,
                why: "inflation",
            });
        }
    }
    // The noise: none below the rule's estimate by more than the band.
    let clocks: Vec<Clock> = at_of
        .iter()
        .map(|at| window.clocks[*at as usize].clone())
        .collect();
    let valid: Vec<((u32, u32), &PairFit)> = published
        .iter()
        .map(|(at, fit)| {
            let (a, b) = window.keys[*at as usize];
            ((local[&a], local[&b]), fit)
        })
        .collect();
    let whole = noise_estimate(&clocks, valid.iter().copied(), 0);
    let within = white_estimate(&clocks, valid.iter().copied());
    let band = 1.0 - crate::verify::NOISE_BAND;
    for (at, clock) in model.clocks.iter().enumerate() {
        if clock.noise_ns < band * whole[at] || clock.white_ns < band * within[at] {
            failures.push(PairModelFailure::Noise(clock.key));
        }
    }
    // The rates: an optimum of their system, and its variances.
    let rates: Vec<f64> = model.clocks.iter().map(|clock| clock.rate).collect();
    let (system, gradient) = rate_system(&clocks, &rates, valid.iter().copied());
    let step = system.solve(&gradient);
    let distance: f64 = step.iter().zip(&gradient).map(|(s, g)| s * g).sum();
    if distance.is_nan() || distance > RATE_OPTIMALITY_TOLERANCE * clocks.len() as f64 {
        failures.push(PairModelFailure::Rates { distance });
    }
    let (rate_var, common_var) = rate_variances(&system);
    for (at, clock) in model.clocks.iter().enumerate() {
        if relative(rate_var[at], f64::from(clock.rate_var)) > DERIVED_TOLERANCE
            || relative(common_var[at], f64::from(clock.common_var)) > DERIVED_TOLERANCE
        {
            failures.push(PairModelFailure::RateVariance(clock.key));
        }
    }
    failures
}

/// A published pair as a fix reads it.
#[derive(Clone, Debug)]
struct Curve {
    knots: Vec<f64>,
    /// Full, row major.
    cov: Vec<f64>,
    kappa: f64,
    share: f64,
    q_phase: f64,
    q_rate: f64,
    /// Each anchor's elapsed picoseconds (`Timebase::elapsed_ps`).
    origin_a: i128,
    origin_b: i128,
}

impl Curve {
    /// `g(x)`, its variance, that variance as the pair's own points alone give it (the fitted
    /// part times its share), its slope, and how far past the last knot `x` is, `x` in `a`'s
    /// nanoseconds from its anchor; past the last knot carried along the last interval, the
    /// variance growing with the process noise.
    fn at(&self, x: f64) -> (f64, f64, f64, f64, f64) {
        let k = self.knots.len() - 1;
        let (i, f) = locate(k, x);
        let (v0, v1) = (self.knots[i], self.knots[i + 1]);
        let g = (1.0 - f) * v0 + f * v1;
        let slope = (v1 - v0) / KNOT_NS;
        let n = k + 1;
        let c = |r: usize, s: usize| self.cov[r * n + s];
        let mut var = ((1.0 - f) * (1.0 - f) * c(i, i)
            + 2.0 * f * (1.0 - f) * c(i, i + 1)
            + f * f * c(i + 1, i + 1))
            * self.kappa;
        let mut own = var * self.share;
        let past = (x / KNOT_NS - k as f64).max(0.0);
        if past > 0.0 {
            let carried =
                self.q_rate * KNOT_NS * KNOT_NS * past * past * past / 3.0 + self.q_phase * past;
            var += carried;
            own += carried;
        }
        (g, var, own, slope, past * KNOT_NS)
    }

    /// `g(x)` alone, as [`Curve::at`] gives it.
    fn value(&self, x: f64) -> f64 {
        let (i, f) = locate(self.knots.len() - 1, x);
        (1.0 - f) * self.knots[i] + f * self.knots[i + 1]
    }

    /// The `a` time (nanoseconds from its anchor) at which `b` reads `y_b`: `x + g(x) = y_b`.
    fn inverse(&self, y_b: f64) -> f64 {
        let mut x = y_b - self.knots[0];
        for _ in 0..4 {
            x = y_b - self.value(x);
        }
        x
    }

    fn ns_a(&self, absolute_ps: i128) -> f64 {
        ps_as_f64(absolute_ps - self.origin_a) / 1000.0
    }

    fn ns_b(&self, absolute_ps: i128) -> f64 {
        ps_as_f64(absolute_ps - self.origin_b) / 1000.0
    }

    fn abs_a(&self, ns: f64) -> i128 {
        self.origin_a + ps_of_f64((ns * 1000.0).round())
    }

    fn abs_b(&self, ns: f64) -> i128 {
        self.origin_b + ps_of_f64((ns * 1000.0).round())
    }
}

/// `ps as f64`, through 64 bits whenever they hold it: the same nearest float, without 128-bit
/// conversion's call.
fn ps_as_f64(ps: i128) -> f64 {
    match i64::try_from(ps) {
        Ok(small) => small as f64,
        Err(_) => ps as f64,
    }
}

/// `whole as i128` of an integral float, through 64 bits whenever they hold it, as [`ps_as_f64`].
fn ps_of_f64(whole: f64) -> i128 {
    // 2^62: well inside `i64`, so the cast is exact and never saturates.
    if whole.abs() < 4.611_686_018_427_388e18 {
        i128::from(whole as i64)
    } else {
        whole as i128
    }
}

/// A published clock as a fix reads it.
#[derive(Clone, Debug)]
struct Prep {
    clock: Clock,
    white_ns: f64,
    rate: f64,
    rate_var: f64,
    common_var: f64,
    /// Whether the model's pairs identify its noise apart from its neighbours': its component of
    /// the model's pairs holds an odd cycle (`identified`). When they do not, `white_ns` is the
    /// most its pairs allow, not the model's split.
    identified: bool,
    /// How well the model's pairs inform its noise: the sum over its pairs of the inverse square
    /// of their summed white variance (ns⁻⁴), to which the precision of a variance read from a
    /// pair's scatter is proportional.
    information: f64,
}

/// Of each clock of a model's pair graph (`adjacency`), whether its noise is identified apart from
/// its neighbours': a pair's scatter is the sum of its two clocks' noise, so over a component
/// whose graph is bipartite (a star, a tree, an even cycle) one shift, up on one side and down on
/// the other, leaves every pair's sum alone and the split is the prior's, not the data's; a
/// component with an odd cycle (a triangle) has no such shift. Found by two-colouring each
/// component from its lowest clock in index order.
fn identified(adjacency: &[Vec<(u32, u32)>]) -> Vec<bool> {
    let n = adjacency.len();
    let mut colour: Vec<Option<bool>> = vec![None; n];
    let mut out = vec![false; n];
    for start in 0..n {
        if colour[start].is_some() {
            continue;
        }
        colour[start] = Some(false);
        let mut component = vec![start];
        let mut odd = false;
        let mut at = 0;
        while let Some(&clock) = component.get(at) {
            at += 1;
            let side = colour[clock] == Some(true);
            for (other, _) in &adjacency[clock] {
                let other = *other as usize;
                match colour[other] {
                    None => {
                        colour[other] = Some(!side);
                        component.push(other);
                    }
                    Some(theirs) => odd |= theirs == side,
                }
            }
        }
        for clock in component {
            out[clock] = odd;
        }
    }
    out
}

/// A pair model ready to normalise and solve fixes by: what a verifier holding it (verified, by
/// itself or by a holder of the window) needs and nothing else.
pub struct Prepared {
    pub model: PairModel,
    pub id: [u8; 32],
    clocks: Vec<Prep>,
    index: BTreeMap<ClockKey, u32>,
    /// Each clock's pairs: (other clock, pair), ascending by the other.
    adjacency: Vec<Vec<(u32, u32)>>,
    curves: Vec<Curve>,
    /// The area of each usable member (`area::of`).
    areas: BTreeMap<PublicKey, Region>,
}

/// A fix's receptions on one timeline, ready to solve, and what made it.
pub struct Normalised {
    pub(crate) problem: Problem,
    /// Unix nanoseconds of the timeline's zero: the reference hearer's arrival.
    pub origin_unix_ns: u64,
    /// The pairs its adjustment used.
    pub used: Vec<(ClockKey, ClockKey)>,
    /// Its clocks, bridges too.
    pub clocks: Vec<ClockKey>,
    pub bridges: usize,
    pub rejected: usize,
    pub dropped: usize,
    pub kappa: f64,
}

impl Normalised {
    /// The fix's solve (crate docs, § Solving) on this timeline.
    pub fn solve(&self) -> Result<solve::Solution, solve::SolveError> {
        solve::solve_problem(&self.problem)
    }

    /// The most any reception was carried past its pairs' last knot, picoseconds.
    pub fn carried_ps(&self) -> i128 {
        self.problem
            .items
            .iter()
            .map(|item| item.time.carried_ps)
            .max()
            .unwrap_or(0)
    }

    /// Each reception's whitened residual under a fix at `position` (ECEF) transmitted at Unix
    /// picoseconds `transmitted_ps`: how far, in standard deviations, the transmit time its
    /// normalised arrival implies is from the fix's, its variance its own (`solve::Problem::sigma`)
    /// and `extra_m2`. By identity, ascending.
    pub fn residual_z(
        &self,
        position: Vec3,
        transmitted_ps: i128,
        extra_m2: f64,
    ) -> Vec<(ObservationId, f64)> {
        let origin_ps = i128::from(self.origin_unix_ns) * 1000;
        (0..self.problem.items.len())
            .map(|at| {
                let item = &self.problem.items[at];
                let heard_ps = origin_ps + item.time.ps;
                let range = linalg::norm(linalg::sub(position, item.site));
                let residual = (heard_ps - transmitted_ps) as f64 * 1e-12 * C - range;
                let sigma = self.problem.sigma(at);
                (item.id, residual.abs() / (sigma * sigma + extra_m2).sqrt())
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.problem.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.problem.items.is_empty()
    }
}

impl Prepared {
    /// `model` with its indices built. `None` when a clock's receiver is not a usable member of
    /// its scope.
    pub fn of(model: PairModel, id: [u8; 32]) -> Option<Self> {
        let sites: BTreeMap<PublicKey, &Site> = model
            .scope
            .iter()
            .filter(|site| site.usable())
            .map(|site| (site.receiver, site))
            .collect();
        let mut clocks = Vec::with_capacity(model.clocks.len());
        for clock in &model.clocks {
            let site = sites.get(&clock.key.receiver)?;
            let timebase = Timebase::of(site.clock)?;
            let mm = site.mm();
            let sigma = site.sigma_mm() as f64 / 1000.0;
            clocks.push(Prep {
                clock: Clock {
                    key: clock.key,
                    timebase,
                    site: geo::from_mm(mm),
                    site_mm: mm,
                    site_m2: sigma * sigma,
                    lowest: clock.lowest,
                    heard_ns: clock.heard_ns,
                },
                white_ns: clock.white_ns,
                rate: clock.rate,
                rate_var: f64::from(clock.rate_var),
                common_var: f64::from(clock.common_var),
                identified: false,
                information: 0.0,
            });
        }
        let index = clocks
            .iter()
            .enumerate()
            .map(|(at, prep)| (prep.clock.key, at as u32))
            .collect();
        let mut adjacency: Vec<Vec<(u32, u32)>> = vec![Vec::new(); clocks.len()];
        let mut curves = Vec::with_capacity(model.pairs.len());
        for (at, pair) in model.pairs.iter().enumerate() {
            let (ta, tb) = (
                clocks.get(pair.a as usize)?.clock.timebase,
                clocks.get(pair.b as usize)?.clock.timebase,
            );
            let (pa, ra) = process_noise(ta);
            let (pb, rb) = process_noise(tb);
            adjacency[pair.a as usize].push((pair.b, at as u32));
            adjacency[pair.b as usize].push((pair.a, at as u32));
            curves.push(Curve {
                knots: pair.knots.clone(),
                cov: full(&pair.cov, pair.knots.len()),
                kappa: f64::from(pair.kappa),
                share: f64::from(pair.share),
                q_phase: pa + pb,
                q_rate: ra + rb,
                origin_a: ta.elapsed_ps(i128::from(pair.anchor_a)),
                origin_b: tb.elapsed_ps(i128::from(pair.anchor_b)),
            });
        }
        for list in &mut adjacency {
            list.sort_unstable();
        }
        // A clock whose noise its pairs do not identify is read at the most its pairs allow: the
        // least of its pairs' summed white noise, since every split of a pair's scatter between
        // its ends gives each end at most the sum.
        let known = identified(&adjacency);
        let white: Vec<f64> = clocks.iter().map(|prep| prep.white_ns).collect();
        for (at, prep) in clocks.iter_mut().enumerate() {
            prep.identified = known[at];
            prep.information = adjacency[at]
                .iter()
                .map(|(other, _)| {
                    let other = white[*other as usize];
                    let sum = white[at] * white[at] + other * other;
                    1.0 / (sum * sum)
                })
                .sum();
            if !known[at] {
                let most = adjacency[at]
                    .iter()
                    .map(|(other, _)| {
                        let other = white[*other as usize];
                        white[at] * white[at] + other * other
                    })
                    .fold(f64::INFINITY, f64::min);
                if most.is_finite() {
                    prep.white_ns = most.sqrt();
                }
            }
        }
        let areas = sites
            .values()
            .filter_map(|site| Some((site.receiver, crate::area::of(site)?)))
            .collect();
        Some(Self {
            model,
            id,
            clocks,
            index,
            adjacency,
            curves,
            areas,
        })
    }

    /// What it allocates beside itself, every list at its capacity: the model's (its scope,
    /// frontier, clocks and pairs with their knots and covariances) and its indices
    /// (each clock, its index entry and adjacency, each pair's curve with its full covariance).
    pub fn bytes(&self) -> usize {
        use tally_wire::footprint::{btree, vec};
        let model = &self.model;
        vec::<Site>(model.scope.capacity())
            + vec::<Frontier>(model.frontier.capacity())
            + vec::<PairClock>(model.clocks.capacity())
            + vec::<ClockPair>(model.pairs.capacity())
            + model
                .pairs
                .iter()
                .map(|pair| vec::<f64>(pair.knots.capacity()) + vec::<f32>(pair.cov.capacity()))
                .sum::<usize>()
            + vec::<Prep>(self.clocks.capacity())
            + btree::<ClockKey, u32>(self.index.len())
            + vec::<Vec<(u32, u32)>>(self.adjacency.capacity())
            + self
                .adjacency
                .iter()
                .map(|list| vec::<(u32, u32)>(list.capacity()))
                .sum::<usize>()
            + vec::<Curve>(self.curves.capacity())
            + self
                .curves
                .iter()
                .map(|curve| vec::<f64>(curve.knots.capacity()) + vec::<f64>(curve.cov.capacity()))
                .sum::<usize>()
            + btree::<PublicKey, Region>(self.areas.len())
    }

    /// The most [`Prepared::bytes`] is for `clocks` clocks, `pairs` pairs (each of at most
    /// `PAIR_KNOTS_MOST` knots; a clock's adjacency, grown a push at a time, holds at most twice
    /// its pairs or the least list of four), with as many members as clocks.
    pub const fn bytes_most(clocks: usize, pairs: usize) -> usize {
        use tally_wire::footprint::{btree, vec};
        let knots = PAIR_KNOTS_MOST;
        let per_pair = std::mem::size_of::<ClockPair>()
            + vec::<f64>(knots)
            + vec::<f64>(knots * (knots + 1) / 2)
            + 2 * 2 * std::mem::size_of::<(u32, u32)>()
            + std::mem::size_of::<Curve>()
            + vec::<f64>(knots)
            + vec::<f64>(knots * knots);
        let per_clock = std::mem::size_of::<Site>()
            + std::mem::size_of::<Frontier>()
            + std::mem::size_of::<PairClock>()
            + std::mem::size_of::<Prep>()
            + vec::<(u32, u32)>(4)
            + std::mem::size_of::<Vec<(u32, u32)>>();
        btree::<ClockKey, u32>(clocks)
            + btree::<PublicKey, Region>(clocks)
            + clocks * per_clock
            + pairs * per_pair
    }

    /// The area of a usable member (`area::of`), by its signed site record.
    pub fn area_of(&self, receiver: &PublicKey) -> Option<Region> {
        self.areas.get(receiver).copied()
    }

    /// The pair of its clocks `a < b` (indices), when it publishes it.
    fn curve_at(&self, a: u32, b: u32) -> Option<&Curve> {
        let list = &self.adjacency[a as usize];
        let at = list.binary_search_by_key(&b, |(other, _)| *other).ok()?;
        Some(&self.curves[list[at].1 as usize])
    }
}

/// The pair models one fix is grouped, normalised and solved by (crate docs, § Areas, the models a
/// fix cites): one verified model per area, every one of one trailing window, read as one set of
/// clocks and pairs. A clock is read from the one of them whose pairs best inform its noise: of
/// those that publish it, one that identifies its noise (`identified`) before one that does not,
/// then the most information (`Prep::information`), ties to its own area's model and then to the
/// lowest area; a pair `a < b` from the model of
/// `a`'s area when that model is one of them and publishes it, else from `b`'s. Every model
/// publishes only pairs with an end in its area (`Network::of_area`), so a pair any of them
/// publishes is read from exactly one. A clock of a boundary receiver is a member of each area that
/// keeps it, so it may be published by two models; it is read from one by this rule.
#[derive(Clone)]
pub struct Models<'a> {
    index: Arc<Index<'a>>,
    /// Which of the index's models these are, by their index there.
    mask: Mask,
}

/// The models a set of `Models` views share: every model, ascending by area, and every clock and
/// receiver any of them publishes. Built once, and narrowed to a subset without a rebuild
/// (`Models::within`).
struct Index<'a> {
    parts: Vec<&'a Prepared>,
    clocks: HashMap<ClockKey, Held>,
    /// Each model's clocks' `Held::id`, by their index in it.
    ids: Vec<Vec<u32>>,
    /// Every receiver with a clock any of them publishes: each model that publishes one of its
    /// clocks with the area that model says it is in (`Prepared::area_of`), ascending by model, and
    /// its clocks ascending.
    receivers: HashMap<PublicKey, Receiver>,
}

/// A receiver as an `Index` holds it: each model that publishes one of its clocks with the area
/// that model says it is in, ascending by model, and its clocks ascending.
type Receiver = (Vec<(u16, Option<Region>)>, Vec<ClockKey>);

/// A set of models of an `Index`, by their index there.
#[derive(Clone, PartialEq, Eq)]
struct Mask(Vec<u64>);

impl Mask {
    fn none(parts: usize) -> Self {
        Self(vec![0; parts.div_ceil(64)])
    }

    fn has(&self, part: u16) -> bool {
        self.0
            .get(usize::from(part / 64))
            .is_some_and(|word| word & (1 << (part % 64)) != 0)
    }

    fn with(mut self, part: u16) -> Self {
        if let Some(word) = self.0.get_mut(usize::from(part / 64)) {
            *word |= 1 << (part % 64);
        }
        self
    }
}

/// A clock as an `Index` holds it: the index of its own area's model among them, and each model
/// that publishes it with its index there, in the order the rule prefers to read it from.
struct Held {
    /// Its place among the index's clocks (`Index::ids`), dense from zero.
    id: u32,
    own: Option<u16>,
    /// By the rule's preference (`Models`): identified first, then the most information, then its
    /// own area's model, then by area.
    ranked: Vec<(u16, u32)>,
}

impl Held {
    /// Its index in model `part`, when that model publishes it.
    fn local(&self, part: u16) -> Option<u32> {
        self.ranked
            .iter()
            .find(|(held, _)| *held == part)
            .map(|(_, local)| *local)
    }
}

/// A reception as `Models` reads it: its clock, that clock as published, and its linear count.
type Located<'s, 'a> = (ClockKey, &'s Held, &'a Prep, i64);

/// How grouping maps a clock's reading to its reference's (`Models::transmissions`): itself, or
/// through one or two pairs, each read from its `a` end, or from its `b` end when the step's
/// target is the lower key.
enum Path<'c> {
    Same,
    One((&'c Curve, bool)),
    Two((&'c Curve, bool), (&'c Curve, bool)),
}

impl Path<'_> {
    fn map(&self, reading: i128) -> i128 {
        let step = |(curve, from_b): (&Curve, bool), reading: i128| {
            if from_b {
                curve.abs_a(curve.inverse(curve.ns_b(reading)))
            } else {
                let x = curve.ns_a(reading);
                curve.abs_b(x + curve.value(x))
            }
        };
        match self {
            Path::Same => reading,
            Path::One(one) => step(*one, reading),
            Path::Two(first, second) => step(*second, step(*first, reading)),
        }
    }
}

/// Unix nanoseconds of `reception`, its clock `prep` reading `linear`: a GNSS-disciplined count
/// on the UTC day its wall clock is in (`sync::origin_unix_ns`), a free-running one by the latest
/// its window's receptions say its lowest count was heard at, and its nominal time since
/// (`PairClock::heard_ns`). A fix's timeline zero (`Models::normalise`) and a transmission's slot
/// (`Models::heard_unix_ns`) are each dated so.
fn dated(prep: &Prep, reception: &Reception, linear: i64) -> Option<u64> {
    let clock = &prep.clock;
    if clock.timebase.disciplined() {
        sync::origin_unix_ns(
            clock.timebase,
            linear,
            reception.wall_ms.saturating_mul(1_000_000),
        )
    } else {
        let since_ns = clock
            .timebase
            .elapsed_ps(i128::from(linear) - i128::from(clock.lowest))
            / 1000;
        u64::try_from(i128::from(clock.heard_ns) + since_ns).ok()
    }
}

impl<'a> Models<'a> {
    /// `parts` as one fix reads them. `None` when there is none, two are of one area, two are of
    /// different trailing windows, or there are more than `tally_wire::MAX_FIX_MODELS`.
    pub fn new(parts: Vec<&'a Prepared>) -> Option<Self> {
        if parts.len() > tally_wire::MAX_FIX_MODELS {
            return None;
        }
        Self::index(parts)
    }

    /// Every one of `parts` as one index (`None` when there is none, two are of one area, or two
    /// are of different trailing windows): what any set of them is read from without a rebuild
    /// (`Models::within`, `Models::of`), however many there are.
    pub fn index(mut parts: Vec<&'a Prepared>) -> Option<Self> {
        parts.sort_by_key(|part| part.model.area);
        let mismatched = parts.windows(2).any(|pair| {
            pair[0].model.area == pair[1].model.area
                || pair[0].model.trailing != pair[1].model.trailing
        });
        if parts.is_empty() || mismatched || parts.len() > usize::from(u16::MAX) {
            return None;
        }
        let mut clocks: HashMap<ClockKey, Held> = HashMap::new();
        let mut receivers: HashMap<PublicKey, Receiver> = HashMap::new();
        let mut ids: Vec<Vec<u32>> = Vec::with_capacity(parts.len());
        for (at, part) in parts.iter().enumerate() {
            let mut of_part = Vec::with_capacity(part.clocks.len());
            for (local, prep) in part.clocks.iter().enumerate() {
                let key = prep.clock.key;
                let next = clocks.len() as u32;
                let held = clocks.entry(key).or_insert_with(|| Held {
                    id: next,
                    own: None,
                    ranked: Vec::new(),
                });
                held.ranked.push((at as u16, local as u32));
                of_part.push(held.id);
                let receiver = receivers.entry(key.receiver).or_default();
                if receiver.0.last().is_none_or(|(last, _)| *last != at as u16) {
                    receiver.0.push((at as u16, part.area_of(&key.receiver)));
                }
                if let Err(slot) = receiver.1.binary_search(&key) {
                    receiver.1.insert(slot, key);
                }
            }
            ids.push(of_part);
        }
        for (key, held) in &mut clocks {
            // Its own area's model: the area the first model publishing it says.
            held.own = receivers
                .get(&key.receiver)
                .and_then(|(areas, _)| areas.first().and_then(|(_, area)| *area))
                .and_then(|area| {
                    parts
                        .binary_search_by_key(&area, |part| part.model.area)
                        .ok()
                })
                .map(|at| at as u16);
            let own = held.own;
            held.ranked.sort_by(|(pa, la), (pb, lb)| {
                let (a, b) = (
                    &parts[usize::from(*pa)].clocks[*la as usize],
                    &parts[usize::from(*pb)].clocks[*lb as usize],
                );
                b.identified
                    .cmp(&a.identified)
                    .then(b.information.total_cmp(&a.information))
                    .then((Some(*pa) != own).cmp(&(Some(*pb) != own)))
                    .then(pa.cmp(pb))
            });
        }
        let mask = (0..parts.len() as u16).fold(Mask::none(parts.len()), Mask::with);
        Some(Self {
            index: Arc::new(Index {
                parts,
                clocks,
                ids,
                receivers,
            }),
            mask,
        })
    }

    /// One model alone.
    pub fn one(prepared: &'a Prepared) -> Self {
        Self::new(vec![prepared]).unwrap_or_else(|| unreachable!("one model is one area's"))
    }

    /// The models of `areas` among these, read as one fix reads them: `None` when one of `areas`
    /// has none here, or `areas` is empty. Shares their index, so it costs no rebuild.
    pub fn within(&self, areas: &[Region]) -> Option<Self> {
        if areas.len() > tally_wire::MAX_FIX_MODELS {
            return None;
        }
        let mut mask = Mask::none(self.index.parts.len());
        for area in areas {
            let at = self
                .index
                .parts
                .binary_search_by_key(area, |part| part.model.area)
                .ok()? as u16;
            if !self.mask.has(at) {
                return None;
            }
            mask = mask.with(at);
        }
        (!areas.is_empty()).then(|| Self {
            index: Arc::clone(&self.index),
            mask,
        })
    }

    /// `parts` as one fix reads them (`Models::new`), read from these when they hold every one of
    /// them, so without a rebuild: the same models either way.
    pub fn of<'b>(&self, parts: &[&'b Prepared]) -> Option<Models<'b>>
    where
        'a: 'b,
    {
        let mut areas: Vec<Region> = parts.iter().map(|part| part.model.area).collect();
        areas.sort_unstable();
        let held = areas.windows(2).all(|pair| pair[0] < pair[1])
            && parts.iter().all(|part| {
                self.index
                    .parts
                    .binary_search_by_key(&part.model.area, |held| held.model.area)
                    .is_ok_and(|at| std::ptr::eq(self.index.parts[at], *part))
            });
        if held {
            self.within(&areas)
        } else {
            Models::new(parts.to_vec())
        }
    }

    /// The models, ascending by area.
    pub fn parts(&self) -> Vec<&'a Prepared> {
        self.index
            .parts
            .iter()
            .enumerate()
            .filter(|(at, _)| self.mask.has(*at as u16))
            .map(|(_, part)| *part)
            .collect()
    }

    /// Their ids ascending: the list a fix solved by them carries (`tally_wire::Fix::models`).
    pub fn ids(&self) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = self.parts().iter().map(|part| part.id).collect();
        ids.sort_unstable();
        ids
    }

    /// Their areas, ascending.
    pub fn areas(&self) -> Vec<Region> {
        self.parts().iter().map(|part| part.model.area).collect()
    }

    /// The area of a receiver with a clock any of them publishes (`area::of`).
    pub fn area_of(&self, receiver: &PublicKey) -> Option<Region> {
        let (areas, _) = self.receivers(receiver)?;
        areas
            .iter()
            .find(|(part, _)| self.mask.has(*part))
            .and_then(|(_, area)| *area)
    }

    fn receivers(&self, receiver: &PublicKey) -> Option<&Receiver> {
        self.index.receivers.get(receiver)
    }

    /// The areas a fix whose used hearers are `used` must cite (crate docs, § Areas): each one's
    /// area, ascending and without repeats. `None` when one has no clock any of them publishes.
    pub fn areas_of(&self, used: impl IntoIterator<Item = PublicKey>) -> Option<Vec<Region>> {
        let areas: BTreeSet<Region> = used
            .into_iter()
            .map(|receiver| self.area_of(&receiver))
            .collect::<Option<_>>()?;
        Some(areas.into_iter().collect())
    }

    /// Clock `key` as the rule reads it.
    fn prep(&self, key: &ClockKey) -> Option<&'a Prep> {
        self.held(key).map(|(_, prep)| prep)
    }

    /// Clock `key` as held, and as the rule reads it: from the first of its models, by the rule's
    /// preference, that is one of these.
    fn held(&self, key: &ClockKey) -> Option<(&Held, &'a Prep)> {
        let held = self.index.clocks.get(key)?;
        let (part, local) = held.ranked.iter().find(|(part, _)| self.mask.has(*part))?;
        Some((
            held,
            &self.index.parts[usize::from(*part)].clocks[*local as usize],
        ))
    }

    /// The pair of clocks `a` and `b` as the rule reads it, its `a` the lower key.
    fn curve(&self, a: &ClockKey, b: &ClockKey) -> Option<&'a Curve> {
        let (a, b) = if a < b { (a, b) } else { (b, a) };
        let clocks = &self.index.clocks;
        self.curve_held(clocks.get(a)?, clocks.get(b)?)
    }

    /// The pair of two held clocks, `a` the lower key, as the rule reads it: from `a`'s own area's
    /// model when it is one of these and publishes the pair, else from `b`'s.
    fn curve_held(&self, a: &Held, b: &Held) -> Option<&'a Curve> {
        [a.own, b.own]
            .into_iter()
            .flatten()
            .filter(|part| self.mask.has(*part))
            .find_map(|part| {
                let (la, lb) = (a.local(part)?, b.local(part)?);
                self.index.parts[usize::from(part)].curve_at(la, lb)
            })
    }

    /// The pair of two clocks as the rule reads it, each with its held entry, its `a` the lower.
    fn curve_of(&self, a: (&ClockKey, &Held), b: (&ClockKey, &Held)) -> Option<&'a Curve> {
        if a.0 < b.0 {
            self.curve_held(a.1, b.1)
        } else {
            self.curve_held(b.1, a.1)
        }
    }

    /// The lowest-keyed clock some pair of these joins to `key` that has a pair with the clock
    /// whose neighbours (`Models::neighbours`, ascending) are `to`: a model's clocks are in key
    /// order, so its first such pair of `key`'s is its lowest.
    fn via(&self, key: &ClockKey, to: &[ClockKey]) -> Option<ClockKey> {
        let held = self.index.clocks.get(key)?;
        let mut best: Option<ClockKey> = None;
        for (part, local) in held.ranked.iter().filter(|(part, _)| self.mask.has(*part)) {
            let part = self.index.parts[usize::from(*part)];
            for (other, _) in &part.adjacency[*local as usize] {
                let other = part.clocks[*other as usize].clock.key;
                if best.is_some_and(|best| best <= other) {
                    break;
                }
                if to.binary_search(&other).is_ok() {
                    best = Some(other);
                    break;
                }
            }
        }
        best
    }

    /// Every clock some pair of these joins to `key`, each once, ascending.
    fn neighbours(&self, key: &ClockKey) -> Vec<ClockKey> {
        let Some(held) = self.index.clocks.get(key) else {
            return Vec::new();
        };
        let mut out: Vec<ClockKey> = held
            .ranked
            .iter()
            .filter(|(part, _)| self.mask.has(*part))
            .flat_map(|(part, local)| {
                let part = self.index.parts[usize::from(*part)];
                part.adjacency[*local as usize]
                    .iter()
                    .map(|(other, _)| part.clocks[*other as usize].clock.key)
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Whether they publish the pair of clocks `a` and `b`.
    pub fn holds(&self, a: &ClockKey, b: &ClockKey) -> bool {
        a != b && self.curve(a, b).is_some()
    }

    /// A clock of `receiver`'s noise within each aircraft (nanoseconds) and absolute rate: of its
    /// lowest epoch they publish.
    pub fn clock_of(&self, receiver: &PublicKey) -> Option<(f64, f64)> {
        let (_, keys) = self.receivers(receiver)?;
        let prep = keys.iter().find_map(|key| self.prep(key))?;
        Some((prep.white_ns, prep.rate))
    }
    /// A reception's clock and linear count.
    fn locate(&self, reception: &Reception) -> Option<Located<'_, 'a>> {
        let key = ClockKey {
            receiver: reception.receiver,
            epoch: reception.epoch,
        };
        let (held, prep) = self.held(&key)?;
        let linear = prep
            .clock
            .timebase
            .linear_near(reception.timestamp, prep.clock.lowest)?;
        Some((key, held, prep, linear))
    }

    /// A considered set's receptions split into the transmissions they are (crate docs, § The
    /// pairwise path, grouping): each mapped to one clock's time through its direct pair with it
    /// (the clock with the most pairs to the set's others, ties to the lowest key), or with none,
    /// through the lowest-keyed clock with a pair to both; sorted, and cut where two consecutive
    /// are more than `GATE_PS` apart. A reception mapped neither way is left out. Each part is
    /// split again by the same rule, its own reference chosen among its own clocks, until every
    /// part is its own split: so a transmission is exactly a set the rule returns whole, which is
    /// what the verifier checks of a fix's considered set.
    pub fn transmissions(&self, receptions: &[Reception]) -> Vec<Vec<Reception>> {
        let all: Vec<&Reception> = receptions.iter().collect();
        let mut out = Vec::new();
        self.settle_split(&all, None, &mut out);
        owned(out)
    }

    /// [`Self::transmissions`] of `receptions` but for the parts `skip` names: each part the first
    /// split returns that `skip` takes is left out, unsplit. Whatever `skip` takes, every
    /// transmission returned is one the rule returns whole. The second of the pair is how many
    /// parts were skipped. The splitting reads the receptions where they lie; only the
    /// transmissions returned are copied, once.
    pub fn transmissions_unless(
        &self,
        receptions: &[Reception],
        skip: impl Fn(&[&Reception]) -> bool,
    ) -> (Vec<Vec<Reception>>, usize) {
        let all: Vec<&Reception> = receptions.iter().collect();
        // Split in full: there is no parent reference to find again.
        let (parts, reference) = self
            .split(&all, None)
            .unwrap_or_else(|| (vec![all.clone()], None));
        let mut out = Vec::new();
        let mut skipped = 0;
        if let [one] = parts.as_slice()
            && one.len() == receptions.len()
        {
            if skip(one) {
                return (Vec::new(), 1);
            }
            return (owned(parts), 0);
        }
        for part in &parts {
            if skip(part) {
                skipped += 1;
            } else {
                self.settle_split(part, reference.as_ref(), &mut out);
            }
        }
        (owned(out), skipped)
    }

    /// `receptions`, a part a split by reference `parent` returned (none for a whole set), split
    /// until every part is its own split.
    fn settle_split<'r>(
        &self,
        receptions: &[&'r Reception],
        parent: Option<&ClockKey>,
        out: &mut Vec<Vec<&'r Reception>>,
    ) {
        let Some((parts, reference)) = self.split(receptions, parent) else {
            out.push(receptions.to_vec());
            return;
        };
        if let [one] = parts.as_slice()
            && one.len() == receptions.len()
        {
            out.extend(parts);
            return;
        }
        // Every part is smaller than the whole (a reception was cut off or left out), so this ends.
        for part in &parts {
            self.settle_split(part, reference.as_ref(), out);
        }
    }

    /// One split of `receptions` by the rule, and the reference it mapped them to. `None` when
    /// they are a part a split by reference `parent` returned and the rule picks `parent` again:
    /// then they are their own split, as given. A clock's path to a reference is a function of
    /// the clock, the reference and these models alone, never of the set, so each reception maps
    /// to the time it did in the parent's split; the part was a run of those times, in order, no
    /// two consecutive more than `GATE_PS` apart, and it is cut nowhere and reordered by nothing.
    fn split<'r>(
        &self,
        receptions: &[&'r Reception],
        parent: Option<&ClockKey>,
    ) -> Option<(Vec<Vec<&'r Reception>>, Option<ClockKey>)> {
        // Each reception's clock as held, and its reading; a run of one clock's receptions (a
        // considered set is in identity order) looked up once.
        let mut last: Option<(ClockKey, Option<(&Held, &Prep)>)> = None;
        let mut located: Vec<(ClockKey, &Held, i128, &'r Reception)> =
            Vec::with_capacity(receptions.len());
        for &reception in receptions {
            let key = ClockKey {
                receiver: reception.receiver,
                epoch: reception.epoch,
            };
            let found = match last {
                Some((at, found)) if at == key => found,
                _ => {
                    let found = self.held(&key);
                    last = Some((key, found));
                    found
                }
            };
            let Some((held, prep)) = found else {
                continue;
            };
            let Some(linear) = prep
                .clock
                .timebase
                .linear_near(reception.timestamp, prep.clock.lowest)
            else {
                continue;
            };
            located.push((
                key,
                held,
                prep.clock.timebase.elapsed_ps(i128::from(linear)),
                reception,
            ));
        }
        // The set's clocks, ascending, each with its held entry.
        let mut members: Vec<(ClockKey, &Held)> = Vec::new();
        let mut last: Option<ClockKey> = None;
        for (key, held, _, _) in &located {
            if last != Some(*key) {
                last = Some(*key);
                members.push((*key, *held));
            }
        }
        members.sort_unstable_by_key(|(key, _)| *key);
        members.dedup_by_key(|(key, _)| *key);
        // The clock with the most pairs to the set's others, ties to the lowest key: each clock's
        // pairs read from the adjacency of every model of these that publishes it (a pair is
        // published only by a model of one of its ends' areas, so these are the pairs the rule
        // reads), each other clock of the set counted once.
        // Each member's place among them, by its clock's `Held::id`.
        let mut place = vec![u32::MAX; self.index.clocks.len()];
        for (at, (_, held)) in members.iter().enumerate() {
            place[held.id as usize] = at as u32;
        }
        let mut counted = vec![u32::MAX; members.len()];
        let mut reference: Option<(usize, std::cmp::Reverse<ClockKey>)> = None;
        for (at, (key, held)) in members.iter().enumerate() {
            let mut pairs = 0usize;
            for (part, local) in held.ranked.iter().filter(|(part, _)| self.mask.has(*part)) {
                let ids = &self.index.ids[usize::from(*part)];
                for (other, _) in &self.index.parts[usize::from(*part)].adjacency[*local as usize] {
                    let to = place[ids[*other as usize] as usize];
                    if to != u32::MAX && to as usize != at && counted[to as usize] != at as u32 {
                        counted[to as usize] = at as u32;
                        pairs += 1;
                    }
                }
            }
            let candidate = (pairs, std::cmp::Reverse(*key));
            if reference.as_ref().is_none_or(|best| candidate > *best) {
                reference = Some(candidate);
            }
        }
        let Some(reference) = reference.map(|(_, key)| key.0) else {
            return Some((Vec::new(), None));
        };
        if parent == Some(&reference) {
            return None;
        }
        let Ok(reference_at) = members.binary_search_by_key(&reference, |(key, _)| *key) else {
            return Some((Vec::new(), None));
        };
        let to_reference: std::cell::OnceCell<Vec<ClockKey>> = std::cell::OnceCell::new();
        let to = (&reference, members[reference_at].1);
        // How each clock's reading maps to the reference's: through its own pair with it, else
        // through the lowest-keyed clock with a pair to both. Each step a pair and whether it is
        // read from its `b` end (the step's target the lower key).
        let path_of = |key: &ClockKey, held: &Held| -> Option<Path<'_>> {
            if *key == reference {
                return Some(Path::Same);
            }
            if let Some(curve) = self.curve_of((key, held), to) {
                return Some(Path::One((curve, reference < *key)));
            }
            let via = self.via(
                key,
                to_reference.get_or_init(|| self.neighbours(&reference)),
            )?;
            let via_held = self.index.clocks.get(&via)?;
            let first = self.curve_of((key, held), (&via, via_held))?;
            let second = self.curve_of((&via, via_held), to)?;
            Some(Path::Two((first, via < *key), (second, reference < via)))
        };
        let paths: Vec<Option<Path<'_>>> = members
            .iter()
            .map(|(key, held)| path_of(key, held))
            .collect();
        let mut last: Option<(ClockKey, Option<&Path<'_>>)> = None;
        let mut mapped: Vec<(i128, &'r Reception)> = Vec::with_capacity(located.len());
        for (key, _, reading, reception) in &located {
            let path = match last {
                Some((at, path)) if at == *key => path,
                _ => {
                    let path = members
                        .binary_search_by_key(key, |(key, _)| *key)
                        .ok()
                        .and_then(|at| paths[at].as_ref());
                    last = Some((*key, path));
                    path
                }
            };
            let Some(path) = path else {
                continue;
            };
            mapped.push((path.map(*reading), *reception));
        }
        mapped.sort_by_key(|(time, reception)| {
            (
                *time,
                reception.receiver,
                reception.epoch,
                reception.timestamp,
            )
        });
        let mut out: Vec<Vec<&'r Reception>> = Vec::new();
        let mut last: Option<i128> = None;
        for (time, reception) in mapped {
            if last.is_none_or(|last| time - last > GATE_PS) {
                out.push(Vec::new());
            }
            if let Some(group) = out.last_mut() {
                group.push(reception);
            }
            last = Some(time);
        }
        Some((out, Some(reference)))
    }

    /// When a transmission was heard, Unix nanoseconds (`dated`): by the reception of its
    /// lowest-keyed GNSS-disciplined hearer's clock, else of its lowest-keyed clock, of that
    /// clock's the lowest count. What its slot is (`backoff`): a function of the receptions as a
    /// set, the same in any order. `None` when no reception is of a clock these publish.
    pub fn heard_unix_ns<R: std::borrow::Borrow<Reception>>(
        &self,
        receptions: &[R],
    ) -> Option<u64> {
        let (reception, (_, _, prep, linear)) = receptions
            .iter()
            .map(std::borrow::Borrow::borrow)
            .filter_map(|reception| Some((reception, self.locate(reception)?)))
            .min_by_key(|(reception, (key, _, prep, _))| {
                (
                    !prep.clock.timebase.disciplined(),
                    *key,
                    reception.timestamp,
                )
            })?;
        dated(prep, reception, linear)
    }

    /// A transmission's receptions cut to the receivers it is solved from (crate docs, § Solving,
    /// the cap): every reception of a clock these publish when their receivers are at most
    /// `HEARERS_MOST`, else those of that many receivers chosen by their sites alone, farthest
    /// first: the lowest-keyed receiver with a GNSS-disciplined clock heard (else the lowest
    /// keyed), then each time the receiver whose nearest chosen one is farthest (squared integer
    /// millimetres, ties to the lowest key). In `receptions`' order; a function of them as a set,
    /// so the same in any order, and what the verifier recomputes of a fix's considered set.
    pub fn capped(&self, receptions: &[Reception]) -> Vec<Reception> {
        let mut receivers: BTreeMap<PublicKey, ([i64; 3], bool)> = BTreeMap::new();
        let located: Vec<&Reception> = receptions
            .iter()
            .filter(|reception| {
                let Some((_, _, prep, _)) = self.locate(reception) else {
                    return false;
                };
                let entry = receivers
                    .entry(reception.receiver)
                    .or_insert((prep.clock.site_mm, false));
                entry.1 |= prep.clock.timebase.disciplined();
                true
            })
            .collect();
        if receivers.len() > HEARERS_MOST {
            let sites: Vec<(PublicKey, [i64; 3], bool)> = receivers
                .into_iter()
                .map(|(receiver, (site, disciplined))| (receiver, site, disciplined))
                .collect();
            let apart = |a: &[i64; 3], b: &[i64; 3]| -> i128 {
                (0..3)
                    .map(|axis| {
                        let d = i128::from(a[axis]) - i128::from(b[axis]);
                        d * d
                    })
                    .sum()
            };
            let first = sites.iter().position(|site| site.2).unwrap_or(0);
            // Each one's squared distance to its nearest chosen; `None` once chosen.
            let mut nearest: Vec<Option<i128>> = sites
                .iter()
                .map(|site| Some(apart(&site.1, &sites[first].1)))
                .collect();
            nearest[first] = None;
            let mut chosen = BTreeSet::from([sites[first].0]);
            while chosen.len() < HEARERS_MOST {
                // The farthest, ties to the first (the lowest key).
                let Some(next) = (0..sites.len())
                    .filter_map(|at| Some((nearest[at]?, std::cmp::Reverse(at))))
                    .max()
                    .map(|(_, at)| at.0)
                else {
                    break;
                };
                chosen.insert(sites[next].0);
                nearest[next] = None;
                for (at, site) in sites.iter().enumerate() {
                    if let Some(distance) = nearest[at].as_mut() {
                        *distance = (*distance).min(apart(&site.1, &sites[next].1));
                    }
                }
            }
            return located
                .into_iter()
                .filter(|reception| chosen.contains(&reception.receiver))
                .cloned()
                .collect();
        }
        located.into_iter().cloned().collect()
    }

    /// One transmission's receptions normalised by the pairs among its hearers (crate docs, § The
    /// pairwise path, the adjustment).
    pub fn normalise(&self, receptions: &[Reception]) -> Result<Normalised, &'static str> {
        struct Node<'s, 'p> {
            clock: ClockKey,
            held: &'s Held,
            prep: &'p Prep,
            /// Its reading at its reception (a bridge: at a neighbour's), picoseconds.
            reading: i128,
            /// The reception it is, by index into `heard`.
            heard: Option<usize>,
        }
        #[derive(Clone, Copy)]
        struct Edge {
            a: usize,
            b: usize,
            o: f64,
            var: f64,
            slope: f64,
            carried: f64,
            /// The variance of `o` from the pair's own points alone ([`Curve::at`]).
            own: f64,
        }
        // Of copies of one reception, the earliest wall clock's.
        let mut heard: Vec<(ObservationId, &Reception, Located<'_, 'a>)> =
            crate::obs::ids(receptions)
                .into_iter()
                .zip(receptions)
                .filter_map(|(id, reception)| Some((id, reception, self.locate(reception)?)))
                .collect();
        heard.sort_by_key(|(id, reception, _)| (*id, reception.wall_ms));
        heard.dedup_by_key(|(id, _, _)| *id);
        let total = heard.len();
        if total < solve::MIN_RECEIVERS_WITH_ALTITUDE {
            return Err("too few receptions");
        }
        // A clock heard twice is left out.
        let mut counts: BTreeMap<ClockKey, usize> = BTreeMap::new();
        for (_, _, (key, _, _, _)) in &heard {
            *counts.entry(*key).or_default() += 1;
        }
        heard.retain(|(_, _, (key, _, _, _))| counts[key] == 1);
        let mut nodes: Vec<Node<'_, 'a>> = heard
            .iter()
            .enumerate()
            .map(|(at, (_, _, (key, held, prep, linear)))| Node {
                clock: *key,
                held,
                prep,
                reading: prep.clock.timebase.elapsed_ps(i128::from(*linear)),
                heard: Some(at),
            })
            .collect();
        let edge = |nodes: &[Node<'_, 'a>], i: usize, j: usize| -> Option<Edge> {
            let (i, j) = if nodes[i].clock < nodes[j].clock {
                (i, j)
            } else {
                (j, i)
            };
            let curve = self.curve_held(nodes[i].held, nodes[j].held)?;
            let x = curve.ns_a(nodes[i].reading);
            let (g, var, own, slope, carried) = curve.at(x);
            let o = x + g - curve.ns_b(nodes[j].reading);
            Some(Edge {
                a: i,
                b: j,
                o,
                var,
                slope,
                carried,
                own,
            })
        };
        let mut edges: Vec<Edge> = Vec::new();
        for i in 0..nodes.len() {
            for j in i + 1..nodes.len() {
                edges.extend(edge(&nodes, i, j));
            }
        }
        let components = |count: usize, edges: &[Edge]| -> Vec<usize> {
            let mut parent: Vec<usize> = (0..count).collect();
            fn root(parent: &mut [usize], mut at: usize) -> usize {
                while parent[at] != at {
                    parent[at] = parent[parent[at]];
                    at = parent[at];
                }
                at
            }
            for e in edges {
                let (ra, rb) = (root(&mut parent, e.a), root(&mut parent, e.b));
                if ra != rb {
                    parent[ra.max(rb)] = ra.min(rb);
                }
            }
            (0..count).map(|at| root(&mut parent, at)).collect()
        };
        let main_of = |nodes: &[Node<'_, 'a>], roots: &[usize]| -> usize {
            let mut sizes: BTreeMap<usize, usize> = BTreeMap::new();
            for (at, node) in nodes.iter().enumerate() {
                if node.heard.is_some() {
                    *sizes.entry(roots[at]).or_default() += 1;
                }
            }
            sizes
                .iter()
                .fold((usize::MAX, 0), |best, (root, size)| {
                    if *size > best.1 { (*root, *size) } else { best }
                })
                .0
        };
        let mut bridges = 0;
        loop {
            let roots = components(nodes.len(), &edges);
            let main = main_of(&nodes, &roots);
            let split = nodes
                .iter()
                .enumerate()
                .any(|(at, node)| node.heard.is_some() && roots[at] != main);
            if !split || bridges >= BRIDGES_MOST {
                break;
            }
            // The lowest-keyed clock outside the graph with a pair into the main part and one
            // into a hearer of another.
            let present: BTreeSet<ClockKey> = nodes.iter().map(|node| node.clock).collect();
            let into_main: BTreeMap<ClockKey, usize> = {
                let mut map = BTreeMap::new();
                for (at, node) in nodes.iter().enumerate() {
                    if roots[at] != main {
                        continue;
                    }
                    for other in self.neighbours(&node.clock) {
                        map.entry(other).or_insert(at);
                    }
                }
                map
            };
            let into_other: BTreeSet<ClockKey> = nodes
                .iter()
                .enumerate()
                .filter(|(at, node)| roots[*at] != main && node.heard.is_some())
                .flat_map(|(_, node)| self.neighbours(&node.clock))
                .collect();
            let found = into_main
                .iter()
                .find(|(z, _)| !present.contains(z) && into_other.contains(z))
                .and_then(|(z, from)| {
                    let from = &nodes[*from];
                    let curve = self.curve(&from.clock, z)?;
                    // Its reading at `from`'s reception.
                    let reading = if from.clock < *z {
                        let x = curve.ns_a(from.reading);
                        curve.abs_b(x + curve.value(x))
                    } else {
                        curve.abs_a(curve.inverse(curve.ns_b(from.reading)))
                    };
                    let (held, prep) = self.held(z)?;
                    Some(Node {
                        clock: *z,
                        held,
                        prep,
                        reading,
                        heard: None,
                    })
                });
            let Some(node) = found else {
                break;
            };
            nodes.push(node);
            bridges += 1;
            let z = nodes.len() - 1;
            for i in 0..z {
                edges.extend(edge(&nodes, i, z));
            }
        }
        let roots = components(nodes.len(), &edges);
        let main = main_of(&nodes, &roots);
        let keep: Vec<usize> = (0..nodes.len()).filter(|at| roots[*at] == main).collect();
        let hearers = keep.iter().filter(|at| nodes[**at].heard.is_some()).count();
        if hearers < 2 {
            return Err("fewer than two hearers connect");
        }
        let mut renumber = vec![usize::MAX; nodes.len()];
        for (new, old) in keep.iter().enumerate() {
            renumber[*old] = new;
        }
        let edges: Vec<Edge> = edges
            .into_iter()
            .filter(|e| renumber[e.a] != usize::MAX && renumber[e.b] != usize::MAX)
            .map(|e| Edge {
                a: renumber[e.a],
                b: renumber[e.b],
                ..e
            })
            .collect();
        let nodes: Vec<Node<'_, 'a>> = keep
            .iter()
            .map(|old| Node {
                clock: nodes[*old].clock,
                held: nodes[*old].held,
                prep: nodes[*old].prep,
                reading: nodes[*old].reading,
                heard: nodes[*old].heard,
            })
            .collect();
        // The reference: the lowest-keyed GNSS-disciplined clock that heard it, else the lowest.
        let reference = (0..nodes.len())
            .filter(|at| nodes[*at].heard.is_some())
            .min_by_key(|at| {
                let node = &nodes[*at];
                (!node.prep.clock.timebase.disciplined(), node.clock)
            })
            .ok_or("no reference")?;
        let unknown: Vec<usize> = {
            let mut next = 0;
            (0..nodes.len())
                .map(|at| {
                    if at == reference {
                        usize::MAX
                    } else {
                        next += 1;
                        next - 1
                    }
                })
                .collect()
        };
        let m = nodes.len() - 1;
        let solve =
            |edges: &[Edge], skip: &BTreeSet<usize>| -> Option<(Vec<f64>, Cholesky, Vec<f64>)> {
                let mut normal = Matrix::zeros(m);
                let mut rhs = vec![0.0; m];
                for (at, e) in edges.iter().enumerate() {
                    if skip.contains(&at) {
                        continue;
                    }
                    let w = 1.0 / e.var;
                    let terms = [(unknown[e.b], 1.0), (unknown[e.a], -(1.0 + e.slope))];
                    for (r, cr) in terms {
                        if r == usize::MAX {
                            continue;
                        }
                        rhs[r] += w * cr * e.o;
                        for (s, cs) in terms {
                            if s != usize::MAX {
                                normal.add(r, s, w * cr * cs);
                            }
                        }
                    }
                }
                let cholesky = normal.cholesky()?;
                let theta = cholesky.solve(&rhs);
                let value = |at: usize| {
                    if unknown[at] == usize::MAX {
                        0.0
                    } else {
                        theta[unknown[at]]
                    }
                };
                let residuals = edges
                    .iter()
                    .map(|e| (e.o - (value(e.b) - (1.0 + e.slope) * value(e.a))) / e.var.sqrt())
                    .collect();
                Some((theta, cholesky, residuals))
            };
        let mut skip: BTreeSet<usize> = BTreeSet::new();
        let mut protected: BTreeSet<usize> = BTreeSet::new();
        let mut rejected = 0;
        let (theta, inverse, kappa) = loop {
            let (theta, cholesky, residuals) = solve(&edges, &skip).ok_or("singular adjustment")?;
            let live = edges.len() - skip.len();
            let worst = residuals
                .iter()
                .enumerate()
                .filter(|(at, z)| !skip.contains(at) && !protected.contains(at) && z.abs() > LOOP_Z)
                .max_by(|a, b| a.1.abs().total_cmp(&b.1.abs()).then(b.0.cmp(&a.0)))
                .map(|(at, _)| at);
            match worst {
                Some(at) if live > m && rejected < LOOP_REJECTS_MOST => {
                    skip.insert(at);
                    let kept: Vec<Edge> = edges
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| !skip.contains(i))
                        .map(|(_, e)| *e)
                        .collect();
                    let roots = components(nodes.len(), &kept);
                    if roots.iter().any(|root| *root != roots[0]) {
                        skip.remove(&at);
                        protected.insert(at);
                    } else {
                        rejected += 1;
                    }
                }
                _ => {
                    let dof = live.saturating_sub(m);
                    let chi: f64 = residuals
                        .iter()
                        .enumerate()
                        .filter(|(at, _)| !skip.contains(at))
                        .map(|(_, z)| z * z)
                        .sum();
                    let kappa = if dof >= 2 {
                        (chi / dof as f64).max(1.0)
                    } else {
                        1.0
                    };
                    break (theta, cholesky.inverse_triangular(), kappa);
                }
            }
        };
        let used: Vec<(ClockKey, ClockKey)> = edges
            .iter()
            .enumerate()
            .filter(|(at, _)| !skip.contains(at))
            .map(|(_, e)| (nodes[e.a].clock, nodes[e.b].clock))
            .collect();
        let carried: Vec<f64> = {
            let mut carried = vec![0.0f64; nodes.len()];
            for (at, e) in edges.iter().enumerate() {
                if !skip.contains(&at) {
                    carried[e.a] = carried[e.a].max(e.carried);
                    carried[e.b] = carried[e.b].max(e.carried);
                }
            }
            carried
        };
        let theta_of = |at: usize| {
            if unknown[at] == usize::MAX {
                0.0
            } else {
                theta[unknown[at]]
            }
        };
        // Each hearer's arrival after the reference's, true nanoseconds: τ = −θ / (1 + ρ).
        let hearers: Vec<usize> = (0..nodes.len())
            .filter(|at| nodes[*at].heard.is_some())
            .collect();
        let tau: Vec<f64> = hearers
            .iter()
            .map(|at| -theta_of(*at) / (1.0 + nodes[*at].prep.rate))
            .collect();
        let ps: Vec<i128> = tau.iter().map(|t| (t * 1000.0).round() as i128).collect();
        let reference_ps = ps.iter().copied().min().ok_or("no hearer")?;
        let mut items: Vec<(usize, Item)> = hearers
            .iter()
            .enumerate()
            .filter_map(|(k, at)| {
                let node = &nodes[*at];
                let prep = node.prep;
                let (id, _, (_, _, _, linear)) = heard[node.heard?];
                let noise = prep.white_ns * 1e-9 * C;
                Some((
                    k,
                    Item {
                        id,
                        time: ModelTime {
                            linear,
                            ps: ps[k],
                            carried_ps: (carried[*at] * 1000.0) as i128,
                        },
                        site: prep.clock.site,
                        site_mm: prep.clock.site_mm,
                        z: (ps[k] - reference_ps) as f64 * 1e-12 * C,
                        noise_m2: noise * noise + prep.clock.site_m2,
                    },
                ))
            })
            .collect();
        items.sort_by_key(|(_, item)| item.id);
        // The rates' covariance among the free-running hearers (a GNSS-disciplined clock's is
        // zero by rule): each clock's own variance and its component's common one.
        let rate_cov = |ni: usize, nj: usize| -> f64 {
            let (pi, pj) = (nodes[ni].prep, nodes[nj].prep);
            if pi.clock.timebase.disciplined() || pj.clock.timebase.disciplined() {
                return 0.0;
            }
            let own = if nodes[ni].clock == nodes[nj].clock {
                pi.rate_var
            } else {
                0.0
            };
            own + pi.common_var.max(pj.common_var)
        };
        // The edges share their clocks' errors (crate docs, § The pairwise path, the adjustment):
        // each node's own part, at the least its used edges' own variances give its end, and each
        // used edge's remainder, independent across edges and carried through the solution.
        let white2 = |at: usize| nodes[at].prep.white_ns * nodes[at].prep.white_ns;
        let mut clock_var = vec![f64::INFINITY; nodes.len()];
        for (at, e) in edges.iter().enumerate() {
            if skip.contains(&at) {
                continue;
            }
            let (wa, wb) = (white2(e.a), white2(e.b));
            let sum = (wa + wb).max(f64::MIN_POSITIVE);
            clock_var[e.a] = clock_var[e.a].min(e.own * wa / sum);
            clock_var[e.b] = clock_var[e.b].min(e.own * wb / sum);
        }
        let mut remainder = Matrix::zeros(m);
        for (at, e) in edges.iter().enumerate() {
            if skip.contains(&at) {
                continue;
            }
            let delta = (e.own - clock_var[e.a] - clock_var[e.b]).max(0.0);
            let w = 1.0 / e.var;
            let terms = [(unknown[e.b], 1.0), (unknown[e.a], -(1.0 + e.slope))];
            for (r, cr) in terms {
                if r == usize::MAX {
                    continue;
                }
                for (s, cs) in terms {
                    if s != usize::MAX {
                        remainder.add(r, s, w * w * delta * cr * cs);
                    }
                }
            }
        }
        // Its covariance in `theta`: inverse · remainder · inverse.
        let propagated = inverse.sandwich(&remainder);
        let theta_cov = |ni: usize, nj: usize| -> f64 {
            let own = if ni == nj { clock_var[ni] } else { 0.0 };
            let carried = if unknown[ni] == usize::MAX || unknown[nj] == usize::MAX {
                0.0
            } else {
                propagated.get(unknown[ni], unknown[nj])
            };
            (own + carried) * kappa
        };
        let clock_m2: Vec<Vec<f64>> = items
            .iter()
            .map(|(ki, _)| {
                let ni = hearers[*ki];
                items
                    .iter()
                    .map(|(kj, _)| {
                        let nj = hearers[*kj];
                        let scale = (1.0 + nodes[ni].prep.rate) * (1.0 + nodes[nj].prep.rate);
                        let ns2 = theta_cov(ni, nj) / scale
                            + theta_of(ni) * theta_of(nj) * rate_cov(ni, nj);
                        ns2 * NS2_TO_M2
                    })
                    .collect()
            })
            .collect();
        // The timeline's zero in Unix terms: the reference's reading of its reception.
        let reference_node = &nodes[reference];
        let (_, reference_reception, (_, _, _, reference_linear)) =
            heard[reference_node.heard.ok_or("no reference")?];
        let origin_unix_ns =
            dated(reference_node.prep, reference_reception, reference_linear).ok_or("no origin")?;
        let data = &receptions.first().ok_or("no reception")?.message;
        Ok(Normalised {
            problem: Problem {
                items: items.into_iter().map(|(_, item)| item).collect(),
                clock_m2: Some(clock_m2),
                reference_ps,
                altitude: solve::altitude_prior(data),
            },
            origin_unix_ns,
            used,
            clocks: nodes.iter().map(|node| node.clock).collect(),
            bridges,
            rejected,
            dropped: total - hearers.len(),
            kappa,
        })
    }
}

/// Parts split from borrowed receptions, each copied once into its own list.
fn owned(parts: Vec<Vec<&Reception>>) -> Vec<Vec<Reception>> {
    parts
        .into_iter()
        .map(|part| part.into_iter().cloned().collect())
        .collect()
}
